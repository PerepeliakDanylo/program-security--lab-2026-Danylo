"""drs_hub — журнал записів, криптографічно зв'язаних у ланцюг (версія ЛР13–14).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_ledger.py

Принцип блокчейну без консенсусу (сервер один, Proof of Work тут нічого не дає — обґрунтування в
docs/security/e2ee_ledger.md): кожна критична подія — публікація релізу, прийом звіту тестера —
дописує блок {idx, ts, kind, ref, payload_sha256, prev_hash} з hash = SHA-256 канонічного JSON блока.
Блок пишеться в ТІЙ САМІЙ транзакції SQLite, що й запис даних (через подію app.emit), тож запис без
блока неможливий. Початковий блок (genesis) створюється при першому використанні; наявні до того
релізи й звіти дописуються в журнал у порядку появи (backfill) — з позначкою ref.

verify() перевіряє: безперервність номерів, hash кожного блока, prev_hash = hash попереднього, і
звіряє payload_sha256 з поточними даними (SHA-256 канонічного JSON релізу чи конверта звіту): зміна
запису після фіксації, зникнення запису чи запис, доданий у базу в обхід журналу, — виявляються.
Обмеження: той, хто контролює базу, може перерахувати весь ланцюг — тому голова ланцюга (idx, hash)
фіксується поза сервером (запис журналу змін у git — «якорення»).

    python hub_ledger.py verify [--data-dir D | --db ШЛЯХ]     перевірка (код 1 — порушення)
    python hub_ledger.py head   [--data-dir D | --db ШЛЯХ]     голова ланцюга для якорення
    python hub_ledger.py list   [--data-dir D | --db ШЛЯХ]     усі блоки
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys

from hub_store import utc_now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    idx            INTEGER PRIMARY KEY,
    ts             TEXT NOT NULL,
    kind           TEXT NOT NULL,
    ref            TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL
);
"""

ZERO_HASH = "0" * 64
GENESIS_PAYLOAD = hashlib.sha256(b"drs-hub ledger genesis v1").hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def block_hash(idx: int, ts: str, kind: str, ref: str, payload_sha256: str, prev_hash: str) -> str:
    body = json.dumps({"idx": idx, "ts": ts, "kind": kind, "ref": ref, "payload_sha256": payload_sha256,
                       "prev_hash": prev_hash}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256_text(body)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone() is not None


def _insert(conn: sqlite3.Connection, idx: int, kind: str, ref: str, payload: str, prev: str) -> str:
    ts = utc_now_iso()
    digest = block_hash(idx, ts, kind, ref, payload, prev)
    conn.execute("INSERT INTO ledger (idx, ts, kind, ref, payload_sha256, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (idx, ts, kind, ref, payload, prev, digest))
    return digest


def ensure_genesis(conn: sqlite3.Connection) -> int:
    """Genesis + дописати наявні релізи й звіти, яких ще немає в журналі. Повертає кількість нових блоків."""
    added = 0
    if conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == 0:
        _insert(conn, 0, "genesis", "drs-hub", GENESIS_PAYLOAD, ZERO_HASH)
        added += 1
    known = {(row["kind"], row["ref"]) for row in conn.execute("SELECT kind, ref FROM ledger")}
    pending: list[tuple[str, str, str, str]] = []
    if _table_exists(conn, "releases"):
        for row in conn.execute("SELECT version, record_json, published_at FROM releases"):
            if ("release", row["version"]) not in known:
                pending.append((row["published_at"], "release", row["version"], sha256_text(row["record_json"])))
    if _table_exists(conn, "reports"):
        for row in conn.execute("SELECT report_id, envelope_json, received_at FROM reports"):
            if ("report", row["report_id"]) not in known:
                pending.append((row["received_at"], "report", row["report_id"], sha256_text(row["envelope_json"])))
    for _when, kind, ref, payload in sorted(pending):
        append(conn, kind, ref, payload)
        added += 1
    return added


def append(conn: sqlite3.Connection, kind: str, ref: str, payload_sha256: str) -> tuple[int, str]:
    """Дописати блок у відкритій транзакції (conn з store.write()). Повертає (idx, hash)."""
    last = conn.execute("SELECT idx, hash FROM ledger ORDER BY idx DESC LIMIT 1").fetchone()
    if last is None:
        _insert(conn, 0, "genesis", "drs-hub", GENESIS_PAYLOAD, ZERO_HASH)
        last = conn.execute("SELECT idx, hash FROM ledger ORDER BY idx DESC LIMIT 1").fetchone()
    idx = int(last["idx"]) + 1
    return idx, _insert(conn, idx, kind, ref, payload_sha256, last["hash"])


def head(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute("SELECT idx, ts, hash FROM ledger ORDER BY idx DESC LIMIT 1").fetchone()
    return {"idx": row["idx"], "ts": row["ts"], "hash": row["hash"]} if row else None


def verify(conn: sqlite3.Connection) -> dict:
    rows = conn.execute("SELECT * FROM ledger ORDER BY idx").fetchall()
    problems: list[str] = []
    prev = ZERO_HASH
    for position, row in enumerate(rows):
        idx = row["idx"]
        if idx != position:
            problems.append(f"блок {idx}: розрив нумерації (очікувався {position})")
        if row["hash"] != block_hash(idx, row["ts"], row["kind"], row["ref"], row["payload_sha256"], row["prev_hash"]):
            problems.append(f"блок {idx}: хеш не відповідає вмісту блока (блок змінено)")
        if row["prev_hash"] != prev:
            problems.append(f"блок {idx}: prev_hash не дорівнює хешу попереднього блока (ланцюг розірвано)")
        prev = row["hash"]
    data: dict[tuple[str, str], str] = {}
    if _table_exists(conn, "releases"):
        for row in conn.execute("SELECT version, record_json FROM releases"):
            data[("release", row["version"])] = sha256_text(row["record_json"])
    if _table_exists(conn, "reports"):
        for row in conn.execute("SELECT report_id, envelope_json FROM reports"):
            data[("report", row["report_id"])] = sha256_text(row["envelope_json"])
    seen = set()
    for row in rows:
        key = (row["kind"], row["ref"])
        if row["kind"] not in ("release", "report"):
            continue
        seen.add(key)
        actual = data.get(key)
        if actual is None:
            problems.append(f"блок {row['idx']}: {row['kind']} {row['ref']} зник із бази")
        elif actual != row["payload_sha256"]:
            problems.append(f"блок {row['idx']}: {row['kind']} {row['ref']} змінено після фіксації "
                            "(SHA-256 даних ≠ зафіксованого)")
    for kind, ref in sorted(set(data) - seen):
        problems.append(f"{kind} {ref} є в базі, але відсутній у журналі (додано в обхід)")
    return {"ok": not problems, "blocks": len(rows), "head": head(conn) if rows else None,
            "problems": problems[:50]}


# --- CLI (локальна перевірка без сервера) --------------------------------------------
def _open(args) -> sqlite3.Connection:
    if args.db:
        path = args.db
    else:
        import hub_config
        path = hub_config.load_config(args.data_dir).db_path
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    conn = sqlite3.connect(path, timeout=10)     # лише читання: команди нічого не змінюють
    conn.row_factory = sqlite3.Row
    return conn


def main(argv: list[str] | None = None) -> int:
    import hub_config
    hub_config.safe_console()
    parser = argparse.ArgumentParser(prog="hub_ledger", description="DRS Hub — перевірка хеш-ланцюга записів.")
    parser.add_argument("command", choices=("verify", "head", "list"))
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--db", default=None, help="шлях до копії бази (напр. для демонстрації підміни)")
    args = parser.parse_args(argv)
    try:
        conn = _open(args)
    except (FileNotFoundError, sqlite3.Error) as exc:
        print(f"Помилка: базу не відкрито ({exc})")
        return 2
    try:
        if args.command == "head":
            print(json.dumps(head(conn), ensure_ascii=False))
            return 0
        if args.command == "list":
            for row in conn.execute("SELECT * FROM ledger ORDER BY idx"):
                print(f"{row['idx']:>4} {row['ts']} {row['kind']:<8} {row['ref'][:32]:<32} "
                      f"payload {row['payload_sha256'][:12]}… prev {row['prev_hash'][:12]}… hash {row['hash'][:16]}…")
            return 0
        result = verify(conn)
        print(f"Блоків: {result['blocks']}; голова: {result['head']}")
        if result["ok"]:
            print("Ланцюг цілий: хеші блоків, зв'язки prev_hash і SHA-256 даних збігаються.")
            return 0
        print("ПОРУШЕННЯ ЦІЛІСНОСТІ:")
        for problem in result["problems"]:
            print("  — " + problem)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
