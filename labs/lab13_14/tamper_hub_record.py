"""ЛР13–14, п. 10 — навмисна зміна запису в КОПІЇ бази drs_hub для перевірки журналу записів.

Імітує порушника з доступом до файла бази (обхід API сервера):
    python tamper_hub_record.py <копія drs_hub.db> release <версія>   — підмінити SHA-256 першого файла релізу
    python tamper_hub_record.py <копія drs_hub.db> report <report_id> — змінити 1 байт шифротексту звіту
    python tamper_hub_record.py <копія drs_hub.db> ledger <idx>       — змінити поле ref блока журналу
Після цього: python ..\\..\\tools\\drs_hub\\hub_ledger.py verify --db <копія> → «ПОРУШЕННЯ ЦІЛІСНОСТІ».

Робочу базу (тека даних сервера) інструмент змінювати відмовляється — лише копію.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sqlite3
import sys


def _is_live_db(path: str) -> bool:
    base = os.environ.get("DRS_HUB_DATA") or os.path.join(os.environ.get("USERPROFILE") or os.path.expanduser("~"), ".drs_hub")
    return os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(os.path.join(base, "drs_hub.db")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Зміна запису в копії бази drs_hub (ЛР13–14).")
    parser.add_argument("db")
    parser.add_argument("kind", choices=("release", "report", "ledger"))
    parser.add_argument("ref")
    args = parser.parse_args(argv)
    if _is_live_db(args.db):
        print("Відмовлено: це робоча база сервера. Скопіюйте її й змінюйте копію.")
        return 2
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    try:
        if args.kind == "release":
            row = conn.execute("SELECT record_json FROM releases WHERE version = ?", (args.ref,)).fetchone()
            if row is None:
                print("Немає такого релізу.")
                return 1
            record = json.loads(row["record_json"])
            old = record["files"][0]["sha256"]
            record["files"][0]["sha256"] = "f" * 64
            conn.execute("UPDATE releases SET record_json = ? WHERE version = ?",
                         (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), args.ref))
            print(f"Реліз {args.ref}: SHA-256 файла {record['files'][0]['name']} {old[:16]}… → {'f' * 16}…")
        elif args.kind == "report":
            row = conn.execute("SELECT envelope_json FROM reports WHERE report_id = ?", (args.ref,)).fetchone()
            if row is None:
                print("Немає такого звіту.")
                return 1
            envelope = json.loads(row["envelope_json"])
            raw = bytearray(base64.b64decode(envelope["ct"]))
            raw[len(raw) // 2] ^= 0x01
            envelope["ct"] = base64.b64encode(bytes(raw)).decode("ascii")
            conn.execute("UPDATE reports SET envelope_json = ? WHERE report_id = ?",
                         (json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")), args.ref))
            print(f"Звіт {args.ref}: змінено 1 байт шифротексту (позиція {len(raw) // 2}).")
        else:
            row = conn.execute("SELECT ref FROM ledger WHERE idx = ?", (int(args.ref),)).fetchone()
            if row is None:
                print("Немає такого блока.")
                return 1
            conn.execute("UPDATE ledger SET ref = ? WHERE idx = ?", (row["ref"] + "-forged", int(args.ref)))
            print(f"Блок {args.ref}: ref {row['ref']} → {row['ref']}-forged (хеш блока не перераховано).")
        conn.commit()
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
