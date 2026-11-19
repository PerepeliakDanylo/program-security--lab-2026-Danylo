"""drs_hub — резервне копіювання, перевірка й відновлення (версія ЛР15–16).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_backup.py

Стратегія (обґрунтування, RPO/RTO — docs/security/backup_recovery.md):
  * ПОВНА копія щоразу: дані сервера займають кілобайти–мегабайти, тож інкрементні копії не дають
    виграшу, а відновлення з одного файла — найпростіше й найнадійніше;
  * склад: узгоджений знімок бази (онлайн, SQLite backup API — сервер може працювати) БЕЗ сеансового
    стану (токени й лічильники невдач очищено, VACUUM), hub.json, TLS (CA, сертифікат і ключ сервера),
    безпекові журнали (security*.jsonl) і ключовий матеріал супроводжувача з профілю (закритий ключ
    звітів, ключі підпису релізу, файл облікових записів drs_release) — те, що неможливо відтворити;
  * архів ZIP (MANIFEST.json із SHA-256 кожного файла) шифрується AES-256-GCM ключем scrypt
    (N=2^15, r=8, p=1) від парольної фрази ≥ 16 символів; параметри — в автентифікованому заголовку;
    поруч — <архів>.sha256 (перевірка цілісності без фрази);
  * відновлення — лише в теку, з якою сервер НЕ працює (блокування теки), після повної перевірки
    (SHA-256, GCM, маніфест, integrity_check, хеш-ланцюг); наявна база не видаляється, а відкладається
    в pre-restore-<час>/; ключовий матеріал — у restored_extra/ з підказками, куди його повернути;
  * зберігання за схемою GFS: 7 щоденних, 4 щотижневих, 6 щомісячних (prune).

    python hub_backup.py create  [--dest DIR] [--profile FILE] [--label L]
    python hub_backup.py verify  АРХІВ [--deep]
    python hub_backup.py restore АРХІВ --target ТЕКА [--force]
    python hub_backup.py list    [--dest DIR]
    python hub_backup.py prune   [--dest DIR] [--keep-daily 7 --keep-weekly 4 --keep-monthly 6] [--dry-run]
Парольна фраза — змінна DRS_HUB_BACKUP_PASSPHRASE або getpass; поруч із копіями її не зберігати.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import getpass
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import hub_config
import hub_log

FORMAT = "drs-hub-backup/1"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1        # ≈ 32 МіБ пам'яті й ~0,1–0,3 с на спробу фрази
SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSPHRASE = 16
MAX_MEMBER_BYTES = 512 * 1024 * 1024
NAME_RE = re.compile(r"^drs-hub-(\d{8})-(\d{6})(?:-[a-z0-9-]{1,32})?(?:-\d+)?\.dhbk$")
_ARC_RE = re.compile(r"^(db|config|tls|logs|extra)/[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")   # «..» неможливе
_EXTRA_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")


class BackupError(Exception):
    """Копію не створено, не підтверджено або не відновлено — причина в тексті."""


def default_dest() -> str:
    return os.environ.get("DRS_HUB_BACKUP_DEST") or os.path.join(
        os.environ.get("USERPROFILE") or os.path.expanduser("~"), "DRS_backups")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _derive(passphrase: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(passphrase, salt=salt, n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM, dklen=32)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _db_checks(path: str) -> dict:
    """integrity_check і, якщо є журнал записів, повна перевірка хеш-ланцюга."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        result = {"integrity": str(conn.execute("PRAGMA integrity_check").fetchone()[0]),
                  "ledger_ok": None, "ledger_head": None, "ledger_problems": []}
        if _table_exists(conn, "ledger"):
            import hub_ledger
            checked = hub_ledger.verify(conn)
            result.update(ledger_ok=checked["ok"], ledger_head=checked["head"], ledger_problems=checked["problems"])
        result["counts"] = {name: int(conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0])
                            for name in ("clients", "releases", "reports", "ledger") if _table_exists(conn, name)}
        return result
    finally:
        conn.close()


def _snapshot_db(db_path: str, out_path: str) -> dict:
    """Онлайн-знімок бази без сеансового стану."""
    source = sqlite3.connect(db_path, timeout=30)
    target = sqlite3.connect(out_path)
    try:
        source.backup(target)
        target.execute("PRAGMA journal_mode = DELETE")
        for table in ("tokens", "auth_failures"):
            if _table_exists(target, table):
                target.execute(f"DELETE FROM {table}")
        target.commit()
        target.execute("VACUUM")          # видалені сторінки (хеші токенів) не лишаються у файлі
    finally:
        target.close()
        source.close()
    return _db_checks(out_path)


def load_profile(path: str | None) -> list[dict]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8-sig") as fh:     # Set-Content -Encoding utf8 (PS 5.1) пише BOM
        data = json.load(fh)
    items = data.get("extra", []) if isinstance(data, dict) else []
    clean = []
    for item in items:
        if not isinstance(item, dict) or not _EXTRA_NAME_RE.fullmatch(str(item.get("name", ""))) or not item.get("path"):
            raise BackupError("профіль: кожен елемент extra — {name, path[, restore_to]}")
        clean.append({"name": item["name"], "path": os.path.expandvars(item["path"]),
                      "restore_to": os.path.expandvars(item.get("restore_to", item["path"]))})
    return clean


def _member_list(cfg, snapshot: str, extras: list[dict]) -> tuple[list[tuple[str, str]], list[str]]:
    members = [("db/drs_hub.db", snapshot)]
    missing: list[str] = []
    if os.path.exists(cfg.config_path):
        members.append(("config/hub.json", cfg.config_path))
    for name in ("ca_cert.pem", "server_cert.pem", "server_key.pem"):
        path = os.path.join(cfg.tls_dir, name)
        if os.path.exists(path):
            members.append(("tls/" + name, path))
        else:
            missing.append("tls/" + name)
    if os.path.isdir(cfg.log_dir):
        for name in sorted(os.listdir(cfg.log_dir)):
            if name.startswith("security") and name.endswith(".jsonl"):
                members.append(("logs/" + name, os.path.join(cfg.log_dir, name)))
    for item in extras:
        if os.path.exists(item["path"]):
            members.append(("extra/" + item["name"], item["path"]))
        else:
            missing.append("extra/" + item["name"] + " (" + item["path"] + ")")
    return members, missing


def create_backup(cfg, dest: str, passphrase: bytes, profile: str | None = None, label: str = "") -> str:
    if len(passphrase) < MIN_PASSPHRASE:
        raise BackupError(f"Парольна фраза коротша за {MIN_PASSPHRASE} символів.")
    if not os.path.exists(cfg.db_path):
        raise BackupError(f"Бази {cfg.db_path} немає.")
    dest = os.path.abspath(dest)
    if hub_config.path_inside_git_worktree(dest):
        raise BackupError("Резервні копії не можна класти в робоче дерево git.")
    if label and not re.fullmatch(r"[a-z0-9-]{1,32}", label):
        raise BackupError("label: 1–32 символи a-z 0-9 -")
    os.makedirs(dest, exist_ok=True)
    extras = load_profile(profile)
    created = datetime.datetime.now(datetime.timezone.utc)
    with tempfile.TemporaryDirectory(prefix="drs_hub_backup_") as tmp:
        snapshot = os.path.join(tmp, "drs_hub.db")
        checks = _snapshot_db(cfg.db_path, snapshot)
        members, missing = _member_list(cfg, snapshot, extras)
        manifest = {"format": FORMAT, "created": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "hub_version": hub_config.HUB_VERSION, "label": label, "db": checks,
                    "files": [], "missing": missing,
                    "restore_hints": {"extra/" + e["name"]: e["restore_to"] for e in extras}}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for arcname, path in sorted(members):
                with open(path, "rb") as fh:
                    data = fh.read()
                manifest["files"].append({"path": arcname, "size": len(data),
                                          "sha256": hashlib.sha256(data).hexdigest()})
                archive.writestr(arcname, data)
            archive.writestr("MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {"format": FORMAT, "created": manifest["created"], "label": label, "hub_version": hub_config.HUB_VERSION,
              "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                      "salt": base64.b64encode(salt).decode("ascii")},
              "cipher": "AES-256-GCM", "nonce": base64.b64encode(nonce).decode("ascii")}
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(_derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)).encrypt(nonce, buffer.getvalue(),
                                                                                       header_bytes)
    stem = "drs-hub-" + created.strftime("%Y%m%d-%H%M%S") + (f"-{label}" if label else "")
    path = os.path.join(dest, stem + ".dhbk")
    counter = 1
    while os.path.exists(path):
        path = os.path.join(dest, f"{stem}-{counter}.dhbk")
        counter += 1
    with open(path, "xb") as fh:
        fh.write(header_bytes + b"\n" + ciphertext)
    with open(path + ".sha256", "w", encoding="ascii", newline="\n") as fh:
        fh.write(f"{_sha256_file(path)}  {os.path.basename(path)}\n")
    hub_log.event("info", "admin.backup_created", archive=os.path.basename(path), size=os.path.getsize(path),
                  files=len(manifest["files"]), missing=len(missing), db_integrity=checks["integrity"],
                  ledger_ok=checks["ledger_ok"])
    return path


def _read_archive(path: str) -> tuple[dict, bytes, bytes]:
    with open(path, "rb") as fh:
        raw = fh.read()
    header_bytes, sep, ciphertext = raw.partition(b"\n")
    if not sep:
        raise BackupError("Файл не схожий на копію drs_hub (немає заголовка).")
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BackupError("Заголовок копії пошкоджено.") from None
    if header.get("format") != FORMAT:
        raise BackupError(f"Невідомий формат копії: {header.get('format')!r}")
    return header, header_bytes, ciphertext


def _decrypt(header: dict, header_bytes: bytes, ciphertext: bytes, passphrase: bytes) -> bytes:
    kdf = header["kdf"]
    key = _derive(passphrase, base64.b64decode(kdf["salt"]), int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
    try:
        return AESGCM(key).decrypt(base64.b64decode(header["nonce"]), ciphertext, header_bytes)
    except InvalidTag:
        raise BackupError("Автентифікацію AES-GCM не пройдено: невірна фраза або копію змінено.") from None


def verify_backup(path: str, passphrase: bytes | None = None) -> dict:
    problems: list[str] = []
    result: dict = {"archive": os.path.basename(path), "sha256_ok": None, "deep": passphrase is not None}
    sidecar = path + ".sha256"
    if os.path.exists(sidecar):
        with open(sidecar, "r", encoding="ascii") as fh:
            expected = fh.read().split()[0]
        result["sha256_ok"] = expected == _sha256_file(path)
        if not result["sha256_ok"]:
            problems.append("SHA-256 архіву не збігається з <архів>.sha256 (копію пошкоджено чи змінено)")
    else:
        problems.append("немає <архів>.sha256 — цілісність без фрази не перевірити")
    try:
        header, header_bytes, ciphertext = _read_archive(path)
        result["created"] = header.get("created")
    except BackupError as exc:
        problems.append(str(exc))
        result.update(ok=False, problems=problems)
        return result
    if passphrase is not None:
        try:
            payload = _decrypt(header, header_bytes, ciphertext, passphrase)
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                manifest = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
                for entry in manifest["files"]:
                    if not _ARC_RE.fullmatch(entry["path"]):
                        problems.append(f"недопустимий шлях у копії: {entry['path']}")
                        continue
                    info = archive.getinfo(entry["path"])
                    if info.file_size > MAX_MEMBER_BYTES:
                        problems.append(f"{entry['path']}: завеликий")
                        continue
                    if hashlib.sha256(archive.read(entry["path"])).hexdigest() != entry["sha256"]:
                        problems.append(f"{entry['path']}: SHA-256 не збігається з маніфестом")
                with tempfile.TemporaryDirectory(prefix="drs_hub_verify_") as tmp:
                    db_copy = os.path.join(tmp, "drs_hub.db")
                    with open(db_copy, "wb") as fh:
                        fh.write(archive.read("db/drs_hub.db"))
                    checks = _db_checks(db_copy)
            result.update(manifest_files=len(manifest["files"]), missing=manifest.get("missing", []), db=checks)
            if checks["integrity"] != "ok":
                problems.append(f"integrity_check бази: {checks['integrity']}")
            if checks["ledger_ok"] is False:
                problems.append("хеш-ланцюг у копії порушено: " + "; ".join(checks["ledger_problems"][:2]))
        except (BackupError, zipfile.BadZipFile, KeyError, ValueError) as exc:
            problems.append(str(exc))
    result.update(ok=not problems, problems=problems)
    return result


def restore_backup(path: str, target: str, passphrase: bytes, force: bool = False) -> dict:
    started = time.perf_counter()
    checked = verify_backup(path, passphrase)
    if not checked["ok"]:
        raise BackupError("Копію не підтверджено: " + "; ".join(checked["problems"][:3]))
    target = os.path.abspath(target)
    if hub_config.path_inside_git_worktree(target):
        raise BackupError("Цільова тека всередині робочого дерева git.")
    os.makedirs(target, exist_ok=True)
    lock = hub_config.DataDirLock(os.path.join(target, hub_config.LOCK_NAME))
    if not lock.acquire():
        raise BackupError("З цією текою працює сервер (тека заблокована) — спершу зупиніть його.")
    try:
        db_target = os.path.join(target, hub_config.DB_NAME)
        if os.path.exists(db_target):
            if not force:
                raise BackupError("У цільовій теці вже є база — повторіть із --force (стара буде відкладена).")
            aside = os.path.join(target, "pre-restore-" + time.strftime("%Y%m%d-%H%M%S", time.gmtime()))
            os.makedirs(aside, exist_ok=True)
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(db_target + suffix):
                    shutil.move(db_target + suffix, os.path.join(aside, hub_config.DB_NAME + suffix))
        header, header_bytes, ciphertext = _read_archive(path)
        payload = _decrypt(header, header_bytes, ciphertext, passphrase)
        placed, extras = 0, []
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            manifest = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
            for entry in manifest["files"]:
                area, name = entry["path"].split("/", 1)
                if area == "db":
                    out = db_target
                elif area == "config":
                    out = os.path.join(target, hub_config.CONFIG_NAME)
                elif area == "tls":
                    out = os.path.join(target, "tls", name)
                elif area == "logs":
                    out = os.path.join(target, "logs", name)
                    if os.path.exists(out):
                        out += ".restored"
                else:
                    out = os.path.join(target, "restored_extra", name)
                    extras.append((name, manifest.get("restore_hints", {}).get(entry["path"], "")))
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "wb") as fh:
                    fh.write(archive.read(entry["path"]))
                placed += 1
        if extras:
            with open(os.path.join(target, "restored_extra", "RESTORE_HINTS.txt"), "w", encoding="utf-8") as fh:
                fh.write("Ключовий матеріал супроводжувача: перенесіть файли на місця нижче й видаліть цю теку.\n")
                for name, hint in extras:
                    fh.write(f"{name} -> {hint}\n")
        checks = _db_checks(db_target)
        with open(os.path.join(target, "RESTORED_FROM.txt"), "w", encoding="utf-8") as fh:
            fh.write(f"{os.path.basename(path)}  created {header.get('created')}  restored "
                     f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
    finally:
        lock.release()
    seconds = round(time.perf_counter() - started, 2)
    hub_log.event("info", "admin.backup_restored", archive=os.path.basename(path), target=target, files=placed,
                  db_integrity=checks["integrity"], ledger_ok=checks["ledger_ok"], seconds=seconds)
    return {"target": target, "files": placed, "extras": extras, "integrity": checks["integrity"],
            "ledger_ok": checks["ledger_ok"], "ledger_head": checks["ledger_head"], "counts": checks.get("counts"),
            "seconds": seconds}


def list_backups(dest: str) -> list[tuple[datetime.datetime, str]]:
    found = []
    if os.path.isdir(dest):
        for name in os.listdir(dest):
            match = NAME_RE.match(name)
            if match:
                when = datetime.datetime.strptime(match.group(1) + match.group(2), "%Y%m%d%H%M%S")
                found.append((when, os.path.join(dest, name)))
    return sorted(found, reverse=True)


def prune(dest: str, keep_daily: int = 7, keep_weekly: int = 4, keep_monthly: int = 6,
          dry_run: bool = False) -> tuple[list[str], list[str]]:
    """GFS: найновіша копія кожного з останніх N днів, тижнів (ISO) і місяців; решта видаляється."""
    if keep_daily < 1 or keep_weekly < 0 or keep_monthly < 0:
        raise BackupError("keep-daily ≥ 1 (найсвіжіша копія не видаляється ніколи), keep-weekly/monthly ≥ 0")
    backups = list_backups(dest)
    keep: set[str] = set()
    for rule, limit in ((lambda d: d.date(), keep_daily), (lambda d: d.isocalendar()[:2], keep_weekly),
                        (lambda d: (d.year, d.month), keep_monthly)):
        seen = []
        for when, path in backups:
            bucket = rule(when)
            if bucket not in seen:
                seen.append(bucket)
                if len(seen) <= limit:
                    keep.add(path)
    kept = [p for _, p in backups if p in keep]
    removed = [p for _, p in backups if p not in keep]
    if not dry_run:
        for path in removed:
            for victim in (path, path + ".sha256"):
                if os.path.exists(victim):
                    os.remove(victim)
    return kept, removed


# --- CLI -----------------------------------------------------------------------------
def _passphrase(confirm: bool) -> bytes:
    env = os.environ.get("DRS_HUB_BACKUP_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    first = getpass.getpass("Парольна фраза резервних копій: ")
    if confirm and getpass.getpass("Повторіть: ") != first:
        raise BackupError("Фрази не збігаються.")
    return first.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    hub_config.safe_console()
    parser = argparse.ArgumentParser(prog="hub_backup", description="DRS Hub — резервні копії й відновлення.")
    parser.add_argument("--data-dir", default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--dest", default=default_dest())
    create.add_argument("--profile", default=None, help="JSON із ключовим матеріалом поза текою даних")
    create.add_argument("--label", default="")
    verify = sub.add_parser("verify")
    verify.add_argument("archive")
    verify.add_argument("--deep", action="store_true", help="розшифрувати й перевірити вміст (потрібна фраза)")
    restore = sub.add_parser("restore")
    restore.add_argument("archive")
    restore.add_argument("--target", required=True)
    restore.add_argument("--force", action="store_true")
    listing = sub.add_parser("list")
    listing.add_argument("--dest", default=default_dest())
    pruning = sub.add_parser("prune")
    pruning.add_argument("--dest", default=default_dest())
    pruning.add_argument("--keep-daily", type=int, default=7)
    pruning.add_argument("--keep-weekly", type=int, default=4)
    pruning.add_argument("--keep-monthly", type=int, default=6)
    pruning.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        cfg = hub_config.load_config(args.data_dir)
        if not hub_config.path_inside_git_worktree(cfg.data_dir):
            hub_log.setup(cfg, console=False, component="drs_hub.admin")
        if args.command == "create":
            started = time.perf_counter()
            path = create_backup(cfg, args.dest, _passphrase(confirm=True), args.profile, args.label)
            print(f"Копію створено за {time.perf_counter() - started:.1f} с: {path}")
            print(f"  розмір {os.path.getsize(path)} Б; SHA-256 → {os.path.basename(path)}.sha256")
            return 0
        if args.command == "verify":
            result = verify_backup(args.archive, _passphrase(False) if args.deep else None)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["ok"] else 1
        if args.command == "restore":
            result = restore_backup(args.archive, args.target, _passphrase(False), args.force)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "list":
            for when, path in list_backups(args.dest):
                print(f"{when:%Y-%m-%d %H:%M:%S} UTC  {os.path.getsize(path):>10} Б  {os.path.basename(path)}")
            return 0
        kept, removed = prune(args.dest, args.keep_daily, args.keep_weekly, args.keep_monthly, args.dry_run)
        print(f"Залишено {len(kept)}, {'буде видалено' if args.dry_run else 'видалено'} {len(removed)}:")
        for path in removed:
            print("  - " + os.path.basename(path))
        return 0
    except (BackupError, OSError, ValueError) as exc:
        print(f"Помилка: {exc}")
        return 2
    finally:
        hub_log.shutdown()


if __name__ == "__main__":
    sys.exit(main())
