"""drs_hub — локальне адміністрування сервера (версія ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_admin.py

Керування клієнтами — НЕ мережева операція: мережевого API адміністрування в сервера немає (урок
Libraxis: /api/admin/* був досяжний будь-яким токеном адміністратора з будь-якої адреси). Адмініструє
той, хто має доступ до хоста й теки даних, — цим CLI напряму в базі.

    python hub_admin.py init [--force-tls]                 тека даних, база, CA і сертифікат сервера
    python hub_admin.py add-client <id> --role <роль> [--note …] [--secret-out ФАЙЛ]
    python hub_admin.py list-clients
    python hub_admin.py disable-client <id> | enable-client <id>
    python hub_admin.py rotate-secret <id> [--secret-out ФАЙЛ]
    python hub_admin.py revoke-tokens <id>
    python hub_admin.py show-ca
    python hub_admin.py status

Секрет клієнта показується один раз (або пишеться у файл поза репозиторієм з --secret-out); сервер
зберігає лише його SHA-256 — відновити секрет неможливо, лише ротувати. Ролі: tester | maintainer |
auditor (скоупи — hub_auth.ROLE_SCOPES).
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time

import hub_auth
import hub_config
import hub_server
import hub_tls
from hub_config import DataDirLock, HubConfigError
from hub_store import HubStore


def _store(cfg) -> HubStore:
    if not os.path.exists(cfg.db_path):
        raise HubConfigError("Бази немає — спершу: python hub_admin.py init")
    return HubStore(cfg.db_path)


def _write_secret_file(path: str, secret: str) -> None:
    path = os.path.abspath(path)
    if hub_config.path_inside_git_worktree(os.path.dirname(path)):
        raise HubConfigError(f"{path}: файл секрету не можна класти в робоче дерево git.")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as fh:
        fh.write(secret + "\n")


def _deliver_secret(client_id: str, secret: str, out: str | None) -> None:
    if out:
        _write_secret_file(out, secret)
        print(f"Секрет клієнта {client_id} записано у {os.path.abspath(out)} (лише власник; у репозиторій не класти).")
    else:
        print(f"Секрет клієнта {client_id} (показується ОДИН раз, сервер зберігає лише SHA-256):")
        print("  " + secret)


def cmd_init(cfg, args) -> int:
    if hub_config.path_inside_git_worktree(cfg.data_dir):
        raise HubConfigError(f"Тека даних {cfg.data_dir} усередині робочого дерева git — задайте іншу "
                             "(--data-dir або змінна DRS_HUB_DATA).")
    os.makedirs(cfg.data_dir, exist_ok=True)
    if not os.path.exists(cfg.config_path):
        hub_config.save_config(cfg)
    HubStore(cfg.db_path).init_db(hub_server.collect_schemas())
    if args.force_tls or not (os.path.exists(cfg.cert_path) and os.path.exists(cfg.key_path)
                              and os.path.exists(cfg.ca_path)):
        info = hub_tls.create_ca_and_server_cert(cfg.tls_dir)
        print(f"TLS: новий CA і сертифікат сервера (localhost, 127.0.0.1) до {info['not_after']}.")
    print(f"Тека даних: {cfg.data_dir}")
    print(f"База:       {cfg.db_path}")
    print(f"CA для клієнтів (відкритий, можна передавати): {cfg.ca_path}")
    print(f"Відбиток CA (SHA-256): {hub_tls.fingerprint(cfg.ca_path)}")
    return 0


def cmd_add_client(cfg, args) -> int:
    if not hub_auth.CLIENT_ID_RE.fullmatch(args.client_id):
        print("client_id: 3–48 символів a-z 0-9 . _ -, починається з літери чи цифри.")
        return 1
    secret = hub_auth.new_client_secret()
    try:
        _store(cfg).add_client(args.client_id, args.role, hub_auth.sha256_hex(secret), args.note or "")
    except sqlite3.IntegrityError:
        print(f"Клієнт {args.client_id} уже існує (новий секрет — rotate-secret).")
        return 1
    print(f"Додано клієнта {args.client_id}, роль {args.role}, скоупи: "
          f"{' '.join(hub_auth.ROLE_SCOPES[args.role])}.")
    _deliver_secret(args.client_id, secret, args.secret_out)
    return 0


def cmd_list_clients(cfg, args) -> int:
    rows = _store(cfg).list_clients()
    if not rows:
        print("Клієнтів немає.")
        return 0
    print(f"{'client_id':<24} {'роль':<11} {'стан':<9} {'створено (UTC)':<21} примітка")
    for row in rows:
        state = "увімкнено" if row["enabled"] else "вимкнено"
        print(f"{row['client_id']:<24} {row['role']:<11} {state:<9} {row['created_at']:<21} {row['note']}")
    return 0


def cmd_set_enabled(cfg, args, enabled: bool) -> int:
    store = _store(cfg)
    if not store.set_client_enabled(args.client_id, enabled):
        print("Немає такого клієнта.")
        return 1
    revoked = 0 if enabled else store.revoke_client_tokens(args.client_id)
    print(f"Клієнт {args.client_id} {'увімкнено' if enabled else 'вимкнено'}"
          + ("" if enabled else f"; відкликано токенів: {revoked}") + ".")
    return 0


def cmd_rotate_secret(cfg, args) -> int:
    store = _store(cfg)
    secret = hub_auth.new_client_secret()
    if not store.set_client_secret(args.client_id, hub_auth.sha256_hex(secret)):
        print("Немає такого клієнта.")
        return 1
    revoked = store.revoke_client_tokens(args.client_id)
    print(f"Секрет {args.client_id} змінено; відкликано активних токенів: {revoked}.")
    _deliver_secret(args.client_id, secret, args.secret_out)
    return 0


def cmd_revoke_tokens(cfg, args) -> int:
    print(f"Відкликано токенів {args.client_id}: {_store(cfg).revoke_client_tokens(args.client_id)}.")
    return 0


def cmd_show_ca(cfg, args) -> int:
    if not os.path.exists(cfg.ca_path):
        print("CA немає — спершу init.")
        return 1
    print(f"CA: {cfg.ca_path}")
    print(f"Відбиток (SHA-256): {hub_tls.fingerprint(cfg.ca_path)}")
    return 0


def cmd_status(cfg, args) -> int:
    store = _store(cfg)
    lock = DataDirLock(cfg.lock_path)
    running = not lock.acquire()
    if not running:
        lock.release()
    print(f"Версія коду: {hub_config.HUB_VERSION}; тека даних: {cfg.data_dir}")
    print(f"Сервер: {'працює' if running else 'зупинено'}; база: integrity_check = {store.integrity_check()}")
    print(f"Клієнтів: {len(store.list_clients())}; активних токенів: {store.count_active_tokens(time.time())}; "
          f"релізів: {len(store.list_releases())}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hub_admin", description="DRS Hub — локальне адміністрування.")
    parser.add_argument("--data-dir", default=None, help="тека даних (типово %%USERPROFILE%%\\.drs_hub)")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="створити теку даних, базу, CA і сертифікат сервера")
    init.add_argument("--force-tls", action="store_true", help="перевипустити CA і сертифікат")
    add = sub.add_parser("add-client", help="зареєструвати клієнта")
    add.add_argument("client_id")
    add.add_argument("--role", required=True, choices=sorted(hub_auth.ROLE_SCOPES))
    add.add_argument("--note", default="")
    add.add_argument("--secret-out", default=None, help="файл для секрету (поза репозиторієм)")
    sub.add_parser("list-clients", help="перелік клієнтів (без секретів)")
    for name in ("disable-client", "enable-client", "revoke-tokens"):
        one = sub.add_parser(name)
        one.add_argument("client_id")
    rot = sub.add_parser("rotate-secret", help="новий секрет; старі токени відкликаються")
    rot.add_argument("client_id")
    rot.add_argument("--secret-out", default=None)
    sub.add_parser("show-ca", help="шлях і відбиток CA")
    sub.add_parser("status", help="стан бази й сервера")
    return parser


def main(argv: list[str] | None = None) -> int:
    hub_config.safe_console()
    args = build_parser().parse_args(argv)
    try:
        cfg = hub_config.load_config(args.data_dir)
        handlers = {
            "init": cmd_init, "add-client": cmd_add_client, "list-clients": cmd_list_clients,
            "disable-client": lambda c, a: cmd_set_enabled(c, a, False),
            "enable-client": lambda c, a: cmd_set_enabled(c, a, True),
            "rotate-secret": cmd_rotate_secret, "revoke-tokens": cmd_revoke_tokens,
            "show-ca": cmd_show_ca, "status": cmd_status,
        }
        return handlers[args.command](cfg, args)
    except (HubConfigError, OSError) as exc:
        print(f"Помилка: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
