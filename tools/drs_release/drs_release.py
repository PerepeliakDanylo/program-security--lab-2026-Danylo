"""drs_release — офлайн-інструмент супроводжувача релізів DynamicReloadSpeed (CLI).

Призначення цільового файлу в репозиторії: tools/drs_release/drs_release.py

Запускає супроводжувач У ВЛАСНОМУ терміналі (не в грі). Пароль вводиться через
getpass — як sudo чи git-credential; жодного перехоплення введення в процесі гри.

ЛР4 реалізує автентифікацію:
    python drs_release.py init                                   # порожній файл облікових записів
    python drs_release.py add-user maintainer --role maintainer  # користувач (пароль — getpass)
    python drs_release.py login maintainer                       # увійти й відкрити сесію

Сесія обмежена часом: простій 10 хв, абсолютно 60 хв (перевіряється на кожній команді).
Команди ЛР4: help, whoami, status, exit. Рольові операції (sign, rotate-key, verify)
додаються в ЛР5-7. Свідоме тимчасове обмеження ЛР4: ролі ще не застосовуються, тож
add-user у CLI доступний без входу; ЛР5 залишає його лише для порожнього сховища.

Залежності ядра автентифікації — лише стандартна бібліотека.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time

from accounts import AccountStore

DEFAULT_STORE = "drs_release.accounts.json"
DEFAULT_AUDIT = "drs_release.audit.log"

IDLE_TIMEOUT_S = 10 * 60
ABSOLUTE_TIMEOUT_S = 60 * 60

# Єдине повідомлення на будь-яку невдачу входу — щоб не підказувати, що саме не так.
GENERIC_LOGIN_ERROR = "Автентифікацію відхилено."


class Session:
    def __init__(self, username: str, roles: list[str], master: bytes) -> None:
        self.username = username
        self.roles = roles
        self.master = master          # потрібен у ЛР6 для секрету TOTP; не зберігається на диск
        self.started = time.time()
        self.last_activity = self.started

    def timed_out(self, now: float) -> str | None:
        if now - self.last_activity > IDLE_TIMEOUT_S:
            return "Сесію закрито через простій."
        if now - self.started > ABSOLUTE_TIMEOUT_S:
            return "Сесію закрито: вичерпано граничний час."
        return None


# --- команди сесії (реєстр розширюється в наступних лабах) ------------------
def cmd_help(session: Session, store: AccountStore, args: list[str]) -> bool:
    print("Команди: help | whoami | status | exit")
    print("(рольові операції sign/rotate-key/verify з'являться в ЛР5-7)")
    return True


def cmd_whoami(session: Session, store: AccountStore, args: list[str]) -> bool:
    print(f"{session.username}   ролі: {', '.join(session.roles)}")
    return True


def cmd_status(session: Session, store: AccountStore, args: list[str]) -> bool:
    now = time.time()
    idle_left = int(IDLE_TIMEOUT_S - (now - session.last_activity))
    abs_left = int(ABSOLUTE_TIMEOUT_S - (now - session.started))
    print(f"Сесія активна. До тайм-ауту простою: {idle_left} с; граничного: {abs_left} с.")
    return True


def cmd_exit(session: Session, store: AccountStore, args: list[str]) -> bool:
    print("Вихід із сесії.")
    return False


COMMANDS = {
    "help": cmd_help,
    "whoami": cmd_whoami,
    "status": cmd_status,
    "exit": cmd_exit,
    "quit": cmd_exit,
}


def run_session(session: Session, store: AccountStore) -> None:
    print(f"Вхід виконано як {session.username}. Введіть help для списку команд.")
    while True:
        now = time.time()
        reason = session.timed_out(now)
        if reason:
            print(reason)
            store.audit("session-timeout", session.username)
            return
        try:
            raw = input(f"drs:{session.username}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            store.audit("session-eof", session.username)
            return
        session.last_activity = time.time()
        if not raw:
            continue
        parts = raw.split()
        handler = COMMANDS.get(parts[0].lower())
        if handler is None:
            print("Невідома команда. help — список команд.")
            continue
        store.audit(f"cmd:{parts[0].lower()}", session.username)
        if not handler(session, store, parts[1:]):
            return


# --- підкоманди CLI ---------------------------------------------------------
def do_init(args: argparse.Namespace) -> int:
    import os
    if os.path.exists(args.store):
        print("Файл облікових записів уже існує — init скасовано.")
        return 1
    store = AccountStore(args.store, args.audit)
    store.save()
    store.audit("init")
    print(f"Створено порожній файл облікових записів: {args.store}")
    return 0


def do_add_user(args: argparse.Namespace) -> int:
    store = AccountStore(args.store, args.audit).load()
    pw1 = getpass.getpass("Новий пароль: ")
    pw2 = getpass.getpass("Повторіть пароль: ")
    if pw1 != pw2:
        print("Паролі не збігаються.")
        return 1
    if len(pw1) < 12:
        print("Пароль закороткий: мінімум 12 символів.")
        return 1
    try:
        store.add_user(args.username, pw1, roles=args.role or None)
    except ValueError as exc:
        print(str(exc))
        return 1
    store.save()
    print(f"Додано користувача {args.username} (ролі: {', '.join(args.role or ['viewer'])}).")
    return 0


def do_login(args: argparse.Namespace) -> int:
    store = AccountStore(args.store, args.audit).load()
    password = getpass.getpass("Пароль: ")
    result = store.authenticate(args.username, password)
    if not result.ok:
        # Єдине загальне повідомлення на будь-яку причину (невірні дані / блокування /
        # нема такого користувача) — щоб виклик не викривав ні існування акаунта, ні стан
        # блокування (SR-22). Деталі (locked, retry_after, no-such-user) — лише в журналі.
        print(GENERIC_LOGIN_ERROR)
        return 1
    session = Session(args.username, result.roles, result.master or b"")
    run_session(session, store)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="drs_release",
                                description="Офлайн-інструмент супроводжувача релізів DynamicReloadSpeed.")
    p.add_argument("--store", default=DEFAULT_STORE, help="файл облікових записів")
    p.add_argument("--audit", default=DEFAULT_AUDIT, help="файл журналу аудиту")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="створити порожній файл облікових записів")

    a = sub.add_parser("add-user", help="додати користувача (у ЛР4 — без входу; ЛР5 обмежує бутстрапом)")
    a.add_argument("username")
    a.add_argument("--role", action="append", help="роль (можна кілька разів); типово viewer")

    l = sub.add_parser("login", help="увійти й відкрити сесію")
    l.add_argument("username")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init":
        return do_init(args)
    if args.command == "add-user":
        return do_add_user(args)
    if args.command == "login":
        return do_login(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
