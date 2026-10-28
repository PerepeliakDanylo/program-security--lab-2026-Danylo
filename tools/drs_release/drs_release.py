"""drs_release — CLI інструмента супроводжувача релізів (версія ЛР5: керування доступом).

Призначення цільового файлу в репозиторії: tools/drs_release/drs_release.py
Ця версія ЗАМІНЮЄ версію ЛР4: додано RBAC+ABAC+DAC (authz.py), step-up і керовані
доступом операції в сесії. Автентифікація (ЛР4) незмінна: getpass, офлайн, не в грі.
CLI-add-user тепер лише бутстрап першого власника (свідоме обмеження ЛР4 закрито).

CLI:
    python drs_release.py init                      # порожній файл облікових записів
    python drs_release.py add-user <owner>          # БУТСТРАП: лише коли записів ще немає → owner
    python drs_release.py login <user>              # вхід і сесія

У сесії (перевірка прав — у точці виконання кожної операції, не ховаємо меню):
    help whoami status                               # будь-який автентифікований
    list-users                                       # viewer+
    build-manifest                                   # contributor+          (тіло — ЛР7)
    sign <build>                                     # maintainer+, ABAC чистий master (тіло — ЛР7)
    add-user <user> <role> | set-role <user> <role...> | rotate-key   # owner (rotate — ЛР6)
    passwd [user]                                    # власник свого запису або owner
    verify                                           # viewer+               (тіло — ЛР7)
    exit
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time

from accounts import AccountStore
from authz import ROLES, authorize

DEFAULT_STORE = "drs_release.accounts.json"
DEFAULT_AUDIT = "drs_release.audit.log"
RELEASE_STATE = "release.state.json"

IDLE_TIMEOUT_S = 10 * 60
ABSOLUTE_TIMEOUT_S = 60 * 60

GENERIC_LOGIN_ERROR = "Автентифікацію відхилено."
DENY = "Операцію відхилено."


class Session:
    def __init__(self, username: str, roles: list[str], master: bytes) -> None:
        self.username = username
        self.roles = roles
        self.master = master              # для ЛР6 (секрет TOTP); на диск не пишеться
        self.started = time.time()
        self.last_activity = self.started
        self.last_stepup = self.started   # вхід рахується свіжим підтвердженням

    def timed_out(self, now: float) -> str | None:
        if now - self.last_activity > IDLE_TIMEOUT_S:
            return "Сесію закрито через простій."
        if now - self.started > ABSOLUTE_TIMEOUT_S:
            return "Сесію закрито: вичерпано граничний час."
        return None


# --- спільні помічники авторизації ------------------------------------------
def require_step_up(session: Session, store: AccountStore) -> bool:
    """Повторне підтвердження пароля для критичної операції."""
    print("Критична операція потребує повторного підтвердження пароля.")
    pw = getpass.getpass("Пароль: ")
    if store.authenticate(session.username, pw).ok:
        session.last_stepup = time.time()
        store.audit("stepup-ok", session.username)
        return True
    store.audit("stepup-fail", session.username)
    return False


def guard(session: Session, store: AccountStore, operation: str,
          resource: dict | None = None, target_user: str | None = None) -> bool:
    """Перевірка прав у точці виконання. True → дозволено. Користувачеві — лише
    загальне повідомлення; причина відмови — у журнал."""
    age = time.time() - session.last_stepup
    dec = authorize(session.roles, operation, target_user=target_user,
                    current_user=session.username, resource=resource, session_stepup_age=age)
    if not dec.allow and dec.reason == "stepup-required":
        if not require_step_up(session, store):
            store.audit(f"authz-deny:{operation}:stepup-failed", session.username)
            print(DENY)
            return False
        age = time.time() - session.last_stepup
        dec = authorize(session.roles, operation, target_user=target_user,
                        current_user=session.username, resource=resource, session_stepup_age=age)
    if not dec.allow:
        store.audit(f"authz-deny:{operation}:{dec.reason}", session.username)
        print(DENY)
        return False
    store.audit(f"authz-allow:{operation}", session.username)
    return True


def read_release_state() -> dict:
    """Атрибути релізу-кандидата для ABAC-правила sign. У ЛР7 замінюється на реальний
    git (branch + `git status --porcelain`); тут читається з release.state.json, а за
    відсутності файлу повертає небезпечний стан (dirty) → sign буде відхилено."""
    if os.path.exists(RELEASE_STATE):
        try:
            with open(RELEASE_STATE, "r", encoding="utf-8") as fh:
                s = json.load(fh)
            return {"branch": s.get("branch"), "dirty": bool(s.get("dirty", True))}
        except (OSError, ValueError):
            pass
    return {"branch": None, "dirty": True}


# --- команди сесії ----------------------------------------------------------
def cmd_help(session, store, args):
    print("help whoami status | list-users verify | build-manifest | sign <build> |")
    print("add-user <user> <role> | set-role <user> <role...> | passwd [user] | rotate-key | exit")
    return True


def cmd_whoami(session, store, args):
    print(f"{session.username}   ролі: {', '.join(session.roles)}")
    return True


def cmd_status(session, store, args):
    now = time.time()
    print(f"Сесія активна. Простій до тайм-ауту: {int(IDLE_TIMEOUT_S-(now-session.last_activity))} с; "
          f"граничний: {int(ABSOLUTE_TIMEOUT_S-(now-session.started))} с; "
          f"свіжість підтвердження: {int(now-session.last_stepup)} с тому.")
    return True


def cmd_list_users(session, store, args):
    if not guard(session, store, "list-users"):
        return True
    for name, roles in store.list_users().items():
        print(f"  {name:<16} {', '.join(roles)}")
    return True


def cmd_add_user(session, store, args):
    if len(args) < 2 or args[1] not in ROLES:
        print(f"Використання: add-user <user> <role>   ролі: {', '.join(ROLES)}")
        return True
    if not guard(session, store, "add-user"):
        return True
    name, role = args[0], args[1]
    pw1 = getpass.getpass("Пароль нового користувача: ")
    pw2 = getpass.getpass("Повторіть: ")
    if pw1 != pw2 or len(pw1) < 12:
        print("Паролі не збігаються або коротші за 12 символів.")
        return True
    try:
        store.add_user(name, pw1, roles=[role])
    except ValueError as exc:
        print(str(exc))
        return True
    store.save()
    print(f"Додано {name} (роль: {role}).")
    return True


def cmd_set_role(session, store, args):
    if len(args) < 2 or any(r not in ROLES for r in args[1:]):
        print(f"Використання: set-role <user> <role...>   ролі: {', '.join(ROLES)}")
        return True
    if not guard(session, store, "set-role"):
        return True
    try:
        store.set_roles(args[0], list(args[1:]))
    except KeyError:
        print("Немає такого користувача.")
        return True
    except ValueError as exc:          # останній owner (інваріант сховища)
        print(str(exc))
        return True
    store.save()
    print(f"Ролі {args[0]}: {', '.join(args[1:])}.")
    return True


def cmd_passwd(session, store, args):
    target = args[0] if args else session.username
    if not guard(session, store, "passwd", target_user=target):
        return True
    pw1 = getpass.getpass(f"Новий пароль для {target}: ")
    pw2 = getpass.getpass("Повторіть: ")
    if pw1 != pw2 or len(pw1) < 12:
        print("Паролі не збігаються або коротші за 12 символів.")
        return True
    try:
        store.change_password(target, pw1)
    except KeyError:
        print("Немає такого користувача.")
        return True
    store.save()
    print(f"Пароль для {target} змінено.")
    return True


def cmd_sign(session, store, args):
    state = read_release_state()
    if not guard(session, store, "sign", resource=state):
        return True
    build = args[0] if args else "(без імені)"
    print(f"[ЛР7] Тут буде підпис збірки {build}. Стан релізу: branch={state['branch']}, "
          f"dirty={state['dirty']}. Доступ надано — криптографію додає ЛР7.")
    return True


def cmd_build_manifest(session, store, args):
    if not guard(session, store, "build-manifest"):
        return True
    print("[ЛР7] Тут буде формування SHA-256-маніфесту релізу. Доступ надано.")
    return True


def cmd_rotate_key(session, store, args):
    if not guard(session, store, "rotate-key"):
        return True
    print("[ЛР6] Тут буде ротація ключа шифрування секрету TOTP. Доступ надано.")
    return True


def cmd_verify(session, store, args):
    if not guard(session, store, "verify"):
        return True
    print("[ЛР7] Тут буде перевірка маніфесту/підпису релізу. Доступ надано (read-only).")
    return True


def cmd_exit(session, store, args):
    print("Вихід із сесії.")
    return False


COMMANDS = {
    "help": cmd_help, "whoami": cmd_whoami, "status": cmd_status,
    "list-users": cmd_list_users, "add-user": cmd_add_user, "set-role": cmd_set_role,
    "passwd": cmd_passwd, "sign": cmd_sign, "build-manifest": cmd_build_manifest,
    "rotate-key": cmd_rotate_key, "verify": cmd_verify,
    "exit": cmd_exit, "quit": cmd_exit,
}


def run_session(session: Session, store: AccountStore) -> None:
    print(f"Вхід виконано як {session.username} (ролі: {', '.join(session.roles)}). help — команди.")
    while True:
        reason = session.timed_out(time.time())
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
            print("Невідома команда. help — список.")
            continue
        if not handler(session, store, parts[1:]):
            return


# --- підкоманди CLI ---------------------------------------------------------
def do_init(args) -> int:
    if os.path.exists(args.store):
        print("Файл облікових записів уже існує — init скасовано.")
        return 1
    store = AccountStore(args.store, args.audit)
    store.save()
    store.audit("init")
    print(f"Створено порожній файл облікових записів: {args.store}")
    return 0


def do_add_user(args) -> int:
    """Бутстрап ПЕРШОГО власника: дозволено лише коли записів ще немає. Коли вони вже
    є, додавання — лише через сесію owner (команда add-user), щоб не було обхідного
    шляху повз перевірку прав."""
    store = AccountStore(args.store, args.audit).load()
    if store.list_users():
        print("Облікові записи вже існують. Додавання — лише в сесії owner (add-user).")
        return 1
    pw1 = getpass.getpass("Пароль власника: ")
    pw2 = getpass.getpass("Повторіть пароль: ")
    if pw1 != pw2:
        print("Паролі не збігаються.")
        return 1
    if len(pw1) < 12:
        print("Пароль закороткий: мінімум 12 символів.")
        return 1
    try:
        store.add_user(args.username, pw1, roles=["owner"])
    except ValueError as exc:
        print(str(exc))
        return 1
    store.save()
    print(f"Створено першого користувача {args.username} з роллю owner (бутстрап).")
    return 0


def do_login(args) -> int:
    store = AccountStore(args.store, args.audit).load()
    password = getpass.getpass("Пароль: ")
    result = store.authenticate(args.username, password)
    if not result.ok:
        # Єдине загальне повідомлення; причина (locked/no-such-user) — лише в журналі (SR-22).
        print(GENERIC_LOGIN_ERROR)
        return 1
    run_session(Session(args.username, result.roles, result.master or b""), store)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="drs_release",
                                description="Офлайн-інструмент супроводжувача релізів DynamicReloadSpeed.")
    p.add_argument("--store", default=DEFAULT_STORE)
    p.add_argument("--audit", default=DEFAULT_AUDIT)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="створити порожній файл облікових записів")
    a = sub.add_parser("add-user", help="бутстрап першого власника (лише для порожнього сховища)")
    a.add_argument("username")
    l = sub.add_parser("login", help="увійти й відкрити сесію")
    l.add_argument("username")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"init": do_init, "add-user": do_add_user, "login": do_login}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
