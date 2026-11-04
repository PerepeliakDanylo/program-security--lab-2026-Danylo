"""drs_release — CLI інструмента супроводжувача релізів (версія ЛР8: паспорт релізу).

Призначення цільового файлу в репозиторії: tools/drs_release/drs_release.py
Ця версія ЗАМІНЮЄ версію ЛР7. Додано в ЛР8:
  * make-passport <тека> [версія] — зібрати й підписати паспорт релізу (RSA-PSS, passport.py):
    продукт, версія, автор, домашня сторінка, тип ліцензії (Freeware / MIT) і SHA-256 маніфесту
    ЛР7. Лише на актуальний маніфест; закритий ключ — зашифрований паролем PKCS#8 поза
    репозиторієм (getpass); доступ — maintainer + чистий master;
  * check-passport <тека> — перевірити весь ланцюг: підпис паспорта відкритим ключем із
    репозиторію → хеш маніфесту дорівнює засвідченому → файли теки збігаються з маніфестом
    (viewer+, лише читання).
Автентифікація (ЛР4), доступ (ЛР5), другий фактор (ЛР6), цілісність (ЛР7) — ті самі.

CLI (запускати з теки tools/drs_release):
    python drs_release.py init | add-user <owner> | login <user> | protect

У сесії:
    help whoami status | list-users | verify <тека> | check-passport <тека>   # viewer+
    enroll-totp [--force]                                                       # viewer+, свій запис
    build-manifest <тека>                                                       # contributor+
    sign <тека> | make-passport <тека> [версія]                                 # maintainer+, чистий master
    add-user <user> <role> | set-role <user> <role...> | rotate-key             # owner
    passwd [user]                                                               # власник або owner
    exit

Закритий ключ паспорта лежить поза текою репозиторію: шлях зі змінної середовища DRS_PASSPORT_KEY
або %USERPROFILE%\\.drs_release\\release_passport.key (passport.default_key_path). Якщо шлях ключа
виявився всередині робочого дерева git, make-passport відмовляє (SR-34). Паспорт видається лише на
маніфест, що збігається з теперішнім вмістом теки (як і підпис маніфесту в ЛР7).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import re
import subprocess
import sys
import time

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm

import integrity
import passport
from accounts import AccountStore, IntegrityError
from authz import ROLES, authorize
from crypto import (new_totp_secret, open_totp_secret, provisioning_uri, rewrap_for_new_master,
                    rotate as crypto_rotate, seal_totp_secret, totp_match_counter)

DEFAULT_STORE = "drs_release.accounts.json"
DEFAULT_AUDIT = "drs_release.audit.log"

IDLE_TIMEOUT_S = 10 * 60
ABSOLUTE_TIMEOUT_S = 60 * 60
GIT_TIMEOUT_S = 15
PRODUCT_VERSION = "1.2.1"            # типова версія паспорта, якщо не вказано аргументом

GENERIC_LOGIN_ERROR = "Автентифікацію відхилено."
DENY = "Операцію відхилено."

ENVELOPE_ERRORS = (InvalidTag, KeyError, TypeError, ValueError)


class Session:
    def __init__(self, username: str, roles: list[str], master: bytes) -> None:
        self.username = username
        self.roles = roles
        self.master = master              # відкриває лише ВЛАСНИЙ секрет TOTP; на диск не пишеться
        self.started = time.time()
        self.last_activity = self.started
        self.last_stepup = self.started

    def timed_out(self, now: float) -> str | None:
        if now - self.last_activity > IDLE_TIMEOUT_S:
            return "Сесію закрито через простій."
        if now - self.started > ABSOLUTE_TIMEOUT_S:
            return "Сесію закрито: вичерпано граничний час."
        return None


# --- спільні помічники авторизації ------------------------------------------
def require_step_up(session: Session, store: AccountStore) -> bool:
    print("Критична операція потребує повторного підтвердження пароля.")
    pw = getpass.getpass("Пароль: ")
    if store.authenticate(session.username, pw, second_factor_pending=True).ok:
        session.last_stepup = time.time()
        store.audit("stepup-ok", session.username)
        return True
    store.audit("stepup-fail", session.username)
    return False


def guard(session: Session, store: AccountStore, operation: str,
          resource: dict | None = None, target_user: str | None = None) -> bool:
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


def _git(*args: str) -> str:
    done = subprocess.run(["git", *args], capture_output=True, text=True,
                          timeout=GIT_TIMEOUT_S, check=True)
    return done.stdout.strip()


def read_release_state() -> dict:
    """Атрибути реліз-кандидата для ABAC-правил sign / make-passport — з реального git. Помилка
    git або не репозиторій → небезпечний стан (dirty) → відмова (fail closed)."""
    try:
        branch = _git("rev-parse", "--abbrev-ref", "HEAD")
        dirty = bool(_git("status", "--porcelain"))
        return {"branch": branch, "dirty": dirty}
    except (OSError, subprocess.SubprocessError):
        return {"branch": None, "dirty": True}


def check_second_factor(store: AccountStore, username: str, master: bytes) -> bool:
    try:
        secret = open_totp_secret(master, store.get_totp(username), username)
    except ENVELOPE_ERRORS:
        store.record_failure(username, "totp-envelope")
        return False
    counter = totp_match_counter(secret, getpass.getpass("Код TOTP: "))
    if counter is None:
        store.record_failure(username, "totp")
        return False
    last = store.get_totp_counter(username)
    if last is not None and counter <= last:
        store.record_failure(username, "totp-replay")
        return False
    store.set_totp_counter(username, counter)
    store.complete_login(username)
    return True


def _dir_arg(args: list[str]) -> str:
    return " ".join(args).strip().strip('"')


# Версія релізу в make-passport: MAJOR.MINOR.PATCH з необов'язковим суфіксом (1.2.1, 1.3.0-rc1).
_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?")


def _passport_key_path() -> str:
    """Закритий ключ паспорта — поза репозиторієм: DRS_PASSPORT_KEY або тека .drs_release профілю."""
    return passport.default_key_path()


# --- команди сесії ----------------------------------------------------------
def cmd_help(session, store, args):
    print("help whoami status | list-users | verify <тека> | check-passport <тека> | enroll-totp [--force] |")
    print("build-manifest <тека> | sign <тека> | make-passport <тека> [версія] |")
    print("add-user <user> <role> | set-role <user> <role...> | passwd [user] | rotate-key | exit")
    return True


def cmd_whoami(session, store, args):
    second = "TOTP" if store.has_totp(session.username) else "не підключено"
    print(f"{session.username}   ролі: {', '.join(session.roles)}   другий фактор: {second}")
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
    except ValueError as exc:
        print(str(exc))
        return True
    store.save()
    print(f"Ролі {args[0]}: {', '.join(args[1:])}.")
    return True


def cmd_passwd(session, store, args):
    target = args[0] if args else session.username
    if not guard(session, store, "passwd", target_user=target):
        return True
    if target not in store.list_users():
        print("Немає такого користувача.")
        return True
    own = target == session.username
    blob = store.get_totp(target)
    if own and blob is not None:
        try:
            open_totp_secret(session.master, blob, target)
        except ENVELOPE_ERRORS:
            store.audit("passwd-deny:totp-envelope", target)
            print(DENY)
            return True
    pw1 = getpass.getpass(f"Новий пароль для {target}: ")
    pw2 = getpass.getpass("Повторіть: ")
    if pw1 != pw2 or len(pw1) < 12:
        print("Паролі не збігаються або коротші за 12 символів.")
        return True
    new_master = store.change_password(target, pw1)
    if own:
        if blob is not None:
            store.rewrap_totp(target, rewrap_for_new_master(session.master, new_master, blob, target))
        session.master = new_master
    elif blob is not None:
        store.set_totp(target, None)
        print(f"TOTP користувача {target} скинуто — після входу він підключає його знову (enroll-totp).")
    store.save()
    print(f"Пароль для {target} змінено.")
    return True


def cmd_enroll_totp(session, store, args):
    force = bool(args) and args[0] == "--force"
    if store.has_totp(session.username) and not force:
        print("TOTP уже підключено. enroll-totp --force — підключити новий (старий перестане діяти).")
        return True
    if not guard(session, store, "enroll-totp"):
        return True
    secret = new_totp_secret()
    print("Додайте ключ у застосунок-автентифікатор (значення secret= у рядку нижче):")
    print("  " + provisioning_uri(session.username, secret))
    counter = totp_match_counter(secret, input("Код із застосунку для підтвердження: "))
    if counter is None:
        store.audit("enroll-totp-fail:bad-code", session.username)
        print("Код не підійшов — TOTP НЕ підключено. Перевірте ключ і час на пристрої, повторіть enroll-totp.")
        return True
    store.set_totp(session.username, seal_totp_secret(session.master, secret, session.username))
    store.set_totp_counter(session.username, counter)
    store.save()
    print("TOTP підключено. Наступний вхід попросить код.")
    return True


def cmd_rotate_key(session, store, args):
    if not guard(session, store, "rotate-key"):
        return True
    blob = store.get_totp(session.username)
    if blob is None:
        print("TOTP не підключено — ротувати нічого (спершу enroll-totp).")
        return True
    try:
        rotated = crypto_rotate(session.master, blob, session.username)
    except ENVELOPE_ERRORS:
        store.audit("rotate-key-fail:totp-envelope", session.username)
        print(DENY)
        return True
    store.rewrap_totp(session.username, rotated)
    store.save()
    print("Ключ шифрування секрету TOTP ротовано: новий DEK і нова сіль KEK; секрет і пароль ті самі.")
    return True


def cmd_build_manifest(session, store, args):
    if not guard(session, store, "build-manifest"):
        return True
    root = _dir_arg(args)
    if not root or not os.path.isdir(root):
        print("Використання: build-manifest <тека релізу>")
        return True
    manifest = integrity.build_manifest(root)
    with open(os.path.join(root, integrity.MANIFEST_NAME), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(manifest)
    count = len(manifest.splitlines())
    store.audit(f"build-manifest:{count}", session.username)
    print(f"Маніфест {integrity.MANIFEST_NAME} створено: {count} файл(ів).")
    return True


def cmd_sign(session, store, args):
    state = read_release_state()
    if not guard(session, store, "sign", resource=state):
        return True
    root = _dir_arg(args)
    if not root or not os.path.isdir(root):
        print("Використання: sign <тека релізу>   (спершу build-manifest)")
        return True
    mpath = os.path.join(root, integrity.MANIFEST_NAME)
    if not os.path.exists(mpath):
        print("Немає маніфесту — спершу build-manifest.")
        return True
    if not os.path.exists(integrity.PRIV_KEY_FILE):
        print(f"Немає ключа підпису {integrity.PRIV_KEY_FILE} — створіть: python integrity.py genkey")
        return True
    with open(mpath, "rb") as fh:
        manifest = fh.read()
    problems = integrity.diff_manifest(root, manifest.decode("utf-8"))
    if problems:
        store.audit("sign-deny:stale-manifest", session.username)
        print("Маніфест не відповідає теці (" + "; ".join(problems[:3]) + ") — спершу build-manifest.")
        return True
    signature = integrity.sign(integrity.load_key(integrity.PRIV_KEY_FILE), manifest)
    with open(os.path.join(root, integrity.SIG_NAME), "w", encoding="ascii", newline="\n") as fh:
        fh.write(base64.b64encode(signature).decode("ascii") + "\n")
    store.audit("sign:ok", session.username)
    print(f"Маніфест підписано Ed25519 (branch={state['branch']}, dirty={state['dirty']}) → {integrity.SIG_NAME}.")
    return True


def cmd_make_passport(session, store, args):
    """Зібрати й підписати паспорт релізу (RSA-PSS). Доступ — maintainer+ і чистий master; паспорт
    видається лише на маніфест, що збігається з текою; закритий ключ — поза репозиторієм (SR-34),
    розшифровується паролем лише на час операції."""
    state = read_release_state()
    if not guard(session, store, "make-passport", resource=state):
        return True
    tokens = list(args)
    version = PRODUCT_VERSION
    if len(tokens) > 1 and _VERSION_RE.fullmatch(tokens[-1]):
        version = tokens.pop()                 # останнє слово — версія; решта — шлях (можна з пробілами)
    root = _dir_arg(tokens)
    if not root or not os.path.isdir(root):
        print("Використання: make-passport <тека релізу> [версія]   (спершу build-manifest і sign)")
        return True
    mpath = os.path.join(root, passport.MANIFEST_NAME)
    if not os.path.exists(mpath):
        print("Немає маніфесту релізу — спершу build-manifest.")
        return True
    with open(mpath, "rb") as fh:
        problems = integrity.diff_manifest(root, fh.read().decode("utf-8", errors="replace"))
    if problems:
        store.audit("make-passport-deny:stale-manifest", session.username)
        print("Маніфест не відповідає теці (" + "; ".join(problems[:3]) + ") — спершу build-manifest і sign.")
        return True
    key_path = _passport_key_path()
    if passport.key_inside_repo(key_path):
        store.audit("make-passport-deny:key-in-repo", session.username)
        print(f"Закритий ключ паспорта {key_path} лежить у теці репозиторію — перенесіть його поза неї "
              "й задайте DRS_PASSPORT_KEY (SR-34).")
        return True
    if not os.path.exists(key_path):
        print(f"Немає закритого ключа паспорта {key_path} — створіть: python passport.py genkey "
              "(інший шлях — змінна DRS_PASSPORT_KEY).")
        return True
    try:
        priv = passport.load_private(key_path, getpass.getpass("Пароль закритого ключа паспорта: ").encode("utf-8"))
    except (ValueError, TypeError):
        store.audit("make-passport-fail:key", session.username)
        print("Не вдалося відкрити закритий ключ (невірний пароль або пошкоджений файл).")
        return True
    doc = passport.build_passport(root, version, time.strftime("%Y-%m-%d"))
    signature = passport.sign_passport(priv, doc)
    import json as _json
    with open(os.path.join(root, passport.PASSPORT_NAME), "w", encoding="utf-8", newline="\n") as fh:
        _json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    with open(os.path.join(root, passport.PASSPORT_SIG), "w", encoding="ascii", newline="\n") as fh:
        fh.write(base64.b64encode(signature).decode("ascii") + "\n")
    store.audit("make-passport:ok", session.username)
    print(f"Паспорт релізу створено й підписано (RSA-PSS): {passport.PASSPORT_NAME} (+ .sig). "
          f"Версія {version}, ліцензія {passport.LICENSE_TYPE}.")
    return True


def cmd_check_passport(session, store, args):
    """Перевірити реліз через паспорт — увесь ланцюг: підпис паспорта RSA-PSS відкритим ключем із
    репозиторію → SHA-256 маніфесту дорівнює засвідченому → файли теки збігаються з маніфестом.
    Відсутній паспорт, підпис, ключ чи маніфест — «не підтверджено» (fail closed)."""
    if not guard(session, store, "check-passport"):
        return True
    root = _dir_arg(args)
    if not root or not os.path.isdir(root):
        print("Використання: check-passport <тека релізу>")
        return True
    ppath = os.path.join(root, passport.PASSPORT_NAME)
    spath = os.path.join(root, passport.PASSPORT_SIG)
    problems: list[str] = []
    doc = None
    if not (os.path.exists(ppath) and os.path.exists(spath) and os.path.exists(passport.PUB_KEY_FILE)):
        problems.append(f"бракує {passport.PASSPORT_NAME}, {passport.PASSPORT_SIG} або {passport.PUB_KEY_FILE}")
    else:
        import json as _json
        try:
            with open(ppath, "r", encoding="utf-8") as fh:
                doc = _json.load(fh)
            with open(spath, "r", encoding="ascii") as fh:
                signature = base64.b64decode(fh.read().strip())
            pub = passport.load_public(passport.PUB_KEY_FILE)
            if not passport.verify_passport(pub, doc, signature):
                problems.append("підпис паспорта недійсний (чужий ключ або змінений паспорт)")
        except (OSError, ValueError, UnsupportedAlgorithm):
            problems.append("паспорт, підпис або відкритий ключ пошкоджено")
            doc = None
        if doc is not None and not problems:
            mpath = os.path.join(root, passport.MANIFEST_NAME)
            if not os.path.exists(mpath):
                problems.append(f"у теці немає {passport.MANIFEST_NAME}, на який посилається паспорт")
            elif passport.sha256_file(mpath) != doc.get("manifest_sha256"):
                problems.append("хеш маніфесту не збігається з паспортом (маніфест перебудовано чи підмінено "
                                "після видачі паспорта)")
            else:
                # Ланцюг до кінця: файли теки — саме ті, що в засвідченому паспортом маніфесті.
                with open(mpath, "rb") as fh:
                    problems.extend(integrity.diff_manifest(root, fh.read().decode("utf-8", errors="replace")))
    if not problems:
        print(f"Паспорт дійсний: {doc['product_id']} {doc['product_version']}, ліцензія {doc['license_type']}, "
              f"автор {doc['author']}, видано {doc['issued']}. Маніфест і файли теки збігаються.")
        print("  Підпис самого маніфесту (Ed25519, ЛР7) перевіряє: verify " + root)
    else:
        print("ПАСПОРТ НЕ ПІДТВЕРДЖЕНО:")
        for p in problems:
            print("  —", p)
    store.audit(f"check-passport:{'ok' if not problems else 'fail'}", session.username)
    return True


def cmd_verify(session, store, args):
    if not guard(session, store, "verify"):
        return True
    root = _dir_arg(args)
    if not root or not os.path.isdir(root):
        print("Використання: verify <тека релізу>")
        return True
    mpath = os.path.join(root, integrity.MANIFEST_NAME)
    spath = os.path.join(root, integrity.SIG_NAME)
    problems: list[str] = []
    sig_ok = False
    if not (os.path.exists(mpath) and os.path.exists(spath) and os.path.exists(integrity.PUB_KEY_FILE)):
        problems.append(f"бракує {integrity.MANIFEST_NAME}, {integrity.SIG_NAME} або {integrity.PUB_KEY_FILE}")
    else:
        with open(mpath, "rb") as fh:
            data = fh.read()
        try:
            with open(spath, "r", encoding="ascii") as fh:
                signature = base64.b64decode(fh.read().strip())
            sig_ok = integrity.verify(integrity.load_key(integrity.PUB_KEY_FILE), data, signature)
        except (OSError, ValueError):
            sig_ok = False
        if not sig_ok:
            problems.append("підпис недійсний (чужий ключ або змінений маніфест)")
        problems.extend(integrity.diff_manifest(root, data.decode("utf-8", errors="replace")))
    if not problems:
        print("Перевірку пройдено: підпис маніфесту дійсний і вміст теки збігається.")
    else:
        print("ПЕРЕВІРКА НЕ ПРОЙДЕНА:")
        for p in problems:
            print("  —", p)
    store.audit(f"verify:{'ok' if not problems else 'fail'}", session.username)
    return True


def cmd_exit(session, store, args):
    print("Вихід із сесії.")
    return False


COMMANDS = {
    "help": cmd_help, "whoami": cmd_whoami, "status": cmd_status,
    "list-users": cmd_list_users, "add-user": cmd_add_user, "set-role": cmd_set_role,
    "passwd": cmd_passwd, "sign": cmd_sign, "build-manifest": cmd_build_manifest,
    "make-passport": cmd_make_passport, "check-passport": cmd_check_passport,
    "rotate-key": cmd_rotate_key, "verify": cmd_verify, "enroll-totp": cmd_enroll_totp,
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
    store = AccountStore(args.store, args.audit)
    if os.path.exists(args.store):
        print("Файл облікових записів уже існує — init скасовано.")
        return 1
    if os.path.exists(store.key_path):
        print(f"Є ключ цілісності {store.key_path}, але немає файла облікових записів — init скасовано. "
              "Відновіть файл або свідомо видаліть ключ.")
        return 1
    store.save()
    store.audit("init")
    print(f"Створено порожній файл облікових записів: {args.store} (ключ цілісності: {store.key_path})")
    return 0


def do_add_user(args) -> int:
    store = AccountStore(args.store, args.audit).load()
    if not os.path.exists(args.store):
        print("Спершу init.")
        return 1
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
    two_factor = store.has_totp(args.username)
    result = store.authenticate(args.username, password, second_factor_pending=two_factor)
    if not result.ok or (two_factor and not check_second_factor(store, args.username, result.master)):
        print(GENERIC_LOGIN_ERROR)
        return 1
    run_session(Session(args.username, result.roles, result.master or b""), store)
    return 0


def do_protect(args) -> int:
    store = AccountStore(args.store, args.audit)
    if not store.load_unverified():
        print("protect не потрібен: файла немає або захист цілісності вже ввімкнено.")
        return 1
    store.save()
    store.audit("integrity-protect")
    print(f"Захист цілісності ввімкнено: мітка у {args.store}, ключ у {store.key_path} (не комітити).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="drs_release",
                                description="Офлайн-інструмент супроводжувача релізів DynamicReloadSpeed.")
    p.add_argument("--store", default=DEFAULT_STORE)
    p.add_argument("--audit", default=DEFAULT_AUDIT)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="створити порожній файл облікових записів і ключ цілісності")
    a = sub.add_parser("add-user", help="бутстрап першого власника (лише для порожнього сховища)")
    a.add_argument("username")
    l = sub.add_parser("login", help="увійти (пароль [+ код TOTP]) і відкрити сесію")
    l.add_argument("username")
    sub.add_parser("protect", help="один раз: захист цілісності для сховища, створеного до ЛР7")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"init": do_init, "add-user": do_add_user, "login": do_login, "protect": do_protect}
    try:
        return handlers[args.command](args)
    except IntegrityError as exc:
        print(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
