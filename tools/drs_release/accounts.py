"""drs_release / accounts.py — сховище облікових записів супроводжувача релізів (версія ЛР5).

Призначення цільового файлу в репозиторії: tools/drs_release/accounts.py
Ця версія ЗАМІНЮЄ версію ЛР4: ядро автентифікації без змін, додано керування записами
для авторизованих операцій (list_users, get_roles, set_roles, change_password).

Це ОФЛАЙН-інструмент супроводжувача. Він не має нічого спільного з процесом гри й
НЕ перехоплює введення в грі: пароль вводиться у власному терміналі супроводжувача
через getpass (як у sudo чи git). Ядро автентифікації (ЛР4):

  * похідний майстер-секрет        PBKDF2-HMAC-SHA256, 600 000 ітерацій, сіль 16 Б
  * верифікатор пароля             HMAC-SHA256(master, "drs-release/verifier")
  * стала за часом перевірка       hmac.compare_digest
  * блокування після 5 невдач      5 хв, далі подвоєння до 60 хв
  * однакова ціна кожної відмови   PBKDF2 рахується і для невідомого, і для
                                   заблокованого запису (SR-22)
  * перевірені імена користувачів  лише ^[A-Za-z0-9_.-]{1,32}$ (SR-23)
  * журнал аудиту                  додавання у файл, окремо від загального повідомлення

Рішення «чи можна» тут НЕ приймаються: це робить authz.py у точці виконання команди.
Сховище лише гарантує інваріант, який не залежить від того, хто питає: у системі завжди
лишається щонайменше один owner.

Жодних сторонніх залежностей — лише стандартна бібліотека.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from dataclasses import dataclass, field

# --- параметри, однакові для всього файлу облікових записів -----------------
KDF_NAME = "pbkdf2_hmac_sha256"
KDF_ITERATIONS = 600_000          # рекомендація OWASP для PBKDF2-HMAC-SHA256
SALT_BYTES = 16
MASTER_BYTES = 32
VERIFIER_INFO = b"drs-release/verifier"

# --- політика блокування ----------------------------------------------------
MAX_FAILS_BEFORE_LOCK = 5
BASE_LOCK_SECONDS = 5 * 60         # перше блокування — 5 хв
MAX_LOCK_SECONDS = 60 * 60         # стеля — 60 хв

# --- імена користувачів і ролі ----------------------------------------------
USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
DEFAULT_ROLES = ["viewer"]         # найменші привілеї
OWNER_ROLE = "owner"

# Фіксована сіль для фіктивного обчислення, коли користувача не існує: вирівнює
# час відповіді, щоб не можна було відрізнити «нема такого» від «невірний пароль».
_DUMMY_SALT = b"drs-release/dummy-user-constant.."[:SALT_BYTES]

# Керувальні символи (включно з табуляцією й переведенням рядка) у журналі
# замінюються, щоб одне подання не могло «дописати» в журнал фальшивий рядок.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def valid_username(name: str) -> bool:
    return bool(USERNAME_RE.fullmatch(name or ""))


def _clean(text: str, limit: int = 64) -> str:
    return _CONTROL_RE.sub("?", str(text))[:limit]


def derive_master_secret(password: str, salt: bytes) -> bytes:
    """Повільне виведення майстер-секрета з пароля. Його НЕ зберігають: з нього
    рахують верифікатор (ЛР4) і ключ шифрування секрету TOTP (ЛР6)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                               KDF_ITERATIONS, dklen=MASTER_BYTES)


def compute_verifier(master: bytes) -> bytes:
    """Те, що реально лежить у файлі. З верифікатора не відновити ні пароль, ні
    майстер-секрет; він лише дозволяє перевірити введений пароль."""
    return hmac.new(master, VERIFIER_INFO, hashlib.sha256).digest()


@dataclass
class AuthResult:
    ok: bool
    reason: str                    # машинний код для журналу: ok / bad-credentials / locked / no-such-user
    master: bytes | None = None    # лише за успіху; потрібен для секрету TOTP (ЛР6)
    roles: list[str] = field(default_factory=list)
    retry_after: int = 0           # секунд до кінця блокування (для журналу, не для користувача)


class AccountStore:
    """Файл облікових записів у форматі JSON. Запис атомарний (tmp + os.replace),
    щоб переривання не лишило пошкодженого файлу."""

    def __init__(self, path: str, audit_log: str | None = None) -> None:
        self.path = path
        self.audit_log = audit_log
        self.data: dict = {
            "version": 1,
            "kdf": {"name": KDF_NAME, "iterations": KDF_ITERATIONS, "salt_bytes": SALT_BYTES},
            "users": {},
        }

    # --- завантаження / збереження ------------------------------------------
    def load(self) -> "AccountStore":
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)
        return self

    def save(self) -> None:
        folder = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    # --- журнал аудиту -------------------------------------------------------
    def audit(self, event: str, username: str = "-") -> None:
        if not self.audit_log:
            return
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')}\t{_clean(event)}\t{_clean(username)}\n"
        with open(self.audit_log, "a", encoding="utf-8") as fh:
            fh.write(line)

    # --- створення користувача ----------------------------------------------
    def add_user(self, username: str, password: str, roles: list[str] | None = None) -> None:
        if not valid_username(username):
            raise ValueError("Недопустиме ім'я: латиниця, цифри, «_», «.», «-», до 32 символів.")
        if username in self.data["users"]:
            raise ValueError("Користувач уже існує.")
        salt = secrets.token_bytes(SALT_BYTES)
        master = derive_master_secret(password, salt)
        self.data["users"][username] = {
            "salt": _b64e(salt),
            "verifier": _b64e(compute_verifier(master)),
            "roles": list(roles) if roles else list(DEFAULT_ROLES),
            "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "failed_count": 0,
            "lock_level": 0,
            "locked_until": 0,
            "totp": None,                        # конвертне шифрування секрету — ЛР6
        }
        self.audit("add-user", username)

    # --- автентифікація ------------------------------------------------------
    def authenticate(self, username: str, password: str, now: float | None = None) -> AuthResult:
        now = time.time() if now is None else now
        user = self.data["users"].get(username) if valid_username(username) else None

        if user is None:
            # Фіктивне обчислення тієї самої ваги — вирівнює час відповіді.
            derive_master_secret(password, _DUMMY_SALT)
            self.audit("login-fail:no-such-user", username)
            return AuthResult(ok=False, reason="no-such-user")

        # PBKDF2 рахується ДО перевірки блокування: інакше заблокований запис
        # відповідав би миттєво, і час відповіді видавав би стан блокування.
        master = derive_master_secret(password, _b64d(user["salt"]))

        if user["locked_until"] and now < user["locked_until"]:
            retry = int(user["locked_until"] - now)
            self.audit("login-fail:locked", username)
            return AuthResult(ok=False, reason="locked", retry_after=retry)

        if hmac.compare_digest(compute_verifier(master), _b64d(user["verifier"])):
            user["failed_count"] = 0
            user["lock_level"] = 0
            user["locked_until"] = 0
            self.save()
            self.audit("login-ok", username)
            return AuthResult(ok=True, reason="ok", master=master, roles=list(user["roles"]))

        # невдала спроба
        user["failed_count"] += 1
        if user["failed_count"] >= MAX_FAILS_BEFORE_LOCK:
            user["lock_level"] += 1
            duration = min(BASE_LOCK_SECONDS * (2 ** (user["lock_level"] - 1)), MAX_LOCK_SECONDS)
            user["locked_until"] = now + duration
            user["failed_count"] = 0
            self.save()
            self.audit(f"lockout:{int(duration)}s", username)
            return AuthResult(ok=False, reason="locked", retry_after=int(duration))
        self.save()
        self.audit("login-fail:bad-credentials", username)
        return AuthResult(ok=False, reason="bad-credentials")

    # --- додано в ЛР5: керування записами (для авторизованих операцій) -------
    def list_users(self) -> dict:
        """Імена й ролі (без секретів) — для команди list-users."""
        return {name: list(rec.get("roles", [])) for name, rec in self.data["users"].items()}

    def get_roles(self, username: str) -> list:
        return list(self.data["users"][username]["roles"])

    def owners(self) -> list:
        return [name for name, roles in self.list_users().items() if OWNER_ROLE in roles]

    def set_roles(self, username: str, roles: list) -> None:
        if username not in self.data["users"]:
            raise KeyError(username)
        if OWNER_ROLE not in roles and self.owners() == [username]:
            # Інваріант сховища, незалежний від того, хто питає: без жодного owner
            # ніхто більше не зміг би додати користувача чи змінити роль.
            raise ValueError("Не можна позбавити ролі owner останнього власника.")
        self.data["users"][username]["roles"] = list(roles)
        self.audit("set-role", username)

    def change_password(self, username: str, new_password: str) -> bytes:
        """Новий пароль → нова сіль і верифікатор; лічильники блокування скидаються.
        Повертає новий майстер-секрет: ЛР6 переобгортає ним секрет TOTP."""
        if username not in self.data["users"]:
            raise KeyError(username)
        salt = secrets.token_bytes(SALT_BYTES)
        master = derive_master_secret(new_password, salt)
        rec = self.data["users"][username]
        rec["salt"] = _b64e(salt)
        rec["verifier"] = _b64e(compute_verifier(master))
        rec["failed_count"] = 0
        rec["lock_level"] = 0
        rec["locked_until"] = 0
        self.audit("change-password", username)
        return master
