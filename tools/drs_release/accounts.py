"""drs_release / accounts.py — сховище облікових записів супроводжувача релізів (версія ЛР7).

Призначення цільового файлу в репозиторії: tools/drs_release/accounts.py
Ця версія ЗАМІНЮЄ версію ЛР6. Додано в ЛР7 — цілісність самого файлу:
  * поле `mac` у тому ж файлі = HMAC-SHA256 над канонічним JSON решти вмісту; ключ — окремий
    файл `<сховище>.key` (32 випадкові байти, створюється один раз, у репозиторій не потрапляє);
  * fail closed: розбіжність мітки, відсутня мітка чи відсутній ключ — IntegrityError, жодних
    даних не завантажено, подія — у журнал аудиту;
  * мітка лежить у тому самому файлі, тож атомарний запис (tmp + os.replace) оновлює дані й
    мітку разом — немає проміжку, коли вони розходяться;
  * сховище з ЛР4-ЛР6 (без ключа й мітки) не відкривається, доки його явно не захистять
    командою `protect` (load_unverified + save).

Ядро автентифікації (ЛР4) і поля TOTP (ЛР6) — без змін по суті:
  * похідний майстер-секрет        PBKDF2-HMAC-SHA256, 600 000 ітерацій, сіль 16 Б
  * верифікатор пароля             HMAC-SHA256(master, "drs-release/verifier")
  * стала за часом перевірка       hmac.compare_digest
  * блокування після 5 невдач      5 хв, далі подвоєння до 60 хв (пароль або код TOTP)
  * однакова ціна кожної відмови   PBKDF2 і для невідомого, і для заблокованого запису (SR-22)
  * перевірені імена користувачів  лише ^[A-Za-z0-9_.-]{1,32}$ (SR-23)

Офлайн-інструмент: пароль — getpass у терміналі супроводжувача; у грі нічого не відбувається.
Жодних сторонніх залежностей — лише стандартна бібліотека (cryptography потрібен тільки crypto.py
та integrity.py).
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

# --- цілісність файлу (ЛР7) -------------------------------------------------
MAC_FIELD = "mac"                  # HMAC-SHA256 (hex) над канонічним JSON решти полів
INTEGRITY_KEY_BYTES = 32

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


class IntegrityError(Exception):
    """Файл облікових записів не пройшов перевірку цілісності — роботу зупинено."""


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


def _canonical(body: dict) -> bytes:
    """Канонічне подання для мітки: не залежить від відступів і порядку ключів у файлі."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass
class AuthResult:
    ok: bool
    reason: str                    # машинний код для журналу: ok / bad-credentials / locked / no-such-user / totp
    master: bytes | None = None    # лише за успіху; потрібен для секрету TOTP (ЛР6)
    roles: list[str] = field(default_factory=list)
    retry_after: int = 0           # секунд до кінця блокування (для журналу, не для користувача)


class AccountStore:
    """Файл облікових записів у форматі JSON із вбудованою міткою цілісності (ЛР7).
    Запис атомарний (tmp + os.replace): дані й мітка змінюються одночасно."""

    def __init__(self, path: str, audit_log: str | None = None) -> None:
        self.path = path
        self.key_path = path + ".key"
        self.audit_log = audit_log
        self.data: dict = {
            "version": 1,
            "kdf": {"name": KDF_NAME, "iterations": KDF_ITERATIONS, "salt_bytes": SALT_BYTES},
            "users": {},
        }

    # --- ключ і мітка цілісності (ЛР7) ---------------------------------------
    def _read_key(self) -> bytes | None:
        if not os.path.exists(self.key_path):
            return None
        try:
            with open(self.key_path, "r", encoding="ascii") as fh:
                key = bytes.fromhex(fh.read().strip())
        except (OSError, ValueError):
            key = b""
        if len(key) != INTEGRITY_KEY_BYTES:
            self.audit("integrity-fail:key")
            raise IntegrityError("Ключ цілісності файла облікових записів пошкоджено — роботу зупинено.")
        return key

    def _create_key(self) -> bytes:
        """Новий ключ: O_EXCL (не перезаписує наявний), права 0600 там, де ОС їх підтримує."""
        key = secrets.token_bytes(INTEGRITY_KEY_BYTES)
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(key.hex() + "\n")
        self.audit("integrity-key-created")
        return key

    @staticmethod
    def _mac(key: bytes, body: dict) -> str:
        return hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()

    def _read_raw(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except ValueError:
            raw = None
        if not isinstance(raw, dict):
            self.audit("integrity-fail:format")
            raise IntegrityError("Файл облікових записів пошкоджено (не JSON-об'єкт) — роботу зупинено.")
        return raw

    def _verify(self, raw: dict) -> None:
        key = self._read_key()
        tag = raw.get(MAC_FIELD)
        if key is None and tag is None:
            self.audit("integrity-fail:unprotected")
            raise IntegrityError("Файл облікових записів без захисту цілісності (створений до ЛР7). "
                                 "Один раз виконайте: python drs_release.py protect")
        if key is None or not isinstance(tag, str):
            self.audit("integrity-fail:missing")
            raise IntegrityError("Немає ключа або мітки цілісності файла облікових записів — роботу зупинено.")
        body = {k: v for k, v in raw.items() if k != MAC_FIELD}
        if not hmac.compare_digest(self._mac(key, body), tag):
            self.audit("integrity-fail:mac")
            raise IntegrityError("Файл облікових записів не пройшов перевірку цілісності (HMAC) — роботу зупинено.")

    # --- завантаження / збереження ------------------------------------------
    def load(self) -> "AccountStore":
        """Завантажити з перевіркою цілісності. Будь-яка невідповідність — IntegrityError,
        self.data лишається порожнім (fail closed). Файла немає, а ключ є — теж відмова:
        інакше видалення файла відкривало б бутстрап нового власника."""
        if os.path.exists(self.path):
            raw = self._read_raw()
            self._verify(raw)
            raw.pop(MAC_FIELD, None)
            self.data = raw
        elif os.path.exists(self.key_path):
            self.audit("integrity-fail:store-missing")
            raise IntegrityError("Файла облікових записів немає, а ключ цілісності є (можливе видалення) — "
                                 "відновіть файл із резервної копії або свідомо видаліть ключ.")
        return self

    def load_unverified(self) -> bool:
        """Лише для `protect`: прочитати сховище з ЛР4-ЛР6, у якого немає НІ ключа, НІ мітки.
        Повертає True, якщо це саме такий випадок (і дані завантажено), інакше False."""
        if not os.path.exists(self.path) or os.path.exists(self.key_path):
            return False
        raw = self._read_raw()
        if MAC_FIELD in raw:
            return False
        self.data = raw
        return True

    def save(self) -> None:
        key = self._read_key() or self._create_key()
        body = {k: v for k, v in self.data.items() if k != MAC_FIELD}
        out = dict(body)
        out[MAC_FIELD] = self._mac(key, body)
        folder = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(out, fh, ensure_ascii=False, indent=2)
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
            "totp": None,                        # конверт секрету TOTP (crypto.py)
            "totp_last_counter": None,           # останній прийнятий крок TOTP
        }
        self.audit("add-user", username)

    # --- автентифікація ------------------------------------------------------
    def authenticate(self, username: str, password: str, now: float | None = None,
                     second_factor_pending: bool = False) -> AuthResult:
        """Перевірка пароля. second_factor_pending=True — у запису є TOTP: за
        правильного пароля лічильник невдач НЕ скидається, поки не пройде й код
        (complete_login); невдалий код — record_failure, як і невдалий пароль."""
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
            if second_factor_pending:
                self.audit("login-password-ok", username)
            else:
                self.complete_login(username)
            return AuthResult(ok=True, reason="ok", master=master, roles=list(user["roles"]))

        return self.record_failure(username, "bad-credentials", now)

    def complete_login(self, username: str) -> None:
        """Повний вхід пройдено: скинути лічильник і рівень блокування."""
        user = self.data["users"][username]
        user["failed_count"] = 0
        user["lock_level"] = 0
        user["locked_until"] = 0
        self.save()
        self.audit("login-ok", username)

    def record_failure(self, username: str, reason: str, now: float | None = None) -> AuthResult:
        """Невдала спроба (пароль або другий фактор): лічильник, за потреби — блокування."""
        now = time.time() if now is None else now
        user = self.data["users"][username]
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
        self.audit(f"login-fail:{reason}", username)
        return AuthResult(ok=False, reason=reason)

    # --- керування записами (ЛР5) --------------------------------------------
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
            raise ValueError("Не можна позбавити ролі owner останнього власника.")
        self.data["users"][username]["roles"] = list(roles)
        self.audit("set-role", username)

    def change_password(self, username: str, new_password: str) -> bytes:
        """Новий пароль → нова сіль і верифікатор; лічильники блокування скидаються.
        Повертає новий майстер-секрет: ним переобгортається секрет TOTP."""
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

    # --- конверт секрету TOTP і одноразовість кодів (ЛР6) --------------------
    def has_totp(self, username: str) -> bool:
        rec = self.data["users"].get(username) if valid_username(username) else None
        return bool(rec and rec.get("totp"))

    def get_totp(self, username: str):
        return self.data["users"][username].get("totp")

    def set_totp(self, username: str, blob) -> None:
        """Записати (або з blob=None — прибрати) конверт секрету. Новий секрет —
        нова історія кроків: лічильник одноразовості скидається."""
        if username not in self.data["users"]:
            raise KeyError(username)
        rec = self.data["users"][username]
        rec["totp"] = blob
        rec["totp_last_counter"] = None
        self.audit("set-totp" if blob is not None else "clear-totp", username)

    def rewrap_totp(self, username: str, blob) -> None:
        """Той самий секрет під новим ключем (ротація, зміна пароля): історія кроків
        лишається — вже використаний код не стає знову дійсним."""
        if username not in self.data["users"]:
            raise KeyError(username)
        self.data["users"][username]["totp"] = blob
        self.audit("rewrap-totp", username)

    def get_totp_counter(self, username: str):
        return self.data["users"][username].get("totp_last_counter")

    def set_totp_counter(self, username: str, counter: int) -> None:
        self.data["users"][username]["totp_last_counter"] = int(counter)
