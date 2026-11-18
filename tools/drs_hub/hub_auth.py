"""drs_hub — мережева автентифікація й авторизація на боці сервера (версія ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_auth.py

Модель (обґрунтування — docs/architecture/client_server.md):
  * OAuth 2.0, грант Client Credentials (RFC 6749 §4.4): клієнт (CLI супроводжувача, тестера чи
    аудитора) автентифікується client_id + client_secret за схемою HTTP Basic (RFC 6749 §2.3.1) на
    POST /oauth/token і отримує ТОКЕН ДОСТУПУ. Пароля людини й гранту Resource Owner Password
    Credentials немає (сучасна практика його забороняє); токенів оновлення немає (RFC 6749 §4.4.3:
    для Client Credentials вони не потрібні — клієнт просто бере новий токен).
  * Токен непрозорий (opaque): 256 біт із secrets, префікс «dha_». Сервер зберігає лише SHA-256
    токена, власника, скоуп і строк дії (10 хв); перевіряє на кожному запиті; відкликання —
    POST /oauth/revoke (RFC 7009). Передається за схемою Bearer (RFC 6750) і лише через TLS.
  * Секрет клієнта генерує сервер (256 біт, префікс «dhs_»); зберігається лише SHA-256. Повільна
    KDF тут не потрібна: на відміну від пароля людини (FR-70, PBKDF2), секрет має повну ентропію —
    перебір за хешем неможливий, а повільна KDF лише дала б нападнику спосіб навантажити сервер.
  * Авторизація — лише на сервері: роль клієнта → дозволені скоупи; маршрут вимагає скоуп; суб'єкт
    і роль беруться з перевіреного токена, ніколи з тіла чи заголовків запиту клієнта.
  * Перебір: 5 невдач поспіль для client_id → блокування 5 хв із подвоєнням до 60 хв (як FR-71);
    20 невдач з однієї адреси за 10 хв → тимчасова відмова (password spraying). Лічильник ведеться
    для БУДЬ-ЯКОГО рядка client_id, тож відповідь 429 не видає, чи існує клієнт; помилка входу
    завжди однакова: invalid_client.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import re
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

from hub_config import HubConfig
from hub_store import HubStore

REALM = "drs-hub"
TOKEN_PREFIX = "dha_"      # DRS Hub Access — префікс полегшує пошук випадково опублікованих токенів
SECRET_PREFIX = "dhs_"     # DRS Hub Secret

# Роль → дозволені скоупи. Найменші привілеї: тестер лише подає й бачить власні звіти; аудитор лише
# читає показники й журнал; керування клієнтами — НЕ мережева операція (лише hub_admin.py на хості).
ROLE_SCOPES: dict[str, tuple[str, ...]] = {
    "tester":     ("reports:submit", "reports:read:own"),
    "maintainer": ("releases:write", "reports:read", "ledger:read", "metrics:read"),
    "auditor":    ("ledger:read", "metrics:read"),
}

CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,47}$")
_B64TOKEN_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")       # RFC 6750 §2.1, b64token
_SCOPE_RE = re.compile(r"^[a-z:]{1,40}$")
_DUMMY_HASH = hashlib.sha256(b"drs-hub/no-such-client").hexdigest()


class AuthError(Exception):
    """Відмова автентифікації/авторизації з HTTP-статусом і кодом помилки OAuth."""

    def __init__(self, status: int, error: str, description: str,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(description)
        self.status = status
        self.error = error
        self.description = description
        self.headers = headers or {}


@dataclass(frozen=True)
class Principal:
    """Встановлений суб'єкт запиту — лише з перевіреного токена."""
    client_id: str
    role: str
    scopes: frozenset = field(default_factory=frozenset)
    token_sha256: str = ""
    expires_at: float = 0.0

    @property
    def token_fp(self) -> str:
        """Відбиток токена для журналів: 12 hex-символів SHA-256, сам токен не журналюється."""
        return self.token_sha256[:12]


# --- секрети й токени --------------------------------------------------------------
def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_client_secret() -> str:
    return SECRET_PREFIX + secrets.token_urlsafe(32)


def _new_access_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def parse_basic(header: str | None) -> tuple[str, str] | None:
    """Authorization: Basic base64(client_id:client_secret) → (id, secret) або None."""
    if not header:
        return None
    scheme, _, value = header.strip().partition(" ")
    if scheme.lower() != "basic" or not value:
        return None
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    client_id, sep, secret = decoded.partition(":")
    if not sep:
        return None
    # RFC 6749 §2.3.1: обидві частини перед Basic кодуються як form-urlencoded.
    return unquote_plus(client_id), unquote_plus(secret)


def _basic_challenge() -> dict[str, str]:
    return {"WWW-Authenticate": f'Basic realm="{REALM}", charset="UTF-8"'}


def _bearer_challenge(error: str | None = None, scope: str | None = None) -> dict[str, str]:
    value = f'Bearer realm="{REALM}"'
    if error:
        value += f', error="{error}"'
    if scope:
        value += f', scope="{scope}"'
    return {"WWW-Authenticate": value}


# --- блокування перебору ------------------------------------------------------
def _check_locks(store: HubStore, keys: list[str], now: float) -> None:
    for key in keys:
        row = store.get_failure(key)
        if row is not None and row["locked_until"] > now:
            retry = max(1, math.ceil(row["locked_until"] - now))
            raise AuthError(429, "too_many_attempts",
                            "Забагато невдалих спроб. Повторіть пізніше.",
                            {"Retry-After": str(retry)})


def _record_failure(store: HubStore, cfg: HubConfig, client_key: str, ip_key: str, now: float) -> dict:
    """Невдача: +1 до лічильника клієнта (блокування з подвоєнням) і до вікна адреси."""
    result = {"client_locked_s": 0, "ip_locked_s": 0}
    row = store.get_failure(client_key)
    failures = (row["failures"] if row else 0) + 1
    level = row["lock_level"] if row else 0
    locked_until = 0.0
    if failures >= cfg.lockout_threshold:
        level += 1
        duration = min(cfg.lockout_base_s * (2 ** (level - 1)), cfg.lockout_max_s)
        locked_until = now + duration
        failures = 0
        result["client_locked_s"] = duration
    store.put_failure(client_key, failures, row["window_start"] if row else now, locked_until, level)

    row = store.get_failure(ip_key)
    if row is None or now - row["window_start"] > cfg.ip_fail_window_s:
        failures, window_start = 1, now
    else:
        failures, window_start = row["failures"] + 1, row["window_start"]
    ip_locked = 0.0
    if failures >= cfg.ip_fail_limit:
        ip_locked = now + cfg.ip_fail_window_s
        result["ip_locked_s"] = cfg.ip_fail_window_s
    store.put_failure(ip_key, failures, window_start, ip_locked, 0)
    return result


# --- POST /oauth/token -----------------------------------------------------------
def authenticate_client(store: HubStore, cfg: HubConfig, authorization: str | None,
                        client_ip: str, now: float | None = None) -> tuple[str, str, dict]:
    """Перевірити облікові дані клієнта (HTTP Basic). Повертає (client_id, role, info) або AuthError.

    info — для журналу: {"failure": True/False, "client_locked_s": …, "ip_locked_s": …}.
    """
    now = time.time() if now is None else now
    creds = parse_basic(authorization)
    if creds is None:
        raise AuthError(401, "invalid_client", "Потрібна автентифікація клієнта (HTTP Basic).",
                        _basic_challenge())
    client_id, secret = creds
    client_key = "client:" + client_id[:64]
    ip_key = "ip:" + client_ip
    try:
        _check_locks(store, [client_key, ip_key], now)
    except AuthError as exc:
        exc.info = {"failure": True, "reason": "locked",  # type: ignore[attr-defined]
                    "client_id_attempt": client_id[:64]}
        raise

    row = store.get_client(client_id) if CLIENT_ID_RE.fullmatch(client_id) else None
    expected = row["secret_sha256"] if row is not None else _DUMMY_HASH
    # Порівняння в сталий час і однаковий шлях для «немає клієнта» та «невірний секрет».
    secret_ok = hmac.compare_digest(sha256_hex(secret), expected)
    if row is None or not secret_ok or not row["enabled"]:
        info = _record_failure(store, cfg, client_key, ip_key, now)
        info["failure"] = True
        info["client_id_attempt"] = client_id[:64]   # не секрет; потрібен, щоб бачити, який запис підбирають
        info["reason"] = ("unknown-client" if row is None else
                          "disabled" if secret_ok and not row["enabled"] else "bad-secret")
        error = AuthError(401, "invalid_client", "Автентифікацію клієнта відхилено.", _basic_challenge())
        error.info = info  # type: ignore[attr-defined]
        raise error
    store.clear_failure(client_key)
    return client_id, row["role"], {"failure": False}


def issue_token(store: HubStore, cfg: HubConfig, client_id: str, role: str,
                requested_scope: str | None, now: float | None = None) -> dict:
    """Видати токен доступу з НЕ ширшим за роль скоупом (RFC 6749 §3.3)."""
    now = time.time() if now is None else now
    allowed = set(ROLE_SCOPES.get(role, ()))
    if requested_scope:
        wanted = set(requested_scope.split())
        if not all(_SCOPE_RE.fullmatch(s) for s in wanted) or not wanted <= allowed:
            raise AuthError(400, "invalid_scope", "Запитаний скоуп не дозволений ролі клієнта.")
    else:
        wanted = allowed
    if not wanted:
        raise AuthError(400, "invalid_scope", "Ролі клієнта не дозволено жодного скоупу.")
    token = _new_access_token()
    scope = " ".join(sorted(wanted))
    store.insert_token(sha256_hex(token), client_id, scope, now, now + cfg.token_ttl_s)
    return {"access_token": token, "token_type": "Bearer", "expires_in": cfg.token_ttl_s, "scope": scope}


# --- Bearer на захищених маршрутах ---------------------------------------------------
def authenticate_bearer(store: HubStore, authorization: str | None,
                        now: float | None = None) -> Principal:
    now = time.time() if now is None else now
    if not authorization:
        raise AuthError(401, "invalid_request", "Потрібен токен доступу (Authorization: Bearer).",
                        _bearer_challenge())
    scheme, _, token = authorization.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or len(token) > 256 or not _B64TOKEN_RE.fullmatch(token):
        raise AuthError(401, "invalid_request", "Очікувалась схема Bearer.", _bearer_challenge())
    digest = sha256_hex(token)
    row = store.get_token(digest)
    if row is None or row["revoked"] or row["expires_at"] <= now or not row["client_enabled"]:
        raise AuthError(401, "invalid_token", "Токен недійсний, відкликаний або прострочений.",
                        _bearer_challenge("invalid_token"))
    return Principal(client_id=row["client_id"], role=row["role"],
                     scopes=frozenset(row["scope"].split()), token_sha256=digest,
                     expires_at=float(row["expires_at"]))


def require_scope(principal: Principal, scope: str) -> None:
    if scope not in principal.scopes:
        raise AuthError(403, "insufficient_scope", f"Потрібен скоуп {scope}.",
                        _bearer_challenge("insufficient_scope", scope))


def revoke_token(store: HubStore, client_id: str, token: str) -> bool:
    """RFC 7009: відкликати можна лише власний токен; невідомий токен — не помилка."""
    if not token or len(token) > 256:
        return False
    return store.revoke_token(sha256_hex(token), client_id)
