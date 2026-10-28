"""drs_release / crypto.py — симетричний захист чутливих даних (ЛР6).

Призначення цільового файлу в репозиторії: tools/drs_release/crypto.py

Найчутливіші дані інструмента — **секрет TOTP** (другий фактор). Його не можна
зберігати відкрито. Схема — **конвертне шифрування** (key wrapping):

    пароль ──PBKDF2(ЛР4)──► master ──HKDF-SHA256──► KEK        (ключ-обгортка)
    секрет TOTP ──AES-256-GCM(DEK)──► шифротекст секрету        (DEK — випадковий)
    DEK ──AES-256-GCM(KEK)──► обгорнутий DEK

Чому так:
  * HKDF з info="drs-release/totp-kek" дає ключ, НЕЗАЛЕЖНИЙ від верифікатора пароля
    (той — HMAC з info="drs-release/verifier"): **розділення ключів за призначенням**.
  * AES-256-GCM — **автентифіковане** шифрування: ловить будь-яку підміну (на відміну
    від CTR із вправи). AAD = ім'я користувача прив'язує шифротекст до запису.
  * DEK окремо від KEK → **ротація**: згенерувати новий DEK і переобгорнути, не
    змінюючи пароль; зміна пароля → переобгортання під новий KEK (rewrap_for_new_master).
  * KEK виводиться з master, який існує лише в пам'яті сесії (ЛР4) → відкрити секрет
    можна лише одразу після успішного входу власника запису.

TOTP (RFC 6238) рахується лише стандартною бібліотекою (hmac/hashlib); `cryptography`
потрібен для AES-GCM і HKDF. Нічого саморобного в криптографії — лише стандартні примітиви.

Залежність: pip install cryptography
Самоперевірка: python crypto.py
"""

from __future__ import annotations

import base64
import hmac
import os
import struct
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEK_INFO = b"drs-release/totp-kek"   # відрізняється від верифікатора — розділення ключів
KEK_SALT_BYTES = 16
DEK_BYTES = 32                       # AES-256
GCM_NONCE_BYTES = 12                 # рекомендований розмір nonce для GCM
TOTP_SECRET_BYTES = 20               # 160 біт, як у стандартних автентифікаторах


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# --- конвертне шифрування секрету TOTP --------------------------------------
def derive_kek(master: bytes, salt: bytes) -> bytes:
    """KEK із майстер-секрета пароля. info відрізняє його від усіх інших похідних ключів."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=KEK_INFO).derive(master)


def seal_totp_secret(master: bytes, totp_secret: bytes, username: str) -> dict:
    """Запечатати секрет: випадковий DEK шифрує секрет, KEK обгортає DEK. AAD = username."""
    aad = username.encode("utf-8")
    kek_salt = os.urandom(KEK_SALT_BYTES)
    kek = derive_kek(master, kek_salt)
    dek = os.urandom(DEK_BYTES)
    n_s = os.urandom(GCM_NONCE_BYTES)
    secret_ct = AESGCM(dek).encrypt(n_s, totp_secret, aad)
    n_k = os.urandom(GCM_NONCE_BYTES)
    dek_wrapped = AESGCM(kek).encrypt(n_k, dek, aad)
    return {
        "v": 1, "alg": "AES-256-GCM", "kdf": "HKDF-SHA256",
        "kek_salt": _b64e(kek_salt),
        "dek_wrap_nonce": _b64e(n_k), "dek_wrapped": _b64e(dek_wrapped),
        "secret_nonce": _b64e(n_s), "secret_ct": _b64e(secret_ct),
    }


def open_totp_secret(master: bytes, blob: dict, username: str) -> bytes:
    """Розпечатати секрет. Кидає InvalidTag, якщо щось підмінено або AAD/ключ не ті."""
    aad = username.encode("utf-8")
    kek = derive_kek(master, _b64d(blob["kek_salt"]))
    dek = AESGCM(kek).decrypt(_b64d(blob["dek_wrap_nonce"]), _b64d(blob["dek_wrapped"]), aad)
    return AESGCM(dek).decrypt(_b64d(blob["secret_nonce"]), _b64d(blob["secret_ct"]), aad)


def rotate(master: bytes, blob: dict, username: str) -> dict:
    """Ротація ключів: новий DEK (і новий KEK-salt), той самий секрет, той самий пароль."""
    secret = open_totp_secret(master, blob, username)
    return seal_totp_secret(master, secret, username)


def rewrap_for_new_master(old_master: bytes, new_master: bytes, blob: dict, username: str) -> dict:
    """Переобгортання під новий пароль (зміна власного пароля): потрібен старий master."""
    secret = open_totp_secret(old_master, blob, username)
    return seal_totp_secret(new_master, secret, username)


# --- TOTP (RFC 6238), лише стандартна бібліотека ----------------------------
def new_totp_secret() -> bytes:
    return os.urandom(TOTP_SECRET_BYTES)


def _hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    """HOTP (RFC 4226) для одного кроку: HMAC-SHA1 + динамічне усічення."""
    mac = hmac.new(secret, struct.pack(">Q", counter), "sha1").digest()
    off = mac[-1] & 0x0F
    value = int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def totp_code(secret: bytes, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    return _hotp(secret, int((time.time() if at is None else at) // step), digits)


def totp_match_counter(secret: bytes, code: str, at: float | None = None,
                       step: int = 30, digits: int = 6, window: int = 1) -> int | None:
    """Номер кроку, для якого код дійсний (з допуском ±window кроків на розбіжність
    годинників), або None. Номер потрібен для одноразовості: викликач відхиляє код,
    якщо його крок не новіший за останній прийнятий (повтор у межах вікна)."""
    now = time.time() if at is None else at
    code = str(code).strip()
    if not (code.isdigit() and len(code) == digits):
        return None
    base = int(now // step)
    for drift in range(-window, window + 1):
        counter = base + drift
        if counter < 0:                 # до епохи кроків немає (struct ">Q" не бере від'ємних)
            continue
        if hmac.compare_digest(_hotp(secret, counter, digits), code):
            return counter
    return None


def totp_verify(secret: bytes, code: str, at: float | None = None,
                step: int = 30, digits: int = 6, window: int = 1) -> bool:
    return totp_match_counter(secret, code, at, step, digits, window) is not None


def provisioning_uri(username: str, secret: bytes, issuer: str = "drs_release") -> str:
    """otpauth:// для додавання в застосунок-автентифікатор (секрет у base32)."""
    b32 = base64.b32encode(secret).decode("ascii").rstrip("=")
    return f"otpauth://totp/{issuer}:{username}?secret={b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


# --- самоперевірка ----------------------------------------------------------
def _selftest() -> int:
    from cryptography.exceptions import InvalidTag
    master = os.urandom(32)
    user = "maintainer"
    secret = new_totp_secret()

    blob = seal_totp_secret(master, secret, user)
    assert open_totp_secret(master, blob, user) == secret, "round-trip secret"

    code = totp_code(secret)
    assert totp_verify(secret, code), "TOTP self-verify"
    assert not totp_verify(secret, "000000", at=0), "TOTP wrong code rejected"
    now = time.time()
    assert totp_match_counter(secret, totp_code(secret, now), now) == int(now // 30), \
        "номер кроку для одноразовості"
    assert totp_match_counter(secret, "12345a", now) is None, "нецифровий код відхилено"

    # RFC 6238, додаток B: секрет "12345678901234567890", T = 59 c, 8 цифр → 94287082
    rfc_secret = b"12345678901234567890"
    assert totp_code(rfc_secret, at=59, digits=8) == "94287082", "тестовий вектор RFC 6238"

    # підміна шифротексту секрету має провалити перевірку мітки GCM
    bad = dict(blob)
    raw = bytearray(_b64d(blob["secret_ct"]))
    raw[0] ^= 0x01
    bad["secret_ct"] = _b64e(bytes(raw))
    try:
        open_totp_secret(master, bad, user)
        raise AssertionError("підміну не виявлено")
    except InvalidTag:
        pass

    # інший username (AAD) не має розпечатати
    try:
        open_totp_secret(master, blob, "owner")
        raise AssertionError("AAD не прив'язав запис")
    except InvalidTag:
        pass

    rotated = rotate(master, blob, user)
    assert rotated["dek_wrapped"] != blob["dek_wrapped"], "ротація змінила обгортку DEK"
    assert open_totp_secret(master, rotated, user) == secret, "секрет після ротації той самий"

    new_master = os.urandom(32)
    rewrapped = rewrap_for_new_master(master, new_master, blob, user)
    assert open_totp_secret(new_master, rewrapped, user) == secret, "переобгортання під новий пароль"

    print("crypto.py self-test OK: seal/open, TOTP (вектор RFC 6238, номер кроку), виявлення підміни, "
          "AAD, ротація, переобгортання.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
