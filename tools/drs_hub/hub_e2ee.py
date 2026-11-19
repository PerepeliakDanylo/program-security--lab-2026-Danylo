"""drs_hub — наскрізне шифрування діагностичних звітів тестерів (версія ЛР13–14).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_e2ee.py

Хто й що (обґрунтування — docs/security/e2ee_ledger.md):
  * Дані: діагностичний пакет тестера — лог плагіна, INI, перелік модів / дерево теки гри, примітка.
    Перелік модів і шляхи можуть містити ім'я користувача Windows і склад ПК — політика
    конфіденційності мода обіцяє, що такі дані ніхто, крім супроводжувача, не бачить.
  * Сторони: тестер (шифрує на своїй машині) → сервер drs_hub (лише передає й зберігає шифротекст) →
    супроводжувач (розшифровує на своїй машині закритим ключем).
  * Ключі: супроводжувач має довготривалу пару X25519; закритий ключ — PKCS#8, зашифрований
    парольною фразою, поза репозиторієм; відкритий — файл report_recipient.pub у репозиторії: клієнт
    читає його ЛОКАЛЬНО (не з сервера), тож сервер не може підставити власний ключ. Тестер на кожен
    звіт генерує ефемерну пару X25519 і знищує її.
  * Схема (ECIES-подібна): shared = X25519(ефемерний, отримувач); ключ = HKDF-SHA256(shared,
    salt = epk ‖ rpk, info = "drs-hub/report/v1", 32 Б); AES-256-GCM з випадковим nonce 96 біт.
    AAD — канонічний JSON заголовка {v, alg, kid, epk, meta}: метадані (report_id, submitter, created,
    content_type, версії) сервер бачить, але змінити непомітно не може.
  * Пряма секретність лише з боку відправника: компрометація довготривалого ключа отримувача
    розкриває всі звіти, зашифровані на нього, — тому ротація ключа (kid) і знищення старих ключів
    після обробки звітів.
Пакет перед шифруванням стискається zlib; розпакування обмежене 8 МіБ, імена файлів нормалізуються
(обхід шляху «..\\..\\» неможливий).
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import uuid
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import hub_config

VERSION = 1
ALG = "X25519-HKDF-SHA256-AES256GCM"
HKDF_INFO = b"drs-hub/report/v1"
CONTENT_TYPE = "application/x-drs-report+json+zlib"
PUB_HEADER = "drs-hub-report-recipient-v1"
MAX_CT_BYTES = 2 * 1024 * 1024            # шифротекст (стиснений пакет) — до 2 МіБ
MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024     # розпакований пакет — до 8 МіБ
BUNDLE_FORMAT = "drs-report-bundle/1"

_ENVELOPE_FIELDS = {"v", "alg", "kid", "epk", "nonce", "ct", "meta"}
_META_REQUIRED = {"report_id", "submitter", "created", "content_type"}
_META_OPTIONAL = {"plugin_version": 16, "game_build": 32}
_REPORT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SUBMITTER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,47}$")
_CREATED_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_KID_RE = re.compile(r"^[0-9a-f]{16}$")
_NAME_BAD_CHARS = re.compile(r"[^A-Za-z0-9._ -]")
_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class E2EEError(ValueError):
    """Конверт некоректний, ключ не той, або автентифікацію AEAD не пройдено."""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value, field: str, expected_len: int | None = None, max_len: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise E2EEError(f"{field}: очікувався рядок base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise E2EEError(f"{field}: некоректний base64") from None
    if expected_len is not None and len(raw) != expected_len:
        raise E2EEError(f"{field}: очікувалось {expected_len} Б, отримано {len(raw)}")
    if max_len is not None and len(raw) > max_len:
        raise E2EEError(f"{field}: більше за {max_len} Б")
    return raw


# --- ключі ------------------------------------------------------------------------
def key_id(public_key: X25519PublicKey) -> str:
    """kid — 16 hex SHA-256 сирого відкритого ключа: його показують для звірки поза каналом."""
    return hashlib.sha256(public_key.public_bytes(*_RAW)).hexdigest()[:16]


def generate_keypair(private_path: str, public_path: str, passphrase: bytes) -> str:
    private_path = os.path.abspath(private_path)
    if hub_config.path_inside_git_worktree(os.path.dirname(private_path)):
        raise E2EEError("Закритий ключ не можна класти в робоче дерево git — оберіть теку поза репозиторієм.")
    if len(passphrase) < 12:
        raise E2EEError("Парольна фраза коротша за 12 символів.")
    key = X25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(passphrase))
    os.makedirs(os.path.dirname(private_path), exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    with open(public_path, "w", encoding="ascii", newline="\n") as fh:
        fh.write(f"{PUB_HEADER} {_b64e(key.public_key().public_bytes(*_RAW))}\n")
    return key_id(key.public_key())


def load_public(path: str) -> X25519PublicKey:
    with open(path, "r", encoding="utf-8-sig") as fh:
        header, _, value = fh.read().strip().partition(" ")
    if header != PUB_HEADER:
        raise E2EEError(f"{path}: не файл відкритого ключа отримувача звітів ({PUB_HEADER})")
    return X25519PublicKey.from_public_bytes(_b64d(value.strip(), "ключ", 32))


def load_private(path: str, passphrase: bytes) -> X25519PrivateKey:
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        key = serialization.load_pem_private_key(data, password=passphrase)
    except (ValueError, TypeError):
        raise E2EEError("Не вдалося відкрити закритий ключ: невірна парольна фраза або пошкоджений файл.") from None
    if not isinstance(key, X25519PrivateKey):
        raise E2EEError("Файл містить не ключ X25519.")
    return key


# --- метадані, конверт ------------------------------------------------------------
def new_meta(submitter: str, plugin_version: str | None = None, game_build: str | None = None) -> dict:
    meta = {"report_id": uuid.uuid4().hex, "submitter": submitter,
            "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "content_type": CONTENT_TYPE}
    if plugin_version:
        meta["plugin_version"] = str(plugin_version)[:_META_OPTIONAL["plugin_version"]]
    if game_build:
        meta["game_build"] = str(game_build)[:_META_OPTIONAL["game_build"]]
    return validate_meta(meta)


def validate_meta(meta) -> dict:
    if not isinstance(meta, dict):
        raise E2EEError("meta: очікувався об'єкт")
    keys = set(meta)
    if not _META_REQUIRED <= keys or not keys <= _META_REQUIRED | set(_META_OPTIONAL):
        raise E2EEError("meta: обов'язкові report_id, submitter, created, content_type; інших полів, крім "
                        "plugin_version і game_build, немає")
    if not isinstance(meta["report_id"], str) or not _REPORT_ID_RE.fullmatch(meta["report_id"]):
        raise E2EEError("meta.report_id: 32 hex")
    if not isinstance(meta["submitter"], str) or not _SUBMITTER_RE.fullmatch(meta["submitter"]):
        raise E2EEError("meta.submitter: ідентифікатор клієнта")
    if not isinstance(meta["created"], str) or not _CREATED_RE.fullmatch(meta["created"]):
        raise E2EEError("meta.created: YYYY-MM-DDTHH:MM:SSZ")
    if meta["content_type"] != CONTENT_TYPE:
        raise E2EEError("meta.content_type: невідомий формат пакета")
    for name, limit in _META_OPTIONAL.items():
        if name in meta:
            value = meta[name]
            if not isinstance(value, str) or not value or len(value) > limit or not value.isprintable():
                raise E2EEError(f"meta.{name}: друкований рядок до {limit} символів")
    return meta


def _aad(header: dict) -> bytes:
    return json.dumps(header, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_key(shared: bytes, epk_raw: bytes, rpk_raw: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk_raw + rpk_raw, info=HKDF_INFO).derive(shared)


def validate_envelope(envelope, max_ct: int = MAX_CT_BYTES) -> dict:
    """Структурна перевірка без ключів (виконує сервер): поля, типи, довжини, метадані."""
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
        raise E2EEError("конверт: рівно поля v, alg, kid, epk, nonce, ct, meta")
    if type(envelope["v"]) is not int or envelope["v"] != VERSION or envelope["alg"] != ALG:
        raise E2EEError(f"конверт: підтримується лише v={VERSION}, alg={ALG}")
    if not isinstance(envelope["kid"], str) or not _KID_RE.fullmatch(envelope["kid"]):
        raise E2EEError("kid: 16 hex")
    _b64d(envelope["epk"], "epk", 32)
    _b64d(envelope["nonce"], "nonce", 12)
    ct = _b64d(envelope["ct"], "ct", max_len=max_ct + 16)
    if len(ct) < 17:
        raise E2EEError("ct: закороткий шифротекст")
    validate_meta(envelope["meta"])
    return envelope


def encrypt_report(recipient: X25519PublicKey, plaintext: bytes, meta: dict) -> dict:
    """Зашифрувати пакет для отримувача. Повертає конверт (JSON-сумісний словник)."""
    validate_meta(meta)
    ephemeral = X25519PrivateKey.generate()
    epk_raw = ephemeral.public_key().public_bytes(*_RAW)
    rpk_raw = recipient.public_bytes(*_RAW)
    key = _derive_key(ephemeral.exchange(recipient), epk_raw, rpk_raw)
    nonce = os.urandom(12)
    header = {"v": VERSION, "alg": ALG, "kid": key_id(recipient), "epk": _b64e(epk_raw), "meta": meta}
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(header))
    if len(ciphertext) > MAX_CT_BYTES + 16:
        raise E2EEError("звіт завеликий навіть після стиснення (понад 2 МіБ)")
    envelope = dict(header)
    envelope["nonce"] = _b64e(nonce)
    envelope["ct"] = _b64e(ciphertext)
    return envelope


def decrypt_report(private_key: X25519PrivateKey, envelope: dict) -> tuple[bytes, dict]:
    """Розшифрувати конверт закритим ключем отримувача; будь-яка зміна → E2EEError."""
    validate_envelope(envelope)
    if envelope["kid"] != key_id(private_key.public_key()):
        raise E2EEError(f"звіт зашифровано іншим ключем (kid {envelope['kid']})")
    epk_raw = _b64d(envelope["epk"], "epk", 32)
    rpk_raw = private_key.public_key().public_bytes(*_RAW)
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(epk_raw))
    except ValueError:     # точка малого порядку → нульовий спільний секрет (OpenSSL відмовляє)
        raise E2EEError("epk: некоректний ефемерний ключ") from None
    key = _derive_key(shared, epk_raw, rpk_raw)
    header = {k: envelope[k] for k in ("v", "alg", "kid", "epk", "meta")}
    try:
        plaintext = AESGCM(key).decrypt(_b64d(envelope["nonce"], "nonce", 12),
                                        _b64d(envelope["ct"], "ct"), _aad(header))
    except InvalidTag:
        raise E2EEError("автентифікацію AES-GCM не пройдено: шифротекст, nonce або метадані змінено") from None
    return plaintext, envelope["meta"]


# --- пакет файлів ----------------------------------------------------------------------
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def safe_name(name: str) -> str:
    """Лише базове ім'я з дозволеними символами — жодних «..», дисків, підтек і пристроїв Windows."""
    base = os.path.basename(str(name).replace("\\", "/"))
    base = _NAME_BAD_CHARS.sub("_", base).strip(" .")
    base = (base or "file")[:100]
    if base.split(".")[0].strip().upper() in _RESERVED:
        base = "_" + base
    return base


def build_bundle(files: list[tuple[str, bytes]], note: str = "") -> bytes:
    items = [{"name": safe_name(name), "text": data.decode("utf-8", errors="replace")} for name, data in files]
    raw = json.dumps({"format": BUNDLE_FORMAT, "note": note[:2000], "files": items},
                     ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_PLAINTEXT_BYTES:
        raise E2EEError("пакет звіту більший за 8 МіБ")
    return zlib.compress(raw, 9)


def parse_bundle(blob: bytes) -> dict:
    decompressor = zlib.decompressobj()
    try:
        raw = decompressor.decompress(blob, MAX_PLAINTEXT_BYTES + 1)
    except zlib.error:
        raise E2EEError("пакет звіту пошкоджено") from None
    if len(raw) > MAX_PLAINTEXT_BYTES or decompressor.unconsumed_tail:
        raise E2EEError("розпакований пакет більший за 8 МіБ")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise E2EEError("пакет звіту — не JSON") from None
    if not isinstance(data, dict) or data.get("format") != BUNDLE_FORMAT or not isinstance(data.get("files"), list):
        raise E2EEError("невідомий формат пакета звіту")
    return data


def write_bundle(bundle: dict, out_dir: str) -> list[str]:
    """Записати файли пакета в out_dir (імена нормалізовано; вихід за межі теки неможливий)."""
    os.makedirs(out_dir, exist_ok=True)
    root = os.path.realpath(out_dir)
    written: list[str] = []
    entries = list(bundle.get("files", []))
    if bundle.get("note"):
        entries.append({"name": "note.txt", "text": bundle["note"]})
    for entry in entries[:50]:
        name = safe_name(entry.get("name", "file"))
        path = os.path.realpath(os.path.join(root, name))
        if os.path.dirname(path) != root:
            raise E2EEError(f"ім'я файла {name!r} виходить за межі теки")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(str(entry.get("text", "")))
        written.append(path)
    return written
