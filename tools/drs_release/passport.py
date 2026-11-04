"""drs_release / passport.py — підписаний паспорт релізу (ЛР8).

Призначення цільового файлу в репозиторії: tools/drs_release/passport.py

Паспорт релізу — це підписаний JSON, який посвідчує **походження й умови** випуску мода:
продукт, версію, автора, домашню сторінку, тип ліцензії (Freeware / MIT) і SHA-256 маніфесту
релізу з ЛР7. Тобто один підписаний об'єкт одночасно засвідчує і умови поширення, і точні байти
збірки (через хеш маніфесту). Сам паспорт у маніфест не входить (integrity.py, версія ЛР8), тож
кругової залежності «паспорт → маніфест → паспорт» немає.

Підпис — **RSA-PSS/SHA-256** (RSA-3072), сумісний із командами OpenSSL із вправи ЛР8:
  * закритий ключ `release_passport.key` — **зашифрований паролем PKCS#8** (PEM; OpenSSL читає його
    як звичайний зашифрований приватний ключ) і лежить **поза текою репозиторію**: шлях зі змінної
    середовища DRS_PASSPORT_KEY або, якщо її немає, `%USERPROFILE%\\.drs_release\\release_passport.key`
    (на інших ОС — `~/.drs_release/release_passport.key`). genkey і make-passport відмовляють, якщо
    шлях ключа виявився всередині робочого дерева git, де лежить інструмент (SR-34);
  * відкритий ключ `release_passport.pub` — поруч з інструментом, комітиться: це еталон перевірки.

Чому окремо від Ed25519-підпису маніфесту (ЛР7): маніфест підписується компактним Ed25519 заради
швидкості й простоти; паспорт — це «ліцензія/посвідчення релізу», і для нього взято RSA-PSS —
схему, сумісну з інфраструктурою відкритих ключів і командами OpenSSL (вимога методички ЛР8).

Залежність: pip install cryptography
Генерація ключів: python passport.py genkey        (запитає пароль закритого ключа)
Самоперевірка:    python passport.py                (тимчасові ключі й теки, нічого не записує)
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PASSPORT_NAME = "RELEASE_PASSPORT.json"
PASSPORT_SIG = "RELEASE_PASSPORT.json.sig"
PRIV_KEY_FILE = "release_passport.key"   # зашифрований PKCS#8 — поза репозиторієм
PUB_KEY_FILE = "release_passport.pub"    # відкритий — комітиться
MANIFEST_NAME = "MANIFEST.sha256"        # з integrity.py (ЛР7)
KEY_DIR_NAME = ".drs_release"            # тека ключа в профілі користувача
KEY_ENV = "DRS_PASSPORT_KEY"             # явний шлях закритого ключа

PRODUCT_ID = "DynamicReloadSpeed"
LICENSE_TYPE = "Freeware / MIT"
AUTHOR = "RedziYT (Данило Перепеляк)"
HOMEPAGE = "https://github.com/PerepeliakDanylo/program-security--lab-2026-Danylo"

RSA_BITS = 3072
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size)
_TOOL_DIR = os.path.dirname(os.path.abspath(__file__))


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.strip().encode("ascii"))


def _canonical(passport: dict) -> bytes:
    """Детерміноване подання паспорта для підпису — не залежить від відступів і порядку ключів."""
    return json.dumps(passport, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --- де лежить закритий ключ ------------------------------------------------
def default_key_path() -> str:
    """Шлях закритого ключа: DRS_PASSPORT_KEY, якщо задано, інакше тека .drs_release у профілі
    користувача — за побудовою поза будь-яким репозиторієм."""
    explicit = os.environ.get(KEY_ENV, "").strip()
    if explicit:
        return os.path.abspath(os.path.expanduser(explicit))
    return os.path.join(os.path.expanduser("~"), KEY_DIR_NAME, PRIV_KEY_FILE)


def git_worktree_root(start: str | None = None) -> str | None:
    """Корінь робочого дерева git, якому належить тека start (типово — тека інструмента):
    найближча тека вгору, що містить `.git`. None — поза репозиторієм."""
    path = os.path.abspath(start or _TOOL_DIR)
    while True:
        if os.path.exists(os.path.join(path, ".git")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def key_inside_repo(key_path: str, repo_root: str | None = None) -> bool:
    """True, якщо файл ключа лежить у робочому дереві git, де працює інструмент (SR-34)."""
    root = repo_root if repo_root is not None else git_worktree_root()
    if root is None:
        return False
    key_abs = os.path.normcase(os.path.abspath(key_path))
    root_abs = os.path.normcase(os.path.abspath(root))
    try:
        return os.path.commonpath([key_abs, root_abs]) == root_abs
    except ValueError:                       # різні диски Windows — точно не всередині
        return False


# --- ключі ------------------------------------------------------------------
def generate_keypair(passphrase: bytes) -> tuple[bytes, bytes]:
    """Нова пара RSA-3072. Закритий ключ — зашифрований паролем PKCS#8 (PEM); відкритий — PEM."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase))
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


def write_keypair(passphrase: bytes, priv_path: str | None = None,
                  pub_folder: str | None = None) -> tuple[str, str]:
    """Записати нову пару. Закритий — у priv_path (типово default_key_path()), з O_EXCL (наявний
    ключ ніколи не перезаписується) і правами 0600 від самого створення; відкритий — у теку
    інструмента (його комітять)."""
    priv_path = priv_path or default_key_path()
    pub_path = os.path.join(pub_folder or _TOOL_DIR, PUB_KEY_FILE)
    key_dir = os.path.dirname(priv_path)
    if key_dir:
        os.makedirs(key_dir, exist_ok=True)
    priv_pem, pub_pem = generate_keypair(passphrase)
    try:
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise FileExistsError(f"{priv_path} уже існує — генерацію скасовано.") from None
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv_pem)
    with open(pub_path, "wb") as fh:
        fh.write(pub_pem)
    return priv_path, pub_path


def load_private(path: str, passphrase: bytes):
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=passphrase)


def load_public(path: str):
    with open(path, "rb") as fh:
        return serialization.load_pem_public_key(fh.read())


# --- паспорт ----------------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_passport(release_dir: str, version: str, issued: str) -> dict:
    """Зібрати паспорт релізу. Прив'язується до маніфесту ЛР7 через його SHA-256, тож підпис
    паспорта непрямо засвідчує й усі файли релізу. Поля — читні, умови поширення явні."""
    manifest_path = os.path.join(release_dir, MANIFEST_NAME)
    return {
        "schema": "drs-release-passport/1",
        "product_id": PRODUCT_ID,
        "product_version": version,
        "license_type": LICENSE_TYPE,
        "author": AUTHOR,
        "homepage": HOMEPAGE,
        "issued": issued,
        "manifest_name": MANIFEST_NAME,
        "manifest_sha256": sha256_file(manifest_path),
    }


def sign_passport(priv, passport: dict) -> bytes:
    return priv.sign(_canonical(passport), _PSS, hashes.SHA256())


def verify_passport(pub, passport: dict, signature: bytes) -> bool:
    """True лише для дійсного підпису RSA-PSS. Невідповідний тип ключа чи зіпсовані дані — теж
    False (fail closed), а не виняток."""
    try:
        pub.verify(signature, _canonical(passport), _PSS, hashes.SHA256())
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


# --- самоперевірка / CLI ----------------------------------------------------
def _selftest() -> int:
    import tempfile
    passphrase = b"self-test-passphrase"
    priv_pem, pub_pem = generate_keypair(passphrase)
    priv = serialization.load_pem_private_key(priv_pem, password=passphrase)
    pub = serialization.load_pem_public_key(pub_pem)

    try:   # невірний пароль не має відкрити закритий ключ
        serialization.load_pem_private_key(priv_pem, password=b"wrong")
        raise AssertionError("закритий ключ відкрито невірним паролем")
    except (ValueError, TypeError):
        pass

    with tempfile.TemporaryDirectory() as root:
        with open(os.path.join(root, MANIFEST_NAME), "w", encoding="utf-8") as fh:
            fh.write("aa  file.txt\n")
        passport = build_passport(root, "1.2.1", "2026-10-28")
        sig = sign_passport(priv, passport)
        assert verify_passport(pub, passport, sig), "коректний паспорт має перевірятися"

        tampered = dict(passport)
        tampered["license_type"] = "Commercial"
        assert not verify_passport(pub, tampered, sig), "змінений паспорт не має проходити"

        wrong_pub = serialization.load_pem_public_key(generate_keypair(passphrase)[1])
        assert not verify_passport(wrong_pub, passport, sig), "чужий ключ не має перевіряти"

    # Розміщення закритого ключа (SR-34): у репозиторії — виявляється; поза ним — дозволено;
    # DRS_PASSPORT_KEY має пріоритет над типовою текою профілю.
    with tempfile.TemporaryDirectory() as fake_repo, tempfile.TemporaryDirectory() as outside:
        os.makedirs(os.path.join(fake_repo, ".git"))
        assert key_inside_repo(os.path.join(fake_repo, "tools", PRIV_KEY_FILE), fake_repo), \
            "ключ у робочому дереві git має виявлятися"
        assert not key_inside_repo(os.path.join(outside, PRIV_KEY_FILE), fake_repo), \
            "ключ поза репозиторієм має дозволятися"
        saved = os.environ.get(KEY_ENV)
        try:
            os.environ[KEY_ENV] = os.path.join(outside, "k.key")
            assert default_key_path() == os.path.abspath(os.path.join(outside, "k.key")), \
                "DRS_PASSPORT_KEY має задавати шлях ключа"
            os.environ.pop(KEY_ENV)
            assert default_key_path().endswith(os.path.join(KEY_DIR_NAME, PRIV_KEY_FILE)), \
                "типовий шлях — тека .drs_release у профілі"
        finally:
            if saved is None:
                os.environ.pop(KEY_ENV, None)
            else:
                os.environ[KEY_ENV] = saved
    print("passport.py self-test OK: RSA-3072, зашифрований ключ, RSA-PSS підпис, підміна, чужий ключ, "
          "ключ поза репозиторієм.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "genkey":
        priv_path = default_key_path()
        if key_inside_repo(priv_path):
            print(f"Шлях закритого ключа {priv_path} — усередині робочого дерева git. Задайте "
                  f"{KEY_ENV} поза репозиторієм (SR-34). Генерацію скасовано.")
            return 1
        pw1 = getpass.getpass("Пароль для закритого ключа паспорта: ")
        pw2 = getpass.getpass("Повторіть: ")
        if pw1 != pw2 or len(pw1) < 12:
            print("Паролі не збігаються або коротші за 12 символів.")
            return 1
        try:
            priv_path, pub_path = write_keypair(pw1.encode("utf-8"), priv_path)
        except FileExistsError as exc:
            print(str(exc))
            return 1
        print(f"Закритий ключ (зашифрований паролем, поза репозиторієм): {priv_path}  (НЕ комітити)")
        print(f"Відкритий ключ: {pub_path}  (закомітити в репозиторій)")
        return 0
    return _selftest()


if __name__ == "__main__":
    raise SystemExit(main())
