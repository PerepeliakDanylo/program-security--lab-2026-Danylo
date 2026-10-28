"""drs_release / integrity.py — цілісність і автентичність релізу (ЛР7).

Призначення цільового файлу в репозиторії: tools/drs_release/integrity.py

Два механізми для артефактів релізу мода:
  * SHA-256-**маніфест** — список «хеш  шлях» усіх файлів релізу (цілісність вмісту);
  * **Ed25519-підпис** маніфесту — автентичність походження (перевіряється відкритим
    ключем без спільного секрету, на відміну від HMAC).

Приватний ключ підпису (`drs_release.signing.key`) тримає власник — у репозиторій НЕ
комітиться. Відкритий ключ (`release_signing.pub`) комітиться й слугує еталоном перевірки.

Цілісність самого файлу облікових записів забезпечує HMAC у accounts.py (стандартна
бібліотека, окремий ключ) — тут не дублюється, щоб ядро автентифікації лишалося без
сторонніх залежностей.

Залежність: pip install cryptography
Генерація ключів: python integrity.py genkey
Самоперевірка:    python integrity.py
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

MANIFEST_NAME = "MANIFEST.sha256"
SIG_NAME = "MANIFEST.sha256.sig"
PRIV_KEY_FILE = "drs_release.signing.key"   # приватний — gitignore
PUB_KEY_FILE = "release_signing.pub"        # публічний — у репозиторії
_EXCLUDE = {MANIFEST_NAME, SIG_NAME}


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.strip().encode("ascii"))


# --- SHA-256-маніфест -------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: str) -> str:
    """Рядок «хеш  відносний/шлях\\n», відсортований за шляхом. Самі маніфест і підпис
    виключені."""
    entries: list[tuple[str, str]] = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name in _EXCLUDE:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            entries.append((rel, sha256_file(full)))
    entries.sort()
    return "".join(f"{h}  {rel}\n" for rel, h in entries)


def _parse(manifest_text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in manifest_text.splitlines():
        if not line.strip():
            continue
        h, _, rel = line.partition("  ")
        out[rel] = h
    return out


def diff_manifest(root: str, expected_text: str) -> list[str]:
    """Перелік розбіжностей між поточним станом теки й очікуваним маніфестом. Порожній → збіг."""
    cur, exp = _parse(build_manifest(root)), _parse(expected_text)
    problems = []
    for rel, h in exp.items():
        if rel not in cur:
            problems.append(f"відсутній: {rel}")
        elif cur[rel] != h:
            problems.append(f"змінено: {rel}")
    for rel in cur:
        if rel not in exp:
            problems.append(f"зайвий: {rel}")
    return sorted(problems)


# --- Ed25519-підпис ---------------------------------------------------------
def generate_keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def sign(priv_raw: bytes, data: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(priv_raw).sign(data)


def verify(pub_raw: bytes, data: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(signature, data)
        return True
    except InvalidSignature:
        return False


def write_keypair(folder: str = ".") -> tuple[str, str]:
    """Нова пара ключів. Приватний — O_EXCL (наявний ключ ніколи не перезаписується) і права
    0600 від самого створення (там, де ОС їх підтримує); відкритий — звичайний файл."""
    priv_path = os.path.join(folder, PRIV_KEY_FILE)
    pub_path = os.path.join(folder, PUB_KEY_FILE)
    pr, pub = generate_keypair()
    try:
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise FileExistsError(f"{priv_path} уже існує — генерацію скасовано.") from None
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(_b64e(pr) + "\n")
    with open(pub_path, "w", encoding="ascii") as fh:
        fh.write(_b64e(pub) + "\n")
    return priv_path, pub_path


def load_key(path: str) -> bytes:
    with open(path, "r", encoding="ascii") as fh:
        return _b64d(fh.read())


# --- CLI / самоперевірка ----------------------------------------------------
def _selftest() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as root:
        with open(os.path.join(root, "a.txt"), "w") as fh:
            fh.write("DynamicReloadSpeed.asi stand-in\n")
        os.makedirs(os.path.join(root, "sub"))
        with open(os.path.join(root, "sub", "b.ini"), "w") as fh:
            fh.write("[settings]\n")

        manifest = build_manifest(root)
        pr, pub = generate_keypair()
        sig = sign(pr, manifest.encode("utf-8"))

        assert verify(pub, manifest.encode("utf-8"), sig), "підпис маніфесту має перевірятися"
        assert diff_manifest(root, manifest) == [], "незмінена тека має збігатися з маніфестом"

        with open(os.path.join(root, "a.txt"), "a") as fh:
            fh.write("tampered\n")
        assert diff_manifest(root, manifest) == ["змінено: a.txt"], "зміну файлу має бути виявлено"
        assert not verify(pub, build_manifest(root).encode("utf-8"), sig), "підпис не має пасувати зміненому"

        wrong_pub = generate_keypair()[1]
        assert not verify(wrong_pub, manifest.encode("utf-8"), sig), "чужий ключ не має перевіряти"
    print("integrity.py self-test OK: маніфест, виявлення зміни, Ed25519-підпис і чужий ключ.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "genkey":
        try:
            priv_path, pub_path = write_keypair()
        except FileExistsError as exc:
            print(str(exc))
            return 1
        print(f"Приватний ключ: {priv_path}  (НЕ комітити)")
        print(f"Відкритий ключ: {pub_path}  (закомітити в репозиторій)")
        return 0
    return _selftest()


if __name__ == "__main__":
    raise SystemExit(main())
