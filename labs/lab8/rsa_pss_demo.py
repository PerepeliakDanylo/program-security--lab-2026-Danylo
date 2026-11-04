"""Вправа ЛР8 — підпис і перевірка файла ліцензії за схемою RSA-PSS/SHA-256 (перехресна перевірка).

Основне завдання виконується командами OpenSSL (openssl_license.md): ключі private.pem/public.pem,
підпис license.sig. Цей скрипт робить те саме через бібліотеку cryptography і перевіряє, що схеми
сумісні в обидва боки, НЕ чіпаючи файлів основного завдання:

    python rsa_pss_demo.py --verify-only
        OpenSSL → Python: перевірити підпис OpenSSL (public.pem + license.sig + license.json).

    python rsa_pss_demo.py
        Повний цикл у пам'яті: нова пара RSA-3072 (закритий ключ на диск не пишеться), підпис
        license.json, перевірка, підміна одного байта (лише в пам'яті — license.json не змінюється),
        повторна перевірка. Потім Python → OpenSSL: записує demo_public.pem і license.py.sig і друкує
        команду OpenSSL, якою той самий підпис перевіряється (Verified OK).

Параметри PSS відповідають командам методички: MGF1-SHA256, довжина солі = довжині геша
(rsa_pss_saltlen:digest); при перевірці OpenSSL бере saltlen:auto, тож приймає й це значення.
"""

from __future__ import annotations

import argparse
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

LICENSE = "license.json"
SIG = "license.sig"            # підпис основного завдання (OpenSSL)
PUB = "public.pem"             # відкритий ключ основного завдання (OpenSSL)
DEMO_SIG = "license.py.sig"    # підпис, створений цим скриптом
DEMO_PUB = "demo_public.pem"   # відкритий ключ цього скрипта (закритий лишається в пам'яті)

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size)


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _check(pub, signature: bytes, data: bytes, label: str) -> bool:
    try:
        pub.verify(signature, data, _PSS, hashes.SHA256())
        print(f"{label}: Verified OK")
        return True
    except InvalidSignature:
        print(f"{label}: Verification failure")
        return False


def verify_openssl_artifacts() -> int:
    """OpenSSL → Python: підпис license.sig, створений командою з методички."""
    try:
        pub = serialization.load_pem_public_key(_read(PUB))
        ok = _check(pub, _read(SIG), _read(LICENSE), f"Підпис OpenSSL ({SIG}, {PUB})")
    except FileNotFoundError as exc:
        print(f"Немає файла {exc.filename} — спершу виконайте команди OpenSSL з openssl_license.md.")
        return 1
    return 0 if ok else 1


def full_cycle() -> int:
    data = _read(LICENSE)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pub = priv.public_key()
    signature = priv.sign(data, _PSS, hashes.SHA256())
    print("Згенеровано RSA-3072 у пам'яті; license.json підписано (RSA-PSS/SHA-256).")

    print("\n— коректна ліцензія —")
    ok = _check(pub, signature, data, "Перевірка")

    print("\n— підміна одного байта license.json (лише в пам'яті; файл і підпис не змінюються) —")
    tampered = bytearray(data)
    pos = data.find(b"2027")                 # перша цифра року valid_until — валідний JSON, інший вміст
    tampered[pos if pos >= 0 else len(data) // 2] ^= 0x01
    tampered_ok = _check(pub, signature, bytes(tampered), "Перевірка")

    # Python → OpenSSL: відкритий ключ і підпис цього скрипта — для перевірки командою OpenSSL.
    with open(DEMO_PUB, "wb") as fh:
        fh.write(pub.public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(DEMO_SIG, "wb") as fh:
        fh.write(signature)
    print(f"\nЗаписано {DEMO_PUB} і {DEMO_SIG}. Перевірка тим самим OpenSSL (очікується Verified OK):")
    print(f"  openssl dgst -sha256 -verify {DEMO_PUB} -signature {DEMO_SIG} "
          f"-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto {LICENSE}")

    if not ok or tampered_ok:
        print("ПОМИЛКА: очікувалось «OK» для коректної ліцензії й «failure» для підміненої.")
        return 1
    print("\nВисновок: зміна license.json без закритого ключа робить підпис недійсним; відкритого ключа "
          "досить для перевірки, але недостатньо для підробки нового підпису.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="RSA-PSS підпис файла ліцензії (ЛР8), перехресна перевірка.")
    ap.add_argument("--verify-only", action="store_true",
                    help="лише перевірити підпис OpenSSL: public.pem + license.sig + license.json")
    args = ap.parse_args(argv)
    return verify_openssl_artifacts() if args.verify_only else full_cycle()


if __name__ == "__main__":
    sys.exit(main())
