"""ЛР7, кроки 2-11: цілісність та автентичність — SHA-256, HMAC, AES-GCM.

Три демонстрації на одному рядку (шаблон методички, варіант дволітерний):

  2-4  SHA-256 і «лавина»: зміна одного символу → хеш змінюється приблизно наполовину бітів.
  5-9  HMAC-SHA256: зміна повідомлення або ключа робить перевірку невдалою; зміна одного
       біта ключа змінює ~половину бітів результату (HMAC не можна підробити без ключа).
  10-11 AES-GCM: зміна одного байта шифротексту → перевірка мітки провалюється (InvalidTag),
       тобто автентифіковане шифрування виявляє підміну (на відміну від «голого» CTR із ЛР6).

Залежність: pip install cryptography   (SHA-256/HMAC — стандартна бібліотека; AES-GCM — cryptography)
Запуск:     python integrity_demo.py
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MESSAGE = "2026_КБЗІ-24-1_Перепеляк_Данило_варіант:14"


def bit_diff(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def flip_one_bit(data: bytes, index: int = 0, bit: int = 0) -> bytes:
    raw = bytearray(data)
    raw[index] ^= (1 << bit)
    return bytes(raw)


def part_sha256() -> None:
    print("== SHA-256 і лавинний ефект (кроки 3-4) ==")
    h1 = hashlib.sha256(MESSAGE.encode("utf-8")).digest()
    altered = "2026_КБЗІ-24-1_Перепеляк_Данило_варіант:15"   # змінено один символ (4→5)
    h2 = hashlib.sha256(altered.encode("utf-8")).digest()
    print(f"Хеш №1: {h1.hex()}")
    print(f"Хеш №2: {h2.hex()}  (змінено один символ)")
    print(f"Відмінність: {bit_diff(h1, h2)} із 256 бітів (~половина — лавинний ефект).\n")


def part_hmac() -> None:
    print("== HMAC-SHA256 (кроки 5-9) ==")
    msg = MESSAGE.encode("utf-8")
    key1 = os.urandom(32)
    mac1 = hmac.new(key1, msg, hashlib.sha256).digest()
    print(f"Ключ №1: {key1.hex()}")
    print(f"HMAC №1: {mac1.hex()}")

    # крок 6: змінене повідомлення проти HMAC №1
    msg_bad = MESSAGE.replace(":14", ":15").encode("utf-8")
    ok_msg = hmac.compare_digest(hmac.new(key1, msg_bad, hashlib.sha256).digest(), mac1)
    print(f"Перевірка зміненого повідомлення проти HMAC №1: {'OK' if ok_msg else 'НЕВДАЛО'}")

    # кроки 7-8: ключ зі зміненим одним бітом проти HMAC №1
    key2 = flip_one_bit(key1)
    ok_key = hmac.compare_digest(hmac.new(key2, msg, hashlib.sha256).digest(), mac1)
    print(f"Перевірка з ключем (1 біт змінено) проти HMAC №1: {'OK' if ok_key else 'НЕВДАЛО'}")

    # крок 9: HMAC №2 оригінального повідомлення зі зміненим ключем
    mac2 = hmac.new(key2, msg, hashlib.sha256).digest()
    print(f"HMAC №2: {mac2.hex()}")
    print(f"Відмінність HMAC №1/№2 при зміні 1 біта ключа: {bit_diff(mac1, mac2)} із 256 бітів.\n")


def part_aes_gcm() -> None:
    print("== AES-GCM: виявлення підміни (кроки 10-11) ==")
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, MESSAGE.encode("utf-8"), None)   # містить і шифротекст, і мітку
    print(f"Ключ:     {key.hex()}")
    print(f"Nonce:    {nonce.hex()}")
    print(f"Шифротекст+мітка: {ct.hex()}")
    ok = aes.decrypt(nonce, ct, None).decode("utf-8")
    print(f"Штатне розшифрування: {ok}")

    tampered = flip_one_bit(ct, index=0)                     # змінено один байт
    try:
        aes.decrypt(nonce, tampered, None)
        print("ПОМИЛКА: підміну не виявлено!")
    except InvalidTag:
        print("Зміну одного байта шифротексту виявлено: InvalidTag — дані відхилено.\n")


def main() -> int:
    part_sha256()
    part_hmac()
    part_aes_gcm()
    print("Висновок: SHA-256 виявляє зміну, лише якщо еталонний хеш захищено від підміни; проти")
    print("активного порушника потрібні HMAC (спільний секрет) або цифровий підпис, а для даних,")
    print("що й шифруються, — автентифіковане шифрування (AES-GCM). Вибір залежить від моделі загроз.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
