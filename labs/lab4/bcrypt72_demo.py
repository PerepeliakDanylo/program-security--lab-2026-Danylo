"""ЛР4, кроки 2-8: межа bcrypt у 72 БАЙТИ, а не символи.

Будує базовий рядок «2026_КБЗІ-24-1_Перепеляк_14_», рахує його розмір у кодуванні
UTF-8, доповнює символами «_» рівно до 72 байтів і формує чотири рядки:

    №1  базовий рядок                         (72 байти)
    №2  базовий + «1»                         (73 байти)
    №3  базовий + 10 випадкових символів      (82 байти)
    №4  базовий без останнього «_»            (71 байт)

Для кожного рахує хеш bcrypt, а потім перевіряє всі 16 пар «рядок × хеш».

Кирилиця в UTF-8 займає 2 байти на літеру, тому 28 символів базового рядка дають
41 байт — саме тут видно, що межа рахується в байтах.

Залежність: pip install bcrypt
Запуск:     python bcrypt72_demo.py
"""

from __future__ import annotations

import secrets
import string
import sys

import bcrypt

YEAR = "2026"
GROUP = "КБЗІ-24-1"
SURNAME = "Перепеляк"
VARIANT = "14"

TARGET_BYTES = 72
ROUNDS = 10  # як за замовчуванням у CyberChef


def utf8_len(text: str) -> int:
    return len(text.encode("utf-8"))


def build_strings() -> list[tuple[str, str]]:
    raw = f"{YEAR}_{GROUP}_{SURNAME}_{VARIANT}_"
    raw_bytes = utf8_len(raw)
    print(f"Сирий рядок:   {raw}")
    print(f"  символів: {len(raw)}, байтів UTF-8: {raw_bytes}")
    if raw_bytes > TARGET_BYTES:
        sys.exit("Сирий рядок уже довший за 72 байти — перевір вхідні дані.")

    base = raw + "_" * (TARGET_BYTES - raw_bytes)  # «_» — 1 байт
    alphabet = string.ascii_letters + string.digits
    random10 = "".join(secrets.choice(alphabet) for _ in range(10))

    strings = [
        ("№1 базовий", base),
        ("№2 базовий + «1»", base + "1"),
        ("№3 базовий + 10 випадкових", base + random10),
        ("№4 без останнього «_»", base[:-1]),
    ]
    print(f"Доповнено {TARGET_BYTES - raw_bytes} символами «_».\n")
    for label, text in strings:
        print(f"{label:<30} {utf8_len(text):>3} Б  {text}")
    print()
    return strings


def bcrypt_hash(data: bytes) -> tuple[bytes, str]:
    """Хеш bcrypt. Нові версії бібліотеки (bcrypt >= 5.0) не обрізають вхід довший
    за 72 байти мовчки, а відхиляють його. Тоді відтворюємо класичну поведінку
    (так працює і CyberChef, і більшість реалізацій) явним зрізом до 72 байтів
    і кажемо про це у виводі — це теж результат, який варто записати у звіт."""
    try:
        return bcrypt.hashpw(data, bcrypt.gensalt(rounds=ROUNDS)), ""
    except ValueError:
        return (bcrypt.hashpw(data[:TARGET_BYTES], bcrypt.gensalt(rounds=ROUNDS)),
                "бібліотека відхилила вхід > 72 Б; захешовано перші 72 Б")


def bcrypt_check(data: bytes, hashed: bytes) -> tuple[bool, str]:
    try:
        return bcrypt.checkpw(data, hashed), ""
    except ValueError:
        return bcrypt.checkpw(data[:TARGET_BYTES], hashed), "обрізано до 72 Б"


def main() -> int:
    print(f"bcrypt (pyca) версії {getattr(bcrypt, '__version__', '?')}, rounds = {ROUNDS}\n")
    strings = build_strings()

    hashes: list[bytes] = []
    for i, (label, text) in enumerate(strings, 1):
        hashed, note = bcrypt_hash(text.encode("utf-8"))
        hashes.append(hashed)
        print(f"Хеш №{i}: {hashed.decode()}" + (f"   [{note}]" if note else ""))
    print()

    print("Матриця перевірки (рядок → хеш): ✓ — checkpw повернув True")
    header = "".join(f"  Хеш №{j}" for j in range(1, len(hashes) + 1))
    print(f"{'':<30}{header}")
    notes = set()
    for label, text in strings:
        row = ""
        for hashed in hashes:
            ok, note = bcrypt_check(text.encode("utf-8"), hashed)
            if note:
                notes.add(note)
            row += f"  {'   ✓   ' if ok else '   ✗   '}"
        print(f"{label:<30}{row}")
    if notes:
        print("\nПримітка: " + "; ".join(sorted(notes)) + ".")

    print("\nОчікування: рядки №1-№3 збігаються в перших 72 байтах, тому хеші №1-№3 "
          "приймають усі три (9 пар ✓). Рядок №4 коротший на байт — його приймає лише хеш №4.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
