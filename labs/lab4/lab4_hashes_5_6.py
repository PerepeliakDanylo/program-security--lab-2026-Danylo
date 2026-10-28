"""ЛР4, кроки 9, 11, 12: рядок «pass: Перепеляк» і два його хеші.

    Хеш №5 — SHA-256 (швидка хеш-функція загального призначення)
    Хеш №6 — bcrypt із параметром вартості 12 (спеціальний алгоритм для паролів)

Обидва хеші друкуються й записуються у targets.txt поруч зі скриптом — звідти їх беруть
скрипти перебору (кроки 10 і 13).

Чому саме так показово:
  SHA-256 рахується мільйонами за секунду, тому короткий словник «проб'є» його миттєво.
  bcrypt із вартістю 12 робить 2^12 = 4096 ітерацій на одну спробу, тому той самий словник
  перебирається помітно повільніше — у цьому й суть «повільного» хешування паролів.

Залежність: pip install bcrypt
Запуск:     python lab4_hashes_5_6.py
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

import bcrypt

PASSWORD = "pass: Перепеляк"
BCRYPT_COST = 12
TARGETS = pathlib.Path(__file__).with_name("targets.txt")


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bcrypt_hash(text: str) -> str:
    return bcrypt.hashpw(text.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_COST)).decode()


def main() -> int:
    data = PASSWORD.encode("utf-8")
    print(f"Рядок:        {PASSWORD!r}")
    print(f"  символів: {len(PASSWORD)}, байтів UTF-8: {len(data)}\n")

    h5 = sha256_hex(PASSWORD)
    h6 = bcrypt_hash(PASSWORD)

    print(f"Хеш №5 (SHA-256):            {h5}")
    print(f"Хеш №6 (bcrypt, cost={BCRYPT_COST}):     {h6}")

    # Самоперевірка: bcrypt має приймати свій же рядок.
    assert bcrypt.checkpw(data, h6.encode("utf-8")), "bcrypt.checkpw не підтвердив власний хеш"

    TARGETS.write_text(
        "# Цілі для скриптів перебору (крок 10 — SHA-256, крок 13 — bcrypt).\n"
        f"# Пароль-джерело: {PASSWORD}\n"
        f"sha256:{h5}\n"
        f"bcrypt:{h6}\n",
        encoding="utf-8",
    )
    print(f"\nЗаписано у {TARGETS.name}: рядки sha256:… і bcrypt:… для скриптів перебору.")
    print("Примітка: bcrypt щоразу бере нову сіль, тому Хеш №6 буде іншим за кожного запуску —")
    print("це нормально; checkpw усе одно підтверджує пароль, бо сіль зберігається всередині хеша.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
