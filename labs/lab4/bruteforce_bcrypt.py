"""ЛР4, крок 13: перебір Хеша №6 (bcrypt, вартість 12) за тим самим словником.

Читає ціль `bcrypt:…` з targets.txt і для кожного слова словника викликає
bcrypt.checkpw. Сіль і вартість зберігаються всередині самого хеша, тому окремо
їх передавати не треба. Друкує знайдений пароль, спроби, час і швидкість.

Порівняй швидкість зі скриптом bruteforce_sha256.py: вона буде в тисячі разів
нижчою — у цьому й сенс «повільного» хешування паролів.

Запуск: python bruteforce_bcrypt.py
        (спершу запусти lab4_hashes_5_6.py, щоб з'явився targets.txt)
"""

from __future__ import annotations

import pathlib
import sys
import time

import bcrypt

HERE = pathlib.Path(__file__).parent
TARGETS = HERE / "targets.txt"
DICTIONARY = HERE / "dictionary.txt"


def read_target(prefix: str) -> str:
    if not TARGETS.exists():
        sys.exit("Немає targets.txt — спершу запусти lab4_hashes_5_6.py.")
    for line in TARGETS.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    sys.exit(f"У targets.txt немає рядка, що починається з «{prefix}».")


def read_words() -> list[str]:
    if not DICTIONARY.exists():
        sys.exit("Немає dictionary.txt поруч зі скриптом.")
    return [w for w in DICTIONARY.read_text(encoding="utf-8").splitlines() if w != ""]


def main() -> int:
    target = read_target("bcrypt:").encode("utf-8")
    words = read_words()
    cost = target.split(b"$")[2].decode() if target.count(b"$") >= 3 else "?"
    print(f"Ціль bcrypt: {target.decode()}")
    print(f"Вартість (cost): {cost}   Слів у словнику: {len(words)}\n")

    start = time.perf_counter()
    found: str | None = None
    attempts = 0
    for word in words:
        attempts += 1
        if bcrypt.checkpw(word.encode("utf-8"), target):
            found = word
            break
    elapsed = time.perf_counter() - start

    rate = attempts / elapsed if elapsed > 0 else float("inf")
    if found is not None:
        print(f"ЗНАЙДЕНО за {attempts} спроб: {found!r}")
    else:
        print(f"НЕ знайдено за {attempts} спроб (пароля немає у словнику).")
    print(f"Час: {elapsed:.3f} с   Швидкість: {rate:,.1f} спроб/с")
    print("\nВисновок: та сама словникова атака проти bcrypt іде в тисячі разів повільніше, "
          "ніж проти SHA-256, бо кожна спроба — це 2^12 = 4096 внутрішніх ітерацій. "
          "Вартість можна підвищувати з роками, не змінюючи код, — у цьому цінність bcrypt для паролів.")
    return 0 if found is not None else 1


if __name__ == "__main__":
    sys.exit(main())
