"""ЛР4, крок 10: перебір Хеша №5 (SHA-256) за словником.

Читає ціль `sha256:…` з targets.txt, проходить dictionary.txt і для кожного слова
рахує SHA-256, доки не збіжиться з ціллю. Друкує знайдений пароль, кількість спроб,
час і швидкість (спроб/с) — щоб потім порівняти з bcrypt (крок 13).

Запуск: python bruteforce_sha256.py
        (спершу запусти lab4_hashes_5_6.py, щоб з'явився targets.txt)
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
import time

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
    target = read_target("sha256:")
    words = read_words()
    print(f"Ціль SHA-256: {target}")
    print(f"Слів у словнику: {len(words)}\n")

    start = time.perf_counter()
    found: str | None = None
    attempts = 0
    for word in words:
        attempts += 1
        if hashlib.sha256(word.encode("utf-8")).hexdigest() == target:
            found = word
            break
    elapsed = time.perf_counter() - start

    rate = attempts / elapsed if elapsed > 0 else float("inf")
    if found is not None:
        print(f"ЗНАЙДЕНО за {attempts} спроб: {found!r}")
    else:
        print(f"НЕ знайдено за {attempts} спроб (пароля немає у словнику).")
    print(f"Час: {elapsed * 1000:.3f} мс   Швидкість: {rate:,.0f} спроб/с")
    print("\nВисновок: SHA-256 — швидка хеш-функція, тому навіть простий перебір "
          "«пробиває» словниковий пароль практично миттєво. Саме тому паролі не можна "
          "зберігати під SHA-256 — для цього є bcrypt/scrypt/Argon2 (див. крок 13).")
    return 0 if found is not None else 1


if __name__ == "__main__":
    sys.exit(main())
