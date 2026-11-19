"""ЛР13–14, п. 2–4 — програмна модель блокчейну на SHA-256 (лише стандартна бібліотека).

Блок: порядковий номер, час, дані, хеш попереднього блока, nonce, власний хеш.
hash = SHA-256(канонічний JSON {index, timestamp, data, prev_hash, nonce}).
Proof of Work (необов'язково, --difficulty N): nonce підбирається, доки шістнадцятковий хеш не
почнеться з N нулів — так «переписати історію» стає обчислювально дорого.

Сценарій (усе в одному запуску):
  1. початковий блок (Genesis) і 5 наступних; таблиця блоків;
  2. перевірка цілісності ланцюга → цілий;
  3а. зміна даних блока 2 без перерахунку хешу → блок 2 недійсний (хеш ≠ вмісту);
  3б. зміна даних блока 2 з перерахунком (і майнінгом) лише його хешу → блок 2 «правильний», але
      блок 3 посилається на старий хеш — ланцюг розірвано;
  4. відновлення коректності: повторне формування блока 2 і всіх наступних → ланцюг знову цілий,
     але хеші блоків 2–5 і голови ланцюга інші — той, хто зберіг стару голову (якір), підміну бачить;
     заміряно ціну перебудови (спроби, час) проти ціни перевірки.

    python blockchain_demo.py [--difficulty 4] [--fixed-time]
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import time
from dataclasses import dataclass

ZERO_HASH = "0" * 64

RECORDS = [
    "Genesis — ЛР13–14, КБЗІ-24-1, Перепеляк Данило, варіант 14",
    "DRS 1.2.1 опубліковано на NexusMods (2026-11-16)",
    "DRS 1.2.2: виправлення резолвера за логом гравця (2026-11-16)",
    "DRS 1.2.2 опубліковано: SHA-256 архіву 125f0ac7…2b7 (2026-11-17)",
    "Лог гравця з Munitions підтвердив AT-94 (2026-11-18)",
    "drs_hub 0.3.0: наскрізне шифрування звітів і журнал записів (ЛР13–14)",
]


@dataclass
class Block:
    index: int
    timestamp: str
    data: str
    prev_hash: str
    nonce: int = 0
    hash: str = ""

    def compute_hash(self) -> str:
        body = json.dumps({"index": self.index, "timestamp": self.timestamp, "data": self.data,
                           "prev_hash": self.prev_hash, "nonce": self.nonce},
                          ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


def mine(block: Block, difficulty: int) -> int:
    """Підібрати nonce (Proof of Work). Повертає кількість спроб."""
    target = "0" * difficulty
    block.nonce = 0
    attempts = 0
    while True:
        attempts += 1
        digest = block.compute_hash()
        if digest.startswith(target):
            block.hash = digest
            return attempts
        block.nonce += 1


def make_timestamp(index: int, fixed: bool) -> str:
    if fixed:
        return f"2026-11-18T12:00:{index:02d}Z"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build_chain(difficulty: int, fixed_time: bool) -> tuple[list[Block], int, float]:
    chain: list[Block] = []
    attempts_total = 0
    started = time.perf_counter()
    for index, data in enumerate(RECORDS):
        prev = chain[-1].hash if chain else ZERO_HASH
        block = Block(index, make_timestamp(index, fixed_time), data, prev)
        attempts_total += mine(block, difficulty)
        chain.append(block)
    return chain, attempts_total, time.perf_counter() - started


def verify_chain(chain: list[Block], difficulty: int) -> list[str]:
    problems = []
    for position, block in enumerate(chain):
        if block.index != position:
            problems.append(f"блок {block.index}: невірний порядковий номер (очікувався {position})")
        if block.hash != block.compute_hash():
            problems.append(f"блок {block.index}: власний хеш не відповідає вмісту (дані змінено)")
        if difficulty and not block.hash.startswith("0" * difficulty):
            problems.append(f"блок {block.index}: хеш не задовольняє складності {difficulty}")
        expected_prev = chain[position - 1].hash if position else ZERO_HASH
        if block.prev_hash != expected_prev:
            problems.append(f"блок {block.index}: prev_hash ≠ хешу блока {block.index - 1} (зв'язок розірвано)")
    return problems


def print_chain(title: str, chain: list[Block]) -> None:
    print(f"\n=== {title} ===")
    print(f"{'№':>2} | {'nonce':>7} | {'prev_hash':<16} | {'hash':<16} | дані")
    print("---+---------+------------------+------------------+" + "-" * 40)
    for block in chain:
        print(f"{block.index:>2} | {block.nonce:>7} | {block.prev_hash[:16]} | {block.hash[:16]} | {block.data}")


def report(title: str, chain: list[Block], difficulty: int) -> None:
    started = time.perf_counter()
    problems = verify_chain(chain, difficulty)
    elapsed = (time.perf_counter() - started) * 1000
    print(f"\n--- Перевірка: {title} ({elapsed:.2f} мс) ---")
    if not problems:
        print("Ланцюг цілий: кожен хеш відповідає вмісту, кожен prev_hash — хешу попереднього блока.")
    for problem in problems:
        print("  ПОРУШЕННЯ: " + problem)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):      # кирилиця в каналі cp1251/cp1252 не валить вивід
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(description="ЛР13–14: модель блокчейну на SHA-256.")
    parser.add_argument("--difficulty", type=int, default=4, help="кількість нулів на початку хешу (0 — без PoW)")
    parser.add_argument("--fixed-time", action="store_true", help="фіксовані мітки часу (відтворюваний вивід)")
    args = parser.parse_args(argv)
    difficulty = max(0, min(args.difficulty, 6))

    chain, attempts, seconds = build_chain(difficulty, args.fixed_time)
    print(f"Побудовано Genesis + {len(chain) - 1} блоків; складність {difficulty}: {attempts} обчислень SHA-256 "
          f"за {seconds:.2f} с (≈ {attempts / max(1, len(chain)):.0f} на блок; очікувано ≈ {16 ** difficulty})")
    print_chain("1. Початковий ланцюг", chain)
    report("початковий ланцюг", chain, difficulty)
    anchor = chain[-1].hash
    print(f"\nГолова ланцюга (якір, збережений поза системою): {anchor}")

    tampered = copy.deepcopy(chain)
    tampered[2].data = tampered[2].data.replace("1.2.2", "9.9.9")
    print_chain("3а. Змінено дані блока 2 без перерахунку хешу", tampered)
    report("після зміни даних блока 2", tampered, difficulty)
    print(f"  Хеш блока 2: збережений {tampered[2].hash[:16]}…, фактичний {tampered[2].compute_hash()[:16]}…")

    rehashed = copy.deepcopy(tampered)
    mine(rehashed[2], difficulty)
    print_chain("3б. Блок 2 перераховано (і перемайнено), наступні — ні", rehashed)
    report("після перерахунку лише блока 2", rehashed, difficulty)

    rebuilt = copy.deepcopy(tampered)
    started = time.perf_counter()
    redo_attempts = 0
    for position in range(2, len(rebuilt)):
        rebuilt[position].prev_hash = rebuilt[position - 1].hash if position else ZERO_HASH
        redo_attempts += mine(rebuilt[position], difficulty)
    redo_seconds = time.perf_counter() - started
    print_chain("4. Блок 2 і всі наступні сформовано повторно", rebuilt)
    report("після повторного формування блоків 2–5", rebuilt, difficulty)
    print(f"\nЦіна переписування історії: {redo_attempts} обчислень SHA-256 за {redo_seconds:.2f} с "
          f"(4 блоки) проти 1 обчислення на блок для перевірки.")
    print(f"Голова після переписування: {rebuilt[-1].hash}")
    print(f"Збігається з якорем?  {'так' if rebuilt[-1].hash == anchor else 'НІ — підміну історії виявлено за якорем'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
