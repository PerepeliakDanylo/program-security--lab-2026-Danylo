"""drs_hub — сховище сервера на SQLite (версія ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_store.py

Один файл бази drs_hub.db у теці даних (поза репозиторієм). SQLite — зі стандартної бібліотеки:
атомарні транзакції, журнал WAL і вбудоване онлайн-копіювання (знадобиться для резервних копій).

Що зберігається і чого НЕ зберігається:
  * clients  — ідентифікатор, роль, SHA-256 секрету клієнта (не сам секрет), стан, примітка;
  * tokens   — SHA-256 токена доступу (не сам токен), власник, скоуп, строк дії, ознака відкликання.
               Викрадена копія бази не дає жодного робочого токена (урок Libraxis: таблиця sessions
               з відкритими токенами);
  * auth_failures — лічильники невдалих автентифікацій для блокувань (за клієнтом і за адресою);
  * releases — записи про опубліковані релізи (канонічний JSON + його SHA-256 + хто опублікував).
Модулі-розширення додають власні таблиці через атрибут SCHEMA (CREATE TABLE IF NOT EXISTS).

Записи серіалізуються одним замком процесу + BEGIN IMMEDIATE: сервер багатопотоковий, а SQLite
допускає одного записувача.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

SCHEMA_VERSION = 1

CORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id     TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    secret_sha256 TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    note          TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tokens (
    token_sha256  TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    scope         TEXT NOT NULL,
    issued_at     REAL NOT NULL,
    expires_at    REAL NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_by_client ON tokens(client_id);
CREATE TABLE IF NOT EXISTS auth_failures (
    key           TEXT PRIMARY KEY,
    failures      INTEGER NOT NULL DEFAULT 0,
    window_start  REAL NOT NULL DEFAULT 0,
    locked_until  REAL NOT NULL DEFAULT 0,
    lock_level    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS releases (
    version       TEXT PRIMARY KEY,
    record_json   TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    published_by  TEXT NOT NULL,
    published_at  TEXT NOT NULL
);
"""


def utc_now_iso() -> str:
    """Час UTC в ISO 8601 до секунди з «Z» — одна часова основа для бази, журналів і відповідей."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class HubStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._write_lock = threading.Lock()

    # --- з'єднання й транзакції ------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                conn.close()

    def init_db(self, extra_schemas: tuple[str, ...] = ()) -> None:
        """Створити файл бази (якщо немає), увімкнути WAL і застосувати схеми ядра й розширень."""
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.executescript(CORE_SCHEMA)
                for sql in extra_schemas:
                    conn.executescript(sql)
                if conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
                    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            finally:
                conn.close()

    def integrity_check(self) -> str:
        with self.read() as conn:
            return str(conn.execute("PRAGMA integrity_check").fetchone()[0])

    # --- клієнти -------------------------------------------------------------------
    def add_client(self, client_id: str, role: str, secret_sha256: str, note: str = "") -> None:
        with self.write() as conn:
            conn.execute("INSERT INTO clients (client_id, role, secret_sha256, enabled, created_at, note) "
                         "VALUES (?, ?, ?, 1, ?, ?)",
                         (client_id, role, secret_sha256, utc_now_iso(), note))

    def get_client(self, client_id: str) -> sqlite3.Row | None:
        with self.read() as conn:
            return conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()

    def list_clients(self) -> list[sqlite3.Row]:
        with self.read() as conn:
            return conn.execute("SELECT client_id, role, enabled, created_at, note FROM clients "
                                "ORDER BY client_id").fetchall()

    def set_client_enabled(self, client_id: str, enabled: bool) -> bool:
        with self.write() as conn:
            cur = conn.execute("UPDATE clients SET enabled = ? WHERE client_id = ?",
                               (1 if enabled else 0, client_id))
            return cur.rowcount == 1

    def set_client_secret(self, client_id: str, secret_sha256: str) -> bool:
        with self.write() as conn:
            cur = conn.execute("UPDATE clients SET secret_sha256 = ? WHERE client_id = ?",
                               (secret_sha256, client_id))
            return cur.rowcount == 1

    # --- токени ----------------------------------------------------------------
    def insert_token(self, token_sha256: str, client_id: str, scope: str,
                     issued_at: float, expires_at: float) -> None:
        with self.write() as conn:
            conn.execute("INSERT INTO tokens (token_sha256, client_id, scope, issued_at, expires_at, revoked) "
                         "VALUES (?, ?, ?, ?, ?, 0)", (token_sha256, client_id, scope, issued_at, expires_at))
            # Прострочені понад годину токени більше не потрібні навіть для розслідування.
            conn.execute("DELETE FROM tokens WHERE expires_at < ?", (issued_at - 3600,))

    def get_token(self, token_sha256: str) -> sqlite3.Row | None:
        with self.read() as conn:
            return conn.execute(
                "SELECT t.*, c.role AS role, c.enabled AS client_enabled FROM tokens t "
                "JOIN clients c ON c.client_id = t.client_id WHERE t.token_sha256 = ?",
                (token_sha256,)).fetchone()

    def revoke_token(self, token_sha256: str, client_id: str) -> bool:
        with self.write() as conn:
            cur = conn.execute("UPDATE tokens SET revoked = 1 WHERE token_sha256 = ? AND client_id = ?",
                               (token_sha256, client_id))
            return cur.rowcount == 1

    def revoke_client_tokens(self, client_id: str) -> int:
        with self.write() as conn:
            cur = conn.execute("UPDATE tokens SET revoked = 1 WHERE client_id = ? AND revoked = 0",
                               (client_id,))
            return cur.rowcount

    def count_active_tokens(self, now: float) -> int:
        with self.read() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND expires_at > ?",
                                    (now,)).fetchone()[0])

    # --- лічильники невдач --------------------------------------------------------
    def get_failure(self, key: str) -> sqlite3.Row | None:
        with self.read() as conn:
            return conn.execute("SELECT * FROM auth_failures WHERE key = ?", (key,)).fetchone()

    def put_failure(self, key: str, failures: int, window_start: float,
                    locked_until: float, lock_level: int) -> None:
        with self.write() as conn:
            conn.execute("INSERT INTO auth_failures (key, failures, window_start, locked_until, lock_level) "
                         "VALUES (?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET failures = excluded.failures, "
                         "window_start = excluded.window_start, locked_until = excluded.locked_until, "
                         "lock_level = excluded.lock_level",
                         (key, failures, window_start, locked_until, lock_level))

    def clear_failure(self, key: str) -> None:
        with self.write() as conn:
            conn.execute("DELETE FROM auth_failures WHERE key = ?", (key,))

    # --- релізи ----------------------------------------------------------------------
    def insert_release(self, version: str, record_json: str, record_sha256: str,
                       published_by: str, published_at: str,
                       conn: sqlite3.Connection | None = None) -> None:
        """Повторна версія → sqlite3.IntegrityError (обробник перетворює на 409).

        conn — відкрита транзакція (store.write()): тоді запис і пов'язані з ним дії розширень
        (напр. блок журналу) фіксуються атомарно; без conn — власна транзакція.
        """
        sql = ("INSERT INTO releases (version, record_json, record_sha256, published_by, published_at) "
               "VALUES (?, ?, ?, ?, ?)")
        params = (version, record_json, record_sha256, published_by, published_at)
        if conn is not None:
            conn.execute(sql, params)
            return
        with self.write() as own:
            own.execute(sql, params)

    def get_release(self, version: str) -> sqlite3.Row | None:
        with self.read() as conn:
            return conn.execute("SELECT * FROM releases WHERE version = ?", (version,)).fetchone()

    def list_releases(self) -> list[sqlite3.Row]:
        with self.read() as conn:
            return conn.execute("SELECT * FROM releases ORDER BY published_at, version").fetchall()
