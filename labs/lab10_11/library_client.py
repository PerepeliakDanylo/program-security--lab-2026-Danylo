"""ЛР10–11, п. 8 — власний клієнт навчального сервера бібліотеки (Додаток Б методички).

Варіант 14: client_id = azalea-14 (не секрет). client_secret у код НЕ вписано: він береться зі
змінної середовища LAB10_CLIENT_SECRET або запитується getpass — секрет, вшитий у програму, яка
виконується в середовищі користувача, не можна вважати захищеним (теорія ЛР10–11).

Що робить клієнт:
  1. GET /  — публічний опис сервісу й маршрутів;
  2. POST /auth/token — автентифікація client_id + client_secret, отримання токена доступу;
  3. зберігає токен ЛИШЕ в пам'яті разом зі строком дії й автоматично додає його до запитів як
     «Authorization: Bearer …»; за 30 с до закінчення строку або на 401 — одна повторна автентифікація;
  4. GET /whoami, /api/books, /api/books/{id}, /api/loans, /api/summary — показує дані поточного
     читача, список книг, активні позики й зведення (таблицями);
  5. з --negative — показує відмови сервера: без токена (401), з підробленим токеном (401),
     неіснуюча книга (404), GET на /auth/token (405).
Секрет і сам токен на екран не виводяться — лише відбиток токена (12 hex SHA-256).

    $env:LAB10_CLIENT_SECRET = "<секрет варіанта>"
    python library_client.py [--url http://127.0.0.1:8080] [--client-id azalea-14] [--book ID] [--negative] [--raw]

Лише стандартна бібліотека Python 3. HTTP без TLS дозволено тільки для loopback-адреси (навчальний
сервер слухає 127.0.0.1): відправляти секрет відкритим каналом на віддалений хост клієнт відмовиться.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import http.client
import ipaddress
import json
import os
import sys
import time
from urllib.parse import urlencode, urlsplit

DEFAULT_CLIENT_ID = "azalea-14"
REFRESH_MARGIN_S = 30


class ClientError(Exception):
    pass


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


class LibraryClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str, timeout: float = 10.0) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ClientError("Адреса сервера має вигляд http://127.0.0.1:8080")
        if parts.scheme == "http" and not _is_loopback(parts.hostname):
            raise ClientError("HTTP без TLS дозволено лише для 127.0.0.1/localhost: інакше секрет піде відкритим каналом.")
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.token: str | None = None
        self.token_type = "Bearer"
        self.deadline = 0.0
        self.token_info: dict = {}

    def _request(self, method: str, path: str, body: bytes | None = None,
                 headers: dict | None = None) -> tuple[int, dict, object]:
        cls = http.client.HTTPSConnection if self.scheme == "https" else http.client.HTTPConnection
        conn = cls(self.host, self.port, timeout=self.timeout)
        try:
            conn.request(method, path, body=body,
                         headers={"Accept": "application/json", "User-Agent": "lab10-client/1.0",
                                  **(headers or {})})
            response = conn.getresponse()
            data = response.read()
            status = response.status
            response_headers = {k.lower(): v for k, v in response.getheaders()}
        finally:
            conn.close()
        text = data.decode("utf-8", errors="replace")
        try:
            payload = json.loads(text) if text else None
        except json.JSONDecodeError:
            payload = text
        return status, response_headers, payload

    # --- автентифікація ----------------------------------------------------------------
    def authenticate(self) -> dict:
        credentials = {"client_id": self.client_id, "client_secret": self.client_secret}
        status, _, payload = self._request("POST", "/auth/token", json.dumps(credentials).encode("utf-8"),
                                           {"Content-Type": "application/json"})
        if status in (400, 415):     # запасний формат — application/x-www-form-urlencoded
            status, _, payload = self._request("POST", "/auth/token", urlencode(credentials).encode("ascii"),
                                               {"Content-Type": "application/x-www-form-urlencoded"})
        if status != 200 or not isinstance(payload, dict):
            raise ClientError(f"Автентифікацію відхилено: HTTP {status} {payload}")
        token = payload.get("access_token")
        if not isinstance(token, str):
            token = next((v for k, v in payload.items() if "token" in k.lower() and isinstance(v, str)), None)
        if not token:
            raise ClientError(f"У відповіді немає токена: {sorted(payload)}")
        self.token = token
        self.token_type = str(payload.get("token_type") or "Bearer")
        expires_in = payload.get("expires_in")
        expires_in = int(expires_in) if isinstance(expires_in, (int, float)) else 1800
        self.deadline = time.monotonic() + expires_in
        # Решта полів відповіді (без самого токена) — для показу.
        self.token_info = {k: v for k, v in payload.items() if v != token}
        self.token_info["token_fp"] = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
        return self.token_info

    def _authorization(self) -> str:
        if self.token is None or time.monotonic() > self.deadline - REFRESH_MARGIN_S:
            self.authenticate()
        return f"Bearer {self.token}"

    def get(self, path: str, *, auth: bool = True) -> tuple[int, object]:
        status, payload = 0, None
        for attempt in (1, 2):
            headers = {"Authorization": self._authorization()} if auth else {}
            status, _, payload = self._request("GET", path, headers=headers)
            if auth and status == 401 and attempt == 1:
                self.token = None            # строк минув або токен відкликано — одна повторна автентифікація
                continue
            break
        return status, payload


# --- відображення ---------------------------------------------------------------------
def _cell(value) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 42 else text[:41] + "…"


def print_table(rows: list) -> None:
    if not rows:
        print("    (порожньо)")
        return
    if not all(isinstance(row, dict) for row in rows):
        for row in rows:
            print("    " + _cell(row))
        return
    columns: list[str] = []
    for row in rows:
        for key in row:
            if key not in columns:
                columns.append(key)
    widths = {c: max(len(c), *(len(_cell(row.get(c, ""))) for row in rows)) for c in columns}
    print("    " + " | ".join(c.ljust(widths[c]) for c in columns))
    print("    " + "-+-".join("-" * widths[c] for c in columns))
    for row in rows:
        print("    " + " | ".join(_cell(row.get(c, "")).ljust(widths[c]) for c in columns))


def show(title: str, status: int, payload, raw: bool) -> None:
    print(f"\n=== {title} (HTTP {status}) ===")
    if raw or not isinstance(payload, dict):
        print(json.dumps(payload, ensure_ascii=False, indent=2) if not isinstance(payload, str) else payload)
        return
    for key, value in payload.items():
        if isinstance(value, list):
            print(f"  {key}: {len(value)} запис(ів)")
            print_table(value)
        elif isinstance(value, dict):
            print(f"  {key}:")
            for sub_key, sub_value in value.items():
                print(f"    {sub_key}: {_cell(sub_value)}")
        else:
            print(f"  {key}: {_cell(value)}")


def _first_book_id(payload) -> str | None:
    if isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                for key in ("id", "book_id", "code"):
                    if key in value[0]:
                        return str(value[0][key])
    return None


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):      # кирилиця в каналі cp1251/cp1252 не валить вивід
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(description="Клієнт навчального сервера бібліотеки (ЛР10–11, варіант 14).")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--book", default=None, help="ідентифікатор книги для /api/books/{id}")
    parser.add_argument("--negative", action="store_true", help="показати відмови сервера (401/404/405)")
    parser.add_argument("--raw", action="store_true", help="друкувати JSON як є")
    args = parser.parse_args(argv)

    secret = os.environ.get("LAB10_CLIENT_SECRET") or getpass.getpass(f"client_secret для {args.client_id}: ")
    try:
        client = LibraryClient(args.url, args.client_id, secret)
        status, _, payload = client._request("GET", "/")
        show("Публічний опис сервісу (GET /)", status, payload, args.raw)

        info = client.authenticate()
        show("Автентифікація (POST /auth/token) — токен збережено в пам'яті, показано лише відбиток",
             200, info, args.raw)

        status, payload = client.get("/whoami")
        show("Поточний читач (GET /whoami)", status, payload, args.raw)
        status, books = client.get("/api/books")
        show("Книги (GET /api/books)", status, books, args.raw)
        book_id = args.book or _first_book_id(books)
        if book_id:
            status, payload = client.get(f"/api/books/{book_id}")
            show(f"Книга {book_id} (GET /api/books/{book_id})", status, payload, args.raw)
        status, payload = client.get("/api/loans")
        show("Активні позики (GET /api/loans)", status, payload, args.raw)
        status, payload = client.get("/api/summary")
        show("Зведення (GET /api/summary)", status, payload, args.raw)

        if args.negative:
            status, _, payload = client._request("GET", "/api/books")
            show("Без токена (GET /api/books)", status, payload, True)
            status, _, payload = client._request("GET", "/api/books",
                                                 headers={"Authorization": "Bearer forged-token-123"})
            show("Підроблений токен (GET /api/books)", status, payload, True)
            status, payload = client.get("/api/books/does-not-exist")
            show("Неіснуюча книга (GET /api/books/does-not-exist)", status, payload, True)
            status, _, payload = client._request("GET", "/auth/token")
            show("Невірний метод (GET /auth/token)", status, payload, True)
    except (ClientError, OSError, http.client.HTTPException) as exc:
        print(f"Помилка: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
