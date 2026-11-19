"""drs_hub — службовий HTTPS-сервер супроводжувача DRS (версія ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_server.py

Що це: невеликий REST-сервер (лише стандартна бібліотека + `cryptography` для сертифікатів) для
службових даних супроводу мода: реєстр опублікованих релізів (публічне читання, запис — лише
супроводжувач) і, з ЛР13–14, прийом зашифрованих звітів тестерів. Плагін DynamicReloadSpeed.asi і
гра з сервером НЕ взаємодіють (NFR-12 для `asi` незмінна) — це інструмент супроводжувача, як
tools/drs_release.

Межа довіри (docs/architecture/client_server.md): клієнт недовірений. Сервер сам встановлює суб'єкта
(токен → клієнт → роль) і сам ухвалює кожне рішення про доступ у точці виконання маршруту; дані про
роль чи ідентифікатор із тіла запиту не беруться до уваги.

Ядро: маршрутизатор, читання тіла з межею розміру, автентифікація Bearer перед обробником, єдиний
формат помилок без внутрішніх деталей (урок Libraxis: детальні помилки SQL у відповіді допомогли
нападнику), заголовки безпеки, X-Request-ID, журнал доступу. TLS обов'язковий; HTTP без TLS — лише
на loopback і лише прапорцем --insecure-http (налагодження).

Маршрути живуть у модулях-розширеннях зі списку FEATURES: кожен має register(app) і, за потреби,
SCHEMA (таблиці SQLite). Розширення спілкуються подіями app.emit(...): обробник отримує conn — відкриту
транзакцію — і не відкриває власних (атомарність запису й пов'язаних дій).

Запуск: python hub_server.py [--data-dir D] [--host H] [--port P] [--insecure-http]
(спершу один раз: python hub_admin.py init).
"""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import json
import os
import re
import socketserver
import ssl
import sys
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlsplit

import hub_auth
import hub_config
import hub_log
from hub_config import DataDirLock, HubConfig, HubConfigError
from hub_store import HubStore

FEATURES: tuple[str, ...] = ("hub_routes_core", "hub_routes_ops", "hub_routes_reports", "hub_routes_ledger")

_DRAIN_LIMIT = 8 * 1024 * 1024     # завелике тіло дочитується (до цієї межі), щоб клієнт отримав 413


class HubError(Exception):
    """Очікувана відмова обробника: статус + код помилки + опис для клієнта (без внутрішніх деталей)."""

    def __init__(self, status: int, error: str, description: str,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(description)
        self.status = status
        self.error = error
        self.description = description
        self.headers = headers or {}


@dataclass
class Request:
    method: str
    path: str
    query: dict
    headers: object
    body: bytes
    client_ip: str
    request_id: str
    params: dict = field(default_factory=dict)
    principal: hub_auth.Principal | None = None
    log: dict = field(default_factory=dict)       # поля, які обробник додає до рядка журналу доступу

    def content_type(self) -> str:
        return (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()

    def json(self) -> dict:
        if self.content_type() != "application/json":
            raise HubError(415, "unsupported_media_type", "Очікувався Content-Type: application/json.")
        try:
            data = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HubError(400, "invalid_json", "Тіло запиту — не коректний JSON.") from None
        if not isinstance(data, dict):
            raise HubError(400, "invalid_json", "Очікувався об'єкт JSON.")
        return data

    def form(self) -> dict[str, str]:
        if self.content_type() != "application/x-www-form-urlencoded":
            raise HubError(400, "invalid_request",
                           "Очікувався Content-Type: application/x-www-form-urlencoded.")
        try:
            pairs = parse_qs(self.body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
        except UnicodeDecodeError:
            raise HubError(400, "invalid_request", "Тіло форми — не UTF-8.") from None
        if any(len(values) > 1 for values in pairs.values()):
            # RFC 6749 §3.1: параметр не може повторюватися
            raise HubError(400, "invalid_request", "Параметр форми повторюється.")
        return {key: values[0] for key, values in pairs.items()}


@dataclass
class Response:
    status: int
    payload: dict | list | None = None
    headers: dict = field(default_factory=dict)


@dataclass
class Route:
    method: str
    pattern: re.Pattern
    handler: Callable
    auth: str                 # "none" | "token" | "scope"
    scope: str | None
    max_body: int | None
    name: str


class HubApp:
    """Стан застосунку: налаштування, сховище, маршрути, підписки на події."""

    def __init__(self, cfg: HubConfig, store: HubStore, features: tuple[str, ...] = FEATURES) -> None:
        self.cfg = cfg
        self.store = store
        self.version = hub_config.HUB_VERSION
        self.started = time.time()
        self.features = features
        self.routes: list[Route] = []
        self._subscribers: dict[str, list[Callable]] = {}
        for name in features:
            importlib.import_module(name).register(self)

    def route(self, method: str, path_regex: str, handler: Callable, *, auth: str = "none",
              scope: str | None = None, max_body: int | None = None) -> None:
        if scope:
            auth = "scope"
        if auth not in ("none", "token", "scope"):
            raise ValueError(f"невідомий режим доступу {auth!r}")
        self.routes.append(Route(method, re.compile("^" + path_regex + "$"), handler, auth, scope,
                                 max_body, handler.__name__))

    def subscribe(self, event_name: str, handler: Callable) -> None:
        self._subscribers.setdefault(event_name, []).append(handler)

    def emit(self, event_name: str, **payload) -> None:
        """Синхронно викликати підписників. Виняток підписника скасовує транзакцію ініціатора."""
        for handler in self._subscribers.get(event_name, []):
            handler(self, **payload)

    def match(self, method: str, path: str) -> tuple[Route | None, dict, list[str]]:
        allowed: list[str] = []
        for route in self.routes:
            found = route.pattern.match(path)
            if found:
                if route.method == method:
                    return route, found.groupdict(), []
                allowed.append(route.method)
        return None, {}, allowed


def collect_schemas(features: tuple[str, ...] = FEATURES) -> tuple[str, ...]:
    """SCHEMA усіх розширень — для hub_admin.py init і старту сервера."""
    schemas = []
    for name in features:
        module = importlib.import_module(name)
        sql = getattr(module, "SCHEMA", "")
        if sql:
            schemas.append(sql)
    return tuple(schemas)


class HubHandler(BaseHTTPRequestHandler):
    server_version = "drs-hub"
    sys_version = ""                 # не розкривати версію Python у заголовку Server
    protocol_version = "HTTP/1.0"    # одне з'єднання — один запит: простіше й без зависань keep-alive

    def setup(self) -> None:
        self.timeout = self.server.app.cfg.request_timeout_s
        super().setup()

    def log_message(self, format, *args) -> None:  # noqa: A002 — сигнатура http.server
        """Стандартний вивід http.server у stderr вимкнено: журнал веде hub_log."""

    def send_error(self, code, message=None, explain=None) -> None:
        """Помилки рівня протоколу (кривий рядок запиту, 501 для невідомого методу) — теж JSON."""
        rid = getattr(self, "_rid", None) or hub_log.new_request_id()
        short = self.responses.get(code, ("Error", ""))[0]
        body = json.dumps({"error": f"http_{int(code)}", "error_description": message or short,
                           "request_id": rid}, ensure_ascii=False).encode("utf-8")
        self.close_connection = True
        self.send_response(code, short)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Request-ID", rid)
        self.end_headers()
        if getattr(self, "command", None) != "HEAD":
            self.wfile.write(body)
        hub_log.event("warning", "http.protocol_error", request_id=rid, ip=self.client_address[0],
                      status=int(code), detail=message)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    # --- обробка -------------------------------------------------------------
    def _read_body(self, route: Route, cfg: HubConfig) -> bytes:
        raw_length = self.headers.get("Content-Length")
        if self.command not in ("POST", "PUT", "PATCH"):
            if raw_length not in (None, "0"):
                raise HubError(400, "unexpected_body", "Цей метод не приймає тіла запиту.")
            return b""
        if self.headers.get("Transfer-Encoding"):
            raise HubError(411, "length_required", "Потрібен Content-Length (chunked не підтримується).")
        if raw_length is None:
            raise HubError(411, "length_required", "Потрібен заголовок Content-Length.")
        try:
            length = int(raw_length)
        except ValueError:
            raise HubError(400, "bad_content_length", "Некоректний Content-Length.") from None
        if length < 0:
            raise HubError(400, "bad_content_length", "Некоректний Content-Length.")
        limit = route.max_body or cfg.max_body_bytes
        if length > limit:
            if length <= _DRAIN_LIMIT:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
            raise HubError(413, "payload_too_large", f"Тіло запиту більше за {limit} Б.")
        data = self.rfile.read(length)
        if len(data) != length:
            raise HubError(400, "incomplete_body", "Тіло запиту коротше за Content-Length.")
        return data

    def _dispatch(self) -> None:
        app: HubApp = self.server.app
        started = time.perf_counter()
        rid = hub_log.new_request_id()
        self._rid = rid
        ip = self.client_address[0]
        method = self.command
        path = self.path[:200]
        route_name = "-"
        req: Request | None = None
        try:
            if len(self.path) > 2048:
                raise HubError(414, "uri_too_long", "Задовгий URI.")
            parts = urlsplit(self.path)
            path = parts.path or "/"
            query = parse_qs(parts.query, keep_blank_values=True) if parts.query else {}
            route, params, allowed = app.match(method, path)
            if route is None:
                if allowed:
                    raise HubError(405, "method_not_allowed", "Метод не дозволено для цього маршруту.",
                                   {"Allow": ", ".join(sorted(set(allowed)))})
                raise HubError(404, "not_found", "Маршрут не існує.")
            route_name = route.name
            body = self._read_body(route, app.cfg)
            req = Request(method, path, query, self.headers, body, ip, rid, params)
            if route.auth in ("token", "scope"):
                req.principal = hub_auth.authenticate_bearer(app.store, self.headers.get("Authorization"))
                if route.auth == "scope":
                    hub_auth.require_scope(req.principal, route.scope)
            response = route.handler(app, req)
        except hub_auth.AuthError as exc:
            response = Response(exc.status, {"error": exc.error, "error_description": exc.description},
                                dict(exc.headers))
            principal = req.principal if req is not None else None
            info = dict(getattr(exc, "info", None) or {})
            hub_log.event("warning", "auth.denied", request_id=rid, ip=ip, route=route_name,
                          status=exc.status, error=exc.error,
                          client_id=principal.client_id if principal else None,
                          token_fp=principal.token_fp if principal else None, **info)
        except HubError as exc:
            response = Response(exc.status, {"error": exc.error, "error_description": exc.description},
                                dict(exc.headers))
        except Exception as exc:  # noqa: BLE001 — будь-яка непередбачена помилка: 500 без подробиць
            response = Response(500, {"error": "server_error",
                                      "error_description": "Внутрішня помилка сервера."})
            hub_log.event("error", "http.unhandled", request_id=rid, ip=ip, route=route_name,
                          exc_type=type(exc).__name__, detail=str(exc))
        status, size = self._send(response, rid)
        principal = req.principal if req is not None else None
        extra = req.log if req is not None else {}
        hub_log.access(request_id=rid, ip=ip, method=method, path=path, route=route_name,
                       status=status, bytes=size, ms=round((time.perf_counter() - started) * 1000, 1),
                       client_id=principal.client_id if principal else extra.get("client_id"),
                       token_fp=principal.token_fp if principal else None,
                       ua=(self.headers.get("User-Agent") or "")[:80])

    def _send(self, response: Response, rid: str) -> tuple[int, int]:
        payload = response.payload
        if response.status >= 400 and isinstance(payload, dict):
            payload.setdefault("request_id", rid)
        body = b"" if payload is None else json.dumps(payload, ensure_ascii=False,
                                                       separators=(",", ":")).encode("utf-8")
        self.send_response(response.status)
        if body:
            self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")      # RFC 6749 §5.1: відповідь із токеном не кешується
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Request-ID", rid)
        if self.server.tls_enabled:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)
        return response.status, len(body)


class HubHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False      # на Windows SO_REUSEADDR дозволив би іншому процесу зайняти порт

    def __init__(self, address: tuple[str, int], app: HubApp, ssl_context: ssl.SSLContext | None) -> None:
        self.app = app
        self.ssl_context = ssl_context
        self.tls_enabled = ssl_context is not None
        super().__init__(address, HubHandler)

    def server_bind(self) -> None:
        """Без socket.getfqdn() з HTTPServer.server_bind: зворотний DNS-запит при старті не потрібен."""
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def finish_request(self, request, client_address) -> None:
        """Рукостискання TLS — у робочому потоці запиту, а не в потоці прийому з'єднань."""
        if self.ssl_context is None:
            HubHandler(request, client_address, self)
            return
        request.settimeout(self.app.cfg.request_timeout_s)
        try:
            tls_socket = self.ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            hub_log.event("warning", "tls.handshake_failed", ip=client_address[0], detail=str(exc)[:160])
            return
        try:
            HubHandler(tls_socket, client_address, self)
        finally:
            try:
                tls_socket.close()
            except OSError:
                pass

    def handle_error(self, request, client_address) -> None:
        hub_log.event("error", "http.connection_error", ip=client_address[0],
                      detail=repr(sys.exc_info()[1])[:200])


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def make_ssl_context(cfg: HubConfig) -> ssl.SSLContext:
    for path in (cfg.cert_path, cfg.key_path):
        if not os.path.exists(path):
            raise HubConfigError(f"Немає {path} — спершу: python hub_admin.py init")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cfg.cert_path, cfg.key_path)
    return context


def build_server(cfg: HubConfig, store: HubStore | None = None,
                 features: tuple[str, ...] = FEATURES) -> tuple[HubHTTPServer, HubApp]:
    store = store or HubStore(cfg.db_path)
    store.init_db(collect_schemas(features))
    app = HubApp(cfg, store, features)
    ssl_context = None
    if cfg.insecure_http:
        if not _is_loopback(cfg.host):
            raise HubConfigError("HTTP без TLS дозволено лише на loopback-адресі (127.0.0.1, localhost).")
    else:
        ssl_context = make_ssl_context(cfg)
    return HubHTTPServer((cfg.host, cfg.port), app, ssl_context), app


def main(argv: list[str] | None = None) -> int:
    hub_config.safe_console()
    parser = argparse.ArgumentParser(prog="hub_server",
                                     description="DRS Hub — службовий HTTPS-сервер супроводжувача.")
    parser.add_argument("--data-dir", default=None, help="тека даних (типово %%USERPROFILE%%\\.drs_hub)")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--insecure-http", action="store_true",
                        help="HTTP без TLS — лише налагодження на 127.0.0.1")
    args = parser.parse_args(argv)
    try:
        cfg = hub_config.load_config(args.data_dir)
        if args.host:
            cfg.host = args.host
        if args.port is not None:
            cfg.port = args.port
        if args.insecure_http:
            cfg.insecure_http = True
        cfg.validate()
        if hub_config.path_inside_git_worktree(cfg.data_dir):
            raise HubConfigError(f"Тека даних {cfg.data_dir} усередині робочого дерева git — "
                                 "перенесіть її (змінна DRS_HUB_DATA).")
        if not os.path.exists(cfg.db_path):
            raise HubConfigError("Бази немає — спершу: python hub_admin.py init")
    except (HubConfigError, ValueError, OSError) as exc:
        print(f"Сервер не запущено: {exc}")
        return 2
    lock = DataDirLock(cfg.lock_path)
    if not lock.acquire():
        print("Сервер не запущено: тека даних зайнята (сервер уже працює або йде відновлення з копії).")
        return 2
    hub_log.setup(cfg)
    try:
        httpd, app = build_server(cfg)
    except (HubConfigError, OSError, ssl.SSLError) as exc:
        hub_log.event("error", "server.start_failed", detail=str(exc))
        lock.release()
        return 2
    scheme = "http" if cfg.insecure_http else "https"
    host, port = httpd.server_address[:2]
    if cfg.insecure_http:
        hub_log.event("warning", "server.insecure_http", detail="TLS вимкнено прапорцем --insecure-http")
    hub_log.event("info", "server.started", version=app.version, url=f"{scheme}://{host}:{port}",
                  tls=not cfg.insecure_http, features=",".join(app.features), token_ttl_s=cfg.token_ttl_s)
    print(f"DRS Hub {app.version} слухає {scheme}://{host}:{port}  (Ctrl+C — зупинка)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        hub_log.event("info", "server.stopped", version=app.version)
        lock.release()
    return 0


if __name__ == "__main__":
    # Розширення імпортують hub_server за іменем (HubError, Response). Запуск файла як __main__ створив
    # би другу копію модуля з іншими класами, і їхні винятки ядро не впізнало б. Тому main() виконується
    # з модуля, імпортованого під власним іменем.
    import hub_server
    sys.exit(hub_server.main())
