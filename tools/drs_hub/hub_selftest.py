"""drs_hub — самоперевірка сервера й клієнта (версія ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_selftest.py

Піднімає справжній сервер (TLS, власний CA) у тимчасовій теці на випадковому порту 127.0.0.1,
створює тестових клієнтів (лише в тимчасовій базі — у робочу базу нічого не потрапляє) і проганяє
сценарії через справжній HubClient. Жодного стороннього тестового фреймворку (політика §2): перелік
перевірок, таблиця результатів і код завершення 0/1.

    python hub_selftest.py            → таблиця «№ | перевірка | результат | подробиці»
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import ssl
import sys
import tempfile
import threading
import time
import traceback
from typing import Callable

import hub_auth
import hub_config
import hub_log
import hub_routes_core
import hub_server
import hub_tls
from hub_client import ApiError, HubClient, HubClientError
from hub_store import HubStore

SAMPLE_RELEASE = {
    "product": "DynamicReloadSpeed", "version": "1.2.2", "date": "2026-11-17",
    "files": [
        {"name": "DynamicReloadSpeed-1.2.2.zip", "size": 214725,
         "sha256": "125f0ac7ef7341241e8de5cf8ec9f5f0a2740aec6b8e0408fdf2b9a3fb62a2b7"},
        {"name": "DynamicReloadSpeed.asi", "size": 373248,
         "sha256": "345a2868dd3a4b761b746d83d8886e7aa83861fa2eb4d7cf8ce01c9076f2734a"},
    ],
    "tag": "v1.2.2", "commit": "a73bbcd1b50d8695babbb70b4360152a6f9c931f", "channel": "NexusMods",
}

CASES: list[tuple[str, Callable]] = []


def case(title: str):
    def decorator(fn):
        CASES.append((title, fn))
        return fn
    return decorator


class Harness:
    """Тимчасовий сервер + тестові клієнти. Усе зникає після close()."""

    CLIENTS = (("st-maintainer", "maintainer"), ("st-tester", "tester"), ("st-tester2", "tester"),
               ("st-auditor", "auditor"), ("st-lockme", "tester"))

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="drs_hub_selftest_", ignore_cleanup_errors=True)
        self.cfg = hub_config.HubConfig(data_dir=os.path.join(self.tmp.name, "data"), port=0)
        os.makedirs(self.cfg.data_dir)
        hub_log.setup(self.cfg, console=False)
        self.store = HubStore(self.cfg.db_path)
        hub_tls.create_ca_and_server_cert(self.cfg.tls_dir)
        self.httpd, self.app = hub_server.build_server(self.cfg, self.store)
        self.port = self.httpd.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.1},
                                       daemon=True)
        self.thread.start()
        self.secrets: dict[str, str] = {}
        self.tokens: list[str] = []          # усі видані токени — для перевірки журналу
        for client_id, role in self.CLIENTS:
            secret = hub_auth.new_client_secret()
            self.store.add_client(client_id, role, hub_auth.sha256_hex(secret), "selftest")
            self.secrets[client_id] = secret

    def client(self, client_id: str | None = None, secret: str | None = None,
               ca: str | None = None, scope: str | None = None) -> HubClient:
        return HubClient(self.url, ca_file=ca or self.cfg.ca_path, client_id=client_id,
                         client_secret=secret if secret is not None else self.secrets.get(client_id or ""),
                         scope=scope)

    def token_of(self, client: HubClient) -> str:
        client.fetch_token()
        self.tokens.append(client._token)
        return client._token

    def raw(self, method: str, path: str, *, body: bytes | None = None, headers: dict | None = None):
        return self.client().raw(method, path, body=body, headers=headers)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(5)
        closer = getattr(hub_log, "shutdown", None)
        if closer is not None:
            closer()
        logger = logging.getLogger("drs_hub")
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
        self.tmp.cleanup()


def _api_error(fn) -> ApiError | None:
    try:
        fn()
    except ApiError as exc:
        return exc
    return None


# --- TLS і транспорт ------------------------------------------------------------------
@case("TLS: /health через HTTPS, довіра лише до CA сервера")
def t_tls_ok(h):
    status, payload = h.client().call("GET", "/api/v1/health", auth=False)
    return status == 200 and payload.get("status") == "ok", f"HTTP {status}, version {payload.get('version')}"


@case("TLS: клієнт із чужим CA відмовляється від з'єднання (захист від підміни сервера)")
def t_tls_foreign_ca(h):
    other = hub_tls.create_ca_and_server_cert(os.path.join(h.tmp.name, "other_tls"))
    try:
        h.client(ca=other["ca"]).call("GET", "/api/v1/health", auth=False)
    except ssl.SSLCertVerificationError as exc:
        return True, f"SSLCertVerificationError: {exc.verify_message}"
    return False, "з'єднання встановлено з чужим CA"


@case("TLS: відкритий HTTP на порт сервера не обслуговується")
def t_plain_http(h):
    conn = http.client.HTTPConnection("127.0.0.1", h.port, timeout=5)
    try:
        conn.request("GET", "/api/v1/health")
        response = conn.getresponse()
        response.read()
        return False, f"отримано HTTP {response.status} без TLS"
    except (http.client.HTTPException, OSError) as exc:
        return True, type(exc).__name__
    finally:
        conn.close()


@case("Клієнт відмовляється від http:// без --insecure-http і від HTTP на не-loopback")
def t_client_refuses_http(h):
    refused = 0
    for url, insecure in (("http://127.0.0.1:1", False), ("http://192.0.2.10:8080", True)):
        try:
            HubClient(url, insecure_http=insecure)
        except HubClientError:
            refused += 1
    return refused == 2, f"відмов: {refused}/2"


# --- POST /oauth/token ---------------------------------------------------------
@case("Токен: невірний секрет → 401 invalid_client + WWW-Authenticate: Basic")
def t_bad_secret(h):
    exc = _api_error(lambda: h.client("st-tester", secret="dhs_wrong").fetch_token())
    return exc is not None and exc.status == 401 and exc.error == "invalid_client", str(exc)


@case("Токен: неіснуючий клієнт → та сама відповідь (існування не розкривається)")
def t_unknown_client(h):
    a = _api_error(lambda: h.client("st-tester", secret="dhs_wrong").fetch_token())
    b = _api_error(lambda: h.client("st-nobody", secret="dhs_wrong").fetch_token())
    same = a is not None and b is not None and (a.status, a.error, a.description) == (b.status, b.error, b.description)
    return same, f"{a.status if a else '-'} {a.error if a else '-'} = {b.status if b else '-'} {b.error if b else '-'}"


@case("Токен: секрет у тілі форми замість Basic → 400 invalid_request")
def t_secret_in_body(h):
    body = f"grant_type=client_credentials&client_id=st-tester&client_secret={h.secrets['st-tester']}"
    status, _, payload = h.raw("POST", "/oauth/token", body=body.encode("ascii"),
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
    return status == 400 and payload.get("error") == "invalid_request", f"HTTP {status} {payload.get('error')}"


@case("Токен: grant_type=password (ROPC) → 400 unsupported_grant_type")
def t_password_grant(h):
    client = h.client("st-tester")
    status, _, payload = h.raw("POST", "/oauth/token", body=b"grant_type=password&username=a&password=b",
                               headers={"Content-Type": "application/x-www-form-urlencoded",
                                        "Authorization": client._basic_header()})
    return status == 400 and payload.get("error") == "unsupported_grant_type", f"HTTP {status} {payload.get('error')}"


@case("Токен видано: Bearer, строк = token_ttl_s, скоуп = скоупи ролі; відповідь no-store")
def t_token_issued(h):
    client = h.client("st-maintainer")
    status, headers, payload = h.raw(
        "POST", "/oauth/token", body=b"grant_type=client_credentials",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Authorization": client._basic_header()})
    h.tokens.append(payload.get("access_token", ""))
    expected_scope = " ".join(sorted(hub_auth.ROLE_SCOPES["maintainer"]))
    ok = (status == 200 and payload.get("token_type") == "Bearer"
          and payload.get("expires_in") == h.cfg.token_ttl_s and payload.get("scope") == expected_scope
          and headers.get("cache-control") == "no-store"
          and str(payload.get("access_token", "")).startswith(hub_auth.TOKEN_PREFIX))
    return ok, f"HTTP {status}, expires_in {payload.get('expires_in')}, scope «{payload.get('scope')}», " \
               f"Cache-Control {headers.get('cache-control')}"


@case("Сервер зберігає лише SHA-256 токена (у базі самого токена немає)")
def t_token_hashed(h):
    client = h.client("st-auditor")
    token = h.token_of(client)
    with h.store.read() as conn:
        rows = conn.execute("SELECT token_sha256, scope FROM tokens").fetchall()
    values = {row["token_sha256"] for row in rows}
    ok = hub_auth.sha256_hex(token) in values and token not in values and \
        all(token not in str(tuple(row)) for row in rows)
    return ok, f"рядків у tokens: {len(rows)}; шукали відбиток {hub_auth.sha256_hex(token)[:12]}"


@case("Скоуп: звуження до releases:write дає лише його; понад роль → 400 invalid_scope")
def t_scopes(h):
    narrowed = h.client("st-maintainer", scope="releases:write")
    h.token_of(narrowed)
    exc = _api_error(lambda: h.client("st-tester", scope="releases:write").fetch_token())
    ok = narrowed.token_scope == "releases:write" and exc is not None and exc.error == "invalid_scope"
    return ok, f"звужений: «{narrowed.token_scope}»; тестер просить releases:write → {exc.error if exc else 'видано!'}"


# --- Bearer на захищених маршрутах -------------------------------------------------
@case("Без токена → 401 + WWW-Authenticate: Bearer")
def t_no_token(h):
    status, headers, payload = h.raw("GET", "/api/v1/whoami")
    ok = status == 401 and headers.get("www-authenticate", "").startswith("Bearer")
    return ok, f"HTTP {status}, WWW-Authenticate: {headers.get('www-authenticate')}"


@case("Підроблений токен → 401 invalid_token")
def t_fake_token(h):
    status, headers, payload = h.raw("GET", "/api/v1/whoami",
                                     headers={"Authorization": "Bearer dha_" + "A" * 43})
    return status == 401 and payload.get("error") == "invalid_token", f"HTTP {status} {payload.get('error')}"


@case("whoami: суб'єкт і роль сервер бере з токена")
def t_whoami(h):
    status, payload = h.client("st-maintainer").call("GET", "/api/v1/whoami")
    ok = status == 200 and payload.get("client_id") == "st-maintainer" and payload.get("role") == "maintainer"
    return ok, f"HTTP {status}: {payload.get('client_id')} / {payload.get('role')} / {payload.get('scope')}"


@case("Тестер публікує реліз → 403 insufficient_scope (перевірка на сервері)")
def t_tester_publish(h):
    status, payload = h.client("st-tester").call("POST", "/api/v1/releases", SAMPLE_RELEASE)
    return status == 403 and payload.get("error") == "insufficient_scope", f"HTTP {status} {payload.get('error')}"


@case("Супроводжувач публікує реліз → 201; SHA-256 запису відтворюваний")
def t_publish(h):
    status, payload = h.client("st-maintainer").call("POST", "/api/v1/releases", SAMPLE_RELEASE)
    record = hub_routes_core.validate_release(dict(SAMPLE_RELEASE))
    expected = hashlib.sha256(hub_routes_core.canonical_json(record).encode("utf-8")).hexdigest()
    ok = status == 201 and payload.get("record_sha256") == expected
    return ok, f"HTTP {status}, record_sha256 {str(payload.get('record_sha256'))[:16]}…"


@case("Публічний реєстр показує реліз, автора (client_id) не розкриває; автор у базі — з токена")
def t_public_list(h):
    status, payload = h.client().call("GET", "/api/v1/releases", auth=False)
    row = h.store.get_release("1.2.2")
    items = payload.get("releases", []) if isinstance(payload, dict) else []
    ok = (status == 200 and payload.get("count") == 1 and "published_by" not in items[0]
          and row is not None and row["published_by"] == "st-maintainer")
    return ok, f"HTTP {status}, релізів {payload.get('count')}, published_by у базі: {row['published_by'] if row else '-'}"


@case("Повторна версія → 409; чуже поле (published_by) у тілі → 400 unknown_field")
def t_conflict_and_unknown(h):
    client = h.client("st-maintainer")
    status1, payload1 = client.call("POST", "/api/v1/releases", SAMPLE_RELEASE)
    forged = dict(SAMPLE_RELEASE, version="9.9.9", published_by="someone-else")
    status2, payload2 = client.call("POST", "/api/v1/releases", forged)
    ok = status1 == 409 and status2 == 400 and payload2.get("error") == "unknown_field"
    return ok, f"повтор → HTTP {status1}; published_by у тілі → HTTP {status2} {payload2.get('error')}"


@case("Відкликаний токен (RFC 7009) → 401 invalid_token")
def t_revoke(h):
    client = h.client("st-tester")
    token = h.token_of(client)
    client.revoke()
    status, _, payload = h.raw("GET", "/api/v1/whoami", headers={"Authorization": "Bearer " + token})
    return status == 401 and payload.get("error") == "invalid_token", f"HTTP {status} {payload.get('error')}"


@case("Прострочений токен → 401 invalid_token")
def t_expired(h):
    client = h.client("st-tester2")
    token = h.token_of(client)
    with h.store.write() as conn:      # імітуємо закінчення строку, не чекаючи 10 хв
        conn.execute("UPDATE tokens SET expires_at = ? WHERE token_sha256 = ?",
                     (time.time() - 1, hub_auth.sha256_hex(token)))
    status, _, payload = h.raw("GET", "/api/v1/whoami", headers={"Authorization": "Bearer " + token})
    return status == 401 and payload.get("error") == "invalid_token", f"HTTP {status} {payload.get('error')}"


@case("Вимкнений клієнт: його токен недійсний, новий не видається")
def t_disabled(h):
    client = h.client("st-auditor")
    token = h.token_of(client)
    h.store.set_client_enabled("st-auditor", False)
    try:
        status, _, payload = h.raw("GET", "/api/v1/whoami", headers={"Authorization": "Bearer " + token})
        exc = _api_error(lambda: h.client("st-auditor").fetch_token())
    finally:
        h.store.set_client_enabled("st-auditor", True)
    ok = status == 401 and exc is not None and exc.error == "invalid_client"
    return ok, f"старий токен → HTTP {status}; новий токен → {exc.error if exc else 'видано!'}"


@case("Блокування перебору: 5 невдач → 429 і Retry-After навіть із правильним секретом")
def t_lockout(h):
    for _ in range(h.cfg.lockout_threshold):
        _api_error(lambda: h.client("st-lockme", secret="dhs_wrong").fetch_token())
    good = h.client("st-lockme")
    status, headers, payload = h.raw("POST", "/oauth/token", body=b"grant_type=client_credentials",
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Authorization": good._basic_header()})
    row = h.store.get_failure("client:st-lockme")
    ok = (status == 429 and payload.get("error") == "too_many_attempts" and headers.get("retry-after")
          and row is not None and row["locked_until"] > time.time())
    return bool(ok), f"правильний секрет після 5 невдач → HTTP {status} {payload.get('error')}, " \
                     f"Retry-After {headers.get('retry-after')} с"


# --- межі й формат помилок ----------------------------------------------------------
@case("Тіло понад межу маршруту → 413")
def t_body_limit(h):
    body = b'{"x":"' + b"a" * 20000 + b'"}'
    status, _, payload = h.raw("POST", "/api/v1/releases", body=body,
                               headers={"Content-Type": "application/json"})
    return status == 413, f"HTTP {status} {payload.get('error') if isinstance(payload, dict) else ''}"


@case("Невідомий маршрут → 404; невірний метод → 405 з Allow")
def t_404_405(h):
    s1, _, _ = h.raw("GET", "/api/v1/nope")
    s2, headers, _ = h.raw("DELETE", "/api/v1/releases")
    return s1 == 404 and s2 == 405 and "GET" in headers.get("allow", ""), \
        f"GET /nope → {s1}; DELETE /releases → {s2}, Allow: {headers.get('allow')}"


@case("Помилка без внутрішніх подробиць (немає Traceback і шляхів .py); є request_id і X-Request-ID")
def t_error_format(h):
    client = h.client("st-maintainer")
    status, headers, payload = h.raw("POST", "/api/v1/releases", body=b"{",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": client.bearer_header()})
    text = json.dumps(payload, ensure_ascii=False)
    ok = (status == 400 and payload.get("error") == "invalid_json" and "Traceback" not in text
          and ".py" not in text and payload.get("request_id") == headers.get("x-request-id"))
    return ok, f"HTTP {status} {payload.get('error')}, request_id {payload.get('request_id')}"


# --- кінець переліку перевірок (нові перевірки додавати вище) ---


def _log_has_no_secrets(h) -> tuple[bool, str]:
    """Остання перевірка: жоден секрет клієнта й жоден виданий токен не потрапив у журнали."""
    leaked = []
    for name in os.listdir(h.cfg.log_dir):
        with open(os.path.join(h.cfg.log_dir, name), "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        for value in list(h.secrets.values()) + [t for t in h.tokens if t]:
            if value and value in text:
                leaked.append(f"{name}: {value[:8]}…")
    return not leaked, "секретів і токенів у журналі немає" if not leaked else "; ".join(leaked[:3])


def main() -> int:
    hub_config.safe_console()
    print(f"drs_hub {hub_config.HUB_VERSION} — самоперевірка (Python {sys.version.split()[0]}, "
          f"ssl {ssl.OPENSSL_VERSION})")
    harness = Harness()
    results: list[tuple[str, bool, str]] = []
    try:
        for title, fn in CASES:
            try:
                ok, detail = fn(harness)
            except Exception as exc:  # noqa: BLE001 — збій однієї перевірки не зупиняє решту
                ok, detail = False, f"{type(exc).__name__}: {exc} | {traceback.format_exc(limit=2).splitlines()[-1]}"
            results.append((title, bool(ok), detail))
        ok, detail = _log_has_no_secrets(harness)
        results.append(("Журнали сервера не містять секретів клієнтів і токенів", ok, detail))
    finally:
        harness.close()
    width = max(len(title) for title, _, _ in results)
    for index, (title, ok, detail) in enumerate(results, 1):
        print(f"{index:>2}. {'OK  ' if ok else 'FAIL'} {title:<{width}}  {detail}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"drs_hub self-test: {passed}/{len(results)} OK" + ("" if passed == len(results) else " — Є ЗБОЇ"))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
