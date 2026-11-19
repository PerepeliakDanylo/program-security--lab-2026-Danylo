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


# --- ЛР12: журнал, кореляція, показники, сповіщення, цілісність -----------------------
def _read_jsonl(h, prefix: str) -> list[dict]:
    records = []
    for name in sorted(os.listdir(h.cfg.log_dir)):
        if name.startswith(prefix + "-") and name.endswith(".jsonl") and name[len(prefix) + 1:len(prefix) + 2].isdigit():
            with open(os.path.join(h.cfg.log_dir, name), "r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue          # рядок, який сервер саме дописує
    return records


@case("Журнал (ЛР12): JSON Lines; request_id відповіді є в записі доступу й у події обробника")
def t_log_correlation(h):
    client = h.client("st-maintainer")
    status, headers, payload = h.raw("POST", "/oauth/token", body=b"grant_type=client_credentials",
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Authorization": client._basic_header()})
    h.tokens.append(payload.get("access_token", ""))
    rid = headers.get("x-request-id")
    events: list[str] = []
    for _ in range(20):                       # запис доступу пишеться одразу після відповіді
        events = [r["event"] for r in _read_jsonl(h, "hub") if r.get("request_id") == rid]
        if "http.access" in events and "auth.token_issued" in events:
            break
        time.sleep(0.1)
    sample = next((r for r in _read_jsonl(h, "hub") if r.get("request_id") == rid), {})
    ok = (status == 200 and "http.access" in events and "auth.token_issued" in events
          and str(sample.get("ts", "")).endswith("Z"))
    return ok, f"request_id {rid}: {', '.join(events)}; ts {sample.get('ts')}"


@case("Показники (ЛР12): /api/v1/metrics — тестер 403, аудитор 200 з лічильниками й станом бази")
def t_metrics(h):
    s1, _ = h.client("st-tester").call("GET", "/api/v1/metrics")
    s2, snap = h.client("st-auditor").call("GET", "/api/v1/metrics")
    snap = snap if isinstance(snap, dict) else {}
    ok = (s1 == 403 and s2 == 200 and snap.get("requests_total", 0) > 0 and "p95" in snap.get("latency_ms", {})
          and snap.get("db", {}).get("integrity") == "ok")
    return ok, (f"тестер → {s1}; аудитор → {s2}: запитів {snap.get('requests_total')}, відмови {snap.get('denied')}, "
                f"невдач автентифікації {snap.get('auth_failures_total')}, сповіщень {snap.get('alerts_total')}")


@case("Сповіщення (ЛР12): блокування перебору → alert.raised auth.lockout у безпековому журналі")
def t_alert_lockout(h):
    alerts = [r for r in _read_jsonl(h, "security") if r.get("event") == "alert.raised"]
    hit = [r for r in alerts if r.get("rule") == "auth.lockout" and r.get("subject") == "st-lockme"]
    return bool(hit), f"сповіщень у security-журналі: {len(alerts)}; auth.lockout для st-lockme: {len(hit)}"


@case("Цілісність (ЛР12): ланцюг SHA-256 безпекового журналу цілий; змінений рядок виявляється")
def t_log_chain(h):
    time.sleep(0.3)                          # дати серверу дописати події попередніх запитів
    names = sorted(n for n in os.listdir(h.cfg.log_dir) if n.startswith("security-") and n.endswith(".jsonl")
                   and n[9:10].isdigit())
    path = os.path.join(h.cfg.log_dir, names[-1])
    ok_before, problems_before, count = hub_log.verify_log_file(path)
    with open(path, "r", encoding="utf-8") as fh:
        lines = [line for line in fh if line.strip()]
    index = len(lines) // 2
    forged = json.loads(lines[index])
    forged["ip"] = "203.0.113.66"            # «підчистити» адресу в одному записі
    lines[index] = json.dumps(forged, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    copy = os.path.join(h.tmp.name, "security-forged.jsonl")
    with open(copy, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)
    ok_after, problems_after, _ = hub_log.verify_log_file(copy)
    ok = ok_before and not ok_after and f"рядок {index + 1}" in problems_after[0]
    return ok, (f"{count} записів: {'цілий' if ok_before else problems_before[:1]}; після зміни рядка "
                f"{index + 1}: {problems_after[0] if problems_after else 'НЕ виявлено'}")


@case("Редагування (ЛР12): секрет у полі події й «Bearer …» у тексті замінюються на [REDACTED]")
def t_redaction(h):
    rec = hub_log.build_record(time.time(), "INFO", "test.redact",
                               {"client_secret": "dhs_" + "s" * 30, "detail": "Authorization: Bearer dha_" + "x" * 30,
                                "note": "line1\nline2"})
    line = json.dumps(rec, ensure_ascii=False)
    ok = (rec["client_secret"] == "[REDACTED]" and "dha_" not in rec["detail"] and "dhs_" not in line
          and "\n" not in line)
    return ok, f"client_secret → {rec['client_secret']}; detail → {rec['detail']}"

# --- ЛР13–14: наскрізне шифрування звітів і журнал записів ------------------------------
_MARKER = "DRS-SELFTEST-PLAINTEXT-7f3a"
_PASS = b"selftest-passphrase"


def _report_keys(h):
    import hub_e2ee
    keys = getattr(h, "_report_keys", None)
    if keys is None:
        private = os.path.join(h.tmp.name, "keys", "report_key.pem")
        public = os.path.join(h.tmp.name, "report_recipient.pub")
        hub_e2ee.generate_keypair(private, public, _PASS)
        h.cfg.report_recipient_pub = public          # сервер читає відкритий ключ лише для звірки kid
        keys = (private, public)
        h._report_keys = keys
        h._reports = {}
    return keys


def _submit(h, client_id: str, marker: str = _MARKER, submitter: str | None = None):
    import hub_e2ee
    _private, public = _report_keys(h)
    bundle = hub_e2ee.build_bundle([("DynamicReloadSpeed.log", f"[info ] selftest {marker}\n".encode("utf-8")),
                                    ("mods.txt", b"Munitions.asi\nDynamicReloadSpeed.asi\n")], note="selftest")
    meta = hub_e2ee.new_meta(submitter or client_id, plugin_version="1.2.2", game_build="1.0.1491.50")
    envelope = hub_e2ee.encrypt_report(hub_e2ee.load_public(public), bundle, meta)
    status, payload = h.client(client_id).call("POST", "/api/v1/reports", envelope)
    return status, payload if isinstance(payload, dict) else {}, envelope


@case("E2EE (ЛР13): шифрування й розшифрування; змінений шифротекст, метадані, чужий ключ, невірна фраза → відмова")
def t_e2ee_unit(h):
    import base64
    import hub_e2ee
    private_path, public_path = _report_keys(h)
    private = hub_e2ee.load_private(private_path, _PASS)
    envelope = hub_e2ee.encrypt_report(hub_e2ee.load_public(public_path), b"hello " + _MARKER.encode("utf-8"),
                                       hub_e2ee.new_meta("st-tester"))
    plain, _meta = hub_e2ee.decrypt_report(private, envelope)
    bad_ct = dict(envelope)
    raw = bytearray(base64.b64decode(envelope["ct"]))
    raw[0] ^= 1
    bad_ct["ct"] = base64.b64encode(bytes(raw)).decode("ascii")
    bad_meta = json.loads(json.dumps(envelope))
    bad_meta["meta"]["submitter"] = "st-tester2"
    hub_e2ee.generate_keypair(os.path.join(h.tmp.name, "keys", "other.pem"),
                              os.path.join(h.tmp.name, "other.pub"), b"another-passphrase")
    other = hub_e2ee.load_private(os.path.join(h.tmp.name, "keys", "other.pem"), b"another-passphrase")
    refused = 0
    for key, candidate in ((private, bad_ct), (private, bad_meta), (other, envelope)):
        try:
            hub_e2ee.decrypt_report(key, candidate)
        except hub_e2ee.E2EEError:
            refused += 1
    try:
        hub_e2ee.load_private(private_path, b"wrong-passphrase")
        wrong_pass = False
    except hub_e2ee.E2EEError:
        wrong_pass = True
    ok = plain.endswith(_MARKER.encode("utf-8")) and refused == 3 and wrong_pass
    return ok, f"розшифровано {len(plain)} Б; відмов на підробках {refused}/3; невірна фраза → " \
               f"{'відмова' if wrong_pass else 'ВІДКРИТО'}"


@case("Звіт (ЛР13): тестер подає → 201 + квитанція журналу; у базі сервера немає відкритого тексту")
def t_report_submit(h):
    status, payload, _env = _submit(h, "st-tester")
    h._reports["st-tester"] = payload.get("report_id")
    with h.store.read() as conn:
        dump = "\n".join(str(tuple(row)) for row in conn.execute("SELECT * FROM reports"))
    clean = _MARKER not in dump and "DynamicReloadSpeed.log" not in dump and "Munitions" not in dump
    ok = status == 201 and payload.get("ledger_index") is not None and clean
    return ok, f"HTTP {status}, шифротекст {payload.get('size')} Б, блок {payload.get('ledger_index')}; " \
               f"відкритого тексту в базі: {'немає' if clean else 'Є'}"


@case("Звіт (ЛР13): meta.submitter ≠ client_id токена → 400; чужий ключ отримувача → 400")
def t_report_mismatch(h):
    import hub_e2ee
    s1, p1, _ = _submit(h, "st-tester", submitter="st-tester2")
    envelope = hub_e2ee.encrypt_report(hub_e2ee.load_public(os.path.join(h.tmp.name, "other.pub")),
                                       hub_e2ee.build_bundle([("a.txt", b"a")]), hub_e2ee.new_meta("st-tester"))
    s2, p2 = h.client("st-tester").call("POST", "/api/v1/reports", envelope)
    ok = s1 == 400 and p1.get("error") == "submitter_mismatch" and s2 == 400 and p2.get("error") == "unknown_recipient_key"
    return ok, f"підставний автор → {s1} {p1.get('error')}; чужий kid → {s2} {p2.get('error')}"


@case("Доступ до звітів (ЛР13): свій — 200, чужий — 404; тестер бачить свої, супроводжувач — усі, аудитор — 403")
def t_report_access(h):
    rid = h._reports.get("st-tester")
    s_own, _ = h.client("st-tester").call("GET", f"/api/v1/reports/{rid}")
    s_foreign, _ = h.client("st-tester2").call("GET", f"/api/v1/reports/{rid}")
    _submit(h, "st-tester2", marker="second-report")
    s1, own_list = h.client("st-tester").call("GET", "/api/v1/reports")
    s2, all_list = h.client("st-maintainer").call("GET", "/api/v1/reports")
    s3, _ = h.client("st-auditor").call("GET", "/api/v1/reports")
    ok = (s_own == 200 and s_foreign == 404 and own_list.get("scope") == "own" and own_list.get("count") == 1
          and all_list.get("count") == 2 and s3 == 403
          and all("ct" not in item and "envelope_json" not in item for item in all_list.get("reports", [])))
    return ok, f"свій {s_own}, чужий {s_foreign}; список тестера {own_list.get('count')} ({own_list.get('scope')}), " \
               f"супроводжувача {all_list.get('count')}, аудитор {s3}"


@case("Розшифрування (ЛР13): лише ключем супроводжувача; ім'я «..\\..\\evil.txt» лишається в межах теки")
def t_report_decrypt(h):
    import hub_e2ee
    private_path, _public = _report_keys(h)
    rid = h._reports.get("st-tester")
    status, envelope = h.client("st-maintainer").call("GET", f"/api/v1/reports/{rid}")
    plain, meta = hub_e2ee.decrypt_report(hub_e2ee.load_private(private_path, _PASS), envelope)
    bundle = hub_e2ee.parse_bundle(plain)
    bundle["files"].append({"name": "..\\..\\evil.txt", "text": "path traversal attempt"})
    out = os.path.join(h.tmp.name, "decrypted")
    written = hub_e2ee.write_bundle(bundle, out)
    inside = all(os.path.dirname(os.path.realpath(p)) == os.path.realpath(out) for p in written)
    log_path = next(p for p in written if p.endswith("DynamicReloadSpeed.log"))
    with open(log_path, "r", encoding="utf-8") as fh:
        text = fh.read()
    ok = status == 200 and meta["submitter"] == "st-tester" and _MARKER in text and inside \
        and any(p.endswith("evil.txt") for p in written)
    return ok, f"HTTP {status}; від {meta['submitter']}; файлів {len(written)}, усі в межах теки: {inside}"


@case("Журнал записів (ЛР14): genesis + реліз + звіти, ланцюг цілий; аудитор 200, тестер 403")
def t_ledger_ok(h):
    s_tester, _ = h.client("st-tester").call("GET", "/api/v1/ledger/verify")
    s_auditor, result = h.client("st-auditor").call("GET", "/api/v1/ledger/verify")
    s_list, listing = h.client("st-auditor").call("GET", "/api/v1/ledger")
    kinds = [block["kind"] for block in listing.get("blocks", [])] if isinstance(listing, dict) else []
    ok = (s_tester == 403 and s_auditor == 200 and result.get("ok") is True and result.get("blocks", 0) >= 4
          and kinds[:1] == ["genesis"] and "release" in kinds and kinds.count("report") >= 2)
    return ok, f"тестер {s_tester}; аудитор {s_auditor}: блоків {result.get('blocks')}, ok={result.get('ok')}, " \
               f"види {kinds}"


@case("Підміна (ЛР14): змінений реліз, змінений блок і запис в обхід журналу виявляються; після відновлення — цілий")
def t_ledger_tamper(h):
    import hub_ledger
    findings = []
    with h.store.write() as conn:
        original = conn.execute("SELECT record_json FROM releases WHERE version = '1.2.2'").fetchone()["record_json"]
        conn.execute("UPDATE releases SET record_json = ? WHERE version = '1.2.2'",
                     (original.replace("125f0ac7", "deadbeef", 1),))
    with h.store.read() as conn:
        findings.append(hub_ledger.verify(conn))
    with h.store.write() as conn:
        conn.execute("UPDATE releases SET record_json = ? WHERE version = '1.2.2'", (original,))
        ref = conn.execute("SELECT ref FROM ledger WHERE idx = 1").fetchone()["ref"]
        conn.execute("UPDATE ledger SET ref = ? WHERE idx = 1", (ref + "x",))
    with h.store.read() as conn:
        findings.append(hub_ledger.verify(conn))
    with h.store.write() as conn:
        conn.execute("UPDATE ledger SET ref = ? WHERE idx = 1", (ref,))
        conn.execute("INSERT INTO releases (version, record_json, record_sha256, published_by, published_at) "
                     "VALUES ('9.9.9', '{}', ?, 'intruder', '2026-01-01T00:00:00Z')",
                     (hashlib.sha256(b"{}").hexdigest(),))
    with h.store.read() as conn:
        findings.append(hub_ledger.verify(conn))
    with h.store.write() as conn:
        conn.execute("DELETE FROM releases WHERE version = '9.9.9'")
    with h.store.read() as conn:
        final = hub_ledger.verify(conn)
    ok = all(not f["ok"] for f in findings) and final["ok"]
    detail = " | ".join(f["problems"][0] for f in findings if f["problems"])
    return ok, detail + f" | після відновлення: {'цілий' if final['ok'] else final['problems'][:1]}"

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
