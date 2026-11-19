"""drs_hub — клієнт командного рядка (версія ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_client.py

Клієнт НЕ ухвалює рішень про доступ — лише показує відповіді сервера. Його обов'язки — правильно
автентифікуватися й не розкидати секрети:
  * TLS обов'язковий; довіра — лише до CA сервера (--ca), ім'я хоста перевіряється. HTTP без TLS —
    лише 127.0.0.1 і лише з --insecure-http (налагодження);
  * client_id + секрет → POST /oauth/token (Basic, grant_type=client_credentials) → токен доступу;
  * токен живе лише в пам'яті процесу (на диск не пишеться), оновлюється за 30 с до закінчення;
    на 401 invalid_token — один повтор із новим токеном;
  * секрет — з файла (--secret-file, поза репозиторієм), змінної DRS_HUB_CLIENT_SECRET або getpass;
    у командний рядок секрет не передається (його видно в історії й списку процесів).

    python hub_client.py [--url URL] [--ca CA.pem] [--client-id ID] [--secret-file F] <команда>
    команди: health | token [--print] | whoami | releases [версія] | publish-release ФАЙЛ.json | revoke
Значення за замовчуванням — змінні DRS_HUB_URL, DRS_HUB_CA, DRS_HUB_CLIENT_ID.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import http.client
import ipaddress
import json
import os
import ssl
import sys
import time
from urllib.parse import quote_plus, urlencode, urlsplit

import hub_e2ee

USER_AGENT = "drs-hub-client/0.1.0"
TOKEN_REFRESH_MARGIN_S = 30


class HubClientError(Exception):
    """Помилка налаштування чи з'єднання на боці клієнта."""


class ApiError(HubClientError):
    def __init__(self, status: int, payload) -> None:
        payload = payload if isinstance(payload, dict) else {}
        self.status = status
        self.error = payload.get("error", "unknown")
        self.description = payload.get("error_description", "")
        self.request_id = payload.get("request_id", "-")
        super().__init__(f"HTTP {status} {self.error}: {self.description} (request_id {self.request_id})")


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


class HubClient:
    def __init__(self, base_url: str, *, ca_file: str | None = None, client_id: str | None = None,
                 client_secret: str | None = None, insecure_http: bool = False,
                 timeout: float = 15.0, scope: str | None = None) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise HubClientError("Адреса сервера: https://host:port")
        if parts.scheme == "http":
            if not insecure_http:
                raise HubClientError("HTTP без TLS заборонено: секрет і токени йшли б відкритим каналом. "
                                     "Налагодження на 127.0.0.1 — прапорець --insecure-http.")
            if not _is_loopback(parts.hostname):
                raise HubClientError("HTTP без TLS дозволено лише для loopback-адреси.")
            self._ssl = None
        else:
            context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._ssl = context
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.prefix = parts.path.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.scope = scope
        self._token: str | None = None
        self._token_deadline = 0.0
        self.token_scope = ""

    # --- транспорт ---------------------------------------------------------------
    def _connection(self) -> http.client.HTTPConnection:
        if self._ssl is None:
            return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self._ssl)

    def raw(self, method: str, path: str, *, body: bytes | None = None,
            headers: dict | None = None) -> tuple[int, dict, object]:
        all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        all_headers.update(headers or {})
        conn = self._connection()
        try:
            conn.request(method, self.prefix + path, body=body, headers=all_headers)
            response = conn.getresponse()
            data = response.read()
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            status = response.status
        finally:
            conn.close()
        payload = None
        if data:
            try:
                payload = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {"raw": data[:200].decode("utf-8", "replace")}
        return status, response_headers, payload

    # --- OAuth 2.0 ------------------------------------------------------------------
    def _basic_header(self) -> str:
        if not self.client_id or self.client_secret is None:
            raise HubClientError("Потрібні client_id і секрет клієнта.")
        raw = f"{quote_plus(self.client_id)}:{quote_plus(self.client_secret)}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def fetch_token(self, scope: str | None = None) -> dict:
        form = {"grant_type": "client_credentials"}
        if scope or self.scope:
            form["scope"] = scope or self.scope
        status, _, payload = self.raw("POST", "/oauth/token", body=urlencode(form).encode("ascii"),
                                      headers={"Content-Type": "application/x-www-form-urlencoded",
                                               "Authorization": self._basic_header()})
        if status != 200:
            raise ApiError(status, payload)
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str):
            raise HubClientError("Сервер не повернув access_token.")
        self._token = token
        self._token_deadline = time.monotonic() + int(payload.get("expires_in", 0))
        self.token_scope = payload.get("scope", "")
        return {"token_type": payload.get("token_type"), "expires_in": payload.get("expires_in"),
                "scope": self.token_scope}

    def bearer_header(self) -> str:
        if self._token is None or time.monotonic() > self._token_deadline - TOKEN_REFRESH_MARGIN_S:
            self.fetch_token()
        return "Bearer " + self._token

    def call(self, method: str, path: str, json_body=None, *, auth: bool = True,
             body: bytes | None = None, content_type: str | None = None) -> tuple[int, object]:
        headers: dict[str, str] = {}
        if json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            content_type = "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        status, payload = 0, None
        for attempt in (1, 2):
            if auth:
                headers["Authorization"] = self.bearer_header()
            status, _, payload = self.raw(method, path, body=body, headers=headers)
            if (auth and attempt == 1 and status == 401 and isinstance(payload, dict)
                    and payload.get("error") == "invalid_token"):
                self._token = None          # прострочений або відкликаний — один повтор із новим
                continue
            break
        return status, payload

    def revoke(self) -> bool:
        if self._token is None:
            return False
        status, _, payload = self.raw("POST", "/oauth/revoke",
                                      body=urlencode({"token": self._token}).encode("ascii"),
                                      headers={"Content-Type": "application/x-www-form-urlencoded",
                                               "Authorization": self._basic_header()})
        if status != 200:
            raise ApiError(status, payload)
        self._token = None
        return True


# --- CLI ------------------------------------------------------------------------
def _print_json(payload) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _expect(status: int, payload, ok: tuple[int, ...] = (200,)):
    if status not in ok:
        raise ApiError(status, payload)
    return payload


def cmd_health(client: HubClient, args) -> int:
    status, payload = client.call("GET", "/api/v1/health", auth=False)
    _print_json(_expect(status, payload))
    return 0


def cmd_token(client: HubClient, args) -> int:
    info = client.fetch_token()
    print(f"Токен отримано: тип {info['token_type']}, діє {info['expires_in']} с, скоуп: {info['scope']}")
    if args.print:
        print("УВАГА: токен на екрані — для ручної перевірки (curl/Postman); не зберігайте його.",
              file=sys.stderr)
        print(client._token)
    return 0


def cmd_whoami(client: HubClient, args) -> int:
    status, payload = client.call("GET", "/api/v1/whoami")
    _print_json(_expect(status, payload))
    return 0


def cmd_releases(client: HubClient, args) -> int:
    path = "/api/v1/releases" + (f"/{args.version}" if args.version else "")
    status, payload = client.call("GET", path, auth=False)
    payload = _expect(status, payload)
    if args.version:
        _print_json(payload)
        return 0
    print(f"Зареєстровано релізів: {payload['count']}")
    for item in payload["releases"]:
        print(f"  {item['product']} {item['version']} ({item['date']}) — запис {item['record_sha256'][:16]}…")
        for entry in item["files"]:
            print(f"      {entry['name']:<36} {entry['size']:>10} Б  sha256 {entry['sha256']}")
    return 0


def cmd_publish_release(client: HubClient, args) -> int:
    with open(args.file, "r", encoding="utf-8-sig") as fh:     # Set-Content -Encoding utf8 (PS 5.1) пише BOM
        record = json.load(fh)
    status, payload = client.call("POST", "/api/v1/releases", record)
    payload = _expect(status, payload, (201,))
    print(f"Реліз {payload['version']} зареєстровано; SHA-256 запису {payload['record_sha256']}")
    return 0


def cmd_revoke(client: HubClient, args) -> int:
    client.fetch_token()
    client.revoke()
    print("Поточний токен відкликано (RFC 7009).")
    return 0


# --- звіти тестерів (наскрізне шифрування) і журнал записів (ЛР13–14) ----------------------
DEFAULT_RECIPIENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_recipient.pub")


def _passphrase(prompt: str, confirm: bool = False) -> bytes:
    env = os.environ.get("DRS_HUB_KEY_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    first = getpass.getpass(prompt)
    if confirm and getpass.getpass("Повторіть: ") != first:
        raise HubClientError("Парольні фрази не збігаються.")
    if len(first) < 12:
        raise HubClientError("Парольна фраза коротша за 12 символів.")
    return first.encode("utf-8")


def cmd_keygen(client: HubClient, args) -> int:
    kid = hub_e2ee.generate_keypair(args.private, args.public,
                                    _passphrase("Парольна фраза закритого ключа звітів: ", confirm=True))
    print(f"Пару X25519 створено. Закритий (PKCS#8, зашифрований): {os.path.abspath(args.private)}")
    print(f"Відкритий (у репозиторій): {os.path.abspath(args.public)}; kid {kid}")
    return 0


def cmd_submit_report(client: HubClient, args) -> int:
    recipient = hub_e2ee.load_public(args.recipient)
    files = []
    for path in args.files:
        with open(path, "rb") as fh:
            files.append((os.path.basename(path), fh.read()))
    plaintext = hub_e2ee.build_bundle(files, args.note or "")
    meta = hub_e2ee.new_meta(client.client_id, plugin_version=args.plugin_version, game_build=args.game_build)
    envelope = hub_e2ee.encrypt_report(recipient, plaintext, meta)
    status, payload = client.call("POST", "/api/v1/reports", envelope)
    payload = _expect(status, payload, (201,))
    print(f"Звіт {payload['report_id']} прийнято: файлів {len(files)}, стиснений пакет {len(plaintext)} Б → "
          f"шифротекст {payload['size']} Б; отримувач kid {hub_e2ee.key_id(recipient)} (звір із README).")
    if payload.get("ledger_index") is not None:
        print(f"Квитанція журналу: блок {payload['ledger_index']}, hash {payload['ledger_hash']}")
    return 0


def cmd_reports(client: HubClient, args) -> int:
    status, payload = client.call("GET", "/api/v1/reports")
    payload = _expect(status, payload)
    print(f"Звітів ({payload['scope']}): {payload['count']}")
    for item in payload["reports"]:
        print(f"  {item['report_id']}  {item['submitter']:<16} {item['received_at']}  {item['size']:>8} Б  "
              f"kid {item['kid']}  sha256 {item['envelope_sha256'][:16]}…")
    return 0


def cmd_get_report(client: HubClient, args) -> int:
    status, payload = client.call("GET", f"/api/v1/reports/{args.report_id}")
    payload = _expect(status, payload)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"Конверт (лише шифротекст і метадані) збережено: {args.out}")
    return 0


def cmd_decrypt_report(client: HubClient, args) -> int:
    status, envelope = client.call("GET", f"/api/v1/reports/{args.report_id}")
    envelope = _expect(status, envelope)
    private_key = hub_e2ee.load_private(args.private, _passphrase("Парольна фраза закритого ключа звітів: "))
    plaintext, meta = hub_e2ee.decrypt_report(private_key, envelope)
    if meta.get("report_id") != args.report_id:
        raise HubClientError("report_id у метаданих не збігається з запитаним — звіт підмінено.")
    bundle = hub_e2ee.parse_bundle(plaintext)
    written = hub_e2ee.write_bundle(bundle, os.path.join(args.out_dir, args.report_id))
    print(f"Звіт {args.report_id} розшифровано (автентифікацію AES-GCM пройдено): від {meta['submitter']}, "
          f"створено {meta['created']}, плагін {meta.get('plugin_version', '-')}, гра {meta.get('game_build', '-')}")
    for path in written:
        print("  " + path)
    return 0


def cmd_ledger(client: HubClient, args) -> int:
    status, payload = client.call("GET", "/api/v1/ledger")
    payload = _expect(status, payload)
    for block in payload["blocks"]:
        print(f"{block['idx']:>4} {block['ts']} {block['kind']:<8} {block['ref'][:32]:<32} "
              f"prev {block['prev_hash'][:12]}… hash {block['hash'][:16]}…")
    print(f"Голова: {payload['head']}")
    return 0


def cmd_ledger_verify(client: HubClient, args) -> int:
    status, payload = client.call("GET", "/api/v1/ledger/verify")
    payload = _expect(status, payload)
    print(f"Блоків: {payload['blocks']}; голова: {payload['head']}")
    if payload["ok"]:
        print("Ланцюг цілий: хеші блоків, prev_hash і SHA-256 даних збігаються.")
        return 0
    print("ПОРУШЕННЯ ЦІЛІСНОСТІ:")
    for problem in payload["problems"]:
        print("  — " + problem)
    return 1


COMMANDS = {
    "health": cmd_health,
    "token": cmd_token,
    "whoami": cmd_whoami,
    "releases": cmd_releases,
    "publish-release": cmd_publish_release,
    "revoke": cmd_revoke,
    "keygen": cmd_keygen,
    "submit-report": cmd_submit_report,
    "reports": cmd_reports,
    "get-report": cmd_get_report,
    "decrypt-report": cmd_decrypt_report,
    "ledger": cmd_ledger,
    "ledger-verify": cmd_ledger_verify,
}

PUBLIC_COMMANDS = {"health", "releases", "keygen"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hub_client", description="DRS Hub — клієнт командного рядка.")
    parser.add_argument("--url", default=os.environ.get("DRS_HUB_URL", "https://127.0.0.1:8443"))
    parser.add_argument("--ca", default=os.environ.get("DRS_HUB_CA"), help="ca_cert.pem сервера")
    parser.add_argument("--client-id", default=os.environ.get("DRS_HUB_CLIENT_ID"))
    parser.add_argument("--secret-file", default=None, help="файл із секретом клієнта (поза репозиторієм)")
    parser.add_argument("--scope", default=None, help="звузити скоуп токена (через пробіл)")
    parser.add_argument("--insecure-http", action="store_true", help="лише налагодження на 127.0.0.1")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health", help="стан сервера (публічно)")
    tok = sub.add_parser("token", help="отримати токен і показати строк та скоуп")
    tok.add_argument("--print", action="store_true", help="надрукувати сам токен (для curl/Postman)")
    sub.add_parser("whoami", help="хто я для сервера")
    rel = sub.add_parser("releases", help="реєстр релізів (публічно)")
    rel.add_argument("version", nargs="?")
    pub = sub.add_parser("publish-release", help="зареєструвати реліз (скоуп releases:write)")
    pub.add_argument("file")
    sub.add_parser("revoke", help="відкликати поточний токен (RFC 7009)")
    keygen = sub.add_parser("keygen", help="пара ключів отримувача звітів X25519 (супроводжувач, один раз)")
    keygen.add_argument("--private", required=True, help="закритий ключ — поза репозиторієм")
    keygen.add_argument("--public", default=DEFAULT_RECIPIENT, help="відкритий ключ (report_recipient.pub)")
    submit = sub.add_parser("submit-report", help="зашифрувати пакет локально й подати (тестер)")
    submit.add_argument("files", nargs="+")
    submit.add_argument("--recipient", default=DEFAULT_RECIPIENT, help="відкритий ключ отримувача з репозиторію")
    submit.add_argument("--note", default="")
    submit.add_argument("--plugin-version", default=None)
    submit.add_argument("--game-build", default=None)
    sub.add_parser("reports", help="перелік звітів (без шифротексту)")
    get_report = sub.add_parser("get-report", help="зберегти конверт звіту (лише шифротекст)")
    get_report.add_argument("report_id")
    get_report.add_argument("--out", required=True)
    decrypt = sub.add_parser("decrypt-report", help="розшифрувати звіт локально (супроводжувач)")
    decrypt.add_argument("report_id")
    decrypt.add_argument("--private", required=True)
    decrypt.add_argument("--out-dir", default=".")
    sub.add_parser("ledger", help="блоки журналу записів")
    sub.add_parser("ledger-verify", help="перевірка хеш-ланцюга на сервері")
    return parser


def _read_secret(args) -> str | None:
    if args.secret_file:
        with open(args.secret_file, "r", encoding="utf-8-sig") as fh:
            return fh.readline().strip()
    env = os.environ.get("DRS_HUB_CLIENT_SECRET")
    if env:
        return env.strip()
    if args.command in PUBLIC_COMMANDS:
        return None
    return getpass.getpass(f"Секрет клієнта {args.client_id}: ")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):      # кирилиця в каналі cp1251/cp1252 не валить вивід
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        if args.command not in PUBLIC_COMMANDS and not args.client_id:
            raise HubClientError("Потрібен --client-id (або змінна DRS_HUB_CLIENT_ID).")
        client = HubClient(args.url, ca_file=args.ca, client_id=args.client_id,
                           client_secret=_read_secret(args), insecure_http=args.insecure_http,
                           scope=args.scope)
        return COMMANDS[args.command](client, args)
    except ApiError as exc:
        print(f"Відмова сервера: {exc}")
        return 1
    except ssl.SSLCertVerificationError as exc:
        print(f"Сертифікат сервера НЕ підтверджено ({exc.verify_message}) — з'єднання перервано. "
              "Перевірте --ca: можливе перехоплення з'єднання.")
        return 2
    except (HubClientError, OSError, ssl.SSLError, ValueError) as exc:   # ValueError: JSON, E2EEError (ЛР13–14)
        print(f"Помилка: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
