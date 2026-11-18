"""drs_hub — базові маршрути: стан, OAuth 2.0, whoami, реєстр релізів (версія ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_routes_core.py

| Метод і маршрут                     | Доступ                      | Призначення |
|-------------------------------------|-----------------------------|-------------|
| GET  /api/v1/health                 | публічний                   | живість сервера (без внутрішніх подробиць) |
| POST /oauth/token                   | Basic (client credentials)  | видача токена доступу (RFC 6749 §4.4) |
| POST /oauth/revoke                  | Basic (client credentials)  | відкликання власного токена (RFC 7009) |
| GET  /api/v1/whoami                 | будь-який дійсний токен     | хто я для сервера: клієнт, роль, скоуп, строк |
| GET  /api/v1/releases[/{версія}]    | публічний                   | записи про опубліковані релізи й SHA-256 файлів |
| POST /api/v1/releases               | скоуп releases:write        | зареєструвати реліз (запис незмінний: повтор → 409) |

Хто опублікував реліз, сервер бере з токена, а не з тіла запиту. Запис релізу перевіряється за
жорсткою схемою: невідоме поле, неправильний формат версії, хешу чи дати → 400 (зайві дані не
приймаються мовчки).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import sqlite3
import time

import hub_auth
import hub_log
from hub_server import HubError, Request, Response
from hub_store import utc_now_iso

_VERSION_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}(?:-[0-9A-Za-z.]{1,20})?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")
_TEXT_LIMITS = {"product": 64, "channel": 64, "tag": 64, "notes": 2000}
_RELEASE_FIELDS = {"product", "version", "date", "files", "tag", "commit", "channel", "notes"}
_FILE_FIELDS = {"name", "sha256", "size"}


def register(app) -> None:
    app.route("GET", r"/api/v1/health", health)
    app.route("POST", r"/oauth/token", token, max_body=4096)
    app.route("POST", r"/oauth/revoke", revoke, max_body=4096)
    app.route("GET", r"/api/v1/whoami", whoami, auth="token")
    app.route("GET", r"/api/v1/releases", list_releases)
    app.route("GET", r"/api/v1/releases/(?P<version>[0-9A-Za-z.+-]{1,40})", get_release)
    app.route("POST", r"/api/v1/releases", publish_release, scope="releases:write", max_body=16 * 1024)


def health(app, req: Request) -> Response:
    return Response(200, {"status": "ok", "service": "drs-hub", "version": app.version,
                          "time": utc_now_iso()})


# --- OAuth 2.0 ---------------------------------------------------------------------
def token(app, req: Request) -> Response:
    form = req.form()
    grant = form.get("grant_type")
    if grant != "client_credentials":
        raise HubError(400, "unsupported_grant_type" if grant else "invalid_request",
                       "Підтримується лише grant_type=client_credentials.")
    if "client_secret" in form or "client_id" in form:
        raise HubError(400, "invalid_request",
                       "Облікові дані клієнта передаються лише в заголовку Authorization: Basic.")
    client_id, role, _ = hub_auth.authenticate_client(app.store, app.cfg, req.headers.get("Authorization"),
                                                      req.client_ip)
    issued = hub_auth.issue_token(app.store, app.cfg, client_id, role, form.get("scope"))
    req.log["client_id"] = client_id
    hub_log.event("info", "auth.token_issued", request_id=req.request_id, ip=req.client_ip,
                  client_id=client_id, role=role, scope=issued["scope"],
                  token_fp=hub_auth.sha256_hex(issued["access_token"])[:12],
                  expires_in=issued["expires_in"])
    return Response(200, issued)


def revoke(app, req: Request) -> Response:
    form = req.form()
    client_id, _role, _ = hub_auth.authenticate_client(app.store, app.cfg, req.headers.get("Authorization"),
                                                       req.client_ip)
    value = form.get("token", "")
    revoked = hub_auth.revoke_token(app.store, client_id, value)
    req.log["client_id"] = client_id
    hub_log.event("info", "auth.token_revoked", request_id=req.request_id, ip=req.client_ip,
                  client_id=client_id, revoked=revoked,
                  token_fp=hub_auth.sha256_hex(value)[:12] if value else None)
    return Response(200, {})          # RFC 7009 §2.2: 200 і для невідомого токена


def whoami(app, req: Request) -> Response:
    principal = req.principal
    return Response(200, {"client_id": principal.client_id, "role": principal.role,
                          "scope": " ".join(sorted(principal.scopes)),
                          "expires_in": max(0, int(principal.expires_at - time.time())),
                          "token_fp": principal.token_fp})


# --- релізи ---------------------------------------------------------------------------
def _public_record(row) -> dict:
    record = json.loads(row["record_json"])
    record["record_sha256"] = row["record_sha256"]
    record["published_at"] = row["published_at"]
    return record


def list_releases(app, req: Request) -> Response:
    items = [_public_record(row) for row in app.store.list_releases()]
    return Response(200, {"count": len(items), "releases": items})


def get_release(app, req: Request) -> Response:
    row = app.store.get_release(req.params["version"])
    if row is None:
        raise HubError(404, "not_found", "Такого релізу немає.")
    return Response(200, _public_record(row))


def _text(data: dict, key: str, required: bool = False) -> str | None:
    value = data.get(key)
    if value is None:
        if required:
            raise HubError(400, "invalid_field", f"Поле {key} обов'язкове.")
        return None
    if not isinstance(value, str) or len(value) > _TEXT_LIMITS.get(key, 64):
        raise HubError(400, "invalid_field", f"Поле {key}: рядок до {_TEXT_LIMITS.get(key, 64)} символів.")
    allowed_controls = "\n" if key == "notes" else ""
    if any(ord(ch) < 32 and ch not in allowed_controls for ch in value):
        raise HubError(400, "invalid_field", f"Поле {key} містить керувальні символи.")
    return value


def validate_release(data: dict) -> dict:
    unknown = sorted(set(data) - _RELEASE_FIELDS)
    if unknown:
        raise HubError(400, "unknown_field", "Невідомі поля: " + ", ".join(unknown[:5]))
    version = data.get("version")
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise HubError(400, "invalid_field", "version: очікувалось MAJOR.MINOR.PATCH[-суфікс].")
    date = data.get("date")
    if not isinstance(date, str) or not _DATE_RE.fullmatch(date):
        raise HubError(400, "invalid_field", "date: очікувалось YYYY-MM-DD.")
    try:
        datetime.date.fromisoformat(date)
    except ValueError:
        raise HubError(400, "invalid_field", "date: неіснуюча дата.") from None
    files = data.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 20:
        raise HubError(400, "invalid_field", "files: список з 1–20 файлів.")
    clean_files, names = [], set()
    for item in files:
        if not isinstance(item, dict) or set(item) != _FILE_FIELDS:
            raise HubError(400, "invalid_field", "files[]: рівно поля name, sha256, size.")
        name, digest, size = item["name"], item["sha256"], item["size"]
        if not isinstance(name, str) or not _FILE_RE.fullmatch(name) or name in names:
            raise HubError(400, "invalid_field", "files[].name: допустимі літери, цифри, «._ -», без повторів.")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise HubError(400, "invalid_field", "files[].sha256: 64 hex-символи в нижньому регістрі.")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size < 2 ** 31:
            raise HubError(400, "invalid_field", "files[].size: ціле число байтів.")
        names.add(name)
        clean_files.append({"name": name, "sha256": digest, "size": size})
    record = {"product": _text(data, "product") or "DynamicReloadSpeed", "version": version,
              "date": date, "files": clean_files}
    for key in ("tag", "channel", "notes"):
        value = _text(data, key)
        if value is not None:
            record[key] = value
    commit = data.get("commit")
    if commit is not None:
        if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit):
            raise HubError(400, "invalid_field", "commit: 7–40 hex-символів.")
        record["commit"] = commit
    return record


def canonical_json(record: dict) -> str:
    """Канонічна форма запису: ключі за абеткою, без пробілів — щоб SHA-256 був відтворюваним."""
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def publish_release(app, req: Request) -> Response:
    record = validate_release(req.json())
    canonical = canonical_json(record)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    principal = req.principal
    try:
        with app.store.write() as conn:
            app.store.insert_release(record["version"], canonical, digest, principal.client_id,
                                     utc_now_iso(), conn=conn)
            app.emit("release.published", conn=conn, version=record["version"], record_sha256=digest,
                     client_id=principal.client_id, request_id=req.request_id)
    except sqlite3.IntegrityError:
        raise HubError(409, "conflict", f"Реліз {record['version']} уже зареєстровано; записи незмінні.") from None
    hub_log.event("info", "release.published", request_id=req.request_id, client_id=principal.client_id,
                  token_fp=principal.token_fp, version=record["version"], record_sha256=digest)
    return Response(201, {"version": record["version"], "record_sha256": digest},
                    {"Location": f"/api/v1/releases/{record['version']}"})
