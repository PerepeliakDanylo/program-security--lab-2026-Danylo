"""drs_hub — прийом і видача наскрізно зашифрованих звітів тестерів (версія ЛР13–14).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_routes_reports.py

    POST /api/v1/reports          скоуп reports:submit — прийняти конверт (лише шифротекст + метадані)
    GET  /api/v1/reports          reports:read — усі; reports:read:own — лише власні (без шифротексту)
    GET  /api/v1/reports/{id}     reports:read — будь-який; reports:read:own — лише власний (чужий → 404)

Сервер НЕ має закритого ключа отримувача й не може розшифрувати звіт. Він перевіряє лише структуру
конверта (hub_e2ee.validate_envelope), що kid — чинний ключ отримувача, і що meta.submitter = client_id
токена (метадані входять в AAD, тож підставити іншого автора непомітно не вийде). Відкритий ключ
отримувача сервер читає з файла report_recipient.pub поруч із кодом (або шляху з hub.json
report_recipient_pub) лише для звірки kid. Чужий звіт для тестера — 404, як неіснуючий (без
розкриття існування).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3

import hub_e2ee
import hub_log
from hub_auth import AuthError
from hub_server import HubError, Request, Response
from hub_store import utc_now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    report_id       TEXT PRIMARY KEY,
    submitter       TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    received_at     TEXT NOT NULL,
    kid             TEXT NOT NULL,
    size            INTEGER NOT NULL,
    envelope_sha256 TEXT NOT NULL,
    envelope_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_by_submitter ON reports(submitter);
"""

DEFAULT_RECIPIENT_PUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_recipient.pub")
_LIST_COLUMNS = "report_id, submitter, created_at, received_at, kid, size, envelope_sha256"


def register(app) -> None:
    app.route("POST", r"/api/v1/reports", submit_report, scope="reports:submit", max_body=3 * 1024 * 1024)
    app.route("GET", r"/api/v1/reports", list_reports, auth="token")
    app.route("GET", r"/api/v1/reports/(?P<report_id>[0-9a-f]{32})", get_report, auth="token")


def _recipient_kid(app) -> str:
    path = getattr(app.cfg, "report_recipient_pub", "") or DEFAULT_RECIPIENT_PUB
    cached = getattr(app, "_report_recipient", None)
    if cached is not None and cached[0] == path:
        return cached[1]
    if not os.path.exists(path):
        raise HubError(503, "report_key_not_configured", "Ключ отримувача звітів не налаштовано.")
    kid = hub_e2ee.key_id(hub_e2ee.load_public(path))
    app._report_recipient = (path, kid)
    return kid


def _read_mode(principal) -> str:
    if "reports:read" in principal.scopes:
        return "all"
    if "reports:read:own" in principal.scopes:
        return "own"
    raise AuthError(403, "insufficient_scope", "Потрібен скоуп reports:read або reports:read:own.",
                    {"WWW-Authenticate": 'Bearer realm="drs-hub", error="insufficient_scope", scope="reports:read"'})


def submit_report(app, req: Request) -> Response:
    try:
        envelope = hub_e2ee.validate_envelope(req.json())
    except hub_e2ee.E2EEError as exc:
        raise HubError(400, "invalid_envelope", str(exc)) from None
    meta = envelope["meta"]
    principal = req.principal
    if meta["submitter"] != principal.client_id:
        raise HubError(400, "submitter_mismatch", "meta.submitter має дорівнювати client_id токена.")
    kid = _recipient_kid(app)
    if envelope["kid"] != kid:
        raise HubError(400, "unknown_recipient_key", "Звіт зашифровано не чинним ключем отримувача.")
    canonical = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    size = len(base64.b64decode(envelope["ct"]))
    receipt: dict = {}
    try:
        with app.store.write() as conn:
            conn.execute("INSERT INTO reports (report_id, submitter, created_at, received_at, kid, size, "
                         "envelope_sha256, envelope_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (meta["report_id"], meta["submitter"], meta["created"], utc_now_iso(), kid, size,
                          digest, canonical))
            app.emit("report.submitted", conn=conn, report_id=meta["report_id"], envelope_sha256=digest,
                     client_id=principal.client_id, receipt=receipt, request_id=req.request_id)
    except sqlite3.IntegrityError:
        raise HubError(409, "conflict", "Звіт із таким report_id уже прийнято.") from None
    hub_log.event("info", "report.submitted", request_id=req.request_id, client_id=principal.client_id,
                  token_fp=principal.token_fp, report_id=meta["report_id"], size=size, kid=kid,
                  envelope_fp=digest[:16], ledger_index=receipt.get("ledger_index"))
    body = {"report_id": meta["report_id"], "envelope_sha256": digest, "size": size, **receipt}
    return Response(201, body, {"Location": f"/api/v1/reports/{meta['report_id']}"})


def list_reports(app, req: Request) -> Response:
    mode = _read_mode(req.principal)
    with app.store.read() as conn:
        if mode == "all":
            rows = conn.execute(f"SELECT {_LIST_COLUMNS} FROM reports ORDER BY received_at").fetchall()
        else:
            rows = conn.execute(f"SELECT {_LIST_COLUMNS} FROM reports WHERE submitter = ? ORDER BY received_at",
                                (req.principal.client_id,)).fetchall()
    items = [dict(row) for row in rows]
    return Response(200, {"scope": mode, "count": len(items), "reports": items})


def get_report(app, req: Request) -> Response:
    mode = _read_mode(req.principal)
    with app.store.read() as conn:
        row = conn.execute("SELECT submitter, envelope_json FROM reports WHERE report_id = ?",
                           (req.params["report_id"],)).fetchone()
    if row is None or (mode == "own" and row["submitter"] != req.principal.client_id):
        raise HubError(404, "not_found", "Звіту немає.")
    hub_log.event("info", "report.read", request_id=req.request_id, client_id=req.principal.client_id,
                  report_id=req.params["report_id"], mode=mode)
    return Response(200, json.loads(row["envelope_json"]))
