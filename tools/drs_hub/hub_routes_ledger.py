"""drs_hub — маршрути й підписки журналу записів (версія ЛР13–14).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_routes_ledger.py

    GET /api/v1/ledger          скоуп ledger:read — блоки (останні 200) і голова ланцюга
    GET /api/v1/ledger/verify   скоуп ledger:read — перевірка всього ланцюга й звірка з даними

Підписки: release.published і report.submitted → hub_ledger.append у ТІЙ САМІЙ транзакції, що й
запис даних; номер і хеш блока повертаються клієнту квитанцією (receipt). При старті сервера —
genesis і дописування наявних записів (ensure_genesis).
"""

from __future__ import annotations

import hub_ledger
import hub_log
from hub_server import Request, Response

SCHEMA = hub_ledger.SCHEMA


def register(app) -> None:
    with app.store.write() as conn:
        added = hub_ledger.ensure_genesis(conn)
    if added:
        hub_log.event("info", "ledger.backfilled", blocks=added)
    app.subscribe("release.published", _on_release)
    app.subscribe("report.submitted", _on_report)
    app.route("GET", r"/api/v1/ledger", list_ledger, scope="ledger:read")
    app.route("GET", r"/api/v1/ledger/verify", verify_ledger, scope="ledger:read")


def _record(conn, kind: str, ref: str, payload: str, receipt: dict | None, request_id: str | None) -> None:
    idx, digest = hub_ledger.append(conn, kind, ref, payload)
    if receipt is not None:
        receipt.update({"ledger_index": idx, "ledger_hash": digest})
    hub_log.event("info", "ledger.appended", request_id=request_id, kind=kind, ref=ref, idx=idx,
                  hash=digest[:16])


def _on_release(app, conn, version: str, record_sha256: str, receipt: dict | None = None,
                request_id: str | None = None, **_ignored) -> None:
    _record(conn, "release", version, record_sha256, receipt, request_id)


def _on_report(app, conn, report_id: str, envelope_sha256: str, receipt: dict | None = None,
               request_id: str | None = None, **_ignored) -> None:
    _record(conn, "report", report_id, envelope_sha256, receipt, request_id)


def list_ledger(app, req: Request) -> Response:
    with app.store.read() as conn:
        rows = conn.execute("SELECT * FROM ledger ORDER BY idx DESC LIMIT 200").fetchall()
        current = hub_ledger.head(conn)
    blocks = [dict(row) for row in reversed(rows)]
    return Response(200, {"head": current, "count": len(blocks), "blocks": blocks})


def verify_ledger(app, req: Request) -> Response:
    with app.store.read() as conn:
        result = hub_ledger.verify(conn)
    hub_log.event("info" if result["ok"] else "warning", "ledger.verified", request_id=req.request_id,
                  client_id=req.principal.client_id, ok=result["ok"], blocks=result["blocks"],
                  problems=len(result["problems"]))
    return Response(200, result)
