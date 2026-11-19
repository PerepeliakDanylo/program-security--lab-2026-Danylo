"""drs_hub — маршрут моніторингу (версія ЛР12).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_routes_ops.py

    GET /api/v1/metrics   скоуп metrics:read (maintainer, auditor)

Повертає показники процесу (hub_log.metrics_snapshot: запити за статусами й маршрутами, відмови,
невдалі автентифікації, затримка p50/p95, вікно 5 хв, останні сповіщення) і стан сховища (кількість
клієнтів, активних токенів, релізів, PRAGMA integrity_check, обсяг теки журналів). Секретів, токенів
і ідентифікаторів клієнтів тут немає — лише лічильники; маршрут не публічний (розвідка стану сервера
— теж інформація для нападника, урок Libraxis /api/admin/system/info).
"""

from __future__ import annotations

import os
import time

import hub_log
from hub_server import Request, Response


def register(app) -> None:
    app.route("GET", r"/api/v1/metrics", metrics, scope="metrics:read")


def _dir_size_mb(path: str) -> float:
    total = 0
    if os.path.isdir(path):
        for name in os.listdir(path):
            full = os.path.join(path, name)
            if os.path.isfile(full):
                total += os.path.getsize(full)
    return round(total / (1024 * 1024), 2)


def metrics(app, req: Request) -> Response:
    snapshot = hub_log.metrics_snapshot()
    snapshot["db"] = {
        "clients": len(app.store.list_clients()),
        "active_tokens": app.store.count_active_tokens(time.time()),
        "releases": len(app.store.list_releases()),
        "integrity": app.store.integrity_check(),
    }
    snapshot["log_dir_mb"] = _dir_size_mb(app.cfg.log_dir)
    snapshot["features"] = list(app.features)
    hub_log.event("info", "ops.metrics_read", request_id=req.request_id, client_id=req.principal.client_id)
    return Response(200, snapshot)
