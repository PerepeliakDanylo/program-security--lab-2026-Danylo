"""drs_hub — журнал сервера, базова версія (ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_log.py

Мінімум для ЛР10–11: кожна подія автентифікації/авторизації й кожен запит лишають рядок «час UTC,
рівень, подія, поля key=value» у logs/hub.log теки даних і в консолі. Значення очищуються від
переводів рядка (підробка рядків журналу) й обрізаються. Секрети в журнал не потрапляють: сервер
передає сюди лише відбитки токенів (12 hex SHA-256), ніколи сам токен, секрет чи заголовок
Authorization. Структурований формат, ротація, показники й сповіщення — ЛР12 (цей файл буде замінено).
"""

from __future__ import annotations

import logging
import os
import sys
import time
import uuid

_LOGGER = logging.getLogger("drs_hub")
_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING,
           "error": logging.ERROR, "critical": logging.CRITICAL}
_MAX_VALUE = 200


class _UtcFormatter(logging.Formatter):
    converter = time.gmtime

    def formatTime(self, record, datefmt=None):  # noqa: N802 — ім'я з logging
        return time.strftime("%Y-%m-%dT%H:%M:%S", self.converter(record.created)) + \
            f".{int(record.msecs):03d}Z"


def setup(cfg, console: bool = True) -> None:
    """Налаштувати журнал: файл logs/hub.log у теці даних (+ консоль)."""
    os.makedirs(cfg.log_dir, exist_ok=True)
    _LOGGER.handlers.clear()
    _LOGGER.setLevel(_LEVELS.get(cfg.log_level, logging.INFO))
    _LOGGER.propagate = False
    fmt = _UtcFormatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(os.path.join(cfg.log_dir, "hub.log"), encoding="utf-8")
    file_handler.setFormatter(fmt)
    _LOGGER.addHandler(file_handler)
    if console:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(fmt)
        _LOGGER.addHandler(stream)


def _clean(value) -> str:
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= _MAX_VALUE else text[:_MAX_VALUE] + "…"


def event(level: str, name: str, **fields) -> None:
    """Одна подія: назва + поля. Порядок полів — як передано."""
    parts = " ".join(f"{key}={_clean(value)}" for key, value in fields.items() if value is not None)
    _LOGGER.log(_LEVELS.get(level, logging.INFO), "%s %s", name, parts)


def access(**fields) -> None:
    """Рядок журналу доступу для кожного HTTP-запиту."""
    event("info", "http.access", **fields)


def new_request_id() -> str:
    """Ідентифікатор запиту: повертається клієнту в X-Request-ID і пишеться в кожну подію запиту."""
    return uuid.uuid4().hex[:16]
