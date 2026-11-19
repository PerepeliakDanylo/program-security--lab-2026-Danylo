"""drs_hub — структурований журнал, показники й сповіщення (версія ЛР12).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_log.py
Ця версія ЗАМІНЮЄ базову версію ЛР10–11 (API той самий: setup, event, access, new_request_id;
додано shutdown, metrics_snapshot, verify_log_file).

Рішення (обґрунтування — docs/security/logging_monitoring.md):
  * Формат — JSON Lines: один рядок = одна подія, однакова схема полів для всіх подій.
    Час — UTC ISO 8601 з мілісекундами й «Z» (одна часова основа; урок Libraxis — сім форматів часу
    без пояса). Поля ts, level, event, component, version, host, pid + поля події; request_id
    зв'язує запис доступу з усіма подіями того самого запиту.
  * Два журнали в logs/ теки даних, ротація щодоби (UTC):
      hub-YYYY-MM-DD.jsonl       — усі події рівня ≥ налаштованого; зберігається 14 діб;
      security-YYYY-MM-DD.jsonl  — лише безпекові події (auth., admin., release., report., ledger.,
                                   alert., tls., server.); зберігається 90 діб; кожен рядок містить
                                   prev і chain = SHA-256(prev + канонічний JSON запису) — зміна,
                                   видалення чи вставка рядка виявляються (verify_log_file).
    Процес адміністрування пише у власні файли (hub-admin-…, security-admin-…), щоб два процеси
    не переплітали один ланцюг.
  * Редагування чутливого: поля з іменами authorization, password, secret, token, private_key,
    envelope, ciphertext, plaintext, body… → «[REDACTED]»; у будь-якому рядку значення, схожі на
    токен (dha_…), секрет (dhs_…), «Bearer …» чи PEM закритого ключа, замінюються; рядки
    обрізаються до 300 символів. Сервер і так передає лише відбитки токенів — це другий рубіж.
  * Показники (у пам'яті процесу): запити за класами статусів і маршрутами, відмови 401/403/429,
    невдалі автентифікації, видані токени, затримка p50/p95, вікно 5 хв.
  * Сповіщення (ковзні вікна, повтор того самого не частіше ніж раз на 5 хв) → подія alert.raised:
      auth.bruteforce_ip   ≥ 10 невдалих автентифікацій з однієї адреси за 60 с   (WARNING)
      auth.lockout         блокування client_id                                  (WARNING)
      authz.denied_burst   ≥ 10 відповідей 403 одному суб'єкту за 60 с          (WARNING)
      http.scan_404        ≥ 20 відповідей 404 одній адресі за 60 с             (WARNING)
      http.error_burst     ≥ 5 відповідей 5xx за 60 с                            (CRITICAL)
      tls.handshake_burst  ≥ 20 невдалих рукостискань TLS за 60 с                (WARNING)
"""

from __future__ import annotations

import collections
import datetime
import hashlib
import json
import logging
import os
import platform
import re
import sys
import threading
import time
import uuid

import hub_config

_LOGGER = logging.getLogger("drs_hub")
_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING,
           "error": logging.ERROR, "critical": logging.CRITICAL}

GENERAL_RETENTION_DAYS = 14
SECURITY_RETENTION_DAYS = 90
SECURITY_PREFIXES = ("auth.", "admin.", "release.", "report.", "ledger.", "alert.", "tls.", "server.")
ZERO_CHAIN = "0" * 64
ALERT_COOLDOWN_S = 300
_MAX_STR = 300
_BASE_FIELDS = ("ts", "level", "event", "component", "version", "host", "pid")
_SENSITIVE_KEYS = {"authorization", "password", "secret", "client_secret", "token", "access_token",
                   "refresh_token", "cookie", "private_key", "envelope", "ciphertext", "plaintext", "body"}
SECRET_PATTERNS = (
    re.compile(r"dha_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"dhs_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/\-]{8,}=*"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_STATE = {"component": "drs_hub", "version": hub_config.HUB_VERSION, "host": platform.node(),
          "pid": os.getpid()}


# --- запис події ----------------------------------------------------------------
def _utc_ts(created: float) -> str:
    moment = datetime.datetime.fromtimestamp(created, tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def redact(value):
    """Прибрати чутливе з будь-якого значення (рекурсивно)."""
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if str(k).lower() in _SENSITIVE_KEYS else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in list(value)[:50]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text if len(text) <= _MAX_STR else text[:_MAX_STR] + "…"


def build_record(created: float, levelname: str, name: str, fields: dict) -> dict:
    record = {"ts": _utc_ts(created), "level": levelname, "event": name,
              "component": _STATE["component"], "version": _STATE["version"],
              "host": _STATE["host"], "pid": _STATE["pid"]}
    for key, value in fields.items():
        if value is None or key in record:
            continue
        record[key] = "[REDACTED]" if key.lower() in _SENSITIVE_KEYS else redact(value)
    return record


def _canonical(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# --- обробники ------------------------------------------------------------------
class DailyJsonHandler(logging.Handler):
    """JSON Lines у файл <prefix>-YYYY-MM-DD.jsonl (UTC); старі файли видаляються за строком зберігання."""

    def __init__(self, log_dir: str, prefix: str, retention_days: int, *, chained: bool = False,
                 security_only: bool = False) -> None:
        super().__init__()
        self.log_dir = log_dir
        self.prefix = prefix
        self.retention_days = retention_days
        self.chained = chained
        self.security_only = security_only
        self._name_re = re.compile(rf"^{re.escape(prefix)}-(\d{{4}}-\d{{2}}-\d{{2}})\.jsonl$")
        self._fh = None
        self._date = None
        self._prev = ZERO_CHAIN
        self._restart = False

    def _prune(self, today: str) -> None:
        cutoff = (datetime.date.fromisoformat(today) - datetime.timedelta(days=self.retention_days)).isoformat()
        for name in os.listdir(self.log_dir):
            found = self._name_re.match(name)
            if found and found.group(1) < cutoff:
                try:
                    os.remove(os.path.join(self.log_dir, name))
                except OSError:
                    pass

    def _open(self, date: str) -> None:
        if self._fh is not None:
            self._fh.close()
        path = os.path.join(self.log_dir, f"{self.prefix}-{date}.jsonl")
        self._prev, self._restart = ZERO_CHAIN, False
        if self.chained and os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "rb") as fh:          # продовжити ланцюг після перезапуску процесу
                fh.seek(max(0, os.path.getsize(path) - 65536))
                tail = [line for line in fh.read().splitlines() if line.strip()]
            try:
                last = json.loads(tail[-1].decode("utf-8"))
                self._prev = last["chain"]
            except (IndexError, ValueError, KeyError, UnicodeDecodeError):
                self._restart = True              # хвіст пошкоджено — новий сегмент, позначений явно
        self._fh = open(path, "a", encoding="utf-8", newline="\n")
        self._date = date
        self._prune(date)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            rec = getattr(record, "drs", None) or build_record(record.created, record.levelname,
                                                               record.getMessage(), {})
            if self.security_only and not rec["event"].startswith(SECURITY_PREFIXES):
                return
            date = rec["ts"][:10]
            if self._fh is None or date != self._date:
                self._open(date)
            if self.chained:
                rec = dict(rec)
                rec["prev"] = self._prev
                if self._restart:
                    rec["chain_restart"] = True
                    self._restart = False
                rec["chain"] = hashlib.sha256((self._prev + _canonical(rec)).encode("utf-8")).hexdigest()
                self._prev = rec["chain"]
                line = _canonical(rec)
            else:
                line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
            self._fh.write(line + "\n")
            self._fh.flush()
        except Exception:  # noqa: BLE001 — збій журналу не повинен валити запит
            self.handleError(record)

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        super().close()


class ConsoleHandler(logging.Handler):
    """Короткий людський рядок у stderr: час, рівень, подія, поля."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            rec = getattr(record, "drs", None) or build_record(record.created, record.levelname,
                                                               record.getMessage(), {})
            extra = " ".join(f"{k}={v}" for k, v in rec.items() if k not in _BASE_FIELDS)
            sys.stderr.write(f"{rec['ts']} {rec['level']:<8} {rec['event']} {extra}\n")
            sys.stderr.flush()
        except Exception:  # noqa: BLE001
            self.handleError(record)


# --- показники й сповіщення ------------------------------------------------------
class _Monitor:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.started = time.time()
        self.requests_total = 0
        self.by_status: collections.Counter = collections.Counter()
        self.by_route: collections.Counter = collections.Counter()
        self.denied: collections.Counter = collections.Counter()
        self.auth_failures_total = 0
        self.tokens_issued_total = 0
        self.latencies: collections.deque = collections.deque(maxlen=1000)
        self.window5: collections.deque = collections.deque()
        self.windows: dict = collections.defaultdict(collections.deque)
        self.alert_last: dict = {}
        self.alerts: collections.deque = collections.deque(maxlen=20)
        self.alerts_total = 0

    def _fire(self, rule: str, subject: str, now: float, level: str, count: int, window: int) -> list:
        last = self.alert_last.get((rule, subject))
        if last is not None and now - last < ALERT_COOLDOWN_S:
            return []
        self.alert_last[(rule, subject)] = now
        self.alerts_total += 1
        self.alerts.append({"ts": _utc_ts(now), "rule": rule, "subject": subject, "count": count,
                            "level": level.upper()})
        return [{"level": level, "rule": rule, "subject": subject, "count": count, "window_s": window}]

    def _hit(self, rule: str, subject: str, now: float, threshold: int, window: int, level: str) -> list:
        hits = self.windows[(rule, subject)]
        hits.append(now)
        while hits and hits[0] < now - window:
            hits.popleft()
        if len(hits) >= threshold:
            return self._fire(rule, subject, now, level, len(hits), window)
        return []

    def observe(self, rec: dict) -> list:
        name = rec.get("event")
        if name == "alert.raised":
            return []
        now = time.time()
        alerts: list = []
        with self.lock:
            if name == "http.access":
                status = int(rec.get("status") or 0)
                self.requests_total += 1
                self.by_status[f"{status // 100}xx"] += 1
                self.by_route[str(rec.get("route", "-"))] += 1
                if isinstance(rec.get("ms"), (int, float)):
                    self.latencies.append(float(rec["ms"]))
                if status in (401, 403, 429):
                    self.denied[str(status)] += 1
                self.window5.append((now, status, False))
                if status == 404:
                    alerts += self._hit("http.scan_404", str(rec.get("ip", "-")), now, 20, 60, "warning")
                if status == 403:
                    who = str(rec.get("client_id") or rec.get("ip", "-"))
                    alerts += self._hit("authz.denied_burst", who, now, 10, 60, "warning")
                if status >= 500:
                    alerts += self._hit("http.error_burst", "*", now, 5, 60, "critical")
            elif name == "auth.denied" and rec.get("failure"):
                self.auth_failures_total += 1
                self.window5.append((now, 0, True))
                alerts += self._hit("auth.bruteforce_ip", str(rec.get("ip", "-")), now, 10, 60, "warning")
                if rec.get("client_locked_s"):
                    alerts += self._fire("auth.lockout", str(rec.get("client_id_attempt", "-")), now,
                                         "warning", 1, 0)
            elif name == "auth.token_issued":
                self.tokens_issued_total += 1
            elif name == "tls.handshake_failed":
                alerts += self._hit("tls.handshake_burst", "*", now, 20, 60, "warning")
            while self.window5 and self.window5[0][0] < now - 300:
                self.window5.popleft()
            if len(self.windows) > 5000:                      # межа пам'яті на випадок сканування
                for key in [k for k, v in self.windows.items() if not v or v[-1] < now - 60]:
                    del self.windows[key]
        return alerts

    def snapshot(self) -> dict:
        with self.lock:
            lat = sorted(self.latencies)

            def pct(p: float) -> float:
                return round(lat[min(len(lat) - 1, int(p * len(lat)))], 1) if lat else 0.0

            return {
                "uptime_s": int(time.time() - self.started),
                "requests_total": self.requests_total,
                "by_status": dict(self.by_status),
                "by_route": dict(self.by_route.most_common(15)),
                "denied": dict(self.denied),
                "auth_failures_total": self.auth_failures_total,
                "tokens_issued_total": self.tokens_issued_total,
                "latency_ms": {"p50": pct(0.50), "p95": pct(0.95), "max": round(lat[-1], 1) if lat else 0.0,
                               "samples": len(lat)},
                "window_5m": {"requests": sum(1 for _, s, a in self.window5 if not a),
                              "errors_5xx": sum(1 for _, s, a in self.window5 if s >= 500),
                              "auth_failures": sum(1 for _, s, a in self.window5 if a)},
                "alerts_total": self.alerts_total,
                "alerts_recent": list(self.alerts),
            }


_MONITOR = _Monitor()


# --- публічний API ---------------------------------------------------------------
def setup(cfg, console: bool = True, component: str = "drs_hub") -> None:
    """Налаштувати журнали теки даних. component="drs_hub.admin" → власні файли hub-admin/security-admin."""
    shutdown()
    _STATE["component"] = component
    _STATE["version"] = hub_config.HUB_VERSION
    suffix = "" if component == "drs_hub" else "-" + component.split(".")[-1]
    os.makedirs(cfg.log_dir, exist_ok=True)
    level = _LEVELS.get(cfg.log_level, logging.INFO)
    _LOGGER.setLevel(logging.DEBUG)       # фільтрують обробники: безпековий журнал завжди отримує INFO+
    _LOGGER.propagate = False
    general = DailyJsonHandler(cfg.log_dir, "hub" + suffix, GENERAL_RETENTION_DAYS)
    general.setLevel(level)
    security = DailyJsonHandler(cfg.log_dir, "security" + suffix, SECURITY_RETENTION_DAYS,
                                chained=True, security_only=True)
    security.setLevel(logging.INFO)
    _LOGGER.addHandler(general)
    _LOGGER.addHandler(security)
    if console:
        stream = ConsoleHandler()
        stream.setLevel(level)
        _LOGGER.addHandler(stream)
    _MONITOR.reset()


def shutdown() -> None:
    for handler in list(_LOGGER.handlers):
        handler.close()
        _LOGGER.removeHandler(handler)


def event(level: str, name: str, **fields) -> None:
    """Одна подія. Поля зі значенням None не пишуться; чутливе редагується (redact)."""
    lvl = _LEVELS.get(level, logging.INFO)
    rec = build_record(time.time(), logging.getLevelName(lvl), name, fields)
    _LOGGER.log(lvl, name, extra={"drs": rec})
    for alert in _MONITOR.observe(rec):
        alert_level = alert.pop("level")
        event(alert_level, "alert.raised", **alert)


def access(**fields) -> None:
    event("info", "http.access", **fields)


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def metrics_snapshot() -> dict:
    snap = _MONITOR.snapshot()
    snap["version"] = _STATE["version"]
    return snap


def verify_log_file(path: str) -> tuple[bool, list[str], int]:
    """Перевірити файл журналу: валідний JSON, обов'язкові поля, немає секретів; для security-* — ланцюг."""
    problems: list[str] = []
    chained = os.path.basename(path).startswith("security")
    prev = ZERO_CHAIN
    count = 0
    with open(path, "r", encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            count += 1
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                problems.append(f"рядок {number}: схоже на секрет або токен")
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"рядок {number}: не JSON")
                continue
            missing = [f for f in ("ts", "level", "event") if f not in rec]
            if missing:
                problems.append(f"рядок {number}: бракує полів {missing}")
            if chained:
                chain = rec.pop("chain", None)
                if rec.get("chain_restart"):
                    prev = rec.get("prev", ZERO_CHAIN)
                    problems.append(f"рядок {number}: позначений перезапуск ланцюга (chain_restart)")
                expected = hashlib.sha256((rec.get("prev", "") + _canonical(rec)).encode("utf-8")).hexdigest()
                if rec.get("prev") != prev or chain != expected:
                    problems.append(f"рядок {number}: ланцюг SHA-256 розірвано (рядок змінено, видалено чи вставлено)")
                    prev = chain or ZERO_CHAIN
                else:
                    prev = chain
    return not problems, problems, count
