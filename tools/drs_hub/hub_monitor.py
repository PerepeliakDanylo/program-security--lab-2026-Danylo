"""drs_hub — аналіз журналів і базовий моніторинг (версія ЛР12).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_monitor.py

    python hub_monitor.py summary [--day YYYY-MM-DD]   зведення за добу: статуси, маршрути, джерела відмов,
                                                       невдалі автентифікації, затримка, сповіщення, помилки
    python hub_monitor.py trace <request_id>           усі події одного запиту з усіх журналів (кореляція)
    python hub_monitor.py verify                       кожен файл: JSON, обов'язкові поля, немає секретів;
                                                       security-*: ланцюг SHA-256 (код 1 — якщо є порушення)
    python hub_monitor.py metrics [--watch N --interval S] --client-id ID --secret-file F
                                                       показники живого сервера (/api/v1/metrics, скоуп
                                                       metrics:read) з порогами «УВАГА»/«КРИТИЧНО»

Читає лише теку журналів (`--data-dir`, типово %USERPROFILE%\\.drs_hub); нічого не змінює.
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import os
import re
import sys
import time

import hub_config
import hub_log

_FILE_RE = re.compile(r"^(hub|security)(-[a-z]+)?-(\d{4}-\d{2}-\d{2})\.jsonl$")

# Пороги моніторингу «живого» сервера (вікно — останні 5 хв).
WARN_AUTH_FAILURES_5M = 10
WARN_P95_MS = 500.0


def _log_files(log_dir: str, kind: str | None = None, day: str | None = None) -> list[str]:
    result = []
    if not os.path.isdir(log_dir):
        return result
    for name in sorted(os.listdir(log_dir)):
        found = _FILE_RE.match(name)
        if not found:
            continue
        if kind and found.group(1) != kind:
            continue
        if day and found.group(3) != day:
            continue
        result.append(os.path.join(log_dir, name))
    return result


def _records(paths: list[str]):
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    yield path, number, json.loads(line)
                except json.JSONDecodeError:
                    continue


def cmd_summary(cfg, args) -> int:
    day = args.day or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    paths = _log_files(cfg.log_dir, "hub", day)
    if not paths:
        print(f"Журналів за {day} у {cfg.log_dir} немає.")
        return 1
    status = collections.Counter()
    routes = collections.Counter()
    deny_ip = collections.Counter()
    fail_reason = collections.Counter()
    fail_client = collections.Counter()
    levels = collections.Counter()
    latencies: list[float] = []
    errors: list[str] = []
    alerts: list[str] = []
    for _path, _n, rec in _records(paths):
        levels[rec.get("level", "?")] += 1
        name = rec.get("event")
        if name == "http.access":
            code = int(rec.get("status") or 0)
            status[code] += 1
            routes[rec.get("route", "-")] += 1
            if code in (401, 403, 404, 429):
                deny_ip[(rec.get("ip", "-"), code)] += 1
            if isinstance(rec.get("ms"), (int, float)):
                latencies.append(float(rec["ms"]))
        elif name == "auth.denied" and rec.get("failure"):
            fail_reason[rec.get("reason", "-")] += 1
            fail_client[rec.get("client_id_attempt", "-")] += 1
        elif name == "alert.raised":
            alerts.append(f"{rec['ts']} {rec['level']} {rec.get('rule')} subject={rec.get('subject')} "
                          f"count={rec.get('count')}")
        if rec.get("level") in ("ERROR", "CRITICAL"):
            errors.append(f"{rec['ts']} {rec['level']} {name} request_id={rec.get('request_id', '-')}")
    latencies.sort()
    p95 = latencies[min(len(latencies) - 1, int(0.95 * len(latencies)))] if latencies else 0.0
    print(f"Зведення за {day} ({len(paths)} файл(и)): подій {sum(levels.values())} — "
          + ", ".join(f"{k} {v}" for k, v in sorted(levels.items())))
    print(f"Запитів: {sum(status.values())}; статуси: "
          + ", ".join(f"{k}×{v}" for k, v in sorted(status.items())))
    print(f"Затримка: медіана {latencies[len(latencies) // 2] if latencies else 0:.1f} мс, p95 {p95:.1f} мс")
    print("Маршрути (топ 8): " + ", ".join(f"{k} {v}" for k, v in routes.most_common(8)))
    print("Відмови за адресою (топ 5): "
          + (", ".join(f"{ip} → {code}×{n}" for (ip, code), n in deny_ip.most_common(5)) or "немає"))
    print("Невдалі автентифікації: "
          + (", ".join(f"{k} {v}" for k, v in fail_reason.items()) or "немає")
          + ("; клієнти: " + ", ".join(f"{k}×{v}" for k, v in fail_client.most_common(5)) if fail_client else ""))
    print("Сповіщення:" + ("\n  " + "\n  ".join(alerts) if alerts else " немає"))
    print("Помилки ERROR/CRITICAL:" + ("\n  " + "\n  ".join(errors[-10:]) if errors else " немає"))
    return 0


def cmd_trace(cfg, args) -> int:
    found = [(rec["ts"], os.path.basename(path), rec) for path, _n, rec in _records(_log_files(cfg.log_dir))
             if rec.get("request_id") == args.request_id]
    if not found:
        print(f"Подій із request_id={args.request_id} немає.")
        return 1
    for ts, name, rec in sorted(found, key=lambda item: item[0]):
        extra = " ".join(f"{k}={v}" for k, v in rec.items()
                         if k not in ("ts", "level", "event", "component", "version", "host", "pid",
                                      "request_id", "prev", "chain"))
        print(f"{ts} [{name}] {rec['level']} {rec['event']} {extra}")
    return 0


def cmd_verify(cfg, args) -> int:
    paths = _log_files(cfg.log_dir)
    if not paths:
        print(f"Журналів у {cfg.log_dir} немає.")
        return 1
    bad = 0
    for path in paths:
        ok, problems, count = hub_log.verify_log_file(path)
        label = "ланцюг SHA-256 цілий, " if os.path.basename(path).startswith("security") and ok else ""
        print(f"{'OK  ' if ok else 'FAIL'} {os.path.basename(path)}: {count} запис(ів); "
              + (label + "секретів немає" if ok else "; ".join(problems[:5])))
        bad += 0 if ok else 1
    print("Журнали цілі." if not bad else f"Порушень у файлах: {bad}.")
    return 0 if not bad else 1


def cmd_metrics(cfg, args) -> int:
    from hub_client import HubClient   # клієнт потрібен лише для цієї команди
    secret = None
    if args.secret_file:
        with open(args.secret_file, "r", encoding="utf-8-sig") as fh:
            secret = fh.readline().strip()
    secret = secret or os.environ.get("DRS_HUB_CLIENT_SECRET")
    client = HubClient(args.url, ca_file=args.ca or cfg.ca_path, client_id=args.client_id,
                       client_secret=secret, scope="metrics:read")
    rounds = max(1, args.watch)
    for index in range(rounds):
        status, snap = client.call("GET", "/api/v1/metrics")
        if status != 200:
            print(f"HTTP {status}: {snap}")
            return 1
        if index == 0 and rounds == 1:
            print(json.dumps(snap, ensure_ascii=False, indent=2))
        window = snap["window_5m"]
        marks = []
        if window["errors_5xx"] > 0:
            marks.append(f"УВАГА: 5xx за 5 хв = {window['errors_5xx']}")
        if window["auth_failures"] >= WARN_AUTH_FAILURES_5M:
            marks.append(f"УВАГА: невдалих автентифікацій за 5 хв = {window['auth_failures']}")
        if snap["latency_ms"]["p95"] > WARN_P95_MS:
            marks.append(f"УВАГА: p95 = {snap['latency_ms']['p95']} мс")
        if snap["db"]["integrity"] != "ok":
            marks.append(f"КРИТИЧНО: integrity_check = {snap['db']['integrity']}")
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%SZ")
        print(f"{stamp} up {snap['uptime_s']} с | запитів {snap['requests_total']} | 5 хв: {window['requests']} "
              f"запитів, 5xx {window['errors_5xx']}, невдач автентифікації {window['auth_failures']} | "
              f"p95 {snap['latency_ms']['p95']} мс | сповіщень {snap['alerts_total']} | "
              + ("; ".join(marks) if marks else "стан у нормі"))
        if index + 1 < rounds:
            time.sleep(max(1, args.interval))
    return 0


def main(argv: list[str] | None = None) -> int:
    hub_config.safe_console()
    parser = argparse.ArgumentParser(prog="hub_monitor", description="DRS Hub — аналіз журналів і моніторинг.")
    parser.add_argument("--data-dir", default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    summary = sub.add_parser("summary", help="зведення журналу за добу")
    summary.add_argument("--day", default=None)
    trace = sub.add_parser("trace", help="усі події одного запиту")
    trace.add_argument("request_id")
    sub.add_parser("verify", help="перевірити журнали (JSON, секрети, ланцюг SHA-256)")
    metrics = sub.add_parser("metrics", help="показники живого сервера")
    metrics.add_argument("--url", default=os.environ.get("DRS_HUB_URL", "https://127.0.0.1:8443"))
    metrics.add_argument("--ca", default=os.environ.get("DRS_HUB_CA"))
    metrics.add_argument("--client-id", default=os.environ.get("DRS_HUB_CLIENT_ID"), required=False)
    metrics.add_argument("--secret-file", default=None)
    metrics.add_argument("--watch", type=int, default=1, help="скільки разів опитати")
    metrics.add_argument("--interval", type=int, default=30, help="інтервал опитування, с")
    args = parser.parse_args(argv)
    try:
        cfg = hub_config.load_config(args.data_dir)
        handlers = {"summary": cmd_summary, "trace": cmd_trace, "verify": cmd_verify, "metrics": cmd_metrics}
        return handlers[args.command](cfg, args)
    except Exception as exc:  # noqa: BLE001 — CLI: показати причину, а не стек
        print(f"Помилка: {type(exc).__name__}: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
