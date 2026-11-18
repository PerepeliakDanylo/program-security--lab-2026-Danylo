"""drs_hub — налаштування службового сервера супроводжувача (версія ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_config.py

Тут — лише НЕсекретні параметри (адреса, порт, строки дії, межі) і шляхи до даних. Секрети (ключ TLS
сервера, база з верифікаторами секретів клієнтів) лежать у теці даних ПОЗА репозиторієм:
%USERPROFILE%\\.drs_hub або шлях зі змінної DRS_HUB_DATA. Тека даних усередині робочого дерева git
відхиляється (path_inside_git_worktree) — так база й ключ не потраплять у коміт випадково.

Файл hub.json у теці даних перевизначає значення за замовчуванням; невідомі ключі ігноруються з
попередженням, а значення поза межами — відхиляються (HubConfigError), а не обрізаються мовчки.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, fields

HUB_VERSION = "0.1.0"          # 0.1.0 — ЛР10–11

DEFAULT_HOST = "127.0.0.1"     # лише локальний інтерфейс: зовнішній доступ — свідоме рішення власника
DEFAULT_PORT = 8443
CONFIG_NAME = "hub.json"
DB_NAME = "drs_hub.db"
LOCK_NAME = "server.lock"


class HubConfigError(ValueError):
    """Неприйнятне значення налаштування або небезпечний шлях до даних."""


def safe_console() -> None:
    """Вивід кирилиці й символів «→ ≠ ≥» не повинен падати, коли stdout — канал (pipe) з кодуванням
    cp1251/cp1252 (Windows): незображуваний символ замінюється, а не зупиняє програму. Повне
    відображення — з PYTHONIOENCODING=utf-8 і UTF-8 у консолі."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def default_data_dir() -> str:
    env = os.environ.get("DRS_HUB_DATA", "").strip()
    if env:
        return os.path.abspath(env)
    base = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    return os.path.join(base, ".drs_hub")


def path_inside_git_worktree(path: str) -> bool:
    """True, якщо path лежить усередині робочого дерева git (є .git у ньому чи в батьківській теці)."""
    current = os.path.abspath(path)
    while True:
        if os.path.exists(os.path.join(current, ".git")):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


# Межі значень: (мінімум, максимум). Межа — не «рекомендація», а умова запуску.
_LIMITS = {
    "port": (0, 65535),                 # 0 — випадковий вільний порт (лише самотест)
    "token_ttl_s": (60, 3600),          # токен доступу: від 1 хв до 1 год (за замовчуванням 10 хв)
    "max_body_bytes": (1024, 4 * 1024 * 1024),
    "lockout_threshold": (3, 20),
    "lockout_base_s": (30, 3600),
    "lockout_max_s": (60, 86400),
    "ip_fail_window_s": (60, 3600),
    "ip_fail_limit": (5, 1000),
    "request_timeout_s": (2, 120),
}


@dataclass
class HubConfig:
    data_dir: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    token_ttl_s: int = 600            # короткий строк дії: украдений токен живе ≤ 10 хв
    max_body_bytes: int = 64 * 1024   # типова межа тіла запиту; маршрут може задати власну
    insecure_http: bool = False       # HTTP без TLS — лише для loopback і лише явним прапорцем
    lockout_threshold: int = 5        # невдалих автентифікацій клієнта поспіль до блокування
    lockout_base_s: int = 300         # перше блокування 5 хв, далі подвоєння (як FR-71)…
    lockout_max_s: int = 3600         # …до 60 хв
    ip_fail_window_s: int = 600       # вікно підрахунку невдач з однієї адреси
    ip_fail_limit: int = 20           # невдач з адреси у вікні до тимчасової відмови (password spraying)
    request_timeout_s: int = 15       # тайм-аут читання запиту (повільні клієнти не тримають потік)
    log_level: str = "info"

    # --- шляхи (похідні, не зберігаються в hub.json) -------------------------
    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, DB_NAME)

    @property
    def tls_dir(self) -> str:
        return os.path.join(self.data_dir, "tls")

    @property
    def ca_path(self) -> str:
        return os.path.join(self.tls_dir, "ca_cert.pem")

    @property
    def cert_path(self) -> str:
        return os.path.join(self.tls_dir, "server_cert.pem")

    @property
    def key_path(self) -> str:
        return os.path.join(self.tls_dir, "server_key.pem")

    @property
    def log_dir(self) -> str:
        return os.path.join(self.data_dir, "logs")

    @property
    def config_path(self) -> str:
        return os.path.join(self.data_dir, CONFIG_NAME)

    @property
    def lock_path(self) -> str:
        return os.path.join(self.data_dir, LOCK_NAME)

    def validate(self) -> None:
        if not isinstance(self.host, str) or not self.host.strip():
            raise HubConfigError("host має бути непорожнім рядком (напр. 127.0.0.1)")
        for name, (low, high) in _LIMITS.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
                raise HubConfigError(f"{name}={value!r} поза межами [{low}, {high}]")
        if self.lockout_max_s < self.lockout_base_s:
            raise HubConfigError("lockout_max_s менше за lockout_base_s")
        if self.log_level not in ("debug", "info", "warning", "error"):
            raise HubConfigError(f"log_level={self.log_level!r}: debug | info | warning | error")
        if not isinstance(self.insecure_http, bool):
            raise HubConfigError("insecure_http має бути true/false")


_SAVED_FIELDS = tuple(f.name for f in fields(HubConfig) if f.name != "data_dir")


def load_config(data_dir: str | None = None) -> HubConfig:
    """Значення за замовчуванням + hub.json з теки даних (якщо є)."""
    cfg = HubConfig(data_dir=os.path.abspath(data_dir or default_data_dir()))
    if os.path.exists(cfg.config_path):
        with open(cfg.config_path, "r", encoding="utf-8-sig") as fh:    # -sig: BOM після Блокнота/PowerShell 5.1
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raise HubConfigError(f"{cfg.config_path}: очікувався об'єкт JSON")
        for key, value in raw.items():
            if key in _SAVED_FIELDS:
                setattr(cfg, key, value)
            else:
                print(f"[drs_hub] попередження: невідомий ключ {key!r} у {CONFIG_NAME} пропущено",
                      file=sys.stderr)
    cfg.validate()
    return cfg


def save_config(cfg: HubConfig) -> None:
    cfg.validate()
    data = {k: v for k, v in asdict(cfg).items() if k in _SAVED_FIELDS}
    os.makedirs(cfg.data_dir, exist_ok=True)
    tmp = cfg.config_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, cfg.config_path)


class DataDirLock:
    """Виключне блокування теки даних на час роботи сервера (і відновлення з копії).

    Ознака «сервер працює» — не PID у файлі (на Windows перевірка PID через os.kill небезпечна),
    а блокування самого файла ОС: воно знімається автоматично, навіть якщо процес аварійно завершився.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = None

    def acquire(self) -> bool:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fh = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            return False
        fh.seek(0)
        fh.truncate()
        fh.write(f"pid={os.getpid()}\n".encode("ascii"))
        fh.flush()
        self._fh = fh
        return True

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        self._fh.close()
        self._fh = None
