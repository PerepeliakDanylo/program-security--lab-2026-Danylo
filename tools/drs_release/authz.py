"""drs_release / authz.py — керування доступом: RBAC + ABAC + DAC (ЛР5; доповнено в ЛР6, ЛР8).

Призначення цільового файлу в репозиторії: tools/drs_release/authz.py
Ця версія ЗАМІНЮЄ версію ЛР6. Зміни ЛР8:
  * `make-passport` — формування й підпис паспорта релізу — додано до ролі `maintainer` і до
    критичних операцій (як і `sign`): це випуск, що вимагає свіжого підтвердження;
  * `check-passport` — перевірка паспорта — додано до `viewer` (як `verify`): лише читання.
Зміна ЛР6: `enroll-totp` у `viewer` і в `CRITICAL`.

Політика **вкомпільована** у код і не розширюється з конфігурації. Рішення приймає authorize(),
яку кожен обробник команди викликає **безпосередньо перед** виконанням операції. Модель змішана:

  RBAC — роль визначає набір дозволених операцій (viewer ⊂ contributor ⊂ maintainer ⊂ owner).
  ABAC — умови на атрибутах ресурсу й контексту: sign/make-passport лише для «чистого master»;
         критичні операції потребують «свіжого» підтвердження (step-up).
  DAC  — пароль (passwd) може міняти ВЛАСНИК свого запису; чужі — лише owner. enroll-totp діє
         лише на власний запис.

У разі відмови користувачеві — загальне «Операцію відхилено»; причина — лише в журнал аудиту.
"""

from __future__ import annotations

from dataclasses import dataclass

# Ролі за зростанням привілеїв. Вища роль успадковує дозволи нижчих.
ROLES = ["viewer", "contributor", "maintainer", "owner"]

# Базові набори RBAC (лише «власні» дозволи рівня; успадкування додає нижні рівні).
_BASE: dict[str, set[str]] = {
    "viewer":      {"help", "whoami", "status", "list-users", "verify", "check-passport", "enroll-totp"},
    "contributor": {"build-manifest"},
    "maintainer":  {"sign", "make-passport"},
    "owner":       {"add-user", "set-role", "rotate-key"},
}

# passwd не входить до RBAC-наборів: це DAC-операція (див. authorize).
# Операції, що потребують свіжого step-up (повторного підтвердження).
CRITICAL = {"sign", "make-passport", "rotate-key", "add-user", "set-role", "passwd", "enroll-totp"}
# Операції, які вимагають «чистого master» (ABAC): випуск підписаних артефактів.
CLEAN_MASTER = {"sign", "make-passport"}
STEPUP_WINDOW_S = 5 * 60   # «свіжість» підтвердження для критичних операцій


def role_level(roles: list[str]) -> int:
    return max((ROLES.index(r) for r in roles if r in ROLES), default=-1)


def permissions_for(roles: list[str]) -> set[str]:
    """Усі дозволи, доступні за найвищою роллю (з успадкуванням нижчих рівнів)."""
    top = role_level(roles)
    perms: set[str] = set()
    for i in range(top + 1):
        perms |= _BASE[ROLES[i]]
    return perms


@dataclass
class Decision:
    allow: bool
    reason: str   # ok / rbac / abac-dirty / not-owner / stepup-required


def authorize(roles: list[str], operation: str, *,
              target_user: str | None = None, current_user: str = "",
              resource: dict | None = None,
              session_stepup_age: float = 0.0) -> Decision:
    """Єдина точка рішення. reason='stepup-required' — не остаточна відмова, а сигнал
    обробнику виконати повторне підтвердження й спитати ще раз."""
    resource = resource or {}

    # --- DAC: зміна пароля --------------------------------------------------
    if operation == "passwd":
        tgt = target_user or current_user
        if tgt != current_user and "owner" not in roles:
            return Decision(False, "not-owner")
    else:
        # --- RBAC ------------------------------------------------------------
        if operation not in permissions_for(roles):
            return Decision(False, "rbac")

    # --- ABAC: випуск підписаних артефактів лише для чистого master ----------
    if operation in CLEAN_MASTER:
        if resource.get("branch") != "master" or resource.get("dirty", True):
            return Decision(False, "abac-dirty")

    # --- ABAC: свіжість підтвердження для критичних операцій ----------------
    if operation in CRITICAL and session_stepup_age > STEPUP_WINDOW_S:
        return Decision(False, "stepup-required")

    return Decision(True, "ok")
