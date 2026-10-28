"""drs_release / authz.py — керування доступом (ЛР5): RBAC + ABAC + DAC.

Призначення цільового файлу в репозиторії: tools/drs_release/authz.py

Політика **вкомпільована** у код і не розширюється з конфігурації — так її не можна
послабити ззовні. Рішення приймається у функції authorize(), яку кожен обробник
команди викликає **безпосередньо перед** виконанням операції (а не ховаючи пункт
меню). Модель змішана, як дозволяє методичка:

  RBAC — базовий рівень: роль визначає набір дозволених операцій (з успадкуванням
         viewer ⊂ contributor ⊂ maintainer ⊂ owner, принцип найменших привілеїв).
  ABAC — умови на атрибутах ресурсу й контексту понад роль:
         * sign дозволено лише для «чистого master» (атрибут релізу dirty=False,
           branch=master) — не можна підписати брудну/не-master збірку;
         * критичні операції потребують «свіжого» підтвердження (step-up): якщо від
           останнього введення пароля минуло більше вікна — потрібне повторне.
  DAC  — дискреційний елемент: пароль (passwd) може міняти ВЛАСНИК свого запису;
         чужі записи — лише роль owner.

Користувачеві у разі відмови повертається **загальне** «Операцію відхилено»; точна
причина (rbac/abac-dirty/not-owner/stepup) пишеться лише в журнал аудиту.
"""

from __future__ import annotations

from dataclasses import dataclass

# Ролі за зростанням привілеїв. Вища роль успадковує дозволи нижчих.
ROLES = ["viewer", "contributor", "maintainer", "owner"]

# Базові набори RBAC (лише «власні» дозволи рівня; успадкування додає нижні рівні).
_BASE: dict[str, set[str]] = {
    "viewer":      {"help", "whoami", "status", "list-users", "verify"},
    "contributor": {"build-manifest"},
    "maintainer":  {"sign"},
    "owner":       {"add-user", "set-role", "rotate-key"},
}

# passwd не входить до RBAC-наборів: це DAC-операція (див. authorize).
# Операції, що потребують свіжого step-up (повторного підтвердження).
CRITICAL = {"sign", "rotate-key", "add-user", "set-role", "passwd"}
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
    """Єдина точка рішення. Повертає Decision; reason='stepup-required' — це не
    остаточна відмова, а сигнал обробнику виконати повторне підтвердження й
    спитати ще раз."""
    resource = resource or {}

    # --- DAC: зміна пароля --------------------------------------------------
    if operation == "passwd":
        tgt = target_user or current_user
        if tgt != current_user and "owner" not in roles:
            return Decision(False, "not-owner")
        # критична → нижче перевіримо step-up
    else:
        # --- RBAC ------------------------------------------------------------
        if operation not in permissions_for(roles):
            return Decision(False, "rbac")

    # --- ABAC: підпис лише чистого master -----------------------------------
    if operation == "sign":
        if resource.get("branch") != "master" or resource.get("dirty", True):
            return Decision(False, "abac-dirty")

    # --- ABAC: свіжість підтвердження для критичних операцій ----------------
    if operation in CRITICAL and session_stepup_age > STEPUP_WINDOW_S:
        return Decision(False, "stepup-required")

    return Decision(True, "ok")
