# YMT Reload Tweaker v5

Офлайн-препроцесор метафайлу `weapons.ymt` для Red Dead Redemption 2.
Скрипт задає «повільний» профіль перезарядки зброї для стану поза боєм.

## Що робить скрипт

Читає XML-дамп `weapons.ymt`, перераховує та змінює **три поля** кожного
профілю зброї:

| Поле | Де у YMT | Ефект |
|---|---|---|
| `AnimReloadRate` | `CWeaponInfo / WeaponReload` | загальна швидкість анімації перезарядки |
| `LoopRate` | `CSectionedReloadInfo / * / LoopRate` | швидкість циклу вставляння набоїв |
| `TimeBetweenBulletsInLoop` | `CSectionedReloadInfo / * / TimeBetweenBulletsInLoop` | пауза між набоями (секунди) |

Нові значення розраховуються з реальних ігрових замірів
(`rdr2_reload_measurements_v5.csv`) за моделлю `coupled`, підтвердженою
вимірюваннями у грі.

## Приклади запуску

```bash
# Калібрування: тільки показати арифметику розрахунку, нічого не писати
python rdr2_reload_tweaker-v5.py --calibrate

# Звіт: прочитати оригінальний YMT, згенерувати INI і CSV, не змінювати файл
python rdr2_reload_tweaker-v5.py weapons_ORIGINAL.ymt --report-only

# Повний прогін: патч YMT + CSV + INI
python rdr2_reload_tweaker-v5.py weapons.ymt weapons_reloaded.ymt
```

## Застереження

> **`Combat_*` значення в згенерованому INI коректні лише тоді, коли скрипт
> запущено на **оригінальному** (стоковому) `weapons.ymt`.**
>
> Якщо вхідний файл уже оброблений попередньою версією скрипту, «бойові»
> значення будуть неправильними — скрипт попередить про це і залишить їх
> закоментованими.

## Файли

- `rdr2_reload_tweaker-v5.py` — основний скрипт (Python 3, стандартна бібліотека).
- `rdr2_reload_measurements_v5.csv` — таблиця ігрових замірів часу перезарядки.
