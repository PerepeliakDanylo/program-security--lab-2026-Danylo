#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RDR2 Weapons Reload Tweaker v5.0.1
==================================
Розвиток v4.0. Головна зміна: значення більше не «на око» — вони рахуються
з ваших реальних замірів у грі.

ПАТЧ 5.0.1 (2026-09-21, після прогону в грі). Результатів не змінює:
  - Прибрано два DeprecationWarning: `direct_child(...) or find_first(...)`
    покладалося на істинність елемента ElementTree. Порожній елемент там
    falsy, тож перша гілка ніколи не спрацьовувала, а в майбутніх версіях
    Python поведінка стане протилежною. Тепер порівняння з None.
  - Виправлено напрямок правила в шапці згенерованого INI: менший
    AnimReloadRate = повільніше, тому множник анімації обернений до s.
  - МОДЕЛЬ ТЕМПІВ ПІДТВЕРДЖЕНО В ГРІ: цільові 18.0 с для Вармінта дали
    ≈18 с. Модель `coupled` остаточна, --rate-model independent більше
    не потрібен (лишений як аварійний).

ЩО НОВОГО ПРОТИ v4:

  1. КАЛІБРУВАННЯ ЗА ЗАМІРАМИ. Таблиця MEASUREMENTS містить ваші заміри
     (повна розрядка / один набій) разом із значеннями, що стояли у ymt під
     час заміру. Задаєте лише ОДНЕ число — target_full_s, бажаний час повної
     перезарядки, — решта рахується. `--calibrate` друкує всю арифметику.

  2. ВИПРАВЛЕНО ІМ'Я ПРОФІЛЮ КАРКАНО. У v4 стояло 'SNIPERRIFLE_CARCANO'.
     У файлі профіль називається 'SNIPER_CARCANO' — v4 його ніколи не знаходив.

  3. РОЗПІЗНАВАННЯ ХЕШОВАНИХ ІМЕН. У weapons.ymt частина Item має ім'я виду
     <Name>0xD06705B5</Name>. v5 рахує joaat по словнику кандидатів і показує,
     який це насправді профіль. Конфіг може цілитись і в хеш.

  4. МОДЕЛЬ ЧАСУ ПЕРЕЗАРЯДКИ + ПРОГНОЗ. Скрипт друкує, скільки секунд має
     зайняти перезарядка після зміни, за двома можливими моделями рушія
     (див. RATE_MODEL). Один заміру після прогону — і модель зафіксована.

  5. ЗАХИСТ INI ВІД «ПОВІЛЬНОГО COMBAT». Якщо вхідний файл уже оброблений,
     v5 більше не пише у Combat_* повільні значення (v4 лише попереджав),
     а лишає їх закоментованими. Обійти: --force-ini.

  6. СТВОЛИ, ЯКИХ НЕМАЄ У ФАЙЛІ (Ле-Ма, Флотський, M1899, Еванс, Слонобій)
     винесені в окрему таблицю ABSENT_IN_YMT. Їх неможливо сповільнити через
     weapons.ymt — лише плагіном. Їхні секції все одно потрапляють в INI.

Використання:
  python rdr2_reload_tweaker-v5.py [вхід] [вихід]
        [--report-only] [--calibrate] [--ini PATH] [--csv PATH]
        [--no-ini] [--no-csv] [--force-ini] [--rate-model coupled|independent]

Типові сценарії:
  python rdr2_reload_tweaker-v5.py --calibrate
        нічого не читає й не пише, лише показує розрахунок значень із замірів.
  python rdr2_reload_tweaker-v5.py weapons_ORIGINAL.ymt --report-only
        звіт + INI з правильними Combat_* (вимагає НЕобробленого файлу).
  python rdr2_reload_tweaker-v5.py weapons.ymt weapons_reloaded.ymt
        робочий ymt + CSV + INI.
"""

import csv
import os
import re
import sys
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# МОДЕЛЬ ЧАСУ ПЕРЕЗАРЯДКИ
# ---------------------------------------------------------------------------
# Час повної перезарядки розкладається на три доданки:
#
#   T = A/r  +  N * L/(lr * r^k)  +  N * tb
#       ^         ^                   ^
#       вхід      цикл вставляння     фіксована пауза між набоями
#       і вихід   одного набою        (секунди, темпом не масштабується)
#
#   r  = CWeaponInfo/WeaponReload/AnimReloadRate
#   lr = CSectionedReloadInfo/*/LoopRate
#   tb = CSectionedReloadInfo/*/TimeBetweenBulletsInLoop
#   N  = скільки набоїв заряджається,  A, L = «внутрішні» тривалості анімацій
#
# k = 1  ('coupled')      AnimReloadRate масштабує і цикл теж.
# k = 0  ('independent')  цикл керується лише LoopRate.
#
# Чому за замовчуванням coupled: якщо підставити ваші заміри у формулу й
# перерахувати назад на стокові значення (r=1, lr=1.85, tb=0.10), то
#   обріз       -> 2.26 с   (у грі ~2.3)
#   двостволка  -> 2.32 с   (у грі ~2.4)
#   помпова     -> 4.79 с   (у грі ~4.8)
# Модель independent дає для тих самих замірів 2.9-8.6 с, чого у ваніллі немає.
#
# Наслідок для перерахунку: щоб зробити перезарядку у s разів ПОВІЛЬНІШОЮ
# (s > 1; менший AnimReloadRate = повільніше, тому r ділиться, а не множиться):
#   coupled      -> r' = r / s,  lr' = lr,      tb' = tb * s
#   independent  -> r' = r / s,  lr' = lr / s,  tb' = tb * s
#
# ПІДТВЕРДЖЕНО В ГРІ 2026-09-21: прогін v5 із ціллю 18.0 с для Вармінта дав
# ≈18 с (модель independent прогнозувала ≈23 с). Модель coupled остаточна;
# --rate-model independent лишений тільки як аварійний перемикач.
RATE_MODEL = 'coupled'          # 'coupled' | 'independent'


# ---------------------------------------------------------------------------
# ЗАМІРИ В ГРІ (Rampage Trainer, чиста зброя = GoodCondition)
# ---------------------------------------------------------------------------
#   measured_full_s / measured_one_s — ваші П.р. і О.п. у секундах
#   at             — значення (AnimReloadRate, LoopRate, TimeBetween), які
#                    стояли у ymt у момент заміру; для стволів без конфігу v3
#                    це стокові значення з вашого злитого файлу
#   rounds         — скільки набоїв заряджалося при вимірі П.р. (None = невідомо)
#   verdict        — ваш вердикт дослівно
#   target_full_s  — бажаний час. None = НЕ ЧІПАТИ, лишити як є.
#
# ВАЖЛИВО: усе, що ви позначили «норм», має target_full_s = None і не
# перераховується. Перетюновано рівно чотири позиції.
MEASUREMENTS = {
    'WEAPON_RIFLE_VARMINT': {
        'ua': 'Гвинтівка «Вармінт»',
        'measured_full_s': 23.69,          # середнє з двох заходів: 23.26 і 24.12
        'measured_one_s': 5.91,            # середнє з 5.81 і 6.01
        'at': (0.38, 1.60, 0.20),
        'rounds': 14,
        'verdict': 'все ж повільно; у спокої має бути трішки швидше',
        'target_full_s': 18.0,
    },
    'WEAPON_REPEATER_HENRY': {
        'ua': 'Магазинка «Лічфілд»',
        'measured_full_s': 33.70,
        'measured_one_s': 8.45,
        'at': (0.35, 1.75, 0.25),
        'rounds': 14,
        'verdict': 'вердикту не було; 33.7 с на повну і 8.45 с на один набій — '
                   'викид проти Ланкастера (19.66 с) з майже тим самим конфігом',
        'target_full_s': 20.0,             # ПРОПОЗИЦІЯ: постав None, щоб лишити як було
    },
    'WEAPON_SNIPERRIFLE_ROLLINGBLOCK': {
        'ua': 'Гвинтівка з відкидним затвором',
        'measured_full_s': 2.17,           # однозарядна: П.р. == О.п.
        'measured_one_s': 2.17,
        'at': (1.00, None, None),          # стокова: конфігу v3 не мала
        'rounds': 1,
        'verdict': 'не змінилася по швидкості — треба змінити',
        'target_full_s': 3.50,
    },
    'WEAPON_SNIPERRIFLE_CARCANO': {
        'ua': 'Гвинтівка «Каркано»',
        'measured_full_s': 3.41,
        'measured_one_s': 4.47,
        'at': (0.585, None, None),         # 0.585 — значення оверхолу, не v3
        'rounds': None,                    # обойма, не поштучно
        'verdict': 'трішки пришвидшити — заряджається обоймою, а не по набою',
        'target_full_s': 3.00,
    },

    # --- нижче: заміряно, вердикт «норм» або без зауважень -> НЕ ЧІПАЄМО ---
    'WEAPON_REPEATER_CARBINE': {
        'ua': 'Магазинний карабін', 'measured_full_s': 6.10, 'measured_one_s': 5.84,
        'at': (0.45, 1.80, 0.35), 'rounds': 7,
        'verdict': 'норм, заряджається одразу 7 набоїв', 'target_full_s': None},
    'WEAPON_REPEATER_WINCHESTER': {
        'ua': 'Магазинка «Ланкастер»', 'measured_full_s': 19.66, 'measured_one_s': 3.88,
        'at': (0.36, 1.80, 0.25), 'rounds': 14,
        'verdict': 'без зауважень', 'target_full_s': None},
    'WEAPON_REPEATER_WINCHESTER_JOHN': {
        'ua': 'Ланкастер Джона', 'measured_full_s': 18.15, 'measured_one_s': 3.33,
        'at': (0.36, 1.80, 0.25), 'rounds': 14,
        'verdict': 'без зауважень', 'target_full_s': None},
    'WEAPON_RIFLE_SPRINGFIELD': {
        'ua': 'Гвинтівка «Спрінгфілд»', 'measured_full_s': None, 'measured_one_s': 2.67,
        'at': (0.42, 2.00, 0.20), 'rounds': None,
        'verdict': 'норм', 'target_full_s': None},
    'WEAPON_RIFLE_BOLTACTION': {
        'ua': 'Болтова гвинтівка', 'measured_full_s': 11.20, 'measured_one_s': 6.90,
        'at': (0.45, 1.80, 0.20), 'rounds': 5,
        'verdict': 'подобається — 5 набоїв за 11.20 з передьоргуванням затвора',
        'target_full_s': None},
    'WEAPON_REVOLVER_CATTLEMAN': {
        'ua': 'Ковбойський револьвер', 'measured_full_s': 10.12, 'measured_one_s': 4.37,
        'at': (0.32, 2.00, 0.20), 'rounds': 6,
        'verdict': 'без зауважень', 'target_full_s': None},
    'WEAPON_REVOLVER_SCHOFIELD': {
        'ua': 'Револьвер «Скофілд»', 'measured_full_s': 11.53, 'measured_one_s': 3.90,
        'at': (0.42, 2.00, 0.15), 'rounds': 6,
        'verdict': 'без зауважень', 'target_full_s': None},
    'WEAPON_REVOLVER_DOUBLEACTION': {
        'ua': 'Самозведений револьвер', 'measured_full_s': 8.29, 'measured_one_s': 3.74,
        'at': (0.38, 2.00, 0.15), 'rounds': 6,
        'verdict': 'без зауважень', 'target_full_s': None},
    'WEAPON_PISTOL_VOLCANIC': {
        'ua': 'Пістолет «Волканік»', 'measured_full_s': 11.96, 'measured_one_s': 4.78,
        'at': (0.35, 1.80, 0.28), 'rounds': 7,
        'verdict': 'норм', 'target_full_s': None},
    'WEAPON_PISTOL_MAUSER': {
        'ua': 'Пістолет «Маузер»', 'measured_full_s': 4.30, 'measured_one_s': 4.51,
        'at': (0.48, 2.50, 0.10), 'rounds': None,
        'verdict': 'без зауважень; обойма — О.п. дорівнює П.р., різниця = похибка',
        'target_full_s': None},
    'WEAPON_PISTOL_SEMIAUTO': {
        'ua': 'Напівавтоматичний пістолет', 'measured_full_s': 2.85, 'measured_one_s': 3.29,
        'at': (0.48, 2.50, 0.10), 'rounds': None,
        'verdict': 'без зауважень; магазин', 'target_full_s': None},
    'WEAPON_SHOTGUN_PUMP': {
        'ua': 'Помпова рушниця', 'measured_full_s': 12.55, 'measured_one_s': 4.11,
        'at': (0.40, 1.80, 0.32), 'rounds': 5,
        'verdict': 'без зауважень', 'target_full_s': None},
    'WEAPON_SHOTGUN_REPEATING': {
        'ua': 'Багатозарядна рушниця', 'measured_full_s': 18.11, 'measured_one_s': 5.14,
        'at': (0.40, 1.80, 0.32), 'rounds': 6,
        'verdict': 'без зауважень (але 18.1 с — другий за тривалістю після Лічфілда)',
        'target_full_s': None},
    'WEAPON_SHOTGUN_SEMIAUTO': {
        'ua': 'Напівавтоматична рушниця', 'measured_full_s': 11.01, 'measured_one_s': 3.75,
        'at': (0.42, 2.00, 0.28), 'rounds': 5,
        'verdict': 'без зауважень', 'target_full_s': None},
    'WEAPON_SHOTGUN_DOUBLEBARREL': {
        'ua': 'Рушниця (двостволка)', 'measured_full_s': 4.63, 'measured_one_s': 3.95,
        'at': (0.48, 2.00, 0.15), 'rounds': 2,
        'verdict': 'норм — вставляється лише два дроби', 'target_full_s': None},
    'WEAPON_SHOTGUN_SAWEDOFF': {
        'ua': 'Рушниця-обріз', 'measured_full_s': 4.39, 'measured_one_s': 3.02,
        'at': (0.48, 2.00, 0.15), 'rounds': 2,
        'verdict': 'без зауважень', 'target_full_s': None},
}

# Варіанти, заміряні окремо. Значення беруть із базового ствола за правилом
# «найдовший збіг за префіксом», тому окремого конфігу не потребують —
# таблиця тут лише щоб заміри не загубилися.
VARIANT_MEASUREMENTS = [
    # (заміряна назва, базовий ствол, П.р., О.п.)
    ('Револьвер Джона',            'WEAPON_REVOLVER_CATTLEMAN',    10.02, 4.22),
    ('Револьвер Отіса Міллера',    'WEAPON_REVOLVER_CATTLEMAN',    11.28, 3.87),
    ('Револьвер Ельджернона',      'WEAPON_REVOLVER_CATTLEMAN',     8.26, 3.39),
    ('Револьвер Ґрейнджера',       'WEAPON_REVOLVER_CATTLEMAN',     9.94, 4.45),
    ('Револьвер Гернадзера',       'WEAPON_REVOLVER_CATTLEMAN',     9.95, 4.01),
    ('Револьвер Келоувея',         'WEAPON_REVOLVER_SCHOFIELD',    11.38, 3.72),
    ('Револьвер Міки',             'WEAPON_REVOLVER_DOUBLEACTION',  8.11, 3.64),
    ('Пістолет Вечірнього Білла',  'WEAPON_PISTOL_MAUSER',          3.72, 4.75),
    ('Рідкісна рушниця',           'WEAPON_SHOTGUN_DOUBLEBARREL',   4.35, 4.17),
    ('Рідкісна гвинтівка з відкидним затвором',
     'WEAPON_SNIPERRIFLE_ROLLINGBLOCK', 2.46, 2.46),
    # Не ідентифіковано однозначно: «Револьвер гравця» 3.38 / 1.60.
    # Такий швидкий час означає, що конфіг на нього не діяв. Якщо зустрінете
    # знову — зафіксуйте внутрішню назву через Rampage і допишіть сюди.
]

# Стволи, яких у вашому weapons.ymt НЕМАЄ ВЗАГАЛІ (перевірено пошуком по файлу:
# жодного CWeaponInfo з таким Name). Їх неможливо сповільнити правкою ymt —
# тільки плагіном DynamicReloadSpeed.asi, який патчить пам'ять за хешем імені.
# Заміри зроблені на стокових значеннях (AnimReloadRate = 1.0).
ABSENT_IN_YMT = {
    'WEAPON_REVOLVER_LEMAT': {
        'ua': 'Револьвер «Ле-Ма»', 'measured_full_s': 7.42, 'measured_one_s': 2.02,
        'verdict': 'норм на стоці (дріб окремо: 2.84)',
        'target_full_s': 10.0},                  # ПРОПОЗИЦІЯ
    'WEAPON_REVOLVER_NAVY': {
        'ua': 'Флотський револьвер', 'measured_full_s': 5.56, 'measured_one_s': 2.10,
        'verdict': 'без зауважень', 'target_full_s': 9.0},        # ПРОПОЗИЦІЯ
    'WEAPON_PISTOL_M1899': {
        'ua': 'Пістолет M1899', 'measured_full_s': 1.52, 'measured_one_s': 2.22,
        'verdict': 'без зауважень; магазин', 'target_full_s': 3.0},   # ПРОПОЗИЦІЯ
    'WEAPON_REPEATER_EVANS': {
        'ua': 'Карабін «Еванс»', 'measured_full_s': 13.64, 'measured_one_s': 2.08,
        'verdict': 'нічого не змінилося — його немає у файлі; 26 набоїв',
        'target_full_s': 20.0},                  # ПРОПОЗИЦІЯ
    'WEAPON_RIFLE_ELEPHANT': {
        'ua': 'Слонобій', 'measured_full_s': None, 'measured_one_s': None,
        'verdict': 'не заміряно', 'target_full_s': None},
}


# ---------------------------------------------------------------------------
# КОНФІГ ПЕРЕЗАРЯДКИ (CALM-профіль — те, що пишеться у weapons.ymt)
#   AnimReloadRate     — темп анімації перезарядки (менше = повільніше)
#   TimeBetweenBullets — пауза між набоями при поштучному заряджанні
#   LoopRate           — темп циклу вставляння одного набою
#   SectionedName      — рядок / список / None (не чіпати профіль)
#   SkipSectioned      — True: профіль знайти й показати у звіті, але не міняти
#
# Значення без позначки «v5» дослівно перенесені з v3/v4 — саме з ними
# зроблені заміри, і саме їх ви визнали прийнятними. Не чіпаю.
# ---------------------------------------------------------------------------
RELOAD_CONFIGS = {
    # --- ГВИНТІВКИ ТА МАГАЗИНКИ ---
    'WEAPON_RIFLE_VARMINT': {
        'AnimReloadRate': 0.50,              # v5: було 0.38, 23.69 с -> ціль 18.0 с
        'SectionedName': 'RIFLE_VARMINT',
        'TimeBetweenBullets': 0.15,          # v5: було 0.20
        'LoopRate': 1.60
    },
    'WEAPON_REPEATER_WINCHESTER': {          # Ланкастер
        'AnimReloadRate': 0.36,
        'SectionedName': 'REPEATER_WINCHESTER',
        'TimeBetweenBullets': 0.25,
        'LoopRate': 1.80
    },
    'WEAPON_REPEATER_HENRY': {               # Лічфілд
        'AnimReloadRate': 0.59,              # v5: було 0.35, 33.70 с -> ціль 20.0 с
        'SectionedName': 'REPEATER_HENRY',
        'TimeBetweenBullets': 0.15,          # v5: було 0.25
        'LoopRate': 1.75
    },
    'WEAPON_REPEATER_CARBINE': {
        'AnimReloadRate': 0.45,
        'SectionedName': 'REPEATER_CARBINE',
        'TimeBetweenBullets': 0.35,
        'LoopRate': 1.80
    },
    'WEAPON_RIFLE_BOLTACTION': {
        'AnimReloadRate': 0.45,
        'SectionedName': 'RIFLE_BOLTACTION',
        'TimeBetweenBullets': 0.20,
        'LoopRate': 1.80
    },
    'WEAPON_RIFLE_SPRINGFIELD': {
        'AnimReloadRate': 0.42,
        'SectionedName': 'RIFLE_SPRINGFIELD',
        'TimeBetweenBullets': 0.20,
        'LoopRate': 2.00
    },
    'WEAPON_SNIPERRIFLE_ROLLINGBLOCK': {     # v5: додано (однозарядна, була стокова)
        'AnimReloadRate': 0.62,              # v5: було 1.00, 2.17 с -> ціль 3.50 с
        'SectionedName': None,               # у файлі профілю немає — нічого не чіпаємо
        'TimeBetweenBullets': None,
        'LoopRate': None
    },
    'WEAPON_SNIPERRIFLE_CARCANO': {
        'AnimReloadRate': 0.66,              # v5: було 0.585 (оверхол) -> ціль 3.0 с
        'SectionedName': 'SNIPER_CARCANO',   # v4 мав 'SNIPERRIFLE_CARCANO' — не збігалося
        'SkipSectioned': True,               # обойма; у профілю різні Good/Worn — не чіпаємо
        'TimeBetweenBullets': None,
        'LoopRate': None
    },

    # --- РЕВОЛЬВЕРИ ---
    'WEAPON_REVOLVER_CATTLEMAN': {
        'AnimReloadRate': 0.32,
        'SectionedName': 'REVOLVER_CATTLEMAN',
        'TimeBetweenBullets': 0.20,
        'LoopRate': 2.00
    },
    'WEAPON_REVOLVER_DOUBLEACTION': {
        'AnimReloadRate': 0.38,
        'SectionedName': 'REVOLVER_DOUBLEACTION',
        'TimeBetweenBullets': 0.15,
        'LoopRate': 2.00
    },
    'WEAPON_REVOLVER_SCHOFIELD': {
        'AnimReloadRate': 0.42,
        'SectionedName': 'REVOLVER_SCHOFIELD',
        'TimeBetweenBullets': 0.15,
        'LoopRate': 2.00
    },

    # --- ДРОБОВИКИ ---
    'WEAPON_SHOTGUN_PUMP': {
        'AnimReloadRate': 0.40,
        'SectionedName': 'SHOTGUN_PUMP',
        'TimeBetweenBullets': 0.32,
        'LoopRate': 1.80
    },
    'WEAPON_SHOTGUN_REPEATING': {
        'AnimReloadRate': 0.40,
        'SectionedName': 'SHOTGUN_REPEATING',
        'TimeBetweenBullets': 0.32,
        'LoopRate': 1.80
    },
    'WEAPON_SHOTGUN_SEMIAUTO': {
        'AnimReloadRate': 0.42,
        'SectionedName': 'SHOTGUN_SEMIAUTO',
        'TimeBetweenBullets': 0.28,
        'LoopRate': 2.00
    },
    'WEAPON_SHOTGUN_DOUBLEBARREL': {
        'AnimReloadRate': 0.48,
        'SectionedName': 'SHOTGUN_DOUBLEBARREL',
        'TimeBetweenBullets': 0.15,
        'LoopRate': 2.00
    },
    'WEAPON_SHOTGUN_SAWEDOFF': {
        'AnimReloadRate': 0.48,
        'SectionedName': 'SHOTGUN_SAWEDOFF',
        'TimeBetweenBullets': 0.15,
        'LoopRate': 2.00
    },

    # --- ПІСТОЛЕТИ ---
    'WEAPON_PISTOL_VOLCANIC': {
        'AnimReloadRate': 0.35,
        'SectionedName': 'PISTOL_VOLCANIC',
        'TimeBetweenBullets': 0.28,
        'LoopRate': 1.80
    },
    'WEAPON_PISTOL_MAUSER': {                # обойма — не поштучно
        'AnimReloadRate': 0.48,
        'SectionedName': 'PISTOL_MAUSER',
        'TimeBetweenBullets': 0.10,
        'LoopRate': 2.50
    },
    'WEAPON_PISTOL_SEMIAUTO': {              # магазин — не поштучно
        'AnimReloadRate': 0.48,
        'SectionedName': 'PISTOL_SEMIAUTO',
        'TimeBetweenBullets': 0.10,
        'LoopRate': 2.50
    },

    # --- НЕМАЄ У ВАШОМУ ФАЙЛІ, але лишаємо для чужих/оригінальних ymt ---
    # Якщо запустити скрипт на файлі, де ці стволи Є, вони теж сповільняться.
    # AnimReloadRate і TimeBetweenBullets пораховані з ваших стокових замірів
    # (див. ABSENT_IN_YMT). LoopRate = 1.85 — найчастіше стокове значення у файлі;
    # за моделлю coupled його однаково не треба міняти.
    'WEAPON_REVOLVER_LEMAT': {
        'AnimReloadRate': 0.74, 'SectionedName': 'REVOLVER_LEMAT',
        'TimeBetweenBullets': 0.13, 'LoopRate': 1.85},
    'WEAPON_REVOLVER_NAVY': {
        'AnimReloadRate': 0.62, 'SectionedName': 'REVOLVER_NAVY',
        'TimeBetweenBullets': 0.16, 'LoopRate': 1.85},
    'WEAPON_PISTOL_M1899': {
        'AnimReloadRate': 0.51, 'SectionedName': 'PISTOL_M1899',
        'TimeBetweenBullets': 0.20, 'LoopRate': 1.85},
    'WEAPON_REPEATER_EVANS': {
        'AnimReloadRate': 0.68, 'SectionedName': 'REPEATER_EVANS',
        'TimeBetweenBullets': 0.15, 'LoopRate': 1.85},
    'WEAPON_RIFLE_ELEPHANT': {               # без замірів — значення за аналогією
        'AnimReloadRate': 0.48, 'SectionedName': 'RIFLE_ELEPHANT',
        'TimeBetweenBullets': 0.15, 'LoopRate': 2.00},
}

INPUT_FALLBACKS = ['weapons.ymt', 'weapons_merged.ymt',
                   'weapons (RUCO).txt', 'weapons.txt']

# Поля, у які скрипт має право писати. Більше — жодного.
WRITABLE_FIELDS = ('AnimReloadRate', 'TimeBetweenBulletsInLoop', 'LoopRate')

# Межі здорового глузду. Гра приймає й дурні числа, але грати стане неможливо.
MIN_RATE, MAX_RATE = 0.05, 8.0
MIN_TIME, MAX_TIME = 0.00, 3.0


# ---------------------------------------------------------------------------
# joaat (RAGE) — для розпізнавання імен виду 0xD06705B5
# ---------------------------------------------------------------------------
def joaat(text):
    h = 0
    for ch in text.lower():
        h = (h + ord(ch)) & 0xFFFFFFFF
        h = (h + (h << 10)) & 0xFFFFFFFF
        h ^= (h >> 6)
    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= (h >> 11)
    h = (h + (h << 15)) & 0xFFFFFFFF
    return h


HASH_CANDIDATE_BASES = [
    'PISTOL_MAUSER', 'PISTOL_SEMIAUTO', 'PISTOL_VOLCANIC', 'PISTOL_M1899',
    'REVOLVER_CATTLEMAN', 'REVOLVER_SCHOFIELD', 'REVOLVER_DOUBLEACTION',
    'REVOLVER_LEMAT', 'REVOLVER_NAVY',
    'REPEATER_CARBINE', 'REPEATER_HENRY', 'REPEATER_WINCHESTER',
    'REPEATER_EVANS', 'REPEATER_PUMPACTION',
    'RIFLE_VARMINT', 'RIFLE_BOLTACTION', 'RIFLE_SPRINGFIELD', 'RIFLE_ELEPHANT',
    'SHOTGUN_PUMP', 'SHOTGUN_REPEATING', 'SHOTGUN_SEMIAUTO',
    'SHOTGUN_DOUBLEBARREL', 'SHOTGUN_SAWEDOFF',
    'SNIPER_CARCANO', 'SNIPER_ROLLINGBLOCK', 'SNIPERRIFLE_ROLLINGBLOCK',
    'SNIPERRIFLE_CARCANO', 'BOW', 'MOONSHINEJUG', 'TURRET_GATLING',
]

HASH_CANDIDATE_SUFFIXES = [
    '', '_DUALWIELD', '_DUAL', '_AKIMBO', '_LEFT', '_RIGHT', '_OFFHAND',
    '_MOUNTED', '_ONHORSEBACK', '_HORSEBACK', '_HORSE', '_COVER', '_CANOE',
    '_AI', '_NPC', '_PED', '_PLAYER', '_MP', '_ONLINE', '_SP',
    '_EXOTIC', '_GOLDEN', '_MEXICAN', '_PIG', '_DRUNK', '_RUSTED',
    '_ALT', '_ALT1', '_ALT2', '_2', '_V2', '_B', '_SLOW', '_FAST',
]

HASH_CANDIDATE_PREFIXES = ['', 'WEAPON_', 'RELOAD_', 'SECTIONED_']


def build_hash_dictionary():
    table = {}
    for pre in HASH_CANDIDATE_PREFIXES:
        for base in HASH_CANDIDATE_BASES:
            for suf in HASH_CANDIDATE_SUFFIXES:
                name = '%s%s%s' % (pre, base, suf)
                table.setdefault(joaat(name), name)
    return table


def looks_like_hash_name(name):
    return bool(re.match(r'^0[xX][0-9A-Fa-f]{1,8}$', name or ''))


# ---------------------------------------------------------------------------
# КАЛІБРУВАННЯ: із заміру й цілі -> нові значення
# ---------------------------------------------------------------------------
def scale_factor(measured_s, target_s):
    """s > 1 -> треба пришвидшити, s < 1 -> треба сповільнити."""
    if not measured_s or not target_s or target_s <= 0:
        return None
    return measured_s / float(target_s)


def rescale_triple(at, s, model=None):
    """(r, lr, tb) + коефіцієнт -> нові (r, lr, tb). None лишається None."""
    model = model or RATE_MODEL
    r, lr, tb = at
    new_r = clamp(r * s, MIN_RATE, MAX_RATE) if r is not None else None
    if lr is None:
        new_lr = None
    elif model == 'independent':
        new_lr = clamp(lr * s, MIN_RATE, MAX_RATE)
    else:
        new_lr = lr
    new_tb = clamp(tb / s, MIN_TIME, MAX_TIME) if tb is not None else None
    return new_r, new_lr, new_tb


def predict_time(measured_s, at, new_triple, rounds, model):
    """Прогноз часу після зміни. Повертає None, якщо даних бракує."""
    if measured_s is None or at[0] is None or new_triple[0] is None:
        return None
    r, lr, tb = at
    nr, nlr, ntb = new_triple
    n = rounds or 1
    tb = tb or 0.0
    ntb = ntb if ntb is not None else tb
    fixed_old = n * tb                      # доданок, що не залежить від темпів
    dynamic_old = measured_s - fixed_old
    if dynamic_old <= 0:
        return None
    k = nr / float(r)
    if model == 'independent' and lr:
        # темпова частина ділиться на (nr/r) для входу-виходу і (nlr/lr) для циклу;
        # без розділення A і L точний прогноз неможливий — беремо песимістичну оцінку
        k = min(k, (nlr if nlr else lr) / float(lr))
    if k <= 0:
        return None
    return dynamic_old / k + n * ntb


def clamp(value, low, high):
    if value is None:
        return None
    return max(low, min(high, value))


def calibration_rows():
    """Повний розрахунок по всіх стволах із замірами."""
    rows = []
    for wid, m in MEASUREMENTS.items():
        cfg = RELOAD_CONFIGS.get(wid, {})
        cur = (cfg.get('AnimReloadRate'), cfg.get('LoopRate'),
               cfg.get('TimeBetweenBullets'))
        s = scale_factor(m.get('measured_full_s') or m.get('measured_one_s'),
                         m.get('target_full_s'))
        computed = rescale_triple(m['at'], s) if s else None
        pred_c = pred_i = None
        if s:
            pred_c = predict_time(m.get('measured_full_s'), m['at'], cur,
                                  m.get('rounds'), 'coupled')
            pred_i = predict_time(m.get('measured_full_s'), m['at'], cur,
                                  m.get('rounds'), 'independent')
        rows.append({
            'weapon': wid, 'ua': m['ua'],
            'measured_full_s': m.get('measured_full_s'),
            'measured_one_s': m.get('measured_one_s'),
            'rounds': m.get('rounds'),
            'at': m['at'], 'target_full_s': m.get('target_full_s'),
            'scale': s, 'computed': computed, 'in_config': cur,
            'predict_coupled': pred_c, 'predict_independent': pred_i,
            'verdict': m.get('verdict', ''),
        })
    return rows


def print_calibration():
    line = '=' * 78
    print(line)
    print('[+] КАЛІБРУВАННЯ ЗА ЗАМІРАМИ   (модель темпів: %s)' % RATE_MODEL)
    print(line)
    changed, kept = [], []
    for row in calibration_rows():
        (changed if row['target_full_s'] else kept).append(row)

    print('')
    print('ПЕРЕРАХОВАНО (%d):' % len(changed))
    for row in changed:
        if not row['computed']:
            print('')
            print('  %s — %s' % (row['weapon'], row['ua']))
            print('    [!] ціль задано, але заміру немає — перерахувати неможливо')
            continue
        r, lr, tb = row['at']
        nr, nlr, ntb = row['computed']
        print('')
        print('  %s — %s' % (row['weapon'], row['ua']))
        print('    вердикт:      %s' % row['verdict'])
        print('    заміряно:     %.2f с на повну%s'
              % (row['measured_full_s'] or 0,
                 (' (%d набоїв)' % row['rounds']) if row['rounds'] else ''))
        print('    ціль:         %.2f с   ->  коефіцієнт %.4f'
              % (row['target_full_s'], row['scale']))
        print('    було:         AnimReloadRate=%s  LoopRate=%s  TimeBetween=%s'
              % (fmt_opt(r), fmt_opt(lr), fmt_opt(tb)))
        print('    розраховано:  AnimReloadRate=%s  LoopRate=%s  TimeBetween=%s'
              % (fmt_opt(nr), fmt_opt(nlr), fmt_opt(ntb)))
        print('    у конфігу:    AnimReloadRate=%s  LoopRate=%s  TimeBetween=%s'
              % (fmt_opt(row['in_config'][0]), fmt_opt(row['in_config'][1]),
                 fmt_opt(row['in_config'][2])))
        if row['predict_coupled']:
            print('    прогноз часу: %.2f с якщо модель coupled, %.2f с якщо independent'
                  % (row['predict_coupled'],
                     row['predict_independent'] or row['predict_coupled']))
        mism = value_mismatch(row)
        if mism:
            print('    [!] РОЗБІЖНІСТЬ конфігу з розрахунком: %s' % mism)

    print('')
    print('ЗАЛИШЕНО БЕЗ ЗМІН (%d) — ваш вердикт «норм» або без зауважень:'
          % len(kept))
    for row in kept:
        print('  %-38s %-30s %s'
              % (row['weapon'], row['ua'],
                 ('%.2f с' % row['measured_full_s'])
                 if row['measured_full_s'] else ('%.2f с (один набій)'
                                                 % (row['measured_one_s'] or 0))))

    print('')
    print('НЕМАЄ У ВАШОМУ weapons.ymt (%d) — лише через плагін:' % len(ABSENT_IN_YMT))
    for wid, m in ABSENT_IN_YMT.items():
        s = scale_factor(m.get('measured_full_s'), m.get('target_full_s'))
        calc = ('AnimReloadRate=%.2f' % clamp(1.0 * s, MIN_RATE, MAX_RATE)) \
            if s else 'замірів/цілі немає'
        print('  %-30s %-24s %s  ->  %s'
              % (wid, m['ua'],
                 ('%.2f с стоково' % m['measured_full_s'])
                 if m.get('measured_full_s') else 'не заміряно', calc))

    print('')
    print('ВАРІАНТИ (значення успадковують від базового ствола):')
    for name, base, full_s, one_s in VARIANT_MEASUREMENTS:
        print('  %-42s <- %-34s %5.2f / %.2f с' % (name, base, full_s, one_s))
    print(line)


def value_mismatch(row):
    """Чи збігається те, що в RELOAD_CONFIGS, з розрахунком (допуск 0.01)."""
    if not row['computed']:
        return None
    names = ('AnimReloadRate', 'LoopRate', 'TimeBetween')
    bad = []
    for name, want, have in zip(names, row['computed'], row['in_config']):
        if want is None and have is None:
            continue
        if want is None or have is None:
            bad.append('%s: розрахунок=%s, конфіг=%s'
                       % (name, fmt_opt(want), fmt_opt(have)))
        elif abs(want - have) > 0.01:
            bad.append('%s: розрахунок=%.4f, конфіг=%.4f' % (name, want, have))
    return '; '.join(bad) if bad else None


def fmt_opt(value):
    return '-' if value is None else ('%.4f' % value)


# ---------------------------------------------------------------------------
# XML: лікування / відновлення (без змін проти v3 — воно перевірене в грі)
# ---------------------------------------------------------------------------
def pre_heal_xml(text):
    if text and ord(text[0]) == 0xFEFF:   # BOM (U+FEFF) без невидимих літералів
        text = text[1:]
    text = re.sub(r'<(/?)([0-9\-][a-zA-Z0-9.\\-_]*)', r'<\1_HEALED_\2', text)
    text = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;)', '&amp;', text)
    return text


def post_restore_xml(text):
    return re.sub(r'<(/?)_HEALED_([a-zA-Z0-9.\\-_]*)', r'<\1\2', text)


# ---------------------------------------------------------------------------
# Обхід дерева з нормалізацією _HEALED_
# ---------------------------------------------------------------------------
def tag_of(el):
    tag = el.tag if isinstance(el.tag, str) else ''
    return tag.replace('_HEALED_', '')


def direct_child(node, name):
    for el in list(node):
        if tag_of(el) == name:
            return el
    return None


def find_first(node, name):
    for el in node.iter():
        if el is not node and tag_of(el) == name:
            return el
    return None


def find_all(node, name):
    return [el for el in node.iter() if el is not node and tag_of(el) == name]


def items_of_type(root, type_name):
    out = []
    for el in root.iter():
        if tag_of(el) == 'Item' and el.get('type') == type_name:
            out.append(el)
    return out


def node_name(item):
    # Увага: у ElementTree порожній елемент є falsy, тому `a or b` тут
    # давало б хибний результат — порівнюємо саме з None.
    n = direct_child(item, 'Name')
    if n is None:
        n = find_first(item, 'Name')
    if n is not None and n.text:
        return n.text.strip()
    return None


def read_float(node, default=None):
    if node is None:
        return default
    try:
        return float(node.get('value', ''))
    except (TypeError, ValueError):
        return default


def fmt(value):
    return '%.8f' % value


# ---------------------------------------------------------------------------
# Підбір конфігу: точний збіг -> найдовший збіг за префіксом -> найдовший підрядок
# ---------------------------------------------------------------------------
def resolve_config_key(weapon_name):
    name = weapon_name.upper()
    if name in RELOAD_CONFIGS:
        return name
    prefix = [k for k in RELOAD_CONFIGS if name.startswith(k)]
    if prefix:
        return max(prefix, key=len)
    inner = [k for k in RELOAD_CONFIGS if k in name]
    if inner:
        return max(inner, key=len)
    return None


def sectioned_aliases(cfg):
    val = cfg.get('SectionedName')
    if val is None:
        return []
    if isinstance(val, (list, tuple, set)):
        return [str(v).upper() for v in val]
    return [str(val).upper()]


# ---------------------------------------------------------------------------
# Основна робота
# ---------------------------------------------------------------------------
def apply_reload_tweaks(input_file, output_file, report_only=False,
                        ini_path=None, csv_path=None, force_ini=False):
    line = '=' * 78
    print(line)
    print('[+] RDR2 Weapons Reload Tweaker v5.0   (модель темпів: %s)' % RATE_MODEL)
    print('[+] Вхідний файл: %s' % input_file)
    if report_only:
        print('[!] РЕЖИМ ЗВІТУ: вихідний .ymt НЕ записується')
    print(line)

    try:
        with open(input_file, 'r', encoding='utf-8-sig', errors='ignore') as f:
            content = f.read()
    except Exception as exc:
        print('[-] Не вдалося прочитати %s: %s' % (input_file, exc))
        sys.exit(1)

    print('[+] Лікування XML (числові теги, BOM, голі &)...')
    try:
        root = ET.fromstring(pre_heal_xml(content))
    except ET.ParseError as exc:
        print('[-] Критична помилка XML: %s' % exc)
        sys.exit(1)
    print('[+] XML розібрано успішно')

    weapon_items = items_of_type(root, 'CWeaponInfo')
    sect_items = items_of_type(root, 'CSectionedReloadInfo')
    print('[+] Знайдено: CWeaponInfo = %d, CSectionedReloadInfo = %d'
          % (len(weapon_items), len(sect_items)))
    print('-' * 78)

    # ---- 1) CWeaponInfo -> AnimReloadRate --------------------------------
    rows = []
    originals = {}            # config_key -> оригінальні значення (для INI)
    found_weapon = set()      # config_key, для якого справді знайдено CWeaponInfo
    seen_names = {}
    patched_weapons = 0
    skipped_no_reload = 0
    untouched = []

    for item in weapon_items:
        wname = node_name(item)
        if not wname:
            continue
        wname_u = wname.upper()

        reload_node = find_first(item, 'WeaponReload')
        anim_node = None
        if reload_node is not None:
            anim_node = direct_child(reload_node, 'AnimReloadRate')
            if anim_node is None:
                anim_node = find_first(reload_node, 'AnimReloadRate')
        if anim_node is None:
            anim_node = find_first(item, 'AnimReloadRate')

        old_anim = read_float(anim_node)
        sect_ref = None
        for el in item.iter():
            if 'SECTIONED' in tag_of(el).upper():
                if el.text and el.text.strip():
                    sect_ref = el.text.strip()
                    break

        seen_names.setdefault(wname_u, []).append(old_anim)

        cfg_key = resolve_config_key(wname_u)
        if cfg_key is None:
            if anim_node is not None:
                untouched.append((wname, old_anim))
            rows.append({'weapon': wname, 'config_key': '', 'status': 'БЕЗ ЗМІН',
                         'old_anim': old_anim, 'new_anim': '',
                         'new_loop': '', 'new_time': '',
                         'sectioned_ref': sect_ref or ''})
            continue

        if anim_node is None:
            skipped_no_reload += 1
            rows.append({'weapon': wname, 'config_key': cfg_key,
                         'status': 'НЕМА AnimReloadRate', 'old_anim': '',
                         'new_anim': '', 'new_loop': '', 'new_time': '',
                         'sectioned_ref': sect_ref or ''})
            print('  [!] %s: конфіг є, але вузла AnimReloadRate немає — пропущено'
                  % wname)
            continue

        cfg = RELOAD_CONFIGS[cfg_key]
        found_weapon.add(cfg_key)
        if cfg_key not in originals:
            originals[cfg_key] = {}
        originals[cfg_key].setdefault('AnimReloadRate', old_anim)

        new_anim = cfg.get('AnimReloadRate')
        if new_anim is None:
            rows.append({'weapon': wname, 'config_key': cfg_key,
                         'status': 'ПРОПУЩЕНО (конфіг без AnimReloadRate)',
                         'old_anim': old_anim, 'new_anim': '',
                         'new_loop': '', 'new_time': '',
                         'sectioned_ref': sect_ref or ''})
            continue

        new_anim = clamp(new_anim, MIN_RATE, MAX_RATE)
        if not report_only:
            anim_node.set('value', fmt(new_anim))
        patched_weapons += 1
        rows.append({'weapon': wname, 'config_key': cfg_key, 'status': 'ЗМІНЕНО',
                     'old_anim': old_anim, 'new_anim': new_anim,
                     'new_loop': cfg.get('LoopRate') if not cfg.get('SkipSectioned') else '',
                     'new_time': cfg.get('TimeBetweenBullets') if not cfg.get('SkipSectioned') else '',
                     'sectioned_ref': sect_ref or ''})
        print('  [~] %-44s AnimReloadRate %s -> %.2f'
              % (wname, ('%.4f' % old_anim) if old_anim is not None else '?',
                 new_anim))

    # ---- 2) CSectionedReloadInfo -> TimeBetweenBulletsInLoop / LoopRate --
    alias_to_key = {}
    for key, cfg in RELOAD_CONFIGS.items():
        for alias in sectioned_aliases(cfg):
            if alias in alias_to_key:
                print('  [!] УВАГА: SectionedName "%s" вказано і в %s, і в %s'
                      % (alias, alias_to_key[alias], key))
            alias_to_key[alias] = key

    hash_dict = build_hash_dictionary()
    patched_sections = 0
    unmatched_sections = []
    resolved_hashes = []
    skipped_sections = []

    for item in sect_items:
        sname = node_name(item)
        if not sname:
            continue
        sname_u = sname.upper()

        resolved = None
        if looks_like_hash_name(sname_u):
            resolved = hash_dict.get(int(sname_u, 16))
            resolved_hashes.append((sname, resolved))
            if resolved:
                sname_u = resolved.upper()

        cfg_key = alias_to_key.get(sname_u)
        if cfg_key is None and sname_u.startswith('WEAPON_'):
            cfg_key = alias_to_key.get(sname_u[len('WEAPON_'):])
        if cfg_key is None:
            unmatched_sections.append(sname if not resolved
                                      else '%s (= %s)' % (sname, resolved))
            continue

        cfg = RELOAD_CONFIGS[cfg_key]
        time_nodes = find_all(item, 'TimeBetweenBulletsInLoop')
        loop_nodes = find_all(item, 'LoopRate')

        store = originals.setdefault(cfg_key, {})
        if 'TimeBetweenBullets' not in store and time_nodes:
            store['TimeBetweenBullets'] = read_float(time_nodes[0])
        if 'LoopRate' not in store and loop_nodes:
            store['LoopRate'] = read_float(loop_nodes[0])

        if cfg.get('SkipSectioned'):
            skipped_sections.append(sname)
            print('  [=] Профіль %-32s знайдено, але за конфігом НЕ змінюється'
                  % sname)
            continue

        new_tb = clamp(cfg.get('TimeBetweenBullets'), MIN_TIME, MAX_TIME)
        new_lr = clamp(cfg.get('LoopRate'), MIN_RATE, MAX_RATE)
        if new_tb is None and new_lr is None:
            skipped_sections.append(sname)
            continue

        if not report_only:
            if new_tb is not None:
                for n in time_nodes:
                    n.set('value', fmt(new_tb))
            if new_lr is not None:
                for n in loop_nodes:
                    n.set('value', fmt(new_lr))

        patched_sections += 1
        print('  [~] Профіль %-32s TimeBetweenBullets -> %s s, LoopRate -> %s'
              % (sname, fmt_opt(new_tb), fmt_opt(new_lr)))

    # ---- 3) Діагностика --------------------------------------------------
    print('-' * 78)
    print('[+] Змінено CWeaponInfo:            %d' % patched_weapons)
    print('[+] Змінено профілів перезарядки:   %d' % patched_sections)

    if resolved_hashes:
        print('')
        print('[i] Профілі з хешованими іменами (%d). joaat-розпізнавання:'
              % len(resolved_hashes))
        for raw, name in resolved_hashes:
            print('      %-14s -> %s' % (raw, name or 'не знайдено у словнику кандидатів'))
        print('      Нерозпізнане не означає помилку: у словнику просто немає')
        print('      відповідного рядка. Додайте здогадку в HASH_CANDIDATE_BASES.')

    dupes = {n: v for n, v in seen_names.items() if len(v) > 1}
    if dupes:
        print('')
        print('[!] ДУБЛІКАТИ CWeaponInfo (типово для злитого файлу з кількох модів).')
        print('[!] Гра зазвичай бере ПЕРШЕ або ПОСЛІДНЄ входження — якщо значення різні,')
        print('[!] результат у грі непередбачуваний. Варто прибрати зайві:')
        for name, vals in sorted(dupes.items()):
            uniq = {v for v in vals if v is not None}
            mark = '  <-- значення РІЗНІ' if len(uniq) > 1 else ''
            print('      %-44s x%d  %s%s'
                  % (name, len(vals),
                     ', '.join('%.4f' % v for v in vals if v is not None), mark))
    else:
        print('')
        print('[i] Дублікатів CWeaponInfo немає — злиття оверхолів пройшло чисто.')

    missing_cfg = [k for k in RELOAD_CONFIGS if k not in found_weapon]
    if missing_cfg:
        print('')
        print('[!] Є в конфігу, але у файлі не знайдено (%d):' % len(missing_cfg))
        for k in sorted(missing_cfg):
            note = ''
            if k in ABSENT_IN_YMT:
                note = '  <-- цього ствола у weapons.ymt немає в принципі'
            print('      %s%s' % (k, note))
        print('      Такі стволи неможливо сповільнити правкою ymt. Єдиний спосіб —')
        print('      плагін DynamicReloadSpeed.asi: він патчить структури в пам\'яті')
        print('      за joaat-хешем імені, тому дістає і ті, яких у файлі немає.')

    if skipped_sections:
        print('')
        print('[i] Профілі, знайдені, але свідомо НЕ змінені (SkipSectioned): %s'
              % ', '.join(sorted(set(skipped_sections))))

    if unmatched_sections:
        print('')
        print('[i] Профілі CSectionedReloadInfo без конфігу (%d). Якщо якийсь ствол'
              % len(set(unmatched_sections)))
        print('[i] заряджається не так, як налаштовано — його профіль, найпевніше, тут:')
        for s in sorted(set(unmatched_sections))[:40]:
            print('      %s' % s)
        if len(set(unmatched_sections)) > 40:
            print('      ... ще %d' % (len(set(unmatched_sections)) - 40))

    if untouched:
        print('')
        print('[i] Стволів з перезарядкою, але без конфігу: %d (див. CSV, статус "БЕЗ ЗМІН")'
              % len(untouched))

    looks_processed = detect_processed(originals)
    if looks_processed:
        print('')
        print('[!] Вхідний файл СХОЖИЙ НА ВЖЕ ОБРОБЛЕНИЙ цим набором значень')
        print('[!] (%d із %d стволів уже мають конфігові числа).' % looks_processed)
        print('[!] Для самого .ymt це нормально: значення абсолютні, повторний')
        print('[!] прогін нічого не зіпсує. Але Combat_* в INI з такого файлу')
        print('[!] брати НЕ МОЖНА — туди потраплять повільні числа замість швидких.')

    # ---- 4) CSV-звіт -----------------------------------------------------
    if csv_path:
        try:
            with open(csv_path, 'w', encoding='utf-8-sig', newline='') as f:
                w = csv.DictWriter(f, fieldnames=['weapon', 'config_key', 'status',
                                                  'old_anim', 'new_anim',
                                                  'new_loop', 'new_time',
                                                  'sectioned_ref'])
                w.writeheader()
                for r in sorted(rows, key=lambda x: (x['status'] != 'БЕЗ ЗМІН',
                                                     x['weapon'])):
                    w.writerow(r)
            print('')
            print('[+] Звіт по всіх стволах: %s' % csv_path)
        except Exception as exc:
            print('[-] Не вдалося записати CSV: %s' % exc)

    # ---- 5) INI для DynamicReloadSpeed.asi -------------------------------
    if ini_path:
        write_plugin_ini(ini_path, input_file, originals,
                         allow_combat=(not looks_processed) or force_ini)

    # ---- 6) Запис .ymt ---------------------------------------------------
    if report_only:
        print(line)
        print('[+] Готово (режим звіту). Вихідний .ymt не змінювався.')
        print(line)
        return

    print('')
    print('[+] Формування та відновлення XML...')
    out_xml = ET.tostring(root, encoding='utf-8').decode('utf-8')
    out_xml = post_restore_xml(out_xml)
    out_xml = '<?xml version="1.0" encoding="utf-8"?>\n' + out_xml

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(out_xml)
        print(line)
        print('[+] ГОТОВО: %s' % output_file)
        print(line)
    except Exception as exc:
        print('[-] Не вдалося записати вихідний файл: %s' % exc)


def detect_processed(originals):
    """(скільки збіглося, скільки перевірено) або None."""
    checked = [k for k, v in originals.items()
               if v.get('AnimReloadRate') is not None
               and RELOAD_CONFIGS.get(k, {}).get('AnimReloadRate') is not None]
    if not checked:
        return None
    same = [k for k in checked
            if abs(originals[k]['AnimReloadRate']
                   - RELOAD_CONFIGS[k]['AnimReloadRate']) < 1e-4]
    if len(same) >= max(3, len(checked) // 2):
        return (len(same), len(checked))
    return None


def write_plugin_ini(ini_path, input_file, originals, allow_combat):
    """INI для DynamicReloadSpeed.asi. Calm_* — з конфігу, Combat_* — з файлу."""
    try:
        with open(ini_path, 'w', encoding='utf-8') as f:
            f.write('; Згенеровано rdr2_reload_tweaker-v5.py з файлу: %s\n'
                    % os.path.basename(input_file))
            f.write('; Calm_*   = повільний профіль (значення з RELOAD_CONFIGS).\n')
            f.write('; Combat_* = значення, ЗНАЙДЕНІ у вхідному файлі (швидкий профіль).\n')
            f.write(';            Генеруйте INI з ОРИГІНАЛЬНОГО weapons.ymt, інакше\n')
            f.write(';            у Combat_* потраплять повільні числа.\n')
            if not allow_combat:
                f.write(';\n')
                f.write('; !! Вхідний файл визначено як уже оброблений, тому всі Combat_*\n')
                f.write(';    закоментовані навмисно. Перезапустіть скрипт на оригіналі\n')
                f.write(';    або додайте --force-ini, якщо впевнені.\n')
            f.write(';\n')
            f.write('; Модель темпів, з якою пораховано Calm_*: %s\n' % RATE_MODEL)
            f.write('; Для [Defaults] плагіна з цієї моделі випливає:\n')
            f.write(';   s = у скільки разів ПОВІЛЬНІШЕ (s > 1). Менший AnimReloadRate = повільніше,\n')
            f.write(';   тому множник анімації обернений до s:\n')
            f.write(';     CalmAnimReloadRateMul = 1.0 / s\n')
            f.write(';     CalmLoopRateMul       = 1.0      (LoopRate НЕ чіпати: AnimReloadRate\n')
            f.write(';                                       масштабує й поцикловий крок теж)\n')
            f.write(';     CalmTimeBetweenMul    = s\n')
            f.write(';   Тобто CalmTimeBetweenMul = 1 / CalmAnimReloadRateMul — це інваріант.\n')
            f.write(';   Перша редакція ТЗ мала 0.40 / 0.75 / 1.60: напрямок був правильний,\n')
            f.write(';   але LoopRate чіпати не можна, а пара 0.40/1.60 неузгоджена\n')
            f.write(';   (до 0.40 пасує 2.50). Виправлено на 0.50 / 1.00 / 2.00.\n\n')

            for key in RELOAD_CONFIGS:
                cfg = RELOAD_CONFIGS[key]
                orig = originals.get(key)
                f.write('[%s]\n' % key)
                if key in ABSENT_IN_YMT:
                    f.write('; ствола немає у цьому weapons.ymt — патчиться лише плагіном\n')
                elif orig is None:
                    f.write('; у вхідному файлі не знайдено\n')
                write_ini_pair(f, 'Calm_AnimReloadRate', cfg.get('AnimReloadRate'))
                write_ini_pair(f, 'Calm_TimeBetweenBulletsInLoop',
                               cfg.get('TimeBetweenBullets'))
                write_ini_pair(f, 'Calm_LoopRate', cfg.get('LoopRate'))
                for ini_key, src_key in (('Combat_AnimReloadRate', 'AnimReloadRate'),
                                         ('Combat_TimeBetweenBulletsInLoop',
                                          'TimeBetweenBullets'),
                                         ('Combat_LoopRate', 'LoopRate')):
                    val = (orig or {}).get(src_key) if allow_combat else None
                    write_ini_pair(f, ini_key, val)
                f.write('\n')
        print('[+] Конфіг для DynamicReloadSpeed.asi: %s' % ini_path)
    except Exception as exc:
        print('[-] Не вдалося записати INI: %s' % exc)


def write_ini_pair(handle, key, value):
    if value is None:
        handle.write('; %-31s = ?\n' % key)
    else:
        handle.write('%-33s = %.4f\n' % (key, value))


def main():
    global RATE_MODEL
    args = list(sys.argv[1:])
    report_only = '--report-only' in args
    calibrate = '--calibrate' in args
    no_ini = '--no-ini' in args
    no_csv = '--no-csv' in args
    force_ini = '--force-ini' in args

    ini_path = 'DynamicReloadSpeed.generated.ini'
    csv_path = 'weapons_reload_report.csv'
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == '--ini' and i + 1 < len(args):
            ini_path = args[i + 1]
            i += 2
            continue
        if a == '--csv' and i + 1 < len(args):
            csv_path = args[i + 1]
            i += 2
            continue
        if a == '--rate-model' and i + 1 < len(args):
            if args[i + 1] in ('coupled', 'independent'):
                RATE_MODEL = args[i + 1]
            else:
                print('[-] --rate-model приймає тільки coupled або independent')
                sys.exit(2)
            i += 2
            continue
        if a.startswith('--'):
            i += 1
            continue
        positional.append(a)
        i += 1

    if calibrate:
        print_calibration()
        if not positional:
            return

    infile = positional[0] if positional else 'weapons.ymt'
    outfile = positional[1] if len(positional) > 1 else 'weapons_reloaded.ymt'

    if not os.path.exists(infile):
        for candidate in INPUT_FALLBACKS:
            if os.path.exists(candidate):
                infile = candidate
                break

    if not os.path.exists(infile):
        print('[-] Вхідний файл не знайдено. Покладіть weapons.ymt поруч зі скриптом')
        print('    або вкажіть шлях: python rdr2_reload_tweaker-v5.py <файл>')
        print('    Розрахунок значень без файлу: --calibrate')
        sys.exit(1)

    apply_reload_tweaks(infile, outfile,
                        report_only=report_only,
                        ini_path=None if no_ini else ini_path,
                        csv_path=None if no_csv else csv_path,
                        force_ini=force_ini)


if __name__ == '__main__':
    main()
