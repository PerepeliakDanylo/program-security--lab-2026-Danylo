# Вправа ЛР8 — підпис файла ліцензії за схемою RSA-PSS (OpenSSL 3.x)

Команди точно за методичкою. Виконувати в теці `labs/lab8` (поряд із `license.json`). На Windows
OpenSSL 3.x є у складі Git for Windows (`C:\Program Files\Git\usr\bin\openssl.exe`) або в
пакеті OpenSSL; перевірка версії: `openssl version` (має бути 3.x).

## Крок 3 — пара ключів RSA-3072

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```
`private.pem` — закритий ключ (секрет, НЕ публікувати, НЕ комітити); `public.pem` — відкритий.

## Крок 4 — підпис license.json (RSA-PSS, SHA-256)

```
openssl dgst -sha256 -sign private.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -out license.sig license.json
```
Створює двійковий підпис `license.sig`.

## Крок 5 — перевірка підпису відкритим ключем

```
openssl dgst -sha256 -verify public.pem -signature license.sig -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto license.json
```
Очікуваний вивід: `Verified OK`. 📸 зафіксувати.

## Крок 6 — зміна параметра без зміни підпису

Змінити один параметр у `license.json` (наприклад `valid_until` на `2099-12-31` або додати функцію в
`features`), **не** чіпаючи `license.sig`, і повторити команду кроку 5:

```
openssl dgst -sha256 -verify public.pem -signature license.sig -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto license.json
```
Очікуваний вивід: `Verification failure` (і повідомлення OpenSSL про помилку). 📸 зафіксувати.
Після досліду повернути `license.json` у вихідний стан.

## Чому цифровий підпис, а не MDC чи MAC (крок 6, пояснення)

- **MDC (просто SHA-256-хеш)** виявляє зміну, лише якщо сам еталонний хеш захищений від підміни.
  Порушник, який змінює `license.json`, так само перерахує й опублікований поруч хеш — перевірка
  пройде для підміненого файла. MDC захищає від випадкового пошкодження, не від зловмисника.
- **MAC (наприклад HMAC)** додає секретний ключ, але **той самий** ключ потрібен і для створення, і
  для перевірки. Щоб клієнт міг перевірити ліцензію самостійно, ключ довелося б вкласти в
  клієнтську програму — у середовищі користувача його можна дістати й підробляти ліцензії.
- **Цифровий підпис (RSA-PSS)** розділяє ролі: **закритий** ключ лише в автора — ним підписують;
  **відкритий** ключ не секретний, його вкладають у клієнта чи публікують — ним лише перевіряють.
  Мати відкритий ключ достатньо, щоб перевірити підпис, але недостатньо, щоб підробити новий. Саме
  тому для ліцензії/паспорта релізу, який перевіряють треті сторони, потрібен підпис, а не MDC/MAC.

## Еквівалент у коді (перехресна перевірка в обидва боки)

Скрипт не чіпає файлів основного завдання (`private.pem`, `public.pem`, `license.sig`, `license.json`):

- `python rsa_pss_demo.py --verify-only` — **OpenSSL → Python**: бібліотека `cryptography` перевіряє
  підпис `license.sig`, створений командою кроку 4, → `Verified OK`.
- `python rsa_pss_demo.py` — повний цикл **у пам'яті**: нова пара RSA-3072 (закритий ключ на диск не
  пишеться), підпис `license.json` схемою RSA-PSS/SHA-256, перевірка → `Verified OK`, підміна одного
  байта (лише в пам'яті) → `Verification failure`. Потім **Python → OpenSSL**: скрипт записує
  `demo_public.pem` і `license.py.sig` і друкує команду, якою OpenSSL перевіряє цей підпис:

```
openssl dgst -sha256 -verify demo_public.pem -signature license.py.sig -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto license.json
```
Очікуваний вивід: `Verified OK` — схеми сумісні в обидва боки. Файли `*.pem` і `*.sig` вправи в
репозиторій не потрапляють (`.gitignore`).
