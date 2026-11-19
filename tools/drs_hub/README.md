# drs_hub — службовий сервер супроводжувача DRS

Цільова тека в репозиторії: `tools/drs_hub/`

Клієнт-серверна частина проєкту (ЛР10–11 і далі). Невеликий HTTPS-сервер на стандартній бібліотеці
Python (+ `cryptography` для сертифікатів) і клієнт командного рядка. Призначення — службові дані
супроводу мода:

- **реєстр релізів**: записи «версія → файли → SHA-256 → тег/коміт → канал» (публічне читання,
  запис — лише супроводжувач). Гравець чи інструмент може звірити хеш завантаженого архіву;
- з ЛР13–14 — **прийом діагностичних звітів тестерів** (лог, INI, перелік модів), зашифрованих на
  боці тестера для супроводжувача (сервер бачить лише шифротекст).

**Чого тут немає і не буде:** плагін `DynamicReloadSpeed.asi` і гра з сервером не взаємодіють —
плагін, як і раніше, не має мережевої функціональності (NFR-12). Сервер — інструмент супроводжувача.

## Файли

| Файл | Призначення |
|---|---|
| `hub_server.py` | ядро: HTTPS, маршрутизатор, читання тіла з межами, автентифікація Bearer перед обробником, єдиний формат помилок, заголовки безпеки, `X-Request-ID`, журнал доступу |
| `hub_routes_core.py` | маршрути: `/api/v1/health`, `/oauth/token`, `/oauth/revoke`, `/api/v1/whoami`, `/api/v1/releases` |
| `hub_auth.py` | OAuth 2.0 Client Credentials, непрозорі Bearer-токени (лише SHA-256 у базі), ролі й скоупи, блокування перебору |
| `hub_store.py` | SQLite: клієнти, токени, лічильники невдач, релізи |
| `hub_config.py` | несекретні налаштування (`hub.json`), шляхи, блокування теки даних |
| `hub_tls.py` | власний CA (ключ CA не зберігається) і сертифікат сервера для `localhost`/`127.0.0.1` |
| `hub_log.py` | журнал JSON Lines (UTC, `request_id`), безпековий журнал із ланцюгом SHA-256, редагування секретів, ротація, показники й сповіщення |
| `hub_routes_ops.py` | `GET /api/v1/metrics` (скоуп `metrics:read`) |
| `hub_monitor.py` | аналіз журналів (`summary`, `trace`, `verify`) і опитування показників (`metrics --watch`) |
| `hub_e2ee.py` | наскрізне шифрування звітів: X25519 + HKDF-SHA256 + AES-256-GCM, конверт, ключі, безпечний пакет файлів |
| `hub_routes_reports.py` | `POST/GET /api/v1/reports` — лише шифротекст і метадані; доступ свій / усі |
| `hub_ledger.py`, `hub_routes_ledger.py` | хеш-ланцюг записів (релізи, звіти), квитанції, `GET /api/v1/ledger[/verify]`, CLI `verify | head | list` |
| `report_recipient.pub` | відкритий ключ отримувача звітів (закритий — у супроводжувача, поза репозиторієм) |
| `hub_backup.py`, `backup_profile.example.json` | повні зашифровані резервні копії, перевірка, відновлення, GFS; приклад профілю ключового матеріалу |
| `hub_admin.py` | локальне адміністрування: `init`, клієнти, ротація секретів, відкликання токенів |
| `hub_client.py` | клієнт командного рядка |
| `hub_selftest.py` | самоперевірка: справжній сервер у тимчасовій теці + сценарії через клієнт |
| `requirements.txt` | `cryptography` |

## Модель автентифікації й авторизації

| Що | Рішення |
|---|---|
| Канал | TLS 1.2+; клієнт довіряє лише CA сервера (`ca_cert.pem`) і перевіряє ім'я хоста; HTTP без TLS — лише `127.0.0.1` з `--insecure-http` |
| Хто клієнт | Супроводжувач, тестер чи аудитор — **програма-клієнт** з `client_id` + `client_secret` (OAuth 2.0 Client Credentials, RFC 6749 §4.4; секрет — лише в `Authorization: Basic`) |
| Стан після входу | Непрозорий токен доступу 256 біт (`dha_…`), 10 хв, схема Bearer (RFC 6750). Сервер зберігає **лише SHA-256** токена; відкликання — `POST /oauth/revoke` (RFC 7009). Токенів оновлення немає (для Client Credentials не потрібні) |
| Права | Роль → скоупи (`hub_auth.ROLE_SCOPES`); маршрут вимагає скоуп; суб'єкт — лише з токена. Керування клієнтами — лише локально (`hub_admin.py`), мережевого API адміністрування немає |
| Перебір | 5 невдач для `client_id` → блокування 5 хв із подвоєнням до 60 хв; 20 невдач з адреси за 10 хв → тимчасова відмова; відповідь однакова для неіснуючого й наявного клієнта |

| Роль | Скоупи |
|---|---|
| `tester` | `reports:submit`, `reports:read:own` |
| `maintainer` | `releases:write`, `reports:read`, `ledger:read`, `metrics:read` |
| `auditor` | `ledger:read`, `metrics:read` |

## Встановлення й запуск (Windows, PowerShell)

```powershell
cd tools\drs_hub
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python hub_selftest.py                          # → drs_hub self-test: N/N OK
python hub_admin.py init                        # тека даних %USERPROFILE%\.drs_hub (поза репозиторієм)
python hub_admin.py add-client dan-maintainer --role maintainer --secret-out "$env:USERPROFILE\.drs_hub_clients\dan-maintainer.secret"
python hub_server.py                            # https://127.0.0.1:8443, Ctrl+C — зупинка
```

В іншому вікні:

```powershell
$env:DRS_HUB_CA = "$env:USERPROFILE\.drs_hub\tls\ca_cert.pem"
$env:DRS_HUB_CLIENT_ID = "dan-maintainer"
python hub_client.py health
python hub_client.py --secret-file "$env:USERPROFILE\.drs_hub_clients\dan-maintainer.secret" whoami
python hub_client.py --secret-file "…\dan-maintainer.secret" publish-release release_1.2.2.json
python hub_client.py releases
```

Тека даних і файли секретів **ніколи** не лежать у репозиторії: `hub_admin.py init`, `hub_server.py`
і `--secret-out` відмовляють, якщо шлях усередині робочого дерева git.

## Журнали й моніторинг (ЛР12)

| Файл (`<тека даних>\logs\`) | Вміст | Зберігання |
|---|---|---|
| `hub-YYYY-MM-DD.jsonl` | усі події (JSON Lines, UTC) | 14 діб |
| `security-YYYY-MM-DD.jsonl` | безпекові події з ланцюгом SHA-256 (`prev`, `chain`) | 90 діб |
| `hub-admin-…`, `security-admin-…` | те саме від `hub_admin.py` | 14 / 90 діб |

Кожна відповідь має `X-Request-ID`; той самий `request_id` — у всіх подіях запиту. Секретів, токенів і
тіл запитів у журналі немає (лише відбиток токена `token_fp`). Каталог подій, пороги сповіщень і
рішення — `docs/security/logging_monitoring.md`.

```powershell
python hub_monitor.py summary                     # зведення за сьогодні (UTC)
python hub_monitor.py trace <request_id>          # усі події одного запиту
python hub_monitor.py verify                      # JSON, відсутність секретів, ланцюг SHA-256
python hub_monitor.py metrics --client-id auditor-demo --secret-file "…\auditor-demo.secret" --watch 3 --interval 10
```

`GET /api/v1/metrics` (скоуп `metrics:read`) — показники процесу й стан бази; сповіщення
`alert.raised`: `auth.bruteforce_ip`, `auth.lockout`, `authz.denied_burst`, `http.scan_404`,
`http.error_burst`, `tls.handshake_burst`.

## Звіти тестерів із наскрізним шифруванням і журнал записів (ЛР13–14)

Тестер шифрує діагностичний пакет (лог, INI, перелік модів, примітку) **на своїй машині** відкритим
ключем супроводжувача з файла `report_recipient.pub` (у репозиторії; із сервера ключ не береться):
ефемерний X25519 → HKDF-SHA256 → AES-256-GCM, метадані — в AAD. Сервер зберігає лише шифротекст і
метадані; розшифрувати може тільки супроводжувач своїм закритим ключем (PKCS#8, зашифрований фразою,
поза репозиторієм). Кожен реліз і кожен звіт дописують блок у хеш-ланцюг (`prev_hash`, `hash`) у тій
самій транзакції; клієнт отримує квитанцію (номер і хеш блока).

| Маршрут | Доступ |
|---|---|
| `POST /api/v1/reports` | `reports:submit`; `meta.submitter` має дорівнювати `client_id` токена |
| `GET /api/v1/reports`, `GET /api/v1/reports/{id}` | `reports:read` — усі; `reports:read:own` — лише власні (чужий → 404) |
| `GET /api/v1/ledger`, `GET /api/v1/ledger/verify` | `ledger:read` |

```powershell
# супроводжувач, один раз (фраза ≥ 12 символів; закритий ключ — поза репозиторієм):
python hub_client.py keygen --private "$env:USERPROFILE\.drs_hub_keys\report_key.pem" --public report_recipient.pub
# тестер:
python hub_client.py --client-id tester-demo --secret-file "…\tester-demo.secret" submit-report DynamicReloadSpeed.log mods.txt --note "…" --plugin-version 1.2.2 --game-build 1.0.1491.50
# супроводжувач:
python hub_client.py --client-id dan-maintainer --secret-file "…\dan-maintainer.secret" reports
python hub_client.py --client-id dan-maintainer --secret-file "…\dan-maintainer.secret" decrypt-report <report_id> --private "…\report_key.pem"
python hub_client.py --client-id auditor-demo --secret-file "…\auditor-demo.secret" ledger-verify
python hub_ledger.py verify | head | list            # локально, без сервера
```

Рішення й обмеження — `docs/security/e2ee_ledger.md`.

## Резервні копії й відновлення (ЛР15–16)

Повна зашифрована копія (scrypt + AES-256-GCM, маніфест SHA-256, `<архів>.sha256`): знімок бази без сеансового
стану (онлайн, сервер може працювати), `hub.json`, TLS, безпекові журнали й ключовий матеріал супроводжувача з
профілю (приклад — `backup_profile.example.json`; справжній профіль — у теці даних). Відновлення — лише в теку,
з якою сервер не працює, після повної перевірки; наявна база відкладається, ключі — у `restored_extra\`.

```powershell
$env:DRS_HUB_BACKUP_PASSPHRASE = "<фраза ≥ 16 символів — з менеджера паролів>"
python hub_backup.py create --dest D:\DRS_backups --profile "$env:USERPROFILE\.drs_hub\backup_profile.json" --label daily
python hub_backup.py verify D:\DRS_backups\drs-hub-YYYYMMDD-HHMMSS-daily.dhbk --deep
python hub_backup.py restore D:\DRS_backups\drs-hub-…dhbk --target "$env:USERPROFILE\.drs_hub" --force   # сервер зупинено
python hub_backup.py prune --dest D:\DRS_backups --dry-run          # GFS 7/4/6
```

Стратегія, RPO ≤ 24 год, RTO ≤ 1 год, 3-2-1 — `docs/security/backup_recovery.md`; реліз і підтримка —
`docs/security/release_support.md`, `SECURITY.md`, `tools/release/release_tools.py`.

## Відомі обмеження

- Сертифікат виписано лише на `localhost`/`127.0.0.1`; для доступу ззовні потрібен сертифікат на
  справжнє ім'я хоста (і, ймовірно, зворотний проксі).
- Закритий ключ сервера лежить у теці даних незашифрованим (сервер стартує без участі людини);
  захищає його ACL профілю Windows.
- Блокування `client_id` за 5 невдач дає змогу навмисно заблокувати чужого клієнта (відмова в
  обслуговуванні); пом'якшення — короткі строки блокування й ліміт за адресою.
- Сервер однопроцесний (потік на з'єднання) — для службового навантаження супроводу достатньо.
