# 27 — اصل «همه‌چیز قابل‌تنظیم» و فهرست تنظیمات

وضعیت: **مصوب مالک — 2026-11-08**

## 1. اصل

هیچ رفتاری در محصول نباید تحمیلی باشد. از ریزترین تا درشت‌ترین قابلیت، کاربر باید بتواند خودش آن را
تنظیم کند. قواعد اجرایی:

1. **هر مقدار ثابت در کد یک پیش‌فرض است، نه یک قانون.** هر عدد، آدرس، mirror، timeout یا سقفی که روی رفتار
   اثر دارد باید از تنظیمات خوانده شود و مقدار پیش‌فرض امن داشته باشد.
2. **سه لایه تنظیم، به ترتیب اولویت:**
   - **پنل (runtime):** هر تنظیمی که امکانش هست بدون restart از پنل تغییر کند، با validation، audit و
     امکان تست قبل از ذخیره (مثل DNS و upstreamها).
   - **متغیر محیطی (startup):** تنظیماتی که فقط هنگام شروع process معنا دارند (`MRK_*`).
   - **build arg (image):** منابع دانلود هنگام ساخت image (`NPM_REGISTRY`، `PIP_INDEX_URL`).
3. **امنیت قابل‌تنظیم است، ولی پیش‌فرض امن می‌ماند.** کاربر می‌تواند یک محافظ را عوض کند، ولی پنل اثر آن را
   صریح نشان می‌دهد و تغییر در audit ثبت می‌شود (مثل `MRK_PYPI_ROUTER_ALLOW_PRIVATE`).
4. **ورودی نامعتبر هیچ‌وقت سرویس را از کار نمی‌اندازد.** فایل تنظیمات خراب به پیش‌فرض برمی‌گردد و در log
   گزارش می‌شود.
5. **هر ماژول جدید** (Uptime، DNS، Docker Registry) باید صفحه تنظیمات خودش را در پنل داشته باشد و هیچ
   ثابت پنهانی نداشته باشد. این بخشی از Definition of Done است.

### 1.6 رجیستری تنظیمات و «همه تنظیمات» (منبع حقیقت)

از این نسخه، **رجیستری تنظیمات** (`settings_registry.py` و `settings_registry_entries_*.py`) منبع حقیقت همه
تنظیمات است: هر متغیر `MRK_*`، هر تنظیم runtime ماژول‌ها و ثابت‌های مهم یک ورودی با نام و توضیح ساده فارسی و
انگلیسی، نوع، پیش‌فرض، بازه، واحد، سطح خطر، مجوز لازم و منبع (`runtime`، `startup`، `build`، `constant`) دارند.
جدول‌های پایین همچنان راهنمای خواندنی‌اند؛ اگر با رجیستری فرق داشتند، رجیستری درست است.

- **API:**
  - `GET /api/v1/settings/registry` → `{groups: [{id, name_fa, name_en, items: [...]}], restart}`؛ هر item
    شامل schema کامل به‌علاوه `value`، `effective_source` (`env` | `override` | `default` | `runtime` | `constant`)،
    `locked_by_env`، `pending_restart`، `editable` است. فقط itemهایی که کاربر مجوز خواندنشان را دارد برگردانده
    می‌شوند. **رازها هرگز برگردانده نمی‌شوند**؛ فقط `secret_configured`. مجموعه‌ها (پروکسی‌ها، کانال‌ها، قوانین،
    کارهای پشتیبان) فقط تعداد دارند و از صفحه خودشان ویرایش می‌شوند (`edit_in`).
  - `PUT /api/v1/settings/registry/{key}` با `{"value": ...}`: مجوز همان ورودی + CSRF؛ اعتبارسنجی با schema و
    سپس validator خود ماژول. کلیدهای runtime از طریق سرویس همان ماژول نوشته می‌شوند و بدون restart اعمال می‌شوند.
  - `DELETE /api/v1/settings/registry/{key}`: بازگشت به پیش‌فرض (برای startup یعنی حذف override).
  - `GET /api/v1/settings/registry/restart` → `{pending, keys, processes, container_restart_recommended}`.
  - audit: `settings.registry.update` و `settings.registry.reset` با `object_type=setting` و کلید؛ **مقدار هرگز در
    audit نوشته نمی‌شود**.
- **override تنظیمات startup:** پنل مقدار را در `data_dir/control-plane/settings-overrides.json` (mode 0600) می‌نویسد.
  ترتیب اولویت: **متغیر محیطی صریح** (در پنل قفل، `locked_by_env`) ← فایل override ← پیش‌فرض کد. مقدارهایی که
  image رسمی در Dockerfile گذاشته (مثل `MRK_SESSION_TTL_SECONDS=28800`) پیش‌فرض حساب می‌شوند، نه انتخاب اپراتور؛
  پس override روی آن‌ها اعمال می‌شود. نوشتن override فقط با مجوز `settings:write` است که هیچ نقش داخلی‌ای جز owner
  ندارد. پیش از ذخیره، کل تنظیمات startup با مقدار تازه یک بار ساخته می‌شود تا مقداری که سرویس را از کار
  بیندازد پذیرفته نشود. تغییر بعد از restart فرایندهای نام‌برده (`processes`) اعمال می‌شود.
- **چه کسی override را می‌خواند:** `config.setting_env(name, default)` جایگزین `os.getenv` است (env ← override ←
  default). `Settings.from_env` و `RouterSettings.from_env` (روتر PyPI) از آن استفاده می‌کنند. control plane
  (`create_app` بدون settings)، موتور S3 و `verdaccio_runtime` هنگام شروع `apply_startup_overrides()` را صدا
  می‌زنند که مقدارهای override را فقط برای نام‌هایی که در محیط نیستند در `os.environ` می‌گذارد؛ پس خواننده‌هایی که
  هنوز مستقیم `os.getenv` دارند (auth، ماژول‌ها، tasks، catalog، backup) هم بعد از restart آن را می‌بینند.
- **فقط از Compose (`env_only_reason`):** نام‌هایی که جای فایل را تعیین می‌کنند (`MRK_ENV`، `MRK_DATA_DIR`)، رازها،
  مسیرها، نشانی/درگاه گوش‌دادن (خطر قفل شدن پنل)، تنظیمات کانتینرهای جدا (Agent و دستیار فایروال)، اسکریپت‌های
  پوسته devpi (`devpi-start.sh`، `devpi-configure.sh` فقط env می‌خوانند) و ابزارهای جدا (healthcheck، `mrk-restore`،
  supervisor listener). پنل برای این‌ها مقدار مؤثر و دلیل را نشان می‌دهد و خط Compose را پیشنهاد می‌کند.
- **تست پوشش:** `tests/test_settings_registry.py` همه کد (`src`، `deploy`، `scripts`، `compose.yaml`،
  `.env.example`) را برای `MRK_*` جست‌وجو می‌کند و اگر نامی در رجیستری نباشد شکست می‌خورد (فهرست استثنای صریح فقط
  برای نام‌های تست/CI و env داخلی dump دیتابیس). همچنین هر کلید `DEFAULT_SETTINGS` ماژول‌ها باید ورودی هم‌پیش‌فرض
  داشته باشد.

## 2. تنظیمات قابل‌تغییر از پنل (runtime، بدون restart)

| تنظیم | مسیر پنل | API |
|---|---|---|
| upstreamهای npm و PyPI (آدرس، اولویت، timeout، فعال/غیرفعال، block) | منابع بالادستی | `/api/v1/upstreams` |
| credential هر upstream | منابع بالادستی | `/api/v1/upstreams/{id}/credential` |
| حالت آفلاین هر ecosystem | منابع بالادستی | `/api/v1/ecosystems/{eco}/offline` |
| **DNS ارتباط با upstreamها** (سیستم یا سرورهای دلخواه، timeout، ترجیح IPv4، تست قبل از ذخیره) | منابع بالادستی | `/api/v1/settings/network` |
| **اجازه upstream داخلی** `allow_private_upstreams` (پیش‌فرض خاموش؛ با روشن‌کردن، آدرس‌های RFC1918، ULA `fc00::/7`، CGNAT `100.64.0.0/10` و نام‌های LAN مثل `nexus.lan` یا نام تک‌بخشی مجاز می‌شوند؛ loopback، link-local و آدرس metadata `169.254.169.254` و `localhost` همیشه رد می‌شوند). روی ذخیره upstream، تست اتصال و روتر PyPI اعمال می‌شود؛ uplinkهای npm را Verdaccio مستقیم می‌خواند. در `network.json` ذخیره و با `settings.network.upstream_policy` در audit ثبت می‌شود. نیازمند `upstream:write` | منابع بالادستی | `/api/v1/settings/network/upstream-policy` |
| **پروکسی خروجی** (پروفایل‌های HTTP/HTTPS/SOCKS5/SOCKS5h، پروکسی پیش‌فرض، تیک پروکسی برای هر سرویس خروجی، تست اتصال) — بخش ۹ | منابع بالادستی / شبکه | `/api/v1/settings/proxies`، `/api/v1/settings/outbound-services` |
| ثبت‌نام عمومی | دسترسی‌ها | `/api/v1/settings/registration` |
| کاربران، نقش‌ها، API token | دسترسی‌ها | `/api/v1/users`، `/api/v1/tokens` |
| pin، quarantine، purge، revalidate، prefetch | پکیج‌ها | `/api/v1/packages/...` |
| backup، cleanup، integrity scan | چرخه داده | `/api/v1/backups`، ... |

## 3. تنظیمات startup (متغیر محیطی)

| گروه | متغیرها |
|---|---|
| عمومی | `MRK_ENV`، `MRK_DATA_DIR`، `MRK_LOG_LEVEL`، `MRK_HOST`، `MRK_PORT` |
| دیتابیس | `MRK_DATABASE_URL`، `MRK_DATABASE_WAIT_SECONDS` |
| امنیت وب | `MRK_TRUSTED_HOSTS`، `MRK_CORS_ORIGINS`، `MRK_TRUSTED_PROXIES`، `MRK_AUTH_COOKIE_SECURE`، `MRK_SESSION_TTL_SECONDS`، `MRK_PASSWORD_HASH_CONCURRENCY` |
| محدودیت ورود | `MRK_LOGIN_RATE_LIMIT_ATTEMPTS` (پیش‌فرض 5، بازه 1 تا 100)، `MRK_LOGIN_RATE_LIMIT_WINDOW_SECONDS` (پیش‌فرض 300، بازه 10 تا 86400)؛ برای ورود، ثبت‌نام و راه‌اندازی اولیه به ازای هر IP |
| نگهداری داده | `MRK_AUDIT_RETENTION_DAYS` (پیش‌فرض 365؛ 0 یعنی هرگز حذف نشود)، `MRK_SESSION_PRUNE_AGE_SECONDS` (پیش‌فرض 604800 یعنی ۷ روز پس از انقضا/ابطال؛ بازه 3600 تا 31536000)، `MRK_DB_VACUUM_INTERVAL_HOURS` (پیش‌فرض 24؛ 0 یعنی خاموش؛ VACUUM (ANALYZE) خودکار برای PGlite) |
| بازه‌های پس‌زمینه | `MRK_NPM_BLOCK_POLL_SECONDS` (پیش‌فرض 30، بازه 5 تا 3600): بررسی انقضای block موقت npm و reload Verdaccio |
| رجیستری npm | `MRK_NPM_ENABLED`، `MRK_NPM_PRIMARY_UPSTREAM`، `MRK_NPM_FALLBACK_UPSTREAM` |
| رجیستری PyPI | `MRK_PYPI_ENABLED`، `MRK_PYPI_PRIMARY_UPSTREAM`، `MRK_PYPI_FALLBACK_UPSTREAM`، `MRK_PYPI_OUTSIDE_URL`، `MRK_PYPI_REQUEST_TIMEOUT`، `MRK_PYPI_CACHE_EXPIRY`، `MRK_PYPI_THREADS`، `MRK_PYPI_ROOT_PASSWORD_FILE`، `MRK_PYPI_BOOTSTRAP_WAIT_SECONDS` |
| روتر PyPI | `MRK_PYPI_ROUTER_CONNECT_TIMEOUT`، `..._READ_TIMEOUT`، `..._ARTIFACT_DEADLINE`، `..._FAILURE_THRESHOLD`، `..._COOLDOWN`، `..._MAX_ARTIFACT_BYTES`، `..._SPOOL_DIR`، `..._ALLOW_PRIVATE` (کلید اضطراری قدیمی که همه آدرس‌ها حتی loopback را مجاز می‌کند؛ با تنظیم پنل `allow_private_upstreams` به‌صورت OR ترکیب می‌شود. برای mirror داخلی همان تنظیم پنل را ترجیح دهید) |
| کلیدها | `MRK_UPSTREAM_SECRET_KEY_FILE` |
| healthcheck | `MRK_HEALTHCHECK_ATTEMPTS` |
| supervisor | `MRK_FATAL_IGNORE` |
| پشتیبان‌گیری | `MRK_BACKUP_RETAIN_COUNT` (پیش‌فرض 7؛ 0 یعنی بدون سقف تعداد)، `MRK_BACKUP_RETAIN_DAYS` (پیش‌فرض 30؛ 0 یعنی بدون سقف سن)؛ جدیدترین پشتیبان معتبر هرگز حذف نمی‌شود. `MRK_BACKUP_MIN_FREE_BYTES` (پیش‌فرض 1073741824): فضای آزادی که پس از برآورد حجم پشتیبان باید باقی بماند |
| سطل بازیافت purge | `MRK_PURGE_TRASH_RETENTION_DAYS` (پیش‌فرض 7): بسته‌های npm حذف‌شده تا این مدت قابل بازگردانی‌اند و سپس خودکار پاک می‌شوند |
| کاتالوگ و یکپارچگی | `MRK_CATALOG_CACHE_SECONDS` (پیش‌فرض 30): عمر کش اسکن کاتالوگ بسته‌ها؛ `MRK_INTEGRITY_FULL_RESCAN_DAYS` (پیش‌فرض 30): پس از این مدت فایل بدون تغییر هم دوباره hash می‌شود |
| revalidate PyPI | `MRK_PYPI_UPSTREAM_URL` (پیش‌فرض `http://127.0.0.1:3142/simple/`): قبل از حذف کش devpi در دسترس بودن upstream از این آدرس بررسی می‌شود |
| بازیابی آفلاین | `MRK_RESTORE_ENGINE_PORTS` (پیش‌فرض `4873,3141,3142,8080`): اگر هر کدام از این پورت‌ها روی 127.0.0.1 باز باشد `mrk-restore` اجرا نمی‌شود |

پیش‌فرض‌های upstream (`*_PRIMARY_UPSTREAM`، `*_FALLBACK_UPSTREAM`) فقط یک‌بار در اولین اجرا seed می‌شوند؛
بعد از آن upstreamها کاملاً از پنل مدیریت می‌شوند و حذف یک پیش‌فرض دیگر آن را برنمی‌گرداند.

## 4. تنظیمات build

| build arg | متغیر compose | کاربرد |
|---|---|---|
| `NPM_REGISTRY` | `MRK_BUILD_NPM_REGISTRY` | registry دلخواه برای `npm ci` هنگام build؛ خالی یعنی همان hostهای lockfile |
| `PIP_INDEX_URL` | `MRK_BUILD_PIP_INDEX_URL` | index دلخواه برای نصب پکیج‌های Python هنگام build |

hashهای integrity در lockfileها همچنان اجباری‌اند؛ تغییر mirror محتوای پکیج را تغییر نمی‌دهد. CI نیز hostهای
مجاز lockfile را از `NPM_LOCKFILE_ALLOWED_HOSTS` می‌خواند.

## 5. DNS: دامنه اثر و محدودیت فعلی

- تنظیم DNS پنل روی روتر PyPI و تست اتصال upstream اعمال می‌شود و پس از resolve، اتصال به همان IP بررسی‌شده
  pin می‌شود (SNI و بررسی گواهی با نام اصلی). این کار حمله DNS rebinding را هم می‌بندد.
- Verdaccio (npm) از DNS کانتینر استفاده می‌کند. برای آن، گزینه `dns:` در Compose را تنظیم کنید
  (نیازمند restart کانتینر). هدف بعدی: عبور ترافیک npm از همان لایه شبکه داخلی تا این تنظیم هم runtime شود.
- چون Verdaccio آدرس resolve‌شده را بررسی نمی‌کند، هنگام ذخیره upstream npm نام میزبان یک‌بار resolve می‌شود و
  اگر به آدرس خصوصی/محلی برسد رد می‌شود؛ نام‌های محلی (`localhost`، `*.local`، `*.internal`، نام تک‌بخشی و
  شکل‌های کوتاه IPv4 مثل `127.1`) برای همه upstreamها رد می‌شوند.
- ماژول‌های آینده (Uptime، DNS، Registry) باید از همین `netresolve` استفاده کنند.

## 6. بدهی شناخته‌شده (هنوز ثابت در کد)

این موارد باید در مرحله بعد به تنظیمات منتقل شوند. همه آن‌ها اکنون با `source: constant` در رجیستری دیده
می‌شوند («هنوز قابل تغییر نیست») تا حالت پیشرفته درباره هر چیزی که وجود دارد صادق باشد:

- `max_fails`/`fail_timeout`/`maxage` uplinkهای Verdaccio؛
- سقف ۵۰۰ مورد prefetch و ۴۰ فایل برای هر نسخه PyPI؛
- آستانه‌های دیسک در Prometheus rules؛
- رزرو فضای ۲۵۶ مگابایتی spool روتر PyPI؛
- بازه‌های heartbeat (۵ ثانیه) و retention (۶ ساعت).

TODO (مسئله ۲۰۳۸): ستون‌های زمان (`created_at`، `expires_at`، `occurred_at`، ...) در مدل‌ها `Integer` 32 بیتی‌اند و
در PostgreSQL از ژانویه ۲۰۳۸ سرریز می‌کنند. باید با یک migration به `BigInteger` منتقل شوند (هنوز انجام نشده).

## 7. قرنطینه پکیج (quarantine)

- npm: نام قرنطینه‌شده در پیکربندی Verdaccio پیش از قواعد عمومی با `access: mrk-quarantine-none` و بدون
  `proxy` نوشته می‌شود؛ پس از تغییر، Verdaccio خودکار reload می‌شود (اگر reload شکست بخورد، تغییر ذخیره و
  در audit با `npm.reload` ثبت می‌شود و در شروع بعدی اعمال می‌شود).
- PyPI: روتر برای `/simple/<name>/` و `/files/<name>/...` پروژه قرنطینه‌شده (نام نرمال‌شده PEP 503) پاسخ 404
  می‌دهد و فایل سیاست را با mtime دوباره می‌خواند (بدون restart). هنگام قرنطینه، purge نسخه‌های cache‌شده در
  devpi به‌صورت task صف می‌شود؛ پروژه pin‌شده purge نمی‌شود و باید دستی purge شود. نسخه‌هایی که devpi
  پیش‌تر cache کرده تا اجرای purge ممکن است هنوز از devpi سرو شوند.

## 8. مرکز اعلان‌ها (S5)

همه تنظیمات از پنل و API (`/api/v1/notifications/*`) و بدون restart اعمال می‌شوند. backend هیچ کانال یا قاعده‌ای
را خودکار نمی‌سازد؛ فقط اگر هنگام ساخت کانال `create_default_rule: true` فرستاده شود، قاعده `* / warning` ساخته می‌شود.

| تنظیم | پیش‌فرض | توضیح |
|---|---|---|
| `quiet_hours.enabled` | `false` | ساعات سکوت |
| `quiet_hours.start` / `end` | `23:00` / `07:00` | `HH:MM`؛ بازه می‌تواند از نیمه‌شب عبور کند |
| `quiet_hours.timezone` | `Asia/Tehran` | نام IANA (zoneinfo)؛ نام ناشناخته با 422 `invalid_timezone` رد می‌شود |
| `quiet_hours.min_severity_during_quiet` | `critical` | رویدادهای پایین‌تر در وضعیت `delayed` تا پایان ساعات سکوت می‌مانند (حذف نمی‌شوند) |
| `dedupe_window_seconds` | `300` | رویداد هم‌کلید (`dedupe_key` یا type+title) در این بازه برای همان کانال `suppressed` می‌شود؛ `0` یعنی خاموش |
| `max_attempts` | `5` | سقف تلاش برای هر تحویل (۱ تا ۲۰) |
| `retry_base_seconds` / `retry_max_seconds` | `30` / `3600` | backoff نمایی با jitter؛ `retry_after` سرویس (مثلاً 429 تلگرام) مقدم است |
| `retention_days` | `30` | تحویل‌های قدیمی‌تر هر ساعت پاک می‌شوند |

تنظیمات هر کانال (در `config`):

- Telegram / بله: `chat_id`، `api_base_url` اختیاری (فقط https؛ برای mirror/proxy تلگرام؛ پیش‌فرض
  `https://api.telegram.org` و `https://tapi.bale.ai`)، `parse_mode` اختیاری (`HTML`)، `timeout_seconds` (۲ تا ۶۰، پیش‌فرض ۱۵).
  secret: `bot_token`.
- Email: `smtp_host`، `smtp_port`، `security` (`starttls`|`tls`|`none`)، `username`، `from_address`، `to_addresses[]`،
  `timeout_seconds`. secret: `password`. ورود با `security: none` رد می‌شود (`insecure_smtp_auth`).
- Webhook: `url` (http/https)، `headers` اختیاری (حداکثر ۲۰؛ headerهای کنترلی مثل Host ممنوع)، `timeout_seconds`.
  secret: `signing_key` اختیاری → header `X-MRK-Signature: sha256=<hex>` روی بدنه خام.

نکات امنیتی: secretها با `SecretStore` رمز می‌شوند و هرگز برگردانده نمی‌شوند (فقط `secret_configured`)؛ URLها و
توکن‌ها در لاگ و پیام خطا نمی‌آیند (فقط `error_code`). همه اتصال‌ها با DNS پنل resolve و به IP بررسی‌شده pin می‌شوند؛
مقصد LAN فقط با روشن بودن `allow_private_upstreams` مجاز است و loopback/link-local هرگز. headerهای ثابت webhook
در `config` ذخیره و به ادمین نمایش داده می‌شوند؛ مقدار محرمانه را در آن‌ها نگذارید و از `signing_key` استفاده کنید.

## 9. مانیتورینگ، لاگ و مدیریت Docker (Gate 17)

تنظیمات مانیتورینگ از پنل و API (`GET/PUT /api/v1/metrics/settings`، نوشتن نیازمند `agent:write` + CSRF) و بدون
restart اعمال می‌شوند و در `data_dir/control-plane/monitoring.json` ذخیره می‌شوند. PUT می‌تواند جزئی باشد
(روی مقدار فعلی merge می‌شود)؛ کلید ناشناخته یا مقدار خارج از بازه با 422 `invalid_settings` رد می‌شود. فایل
خراب نادیده گرفته و پیش‌فرض‌ها استفاده می‌شوند.

| تنظیم | پیش‌فرض | بازه / توضیح |
|---|---|---|
| `enabled` | `true` | جمع‌آوری از `/v1/metrics` agent (فقط وقتی agent پیکربندی شده باشد) |
| `interval_seconds` | `15` | 5 تا 3600 |
| `minute_retention_days` | `7` | 1 تا 90؛ بازه‌های تا 24 ساعت از جدول دقیقه‌ای خوانده می‌شوند |
| `hour_retention_days` | `90` | 1 تا 3650؛ باید ≥ `minute_retention_days` باشد؛ بازه‌های 7d/30d از جدول ساعتی |
| `alerts.enabled` | `true` | هشدارهای میزبان (CPU، RAM، دیسک = پرترین دیسک) |
| `alerts.cpu_percent` / `mem_percent` / `disk_percent` | `90` / `90` / `85` | 1 تا 100 |
| `alerts.duration_minutes` | `5` | 1 تا 1440؛ مقدار باید پیوسته بالای آستانه بماند تا `metrics.*_high` (warning) منتشر شود؛ `*_recovered` (info) پس از 60 ثانیه پیوسته زیر آستانه |

رفتار ثابت (طبق قرارداد docs/29): داده‌های هر دقیقه در حافظه تجمیع و **یک insert در دقیقه** نوشته می‌شود؛ rollup
ساعتی و حذف داده‌های قدیمی ساعتی یک بار اجرا می‌شود؛ پاسخ‌های نمودار حداکثر 500 نقطه دارند؛ `cpu_percent`
کانتینر سهم از کل CPU میزبان است (`cpu_usage_usec` / زمان / `cpu_count`). dedupe_key هشدار و بازگشت جدا است
(`metrics.cpu_high` و `metrics.cpu_recovered`) تا dedupe مرکز اعلان پیام بازگشت را حذف نکند.

متغیرهای محیطی (startup):

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `MRK_LOGS_STREAM_MAX_SECONDS` | `600` | 10 تا 600؛ سقف عمر هر SSE لاگ زنده (`/logs/stream`)؛ keepalive هر 15 ثانیه |
| `MRK_AGENT_JOB_MAX` | `50` | 5 تا 1000؛ سقف jobهای pull نگه‌داشته‌شده در حافظه (حداکثر 5 در حال اجرا هم‌زمان، بیشتر → 429 `too_many_jobs`) |
| `MRK_AGENT_JOB_TTL_SECONDS` | `3600` | 60 تا 86400؛ عمر job تمام‌شده پیش از حذف |

لاگ‌ها: `tail` 1 تا 5000 (stream: 0 تا 5000)، `search` حداکثر 200 نویسه (substring بدون حساسیت به حروف؛
`regex=true` فقط برای الگوی معتبر بدون quantifier تودرتو)، فیلتر روی متن redact‌شده اجرا می‌شود. هر درخواست لاگ
یک رکورد audit `logs.view` دارد (بدون محتوای لاگ). عملیات Docker: کانتینر محافظت‌شده نیازمند
`allow_protected: true` و `confirmation` برابر نام کانتینر؛ prune نیازمند token پیش‌نمایش و `confirmation: "PRUNE"`؛
همه با audit تلاش (`attempted`) و نتیجه (`success`/`failure`/`denied`).

## 9. پروکسی خروجی (outbound proxy)

هیچ اتصالی اجباراً از پروکسی عبور نمی‌کند: پیش‌فرض همه سرویس‌ها «مستقیم» است و اپراتور برای هر سرویس خروجی
(upstreamهای npm/PyPI، کانال‌های اعلان، و ماژول‌های بعدی) با یک تیک پروکسی را انتخاب می‌کند. کد مشترک در
`outbound.py` است و همه مصرف‌کننده‌ها از آن استفاده می‌کنند (`outbound_client(...)`).

- **پروفایل‌ها** در `network.json` زیر `proxies` و `default_proxy_id` ذخیره می‌شوند: `name` (یکتا)، `type`
  (`http`|`https`|`socks5`|`socks5h`)، `host`، `port` (1 تا 65535)، `username` اختیاری، `enabled`، `no_proxy[]`
  (نام، `*.domain`/`.domain` یا CIDR؛ حداکثر ۳۲). رمز پروکسی در `SecretStore` رمز می‌شود و هرگز برگردانده نمی‌شود
  (فقط `secret_configured`). host پروکسی انتخاب اپراتور است: آدرس LAN و loopback (مثلاً تونل محلی `127.0.0.1:1080`)
  مجاز است؛ link-local/metadata، multicast و unspecified رد می‌شوند. جابه‌جایی host/port پروفایلی که رمز دارد بدون
  وارد کردن دوباره یا پاک کردن رمز رد می‌شود (`proxy_credential_host_change`).
- **ارجاع هر سرویس** (`proxy_id`): `null` = مستقیم (رفتار قبلی با DNS پنل و pin کردن IP)، `"default"` = پروکسی
  پیش‌فرض، یا شناسه یک پروفایل. اگر پروفایل وجود نداشته باشد، غیرفعال باشد یا پیش‌فرضی تنظیم نشده باشد، خطای
  `proxy_unavailable` برمی‌گردد و ترافیک **هرگز بی‌صدا مستقیم نمی‌رود**.
- **سیاست مقصد از پشت پروکسی:** با `socks5` نام به‌صورت محلی (DNS پنل) resolve، بررسی و به IP pin می‌شود. با
  `http`/`https`/`socks5h` پروکسی نام را resolve می‌کند؛ IP لیترال غیرمجاز، `localhost` و نام‌های LAN (بدون
  `allow_private_upstreams`) رد می‌شوند و اگر نام به‌صورت محلی هم resolve شود، پاسخ loopback/link-local/metadata رد
  می‌شود. شکست DNS محلی خطا نیست (ممکن است دلیل استفاده از پروکسی همین فیلتر DNS باشد) و پاسخ‌های RFC1918 نادیده
  گرفته می‌شوند، چون resolverهای فیلترکننده برای نام‌های مسدود آدرس خصوصی (مثل `10.10.34.x`) برمی‌گردانند. اگر DNS
  محلی فیلتر است `socks5h` را انتخاب کنید.
- **npm (Verdaccio):** فقط `http`/`https` پشتیبانی می‌شود (`http_proxy`/`https_proxy`/`no_proxy` در هر uplink؛ CIDRها
  حذف می‌شوند چون Verdaccio فقط پسوند نام را تطبیق می‌دهد). SOCKS برای upstream npm با `proxy_type_unsupported_for_npm`
  رد می‌شود و uplink با پروکسی ناموجود/غیرفعال از پیکربندی حذف می‌شود (نه اتصال مستقیم). Verdaccio پروکسی را فقط از
  فایل config (یا یک متغیر محیطی سراسری برای همه uplinkها) می‌خواند، پس **نام کاربری/رمز پروکسی در
  `/data/npm/config/generated.yaml` با مجوز 0600 نوشته می‌شود** و در هر شروع دوباره ساخته می‌شود. تغییر پروکسی‌ای که
  upstream npm از آن استفاده می‌کند Verdaccio را reload می‌کند.
- **PyPI:** روتر PyPI و تست اتصال upstream (`stages`: `dns` → `proxy` → `http`) از پروکسی upstream استفاده می‌کنند؛
  تغییرات بدون restart اعمال می‌شود.
- **اعلان‌ها:** `config.proxy_id` در Telegram/بله/webhook همه نوع پروکسی را می‌پذیرد. Email (SMTP) فقط با
  `socks5`/`socks5h` (handshake با `socksio`)؛ پروکسی HTTP برای email با `proxy_type_unsupported_for_email` رد می‌شود.
- **تست DNS** (`/api/v1/settings/network/dns-test`) تحت تأثیر پروکسی نیست.
- رمز و URL حاوی credential هرگز در لاگ، audit یا پاسخ API نمی‌آید (httpx فقط URL مقصد را لاگ می‌کند).
- میزبان پروکسی با resolver سیستم resolve می‌شود (نه DNS پنل)؛ برای پروکسی ترجیحاً IP وارد کنید.
- وابستگی: `httpx[socks]==0.28.1` و `socksio==1.0.0`.

| API | مجوز | توضیح |
|---|---|---|
| `GET /api/v1/settings/proxies` | `upstream:read` | `{items:[{id,name,type,host,port,username,secret_configured,enabled,no_proxy,is_default,created_at,updated_at,used_by:[{kind,id,name,via_default}]}], default_proxy_id}` |
| `POST /api/v1/settings/proxies` | `upstream:write` + CSRF | `{name,type,host,port,username?,password?,enabled?,no_proxy?}` → 201 |
| `PATCH /api/v1/settings/proxies/{id}` | `upstream:write` + CSRF | رمز فقط اگر `password` فرستاده شود عوض می‌شود؛ `""` یا `null` آن را پاک می‌کند |
| `DELETE /api/v1/settings/proxies/{id}` | `upstream:write` + CSRF | `{confirmation: name}`؛ اگر استفاده شود 409 `proxy_in_use` با `error.used_by` |
| `PUT /api/v1/settings/proxies/default` | `upstream:write` + CSRF | `{proxy_id}` (شناسه یا `null`)؛ پاک کردن پیش‌فرضی که سرویسی با `"default"` استفاده می‌کند 409 |
| `POST /api/v1/settings/proxies/{id}/test` | `upstream:write` + CSRF | `{url?}` (پیش‌فرض `https://api.telegram.org`) → `{ok,status_code?,latency_ms,error_code?}` |
| `GET /api/v1/settings/outbound-services` | `upstream:read` | جدول «سرویس → پروکسی»: `{items:[{kind,id,name,group,proxy_id,supported_proxy_types}], default_proxy_id}` |
| `PUT /api/v1/settings/outbound-services/{kind}/{id}` | مجوز نوشتن همان سرویس + CSRF | `{proxy_id}` (تیک پروکسی) |

همه تغییرها با `settings.proxy.*` و `settings.outbound_service.update` در audit ثبت می‌شوند (بدون secret).
ماژول جدید با `outbound_registry(data_dir).register(OutboundProvider(...))` در همین جدول ظاهر می‌شود.

## 10. سرویس S3 — سمت Control Plane (Gate 18)

قرارداد کامل در `docs/31 §3`؛ کد در `modules/s3.py` (router)، `s3_store.py` (DB + snapshot)، `s3_policy.py`
(قواعد نام و policy)، `s3_client.py` (SigV4 و API مدیریت موتور) و `s3_snippets.py`.

**تنظیمات پنل** (`PUT /api/v1/s3/settings`، `s3:admin` + CSRF؛ در `system_settings` با کلید `s3.settings`):

| کلید | پیش‌فرض | محدوده/توضیح |
|---|---|---|
| `enabled` | `true` | خاموش‌کردن سرویس در snapshot موتور |
| `region` | `us-east-1` | `[a-z0-9-]` 2 تا 32 نویسه؛ در scope امضا و snippetها |
| `public_endpoint` | `null` | `http(s)://host[:port]` بدون path/query/credential؛ برای لینک اشتراک و snippetها. خالی → `http://127.0.0.1:9000` با `endpoint_is_fallback`/`warning: public_endpoint_not_configured` |
| `virtual_host_suffix` | `null` | hostname (مثلاً `s3.example.com`) برای virtual-host |
| `max_object_bytes` | `5497558138880` (5 TiB) | 1 تا 5 TiB؛ آپلود پنل با `Content-Length` بزرگ‌تر → 413 `object_too_large` |
| `default_quota_bytes` | `null` | سهمیه پیش‌فرض باکت managed جدید (اگر `quota_bytes` داده نشود) |

**متغیرهای محیطی (startup):**

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `MRK_S3_ENGINE_URL` | `http://127.0.0.1:9000` | endpoint داخلی S3 موتور برای فایل‌منیجر (امضای SigV4 با identity `__mrk_panel__`) |
| `MRK_S3_ADMIN_URL` | `http://127.0.0.1:9001` | API داخلی مدیریت موتور (هدر `X-MRK-Admin-Token`) |
| `MRK_S3_LINKS_ROOT` | `/mnt/links` | ریشه پوشه‌های mount‌شده برای باکت linked (در تست به tmp اشاره می‌کند) |

**Snapshot موتور:** `<data>/modules/s3/config.json` با write اتمیک (`O_EXCL` temp در همان پوشه → fsync →
`os.replace` → fsync پوشه؛ mode 0600) پس از هر تغییر و در هر startup دوباره ساخته می‌شود. اولین identity همیشه
`__mrk_panel__` (`system: true`، policy `s3:*` روی `*`) است؛ secret آن یک‌بار ساخته و در SecretStore با ref ثابت
`s3-panel` نگه داشته می‌شود و در `GET /identities` دیده نمی‌شود. هر کلید در snapshot فقط `secret_ref` دارد؛
مقدار SecretStore یک dict `{"access_key_id", "secret_access_key"}` است. `admin.token` (0600) اگر نباشد با
`O_EXCL` ساخته می‌شود (موتور هم می‌تواند بسازد؛ اولی برنده است).

**قواعد و محدودیت‌ها:**
- نام باکت: 3 تا 63، `[a-z0-9.-]`، شروع/پایان حرف یا رقم، بدون `..`، نه شبیه IP، بدون `xn--`/`sthree-` و پسوندهای
  `-s3alias`/`--ol-s3`/`.mrap`/`--x-s3`؛ رزرو: `mrk`، `admin`، `api`، `www`، `_` → 422 `invalid_bucket_name`.
- باکت linked فقط owner (`*`) → 403 `linked_requires_owner` (تغییر `link_mode` هم)؛ `link_path` (مطلق یا نسبی به
  ریشه) باید پوشه موجود **زیر** `MRK_S3_LINKS_ROOT` باشد (realpath، بدون `..`، نه خود ریشه) → 422
  `link_path_invalid`؛ هم‌پوشانی با پوشه باکت دیگر → 409 `link_path_in_use`؛ پیش‌فرض `link_mode: "ro"`. حذف باکت
  linked هرگز فایل‌ها را پاک نمی‌کند (`files_removed: false`). `GET /links` تا عمق 2 و حداکثر 500 پوشه.
- حذف باکت: `confirmation` = نام؛ managed غیرخالی بدون `force` → 409 `bucket_not_empty`؛ موتور در دسترس نیست →
  503 `engine_unreachable`. حذف باکت آن را از identityهای template‌دار هم حذف می‌کند (policy دوباره ساخته می‌شود).
- Identity: نام 1 تا 64 (`[A-Za-z0-9._@+=-]`، شروع با حرف/رقم؛ پس `__mrk_panel__` رزرو است)؛ templateها
  `read_only`، `read_write`، `admin` (بدون باکت = همه)، `backup_client` (Get/Put/Delete/multipart روی اشیا +
  `ListBucket` + `ListAllMyBuckets` برای «Test» در Dokploy/rclone)، `custom` (policy با زیرمجموعه IAM ما، حداکثر
  6 KB و 50 statement، بدون `Principal`) → 422 `invalid_policy` با پیام دقیق.
- کلید: `MRK` + 17 نویسه `[A-Z0-9]`، secret 40 نویسه `[A-Za-z0-9+/]` فقط یک‌بار در پاسخ؛ حداکثر 2 کلید فعال (و 10
  کل) برای هر identity → 409 `key_limit_reached`.
- فایل‌منیجر: کلید 1 تا 1024 بایت، بدون نویسه کنترلی، `/` آغازین، `//`، `.`/`..` و پیشوند `.mrk/` → 422
  `invalid_key`؛ باکت linked فقط‌خواندنی → 409 `bucket_read_only`. آپلود stream است: تا 64 MiB یک `PutObject`
  (`UNSIGNED-PAYLOAD`)، بزرگ‌تر یا بدون طول → multipart با part حداقل 16 MiB (با طول معلوم بدون buffer کردن part،
  با طول نامعلوم حداکثر یک part در حافظه؛ شکست → `AbortMultipartUpload`). دانلود stream با `Content-Disposition:
  attachment` و پشتیبانی `Range`. حذف حداکثر 1000 کلید؛ جابه‌جایی پوشه حداکثر 10000 شیء (copy+delete). لینک
  اشتراک: presigned GET روی `public_endpoint`، `expires_seconds` 1 تا 604800 (پیش‌فرض 3600) → 422 `invalid_expiry`.
- همه mutationها CSRF و audit (`s3.settings.update`، `s3.bucket.*`، `s3.identity.*`، `s3.key.*`، `s3.object.*`،
  `s3.folder.create`) دارند؛ هیچ secret در audit، snapshot یا DB نمی‌آید.

## 11. پیگیری آپدیت image (S10، Gate 18)

تنظیمات و آخرین نتایج در `data_dir/control-plane/updates.json` (بدون جدول دیتابیس). `PUT /api/v1/updates/settings`
(`updates:write` + CSRF) فیلدهای فرستاده‌شده را با تنظیمات فعلی ادغام و کل نتیجه را اعتبارسنجی می‌کند؛ خطا 422
`invalid_settings` (یا کد پروکسی مثل `proxy_not_found`/`no_default_proxy`).

| تنظیم | پیش‌فرض | بازه / توضیح |
|---|---|---|
| `enabled` | `true` | بررسی زمان‌بندی‌شده؛ بررسی دستی (`POST /check` → 202) همیشه مجاز است |
| `interval_hours` | `12` | 1 تا 720؛ اولین بررسی 60 ثانیه بعد از شروع؛ بعد از شکست agent، تلاش دوباره بعد از 15 دقیقه |
| `ignore` | `[]` | حداکثر 100 الگوی `fnmatch` (حساس به حروف) روی `nginx`، `nginx:tag`، `docker.io/library/nginx[:tag]`، `library/nginx[:tag]` |
| `include_stopped` | `false` | بدون آن فقط کانتینرهای `running`/`restarting`/`paused` |
| `notify` | `true` | انتشار `update.available` (info)؛ dedupe_key `update.available:<reference>@<digest>` و ثبت پایدار آخرین digest اعلام‌شده (بعد از restart تکرار نمی‌شود) |
| `proxy_id` | `null` | پروکسی همه بررسی‌ها (`null` مستقیم، `"default"`، یا شناسه) |
| `registry_proxies` | `{}` | override به ازای رجیستری منطقی (`docker.io`) یا host یک mirror؛ مقدار `null` یعنی مستقیم |
| `mirrors` | `{}` | رجیستری → حداکثر 5 endpoint به ترتیب، مثلاً `{"docker.io": ["docker.arvancloud.ir"]}`؛ `host[:port]` (https) یا URL `http(s)://host[:port]/prefix` (مثلاً `https://registry.example.com/ghcr.io` → `/v2/ghcr.io/<repo>/manifests/<tag>`) |
| `mirror_fallback` | `true` | بعد از شکست همه mirrorها، رجیستری اصلی هم امتحان شود؛ در صورت شکست همه، خطای اولین endpoint گزارش می‌شود |
| `insecure_registries` | `[]` | رجیستری‌هایی که با HTTP صحبت می‌کنند (`docker.io` مجاز نیست) |
| `allow_get_fallback` | `true` | اگر HEAD هدر `Docker-Content-Digest` نداشت، manifest با GET (≤4 MiB) هش شود — **هرگز** روی `registry-1.docker.io` (GET از سهمیه کم می‌کند) |
| `timeout_seconds` | `15` | 3 تا 120 |
| `concurrency` | `4` | 1 تا 16 بررسی هم‌زمان |

رفتار ثابت: Docker Hub از `registry-1.docker.io` با `HEAD` (Accept: OCI index، Docker manifest list v2، OCI manifest،
Docker schema2) و token anonymous (`WWW-Authenticate` → realm/service/scope؛ realm باید https باشد، cache تا
`expires_in - 30s`) بررسی می‌شود. هدرهای `ratelimit-limit`/`ratelimit-remaining`/`docker-ratelimit-source` در
`rate_limits` پاسخ `GET /images` نمایش داده می‌شوند. همه درخواست‌ها از `outbound.py` (سیاست مقصد، DNS پنل، پروکسی)
می‌گذرند و در جدول «سرویس → پروکسی» با kind `registry` دیده می‌شوند (ردیف `default` + هر رجیستری/mirror). image
pinned (`@sha256:`) هرگز به رجیستری درخواست نمی‌دهد و `update_available: false` دارد. digest محلی از RepoDigests همان
رجیستری+repository (نیازمند endpoint `GET /v1/docker/images` و `image_id` کانتینر در agent؛ بدون آن `update_available:
null`). کدهای خطای هر image: `auth_required`، `not_found`، `rate_limited`، `unreachable`، `proxy_unavailable`،
`digest_unavailable`، `invalid_reference` (جزئیات در `error_detail`). **هیچ آپدیت خودکاری انجام نمی‌شود.**

## بکاپ سرور و دیتابیس‌ها (Gate 18 S6) — `server_backups`

قرارداد API در `docs/31 §4`؛ این بخش تنظیمات، جزئیات پیاده‌سازی و دستورهای restore دستی است.

- **تنظیمات ماژول:** `GET/PUT /api/v1/server-backups/settings` → `{timezone}` (پیش‌فرض `Asia/Tehran`، هر نام
  IANA؛ در `data_dir/control-plane/server-backups.json`). تغییر منطقه زمانی `next_run_at` همه jobها را دوباره
  محاسبه می‌کند. scheduler هر ۳۰ ثانیه jobهای سررسید را اجرا می‌کند؛ اگر اجرای قبلی هنوز تمام نشده باشد آن نوبت رد
  می‌شود. cron پنج‌فیلدی: `*`، `*/n`، `a-b`، `a-b/n`، `a/n`، فهرست، نام ماه (`jan`..`dec`) و روز (`sun`..`sat`،
  `0` و `7` = یکشنبه)؛ اگر هر دو فیلد روز محدود باشند یکی کافی است (Vixie). زمان ناموجود (DST) رد می‌شود.
- **متغیرهای محیطی Control Plane:** `MRK_SERVER_BACKUP_CONCURRENCY` (پیش‌فرض 2، 1..8)،
  `MRK_SERVER_BACKUP_PART_BYTES` (اندازه part در multipart، پیش‌فرض 8MiB، حداقل 5MiB)، `MRK_S3_ENGINE_URL`
  (مقصد `mrk_s3`، پیش‌فرض `http://127.0.0.1:9000`).
- **متغیرهای محیطی Agent:** `MRK_AGENT_HOST_VOLUMES` (پیش‌فرض `/host/volumes` = mount فقط‌خواندنی
  `/var/lib/docker/volumes`)، `MRK_AGENT_BACKUP_MAX_SECONDS` (سقف هر dump/archive، پیش‌فرض 6 ساعت). کاربر 10001
  فایل‌هایی را که نمی‌تواند بخواند رد و شمارش می‌کند (`details.stats.unreadable`)؛ برای volumeهای root-owned،
  Agent را با `user: "0:0"` و `cap_add: [DAC_READ_SEARCH]` (بقیه همچنان `cap_drop: ALL`) اجرا کنید.
- **مقصدها:** `local` فقط زیر data dir (پیش‌فرض `/data/modules/server-backups/local`؛ `control-plane`، `npm`،
  `pypi`، `logs`، `backups`، `modules/s3` و `agent` رد می‌شوند)؛ `s3` از `outbound.py` (پروکسی در جدول «سرویس →
  پروکسی» با kind `server_backup_destination`)؛ `mrk_s3` روی loopback، path-style، با کلید تایپ‌شده یا یک access key
  موجود از identityهای S3 (secret از SecretStore). تغییر endpoint یا access key بدون وارد کردن دوباره secret →
  `422 secret_required`. حذف مقصد در حال استفاده → `409 destination_in_use`.
- **منابع:** `GET /sources` از Agent (`GET /v1/backup/sources`). تشخیص دیتابیس از نام image
  (postgres/postgis/timescaledb، mysql/percona، mariadb، mongo، redis/valkey/keydb). کانتینرهای Dokploy
  `protected` و با `note` نمایش داده می‌شوند؛ dump مجاز است (فقط‌خواندنی) ولی بکاپ خود Dokploy توصیه می‌شود.
- **Agent (امضاشده):** `GET /v1/backup/sources`، `GET /v1/backup/volumes/{name}/archive` (فقط driver `local` با
  Mountpoint استاندارد)، `POST /v1/backup/db/{container}/dump` `{engine, database?}` (فقط همین دو فیلد). خروجی
  stream قاب‌بندی‌شده `D|u32|data` … و یک قاب پایانی `E|u32|{"ok",…}`؛ بدون قاب `E` موفق، اجرا شکست می‌خورد. exec
  Docker فقط `POST /containers/{64hex}/exec` (بدنه ساخته‌شده در Agent با `Cmd` برابر یکی از templateهای ثابت،
  `Env` فقط `PGPASSWORD|MYSQL_PWD|MRK_DB_USER|MRK_DB_PASSWORD|MRK_DB_NAME|REDISCLI_AUTH`، بدون `User`/`Privileged`/
  TTY/stdin)، `POST /exec/{64hex}/start` و `GET /exec/{64hex}/json`. templateها: `pg_dump --format=custom
  --no-password --username U --dbname D`؛ `mysqldump|mariadb-dump --single-transaction --routines --events
  --triggers --hex-blob --user=U (--databases D | --all-databases)` با `MYSQL_PWD`؛ mongo:
  `sh -c 'printf "%s\n" "$MRK_DB_PASSWORD" | mongodump --archive --username="$MRK_DB_USER"
  --authenticationDatabase=admin [--db="$MRK_DB_NAME"]'` (رمز از stdin، هرگز در argv)؛ `redis-cli --rdb -` با
  `REDISCLI_AUTH` (از `REDIS_PASSWORD` یا `--requirepass` در Cmd). credential از env کانتینر و فقط داخل Agent؛
  stderr ابزار (redact‌شده) فقط در لاگ Agent می‌ماند. tar volume: symlink به‌صورت link ذخیره و هرگز دنبال نمی‌شود،
  باز کردن با `O_NOFOLLOW` نسبت به descriptor والد، FIFO/socket/device رد و شمارش می‌شوند.
- **رمزنگاری:** MRKBKP2 (همان `backup.py`) با header `kind: "server-backup"`، passphrase تصادفی ۲۵۶ بیتی per job
  در SecretStore (header فقط `key_ref` دارد)، scrypt `n=2^15`. فشرده‌سازی gzip داخل رمز برای همه جز postgres
  (`-Fc` خودش فشرده است). در `runs` مقدار `sha256` چکسام فایل رمز‌شده ذخیره‌شده و `source_bytes` حجم خام است.
  کلید: `POST /jobs/{id}/key` (`backup:server:write` + CSRF، audit `server_backup.key.export`) →
  `{passphrase, key_ref, decrypt_command}`. حذف job کلید را نگه می‌دارد مگر `delete_artifacts: true`.
- **رویدادها و audit:** `server_backup.succeeded` (info) و `server_backup.failed` (error، `details.error_code`)
  با `dedupe_key=server_backup:<job_id>`؛ audit: `server_backup.destination.create|update|delete|test`،
  `server_backup.job.create|update|delete|run`، `server_backup.run` (نتیجه هر اجرا، بدون actor)،
  `server_backup.run.download`، `server_backup.key.export`، `server_backup.settings.update`.

### Restore دستی (P1؛ restore خودکار هنوز نیست)

1. فایل را از `GET /runs/{id}/download` بگیرید و کلید را از «Export key» در یک فایل `key.txt` (mode 0600) بگذارید.
2. رمزگشایی (چکسام و احراز هویت همه رکوردها بررسی می‌شود؛ فایل ناقص حذف می‌شود):
   ```sh
   python -m mrk_control_plane.modules.server_backups_crypto backup.mrkbak -o payload --passphrase-file key.txt --decompress
   # داخل کانتینر MRK بدون export کلید:  ... -o payload --data-dir /data --decompress
   ```
3. بر اساس نوع:
   ```sh
   # volume (tar): سرویس مصرف‌کننده را متوقف کنید
   docker run --rm -v VOLUME:/restore -v "$PWD":/in alpine sh -c 'cd /restore && tar -xpf /in/payload'
   # postgres (custom format)
   docker exec -i DB pg_restore -U USER -d DB --clean --if-exists < payload
   # mysql / mariadb (SQL)
   docker exec -i DB sh -c 'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD"' < payload      # mariadb: mariadb ... $MARIADB_ROOT_PASSWORD
   # mongo (archive)
   docker exec -i DB sh -c 'mongorestore --archive --drop -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin' < payload
   # redis (RDB): redis را متوقف کنید، dump.rdb را در دایرکتوری داده (معمولاً /data) جایگزین و دوباره start کنید
   docker cp payload DB:/data/dump.rdb && docker restart DB
   ```

## اسکن آسیب‌پذیری image (Gate 19 S8) — `vuln`

- **تنظیمات پنل** (`GET/PUT /api/v1/vuln/settings`، PUT ادغامی؛ ذخیره در `data_dir/control-plane/vuln.json`):
  `enabled` (true)، `interval_hours` (24؛ 1..720)، `ecosystems_extra` ([]؛ feedهایی که همیشه دانلود شوند، از
  `Debian, Ubuntu, Alpine, Wolfi, Chainguard, AlmaLinux, Rocky Linux, npm, PyPI`؛ شکل `Debian:12` هم پذیرفته و به
  `Debian` نرمال می‌شود)، `feed_base_url` (`https://osv-vulnerabilities.storage.googleapis.com`؛ mirror محلی با همان
  ساختار `<base>/<Ecosystem>/all.zip`)، `severities_to_notify` (`["critical","high"]`؛ زیرمجموعه
  critical/high/medium/low، خالی = بدون اعلان)، `include_stopped` (false)، `proxy_id` (null = مستقیم، `default`
  یا شناسه پروکسی؛ از جدول «سرویس‌های خارجی» هم با kind `vuln_feed` و id `osv` قابل تغییر)، `feed_max_mb` (1024؛
  16..4096؛ سقف دانلود هر zip، محتوای باز‌شده حداکثر 8 برابر).
- **ثابت در کد (بدهی شناخته‌شده):** بازه بررسی مجدد feed حداقل 1 ساعت (`FEED_RECHECK_SECONDS`)، اعتبار cache
  فهرست پکیج هر image id هفت روز (`refresh_inventory` در اسکن دستی آن را دور می‌زند)، حداکثر 300 image در هر
  اسکن، تأخیر شروع زمان‌بندی 120 ثانیه، تلاش مجدد پس از خطا 30 دقیقه، سقف هر فایل در Agent 8MiB (rpmdb 40MiB،
  `status.d` 16MiB) و کل پاسخ 40MiB، timeout درخواست Agent 180 ثانیه، حداکثر 500 قاعده ignore.
- **ذخیره‌سازی:** ایندکس OSV در `data_dir/modules/vuln/osv.sqlite` و نتایج/ cache فهرست پکیج/ dedupe اعلان‌ها در
  `data_dir/modules/vuln/results.sqlite` (قابل بازسازی با اسکن مجدد؛ عمداً روی PGlite نیست و در بکاپ نیست).
  قواعد ignore در جدول `vuln_ignores` دیتابیس Control Plane (migration `20261108_0008`) و در بکاپ هستند.
- **audit:** `vuln.scan`، `vuln.settings.update`، `vuln.ignore.create`، `vuln.ignore.delete`.

## فایروال و ضدحمله (Gate 19 S7) — `firewall`

مرجع کامل API: `docs/32` §3.1. همه از پنل (`PUT /api/v1/firewall/settings`، merge جزئی) قابل تنظیم است:

| کلید | پیش‌فرض | بازه/توضیح |
|---|---|---|
| `mode` | `dry_run` | `off` (بدون تشخیص، جدول `inet mrk` حذف) / `dry_run` (فقط ثبت، `simulated`) / `enforce` (نیازمند `"confirmation": "ENFORCE"`؛ IP درخواست‌دهنده خودکار allowlist می‌شود) |
| `allowlist` | `[]` | حداکثر 256 مورد `{cidr, note}`؛ همیشه اول ارزیابی می‌شود |
| `allowlist_private` | `true` | افزودن RFC1918، `100.64/10`، link-local، ULA و loopback به allow set |
| `allow_private_blocks` | `false` | اجازه مسدود کردن محدوده خصوصی (با `allowlist_private: true` همچنان allowlist برنده است) |
| `default_ban_seconds` | 3600 | 60..`max_ban_seconds`؛ برای block دستی بدون `duration_seconds` |
| `max_ban_seconds` | 30 روز | سقف 365 روز |
| `max_blocks` | 10000 | 1..65536 (blockهای فعال + simulated) |
| `poll_interval_seconds` | 15 | 5..3600؛ هر tick: انقضا، خواندن سیگنال‌ها، قواعد، همگام‌سازی helper |
| `history_retention_days` | 30 | 1..3650؛ پاک‌سازی ساعتی تاریخچه تصمیم‌ها و blockهای حذف‌شده |
| `notify` | `true` | رویدادهای `firewall.blocked` / `firewall.would_block` |
| `sources.sshd` | `{enabled: true, path: /host/log/system/auth.log}` | مسیر از دید `mrk-firewall` و فقط زیر `/host/log/` |
| `sources.traefik` | `{enabled: false, path: /host/log/traefik/access.log}` | JSON یا CLF |
| `sources.mrk` | `{enabled: true}` | شکست‌های `auth.login` از audit همین Control Plane |
| `sensitive_paths` | `/.env`، `/.git/`، `/wp-login.php`، … (16 مورد) | حداکثر 100؛ تطبیق segment کامل، بدون حساسیت به حروف |

قواعد آستانه‌ای در `GET/POST/PATCH/DELETE /api/v1/firewall/rules` (threshold 1..100000، window 10..86400s، ban
60s..365d). **متغیرهای محیطی Control Plane:** `MRK_FIREWALL_URL` + `MRK_FIREWALL_KEY_FILE` (جفت‌سازی از env، فرم پنل
قفل می‌شود). **متغیرهای محیطی helper:** `MRK_FIREWALL_LISTEN` (پیش‌فرض `unix:/run/mrk-firewall/firewall.sock`؛ یا
`host:port`)، `MRK_FIREWALL_STATE_DIR` (`/var/lib/mrk-firewall`)، `MRK_FIREWALL_LOG_ROOT` (`/host/log`؛ ریشه واقعی برای
مسیرهای منطقی `/host/log/...`)، `MRK_FIREWALL_NFT` (`/usr/sbin/nft`)، `MRK_FIREWALL_FORCE_DRY_RUN` (`false`؛ `true` =
هرگز قاعده نصب نشود). ثابت‌های کد (عمداً غیرقابل تنظیم برای ایمنی): حداقل prefix block (`/16` و `/32`)، سقف 1024
مورد allow و 65536 block در helper، حداکثر 8 منبع و 5000 سیگنال در هر poll، 2MiB خواندن در هر منبع در هر poll،
طول خط 16KiB.

## مدیریت دیتابیس (Gate 19 S9) — `dbadmin`

مرجع کامل API: `docs/32` §5.1. تنظیمات از پنل (`GET/PUT /api/v1/dbadmin/settings`، merge جزئی، `db:write` + CSRF؛
فایل `data_dir/control-plane/dbadmin.json`):

| کلید | پیش‌فرض | بازه/توضیح |
|---|---|---|
| `connect_timeout_seconds` | 5 | 1..60 |
| `statement_timeout_ms` | 15000 | 100..600000؛ PostgreSQL `statement_timeout`، MySQL `max_execution_time` / MariaDB `max_statement_time`، Mongo `maxTimeMS`، Redis socket timeout |
| `max_rows` | 1000 | 1..1000 (سقف ردیف query؛ صفحه جدول حداکثر 500) |
| `max_cell_bytes` | 65536 | 256..1MiB؛ سلول بزرگ‌تر کوتاه و در `truncated_cells` شمرده می‌شود |
| `max_response_bytes` | 5MiB | 64KiB..5MiB؛ پس از آن `truncated_reason: "response_size"` |
| `export_max_rows` | 100000 | 1..5,000,000 |
| `export_max_bytes` | 100MiB | 1MiB..2GiB |
| `export_statement_timeout_ms` | 300000 | 1s..1h |
| `concurrency_per_connection` | 2 | 1..2 (بیشتر → `429 connection_busy` پس از 10 ثانیه انتظار) |

- **اتصال‌ها:** جدول `dbadmin_connections` (migration `20261108_0010`)؛ رمز فقط در SecretStore (write-only، هرگز در
  پاسخ/لاگ/audit). تغییر engine/host/port یا پایین آوردن `tls_mode` بدون وارد کردن دوباره رمز → `422 password_required`.
- **شبکه:** دیتابیس‌های Dokploy فقط روی شبکه `dokploy-network` هستند؛ سرویس `mrk-mirror` باید به آن (با
  `external: true`) بپیوندد — `GET /api/v1/dbadmin/network-guide` snippet compose را می‌دهد. MRK شبکه Dokploy را
  تغییر نمی‌دهد.
- **سیاست مقصد:** private/LAN و عمومی مجاز؛ loopback (خود appliance/PGlite)، link-local و metadata ابری
  (`169.254.169.254`، `fd00:ec2::254`، `100.100.100.200`)، multicast/reserved رد. نام یک بار resolve و همه پاسخ‌ها
  بررسی می‌شوند و driver به همان IP وصل می‌شود (در `tls_mode: verify` نام برای تأیید گواهی داده می‌شود).
- **درایورها (pin در `apps/control-plane/pyproject.toml`؛ همین pinها باید در `deploy/appliance/requirements.txt`
  هم اضافه شوند):** `psycopg[binary]==3.3.8` (موجود)، `PyMySQL==1.2.3` (MIT)، `pymongo==4.19.0` (Apache-2.0) +
  `dnspython==2.9.2` (ISC)، `redis==8.1.0` (MIT).
- **تست یکپارچه اختیاری:** `MRK_DBADMIN_DOCKER_TESTS=1 pytest apps/control-plane/tests/test_dbadmin_integration.py`
  (کانتینرهای موقت postgres:16-alpine، mysql:8، mongo:7، redis:7 روی پورت تصادفی 127.0.0.1، حذف خودکار).
