# 10 — Execution Plan و گزارش Gateها

این سند مرجع اجرای پروژه است. بعد از هر Gate، وضعیت، شواهد و کار باقی‌مانده در همین فایل و گزارش گفتگو به‌روزرسانی می‌شود.

## وضعیت کلی

- [x] Gate 0 — بازبینی محصول، معماری، امنیت و انتخاب فناوری
- [x] Gate 1 — Foundation قابل اجرا
- [x] Gate 2 — npm Registry baseline
- [x] Gate 3 — PyPI Registry baseline
- [x] Gate 4 — Multi-upstream failover و offline cache
- [x] Gate 5 — Admin authentication و RBAC
- [x] Gate 6 — Upstream management UI/API
- [x] Gate 7 — Package catalog و cache operations
- [x] Gate 8 — Observability، audit و task management
- [x] Gate 9 — Backup، restore و lifecycle
- [ ] Gate 10 — Security hardening و production release
- [ ] Gate 11 — Modular Edge و Domain Routing
- [ ] Gate 12 — Uptime Monitoring
- [ ] Gate 13 — DNS Management
- [ ] Gate 14 — Unified Modular Appliance

## Gate 0 — Review Baseline

### انجام‌شده

- دامنه MVP و non-goalها
- 122 User Story با Acceptance Criteria
- معماری دو موتور بالغ
- repository scorecard
- trust boundary، access matrix و threat baseline
- بررسی نسخه‌های فعال در 2026-11-07

### تصمیم نسخه اولیه

- Verdaccio: خط maintenance `6.11.1`؛ major 7 تا پایان compatibility review وارد production نمی‌شود.
- devpi-server: `6.21.0`؛ beta 7 رد می‌شود.
- devpi-web: `5.2.0`
- devpi-client: `7.3.0` فقط برای bootstrap داخلی
- FastAPI: `0.162.0`
- React Admin: `5.15.5`

این pinها تا قبل از lock/hash/security scan «candidate» هستند.

## Gate 1 — Foundation

### کارها

- [x] ساخت monorepo directories
- [x] `.gitignore`، `.editorconfig` و `.env.example`
- [x] `versions.lock.yaml`
- [x] FastAPI application skeleton
- [x] liveness/readiness/status endpoints
- [x] correlation ID و security headers middleware
- [x] error envelope و structured logging baseline
- [x] unit tests بدون dependency خارجی
- [x] React Admin/Vite skeleton
- [x] Compose development skeleton
- [x] Docker Appliance skeleton با یک image و `/data`
- [x] process supervision و health aggregation design
- [x] CI baseline و انتشار GHCR
- [x] اجرای تست و ثبت نتیجه

### خروجی Gate

API و UI skeleton قابل build، Docker Appliance skeleton با یک bind mount، health contract روشن و هیچ secret committed وجود ندارد.

### گزارش Gate 1 — 2026-11-07

#### انجام‌شده

- control plane خواندنی، UI اولیه، Docker/Compose تک‌کانتینری و workflowهای CI/GHCR ساخته شد.
- dependencyها lock شدند و override امنیتی محدود برای `decode-uri-component@0.5.1` ثبت شد.
- قرارداد Supervisor و health aggregation در `docs/11-process-supervision-and-health.md` ثبت شد.

#### تست و شواهد

- Ruff: موفق، بدون finding.
- pytest: `5 passed`؛ یک deprecation warning از TestClient وابسته به httpx باقی است.
- TypeScript typecheck و Vite production build: موفق.
- npm audit رسمی: صفر vulnerability.
- Docker build: موفق، image ID با prefix `9a903a1e56b3`.
- smoke test: readiness و admin HTML برابر HTTP 200؛ health برابر healthy.

#### امنیت و دسترسی

- runtime با UID/GID `10001`، root filesystem فقط‌خواندنی، `cap_drop: ALL` و
  `no-new-privileges` اجرا شد.
- CORS/Host wildcard در production رد می‌شود؛ responseها correlation ID و headerهای امنیتی دارند.
- هیچ secret، Docker socket، SSH key یا host root mount اضافه نشد.

#### باقی‌مانده

- هشدار bundle بزرگ UI باید با code splitting در Gate UI بهینه شود.
- [x] deprecation مسیر TestClient/httpx با `httpx2 2.16.0` پیش از Gate 10 حذف شد.
- Verdaccio و Supervisor در Gate 2 تکمیل شدند؛ devpi در Gate 3 باقی مانده است.

## Gate 2 — npm Registry

- [x] Verdaccio image/tag candidate pin
- [x] storage و auth config
- [x] npmjs و Liara uplinks
- [x] scoped/unscoped routing
- [x] anonymous read و authenticated publish policy
- [x] health probe
- [x] npm/pnpm/Yarn E2E
- [x] cache-hit و قطع کامل اینترنت test

### گزارش Gate 2 — 2026-11-07

#### انجام‌شده

- Verdaccio 6.11.1 و Supervisor 4.3.0 داخل image تک‌کانتینری اضافه شدند.
- npmjs به‌عنوان primary و Liara به‌عنوان fallback برای scoped/unscoped تنظیم شد.
- health تجمیعی control plane، خرابی registry محلی را readiness=503 می‌کند.
- CI اکنون dependency audit و E2E cache آنلاین/آفلاین را اجرا می‌کند.

#### تست و شواهد

- 7 تست Python و Ruff موفق.
- npm audit: صفر High/Critical؛ ریسک Moderate در سند Gate 2 ثبت شده است.
- npm، pnpm، Yarn 1 و Yarn 4 نصب واقعی موفق داشتند.
- failover واقعی با primary قطع و پاسخ HTTP 200 از Liara اثبات شد.
- cache واقعی روی Docker internal network بدون اینترنت قابل دریافت بود.

#### امنیت و دسترسی

- self-registration خاموش، anonymous فقط read و publish/unpublish نیازمند authentication است.
- TLS validation uplinkها فعال و health target فقط loopback IP پذیرفته می‌شود.
- config رجیستری داخل root filesystem فقط‌خواندنی است و cache فقط در `/data/npm` نوشته می‌شود.

#### باقی‌مانده

- احراز هویت و مدیریت کاربران از پنل در Gate 5 اضافه می‌شود.
- TLS روی endpoint عمومی وظیفه PaaS/reverse proxy است و Gate 10 validate می‌شود.
- PyPI/devpi و cache آفلاین آن در Gate 3 پیاده‌سازی می‌شود.

## Gate 3 — PyPI Registry

- [x] reproducible devpi image از package pin‌شده
- [x] non-root runtime
- [x] persistent storage و secure initialization
- [x] outside URL/proxy contract
- [x] pip/uv/Poetry E2E
- [x] cache-hit و restart persistence

### گزارش Gate 3 — 2026-11-07

#### انجام‌شده

- devpi-server `6.21.0`، devpi-web `5.2.0` و devpi-client `7.3.0` به image واحد اضافه شدند.
- initialization با root password تصادفی و secret پایدار، permission برابر `0600` و marker یک‌بارمصرف انجام می‌شود.
- bootstrap فقط دیتای تازه را پیکربندی می‌کند و تغییر خودکار upstream روی دیتای موجود را fail-closed رد می‌کند.
- به‌دلیل timeout قطعی IPv4 سرور فعلی به `pypi.org`، upstream قابل‌دسترسی رسمی لیارا برای baseline تنظیم شد؛ ترتیب primary/fallback در Gate 4 به router منتقل می‌شود.
- endpoint عمومی pip/uv/Poetry برابر `/root/pypi/+simple/` و پورت `3141` است.

#### تست و شواهد

- 10 تست Python و Ruff موفق؛ build TypeScript/Vite و Docker image موفق.
- fresh-install و health تجمیعی هر سه process موفق؛ status دو registry را ready گزارش کرد.
- `sampleproject==4.0.0` آنلاین از Liara وارد devpi شد و artifact در volume ذخیره شد.
- همان container با همان volume روی Docker network از نوع `--internal` بالا آمد؛ اتصال مستقیم به Liara با DNS failure شکست خورد ولی pip همان artifact را از کش دریافت کرد.
- restart persistence و اجرای read-only/cap-drop/no-new-privileges موفق بود.

#### امنیت و دسترسی

- devpi با UID/GID `10001` اجرا می‌شود؛ root credential فقط داخل `/data/pypi/auth` یا Docker secret خوانده می‌شود و به browser/API ارسال نمی‌شود.
- control plane تا ایجاد marker موفق bootstrap، readiness را `503` نگه می‌دارد.
- `--restrict-modify root` فعال است و تعویض خودکار mirror روی دیتای قبلی برای جلوگیری از serial mismatch ممنوع است.

#### باقی‌مانده

- harness سازگاری سه client در CI نگهداری و در Gate 4 همراه router دوباره اجرا می‌شود.
- router چند upstream، circuit breaker و حالت offline صریح در Gate 4 پیاده‌سازی می‌شود.

## Gate 4 — Failover و Offline

- [x] upstream policy model
- [x] SSRF-safe probe client
- [x] error classifier
- [x] circuit breaker
- [x] PyPI upstream router
- [x] Verdaccio multi-uplink contract
- [x] offline mode
- [x] chaos tests: DNS/timeout/reset/5xx/checksum

### گزارش میان‌مرحله Gate 4 — 2026-11-07

#### انجام‌شده

- router اختصاصی PyPI روی loopback و خارج از core devpi ساخته شد؛ ترتیب پیش‌فرض `pypi.org → Liara` است.
- URLها فقط HTTPS، بدون credential و با host allowlist پذیرفته می‌شوند؛ DNS هر مقصد پیش از درخواست بررسی و IP خصوصی/loopback/link-local رد می‌شود.
- redirect دستی و محدود است و هر hop دوباره با SSRF policy اعتبارسنجی می‌شود.
- timeout/DNS/network و HTTPهای retryable طبقه‌بندی می‌شوند؛ circuit پس از threshold باز و بعد از cooldown half-open می‌شود.
- حالت cache-only با marker پایدار فعال است و status امن router از Control Plane در `/api/v1/upstreams` دیده می‌شود.

#### تست و شواهد

- primary عمداً خراب شد؛ پس از دو خطا circuit آن `open` و `last_selected` برابر `Liara` شد.
- دانلود واقعی `sampleproject==4.0.0` از مسیر devpi→router→Liara موفق بود.
- در offline mode، artifact کش‌شده موفق و cache-miss برای `peppercorn==0.6` بدون outbound ناموفق بود.
- 15 تست Python، Ruff و build کامل image موفق‌اند.

#### امنیت و دسترسی

- router فقط روی `127.0.0.1:3142` گوش می‌دهد و از host publish نمی‌شود.
- `trust_env=False` مانع proxy injection محیطی است؛ credential در URL رد و response status هیچ secret ندارد.
- devpi fresh-install با `--no-root-pypi` ساخته می‌شود تا حتی اولین sync نیز نتواند router را دور بزند.

### گزارش تکمیل Gate 4 — 2026-11-07

- chaos خودکار `DNS error`، connect/read timeout، TCP reset و HTTP 503، انتخاب fallback و state circuit را اثبات می‌کند.
- لینک hash استاندارد PEP 503 حفظ می‌شود و artifact پیش از exposure در فایل موقت محدود spool و SHA-256 آن verify می‌شود.
- checksum نامعتبر با `checksum_mismatch` ثبت، فایل موقت پاک و upstream بعدی امتحان می‌شود؛ byte خراب هرگز به client ارسال نمی‌شود.
- حداکثر اندازه artifact قابل تنظیم است و redirect همچنان در هر hop SSRF-validate می‌شود.
- ۴۶ تست کامل backend، Ruff و build تولیدی پنل پس از این تغییرات موفق‌اند.

## Gate 5 — Identity و Access

- [x] Argon2id local auth
- [x] secure session/refresh flow
- [x] CSRF/CORS policy
- [x] roles و object permissions
- [x] scoped API tokens
- [x] audit login/access changes
- [x] MFA/OIDC design hooks

### گزارش میانی Gate 5 — 2026-11-07

- صفحه ورود فارسی/انگلیسی، bootstrap امن Owner و rate limit ورود فعال شد.
- session در cookie از نوع HttpOnly/SameSite=Strict و در production از نوع Secure است؛ mutationهای browser به CSRF نیاز دارند.
- نقش‌های immutable شامل Owner، Admin، Operator، Developer و Viewer هستند و permissionها روی endpointها enforce می‌شوند.
- ساخت، تغییر نقش و فعال/غیرفعال‌سازی کاربر از پنل انجام می‌شود؛ تغییر هویت تمام sessionها و tokenهای قبلی را revoke می‌کند.
- API token دارای scope و expiry اجباری است، مقدار کامل فقط یک‌بار نمایش داده می‌شود و فقط hash در SQLite ذخیره می‌شود.
- schema هویت دارای `identity_provider` و `mfa_enabled` است و capability endpoint وضعیت fail-closed قابلیت‌های OIDC/MFA را اعلام می‌کند.
- 20 تست Python، Ruff و TypeScript موفق هستند؛ گزارش کامل در `docs/17-gate5-identity-access.md` ثبت شده است.

## Gate 6 — Upstream Admin

- [x] upstream CRUD و reorder
- [x] connection test breakdown
- [x] block/unblock/offline controls
- [x] secret replace flow
- [x] health timeline
- [x] typed confirmation برای عملیات حساس

### گزارش میانی Gate 6 — 2026-11-07

- upstreamهای PyPI در فایل پایدار و atomic ذخیره می‌شوند و router تغییر ترتیب، enable و block را بدون restart کامل می‌خواند.
- URL policy آدرس‌های credentialدار، scheme ناامن و IPهای private/local را رد می‌کند؛ runtime نیز DNS/redirect را دوباره validate می‌کند.
- connection test مراحل DNS، TCP، TLS و HTTP را جدا با latency گزارش می‌کند.
- block/unblock، حالت cache-only برای PyPI، permission و audit از API و پنل دوزبانه فعال است.
### گزارش تکمیل Gate 6 — 2026-11-07

- health check هر upstream در جدول ORM نسخه‌دار با stageهای DNS/TCP/TLS/HTTP، latency، نتیجه، actor و retention محدود ذخیره می‌شود.
- endpoint تاریخچه و پنل دوزبانه timeline، تست لحظه‌ای و tooltip امن را نمایش می‌دهند.
- credential خصوصی با AES-256-GCM، nonce یکتا، فایل atomic و permission حداقل نگه‌داری می‌شود؛ API فقط metadata برمی‌گرداند و secret/reference در list، audit یا support bundle نیست.
- Bearer برای npm/PyPI و Basic برای PyPI پشتیبانی می‌شود؛ replace/remove permission و CSRF و audit دارد.
- PyPI router credential را واقعاً مصرف می‌کند و Authorization فقط به host اصلی فرستاده می‌شود، نه CDN یا redirect host.
- Verdaccio config را از upstream store تولید می‌کند؛ bearer token فقط از `token_env` process خوانده می‌شود و در YAML نوشته نمی‌شود.
- mutation npm فقط process Verdaccio را از socket محلی Supervisor reload می‌کند؛ offline mode با حذف proxyها واقعاً cache/private-only است.
- ویرایش نام/URL/priority/timeout/enabled و حذف با typed confirmation در API و پنل کامل است؛ حذف یا غیرفعال‌سازی آخرین upstream فعال فقط پس از ورود صریح ecosystem به offline mode مجاز است.
- migration `20261107_0003` روی rehearsal تا `0001` downgrade و دوباره تا head upgrade شد و داده Owner حفظ شد.
- build TypeScript، ۵۱ تست کامل backend و Ruff همگی موفق‌اند.

## Gate 7 — Package/Cache Admin

- [x] catalog projection
- [x] unified search
- [x] version/artifact detail
- [x] purge preview/job
- [x] revalidate/pin/quarantine
- [x] prefetch از lockfile

### گزارش میانی Gate 7 — 2026-11-07

- کاتالوگ read-only از artifactهای واقعی Verdaccio/devpi ساخته می‌شود و نام، نسخه، تعداد فایل، حجم، pin و quarantine را یکپارچه نمایش می‌دهد.
- search/filter برای npm و PyPI و UI دوزبانه فعال است.
- pin و quarantine دارای permission/audit هستند و quarantine دلیل اجباری دارد.
- purge-preview تعداد artifact، حجم، وضعیت pin و عبارت typed confirmation را بدون حذف داده برمی‌گرداند.
- worker پایدار SQLite برای حذف، revalidate و prefetch اضافه شده و عملیات پس از restart از صف ادامه پیدا می‌کند.
- حذف npm به trash قابل‌بازیابی منتقل می‌شود و حذف PyPI از API رسمی devpi استفاده می‌کند؛ Pin حذف را fail-closed متوقف می‌کند.
- prefetch برای `requirements.txt` و `package-lock.json` از مسیر registry محلی انجام می‌شود و progress/cancel/retry در پنل دیده می‌شود.

### گزارش تکمیل Gate 7 — 2026-11-07

- harness ایزوله `scripts/e2e_local_engines.py` موتور واقعی Verdaccio 6.11.1 و devpi-server 6.21.0 را روی پورت و storage موقت اجرا کرد.
- یک package واقعی npm publish و یک wheel واقعی PyPI upload شد؛ هر موتور متوقف و با همان storage دوباره اجرا شد و دریافت با cache خالی client و بدون هیچ upstream خارجی موفق بود.
- catalog کنترل‌پلین هر دو artifact واقعی را با ecosystemهای `npm` و `pypi` کشف کرد.
- harness در CI به job مستقل `engine-e2e` اضافه شد و build image به موفقیت آن وابسته است؛ diagnostics شکست نیز artifact می‌شود.
- ۵۱ تست backend، Ruff، release validator، inventory مجوز ۵۶۱ dependency و migration rehearsal همگی پاس هستند.
- اعتبارسنجی نهایی داخل image تک‌کانتینری در job `image-build` موجود است و اجرای محلی مجدد آن به daemon Docker وابسته است؛ این مورد blocker Gate 10 است، نه Gate 7.

## Gate 8 — Operations Visibility

- [x] Prometheus metrics
- [x] JSON logs و redaction
- [x] task list/cancel/retry
- [x] audit append-only view/export
- [x] support bundle
- [x] alert rules و runbook links

### گزارش میانی Gate 8 — 2026-11-07

- endpoint احراز هویت‌شده `/metrics` ظرفیت، uptime، سلامت componentها، وضعیت jobها، upstream فعال و offline mode را بدون label پرکاردینالیتی ارائه می‌دهد.
- صفحه مانیتورینگ دوزبانه شامل سلامت سرویس، مصرف storage، شمارنده jobها، audit و راهنمای واکنش عملیاتی اضافه شد.
- audit به‌صورت CSV با محافظت در برابر spreadsheet formula injection قابل export است.
- Support Bundle در حافظه ساخته می‌شود و status، upstream، tasks، audit و package catalog را بدون raw log و credential بسته‌بندی می‌کند.
- formatter لاگ، Bearer token، API token، password/secret و credential داخل URL را redact می‌کند.
- ruleهای Prometheus برای down/unready/storage/offline/failed-jobs و Runbook متناظر در `docs/18-operations-runbooks.md` اضافه شد.
- تست‌های کنترل‌پلین، Ruff و TypeScript موفق‌اند؛ E2E واقعی موتورهای رجیستری اکنون در harness محلی و CI پوشش داده می‌شود.

## Gate 9 — Data Lifecycle

- [x] storage thresholds
- [x] cleanup dry-run
- [x] integrity scan
- [x] encrypted backup manifest
- [x] isolated restore validation
- [x] production restore guardrails

### گزارش میانی Gate 9 — 2026-11-07

- صفحه چرخه عمر داده، آستانه هدف ۲۰ تا ۹۰ درصد، مصرف فعلی و candidateهای پاک‌سازی را بدون mutation نمایش می‌دهد.
- پکیج‌های Pin و Quarantine از cleanup candidateها کنار گذاشته می‌شوند و endpoint همیشه `dry_run=true` برمی‌گرداند.
- Integrity Scan به‌صورت job قابل لغو/تلاش مجدد، artifactها را با SHA-256 می‌خواند، symlink را رد و SQLiteها را با `PRAGMA quick_check` بررسی می‌کند.
- smoke test زنده روی دیتای ایزوله: cleanup dry-run موفق، integrity task برابر `succeeded` و `healthy=true` بود.
- ۳۱ تست کنترل‌پلین، Ruff و TypeScript موفق‌اند.
- backup با PyCA `cryptography 50.0.2`، AES-256-GCM و Scrypt ساخته می‌شود؛ هر فایل در manifest دارای SHA-256 است و SQLiteها با snapshot API پشتیبان‌گیری می‌شوند.
- passphrase فقط در حافظه request استفاده می‌شود و در database، task payload یا فایل نوشته نمی‌شود.
- validation ابتدا AEAD tag، سپس path safety، member type، manifest hash و hash/size تمام فایل‌ها را در فضای موقت بررسی می‌کند و هیچ داده فعالی را overwrite نمی‌کند.
- ۳۵ تست کنترل‌پلین، Ruff و build تولیدی TypeScript موفق‌اند؛ API زنده health/login/backup-list برابر ۲۰۰ است.
- restore از داخل API اجرا نمی‌شود. پنل فقط backup را validate و یک plan کوتاه‌عمر می‌سازد؛ plan هیچ passphraseای ذخیره نمی‌کند و اعمال آن فقط با CLI آفلاین، عبارت تأیید دوم و heartbeat خاموش مجاز است.
- پیش از mutation یک backup رمزنگاری‌شده rollback و journal ساخته می‌شود. جابه‌جایی فایل‌ها staged و قابل بازگشت است؛ SQLite با Backup API و PostgreSQL/PGlite در یک transaction منطقی بازگردانی می‌شود.
- revision مربوط به Alembic در snapshot با revision برنامه تطبیق داده می‌شود و restore ناسازگار fail-closed است. path traversal، symlink، member ناشناخته، کمبود فضا و checksum نامعتبر نیز پیش از اعمال رد می‌شوند.
- smoke test واقعی روی PGlite با dialect PostgreSQL، migration `20261107_0003`، authentication، task repository، encrypted backup و offline restore را همگی `ok` گزارش کرد.

## Gate 10 — Production

- [x] production Compose
- [x] non-root/read-only/cap-drop review
- [x] egress policy تعریف‌شده و application enforcement
- [x] SBOM/signature/vulnerability scan در CI
- [ ] load و soak test — load محلی پاس؛ اجرای scheduled CI باقی است
- [x] upgrade/rollback rehearsal ایزوله
- [x] final license review — dependencyها پاس و license پروژه MIT از commit اولیه مالک حفظ شد
- [x] go-live checklist آماده

### گزارش میانی معماری Control Plane — 2026-11-07

- SQL خام Auth و Task به SQLAlchemy 2 repository منتقل شد و schema با Alembic revisionهای `20261107_0001` و `20261107_0002` مدیریت می‌شود.
- ایمیج تک‌سرویسی PGlite و `pglite-socket` را فقط روی loopback اجرا می‌کند؛ Psycopg همان URL استاندارد PostgreSQL را به ORM می‌دهد.
- migration به PostgreSQL واقعی فقط با `MRK_DATABASE_URL` انجام می‌شود؛ برای HA و چند replica PostgreSQL خارجی الزامی است.
- smoke test واقعی PGlite شامل migration، authentication، task repository، encrypted logical backup و offline restore همگی `ok` بود.
- First Time Setup بدون رمز یا کد از پیش‌ساخته، فقط هنگام خالی بودن جدول کاربران فعال است و ساخت Owner با claim یکتای دیتابیسی اتمیک شده است.
- ثبت‌نام عمومی پیش‌فرض بسته و از پنل Access Control قابل فعال/غیرفعال‌سازی است؛ نقش ثبت‌نام عمومی به‌صورت fail-closed فقط `viewer` است.
- UI احراز هویت دوزبانه و RTL بازطراحی و feature panelها lazy-loaded شدند؛ build اصلی از حدود ۶۳۵KB به حدود ۴۰۷KB کاهش یافت.
- ۵۱ تست کامل Python، Ruff، build TypeScript و smoke واقعی PGlite موفق‌اند.

### گزارش میانی Gate 10 — 2026-11-07

- base imageهای Node و Python با digest چندمعماری رسمی pin شدند و `TO_BE_RESOLVED` حذف شد.
- production Compose credential قدیمی bootstrap ندارد؛ release validator، Compose syntax و YAML workflowها موفق‌اند.
- CI و release workflow اکنون license artifact، migration rehearsal و load gate دارند؛ workflow هفتگی/دستی soak نیز اضافه شد.
- inventory کامل ۵۶۱ dependency runtime/lockfile با override نسخه‌محور legacy، صفر finding دارد. پروژه طبق فایل `LICENSE` موجود در commit اولیه مالک تحت MIT منتشر می‌شود.
- load محلی ۳۰ ثانیه‌ای با ۳۶٬۴۴۸ request، نرخ ۱٬۲۱۴٫۶۲ درخواست/ثانیه، p95 برابر ۸٫۲۱۱ms و error rate برابر ۰٫۰۰۰۰۲۷ پاس شد.
- downgrade/upgrade `20261107_0003 → 0001 → 0003` داده Owner را حفظ کرد؛ restore آفلاین PGlite نیز با head فعلی پاس شده است.
- موتور Docker Desktop محلی به `docker version` پاسخ نداد؛ build واقعی image بدون restart یا دست‌کاری daemon باز مانده است. هیچ deploy روی Dokploy انجام نشده است.
- Starlette TestClient به `httpx2 2.16.0` منتقل شد و ۵۱ تست بدون deprecation warning پاس شدند؛ `httpx 0.28.1` فقط برای درخواست‌های runtime باقی مانده است.
- برای profile سخت‌گیرانه، کلید AES credentialهای upstream می‌تواند از فایل secret خارجی ۳۲‌بایتی و فقط‌خواندنی خوانده شود؛ نبود/خرابی فایل fail-closed است و برنامه آن را ایجاد یا overwrite نمی‌کند.
- مسیر پیش‌فرض داده در production همچنان `/data` است، اما اجرای source/development بدون env از `.data` داخل workspace استفاده می‌کند تا import و تست روی runner غیرroot به filesystem ریشه نیاز نداشته باشد.

## قالب گزارش بعد از هر Gate

### انجام‌شده

- تغییرات دقیق و فایل‌ها

### تست و شواهد

- دستورها، نتیجه و محدودیت‌ها

### امنیت و دسترسی

- کنترل‌های اضافه‌شده و ریسک‌های باز

### باقی‌مانده

- کارهای Gate بعد و blockerها

## سیاست پاک‌سازی Plan پس از پیاده‌سازی

این سند در زمان توسعه working plan است. پاک‌سازی فقط وقتی انجام می‌شود که تمام Acceptance Criteria بخش موردنظر پاس، گزارش Gate ثبت و مالک آن را تأیید کرده باشد.

پس از sign-off:

1. وضعیت، تاریخ، release/gate و شواهد کوتاه به Storyهای متناظر در `docs/03-user-stories.md` منتقل می‌شود.
2. checklist، گزارش میانی و plan اجرایی تکمیل‌شده از این سند حذف می‌شود.
3. سند طراحی موقت یک feature در صورت نداشتن ارزش عملیاتی حذف می‌شود.
4. Architecture Decision، قرارداد نهایی API/data، Runbook، security control، migration/rollback و release evidence حذف نمی‌شوند.
5. موارد Deferred، ریسک‌های باز و بدهی فنی تا زمان بسته‌شدن باقی می‌مانند.
6. حذف گروهی فقط با فهرست دقیق فایل/بخش و پس از یک commit قابل‌بازیابی انجام می‌شود.

تا قبل از تکمیل Gate 14 و تأیید نهایی مالک، planهای Gate 11 تا 14 و اسناد طراحی ماژول‌ها حذف نخواهند شد.

## سیاست توقف

در صورت مشاهده یکی از موارد زیر Gate متوقف می‌شود:

- نیاز به secret واقعی
- عملیات destructive روی داده کاربر
- license مبهم یا ناسازگار
- vulnerability بحرانی بدون mitigation
- نیاز به دسترسی Docker socket/host root
- شکست integrity یا احتمال cache poisoning
- تغییر scope خارج از MVP بدون تأیید

## Deployment Contract قطعی

- artifact نهایی یک Docker Image است.
- production Compose فقط یک application service دارد.
- تنها volume اجباری `/data` است.
- یک HTTP entrypoint با route مبتنی بر hostname، به‌علاوه listenerهای منطقی npm/PyPI و پروتکل DNS از همان container ارائه می‌شوند.
- PostgreSQL/Redis برای نصب اولیه اجباری نیستند.
- image بدون mount نیز باید fail امن یا با داده موقت development بالا بیاید؛ production بدون volume persistent هشدار واضح دارد.

## Scope Expansion مصوب — 2026-11-07

در این مرحله فقط Product/Architecture/User Story به‌روزرسانی شده و هیچ engine جدیدی نصب، اجرا یا deploy نشده است.

- معماری تک‌ایمیج با processهای ماژولار و دامنه‌های مستقل تأیید شد.
- Uptime Monitoring با Uptime Kuma به‌عنوان baseline مشروط و adapter/fork حداقلی وارد roadmap شد.
- DNS Management با Technitium به‌عنوان engine مشروط به GPL Legal Gate وارد roadmap شد.
- UI هر دو ماژول متعلق به MRK است؛ هدف capability parity است، نه کپی ظاهری.
- DNS کلاسیک UDP/TCP به دلیل نداشتن Host header با دامنه HTTP route نمی‌شود؛ DoH و پنل DNS دامنه مستقل دارند.
- اسناد تفصیلی: `docs/20-modular-appliance-and-domain-routing.md`، `docs/21-uptime-monitoring-module.md` و `docs/22-dns-management-module.md`.

## Gate 11 — Modular Edge و Domain Routing

- [ ] ADR انتخاب Edge Gateway
- [ ] module manifest/registry contract
- [ ] hostname route CRUD و conflict detection
- [ ] trusted proxy و Host security
- [ ] per-module lifecycle/restart/crash-loop
- [ ] failure-isolation test
- [ ] backup/upgrade contributor contract

## Gate 12 — Uptime Monitoring

- [ ] pin/security/license baseline Uptime Kuma
- [ ] adapter و contract tests
- [ ] monitor core و Simple/Advanced UI
- [ ] history/metrics/notifications
- [ ] incident/maintenance/status pages
- [ ] custom domains و public/private boundary
- [ ] parity matrix بدون gap P0/P1
- [ ] backup/restore/load/security rehearsal

## Gate 13 — DNS Management

- [ ] GPL Legal/Distribution Gate
- [ ] pin/security baseline Technitium
- [ ] adapter و engine admin-port isolation
- [ ] Simple Mode zones/records/forwarders/cache
- [ ] Advanced Mode ACL/transfer/TSIG/DNSSEC
- [ ] DoH/DoT/DoQ و protocol listeners
- [ ] change-set/preview/approval/rollback
- [ ] parity matrix بدون gap P0/P1
- [ ] backup/restore/load/open-resolver test

## Gate 14 — Unified Modular Appliance

- [ ] یک image و یک volume با تمام moduleهای مصوب
- [ ] resource/size budget و isolation
- [ ] SBOM/license/source-offer همه runtimeها
- [ ] upgrade/rollback per-module
- [ ] production-like domain/TLS/DNS E2E
- [ ] operations/security/legal sign-off

### ترتیب اجرای Scope جدید

1. ابتدا Gateهای باز 4/6/7/10 فعلی بسته می‌شوند؛ تغییر scope نباید validation موجود registry را دور بزند.
2. Gate 11 قبل از هر engine جدید اجرا می‌شود تا moduleها از ابتدا روی قرارداد مشترک سوار شوند.
3. Gate 12 و Gate 13 می‌توانند پس از ثبات contract به‌صورت مستقل توسعه یابند.
4. Gate 14 فقط پس از Legal Gate Technitium و parity/security sign-off شروع می‌شود.
5. deploy روی Dokploy فقط با تأیید صریح مالک و پس از معماری/تصویر نهایی انجام می‌شود.

