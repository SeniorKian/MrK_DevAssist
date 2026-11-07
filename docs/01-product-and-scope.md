# 01 — محصول و دامنه

## 1. مسئله

تیم‌ها علاوه بر npmjs و PyPI به مانیتورینگ سرویس و DNS قابل‌کنترل وابسته‌اند. قطعی اینترنت، تحریم، اختلال IPv4/IPv6، timeout، محدودیت CDN یا خرابی DNS می‌تواند build و deploy را متوقف کند. راهکار باید در قالب یک Appliance فشرده، رجیستری پکیج، پایش uptime و مدیریت DNS را از یک Control Plane واحد ارائه کند؛ در عین حال هر ماژول دامنه، policy، داده و lifecycle مستقل داشته باشد.

## 2. چشم‌انداز

یک پنل واحد و ماژولار که مدیر سیستم بدون کار با فایل config بتواند:

- upstream بسازد، ویرایش کند، تست کند و اولویت بدهد؛
- سلامت، latency و خطاهای هر upstream را ببیند؛
- پکیج‌های کش‌شده را جست‌وجو و مدیریت کند؛
- مصرف فضای ذخیره‌سازی و نرخ cache hit را ببیند؛
- سیستم را به offline mode ببرد؛
- کاربران، tokenها، نقش‌ها و audit log را مدیریت کند؛
- backup، restore و upgrade را کنترل کند.
- مانیتورهای uptime، اعلان‌ها، maintenance و status page عمومی بسازد؛
- zone، record، resolver، forwarder، DNSSEC و policyهای DNS را در دو حالت ساده و پیشرفته مدیریت کند؛
- دامنه‌های ورودی را به پنل، npm، PyPI، status page یا DoH نگاشت کند؛
- process هر ماژول را ببیند، restart کنترل‌شده انجام دهد و خرابی یا restart loop را تشخیص دهد.

## 3. Personaها

### P-01 — Platform Administrator

مالک استقرار، دامنه، TLS، storage، backup، upgrade و incident response.

### P-02 — Repository Administrator

مدیر upstreamها، package policy، cache، کاربران و دسترسی‌ها.

### P-03 — Developer

مصرف‌کننده endpointهای npm/PyPI و در صورت مجاز بودن ناشر پکیج خصوصی.

### P-04 — Security/Auditor

خواننده audit log، رخدادهای امنیتی، checksum و تغییرات دسترسی.

### P-05 — Support/Observer

دارای دسترسی read-only برای مشاهده سلامت، taskها و خطاها.

## 4. دامنه MVP

### Registry

- npm proxy/cache بر پایه Verdaccio
- PyPI proxy/cache بر پایه devpi
- local/private npm packages
- local/private Python packages
- چند upstream برای هر ecosystem
- اولویت، timeout، retry، circuit breaker و failover
- cache-first در حالت offline

### Admin Panel

- Dashboard
- Upstreams
- Packages and versions
- Cache operations
- Users, roles and tokens
- Tasks/jobs
- Server status
- Storage and retention
- Logs and audit events
- Backup/restore status
- Settings

### Operations

- Docker Compose production profile
- health/readiness probes
- structured logs
- Prometheus metrics
- backup قابل آزمون
- migration و rollback مستند

### Uptime Monitoring

- monitorهای HTTP(S)، keyword/JSON، TCP، ping، DNS، push و certificate
- retry، dependency، maintenance، incident و heartbeat history
- notification channel و escalation policy
- چند status page عمومی، دامنه اختصاصی و badge/RSS
- مشاهده زنده وضعیت، uptime و latency از پنل یکپارچه

### DNS Management

- authoritative و recursive DNS با cache و forwarder
- zoneهای Primary، Secondary، Stub و Conditional Forwarder
- record editor، import/export، AXFR/IXFR، TSIG و Dynamic Update
- DNSSEC، DoH/DoT/DoQ، blocklist، query log و آمار
- Simple Mode برای کارهای روزمره و Advanced Mode برای قابلیت‌های حساس
- استفاده از موتور Technitium به‌صورت process داخلیِ بدون تغییر و adapter مبتنی بر API رسمی

### Modular Appliance

- یک Docker Image و یک volume اصلی `/data`
- یک HTTP entrypoint با route مبتنی بر hostname
- listenerهای پروتکلی مستقل برای npm، PyPI و DNS کلاسیک
- service catalog و supervisor برای start/stop/restart/readiness
- قرارداد plugin/module برای افزودن سرویس‌های آینده بدون تغییر هسته پنل

## 5. Non-Goals فاز اول

- پشتیبانی Maven، NuGet، Docker Registry، APT یا Composer
- full mirror پیش‌فرض
- اجرای arbitrary shell از پنل
- ویرایش مستقیم فایل‌های Verdaccio/devpi توسط مرورگر
- حذف خودکار package بدون policy و audit
- dependency vulnerability scanner اختصاصی
- بازنویسی موتور DNS از صفر
- کپی مستقیم UI، نام تجاری یا دارایی‌های Uptime Kuma و Technitium
- ادعای HA برای Appliance تک‌نودی
- مسیریابی DNS کلاسیک UDP/TCP بر اساس hostname؛ این پروتکل Host header ندارد

## 6. الزامات عملکردی

| ID | الزام |
|---|---|
| FR-001 | سیستم باید npm و PyPI را با endpoint جداگانه پشتیبانی کند. |
| FR-002 | هر ecosystem باید حداقل دو upstream مرتب‌شده داشته باشد. |
| FR-003 | Failover فقط بر اساس policy مشخص و قابل مشاهده انجام شود. |
| FR-004 | محتوای کش‌شده بدون اینترنت قابل دریافت باشد. |
| FR-005 | مدیر باید upstream را بدون redeploy کامل تغییر دهد. |
| FR-006 | package، version، checksum، source و cache state قابل مشاهده باشد. |
| FR-007 | عملیات purge، revalidate، prefetch و quarantine audit شود. |
| FR-008 | سیستم باید role-based access control داشته باشد. |
| FR-009 | secretها رمزگذاری و در UI mask شوند. |
| FR-010 | backup و restore باید قابل اجرا و قابل اعتبارسنجی باشد. |
| FR-011 | hostnameهای ورودی باید از پنل به module/route مشخص نگاشت شوند و conflict قبل از اعمال رد شود. |
| FR-012 | status page عمومی باید از پنل مدیریتی و API خصوصی جدا و با دامنه مستقل قابل انتشار باشد. |
| FR-013 | monitorها، heartbeatها، maintenanceها و notificationها باید از پنل مدیریت شوند. |
| FR-014 | DNS authoritative/recursive، zoneها، recordها، DNSSEC و transportهای امن باید مدیریت شوند. |
| FR-015 | تنظیمات DNS باید Simple Mode و Advanced Mode با guardrail جدا داشته باشند. |
| FR-016 | هر module باید health، readiness، version، restart count و lifecycle action استاندارد داشته باشد. |
| FR-017 | افزودن module آینده نباید نیازمند تغییر routing/auth/audit core باشد. |

## 7. الزامات غیرعملکردی

| ID | الزام هدف |
|---|---|
| NFR-001 | endpoint کش‌شده در شرایط عادی p95 کمتر از 500ms روی LAN باشد. |
| NFR-002 | خطای یک upstream نباید endpoint دیگر یا cache را از دسترس خارج کند. |
| NFR-003 | هیچ پکیج ناقص نباید به‌عنوان cache سالم publish شود. |
| NFR-004 | تمام تغییرات مدیریتی actor، زمان، IP و نتیجه داشته باشند. |
| NFR-005 | deploy و upgrade باید rollback مستند داشته باشد. |
| NFR-006 | هسته‌های upstream با نسخه دقیق pin شوند؛ استفاده از latest ممنوع است. |
| NFR-007 | استفاده از پروژه بدون release فعال، تست یا security policy نیازمند ADR و تأیید است. |
| NFR-008 | طراحی برای حداقل 500 درخواست هم‌زمان burst و scale افقی Control Plane آماده باشد. |
| NFR-009 | خرابی یک module نباید moduleهای دیگر یا entrypoint را از دسترس خارج کند. |
| NFR-010 | restart خودکار باید backoff، سقف تلاش و تشخیص crash-loop داشته باشد. |
| NFR-011 | تمام hostnameها canonicalize شوند و Host-header spoofing و open-proxy fail-closed باشد. |
| NFR-012 | API داخلی engineها فقط روی loopback/Unix socket در دسترس باشد. |
| NFR-013 | DNS change باید preview، validation، audit و rollback snapshot داشته باشد. |
| NFR-014 | قابلیت‌های اقتباس‌شده از پروژه خارجی با contract test و license notice پوشش داده شوند. |

## 8. شاخص‌های موفقیت

- cache hit ratio هفتگی
- درصد درخواست‌های موفق npm/PyPI
- تعداد failover موفق و ناموفق
- upstream availability و latency
- زمان تشخیص قطعی upstream
- زمان بازیابی بعد از outage
- فضای cache و نرخ رشد
- تعداد packageهای stale/quarantined
- موفقیت backup و restore drill
- monitor check success، false-positive rate و notification latency
- status page availability و زمان انتشار incident
- DNS query latency، cache-hit، SERVFAIL/NXDOMAIN rate و DNSSEC failures
- restart count، crash-loop و mean time to recovery هر module

