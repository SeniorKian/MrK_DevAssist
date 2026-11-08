# MRK Modular Infrastructure Appliance

نسخه سند: 0.1  
تاریخ مبنا: 2026-11-07  
وضعیت: پیاده‌سازی فعال — پیش‌نمایش لوکال در حال اجرا

## هدف

ساخت یک Appliance خودمیزبان و ماژولار برای npm، PyPI، پایش uptime و DNS با پنل مدیریتی یکپارچه، دامنه‌های مستقل، lifecycle کنترل‌شده و معماری قابل توسعه برای سرویس‌های آینده.

این محصول پروتکل npm یا PyPI را از صفر بازنویسی نمی‌کند. موتورهای بالغ و پرکاربرد به‌صورت وابستگی version-pinned استفاده می‌شوند و توسعه اختصاصی روی Control Plane، پنل، مشاهده‌پذیری و سیاست failover متمرکز است.

## تصمیم فنی اولیه

- موتور npm: Verdaccio stable 6.x
- موتور PyPI: devpi-server/devpi-web
- Control Plane API: FastAPI
- پنل: React 19 + TypeScript + Material UI با feature panelهای lazy-loaded
- ORM و migration: SQLAlchemy 2 + Alembic
- پایگاه داده تک‌نودی داخل Appliance: PGlite پایدار روی loopback با داده در `/data/database/pglite`
- PostgreSQL خارجی: با `MRK_DATABASE_URL` و بدون تغییر کد یا مدل‌ها
- صف و cache کنترل‌پلین: Redis، فقط در صورت نیاز عملیاتی
- Metrics: Prometheus/OpenMetrics
- Dashboard عملیاتی: پنل داخلی؛ Grafana به‌عنوان ابزار مکمل اختیاری
- خروجی اصلی: یک Docker Image واحد با یک bind mount روی `/data`
- استقرار: یک service در Docker Compose؛ پنل، API، Verdaccio و devpi داخل Appliance
- ماژول‌های مصوب بعدی: Uptime Monitoring و DNS Management
- مسیریابی وب: یک entrypoint و نگاشت hostname به پنل، npm، PyPI، status page و DoH
- DNS کلاسیک: listener مستقل UDP/TCP روی پورت 53؛ به دلیل نبود Host header با دامنه HTTP route نمی‌شود

## راه‌اندازی اولین کاربر

- اگر جدول کاربران خالی باشد، پنل فقط فرم `First Time Setup` را نشان می‌دهد.
- فرم نام، ایمیل، رمز و تکرار رمز را می‌گیرد و اولین حساب را به‌صورت اتمیک با نقش `owner` می‌سازد.
- هیچ کد یک‌بارمصرف یا رمز پیش‌فرضی تولید نمی‌شود.
- پس از ایجاد Owner، endpoint راه‌اندازی بسته می‌شود و ورود عادی نمایش داده می‌شود.
- ثبت‌نام عمومی پیش‌فرض خاموش است؛ Owner/Admin می‌تواند آن را از «دسترسی‌ها» فعال یا غیرفعال کند. حساب عمومی همیشه با نقش `viewer` ساخته می‌شود.

## حالت‌های دیتابیس

- حالت پیش‌فرض ایمیج: PGlite داخل همان container، بدون پورت عمومی و با یک pool تک‌اتصالی.
- حالت PostgreSQL خارجی: مقدار `MRK_DATABASE_URL` را به URL نوع `postgresql+psycopg://...` تغییر دهید.
- تست‌های سورس می‌توانند از SQLite استفاده کنند؛ repositoryها و migrationها بین هر سه حالت مشترک‌اند.
- برای چند replica یا HA از PostgreSQL خارجی استفاده کنید؛ PGlite برای appliance تک‌نودی طراحی شده است.

## پشتیبان‌گیری و بازیابی

- backupها با AES-256-GCM و Scrypt رمزگذاری و تمام entryها با SHA-256 کنترل می‌شوند.
- پنل می‌تواند backup را بسازد، فهرست کند، validate کند و plan کوتاه‌عمر restore بسازد؛ اجرای restore عمداً از پنل ممکن نیست.
- restore فقط پس از توقف سرویس با فرمان `mrk-restore apply`، فایل passphrase جداگانه و دو عبارت تأیید انجام می‌شود.
- برای PGlite/PostgreSQL، snapshot و restore دیتابیس منطقی و transaction-based است و revision مربوط به Alembic باید دقیقاً سازگار باشد.
- پیش از اعمال، یک backup rollback رمزنگاری‌شده و journal ساخته می‌شود. دستور کامل در [Operations Runbooks](docs/18-operations-runbooks.md) آمده است.

## اصل مهم Fork

Core موتورهای Verdaccio و devpi مستقیماً تغییر داده نمی‌شوند مگر یک Gap اثبات‌شده وجود داشته باشد. ادغام ترجیحاً از طریق plugin، API، config adapter یا sidecar انجام می‌شود تا ارتقای upstream ساده بماند.

## نقشه مستندات

1. [محصول و دامنه](docs/01-product-and-scope.md)
2. [معماری و ارزیابی ریپوها](docs/02-architecture-and-repository-selection.md)
3. [تمام User Storyها و Acceptance Criteria](docs/03-user-stories.md)
4. [Roadmap و برنامه تحویل](docs/04-roadmap-and-delivery.md)
5. [API، مدل داده و امنیت](docs/05-api-data-security.md)
6. [تست، مشاهده‌پذیری و عملیات](docs/06-testing-observability-operations.md)
7. [شروع پیاده‌سازی](docs/07-implementation-start.md)
8. [Scorecard انتخاب ریپوها](docs/08-repository-selection-scorecard.md)
9. [بازبینی امنیت و دسترسی](docs/09-security-access-review.md)
10. [Execution Plan و گزارش Gateها](docs/10-execution-plan.md)
11. [قرارداد supervision و health](docs/11-process-supervision-and-health.md)
12. [CI/CD و انتشار GHCR](docs/12-ci-cd-and-release.md)
13. [Gate 2 و رجیستری npm](docs/13-gate2-npm-registry.md)
14. [طراحی پنل مدیریت حرفه‌ای](docs/14-professional-admin-ui.md)
15. [Gate 3 و رجیستری PyPI](docs/15-gate3-pypi-registry.md)
16. [Gate 4 و failover چند upstream](docs/16-gate4-failover-router.md)
17. [Gate 5 و Identity/Access](docs/17-gate5-identity-access.md)
18. [Runbookهای عملیاتی](docs/18-operations-runbooks.md)
19. [Production release gate و Go-live checklist](docs/19-production-release-gate.md)
20. [معماری Modular Appliance و مسیریابی دامنه](docs/20-modular-appliance-and-domain-routing.md)
21. [طراحی سرویس Uptime Monitoring](docs/21-uptime-monitoring-module.md)
22. [طراحی سرویس DNS Management](docs/22-dns-management-module.md)
23. [ADR موتورهای بومی و بودجه منابع](docs/23-adr-native-modules-and-resource-budget.md)
24. [Spec موتور بومی Uptime](docs/24-native-uptime-engine-spec.md)
25. [Spec موتور بومی DNS](docs/25-native-dns-engine-spec.md)
26. [Spec ماژول Docker/OCI Registry](docs/26-oci-registry-module-spec.md)
27. [اصل تنظیم‌پذیری و فهرست تنظیمات](docs/27-configurability-and-settings.md)
28. [ماژول‌های کنترل سرور در کنار Dokploy](docs/28-server-control-modules.md)
29. [قراردادهای Gate 17](docs/29-gate17-contracts.md)
30. [مشخصات سرویس S3 بومی](docs/30-s3-object-storage-spec.md)
31. [قراردادهای Gate 18](docs/31-gate18-contracts.md)
32. [قراردادهای Gate 19](docs/32-gate19-contracts.md)
33. [طرح بازطراحی پنل](docs/33-ux-redesign-plan.md)
34. [APIهای پنل جدید](docs/34-ui-backend-contracts.md)

## Definition of Success

- نصب `pip`، `uv`، `poetry`، `npm`، `pnpm` و `yarn` از endpointهای محصول انجام شود.
- در دسترس بودن upstream اصلی، ترافیک به آن هدایت شود.
- در timeout، خطای شبکه یا 5xx، upstream بعدی طبق سیاست انتخاب شود.
- پکیج کش‌شده در قطع کامل اینترنت قابل نصب باشد.
- وضعیت upstream، cache، disk، task و خطاها از پنل دیده و مدیریت شود.
- هیچ secret در log، UI یا Compose ذخیره‌شده در Git نمایش داده نشود.
- ارتقای Verdaccio/devpi بدون merge سنگین با fork داخلی ممکن باشد.

## موارد خارج از MVP

- Mirror کامل همه PyPI یا npm
- جایگزینی کامل Nexus یا Artifactory در تمام package formatها
- اسکن امنیتی تجاری در سطح SCA
- Multi-region active-active
- Billing و multi-tenant SaaS عمومی

