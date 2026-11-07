# 03 — User Stories و Acceptance Criteria

## سیاست ماندگاری Storyها

این فایل مرجع دائمی «چه چیزی، چرا و با چه معیار پذیرشی ساخته شد» است. پس از تکمیل هر Story:

- وضعیت آن به `Done`، تاریخ تکمیل و release/gate مربوط ثبت می‌شود؛
- یک خلاصه کوتاه از نتیجه و شواهد تست باقی می‌ماند؛
- plan اجرایی، checklist موقت و گزارش‌های تکراری همان Story پس از sign-off حذف می‌شوند؛
- Story، Acceptance Criteria و تصمیم‌های امنیتی آن حذف نمی‌شوند؛
- Runbook عملیاتی، معماری نهایی، migration/rollback و مستندات امنیتی چون برای بهره‌برداری لازم‌اند حفظ می‌شوند.

قالب نهایی هر Story تکمیل‌شده:

```text
Status: Done
Completed: YYYY-MM-DD
Release/Gate: ...
Evidence: test/report/ADR reference
```

## قواعد بک‌لاگ

- اولویت‌ها: P0 ضروری، P1 مهم، P2 تکمیلی.
- هر Story باید تست خودکار، مستندات و telemetry لازم را همراه خود داشته باشد.
- Story بدون Acceptance Criteria و owner وارد Sprint نمی‌شود.
- عملیات مخرب همیشه confirmation، permission و audit می‌خواهند.

## Epic E01 — Source Governance و Bootstrap

### US-001 — ثبت کاندیدای upstream — P0

به‌عنوان Tech Lead می‌خواهم هر dependency در scorecard ثبت شود تا انتخاب فناوری قابل دفاع باشد.

پذیرش:
- star، fork، سن، آخرین release، open issue، CI، security policy و license ثبت شود.
- امتیاز نهایی و دلیل قبول/رد قابل مشاهده باشد.
- داده دارای تاریخ بررسی و لینک منبع باشد.

### US-002 — Pin نسخه‌ها — P0

به‌عنوان Release Manager می‌خواهم تمام image و dependencyها به نسخه دقیق pin شوند تا build قابل تکرار باشد.

پذیرش:
- production هیچ `latest` یا range باز نداشته باشد.
- digest image در lock manifest ذخیره شود.
- CI استفاده از tag ممنوع را fail کند.

### US-003 — Mirror داخلی source — P1

به‌عنوان Maintainer می‌خواهم mirror داخلی ریپوهای upstream داشته باشم تا حذف یا قطعی GitHub توسعه را متوقف نکند.

پذیرش:
- tagها و branchهای انتخاب‌شده mirror شوند.
- job دوره‌ای وضعیت sync را گزارش کند.
- اختلاف و خطای sync alert شود.

### US-004 — Patch registry — P0

به‌عنوان Maintainer می‌خواهم تمام patchهای downstream فهرست شوند تا upgrade قابل کنترل باشد.

پذیرش:
- هر patch دارای دلیل، upstream issue/PR، owner و expiry review باشد.
- patch بدون تست پذیرفته نشود.
- تعداد و LOC patch در dashboard engineering دیده شود.

### US-005 — Development Compose — P0

به‌عنوان Developer می‌خواهم محیط توسعه با یک فرمان بالا بیاید تا onboarding سریع باشد.

پذیرش:
- API، UI، npm، PyPI، DB و mock upstream اجرا شوند.
- داده seed و credential توسعه‌ای غیرواقعی فراهم باشد.
- teardown فقط volumeهای توسعه را هدف بگیرد.

## Epic E02 — Authentication، Users و RBAC

### US-010 — ورود مدیر — P0

به‌عنوان Administrator می‌خواهم با credential امن وارد پنل شوم تا عملیات مدیریتی محافظت شود.

پذیرش:
- password hash استاندارد و rate limit فعال باشد.
- session امن، HttpOnly، Secure و SameSite باشد.
- خطای ورود اطلاعات حساس افشا نکند.

### US-011 — نقش‌های پیش‌فرض — P0

به‌عنوان Owner می‌خواهم نقش‌های Owner، Admin، Operator، Developer و Viewer داشته باشم.

پذیرش:
- permission matrix مستند و تست شود.
- Viewer هیچ mutation انجام ندهد.
- فقط Owner بتواند Owner دیگری بسازد یا حذف کند.

### US-012 — کاربر محلی — P0

به‌عنوان Admin می‌خواهم کاربر بسازم، غیرفعال کنم و role بدهم.

پذیرش:
- username یکتا و normalize شود.
- غیرفعال‌سازی token و session فعال را revoke کند.
- تمام تغییرات audit شوند.

### US-013 — API Token — P0

به‌عنوان Developer می‌خواهم token محدود بسازم تا CI بدون password کار کند.

پذیرش:
- token فقط یک بار کامل نمایش داده شود.
- expiry و scope اجباری باشد.
- revoke آنی و audit شود.

### US-014 — Service Account — P1

به‌عنوان Platform Admin می‌خواهم service account جدا از کاربر انسانی بسازم.

پذیرش:
- login تعاملی برای service account غیرفعال باشد.
- owner، purpose و expiry ثبت شود.
- token بدون owner فعال نماند.

### US-015 — SSO/OIDC — P2

به‌عنوان Enterprise Admin می‌خواهم OIDC وصل کنم تا مدیریت هویت متمرکز باشد.

پذیرش:
- issuer discovery و PKCE پشتیبانی شود.
- group-to-role mapping قابل تنظیم باشد.
- local break-glass admin باقی بماند.

### US-016 — MFA مدیر — P1

به‌عنوان Owner می‌خواهم MFA برای نقش‌های حساس اجباری باشد.

پذیرش:
- TOTP و recovery codes پشتیبانی شود.
- recovery code یک‌بار مصرف باشد.
- reset MFA فقط با permission و audit انجام شود.

## Epic E03 — Upstream Management و Failover

### US-020 — ساخت upstream — P0

به‌عنوان Repository Admin می‌خواهم upstream npm یا PyPI بسازم.

پذیرش:
- نام، ecosystem، URL، priority، timeout و enabled ذخیره شود.
- URL با SSRF policy اعتبارسنجی شود.
- secret در response و log mask شود.

### US-021 — تست اتصال — P0

به‌عنوان Admin می‌خواهم پیش از ذخیره اتصال upstream را تست کنم.

پذیرش:
- DNS، TCP/TLS، HTTP و protocol endpoint جدا گزارش شوند.
- latency هر مرحله نمایش داده شود.
- تست باعث دانلود artifact بزرگ نشود.

### US-022 — اولویت upstream — P0

به‌عنوان Admin می‌خواهم ترتیب upstreamها را تغییر دهم.

پذیرش:
- drag/drop و عدد priority هر دو پشتیبانی شوند.
- ترتیب جدید بدون restart کامل اعمال شود.
- تغییر قبل/بعد audit شود.

### US-023 — Failover خودکار — P0

به‌عنوان Developer می‌خواهم هنگام خرابی upstream اصلی درخواست به بعدی برود.

پذیرش:
- timeout، DNS، reset و 5xx طبق policy failover شوند.
- 401/403 و checksum mismatch موفق تلقی نشوند.
- upstream انتخاب‌شده در trace ثبت شود.

### US-024 — Circuit Breaker — P0

به‌عنوان Operator می‌خواهم upstream خراب موقتاً از rotation خارج شود.

پذیرش:
- threshold، window و cooldown قابل تنظیم باشند.
- half-open probe بدون هجوم درخواست انجام شود.
- تغییر state metric و event تولید کند.

### US-025 — Block دستی — P0

به‌عنوان Admin می‌خواهم upstream را موقتاً block کنم.

پذیرش:
- confirmation و reason اجباری باشد.
- cache محلی همچنان پاسخ دهد.
- unblock دستی و زمان‌دار پشتیبانی شود.

### US-026 — Offline Mode — P0

به‌عنوان Operator می‌خواهم ecosystem را cache-only کنم.

پذیرش:
- npm و PyPI مستقل offline شوند.
- هیچ outbound request در offline mode ارسال نشود.
- banner واضح و audit event ایجاد شود.

### US-027 — Credential upstream — P1

به‌عنوان Admin می‌خواهم credential یک upstream خصوصی را مدیریت کنم.

پذیرش:
- secret رمزگذاری‌شده ذخیره شود.
- rotate بدون downtime ممکن باشد.
- UI فقط fingerprint و آخرین زمان تغییر را نشان دهد.

### US-028 — TLS Trust — P1

به‌عنوان Platform Admin می‌خواهم CA خصوصی upstream را اضافه کنم.

پذیرش:
- certificate chain قبل از ذخیره validate شود.
- bypass کلی TLS در production ممنوع باشد.
- expiry certificate alert شود.

## Epic E04 — npm Registry

### US-030 — نصب npm — P0

به‌عنوان Developer می‌خواهم `npm install` از endpoint محصول کار کند.

پذیرش:
- package metadata و tarball صحیح بازگردند.
- integrity npm حفظ و verify شود.
- نصب تکراری از cache انجام شود.

### US-031 — pnpm و Yarn — P0

به‌عنوان Developer می‌خواهم pnpm و Yarn نیز بدون config خاص غیرضروری کار کنند.

پذیرش:
- ماتریس نسخه‌های stable در CI تست شود.
- scoped package و dist-tag تست شوند.
- lockfile install تست شود.

### US-032 — Scoped package routing — P1

به‌عنوان Admin می‌خواهم scopeهای خاص به upstream مشخص بروند.

پذیرش:
- rule ترتیب‌دار و قابل preview باشد.
- rule conflict قبل از ذخیره هشدار دهد.
- default route مشخص باشد.

### US-033 — npm package publish — P1

به‌عنوان Publisher می‌خواهم package خصوصی منتشر کنم.

پذیرش:
- permission namespace بررسی شود.
- overwrite نسخه موجود ممنوع باشد.
- checksum، actor و timestamp ثبت شوند.

### US-034 — npm dist-tags — P1

به‌عنوان Publisher می‌خواهم dist-tag مدیریت کنم.

پذیرش:
- add، move و remove با permission انجام شود.
- تغییر روی upstream عمومی publish نشود.
- audit کامل ثبت شود.

### US-035 — npm deprecate/unpublish — P1

به‌عنوان Repository Admin می‌خواهم policy کنترل‌شده برای deprecate و unpublish داشته باشم.

پذیرش:
- unpublish confirmation دو مرحله‌ای داشته باشد.
- retention window رعایت شود.
- cached public artifact بدون policy حذف نشود.

### US-036 — npm audit pass-through — P2

به‌عنوان Developer می‌خواهم `npm audit` از registry عبور کند.

پذیرش:
- endpoint سازگار و timeout کنترل‌شده باشد.
- failure audit endpoint نصب package را خراب نکند.
- outbound destination allowlist شود.

## Epic E05 — PyPI Registry

### US-040 — pip install — P0

به‌عنوان Developer می‌خواهم `pip install` از Simple API محصول کار کند.

پذیرش:
- PEP 503 normalization رعایت شود.
- wheel و sdist با hash معتبر ارائه شوند.
- بار دوم از cache محلی پاسخ داده شود.

### US-041 — uv، Poetry و Pipenv — P0

به‌عنوان Developer می‌خواهم clientهای رایج Python کار کنند.

پذیرش:
- نسخه‌های stable در CI ماتریسی تست شوند.
- PEP 691 content negotiation تست شود در صورت پشتیبانی engine.
- private index auth تست شود.

### US-042 — PyPI failover — P0

به‌عنوان Developer می‌خواهم با قطع PyPI اصلی از Liara یا upstream بعدی دریافت کنم.

پذیرش:
- gateway ترتیب upstream را رعایت کند.
- linkهای artifact و hash بدون دست‌کاری ناامن پردازش شوند.
- پاسخ failover در trace و metric مشخص باشد.

### US-043 — Python private publish — P1

به‌عنوان Publisher می‌خواهم با twine پکیج خصوصی منتشر کنم.

پذیرش:
- permission index بررسی شود.
- filename و metadata validate شوند.
- نسخه immutable باشد مگر policy ویژه.

### US-044 — Python index inheritance — P1

به‌عنوان Admin می‌خواهم index خصوصی از public cache ارث ببرد.

پذیرش:
- precedence مستند و تست شود.
- dependency confusion warning نمایش داده شود.
- namespace policy قابل اعمال باشد.

### US-045 — Yank metadata — P1

به‌عنوان Developer می‌خواهم yanked release به‌درستی منعکس شود.

پذیرش:
- metadata upstream حفظ شود.
- cache stale طبق TTL revalidate شود.
- نصب نسخه pin‌شده مطابق رفتار pip باشد.

### US-046 — Prefetch requirements — P1

به‌عنوان Operator می‌خواهم یک requirements/lock file را پیشاپیش cache کنم.

پذیرش:
- dry-run package list نشان دهد.
- job قابل pause/cancel و resume باشد.
- dependencyها و artifactهای انتخابی ثبت شوند.

## Epic E06 — Package Catalog و Cache

### US-050 — جست‌وجوی یکپارچه — P0

به‌عنوان Admin می‌خواهم npm و Python package را از یک search پیدا کنم.

پذیرش:
- فیلتر ecosystem، source، cached/private و status باشد.
- pagination سمت سرور باشد.
- نتایج permission-aware باشند.

### US-051 — جزئیات package — P0

به‌عنوان Admin می‌خواهم version، size، hash، source و last access را ببینم.

پذیرش:
- metadata از artifact جدا نمایش داده شود.
- source upstream و زمان fetch مشخص باشد.
- checksum verification status نمایش داده شود.

### US-052 — Purge cache — P0

به‌عنوان Admin می‌خواهم cache یک package/version را پاک کنم.

پذیرش:
- اثر و حجم آزادشونده preview شود.
- confirmation، reason و permission اجباری باشد.
- حذف به‌صورت job و atomic انجام شود.

### US-053 — Revalidate — P0

به‌عنوان Operator می‌خواهم metadata یا artifact را با upstream تطبیق دهم.

پذیرش:
- metadata-only و full verify جدا باشند.
- mismatch quarantine و alert ایجاد کند.
- cache سالم در خطای upstream حذف نشود.

### US-054 — Pin package — P1

به‌عنوان Admin می‌خواهم package از cleanup مستثنا شود.

پذیرش:
- pin دارای owner و reason باشد.
- cleanup report package pin‌شده را نشان دهد.
- unpin audit شود.

### US-055 — Cache policy — P1

به‌عنوان Admin می‌خواهم TTL و retention بر اساس ecosystem/scope تنظیم کنم.

پذیرش:
- policy precedence preview شود.
- invalid policy ذخیره نشود.
- cleanup dry-run فراهم باشد.

### US-056 — Quarantine — P1

به‌عنوان Security Admin می‌خواهم artifact مشکوک را quarantine کنم.

پذیرش:
- artifact قابل دانلود نباشد.
- metadata و شواهد حذف نشوند.
- release فقط با permission و reason ممکن باشد.

### US-057 — Bulk operations — P2

به‌عنوان Admin می‌خواهم عملیات محدود bulk انجام دهم.

پذیرش:
- سقف selection و impact summary داشته باشد.
- job progress و partial failure گزارش شود.
- عملیات destructive قابلیت cancel قبل از commit داشته باشد.

## Epic E07 — Dashboard و Monitoring

### US-060 — Overview dashboard — P0

به‌عنوان Operator می‌خواهم سلامت کلی را در یک صفحه ببینم.

پذیرش:
- endpoint status، upstream state، error rate، latency، disk و active jobs نمایش داده شوند.
- داده timestamp و refresh indicator داشته باشد.
- degraded state از healthy متمایز باشد.

### US-061 — Upstream timeline — P0

به‌عنوان Operator می‌خواهم history availability هر upstream را ببینم.

پذیرش:
- تغییر state و علت ثبت شود.
- بازه 1h/24h/7d/30d قابل انتخاب باشد.
- deploy/config changes روی timeline علامت‌گذاری شوند.

### US-062 — Request metrics — P0

به‌عنوان Operator می‌خواهم request rate، latency و status code را ببینم.

پذیرش:
- تفکیک ecosystem و upstream وجود داشته باشد.
- cached و upstream fetch جدا شوند.
- cardinality کنترل شود.

### US-063 — Cache metrics — P0

به‌عنوان Admin می‌خواهم hit/miss و حجم cache را ببینم.

پذیرش:
- hit ratio قابل فیلتر بر ecosystem باشد.
- رشد storage و eviction نشان داده شود.
- تعریف metric مستند باشد.

### US-064 — Server resources — P1

به‌عنوان Platform Admin می‌خواهم CPU، RAM، disk و inode را ببینم.

پذیرش:
- منبع metric مشخص باشد.
- threshold alert قابل تنظیم باشد.
- پنل دسترسی مستقیم privileged به host نگیرد.

### US-065 — Synthetic probe — P1

به‌عنوان Operator می‌خواهم نصب package کوچک دوره‌ای تست شود.

پذیرش:
- probe برای npm و PyPI جدا باشد.
- cache-hit و forced-upstream mode داشته باشد.
- failure alert با مرحله دقیق ایجاد کند.

## Epic E08 — Tasks، Logs و Audit

### US-070 — Task list — P0

به‌عنوان Operator می‌خواهم jobهای sync، prefetch، cleanup و backup را ببینم.

پذیرش:
- state، progress، actor، start/end و error نمایش داده شود.
- filter و pagination فراهم باشد.
- retry فقط برای task idempotent مجاز باشد.

### US-071 — Cancel task — P1

به‌عنوان Operator می‌خواهم task طولانی را لغو کنم.

پذیرش:
- safe cancellation point تعریف شود.
- artifact ناقص publish نشود.
- نتیجه cancelled و cleanup ثبت شود.

### US-072 — Structured logs — P0

به‌عنوان Support می‌خواهم logها را بر اساس service، level و correlation ID جست‌وجو کنم.

پذیرش:
- secret redaction تست شود.
- timezone و timestamp استاندارد باشند.
- download log محدود و permission-aware باشد.

### US-073 — Audit log — P0

به‌عنوان Auditor می‌خواهم تغییرات مدیریتی غیرقابل‌انکار ثبت شوند.

پذیرش:
- actor، action، object، before/after، IP، user-agent و result ثبت شوند.
- audit از UI قابل ویرایش یا حذف نباشد.
- export امضاشده یا checksum‌شده باشد.

### US-074 — Correlation trace — P0

به‌عنوان Support می‌خواهم مسیر یک request از client تا upstream را دنبال کنم.

پذیرش:
- correlation ID در gateway، engine و control plane حفظ شود.
- source upstream و failover count مشخص باشد.
- داده حساس در span ثبت نشود.

## Epic E09 — Storage و Lifecycle

### US-080 — Storage overview — P0

به‌عنوان Admin می‌خواهم مصرف metadata، npm cache، PyPI cache و temporary را جدا ببینم.

پذیرش:
- bytes و object count گزارش شود.
- unknown/unowned files مشخص شوند.
- اندازه‌گیری باعث scan سنگین مکرر نشود.

### US-081 — Disk thresholds — P0

به‌عنوان Operator می‌خواهم قبل از پر شدن disk هشدار بگیرم.

پذیرش:
- warning و critical threshold جدا باشند.
- در critical، publish جدید محدود ولی cached read حفظ شود.
- recovery خودکار state را برگرداند.

### US-082 — Cleanup job — P1

به‌عنوان Admin می‌خواهم artifactهای قدیمی طبق policy پاک شوند.

پذیرش:
- dry-run و impact report اجباری باشد.
- pinned/private/quarantined طبق policy محافظت شوند.
- concurrent download باعث حذف فایل in-use نشود.

### US-083 — Integrity scan — P1

به‌عنوان Operator می‌خواهم filesystem و catalog تطبیق داده شوند.

پذیرش:
- missing، orphan و hash mismatch جدا گزارش شوند.
- repair خودکار پیش‌فرض خاموش باشد.
- scan قابل resume باشد.

## Epic E10 — Backup، Restore و Disaster Recovery

### US-090 — Backup تعریف‌شده — P0

به‌عنوان Platform Admin می‌خواهم DB، config، secrets metadata و artifact data backup شوند.

پذیرش:
- consistency point مشخص باشد.
- backup رمزگذاری و checksum شود.
- credential خام در manifest نباشد.

### US-091 — Backup schedule — P0

به‌عنوان Admin می‌خواهم schedule و retention تعیین کنم.

پذیرش:
- timezone صریح باشد.
- overlapping run جلوگیری شود.
- failure alert شود.

### US-092 — Restore validation — P0

به‌عنوان Admin می‌خواهم backup بدون overwrite محیط اصلی validate شود.

پذیرش:
- restore drill در محیط موقت اجرا شود.
- package نمونه npm/PyPI نصب شود.
- گزارش RPO/RTO واقعی ثبت شود.

### US-093 — Restore production — P0

به‌عنوان Owner می‌خواهم restore کنترل‌شده انجام دهم.

پذیرش:
- confirmation چندمرحله‌ای و maintenance mode اجباری باشد.
- pre-restore snapshot ساخته شود.
- rollback plan نمایش داده شود.

## Epic E11 — Security

### US-100 — Secret vault abstraction — P0

به‌عنوان Security Admin می‌خواهم secretها خارج از config عمومی نگه‌داری شوند.

پذیرش:
- provider interface برای Docker Secret/Kubernetes Secret/Vault باشد.
- UI secret را برنگرداند.
- log redaction coverage تست شود.

### US-101 — Checksum enforcement — P0

به‌عنوان Security Admin می‌خواهم artifact پیش از cache شدن verify شود.

پذیرش:
- hash upstream در صورت وجود اجباری باشد.
- mismatch به client success ندهد.
- event امنیتی و quarantine ساخته شود.

### US-102 — SSRF protection — P0

به‌عنوان Owner می‌خواهم upstream URL نتواند شبکه داخلی را اسکن کند.

پذیرش:
- scheme allowlist و DNS/IP validation باشد.
- redirect مجدد اعتبارسنجی شود.
- metadata IP ranges و loopback پیش‌فرض مسدود باشند.

### US-103 — Rate limiting — P1

به‌عنوان Admin می‌خواهم abuse یا loop client کنترل شود.

پذیرش:
- limit per token/IP/endpoint قابل تنظیم باشد.
- package download بزرگ بی‌دلیل قطع نشود.
- 429 و Retry-After استاندارد باشند.

### US-104 — Security headers — P0

به‌عنوان Security Admin می‌خواهم UI و API headerهای امن داشته باشند.

پذیرش:
- CSP، HSTS، nosniff و frame policy تست شوند.
- mixed-content وجود نداشته باشد.
- TLS termination contract مستند باشد.

### US-105 — Dependency/SBOM scan — P0

به‌عنوان Release Manager می‌خواهم imageها SBOM و vulnerability scan داشته باشند.

پذیرش:
- CycloneDX یا SPDX تولید شود.
- critical finding build را طبق policy fail کند.
- exception دارای owner و expiry باشد.

## Epic E12 — UX و Admin Panel

### US-110 — Responsive layout — P1

به‌عنوان Admin می‌خواهم پنل روی desktop و tablet قابل استفاده باشد.

پذیرش:
- breakpointهای اصلی تست شوند.
- tableها horizontal overflow کنترل‌شده داشته باشند.
- destructive action در mobile اشتباهی trigger نشود.

### US-111 — فارسی و انگلیسی — P1

به‌عنوان کاربر می‌خواهم زبان پنل را تغییر دهم.

پذیرش:
- RTL/LTR کامل باشد.
- تاریخ و عدد locale-aware باشند.
- log و identifier ترجمه نشوند.

### US-112 — Dark mode — P2

به‌عنوان Operator می‌خواهم حالت تاریک داشته باشم.

پذیرش:
- preference ذخیره شود.
- chart و status contrast استاندارد داشته باشند.
- system preference پشتیبانی شود.

### US-113 — Safe destructive UX — P0

به‌عنوان Owner می‌خواهم عملیات مخرب سخت اشتباه شوند.

پذیرش:
- impact summary و نام target نشان داده شود.
- برای حذف حساس تایپ نام target لازم باشد.
- undo فقط وقتی واقعاً قابل تضمین است نمایش داده شود.

### US-114 — Contextual help — P1

به‌عنوان Admin می‌خواهم کنار settingها توضیح و نمونه client config ببینم.

پذیرش:
- snippetها دامنه جاری را استفاده کنند.
- secret در snippet ظاهر نشود.
- copy action feedback داشته باشد.

## Epic E13 — API و Integrations

### US-120 — Versioned REST API — P0

به‌عنوان Integrator می‌خواهم API نسخه‌دار داشته باشم.

پذیرش:
- prefix `/api/v1` و OpenAPI منتشر شود.
- breaking change بدون version جدید ممنوع باشد.
- error envelope یکسان باشد.

### US-121 — Webhook — P1

به‌عنوان Operator می‌خواهم رخدادهای مهم به webhook ارسال شوند.

پذیرش:
- امضای HMAC، retry و dead-letter باشد.
- payload version داشته باشد.
- secret قابل rotate باشد.

### US-122 — Prometheus endpoint — P0

به‌عنوان SRE می‌خواهم metrics استاندارد scrape کنم.

پذیرش:
- endpoint auth/network policy داشته باشد.
- label cardinality محدود باشد.
- metric names و units مستند شوند.

### US-123 — CLI/config generator — P1

به‌عنوان Developer می‌خواهم دستورهای آماده تنظیم client بگیرم.

پذیرش:
- pip، uv، poetry، npm، pnpm و yarn پشتیبانی شوند.
- Linux/Windows تفاوت مسیرها مشخص باشد.
- command حاوی secret خام نباشد.

## Epic E14 — Deploy، Upgrade و Maintenance

### US-130 — Production Compose — P0

به‌عنوان Platform Admin می‌خواهم Compose production-ready داشته باشم.

پذیرش:
- healthcheck، resource limit، restart و log rotation باشد.
- volume paths placeholder و مستند باشند.
- containerها non-root تا حد امکان اجرا شوند.

### US-131 — First-run wizard — P1

به‌عنوان Owner می‌خواهم راه‌اندازی اولیه از پنل انجام شود.

پذیرش:
- admin password، domain، storage و upstreamها تنظیم شوند.
- wizard بعد از completion غیرفعال شود.
- resume امن داشته باشد.

### US-132 — Upgrade preflight — P0

به‌عنوان Admin می‌خواهم قبل از upgrade سازگاری بررسی شود.

پذیرش:
- DB migration، disk، backup و version path بررسی شوند.
- known breaking changes نشان داده شوند.
- upgrade بدون backup سالم در production متوقف شود.

### US-133 — Rolling/restart upgrade — P1

به‌عنوان Admin می‌خواهم upgrade با کمترین downtime انجام شود.

پذیرش:
- maintenance/read-only strategy مشخص باشد.
- migration idempotent باشد.
- rollback محدودیت‌ها را شفاف بیان کند.

### US-134 — Maintenance mode — P0

به‌عنوان Operator می‌خواهم writeها را موقتاً متوقف ولی cached read را حفظ کنم.

پذیرش:
- UI banner و API status مشخص باشد.
- publish و mutation رد شوند.
- owner و expiry برای maintenance ثبت شود.

### US-135 — Support bundle — P1

به‌عنوان Support می‌خواهم bundle بدون secret تولید کنم.

پذیرش:
- version، sanitized config، recent errors و metrics summary باشد.
- secret scan قبل از download اجرا شود.
- تولید bundle audit شود.

## Epic E15 — Quality Gates

### US-140 — Contract tests — P0

به‌عنوان Maintainer می‌خواهم adapterها در برابر نسخه pin‌شده engine تست شوند.

پذیرش:
- API/config behavior snapshot شود.
- upgrade PR بدون contract pass merge نشود.
- backward incompatibility report تولید شود.

### US-141 — Offline E2E — P0

به‌عنوان QA می‌خواهم قطع کامل outbound در CI شبیه‌سازی شود.

پذیرش:
- package cached نصب شود.
- package uncached خطای واضح بدهد.
- هیچ outbound packet ثبت نشود.

### US-142 — Failover chaos test — P0

به‌عنوان QA می‌خواهم DNS، timeout، reset و 5xx تزریق شوند.

پذیرش:
- state machine و metric صحیح باشند.
- cache corruption رخ ندهد.
- recovery بعد از بازگشت upstream تست شود.

### US-143 — Load test — P1

به‌عنوان SRE می‌خواهم ظرفیت و bottleneck اندازه‌گیری شود.

پذیرش:
- cached و miss workload جدا باشند.
- p50/p95/p99 و resource profile ثبت شود.
- regression threshold در CI دوره‌ای باشد.

### US-144 — Upgrade rehearsal — P0

به‌عنوان Release Manager می‌خواهم upgrade روی clone داده production تمرین شود.

پذیرش:
- backup anonymized یا کنترل‌شده استفاده شود.
- migration و rollback test شوند.
- گزارش sign-off ذخیره شود.

## Epic E16 — Modular Appliance و Domain Routing

### US-150 — نگاشت دامنه به سرویس — P0

به‌عنوان Owner می‌خواهم hostname را به پنل، npm، PyPI، status page یا DoH نگاشت کنم.

پذیرش:
- hostname با IDNA/lower-case canonicalize و conflict پیش از save رد شود.
- route فقط به module/capability ثبت‌شده اشاره کند.
- تغییر route atomic، auditشده و بدون restart کامل Appliance باشد.
- hostname ناشناخته fail-closed باشد و به admin یا engine fallback نکند.

### US-151 — Trusted proxy و Host security — P0

به‌عنوان Security Admin می‌خواهم forwarded header فقط از proxyهای مورد اعتماد پذیرفته شود.

پذیرش:
- CIDRهای trusted proxy صریح باشند.
- Host/X-Forwarded-Host spoof و open-proxy test رد شوند.
- scheme و client IP قابل جعل وارد audit نشوند.

### US-152 — دامنه اختصاصی status page — P0

به‌عنوان Operator می‌خواهم هر status page دامنه مستقل داشته باشد.

پذیرش:
- چند دامنه به pageهای متفاوت قابل نگاشت باشند.
- canonical URL، TLS state و DNS readiness نمایش داده شوند.
- public route هیچ bundle یا API مدیریتی را منتشر نکند.

### US-153 — Service catalog — P0

به‌عنوان Owner می‌خواهم moduleهای نصب‌شده، نسخه و capability آنها را ببینم.

پذیرش:
- version، schema، health، readiness، data usage و routeها نمایش داده شوند.
- manifest نامعتبر load نشود و دلیل امن گزارش شود.
- module disabled route عمومی فعال نداشته باشد.

### US-154 — Restart و crash-loop protection — P0

به‌عنوان Operator می‌خواهم module مشکل‌دار را کنترل‌شده restart کنم.

پذیرش:
- impact، in-flight work و reason پیش از تأیید نمایش داده شوند.
- job شامل graceful stop، timeout و verification باشد.
- restart خودکار backoff/jitter/threshold و وضعیت crash-loop داشته باشد.
- actor، reason، مدت و نتیجه audit شوند.

### US-155 — Failure isolation — P0

به‌عنوان Platform Admin می‌خواهم خرابی یک module سرویس‌های دیگر را قطع نکند.

پذیرش:
- health تجمیعی component-level باشد.
- restart uptime یا DNS باعث restart npm/PyPI/control-plane نشود.
- gateway برای route خراب پاسخ واضح و محدود بدهد.

### US-156 — افزودن module آینده — P1

به‌عنوان Maintainer می‌خواهم سرویس جدید بدون fork کردن core اضافه کنم.

پذیرش:
- manifest، adapter، permission، route، migration و UI bundle قرارداد نسخه‌دار داشته باشند.
- یک sample module در contract test ثبت شود.
- حذف module داده را خودکار پاک نکند.

## Epic E17 — Uptime Monitoring

### US-160 — ساخت monitor ساده — P0

به‌عنوان Operator می‌خواهم با wizard کوتاه monitor بسازم.

پذیرش:
- HTTP(S)، TCP، Ping، DNS، Push و TLS certificate حداقل P0 باشند.
- test قبل از save مراحل DNS/connect/TLS/protocol را جدا گزارش کند.
- preset امن interval/timeout/retry داشته باشد.
- SSRF policy مقصد را پیش از probe و پس از redirect بررسی کند.

### US-161 — تنظیمات پیشرفته monitor — P1

به‌عنوان SRE می‌خواهم assertion، header، auth، proxy، retry و dependency تنظیم کنم.

پذیرش:
- Simple/Advanced تغییر mode باعث از دست‌رفتن داده نشود.
- secretها write-only و mask باشند.
- raw request preview secret را redact کند.

### US-162 — مدیریت گروهی monitor — P1

به‌عنوان Operator می‌خواهم monitorها را tag/group و bulk مدیریت کنم.

پذیرش:
- pause/resume، clone، import/export و bulk notification ممکن باشد.
- destructive bulk action impact summary و typed confirmation داشته باشد.

### US-163 — Heartbeat و uptime history — P0

به‌عنوان Observer می‌خواهم وضعیت، latency و history را ببینم.

پذیرش:
- heartbeat، attempt، reason و latency timeline نمایش داده شوند.
- uptime و p50/p95/p99 برای بازه‌های استاندارد و custom محاسبه شوند.
- maintenance از downtime واقعی تفکیک شود و جعل uptime نکند.

### US-164 — Notification channel — P0

به‌عنوان Admin می‌خواهم کانال اعلان بسازم و تست کنم.

پذیرش:
- email، webhook و حداقل کانال‌های پیام‌رسان P0 پشتیبانی شوند.
- retry، dedupe، recovery و delivery log وجود داشته باشد.
- secret rotate شود و در response/log/support bundle برنگردد.

### US-165 — Notification routing و escalation — P1

به‌عنوان SRE می‌خواهم اعلان بر اساس tag، severity و زمان route شود.

پذیرش:
- quiet hours، resend interval و escalation chain باشد.
- policy simulator قبل از save گیرنده‌ها را نشان دهد.
- loop و notification storm محدود شود.

### US-166 — Maintenance — P0

به‌عنوان Operator می‌خواهم maintenance یک‌باره یا تکرارشونده تعریف کنم.

پذیرش:
- timezone و DST صحیح باشند.
- affected monitorها و suppression policy روشن باشند.
- شروع/پایان و تغییر schedule audit شوند.

### US-167 — Incident management — P0

به‌عنوان Incident Manager می‌خواهم incident را draft، publish، update و resolve کنم.

پذیرش:
- severity، component، timeline و message دوزبانه باشد.
- publish روی status page انتخابی atomic و auditشده باشد.
- update عمومی داده خصوصی monitor را لو ندهد.

### US-168 — Status page builder — P0

به‌عنوان Operator می‌خواهم status page عمومی/خصوصی بسازم.

پذیرش:
- group، component، ترتیب، theme، logo و توضیح قابل تنظیم باشد.
- دامنه اختصاصی، badge و RSS/Atom پشتیبانی شوند.
- custom CSS sanitize و CSP محدود داشته باشد.
- accessibility، RTL/LTR و mobile layout تست شوند.

### US-169 — Uptime engine lifecycle — P0

به‌عنوان Operator می‌خواهم scheduler/worker را از پنل مدیریت کنم.

پذیرش:
- queue lag، active check، timeout و event-loop lag دیده شوند.
- restart اعلان تکراری تولید نکند و jobهای in-flight تعیین تکلیف شوند.
- snapshot عمومی آخر در خرابی engine با stale marker باقی بماند.

### US-170 — Uptime parity contract — P0

به‌عنوان Product Owner می‌خواهم هم‌ارزی قابلیت با نسخه pin‌شده Uptime Kuma قابل اثبات باشد.

پذیرش:
- ماتریس native/adapted/mrk/deferred/not-applicable منتشر شود.
- gapهای P0/P1 پیش از release صفر باشند.
- API breaking change در CI contract test را fail کند.
- UI/branding کپی نشود و license notice حفظ شود.

## Epic E18 — DNS Management

### US-175 — DNS onboarding ساده — P0

به‌عنوان Admin می‌خواهم با wizard امن DNS را راه‌اندازی کنم.

پذیرش:
- bind/listener، recursion scope، forwarder و transportها خلاصه شوند.
- open recursion پیش‌فرض یا preset نباشد.
- query test پیش و پس از apply اجرا شود.

### US-176 — Zone management — P0

به‌عنوان DNS Admin می‌خواهم zone بسازم، import/export و مدیریت کنم.

پذیرش:
- Primary، Secondary، Stub و Conditional Forwarder طبق capability پشتیبانی شوند.
- import قبل از apply parse/validate/diff شود.
- حذف/disable zone impact و rollback snapshot داشته باشد.

### US-177 — Record editor — P0

به‌عنوان DNS Admin می‌خواهم recordها را سریع و امن ویرایش کنم.

پذیرش:
- record typeهای رایج و پیشرفته schema-aware باشند.
- conflict، apex rule، IP/hostname و TTL validation باشد.
- bulk edit dry-run و change set atomic داشته باشد.

### US-178 — Simple و Advanced Mode — P0

به‌عنوان Admin می‌خواهم UI روزمره ساده و گزینه‌های حرفه‌ای در Advanced Mode باشد.

پذیرش:
- تغییر mode داده یا config را حذف نکند.
- تنظیم advanced فعال در Simple Mode badge و summary داشته باشد.
- capabilityها بر اساس engine version پنهان/نمایش داده شوند، نه hard-code کور.

### US-179 — Forwarder و cache — P0

به‌عنوان Operator می‌خواهم forwarderها را تست، مرتب و cache را کنترل کنم.

پذیرش:
- UDP/TCP/DoH/DoT/DoQ طبق engine test شوند.
- latency، TLS و failure reason جدا گزارش شوند.
- serve-stale، prefetch و flush با impact/audit مدیریت شوند.

### US-180 — DNSSEC — P0

به‌عنوان Security Admin می‌خواهم validation و signing/rollover را مدیریت کنم.

پذیرش:
- status chain و failure reason قابل مشاهده باشد.
- sign/unsign/rollover preview و typed confirmation داشته باشد.
- key/secret خام در API، log یا backup manifest نباشد.

### US-181 — ACL، transfer و Dynamic Update — P0

به‌عنوان DNS Admin می‌خواهم دسترسی query/recursion/transfer/update را کنترل کنم.

پذیرش:
- ACL ordered و simulator داشته باشد.
- default deny برای transfer و update باشد.
- TSIG rotate/revoke بدون نمایش مجدد secret ممکن باشد.

### US-182 — DoH/DoT/DoQ و دامنه DNS — P0

به‌عنوان Platform Admin می‌خواهم DNS امن با دامنه اختصاصی ارائه کنم.

پذیرش:
- `dns.domain.com/dns-query` فقط به DoH route شود.
- certificate/SNI و client snippet قابل validate باشند.
- پنل توضیح دهد DNS کلاسیک روی 53 با Host route نمی‌شود.

### US-183 — Blocklist و policy — P1

به‌عنوان Security Admin می‌خواهم blocklist و bypass را مدیریت کنم.

پذیرش:
- source، schedule، hash، last-success و item count نمایش داده شوند.
- update در فایل staging validate و سپس atomic فعال شود.
- allow/bypass و false-positive workflow audit شود.

### US-184 — Query log و آمار — P1

به‌عنوان SRE می‌خواهم query، response code، client و latency را تحلیل کنم.

پذیرش:
- retention و permission برای client IP/PII جدا باشد.
- export محدود، auditشده و قابل redaction باشد.
- dashboard QPS، cache hit، SERVFAIL/NXDOMAIN و top zone داشته باشد.

### US-185 — DNS change set — P0

به‌عنوان DNS Admin می‌خواهم تغییرات را قبل از اعمال preview و validate کنم.

پذیرش:
- draft، semantic validation، diff، risk و impact summary باشد.
- High/Critical نیازمند step-up و confirmation مناسب باشد.
- apply idempotent و verification query پس از آن اجرا شود.
- rollback فقط با revision سازگار فعال باشد.

### US-186 — DNS engine lifecycle — P0

به‌عنوان Operator می‌خواهم DNS را بدون خراب‌کردن کل Appliance مدیریت کنم.

پذیرش:
- config parse و backup قبل از restart انجام شود.
- restart job دارای drain/timeout/verify و crash-loop protection باشد.
- safe mode با آخرین config سالم و mutation بسته وجود داشته باشد.

### US-187 — DHCP — P2

به‌عنوان Network Admin می‌خواهم scope، reservation، lease و DNS update را مدیریت کنم.

پذیرش:
- نیازمندی network capability و host mode قبل از فعال‌سازی بررسی شود.
- conflict detection و rollback plan وجود داشته باشد.
- DHCP به‌صورت پیش‌فرض غیرفعال باشد.

### US-188 — DNS Apps — P2

به‌عنوان Advanced Admin می‌خواهم Apps تأییدشده را نصب و مدیریت کنم.

پذیرش:
- فقط catalog allowlist‌شده، hash-pinned و license-reviewed باشد.
- arbitrary upload از مرورگر ممنوع باشد.
- permission/network/filesystem هر App نمایش داده شود.

### US-189 — DNS cluster — P2

به‌عنوان Platform Admin می‌خواهم چند DNS node را یکپارچه مدیریت کنم.

پذیرش:
- member health، role و replication lag دیده شوند.
- quorum/failover drill پیش از ادعای HA لازم باشد.
- یک Appliance تک‌نودی HA نمایش داده نشود.

### US-190 — DNS parity و GPL compliance — P0

به‌عنوان Release Manager می‌خواهم پوشش قابلیت و مجوز Technitium قابل اثبات باشد.

پذیرش:
- ماتریس endpoint/capability نسخه pin‌شده منتشر شود.
- gapهای integrity/security P0/P1 صفر باشند.
- binary، source متناظر، notice و source-offer در artifact انتشار موجود باشند.
- Legal Gate قبل از image عمومی sign-off شود.

## Definition of Done برای همه Storyها

- کد review شده و تست مرتبط دارد.
- threat/permission impact بررسی شده است.
- log و metric کافی اضافه شده است.
- مستندات کاربر و عملیات به‌روز شده است.
- secret یا PII در log/test fixture نیست.
- migration در صورت نیاز forward و rollback note دارد.
- acceptance criteria در محیط نزدیک production اثبات شده است.
- module جدید failure-isolation، lifecycle، backup و upgrade contract را پاس کرده است.
- route عمومی با hostname/trusted-proxy/permission boundary تست شده است.
- capability parity فقط با ماتریس نسخه‌دار و contract test ادعا شده است.

