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

## سابقه تحویل Release 0.1 — 2026-11-07

فقط Storyهای زیر تمام معیارهای پذیرش نسخه compact رجیستری را پاس کرده‌اند. Storyهای فهرست‌نشده
همچنان `Planned` یا `Partial` هستند و صرف وجود زیرساخت مشترک به معنی تکمیل آن‌ها نیست.

| Story | Status | Completed | Release/Gate | Evidence |
|---|---|---|---|---|
| US-001 | Done | 2026-11-07 | Gate 0 | `docs/08-repository-selection-scorecard.md` |
| US-002 | Done | 2026-11-07 | Gate 10 | digest pins، lockfileها و `scripts/validate_release.py` |
| US-005 | Done | 2026-11-07 | Gate 1 | `compose.yaml` و smoke محلی |
| US-010 | Done | 2026-11-07 | Gate 5 | `test_auth.py` و `docs/17-gate5-identity-access.md` |
| US-011 | Done | 2026-11-07 | Gate 5 | permission matrix و تست RBAC |
| US-012 | Done | 2026-11-07 | Gate 5 | User CRUD، revoke session و audit tests |
| US-013 | Done | 2026-11-07 | Gate 5 | token create/list/revoke و scope/expiry tests |
| US-020 | Done | 2026-11-07 | Gate 6 | Upstream CRUD API/UI و `test_upstream_admin.py` |
| US-021 | Done | 2026-11-07 | Gate 6 | SSRF-safe probe و health history |
| US-022 | Done | 2026-11-07 | Gate 6 | priority validation و runtime config generation |
| US-023 | Done | 2026-11-07 | Gate 4 | failover E2E و `test_pypi_router.py` |
| US-024 | Done | 2026-11-07 | Gate 4 | circuit threshold/cooldown tests |
| US-025 | Done | 2026-11-07 | Gate 6 | block/unblock API/UI و audit |
| US-026 | Done | 2026-11-07 | Gate 4 | explicit offline mode و internal-network E2E |
| US-027 | Done | 2026-11-07 | Gate 6 | encrypted secret store و credential redaction tests |
| US-030 | Done | 2026-11-07 | Gate 2 | Verdaccio client online/offline E2E |
| US-033 | Done | 2026-11-07 | Gate 7 | publish/restart/download واقعی در `e2e_local_engines.py` |
| US-040 | Done | 2026-11-07 | Gate 3 | pip online/offline image E2E |
| US-042 | Done | 2026-11-07 | Gate 4 | PyPI primary/fallback chaos tests |
| US-043 | Done | 2026-11-07 | Gate 7 | devpi wheel upload/restart/download E2E |
| US-046 | Done | 2026-11-07 | Gate 7 | prefetch task API/UI و task tests |
| US-050 | Done | 2026-11-07 | Gate 7 | unified npm/PyPI catalog و search tests |
| US-052 | Done | 2026-11-07 | Gate 7 | purge preview، confirmation، task و audit |
| US-053 | Done | 2026-11-07 | Gate 7 | revalidate task و checksum path |
| US-054 | Done | 2026-11-07 | Gate 7 | persistent pin policy و cleanup exclusion |
| US-056 | Done | 2026-11-07 | Gate 7 | quarantine reason/policy و cleanup exclusion |
| US-060 | Done | 2026-11-07 | Gate 8 | responsive live overview dashboard |
| US-061 | Done | 2026-11-07 | Gate 8 | persisted upstream health timeline |
| US-062 | Done | 2026-11-07 | Gate 8 | authenticated Prometheus metrics |
| US-064 | Done | 2026-11-07 | Gate 8 | filesystem/storage/process health status |
| US-065 | Done | 2026-11-07 | Gate 8 | manual synthetic upstream probe |
| US-070 | Done | 2026-11-07 | Gate 8 | persistent task list API/UI |
| US-071 | Done | 2026-11-07 | Gate 8 | cancel/retry state-machine tests |
| US-072 | Done | 2026-11-07 | Gate 8 | structured JSON log و secret redaction tests |
| US-073 | Done | 2026-11-07 | Gate 8 | RBAC audit log و safe CSV export |
| US-074 | Done | 2026-11-07 | Gate 8 | correlation ID middleware/log/audit tests |
| US-080 | Done | 2026-11-07 | Gate 9 | real `/data` capacity dashboard |
| US-081 | Done | 2026-11-07 | Gate 9 | threshold validation و Prometheus alert rules |
| US-083 | Done | 2026-11-07 | Gate 9 | SHA-256/SQLite integrity job tests |
| US-090 | Done | 2026-11-07 | Gate 9 | AES-256-GCM backup manifest |
| US-092 | Done | 2026-11-07 | Gate 9 | isolated AEAD/hash/path validation |
| US-093 | Done | 2026-11-07 | Gate 9 | offline guarded restore CLI و PGlite rehearsal |
| US-100 | Done | 2026-11-07 | Gate 10 | local/external upstream key abstraction tests |
| US-101 | Done | 2026-11-07 | Gate 4 | artifact SHA-256 verification before exposure |
| US-102 | Done | 2026-11-07 | Gate 4 | DNS/IP/redirect/host SSRF enforcement tests |
| US-103 | Done | 2026-11-07 | Gate 5 | login throttling و bounded auth failures |
| US-104 | Done | 2026-11-07 | Gate 5 | security headers، trusted hosts و CORS validation |
| US-105 | Done | 2026-11-07 | Gate 10 | Trivy، audit، SBOM/provenance workflow و license gate |
| US-110 | Done | 2026-11-07 | Gate 5 | desktop/tablet/mobile responsive UI review |
| US-111 | Done | 2026-11-07 | Gate 5 | فارسی/English، RTL/LTR و Vazirmatn/Inter |
| US-112 | Done | 2026-11-07 | Gate 5 | persisted light/dark theme |
| US-113 | Done | 2026-11-07 | Gate 6 | exact-name confirmation و last-upstream guard |
| US-114 | Done | 2026-11-07 | Gate 8 | contextual runbook/help links |
| US-120 | Done | 2026-11-07 | Gate 5 | versioned `/api/v1` contract |
| US-122 | Done | 2026-11-07 | Gate 8 | protected `/metrics` endpoint و rules |
| US-130 | Done | 2026-11-07 | Gate 10 | immutable-image production Compose |
| US-131 | Done | 2026-11-07 | Gate 5 | atomic First-Time Owner setup |
| US-134 | Done | 2026-11-07 | Gate 4 | audited per-ecosystem offline maintenance mode |
| US-135 | Done | 2026-11-07 | Gate 8 | redacted in-memory Support Bundle |
| US-140 | Done | 2026-11-07 | Gate 7 | 55 pytest + real-engine contract/E2E suite |
| US-141 | Done | 2026-11-07 | Gate 10 | npm/PyPI empty-client-cache offline E2E |
| US-142 | Done | 2026-11-07 | Gate 4 | DNS/connect/read/5xx failover chaos tests |
| US-143 | Done | 2026-11-07 | Gate 10 | bounded load gate و GitHub-hosted soak |
| US-144 | Done | 2026-11-07 | Gate 10 | Alembic downgrade/upgrade + data preservation |

## بایگانی سندهای طراحی — 2026-11-10

همه سندهای طراحی، برنامه‌ریزی و قرارداد Gateها که پیاده‌سازی و تست شده‌اند حذف شدند تا مخزن سبک بماند.
آنچه واقعاً ساخته شد در Epicهای همین سند است؛ کامنت‌های کد که به «docs/NN» اشاره می‌کنند به این متن‌ها در
تاریخچه git اشاره دارند. ماندند: همین سند، [18](18-operations-runbooks.md) (runbook عملیاتی)،
[44](44-split-services-and-install-wizard.md) (جدا کردن سرویس‌ها، فازهای باقی‌مانده) و سندهای قابلیت‌های
هنوز ساخته‌نشده: [21](21-uptime-monitoring-module.md) و [24](24-native-uptime-engine-spec.md) (Uptime)،
[23](23-adr-native-modules-and-resource-budget.md) (ADR ماژول‌های بومی)، [26](26-oci-registry-module-spec.md) (رجیستری OCI).

| سند حذف‌شده | موضوع | متن کامل |
|---|---|---|
| docs/01 | 01 — محصول و دامنه | `git show 4fea430:docs/01-product-and-scope.md` |
| docs/02 | 02 — معماری و انتخاب ریپوها | `git show 4fea430:docs/02-architecture-and-repository-selection.md` |
| docs/04 | 04 — Roadmap و برنامه تحویل | `git show 4fea430:docs/04-roadmap-and-delivery.md` |
| docs/05 | 05 — API، مدل داده و امنیت | `git show 4fea430:docs/05-api-data-security.md` |
| docs/06 | 06 — تست، مشاهده‌پذیری و عملیات | `git show 4fea430:docs/06-testing-observability-operations.md` |
| docs/07 | 07 — شروع پیاده‌سازی | `git show 4fea430:docs/07-implementation-start.md` |
| docs/08 | 08 — Scorecard انتخاب ریپوها | `git show 4fea430:docs/08-repository-selection-scorecard.md` |
| docs/09 | 09 — بازبینی امنیت و دسترسی | `git show 4fea430:docs/09-security-access-review.md` |
| docs/10 | 10 — Execution Plan آینده | `git show 4fea430:docs/10-execution-plan.md` |
| docs/11 | Process Supervision and Health Contract | `git show 4fea430:docs/11-process-supervision-and-health.md` |
| docs/12 | CI/CD and GHCR Release | `git show 4fea430:docs/12-ci-cd-and-release.md` |
| docs/13 | Gate 2 — npm Registry | `git show 4fea430:docs/13-gate2-npm-registry.md` |
| docs/14 | Professional bilingual admin UI | `git show 4fea430:docs/14-professional-admin-ui.md` |
| docs/15 | Gate 3 — PyPI Registry Baseline | `git show 4fea430:docs/15-gate3-pypi-registry.md` |
| docs/16 | Gate 4 — Multi-upstream Failover Router | `git show 4fea430:docs/16-gate4-failover-router.md` |
| docs/17 | Gate 5 — Identity and Access | `git show 4fea430:docs/17-gate5-identity-access.md` |
| docs/19 | 19 — Production Release Gate | `git show 4fea430:docs/19-production-release-gate.md` |
| docs/20 | 20 — معماری Modular Appliance و مسیریابی دامنه | `git show 4fea430:docs/20-modular-appliance-and-domain-routing.md` |
| docs/22 | 22 — طراحی ماژول DNS Management | `git show 4fea430:docs/22-dns-management-module.md` |
| docs/25 | Clean-room DNS engine for MRK Appliance — behavioural study of Technitium DNS | `git show 4fea430:docs/25-native-dns-engine-spec.md` |
| docs/27 | 27 — اصل «همه‌چیز قابل‌تنظیم» و فهرست تنظیم | `git show 4fea430:docs/27-configurability-and-settings.md` |
| docs/28 | 28 — ماژول‌های کنترل سرور در کنار Dokploy | `git show 4fea430:docs/28-server-control-modules.md` |
| docs/29 | 29 — قراردادهای Gate 17 (Dokploy، مانیتورینگ، لاگ، | `git show 4fea430:docs/29-gate17-contracts.md` |
| docs/30 | MRK S3-Compatible Object Storage Module — Engineering Spec (research draft) | `git show 4fea430:docs/30-s3-object-storage-spec.md` |
| docs/31 | 31 — قراردادهای Gate 18 (سرویس S3، بکاپ سرور و دیت | `git show 4fea430:docs/31-gate18-contracts.md` |
| docs/32 | 32 — قراردادهای Gate 19 (فایروال و ضدحمله، اسکن | `git show 4fea430:docs/32-gate19-contracts.md` |
| docs/33 | MRK admin panel: UX redesign plan (Simple for everyone, Advanced for everything) | `git show 4fea430:docs/33-ux-redesign-plan.md` |
| docs/34 | 34 — قراردادهای بک‌اند برای بازطراحی پنل (خا | `git show 4fea430:docs/34-ui-backend-contracts.md` |
| docs/42 | 42 — برنامه «فضای من»: مدیریت کل در برابر کار | `git show 4fea430:docs/42-my-space-plan.md` |
| docs/43 | 43 — قرارداد «فضای من» (فضای کاری، بسته، مالک | `git show 4fea430:docs/43-my-space-contract.md` |
| docs/_research-tenancy | Research: Multi-tenancy & "customer area" models for DevAssist | `git show 4fea430:docs/_research-tenancy.md` |

## بایگانی سندهای طراحی — 2026-11-09

سندهای طراحی/قرارداد زیر پس از پیاده‌سازی حذف شدند. قابلیت، معیار پذیرشِ واقعاً پیاده‌شده (از بخش «پذیرش» و §0
«تغییرات نسبت به قرارداد اولیه» هر سند)، تصمیم‌ها و محدودیت‌ها در Storyهای ستون سوم آمده است. متن کامل در تاریخچه git:

| سند حذف‌شده | موضوع | Storyها | متن کامل |
|---|---|---|---|
| docs/35 | سرویس‌های من و دامنه‌ها | US-157، US-158 (+ US-159 بازیابی crash، بدون سند) | `git show 1a568bf:docs/35-services-and-domains.md` |
| docs/36 | برنامه جامع موتور DNS بومی (فازهای D0–D6) | US-191 و کل E18 | `git show 1a568bf:docs/36-dns-engine-master-plan.md` |
| docs/37 | DNS فاز D1 (موتور، زون، راه‌اندازی) | US-175–US-179، US-191، US-198 | `git show 1a568bf:docs/37-dns-d1-contract.md` |
| docs/38 | DNS فاز D2 (لاگ، آمار، پایش فشار) | US-184، US-192 | `git show 1a568bf:docs/38-dns-d2-contract.md` |
| docs/39 | DNS فاز D3 — **لغو شد و ساخته نشد** | — | هرگز commit نشد |
| docs/40 | DNS فاز D4 (حل از ریشه، DNSSEC، DNS رمزدار) | US-180، US-182، US-193، US-194 | `git show 9df9787:docs/40-dns-d4-contract.md` |
| docs/41 | DNS فاز نهایی D5+D6 و قالب دامنه | US-176، US-180، US-181، US-183، US-195–US-197، US-115 | هنوز commit نشده بود؛ فقط همین خلاصه |

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

### US-115 — اعلام نسخه تازه پنل — P2

به‌عنوان کاربر پنل می‌خواهم وقتی نسخه تازه پنل روی سرور نصب شد بدانم، بی‌آنکه صفحه خودبه‌خود reload شود.

پذیرش (پیاده‌شده):
- هر 60 ثانیه، فقط وقتی تب دیده می‌شود، `build.commit`/`ui_version` از `GET /api/v1/system/status` با build جاری مقایسه
  شود؛ برای نقشی که به آن دسترسی ندارد (403) نام فایل `/assets/index-*.js` در `index.html` سرو‌شده مقایسه شود.
- نوار «نسخه تازه پنل آمده» با «تازه کردن صفحه» و «بعداً»؛ reload خودکار قبلی حذف شد (`NewVersionBar.tsx`).

وضعیت: انجام‌شده — در درخت کاری، پیش از commit (همراه DNS فاز نهایی)؛ جایگزین docs/41 §7. بررسی: `npm run build` و `check:copy`.

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

وضعیت: بخشی — برای پنل، npm، PyPI، S3 و DoH (`dns-doh`) در US-158 انجام‌شده؛ status page هنوز نه.

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

وضعیت: بخشی — فهرست سرویس‌ها با وضعیت، مصرف و دامنه‌ها در US-157؛ manifest/schema نسخه‌دار ماژول هنوز نه.

### US-154 — Restart و crash-loop protection — P0

به‌عنوان Operator می‌خواهم module مشکل‌دار را کنترل‌شده restart کنم.

پذیرش:
- impact، in-flight work و reason پیش از تأیید نمایش داده شوند.
- job شامل graceful stop، timeout و verification باشد.
- restart خودکار backoff/jitter/threshold و وضعیت crash-loop داشته باشد.
- actor، reason، مدت و نتیجه audit شوند.

وضعیت: بخشی — برای npm، PyPI و S3: restart دستی با تأیید و audit (US-157) و restart خودکار با backoff و وضعیت
`crashed` (US-159)؛ نمایش in-flight work و jitter ساخته نشد.

### US-155 — Failure isolation — P0

به‌عنوان Platform Admin می‌خواهم خرابی یک module سرویس‌های دیگر را قطع نکند.

پذیرش:
- health تجمیعی component-level باشد.
- restart uptime یا DNS باعث restart npm/PyPI/control-plane نشود.
- gateway برای route خراب پاسخ واضح و محدود بدهد.

وضعیت: بخشی — DNS در container جدا با سقف منابع خودش (US-191)؛ crash npm/PyPI/S3 دیگر کانتینر و پنل را نمی‌اندازد (US-159).

### US-156 — افزودن module آینده — P1

به‌عنوان Maintainer می‌خواهم سرویس جدید بدون fork کردن core اضافه کنم.

پذیرش:
- manifest، adapter، permission، route، migration و UI bundle قرارداد نسخه‌دار داشته باشند.
- یک sample module در contract test ثبت شود.
- حذف module داده را خودکار پاک نکند.

### US-157 — صفحه «سرویس‌های من» — P0

به‌عنوان Owner می‌خواهم همه سرویس‌ها را در یک صفحه، جدا از هم، با وضعیت، کنترل، مصرف و دامنه‌ها ببینم.

پذیرش (پیاده‌شده):
- `GET /api/v1/services`: کارت جدا برای پنل، npm، PyPI، S3، Host Agent، فایروال، DNS و `dns-doh`؛ `state`
  (`running|stopped|starting|degraded|crashed|not_installed|disabled|unknown`) با `reason_code`، پورت داخلی ثابت (پنل `8080`،
  npm `4873`، PyPI `3141`، S3 `9000`، DNS `53`)، مصرف (حجم پوشه داده با بودجه 3 ثانیه و cache 60 ثانیه، تعداد
  بسته/سطل/کاربر، آخرین فعالیت)، دامنه‌های متصل و `public_url` (= دامنه اصلی؛ دستورهای اتصال از آن استفاده می‌کنند).
- start/stop/restart فقط برای npm، PyPI و S3، از راه supervisorctl با فهرست مجاز؛ stop/restart تأیید با شناسه سرویس می‌خواهد.
  پنل، پایگاه‌داده، Agent، فایروال و DNS (container جدا) از این صفحه کنترل نمی‌شوند.
- سرویسی که کاربر خاموش کرده پس از restart کانتینر خاموش می‌ماند (`data/control-plane/stopped-services.json`) و
  `/health/ready` را unhealthy نمی‌کند؛ start/restart آن را پاک می‌کند.
- مجوزها: `services:read` (همه نقش‌ها)، `services:operate` (owner/admin/operator)؛ CSRF و audit `services.action`.
  خانه: quick actionهای «سرویس‌های من» و «افزودن دامنه».
- محدودیت: `requests_24h` اندازه‌گیری نمی‌شود (`null`)؛ بدون socket supervisor (مثلاً محیط توسعه) `controllable:false`.

وضعیت: انجام‌شده — commit `1a568bf`؛ جایگزین docs/35. تست: `test_services_domains.py`.

### US-158 — دامنه‌های سرویس هماهنگ با Dokploy — P0

به‌عنوان Owner می‌خواهم برای هر سرویس چند دامنه اضافه کنم بی‌آنکه با ترافیک Dokploy تداخل کند.

پذیرش (پیاده‌شده):
- اصل: DevAssist هرگز پورت 80/443 را نمی‌گیرد؛ ورودی مال Traefik خود Dokploy است و DevAssist فقط مسیر «دامنه → سرویس:پورت» را
  درخواست می‌کند. DevAssist هرگز خودش redeploy نمی‌کند؛ فقط `suggested_action` برمی‌گرداند.
- چند دامنه بی‌سقف برای هر سرویس (پنل، npm، PyPI، S3)، دقیقاً یکی «اصلی» (اولی خودکار؛ با حذف اصلی، قدیمی‌ترینِ بعدی).
  نام canonical (IDNA، حروف کوچک، بدون نقطه آخر)، یکتا در کل؛ wildcard، IP، پورت، scheme و مسیر رد می‌شوند.
- بررسی تداخل پیش از افزودن: با دامنه‌های خود DevAssist (`domain_exists`) و Dokploy (`domain_in_use` با مالک)؛ اگر Dokploy در
  دسترس نباشد فقط هشدار (`conflict_check:"skipped"`)، با بودجه و cache تا Dokploy زیر بار نرود.
- سه روش با تشخیص خودکار (`auto` به همین ترتیب): `dokploy_api` (کانتینر خود از label compose از راه Host Agent پیدا و دامنه با
  API Dokploy v0.31.0 ساخته می‌شود؛ برای Compose `redeploy_required`)، `traefik_file` (اختیاری؛ Agent فقط فایل
  `mrk-domains.yml` را در یک mount جدای rw می‌نویسد، از ورودی ساخت‌یافته نه YAML خام، atomic و بدون symlink؛ mountهای دیگر Agent
  فقط‌خواندنی می‌مانند)، `manual` (گام‌به‌گام fa/en). هر دامنه روش خودش را نگه می‌دارد.
- بررسی DNS (A/AAAA در برابر `MRK_SERVER_PUBLIC_IPS`)، TLS (SNI، زنجیره، انقضا) و رسیدن به **همان** سرویس (از هدر پاسخ)،
  پس از افزودن و دوره‌ای هر 6 ساعت؛ رویدادهای `domain.unhealthy|cert_expiring|healthy` و قانون خانه `domain_problem`.
- همگام‌سازی خودکار پس از هر تغییر: میزبان‌های مجاز پنل بدون restart (TrustedHost پویا)، outside-url PyPI (restart کنترل‌شده
  devpi)، public endpoint و virtual-host S3 (مقدار دستی صفحه S3 حفظ می‌شود)؛ npm نیازی ندارد.
- مجوزها: `domains:read` (همه)، `domains:write` (owner/admin، verify هم)؛ حذف با تایپ host؛ audit `domain.*` و
  `domains.routing.update`؛ جدول `service_domains` (migration `20261108_0012`) در بکاپ منطقی هست.
- محدودیت‌ها: IP عمومی سرور خودکار کشف نمی‌شود؛ `dokploy_api` به Host Agent جفت‌شده نیاز دارد؛ دامنه موجود Dokploy روی خود
  DevAssist adopt نمی‌شود؛ مسیریابی خودکار برای کانتینر `mrk-mirror` نوشته شده (نصب بومی: بررسی یا حالت دستی).

وضعیت: انجام‌شده — commit `1a568bf`؛ جایگزین docs/35. تست: `test_services_domains.py`.

### US-159 — بازیابی خودکار سرویس از کار افتاده — P0

به‌عنوان Operator می‌خواهم خرابی یک رجیستری کل پنل و کانتینر را پایین نیاورد و خودش برگردد.

پذیرش (پیاده‌شده):
- فقط از کار افتادن (FATAL) پایگاه‌داده یا پنل کانتینر را بیرون می‌برد تا Docker آن را بالا بیاورد؛ npm، PyPI و S3 را watchdog
  پنل با تأخیر رو به رشد دوباره راه می‌اندازد (`services.restart_base_delay_seconds` 30 ثانیه، دوبرابر در هر تلاش تا
  `services.restart_max_delay_seconds` 900؛ خاموش‌شدنی با `services.auto_restart`)؛ پس از 5 دقیقه پایداری تأخیر از اول.
- وضعیت `crashed` با `recovery` (تعداد تلاش، زمان تلاش بعدی) در «سرویس‌های من»؛ یک اعلان `service.crashed` و یک
  `service.recovered`. سرویسی که کاربر عمداً خاموش کرده دست نمی‌خورد.
- راهنمای نصب: سیاست `restart: unless-stopped` یا `always`، نه `on-failure`.

وضعیت: انجام‌شده — commit `1a568bf` (سند طراحی جدا نداشت). تست: `test_services_watchdog.py`.

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

> تصمیم پایه (docs/36، جایگزین بخش runtime/بودجه docs/23 و §10 docs/25): به‌جای Technitium یا موتور Python، موتور DNS
> **بومی Go** خود DevAssist (US-191). فازها: D1 پایه و D2 لاگ/پایش (commit `1a568bf`)، D4 حل از ریشه/DNSSEC/رمزدار (commit
> `9df9787`)، D5+D6 و قالب دامنه (در درخت کاری، پیش از commit). فاز D3 (docs/39) لغو شد و ساخته نشد. بیرون از محدوده
> (کار DNS بسته است): DHCP، DNS Apps، cluster چندنودی، catalog zones، DNS cookies، ACME داخل موتور، DoH3.

### US-175 — DNS onboarding ساده — P0

به‌عنوان Admin می‌خواهم با wizard امن DNS را راه‌اندازی کنم.

پذیرش:
- bind/listener، recursion scope، forwarder و transportها خلاصه شوند.
- open recursion پیش‌فرض یا preset نباشد.
- query test پیش و پس از apply اجرا شود.

وضعیت: انجام‌شده — commit `1a568bf` (D1)؛ جایگزین docs/37. تب «راه‌اندازی» شش گام دارد (`engine_running`، `port_53_free`،
`host_resolver`، `docker_daemon`، `verify_from_host`، `verify_from_container`) که از حقایق فقط‌خواندنی Host Agent
(`GET /v1/dns/facts`) تشخیص داده می‌شوند. DevAssist فایل سیستمی را تغییر نمی‌دهد و کانتینری اجرا نمی‌کند: دستور دقیق (آزاد کردن
53 از `systemd-resolved`، resolv.conf، `daemon.json` با gateway `172.17.0.1` نه 127.0.0.1) همراه DNS پشتیبان
(`dns.fallback_servers`) و دستور برگرداندن می‌دهد و بعد بررسی می‌کند؛ restart داکر با برچسب خطر. بدون Agent گام‌ها `unknown`
با دستورهای کامل‌اند.

### US-176 — Zone management — P0

به‌عنوان DNS Admin می‌خواهم zone بسازم، import/export و مدیریت کنم.

پذیرش:
- Primary، Secondary، Stub و Conditional Forwarder طبق capability پشتیبانی شوند.
- import قبل از apply parse/validate/diff شود.
- حذف/disable zone impact و rollback snapshot داشته باشد.

وضعیت: انجام‌شده (جز Stub) — Primary و Conditional Forwarder در D1 (commit `1a568bf`)، Secondary در D5 (در درخت کاری، پیش از
commit)؛ جایگزین docs/37 و docs/41.
- Primary با SOA/NS خودکار؛ import RFC 1035 پیش از اعمال parse/validate (`$INCLUDE` رد)؛ export؛ تاریخچه 50 نسخه هر زون با
  rollback (نسخه تازه با serial بزرگ‌تر)؛ حذف زون با تایپ نام زون. عمیق‌ترین زون برنده است.
- Secondary: بررسی SOA ← IXFR ← در شکست AXFR، با TSIG؛ refresh/retry از SOA، پس از expire SERVFAIL؛ NOTIFY ورودی فقط از
  primaries/`notify_allow`؛ رکوردها فقط‌خواندنی (`zone_read_only`)؛ «همین حالا بگیر». خانه `dns_secondary_problem`، اعلان
  `dns.secondary_expired`/`dns.transfer_failed`.
- انتقال خروجی فقط TCP، پیش‌فرض بسته، حداکثر 10 هم‌زمان، IXFR از history؛ NOTIFY خروجی 5 تلاش با backoff. سقف‌ها: 8 primary،
  16 هدف notify، 64 مدخل ACL، انتقال ورودی 400k RR / 256MB / 5 دقیقه.
- محدودیت: Stub و Catalog zone ساخته نشد؛ در پنل ساده فقط primary ساخته می‌شود (secondary/forwarder در پیشرفته).

### US-177 — Record editor — P0

به‌عنوان DNS Admin می‌خواهم recordها را سریع و امن ویرایش کنم.

پذیرش:
- record typeهای رایج و پیشرفته schema-aware باشند.
- conflict، apex rule، IP/hostname و TTL validation باشد.
- bulk edit dry-run و change set atomic داشته باشد.

وضعیت: بخشی — commit `1a568bf` (D1)؛ جایگزین docs/37. انواع A، AAAA، CNAME، MX، TXT (تا 4000 نویسه، شکستن 255 بایتی)، SRV، NS،
PTR، CAA و SOA (serial خودکار YYYYMMDDnn، با POST ساخته نمی‌شود) با فیلدهای نام‌دار `data`؛ اعتبارسنجی `cname_conflict`،
`cname_at_apex`، `apex_ns_required`، `occluded_by_delegation`، TTL 0..604800 و TTL یکسان در RRset (RFC 2181). ویرایش گروهی با
dry-run ساخته نشد؛ تنها مسیر گروهی، preview و اعمال اتمی قالب (US-197) است.

### US-178 — Simple و Advanced Mode — P0

به‌عنوان Admin می‌خواهم UI روزمره ساده و گزینه‌های حرفه‌ای در Advanced Mode باشد.

پذیرش:
- تغییر mode داده یا config را حذف نکند.
- تنظیم advanced فعال در Simple Mode badge و summary داشته باشد.
- capabilityها بر اساس engine version پنهان/نمایش داده شوند، نه hard-code کور.

وضعیت: انجام‌شده — D1 تا D5. همه تب‌های DNS حالت ساده و پیشرفته دارند؛ اگر موتور بخشی از تنظیمات (مثلاً `resolution`/`dnssec`)
را نفرستد، کارت پیام «به‌روز کنید» نشان می‌دهد و پیش‌فرض نمی‌فرستد. در ساده: وضعیت، دامنه‌ها با قالب، «نام‌های من»، تست،
مسدودسازی، پشتیبان و دو کارت «روش پیدا کردن نشانی‌ها» و «امضای امنیتی».

### US-179 — Forwarder و cache — P0

به‌عنوان Operator می‌خواهم forwarderها را تست، مرتب و cache را کنترل کنم.

پذیرش:
- UDP/TCP/DoH/DoT/DoQ طبق engine test شوند.
- latency، TLS و failure reason جدا گزارش شوند.
- serve-stale، prefetch و flush با impact/audit مدیریت شوند.

وضعیت: انجام‌شده — D1 (commit `1a568bf`) و `quic://` در D4 (commit `9df9787`)؛ جایگزین docs/37 و docs/40. upstreamها
`IP[:port]`، `udp://`، `tcp://`، `tls://IP:853#name`، `https://…` و `quic://`، با راهبرد `fastest` (EWMA)|`parallel`|`in_order`،
health و `rtt_ms`/`last_error` در status؛ cache با سقف بایت، cache منفی، serve-stale (RFC 8767)، prefetch و single-flight؛
flush با audit `dns.cache.flush`. پیش‌فرض upstream: Cloudflare، Google، Quad9.

### US-180 — DNSSEC — P0

به‌عنوان Security Admin می‌خواهم validation و signing/rollover را مدیریت کنم.

پذیرش:
- status chain و failure reason قابل مشاهده باشد.
- sign/unsign/rollover preview و typed confirmation داشته باشد.
- key/secret خام در API، log یا backup manifest نباشد.

وضعیت: انجام‌شده — اعتبارسنجی در D4 (commit `9df9787`، جایگزین docs/40)، امضای زون در D5 (در درخت کاری، پیش از commit،
جایگزین docs/41).
- اعتبارسنجی پیش‌فرض روشن (`validate`؛ `log_only` برای عیب‌یابی) در هر سه حالت حل؛ trust anchor ریشه KSK-2017 و KSK-2024 با
  به‌روزرسانی RFC 5011؛ NSEC/NSEC3، aggressive NSEC، NTA با انقضا؛ AD/CD/DO طبق RFC؛ bogus ← SERVFAIL + EDE با دلیل ساده در
  پنل؛ زون‌های محلی، forwarder داخلی و reverse خصوصی خودکار «ناامن ولی مجاز». خانه `dns_trust_anchor_problem`.
- امضای خودکار هر زون primary: ECDSAP256SHA256 یا ED25519، NSEC یا NSEC3 (iterations ≤100)، تمدید خودکار امضاها، rollover
  ZSK با پیش‌انتشار و KSK با امضای دوگانه، CDS/CDNSKEY؛ DS آماده کپی با راهنمای ۴ قدمی ثبت‌کننده؛ خاموش کردن با تأیید تایپی و
  هشدار برداشتن DS. کلیدها 0600 و هرگز در API/audit؛ الگوریتم تا امضا روشن است قفل (`algorithm_locked`). اعلان
  `dns.dnssec_signing_failed` و خانه `dns_signing_problem`.
- محدودیت: DS برای delegation امضاشده به زیرزون پشتیبانی نمی‌شود؛ پاسخ‌های view امضا ندارند؛ `kdig`/`delv` در ایمیج نیست و
  بررسی با اعتبارسنج خود موتور انجام شد.

### US-181 — ACL، transfer و Dynamic Update — P0

به‌عنوان DNS Admin می‌خواهم دسترسی query/recursion/transfer/update را کنترل کنم.

پذیرش:
- ACL ordered و simulator داشته باشد.
- default deny برای transfer و update باشد.
- TSIG rotate/revoke بدون نمایش مجدد secret ممکن باشد.

وضعیت: انجام‌شده — ACL در D1 (commit `1a568bf`)، transfer/UPDATE/TSIG در D5 (در درخت کاری، پیش از commit)؛ جایگزین docs/37 و
docs/41. ACL ترتیبی با `!` و «اولین تطابق برنده»؛ `0.0.0.0/0`/`::/0` در recursion/query → `open_resolver`؛ تب «تست» با
`client_ip` نقش simulator را دارد. transfer پیش‌فرض بسته؛ Dynamic Update (RFC 2136) پیش‌فرض خاموش و `require_tsig:false` بدون
`allow` رد (`open_update`)؛ فقط انواع D1، SOA خودکار، آخرین NS حذف نمی‌شود. کلید TSIG (hmac-sha256/512) secret را فقط یک بار
نشان می‌دهد و تنظیم آماده `key "…" {…}` برای سرور دیگر دارد؛ چرخش = کلید تازه، جابه‌جایی، حذف قبلی (`tsig_key_in_use` مانع حذف
کلید در حال استفاده).

### US-182 — DoH/DoT/DoQ و دامنه DNS — P0

به‌عنوان Platform Admin می‌خواهم DNS امن با دامنه اختصاصی ارائه کنم.

پذیرش:
- `dns.domain.com/dns-query` فقط به DoH route شود.
- certificate/SNI و client snippet قابل validate باشند.
- پنل توضیح دهد DNS کلاسیک روی 53 با Host route نمی‌شود.

وضعیت: انجام‌شده — commit `9df9787` (D4)؛ جایگزین docs/40. DoH ساده پشت Traefik (`doh.tls=false` روی
`127.0.0.1:8053`/`172.17.0.1:8053`) به‌صورت سرویس `dns-doh` در «سرویس‌های من» دامنه می‌گیرد و گواهی را Traefik می‌دهد؛ چون موتور
روی host network است، حالت `dokploy_api` برای آن به `traefik_file` یا `manual` تبدیل می‌شود. بررسی دامنه با پرسش DoH واقعی
(`Content-Type: application/dns-message`). جزئیات DNS رمزدار در US-194.

### US-183 — Blocklist و policy — P1

به‌عنوان Security Admin می‌خواهم blocklist و bypass را مدیریت کنم.

پذیرش:
- source، schedule، hash، last-success و item count نمایش داده شوند.
- update در فایل staging validate و سپس atomic فعال شود.
- allow/bypass و false-positive workflow audit شود.

وضعیت: انجام‌شده (بدون bypass؛ فاز D3 لغو شد) — D5، در درخت کاری، پیش از commit؛ جایگزین docs/41. تب «مسدودسازی»:
- فهرست‌های hosts، domains، adblock و rpz (حداکثر 31، فقط https، به‌روزرسانی هر `update_hours`)؛ ساخت matcher تازه و swap اتمی
  (پرسش‌ها منتظر نمی‌مانند)؛ شکست ← نسخه قبلی می‌ماند؛ کش فهرست پس از restart بدون شبکه بار می‌شود؛ در فشار critical عقب می‌افتد.
  status هر فهرست: تعداد، آخرین/بعدی به‌روزرسانی، خطا. (1M نام ≈ 11.7MiB، جست‌وجو ~240ns.)
- ترتیب: allow (دستی + استثنای فهرست) > `blocked_services` > فهرست‌ها و block دستی > safe search؛ فقط برای کلاینت مجاز به
  recursion و نام‌های بیرونی (نه override یا زون محلی). پاسخ `nxdomain`|`null_ip`|`refuse` با EDE 15؛ لاگ `source:"blocked"`.
- «این دامنه چرا بسته شد؟» (`filtering/check`) برای false positive؛ دو پیشنهاد خاموش: StevenBlack hosts و URLhaus. تغییرها با
  `PUT settings` (audit `dns.settings.update`) و `dns.filtering.refresh`. اعلان `dns.filter_list_failed`.

### US-184 — Query log و آمار — P1

به‌عنوان SRE می‌خواهم query، response code، client و latency را تحلیل کنم.

پذیرش:
- retention و permission برای client IP/PII جدا باشد.
- export محدود، auditشده و قابل redaction باشد.
- dashboard QPS، cache hit، SERVFAIL/NXDOMAIN و top zone داشته باشد.

وضعیت: انجام‌شده — commit `1a568bf` (D2)؛ جایگزین docs/38.
- مسیر داغ هرگز منتظر لاگ نیست (ring بدون قفل و بدون allocation؛ پر شدن = شمارش `dropped_total`). ذخیره segment ستونی zstd با
  index و Bloom، WAL با بازیابی پس از crash؛ نگهداری با `max_age_days` و `max_bytes`؛ هرگز دیسک را پر نمی‌کند (فضای کم ←
  `errors_only` ← `off`، با رویداد و برگشت خودکار).
- حریم خصوصی IP: `full|mask|hash|none` پیش از ذخیره؛ `exclude_names`/`exclude_clients`. مجوز `dns:logs` جدا (owner/admin)؛ بدون
  آن top آمار و hot پایش پنهان. جست‌وجو با cursor، جریان زنده SSE (3 برای هر کاربر، 20 در کل)، export CSV/NDJSON (audit
  `dns.logs.export`)، حذف با تأیید `DELETE LOGS` یا IP کلاینت (`dns:admin`).
- آمار مستقل از لاگ (دقیقه/ساعت/روز، top با Space-Saving): qps، p50/p95/p99، cache hit، rcode، source، qtype، و از D4 DNSSEC و
  proto. سنجش: 5M ردیف، صفحه اول 11ms، بدترین اسکن 0.54s.

### US-185 — DNS change set — P0

به‌عنوان DNS Admin می‌خواهم تغییرات را قبل از اعمال preview و validate کنم.

پذیرش:
- draft، semantic validation، diff، risk و impact summary باشد.
- High/Critical نیازمند step-up و confirmation مناسب باشد.
- apply idempotent و verification query پس از آن اجرا شود.
- rollback فقط با revision سازگار فعال باشد.

وضعیت: بخشی — `config_version` جلوی ویرایش هم‌زمان تنظیمات را می‌گیرد (`dns_config_conflict`)، هر تغییر زون نسخه history دارد
و rollback نسخه تازه می‌سازد، import و قالب (US-197) پیش از اعمال validate/preview می‌شوند. draft، diff عمومی، risk و step-up
ساخته نشد.

### US-186 — DNS engine lifecycle — P0

به‌عنوان Operator می‌خواهم DNS را بدون خراب‌کردن کل Appliance مدیریت کنم.

پذیرش:
- config parse و backup قبل از restart انجام شود.
- restart job دارای drain/timeout/verify و crash-loop protection باشد.
- safe mode با آخرین config سالم و mutation بسته وجود داشته باشد.

وضعیت: بخشی — موتور در container جدا با healthcheck (`mrk-dns health`) و `restart: unless-stopped` (US-191)؛ نوشتن همه فایل‌ها
اتمیک، زون خراب از آخرین نسخه history بازیابی می‌شود، تنظیمات بدون restart اعمال می‌شوند و listener ناموفق هر 10 ثانیه دوباره
امتحان می‌شود؛ پشتیبان/بازگردانی در US-196. پنل موتور را restart نمی‌کند و safe mode ساخته نشد.

### US-187 — DHCP — P2

به‌عنوان Network Admin می‌خواهم scope، reservation، lease و DNS update را مدیریت کنم.

پذیرش:
- نیازمندی network capability و host mode قبل از فعال‌سازی بررسی شود.
- conflict detection و rollback plan وجود داشته باشد.
- DHCP به‌صورت پیش‌فرض غیرفعال باشد.

وضعیت: بیرون از محدوده — کار DNS بسته شد (فهرست سرآغاز E18).

### US-188 — DNS Apps — P2

به‌عنوان Advanced Admin می‌خواهم Apps تأییدشده را نصب و مدیریت کنم.

پذیرش:
- فقط catalog allowlist‌شده، hash-pinned و license-reviewed باشد.
- arbitrary upload از مرورگر ممنوع باشد.
- permission/network/filesystem هر App نمایش داده شود.

وضعیت: بیرون از محدوده — کار DNS بسته شد (فهرست سرآغاز E18).

### US-189 — DNS cluster — P2

به‌عنوان Platform Admin می‌خواهم چند DNS node را یکپارچه مدیریت کنم.

پذیرش:
- member health، role و replication lag دیده شوند.
- quorum/failover drill پیش از ادعای HA لازم باشد.
- یک Appliance تک‌نودی HA نمایش داده نشود.

وضعیت: بیرون از محدوده — کار DNS بسته شد (فهرست سرآغاز E18)؛ نزدیک‌ترین قابلیت موجود secondary با AXFR/IXFR/NOTIFY است (US-176).

### US-190 — DNS parity و GPL compliance — P0

به‌عنوان Release Manager می‌خواهم پوشش قابلیت و مجوز Technitium قابل اثبات باشد.

پذیرش:
- ماتریس endpoint/capability نسخه pin‌شده منتشر شود.
- gapهای integrity/security P0/P1 صفر باشند.
- binary، source متناظر، notice و source-offer در artifact انتشار موجود باشند.
- Legal Gate قبل از image عمومی sign-off شود.

وضعیت: منسوخ — Technitium به کار نرفت؛ موتور بومی clean-room از روی RFCها و مطالعه رفتاری docs/25 نوشته شد (US-191) و
وابستگی‌هایش فقط مجوز آزاد دارند (`miekg/dns`، `golang.org/x/*`، `klauspost/compress`، `quic-go` همه BSD/MIT، پنل
`qrcode-generator` MIT)؛ پس ماتریس parity و تعهد GPL موضوعیت ندارد.

### US-191 — موتور DNS بومی و ایزوله — P0

به‌عنوان Platform Admin می‌خواهم یک DNS حرفه‌ای داخل همان ایمیج داشته باشم که فشار یا خرابی آن به پنل، رجیستری‌ها و خود سرور
نرسد.

پذیرش (پیاده‌شده):
- موتور Go در `apps/dns-engine` (کتابخانه پروتکل `miekg/dns`؛ منطق سرور، cache، سیاست، لاگ و API کد خود DevAssist) با باینری‌های
  `mrk-dns` (`serve|health|version`) و `mrk-dnsbench`، داخل همان ایمیج؛ ایمیج جدا ندارد.
- container جدای `mrk-dns` از همان ایمیج (Compose profile `dns`، `network_mode: host` تا IP واقعی کلاینت و سرعت UDP بماند)،
  سقف `MRK_DNS_CPUS`=2، `MRK_DNS_MEMORY`=512m، `MRK_DNS_PIDS`=256، `GOMEMLIMIT` خودکار، `read_only`، `no-new-privileges`،
  `cap_drop: ALL`، healthcheck و `restart: unless-stopped`. DNS به پنل وابسته نیست.
- **مدل مجوز پورت 53:** چون با `no-new-privileges` file capability نادیده گرفته می‌شود، سرویس با `user: "0:10001"` و فقط
  `NET_BIND_SERVICE, SETUID, SETGID` شروع می‌شود و موتور پیش از هر کاری روی همه threadها به `MRK_DNS_RUN_AS` (پیش‌فرض
  `10001:10001`، uid صفر رد) می‌رود و فقط `NET_BIND_SERVICE` را نگه می‌دارد (روی compose واقعی: `Uid 10001`،
  `CapEff=0x400`). `validate_release.py` نبود `setcap` و همین پیکربندی را بررسی می‌کند.
- API مدیریتی فقط روی unix socket (`/run/mrk-dns/admin.sock`) با توکن Bearer (`admin.token`)؛ پنل volume `mrk-dns-run` را
  فقط‌خواندنی دارد. `GET /v1/health` بدون توکن.
- هرگز open resolver نیست: `/0` در `recursion.allow`/`query_allow` رد (`open_resolver`)، بیرون از ACL ← REFUSED؛ سقف qps هر
  کلاینت و RRL (فقط UDP و فقط برای بیرون از `recursion.allow`)، UDP 1232، `ANY` حداقلی (RFC 8482)، CHAOS و AXFR بی‌اجازه REFUSED،
  محافظت DNS rebinding، reverse خصوصی (RFC 6303) و `.invalid` محلی و هرگز به upstream.
- ذخیره فایل اتمیک (temp + fsync + rename) و `config_version`؛ override «این نام → این آدرس» (A/AAAA/CNAME) فقط برای کلاینت‌های
  داخل `recursion.allow`.
- پنل: ماژول `dns` با `dns:read` (همه)، `dns:write` (owner/admin/operator)، `dns:logs` و `dns:admin` (owner/admin) زیر گروه nav
  «سرور و برنامه‌ها»؛ audit همه تغییرها؛ اعلان `dns.unreachable`/`dns.recovered`، خانه `dns_unreachable` و گام `setup_dns`؛
  کارت DNS در «سرویس‌های من» (کنترل‌پذیر نیست).
- سخت‌سازی D6: fuzz برای پارسر پرسش، segment لاگ، فیلتر، فهرست مسدودسازی، UPDATE/NOTIFY/AXFR/IXFR و TSIG، همه در CI (هر کدام
  20 ثانیه)؛ تست بار 10 دقیقه‌ای job دستی `dns-engine-load` در `soak.yml`.

وضعیت: انجام‌شده — commit `1a568bf` (D1)، سخت‌سازی D6 در درخت کاری پیش از commit؛ جایگزین docs/36 و docs/37. سنجش: ≈87–94 هزار
qps از cache روی 2 هسته (لاگ روشن یا خاموش). محدودیت‌های D1 (حل از ریشه، DNSSEC، DoT/DoH ورودی) در D4 برطرف شد؛ DNS cookies
و ECS ساخته نشد.

### US-192 — پایش بحرانی، فشار و مقابله با حمله — P0

به‌عنوان SRE می‌خواهم DNS زیر بار سنگین یا حمله پاسخگو بماند و بدانم چه شده است.

پذیرش (پیاده‌شده):
- چهار سطح `normal|warning|critical|emergency` بر پایه CPU و حافظه container، `qps_percent` از `capacity_qps` و CPU/حافظه میزبان
  (از Host Agent هر 10 ثانیه)؛ با hysteresis (ورود پس از دو نمونه، خروج یک سطح در هر بار پس از `dwell_seconds` و margin).
- اقدام خودکار، برگشت‌پذیر و هرکدام قابل خاموش: warning (نمونه‌برداری لاگ 25٪، بی prefetch، `minimal_any`)، critical
  (+ لاگ `errors_only`، `prefer_stale`، نصف‌کردن سقف کلاینت، رد recursion کلاینت‌های سنگین — داده authoritative را همچنان
  می‌گیرند)، emergency (+ لاگ خاموش، یک‌چهارم سقف). اگر `client_qps=0` باشد سقف پایه 2000 qps اعمال می‌شود.
- تشخیص random-subdomain (HyperLogLog) و NXDOMAIN flood با حالت `off|suggest` (پیش‌فرض)`|auto`؛ محدودسازی دستی/خودکار
  (`throttle|block|refuse` روی کلاینت یا دامنه، مدت‌دار، حداکثر 10000)؛ throttle دامنه فقط کار upstream را محدود می‌کند و cache
  همیشه پاسخ می‌دهد.
- تب «پایش»: جمله وضعیت، نمودارها، پرمصرف‌ترین دامنه‌ها/کلاینت‌ها با «کند کن / مسدود کن» (`dns:write`)، حمله‌ها و محدودسازی‌های
  فعال؛ بدون `dns:logs` فقط شمار. اعلان‌ها `dns.pressure`، `dns.attack_detected`، `dns.mitigation_auto`، `dns.logs_degraded`/
  `recovered`؛ خانه `dns_under_pressure` و `dns_attack_detected` (درخواست خانه هرگز موتور را صدا نمی‌زند).

وضعیت: انجام‌شده — commit `1a568bf` (D2)؛ جایگزین docs/38. آزمون بار: سیل 46 هزار qps از یک کلاینت ← emergency در 2 ثانیه،
کلاینت عادی 7000/7000 NOERROR (p99 34ms)، حافظه ثابت؛ random-subdomain ← تشخیص و محدودسازی خودکار در اولین ارزیابی.

### US-193 — حل مستقل از ریشه — P1

به‌عنوان Admin می‌خواهم DNS بتواند بدون سرور واسط (Cloudflare/Google) نام‌ها را خودش از ریشه پیدا کند.

پذیرش (پیاده‌شده):
- `resolution.mode`: `forward` (پیش‌فرض؛ رفتار نصب‌های قبلی عوض نشد)، `recursive`، `forward_then_recursive` (forward حداکثر نیمی
  از `resolve_timeout_ms`؛ NXDOMAIN معتبر به ریشه نمی‌رود). در پنل سه کارت با جمله روزمره.
- priming ریشه (RFC 8109) در شروع و هر 24 ساعت، QNAME minimisation (`relaxed|strict`)، 0x20 با کنار گذاشتن سرور ناسازگار،
  bailiwick برای glue، سقف ارجاع/پرسش/زمان، `allow_private_ns:false` (ضد SSRF)، fallback بدون EDNS و infra cache؛ هرگز ارسال
  به نشانی‌های listen خود موتور.
- تست «مسیر کامل» گام‌به‌گام ریشه ← TLD ← دامنه (فقط `dns:write`)؛ هشدار غیرمسدودکننده `recursive_needs_outbound_53`؛
  اعلان `dns.priming_failed`.

وضعیت: انجام‌شده — commit `9df9787` (D4)؛ جایگزین docs/40. واقعی: 312 بررسی هم‌خوان با Unbound و کلاینت عادی زیر سیل نام تصادفی
در حالت recursive سالم ماند.

### US-194 — DNS رمزدار برای گوشی، لپ‌تاپ و مرورگر — P0

به‌عنوان کاربر می‌خواهم دستگاه‌هایم با DoT، DoH یا DoQ به DevAssist وصل شوند، بی‌آنکه DevAssist open resolver شود.

پذیرش (پیاده‌شده):
- DoT (RFC 7858، 853/tcp)، DoH (RFC 8484، `/dns-query`، HTTP/2 با TLS یا HTTP ساده پشت Traefik)، DoQ (RFC 9250، 853/udp)؛ سقف
  اتصال کل و هر کلاینت؛ همه از همان مسیر ACL/فشار/mitigation/لاگ (proto `dot|doh|doq`) می‌گذرند.
- گواهی: خودامضا (ECDSA P-256، 397 روز، تمدید خودکار) یا بارگذاری؛ بارگذاری بدون restart؛ کلید خصوصی هرگز برنمی‌گردد و در
  audit نیست. روشن کردن بدون گواهی ← `certificate_required`. اعلان انقضا 14/7/3/1 روز و خانه `dns_certificate_expiring`.
- `encrypted.allow` برای ورودی رمزدار جای ACLها را می‌گیرد؛ دسترسی از اینترنت فقط با توکن DoH (`/dns-query/<token>`، فقط
  SHA-256 ذخیره، qps هر توکن، نمایش یک‌باره با QR)؛ DoH ساده روی نشانی عمومی رد (`plain_doh_public`)؛ هشدار
  `doh_public_needs_token`.
- تب «اتصال رمزدار»: سه کلید، کارت گواهی، توکن‌ها و راهنمای هر دستگاه (Android، iPhone/Mac با پروفایل `.mobileconfig`،
  Windows، Firefox/Chrome، Linux). forwarder خروجی `quic://` هم اضافه شد.

وضعیت: انجام‌شده — commit `9df9787` (D4)؛ جایگزین docs/40. محدودیت: پیش‌فرض DoH
`0.0.0.0:443` روی میزبانی که Traefik دارد `listener.failed` می‌دهد (حالت «پشت Traefik» را به کار ببرید)؛ ACME داخل موتور و
DoH3 نیست.

### US-195 — گروه‌های دستگاه و پاسخ جدا برای شبکه داخلی — P1

به‌عنوان Network Admin می‌خواهم دستگاه‌های مختلف سیاست جدا بگیرند و نام‌ها برای شبکه داخلی پاسخ دیگری بدهند (split-horizon).

پذیرش (پیاده‌شده):
- `client_groups` (اولین گروه منطبق): شبکه‌ها، filtering `inherit|on|off`، فهرست‌ها، upstreamهای جدا (فقط forward، با cache جدا
  تا پاسخ‌ها قاطی نشوند) و `blocked_services`.
- رکورد با فیلد `view` (شناسه گروه) برای همان گروه جای RRset عمومی همان نام/نوع را می‌گیرد؛ زون همیشه معتبر می‌ماند.
- محدودیت: پاسخ view امضای DNSSEC ندارد و در AXFR/export نمی‌آید؛ `blocked_services` و اعلام `views` زون در پنل نیست (رکورد
  دارای `view` = override)؛ گروه‌ها فقط در حالت پیشرفته.

وضعیت: انجام‌شده — D5، در درخت کاری، پیش از commit؛ جایگزین docs/41.

### US-196 — پشتیبان و بازگردانی DNS — P0

به‌عنوان Admin می‌خواهم همه پیکربندی DNS را یک‌جا پشتیبان بگیرم و با اطمینان برگردانم.

پذیرش (پیاده‌شده):
- دانلود (`dns:admin`) فایل `mrk-dns-backup-*.tar.gz` با manifest نسخه‌دار و sha256 هر فایل: تنظیمات، زون‌ها، overrides،
  mitigations، توکن‌ها (فقط hash)، گواهی، TSIG و کلیدهای DNSSEC؛ بدون لاگ، آمار، کش فهرست‌ها و داده secondary. audit
  `dns.backup.download`.
- بازگردانی با تأیید تایپی؛ اعتبارسنجی کامل پیش از اعمال (هر خطا ← `restore_invalid` و هیچ تغییری)؛ اعمال اتمی با journal و
  rollback پس از crash؛ بارگذاری دوباره بدون restart و `config_version` بالاتر؛ `restart_required` اگر TSIG/کلیدها عوض شد. audit
  `dns.restore`.
- سقف فایل در پنل 128MiB (موتور 1GiB).

وضعیت: انجام‌شده — D6، در درخت کاری، پیش از commit؛ جایگزین docs/41.

### US-197 — قالب دامنه — P1

به‌عنوان Admin می‌خواهم دامنه تازه بدون کار تکراری با رکوردهای پیش‌فرض ساخته شود.

پذیرش (پیاده‌شده):
- شش قالب آماده و فقط‌خواندنی (قابل کپی): `website` (پیش‌فرض)، `website_email`، `google_workspace`، `microsoft_365`،
  `dokploy_apps` (wildcard به سرور)، `security_only` (CAA، SPF `-all`، DMARC reject)؛ قالب کاربر در جدول `dns_templates`
  (migration `20261109_0013`)، سقف 200 قالب / 200 رکورد / 20 متغیر.
- متغیرهای خودکار `domain`، `domain_dashed`، `server_ipv4`/`server_ipv6` (از `domains.server_public_ips` یا نشانی‌های عمومی Agent)،
  `mail_host`، `dkim_value`؛ رکوردی که متغیرش خالی است ساخته نمی‌شود (skipped)؛ IPv4 نامعلوم ← هشدار `server_ipv4_unknown`.
- ساخت دامنه تازه قالب پیش‌فرض (`dns.default_template_id`) را خودکار اعمال می‌کند؛ کاربر قالب دیگر یا «بدون قالب» را انتخاب
  می‌کند و فقط متغیرهای غیرخودکار پرسیده می‌شوند. اگر import قالب شکست بخورد زون می‌ماند و پیام روشن داده می‌شود.
- اعمال روی دامنه موجود: preview (تازه / تکراری / ناجور / ساخته نمی‌شود) و اعمال اتمی با import موتور (یک نسخه history)؛ تعارض
  بدون «جایگزین کن» رد می‌شود.
- مجوزها: خواندن `dns:read`، تغییر قالب `dns:admin`، اعمال `dns:write`؛ audit `dns.template.*` و `dns.zone.apply_template`؛
  مقدار متغیرها هرگز در audit نیست.
- محدودیت: در حالت جایگزینی comment رکوردهای باقی‌مانده از بین می‌رود و اگر رکورد خاموش یا دارای `view` بماند اعمال رد می‌شود
  (`dns_template_replace_unsafe`).

وضعیت: انجام‌شده — در درخت کاری، پیش از commit؛ جایگزین docs/41. build و `check:copy` پنل سبز؛ پنل فقط با پاسخ‌های ساختگی در مرورگر
بررسی شد و هنوز با بک‌اند واقعی سرتاسری امتحان نشده است.

### US-198 — DNS برای دامنه‌های «سرویس‌های من» — P1

به‌عنوان Operator می‌خواهم containerهای روی سرور دامنه‌های سرویس‌ها را مستقیم به خود سرور حل کنند.

پذیرش (پیاده‌شده):
- `dns.services_overrides` (پیش‌فرض خاموش): برای هر دامنه سرویس override A/AAAA با TTL 60 و `source:"services"` به
  `dns.services_override_target` (پیش‌فرض gateway داکر)؛ override کاربر روی همان نام دست نمی‌خورد (`skipped`) و override
  مدیریت‌شده را کاربر عوض/حذف نمی‌کند (`dns_override_managed`).
- زون داخلی اختیاری `mrk.internal` با `panel|npm|pypi|s3`؛ با خاموش کردن فقط رکوردهای مدیریت‌شده حذف می‌شوند.
- همگام‌سازی پس از هر تغییر دامنه؛ نتیجه در `sync.dns` پاسخ‌های دامنه؛ بدون موتور هم تنظیم ذخیره می‌شود.

وضعیت: انجام‌شده — commit `1a568bf` (D1)؛ جایگزین docs/37.

## Epic E19 — نصب جدا: پنل اول، سرویس‌ها از داخل پنل

طرح و فازها: [سند 44](44-split-services-and-install-wizard.md).

### US-200 — پنل به تنهایی نصب می‌شود
**به عنوان** مدیر سرور **می‌خواهم** فقط پنل را با یک فرمان (Docker، Dokploy، Coolify یا نصب بومی) بالا بیاورم.
- پذیرش: `compose.yaml` ریشه فقط `mrk-panel` (پنل + PGlite) را دارد و بدون هیچ سرویس دیگری ready می‌شود؛
  شبکه `mrk-net` و volumeهای `mrk-dns-run`/`mrk-firewall-run` را با نام ثابت می‌سازد.
- پذیرش: npm و PyPI که در این نصب نیستند «نصب نشده» نشان داده می‌شوند، نه «خراب».
- پذیرش: نصب بومی (`scripts/install-native.sh`) فقط پنل را نصب می‌کند؛ بقیه سرویس‌ها همیشه Docker هستند.
- وضعیت: **تحویل شد** (2026-11-10).

### US-201 — ویزارد «افزودن سرویس»
**به عنوان** مدیر **می‌خواهم** هر سرویس را از «سرویس‌های من ← افزودن سرویس» با راهنمای قدم‌به‌قدم نصب کنم.
- پذیرش: روش اجرا (Dokploy، Coolify، Docker Compose)، تنظیمات با پیش‌فرض، `compose.yaml` و `.env` آماده
  با دکمه کپی/دریافت، و «اتصال و امتحان» که پنل را وصل و جواب دادن سرویس را بررسی می‌کند.
- پذیرش: بعد از ساختن حساب مالک، پنل مستقیم این صفحه را باز می‌کند.
- پذیرش: کلید اتصال را پنل می‌سازد (Agent، فایروال) یا از قبل دارد (S3) و فقط یک بار در `.env` نشان می‌دهد؛
  سرویس آن را از env می‌خواند و دیگر لازم نیست کلید از گزارش‌ها پیدا شود.
- وضعیت: **تحویل شد** برای Agent، DNS، فایروال و S3؛ npm و PyPI «به‌زودی».

### US-202 — S3 در کانتینر جدا
- پذیرش: پنل snapshot سطل‌ها، کاربران و کلیدها را با `PUT /admin/config` روی `mrk-net` می‌فرستد؛ موتور آن را
  اعتبارسنجی و در volume خودش (0600) نگه می‌دارد؛ اگر موتور با volume خالی برگردد، پنل حداکثر ۳۰ ثانیه بعد
  دوباره می‌فرستد. مدیر فایل، پشتیبان‌ها و «فضای من» از نشانی موتور جدا استفاده می‌کنند.
- وضعیت: **تحویل شد** (تست e2e با دو کانتینر واقعی و کلاینت boto3).

### US-203 — نصب خودکار از طرف پنل (Dokploy/Coolify API)
- پذیرش: پنل با کلید API ‏Dokploy یا Coolify سرویس را خودش می‌سازد، env و دامنه را تنظیم و deploy می‌کند.
- وضعیت: **برنامه‌ریزی‌شده** (فاز ۶).

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

