# 02 — معماری و انتخاب ریپوها

## 1. معماری منتخب

```text
Clients ──> یک Docker Appliance
  ├─ :8080 Edge Gateway + Admin UI + Control Plane API
  ├─ :4873 Verdaccio ──> npm upstreams
  ├─ :3141 devpi ──────> PyPI upstream router
  ├─ Uptime engine ────> monitor workers + public status pages
  └─ :53/:853 DNS engine ─> authoritative/recursive + DoH/DoT/DoQ

Browser ──> React Admin ──> Control Plane API ─┬─ Verdaccio adapter
                                               ├─ devpi adapter
                                               ├─ Upstream health engine
                                               ├─ Policy/audit service
                                               ├─ Uptime adapter
                                               ├─ DNS engine adapter
                                               ├─ Domain route registry
                                               ├─ Module/lifecycle manager
                                               └─ Metrics/storage adapters
```

شرح کامل معماری ماژولار و routing در `docs/20-modular-appliance-and-domain-routing.md` ثبت شده است. دامنه‌های HTTP برای پنل، npm، PyPI، status page و DoH قابل نگاشت‌اند. DNS کلاسیک UDP/TCP بر اساس hostname مسیریابی نمی‌شود و listener پروتکلی مستقل دارد.

## 2. چرا دو موتور بالغ؟

یک موتور واحدِ کاملاً متن‌باز که هم npm و هم PyPI را با بلوغ بالا، کش on-demand و UI کامل ارائه کند محدود است. Pulp هر دو plugin را دارد، اما plugin npm هنوز نسخه 0.x و pull-through آن Tech Preview است. معیار پروژه «کمترین باگ و بیشترین سابقه» است؛ بنابراین در MVP از موتور تخصصی بالغ برای هر ecosystem استفاده می‌شود.

## 3. Scorecard اجباری انتخاب وابستگی

هر ریپو قبل از ورود باید از 100 امتیاز ارزیابی شود:

| معیار | وزن |
|---|---:|
| سابقه و تداوم نگه‌داری | 15 |
| release پایدار و cadence | 15 |
| پوشش تست و CI | 15 |
| تعداد کاربران، star و fork | 10 |
| open issue/PR burden و زمان پاسخ | 10 |
| security policy و سابقه CVE response | 10 |
| سازگاری دقیق با نیاز محصول | 15 |
| لایسنس و امکان استفاده تجاری | 5 |
| کیفیت Docker/upgrade docs | 5 |

حد نصاب ورود: 75. هر استثنا باید ADR، risk owner و exit plan داشته باشد.

## 4. ارزیابی اولیه در تاریخ 2026-11-07

### Verdaccio — انتخاب npm

- حدود 17.9k star، 1.5k fork و بیش از 6,700 commit
- stable line مشخص 6.x و release فعال
- E2E برای npm، pnpm و Yarn
- multi-uplink و failover ترتیبی native
- Docker image رسمی و plugin ecosystem
- MIT

تصمیم: **پذیرفته؛ stable 6.x با tag دقیق، نه latest و نه prerelease.**

### devpi — انتخاب PyPI MVP

- بیش از 1.2k star، سابقه طولانی و توسعه فعال
- server، web و client در یک پروژه
- cache index سازگار با pip و indexهای خصوصی
- بازیابی آفلاین از cache اثبات‌شده
- محدودیت: هر mirror index یک upstream اصلی دارد؛ multi-upstream واقعی در adapter/router اختصاصی حل می‌شود.

تصمیم: **پذیرفته مشروط؛ core بدون fork، failover بیرون از core.**

### React Admin — انتخاب پنل

- حدود 27k star و 5.5k fork
- سابقه از 2016، release فعال و TypeScript/React/MUI
- REST/GraphQL data provider، auth و RBAC patterns
- MIT

تصمیم: **پذیرفته؛ dependency استفاده می‌شود، نه fork کامل مگر برای branding build.**

### FastAPI — انتخاب Control Plane

- بیش از 100k star، release فعال، OpenAPI و async support
- ecosystem قوی و MIT

تصمیم: **پذیرفته؛ API business logic در پروژه خودمان می‌ماند.**

### Uptime Kuma — پایه ماژول Uptime

- حدود 93.3k star و 8.7k fork در snapshot 2026-11-07
- release فعال 2.5.x، جامعه بسیار بزرگ و مجوز MIT
- monitorهای متنوع، notification providerها و status page چندگانه
- محدودیت: API مدیریتی عمدتاً داخلی و ناپایدار است

تصمیم: **پذیرفته مشروط؛ release/commit دقیق پشت adapter و contract test، UI/auth یکپارچه MRK و fork حداقلی.**

### Technitium DNS Server — موتور DNS

- حدود 10k star و نزدیک 800 fork، release فعال
- authoritative/recursive، DNSSEC، DoH/DoT/DoQ، DHCP، clustering و API کامل
- محدودیت مهم: GPL-3.0 و runtime .NET؛ توزیع تک‌ایمیج نیازمند compliance حقوقی و source offer است

تصمیم: **پذیرفته برای PoC/طراحی؛ process داخلیِ بدون تغییر و adapter رسمی. ورود به image انتشار منوط به legal Gate است.**

## 5. گزینه‌های رد یا Deferred

### pulp_npm

قابلیت مناسب دارد، اما star پایین، نسخه 0.x و pull-through Tech Preview است. برای R&D و مهاجرت آینده نگه داشته می‌شود، نه MVP production.

### Nexus Public Source

ریپوی عمومی Nexus Core فعلی عمدتاً Maven، Raw و APT را شامل می‌شود؛ بنابراین clone آن به‌تنهایی npm و PyPI مورد نیاز را نمی‌دهد. استفاده از binary Community Edition ممکن است، اما مبنای محصول قابل fork ما نیست.

### pypiserver

بالغ و پرستاره است، اما تمرکز آن سرو پکیج local است و pull-through cache/failover کامل هدف اصلی آن نیست. برای private-only mode گزینه جایگزین است.

### bandersnatch

پروژه رسمی PyPA و مناسب mirror استاتیک یا allowlist است، اما full mirror فضای بسیار زیادی می‌خواهد و on-demand proxy هدف اصلی آن نیست. برای job اختیاری prefetch/air-gap در فاز بعد قابل استفاده است.

### Warehouse

کد pypi.org است، اما خود پروژه‌های اکوسیستم Python استفاده از آن را برای custom package index توصیه نمی‌کنند. رد می‌شود.

## 6. سیاست Clone و Fork

1. هیچ clone از branch اصلی در production ساخته نمی‌شود؛ فقط release tag امضاشده یا commit pin.
2. mirror داخلی Git از upstream نگه داشته می‌شود.
3. تغییر core فقط در branch patch کوچک و مستند انجام می‌شود.
4. patchها ابتدا به upstream پیشنهاد می‌شوند.
5. فاصله fork با upstream ماهانه اندازه‌گیری می‌شود.
6. اگر patch بیش از 500 LOC یا سه release عقب‌ماندگی ایجاد کند، Architecture Review اجباری است.
7. SBOM و license notice برای هر image ساخته می‌شود.
8. Dependabot/Renovate فقط PR می‌سازد؛ merge خودکار production ممنوع است.

## 7. Failover Policy

### حالت‌ها

- Healthy: upstream در rotation است.
- Degraded: latency یا خطای موقت بالا؛ weight کاهش می‌یابد.
- Open Circuit: درخواست جدید تا پایان cooldown ارسال نمی‌شود.
- Manual Block: مدیر upstream را غیرفعال کرده است.
- Offline: فقط cache پاسخ می‌دهد.

### خطاهای مشمول Failover

- DNS error
- connect timeout
- read timeout پیش از دریافت body معتبر
- connection refused/reset
- HTTP 500/502/503/504

### خطاهای غیرمشمول پیش‌فرض

- 401/403: خطای credential/policy
- 404: نبودن package در upstream؛ قابل تنظیم ولی پیش‌فرض بدون failover کور
- checksum mismatch: upstream quarantine می‌شود و پاسخ موفق محسوب نمی‌شود.

## 8. Storage

- metadata و audit: PostgreSQL
- npm cache: volume اختصاصی Verdaccio
- PyPI cache: volume اختصاصی devpi
- artifact checksum: SHA-256 اجباری در catalog کنترل‌پلین
- content ابتدا با نام temporary نوشته، validate و سپس atomic rename می‌شود.
- حذف cache از طریق queue و tombstone انجام می‌شود، نه حذف مستقیم UI.

## 9. پروفایل استقرار

### Development

Compose چندسرویسی برای توسعه سریع، hot reload و mock upstream. این پروفایل artifact نهایی کاربر نیست.

### Production Appliance — خروجی اصلی

- یک Docker Image و یک service
- یک bind mount: `HOST_PATH:/data`
- پورت 8080 برای پنل/API، 4873 برای npm و 3141 برای PyPI
- route مبتنی بر hostname برای پنل/npm/PyPI/status/DoH و listener مستقل DNS روی 53/853
- process supervisor سبک برای lifecycle داخلی
- SQLite/WAL برای state کنترل‌پلین
- storage فایل‌محور مستقل Verdaccio و devpi
- healthcheck تجمیعی برای تمام processها
- تنظیمات و داده‌ها زیر `/data`؛ image immutable

ساختار volume:

```text
/data/
├─ control-plane/
├─ npm/
│  ├─ storage/
│  ├─ config/
│  └─ auth/
├─ pypi/
│  ├─ server/
│  └─ client/
├─ modules/
│  ├─ uptime/
│  └─ dns/
├─ gateway/
├─ logs/
├─ backups/
└─ tmp/
```

### HA Future

PostgreSQL خارجی، object storage و سرویس‌های جدا فقط در صورت عبور از ظرفیت Appliance. این مسیر نباید نصب تک‌ایمیج را پیچیده کند.

