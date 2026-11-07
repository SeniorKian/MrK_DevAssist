# 08 — Scorecard انتخاب ریپوها

## هدف

این سند Gate رسمی ورود هر کد خارجی به پروژه است. تعداد star به‌تنهایی معیار کیفیت نیست؛ star همراه با سابقه، release cadence، issue burden، CI، تست، security response، license و تطابق قابلیت بررسی می‌شود.

اعداد زیر snapshot تاریخ 2026-11-07 هستند و پیش از pin نهایی دوباره از GitHub و release notes رسمی بررسی می‌شوند.

## معیار و حد نصاب

| معیار | وزن | سؤال اصلی |
|---|---:|---|
| سابقه نگه‌داری | 15 | آیا پروژه چند سال فعال و دارای بیش از یک maintainer است؟ |
| release پایدار | 15 | آیا stable line و release جدید دارد؟ |
| تست و CI | 15 | آیا unit/E2E و workflow فعال دارد؟ |
| adoption | 10 | star، fork و استفاده واقعی چقدر است؟ |
| issue health | 10 | backlog، زمان پاسخ و PR merge مناسب است؟ |
| security | 10 | policy، advisory و patch cadence دارد؟ |
| fit | 15 | قابلیت مورد نیاز را بدون تغییر core بزرگ می‌دهد؟ |
| license | 5 | استفاده، تغییر و توزیع مجاز و روشن است؟ |
| operations | 5 | Docker، upgrade و backup docs مناسب دارد؟ |

- 85 تا 100: انتخاب ترجیحی
- 75 تا 84: قابل قبول با کنترل ریسک
- 60 تا 74: فقط PoC یا component غیرحیاتی
- کمتر از 60: رد

## نتیجه کاندیداهای Registry

### Verdaccio

وضعیت snapshot:

- حدود 17.9k star و 1.5k fork
- بیش از 6,700 commit
- stable 6.x با release فعال
- E2E برای npm، pnpm و Yarn
- multi-uplink و failover native
- Docker رسمی و MIT

نتیجه: **قبول — موتور npm.**

کنترل‌ها:

- فقط آخرین patch stable 6.x پس از security review
- منع استفاده از master، nightly، next-7 و next-9
- contract test برای config و plugin adapter

### devpi

وضعیت snapshot:

- حدود 1.2k star و 150 fork
- سابقه طولانی در اکوسیستم Python
- توسعه و release فعال
- caching index، private index و client/web رسمی
- محدودیت multi-upstream در یک mirror index

نتیجه: **قبول مشروط — موتور PyPI در MVP.**

کنترل‌ها:

- failover بیرون از core
- عدم patch مستقیم مگر gap اثبات‌شده
- تست pip، uv، Poetry و قطع شبکه
- بازبینی open issueهای مرتبط با mirror و PEPهای Simple API قبل از pin

### pypiserver

وضعیت snapshot:

- حدود 2.1k star و بیش از 300 fork
- پروژه بالغ، release فعال و Docker آماده
- مناسب host کردن packageهای local/private
- pull-through proxy و چند upstream هدف اصلی آن نیست

نتیجه: **رد برای موتور cache عمومی؛ نگه‌داری به‌عنوان fallback برای private-only mode.**

### bandersnatch

وضعیت snapshot:

- پروژه رسمی PyPA، حدود 557 star و بیش از 160 fork
- release فعال و پشتیبانی PEP 503/691/658
- mirror استاتیک و قابل verify
- full mirror بسیار پرحجم و on-demand proxy نیست

نتیجه: **Deferred — مناسب prefetch/allowlist یا air-gap، نه MVP on-demand.**

### Pulp + pulp_python + pulp_npm

وضعیت snapshot:

- pulpcore فعال و معماری قوی
- pulp_python فعال ولی adoption عمومی محدودتر
- pulp_npm حدود 15 star، نسخه 0.10.x
- pull-through npm در مستندات Tech Preview

نتیجه: **رد برای هسته MVP production؛ حفظ برای R&D و ارزیابی مجدد پس از stable 1.x.**

### Sonatype nexus-public

وضعیت snapshot:

- حدود 2.7k star و سابقه طولانی
- UI و repository concepts بالغ
- public source فعلی Core شامل Maven، Raw و APT است؛ npm/PyPI مورد نیاز از clone همین source به دست نمی‌آید

نتیجه: **رد به‌عنوان مبنای قابل fork؛ binary Community Edition فقط گزینه خرید/استفاده مستقل است.**

### Warehouse

وضعیت:

- نرم‌افزار رسمی pypi.org و بسیار بالغ
- برای deployment سفارشی package index طراحی و توصیه نشده است

نتیجه: **رد.**

## نتیجه کاندیداهای Control Plane و UI

### FastAPI

- حدود 102k star و 9.9k fork
- release و security activity بسیار فعال
- OpenAPI، typing، async و MIT

نتیجه: **قبول — Control Plane API.**

### React Admin

- حدود 27k star و 5.5k fork
- سابقه از 2016 و release فعال
- REST/GraphQL، TypeScript، React و MUI
- MIT

نتیجه: **قبول — Admin UI framework.**

قاعده: به‌صورت dependency استفاده می‌شود؛ source آن داخل محصول کپی نمی‌شود و fork تنها در صورت gap غیرقابل‌حل ایجاد می‌شود.

## فرآیند بررسی پیش از Clone/Pin

1. دریافت آخرین stable release و دو release قبلی.
2. خواندن changelog و migration guide.
3. بررسی Security tab/advisory و CVEهای dependency.
4. بررسی issueهای open با برچسب bug/security/regression.
5. بررسی CI آخرین tag، نه فقط branch اصلی.
6. ساخت image از source و اجرای test suite.
7. اجرای compatibility E2E پروژه.
8. بررسی license و noticeها.
9. ثبت version، commit و image digest در lock file.
10. ساخت ADR و owner ارتقا.

## نتیجه کاندیداهای ماژول Uptime

### Uptime Kuma

وضعیت snapshot در 2026-11-07:

- حدود 93.3k star و 8.7k fork؛
- releaseهای فعال در stable 2.5.x؛
- MIT؛
- monitor typeها، notification providerها، maintenance، incident، badge و status page چندگانه؛
- مستندات رسمی هشدار می‌دهند API مدیریتی داخلی و ممکن است breaking باشد.

امتیاز اولیه: **88/100 — انتخاب ترجیحی مشروط.**

کنترل‌ها:

- فقط stable tag/commit پس از advisory review؛
- `UptimeAdapter` و contract snapshot برای تمام operationهای مصرف‌شده؛
- عدم دسترسی مستقیم Control Plane به DB engine؛
- عدم کپی UI/branding؛ UI یکپارچه MRK بر مبنای capability ساخته می‌شود؛
- patch فقط برای API gap اثبات‌شده، test-covered و upstreamable؛
- ماتریس parity در هر upgrade بازتولید می‌شود.

### Gatus و Checkmate

هر دو پروژه فعال و مناسب‌اند، اما در snapshot فعلی adoption و breadth قابلیت Uptime Kuma کمتر است. به‌عنوان exit plan و comparison benchmark نگه‌داری می‌شوند، نه پایه MVP.

## نتیجه کاندیداهای ماژول DNS

### Technitium DNS Server

وضعیت snapshot در 2026-11-07:

- حدود 10k star و نزدیک 800 fork؛
- release فعال و سابقه چندساله؛
- authoritative و recursive، DNSSEC، transportهای امن، DHCP، clustering، Apps و HTTP API؛
- مستندات Docker/upgrade/API گسترده؛
- GPL-3.0.

امتیاز فنی اولیه: **86/100 — انتخاب ترجیحی برای engine.**  
وضعیت ورود: **مشروط به Legal/Distribution Gate.**

کنترل‌ها:

- engine process مستقل و بدون link کدی با Control Plane؛
- integration فقط از API مستند و endpoint allowlist‌شده؛
- admin UI engine بیرون publish نمی‌شود؛
- pin نسخه و contract test همه endpointهای مورد استفاده؛
- source code متناظر، copyright notice و source-offer همراه artifact؛
- بررسی حقوقی درباره توزیع MRK و component GPL قبل از اولین image عمومی؛
- عدم patch مگر با ADR و انتشار کامل source متناظر.

### PowerDNS/Knot/BIND/Unbound

engineهای بسیار بالغ‌اند، اما برای رسیدن سریع به authoritative+recursive+API مدیریتی+DNSSEC+DHCP+پنل capability یکپارچه به ترکیب چند engine و adapter بزرگ نیاز دارند. به‌عنوان exit plan فنی برای جداسازی resolver/authoritative نگه‌داری می‌شوند.

## منابع snapshot جدید

- Uptime Kuma repository/releases/license/internal API: `github.com/louislam/uptime-kuma`
- Technitium repository/releases/API/changelog: `github.com/TechnitiumSoftware/DnsServer`
- اعداد star/fork متغیرند و در زمان pin نهایی دوباره ثبت می‌شوند.

## سیاست Fork

- clone برای audit و reproducible build مجاز است.
- fork دائمی فقط وقتی plugin/config/API کافی نباشد.
- patch باید کوچک، test-covered و قابل ارسال به upstream باشد.
- divergence ماهانه گزارش می‌شود.
- سه release عقب‌ماندگی یا patch بزرگ، trigger بازبینی معماری است.

## Evidence لازم برای تغییر انتخاب

تغییر موتور registry فقط وقتی مجاز است که یکی از موارد زیر با PoC اثبات شود:

- bug بحرانی بدون patch یا maintainer response
- license ناسازگار
- پایان پشتیبانی stable line
- incompatibility با clientهای هدف
- شکست SLO یا integrity requirement
- جایگزین جدید حداقل 15 امتیاز scorecard بهتر باشد

