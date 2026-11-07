# 19 — Production Release Gate

این سند خروجی Gate 10 و checklist انتشار است. آماده‌سازی release با deploy فرق دارد؛ هیچ workflow
اینجا به Dokploy یا سرور production متصل نمی‌شود. انتشار CI فقط image و attestation را در GHCR
می‌سازد و deploy نهایی باید پس از تأیید معماری به‌صورت دستی و با digest انجام شود.

## Container hardening

- base imageهای Node و Python با tag دقیق و digest چندمعماری قفل شده‌اند؛
- runtime با UID/GID `10001:10001`، root filesystem فقط‌خواندنی، `cap_drop: ALL` و
  `no-new-privileges` اجرا می‌شود؛
- تنها مسیر قابل‌نوشتن دائمی `/data` و تنها مسیر موقت `/tmp` با `noexec,nosuid,nodev` است؛
- production Compose هیچ `build` یا host `ports` ندارد و `MRK_IMAGE` immutable اجباری است؛
- Docker socket، SSH key، host root و credential اولین ادمین mount نمی‌شوند؛
- First-Time Setup تنها راه ساخت Owner اول است و پس از ایجاد اولین کاربر fail-closed می‌شود.
- profile سخت‌گیرانه کلید credentialهای upstream را با `MRK_UPSTREAM_SECRET_KEY_FILE` از فایل secret
  فقط‌خواندنی ۳۲‌بایتی خارج از `/data` می‌گیرد؛ مسیر مفقود/نامعتبر fail-closed است.

`scripts/validate_release.py` این قرارداد را در CI کنترل می‌کند. syntax فایل production Compose نیز
با یک digest نمونه و `docker compose config --quiet` اعتبارسنجی می‌شود.

## Supply chain

Workflow انتشار:

1. test، Ruff، build UI، auditهای Python/npm، migration rehearsal و license gate را اجرا می‌کند؛
2. image چندمعماری `amd64/arm64` را می‌سازد؛
3. SBOM و provenance تولید و GitHub build attestation را با OIDC ثبت می‌کند؛
4. digest منتشرشده را با Trivy برای HIGH/CRITICAL قابل‌رفع fail می‌کند؛
5. فقط digest immutable را در summary تحویل می‌دهد.

Base imageهای resolveشده در 2026-11-07:

- Node `24.18.0-bookworm-slim`: `sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d`
- Python `3.13-slim-bookworm` (`3.13.18`): `sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72`

## Egress policy

ماتریس دقیق مقصدها در `deploy/security/egress-policy.md` است. uplinkهای npm و PyPI از پنل مدیریت
می‌شوند؛ URL هنگام ثبت با SSRF policy و هنگام probe/request دوباره با DNS/IP/redirect policy بررسی
می‌شود. private، loopback، link-local، reserved و multicast پیش‌فرض رد می‌شوند. credential npm فقط
از process environment به Verdaccio می‌رسد و credential PyPI فقط به host اصلی ارسال می‌شود. enforcement
زیرساخت باید با firewall مبتنی بر FQDN یا egress proxy انجام شود؛ IP ثابت CDN قابل اتکا نیست.

## Registry engine E2E

`scripts/e2e_local_engines.py` Verdaccio و devpi واقعی را با storage ایزوله اجرا می‌کند، artifact
واقعی publish/upload می‌کند، هر موتور را restart می‌کند و با cache خالی client دریافت آفلاین را
تأیید می‌کند. catalog نیز باید هر دو ecosystem را کشف کند. اجرای محلی 2026-11-07 برای هر دو موتور
و catalog برابر `ok` بود. همین harness پیش‌نیاز مستقل `engine-e2e` برای job ساخت image در CI است.

## License review

`scripts/check_licenses.py` closure کامل dependencyهای Python image و هر سه lockfile npm را بررسی
می‌کند. overrideهای legacy فقط برای `(canonical-name, exact-version)` هستند تا upgrade بدون review
شکست بخورد. گزارش فعلی ۵۶۲ پکیج و صفر finding دارد.

موارد مهم عملیاتی:

- `psycopg` با `LGPL-3.0-only` و بدون fork/modification توزیع می‌شود؛
- `docutils` شامل اجزای Public Domain، BSD و GPL است و SBOM/license artifact باید همراه release
  نگه‌داری شود؛
- fontهای Inter و Vazirmatn تحت OFL-1.1 هستند؛
- `uvloop 0.23.0` فقط روی Linux وارد closure می‌شود؛ metadata wheel مقدار مبهم دارد و override دقیق نسخه پس از بررسی هر دو فایل رسمی `LICENSE-MIT` و `LICENSE-APACHE` ثبت شده است؛
- Repoze/Pyramid/Supervisor از license مشتق BSD و Zope packages از ZPL-2.1 استفاده می‌کنند.

در image runtime، `setuptools 81.0.0`، `msgpack 1.2.4` و `urllib3 2.8.0` صریح pin شده‌اند؛
سری 81 بالاترین نسخه سازگار با constraintهای devpi 6.21/Pyramid 2.1 است و wheel آن
`jaraco.context 6.1.0` و `wheel 0.46.3` اصلاح‌شده را vendor می‌کند.
`pip`، `wheel` و bundle قدیمی `ensurepip` پس از نصب حذف می‌شوند چون runtime به build tooling نیاز ندارد؛
این کنترل CVEهای قابل‌رفع build شماره 42388001344 را بدون ignore/VEX دورزننده برطرف می‌کند.

خود پروژه طبق فایل `LICENSE` موجود در commit اولیه مالک تحت MIT است. notice و متن کامل MIT باید در
source distribution، image metadata و release artifact حفظ شود؛ licenseهای dependencyها نیز در
گزارش ۵۶۲ پکیجی جداگانه همراه release نگه‌داری می‌شوند.

## Load and soak

`scripts/load_probe.py` یک probe محدود ۱ تا ۳۶۰۰ ثانیه با keep-alive، threshold خطا و p95 است.
اجرای محلی ۳۰ ثانیه‌ای با concurrency=8 نتیجه زیر داشت:

- 36,448 request؛
- 1,214.62 request/s؛
- error rate برابر `0.000027`؛
- p95 برابر `8.211 ms`؛
- نتیجه `passed=true`.

CI هر image را ۲۰ ثانیه load-test می‌کند و workflow هفتگی/دستی `soak.yml` آن را ۱۰ دقیقه با
concurrency=16 اجرا و readiness قبل و بعد را بررسی می‌کند.

شواهد GitHub-hosted در 2026-11-07:

- CI نهایی Run `42392764617`: تمام source gateها، Trivy، clientهای آنلاین، load، restart روی
  network داخلی و دریافت آفلاین npm/PyPI موفق؛
- Soak نهایی Run `42392784697`: مدت `600.003s`، تعداد `4,198,497` درخواست،
  `6,997.47 req/s`، error rate برابر `0`، p95 برابر `4.185ms` و readiness پس از Soak موفق؛
- bootstrap آزمایشی بدون شبکه و با capabilityهای موقت `CHOWN`/`DAC_OVERRIDE` انجام شد؛ container
  اصلی با UID/GID `10001`، `cap_drop: ALL` و `no-new-privileges` اجرا شد.

## Upgrade and rollback rehearsal

`scripts/rehearse_migrations.py` به‌صورت ایزوله schema را از `20261107_0003` به `0001` downgrade و
دوباره به head upgrade کرد و ورود Owner حفظ شد. نتیجه: `data_preserved=true`.

در production rollback image به‌تنهایی کافی نیست:

1. پیش از upgrade یک backup رمزنگاری‌شده validateشده بسازید؛
2. image فعلی و جدید را با digest ثبت کنید؛
3. سرویس را متوقف و snapshot volume را نگه دارید؛
4. image جدید را بالا آورده و migration/readiness/client smoke را اجرا کنید؛
5. در failure، سرویس را متوقف، backup قبل از upgrade را با runbook آفلاین restore و image digest
   قبلی را اجرا کنید؛
6. از اجرای binary قدیمی روی schema جدید بدون downgrade/restore خودداری کنید.

## Go-live checklist

- [ ] معماری و سه route پراکسی 8080/4873/3141 توسط مالک تأیید شده است.
- [ ] هیچ deploy آزمایشی یا production روی Dokploy بدون تأیید صریح انجام نشده است.
- [ ] GitHub repository/GHCR visibility با تصمیم license سازگار است.
- [ ] CI، image build، Trivy، SBOM، provenance، attestation و soak سبز هستند.
- [ ] image فقط با `@sha256:<digest>` انتخاب شده است.
- [ ] `/opt/mirrors/pypi` روی host با مالک `10001:10001` و mode `0700` آماده است.
- [ ] دامنه‌های واقعی CORS، trusted hosts و PyPI outside URL تنظیم شده‌اند.
- [ ] TLS، HSTS و محدودیت دسترسی admin domain روی reverse proxy فعال است.
- [ ] egress FQDN policy و DNS resolver policy در زیرساخت enforce شده‌اند.
- [ ] هیچ متغیر `MRK_PYPI_ROUTER_ALLOW_PRIVATE=true` در production وجود ندارد.
- [ ] First-Time Setup با نام، ایمیل و passphrase منحصربه‌فرد Owner انجام شده است.
- [ ] ثبت‌نام عمومی پس از setup همچنان خاموش است مگر تصمیم صریح Owner.
- [ ] backup رمزنگاری‌شده، custody passphrase و restore drill تأیید شده‌اند.
- [ ] در صورت استفاده از external upstream key، custody و restore جداگانه همان فایل ۳۲‌بایتی تمرین شده است.
- [ ] نصب online و سپس offline برای npm، pnpm، yarn، pip، uv و poetry موفق است.
- [ ] alertها، retention لاگ، disk threshold و incident contact مشخص‌اند.
- [ ] rollback digest و rollback backup پیش از هر upgrade ثبت شده‌اند.

تا سبزشدن تمام موارد، release candidate آماده deploy نهایی محسوب نمی‌شود.
