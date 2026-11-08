# 10 — Execution Plan آینده

Planهای اجرایی Gate 0 تا 10 پس از تکمیل Acceptance Criteria از این سند پاک شدند. وضعیت، تاریخ و
شواهد هر Story در `docs/03-user-stories.md` و شواهد عملیاتی Release در
`docs/19-production-release-gate.md` نگه‌داری می‌شود. این سند فقط کارهای اجرا‌نشده را نگه می‌دارد.

## سیاست پاک‌سازی Plan پس از پیاده‌سازی

پس از تکمیل هر Gate و ثبت شواهد:

1. وضعیت، تاریخ، release/gate و شواهد کوتاه به Storyهای متناظر منتقل می‌شود.
2. checklist، گزارش میانی و plan اجرایی تکمیل‌شده حذف می‌شود.
3. سند طراحی موقت فاقد ارزش عملیاتی حذف می‌شود.
4. Architecture Decision، قرارداد نهایی API/data، Runbook، security control، migration/rollback و release evidence حذف نمی‌شوند.
5. موارد Deferred، ریسک‌های باز و بدهی فنی تا زمان بسته‌شدن باقی می‌مانند.
6. حذف گروهی فقط در یک commit قابل‌بازیابی انجام می‌شود.

تا قبل از تکمیل Gate 14 و تأیید نهایی مالک، Planهای Gate 11 تا 14 و اسناد طراحی ماژول‌ها حذف
نخواهند شد.

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
- image بدون mount باید fail امن باشد؛ production فقط با volume پایدار اجرا می‌شود.
- deploy روی Dokploy فقط پس از تأیید صریح مالک انجام می‌شود.

## Scope Expansion مصوب — 2026-11-07

در این مرحله فقط Product/Architecture/User Story به‌روزرسانی شده و هیچ engine جدیدی نصب، اجرا یا
deploy نشده است.

- معماری تک‌ایمیج با processهای ماژولار و دامنه‌های مستقل تأیید شد.
- Uptime Monitoring با Uptime Kuma به‌عنوان baseline مشروط و adapter/fork حداقلی وارد roadmap شد.
- DNS Management با Technitium به‌عنوان engine مشروط به GPL Legal Gate وارد roadmap شد.
- UI هر دو ماژول متعلق به MRK است؛ هدف capability parity است، نه کپی ظاهری.
- DNS کلاسیک UDP/TCP به دلیل نداشتن Host header با دامنه HTTP route نمی‌شود؛ DoH و پنل DNS دامنه مستقل دارند.
- اسناد تفصیلی: `docs/20-modular-appliance-and-domain-routing.md`، `docs/21-uptime-monitoring-module.md` و `docs/22-dns-management-module.md`.

## بازبینی کد 2026-11-08 — موارد رفع‌شده و باقی‌مانده

نتیجه بازبینی کامل backend، پنل، استقرار و CI. ۸۷ تست Python، Ruff، build پنل و اعتبارسنجی Compose سبزند.
image داکر در این مرحله روی ماشین توسعه build و اجرا نشده است (Docker Engine در دسترس نبود).

### رفع‌شده

- روتر PyPI: spool زیر `/data/tmp`، بررسی فضای آزاد، خطای محلی بدون باز کردن circuit، deadline دانلود،
  failover روی 401/403، رد allowlist بدون جریمه upstream، رد فضای CGNAT، pin کردن IP پس از بررسی.
- سلامت و supervision: Host درست در healthcheck، بررسی دیتابیس و روتر در readiness، توقف کانتینر با FATAL،
  انتظار برای PGlite پیش از migration، `stop_grace_period` برابر 120s.
- npm: guard برای block آخرین upstream، حالت cache-only به‌جای crash، reload خودکار پس از پایان block.
- امنیت: فایل‌های `/opt/mrk` فقط‌خواندنی، CSRF پایدار در هر session، محدودیت هم‌زمانی Argon2، محدودسازی
  حافظه rate limit، محدودیت ثبت‌نام موفق، حذف `audit:read` از viewer، جلوگیری از نشت credential با تغییر host،
  پشتیبانی trusted proxy، validation و حذف argument injection در prefetch.
- prefetch بومی از طریق HTTP (pip و npm CLI در image وجود نداشتند و prefetch در production کار نمی‌کرد).
- revalidate در حالت آفلاین رد می‌شود؛ پیش‌فرض‌های upstream پس از حذف برنمی‌گردند.
- retention برای session و audit؛ worker تسک در برابر خطای دیتابیس مقاوم شد.
- devpi: crash با فایل رمز خارجی، init قابل‌بازیابی پس از crash، انتظار bootstrap قابل‌تنظیم.
- پنل: بازیابی CSRF، logout مطمئن، دسترسی تفکیک‌شده، RTL کامل MUI، حذف داده‌های ساختگی، race در جست‌وجو و
  slider، وضعیت `offline`، پیام‌های خطای دقیق، دسترس‌پذیری و i18n، کارت تنظیم DNS.
- CI: تفکیک permission انتشار، scan پیش از tag، انتشار فقط از tag، pin همه actionها با SHA، Dependabot،
  تست PGlite واقعی، تست Compose توسعه، بررسی hostهای lockfile.
- تنظیم‌پذیری: DNS runtime از پنل، registry/index دلخواه هنگام build (`docs/27`).

### دور دوم بازبینی خط‌به‌خط (2026-11-08) — رفع‌شده

- backup جدید MRKBKP2: رمزنگاری chunked بدون سقف 64GiB، پروفایل config/full، اجرا به‌صورت task، بررسی فضای
  آزاد، retention؛ restore با جابه‌جایی کامل دایرکتوری، journal، rollback دیتابیس و قفل.
- quarantine واقعاً اعمال می‌شود (Verdaccio و روتر PyPI)، سطل بازیافت purge با بازگردانی/انقضا، integrity scan
  با مقایسه hash مرجع و ledger.
- امنیت: توکن API نمی‌تواند توکن جدید بسازد، scope خالی دسترسی نمی‌دهد، Argon2 بدون نگه داشتن اتصال دیتابیس،
  کد `csrf_failed`، audit پیش از عملیات مخرب، گزینه اختیاری upstream خصوصی/LAN.
- resolver DNS در برابر پاسخ ناقص مقاوم شد و cache دارد؛ circuitها بر اساس id.
- استقرار: `.gitattributes`، devpi init و configure قابل‌بازیابی و idempotent، محدودیت منابع، start_period و
  stop budget، خروج غیرصفر هنگام FATAL، VACUUM دوره‌ای، CI و انتشار سخت‌تر.
- پنل: حالت ساده/پیشرفته سراسری و داخل هر بخش، ConfirmDialog، پیام‌های خطای واقعی، تمدید خودکار session.
- اجرای واقعی image: healthy، دانلود npm و PyPI از طریق روتر، خاموشی تمیز.

### باقی‌مانده (بدهی فنی باز)

- [ ] lock کامل وابستگی‌های Python با hash (`--require-hashes`) روی Linux.
- [ ] احراز هویت async/cached (فعلاً Argon2 بیرون از اتصال است ولی lookup session هنوز sync است).
- [ ] Setup اولیه: گزینه اختیاری کد یک‌بارمصرف یا محدودیت شبکه برای ساخت Owner.
- [ ] DNS runtime برای Verdaccio (فعلاً `dns:` در Compose).
- [ ] تست rollback دیتابیس PostgreSQL در restore و تست باز کردن داده PGlite نسخه قبل.
- [ ] ستون‌های زمان 32 بیتی (مشکل 2038) با migration به BigInteger.
- [ ] اجرای workflowهای جدید روی GitHub.
- [x] ماژول‌های کنترل سرور طبق `docs/28` (Gate 16 تا 19).

## Gate 19 و بازطراحی کامل پنل — تکمیل‌شده 2026-11-08

قراردادها: `docs/32` (فایروال، اسکن آسیب‌پذیری، مدیریت دیتابیس)، `docs/33` (طرح بازطراحی)، `docs/34` (APIهای پنل).

- [x] فایروال و ضدحمله: سرویس جدای اختیاری با فقط NET_ADMIN، جدول nftables اختصاصی `inet mrk`، حالت‌های خاموش /
      فقط تماشا / محافظت، محافظ‌های ایمنی (IP خود مدیر، loopback، IPهای سرور، شبکه خصوصی)، تشخیص از لاگ SSH و Traefik
      و ورود پنل. تست واقعی روی کرنل: اعمال و حذف کامل جدول بدون تغییر جدول‌های Docker.
- [x] اسکن آسیب‌پذیری بومی با داده باز OSV.dev (Debian، Ubuntu، Alpine، RPM، npm، PyPI)؛ تست واقعی با feed
      Debian (۷۳ هزار رکورد).
- [x] مدیریت دیتابیس (PostgreSQL، MySQL/MariaDB، MongoDB، Redis)، پیش‌فرض فقط‌خواندنی؛ تست با دیتابیس‌های واقعی.
- [x] بازطراحی پنل: منوی ۷ گروهی، صفحه خانه «فقط آنچه نیاز به توجه دارد»، کتابخانه قطعات مشترک، متن فارسی روان
      (بررسی خودکار در CI؛ صفر متن ماشینی)، حالت ساده/پیشرفته در همه صفحه‌ها، مرکز «همه تنظیمات» با ۲۸۷ تنظیم در
      ۱۶ گروه، کارت نقش‌ها، دعوت همکار در ۳ قدم، نقش سفارشی، تغییر اجباری رمز.
- [x] پایه image به Debian 13 (trixie): آسیب‌پذیری بحرانی ۴→۱، بالا ۲۲→۱۷، متوسط ۵۴→۳۶.
- [ ] باقی‌مانده: تست کاربری با افراد غیرفنی، routing بر اساس کشور در فایروال، journald باینری، RHEL/SUSE در اسکن،
      Edge Gateway (Gate 11)، versioning و lifecycle در S3، restore خودکار بکاپ سرور.

## Gate 18 — سرویس S3 بومی، بکاپ سرور و دیتابیس، پیگیری آپدیت — تکمیل‌شده 2026-11-08

مشخصات: `docs/30-s3-object-storage-spec.md`؛ قرارداد: `docs/31-gate18-contracts.md`.

- [x] موتور S3 بومی (`s3-engine`، پورت 9000): SigV4 کامل (header، presigned، chunked امضاشده/بدون امضا/trailer)
      و checksumهای جدید SDKها؛ List V1/V2، Put/Get/Head/Delete، batch delete، Copy، Range، شرطی‌ها، multipart؛
      باکت مدیریت‌شده و «لینک به پوشه سرور» (ro/rw، ایمن در برابر symlink و traversal)؛ quota و محافظ پرشدن دیسک.
- [x] مدیریت در پنل: باکت‌ها، فایل‌منیجر (آپلود، پوشه، جابه‌جایی، حذف، لینک اشتراک)، کاربر و access key با
      قالب‌های دسترسی و policy سفارشی، دستورهای اتصال (aws cli، rclone، restic، Dokploy).
- [x] بکاپ سرور: volumeها و dump دیتابیس‌ها (PostgreSQL، MySQL/MariaDB، MongoDB، Redis) با argv ثابت در Agent؛
      رمزنگاری MRKBKP2؛ مقصد دیسک، S3 خارجی (با پروکسی) یا S3 بومی؛ cron، retention، دانلود و ابزار رمزگشایی.
- [x] پیگیری آپدیت image با HEAD manifest، mirrorهای قابل تنظیم و پروکسی؛ فقط اعلان، بدون آپدیت خودکار.
- [x] شواهد روی Docker واقعی: boto3 (put/get، multipart 12MB، فهرست، محدودیت دسترسی، لینک اشتراک)، بکاپ
      volume به S3 بومی و رمزگشایی و بررسی محتوای واقعی، بررسی آپدیت، و نمای پنل S3 و فایل‌منیجر.
- [x] رفع‌های کشف‌شده در تست واقعی: reload فوری موتور پس از ساخت کلید، دسترسی Agent به volumeهای root-only
      (پیش‌فرض root با فقط DAC_READ_SEARCH/DAC_OVERRIDE و mountهای فقط‌خواندنی؛ قابل تنظیم با `MRK_AGENT_USER`)،
      گزارش دلیل واقعی خطای Agent، و یک تست ناپایدار.
- [ ] باقی‌مانده: Edge Gateway برای دامنه بدون Traefik (Gate 11)، versioning، lifecycle، CORS، bucket policy،
      وب‌سایت استاتیک، restore خودکار بکاپ، تست مستقیم با Dokploy و rclone واقعی.

## Gate 17 — Dokploy، مانیتورینگ، لاگ و مدیریت Docker + پروکسی خروجی — تکمیل‌شده 2026-11-08

قرارداد مرجع: `docs/29-gate17-contracts.md`.

- [x] اتصال Dokploy از طریق API رسمی (نسخه pin‌شده v0.31.0): پروژه‌ها و سرویس‌ها، deploy/redeploy/start/stop
      با تأیید و audit، تاریخچه و لاگ deploy، rate limit و cache، رویداد شکست deploy؛ داده حساس Dokploy
      (env و رمز دیتابیس) هرگز به پنل نمی‌رسد.
- [x] مانیتورینگ: CPU، حافظه، دیسک، شبکه و load میزبان و هر کانتینر از cgroup v2؛ یک insert در دقیقه،
      rollup ساعتی، retention، هشدار پایدار با بازیابی.
- [x] لاگ کانتینرها: جست‌وجو، stream زنده SSE، حذف secretها، audit مشاهده.
- [x] مدیریت Docker: start/stop/restart، pull image به‌صورت job، پاک‌سازی با پیش‌نمایش و token؛ کانتینرها و
      networkهای Dokploy، swarm و imageهای در حال استفاده هرگز حذف نمی‌شوند؛ volumeها هرگز.
- [x] پروکسی خروجی مرکزی (HTTP/HTTPS/SOCKS5/SOCKS5h) با تیک برای هر سرویس خارجی (upstreamهای npm و PyPI،
      کانال‌های اعلان)؛ پروکسی پیش‌فرض؛ هرگز بازگشت بی‌صدا به اتصال مستقیم.
- [x] سیاست رمز عبور ساده و قابل‌تنظیم (پیش‌فرض ۶ نویسه با حرف و عدد).
- [x] شواهد: ۲۷۱ تست؛ اجرای واقعی روی Docker: لاگ و SSE، restart/stop/start، pull، پیش‌نمایش پاک‌سازی،
      متریک میزبان و کانتینرها، تست پروکسی، و نمای پنل.
- [ ] باقی‌مانده: rollback و env در Dokploy، لاگ چندکانتینری، فهرست volume و network، تست با یک Dokploy واقعی.

## Gate 16 — Host Agent و مرکز اعلان‌ها — تکمیل‌شده 2026-11-08

- [x] قرارداد ماژول (`module_context.py`، `modules/`) و گذرگاه رویداد؛ رویداد خطای task و نتیجه backup.
- [x] Host Agent فقط‌خواندنی: امضای HMAC با ضد replay، allowlist سخت Docker API (فقط GET)، متریک میزبان،
      علامت‌گذاری کانتینرهای Dokploy به‌عنوان محافظت‌شده، کلید جفت‌سازی، profile اختیاری `agent` در Compose
      روی شبکه داخلی بدون پورت عمومی.
- [x] مرکز اعلان‌ها: Telegram، بله، Email، Webhook امضاشده؛ قواعد، dedupe، ساعات سکوت، retry/backoff،
      ادامه پس از restart، retention؛ ارسال از طریق DNS و SSRF policy کاربر؛ secretها رمزنگاری‌شده.
- [x] صفحه‌های «سرور» و «اعلان‌ها» با حالت ساده/پیشرفته.
- [x] شواهد: ۱۸۷ تست، migration روی PGlite (upgrade/downgrade بدون از دست رفتن داده)، اجرای واقعی image با
      profile agent روی Docker: جفت‌سازی، خواندن ۱۴ کانتینر، نسخه Docker، متریک میزبان و تست اتصال ۶۶ms.
- [ ] باقی‌مانده: تکرار اعلان تا acknowledge، routing بر اساس برچسب، mTLS بین Control Plane و Agent.

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

1. Gate 11 قبل از هر engine جدید اجرا می‌شود تا moduleها از ابتدا روی قرارداد مشترک سوار شوند.
2. Gate 12 و Gate 13 پس از ثبات contract می‌توانند مستقل توسعه یابند.
3. Gate 14 فقط پس از Legal Gate Technitium و parity/security sign-off شروع می‌شود.
4. deploy روی Dokploy فقط با تأیید صریح مالک و پس از معماری/تصویر نهایی انجام می‌شود.
