# 21 — طراحی ماژول Uptime Monitoring

> **به‌روزرسانی 2026-11-08:** طبق `docs/23` موتور خارجی اجرا نمی‌شود و این قابلیت‌ها به‌صورت موتور بومی MRK ساخته می‌شوند. بخش «تصمیم پایه» این سند منسوخ است؛ دامنه قابلیت‌ها همچنان معتبر است.

وضعیت: **Product/Architecture specification؛ پیاده‌سازی نشده**  
هدف: هم‌ارزی قابلیت‌های عملیاتی Uptime Kuma با تجربه کاربری یکپارچه MRK، بدون کپی UI/branding

## 1. تصمیم پایه

کاندیدای پایه `louislam/uptime-kuma` است:

- بیش از 93k star و 8.7k fork در snapshot تاریخ 2026-11-07؛
- توسعه و release فعال در خط 2.5.x؛
- مجوز MIT؛
- monitor typeهای گسترده، notification providerهای متعدد و status page چندگانه؛
- API مدیریتی عمدتاً داخلی/Socket.IO و رسماً ناپایدار برای integration شخص ثالث.

نتیجه: release پایدار و commit دقیق پس از security review clone/pin می‌شود. engine پشت `UptimeAdapter` قرار می‌گیرد و contract test از MRK در برابر همان نسخه اجرا می‌شود. UI و auth متعلق به MRK است. از DB داخلی engine مستقیماً خوانده یا نوشته نمی‌شود. اگر API لازم وجود نداشت، patch کوچک upstreamable با test و ADR ساخته می‌شود؛ fork نامحدود ممنوع است.

منابع بررسی:

- <https://github.com/louislam/uptime-kuma>
- <https://github.com/louislam/uptime-kuma/releases>
- <https://github.com/louislam/uptime-kuma/blob/master/LICENSE>
- <https://github.com/louislam/uptime-kuma/wiki/Internal-API>
- <https://github.com/louislam/uptime-kuma/wiki/Status-Page>

## 2. دامنه قابلیت

### Monitorها

- HTTP/HTTPS با method، headers، body، auth، proxy، redirect، status range و TLS؛
- keyword، inverse keyword و JSON query/assertion؛
- TCP port با TLS/STARTTLS در صورت پشتیبانی engine؛
- ping/ICMP، DNS، push، NTP و certificate expiry؛
- gRPC، WebSocket، SNMP، RADIUS و database/broker monitorها طبق capability نسخه pin‌شده؛
- Docker/container monitor فقط از socket-proxy محدود یا agent، نه mount مستقیم Docker socket؛
- interval، timeout، retries، retry interval، resend interval و max redirects؛
- tag، group، parent dependency، weight و display order؛
- pause/resume/clone/import/export و bulk action.

### نتیجه و history

- heartbeat با status، latency، message، checked_at و attempt؛
- uptime در بازه‌های 24h/7d/30d/90d و custom range؛
- p50/p95/p99 latency و error budget؛
- TLS expiry، DNS answer و response detail با redaction؛
- retention و downsampling قابل تنظیم؛
- timeline incident/maintenance/notification در یک view؛
- timezone و تقویم فارسی/میلادی فقط در presentation، timestamp دیتابیس UTC.

### اعلان‌ها

- کانال‌های email، webhook، Slack/Teams/Discord/Telegram و providerهای نسخه پایه؛
- test قبل از save؛
- routing بر اساس tag/group/severity؛
- retry/backoff، deduplication، quiet hours و escalation؛
- notification on down/up/certificate/maintenance؛
- secretها write-only، encrypted و قابل rotate؛
- delivery log بدون payload حساس.

### Incident و Maintenance

- incident draft/publish/update/resolve؛
- severity و affected components؛
- maintenance یک‌باره و تکرارشونده؛
- timezone/DST-safe scheduling؛
- suppress notification بدون جعل uptime؛
- audit و public timeline.

### Status Page

- چند status page با slug و دامنه اختصاصی؛
- group/component و ترتیب مستقل؛
- theme، logo، title، description و custom CSS فقط با sanitization/CSP؛
- public/private/unlisted؛
- incident و maintenance؛
- uptime/latency، certificate badge، overall badge و RSS/Atom؛
- custom domain mapping و canonical URL؛
- cache کنترل‌شده و invalidation پس از publish؛
- صفحه عمومی بدون code split مدیریتی و بدون endpoint خصوصی.

## 3. تجربه کاربری

### Simple Mode

wizard کوتاه:

1. نام و URL/host؛
2. نوع check پیشنهادی؛
3. interval و timeout با preset امن؛
4. notification channel؛
5. test؛
6. save و پیشنهاد افزودن به status page.

فیلدهای TLS، proxy، assertion، retry و headers تا زمان درخواست کاربر پنهان‌اند، اما خلاصه policy نهایی قبل از save نمایش داده می‌شود.

### Advanced Mode

تمام capabilityهای engine، raw request preview، dependency، retry policy، assertion، certificate، proxy، notification routing، retention و debug probe را نشان می‌دهد. تغییر mode داده را حذف نمی‌کند و تنظیمات advanced در Simple Mode به‌صورت badge «تنظیم پیشرفته فعال» دیده می‌شود.

## 4. دامنه و route

- `panel.domain.com/uptime/*`: مدیریت authenticated؛
- `status.domain.com`: یک status page مشخص؛
- چند دامنه می‌توانند به pageهای متفاوت map شوند؛
- domain conflict با پنل/npm/PyPI/DoH رد می‌شود؛
- Host spoofing و forwarded host فقط با trusted proxy پذیرفته می‌شود؛
- preview عمومی پیش از publish روی URL امضاشده و کوتاه‌عمر است.

## 5. امنیت

- SSRF policy جدا برای monitorها: deny private/link-local/metadata به‌صورت پیش‌فرض؛
- دسترسی به شبکه داخلی فقط با allowlist و permission سطح Owner؛
- DNS rebinding protection در resolve و connect؛
- redirect مقصد جدید را دوباره validate می‌کند؛
- headerهای `Authorization`، cookie، token و body در log redact می‌شوند؛
- response body فقط با سقف حجم و retention کوتاه برای debug ذخیره می‌شود؛
- script monitor یا arbitrary shell در فاز اول ممنوع است؛
- browser monitor در sandbox process با resource/time limit اجرا می‌شود؛
- public page دارای CSP، anti-index option و rate limit است؛
- push token قابل rotate و در UI فقط یک بار نمایش داده می‌شود.

## 6. lifecycle و failure isolation

- scheduler و worker health جدا گزارش می‌شوند؛
- queue lag، active checks، timed-out checks و event-loop lag metric دارند؛
- restart کنترل‌شده checkهای in-flight را drain یا expired می‌کند؛
- failed check پس از restart دوباره‌کاری اعلان ایجاد نمی‌کند؛
- supervisor crash-loop را متوقف و آخرین خطای redactشده را نمایش می‌دهد؛
- خرابی engine نباید public status snapshot آخر یا moduleهای دیگر را قطع کند؛ stale marker واضح است.

## 7. داده، backup و migration

- engine-native DB منبع حقیقت monitor/heartbeat تا زمان ADR بعدی است؛
- Control Plane فقط identity mapping، route، permission، audit و projection لازم را نگه می‌دارد؛
- backup باید نسخه engine، schema، status-page assets، notification metadata و secret envelope را ثبت کند؛
- restore روی فضای ایزوله contract-check می‌شود؛
- retention heartbeat قابل dry-run و estimate است؛
- export بدون secret برای migration/support ارائه می‌شود.

## 8. معیار parity

«شبیه Uptime Kuma» به معنی capability parity قابل آزمون است، نه pixel-copy. ماتریس parity برای هر release pin‌شده شامل monitor typeها، notification providerها، status page، maintenance، incident، badge، metrics، import/export و security behavior ساخته می‌شود.

هر capability یکی از وضعیت‌های زیر دارد:

- `native`: از engine بدون patch؛
- `adapted`: از API رسمی/داخلی پشت adapter؛
- `mrk`: توسط Control Plane/UI؛
- `deferred`: با دلیل، ریسک و milestone؛
- `not-applicable`: ناسازگار با security/product policy.

عبارت «تمام امکانات» فقط پس از صفر شدن gapهای P0/P1 این ماتریس پذیرفته می‌شود.

## 9. Gateهای تحویل

### U1 — Engine Baseline

- pin نسخه/commit، SBOM، license و security review؛
- adapter contract و isolated data root؛
- health و graceful shutdown.

### U2 — Monitor Core

- CRUD/test/pause/resume؛
- HTTP/TCP/Ping/DNS/Push/TLS؛
- heartbeat timeline و metrics.

### U3 — Notifications و Incident

- secret-safe channel management؛
- dedupe/retry/escalation؛
- incident و maintenance.

### U4 — Public Status

- چند page، domain mapping، badge/RSS؛
- public/private policy؛
- accessibility و RTL/LTR.

### U5 — Parity و Production

- ماتریس parity P0/P1 کامل؛
- load/soak و false-positive test؛
- backup/restore/upgrade rehearsal؛
- failure isolation و security test.

## 10. موارد باز

- تعیین نسخه pin فقط پس از بررسی آخرین advisory و test همان tag؛
- تصمیم fork کوچک یا plugin/adapter خالص؛
- انتخاب providerهای اعلان P0 با توجه به بازار هدف؛
- ظرفیت هدف monitorها برای Appliance تک‌نودی؛
- سیاست agent برای monitor شبکه خصوصی و server metrics.

