# 40 — قرارداد فاز D4 موتور DNS: حل از ریشه، DNSSEC و DNS رمزدار

وضعیت: **قرارداد مرجع D4 — 2026-11-09**. برنامه کلی: `docs/36` (جدول فازها، D4). پایه: `docs/37` و `docs/38` (همراه
§0هایشان که معتبرند). هر سازنده اگر شکلی را تغییر داد در §0 همین سند ثبت کند (زیربخش خودش).

## 0. تغییرات نسبت به قرارداد اولیه

(خالی — هر سازنده زیربخش خودش: 0.1 موتور حل/DNSSEC، 0.2 موتور رمزدار، 0.3 بک‌اند، 0.4 پنل)

### 0.1 موتور حل از ریشه و DNSSEC (بخش A موتور)

- **`indeterminate`:** فقط وقتی DNSKEY ریشه با امضا از همان مسیر به‌دست نمی‌آید (forwarder ای که DNSSEC را حذف
  می‌کند یا ریشه در دسترس نیست). چنین پاسخی مثل `insecure` تحویل می‌شود (بدون AD، بدون SERVFAIL) و در شمارنده‌ها و
  `resolve.dnssec.status` دیده می‌شود. زیر ریشه، شکست گرفتن DS/DNSKEY (شبکه) ← `bogus` با EDE 22 (۵ ثانیه کش).
- **EDE 1 و 2** (الگوریتم/digest ناشناخته) روی پاسخ NOERROR ناامن به‌صورت اطلاعاتی می‌آیند، نه SERVFAIL (هم‌خوان با
  «→ insecure»). متن EDE: `<reason> <detail>` (مثلاً `ds_mismatch example.com: no DNSKEY matches the DS`).
- **`resolve.dnssec`:** `status` همیشه یکی از چهار مقدار است؛ اعتبارسنجی خاموش ← `insecure` + `reason:"validation_off"`؛
  داده محلی/override/authoritative ← `insecure` + `local_zone`؛ خطای بدون اعتبارسنجی (مثلاً SERVFAIL بالادست) ←
  `indeterminate` + rcode کوچک. کدهای `reason`: `negative_trust_anchor, local_zone, unsigned_zone, rrsigs_missing,
  signature_expired, signature_not_yet_valid, signature_invalid, dnskey_missing, ds_mismatch, denial_proof_failed,
  unsupported_algorithm, unsupported_digest, nsec3_iterations, nsec3_opt_out, no_reachable_authority,
  trust_anchor_unavailable, signer_mismatch, validation_budget`. ورودی تازه `dnssec` (پیش‌فرض true) DO را تعیین می‌کند؛
  با false رکوردهای RRSIG/NSEC از خروجی حذف می‌شوند. فیلد ناشناخته در بدنه همچنان 422 است.
- **`trace`:** گام‌های اعتبارسنج هم می‌آیند (`server:"validator"`, `qtype: DS|DNSKEY`, `dnssec`، دلیل در `error`)؛ در
  حالت forward هر پرسش یک گام با `zone:"."`, `server` = نشانی forwarder و `server_name` = شناسه آن. trace کش پاسخ،
  کش delegation و کش کلیدهای اعتبارسنج را دور می‌زند.
- **trust anchor:** `since` برای دو کلید داخلی = `validFrom` در root-anchors.xml (2017-02-02 و 2024-07-18)؛ برای بقیه زمان
  تغییر وضعیت. `trust-anchors.json` (0600): `{v:1, updated_at, anchors:[{key_tag, algorithm, digest_type?, digest?,
  public_key?, state, since, first_seen?, last_seen?, builtin?}]}`. به‌روزرسانی خودکار: یک دقیقه پس از شروع، هر 12 ساعت،
  پس از شکست هر 1 ساعت (فقط با `mode != off` و `trust_anchor_auto_update`). رویداد `dnssec.trust_anchor_updated` با
  `{anchors:[…]}` فقط وقتی چیزی عوض شد؛ `dnssec.trust_anchor_failed` با `{error}`. `POST /v1/dnssec/refresh` همیشه 200
  با همان نمای `GET /v1/dnssec`؛ شکست در فیلد `error`.
- **priming:** در شروع (حالت recursive یا forward_then_recursive)، هنگام تغییر به این حالت‌ها، هر 24 ساعت، و پس از شکست
  هر 5 دقیقه. `servers_reachable` = تعداد نام‌های ریشه (یک نشانی هر کدام، طبق `ip_versions`) که به `. SOA` پاسخ دادند؛
  `root_priming.at` پیش از اولین priming برابر `null`. `resolution.priming_failed` با `{error}` یک بار در هر دوره شکست.
- **root_hints پیکربندی‌شده** مورد اعتمادند و `allow_private_ns` روی آن‌ها اعمال نمی‌شود (فقط `ip_versions`)، تا ریشه
  خصوصی/آزمایشگاهی کار کند.
- **اعتبارسنجی تنظیمات (reason_code تازه):** `resolve_timeout_ms < query_timeout_ms` ← `less_than_query_timeout`؛ root hint
  بدون نشانی ← `address_required`؛ نام تکراری ← `duplicate`؛ `reason` بیش از 256 ← `too_long`. نرمال‌سازی: نام root hint
  کوچک و FQDN؛ دامنه NTA کوچک بدون نقطه پایانی؛ `expires_at` به UTC RFC3339.
- **مسیر حل:** `query_timeout_ms` سقف هر تلاش forwarderها هم هست. در `forward_then_recursive` مرحله forward حداکثر نیمی از
  `resolve_timeout_ms` را مصرف می‌کند. با اعتبارسنجی، به forwarder با DO=1 و CD=1 پرسیده می‌شود. QNAME minimization با
  qtype A برای نام‌های میانی، حداکثر 10 گام؛ relaxed: NXDOMAIN میانی ← پرسش با نام کامل؛ strict: NXDOMAIN نهایی. 0x20: اگر
  فقط حروف نام فرق کند سرور «بدون 0x20» علامت می‌خورد و یک بار بی 0x20 تکرار می‌شود. EDNS: FORMERR/NOTIMP/BADVERS ←
  تکرار بی EDNS؛ سروری که هرگز پاسخ نداده پس از 2 timeout بی EDNS امتحان می‌شود؛ موفقیت بی EDNS در infra cache یادآوری
  می‌شود.
- **کش:** delegationها با نوع کلید خصوصی `0xFF01` و نشانی NSها با `0xFF02/0xFF03` در همان cache (flush آن‌ها را هم پاک
  می‌کند). TTL پاسخ امضاشده از انقضای RRSIG بیشتر نمی‌شود. bogus با `bogus_ttl` (0 = کش نمی‌شود) و هرگز stale. با CD=1
  پاسخ برای کش اعتبارسنجی می‌شود ولی داده خام بدون AD برمی‌گردد. کلاینت DO=0 رکوردهای RRSIG/NSEC/NSEC3 را نمی‌گیرد (مگر
  همان qtype را پرسیده باشد). تغییر `dnssec.mode`، `resolution.mode`، `auto_insecure_local`، `nsec3_max_iterations`،
  `sig_skew_seconds` یا فهرست NTA کل کش را پاک می‌کند.
- **aggressive_nsec:** فقط NSEC (نه NSEC3) و فقط ساخت NXDOMAIN؛ در لاگ `source:"cache"`.
- **شمارنده‌های `counters`:** هر اعتبارسنجی (نه هر پاسخ از کش) یک بار شمرده می‌شود.
- **لاگ:** نسخه index سگمنت 2 شد (تعداد sourceها را ذخیره می‌کند)؛ سگمنت‌های نسخه 1 همچنان خوانده می‌شوند؛ قالب ردیف‌ها
  تغییر نکرد. `indeterminate` با پرچم `FlagInsecure` ثبت می‌شود. فیلتر `proto=` برای همه پروتکل‌ها (`udp|tcp|dot|doh|doq`)
  اضافه شد و `ProtoDoQ=4` تعریف شد (برای موتور رمزدار).
- **آمار:** هر نقطه و totals فیلد `dnssec:{secure, insecure, bogus}`؛ در فایل آمار، bucket فیلد `sec` گرفت (فایل قدیمی سازگار).
- **Prometheus:** `mrk_dns_dnssec_validations_total{result}`, `mrk_dns_infra_cache_entries`, `mrk_dns_root_priming_ok`.
- **بیرون از بخش A (برای بخش B):** رویداد `listener.failed`، آمار بر حسب proto، توکن DoH در لاگ، `quic://`.

### 0.2 موتور رمزدار (بخش B موتور)

- **`encrypted.allow`:** اگر null نباشد برای ورودی‌های رمزدار **جای هر دو** `query_allow` و `recursion.allow` را می‌گیرد
  (وگرنه IP عمومی مجاز در allow به‌خاطر query_allow پیش‌فرض خصوصی رد می‌شد). DNS ساده تغییری نمی‌کند. توکن DoH هر سه را
  دور می‌زند ولی `recursion.enabled`، mitigation و فشار همچنان اعمال می‌شوند؛ به‌جای محدودیت کلاینت، `qps` توکن (burst =
  2 ثانیه) و بیش از آن REFUSED با `source:"rate_limited"`. توکن نامعتبر/حذف‌شده ← 404 (مثل مسیر ناشناخته).
- **اعتبارسنجی:** `listen_conflict` فقط برای پروتکل‌های فعال و روی همان transport (tcp: DoT/DoH/listen tcp ساده؛ udp:
  DoQ/listen udp ساده) و همان پورت با نشانی برابر یا یکی wildcard. `plain_doh_public` فقط وقتی `doh.enabled && !doh.tls`
  و نشانی wildcard یا غیرخصوصی است. reason_codeهای تازه: `invalid_path` (path باید `/seg[/seg…]` با نویسه‌های URL-safe ≤128
  باشد)، `invalid_network` برای trusted_proxies، `required` برای listen خالی پروتکل فعال؛ حداکثر 16 listen و 64 proxy.
- **`certificate_required`:** کد خطای مستقل (422) با `fields:[{field:"encrypted.dot.enabled"|"encrypted.doq.enabled"|
  "encrypted.doh.enabled", reason_code:"certificate_required"}]`؛ فقط وقتی گواهی نیست، یا هنگام **روشن‌کردن** با گواهی منقضی
  (تنظیم دیگری را با گواهی منقضی رد نمی‌کند). اگر تنظیم ذخیره‌شده listener رمزدار دارد و گواهی نیست، listener با
  خطای `no TLS certificate` ناسالم می‌ماند و هر 10 ثانیه دوباره امتحان می‌شود (پس از بارگذاری گواهی خودکار بالا می‌آید).
- **`tls_invalid`:** `fields:[{field:"cert_pem"|"key_pem", reason_code}]`. گواهی منقضی ذخیره‌شده در شروع بارگذاری می‌شود
  (رویداد expired). فایل‌ها: `tls/cert.pem`, `tls/key.pem`, `tls/meta.json` (همه 0600، پوشه 0700). کلید: PKCS#8/EC/PKCS#1.
  `names` خودامضا: hostname (با `*.` مجاز) یا IP، ≤32، کوچک و یکتا؛ CN = نام اول. `self_signed` در نما = منبع self_signed یا
  issuer==subject. خطای نام‌های خودامضا هم `tls_invalid` با `names[i]`.
- **رویدادها:** `tls.certificate_expiring` با `{days_left, not_after, fingerprint_sha256}` وقتی days_left (کف روز) از 14/7/3/1
  کمتر شد، هر آستانه یک بار برای هر گواهی؛ `tls.certificate_expired` با `{not_after, fingerprint_sha256}` یک بار. بررسی 5
  ثانیه پس از شروع و هر ساعت (همان‌جا تمدید خودکار خودامضا). `listener.failed` برای همه protoها (udp/tcp هم) و فقط وقتی
  متن خطا عوض شد.
- **توکن‌ها:** فایل `doh-tokens.json` (0600) با `sha256` هگز؛ `id` 12 نویسه base64url؛ خطای ورودی `token_invalid` 422؛
  `queries`/`last_used_at` در حافظه و هر دقیقه (اگر تغییر کرد) و هنگام بستن ذخیره می‌شوند. شمارش شامل پرسش‌های رد‌شده با qps.
- **status:** `encrypted.certificate.days_left` کف روز و حداقل 0. `connections` اتصال‌های باز هر پروتکل.
- **آمار:** هر نقطه و totals فیلد `by_proto:{udp, tcp, dot, doh, doq}`؛ در فایل آمار bucket فیلد `pr`. Prometheus:
  `mrk_dns_encrypted_connections{proto}`، `mrk_dns_tls_certificate_expiry_seconds`؛ `mrk_dns_queries_total{proto="tcp"}`
  پرسش‌های رمزدار را هم می‌شمارد (برچسب تازه اضافه نشد).
- **لاگ:** نمای رکورد `token` (فقط وقتی هست) و `upstream` خالی؛ CSV ستون تازه ندارد (upstream خالی).
- **انتقال‌ها:** DoT: ALPN `dot` (کلاینت بدون ALPN هم پذیرفته)، هم‌زمانی هر اتصال = `max_streams_per_connection`،
  keepalive پاسخ = idle_timeout/100ms فقط اگر پرسش گزینه را داشت. DoH: HTTP/2 با TLS، و در حالت ساده HTTP/1.1 + h2c؛ GET
  غیرفعال ← 405، Content-Type نادرست ← 415، بدنه بزرگ ← 413، پیام خراب ← 400، صف پر ← 503؛ `max-age` = کمترین TTL (SOA با
  minimum) و 0 بدون رکورد. IP کلاینت پشت proxy: از راست `X-Forwarded-For` (یا `Forwarded: for=`) اولین نشانی غیر trusted؛
  اگر همه trusted، چپ‌ترین. اتصال از trusted proxy فقط سقف کل را دارد (نه سقف هر کلاینت). DoQ: TLS 1.3، بدون 0-RTT، بدون
  stream یک‌طرفه، شناسه غیر صفر ← بستن اتصال با `DOQ_PROTOCOL_ERROR`، سقف اتصال ← `DOQ_EXCESSIVE_LOAD`. تغییر
  idle/handshake/streams (و `doh.tls`) listenerهای DoH/DoQ را دوباره راه می‌اندازد؛ DoT و بقیه پارامترها زنده خوانده می‌شوند.
- **`quic://`:** `quic://IP[:853][#server-name]` (مثل `tls://`)؛ یک اتصال QUIC برای هر upstream با یک بار تلاش دوباره روی
  اتصال تازه. کتابخانه `github.com/quic-go/quic-go v0.64.1` (در `versions.lock.yaml`). Dockerfile/compose تغییری نخواست
  (host networking)؛ توجه: پیش‌فرض DoH `0.0.0.0:443` روی میزبانی که Traefik دارد `listener.failed` می‌دهد — حالت پشت Traefik
  را با `127.0.0.1:8053` به‌کار ببرید.

### 0.4 پنل

- **تب «تنظیمات» دیگر فقط-پیشرفته نیست** (همچنان `dns:admin`): در حالت ساده فقط کارت‌های «روش پیدا کردن نشانی‌ها» و
  «امضای امنیتی» (+ یک جمله «بقیه در پیشرفته»)؛ تا قاعده خانه `dns_trust_anchor_problem` (`#/dns/settings`) در حالت ساده هم
  به جایی برسد. هر دو کارت روی همان پیش‌نویس و همان یک ذخیره کل سند تنظیمات‌اند (رقابت `config_version` نمی‌سازند). پارامترهای
  پیشرفته در «تنظیمات پیشرفته» جمع‌شونده (در حالت پیشرفته باز). خاموش‌کردن DNSSEC تأیید می‌خواهد. اگر موتور بخش
  `resolution`/`dnssec` را نفرستد، کارت‌ها جای خود را به پیام «به‌روز کنید» می‌دهند و پیش‌فرض‌ها فرستاده نمی‌شوند.
- **`warnings`:** از بالای پاسخ PUT خوانده می‌شود (`{settings, warnings}` یا خود سند با کلید `warnings`؛ عنصر رشته یا
  `{code}`)؛ کلید `warnings` پیش از ذخیره بعدی از سند حذف می‌شود.
- **تب تازه `encrypted`** (`dns:read`؛ ساخت/تغییر `dns:admin`) با نام‌های مستعار `#/dns/doh|dot|doq|tls|certificate`؛
  `#/dns/dnssec|resolution` ← تنظیمات و `#/dns/trace` ← تست. کلیدهای DoT/DoH/DoQ بخش `encrypted` را با همان
  `DnsSectionSettings` ذخیره می‌کنند؛ «پشت Traefik» یعنی `doh.tls=false` و listen پیش‌فرض `127.0.0.1:8053`,`172.17.0.1:8053`
  (listen فقط وقتی هنوز پیش‌فرض حالت دیگر است جابه‌جا می‌شود). «از دامنه با Traefik» به `#/services` می‌برد.
- **خطاها:** کدهای تازه هم بی‌پیشوند و هم با `dns_` در کاتالوگ‌اند (`certificate_required`, `certificate_in_use`, `tls_invalid`,
  `token_not_found`, `token_invalid`, `dns_settings_invalid`, …). دلیل `tls_invalid` از `fields[0].reason_code` (یا
  `error.reason_code`) خوانده و جمله ساده نشان داده می‌شود.
- **توکن:** QR از نشانی `urls.doh` (اگر نبود فقط کلید نمایش داده می‌شود)؛ کتابخانه **`qrcode-generator@1.4.4`** (MIT، بدون
  وابستگی، سنجاق‌شده) و رسم به‌صورت SVG در `kit/QrCode.tsx`. پروفایل اپل با نام `mrk-dns.mobileconfig` و
  `name:"MRK DNS"` دریافت می‌شود.
- **تست:** «مسیر کامل» فقط با `dns:write` فعال است؛ در پیشرفته گزینه‌های `dnssec` (DO)، `cd` و `no_cache` هم هست. سطح هر گام
  از `zone` حساب می‌شود (`.` = ریشه، یک برچسب = پسوند، بیشتر = دامنه، `server:"validator"` = بررسی امضا).
- **لاگ/پایش:** chip ساده «امضای خراب» (`dnssec=bogus`)، فیلتر پیشرفته DNSSEC و proto، ستون DNSSEC، ستون upstream برای
  ردیف توکن‌دار «با کلید …»؛ نمودار امن/ناامن/خراب فقط وقتی نقطه‌ها `dnssec` دارند.
- **forwarder خروجی `quic://`** به فهرست نوع اتصال «افزودن DNS بیرونی» اضافه شد (اعتبارسنجی بک‌اند باید آن را بپذیرد).
- **فهرست مجاز check:copy:** نام‌های محصول Android, iPhone, iPad, Mac, Windows, Firefox, Chrome, Edge, Wi-Fi, Ethernet, VPN,
  QR, RSA به brands و DNSSEC, DoT, DoH, DoQ به parenthetical اضافه شدند.
- قاعده خانه `dns_certificate_expiring` از `params.days_left` (اگر بود) جمله می‌سازد.

### 0.3 بک‌اند

کد: `modules/dns_validate_d4.py` (اعتبارسنجی بخش‌های تازه، هشدارها، ورودی tls/توکن/پروفایل)، `modules/dns_encrypted.py`
(routeهای dnssec/tls/doh/encrypted)، و تغییر در `dns.py`، `dns_validate.py`، `dns_client.py`، `dns_monitor.py`، `home.py`،
`services*.py`، `domains_routing.py`، `domains_verify.py`، `agent/traefik.py`. تست: `tests/test_dns_d4.py`. متغیر محیطی تازه نیست.

- **فیلدهای خطا** مثل D1/D2 با اندیس نقطه‌ای‌اند (`resolution.root_hints.0.name`، `encrypted.doh.listen.1`)، نه کروشه‌ای موتور.
  کدهای پنل: `listen_conflict` (تداخل با `listen` اصلی یا بین DoT/DoH روی tcp و DoQ روی udp؛ نشانی 0.0.0.0/:: با هر نشانی
  همان خانواده و پورت تداخل دارد)، `plain_doh_public` (با `doh.tls:false` هر listen باید loopback/خصوصی/link-local باشد)،
  `open_resolver` برای `/0` در `encrypted.allow`، `too_broad` برای `/0` در `doh.trusted_proxies`، `doh.path` باید با `/`
  شروع شود (`invalid_format`). `certificate_required` را موتور می‌دهد (پنل از پیش نمی‌سنجد).
- **`warnings`** هم در پاسخ PUT و هم در **GET settings** می‌آید (تا پنل هنگام باز کردن صفحه هم نشان دهد) و اگر پنل آن را دوباره
  در PUT فرستاد، پیش از ارسال به موتور حذف می‌شود. `doh_public_needs_token` = DoH روشن و «عمومی» (TLS روی نشانی
  غیرخصوصی/0.0.0.0 یا DoH ساده با دامنه `dns-doh`) + صفر توکن + allow مؤثر (`encrypted.allow` یا `recursion.allow`) فقط خصوصی.
  `self_signed_certificate` فقط وقتی یک listener با TLS روشن است. اگر خواندن توکن/گواهی از موتور شکست بخورد آن هشدار رد می‌شود.
- **خطاهای موتور:** `certificate_required|certificate_in_use` → 409، `tls_invalid|token_invalid|listen_conflict|plain_doh_public`
  → 422، `token_not_found` → 404 (همه با پیشوند `dns_`). اگر موتور `reason_code` را روی خود error بدهد (مثل `tls_invalid`)،
  پنل آن را در `error.reason_code` و `fields:[{field:"body", reason_code}]` می‌گذارد. خطاهای پنل: `dns_tls_invalid`
  (`required|bad_pem|too_large`)، `dns_token_invalid`، `dns_profile_invalid`، `dns_doh_plain_disabled` 409 (دامنه برای `dns-doh`
  وقتی DoH ساده خاموش است).
- **resolve:** فقط کلیدهای `dnssec|cd|trace|no_cache` (bool) اضافه می‌شوند؛ timeout پنل 35 ثانیه. `trace:true` بدون `dns:write` → 403.
- **tls:** پاسخ‌های tls همیشه بدون `key_pem/private_key/key`؛ `DELETE tls` → `{deleted:true}`. audit: `dns.tls.upload`
  (object_id = fingerprint)، `dns.tls.self_signed` (نام‌ها)، `dns.tls.delete`. نام‌های self-signed: hostname (`*.` مجاز) یا IP، ≤20.
- **توکن:** نام trim می‌شود (1..64، بدون نویسه کنترلی)؛ `urls.doh` = `doh_url` همان `encrypted/clients` + `/<token>` (یا null).
  `DELETE` → `{deleted:id}`. audit `dns.doh_token.create|update|delete` با id (توکن هرگز).
- **`encrypted/clients`:** اضافه بر قرارداد: `certificate:{trusted, present, self_signed, source, not_after}`، `enabled:{dot,doh,doq}`،
  `plain_doh`. `doh_url`: DoH ساده ← اولین دامنه https سرویس `dns-doh` (primary اول)؛ DoH با TLS ← نام DNS گواهی (اولین نام
  غیر wildcard) یا اولین IP عمومی (`domains.server_public_ips`) یا نشانی listen؛ پورت 443 حذف می‌شود؛ listen فقط loopback ← null.
  `dot_name/doq_name` = نام گواهی وقتی همان پروتکل روشن است. `trusted` = گواهی موجود، نه self-signed، منقضی نشده (یا DoH ساده
  با دامنه Traefik). reasonهای راهنما: `encrypted_disabled, dot_disabled, doh_disabled, no_hostname, no_doh_url, no_ip,
  certificate_untrusted`.
- **apple-profile:** بدنه خالی ← از `encrypted/clients` (اول DoH، وگرنه DoT)؛ اگر هر دو داده شوند DoH. `doh_url` فقط https،
  بدون userinfo/query/fragment؛ `dot_name` باید hostname باشد (`hostname_required` برای IP). خروجی plist XML بدون امضا
  (`application/x-apple-aspen-config`، `mrk-dns.mobileconfig`)؛ CSRF لازم است؛ audit ندارد (فقط خواندنی).
- **اعلان‌ها:** dedupe همان نام نوع (برای expiring: `dns.tls_certificate_expiring.<days_left>`) + 5 دقیقه حافظه‌ای.
  `bogus_spike` details `{count, names≤10, route}`. `trust_anchor_updated` و `listener.failed` اعلان ندارند.
- **خانه:** از status کش‌شده. `dns_certificate_expiring` وقتی listener با proto `dot|doq|doh` (و `tls` نه false) هست، گواهی
  present و `days_left ≤ 14` (≤ 3 → error، وگرنه warning)؛ params `{days_left, not_after, self_signed}`.
  `dns_trust_anchor_problem` وقتی `dnssec.mode != off` و (هیچ anchor با `state:"valid"` نیست یا `trust_anchor_error` هست)؛
  params `{valid_anchors, error, updated_at}`.
- **سرویس `dns-doh`:** در کاتالوگ با `domains_supported`، ولی فقط وقتی `doh.enabled && !doh.tls` (یا هنوز دامنه دارد) نشان داده
  می‌شود؛ `internal_port` = پورت اولین listen DoH (پیش‌فرض 8053)؛ وضعیت از موتور، و با DoH خاموش `disabled/doh_plain_disabled`.
  موتور روی host network است، پس حالت `dokploy_api` برای این سرویس به `traefik_file` (اگر در دسترس) وگرنه `manual` تبدیل
  می‌شود. در فایل Traefik، ورودی `dns-doh` فیلدهای `target_host` (اولین listen IPv4 غیر loopback، وگرنه gateway داکر) و `port` دارد؛
  `agent/traefik.py` این دو را **فقط** برای `dns-doh` می‌پذیرد (Agent قدیمی کل فایل را رد می‌کند و ساخت دامنه برمی‌گردد).
  دستور manual: router در Traefik به `http://<target>:<port>`. بررسی دامنه: `GET /dns-query?dns=<پرسش . NS>` و تشخیص با
  `Content-Type: application/dns-message`.
- **upstream:** `quic://host[:port][#sni]` (host = IP یا نام) پذیرفته می‌شود.

## 1. هدف و تجربه کاربر

- **حل مستقل:** موتور بتواند بدون هیچ سرور واسطه‌ای (Cloudflare/Google) نام‌ها را از سرورهای ریشه پیدا کند، یا اول از
  forwarderها بپرسد و اگر همه خراب بودند خودش از ریشه حل کند. پیش‌فرض برای نصب فعلی بدون تغییر رفتار (`forward`).
- **DNSSEC:** پاسخ جعلی/دست‌کاری‌شده پذیرفته نشود؛ پاسخ امن با بیت AD؛ پاسخ خراب (bogus) → SERVFAIL با خطای توسعه‌یافته
  (EDE، RFC 8914) و دلیل ساده در پنل. زون‌های محلی و forwarder داخلی (مثل `corp.lan`) خودکار «ناامن ولی مجاز» تلقی شوند تا
  هیچ‌چیز داخلی خراب نشود.
- **DNS رمزدار ورودی:** گوشی/لپ‌تاپ/مرورگر بتوانند با DoT (853/tcp)، DoH (`/dns-query`) و DoQ (853/udp) به MRK وصل شوند؛
  بدون اینکه MRK «open resolver» شود. برای دسترسی از اینترنت: توکن DoH (`/dns-query/<token>`).
- پنل: ساده (سه گزینه با جمله روزمره، یک کلید DNSSEC، یک صفحه «اتصال رمزدار» با راهنمای هر دستگاه) و پیشرفته (همه پارامترها).

## 2. تنظیمات تازه موتور (همان `GET/PUT /v1/settings`، با `config_version`)

بخش‌های تازه به سند تنظیمات اضافه می‌شوند. **تنظیمات ذخیره‌شده قدیمی که این بخش‌ها را ندارند با پیش‌فرض پر می‌شوند**
(بارگذاری = پیش‌فرض‌ها + سند ذخیره‌شده). خطای اعتبارسنجی همان `settings_invalid` 422 با `fields:[{field, reason_code, params?}]`.

### 2.1 `resolution`

```json
{
  "mode": "forward",                    // forward | recursive | forward_then_recursive
  "qname_minimization": "relaxed",      // off | relaxed | strict   (RFC 9156)
  "ip_versions": "ipv4",                // ipv4 | ipv6 | both   (آدرس سرورهای authoritative)
  "case_randomization": true,           // 0x20؛ با سرور ناسازگار خودکار خاموش برای همان سرور
  "root_hints": [],                     // خالی = داخلی؛ وگرنه [{name, ipv4?, ipv6?}] 1..26 مورد
  "allow_private_ns": false,            // اجازه پرسیدن از NS با IP خصوصی/loopback/link-local (ضد SSRF)
  "max_referrals": 30,                  // 1..64
  "max_queries_per_resolution": 100,    // 10..500 (شامل حل NSها و DS/DNSKEY)
  "max_ns_per_zone": 13,                // 1..32
  "query_timeout_ms": 1500,             // 200..10000 برای هر سرور
  "resolve_timeout_ms": 4000,           // 1000..30000 کل یک حل (جایگزین ثابت resolveTimeout)
  "infra_cache_entries": 10000          // 100..1000000 (RTT/وضعیت EDNS/0x20 هر سرور)
}
```

- `forward`: رفتار D1/D2 (forwarderها، با DNSSEC اگر فعال).
- `recursive`: حل تکراری از ریشه؛ forwarderهای عمومی استفاده نمی‌شوند (zoneهای نوع forwarder همچنان به سرور خودشان).
- `forward_then_recursive`: forwarderها؛ اگر همه شکست خوردند/timeout (نه NXDOMAIN معتبر) → حل از ریشه برای همان پرسش.
- ریشه داخلی: 13 سرور a..m با IPv4/IPv6 فعلی (named.root). در شروع و هر 24 ساعت **priming** (RFC 8109)؛ نتیجه در وضعیت.
- ایمنی حل: شناسه تصادفی و پورت مبدأ تصادفی (سیستم‌عامل)، 0x20، **bailiwick** برای glue و رکوردهای additional (فقط داده
  زیر zone ارجاع‌دهنده)، رد پاسخ با سؤال نامطابق، TCP پس از TC، حلقه CNAME ≤ 16، شناسایی حلقه ارجاع، سقف هم‌زمانی همان
  `limits.max_inflight_upstream`، هرگز ارسال به آدرس‌های listen خود موتور، رعایت `rebinding_protection` روی پاسخ نهایی.
  EDNS 1232، در صورت FORMERR/timeout تکرار بدون EDNS و یادآوری در infra cache.
- کش: delegationها (NS + glue) در همان cache با کلید جدا و TTL خودشان (سقف `cache.max_ttl`)؛ serve-stale و prefetch
  همانند قبل برای حل از ریشه هم.

### 2.2 `dnssec`

```json
{
  "mode": "validate",                   // off | validate | log_only
  "trust_anchor_auto_update": true,     // RFC 5011 برای ریشه
  "negative_trust_anchors": [],         // [{domain, reason?, expires_at?}]  ≤ 500؛ expires_at RFC3339 یا خالی
  "auto_insecure_local": true,          // زون‌های authoritative، forwarder-zoneها، و reverse خصوصی (RFC 6303) بدون اعتبارسنجی
  "aggressive_nsec": true,              // RFC 8198
  "nsec3_max_iterations": 150,          // 0..2500؛ بیشتر → insecure (RFC 9276)
  "bogus_ttl": 60,                      // 0..3600 کش نتیجه bogus
  "sig_skew_seconds": 3600              // 0..86400 تحمل اختلاف ساعت
}
```

- **پیش‌فرض `validate`** (برای نصب‌های قدیمی هم). `log_only` = اعتبارسنجی و ثبت، ولی پاسخ bogus مثل insecure تحویل
  داده می‌شود (برای عیب‌یابی).
- ریشه: دو DS داخلی **KSK-2017 (20326)** و **KSK-2024 (38696)**؛ با RFC 5011 فهرست در data dir موتور (`trust-anchors.json`،
  0600) به‌روز می‌شود (hold-down 30 روز، revoke، missing). اگر به‌روزرسانی نتواند کار کند همان داخلی‌ها می‌مانند.
- الگوریتم‌ها: RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519 (و ED448 اگر
  کتابخانه دارد). digest: SHA-1, SHA-256, SHA-384. الگوریتم/digest ناشناخته → insecure (RFC 4035 §5.2، RFC 6840 §5.2).
- اعتبارسنجی کامل زنجیره DS→DNSKEY→RRSIG، اثبات عدم وجود NSEC/NSEC3 (NXDOMAIN، NODATA، wildcard، opt-out، اثبات delegation
  ناامن)، wildcard expansion، CNAME/DNAME زنجیره‌ای، و در **هر سه حالت حل** (در forward با DO=1 و پرسیدن DS/DNSKEY از همان
  مسیر). وضعیت هر پاسخ: `secure | insecure | bogus | indeterminate`، در کش ذخیره می‌شود.
- پاسخ به کلاینت: AD=1 فقط برای `secure` و وقتی کلاینت DO یا AD فرستاده؛ CD=1 از کلاینت → بدون اعتبارسنجی، داده خام
  (bogus هم)؛ DO=1 → RRSIGها و NSEC/NSEC3 همراه پاسخ. bogus → SERVFAIL + EDE (6 DNSSEC Bogus، 7 Signature Expired،
  8 Signature Not Yet Valid، 9 DNSKEY Missing، 10 RRSIGs Missing، 1 Unsupported DNSKEY Algorithm، 2 Unsupported DS Digest).
  EDE دیگر: 3 Stale Answer (serve-stale)، 22 No Reachable Authority، 18 Prohibited (ACL)، 15 Blocked (mitigation block).

### 2.3 `encrypted` (DNS رمزدار ورودی)

```json
{
  "dot": {"enabled": false, "listen": ["0.0.0.0:853"]},
  "doq": {"enabled": false, "listen": ["0.0.0.0:853"]},
  "doh": {"enabled": false, "listen": ["0.0.0.0:443"], "tls": true, "path": "/dns-query", "allow_get": true,
          "trusted_proxies": ["127.0.0.0/8", "::1/128", "172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"]},
  "allow": null,                        // null = همان recursion.allow؛ وگرنه فهرست CIDR (قاعده‌ی open resolver همان D1)
  "max_connections": 2000,              // 10..100000 مجموع DoT+DoH+DoQ
  "max_connections_per_client": 50,     // 1..10000
  "idle_timeout_ms": 30000,             // 1000..600000
  "max_streams_per_connection": 100,    // 1..1000 (DoQ و HTTP/2)
  "handshake_timeout_ms": 5000          // 500..30000
}
```

- `doh.tls=false` = HTTP ساده برای پشت Traefik/Dokploy (گواهی Let's Encrypt را Traefik می‌دهد)؛ در این حالت هر نشانی listen
  باید loopback یا شبکه خصوصی/Docker باشد (`plain_doh_public` اگر نه). IP واقعی کلاینت از `X-Forwarded-For`/`Forwarded`
  فقط وقتی اتصال از `trusted_proxies` است. پیش‌فرض پنل برای حالت پشت Traefik: `127.0.0.1:8053` و `172.17.0.1:8053`.
- DoH: RFC 8484، `GET ?dns=` (base64url) و `POST application/dns-message`، HTTP/1.1 و HTTP/2 (TLS با ALPN `h2,http/1.1`)،
  سقف بدنه 65535، `Cache-Control: max-age=<کمترین TTL>`. مسیر دیگر → 404. `/dns-query/<token>` برای توکن‌ها (§2.4).
- DoT: RFC 7858، ALPN `dot`، چند پرسش روی یک اتصال (pipelining، پاسخ خارج از ترتیب مجاز)، EDNS keepalive (RFC 7828).
- DoQ: RFC 9250، ALPN `doq`، هر پرسش یک stream، شناسه پیام 0، کتابخانه QUIC با نسخه سنجاق‌شده.
- تکرار listen یکسان بین بخش‌ها/پروتکل‌ها (`listen_conflict`)؛ `dot` و `doq` می‌توانند هر دو `:853` باشند (tcp و udp).
- بدون گواهی معتبر (§3) فعال‌کردن DoT/DoQ/DoH-با-TLS → `certificate_required`.
- همه ورودی‌های رمزدار از همان مسیر پرسش (ACL، محدودیت کلاینت، RRL نه — RRL فقط UDP، فشار، mitigation، لاگ با proto
  `dot|doh|doq`) عبور می‌کنند.

### 2.4 توکن‌های DoH (دسترسی از اینترنت بدون open resolver)

توکن‌ها جدا از سند تنظیمات (API §3). کلاینتِ دارای توکن معتبر از هر IP پذیرفته می‌شود، با محدودیت `qps` همان توکن (به‌جای
`allow`). موتور فقط SHA-256 توکن را نگه می‌دارد (مقایسه ثابت‌زمان). توکن 32 بایت تصادفی base64url (43 نویسه). لاگ: ستون
`client` IP واقعی و `upstream` خالی؛ شناسه توکن در فیلد تازه `token` (§4).

## 3. API تازه موتور (unix socket)

- `GET /v1/status` — اضافه‌ها: `resolution:{mode, root_priming:{ok, at, servers_reachable, error?}, infra_cache_entries}`،
  `dnssec:{mode, trust_anchors:[{key_tag, algorithm, state:"valid"|"pending"|"revoked"|"missing", since}],
  trust_anchor_updated_at, trust_anchor_error?, counters:{secure, insecure, bogus, indeterminate}}`،
  `encrypted:{connections:{dot, doh, doq}, certificate:{present, not_after?, self_signed?, days_left?}}`. فهرست listenerها
  `proto` تازه: `dot | doh | doq`.
- `POST /v1/resolve` — ورودی تازه `{…, dnssec?:true (پیش‌فرض true = DO), cd?:false, trace?:false, no_cache?:false}`؛ خروجی
  اضافه: `dnssec:{status, reason?}`، `ede:[{code, text}]`، `source` ممکن است `recursive` باشد، و با `trace:true` فهرست
  `trace:[{step, zone, server, server_name?, qname, qtype, rcode, rtt_ms, referral?:[ns…], dnssec?, error?}]` (حداکثر 200 گام،
  `trace` همیشه `no_cache` است).
- `GET /v1/dnssec` → `{mode, trust_anchors:[…], updated_at, error?, negative_trust_anchors:[…], counters}`؛
  `POST /v1/dnssec/refresh` → به‌روزرسانی فوری trust anchor (همان پاسخ).
- `GET /v1/tls` → `{present, source:"uploaded"|"self_signed"|null, subject?, names:[…], issuer?, not_before?, not_after?,
  fingerprint_sha256?, self_signed, key_type?}` (**کلید خصوصی هرگز برنمی‌گردد**).
- `PUT /v1/tls {cert_pem, key_pem}` → اعتبارسنجی (زنجیره PEM، تطابق کلید، RSA≥2048/ECDSA P-256/P-384/Ed25519، منقضی نبودن)
  و ذخیره 0600 در data dir، بارگذاری بدون restart. خطا `tls_invalid` 422 با `reason_code`: `bad_pem`, `key_mismatch`,
  `expired`, `weak_key`, `no_names`, `too_large` (سقف 64KiB).
- `POST /v1/tls/self-signed {names:[…]}` → ECDSA P-256، اعتبار 397 روز، تمدید خودکار 30 روز پیش از انقضا (فقط اگر منبع
  self_signed است). `DELETE /v1/tls` → حذف (اگر listener رمزدار فعال است `certificate_in_use` 409).
- `GET /v1/doh/tokens` → `{items:[{id, name, qps, created_at, last_used_at?, queries}]}`؛ `POST /v1/doh/tokens {name, qps?}`
  (name 1..64، qps 1..10000 پیش‌فرض 50؛ سقف 200 توکن `limit_reached`) → `{id, name, qps, token, created_at}` (**token فقط
  همین یک بار**)؛ `PATCH /v1/doh/tokens/{id} {name?, qps?}`؛ `DELETE /v1/doh/tokens/{id}` → 204؛ نبود `token_not_found` 404.
- رویدادها (`/v1/events`): `dnssec.trust_anchor_updated` (info)، `dnssec.trust_anchor_failed` (error)، `dnssec.bogus_spike`
  (warning، `{count, names:[…≤10]}` وقتی bogus در 5 دقیقه > 100 و > 5٪)، `tls.certificate_expiring` (warning، `{days_left}`
  در 14/7/3/1 روز)، `tls.certificate_expired` (error)، `resolution.priming_failed` (error)، `listener.failed` (error،
  `{address, proto, error}` — اگر قبلاً نبود).
- forwarderهای خروجی: طرح تازه **`quic://host[:853]`** (DoQ خروجی) کنار `tls://` و `https://` قبلی.
- خطاهای تازه: `certificate_required`, `certificate_in_use`, `tls_invalid`, `token_not_found`, `listen_conflict`,
  `plain_doh_public` (به‌عنوان reason_code در settings_invalid برای دو مورد آخر).

## 4. لاگ و آمار

- `source` تازه در انتهای فهرست: `recursive` (از ریشه). `proto` تازه: `doq`. پرچم‌های تازه در همان بایت flags:
  `FlagSecure=8`, `FlagBogus=16`, `FlagInsecure=32` (هیچ‌کدام = اعتبارسنجی نشده/خاموش). قالب segment تغییر نمی‌کند.
- نمای رکورد: `flags:{tc, stale, cached}` + `dnssec:"secure"|"insecure"|"bogus"|""`؛ CSV ستون `dnssec` در انتها.
  توکن DoH: برای حفظ قالب، شناسه توکن در segment در جای رشته upstream با پیشوند `t:` ذخیره می‌شود؛ نمای API: `upstream`
  خالی و فیلد تازه `token: "<id>"` (فقط وقتی هست).
- فیلتر تازه جست‌وجو/stream/export: `dnssec=secure|insecure|bogus|none` و `proto=doq` و `source=recursive`.
- آمار (`/v1/stats`): شمارنده‌های `dnssec:{secure, insecure, bogus}` در هر نقطه و totals؛ `proto` شامل `dot, doh, doq`.

## 5. API پنل (`/api/v1/dns/...`)

- `GET/PUT settings`: بخش‌های `resolution`, `dnssec`, `encrypted` با همان اعتبارسنجی پیش از ارسال (`dns_settings_invalid`).
  هشدار غیرمسدودکننده در پاسخ PUT: `warnings:[{code}]` با `recursive_needs_outbound_53` (حالت recursive)،
  `doh_public_needs_token` (DoH عمومی بدون توکن و allow خصوصی)، `self_signed_certificate`.
- `POST resolve`: فیلدهای تازه `dnssec, cd, trace, no_cache` (trace فقط با `dns:write`).
- `GET dnssec` (dns:read)، `POST dnssec/refresh` (dns:admin، audit `dns.dnssec.refresh`).
- `GET tls` (dns:read)؛ `PUT tls` (dns:admin، audit `dns.tls.upload`، object_id = fingerprint)؛ `POST tls/self-signed`
  (dns:admin، audit `dns.tls.self_signed`)؛ `DELETE tls` (dns:admin، audit `dns.tls.delete`). کلید خصوصی در لاگ/audit/پاسخ
  هرگز.
- `GET doh/tokens` (dns:read)؛ `POST doh/tokens` (dns:admin، audit `dns.doh_token.create`، پاسخ شامل `token` و
  `urls:{doh}` آماده بر پایه دامنه متصل یا IP سرور)؛ `PATCH/DELETE doh/tokens/{id}` (dns:admin، audit).
- `POST encrypted/apple-profile {doh_url? , dot_name?, name?}` (dns:read) → فایل `.mobileconfig` (بدون امضا، payload
  `com.apple.dnsSettings.managed`)؛ ورودی فقط URL/نام معتبر https/hostname.
- `GET encrypted/clients` (dns:read) → دستورالعمل آماده هر دستگاه بر پایه وضعیت فعلی: `{doh_url?, dot_name?, doq_name?,
  ip, certificate:{trusted:bool}, guides:[{id:"android"|"ios"|"windows"|"macos"|"linux"|"firefox"|"chrome", available, reason?}]}`.
- اتصال دامنه به DoH: سرویس تازه **`dns-doh`** در کاتالوگ «سرویس‌های من» (docs/35) وقتی `doh.enabled && !doh.tls`، با
  پورت همان listen داخلی؛ دامنه از همان مسیر Dokploy/Traefik اضافه می‌شود و Traefik گواهی می‌دهد. `GET encrypted/clients`
  از دامنه‌های همین سرویس برای ساخت `doh_url` استفاده می‌کند.
- اعلان‌ها (رویدادهای §3 → notifications): `dns.dnssec_trust_anchor_failed` (error)، `dns.dnssec_bogus_spike` (warning)،
  `dns.tls_certificate_expiring` (warning)، `dns.tls_certificate_expired` (error)، `dns.priming_failed` (error).
- خانه: `dns_certificate_expiring` (warning/error، `#/dns/encrypted`)، `dns_trust_anchor_problem` (error، `#/dns/settings`).
- مجوزها همان چهار `dns:*`؛ متغیر محیطی تازه لازم نیست (اگر شد، در registry ثبت شود).

## 6. پنل

- **تنظیمات → «روش پیدا کردن نشانی‌ها»:** سه کارت: «از سرورهای مطمئن بپرس» (forward)، «خودش مستقیم پیدا کند» (recursive)،
  «اول بپرس، اگر نشد خودش» (forward_then_recursive)؛ با یک جمله فایده/هزینه. پیشرفته: همه پارامترهای §2.1 و root hints.
- **تنظیمات → «امضای امنیتی (DNSSEC)»:** کلید روشن/خاموش + حالت «فقط ثبت»؛ وضعیت trust anchor با جمله ساده و دکمه
  «به‌روزرسانی»؛ پیشرفته: فهرست استثناها (NTA) با تاریخ انقضا، و بقیه پارامترها.
- **تب تازه «اتصال رمزدار»** (`#/dns/encrypted`): سه کلید DoT/DoH/DoQ با توضیح یک‌خطی؛ کارت گواهی (ساخت خودامضا / بارگذاری /
  «از دامنه با Traefik» که به «سرویس‌های من» می‌برد)؛ توکن‌ها (ساخت → نمایش یک‌باره با دکمه کپی و QR)؛ راهنمای هر دستگاه
  (Android «DNS خصوصی»، iPhone/Mac با دانلود پروفایل، Windows 11، Firefox/Chrome، Linux systemd-resolved) با گام‌های کوتاه.
- **تب «آزمایش»:** نشان DNSSEC (امن/ناامن/خراب + دلیل ساده از EDE)، گزینه «مسیر کامل را نشانم بده» (trace) با نمایش
  گام‌به‌گام ریشه → TLD → دامنه.
- **لاگ/پایش:** فیلتر و ستون DNSSEC، proto `doq`، source `recursive`؛ نمودار امن/ناامن/خراب در پایش.
- همه متن‌ها در کاتالوگ fa/en، `check:copy` سبز، ریسپانسیو.

## 7. پذیرش (تست)

- موتور: تست واحد با زون‌های امضاشده ساختگی (secure، insecure delegation، bogus: امضای خراب/منقضی/DNSKEY گم/DS نامطابق،
  NSEC و NSEC3 و opt-out و wildcard، الگوریتم ناشناخته → insecure، NTA، CD)، شبیه‌ساز سلسله‌مراتب ریشه/TLD/دامنه برای
  حل تکراری (glue خارج bailiwick رد، حلقه ارجاع، CNAME بین zoneها، TC→TCP، سرور بی‌پاسخ، qname minimization)، DoT/DoH/DoQ
  end-to-end با گواهی خودامضا، توکن، trusted proxy، سقف اتصال؛ `go test -race ./...` سبز.
- واقعی (روی mrkverify): `dnssec-failed.org` → SERVFAIL+EDE، `internetsociety.org`/`isc.org` → AD، حالت recursive برای
  100 دامنه پرکاربرد هم‌خوان با Unbound مرجع (rcode و مجموعه پاسخ)، DoT با `kdig`/`openssl`، DoH با `curl`، DoQ با کلاینت
  آزمایشی، و بار: حالت recursive زیر flood بدون از کار افتادن کلاینت عادی (همان سناریوی D2).
- بک‌اند: pytest برای اعتبارسنجی، مجوزها، audit، پروفایل اپل، کاتالوگ dns-doh؛ ruff؛ validate_release.
- پنل: build و `check:copy`.

## 8. بیرون از D4

DNS cookies (RFC 7873)، ACME مستقیم در موتور، امضای DNSSEC زون‌ها، secondary/AXFR (همه D5/D6).
