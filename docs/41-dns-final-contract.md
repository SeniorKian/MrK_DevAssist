# 41 — قرارداد نهایی موتور DNS: D5 + D6 + قالب دامنه

وضعیت: **قرارداد مرجع و آخرین فاز DNS — 2026-11-09**. پایه: `docs/37`، `docs/38`، `docs/40` (همراه §0ها). بعد از این فاز، کار
موتور DNS بسته می‌شود؛ هر چیز بیرون از این سند به «بیرون از محدوده» (§9) می‌رود. هر سازنده تغییر شکل را در §0 ثبت کند.

## 0. تغییرات نسبت به قرارداد اولیه

(خالی — زیربخش‌ها: 0.1 موتور زون، 0.2 موتور سیاست/سخت‌سازی، 0.3 بک‌اند، 0.4 پنل)

### 0.1 موتور زون

کد: `internal/zone/d5.go` (نوع `secondary`، `D5Config` درون سند زون، کامپایل از فهرست کامل RR، افزودن RRSIG و اثبات NSEC/NSEC3)،
`internal/tsig`، `internal/signer`، `internal/xfr`، `engine/zones_d5.go`، `engine/xfr_d5.go`، `engine/update_d5.go`،
`admin/zones_d5.go`. تست: `server/zones_d5_test.go` (دو موتور primary↔secondary)، `admin/zones_d5_test.go`، `xfr`، `signer`.

- **شکل‌ها:** `POST /v1/zones {name, type:"secondary", primaries, tsig_key?, notify_allow?}`؛ `primaries` به `ip:port` نرمال
  می‌شود (پیش‌فرض 53، نام میزبان پذیرفته نیست، حداکثر 8). `GET /v1/zones/{z}` برای primary همیشه
  `transfer:{allow, tsig_key?}`، `notify:{targets, enabled, tsig_key?}`، `update:{enabled, allow, tsig_key?, require_tsig}`،
  `dnssec:{enabled, algorithm, denial, nsec3:{iterations, salt, opt_out}, signature_validity_days, refresh_days}` دارد (با
  پیش‌فرض)؛ برای secondary `primaries, tsig_key, notify_allow, transfer, notify` و `secondary:{serial, loaded, expired,
  last_refresh, last_success, next_refresh, expires_at, primary?, last_transfer?:"axfr"|"ixfr", error?}`. همه این کلیدها با
  `PATCH /v1/zones/{z}` تغییر می‌کنند (ادغام جزئی درون هر شیء). **اضافه:** `notify.tsig_key` (پیش‌فرض: `transfer.tsig_key`).
  خطای اعتبارسنجی `zone_invalid` 422 با `reason_code`: `invalid_cidr, invalid_address, unknown_tsig_key, open_update,
  algorithm_locked, not_allowed, required, out_of_range, invalid_salt, invalid_choice`.
- `POST /v1/zones/{z}/refresh` همگام است → `{secondary:{…}}` (شکست انتقال = 200 با `error`)؛ زون غیر secondary →
  `zone_type_mismatch` 409. تغییر رکورد/import/rollback روی secondary → `zone_read_only` 409؛ `GET records` آن فقط‌خواندنی
  (شناسه `x<n>`، فقط انواع D1) و export متن کامل.
- `GET /v1/tsig` → `{items:[{name, algorithm, created_at}]}`؛ `POST` → 201 `{name, algorithm, created_at, secret}`؛
  `DELETE /v1/tsig/{name}` → 204. خطا: `tsig_invalid` 422، `tsig_key_exists` 409، `tsig_key_not_found` 404،
  `tsig_key_in_use` 409 (`params.zones`). secret ورودی base64 با 16 تا 128 بایت.
- `GET /v1/zones/{z}/dnssec` → `{enabled, config, keys:[{tag, role, algorithm, created, state, state_since}], ds:[{key_tag,
  digest_type, digest, text}], next_resign, next_key_event, signatures_expire, error?}`؛ rollover همین نما را برمی‌گرداند؛
  `rollover_in_progress` 409، `dnssec_disabled` 409.
- **رفتار secondary:** بررسی SOA (با TSIG اگر کلید دارد) ← IXFR ← در شکست AXFR. refresh/retry از SOA با سقف [10s، 7 روز]؛ پس
  از expire پاسخ SERVFAIL. داده در `secondary/<zone>.zone` و `<zone>.state.json`. NOTIFY ورودی فقط از IP یکی از primaries یا
  `notify_allow`، و اگر `tsig_key` دارد امضاشده با همان. secondary بعد از دریافت داده تازه به `notify.targets` خودش خبر می‌دهد.
- **انتقال خروجی:** فقط TCP؛ IXFR روی UDP = فقط SOA جاری. `allow` خالی = بسته؛ با `tsig_key` فقط درخواست امضاشده با همان کلید.
  TSIG بد → NOTAUTH با BADKEY/BADSIG (بی‌امضا). بیش از 10 انتقال هم‌زمان → SERVFAIL. پیام‌ها تکه‌های 16KB (زیر 64KB). IXFR فشرده
  (یک delta) از history؛ زون امضاشده یا serial ناموجود → قالب AXFR. رکوردهای view (split-horizon) نه امضا و نه منتقل می‌شوند.
  پرسش عادی امضاشده با TSIG پاسخ امضاشده می‌گیرد (برای SOA check سرورهای دیگر).
- **NOTIFY خروجی:** پس از هر تغییر serial، 5 تلاش با فاصله 1/2/4/8 ثانیه؛ تغییر تازه تلاش‌های قبلی را لغو می‌کند.
- **UPDATE:** `allow` خالی یعنی فقط TSIG؛ `require_tsig:false` بدون `allow` رد می‌شود (`open_update`). SOA داخل update نادیده
  (serial خودکار)، آخرین NS در apex حذف نمی‌شود، فقط انواع D1 (بقیه REFUSED)، روی secondary REFUSED. history با reason `update`.
- **DNSSEC:** امضای پیش‌محاسبه‌شده در حافظه پس از هر تغییر. کلیدها `dnssec-keys/<zone>.keys.json` (0600، پوشه 0700) و TSIG در
  `tsig.json` (0600). تمدید وقتی به `expiration − refresh_days` رسید: نسخه تازه با reason `dnssec.resign`، actor `dnssec` و
  serial بالاتر (تا secondaryها هم بگیرند). ZSK: `published` (2 ساعت) ← `active`، کلید قدیم `retired` 26 ساعت و حذف. KSK
  (امضای دوگانه): کلید تازه فوراً `active`، قدیمی `retired` تا 7 روز هنوز DNSKEY را امضا می‌کند و DS هر دو در `ds` است. CDS/CDNSKEY
  برای KSK فعال؛ NSEC3PARAM با TTL 0؛ `iterations` حداکثر 100. خاموش‌کردن کلیدها را نگه می‌دارد؛ روشن‌کردن با الگوریتم دیگر کلید
  تازه می‌سازد؛ تغییر الگوریتم در حالت روشن → `algorithm_locked`. RRSIG و اثبات‌ها فقط برای DO=1.
- **رویدادها:** `zone.secondary_expired` (error)، `zone.transfer_failed` (warning، یک بار در هر دوره شکست)،
  `zone.transfer_recovered` (info)، `zone.notify_failed` (warning)، `zone.dnssec_signing_failed` (error)،
  `zone.dnssec_keys_changed` (info).
- **سقف‌ها:** 8 primary، 16 هدف notify، 64 مدخل ACL، انتقال ورودی 400k RR / 256MB / 5 دقیقه.
- **نشد:** رکورد DS در زون primary (delegation امضاشده به زیرزون) پشتیبانی نمی‌شود؛ `kdig`/`delv` در ایمیج نیست و بررسی با
  اعتبارسنج D4 خود موتور انجام شد.

### 0.2 موتور سیاست

کد: `internal/filter` (پارس چهار قالب، matcher فشرده، دانلود/به‌روزرسانی)، `config/filtering.go`، `zone/views.go`،
`engine/policy.go` (گروه‌ها، views، پاسخ مسدود)، `engine/backup.go`، `admin/policy.go`، `pressure/headroom.go`، `Reload` در
`mitigate`/`tokens`/`certs`. تست: `filter/filter_test.go`، `engine/policy_test.go`، `querylog/cursor_test.go`.

- **معنای قالب‌ها:** hosts و domains = خود نام؛ `*.x` در domains، `||x^` در adblock و `*.x` در rpz = نام و همه زیردامنه‌ها
  (rpz «فقط زیردامنه» را هم شامل خود نام می‌گیرد). adblock: `|x^` خود نام، `@@` = استثنای همان فهرست؛ قانون با modifier جز
  `important|all`، wildcard، مسیر، regex یا cosmetic نادیده. rpz: فقط QNAME؛ `rpz-passthru.` = مجاز؛ `CNAME .`/`*.`/داده محلی =
  مسدود با `action` خود موتور؛ triggerهای IP/NSDNAME نادیده. نام تک‌برچسبی یا IP هرگز وارد نمی‌شود. `allow`/`block` تنظیمات
  همیشه نام + زیردامنه‌ها (`*.` حذف، تکراری‌ها بی‌صدا حذف، فقط ASCII/punycode).
- **ترتیب:** allow (دستی + استثنای فهرست‌های فعال) > `blocked_services` > فهرست‌ها و block دستی > safe search. فقط برای
  کلاینت مجاز به recursion و فقط نام‌هایی که از بیرون حل می‌شوند (نه override، نه زون primary/secondary؛ زون forwarder فیلتر
  می‌شود). کلاینت بدون recursion همان REFUSED قبلی را می‌گیرد.
- **پاسخ:** `nxdomain` (بدون SOA)، `null_ip` (A `0.0.0.0` / AAAA `::` با TTL 10، انواع دیگر NODATA)، `refuse`؛ با EDNS، EDE 15
  با متن `list:<id> <rule>` | `custom <name>` | `service:<id>`. safe search = CNAME به `forcesafesearch.google.com`،
  `restrict.youtube.com`، `strict.bing.com`، `safe.duckduckgo.com`، `familysearch.yandex.ru` و حل همان (source لاگ `override`).
  لاگ `source:"blocked"` (آخر فهرست source؛ در `blocked=true` و `errors_only` هم هست)، `by_source.blocked` در آمار و metrics.
- **ذخیره:** هر نام hash 64 بیتی + mask 32 بیتی فهرست‌ها در یک آرایه مرتب با شاخص 64K (سنجش با 1M نام: 11.7MiB ماندگار = 12.3 بایت/نام، پارس+ساخت ~2.5s، جست‌وجو ~240ns بدون allocation). حداکثر
  31 فهرست. جایگزینی با ساخت matcher تازه و swap اتمی (پرسش‌ها هرگز منتظر نمی‌مانند). کش فهرست‌ها `filter-lists/<id>.list|json`
  (بعد از restart بدون شبکه بار می‌شود؛ GET شرطی ETag/Last-Modified؛ حذف فهرست از تنظیمات کش را پاک می‌کند). شکست → نسخه قبلی
  می‌ماند و تلاش دوباره پس از min(1h, update_hours). در فشار critical/emergency دانلود و بارگذاری عقب می‌افتد؛ ساختی که حافظه را از
  80٪ GOMEMLIMIT بالاتر ببرد رد می‌شود. `update_hours` 1..168 (پیش‌فرض 24)؛ URL فقط https (`https_required`)، redirect فقط https.
- **status:** `GET /v1/filtering/status` → `{enabled, lists:[{id, name, enabled, entries, updated_at|null, next_update_at|null,
  updating, error?, error_detail?}], total_entries, blocked_1h, memory_bytes}`. کدهای `error`: `download_failed, http_status,
  too_large, too_many_entries, empty_list, memory_limit, deferred_pressure, parse_failed, store_failed`. `POST
  /v1/filtering/refresh` (بدنه خالی) همه را فوراً دانلود می‌کند، تا 25 ثانیه صبر و همان status را برمی‌گرداند (بقیه در پس‌زمینه با
  `updating:true`). `POST /v1/filtering/check {name, client?|client_ip?}` → `{name, blocked, list_id?, rule?, reason, service?,
  group?, rewrite?, filtering}` با `reason`: `list|custom_block|service|allow_list|safe_search|not_listed|filtering_off`؛ نام
  نادرست `invalid_request` با `name: invalid_name`. تازه: `GET /v1/filtering/services` → `{items:[{id, domains}]}` (فهرست ثابت
  سرویس‌ها). رویداد `filter.list_failed` (warning) `{list_id, name, error, detail}` فقط وقتی خطا عوض شد.
- **گروه‌ها:** `lists`/`upstreams`/`blocked_services` همیشه آرایه‌اند (خالی = همه فهرست‌های فعال / upstreamهای پیش‌فرض / هیچ)؛
  `networks` اجباری (IP → host prefix). `filtering:"on"` فهرست‌ها را حتی با `filtering.enabled=false` بار می‌کند؛
  `blocked_services` جز با `"off"` همیشه اعمال می‌شود. `upstreams` گروه: فقط forward (بدون حل از ریشه)، cache جدا (1/8
  `cache.max_bytes`، حداقل 1MiB، بدون stale) تا پاسخ‌ها با گروه پیش‌فرض قاطی نشوند؛ زون forwarder همان forwarder خودش را دارد.
  reason_codeهای تازه: `unknown_list`, `unknown_upstream`, `https_required`.
- **views:** اعلام با `PATCH /v1/zones/{z} {views:[{group_id, records_override?}]}` (جایگزین کامل؛ فقط primary؛ تکرار →
  `zone_invalid` با `duplicate`) و در `GET /v1/zones/{z}`: `views` و `record_views` (viewهای استفاده‌شده در رکوردها). رکورد
  فیلد `view` می‌پذیرد (`^[a-z0-9][a-z0-9_-]{0,63}$`، وگرنه `invalid_view`؛ NS در `@` → `not_allowed`). view بدون اعلام =
  `records_override:true`. با override، RRset view جای RRset عمومی همان نام/نوع را می‌گیرد؛ CNAME view همه داده عمومی آن نام را و
  هر داده view، CNAME عمومی آن نام را کنار می‌زند (زون همیشه معتبر). **محدودیت:** پاسخ view امضای DNSSEC ندارد و رکوردهای view در
  AXFR/export نمی‌آیند (فقط نمای عمومی).
- **پشتیبان:** `GET /v1/backup` → `application/gzip` (`mrk-dns-backup-YYYYMMDD-HHMMSS.tar.gz`)؛ عضو اول `manifest.json` =
  `{format:"mrk-dns-backup", version:1, engine_version, created_at, config_version, files:[{path, size, sha256}]}`. محتوا: پیمایش
  data dir، هر `*.json|*.pem|*.key` جز `querylog/`, `stats/`, `filter-lists/`, `secondary/`, `trust-anchors.json` و فایل‌های پنهان
  (پس `settings.json`, `overrides.json`, `mitigations.json`, `doh-tokens.json` (hash)، `zones/**`, `tls/*`, `tsig.json`,
  `dnssec-keys/*` و هر فایل تازه). شکست ساخت → `backup_failed` 500.
- **بازگردانی:** `POST /v1/restore` بدنه خام tar.gz (سقف 1GiB؛ هر فایل 256MiB، کل 1GiB، 200k فایل). یک‌گذر: باز کردن در
  `.restore-*` و بررسی کامل (manifest، sha256، مسیرها، settings با همان Validate، zones با Compile/ValidateRecords، overrides،
  mitigations، tokens، گواهی، JSON بودن بقیه)؛ هر خطا → `restore_invalid` 422 با `fields:[{field: <path>|"archive"|"manifest.json…",
  reason_code: not_gzip|corrupt|path_not_allowed|not_a_regular_file|duplicate|too_large|too_many_files|required|invalid_json|
  invalid_choice|unsupported_version|mismatch|missing_file|checksum_mismatch|invalid_zone|invalid_records|invalid…}]` (خطای
  settings با پیشوند `settings.json.`) و هیچ چیز عوض نمی‌شود. اعمال زیر قفل state با journal (`.restore-journal.json`)؛ crash وسط
  کار در شروع بعدی rollback می‌شود؛ فایل‌های بعد از backup (مثلاً زون تازه) حذف می‌شوند. سپس settings/zones/overrides/mitigations/
  tokens/گواهی در همان پروسه دوباره بار می‌شوند و `config_version` = max(فعلی، backup)+1. پاسخ `{restored, files, config_version,
  backup_created_at, restart_required, restart_for?}`؛ فایل‌های بخش زون (`tsig.json`, `dnssec-keys/`) تا وقتی hook
  (`Engine.RegisterRestoreHook`) ثبت نشده `restart_required:true` می‌دهند.
- **رفع‌ها:** `client_qps=0` زیر فشار: سقف پایه 2000 qps/کلاینت (burst 4000) × مقیاس → critical 1000، emergency 500. cursor لاگ
  `v2:seq:row:gen:ts` (base64url، v1 همچنان پذیرفته): پس از هر DELETE لاگ، ادامه از اولین ردیف با ts ≤ ts ردیف بعدی (نه اندیس
  قدیمی). `TestStrategiesAndHealth` شمارش اکثریت پاسخ‌ها به‌جای آخرین پاسخ.
- **fuzz:** `FuzzParseList` (filter)، `FuzzZoneMessages` (engine: UPDATE/NOTIFY/IXFR/AXFR/TSIG)، `FuzzTransferParse` (xfr)،
  `FuzzTSIGCheck` (tsig)؛ CI همه fuzzها (از جمله `FuzzSegment`/`FuzzParseFilter` که جا مانده بودند) را 20 ثانیه اجرا می‌کند.
  تست بار 10 دقیقه: job دستی `dns-engine-load` در `soak.yml`.

### 0.3 بک‌اند

کد: `modules/dns_templates.py` (اعتبارسنجی، متغیرها، رندر، مقایسه، متن zone)، `modules/dns_templates_builtin.py` (۶ قالب
آماده)، `modules/dns_final.py` (routeهای قالب و پروکسی‌های تازه)، `modules/dns_validate_d5.py`، و تغییر در `dns.py`،
`dns_validate.py`، `dns_client.py`، `dns_filters.py` (`blocked` در انتهای SOURCES)، `dns_monitor.py`، `home.py`، `models.py`،
registry. migration `20261109_0013` (جدول `dns_templates`). تنظیم runtime تازه `dns.default_template_id` (پیش‌فرض `website`،
خالی = بدون قالب)؛ متغیر محیطی تازه نیست. تست: `tests/test_dns_final.py`.

**قالب‌ها.** شکل خروجی: `{id, builtin, name, description, name_fa, name_en, description_fa, description_en, zone:{ttl,
soa:null|{hostmaster, refresh, retry, expire, minimum}, ns:[…]}, records:[{name, type, ttl?, data, comment?}], variables:[{key,
label_fa, label_en, default, required}], copied_from, created_at, updated_at, is_default}`. شناسه‌های آماده: `website`,
`website_email`, `google_workspace`, `microsoft_365`, `dokploy_apps`, `security_only`؛ قالب کاربر `tpl_<12hex>`. ورودی قالب کاربر
`{name, description?, zone?, records, variables?}` (یک name برای هر دو زبان). `data` همان شکل رکورد پنل (D1) است؛ فیلدهای عددی
باید عدد باشند (متغیر فقط در رشته‌ها). سقف: 200 قالب، 200 رکورد، 20 متغیر، 13 NS.
- متغیرهای استاندارد بدون اعلام: `domain`، `domain_dashed` (`example-com`، برای MX مایکروسافت)، `server_ipv4`، `server_ipv6`،
  `mail_host`، `dkim_value`. `domain*` قابل تغییر نیستند؛ `server_ipv4/6` خودکار از `domains.server_public_ips` و سپس نشانی‌های
  عمومی listenerها در facts عامل پر می‌شوند و کاربر می‌تواند در `variables` بدهد. پیش‌فرض متغیر فقط متغیرهای خودکار را می‌پذیرد.
  کلید رزرو → `reserved`، placeholder ناشناخته → `unknown_variable`.
- **رکوردی که متغیرش خالی است «skipped» می‌شود** (AAAA بدون IPv6، DKIM اختیاری)؛ متغیر `required` خالی → خطای
  `dns_template_variables_invalid` 422 با `variables.<key>: required`. اگر IPv4 سرور معلوم نباشد هشدار `server_ipv4_unknown`.
- ذخیره: قالب ثابت با مقادیر نمونه رندر می‌شود؛ رکورد همیشه‌نامعتبر → `dns_template_invalid` با `records.<i>.<field>`.
- قالب‌های آماده فقط‌خواندنی‌اند (`dns_template_builtin` 409)؛ کپی: `POST templates {copy_from, name?}`.

**مقایسه (preview/apply).** هر آیتم: `{index, source:"record"|"ns"|"soa", status:"new"|"duplicate"|"conflict"|"skipped",
record, conflicts:[رکوردهای موجود], reason?, variable?}`. تکراری = همان name/type/data (TTL مهم نیست). تعارض: CNAME کنار هر
داده دیگر؛ مجموعه متفاوت A/AAAA/MX/NS در همان نام (رکوردهای موجودی که در قالب نیستند)؛ SPF یا DMARC دوم؛ SOA متفاوت.
TXT/CAA/SRV دیگر افزودنی‌اند. پاسخ preview: `{template_id, zone, zone_exists, variables, items, summary:{new, duplicate,
conflict, skipped}, can_apply, replace_effects:{removes, comments_dropped, blocked:{disabled, view}}, warnings}` (زون می‌تواند
هنوز نباشد).
- **اعمال اتمی** با import موتور: فقط رکورد تازه ← `import {replace:false}` (بدون خط SOA)؛ با جایگزینی ← `import
  {replace:true}` با کل زون (رکوردهای مانده + SOA + تازه‌ها). هر دو یک نسخه history. محدودیت: در حالت جایگزینی comment رکوردهای
  مانده از بین می‌رود (هشدار `comments_dropped`)، و اگر رکورد خاموش یا دارای `view` می‌ماند، اعمال رد می‌شود
  (`dns_template_replace_unsafe` 409)؛ comment رکوردهای قالب هم در import حفظ نمی‌شود. تعارض بدون `replace_conflicts:true` →
  `dns_template_conflict` 409 با `conflicts:[{index, source, name, type}]` و `summary`. زون غیر primary → `dns_zone_type_mismatch` 409.
  پاسخ apply: `{template_id, zone, applied, mode:"add"|"replace"|null, added, replaced, summary, version, serial, warnings}`.
- **ساخت زون:** `POST zones` با `template_id` ندادن = قالب پیش‌فرض (اگر حذف شده باشد بی‌صدا هیچ)؛ `null`/`""` = بدون قالب؛
  شناسه ناموجود 404 پیش از ساخت. مقادیر پیش از ساخت زون بررسی می‌شوند. قالب روی زون تازه با `replace_conflicts:true` اعمال
  می‌شود (SOA/NS پیش‌فرض موتور جایگزین‌پذیرند). پاسخ = پاسخ موتور + `template: null | <پاسخ apply> | {template_id,
  applied:false, error:{code, message}}` (اگر import شکست بخورد زون می‌ماند). برای secondary/forwarder `template_id` →
  `not_allowed`. audit جدا `dns.zone.apply_template` (`zone:template_id`).
- `PUT templates/default {template_id|null}` (dns:admin، audit `dns.template.default`)؛ حذف قالب پیش‌فرض آن را به `website`
  برمی‌گرداند. audit: `dns.template.create|update|delete|copy` (copy: `source->new`)؛ مقادیر متغیرها هرگز در audit نیستند.

**زون‌ها و پروکسی‌ها (هم‌راستا با §0.1):** بخش‌های `transfer`, `notify` (با `tsig_key`), `update`,
`dnssec`, `views` و برای secondary `primaries`, `tsig_key`, `notify_allow` با **`PATCH /v1/zones/{z}`** فرستاده می‌شوند (و
`POST /v1/zones` برای ساخت secondary). پنل از پیش می‌سنجد (`dns_zone_invalid` + fields؛ خطای `zone_invalid` موتور در PATCH
بخش‌ها هم `dns_zone_invalid` می‌شود، در بقیه جاها همان `invalid_zone_name` D1): primaries (≤8) و notify.targets (≤16) فقط IP
(`ip[:port]` → canonical با پورت 53)، CIDRها (≤64) canonical و `/0` در transfer/update/notify_allow → `too_broad`، نام کلید TSIG →
`invalid_key_name`، `notify.enabled` بدون target → `required`، `update.require_tsig`+`enabled` با `tsig_key:null` → `required`،
`require_tsig:false` با `allow:[]` → `open_update`،
`dnssec.refresh_days < signature_validity_days` (`not_below_validity`)، nsec3 iterations 0..100 و salt hex، views بدون تکرار.
رکورد فیلد اختیاری `view` می‌پذیرد (شناسه view و `views[].group_id` با الگوی §0.2 `^[a-z0-9][a-z0-9_-]{0,63}$`). audit `dns.zone.update` با object_id `zone:sections` وقتی بخش تازه عوض شد.
- `POST zones/{z}/refresh` (dns:write، `dns.zone.refresh`)؛ `GET zones/{z}/dnssec` (dns:read، کلیدهای خصوصی حذف)؛
  `POST zones/{z}/dnssec/rollover {role}` (dns:write، `dns.zone.dnssec_rollover` `zone:role`).
- `GET tsig` (dns:read، `secret` همیشه حذف)؛ `POST tsig {name, algorithm?=hmac-sha256, secret?}` (dns:admin، secret اگر داده
  شد base64 با 16..128 بایت، خطا `dns_tsig_invalid`، پاسخ موتور عیناً با secret یک‌باره)؛ `DELETE tsig/{name}` → `{deleted}`.
- تنظیمات `filtering` و `client_groups` در `PUT settings` بررسی می‌شوند: URL فقط https (`https_required`)، بدون userinfo،
  شناسه یکتا، `update_hours` 1..168، نام‌ها canonical (`*.` مجاز)، ارجاع گروه به فهرست/upstream ناموجود → `unknown_list` /
  `unknown_upstream` (فقط وقتی همان بخش در payload هست)، شبکه گروه `/0` مجاز.
- `GET filtering/status` و `GET filtering/services` (dns:read)، `POST filtering/refresh` (dns:admin، تا 90 ثانیه)، `POST
  filtering/check {name, client_ip?}` (dns:read، CSRF، خطا `dns_query_invalid`)؛ پاسخ‌ها عیناً از موتور (§0.2).
- سقف فایل پشتیبان در پنل 128MiB (دانلود و بازگردانی؛ کمتر از سقف 1GiB موتور، چون پنل فایل را در حافظه نگه می‌دارد). پاسخ
  restore عیناً (`restart_required` را پنل نشان دهد).
- `GET backup` (dns:admin) → فایل `application/gzip` با `mrk-dns-backup-YYYYMMDD-HHMMSS.tar.gz` (سقف 128MiB، audit
  `dns.backup.download` با `sha256:<16hex>,bytes=n`)؛ `POST restore?confirmation=RESTORE` (dns:admin، CSRF، بدنه خام فایل با
  هر Content-Type) → به موتور با `Content-Type: application/gzip`؛ نبود تأیید → `confirmation_mismatch` با
  `expected_confirmation:"RESTORE"`، فایل غیر gzip → `dns_restore_invalid` (`file: not_gzip|required`).
- کدهای تازه موتور: `zone_read_only`, `zone_type_mismatch`, `tsig_invalid`, `tsig_key_not_found|exists|in_use` (→
  `dns_tsig_not_found|exists|in_use`)، `rollover_in_progress`, `dnssec_disabled`,
  `filter_list_not_found`, `filtering_disabled`, `restore_invalid`, `backup_failed` → `dns_<code>`.
- **رویدادها** (نام‌های §0.1 به‌علاوه چند املای دیگر برای تحمل): `zone.secondary_expired` → `dns.secondary_expired`؛
  `zone.transfer_failed` → `dns.transfer_failed`؛ `zone.dnssec_signing_failed` → `dns.dnssec_signing_failed`؛
  `filtering.list_failed` | `filter.list_failed` → `dns.filter_list_failed` (موتور سیاست لطفاً یکی را بدهد). data: `{zone,
  error, primary?}` یا `{list_id, name, error}`. dedupe `<type>.<zone|list_id>`. `zone.transfer_recovered` مشکل secondary خانه را
  پاک می‌کند؛ `zone.notify_failed` و `zone.dnssec_keys_changed` اعلان ندارند. routeها `#/dns/names?zone=<z>` و `#/dns/blocking`.
- **خانه:** `dns_secondary_problem` (error اگر expired، وگرنه warning؛ params `{zone, since, expired, error}`) و
  `dns_signing_problem` (error، `{zone, since, error}`)، مجوز `dns:read`، id `<rule>:<zone>`، حداکثر ۵ از هر کدام. منبع: cache
  ماژول از رویدادها + هر ۶۰ ثانیه `GET /v1/zones` (و برای secondary بدون `secondary` در خلاصه، `GET /v1/zones/{z}` تا ۵۰ زون):
  `secondary.expires_at` گذشته یا `expired:true` → expired؛ `secondary.error` → warning. مشکل امضا از رویداد می‌آید و تا
  خاموش شدن امضا (`dnssec.enabled:false` در نمای زون)، یا `dnssec.error` صریح، یا ۲۴ ساعت بی‌رویداد می‌ماند؛ حذف زون همه
  مشکل‌هایش را پاک می‌کند. درخواست خانه موتور را صدا نمی‌زند.

### 0.4 پنل

کد تازه: `dnsFinal.ts` (نوع‌ها، API و کلمات ساده §2–§5)، `dnsUi.tsx` (`useLoader`/`useList`/`FormDialog` مشترک، از
`DnsNames.tsx` بیرون آمد)، `DnsTemplates.tsx` (تب «قالب‌ها» + `TemplateChooser` + `ApplyTemplateDialog`)، `DnsZoneSync.tsx`
(«انتقال و همگام‌سازی» + کارت نسخه دوم + کلیدهای TSIG)، `DnsZoneSigning.tsx` («امضای امنیتی» هر زون)، `DnsFiltering.tsx`
(تب «مسدودسازی»)، `DnsBackup.tsx` (کارت «پشتیبان DNS» در تنظیمات)، `NewVersionBar.tsx`. تغییر: `DnsNames.tsx`، `DnsPage.tsx`،
`DnsSettings.tsx`، `DnsSectionSettings.tsx`، `dns.ts`، `dnsLive.ts`، `nav.ts`، `homeSummary.ts`، `RulesPanel.tsx`، `AppShell.tsx`
(فقط بخش بررسی نسخه، نه سربرگ/لوگو)، `copy/{audit,errors,confirm}.ts`، `copy/latin-allowlist.json`. بررسی: `npm run build` و
`npm run check:copy` سبز.

- **«دامنه‌ها» در حالت ساده:** کارت دامنه‌ها (و داخل هر دامنه: رکوردها و «امضای امنیتی») حالا در «ساده» هم هست و بالای «نام‌های من»
  آمده تا جریان قالب برای همه باشد. در «ساده» فقط نوع primary ساخته می‌شود؛ forwarder/secondary، خروجی فایل، وارد کردن، تاریخچه،
  `view` رکورد و تب «انتقال و همگام‌سازی» فقط «پیشرفته»اند.
- **ساخت دامنه:** فهرست قالب‌ها با `GET templates` و قالب `is_default` (یا `default_template_id`) از پیش انتخاب می‌شود؛ فقط
  متغیرهای غیرخودکار پرسیده می‌شوند (`domain`، `domain_dashed`، `server_ipv4/6` فقط در «پیشرفته» به‌عنوان جایگزین)، اگر preview
  هشدار `server_ipv4_unknown` بدهد خانه IPv4 در «ساده» هم ظاهر می‌شود. «این‌ها ساخته می‌شود» یک جمله ساده برای هر رکورد است: از
  `POST templates/{id}/preview` (debounce 450ms، با `zone` که هنوز وجود ندارد) و اگر نیامد از خود قالب (متغیر پرنشده «…»؛ `skipped`
  خط‌خورده). «بدون قالب» صریحاً `template_id: null` می‌فرستد (نفرستادن = پیش‌فرض، طبق §0.3)؛ اگر سرور قالب ندارد (404) هیچ کلیدی
  فرستاده نمی‌شود. اگر پاسخ ساخت `template.applied:false` باشد پیام «دامنه ساخته شد ولی رکوردهای قالب نه» نشان داده می‌شود.
  خطاهای `variables.<key>` کنار همان خانه.
- **اعمال روی دامنه موجود:** دکمه «افزودن رکوردهای یک قالب» (dns:write، نه secondary) → preview با برچسب تازه/از قبل هست/ناجور/
  ساخته نمی‌شود و `summary`. با تعارض، دکمه اعمال غیرفعال است تا کاربر کلید «جایگزین کن» (`replace_conflicts:true`) را بزند؛
  `replace_effects.removes`/`comments_dropped` نشان داده می‌شود.
- **صفحه قالب‌ها:** کارت‌ها (پیش‌فرض اول، برچسب «آماده»)، «دیدن» با دامنه نمونه، کپی (ویرایشگر با همان محتوا و نام «کپی …» که با
  `POST templates` بدنه کامل ذخیره می‌شود، نه `copy_from`)، ویرایش/حذف فقط غیر builtin، «پیش‌فرض شود» و «بدون قالب پیش‌فرض» با
  `PUT templates/default {template_id|null}` (اگر 404/405 بود، fallback به registry `dns.default_template_id`). ویرایشگر: رکوردها
  با فیلدهای نام‌دار همان RECORD_SPECS (فیلد عددی بدون `{…}` عدد فرستاده می‌شود)، پرسش‌ها، و در «پیشرفته» TTL/NS/SOA.
- **زون:** تب‌ها «رکوردها | انتقال و همگام‌سازی (پیشرفته) | امضای امنیتی (نه secondary)» با `?zone=<z>&ztab=sync|signing`.
  تنظیمات با `GET /zones/{z}` خوانده و هر کارت جدا با `PATCH` همان بخش (`transfer`، `notify` با `tsig_key`، `update`، `dnssec`،
  و برای secondary `primaries/tsig_key/notify_allow`) ذخیره می‌شود. اعتبارسنجی پنل: notify روشن بی‌هدف، update با «فقط با کلید»
  بی‌کلید، `refresh_days ≥ signature_validity_days`. الگوریتم امضا تا روشن است قفل است (`algorithm_locked`). DS ترجیحاً
  digest 2، چهار خانه کپی‌شدنی + رکورد کامل + راهنمای ۴ قدمی ثبت‌کننده؛ خاموش کردن با تأیید تایپی «تأیید» و دو جمله «DS را برداشته‌ام».
  رکوردهای secondary فقط‌خواندنی (بدون افزودن/تغییر/حذف/وارد کردن/تاریخچه) و کارت «نسخه دوم» (`secondary.expired|error|…`) با «همین
  حالا بگیر». `views` زون در پنل اعلام نمی‌شود (رکورد `view` بدون اعلام = override طبق §0.2)؛ انتخاب گروه رکورد از
  `settings.client_groups` (فقط dns:admin؛ وگرنه خانه متنی شناسه).
- **TSIG:** کارت «کلیدهای امضای انتقال» داخل تب همگام‌سازی (مشترک همه زون‌ها)، secret یک‌باره با `OneTimeSecret` و تنظیم آماده
  `key "…" {…}` برای سرور دیگر.
- **مسدودسازی (تب تازه `#/dns/blocking`، dns:read):** کارت وضعیت (`total_entries`، `blocked_1h`، «همین حالا به‌روز کن»)،
  «این دامنه چرا بسته شد؟» (`reason` → جمله؛ IP دستگاه فقط در «پیشرفته»)، کارت تنظیم `filtering` (dns:admin، از
  `DnsSectionSettings` با `config_version`)، دو پیشنهاد خاموش: StevenBlack hosts (`ads`) و URLhaus hostfile (`malware`)؛ افزودن
  اولین فهرست کلید اصلی را هم روشن می‌کند (هنوز تا «ذخیره» چیزی اعمال نمی‌شود). `action` فقط «پیشرفته». گروه‌های دستگاه فقط
  «پیشرفته»: نام، شناسه (خودکار)، شبکه‌ها، filtering، lists، upstreams؛ **`blocked_services` در پنل نیست** (`GET
  /v1/filtering/services` پروکسی ندارد). `DnsSectionSettings` حالا بخش آرایه‌ای (`client_groups`) را هم می‌پذیرد.
- **پشتیبان:** کارت در «تنظیمات DNS» (هر دو حالت)، دانلود blob با نام `Content-Disposition`، بازگردانی با تأیید تایپی «بازگردانی کن»
  (`CONFIRM_WORDS.restoreDns`) و بدنه خام `application/gzip` به `restore?confirmation=RESTORE`؛ `restart_required` → پیام «یک بار
  DNS را دوباره راه‌اندازی کنید».
- **لاگ/تست:** source `blocked` آخر `LOG_SOURCE_WORDS` و ستون نتیجه «مسدود (فهرست)»؛ `SOURCE_WORDS.blocked` برای تب تست.
- **اعلان/خانه:** چهار رویداد `dns.secondary_expired|transfer_failed|filter_list_failed|dnssec_signing_failed` در RulesPanel؛ قاعده‌های
  خانه با `{zone}` و route `#/dns/names?zone=<z>` (امضا: `&ztab=signing`). audit: `dns.template.*` (و `default`)، `dns.zone.
  apply_template|refresh|dnssec_rollover`، `dns.tsig.*`، `dns.filtering.refresh`، `dns.backup.download`، `dns.restore`.
- **نوار نسخه تازه:** `useBuildCheck` از `AppShell` به `NewVersionBar.tsx` رفت و **دیگر خودکار reload نمی‌کند** (قبلاً یک بار
  خودکار تازه می‌کرد): هر ۶۰ ثانیه وقتی تب دیده می‌شود `GET /api/v1/system/status` (`build.commit`/`ui_version` در برابر
  `VITE_BUILD_COMMIT`/package.json؛ build بی‌commit مقایسه commit را رد می‌کند) و برای نقش‌های بدون مجوز (403) مقایسه نام فایل
  اصلی `/assets/index-*.js` در `index.html` سرو شده. نوار «نسخه تازه پنل آمده» با «تازه کردن صفحه» و «بعداً». کلیدهای قدیمی
  `updating/updateFailed` در `i18n.ts` بی‌استفاده مانده‌اند (به‌خاطر کار هم‌زمان برند دست نخوردند).
- **allowlist:** brands `DS`, `Bing`, `YouTube`؛ parenthetical `TSIG`, `KSK`, `ZSK`, `CSK`.
- **بررسی‌شده در مرورگر** (با پاسخ‌های ساختگی چون بک‌اند در حال اجرا قدیمی بود): ساخت دامنه با قالب پیش‌فرض و قالب ایمیل، تب امضا با
  DS، تب مسدودسازی، صفحه قالب‌ها در عرض موبایل. با بک‌اند واقعی هنوز سرتاسری امتحان نشده.

## 1. هدف

- زون‌ها کامل حرفه‌ای شوند: secondary، انتقال زون، NOTIFY، TSIG، به‌روزرسانی پویا، امضای خودکار DNSSEC.
- مسدودسازی تبلیغات/بدافزار با فهرست‌ها، گروه‌های کلاینت و پاسخ جدا برای شبکه داخلی (split-horizon).
- سخت‌سازی و پشتیبان/بازگردانی.
- **قالب دامنه:** افزودن دامنه تازه بدون کار تکراری؛ رکوردهای پیش‌فرض خودکار ساخته شوند.
- پنل: ساده برای همه، پیشرفته برای حرفه‌ای‌ها؛ هیچ چیز اجباری نیست.

## 2. زون‌ها (موتور — بخش «زون»)

### 2.1 Secondary

- نوع زون تازه `secondary`: `{name, type:"secondary", primaries:["ip[:port]"…], tsig_key?, notify_allow?:[cidr]}`.
- دریافت با AXFR (TCP) و پس از آن IXFR (RFC 1995) با بازگشت به AXFR. رعایت SOA refresh/retry/expire؛ پس از expire پاسخ
  SERVFAIL. NOTIFY ورودی (RFC 1996) فقط از `primaries` یا `notify_allow` → refresh فوری.
- وضعیت: `GET /v1/zones/{z}` اضافه `secondary:{serial, last_refresh, last_success, next_refresh, expires_at, error?}`؛
  `POST /v1/zones/{z}/refresh` (فوری). رکوردهای secondary فقط‌خواندنی (`zone_read_only` 409).

### 2.2 انتقال خروجی و NOTIFY

- تنظیم هر زون primary: `transfer:{allow:[cidr], tsig_key?}` (پیش‌فرض خالی = بسته)، `notify:{targets:["ip[:port]"], enabled}`.
- AXFR و IXFR (با تاریخچه تغییر serial از history موجود؛ اگر نبود AXFR). پس از هر تغییر، NOTIFY به `targets` (تکرار با
  backoff تا 5 بار). سقف هم‌زمانی انتقال 10، اندازه پیام TCP 64KB.

### 2.3 TSIG

- `GET/POST/DELETE /v1/tsig` → کلیدها `{name, algorithm:"hmac-sha256"|"hmac-sha512", secret?}`؛ `secret` فقط در ساخت
  برگردانده می‌شود (موتور می‌سازد اگر داده نشد، 32 بایت base64). ذخیره 0600. در transfer، notify و update استفاده می‌شود.

### 2.4 به‌روزرسانی پویا (RFC 2136)

- هر زون primary: `update:{enabled:false, allow:[cidr], tsig_key?, require_tsig:true}`. پیش‌شرط‌ها، افزودن/حذف RRset،
  افزایش serial، ثبت در history با actor `update:<key|ip>`. رد → REFUSED/NOTAUTH مطابق RFC.

### 2.5 امضای خودکار DNSSEC

- هر زون primary: `dnssec:{enabled:false, algorithm:"ECDSAP256SHA256"|"ED25519", denial:"nsec"|"nsec3", nsec3:{iterations:0,
  salt:"", opt_out:false}, signature_validity_days:14, refresh_days:3}`.
- کلیدها KSK+ZSK در data dir (0600). امضای آنلاین/پیش‌محاسبه‌شده پس از هر تغییر؛ تمدید خودکار امضاها؛ DNSKEY/CDS/CDNSKEY.
- `GET /v1/zones/{z}/dnssec` → `{enabled, keys:[{tag, role, algorithm, created, state}], ds:[{digest_type, digest, text}],
  next_resign}`؛ `POST /v1/zones/{z}/dnssec/rollover {role:"zsk"|"ksk"}` (پیش‌انتشار ساده).
- خاموش‌کردن: هشدار در پنل که DS را اول از ثبت‌کننده دامنه حذف کنید.

## 3. سیاست و فیلترینگ (موتور — بخش «سیاست»)

### 3.1 فهرست‌های مسدودسازی

- بخش تنظیمات `filtering:{enabled:false, lists:[{id, name, url, format:"hosts"|"domains"|"adblock"|"rpz", enabled,
  update_hours:24}], allow:[name…], block:[name…], action:"nxdomain"|"null_ip"|"refuse", safe_search:false}`.
- موتور فهرست‌ها را دانلود می‌کند (HTTPS، سقف 50MB هر فهرست، 2M نام کل، timeout 60s، اگر نشد نسخه قبلی می‌ماند)، در
  ساختار فشرده (trie/پسوند) نگه می‌دارد، بدون توقف پاسخ‌دهی جایگزین می‌کند. `allow` همیشه برنده است.
- `GET /v1/filtering/status` → `{lists:[{id, entries, updated_at, error?}], total_entries, blocked_1h}`؛
  `POST /v1/filtering/refresh`؛ `POST /v1/filtering/check {name}` → `{blocked, list_id?, rule?}`.
- پیش‌فرض‌های پیشنهادی پنل (فقط پیشنهاد، خاموش): یک فهرست تبلیغات و یک فهرست بدافزار شناخته‌شده و رایگان.
- لاگ: source تازه `blocked` (در انتهای فهرست source)؛ آمار `blocked`.

### 3.2 گروه‌های کلاینت

- `client_groups:[{id, name, networks:[cidr], filtering:"inherit"|"on"|"off", lists?:[id], upstreams?:[id], blocked_services?:[]}]`.
  اولین گروه منطبق (ترتیب فهرست) اعمال می‌شود؛ بقیه = پیش‌فرض.

### 3.3 Split-horizon (views)

- هر زون می‌تواند `views:[{group_id, records_override?:true}]` داشته باشد: رکورد با فیلد اختیاری `view` (شناسه گروه یا
  خالی = همه). برای کلاینت آن گروه، رکوردهای `view` همان گروه بر رکوردهای عمومی همان نام/نوع اولویت دارند.

## 4. سخت‌سازی و پشتیبان (موتور — بخش «سیاست»)

- fuzz تازه برای: پارس انتقال زون، UPDATE، فهرست‌های فیلتر، پارس TSIG. همه fuzzها در CI.
- `GET /v1/backup` → یک فایل tar.gz (تنظیمات، زون‌ها، overrides، mitigations، کلیدهای TSIG/DNSSEC، توکن‌ها hash، گواهی) با
  manifest نسخه‌دار؛ `POST /v1/restore` (همان فایل؛ اعتبارسنجی کامل پیش از اعمال، اتمی، `restore_invalid` 422).
- رفع‌های کوچک: `tighten_client_qps` وقتی `client_qps=0` است سقف موقت معقول (مثلاً 1000) اعمال کند؛ cursor جست‌وجوی لاگ پس از
  حذف segment جابه‌جا نشود (cursor بر پایه ts+seq)؛ تست flaky `TestStrategiesAndHealth` پایدار شود.
- تست بار طولانی 10 دقیقه با mrk-dnsbench در CI اختیاری (job دستی).

## 5. قالب دامنه (بک‌اند + پنل)

- قالب: `{id, name, description, builtin, zone:{ttl, soa:{hostmaster?, refresh, retry, expire, minimum}, ns:[name…]},
  records:[{name, type, ttl?, data, comment?}], variables:[{key, label_fa, label_en, default?, required}]}`.
- متغیرها در `name` و `data`: `{domain}`، `{server_ipv4}`، `{server_ipv6}`، `{mail_host}`، `{dkim_value}` و متغیرهای خود قالب.
  `{server_ipv4/6}` از Host Agent/تنظیمات خودکار پر می‌شود.
- قالب‌های آماده (builtin، قابل کپی و ویرایش نسخه کپی): «وب‌سایت ساده» (A/AAAA @ و www)، «وب‌سایت + ایمیل» (MX، SPF، DMARC،
  CAA)، «Google Workspace»، «Microsoft 365»، «برنامه‌های Dokploy» (wildcard `*` به سرور)، «فقط امنیت» (CAA Let's Encrypt،
  SPF `-all`، DMARC reject برای دامنه بدون ایمیل).
- **قالب پیش‌فرض:** تنظیم `dns.default_template_id` (پیش‌فرض «وب‌سایت ساده»). ساخت زون تازه در پنل → قالب پیش‌فرض خودکار
  اعمال می‌شود (کاربر می‌تواند در همان پنجره قالب دیگر یا «بدون قالب» بزند).
- اعمال روی زون موجود: پیش‌نمایش (رکوردهای تازه / تکراری / متضاد) و سپس اعمال اتمی (یک change set، یک نسخه history).
- ذخیره: جدول تازه در پایگاه داده پنل (migration بعدی)؛ API: `GET/POST/PUT/DELETE /api/v1/dns/templates`، `POST
  /api/v1/dns/templates/{id}/preview {zone, variables}`، `POST /api/v1/dns/zones/{zone}/apply-template {template_id, variables}`،
  و `template_id`/`variables` اختیاری در `POST /api/v1/dns/zones`. مجوز: خواندن `dns:read`، تغییر قالب `dns:admin`، اعمال
  `dns:write`. audit: `dns.template.*`، `dns.zone.apply_template`.

## 6. API پنل برای §2–§4

- پروکسی همه routeهای تازه موتور زیر `/api/v1/dns/...` با مجوز: خواندن `dns:read`، تغییر زون/TSIG/update/DNSSEC زون
  `dns:write` (TSIG و backup/restore: `dns:admin`)، فیلترینگ و گروه‌ها `dns:admin`، `filtering/check` `dns:read`.
- اعتبارسنجی پیش از ارسال (`dns_settings_invalid`/`dns_zone_invalid` با fields). کلید TSIG و DNSSEC هرگز در audit/لاگ.
- اعلان‌ها: `dns.secondary_expired` (error)، `dns.transfer_failed` (warning)، `dns.filter_list_failed` (warning)،
  `dns.dnssec_signing_failed` (error). خانه: `dns_secondary_problem`، `dns_signing_problem`.

## 7. پنل

- **نام‌ها:** ساخت دامنه با انتخاب قالب (پیش‌فرض انتخاب‌شده) و پرکردن متغیرها؛ نوع «secondary» در پیشرفته؛ تب‌های هر زون:
  رکوردها، «انتقال و همگام‌سازی» (transfer/notify/update/TSIG)، «امضای امنیتی» (روشن/خاموش، DS آماده کپی با راهنمای ثبت‌کننده).
- **صفحه «قالب‌ها»** (زیر DNS): فهرست، ساخت/ویرایش/کپی، تنظیم قالب پیش‌فرض، پیش‌نمایش.
- **تب «مسدودسازی»:** کلید روشن/خاموش، فهرست‌ها با تعداد و زمان به‌روزرسانی، فهرست مجاز/مسدود، «این دامنه چرا بسته شد؟»،
  گروه‌های کلاینت (پیشرفته).
- **تنظیمات › پشتیبان DNS:** دانلود و بازگردانی با تأیید.
- **پیام نسخه تازه:** وقتی نسخه پنل روی سرور عوض شد (مقایسه نسخه build با `/health` یا هدر)، نوار «نسخه تازه آمده؛ صفحه را
  تازه کنید» با دکمه.
- همه متن‌ها در کاتالوگ fa/en، `check:copy` سبز.

## 7.1 پذیرش

- موتور: تست secondary/AXFR/IXFR/NOTIFY/TSIG/UPDATE در برابر خود موتور (primary↔secondary دو نمونه)، DNSSEC امضاشده که
  اعتبارسنج D4 خود موتور و `kdig`/`delv` آن را secure بداند، فیلترینگ و views، backup→restore رفت‌وبرگشت؛ `go test -race` و fuzzها.
- بک‌اند: pytest قالب‌ها (متغیر، پیش‌نمایش، اتمی بودن)، مجوزها، audit؛ ruff؛ validate_release.
- پنل: build و check:copy.

## 9. بیرون از محدوده (کار DNS بسته است)

DHCP، DNS Apps، cluster چندنودی، catalog zones، DNS cookies، ACME داخل موتور، DoH3.
