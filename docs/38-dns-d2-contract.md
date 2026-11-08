# 38 — قرارداد فاز D2 موتور DNS: لاگ پرس‌وجو، آمار و پایش بحرانی

وضعیت: **قرارداد مرجع D2 — 2026-11-08**. برنامه کلی: `docs/36` (§4 پایش، §5 لاگ). پایه: `docs/37` (D1، شامل §0.1 و §0.2
که معتبرند). هر سازنده اگر شکلی را تغییر داد در §0 همین سند ثبت کند.

## 0. تغییرات نسبت به قرارداد اولیه

### 0.1 بک‌اند (ماژول `dns`، D2، 2026-11-08)

کد: `modules/dns_logs.py` (routeهای D2)، `modules/dns_monitor.py` (حلقه پس‌زمینه)، `modules/dns_filters.py` (اعتبارسنجی
فیلتر/حذف/محدودسازی)، `modules/dns_validate.py` (بخش‌های querylog/stats/pressure تنظیمات)، `dns_client.py`
(`open_stream` + `EngineStream`)، قانون‌های خانه در `modules/home.py`. تست: `tests/test_dns_d2.py`. متغیر محیطی تازه‌ای اضافه نشد.

**مجوز هر route (`/api/v1/dns/...`):** `GET logs|logs/status|logs/stream|logs/export` = `dns:logs`؛ `DELETE logs` = `dns:admin`؛
`GET stats|pressure|events` = `dns:read`؛ `GET/POST mitigations` و `DELETE mitigations/{id}` = `dns:write`. همه DELETE/POST هدر CSRF
می‌خواهند. audit: `dns.logs.export` (object_id خلاصه فیلترها مثل `format=csv,client=10.0.0.1`)، `dns.logs.delete`
(`client=…,before=…` یا `all`)، `dns.mitigation.create` (`kind:match:action`)، `dns.mitigation.delete` (id)، و همان
`dns.settings.update`.

**فیلترهای لاگ** (query string؛ پنل به شکل canonical به موتور می‌فرستد):
`from`/`to` = عدد ms یا RFC3339 **با منطقه زمانی** (قبل از 2000 یا بیش از یک روز در آینده رد)، `from ≤ to`؛
`client` = IP یا CIDR (`10.0.0.7/24` → `10.0.0.0/24`)؛ `name` = زیررشته یا `*.example.com` (حروف کوچک، IDNA، نقطه آخر حذف)؛
`qtype` (A, AAAA, CNAME, MX, TXT, SRV, NS, PTR, CAA, SOA, ANY, HTTPS, SVCB, DS, DNSKEY, … یا `TYPEnnn`)؛
`rcode` (NOERROR, NXDOMAIN, SERVFAIL, REFUSED, FORMERR, NOTIMP, YXDOMAIN, YXRRSET, NXRRSET, NOTAUTH, NOTZONE, BADVERS)؛
`source` (enum §3)؛ `blocked` = `true|false|1|0`؛ `min_ms` 0..600000؛ `limit` 1..1000 (پیش‌فرض 100، فقط search)؛
`cursor` (فقط search، `^[A-Za-z0-9_\-=.:~+/]{1,512}$`)؛ `format` = `ndjson|csv` (فقط export، پیش‌فرض ndjson) و `limit` export
1..1,000,000. پارامتر `_` نادیده گرفته می‌شود؛ پارامتر ناشناخته یا تکراری رد می‌شود. stream فقط فیلترها را می‌پذیرد.
خطا: **`dns_query_invalid`** 422 با `fields:[{field, reason_code, params?}]` (`unknown_field`, `duplicate`, `invalid_time`,
`after_to`, `invalid_client`, `invalid_name`, `invalid_choice`, `invalid_type`, `out_of_range`, `invalid_format`).

**شکل پاسخ‌ها:**
- `GET logs` و `GET logs/status`: پاسخ موتور عیناً (§3).
- `GET logs/stream` → `text/event-stream` (EventSource، پیام‌های **بی‌نام**، فقط `onmessage`). اول `retry: 5000`، سپس هر فریم
  `data: <json>\n\n` با `type`: `hello` | `entry` (رکورد تخت: `{type:"entry", ts, client, proto, name, qtype, rcode, source,
  upstream?, ms, size, flags}`) | `sampled` (`{type, skipped}`) | `ping`؛ و در پایان یکی از
  `{type:"end", reason:"engine_closed"|"max_seconds"|"max_bytes"}` (پنل دوباره وصل شود) یا
  `{type:"error", code:"dns_unreachable", reason}`. اگر موتور 15 ثانیه چیزی نفرستد کامنت `: keep-alive`. سقف هر جریان 30 دقیقه
  و 512MiB. با قطع اتصال مرورگر، اتصال به موتور فوراً بسته می‌شود. حداکثر **3 جریان هم‌زمان برای هر کاربر و 20 در کل**؛ بیشتر →
  **`dns_stream_limit`** 429 با `scope:"user"|"global"` و `limit`. خطاهای پیش از شروع (نصب‌نبودن، موتور، فیلتر) JSON معمولی‌اند.
- `GET logs/export` → جریان دانلود با `Content-Disposition: attachment; filename="mrk-dns-logs-YYYYMMDD-HHMMSS.csv|ndjson"`،
  نوع `text/csv; charset=utf-8` یا `application/x-ndjson`. سقف 15 دقیقه و 2GiB (در سقف، فایل کوتاه می‌شود). حداکثر 1 export
  هم‌زمان برای هر کاربر و 3 در کل (`dns_stream_limit`).
- `DELETE logs` بدنه `{client?, before?, confirmation}`؛ `before` عدد ms یا RFC3339 (به موتور ms می‌رود)؛ `confirmation` =
  `"DELETE LOGS"`، یا اگر `client` داده شده IP همان کلاینت. نادرست → `confirmation_mismatch` 422 با `expected_confirmation`
  (IP کلاینت یا `"DELETE LOGS"`). پاسخ موتور عیناً `{deleted_segments, rewritten_segments, deleted_rows}`.
- `GET stats?range=1h|6h|24h|7d|30d|1y` (پیش‌فرض `24h`) → پاسخ موتور + `top_hidden`. بدون `dns:logs`:
  `top:{domains:[], clients:[], nxdomain:[], refused_clients:[]}` و `top_hidden:true`.
- `GET pressure` → پاسخ موتور با `hot` بازنویسی‌شده: با `dns:logs` `hot:{domains:[…], clients:[…], attacks:[…], hidden:false}`؛
  بدون آن **فقط شمار** `hot:{domains:<n>, clients:<n>, attacks:<n>, hidden:true}`. همین پاسخ cache خانه را هم تازه می‌کند.
- **تازه:** `GET events?after=<seq>` (dns:read) → `{items:[{seq, ts, type, severity, data, hidden}], next}` (پروکسی
  `/v1/events`). بدون `dns:logs` کلیدهای `parent, top_clients, match, client, clients, name, names, domains` از `data` حذف و
  `hidden:true` می‌شود (اگر چیزی حذف شد). `after` عدد صحیح ≥0؛ پارامتر دیگر → `dns_query_invalid`.
- `GET mitigations` → پاسخ موتور عیناً. `POST mitigations` بدنه `{kind:"client"|"domain", match, action:"throttle"|"block"|"refuse",
  qps?, minutes, reason?}`: `client` = IP/CIDR canonical (`/0` رد: `too_broad`)؛ `domain` = نام (`*.` اول حذف، IDNA، حروف کوچک)؛
  `minutes` 1..10080؛ `qps` 1..1,000,000 **فقط و الزاماً** برای `throttle` (`only_for_throttle`)؛ `reason` ≤200 نویسه؛ فیلد
  ناشناخته رد. خطا **`dns_mitigation_invalid`** 422 + fields. `DELETE mitigations/{id}` → `{deleted:id}`؛ نبود →
  `dns_mitigation_not_found` 404 (کد موتور `mitigation_not_found`). کدهای موتور `limit_reached`/`not_found`/`invalid_request`/
  `querylog_disabled`/`query_invalid` به `dns_<code>` نگاشت می‌شوند (موتور لطفاً همین نام‌ها را بدهد).

**تنظیمات** (`PUT settings`، پیش از ارسال؛ خطا `dns_settings_invalid` + fields): `querylog.enabled` bool، `mode` enum،
`sample_percent` 1..100، `max_age_days` 1..365، `max_bytes` 64MiB..1TiB، `min_free_disk_percent` 1..50، `client_ip` enum،
`exclude_names` ≤1000 نام (`*.` مجاز)، `exclude_clients` ≤1000 IP/CIDR، `stream_max_eps` 1..10000؛
`stats.minute_retention_hours` 1..168، `hour_retention_days` 1..365، `day_retention_days` 1..3650، `top_k` 10..1000؛
`pressure.enabled` bool، `capacity_qps` 100..10,000,000، `dwell_seconds` 5..3600، `exit_margin_percent` 0..50؛ آستانه‌ها
`cpu|memory|host_cpu|host_memory` 1..100 و `qps_percent` 1..1000 (عدد صحیح یا اعشاری)، سطح/سنجه ناشناخته `unknown_field`، و
برای هر سنجه warning ≤ critical ≤ emergency (`below_lower_level`)؛ `actions.*` bool؛ `attack_detection.mode` enum،
`nxdomain_unique_per_minute` 10..1,000,000، `mitigation_minutes` 1..10080. کلیدهای ناشناخته دیگر را موتور بررسی می‌کند.

**حلقه پس‌زمینه** (فقط وقتی socket هست؛ اگر موتور جواب ندهد backoff 10، 20، … تا 60 ثانیه): هر 5 ثانیه
`GET /v1/events?after=<seq>` (بار اول بعد از شروع پنل فقط cursor را روی `next` می‌گذارد و چیزی منتشر نمی‌کند؛ اگر `next`
موتور از cursor کمتر شد = موتور restart شده و cursor صفر می‌شود؛ پنل `next` را «بزرگ‌ترین seq» می‌گیرد)؛ هر 10 ثانیه
`GET /v1/pressure` (cache خانه، معتبر 60 ثانیه)؛ هر 10 ثانیه `POST /v1/host-metrics {cpu_percent, memory_percent, load1, ts}`
از آخرین نمونه Host Agent (ماژول monitoring؛ **`ts` به میلی‌ثانیه unix**؛ نمونه قدیمی‌تر از 60 ثانیه فرستاده نمی‌شود).

**اعلان‌ها** (Event در مرکز اعلان، `module:"dns"`):
- `dns.pressure`: از `pressure.level` با `data.level` (یا `data.to`)؛ critical → `warning`، emergency → `error`، برگشت به normal →
  `info` (فقط اگر قبلاً critical/emergency اعلام شده)؛ سطح warning اعلان ندارد (فقط خانه). dedupe `dns.pressure.<level>`؛
  details `{level, previous, reasons:[{metric, value, threshold}], route:"#/dns/monitor"}`.
- `dns.attack_detected` (warning) از `attack.detected` (`data.parent`, `unique_nxdomain_per_min`, `top_clients`, `mitigation_id?`)؛
  dedupe `dns.attack.<parent>`؛ details بدون IP: `{parent, unique_nxdomain_per_min, clients:<شمار>, mitigation_id, route}`.
- `dns.mitigation_auto` (warning) از `mitigation.auto` (`data.id, kind, match, action, expires_at, reason`)؛ dedupe
  `dns.mitigation_auto.<kind>.<match>`. `mitigation.expired` اعلان ندارد.
- `dns.logs_degraded` (warning) / `dns.logs_recovered` (info) از `querylog.degraded|recovered` (`data.reason` مثل
  `disk_low`/`max_bytes`، `data.mode_effective`)؛ dedupe همان نام‌ها، route `#/dns/logs`.
- همه این‌ها در پنل هم 5 دقیقه dedupe حافظه‌ای دارند و در هر دور حداکثر 20 اعلان.

**خانه:** `dns_under_pressure` (مجوز `dns:read`، warning برای warning/critical، critical برای emergency، params
`{level, since, reasons:[نام سنجه‌ها، حداکثر 5]}`) و `dns_attack_detected` (مجوز `dns:read`، warning، یک آیتم برای هر parent تا 5،
id `dns_attack_detected:<parent>`، params `{parent, since}`)، هر دو مسیر `#/dns/monitor`، فقط وقتی موتور reachable است و
cache فشار تازه (≤60 ثانیه) است. درخواست خانه هیچ‌وقت موتور را صدا نمی‌زند. توجه: `parent` (دامنه هدف حمله، نه کلاینت)
در خانه برای `dns:read` دیده می‌شود.

### 0.2 موتور (`apps/dns-engine`، D2، 2026-11-09)

کد: `internal/querylog` (ring، segment، WAL، جست‌وجو، جریان، حریم خصوصی، محافظ دیسک)، `internal/stats` (شمارنده‌ها، دقیقه/ساعت/روز،
top-k)، `internal/pressure` (نمونه‌گیر CPU/حافظه، کنترل‌گر سطح، اقدام‌ها، hot ده‌ثانیه‌ای)، `internal/attack` (تشخیص)، `internal/mitigate`
(محدودسازی‌ها)، `internal/events`، `internal/topk` (Space-Saving)، `internal/hll` (HyperLogLog)، چسب در `internal/engine/monitor.go`،
API در `internal/admin/monitor.go`. وابستگی تازه: `github.com/klauspost/compress v1.20.3` (zstd، BSD-3-Clause). همه مقادیر §0.1
پنل پذیرفته می‌شوند؛ موتور در چند جا آسان‌گیرتر است (پایین).

**مسیر داغ و ذخیره:**
- هر پاسخ (و هر رد/حذف) یک رکورد ثابت (بدون allocation، تست `AllocsPerRun == 0`) در ring چند-shard بدون قفل (صف Vyukov، 2×GOMAXPROCS
  shard، جمعاً ≥65536 خانه) و شمارنده‌های sharded آمار. پر شدن ring = رکورد دور ریخته و در `dropped_total` شمرده می‌شود. goroutine جدا هر
  50ms تخلیه، بر اساس زمان مرتب، و به آمار/hot/تشخیص حمله/لاگ می‌دهد.
- دیسک: `<data_dir>/querylog/` — `NNNNNNNNNNNNNNNN.seg` (ستونی، دیکشنری نام/کلاینت/upstream به ازای segment، varint، zstd، index در
  انتهای فایل: بازه زمان، شمار rcode/source، Bloom پسوندها+برچسب‌های نام و کلاینت؛ CRC32C؛ temp+fsync+rename)، `active-<seq>.wal` (دسته‌های
  فشرده با CRC، fsync هر ثانیه؛ پس از crash پیشوند سالم به segment تبدیل می‌شود)، `hash.key` (32 بایت، 0600). segment در 131072 ردیف یا
  5 دقیقه بسته می‌شود. نگهداری هر دقیقه بر اساس `max_age_days` و `max_bytes` (قدیمی‌ترین اول). آمار: `<data_dir>/stats/stats.json.zst`
  (هر دقیقه، اتمیک). محدودسازی‌ها: `<data_dir>/mitigations.json`.
- `errors_only` = هر rcode غیر از NOERROR/NXDOMAIN، به‌علاوه همه `refused|rate_limited|mitigated`. `blocked=true` همین سه source است.
- حریم خصوصی پیش از ذخیره (و در top آمار و جریان): `full` IP؛ `mask` → `/24` و `/48` (مثلاً `192.168.7.0`)؛ `hash` →
  `h:<16 hex>` (HMAC-SHA256 با `hash.key`)؛ `none` → `""`. فیلتر/حذف با IP واقعی خودکار به همان شکل تبدیل می‌شود (در `none` هیچ ردیفی).
  `exclude_names` پسوند است (`example.com` شامل زیردامنه‌ها).
- محافظ دیسک (statfs هر 10 ثانیه و هنگام شروع): آزاد < `min_free` → `errors_only` (`reason:"disk_low"`)، < نصف آن → `off`
  (`"disk_critical"`)، برگشت با 2 واحد hysteresis. خطای نوشتن → `"write_error"`. فشار `mode_effective` را هم پایین می‌آورد (reason
  `"pressure"` در status) ولی رویداد `querylog.degraded` نمی‌سازد (رویداد آن `pressure.level` است). رسیدن به `max_bytes` حذف عادی
  قدیمی‌ترین‌هاست، **degraded نیست** (کد `max_bytes` از موتور نمی‌آید).

**API (همه با توکن D1):**
- `GET /v1/querylog` → دقیقاً §3. `ts` = RFC3339 UTC با میلی‌ثانیه، `ms` عدد اعشاری، `upstream` فقط اگر هست، `next_cursor` در پایان
  `null`، cursor رشته opaque (`base64url`). ترتیب: جدیدترین اول بر اساس زمان رسیدن (رکوردهای مسیر کند تا ~50ms ممکن است جابه‌جا باشند).
  `qtype` نام یا عدد؛ `rcode` نام یا عدد 0..15. خطای فیلتر: **`query_invalid` 422** + `fields` (`invalid_time`, `after_to`,
  `invalid_client`, `invalid_name`, `invalid_type`, `invalid_rcode`, `invalid_choice`, `invalid_bool`, `invalid_number`, `out_of_range`,
  `invalid_cursor`, `too_long`). بودجه اسکن 2 ثانیه → `truncated:true` و `next_cursor` ادامه می‌دهد.
- `GET /v1/querylog/stream` → NDJSON: `{type:"hello", max_eps, mode_effective}`، `{type:"entry", …همان item}`، `{type:"sampled", skipped}`
  (هر ثانیه اگر به خاطر `stream_max_eps` یا کندی خواننده چیزی رد شد)، `{type:"ping"}` هر 15 ثانیه سکوت. حداکثر **20** جریان هم‌زمان
  (مطابق سقف کل پنل) → `too_many_streams` 429. اگر `querylog.enabled=false` یا `mode:"off"` → **`querylog_disabled` 409**. جریان
  ردیف‌ها را پس از exclude و حریم خصوصی می‌بیند حتی وقتی ذخیره به خاطر دیسک/فشار کم شده است.
- `GET /v1/querylog/export?…&format=ndjson|csv&limit=1..1000000` (`limit` در export سقف ردیف است، پیش‌فرض 1,000,000). ستون‌های CSV:
  `ts,client,proto,name,qtype,rcode,source,upstream,ms,size,tc,stale,cached`. نام فایل `dns-log-YYYYMMDD-HHMMSS.*` (پنل نام خودش را می‌گذارد).
- `DELETE /v1/querylog {client?, before?}` (`before` عدد ms، رشته عددی یا RFC3339؛ بدنه خالی = همه) → `{deleted_segments,
  rewritten_segments, deleted_rows}`؛ segmentهای جزئی اتمیک بازنویسی می‌شوند.
- `GET /v1/querylog/status` → §3 به‌علاوه `sample_percent_effective`, `rows`, `streams`؛ `oldest_ts` و `disk_free_percent` اگر نامعلوم
  `null`؛ `degraded_reason` فقط وقتی هست: `disk_low|disk_critical|write_error|pressure`.
- `GET /v1/stats?range=` (پیش‌فرض موتور `1h`؛ پنل `24h` می‌فرستد) → §3 به‌علاوه `from`, `to` و در `totals`: `p50_ms, p95_ms, p99_ms,
  cache_hit_ratio`. وضوح: `1h`=60s (60 نقطه)، `6h`=300s، `24h`=900s (96)، `7d`=3600s (168)، `30d`=21600s (120)، `1y`=86400s (365)؛ همه
  نقطه‌ها (حتی خالی) برمی‌گردند و نقطه آخر شامل دقیقه جاری است. `by_rcode` همیشه `NOERROR,NXDOMAIN,SERVFAIL,REFUSED` و هر کد غیرصفر دیگر؛
  `by_source` هر هشت source؛ `by_qtype` کلیدهای A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, ANY, HTTPS, SVCB, CAA, DS, DNSKEY, OTHER.
  `cache_hit_ratio` = cache / (cache + upstream + forwarder). top با Space-Saving (هر دقیقه 4×top_k شمارنده)؛ فهرست‌های دقیقه‌ای 6 ساعت،
  ساعتی 7 روز، روزانه به اندازه `day_retention_days` نگه داشته می‌شوند (بازه طولانی top را از سطح درشت‌تر می‌خواند). کلاینت‌های top
  به شکل حریم خصوصی لاگ‌اند.
- `GET /v1/pressure` → §3 به‌علاوه `enabled`؛ `metrics.host_load1` اضافه؛ `metrics.host_*` و `host_metrics_at` فقط اگر نمونه ≤60 ثانیه
  هست؛ `reasons` = سنجه‌هایی که بالای (آستانه سطح فعلی − margin) هستند. `hot.domains[{name,qps}]`، `hot.clients[{client,qps,share}]`
  (`client` = IPv4 یا `prefix/64` برای IPv6 — همان شکلی که برای `POST mitigations` کار می‌کند؛ hot حریم خصوصی ندارد چون برای اقدام لازم
  است و ذخیره نمی‌شود)، `hot.attacks[{kind:"random_subdomain"|"nxdomain_flood", parent?, client?, unique_nxdomain_per_min,
  nxdomain_per_min, top_clients, since, mitigation_id?}]` (برای `nxdomain_flood` به‌جای `parent`، `client` پر است).
- `POST /v1/host-metrics {cpu_percent, memory_percent, load1?, ts?}` (`ts`: ms unix — هر عدد >1e11 ms است، کوچک‌تر ثانیه — یا RFC3339؛
  نبود = اکنون) → `{accepted:bool}`؛ قدیمی‌تر یا جلوتر از 60 ثانیه `accepted:false`. درصد خارج از 0..100 → `invalid_request` 400.
- `GET /v1/mitigations` → `{items:[…]}` جدیدترین اول؛ `POST` → 201 همان آیتم. `match` کلاینت canonical CIDR (`10.1.2.3` → `10.1.2.3/32`)،
  دامنه حروف کوچک بدون `*.` و نقطه آخر. همان `kind+match` آیتم قبلی را جایگزین می‌کند. `minutes` 1..525600، `reason` ≤256، `qps` برای غیر
  throttle نادیده (0). خطا: `mitigation_invalid` 422 (+fields: `invalid_network`, `too_broad`, `invalid_name`, `invalid_choice`,
  `out_of_range`, `too_long`)، `limit_reached` 409 (10000)، `mitigation_not_found` 404. `DELETE` → 204.
- `GET /v1/events?after=<seq>&limit=1..1000` → `{items, next}`؛ `next` = بزرگ‌ترین seq برگشته (اگر چیزی نبود همان `after`؛ با `after=0`
  و ring خالی seq فعلی). seq از `unix_ms×1000` هنگام شروع موتور شروع می‌شود، پس بعد از restart هم بزرگ‌تر می‌ماند؛ `after` بزرگ‌تر از
  آخرین seq (ساعت عقب رفته) = همه رویدادهای موجود.

**رویدادها (`data`):**
- `pressure.level`: `{level, to, from, reasons:[{metric,value,threshold}], actions:[…], metrics:{…}}`؛ severity: برگشت به normal `info`،
  warning `warning`، critical `error`، emergency `critical`.
- `attack.detected` (warning): `{kind, parent, client, unique_nxdomain_per_min, nxdomain_per_min, top_clients, since, mode, mitigation_id?}`
  (در حالت auto محدودسازی اول ساخته می‌شود تا `mitigation_id` در همین رویداد باشد). هر حمله یک بار در شروع.
- `mitigation.auto` (warning): `{id, kind, match, action, qps, minutes, expires_at, reason, source:"auto", attack, parent}`.
- `mitigation.expired` (info): `{id, kind, match, action, qps, minutes, expires_at, source, hits}`.
- `querylog.degraded` (warning؛ `disk_critical`/`write_error` = error): `{reason, mode_effective, disk_free_percent}`؛
  `querylog.recovered` (info): `{mode_effective, disk_free_percent, previous_reason}`.

**فشار:** نمونه هر ثانیه: CPU از cgroup v2 `cpu.stat` نسبت به سهم `cpu.max` (بدون cgroup: getrusage نسبت به GOMAXPROCS)، حافظه Go
نسبت به GOMEMLIMIT (بدون آن `memory.current/memory.max`)، `qps_percent` = qps یک‌ثانیه‌ای / `capacity_qps`. بالا رفتن: دو نمونه پشت هم
بالای آستانه ورود (مستقیم به بالاترین سطح نقض‌شده). پایین آمدن: یک سطح در هر بار، وقتی همه سنجه‌ها `dwell_seconds` پیوسته زیر (آستانه
سطح فعلی − `exit_margin_percent` واحد) بوده‌اند. آستانه 0 = آن سنجه برای آن سطح خاموش. اقدام‌ها (هر کدام با کلید خودش):

| سطح | اقدام‌ها |
|---|---|
| warning | `log_sampling` (نمونه 25٪)، `disable_prefetch`، `minimal_any` (پاسخ RFC 8482 روی همه transportها) |
| critical | + لاگ `errors_only`، `prefer_stale` (stale فوری و تازه‌سازی پس‌زمینه)، `tighten_client_qps` ×0.5، `refuse_heavy_clients` |
| emergency | + لاگ `off`، `tighten_client_qps` ×0.25 |

`tighten_client_qps` فقط روی `limits.client_qps/burst` تنظیم‌شده اثر دارد (0 = نامحدود می‌ماند). کلاینت «سنگین» در 10 ثانیه اخیر: سهم
≥20٪ کل **و** ≥ max(50، 2٪ `capacity_qps`) qps، غیر loopback؛ فقط برای recursion REFUSED می‌گیرد (source `mitigated`)، داده
authoritative را می‌گیرد. با پایین آمدن سطح همه برمی‌گردند.

**حمله:** parent = نام بدون برچسب اول، با حداقل دو برچسب (`x.victim.example` → `victim.example`). HyperLogLog (p=10) در 6 زیرپنجره 10
ثانیه‌ای، حداکثر 256 parent (Space-Saving). شروع وقتی یکتاهای NXDOMAIN یک دقیقه ≥ آستانه، پایان وقتی < نصف آن. NXDOMAIN flood یک کلاینت:
≥ 2×آستانه NXDOMAIN در دقیقه. `auto`: random_subdomain → محدودسازی دامنه `throttle` با `qps = max(20, آستانه/30)`؛ nxdomain_flood →
کلاینت `throttle` 20 qps؛ مدت `mitigation_minutes`؛ اگر کاربر برای همان هدف محدودسازی دارد دست نمی‌خورد.

**محدودسازی در مسیر پرسش** (پس از ACL، پیش از rate limit): کلاینت (longest-prefix در trie): `block`/`refuse` → REFUSED (EDE 18)،
`throttle` → سطل مشترک همان آیتم، اضافه‌ها UDP دور ریخته / TCP REFUSED. دامنه (عمیق‌ترین پسوند): `block` → NXDOMAIN ساختگی (EDE 15)،
`refuse` → REFUSED، **`throttle` فقط کار upstream را محدود می‌کند** (cache همیشه پاسخ می‌دهد؛ اضافه‌ها stale اگر هست وگرنه REFUSED)؛ پس
`hits` throttle دامنه فقط پرسش‌های بدون cache را می‌شمارد. source همه `mitigated`.

**تنظیمات (موتور):** بازه‌ها مثل §0.1 با این تفاوت‌ها (موتور آسان‌گیرتر): `max_age_days` 1..3650، `max_bytes` 16MiB..4TiB،
`hour_retention_days` 1..730، `dwell_seconds` 1..3600، آستانه 0..100 (`qps_percent` 0..1000، 0 = خاموش). ترتیب صعودی سطوح با
`below_lower_level` (برابر مجاز). نبود بخش‌های D2 در `settings.json` قدیمی با پیش‌فرض‌ها پر می‌شود؛ `config_version` همان رفتار D1؛ همه
بخش‌ها بدون restart اعمال می‌شوند.

**Prometheus تازه:** `mrk_dns_querylog_written_total`, `mrk_dns_querylog_dropped_total`, `mrk_dns_querylog_bytes`,
`mrk_dns_pressure_level`, `mrk_dns_mitigations`، sourceهای `mitigated`/`rate_limited` و drop `mitigation`. اصلاح D1: شمارش TC در
مسیر سریع بیت اشتباه را می‌خواند.

**سنجش (Docker Desktop، 4 هسته، موتور `--cpus 2 --memory 512m`، تولیدکننده `--cpus 2`، 20 نام cache):** اشباع c=64/window=16، چهار دور
یک‌درمیان: لاگ `off` میانه ≈87k qps، لاگ `all` میانه ≈94k qps (نوسان ±15٪ بین دورها؛ کاهش قابل اندازه‌گیری نیست)، p99 30–60ms در اشباع؛
11.6M ردیف نوشته، 3915 (0.03٪) در اشباع از ring جا ماند؛ ~1.6 بایت/ردیف روی دیسک برای این ترافیک یکنواخت (9 بایت/ردیف برای ترافیک
متنوع). جست‌وجو روی 5M ردیف (36 segment، 43MiB): صفحه اول 11ms، فیلتر پسوند نادر یا IP نادر 16–18ms سرد (Bloom 35 از 36 segment را
رد کرد)، CIDR/بازه زمانی ~13ms، بدترین حالت (زیررشته ناموجود، اسکن کامل) 0.54s. آزمون بار: `capacity_qps` 20000، سیل 46k qps از یک
کلاینت → emergency در 2 ثانیه با هر شش اقدام؛ سیل REFUSED/محدود شد (23k پاسخ REFUSED در ثانیه، باقی دور ریخته)، کلاینت عادی 100 qps
**7000/7000 NOERROR** (p50 0.35ms، p99 34ms)، حافظه 72→83MiB ثابت؛ بعد از سیل emergency→critical→warning→normal هر کدام پس از 10 ثانیه
dwell. random-subdomain 2000 qps روی زون محلی → `attack.detected` + دو `mitigation.auto` (دامنه و کلاینت) در اولین ارزیابی.

## 1. اصول

- **مسیر داغ هرگز منتظر لاگ نمی‌ماند.** هر پاسخ یک رکورد کوچک در ring buffer بدون قفل (shard به ازای هسته)؛ اگر پر شد رکورد
  دور ریخته و شمرده می‌شود (`dropped_total`). نوشتن، فشرده‌سازی و index در goroutine جدا.
- **هیچ‌وقت دیسک را پر نمی‌کند:** سقف حجم و سن، و اگر فضای آزاد دیسک کمتر از حد شد، ذخیره کامل خودکار به «فقط خطاها» و بعد
  «خاموش» می‌رود (با رویداد) و با برگشت فضا برمی‌گردد.
- **حریم خصوصی قابل تنظیم:** IP کلاینت کامل / ماسک‌شده (/24 و /48) / hash با کلید محلی / هیچ؛ فهرست نام‌ها و کلاینت‌هایی که
  لاگ نمی‌شوند.
- **پایش چندسطحی با hysteresis:** ورود به سطح بالاتر با آستانه ورود، خروج با آستانه پایین‌تر و حداقل ماندن (dwell) تا نوسان نکند.
- **اقدام خودکار قابل برگشت و قابل خاموش کردن** و هر اقدام ثبت و اعلان می‌شود.

## 2. تنظیمات تازه در `GET/PUT /v1/settings` موتور (همان شیء D1، بخش‌های جدید)

```
querylog: {enabled:true, mode:"all"|"sample"|"errors_only"|"off", sample_percent:100,
           max_age_days:7, max_bytes:2147483648, min_free_disk_percent:10,
           client_ip:"full"|"mask"|"hash"|"none", exclude_names:[], exclude_clients:[], stream_max_eps:200},
stats:    {minute_retention_hours:48, hour_retention_days:90, day_retention_days:400, top_k:100},
pressure: {enabled:true, capacity_qps:50000, dwell_seconds:30,
           thresholds:{warning:{cpu:70, memory:75, qps_percent:70, host_cpu:85, host_memory:90},
                       critical:{cpu:85, memory:85, qps_percent:90, host_cpu:92, host_memory:95},
                       emergency:{cpu:95, memory:95, qps_percent:110, host_cpu:97, host_memory:98}},
           exit_margin_percent:10,
           actions:{log_sampling:true, disable_prefetch:true, prefer_stale:true, tighten_client_qps:true,
                    refuse_heavy_clients:true, minimal_any:true},
           attack_detection:{mode:"off"|"suggest"|"auto", nxdomain_unique_per_minute:500, mitigation_minutes:30}}
```
پیش‌فرض `attack_detection.mode` = `"suggest"` (پیشنهاد با اعلان، بدون اقدام خودکار). اعتبارسنجی با `fields` مثل D1.

## 3. API موتور (همان unix socket و توکن D1)

- `GET /v1/querylog?from&to&client&name&qtype&rcode&source&blocked&min_ms&limit&cursor` (زمان‌ها ms یا RFC3339؛ `name`
  زیررشته یا پسوند `*.example.com`؛ `client` IP یا CIDR؛ `limit` ≤ 1000، پیش‌فرض 100؛ جدیدترین اول) →
  `{items:[{ts, client, proto:"udp"|"tcp"|"dot"|"doh", name, qtype, rcode, source:"authoritative"|"override"|"cache"|"upstream"|
  "refused"|"rate_limited"|"mitigated"|"forwarder", upstream?, ms, size, flags:{tc, stale, cached}}], next_cursor, scanned_segments,
  truncated}` (`truncated`=true اگر سقف زمان اسکن 2 ثانیه رسید).
- `GET /v1/querylog/stream?<همان فیلترها>` → NDJSON chunked (`{type:"hello"}`، سپس `{type:"entry", …}`، heartbeat هر 15 ثانیه
  `{type:"ping"}`؛ بیش از `stream_max_eps` نمونه‌برداری و `{type:"sampled", skipped}`).
- `GET /v1/querylog/export?<فیلترها>&format=ndjson|csv` → جریان، حداکثر 1,000,000 ردیف.
- `DELETE /v1/querylog {client?, before?}` (هیچ‌کدام = همه) → `{deleted_segments, rewritten_segments, deleted_rows}`.
- `GET /v1/querylog/status` → `{enabled, mode, mode_effective, degraded_reason?, bytes, segments, oldest_ts, written_total,
  dropped_total, disk_free_percent}`.
- `GET /v1/stats?range=1h|6h|24h|7d|30d|1y` → `{range, resolution_seconds, points:[{ts, queries, qps, p50_ms, p95_ms, p99_ms,
  cache_hit_ratio, by_rcode:{NOERROR,NXDOMAIN,SERVFAIL,REFUSED,…}, by_source:{…}}], totals:{queries, by_rcode, by_source, by_qtype},
  top:{domains:[{name,count}], clients:[{client,count}], nxdomain:[{name,count}], refused_clients:[{client,count}]}}`
  (آمار مستقل از لاگ: حتی با لاگ خاموش ثبت می‌شود؛ top با الگوریتم Space-Saving).
- `GET /v1/pressure` → `{level:"normal"|"warning"|"critical"|"emergency", since, reasons:[{metric, value, threshold}],
  metrics:{cpu_percent, memory_percent, qps, qps_percent, inflight_upstream, drops_1m, host_cpu_percent?, host_memory_percent?,
  host_metrics_at?}, active_actions:[…نام اقدام‌ها], hot:{domains:[{name,qps}], clients:[{client,qps}],
  attacks:[{parent, unique_nxdomain_per_min, top_clients:[…], since, mitigation_id?}]}}`
- `POST /v1/host-metrics {cpu_percent, memory_percent, load1, ts}` (پنل هر 10 ثانیه از Host Agent می‌فرستد؛ قدیمی‌تر از 60
  ثانیه نادیده).
- محدودسازی دستی/خودکار: `GET /v1/mitigations`، `POST /v1/mitigations {kind:"client"|"domain", match, action:"throttle"|"block"|
  "refuse", qps?, minutes, reason?}`، `DELETE /v1/mitigations/{id}` → آیتم: `{id, kind, match, action, qps, created_at, expires_at,
  source:"user"|"auto", reason, hits}`. `match` کلاینت IP/CIDR؛ دامنه پسوند (`example.com` شامل زیردامنه‌ها). حداکثر 10000؛
  منقضی‌ها خودکار حذف. ترتیب پاسخ: ACL ← mitigation ← محدودیت نرخ ← بقیه. `block` = REFUSED برای کلاینت / NXDOMAIN ساختگی
  برای دامنه؛ `throttle` = سقف qps.
- `GET /v1/events?after=<seq>` → `{items:[{seq, ts, type:"pressure.level"|"attack.detected"|"mitigation.auto"|"mitigation.expired"|
  "querylog.degraded"|"querylog.recovered", severity:"info"|"warning"|"error"|"critical", data}], next}` (ring 1000 تایی).

## 4. API پنل (`/api/v1/dns/...`)

- `GET logs` و `GET logs/stream` (SSE یا NDJSON، proxy جریان) و `GET logs/export` و `GET logs/status`: مجوز **`dns:logs`**.
  `DELETE logs {client?, before?, confirmation}`: `dns:admin`، confirmation = `"DELETE LOGS"` یا IP کلاینت؛ audit `dns.logs.delete`.
  audit `dns.logs.export` برای خروجی.
- `GET stats?range`: `dns:read`؛ ولی `top.domains|clients|nxdomain|refused_clients` فقط با `dns:logs` (بدون آن خالی و
  `top_hidden:true`).
- `GET pressure`: `dns:read` (`hot` بدون `dns:logs` فقط شمار، بدون نام/IP).
- `GET/POST mitigations`، `DELETE mitigations/{id}`: `dns:write`؛ audit `dns.mitigation.create|delete`.
- تنظیمات querylog/stats/pressure از همان `PUT settings` (dns:admin).
- **حلقه پس‌زمینه:** هر 10 ثانیه host metrics از Host Agent (اگر وصل است) به موتور؛ هر 5 ثانیه `GET /v1/events` و انتشار در
  مرکز اعلان: `dns.pressure` (warning برای critical، error برای emergency، info برای برگشت به normal)، `dns.attack_detected`،
  `dns.mitigation_auto`، `dns.logs_degraded` / `dns.logs_recovered`. dedupe منطقی.
- **خانه:** قانون `dns_under_pressure` (warning/critical به‌تناسب سطح، مسیر `#/dns/monitor`) و `dns_attack_detected`
  (warning، مسیر `#/dns/monitor`).

## 5. پنل

- تب **«پایش»** (`#/dns/monitor`، dns:read): یک جمله بزرگ با رنگ سطح فشار و دلیل‌ها به زبان ساده؛ نمودارهای زنده
  (پرسش در ثانیه، تأخیر p95، درصد پاسخ از حافظه، درصد خطا) با RangeToggle؛ «پرمصرف‌ترین‌ها» (دامنه‌ها، کلاینت‌ها، «پیدا نشد»ها)
  با دکمه‌های «کند کن / مسدود کن» و مدت (15 دقیقه، 1 ساعت، 1 روز)؛ حمله‌های تشخیص‌داده‌شده با دکمه «جلویش را بگیر»؛ فهرست
  محدودسازی‌های فعال با «برداشتن»؛ تاریخچه رخدادها. پیشرفته: آستانه‌ها، اقدام‌ها، حالت تشخیص حمله.
- تب **«لاگ»** (`#/dns/logs`، dns:logs): جست‌وجوی ساده (نام یا IP)، چیپ‌های نتیجه (همه / پیدا نشد / خطا / رد شده / مسدود)،
  جدول (زمان نسبی، کلاینت، نام، نوع، نتیجه به زبان ساده، منبع، زمان پاسخ)، کلید «زنده»، بارگذاری بیشتر با cursor، خروجی.
  پیشرفته: همه فیلترها و بازه زمانی، تنظیمات نگهداری و حریم خصوصی، وضعیت ذخیره‌سازی (حجم، قدیمی‌ترین، ازدست‌رفته)، حذف لاگ‌ها.
- ریسپانسیو، فارسی/انگلیسی، متن ساده، بدون placeholder برای D3.
