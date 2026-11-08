# 37 — قرارداد فاز D1 موتور DNS (موتور ↔ بک‌اند ↔ پنل)

وضعیت: **قرارداد مرجع D1 — 2026-11-08**. برنامه کلی: `docs/36`. رفتار مرجع: `docs/25`.
هر سازنده اگر شکلی را تغییر داد، در §0 همین سند ثبت کند.

## 0. تغییرات نسبت به قرارداد اولیه

### 0.1 بک‌اند (ماژول `dns`، 2026-11-08)

کد: `dns_client.py` (کلاینت unix socket)، `modules/dns.py` (API، همگام‌سازی سرویس‌ها)، `modules/dns_setup.py`
(گام‌های راه‌اندازی)، `modules/dns_validate.py` (اعتبارسنجی پیش از ارسال)، `agent/dns_facts.py` (حقایق فقط‌خواندنی میزبان).
تست: `tests/test_dns.py`.

- **مجوزها:** چهار مجوز `dns:*` در کاتالوگ مجوزها زیر گروه nav **`server`** («سرور و برنامه‌ها») آمده‌اند، نه گروه جدا
  (گروه‌های کاتالوگ همان بخش‌های nav هستند). نقش‌ها: owner همه، admin هر چهار، operator `dns:read`+`dns:write`،
  developer/viewer فقط `dns:read`. `dns:admin` به `dns:read`+`dns:write` وابسته است. `dns:logs` در D1 استفاده نمی‌شود.
- **مجوز هر route:** `GET status|setup|integration|zones…|overrides` و `POST resolve` = `dns:read`؛ `GET/PUT settings` و
  `PUT integration` = `dns:admin`؛ بقیه تغییرها (زون، رکورد، override، import، rollback، `cache/flush`) = `dns:write`.
  همه POST/PUT/PATCH/DELETE هدر CSRF می‌خواهند (`resolve` هم).
- **خطاها** (قالب عمومی `{error:{code, message, request_id, fields?, field?, reason?, …}}`):
  `dns_not_installed` 503 (فایل socket نیست)، `dns_unreachable` 502 با `error.reason` یکی از
  `connect_failed|timeout|auth_failed|token_unavailable|token_invalid|engine_error|invalid_response|response_too_large`،
  `dns_config_conflict` 409، `dns_zone_exists` 409، `dns_zone_not_found` 404، `dns_record_not_found` 404،
  `dns_record_invalid` 422 (+fields؛ برای override و resolve هم همین کد)، `dns_cname_conflict` 409، `invalid_zone_name` 422.
  **کدهای اضافه:** `dns_settings_invalid` 422 (+fields، از جمله `reason_code:"open_resolver"` برای `0.0.0.0/0` یا `::/0` در
  `recursion.allow`/`query_allow`)، `dns_import_invalid` 422، `dns_version_not_found` 404، `dns_override_not_found` 404،
  `dns_override_managed` 409 (override با `source:"services"` را کاربر عوض/حذف نمی‌کند)، `confirmation_mismatch` 422
  (+`expected_confirmation`)، `dns_request_too_large` 413، `invalid_settings` 422 (integration). کد ناشناخته موتور
  `X` → `dns_X` با همان status (400 → 422) و `error.engine_code`؛ `fields` موتور عیناً منتقل می‌شود.
  نگاشت کد موتور → پنل: `config_conflict, zone_exists, zone_not_found, record_not_found, record_invalid|invalid_record,
  cname_conflict, invalid_zone_name, override_not_found, version_not_found, settings_invalid|invalid_settings,
  import_invalid|invalid_zone_file` (موتور لطفاً همین کدها را بدهد). HTTP 401 موتور → `dns_unreachable/auth_failed`.
- **توکن/سوکت:** مسیرها از `MRK_DNS_ADMIN_SOCKET` (پیش‌فرض `/run/mrk-dns/admin.sock`) و متغیر جدید
  `MRK_DNS_ADMIN_TOKEN_FILE` (پیش‌فرض `/run/mrk-dns/admin.token`). پنل هر درخواست را با `Authorization: Bearer` می‌فرستد.
- **حذف زون** بدنه `{confirmation: "<zone>"}` می‌خواهد (مثل حذف دامنه در docs/35).
- **export** به‌جای متن خام، JSON برمی‌گرداند: `{zone, text}` (موتور متن RFC 1035 می‌دهد).
- **نام‌ها canonical:** زون: IDNA، حروف کوچک، بدون نقطه آخر، بدون wildcard/IP (تک‌برچسبی مثل `internal` مجاز).
  `name` رکورد نسبی (`@`، `*`، `www`، `_sip._tcp`)؛ نام مطلق با نقطه آخر داخل زون نسبی می‌شود. targetها (CNAME/MX/NS/SRV/PTR،
  mname/rname) مطلق و **بدون نقطه آخر** فرستاده می‌شوند (`"."` فقط برای MX/SRV تهی). TTL پیش‌فرض رکورد 3600، override 300.
- **فیلدهای `data` هر نوع (قرارداد پنل ↔ موتور):** A/AAAA `{address}`؛ CNAME `{target}`؛ NS `{nameserver}`؛ PTR `{target}`؛
  MX `{preference, exchange}`؛ TXT `{text}` (حداکثر 4000 نویسه، موتور به رشته‌های 255 بایتی می‌شکند)؛
  SRV `{priority, weight, port, target}`؛ CAA `{flags, tag, value}` (tag کوچک)؛ SOA `{mname, rname, refresh, retry, expire, minimum}`
  (serial خودکار؛ SOA با POST ساخته نمی‌شود → `reason_code:"soa_managed"`؛ CNAME در apex → `cname_at_apex`).
  بدنه رکورد که به موتور می‌رود: `{name, type, ttl, data, disabled, comment}`. فیلد ناشناخته → `unknown_field`.
- **override:** بدنه POST/PUT `{name, type:"A"|"AAAA"|"CNAME", value, ttl?, disabled?}`؛ `source` را پنل می‌گذارد
  (`"user"`؛ همگام‌سازی سرویس‌ها `"services"`). مسیرهای موتور: `PUT/DELETE /v1/overrides/{id}`.
- **resolve:** `{name, type?="A", client_ip?}` (نوع‌ها: همه انواع D1 + `ANY`) → پاسخ موتور عیناً.
  **cache/flush:** `{name?}` → پاسخ موتور. **rollback:** `{version}` (عدد یا رشته).
- `GET /api/v1/dns/status` →
  `{installed, reachable, error_code: null|"dns_not_installed"|"dns_unreachable", reason?, engine: <v1/status>|null,
  setup_complete, checked_at}` (cache ده ثانیه؛ `setup_complete` از آخرین محاسبه setup).
- `GET /api/v1/dns/setup[?refresh=true]` (cache شصت ثانیه) →
  `{steps:[{id, title_fa, title_en, state, detail_code, params, commands:[{id, title_fa, title_en, code, danger?, note_fa?, note_en?}],
  revert:[…همان شکل…]}], complete, agent:"ok"|"not_configured"|"unreachable"|"unsupported", gateway, fallback:[…], checked_at}`.
  `detail_code`ها:
  - `engine_running`: `running` (done، params `{version, uptime_s}`)، `not_installed` (todo)، `engine_unreachable` (warning، `{reason}`)،
    `listener_failed` (warning، `{address, proto, error, failed}`).
  - `port_53_free`: `held_by_mrk`|`free` (done)، `port_in_use` (warning، `{address, proto, process, pid, unit, conflicts, listen}`)،
    `systemd_resolved_stub` (todo؛ فقط اگر resolved روی همان نشانی/wildcard باشد)، `agent_not_configured|agent_unreachable|
    agent_unsupported|host_proc_unavailable` (unknown). stub روی 127.0.0.53 با 127.0.0.1:53 تداخل ندارد.
  - `host_resolver`: `uses_mrk` (done)، `no_fallback` (warning)، `resolved_stub_forwarding` (warning)، `mrk_not_first` (warning)،
    `systemd_resolved_stub` | `uses_other_dns` | `static_resolv_conf` (todo)، `agent_*`|`host_root_unavailable` (unknown).
    params `{nameservers, managed_by, symlink, resolved_mode, mrk_dropin, stub_disabled, fallback}`.
  - `docker_daemon`: `uses_mrk` (done)، `no_fallback`|`daemon_json_invalid` (warning)، `daemon_json_missing`|`dns_not_set`|
    `mrk_not_first`|`uses_other_dns` (todo)، `agent_*` (unknown). params `{gateway, fallback, present, dns, keys}`.
  - `verify_from_host`: `ok` (done)، `engine_ok_host_not_using` (todo)، `engine_ok_host_unknown` (unknown)، `resolve_failed`
    (warning، `{rcode, error}`)، `engine_not_running`. پنل با `POST /v1/resolve` موتور + resolv.conf دیده‌شده توسط Agent بررسی می‌کند.
  - `verify_from_container`: همیشه دستی: `manual_check` (unknown)، یا `docker_dns_not_set`|`engine_not_running` (todo)،
    `gateway_not_listening` (warning). پنل هرگز container اجرا نمی‌کند.
  `complete` = پنج گام اول done و گام آخر done/unknown. شناسه دستورها: `compose_up, compose_check, compose_stop,
  show_port_53, disable_unit, enable_unit, resolved_dropin, resolv_conf_link, resolver_check, resolved_revert,
  resolv_conf_static, resolv_conf_restore, daemon_json_merge, daemon_json_manual, docker_restart (danger), daemon_json_revert
  (danger), dig_local, dig_system, container_nslookup, container_resolv`.
- `GET /api/v1/dns/integration` / `PUT` (بدنه جزئی) →
  `{settings:{services_overrides, services_override_target, internal_zone_enabled, fallback_servers}, effective_target,
  internal_zone:"mrk.internal", internal_names:[…], last_sync}`؛ `last_sync` =
  `{status:"applied"|"disabled"|"not_installed"|"unreachable"|"failed"|"timeout", enabled, internal_zone, target, created, updated,
  deleted, skipped:[نام‌هایی که override کاربر دارند], error_code, at}`. همین شیء در `sync.dns` پاسخ‌های دامنه (docs/35) هم می‌آید.
  override سرویس‌ها: نوع A (یا AAAA برای target IPv6)، TTL 60. زون داخلی: رکوردهای `panel|npm|pypi|s3` با
  `comment:"managed by MRK: services"`؛ با خاموش کردن، فقط رکوردهای مدیریت‌شده حذف می‌شوند و زون اگر رکورد دیگری نداشت حذف می‌شود.
- **تنظیم اضافه:** `dns.fallback_servers` (پیش‌فرض `["1.1.1.1","9.9.9.9"]`) برای DNS پشتیبان در دستورها.
  گروه جدید مرکز تنظیمات: `server.dns` (nav `dns/settings`).
- **سرویس‌های من:** کارت `dns` (`internal_port:53`، `controllable:false`، `manage_route:"#/dns/status"`، `domains_supported:false`)؛
  state: `running` | `not_installed` (`reason_code:"dns_not_installed"`) | `degraded` (`"dns_unreachable"`).
- **خانه:** قانون `dns_unreachable` (error، `params:{error_code, since}`، مسیر `#/dns/status`، مجوز `dns:read`)؛ گام اختیاری
  `setup_dns` (`#/dns/setup`، مجوز `dns:admin`، تشخیص از `setup_complete`).
- **تاریخچه زون:** `GET .../history` پاسخ موتور را عیناً برمی‌گرداند؛ شکل مورد انتظار پنل
  `{items:[{version:number, created_at, records, actor}]}` (موتور همین را بدهد). `rollback` همان `{version}` دریافتی را می‌فرستد.
- **شناسه upstream** در `PUT settings` هر رشته امن `^[A-Za-z0-9_.:-]{1,128}$` است (مثلاً `quad9-3`، ساخته‌شده در پنل) و یکتا.
- `GET/PUT /integration` بدون موتور هم کار می‌کند: تنظیم ذخیره می‌شود و `last_sync.status` = `not_installed`/`unreachable`/`timeout`؛
  خطای غیرمنتظره همگام‌سازی `{status:"failed", error_code:"dns_sync_failed"}`.
- **رویدادها:** `dns.unreachable` (error) و `dns.recovered` (info) با dedupe `dns.reachability`.
- **Agent:** `GET /v1/dns/facts` (امضاشده، بدون پارامتر، مسیرها ثابت) →
  `{host_proc, host_root, port_53:{readable, owners_complete, items:[{proto, family, address, port, process:{pid, comm}|null,
  process_hint?}]}, systemd_resolved_running, resolv_conf:{present, symlink, managed_by, resolved_mode, truncated, nameservers,
  search, options}, resolved:{present, dns, fallback_dns, dns_stub_listener, stub_disabled, domains, dropins, mrk_dropin},
  docker_daemon:{present, valid, dns, keys}, docker_bridge_gateway}`. symlinkها دستی و داخل `/host/root` حل می‌شوند، فایل‌ها
  حداکثر 64KiB. `/v1/info` قابلیت `dns_facts: true` دارد. نام process از `/host/proc/<pid>/fd` فقط اگر Agent اجازه داشته باشد.

### 0.2 موتور (`apps/dns-engine`، 2026-11-08)

کد و معماری: `apps/dns-engine/README.md`. Go 1.27.3 (`golang:1.27.3-trixie@sha256:af1bfc26…`)، `miekg/dns v1.1.73`،
`golang.org/x/sys v0.49.0`، `golang.org/x/net v0.62.0` (همه BSD-3). همه تصمیم‌های §0.1 در موتور اعمال شده‌اند.

- **اجرا:** ENTRYPOINT ایمیج `entrypoint.py` است، پس سرویس compose `entrypoint: ["mrk-dns"]` + `command: ["serve"]` دارد
  (نه `command: ["mrk-dns","serve"]`). سرویس `mrk-dns` با `profiles: [dns]`، `network_mode: host`، شروع با `0:10001` و drop به `10001:10001`
  (همان کاربر پنل؛ socket و توکن مشترک)، `cap_drop: [ALL]` + `cap_add: [NET_BIND_SERVICE, SETUID, SETGID]`، `read_only`، `no-new-privileges`،
  `cpus/mem_limit/pids_limit` از `MRK_DNS_CPUS` (2)، `MRK_DNS_MEMORY` (512m)، `MRK_DNS_PIDS` (256). volume `mrk-dns-run` در
  `mrk-mirror` فقط‌خواندنی روی `/run/mrk-dns` mount شده است.
- **قابلیت bind و کاربر:** با `no-new-privileges` هسته file capability را هنگام execve نادیده می‌گیرد، و Docker به
  کاربر غیر root هیچ قابلیت permitted نمی‌دهد. پس سرویس `mrk-dns` با `user: "0:10001"` و فقط
  `cap_add: [NET_BIND_SERVICE, SETUID, SETGID]` شروع می‌شود (`cap_drop: ALL` و `no-new-privileges` و `read_only` می‌مانند). موتور پیش
  از هر کاری روی همه threadها این‌ها را اجرا می‌کند: `PR_SET_KEEPCAPS`، `setgroups`/`setresgid`/`setresuid` به `MRK_DNS_RUN_AS`
  (پیش‌فرض `10001:10001`، uid صفر رد می‌شود)، سپس `capset` با permitted=effective={NET_BIND_SERVICE} و inheritable/ambient تهی.
  SETUID/SETGID دیگر برنمی‌گردند. bind دوباره بعد از drop کار می‌کند (تغییر listen در تنظیمات، تلاش مجدد ده‌ثانیه‌ای).
  روی پشته واقعی compose بررسی شد: process `mrk-dns` و همه threadهایش `Uid 10001`، `CapPrm=CapEff=0x400`، `NoNewPrivs 1`.
  `docker-init` (PID 1 از `init: true`) root با همان سه قابلیت می‌ماند (رفتار Docker). باینری file capability ندارد و
  `scripts/validate_release.py` نبود `setcap`، کاربر `0:10001`، سه قابلیت و `MRK_DNS_RUN_AS` را بررسی می‌کند. اگر موتور
  غیر root شروع شود، تلاش می‌کند قابلیت permitted را effective کند و اگر نشد هشدار روشن در لاگ می‌نویسد.
- **متغیرهای محیطی:** `MRK_DNS_RUN_AS` (پیش‌فرض `10001:10001`)، `MRK_DNS_DATA_DIR`، `MRK_DNS_ADMIN_SOCKET`، `MRK_DNS_ADMIN_TOKEN_FILE`، `MRK_DNS_LISTEN`،
  `MRK_DNS_GOMEMLIMIT` (خالی = 85٪ سقف حافظه cgroup)، `MRK_DNS_LOG_LEVEL`. در compose هم `MRK_DNS_CPUS`، `MRK_DNS_MEMORY` و
  `MRK_DNS_PIDS`. build arg تازه: `GOPROXY` (go.sum محتوای ماژول‌ها را قفل می‌کند).
- **خطا:** `{error:{code, message, fields?:[{field, reason_code, params?}]}}` (همان شکل پنل). کدها و status:
  `config_conflict` 409، `settings_invalid` 422، `zone_exists` 409، `zone_not_found` 404، `invalid_zone_name` 422،
  `record_not_found` 404، `record_invalid` 422 (اعتبارسنجی override و resolve هم همین)، `cname_conflict` 409 (برای
  `cname_at_apex` هم)، `override_not_found` 404، `version_not_found` 404، `import_invalid` 422. کدهای اضافه (پنل → `dns_X`):
  `zone_invalid` 422 (نوع/forwarderهای نامعتبر)، `zone_type_mismatch` 409 (رکورد روی زون forwarder، forwarder روی primary)،
  `invalid_request` 400 (JSON بد، `unknown_field`، `invalid_type`)، `limit_reached` 409، `unauthorized` 401،
  `body_too_large` 413، `not_found` 404.
- **settings:** `PUT` روی تنظیمات فعلی ادغام می‌شود؛ کلید حذف‌شده مقدار فعلی را نگه می‌دارد و فهرست ارسال‌شده جایگزین
  می‌شود. `config_version` (عدد صحیح) اجباری است و در پاسخ GET/PUT کنار فیلدها می‌آید. `recursion.allow` با
  `0.0.0.0/0` یا `::/0` → `settings_invalid` با `reason_code:"open_resolver"`. ورودی ACL می‌تواند `!` (رد) داشته باشد؛ اولین
  تطابق برنده است. پیش‌فرض upstreamها: `cloudflare` `1.1.1.1:53`، `google` `8.8.8.8:53`، `quad9` `9.9.9.9:53`.
  شکل نشانی upstream: `IP[:port]`، `udp://`، `tcp://`، `tls://IP:853#نام-گواهی`، `https://host/path[#IP,IP]` (برای DoH
  نام میزبان مجاز است و از طریق upstreamهای ساده حل می‌شود، نه resolver سیستم).
- **زون:** ساخت primary خودکار SOA (`ns1.<zone>`، `hostmaster.<zone>`، 3600/600/604800/300، TTL 900) و یک NS در apex
  (`{nameserver:"ns1.<zone>"}`، TTL 14400) می‌سازد. آخرین NS در apex حذف نمی‌شود (`apex_ns_required`). `GET /v1/zones/{zone}`
  خلاصه زون را برمی‌گرداند، به‌اضافه `forwarders`، `version` و `soa` (به شکل رکورد). در `GET …/records` اولین رکورد SOA است
  (`id:"soa"`). `PUT …/records/soa` فیلدهای SOA را عوض می‌کند و `DELETE …/records/soa` رد می‌شود. TTL همه رکوردهای یک RRset
  یکسان نگه داشته می‌شود (RFC 2181). رکورد زیر delegation، جز glue از نوع A/AAAA، رد می‌شود (`occluded_by_delegation`).
  `DELETE` زون → 204. موتور confirmation نمی‌خواهد؛ پنل آن را بررسی می‌کند.
- **data:** همان §0.1. TXT خروجی `{text}` است. فقط اگر مرز رشته‌ها با تقسیم خودکار 255 بایتی فرق کند (مثلاً DKIM
  import‌شده)، `strings:[…]` هم می‌آید. ورودی `strings` هم پذیرفته می‌شود.
- **history:** `{items:[{version, created_at, records, actor, serial, reason}]}` (جدیدترین اول، 50 نسخه). `actor` از هدر
  `X-MRK-Actor` درخواست‌های تغییر خوانده می‌شود (پیش‌فرض `"api"`)؛ پنل لطفاً نام کاربر را بفرستد. `rollback {version}`
  (عدد یا رشته) نسخه جدیدی با serial بزرگ‌تر می‌سازد.
- **import:** پاسخ `{added, skipped, serial, version}`. `$INCLUDE` رد می‌شود. `replace:true` اگر متن NS در apex نداشت، NS فعلی
  را نگه می‌دارد. serial جدید از serial فعلی و serial وارد‌شده هر دو بزرگ‌تر است. **export:** متن خام (`text/dns`).
- **override:** فقط برای کلاینت‌های داخل `recursion.allow` پاسخ داده می‌شود. نام `*.x` wildcard است. اگر نامی override
  دارد ولی نه برای نوع پرسیده‌شده، پاسخ NODATA است و به upstream نمی‌رود. TTL پیش‌فرض 300. CNAME با override دیگر هم‌نام
  → `cname_conflict`.
- **resolve:** پاسخ به‌اضافه `authority[]` و `stale`. `source` فقط پنج مقدار قرارداد را می‌گیرد: نام‌های محلی (`localhost`،
  reverse خصوصی) → `authoritative`، stale → `cache`، SERVFAIL → `upstream`. **cache/flush** → `{flushed}`.
  **status** به‌اضافه `zones` و `overrides`؛ در هر upstream `proto` و `last_error` هم هست. `GET /v1/health` بدون توکن
  `{ok, listeners}` می‌دهد (503 اگر هیچ listener سالم نیست).
- **رفتار:** عمیق‌ترین زون برنده است، چه primary چه forwarder. زون forwarder فقط برای `recursion.allow` کار می‌کند، با
  راهبرد `in_order`، و از فیلتر rebinding معاف است. `refuse_any` → REFUSED. `minimal_any` روی UDP: در زون authoritative
  یک RRset و برای recursion یک HINFO `RFC8482`. CHAOS (`version.bind`) و AXFR/IXFR → REFUSED؛ opcode غیر QUERY → NOTIMP.
  `localhost` محلی پاسخ داده می‌شود. reverse شبکه‌های خصوصی (RFC 6303) و `.invalid` → NXDOMAIN محلی، هرگز به upstream.
  سقف نرخ کلاینت: UDP بی‌صدا drop و TCP REFUSED (IPv6 به ازای /64). RRL فقط روی پاسخ‌های UDP به کلاینت‌های **بیرون**
  از `recursion.allow` اعمال می‌شود (NXDOMAIN به ازای زون جمع می‌شود). کلاینت‌های داخلی را `client_qps` محدود می‌کند.
  listener ناموفق (مثلاً `172.17.0.1` پیش از بالا آمدن docker0) هر 10 ثانیه دوباره امتحان می‌شود و در status `ok:false` با
  `error` دارد.
- **ذخیره:** `settings.json`، `overrides.json`، `zones/<zone>.json` و `zones/<zone>.history/<version>.json` زیر
  `MRK_DNS_DATA_DIR`. هر نوشتن اتمیک است (temp + fsync + rename + fsync دایرکتوری). اگر فایل اصلی زون خراب باشد، از آخرین
  نسخه تاریخچه بازیابی می‌شود.
- **محدودیت‌های D1:** حل iterative از ریشه، DNSSEC، AXFR/NOTIFY، DoT/DoH ورودی، DNS cookies، 0x20 در پرس‌وجوی خروجی،
  ECS و لاگ پرس‌وجو در D1 نیستند. hook حلقه لاگ آماده است ولی خاموش. referral به زیرزون delegate‌شده برای کلاینت recursive
  دنبال نمی‌شود (D4). `pressure` همیشه `"normal"` است (D2).

## 1. اجرا و بسته‌بندی

- کد: `apps/dns-engine` (Go module `mrk/dns-engine`، Go نسخه پایدار جاری با digest پین‌شده؛ کتابخانه `github.com/miekg/dns`
  پین‌شده؛ وابستگی دیگر فقط با مجوز آزاد و ثبت در SBOM).
- باینری‌ها: `mrk-dns` (زیرفرمان‌ها: `serve`، `health`، `version`) و `mrk-dnsbench` (ابزار تست بار داخلی).
- ایمیج: مرحله build جدید `dns-builder` در `deploy/appliance/Dockerfile`؛ باینری استاتیک (`CGO_ENABLED=0`) در
  `/usr/local/bin/` ایمیج runtime. ایمیج جدا ساخته نمی‌شود.
- compose (`compose.yaml` و `deploy/appliance/compose.production.yaml`): سرویس `mrk-dns` با همان ایمیج، `profiles: [dns]`،
  `command: ["mrk-dns","serve"]`، `network_mode: host`، کاربر غیر root، `cap_drop: [ALL]`، `cap_add: [NET_BIND_SERVICE]`،
  `read_only: true`، `security_opt: [no-new-privileges:true]`، `cpus`/`mem_limit`/`pids_limit` از متغیرهای
  `MRK_DNS_CPUS` (2)، `MRK_DNS_MEMORY` (512m)، `MRK_DNS_PIDS` (256)، healthcheck با `mrk-dns health`، `restart: unless-stopped`.
  volumeها: `mrk-dns-data:/var/lib/mrk-dns` (وضعیت) و `mrk-dns-run:/run/mrk-dns` (socket مدیریتی؛ در container پنل هم mount).
- متغیرهای محیطی موتور (همه در مرکز تنظیمات ثبت شوند): `MRK_DNS_DATA_DIR`، `MRK_DNS_ADMIN_SOCKET`
  (`/run/mrk-dns/admin.sock`)، `MRK_DNS_LISTEN` (پیش‌فرض اولیه `127.0.0.1:53,172.17.0.1:53`؛ فقط اولین اجرا، بعد از آن از
  تنظیمات)، `MRK_DNS_GOMEMLIMIT`، `MRK_DNS_LOG_LEVEL`.

## 2. API مدیریتی موتور (HTTP روی unix socket، JSON)

- احراز: هدر `Authorization: Bearer <token>`؛ توکن را موتور در اولین اجرا در `/run/mrk-dns/admin.token` (0640) می‌سازد؛
  socket با 0660. پنل و موتور با یک uid/gid اجرا می‌شوند. اندازه بدنه حداکثر 4 MiB. خطا: `{error:{code, message, fields?}}`.
- `GET /v1/status` → `{version, started_at, uptime_s, listeners:[{address, proto, ok, error?}], qps_1s, qps_1m, queries_total,
  cache:{entries, bytes, max_bytes, hit_ratio}, upstreams:[{id, address, proto, healthy, rtt_ms}], pressure:"normal",
  memory_bytes, goroutines, config_version}`
- `GET /v1/settings`، `PUT /v1/settings` (کل شیء، با `config_version` برای جلوگیری از ویرایش هم‌زمان؛ 409 `config_conflict`):
  ```
  {listen:[{address:"127.0.0.1:53", udp:true, tcp:true}],
   recursion:{enabled:true, allow:["127.0.0.0/8","::1/128","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","fc00::/7"]},
   query_allow:[...همان پیش‌فرض...],
   upstreams:[{id, address:"1.1.1.1:53"|"tls://1.1.1.1:853#cloudflare-dns.com"|"https://dns.google/dns-query", enabled}],
   upstream_strategy:"fastest"|"parallel"|"in_order",
   cache:{max_bytes:67108864, min_ttl:0, max_ttl:86400, negative_max_ttl:3600, serve_stale:true, stale_ttl:86400, prefetch:true},
   limits:{client_qps:200, client_burst:400, rrl_responses_per_second:20, rrl_slip:2, rrl_ipv4_prefix:24, rrl_ipv6_prefix:56,
           max_tcp_connections:1000, tcp_idle_timeout_ms:10000, udp_max_size:1232, max_inflight_upstream:2000},
   minimal_any:true, refuse_any:false, rebinding_protection:true,
   overrides:{enabled:true}}
  ```
- زون‌ها: `GET /v1/zones` → `{items:[{name, type:"primary"|"forwarder", serial, records, disabled, updated_at}]}`؛
  `POST /v1/zones {name, type, forwarders?[]}`؛ `GET /v1/zones/{zone}`؛ `PATCH /v1/zones/{zone} {disabled?, forwarders?}`؛
  `DELETE /v1/zones/{zone}`؛ `GET /v1/zones/{zone}/export` (متن RFC 1035)؛ `POST /v1/zones/{zone}/import {text, replace:bool}`؛
  `GET /v1/zones/{zone}/history` → نسخه‌ها؛ `POST /v1/zones/{zone}/rollback {version}`.
- رکوردها: `GET /v1/zones/{zone}/records` → `{items:[{id, name, type, ttl, data:{...}, disabled, comment}]}`؛
  `POST`، `PUT /{id}`، `DELETE /{id}`. `name` نسبی (`@` برای apex، `*` wildcard). انواع D1: A، AAAA، CNAME، MX، TXT، SRV، NS،
  PTR، CAA، SOA (خودکار، serial خودکار YYYYMMDDnn). `data` برای هر نوع فیلدهای نام‌دار (مثلاً MX: `{preference, exchange}`).
  اعتبارسنجی کامل (CNAME با رکورد دیگر هم‌نام ممنوع، نام‌ها RFC، TTL 0..604800) با `fields`.
- Override (پاسخ محلی بدون مالکیت کل زون، مثل «نام → آدرس»): `GET/POST/PUT/DELETE /v1/overrides` →
  `{items:[{id, name, type:"A"|"AAAA"|"CNAME", value, ttl, source:"user"|"services", disabled}]}`.
- `POST /v1/resolve {name, type, client_ip?}` → `{rcode, answers:[{name,type,ttl,data}], source:"authoritative"|"override"|
  "cache"|"upstream"|"refused", upstream?, rtt_ms}`.
- `POST /v1/cache/flush {name?}`؛ `GET /v1/metrics` (متن Prometheus).

## 3. رفتار موتور در D1

- لیسنرهای UDP/TCP (چند هسته با `SO_REUSEPORT`)، EDNS0 با اندازه 1232، TC و تکرار روی TCP، `ANY` حداقلی (RFC 8482).
- ترتیب پاسخ: ACL ← محدودیت نرخ ← override ← زون authoritative (پاسخ AA، NXDOMAIN/NODATA با SOA، wildcard، CNAME داخل زون،
  delegation با glue) ← زون forwarder ← cache ← upstream (اگر recursion مجاز). خارج از ACL: REFUSED بدون جزئیات.
- cache با سقف بایت، TTL حداقل/حداکثر، cache منفی (RFC 2308)، serve-stale (RFC 8767)، prefetch در 10٪ آخر TTL برای
  پرمصرف‌ها، تجمیع درخواست‌های هم‌زمان یکسان (single-flight).
- upstreamها: UDP/TCP، DoT، DoH؛ health-check، انتخاب سریع‌ترین با EWMA؛ timeout و retry محدود.
- محافظت: rate limit هر کلاینت (token bucket)، RRL به ازای prefix، سقف اتصال TCP، محافظت DNS rebinding (پاسخ upstream با IP
  خصوصی برای نام عمومی حذف شود، قابل خاموش)، رد بسته‌های بدشکل، هرگز recursion برای بیرون از `recursion.allow`.
- پایداری: ذخیره اتمیک (فایل موقت + fsync + rename) در `data_dir`، تاریخچه 50 نسخه به ازای هر زون، بارگذاری مجدد بدون قطعی،
  `GOMEMLIMIT`، خاموشی آرام.
- آمار برای D2: hook ring buffer لاگ پرس‌وجو آماده شود (در D1 فقط شمارنده‌ها).

## 4. API پنل (`/api/v1/dns/...`، ماژول کنترل‌پلین `dns`)

مجوزها (گروه جدید `dns`): `dns:read` (همه نقش‌ها)، `dns:write` (owner/admin/operator)، `dns:logs` (owner/admin)،
`dns:admin` (owner/admin: تنظیمات موتور، ACL، upstream).

- `GET /api/v1/dns/status` → `{installed, reachable, error_code?, engine?:{…/v1/status}, setup_complete}`
  (`installed=false` اگر socket وجود ندارد → پنل راهنمای نصب نشان می‌دهد).
- `GET /api/v1/dns/setup` → `{steps:[{id, state:"done"|"todo"|"warning"|"unknown", detail_code, params, commands:[{id, title_fa,
  title_en, code}], revert?:[{...}] }]}` با شناسه‌های: `engine_running`، `port_53_free`، `host_resolver`، `docker_daemon`،
  `verify_from_host`، `verify_from_container`. تشخیص از Host Agent (خواندن فقط‌خواندنی `/host/proc/1/net/udp|tcp`،
  `/host/root/etc/resolv.conf`، `/host/root/etc/systemd/resolved.conf`، `/host/root/etc/docker/daemon.json`، و نام
  process صاحب پورت 53 از `/host/proc`). دستورها شامل DNS پشتیبان. بدون Agent: `unknown` با دستورهای کامل.
- `GET/PUT /api/v1/dns/settings` (dns:admin)، زون/رکورد/override: `/api/v1/dns/zones…`، `/api/v1/dns/overrides…` (dns:write)
  با همان شکل موتور؛ `POST /api/v1/dns/resolve`، `POST /api/v1/dns/cache/flush`.
- خطاها: `dns_not_installed`، `dns_unreachable`، `dns_config_conflict`، `dns_zone_exists`، `dns_zone_not_found`،
  `dns_record_not_found`، `dns_record_invalid` (+fields)، `dns_cname_conflict`، `invalid_zone_name`.
- audit: `dns.settings.update`، `dns.zone.create|update|delete|import|rollback`، `dns.record.create|update|delete`،
  `dns.override.*`، `dns.cache.flush`.
- خانه: قانون `dns_unreachable` (error) وقتی نصب شده ولی جواب نمی‌دهد؛ چک‌لیست اختیاری `setup_dns`.
- یکپارچگی با «سرویس‌های من»: تنظیم `dns.services_overrides` (پیش‌فرض خاموش) — دامنه‌های سرویس‌ها به‌صورت override با
  `source:"services"` به نشانی داخلی سرور (`dns.services_override_target`، پیش‌فرض gateway Docker) ثبت/حذف می‌شوند تا
  containerها مستقیم به سرور برسند. زون داخلی `mrk.internal` (اختیاری) با `panel/npm/pypi/s3.mrk.internal`.
- کارت «DNS» در «سرویس‌های من» (service id `dns`، پورت 53، کنترل‌پذیر نیست چون container جداست؛ وضعیت از status).

## 5. پنل (گروه nav جدید یا زیر «سرور و برنامه‌ها» → «DNS»)

تب‌ها: «وضعیت» (یک جمله + qps + cache + upstreamها)، «راه‌اندازی» (گام‌ها با بررسی و کپی دستور)، «نام‌ها» (ساده: override
«این نام → این آدرس»؛ پیشرفته: زون‌ها و همه رکوردها، import/export، تاریخچه و برگشت)، «تست» (پرس‌وجو و دیدن پاسخ و منبع)،
«تنظیمات» (پیشرفته: listen، ACL، upstreamها، cache، محدودیت‌ها). D2 تب «لاگ» و «پایش»، D3 تب «دور زدن تحریم».
