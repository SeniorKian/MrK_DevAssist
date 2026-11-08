# 32 — قراردادهای Gate 19 (فایروال و ضدحمله، اسکن آسیب‌پذیری، مدیریت دیتابیس)

وضعیت: **قرارداد مرجع — 2026-11-08**. طراحی پایه در `docs/28` (§S7، §S8، §S9). هر ماژول API نهایی خود را در
گزارش پیاده‌سازی و در این سند (بخش مربوط) ثبت می‌کند تا پنل بر اساس آن ساخته شود.

## 1. مجوزها (auth.py — اضافه شد)

| مجوز | owner | admin | operator | developer | viewer |
|---|---|---|---|---|---|
| `firewall:read` | ✓ | ✓ | ✓ | – | – |
| `firewall:write` (قواعد، مسدودسازی، روشن/خاموش) | ✓ | ✓ | – | – | – |
| `vuln:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `vuln:write` (اسکن، ignore، تنظیمات) | ✓ | ✓ | ✓ | – | – |
| `db:read` (اتصال‌ها، مشاهده ساختار و داده) | ✓ | ✓ | – | – | – |
| `db:write` (حالت نوشتن، مدیریت اتصال‌ها) | ✓ | ✓ | – | – | – |

## 2. اصول مشترک

- همه چیز قابل تنظیم و پیش‌فرض امن؛ حالت ساده و پیشرفته در پنل؛ audit همه تغییرات؛ CSRF روی mutationها.
- Dokploy دست‌نخورده: هیچ قاعده‌ای روی chainهای Docker/Dokploy نوشته نمی‌شود؛ کانتینرهای محافظت‌شده فقط‌خواندنی‌اند.
- ارتباط خارجی (دانلود پایگاه آسیب‌پذیری) فقط از طریق `outbound.py` (DNS و پروکسی کاربر) و ثبت provider در جدول
  «سرویس‌های خارجی».
- رویدادها از طریق `ctx.events` به مرکز اعلان‌ها.

## 3. فایروال (`firewall`)

- اجرا در یک **سرویس جدا و اختیاری** `mrk-firewall` (همان image، profile `firewall`) با `network_mode: host` و
  فقط `CAP_NET_ADMIN`؛ ارتباط با Control Plane مانند Host Agent با امضای HMAC (کلید جفت‌سازی جدا).
- جدول nftables اختصاصی `inet mrk` با set دارای timeout در hook `prerouting` (priority raw)؛ حذف کامل جدول هنگام
  خاموش کردن؛ حالت dry-run پیش‌فرض؛ allowlist اجباری (IP مدیر فعلی + شبکه‌های خصوصی قابل تنظیم)؛ انقضای خودکار.
- تشخیص: لاگ ورود MRK، لاگ SSH (journald یا `/var/log/auth.log` فقط‌خواندنی)، access log Traefik/Dokploy
  (مسیر قابل تنظیم)؛ قواعد آستانه‌ای قابل ویرایش.

### 3.1 پیاده‌سازی (API نهایی)

- **تقسیم کار:** همه منطق (قواعد، پنجره لغزان، allowlist، بررسی ایمنی، تاریخچه، RBAC، audit) در Control Plane
  (`modules/firewall*.py`). helper (`mrk_control_plane/firewall/**`، console script `mrk-firewall`) فقط (1) فایل‌های لاگ
  فقط‌خواندنی را tail و به «سیگنال» `{source, kind, ip, detail, ts}` تبدیل می‌کند (خط خام هرگز خارج نمی‌شود) و (2) وضعیت
  مطلوب را روی جدول خودش اعمال می‌کند؛ همه ورودی‌ها را دوباره اعتبارسنجی می‌کند.
- **ارتباط:** پیش‌فرض Unix socket `unix:/run/mrk-firewall/firewall.sock` در volume `mrk-firewall-run` که فقط
  `mrk-firewall` (rw) و `mrk-mirror` (`:ro`، برای connect کافی است) mount می‌کنند. ارزیابی: با `network_mode: host`
  یک listener روی `127.0.0.1:7071` از کانتینرهای bridge (حتی با `host.docker.internal`/`host-gateway` که به IP
  bridge مثل `172.17.0.1` می‌رسد) قابل دسترسی نیست و bind روی IP bridge یا `0.0.0.0` آن را به همه کانتینرها (و
  شاید LAN) باز می‌کند؛ socket فایل‌محور امن‌ترین گزینه است و نیازی به `extra_hosts` نیست. TCP
  (`MRK_FIREWALL_LISTEN=host:port`) فقط برای bare-metal/dev. همه مسیرها جز `GET /v1/health` با HMAC
  (`agent/signing.py`، پنجره 30 ثانیه، nonce یکبارمصرف) و کلید جفت‌سازی جدا (`/var/lib/mrk-firewall/firewall.key`،
  یک‌بار در لاگ).
- **nftables:** فقط CLI `nft` (بسته Debian `nftables`) با argv ثابت و allowlist‌شده (`-f <state>/.ruleset-*.nft`،
  `-j list table inet mrk`)، بدون shell. اعمال اتمیک: `add table inet mrk` + `delete table inet mrk` + تعریف کامل
  جدول در یک فایل/تراکنش (idempotent). setها: `mrk_allow_v4/v6` (`flags interval`) و `mrk_block_v4/v6`
  (`flags interval, timeout`)؛ chain `mrk_prerouting` با `type filter hook prerouting priority raw; policy accept;`
  و ترتیب `ip saddr @mrk_allow_v4 accept` → `ip6 … accept` → `ip saddr @mrk_block_v4 counter drop` → `ip6 … drop`.
  `accept` فقط chain ما را تمام می‌کند؛ جدول‌های Docker/Dokploy دست‌نخورده و همچنان اجرا می‌شوند. blockهای هم‌پوشان
  ادغام می‌شوند (شبکه دربرگیرنده می‌ماند). **حالت‌ها:** `off` و `dry_run` → جدول ما حذف می‌شود (هیچ قاعده‌ای نصب
  نمی‌شود)؛ `enforce` → جایگزینی کامل جدول. helper آخرین وضعیت را در `desired.json` نگه می‌دارد و هنگام start
  دوباره اعمال می‌کند (timeoutها از `expires_at` مطلق حساب می‌شوند). `MRK_FIREWALL_FORCE_DRY_RUN=true` ترمز اضطراری
  سمت helper است.
- **Helper API (امضاشده):** `GET /v1/info` (version، `nft_available`، `mode`/`effective_mode`، `state_hash`، شمارنده‌های
  جدول، `local_addresses` از `/proc/net/fib_trie` و `if_inet6` میزبان)؛ `POST /v1/apply`
  `{mode, allow: [cidr], blocks: [{cidr, expires_at|null}]}`؛ `POST /v1/signals`
  `{sources: [{name, kind: sshd|traefik, path: /host/log/...}], sensitive_paths: [...], max_bytes?}`.
- **منابع تشخیص:** sshd (`Failed password|publickey…`، `Invalid user`، شامل `sshd-session`)، Traefik access log (JSON:
  `ClientHost`/`ClientAddr`، `DownstreamStatus`، `RequestPath`؛ یا CLF) با سیگنال‌های `http_401|403|404` و
  `http_sensitive_path` (تطبیق segment کامل، حتی با پاسخ 200)، و شکست ورود MRK از جدول `audit_events`
  (`auth.login` با نتیجه `failure|rate_limited`، فقط رکوردهای بعد از start). tail بدون descriptor باز: تغییر
  inode = rotate (باقی‌مانده از `<path>.1` خوانده می‌شود)، کوچک شدن = copytruncate؛ اولین بار از انتهای فایل.
  journald باینری مستقیم خوانده نمی‌شود (راهنما در `deploy/appliance/README.md`).
- **قواعد پیش‌فرض (builtin، قابل ویرایش/غیرفعال، غیرقابل حذف):** `ssh-bruteforce` 5/600s → 3600s؛ `mrk-login`
  10/600s → 1800s؛ `http-auth` (401/403) 30/60s → 900s؛ `http-404` 120/60s → 900s؛ `http-probe` 3/300s → 86400s.
- **ایمنی (به این ترتیب):** شکل (`/16` حداقل برای IPv4 و `/32` برای IPv6، loopback، unspecified/multicast/reserved)
  ← IP درخواست‌دهنده فعلی (`requester_ip`) ← آدرس‌های خود میزبان و gatewayهای bridge Docker (`host_address`) ←
  محدوده‌های خصوصی (`private_range`، مگر `allow_private_blocks`) ← allowlist مؤثر (`allowlisted`: allowlist کاربر +
  loopback + در صورت `allowlist_private` محدوده‌های خصوصی). هنگام روشن کردن enforce، IP درخواست‌دهنده خودکار به
  allowlist اضافه می‌شود (`auto: true`). هر block پیش‌فرض انقضا دارد (`default_ban_seconds`)؛ دائمی فقط با
  `duration_seconds: null` صریح در block دستی؛ سقف `max_blocks`.
- **Dry-run:** تشخیص‌ها در dry_run به‌صورت block با `simulated: true` ثبت می‌شوند و **هرگز** اعمال نمی‌شوند (حتی بعد از
  روشن کردن enforce)؛ block دستی همیشه واقعی است و فقط در enforce اعمال می‌شود.
- **Control Plane API** (`/api/v1/firewall`؛ GET با `firewall:read`، mutationها با `firewall:write` + CSRF؛ خطا به شکل
  `{"error": {"code", "message"}}`):

  | متد و مسیر | توضیح |
  |---|---|
  | `GET /status` | `configured`، `source` (`panel`/`env`)، `url`، `reachable`، `last_error`، `mode`، `helper{version, nft_available, force_dry_run, mode, effective_mode, table, local_addresses}`، `counts{active_blocks, simulated_blocks, rules_enabled, decisions_24h, allowlist}`، `desired_state_hash`، `applied_state_hash`، `in_sync`، `last_poll_at`، `last_apply_at`، `last_apply_error`، `sources{name:{ok,error,rotated,truncated,more,lines,signals}}` |
  | `PUT /config` `{url?=unix:/run/mrk-firewall/firewall.sock, key?}` | جفت‌سازی (کلید در SecretStore؛ env `MRK_FIREWALL_URL`+`MRK_FIREWALL_KEY_FILE` برنده است → 409 `firewall_managed_by_environment`) |
  | `DELETE /config` `{confirmation:"UNPAIR"}` | لغو جفت‌سازی (helper آخرین وضعیت را نگه می‌دارد؛ قبلش `mode: off` کنید) |
  | `POST /test` | `{ok, latency_ms, error_code?}` |
  | `GET /settings` / `PUT /settings` | merge جزئی: `mode` (`off|dry_run|enforce`؛ رفتن به enforce نیازمند `"confirmation":"ENFORCE"`)، `allowlist` `[{cidr, note}]`، `allowlist_private`، `allow_private_blocks`، `default_ban_seconds`، `max_ban_seconds`، `max_blocks`، `poll_interval_seconds` (5..3600، پیش‌فرض 15)، `history_retention_days` (30)، `notify`، `sources{sshd{enabled,path}, traefik{enabled,path}, mrk{enabled}}`، `sensitive_paths`. پاسخ شامل `sync{applied, error?}` |
  | `GET /rules` / `POST /rules` / `PATCH /rules/{id}` / `DELETE /rules/{id}` | `{name, signal_kinds ⊂ [ssh_failed_password, ssh_invalid_user, mrk_login_failure, http_401, http_403, http_404, http_sensitive_path], threshold, window_seconds, ban_seconds?, enabled?}`؛ نام تکراری 409، حذف builtin → 409 `builtin_rule` |
  | `GET /blocks?include_simulated=true` | blockهای فعال |
  | `POST /blocks` `{ip|cidr, duration_seconds?: int|null, reason}` | 201؛ خطاها: 422 با کدهای ایمنی بالا، `invalid_block`؛ 409 `already_blocked`/`max_blocks_reached` |
  | `DELETE /blocks/{id}` `{reason?}` | رفع مسدودی |
  | `POST /blocks/clear` `{confirmation:"UNBLOCK ALL"}` | kill switch: همه blockها (شامل simulated) حذف و فوراً اعمال |
  | `GET /events?ip=&action=&since=&before_id=&limit=` | تاریخچه تصمیم‌ها؛ `action ∈ block, would_block, skipped, manual_block, unblock, expire, clear, mode`؛ `next_before_id` برای صفحه بعد |
  | `GET /preview` | آنچه enforce الان اعمال می‌کند: `would_apply{allow, blocks}`، متن کامل `ruleset`، `simulated`، `state_hash` |

- **رویدادها:** `firewall.blocked` (warning) و `firewall.would_block` (info در dry_run) با
  `dedupe_key=firewall.blocked:<ip>`؛ `firewall.helper_offline` (error) / `firewall.helper_online` (info) با
  `dedupe_key=firewall.helper`.
- **audit:** `firewall.config.update`، `firewall.unpair`، `firewall.test`، `firewall.settings.update`،
  `firewall.mode.change`، `firewall.rule.create|update|delete`، `firewall.block.create|delete`، `firewall.blocks.clear`.
- **ذخیره‌سازی:** جدول‌های `firewall_rules`، `firewall_blocks`، `firewall_decisions` (migration `20261108_0009`)؛
  تنظیمات در `data_dir/control-plane/firewall.json` و جفت‌سازی در `firewall-helper.json` (+ SecretStore).
- **محدودیت‌های شناخته‌شده:** geo-block و rate limit (پیشرفته S7) هنوز نیست؛ پشت CDN/پروکسی، IP واقعی فقط وقتی در
  لاگ Traefik است که `forwardedHeaders.trustedIPs` تنظیم شده باشد؛ برای ورود MRK پشت Traefik باید
  `MRK_TRUSTED_PROXIES` تنظیم شود وگرنه IP داخلی Traefik دیده و (به‌عنوان خصوصی) رد می‌شود. وقتی یک block دربرگیرنده
  زودتر از block زیرمجموعه منقضی شود، زیرمجموعه در tick بعدی (≤ `poll_interval_seconds`) دوباره نصب می‌شود.

## 4. اسکن آسیب‌پذیری (`vuln`)

- بومی: استخراج فهرست پکیج‌ها از کانتینرهای در حال اجرا از طریق Agent (`GET /containers/{id}/archive` فقط برای
  مسیرهای ثابت پایگاه پکیج: dpkg، apk، rpm و lockfileهای رایج) و تطبیق با داده باز **OSV.dev** (دانلود dump
  اکوسیستم‌ها با پروکسی/mirror قابل تنظیم، ذخیره محلی).
- نتیجه per-image: CVEها با شدت، نسخه اصلاح‌شده، کانتینرهای متأثر؛ ignore با دلیل و انقضا؛ رویداد برای Critical/High جدید.

### 4.1 پیاده‌سازی (API نهایی)

**Agent:** قاعده allowlist جدید فقط `GET /containers/{64-hex}/archive?path=<P>` که `P` دقیقاً یکی از مسیرهای ثابت
`agent/package_files.PACKAGE_DB_PATHS` است (`/etc/os-release`، `/usr/lib/os-release`، `/var/lib/dpkg/status`،
`/var/lib/dpkg/status.d`، `/lib/apk/db/installed`، `/var/lib/rpm/rpmdb.sqlite`، `/usr/lib/sysimage/rpm/rpmdb.sqlite`،
`/var/lib/rpm/Packages` (فقط تشخیص وجود) و `{/app,/usr/src/app,/srv,/opt/app,/home/node/app,/code}/` ×
`package-lock.json|node_modules/.package-lock.json|requirements.txt|poetry.lock|Pipfile.lock`). مسیر از سمت فراخوان
نمی‌آید. route امضاشده `GET /v1/vuln/containers/{ref}/package-files` → `{container_id, image_id, image, state,
running, files:[{path, note: null|"symlink"|"present", entries:[{name, size, data_b64}]}], missing:[...],
errors:[{path, error: too_large|total_limit|invalid_archive|docker_<status>}], truncated}`. tar داخل Agent باز
می‌شود (فقط فایل‌های regular خود مسیر یا فرزند مستقیم؛ symlink دنبال نمی‌شود؛ `..` رد می‌شود)؛ در کانتینر چیزی
اجرا نمی‌شود.

**Control Plane** (`/api/v1/vuln`؛ GET با `vuln:read`، تغییرات با `vuln:write` + CSRF، همه audit):

| متد | مسیر | پاسخ |
|---|---|---|
| GET | `/summary` | `{enabled, agent_configured, images, counts:{critical,high,medium,low,unknown}, fixable, ignored, images_by_status:{critical,warning,secure,error,unsupported}, feeds_ready, running, phase, last_run_at, last_attempt_at, last_error, next_run_at}` |
| GET | `/images` | `{items:[{image_id, image, digest, os:{id,version_id,name,ecosystem}, packages_scanned, ecosystems, counts, status, fixable, ignored, containers:[{id,name,state,protected}], scanned_at, inventory_at, errors:[{code, feed?}], notes}], running, phase, last_run_at, …}` |
| GET | `/images/{image_id}/findings?severity=critical,high&q=&include_ignored=1&limit=500&offset=0` | `{image:{…همان شکل بالا}, total, items:[{id, aliases, package, binaries, installed, fixed, severity, score, summary, ecosystem, location, first_seen, ignored, ignore_id}]}`؛ `image_id` با یا بدون `sha256:`؛ 404 `image_not_found` |
| POST | `/scan` body `{refresh_inventory?: bool}` | 202 `{started, running}`؛ 409 `agent_not_configured` |
| GET/PUT | `/settings` | `{enabled, interval_hours, ecosystems_extra, feed_base_url, severities_to_notify, include_stopped, proxy_id, feed_max_mb}`؛ 422 `invalid_settings` / `proxy_not_found` |
| GET | `/ignores` | `{items:[{id, advisory, package, image, reason, expires_at, created_at, created_by, expired}]}` |
| POST | `/ignores` body `{advisory?, package?, image?, reason, expires_at?}` | 201 قاعده؛ الگوها glob (fnmatch، حساس به حروف)؛ `advisory` روی id و aliasها (CVE)، `package` روی پکیج مبدأ و binaryها؛ حداقل یکی از advisory/package؛ 422 `invalid_ignore` |
| DELETE | `/ignores/{id}` | `{deleted:true}`؛ 404 `ignore_not_found` |
| GET | `/feeds` | `{items:[{ecosystem, needed, url, updated_at, checked_at, records, size, status: ok|error|pending, error}], feed_base_url, supported}` |

- وضعیت image: `critical` (critical>0)، `warning` (high یا medium>0)، `error` (خطای Agent/feed)، `unsupported` (هیچ
  پکیجی)، وگرنه `secure`. شمارش‌ها پس از اعمال ignoreهای فعال (منقضی‌نشده) در زمان خواندن محاسبه می‌شوند.
- تطبیق: Debian/Ubuntu بر اساس پکیج **مبدأ** (`Source:` و نسخه مبدأ)، Alpine بر اساس origin (`o:`)، RPM با نام
  binary و نام SRPM؛ ترتیب نسخه dpkg، apk، rpmvercmp، PEP 440 و SemVer؛ رویدادهای `introduced/fixed/last_affected/limit`
  و فهرست صریح `versions`. شدت از بردار CVSS v3 (محاسبه base score)، سپس برچسب‌های database-specific/Ubuntu/
  urgency دبیان، سپس CVSS v2، وگرنه `unknown` (CVSS v4 هنوز محاسبه نمی‌شود).
- رویدادها: `vuln.new_critical` (critical)، `vuln.new_high` (error) و در صورت انتخاب `vuln.new_medium` (warning)/
  `vuln.new_low` (info)؛ یک رویداد برای هر image و شدت با فهرست advisoryهای جدید؛ dedupe دائمی per image+advisory
  (جدول `notified`؛ پس از حذف image پاک می‌شود)؛ `details: {image, image_id, severity, advisories, containers}`.
- Outbound: provider kind `vuln_feed` (یک ورودی `osv`). دانلود شرطی (`If-None-Match`/`If-Modified-Since`)، فقط
  feedهای لازم برای inventory به‌علاوه `ecosystems_extra`.
- محدودیت‌های فعلی (P2): Red Hat/SUSE/Fedora/Amazon Linux، rpm BerkeleyDB، پکیج‌های pip نصب‌شده بدون lockfile
  (site-packages)، `yarn.lock`/`pnpm-lock.yaml`، build info باینری‌های Go، SBOM خروجی، اسکن رجیستری داخلی.

## 5. مدیریت دیتابیس (`dbadmin`)

- اتصال‌ها: کشف از Dokploy/Agent یا تعریف دستی (host، port، user، رمز در SecretStore). دسترسی شبکه: MRK باید به
  شبکه دیتابیس دسترسی داشته باشد (راهنمای اتصال کانتینر MRK به شبکه Dokploy در پنل).
- PostgreSQL، MySQL/MariaDB، MongoDB، Redis؛ **پیش‌فرض فقط‌خواندنی** (تراکنش read-only، statement timeout، سقف
  ردیف)؛ حالت نوشتن فقط با `db:write`، در حالت پیشرفته و با تأیید تایپی؛ audit هر query (بدون داده).

### 5.1 پیاده‌سازی (API نهایی)

کد: `modules/dbadmin.py` (routes + service)، `dbadmin_engines.py` (درایورها)، `dbadmin_policy.py` (اعتبارسنجی،
سیاست مقصد، allowlistها، سقف‌ها)، `dbadmin_sql.py` (tokenizer). جدول `dbadmin_connections` (migration
`20261108_0010`). تنظیمات و درایورها: `docs/27` بخش «مدیریت دیتابیس».

همه زیر `/api/v1/dbadmin`. **CSRF روی همه POST/PUT/PATCH/DELETE** (حتی query خواندنی). خطاها با شکل استاندارد
`{"error": {"code", "message", "request_id"}}`.

| متد و مسیر | مجوز | توضیح |
|---|---|---|
| `GET /settings` · `PUT /settings` | read · write | تنظیمات (`docs/27`)؛ PUT merge جزئی، کلید ناشناخته/خارج بازه → `422 invalid_settings` |
| `GET /network-guide` | read | `{network: "dokploy-network", summary, compose_snippet, docker_command, default_ports, notes[]}` |
| `GET /discover` | read | `{dokploy: {available, error_code?, items[]}, agent: {available, error_code?, items[]}, network}` |
| `GET /connections` | read | `{items: [Connection]}` |
| `GET /connections/{id}` | read | `Connection` |
| `POST /connections` | write | بدنه `{name, engine, host, port?, database?, username?, password?, tls_mode?, options?}` → `201 Connection` |
| `PATCH /connections/{id}` | write | همان فیلدها (اختیاری) + `clear_password: bool` |
| `DELETE /connections/{id}` | write | بدنه `{"confirmation": "<name>"}` |
| `POST /connections/{id}/test` | read | `{ok, latency_ms, server_version, user, database, …}`؛ `last_tested_at/last_test_ok` ذخیره می‌شود |
| `GET /connections/{id}/schema` | read | `{engine, database, namespace_kind: "schema"\|"database", namespaces: [{name, tables: [{name, type, rows_estimate, size_bytes}], keys?}], users[], truncated}` |
| `GET /connections/{id}/tables/{name}` | read | `?schema=&page=1&limit=50(≤500)&sort=-col,col2&filter=<JSON>` → `{schema, table, columns[{name,type,nullable,default}], indexes[], primary_key[], rows_estimate, size_bytes, result_columns[], rows[][], row_count, has_more, truncated, truncated_reason, truncated_cells, page, limit, sort[], elapsed_ms}` |
| `POST /connections/{id}/query` | read (+write برای `write: true`) | زیر |
| `POST /connections/{id}/export` | read | CSV stream (`text/csv`، `Content-Disposition: attachment`) |

- **Connection:** `{id, name, engine: postgres|mysql|mariadb|mongo|redis, host, port, database, username, tls_mode:
  disable|require|verify, options, password_configured, write_confirmation: "WRITE <name>", env_hints[],
  last_tested_at, last_test_ok, created_at, updated_at}` — رمز هرگز برگردانده نمی‌شود. `port` پیش‌فرض بر اساس engine
  (5432/3306/27017/6379). `database` برای Redis شماره 0..255. `options`: postgres `application_name`، mysql/mariadb
  `charset`، mongo `auth_source` (پیش‌فرض `admin`). خطاها: `name_taken` 409، `password_required`، `invalid_host`،
  `destination_forbidden` (loopback/link-local/metadata؛ در test/query هم بررسی می‌شود)، `confirmation_required`.
- **discover items:** Dokploy (از `project.all`، فقط فیلدهای غیرمحرمانه): `{source: "dokploy", engine, name, project,
  environment, host: appName, port: پیش‌فرض, database, username, status, password_hint, env_hints, network,
  configured}`. Agent (`/v1/backup/sources`): `{source: "agent", engine, name, container, image, state, protected,
  host: نام کانتینر, port, password_hint, env_hints, configured}`. **رمزها هرگز خوانده نمی‌شوند**؛ کاربر رمز را
  وارد می‌کند (نام متغیرهای env برای راهنمایی).
- **filter:** آرایه JSON (حداکثر 20) از `{column, op, value}` با `op` ∈ `eq ne lt lte gt gte like ilike is_null
  not_null in` (in: 1..100 مقدار)؛ ستون باید در جدول وجود داشته باشد (Mongo: هر field غیر `$`)؛ همه مقدارها
  پارامتری. `sort`: حداکثر 3 ستون، `-` = نزولی؛ بدون sort با کلید اصلی مرتب می‌شود. Redis: `422 unsupported_for_engine`.
- **query بدنه:** دقیقاً یکی از `text` (SQL) | `mongo: {collection, op, filter, projection, sort, limit, skip,
  pipeline, update, documents|document, key, database}` | `redis: {command, args[]}` + `database?` (MySQL پیش‌فرض/
  Mongo) + `write: false` + `dry_run: false` + `confirmation?`.
  - **خواندنی (پیش‌فرض):** PostgreSQL `SET TRANSACTION READ ONLY` + `statement_timeout` محلی، فقط
    `SELECT/WITH/VALUES/TABLE/SHOW/EXPLAIN`، توابع مدیریتی/فایلی (`pg_terminate_backend`، `pg_read_file`،
    `dblink*`، `set_config`، `lo_export`، advisory lock …) رد؛ اجرا با extended protocol (`prepare=True`، یک دستور).
    MySQL/MariaDB `START TRANSACTION READ ONLY` + `max_execution_time`/`max_statement_time`، فقط
    `SELECT/WITH/SHOW/EXPLAIN/DESCRIBE/TABLE/VALUES`، `INTO OUTFILE/DUMPFILE`، `LOAD_FILE`، `GET_LOCK` و کامنت
    اجرایی `/*! */` رد؛ بدون MULTI_STATEMENTS و `local_infile`. Mongo فقط `find/aggregate/count/distinct`، بدون
    `$out/$merge/$where/$function/$accumulator` (در هر عمقی). Redis فقط allowlist خواندنی (GET، MGET، HGETALL،
    LRANGE، SMEMBERS، ZRANGE، SCAN (COUNT ≤1000)، TYPE، TTL، INFO، DBSIZE، XRANGE، … ؛ KEYS/SORT/EVAL/CONFIG/FLUSH*
    هرگز).
  - **نوشتن:** `db:write` (وگرنه 403) + `"write": true` + `"confirmation": "WRITE <name>"` (وگرنه
    `422 confirmation_required`). SQL: هر دستور، **فقط یک دستور** (tokenizer: رشته‌ها، `E''`، `$tag$`، identifierها،
    کامنت‌های `--`/`#`/`/* */` تودرتو در PG). Mongo: `insert_one/insert_many(≤1000)/update_one/update_many/delete_one/
    delete_many` روی یک collection با filter صریح و غیرخالی (update فقط با operator یا pipeline). Redis: SET، DEL،
    UNLINK، EXPIRE، PEXPIRE، PERSIST، HSET، HDEL، LPUSH، RPUSH، LREM، LSET، SADD، SREM، ZADD، ZREM، INCR*، DECR*،
    RENAME، XADD، XDEL.
  - **`dry_run: true`** (فقط با write و confirmation): SQL `INSERT/UPDATE/DELETE` (+`MERGE` PG، `REPLACE` MySQL)
    در تراکنشی که rollback می‌شود → `affected_rows`؛ Mongo: شمارش `count_documents(filter)`؛ دیگر موارد
    `422 dry_run_unsupported`.
  - **پاسخ:** `{columns: [{name, type}], rows: [[…]], row_count, truncated, truncated_reason: row_limit|response_size|
    null, truncated_cells, affected_rows, statement_kind, elapsed_ms, mode: read|write, dry_run, rolled_back,
    statement_sha256, cursor? (Redis SCAN), inserted_ids?/matched? (Mongo)}`. سقف 1000 ردیف، سلول 64KiB، پاسخ 5MiB
    (قابل تنظیم). باینری → `{"$binary": base64, bytes, truncated?}`؛ عدد بزرگ‌تر از 2^53، Decimal و زمان → رشته.
- **export بدنه:** دقیقاً یکی از `table: {name, schema?, filter?, sort?}` | `text` (فقط خواندنی؛ PG فقط
  SELECT/WITH/VALUES/TABLE با server-side cursor) | `mongo` (find/aggregate) + `max_rows?` (≤ `export_max_rows`) +
  `excel_safe: true` (پیشوند `'` برای متن‌های شروع‌شونده با `= + - @`). Redis → `422 export_unsupported`.
- **خطاهای اجرا:** `db_unreachable` 502، `db_auth_failed` 502، `db_unresolvable` 502، `db_timeout` 504،
  `db_query_failed` 422 (پیام driver redact‌شده، بدون رمز)، `read_only_violation` 422، `sql_multiple_statements`،
  `sql_unterminated`، `sql_empty`، `sql_executable_comment`، `connection_busy` 429، `table_not_found` 404،
  `schema_required`، `secret_unavailable` 409.
- **audit (بدون متن query یا داده؛ object_type `dbadmin_connection`):** `dbadmin.connection.create|update|delete|
  test`، `dbadmin.settings.update`، `dbadmin.schema.read`، `dbadmin.table.read` (`<id>:<hash16>`)،
  `dbadmin.query.read|dry_run|write` و `dbadmin.export` با `object_id = "<connection_id>:<sha256 کامل>"`، نتیجه
  `success|failure|denied`.
- **منابع:** هر عملیات یک اتصال تازه (بدون pool)، حداکثر 2 هم‌زمان per connection؛ ردیف اتصال و رمز قبل از
  I/O خوانده و session دیتابیس Control Plane (PGlite) بسته می‌شود؛ deadline سخت = connect + statement timeout + 10s.
