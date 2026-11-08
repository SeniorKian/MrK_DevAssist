# 28 — ماژول‌های کنترل سرور در کنار Dokploy

وضعیت: **مصوب مالک — 2026-11-08؛ Gate 16 تا 19 پیاده‌سازی شد**
مرتبط: `docs/20` (معماری ماژولار)، `docs/23` (موتورهای بومی)، `docs/27` (اصل تنظیم‌پذیری)

## 1. هدف و اصول

MRK باید کنار Dokploy، کنترل کامل سرور PaaS را از یک پنل ساده بدهد. ماژول‌های انتخاب‌شده توسط مالک:

| # | ماژول | شبیه به | اولویت |
|---|---|---|---|
| S1 | اتصال به Dokploy | — | P0 |
| S2 | مانیتورینگ منابع سرور و کانتینرها | Netdata، Beszel | P0 |
| S3 | مشاهده لاگ کانتینرها | Dozzle | P0 |
| S4 | مدیریت Docker (کانتینر، image، volume، network) | Portainer | P0 |
| S5 | مرکز اعلان‌ها (Telegram، بله، Email، Webhook) | ntfy، Gotify | P0 |
| S6 | بکاپ سرور و دیتابیس‌ها | restic، Kopia | P1 |
| S7 | فایروال و ضدحمله | CrowdSec، Fail2ban | P1 |
| S8 | اسکن آسیب‌پذیری image | Trivy | P1 |
| S9 | مدیریت دیتابیس | Adminer | P1 |
| S10 | پیگیری آپدیت image | Diun | P1 |

اصول غیرقابل‌مذاکره:

1. **Dokploy دست‌نخورده می‌ماند.** MRK هرگز فایل، دیتابیس، Traefik یا شبکه Dokploy را مستقیم تغییر نمی‌دهد. هر
   تغییری روی اپ‌های Dokploy فقط از طریق API رسمی Dokploy انجام می‌شود. کانتینرهای خود Dokploy
   (`dokploy`، `dokploy-postgres`، `dokploy-redis`، `dokploy-traefik`) و هر کانتینر با label مدیریت Dokploy
   در فهرست «محافظت‌شده» هستند: فقط خواندنی، مگر کاربر در حالت پیشرفته و با تأیید تایپی استثنا بگذارد.
2. **سربار ناچیز.** هدف کل Host Agent کمتر از 1٪ CPU و 60MB RAM در حالت idle. هیچ polling سنگین، هیچ
   streaming دائمی لاگ؛ لاگ فقط هنگام باز بودن صفحه stream می‌شود.
3. **بومی.** همه با کد خودمان؛ فقط کتابخانه‌های پایه (درایور دیتابیس، رمزنگاری). بدون image آماده.
4. **ساده/پیشرفته.** هر ماژول یک نمای ساده برای کار روزمره و یک بخش پیشرفته جمع‌شونده دارد (بخش 5).
5. **همه‌چیز قابل‌تنظیم** (`docs/27`): بازه‌ها، آستانه‌ها، retention و مقصدها از پنل.

## 2. معماری: Host Agent

کانتینر MRK عمداً به Docker socket، host network و `/proc` میزبان دسترسی ندارد و نباید داشته باشد. ماژول‌های
S2 تا S10 به این دسترسی‌ها نیاز دارند، پس یک جزء جدا لازم است:

```text
┌───────────── MRK Appliance (فعلی، بدون امتیاز) ─────────────┐
│ Control Plane ── module adapters ── notifications/audit/RBAC │
└───────────────┬─────────────────────────────┬────────────────┘
                │ HTTPS + mTLS / Unix socket  │ HTTPS (API key)
                ▼                             ▼
┌──────── mrk-agent (همان image، entrypoint جدا) ──┐   ┌─ Dokploy ─┐
│ Docker API allowlist proxy (فقط عملیات مجاز)     │   │ API رسمی  │
│ host metrics: /proc، cgroup v2 (فقط خواندنی)     │   └───────────┘
│ firewall: nftables table اختصاصی `inet mrk`      │
│ backup worker: خواندن volumeها، رمزنگاری MRKBKP2 │
└───────────────────────────────────────────────────┘
```

- **یک image، دو نقش:** `mrk-agent` همان image MRK با `--entrypoint mrk-agent` است؛ پس «یک image» حفظ
  می‌شود و فقط یک service دوم در compose اضافه می‌شود. Agent اختیاری است؛ بدون آن رجیستری‌ها مثل قبل کار
  می‌کنند و ماژول‌های S2–S10 «نیازمند Agent» نمایش داده می‌شوند.
- **حداقل امتیاز به تفکیک قابلیت:** Docker socket فقط read-write برای Agent، با allowlist در کد خودمان
  (هیچ `exec`، `create` با `privileged`، mount میزبان یا `build` آزاد). `CAP_NET_ADMIN` فقط اگر S7 فعال باشد.
  `/proc` و `/sys/fs/cgroup` میزبان فقط خواندنی.
- **ارتباط امن:** Agent فقط روی Unix socket مشترک یا loopback گوش می‌دهد؛ هر درخواست با کلید مشترک HMAC
  و timestamp امضا می‌شود (replay window 30s). Agent خودش RBAC ندارد؛ RBAC و audit در Control Plane است.
- **Fail-safe:** خرابی Agent فقط ماژول‌های وابسته را degraded می‌کند.

## 3. ماژول‌ها

### S1 — اتصال به Dokploy

- اتصال با آدرس Dokploy و API key (ذخیره رمزنگاری‌شده در secret store). تست اتصال قبل از ذخیره.
- **ساده:** فهرست پروژه‌ها و اپ‌ها با وضعیت، آخرین deploy، دکمه Redeploy/Stop/Start، لاگ آخرین build،
  دامنه‌های هر اپ.
- **پیشرفته:** تاریخچه deployها، rollback به deploy قبلی، متغیرهای محیطی (فقط نمایش mask‌شده و ویرایش با
  تأیید)، بکاپ‌های دیتابیس Dokploy، webhook.
- **حفاظت از Dokploy:** فقط endpointهای رسمی API (`/api/<router>.<procedure>` با هدر `x-api-key` — دقیق
  فهرست با نسخه pin‌شده Dokploy تأیید می‌شود)؛ rate limit سمت MRK (پیش‌فرض 2 درخواست در ثانیه)؛ cache
  وضعیت 15 ثانیه؛ عملیات مخرب (stop، حذف) با تأیید و audit.
- بکاپ دیتابیس‌های تعریف‌شده در Dokploy ترجیحاً از طریق قابلیت backup خود Dokploy trigger می‌شود تا کار
  تکراری انجام نشود.

### S2 — مانیتورینگ منابع

- Agent هر N ثانیه (پیش‌فرض 15) از `/proc/stat`، `/proc/meminfo`، `/proc/net/dev`، `statvfs` و
  `cgroup v2` (`cpu.stat`، `memory.current`، `io.stat`) هر کانتینر می‌خواند؛ بدون Docker stats API stream.
- ذخیره rollup دقیقه‌ای و ساعتی به‌صورت batch (یک insert در هر دقیقه) برای کم کردن بار PGlite؛ retention
  قابل‌تنظیم (پیش‌فرض 7 روز دقیقه‌ای، 90 روز ساعتی).
- **ساده:** کارت CPU/RAM/دیسک/شبکه سرور، 5 کانتینر پرمصرف، هشدار دیسک.
- **پیشرفته:** نمودار هر کانتینر، p95، آستانه‌های هشدار سفارشی، export Prometheus.

### S3 — لاگ کانتینرها

- live tail فقط هنگام باز بودن صفحه (`/containers/{id}/logs?follow=1`) با SSE به مرورگر؛ قطع خودکار پس از
  بسته شدن صفحه یا 10 دقیقه بیکاری.
- جست‌وجو در بازه زمانی (on-demand، `since/until`) با سقف حجم؛ highlight و فیلتر سطح.
- **ساده:** انتخاب اپ، tail زنده، جست‌وجوی متن، دانلود.
- **پیشرفته:** regex، چند کانتینر هم‌زمان، نگه‌داری پایدار لاگ‌های انتخابی با retention (P2).
- redaction secretها با همان `redact_text` موجود.

### S4 — مدیریت Docker

- فهرست کانتینر/image/volume/network، جزئیات، start/stop/restart، pull، حذف image بی‌استفاده.
- prune فقط با **پیش‌نمایش** (چه چیزی حذف و چقدر فضا آزاد می‌شود) و تأیید تایپی؛ volumeهای متصل به
  کانتینرهای Dokploy هرگز در prune پیش‌فرض نیستند.
- `exec` در MVP وجود ندارد (P2 با audit کامل و فقط در حالت پیشرفته).
- **ساده:** فهرست کانتینرها با وضعیت و دکمه restart، فضای اشغالی imageها.
- **پیشرفته:** volume/network، inspect کامل، prune، labelها.

### S5 — مرکز اعلان‌ها

- کانال‌ها: Telegram Bot API، **بله** (Bot API سازگار با Telegram روی `tapi.bale.ai`)، Email (SMTP با
  STARTTLS)، Webhook عمومی (JSON با امضای HMAC).
- قواعد routing بر اساس ماژول/شدت/برچسب، dedupe، quiet hours، تکرار تا acknowledge، تست ارسال.
- همه ماژول‌ها (رجیستری، Uptime، بکاپ، فایروال، دیسک، deploy) فقط به این مرکز event می‌فرستند.
- ارسال از طریق `netresolve` (DNS دلخواه کاربر) و retry با backoff؛ لاگ تحویل بدون payload حساس.

### S6 — بکاپ سرور و دیتابیس‌ها

- منابع: volumeهای Docker (Agent مستقیم از `/var/lib/docker/volumes` با mount فقط‌خواندنی می‌خواند)،
  دیتابیس‌ها (PostgreSQL با COPY منطقی یا dump از طریق Dokploy؛ MySQL/MariaDB؛ MongoDB؛ Redis RDB).
- فرمت: همان MRKBKP2 (chunked AES-256-GCM) — یک موتور رمزنگاری برای کل محصول.
- مقصدها: دیسک محلی، S3-compatible (امضای SigV4 بومی؛ سازگار با ArvanCloud/لیارا/MinIO)، SFTP (P2).
- زمان‌بندی cron، retention (تعداد/روز/GFS)، تست restore خودکار دوره‌ای، اعلان موفق/ناموفق.
- **ساده:** «از این اپ هر شب بکاپ بگیر و 7 تا نگه دار» + restore با یک کلیک (با تأیید).
- **پیشرفته:** چند مقصد، GFS، رمز جدا، dedup (P2)، hooks قبل/بعد.

### S7 — فایروال و ضدحمله

- منابع تشخیص: access log Traefik (JSON)، لاگ SSH (journald یا `/var/log/auth.log`)، لاگ ورود MRK.
- قواعد: N شکست در بازه، اسکن مسیرهای حساس، نرخ بالای 4xx/5xx، User-Agentهای مخرب؛ هر قاعده قابل‌تنظیم.
- اجرا: جدول nftables **اختصاصی** `inet mrk` با set دارای timeout در hook `prerouting` (priority raw)؛ این
  ترافیک پورت‌های Docker را هم پوشش می‌دهد و هیچ chain مربوط به Docker یا Dokploy دست نمی‌خورد.
- ایمنی: allowlist اجباری IP مدیر (و تشخیص خودکار IP فعلی پنل)، حالت dry-run پیش‌فرض، انقضای خودکار
  مسدودسازی، دکمه «لغو همه» و حذف کامل جدول هنگام غیرفعال کردن ماژول.
- **ساده:** روشن/خاموش، فهرست IPهای مسدود، رفع مسدودی، allowlist.
- **پیشرفته:** ویرایش قواعد، geo-block (با پایگاه داده IP باز)، rate limit، تاریخچه رخدادها.

### S8 — اسکن آسیب‌پذیری

- بومی: Agent لایه‌های image را می‌خواند و فهرست پکیج‌ها را استخراج می‌کند (dpkg، apk، rpm و lockfileهای
  npm/pip/go/cargo) و با پایگاه داده باز **OSV.dev** (دانلود دوره‌ای dumpها، قابل mirror محلی) تطبیق می‌دهد.
- نتیجه: CVE، شدت، نسخه اصلاح‌شده، کانتینرهای آسیب‌پذیر در حال اجرا؛ اعلان برای Critical/High جدید.
- **ساده:** وضعیت هر اپ (امن/هشدار/بحرانی) و «چه چیزی را آپدیت کنم».
- **پیشرفته:** جزئیات CVE، ignore با دلیل و تاریخ انقضا، SBOM خروجی، اسکن رجیستری داخلی.

### S9 — مدیریت دیتابیس

- اتصال به دیتابیس‌های اپ‌ها (کشف خودکار از Dokploy یا دستی): PostgreSQL، MySQL/MariaDB، MongoDB، Redis.
- **پیش‌فرض فقط‌خواندنی**: تراکنش read-only، statement timeout، سقف تعداد ردیف، audit هر query.
- **ساده:** فهرست جدول‌ها، مشاهده داده با صفحه‌بندی و فیلتر، export CSV.
- **پیشرفته:** ویرایشگر SQL، حالت نوشتن (با تأیید تایپی و نمایش پیش‌نمایش تعداد ردیف‌های متأثر)، ساختار
  جدول، indexها، کاربرها.

### S10 — پیگیری آپدیت image

- مقایسه digest image در حال اجرا با digest تگ در رجیستری مبدأ با درخواست `HEAD` manifest (از سهمیه
  Docker Hub کم نمی‌کند)، از طریق mirrorها و DNS تنظیم‌شده.
- **هرگز آپدیت خودکار کور:** فقط اعلان و پیشنهاد؛ آپدیت اپ‌های Dokploy از طریق Redeploy در Dokploy.
- **ساده:** فهرست «آپدیت موجود» با دکمه رفتن به اپ.
- **پیشرفته:** قواعد semver، ignore، زمان‌بندی بررسی.

## 4. بودجه منابع (اضافه بر `docs/23`)

| جزء | RAM idle / peak | CPU | توضیح |
|---|---|---|---|
| mrk-agent | 40 / 150 MB | <1٪ idle | بدون polling سنگین؛ لاگ فقط on-demand |
| ماژول‌های S1–S10 در Control Plane | +40 / +150 MB | کم | jobها در task queue موجود |

## 5. الگوی ساده/پیشرفته (همه ماژول‌ها)

- سوییچ سراسری در نوار بالا (پیش‌فرض ساده، ذخیره برای هر کاربر) + یک بخش «پیشرفته» جمع‌شونده داخل هر
  صفحه که در حالت پیشرفته باز است.
- حالت فقط نمایش را تغییر می‌دهد؛ RBAC، تأیید عملیات مخرب و audit در هر دو حالت یکسان‌اند.

## 6. فازبندی پیشنهادی

1. **Gate 16 — Host Agent + S5 اعلان‌ها:** پایه امن و کانال اعلان برای همه ماژول‌های بعدی.
2. **Gate 17 — S1 Dokploy + S2 مانیتورینگ + S3 لاگ + S4 Docker.**
3. **Gate 18 — S6 بکاپ + S10 آپدیت.**
4. **Gate 19 — S7 فایروال + S8 اسکن + S9 دیتابیس.**

هر Gate: پیاده‌سازی، تست امنیتی (به‌خصوص allowlist Docker و nftables)، تست «Dokploy سالم ماند» (deploy، Traefik
و دیتابیس Dokploy قبل و بعد)، و مستندات.

## 7. ریسک‌ها

| ریسک | کاهش |
|---|---|
| دسترسی Docker socket = دسترسی root میزبان | allowlist سخت در Agent، بدون exec/privileged، Agent جدا از Control Plane، امضای درخواست‌ها |
| فایروال کاربر را از سرور بیرون کند | allowlist اجباری، dry-run پیش‌فرض، انقضای خودکار، حذف جدول هنگام خاموش کردن |
| مزاحمت برای Dokploy | فقط API رسمی، فهرست محافظت‌شده، rate limit، تست سلامت Dokploy در هر Gate |
| تغییر API Dokploy بین نسخه‌ها | adapter نسخه‌دار، contract test روی نسخه pin‌شده، تشخیص نسخه هنگام اتصال |
| بار اضافه روی PGlite | rollup و batch، retention، امکان PostgreSQL خارجی |

## 8. یادداشت‌های پیاده‌سازی Gate 16 — Host Agent (پایه، فقط خواندنی)

- **فرایند:** `mrk-agent` (console script در `apps/control-plane/pyproject.toml`) از همان image؛ کد در
  `mrk_control_plane/agent/` و ماژول Control Plane در `mrk_control_plane/modules/host_agent.py`.
- **ارتباط:** به‌جای Unix socket مشترک (بند ۲)، Agent روی `MRK_AGENT_LISTEN` (پیش‌فرض `0.0.0.0:7070`) فقط در
  شبکه compose داخلی `mrk-agent` (`internal: true`، بدون egress) گوش می‌دهد و **هیچ پورتی publish نمی‌شود**.
  هر درخواست (جز `GET /v1/health` که فقط `{"status":"ok"}` می‌دهد) با HMAC-SHA256 روی
  `METHOD\nPATH?QUERY\nTIMESTAMP\nNONCE\nSHA256(BODY)` و هدرهای `X-MRK-Timestamp`، `X-MRK-Nonce`،
  `X-MRK-Signature` (hex) امضا می‌شود؛ اختلاف ساعت بیش از ۳۰ ثانیه، nonce تکراری در ۶۰ ثانیه (cache محدود
  ۱۰٬۰۰۰؛ اگر پر شود رد می‌شود نه evict) یا امضای نادرست → `401`. Agent هیچ مسیر غیر GET ندارد (`405`).
- **کلید:** اولین اجرا ۳۲ بایت تصادفی در `MRK_AGENT_STATE_DIR/agent.key` (base64url، mode 0600) می‌سازد و فقط
  همان بار در لاگ پیام pairing چاپ می‌کند. در Control Plane کلید در SecretStore رمز می‌شود و
  `data_dir/control-plane/agent.json` فقط `url` و ارجاع secret دارد؛ یا با `MRK_AGENT_URL` + `MRK_AGENT_KEY_FILE`
  از محیط (محیط برنده است و در UI «managed by environment»).
- **Docker allowlist در کد:** فقط `GET` روی `/version`، `/info`، `/containers/json?all=1`، `/containers/{id}/json`،
  `/images/json`، `/volumes`، `/networks`، `/system/df`. هر مسیر دیگر، هر query دیگر، `..`، `%`، `//` قبل از
  ارسال رد می‌شود. نسخه API از `/version` گرفته می‌شود. labelها فقط زیرمجموعه امن برگردانده می‌شوند (labelهای
  دلخواه مثل basic-auth Traefik ممکن است secret داشته باشند).
- **محافظت از Dokploy:** کانتینری `protected: true` است که نامش با `MRK_AGENT_PROTECTED_NAME_REGEX`
  (پیش‌فرض `^/?dokploy([-._]|$)`، شامل نام task‌های swarm) بخورد، یا `com.docker.compose.project` در
  `MRK_AGENT_PROTECTED_COMPOSE_PROJECTS` (پیش‌فرض `dokploy`) باشد، یا `com.docker.swarm.service.name` با regex
  بخورد، یا کلید labelی با `MRK_AGENT_PROTECTED_LABEL_PREFIXES` (پیش‌فرض `com.dokploy,dokploy`) شروع شود.
  Gate 16 هیچ عملیاتی روی هیچ کانتینری ندارد؛ Gateهای بعدی باید protected را رد کنند.
- **متریک میزبان:** از `MRK_AGENT_HOST_PROC` (پیش‌فرض `/host/proc`، وگرنه `/proc`) و `statvfs` روی
  `MRK_AGENT_HOST_ROOT` (فهرست با کاما؛ پیش‌فرض `/host/root` اگر mount شده، وگرنه `/`).
- **ریسک mount ریشه:** `/:/host/root:ro` اختیاری است (فقط برای فضای دیسک و hostname). دسترسی به Docker socket
  به‌خودی‌خود معادل root است، پس این mount ریسک حاشیه‌ای کمی اضافه می‌کند؛ با این حال قابل حذف است.
- **API Control Plane:** `GET /api/v1/agent/status` (agent:read)، `PUT /api/v1/agent/config` و
  `DELETE /api/v1/agent/config` (`{"confirmation":"UNPAIR"}`) و `POST /api/v1/agent/test` (agent:write + CSRF،
  audit بدون secret)، `GET /api/v1/agent/containers` و `GET /api/v1/agent/summary` (agent:read). خطاها:
  `409 agent_not_configured`، `409 agent_managed_by_environment`، `422 invalid_agent_url|invalid_agent_key|
  agent_key_required|confirmation_required`، `502 agent_unreachable|agent_auth_failed`،
  `503 agent_docker_unavailable`. درخواست‌های خروجی: فقط http(s)، بدون credential/path/query، timeout 5s،
  بدون redirect، `trust_env=False`، سقف پاسخ 4MiB.
- **پایش:** هر `MRK_AGENT_CHECK_INTERVAL_SECONDS` (پیش‌فرض ۶۰، بازه ۵ تا ۳۶۰۰) `GET /v1/info`؛ در تغییر وضعیت
  `agent.offline` (error) یا `agent.online` (info) با `dedupe_key="agent.reachability"` منتشر می‌شود.
- **Compose:** سرویس `mrk-agent` زیر `profiles: ["agent"]` در `compose.yaml` و
  `deploy/appliance/compose.production.yaml`: `user 10001:10001` + `group_add ${MRK_DOCKER_GID:-999}`،
  `read_only`، `cap_drop: ALL`، `no-new-privileges`، 256m / 0.5 CPU، volume نام‌دار `mrk-agent-state` روی `/data`.

## 9. یادداشت‌های پیاده‌سازی Gate 17 — S1 اتصال به Dokploy (API رسمی، نسخه pin‌شده)

- **نسخه pin‌شده:** Dokploy **v0.31.0** (انتشار پایدار 2026-11-05، commit `3ac1c8f`)؛ با v0.30.x نیز سازگار است.
  نسخه‌های قدیمی‌تر (≤ v0.28) با feature-detect و کاهش قابلیت پشتیبانی می‌شوند (پایین).
- **منبع:** کد Dokploy در [`apps/dokploy/server/api/routers/*`](https://github.com/Dokploy/dokploy/tree/v0.31.0/apps/dokploy/server/api/routers)،
  [`pages/api/[...trpc].ts`](https://github.com/Dokploy/dokploy/blob/v0.31.0/apps/dokploy/pages/api/%5B...trpc%5D.ts)،
  [`packages/server/src/lib/auth.ts`](https://github.com/Dokploy/dokploy/blob/v0.31.0/packages/server/src/lib/auth.ts) (`validateRequest`)،
  schemaها در [`packages/server/src/db/schema`](https://github.com/Dokploy/dokploy/tree/v0.31.0/packages/server/src/db/schema)،
  adapter [`@dokploy/trpc-openapi@0.0.19`](https://www.npmjs.com/package/@dokploy/trpc-openapi) و راهنمای رسمی
  [docs.dokploy.com/docs/api](https://docs.dokploy.com/docs/api).
- **قرارداد HTTP:** پایه `<panel>/api/<router>.<procedure>`؛ هدر `x-api-key` (کلید از Settings → Profile →
  API/CLI؛ مدیر باید دسترسی API بدهد). procedure از نوع query → `GET` با ورودی در query string (adapter
  مقادیر را coerce می‌کند)؛ mutation → `POST` با `Content-Type: application/json`. پاسخ همان خروجی خام procedure
  است (بدون wrapper tRPC و بدون superjson)؛ mutation بدون خروجی بدنه خالی برمی‌گرداند. خطا: `{"message","code"}`
  با HTTP status متناظر tRPC. کلید نامعتبر/منقضی **یا عبور از rate limit اختیاری خود کلید** (better-auth) همه
  → `401 {"message":"Unauthorized"}`. procedure ناموجود یا method اشتباه → `404 {"message":"Not found"}`
  (این پیام دقیق برای feature-detect استفاده می‌شود؛ NOT_FOUND سرویس پیام خودش را دارد مثل
  `Application not found`). `GET /api/health` عمومی است (`{"ok":true}`) ولی کلید را بررسی نمی‌کند.

| کاربرد در MRK | procedure | method / ورودی | خروجی (فیلدهای مصرفی) |
|---|---|---|---|
| تست اتصال و نسخه | `settings.getDokployVersion` | GET | رشته نسخه (مثل `v0.31.0`) |
| درخت پروژه‌ها | `project.all` | GET | `[{projectId,name,description,environments:[{environmentId,name,applications:[{applicationId,name,applicationStatus}],compose:[{composeId,name,composeStatus}],postgres/mysql/mariadb/mongo/redis:[{<x>Id}]}]}]` — برای owner/admin دیتابیس‌ها **فقط id** دارند |
| تکمیل نام/وضعیت دیتابیس‌ها | `project.one` | GET `projectId` | همان ساختار با `name, appName, applicationStatus` برای همه سرویس‌ها |
| آخرین deployها (درخت + polling) | `deployment.allCentralized` | GET | `[{deploymentId,title,status,createdAt,finishedAt,errorMessage,applicationId,composeId,application/compose:{name,environment:{project:{name}}}}]` (از v0.30) |
| دامنه‌ها | `domain.byApplicationId` / `domain.byComposeId` | GET `applicationId` / `composeId` | `[{host,path,https,port}]` |
| جزئیات سرویس | `application.one`، `compose.one`، `postgres.one`، `mysql.one`، `mariadb.one`، `mongo.one`، `redis.one` | GET `<type>Id` | سرویس + `environment.project`، `domains`، `deployments` (app/compose). **شامل env و رمزها؛ MRK فقط فیلدهای whitelist را برمی‌گرداند** |
| deploy | `application.deploy`، `compose.deploy`، `<db>.deploy` | POST `{<type>Id, title?}` | بدون خروجی (صف Dokploy) |
| redeploy | `application.redeploy`، `compose.redeploy`؛ دیتابیس: `<db>.reload` | POST `{<type>Id}`؛ reload: `{<db>Id, appName}` | — |
| start / stop | `<type>.start`، `<type>.stop` | POST `{<type>Id}` | خروجی (شامل secret) خوانده و دور ریخته می‌شود |
| لاگ deployment | `deployment.readLogs` | GET `deploymentId`, `tail` (1..10000) | متن (`tail -n` فایل لاگ؛ از v0.30) |

- **وضعیت‌ها:** سرویس `applicationStatus`/`composeStatus` ∈ `idle|running|done|error` (running یعنی در حال
  deploy، done یعنی آخرین deploy موفق)؛ deployment ∈ `running|done|error|cancelled`؛ مقدار ناشناخته → `unknown`.
  نوع `libsql` (جدید در Dokploy) در قرارداد Gate 17 نیست و نادیده گرفته می‌شود.
- **هرگز استفاده نمی‌شود:** `<db>.rebuild` (بازسازی volume/داده)، `*.delete|remove`، `deployment.killProcess`،
  `settings.*` تغییردهنده؛ redeploy دیتابیس فقط `reload` (stop + start) است.
- **feature-detect:** `deployment.allCentralized` و `deployment.readLogs` در v0.28 نیستند → `last_deployment: null`
  و `{"available": false}`؛ polling خطای deploy در این حالت از تغییر وضعیت سرویس به `error` در `project.all` است.
  `settings.getDokployVersion` ناموجود → تست با `project.all` و `version` خالی. نسخه‌های قبل از environments
  (سرویس‌ها مستقیم زیر project) هم normalize می‌شوند.
- **حفاظت از Dokploy (پیاده‌سازی):** token bucket سمت MRK (پیش‌فرض 2 req/s، burst 2) + حداکثر 2 درخواست هم‌زمان؛
  اگر صف بیش از `MRK_DOKPLOY_MAX_QUEUE_SECONDS` (پیش‌فرض 10) شود → `429 dokploy_rate_limited`. cache فهرست و
  جزئیات `cache_seconds` (پیش‌فرض 15) و پاک‌شدن کامل بعد از هر action؛ دامنه‌ها 300 ثانیه cache و در هر ساخت
  درخت حداکثر 6 درخواست دامنه (بقیه در درخواست/چرخه بعد؛ پاسخ `partial: true`). درخت = `project.all` +
  `project.one` فقط برای پروژه‌های دارای دیتابیس بی‌نام + یک `deployment.allCentralized`.
- **خروجی:** فقط http(s)، بدون credential/query/fragment، path پیشوند مجاز (`/api` انتهایی حذف می‌شود)، آدرس‌های
  خصوصی/LAN مجاز (Dokploy معمولاً روی همان میزبان است)، link-local/metadata (`169.254.0.0/16`، `fe80::/10`)،
  multicast و `0.0.0.0` همیشه رد، loopback/`localhost` رد مگر `MRK_DOKPLOY_ALLOW_LOOPBACK=1` (در کانتینر MRK
  loopback یعنی خود MRK). بدون redirect (3xx → `dokploy_unreachable`)، `trust_env=False`، timeout
  `MRK_DOKPLOY_TIMEOUT_SECONDS` (پیش‌فرض 15، connect 5)، سقف پاسخ 8MiB. کلید فقط در هدر؛ هرگز در log، خطا، audit
  یا پاسخ API.
- **پیکربندی:** `data_dir/control-plane/dokploy.json` (`url`، `secret_ref`، تنظیمات) + کلید در SecretStore؛ یا
  `MRK_DOKPLOY_URL` + `MRK_DOKPLOY_API_KEY_FILE` (محیط برنده، PUT/DELETE → `409 dokploy_managed_by_environment`).
  تنظیمات: `rate_limit_per_second` (0.1..20)، `poll_interval_seconds` (0 = خاموش، وگرنه حداقل 15)،
  `cache_seconds` (0..600) از پنل در PUT یا env `MRK_DOKPLOY_RATE_LIMIT_PER_SECOND|POLL_SECONDS|CACHE_SECONDS`؛
  `MRK_DOKPLOY_CONCURRENCY` (1..8). تغییر URL بدون وارد کردن دوباره کلید (در PUT و test) رد می‌شود
  (`422 dokploy_api_key_required`) تا کلید ذخیره‌شده هرگز به میزبان دیگری فرستاده نشود.
- **رویدادها:** `dokploy.deploy_failed` (error، `dedupe_key=dokploy.deploy_failed:<deploymentId>`؛ پس از restart فقط
  خطاهای `2×interval` اخیر)، `dokploy.unreachable` (error) و `dokploy.reachable` (info) با
  `dedupe_key=dokploy.reachability` فقط در تغییر وضعیت. خطای rate limit وضعیت دسترسی را تغییر نمی‌دهد.
- **audit:** `dokploy.config.update`، `dokploy.disconnect`، `dokploy.test`، `dokploy.service.<action>`
  (object `<type>:<id>`، موفق/ناموفق؛ تأیید نادرست stop هم ثبت می‌شود)، `dokploy.deployment.log.view`.
