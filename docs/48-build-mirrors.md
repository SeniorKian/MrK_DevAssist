<div dir="rtl">

# 48 — build از مخزن‌های داخلی (فاز ۱)

## تغییرات نسبت به طرح اولیه

- **آزمایش آزمایشگاهی (docker-in-docker، ‏Docker 28.5.2، ‏Zot v2.1.23) طرح را عوض کرد** (بخش «نتیجه آزمایش» پایین‌تر):
  - Zot وقتی کاربر (htpasswd) دارد به Docker روی `/v2/` همیشه 401 می‌دهد، حتی با دریافت ناشناس؛ پس Docker از آینه
    رد می‌شد و مستقیم از اینترنت می‌گرفت. تنظیم `mirror_pull_without_password` حذف شد و به‌جایش **پنل صادرکننده
    مجوز (token) همان یک Zot است** (بخش «سرویس مجوز مخزن ایمیج»). یک نسخه میانی با Zot دوم بدون رمز ساخته و آزموده شد
    ولی کنار گذاشته شد: دو سرویس برای دیباگ گیج‌کننده و برای منابع سنگین بود.
  - گزینه `--default-builder` حذف شد: `docker build` حتی با `buildx use --default` همیشه با سازنده داخلی Docker
    می‌سازد، و همان سازنده داخلی ایمیج‌های Docker Hub را از آینه `daemon.json` می‌گیرد.
  - آزمایش اسکریپت با فهرست مخزن آینه (`/v2/_catalog`) قبل و بعد از pull انجام می‌شود؛ پرسیدن مستقیم ایمیج از آینه
    خودش آن را دریافت می‌کرد و «موفق» دروغی می‌داد. کدهای آزمایش: `ok`، `cached`، `not_via_mirror`، `pull_failed`.
  - `undo` به‌جای پاک کردن کلید، `"registry-mirrors": []` می‌نویسد؛ Docker با کلید پاک‌شده آینه قبلی را در حافظه نگه
    می‌داشت.
  - گزینه تازه `--registry-ca FILE` برای آینه با گواهی خصوصی: هم `/etc/docker/certs.d` و هم مخزن گواهی سیستم (سازنده
    داخلی Docker فقط به مخزن سیستم اعتماد دارد و آن را هنگام شروع Docker می‌خواند).
- بررسی‌های `status`: ‏`dokploy`، `npm_mirror`، `pypi_mirror`، `registry`، `registry_token`، `agent`، `server`،
  `daemon_file`، `daemon_live`، `builder_file`، `self_test`، `projects`، `coverage`؛ هر کدام
  `state` و `code` و `params` دارد و پنل برای هر `code` یک جمله ساده نشان می‌دهد.
- وضعیت تازه پروژه `leftover`: بلوک DevAssist روی برنامه‌ای مانده که دیگر واجد شرایط نیست (مثلاً نوع ساختش عوض شده).
- تنظیم `enabled`: با اولین «اعمال» روشن و با «برگرداندن همه» خاموش می‌شود؛ اعمال خودکار فقط وقتی روشن است کار می‌کند.
- صفحه پنل: «سرور و برنامه‌ها ← ساخت از مخزن داخلی» (`#/server/builds`).

هدف: هر build و deploy که Dokploy روی سرور انجام می‌دهد، ایمیج‌های Docker و پکیج‌های npm و پایتون را **اول** از
مخزن‌های خود DevAssist (Zot، npm و PyPI) بگیرد. اگر چیزی آنجا نبود، خود مخزن‌ها از اینترنت می‌گیرند. به کد و ایمیج
Dokploy دست نمی‌زنیم.

## سه لایه

| لایه | چه چیزی | کجا | چه کسی اعمال می‌کند |
|---|---|---|---|
| الف | `registry-mirrors` در `/etc/docker/daemon.json` ← مخزن ایمیج (فقط Docker Hub؛ هم `docker pull` و هم سازنده داخلی `docker build`)؛ Docker بدون رمز از پنل مجوز می‌گیرد | هر سرور | اسکریپت `devassist-build-mirror.sh` (یک فرمان در SSH) |
| ب | `buildkitd.default.toml` با آینه docker.io و ghcr.io و quay.io و registry.k8s.io | پوشه `buildx` در volume ‏`dokploy` (یا `/root/.docker` روی سرور دور) | همان اسکریپت |
| ج | متغیرهای `NPM_CONFIG_REGISTRY`، `YARN_NPM_REGISTRY_SERVER`، `PIP_INDEX_URL`، `UV_DEFAULT_INDEX` (+ `PIP_TRUSTED_HOST`/`UV_INSECURE_HOST` برای نشانی http) | env هر Application در Dokploy | پنل، با API رسمی Dokploy |

- لایه ب را هر سازنده‌ای که بعداً ساخته شود خودکار می‌خواند (Railpack برای هر build یکی می‌سازد). `docker build`،
  ‏Nixpacks و Compose با سازنده داخلی Docker می‌سازند و ایمیج Docker Hub را از لایه الف می‌گیرند؛ ghcr.io و quay.io
  برای آن‌ها مستقیم دریافت می‌شود.
- آینه با مسیر (`host/ghcr.io`) در BuildKit کار می‌کند (آزموده)؛ اگر آینه جواب ندهد BuildKit سراغ اصل می‌رود.
- `registry-mirrors` بدون ری‌استارت با `systemctl reload docker` خوانده می‌شود (آزموده؛ کانتینرها ری‌استارت نشدند)؛
  اگر Docker آن را نپذیرفت، اسکریپت ری‌استارت نمی‌کند و فقط می‌گوید (گزینه `--allow-restart`).

## لایه ج: کدام پروژه‌ها

| نوع | رفتار |
|---|---|
| Application با build ‏`nixpacks`، `railpack`، `heroku_buildpacks`، `paketo_buildpacks` | متغیرها نوشته می‌شوند |
| Application با `dockerfile` یا `static`، و Compose | نوشته نمی‌شود؛ دلیل `dockerfile_build` / `compose_build` (فاز ۲) |
| Application با منبع `docker` (ایمیج آماده) | build ندارد؛ `no_build` (لایه الف پوشش می‌دهد) |

متغیرها در یک بلوک مشخص در انتهای env نوشته می‌شوند:

<div dir="ltr">

```
# >>> DevAssist build mirrors (managed, change it in DevAssist) >>>
NPM_CONFIG_REGISTRY=https://npm.example.com/
# <<< DevAssist build mirrors <<<
```

</div>

- اگر همان نام بیرون از بلوک هم باشد، وضعیت `overridden` گزارش می‌شود (بلوک آخر است و برنده می‌شود).
- اثر از **دیپلوی بعدی** است؛ پنل خودش redeploy نمی‌کند.
- «برگرداندن» فقط بلوک را برمی‌دارد. `buildArgs` و `buildSecrets` همان مقدار قبلی دوباره فرستاده می‌شوند.
- پروژه تازه: اگر `auto_apply_new` روشن باشد، poller هر پروژه تازه را خودکار اعمال می‌کند.

## سرویس مجوز مخزن ایمیج (token)

Zot وقتی کاربر دارد Docker بی‌رمز را با 401 رد می‌کند و به IP نگاه نمی‌کند (کد `pkg/api/authn.go` نسخه v2.1.23). پس
تصمیم «از این IPها بدون رمز» در پنل گرفته می‌شود: Zot با `http.auth.bearer` Docker را برای مجوز به پنل می‌فرستد و
htpasswd برای درخواست‌های Basic خود پنل می‌ماند.

<div dir="ltr">

```json
"auth": {"htpasswd": {"path": "/etc/zot/htpasswd"},
         "bearer": {"realm": "https://panel.example.com/api/v1/registry/token",
                    "service": "devassist-registry", "cert": "/etc/zot/token.crt"}}
```

</div>

- کلید امضا RSA 2048 در SecretStore (`registry-token-key`)؛ گواهی خودامضای آن در `/etc/zot/token.crt`.
- مجوز JWT ‏RS256، اعتبار 300 ثانیه، با `access` به قالب Docker (`type`/`name`/`actions`).
- `GET /api/v1/registry/token?service&scope…` (بدون نشست پنل؛ Basic اختیاری):

| درخواست‌کننده | مجوز |
|---|---|
| کاربر مخزن با رمز درست | مثل امروز: `pull` یا `pull,push` |
| `mrk-panel` | `pull,push,delete` |
| بی‌رمز از رنج مورد اعتماد | فقط `pull`؛ با `scope=mirrors` فقط `library/**` و مسیرهای آینه، با `all` همه |
| بی‌رمز از جای دیگر | فقط اگر `anonymous_pull` یا «مخزن‌های عمومی» |
| رمز اشتباه | 401 (با یک ثانیه تأخیر) |

  `repository::pull` (نام خالی) را Zot برای `/v2/_catalog` می‌خواهد؛ فهرست فقط مخزن‌هایی را نشان می‌دهد که بقیه
  مجوز اجازه خواندن دارد. هیچ نشانی‌ای بی‌رمز push یا delete نمی‌گیرد.
- `GET/PUT /api/v1/registry/token-settings` ‏(`registry:read`/`registry:write`): `enabled`، `realm` (خالی = دامنه اصلی
  پنل + مسیر)، `trusted_ranges` (پیش‌فرض `127.0.0.0/8`، `::1/128`، `172.16.0.0/12`؛ رنج همه‌جا رد می‌شود)، `scope`.
  روشن کردن بدون نشانی صدور ← 409 `registry_token_realm_missing`. جدا از تنظیمات مخزن ذخیره می‌شود تا صفحه مخزن آن
  را پاک نکند.
- `GET /api/v1/registry/token-log`: ۲۰۰ تصمیم آخر (زمان، IP، کاربر، مورد اعتماد بودن، درخواست، داده‌شده)؛ بدون رمز.
- IP از `request.client` است که uvicorn پشت `MRK_TRUSTED_PROXIES` از `X-Forwarded-For` می‌خواند. نام realm باید جزو
  نام‌های مورد اعتماد پنل باشد (دامنه پنل خودکار هست).
- بررسی `registry_token`: روشن بودن، و این‌که `/v2/` ‏Zot به Docker (با User-Agent خودش) همان realm را برمی‌گرداند.

## API ‏(`/api/v1/build-mirrors`)

| مسیر | دسترسی | کار |
|---|---|---|
| `GET status` | `dokploy:read` | همه بررسی‌ها با `state` ‏(`ok`/`warn`/`fail`/`unknown`)، `code` و `fix` |
| `GET/PUT settings` | `dokploy:read` / `dokploy:write` | `enabled`، `npm`، `pypi`، `auto_apply_new`، `npm_url`، `pypi_url`، `registry_host` (خالی = دامنه اصلی سرویس مخزن ایمیج)، `check_interval_seconds` |
| `GET command?action=install\|status\|undo` | `dokploy:read` | فرمان کامل (اسکریپت درون heredoc) |
| `GET projects` | `dokploy:read` | هر Application/Compose: `eligible`، `state` ‏(`applied`/`missing`/`outdated`/`overridden`/`skipped`)، `reason`، `coverage` |
| `POST projects/apply` و `projects/remove` | `dokploy:write` + CSRF | `{all: true}` یا `{targets: [{type, id}]}`؛ نتیجه هر کدام جدا |
| `GET report` | `dokploy:read` | متن کامل برای گزارش باگ (بدون secret) |

خطاها: `build_mirror_dokploy_missing` ‏(409)، `build_mirror_registry_missing` ‏(409)، `build_mirror_target_invalid` ‏(422)
و خطاهای Dokploy همان‌طور که هستند. تاریخچه کارها: `build_mirror.settings`، `build_mirror.apply`، `build_mirror.remove`.

## Agent (فقط خواندنی)

`GET /v1/build-mirror/facts`:

- `daemon`: `registry-mirrors` در `daemon.json`؛
- `live_mirrors`: `RegistryConfig.Mirrors` از `/info` Docker (آیا reload شده)؛
- `marker`: `/etc/devassist/build-mirror.json` که اسکریپت می‌نویسد (نسخه، زمان، نشانی‌ها، مسیر فایل BuildKit، نتیجه آزمایش)؛
- `builder`: آیا کانتینر `buildx_buildkit_mrk-mirror0` (از نسخه ۱ اسکریپت) هنوز هست.

## پوشش واقعی (تخمینی از لاگ build)

بعد از هر دیپلوی تمام‌شده، لاگ آن خوانده و بررسی می‌شود:

- نام میزبان‌های مستقیم (`registry.npmjs.org`، ‏`registry.yarnpkg.com`، ‏`files.pythonhosted.org`، ‏`pypi.org`) ← `direct`؛
- `Looking in indexes: <نشانی ما>` ← `mirror_seen`؛
- ابزارهایی که متغیر را نادیده می‌گیرند: Yarn 1 ‏(`yarn_v1_lock`)، Poetry ‏(`poetry`)، `uv sync` با lock ‏(`uv_lock`).

خروجی برای هر پروژه: `full` / `partial` / `none` / `unknown`، با دلیل‌ها.

## اسکریپت `devassist-build-mirror.sh`

`install` | `status` | `undo`؛ با root اجرا می‌شود و تکرارش بی‌خطر است. قبل از هر تغییر از فایل پشتیبان می‌گیرد
(`/etc/devassist/backup/`)، `daemon.json` را با `dockerd --validate` بررسی می‌کند، فقط کلید `registry-mirrors` را
تغییر می‌دهد و در پایان یک آزمایش pull انجام می‌دهد. `undo` فقط آینه خودش را برمی‌دارد (با `[]`)، فایل BuildKit را فقط
وقتی پاک می‌کند که هنوز همان نسخه اسکریپت باشد، و گواهی `--registry-ca` و سازنده قدیمی `mrk-mirror` را حذف می‌کند.

## نتیجه آزمایش آزمایشگاهی (۱۴۰۵/۰۸/۲۲)

docker-in-docker با Docker 28.5.2 (همان نسخه Dokploy)، volume ‏`dokploy`، و Zot با تنظیماتی که کد پنل می‌سازد:

| مورد | نتیجه |
|---|---|
| `install` و اجرای دوباره | درست؛ `daemon.json` فقط یک آینه دارد |
| reload بدون ری‌استارت | Docker آینه را گرفت؛ کانتینر در حال اجرا ری‌استارت نشد |
| `docker pull` | manifest و همه لایه‌ها از آینه |
| `docker build` (سازنده داخلی، مثل Dokploy) | ایمیج Docker Hub از آینه |
| سازنده تازه (مثل Railpack) | فایل لایه ب خودکار خوانده شد؛ `ghcr.io/...` از مسیر `/v2/ghcr.io/...` آینه |
| push به آینه | رد شد (401) |
| `status` / `undo` | درست؛ بعد از `undo` آینه از حافظه Docker هم پاک شد |
| فایل نتیجه | پنل آن را درست خواند و همه بررسی‌های سرور «درست» شد |

### دور دوم: یک Zot + سرویس مجوز پنل

پنل واقعی (همین کد) نشانی صدور مجوز بود و Zot تنظیمات و `token.crt` ساخته‌شده پنل را می‌خواند:

| مورد | نتیجه |
|---|---|
| `/v2/` برای Docker | 401 با `Bearer realm=<پنل>` |
| `install` و آزمایش واقعی | Docker از پنل مجوز گرفت و ایمیج از آینه آمد |
| ایمیج خصوصی بی‌رمز | رد شد (پنل چیزی نداد) |
| push بی‌رمز از رنج مورد اعتماد | رد شد (فقط `pull` داده شد) |
| `docker login` + push + pull با کاربر `ci` | درست؛ بعد از logout ایمیج خصوصی رد شد؛ رمز اشتباه رد شد |
| `docker build` و سازنده تازه (مثل Railpack) با ghcr.io | هر دو با مجوز از آینه |
| `undo` | درست؛ کانتینر برنامه ری‌استارت نشد |
| IP دیده‌شده در پنل | `127.0.0.1` در Docker Desktop؛ روی سرور واقعی از «آخرین درخواست‌های Docker» دیده می‌شود |

یک ایراد در همین دور پیدا و رفع شد: Zot برای `/v2/_catalog` دامنه `repository::pull` (نام خالی) می‌خواهد.

آزموده نشده: Dokploy واقعی (لایه ج با API واقعی) و گواهی عمومی پشت Traefik.

## محدودیت‌های فاز ۱

- پروژه‌های Dockerfile و Compose فقط ایمیج پایه را پوشش می‌گیرند، نه npm و pip (فاز ۲: حالت سخت‌گیر).
- Yarn 1 با `yarn.lock`، ‏`uv.lock`، ‏Poetry و `--index-url` داخل `requirements.txt` متغیر را نادیده می‌گیرند.
- دانلود خود Node و Python توسط Nixpacks/Railpack/Heroku پوشش ندارد.
- هر سرور build یا deploy دور باید جدا اسکریپت را اجرا کند؛ مخزن‌ها باید دامنه و HTTPS داشته باشند.

</div>
