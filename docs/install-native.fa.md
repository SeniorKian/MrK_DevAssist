<div dir="rtl">

# نصب بدون Docker

[English](install-native.md) · **فارسی**

اسکریپت `scripts/install-native.sh` DevAssist را مستقیم روی سرور و به‌شکل سرویس‌های systemd نصب
می‌کند. همان چیزهایی را می‌سازد که [`deploy/appliance/Dockerfile`](../deploy/appliance/Dockerfile)
می‌سازد، با همان نسخه‌های [`versions.lock.yaml`](../versions.lock.yaml)، و همان برنامه‌ها را با همان
متغیرها و همان محدودیت‌های امنیتی کانتینر اجرا می‌کند.

وقتی سراغش بروید که نمی‌توانید یا نمی‌خواهید DevAssist را در Docker اجرا کنید. روی سرور Dokploy
[نصب با Docker](install-docker.fa.md) ساده‌تر است و همان چیزی است که CI از اول تا آخر آزمایش
می‌کند؛ حالت بدون Docker تازه‌تر است و کمتر آزموده شده (بخش [تفاوت‌ها](#تفاوتها) را ببینید).

## سیستم‌های پشتیبانی‌شده

- Debian 12، Debian 13، Ubuntu 22.04 و Ubuntu 24.04
- amd64 یا arm64، با systemd
- 2 گیگابایت رم برای سرویس اصلی و دست‌کم 5 گیگابایت فضای خالی برای ساخت، به‌علاوه داده‌ها
- دسترسی به اینترنت هنگام نصب (یا آینه، پایین‌تر)

## شروع سریع

<div dir="ltr">

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist
cd devassist
sudo bash scripts/install-native.sh install --dry-run      # print every step, change nothing
sudo bash scripts/install-native.sh install                # panel, npm, PyPI, S3
# optional parts, now or later (run install again with the flag):
sudo bash scripts/install-native.sh install --with-dns --with-firewall --with-agent
```

</div>

بعد از پایان، پنل را با تونل SSH باز کنید و حساب مالک را بسازید:

<div dir="ltr">

```bash
ssh -L 8080:127.0.0.1:8080 you@your-server            # then open http://localhost:8080
```

</div>

## اسکریپت چه می‌کند

1. **بررسی‌ها** (به‌جای حدس زدن، متوقف می‌شود): دسترسی root، سیستم‌عامل و معماری، systemd، فضای
   خالی دیسک (`--min-free-gb`، پیش‌فرض 5)، رم (زیر 2 گیگابایت هشدار)، پورت‌های جدول پایین و
   این‌که نسخه Docker DevAssist روی همین سرور در حال اجرا نباشد. اگر پوشه `/opt/mrk` را خودش نساخته
   باشد، به آن دست نمی‌زند.
2. **بسته‌های سیستم** (فقط آن‌هایی که نیست): `ca-certificates curl xz-utils tar gzip coreutils
   util-linux iproute2 git` و با `--with-firewall` بسته `nftables`.
3. **کاربر**: کاربر و گروه سیستمی `devassist`، اگر آزاد باشد با uid/gid برابر `10001` (همان ایمیج)،
   تا پوشه داده بین نصب Docker و نصب بومی جابه‌جا شود.
4. **ابزارهای اجرا**، از HTTPS و با بررسی SHA-256 منتشرشده خود سازنده:
   - Python (نسخه پین‌شده) با [uv](https://github.com/astral-sh/uv) (نسخه پین‌شده) در
     `/opt/mrk/runtimes/python`؛ خود uv فقط برای همین کار در `/var/cache/devassist` می‌ماند؛
   - Node.js (پین‌شده) در `/opt/mrk/runtimes/node-v<نسخه>-linux-<معماری>`؛
   - Go (پین‌شده) در `/var/cache/devassist/tools`، فقط برای ساخت موتور DNS.
5. **یک نسخه (release)** در `/opt/mrk/releases/<commit>` با همان گام‌های Dockerfile:
   - یک venv با `apps/control-plane` و `deploy/appliance/requirements.txt`، همان بررسی پین‌ها و
     بعد حذف `pip` و `wheel`؛
   - Verdaccio و PGlite با `npm ci --omit=dev --ignore-scripts` از lockfileها؛
   - پنل با `npm ci --ignore-scripts && npm run build`؛
   - با `--with-dns`: باینری‌های `mrk-dns` و `mrk-dnsbench` با `CGO_ENABLED=0`، `-trimpath`،
     `GOTOOLCHAIN=local`، `go mod verify` و همان `-ldflags`؛
   - فایل‌های `supervisord.conf`، `devpi-start.sh` و `devpi-configure.sh` **بدون تغییر**.

   همه فایل‌های نسخه مال `root:root` و برای کاربر سرویس فقط‌خواندنی‌اند (مثل `/opt/mrk` در ایمیج).
   هر نسخه کامل ساخته می‌شود و بعد به کار می‌افتد؛ ساخت ناموفق هیچ‌وقت فعال نمی‌شود و در اجرای
   بعدی پاک می‌شود.
6. **تنظیمات** در `/etc/devassist` (یک بار نوشته می‌شود و هرگز بازنویسی نمی‌شود): `devassist.env` و
   برای بخش‌های اختیاری `dns.env`، `firewall.env` و `agent.env`.
7. **unitهای systemd** از [`deploy/native/systemd/`](../deploy/native/systemd/) در
   `/etc/systemd/system`، ابزار کمکی `/usr/local/sbin/devassist-exec`، بعد `/opt/mrk/current` را به
   نسخه تازه وصل می‌کند، سرویس‌ها را روشن می‌کند و منتظر همان health check کانتینر
   (`python -m mrk_control_plane.healthcheck`) می‌ماند.

اجرای دوباره `install` بی‌خطر است: کاربر، فایل‌های تنظیمات و داده‌ها می‌مانند، commitی که قبلاً
ساخته شده دوباره استفاده می‌شود (`--rebuild` ساخت تازه را اجبار می‌کند) و گزینه‌های قبلی روشن می‌مانند.

## چیدمان فایل‌ها

| مسیر | محتوا | مالک |
|---|---|---|
| `/opt/mrk/releases/<id>/` | venv، پنل، Verdaccio، PGlite، `bin/` و تنظیم supervisord | root، فقط‌خواندنی |
| `/opt/mrk/current` | پیوند به نسخه فعال؛ `/opt/mrk/{venv,bin,admin-ui,...}` از همین می‌گذرند | root |
| `/opt/mrk/runtimes/` | Python و Node | root |
| `/etc/devassist/` | `devassist.env`، فایل‌های اختیاری و `install.conf` | root:devassist 0750 |
| `/var/lib/devassist/` (`--data-dir`) | همه داده‌ها (همان `/data` کانتینر) | devassist 0750 |
| `/var/lib/mrk-dns`، `/run/mrk-dns` | وضعیت DNS، سوکت و توکن مدیریتی | devassist |
| `/var/lib/mrk-firewall`، `/run/mrk-firewall` | وضعیت و سوکت دستیار فایروال | root (پوشه سوکت root:devassist 0750) |
| `/var/lib/mrk-agent` | کلید جفت‌سازی Host Agent | root 0700 |
| `/var/cache/devassist/` | دانلودها، کش ساخت، uv و Go | root |

### مسیرهای کانتینر چطور حفظ می‌شوند

کد و `supervisord.conf` مسیرهای کانتینر را به کار می‌برند (`/data`، `/usr/local/bin/...`،
`/opt/verdaccio`، `/opt/pglite`). به‌جای دست بردن در آن‌ها، `devassist.service` یک mount namespace
جدا به سرویس می‌دهد:

| داخل سرویس | از کجا می‌آید |
|---|---|
| `/data` | `/var/lib/devassist` (یا `--data-dir`) |
| `/usr/local/bin` | `/opt/mrk/bin` (supervisord، supervisorctl، `mrk-*` و node) |
| `/opt/verdaccio`، `/opt/pglite` | `/opt/mrk/verdaccio`، `/opt/mrk/pglite` |
| `/tmp` | یک tmpfs خصوصی 64 مگابایتی با `noexec,nosuid,nodev` |

`/usr/local/bin` و `/data` خود سرور دست نمی‌خورند (اگر `/data`، `/opt/verdaccio` و `/opt/pglite`
نباشند، پوشه خالی برای mount ساخته و هنگام حذف پاک می‌شود). supervisord را یک wrapper کوچک
(`deploy/native/devassist_supervise.py`) اجرا می‌کند که برای لاگ‌ها یک pipe به آن می‌دهد؛ چون
تنظیم مشترک در `/dev/fd/1` می‌نویسد و وقتی این همان سوکت journal باشد، باز شدن دوباره‌اش ممکن نیست.

## سرویس‌ها

| Unit | معادل | کاربر و دسترسی | پورت |
|---|---|---|---|
| `devassist.service` | `mrk-mirror` (supervisord: pglite، s3-engine، pypi-router، verdaccio، devpi، devpi-configure، control-plane و listener خطای FATAL) | `devassist`، بدون capability | 8080، 4873، 3141، 9000؛ روی loopback ‏5433، 3142، 9001 |
| `devassist-dns.service` | `mrk-dns` | `devassist` فقط با `CAP_NET_BIND_SERVICE` (ambient) | 53 روی UDP و TCP (و DoT/DoH/DoQ اگر روشن باشد) |
| `devassist-firewall.service` | `mrk-firewall` | root فقط با `CAP_NET_ADMIN` | ندارد (Unix socket) |
| `devassist-agent.service` | `mrk-agent` | root فقط با `CAP_DAC_READ_SEARCH` و `CAP_DAC_OVERRIDE` | 127.0.0.1:7070 |

سخت‌گیری در همه unitها، هم‌ارز فایل‌های Compose: `NoNewPrivileges=yes` (معادل
`no-new-privileges`)، `CapabilityBoundingSet` صریح (معادل `cap_drop: ALL` به‌علاوه `cap_add`)،
`ProtectSystem=strict` (معادل فایل‌سیستم فقط‌خواندنی)، `ProtectHome`، `PrivateTmp` یا
`TemporaryFileSystem`، `PrivateDevices`، محافظت از کرنل و cgroup، `RestrictSUIDSGID`،
`RestrictNamespaces`، فقط معماری بومی برای system call و همان سقف منابع (`MemoryMax`، `CPUQuota`،
`TasksMax`، `LimitNOFILE`). سرویس اصلی 180 ثانیه برای توقف وقت دارد و `SIGTERM` فقط به فرایند
اصلی می‌رسد (`KillMode=mixed`)، تا Supervisor مثل کانتینر PGlite را آخر از همه ببندد.

موتور DNS در Docker با uid 0 شروع می‌کند و با نگه داشتن فقط `NET_BIND_SERVICE` به 10001 پایین
می‌آید. در نصب بومی systemd آن را مستقیم با کاربر `devassist` و
`AmbientCapabilities=CAP_NET_BIND_SERVICE` اجرا می‌کند؛ موتور فقط وقتی با root شروع شود دسترسی
را کم می‌کند، پس نتیجه نهایی یکی است.

## پورت‌ها و فایروال

| پورت | سرویس | گوش می‌دهد روی (پیش‌فرض بومی) | تغییر با |
|---|---|---|---|
| 8080 | پنل و API | `127.0.0.1` | `MRK_HOST`، `MRK_PORT` |
| 4873 | npm (Verdaccio) | `127.0.0.1` | `MRK_NPM_LISTEN_HOST` |
| 3141 | PyPI (devpi) | `127.0.0.1` | `MRK_PYPI_LISTEN_HOST` |
| 9000 | API ‏S3 | `127.0.0.1` | `MRK_S3_LISTEN` |
| 9001، 5433، 3142 | مدیریت S3، ‏PGlite، روتر PyPI | فقط `127.0.0.1` | – |
| 53 | DNS | `127.0.0.1` و `172.17.0.1` (اولین اجرا) | تنظیمات DNS در پنل |
| 7070 | Host Agent | `127.0.0.1` | `MRK_AGENT_LISTEN` |

در Docker، Compose پورت‌ها را فقط روی `127.0.0.1` باز می‌کند. فرایند بومی نگاشت پورت ندارد؛ پس
همه سرویس‌ها به‌طور پیش‌فرض فقط روی `127.0.0.1` گوش می‌دهند. **اگر یکی را روی نشانی عمومی باز کردید، با فایروال سرور از اینترنت ببندید**، مثلاً:

<div dir="ltr">

```bash
sudo ufw deny 4873/tcp
sudo ufw deny 3141/tcp
```

</div>

یا با nftables در جدول خودتان. به جدول `inet mrk` قانون اضافه نکنید: مال دستیار فایروال است و
آن را یک‌جا جایگزین می‌کند.

### reverse proxy و دامنه

یک reverse proxy با TLS جلوی پنل، npm، PyPI و S3 بگذارید، مقدارهای `MRK_TRUSTED_HOSTS`،
`MRK_CORS_ORIGINS`، `MRK_PYPI_OUTSIDE_URL` و `MRK_TRUSTED_PROXIES` را در
`/etc/devassist/devassist.env` تنظیم کنید و `sudo systemctl restart devassist` را بزنید. برای S3، proxy
باید هدر `Host` اصلی را نگه دارد و بدنه درخواست را buffer نکند. `MRK_AUTH_COOKIE_SECURE=true` را
نگه دارید: ورود از راه HTTPS یا `localhost` کار می‌کند، نه HTTP ساده روی نشانی دیگر.

Traefik ‏Dokploy داخل Docker اجرا می‌شود و به سرویسی که فقط روی `127.0.0.1` سرور گوش می‌دهد
نمی‌رسد. برای این‌که دامنه‌های Dokploy به نصب بومی برسند، سرویس‌ها باید روی نشانی‌ای گوش دهند که
Traefik به آن دسترسی دارد (مثلاً gateway شبکه Docker) و قانون فایروال آن‌ها را از اینترنت دور نگه
دارد. مسیریابی خودکار دامنه در پنل برای کانتینر `mrk-mirror` نوشته شده است (`target_host` در
[US-158 در سند 03](03-user-stories.md))؛ در نصب بومی مسیرهای ساخته‌شده را بررسی کنید یا حالت دستی را به کار ببرید.

## DNS (پورت 53)

<div dir="ltr">

```bash
sudo bash scripts/install-native.sh install --with-dns
dig @127.0.0.1 localhost +short
journalctl -u devassist-dns -n 50
```

</div>

بررسی‌ها و گام‌ها همان [بخش 7 راهنمای Docker](install-docker.fa.md#7-dns-و-پورت-53) است (آزاد
بودن پورت 53، فایل جدای systemd-resolved، `daemon.json` ‏Docker و آزمایش)، با یک تفاوت: موتور را
با `systemctl start|stop|restart devassist-dns` مدیریت کنید، نه `docker compose`. صفحه راه‌اندازی پنل
برای گام موتور دستور Compose نشان می‌دهد؛ به‌جایش از systemctl استفاده کنید. stub سرویس
systemd-resolved روی `127.0.0.53` با `127.0.0.1:53` تداخل ندارد.

## Host Agent و دستیار فایروال

<div dir="ltr">

```bash
sudo bash scripts/install-native.sh install --with-agent --with-firewall
journalctl -u devassist-agent | grep "pairing key"        # pair with URL http://127.0.0.1:7070
journalctl -u devassist-firewall | grep "pairing key"     # URL unix:/run/mrk-firewall/firewall.sock
```

</div>

- Agent به Docker روی سرور نیاز دارد. نماهایی از میزبان که انتظار دارد، فقط‌خواندنی زیر
  `/opt/mrk/agent-host` mount می‌شوند (`/proc`، `/sys/fs/cgroup`، `/var/lib/docker/volumes` و `/`
  بدون زیرشاخه‌های mount). برای پنهان کردن فایل‌سیستم میزبان، خط `/` را در unit پاک کنید
  (`systemctl edit --full devassist-agent`).
- دستیار فایروال `/var/log` را فقط‌خواندنی می‌خواند (مسیر پیش‌فرض پنل `/host/log/system/auth.log`
  کار می‌کند). عضو گروه `adm` است تا `auth.log` اوبونتو را بخواند. برای لاگ دسترسی Traefik، mount
  نشان‌داده‌شده در unit را با `systemctl edit devassist-firewall` اضافه کنید.

## فرمان‌های روزمره

<div dir="ltr">

```bash
systemctl status devassist                    # state
journalctl -u devassist -f                    # all program logs (Supervisor output)
sudo systemctl restart devassist              # after editing /etc/devassist/devassist.env
sudo devassist-exec supervisorctl -c /opt/mrk/supervisord.conf status
sudo bash scripts/install-native.sh status
```

</div>

`devassist-exec` یک فرمان را با همان نمایی که سرویس از سیستم دارد (namespace بالا و متغیرهایش) و با
کاربر `devassist` اجرا می‌کند: اگر سرویس روشن باشد داخل خود آن، وگرنه در یک unit موقت با همان
mountها. فرمان‌هایی از runbook که با `docker compose exec mrk-mirror ...` شروع می‌شوند
([سند 18](18-operations-runbooks.md)) این‌جا `sudo devassist-exec ...` می‌شوند؛ مثلاً `VACUUM` ‏PGlite:

<div dir="ltr">

```bash
sudo devassist-exec supervisorctl -c /opt/mrk/supervisord.conf stop control-plane
sudo devassist-exec python -c "import psycopg; c = psycopg.connect('postgresql://postgres:postgres@127.0.0.1:5433/postgres?sslmode=disable', autocommit=True); c.execute('VACUUM (ANALYZE)'); c.close()"
sudo devassist-exec supervisorctl -c /opt/mrk/supervisord.conf start control-plane
```

</div>

### بازگردانی آفلاین

برنامه بازگردانی را در پنل آماده کنید ([سند 18](18-operations-runbooks.md#encrypted-backup-and-offline-restore))، بعد:

<div dir="ltr">

```bash
sudo systemctl stop devassist
sudo install -m 0400 -o devassist -g devassist /dev/null /run/devassist-restore-passphrase
sudoedit /run/devassist-restore-passphrase           # paste the passphrase; never on the command line
sudo devassist-exec mrk-restore apply --plan '<plan-id>' \
  --passphrase-file /run/devassist-restore-passphrase \
  --confirmation 'APPLY <backup-id>' --offline-confirm I_HAVE_STOPPED_MRK
sudo shred -u /run/devassist-restore-passphrase
sudo systemctl start devassist
```

</div>

## ارتقا

<div dir="ltr">

```bash
cd devassist
git pull
sudo bash scripts/install-native.sh upgrade
```

</div>

اول از پنل پشتیبان رمزنگاری‌شده بگیرید. `upgrade` گزینه‌های نصب اول را نگه می‌دارد، نسخه تازه را
**در حالی که نسخه قبلی هنوز کار می‌کند** می‌سازد، بعد سرویس را متوقف می‌کند (تا 3 دقیقه)،
`/opt/mrk/current` را عوض می‌کند، دوباره روشنش می‌کند (migrationها هنگام شروع اجرا می‌شوند) و منتظر
health check می‌ماند. نسخه قبلی در `/opt/mrk/releases` می‌ماند (قدیمی‌ترها پاک می‌شوند). برگشت
به نسخه قدیمی بعد از migration دیتابیس، بدون بازگردانی همان پشتیبان، پشتیبانی نمی‌شود.

## حذف

<div dir="ltr">

```bash
sudo bash scripts/install-native.sh uninstall            # programs, units, /opt/mrk, caches
sudo bash scripts/install-native.sh uninstall --purge    # also data, /etc/devassist and the user
```

</div>

بدون `--purge`، پوشه داده، `/var/lib/mrk-*` و `/etc/devassist` می‌مانند تا `install` بعدی از همان‌جا
ادامه دهد. `--purge` از شما می‌خواهد `DELETE` را تایپ کنید (یا `--yes` بدهید) و برگشت ندارد.
حذف، جدول nftables ‏`inet mrk` دستیار فایروال را هم اگر باشد پاک می‌کند. پیش از حذف موتور DNS،
گام‌های DNS (فایل systemd-resolved و `daemon.json`) را خودتان برگردانید.

## گزینه‌ها

| گزینه | معنی |
|---|---|
| `--with-dns`، `--with-firewall`، `--with-agent` | بخش‌های اختیاری |
| `--data-dir DIR` | پوشه داده (پیش‌فرض `/var/lib/devassist`؛ بعد از نصب اول ثابت است) |
| `--dns-binary PATH`، `--dnsbench-binary PATH` | باینری آماده موتور به‌جای ساخت با Go (مثلاً با `docker cp` از ایمیج) |
| `--python PATH` | یک Python 3.13 موجود (مثلاً `/usr/bin/python3.13` در Debian 13) به‌جای نسخه پین‌شده |
| `--pip-index-url URL` | آینه PyPI برای ساخت (pip هیچ hashی را بررسی نمی‌کند؛ مثل PyPI به آن اعتماد کنید) |
| `--npm-registry URL` | آینه npm (hashهای lockfile همچنان بررسی می‌شوند) |
| `--goproxy URL` | proxy ماژول‌های Go (‏`go.sum` همچنان بررسی می‌شود) |
| `--rebuild`، `--no-start`، `--skip-port-check`، `--skip-os-check`، `--min-free-gb N` | کنترل ساخت و بررسی‌ها |
| `--yes`، `--dry-run`، `--lang fa\|en\|both` | پرسش‌ها، پیش‌نمایش، زبان پیام‌ها |

آینه دانلود ابزارها از راه متغیر محیطی: `DEVASSIST_NODE_DIST` (پیش‌فرض `https://nodejs.org/dist`)،
`DEVASSIST_GO_DIST` (پیش‌فرض `https://dl.google.com/go`)، `DEVASSIST_UV_DIST` (پیش‌فرض صفحه انتشار uv
در GitHub) و متغیر خود uv یعنی `UV_PYTHON_INSTALL_MIRROR`. آینه باید همان فایل‌ها و فایل‌های
checksum اصلی را داشته باشد.

## تفاوت‌ها

- چیزی که CI می‌سازد و آزمایش می‌کند ایمیج Docker و فایل‌های Compose است؛ حالت بومی همان کد و
  همان تنظیمات را به کار می‌برد ولی هنوز job جداگانه‌ای در CI ندارد. مشکل‌ها را گزارش کنید.
- pip وابستگی‌های غیرمستقیم Python را هنگام نصب پیدا می‌کند، مثل Dockerfile؛ ممکن است با ایمیجی که
  روز دیگری ساخته شده فرق داشته باشند (پین‌های مستقیم بررسی می‌شوند).
- Verdaccio و devpi روی همه نشانی‌ها گوش می‌دهند (بخش [پورت‌ها و فایروال](#پورتها-و-فایروال)).
- پیگیری آپدیت ایمیج و اسکن آسیب‌پذیری، کانتینرهای Docker را از راه Host Agent می‌بینند؛ خود
  فرایندهای بومی DevAssist ایمیج نیستند و دنبال نمی‌شوند.
- کنترل‌کننده فشار موتور DNS داده cgroup v2 را برای کانتینر می‌خواند؛ در systemd سقف‌ها از unit
  می‌آیند (`MemoryMax`، و `MRK_DNS_GOMEMLIMIT` در `dns.env` صریح تنظیم شده است).

</div>
