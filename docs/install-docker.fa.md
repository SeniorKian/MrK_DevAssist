<div dir="rtl">

# نصب DevAssist با Docker

[English](install-docker.md) · **فارسی**

این راهنما دستورهای Docker را که در [`deploy/appliance/README.md`](../deploy/appliance/README.md)،
[سند 12](12-ci-cd-and-release.md)، [سند 18](18-operations-runbooks.md) و Storyهای DNS
([سند 03، Epic E18](03-user-stories.md)) پخش بودند یک‌جا جمع می‌کند. جزئیات کامل همچنان در همان فایل‌هاست.

## 1. چه چیزهایی اجرا می‌شود

یک ایمیج (`mrk-devassist`) و حداکثر چهار کانتینر:

| سرویس Compose | پروفایل | کارش | دسترسی |
|---|---|---|---|
| `mrk-mirror` | همیشه | پنل و API، PGlite، Verdaccio (npm)، devpi (PyPI)، روتر جابه‌جایی PyPI و موتور S3، زیر Supervisor | کاربر 10001، بدون capability، فایل‌سیستم فقط‌خواندنی |
| `mrk-dns` | `dns` | موتور DNS روی شبکه میزبان | با uid 0 و فقط `NET_BIND_SERVICE`+`SETUID`+`SETGID` شروع می‌کند و بلافاصله به 10001 با فقط `NET_BIND_SERVICE` پایین می‌آید |
| `mrk-firewall` | `firewall` | دستیار nftables روی شبکه میزبان، فقط با Unix socket | root فقط با `NET_ADMIN` |
| `mrk-agent` | `agent` | Host Agent (سوکت Docker و نمای فقط‌خواندنی میزبان) | root فقط با `DAC_READ_SEARCH`+`DAC_OVERRIDE` (یا `MRK_AGENT_USER=10001:<gid گروه docker>`) |

همه داده کانتینر اصلی در یک mount روی `/data` است. پورت‌ها: `8080` پنل، `4873` npm،
`3141` PyPI و `9000` S3. فقط داخلی: `5433` برای PGlite، `3142` برای روتر PyPI و `9001` برای مدیریت S3.

## 2. شروع سریع (ساخت از سورس)

<div dir="ltr">

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist
cd devassist
cp .env.example .env        # optional: ports, memory, build mirrors
docker compose up -d --build
docker compose ps           # wait for "healthy" (first start: a few minutes)
```

</div>

فایل `compose.yaml` ایمیج را همین‌جا می‌سازد، آن را با کاربر `10001:10001` روی volume
`mrk-dev-data` اجرا می‌کند و همه پورت‌ها را فقط روی `127.0.0.1` باز می‌کند. پنل را با تونل SSH باز کنید:

<div dir="ltr">

```bash
ssh -L 8080:127.0.0.1:8080 you@your-server   # then open http://localhost:8080
```

</div>

بار اول صفحه **راه‌اندازی اولیه** می‌آید. همان لحظه حساب مالک را بسازید؛ تا آن وقت هر کس به
پنل برسد می‌تواند این کار را بکند.

آینه دانلود هنگام ساخت (وقتی Docker Hub، npmjs یا PyPI کند است): در `.env` مقدار
`MRK_BUILD_NPM_REGISTRY` (hashهای lockfile همچنان بررسی می‌شوند) و `MRK_BUILD_PIP_INDEX_URL`
(نسخه‌ها پین هستند ولی pip هیچ hashی را بررسی نمی‌کند؛ مثل خود PyPI به آن اعتماد کنید) را بدهید.
اگر ساخت با خطای `proxy.golang.org ... 403 Forbidden` متوقف شد، `MRK_BUILD_GOPROXY` را هم بدهید
(مثلاً `https://goproxy.cn|https://goproxy.io|direct`؛ hashهای `go.sum` همچنان بررسی می‌شوند).
اگر گام `apt-get update` روی `deb.debian.org` معطل ماند، `MRK_BUILD_APT_MIRROR` را بدهید (مثلاً
`https://mirror.arvancloud.ir`؛ آینه باید `/debian` و `/debian-security` را داشته باشد و امضای
فهرست بسته‌ها همچنان بررسی می‌شود).
در Dokploy این مقدارها را در زبانه **Environment** همان سرویس Compose بنویسید.

برای استفاده از یک پوشه روی سرور به‌جای volume، پوشه را با مالک `10001:10001` بسازید و
`MRK_HOST_DATA_PATH` را تنظیم کنید:

<div dir="ltr">

```bash
sudo install -d -o 10001 -g 10001 -m 0750 /srv/devassist-data
echo 'MRK_HOST_DATA_PATH=/srv/devassist-data' >> .env
```

</div>

### پوشه‌های جدا برای npm، PyPI، S3 و DNS

برای اینکه داده هر بخش پوشه (یا دیسک) خودش را روی سرور داشته باشد، به‌جای `compose.yaml` از
`compose.split-storage.yaml` استفاده کنید (در Dokploy: مقدار **Compose Path** را
`./compose.split-storage.yaml` بگذارید):

<div dir="ltr">

```bash
sudo install -d -o 10001 -g 10001 -m 0750 /storage/npm /storage/pypi /storage/s3 /opt/dnsconfig
cat >> .env <<'EOF'
MRK_HOST_NPM_PATH=/storage/npm
MRK_HOST_PYPI_PATH=/storage/pypi
MRK_HOST_S3_PATH=/storage/s3
MRK_HOST_DNS_PATH=/opt/dnsconfig
EOF
docker compose -f compose.split-storage.yaml up -d --build
```

</div>

هر سه متغیر npm، PyPI و S3 در این فایل اجباری‌اند. `MRK_HOST_DNS_PATH` در هر دو فایل کار می‌کند و
فقط با پروفایل `dns` استفاده می‌شود. بقیه وضعیت پنل (دیتابیس، تنظیمات، پشتیبان‌ها و لاگ) روی همان
volume `mrk-dev-data` یا `MRK_HOST_DATA_PATH` می‌ماند. همه پوشه‌ها باید از قبل با مالک `10001:10001`
ساخته شده باشند؛ کانتینر بدون دسترسی اجرا می‌شود و نمی‌تواند مالک را عوض کند.

بهای mount جدا (rename از یک mount به mount دیگر ممکن نیست):

- انتقال پکیج npm به سطل بازیافت و برگرداندنش به‌جای rename با کپی انجام می‌شود؛ برای پکیج‌های
  بزرگ کندتر است.
- بازگردانی آفلاین (`mrk-restore apply`) ریشه‌های `npm` و `pypi` را **رد می‌کند**، چون کل پوشه را
  با rename جابه‌جا می‌کند. ساخت و اعتبارسنجی پشتیبان مثل قبل کار می‌کند. برای بازگردانی داده npm
  یا PyPI، بازگردانی را با `compose.yaml` (یک mount) اجرا کنید و بعد پوشه‌ها را به مسیر خودشان
  کپی کنید.

## 3. نصب واقعی (ایمیج منتشرشده)

فایل `deploy/appliance/compose.production.yaml` ایمیج منتشرشده را می‌کشد. `MRK_IMAGE` اجباری
است و باید digest ثابت باشد (نه `latest`):

<div dir="ltr">

```bash
export MRK_IMAGE=ghcr.io/seniorkian/mrk-devassist@sha256:<digest>
sudo install -d -o 10001 -g 10001 -m 0750 /opt/mirrors/pypi    # the /data mount of this file
export MRK_TRUSTED_HOSTS=panel.example.com,npm.example.com,pypi.example.com
export MRK_CORS_ORIGINS=https://panel.example.com
export MRK_PYPI_OUTSIDE_URL=https://pypi.example.com
docker compose -f deploy/appliance/compose.production.yaml up -d
```

</div>

ایمیج‌ها را workflow `.github/workflows/publish-image.yml` با هر tag از نوع `v*` در GHCR منتشر
می‌کند (amd64 و arm64، با SBOM و provenance)؛ digest در خلاصه workflow هست
([سند 12](12-ci-cd-and-release.md)). تا وقتی نسخه‌ای منتشر نشده، از سورس بسازید (بخش 2).

این فایل به‌جای باز کردن پورت روی میزبان از `expose` استفاده می‌کند. در Dokploy برای همین
سرویس مسیر بسازید: دامنه پنل به پورت `8080`، npm به `4873`، PyPI به `3141` و S3
(`s3.<domain>` و در صورت نیاز `*.s3.<domain>`) به `9000`. TLS در Traefik خود Dokploy تمام می‌شود.
برای S3، proxy باید هدر `Host` اصلی را نگه دارد و بدنه درخواست را buffer نکند. پنل هم می‌تواند
این مسیرها را خودش بسازد (سرویس‌ها ← دامنه‌ها؛ [US-158 در سند 03](03-user-stories.md)).

سخت‌گیری‌هایی که در فایل‌های Compose هست: uid ثابت `10001`، `cap_drop: ALL`، `read_only: true`،
`no-new-privileges`، `/tmp` به‌شکل tmpfs با `noexec,nosuid,nodev` و سقف حافظه، CPU و تعداد
فرایند (`MRK_MEM_LIMIT` پیش‌فرض `2g`، `MRK_CPUS` پیش‌فرض `2.0`، `pids_limit: 512`).

## 4. چرخه کار

- **اولین اجرا** (ساخت PGlite، devpi-init، migrationها و راه‌اندازی آینه) ممکن است چند دقیقه
  طول بکشد؛ healthcheck پنج دقیقه مهلت شروع دارد.
- **خاموش کردن**: Supervisor آخر از همه PGlite را می‌بندد. Compose مقدار `stop_grace_period: 180s`
  دارد؛ با Docker ساده از `docker stop --time 180` استفاده کنید. مهلت پیش‌فرض ده‌ثانیه‌ای ممکن
  است PGlite را وسط بسته شدن قطع کند.
- **سیاست restart**: اگر دیتابیس یا پنل از کار بیفتد (FATAL)، کانتینر بیرون می‌آید تا Docker آن را
  دوباره بالا بیاورد. از `restart: unless-stopped` یا `always` استفاده کنید، نه `on-failure`.
  npm، PyPI و S3 را watchdog خود پنل دوباره راه می‌اندازد.
- **فایل‌های بزرگ PyPI**: برای wheelهای بزرگ timeout بلند بدهید، مثلاً `pip --timeout 900`.

## 5. ارتقا

1. از پنل یک پشتیبان رمزنگاری‌شده بگیرید (چرخه داده ← پشتیبان) و عبارت عبور را بیرون از `/data` نگه دارید.
2. نصب از سورس: `git pull && docker compose up -d --build`.
   نصب واقعی: `MRK_IMAGE` را digest تازه بگذارید و `docker compose -f deploy/appliance/compose.production.yaml up -d` را بزنید.
3. migrationها هنگام شروع اجرا می‌شوند. `docker compose ps` و پنل را بررسی کنید.

اگر نسخه PGlite در ایمیج تازه عوض شده، پیش از آن یک بازگردانی آزمایشی هم انجام دهید ([سند 18](18-operations-runbooks.md)).

## 6. پروفایل‌های اختیاری

### Host Agent (پروفایل `agent`)

<div dir="ltr">

```bash
export MRK_DOCKER_GID="$(getent group docker | cut -d: -f3)"
docker compose --profile agent up -d mrk-agent
docker compose logs mrk-agent | grep "pairing key"
```

</div>

نشانی `http://mrk-agent:7070` و کلید را در پنل (سرور ← Host Agent) بچسبانید. Agent پورت
عمومی ندارد و فقط از شبکه داخلی `mrk-agent` در دسترس است. جزئیات و فهرست دقیق APIهای مجاز
Docker در [deploy/appliance/README.md](../deploy/appliance/README.md#optional-host-agent-gates-16-17) است.

### دستیار فایروال (پروفایل `firewall`)

<div dir="ltr">

```bash
docker compose --profile firewall up -d mrk-firewall
docker compose logs mrk-firewall | grep "pairing key"
```

</div>

در پنل جفت کنید (امنیت ← فایروال؛ نشانی `unix:/run/mrk-firewall/firewall.sock`). در شروع فقط
گزارش می‌دهد و برای اعمال واقعی باید عبارت `ENFORCE` را تایپ کنید. اگر دستیار را حذف کنید،
آخرین جدولش تا اجرای `sudo nft delete table inet mrk` در کرنل می‌ماند.

### موتور DNS (پروفایل `dns`)

<div dir="ltr">

```bash
docker compose --profile dns up -d mrk-dns
docker compose --profile dns ps mrk-dns
docker compose --profile dns logs --tail=50 mrk-dns
```

</div>

بار اول روی `MRK_DNS_LISTEN` گوش می‌دهد (پیش‌فرض `127.0.0.1:53,172.17.0.1:53`) و از آن به بعد
نشانی‌ها از تنظیمات DNS در پنل می‌آیند. جست‌وجوی بازگشتی فقط برای شبکه‌های خصوصی است و هرگز
به اینترنت داده نمی‌شود. سقف‌ها: `MRK_DNS_CPUS` (2)، `MRK_DNS_MEMORY` (512m) و `MRK_DNS_PIDS` (256).

## 7. DNS و پورت 53

صفحه **DNS ← راه‌اندازی** در پنل هر گام را بررسی می‌کند و دستور دقیق سرور شما را نشان می‌دهد
(برای دیدن وضعیت میزبان به Host Agent نیاز دارد). گام‌ها:

1. **روشن بودن موتور**: `docker compose --profile dns up -d mrk-dns`.
2. **آزاد بودن پورت 53.** ببینید چه برنامه‌ای آن را گرفته:
   <div dir="ltr">

   ```bash
   sudo ss -lntup 'sport = :53'
   ```

   </div>

   stub سرویس systemd-resolved روی `127.0.0.53` با `127.0.0.1:53` تداخل **ندارد**. سرور DNS
   دیگری (dnsmasq، bind9 و...) روی `0.0.0.0:53` تداخل دارد؛ فقط اگر دیگر لازمش ندارید خاموشش
   کنید: `sudo systemctl disable --now <unit>`.
3. **DNS خود سرور به DevAssist اشاره کند** (سرورهایی که systemd-resolved دارند)، با یک DNS عمومی پشتیبان:
   <div dir="ltr">

   ```bash
   sudo mkdir -p /etc/systemd/resolved.conf.d
   sudo tee /etc/systemd/resolved.conf.d/mrk.conf >/dev/null <<'EOF'
   [Resolve]
   DNS=127.0.0.1 1.1.1.1
   FallbackDNS=1.1.1.1 9.9.9.9
   DNSStubListener=no
   EOF
   sudo cp -P /etc/resolv.conf /etc/resolv.conf.mrk-backup
   sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
   sudo systemctl restart systemd-resolved
   ```

   </div>

   پیش از این گام موتور باید روشن باشد. برگرداندن: `mrk.conf` را پاک کنید، فایل
   `/etc/resolv.conf.mrk-backup` را برگردانید و systemd-resolved را ری‌استارت کنید. سرورهای بدون
   systemd-resolved یک `/etc/resolv.conf` ثابت با `nameserver 127.0.0.1` و یک DNS پشتیبان می‌گیرند
   (پنل دستورش را نشان می‌دهد).
4. **کانتینرها از DevAssist استفاده کنند**: در `/etc/docker/daemon.json` فقط کلید `dns` را اضافه کنید
   و بقیه کلیدها را نگه دارید، مثلاً `"dns": ["172.17.0.1", "1.1.1.1"]`، بعد
   `sudo systemctl restart docker`. **این کار همه کانتینرهای سرور را ری‌استارت می‌کند**، از جمله
   Dokploy و برنامه‌هایش؛ در زمان کم‌کار انجامش دهید.
5. **بررسی**:
   <div dir="ltr">

   ```bash
   dig @127.0.0.1 localhost +short
   docker run --rm busybox:1.36 nslookup localhost
   ```

   </div>

## 8. پشتیبان و بازگردانی

بازگردانی آفلاین است و هرگز از پنل اجرا نمی‌شود. پنل فایل پشتیبان را بررسی می‌کند و یک برنامه
یک‌ساعته آماده می‌کند؛ بعد، با سرویس خاموش:

<div dir="ltr">

```bash
docker compose run --rm --no-deps \
  -v "$PWD/restore-passphrase:/run/secrets/mrk-restore-passphrase:ro" \
  --entrypoint mrk-restore mrk-mirror apply \
  --plan '<plan-id>' \
  --passphrase-file /run/secrets/mrk-restore-passphrase \
  --confirmation 'APPLY <backup-id>' \
  --offline-confirm I_HAVE_STOPPED_MRK
```

</div>

روند کامل (رسید، پشتیبان برگشت و `MRK_UPSTREAM_SECRET_KEY_FILE`) در
[سند 18](18-operations-runbooks.md#encrypted-backup-and-offline-restore) آمده است.

## 9. حذف

<div dir="ltr">

```bash
docker compose --profile dns --profile firewall --profile agent down        # keeps volumes
docker compose --profile dns --profile firewall --profile agent down -v     # also deletes data volumes
sudo nft delete table inet mrk 2>/dev/null || true                         # if the firewall helper enforced rules
```

</div>

اگر گام‌های DNS بخش 7 را انجام داده‌اید، اول آن‌ها را برگردانید؛ وگرنه سرور و کانتینرها DNS ندارند.

</div>
