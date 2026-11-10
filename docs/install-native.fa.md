<div dir="rtl">

# نصب بومی پنل (بدون Docker)

[English](install-native.md) · **فارسی**

اسکریپت `scripts/install-native.sh` **فقط پنل MrK DevAssist** را به‌شکل یک سرویس systemd (`devassist`) نصب می‌کند: control plane، همان ایمیج `panel` در [`deploy/images/Dockerfile`](../deploy/images/Dockerfile)، ساخته‌شده از همین مخزن با نسخه‌های [`versions.lock.yaml`](../versions.lock.yaml). npm و PyPI در پنل خاموش‌اند. پایگاه داده، PostgreSQL خود توزیع است (`apt install postgresql`، cluster پیش‌فرض): نصب‌کننده نقش و پایگاه داده `devassist` را با رمز تصادفی می‌سازد و رمز را در `/etc/devassist/db-password` (`0640 root:devassist`) نگه می‌دارد؛ در ارتقا عوض نمی‌شود و با `--rotate-db-password` رمز تازه می‌گیرد. برای سرور موجود: `--external-db postgresql+psycopg://user@host:5432/db?sslmode=require --db-password-file /etc/devassist/pg.pass`. بقیه سرویس‌ها (ایجنت سرور، DNS، فایروال، S3 و …) با Docker اجرا می‌شوند و از خود پنل اضافه می‌شوند ([docs/44](44-split-services-and-install-wizard.md)). برای نصب کامل با Docker [install-docker.fa.md](install-docker.fa.md) را ببینید.

## پیش‌نیازها

- Debian 12/13 یا Ubuntu 22.04/24.04، amd64 یا arm64، با systemd
- 1 گیگابایت رم برای پنل، 3 گیگابایت فضای خالی برای ساخت، اینترنت هنگام نصب
- پورت 8080 (پنل) آزاد باشد
- Docker، فقط برای سرویس‌هایی که بعداً اضافه می‌کنید

## نصب

<div dir="ltr">

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist && cd devassist
sudo bash scripts/install-native.sh install --dry-run   # print every step, change nothing
sudo bash scripts/install-native.sh install
```

</div>

پنل روی `127.0.0.1:8080` است. با `ssh -L 8080:127.0.0.1:8080 <server>` و `http://localhost:8080` بازش کنید، حساب مالک را بسازید و به **سرویس‌های من ← افزودن سرویس** بروید. تنظیمات در `/etc/devassist/devassist.env` است (بعد از تغییر `sudo systemctl restart devassist`)، داده در `/var/lib/devassist` و لاگ با `journalctl -u devassist -f`. آینه برای ساخت: `--pip-index-url`، `--npm-registry`، `DEVASSIST_NODE_DIST` و `DEVASSIST_UV_DIST`.

## سرویس‌های Docker کنار پنل بومی

فایل تنظیمات `MRK_PANEL_RUNTIME=native` را می‌گذارد؛ ویزارد پورت سرویس‌ها را روی 127.0.0.1 منتشر می‌کند (ایجنت `http://127.0.0.1:7070`، مدیریت S3 `http://127.0.0.1:9001`) و پوشه سوکت DNS و فایروال را در `/run/mrk-dns` و `/run/mrk-firewall` میزبان mount می‌کند. نصب‌کننده هر دو را در هر بوت می‌سازد (`/etc/tmpfiles.d/devassist.conf`، حالت `2750`، مالک uid 10001 مثل ایمیج‌ها، گروه `devassist`). کاربر `devassist` اگر شناسه 10001 آزاد باشد همان را می‌گیرد و پنل بی‌دردسر به سوکت‌ها وصل می‌شود؛ اگر نصب‌کننده هشدار داد که شناسه دیگری گرفته شد، سوکت‌ها را برای گروه `devassist` قابل‌نوشتن کنید یا uid کاربر را 10001 کنید.

## ارتقا، وضعیت، حذف

<div dir="ltr">

```bash
git pull && sudo bash scripts/install-native.sh upgrade   # builds, then restarts (take a backup first)
sudo bash scripts/install-native.sh status
sudo bash scripts/install-native.sh uninstall             # keeps data, the database and /etc/devassist
sudo bash scripts/install-native.sh uninstall --purge     # also drops the devassist database and role, deletes data, config and the user
```

</div>

خود PostgreSQL هیچ‌وقت حذف نمی‌شود. پایگاه داده داخلی قدیمی (PGlite) در `/var/lib/devassist/database/pglite` منتقل نمی‌شود و نصب‌کننده فقط هشدار می‌دهد. حذف، unitهای `devassist-agent`، `devassist-dns` و `devassist-firewall` باقی‌مانده از نصب‌های بومی قدیمی را هم متوقف و پاک می‌کند. به سرویس‌های Docker دست نمی‌زند: آن‌ها را در Dokploy/Coolify یا با `docker compose down` حذف کنید.

</div>
