<div dir="rtl">

# نصب DevAssist با Docker

[English](install-docker.md) · **فارسی**

DevAssist یک **پنل** است به‌علاوه چند **سرویس** اختیاری. اول پنل را نصب کنید؛ این تنها چیزی است که دستی
راه می‌اندازید. بقیه سرویس‌ها از داخل خود پنل اضافه می‌شوند: پنل برای هر کدام `compose.yaml` و `.env` آماده
می‌دهد و بعد از بالا آمدن به آن وصل می‌شود.

## ۱. پنل (لازم)

پیش‌نیاز: سرور لینوکس (amd64 یا arm64) با Docker و افزونه Compose، و ۱ گیگابایت رم آزاد.

<div dir="ltr">

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist
cd devassist && docker compose up -d
```

</div>

- **Dokploy:** «Create Service ← Compose» از همین مخزن، با Compose Path برابر `./compose.yaml`.
- **Coolify:** «New Resource ← Docker Compose» با `compose.yaml` همین مخزن.
- **بدون Docker** (فقط پنل، با systemd): [install-native.fa.md](install-native.fa.md).

پنل روی `127.0.0.1:8080` باز می‌شود. با تونل SSH بازش کنید و همان اول حساب مالک را بسازید:

<div dir="ltr">

```bash
ssh -L 8080:127.0.0.1:8080 you@your-server   # then open http://localhost:8080
```

</div>

برای دامنه، بعداً از خود پنل اضافه کنید («سرویس‌های من ← افزودن دامنه»).

## ۲. سرویس‌ها (اختیاری، از داخل پنل)

«سرویس‌های من ← افزودن سرویس» را باز کنید، سرویس و محل اجرا (Dokploy، Coolify یا `docker compose`) را
انتخاب کنید. ویزارد فایل‌ها و قدم‌های همان ابزار را نشان می‌دهد و در آخر اتصال را امتحان می‌کند. نصب
خودکار از طرف پنل با API ‏Dokploy و Coolify قدم بعدی است.

| سرویس | کارش | image |
|---|---|---|
| دستیار سرور | سلامت سرور، برنامه‌های Docker، پشتیبان‌گیری، به‌روزرسانی و آسیب‌پذیری | `mrk-agent` |
| DNS | سرور DNS برای سرور، کانتینرها و شبکه، با مسدودسازی | `mrk-dns` |
| فایروال | حمله‌ها و ورودهای ناموفق را می‌بیند و نشانی‌ها را می‌بندد (اول آزمایشی) | `mrk-firewall` |
| فضای فایل (S3) | سطل‌های سازگار با S3 برای برنامه‌ها و پشتیبان‌ها | `mrk-s3` |
| مخزن npm و PyPI | کش بسته‌ها؛ تا وقتی image خودشان آماده شود در بسته یکپارچه قدیمی `deploy/appliance/compose.yaml` | — |

image‌ها `ghcr.io/seniorkian/mrk-<name>` با همان نسخه پنل هستند. دستیار، DNS، فایروال و S3 روی همان سرور
پنل اجرا می‌شوند (شبکه داخلی `mrk-net` را با آن شریک‌اند).

## ۳. ارتقا

<div dir="ltr">

```bash
git pull && docker compose pull && docker compose up -d
```

</div>

هر سرویس را بعد از گذاشتن نسخه تازه در `MRK_IMAGE` در Dokploy یا Coolify دوباره deploy کنید (یا در پوشه
خودش `docker compose pull && docker compose up -d`).

## ۴. پشتیبان و حذف

- پشتیبان: در پنل «فایل‌ها و پشتیبان ← پشتیبان پنل»؛ بازگردانی در
  [18-operations-runbooks.md](18-operations-runbooks.md#encrypted-backup-and-offline-restore).
- حذف: `docker compose down` (داده می‌ماند) یا `docker compose down -v` (داده هم پاک می‌شود). هر سرویس را
  هم از همان جایی که deploy کرده‌اید همین‌طور حذف کنید.

</div>
