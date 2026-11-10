<div dir="rtl">

# نصب DevAssist با Docker

[English](install-docker.md) · **فارسی**

DevAssist یک **پنل** است به‌علاوه چند **سرویس** اختیاری. اول پنل را نصب کنید؛ این تنها چیزی است که دستی
راه می‌اندازید. بقیه سرویس‌ها از داخل خود پنل اضافه می‌شوند: پنل برای هر کدام `compose.yaml` و `.env` آماده
می‌دهد و بعد از بالا آمدن به آن وصل می‌شود.

## ۱. پنل (لازم)

پیش‌نیاز: سرور لینوکس (amd64 یا arm64) با Docker و افزونه Compose، و ۲ گیگابایت رم آزاد برای پنل (هر سرویس مقدار خودش را روی کارتش می‌گوید).

<div dir="ltr">

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist
cd devassist && docker compose up -d
```

</div>

- **Dokploy:** «Create Service ← Compose» از همین مخزن، با Compose Path برابر `./compose.yaml`.
- **Coolify:** «New Resource ← Docker Compose» با `compose.yaml` همین مخزن.
- **بدون Docker** (فقط پنل، با systemd): [install-native.fa.md](install-native.fa.md).

این Stack پنل است به‌علاوه PostgreSQL خودش (`mrk-db`؛ داده در volume ‏`mrk-db-data` یا با
`MRK_HOST_DB_PATH` در پوشه‌ای روی سرور)؛ رمز دیتابیس در اولین اجرا خودکار ساخته می‌شود. پنل روی
`127.0.0.1:8080` باز می‌شود. با تونل SSH بازش کنید و همان اول حساب مالک را بسازید:

<div dir="ltr">

```bash
ssh -L 8080:127.0.0.1:8080 you@your-server   # then open http://localhost:8080
```

</div>

برای دامنه، بعداً از خود پنل اضافه کنید («سرویس‌های من ← افزودن دامنه»).

## ۲. سرویس‌ها (اختیاری، از داخل پنل)

«سرویس‌های من ← افزودن سرویس» را باز کنید، سرویس و محل اجرا (Dokploy، Coolify یا `docker compose`) را
انتخاب کنید. ویزارد فایل‌ها و قدم‌های همان ابزار را نشان می‌دهد و در آخر اتصال را امتحان می‌کند. یا «نصب خودکار» را
بزنید: اگر Dokploy یا Coolify وصل باشد، پنل خودش سرویس را با API آن‌ها می‌سازد، deploy و وصل می‌کند.

| سرویس | کارش | image |
|---|---|---|
| دستیار سرور | سلامت سرور، برنامه‌های Docker، پشتیبان‌گیری، به‌روزرسانی و آسیب‌پذیری | `mrk-agent` |
| DNS | سرور DNS برای سرور، کانتینرها و شبکه، با مسدودسازی | `mrk-dns` |
| فایروال | حمله‌ها و ورودهای ناموفق را می‌بیند و نشانی‌ها را می‌بندد (اول آزمایشی) | `mrk-firewall` |
| فضای فایل (S3) | سطل‌های سازگار با S3 برای برنامه‌ها و پشتیبان‌ها | `mrk-s3` |
| مخزن npm | مخزن خصوصی و کش npm با جابه‌جایی خودکار بین منبع‌ها | `mrk-npm` |
| مخزن PyPI | آینه خصوصی PyPI؛ بسته‌ها را از راه پنل می‌گیرد (جابه‌جایی، پراکسی، قرنطینه) | `mrk-pypi` |

image‌ها `ghcr.io/seniorkian/mrk-<name>` با همان نسخه پنل هستند. همه سرویس‌ها روی همان سرور
پنل اجرا می‌شوند (شبکه داخلی `mrk-net` را با آن شریک‌اند؛ npm و PyPI پوشه داده‌شان را هم با پنل شریک‌اند).

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
