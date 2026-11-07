# Gate 3 — PyPI Registry Baseline

## نتیجه

devpi در همان Docker image اصلی و زیر Supervisor اجرا می‌شود. داده، secret، root credential،
client state و cache فقط زیر `/data/pypi` قرار می‌گیرند؛ root filesystem می‌تواند read-only باشد.

## نسخه‌های pin‌شده

- devpi-server `6.21.0`
- devpi-web `5.2.0`
- devpi-client `7.3.0` برای bootstrap داخلی
- setuptools `81.0.0` (بالاترین سری سازگار با devpi/pyramid) با vendorهای اصلاح‌شده‌ی jaraco.context 6.1.0 و wheel 0.46.3

هیچ prerelease یا tag شناور در runtime استفاده نشده است.

## راه‌اندازی امن

در اولین اجرا، `devpi-start.sh` یک server secret و root password تصادفی با mode `0600` می‌سازد.
اگر `MRK_PYPI_ROOT_PASSWORD_FILE` تعریف شده باشد، password از secret provider خوانده می‌شود.
سپس marker یک‌بارمصرف ایجاد می‌شود و `devpi-configure.sh` فقط از loopback وارد devpi شده و mirror
دیتای تازه را تنظیم می‌کند. readiness تا ثبت `/data/pypi/auth/upstream-configured` سبز نمی‌شود.

اگر volume قبلاً devpi داشته باشد ولی marker/state معتبر نداشته باشد، startup پیکربندی را تغییر
نمی‌دهد. این رفتار از تغییر ناخواسته serial namespace و خراب‌شدن metadata cache جلوگیری می‌کند.

## endpoint کلاینت‌ها

```text
http://HOST:3141/root/pypi/+simple/
```

نمونه‌ها:

```bash
python -m pip install --index-url http://HOST:3141/root/pypi/+simple/ requests
uv pip install --index-url http://HOST:3141/root/pypi/+simple/ requests
poetry source add --priority=primary mrk http://HOST:3141/root/pypi/+simple/
```

در production، TLS باید در reverse proxy/PaaS terminate شود و `MRK_PYPI_OUTSIDE_URL` برابر origin
عمومی HTTPS تنظیم شود.

## آزمون آنلاین و آفلاین

آزمون baseline با `sampleproject==4.0.0` انجام شد. لاگ devpi نشان داد artifact از URL رسمی mirror
لیارا خوانده و داخل volume commit شد. سپس container حذف و همان volume روی Docker network داخلی
بدون DNS یا route اینترنت اجرا شد. اتصال مستقیم به Liara شکست خورد، ولی pip همان wheel را از
endpoint محلی دانلود کرد.

این آزمون در CI نیز برای مسیر آنلاین و آفلاین ثبت شده است. Gate 4 ترتیب `pypi.org -> Liara`،
circuit breaker، probe امن و offline mode صریح را به upstream router منتقل می‌کند.
