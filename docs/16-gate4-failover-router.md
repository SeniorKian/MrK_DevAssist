# Gate 4 — Multi-upstream Failover Router

## مسیر درخواست

```text
pip / uv / Poetry -> devpi :3141 -> router 127.0.0.1:3142
                                      |-> pypi.org
                                      `-> Liara
```

router فقط PEP 503 را برای devpi ارائه می‌دهد. صفحه project بازنویسی می‌شود تا artifact نیز از router
عبور کند؛ در نتیجه خرابی metadata یا فایل هر دو می‌توانند به upstream بعدی failover شوند. خود devpi
کش پایدار و پاسخ آفلاین را نگه می‌دارد.

## کنترل‌های امنیتی

- scheme اجباری HTTPS برای upstream خارجی؛
- ممنوعیت userinfo/credential، query و fragment در base URL؛
- host allowlist مجزا برای index و artifact CDN؛
- resolve و رد IP خصوصی، loopback، reserved، link-local و multicast؛
- redirect محدود با validate مجدد هر hop؛
- عدم استفاده از proxy environment؛
- listen فقط روی loopback و عدم publish پورت `3142`.
- credential خارج URL و رمزنگاری‌شده است؛ Authorization فقط به host اصلی upstream ارسال می‌شود.
- artifact دارای hash پیش از ارسال کامل spool و SHA-256 آن verify می‌شود.

## circuit breaker

خطاهای connect/read/DNS/network و statusهای `408/425/429/500/502/503/504` failure محسوب می‌شوند.
با رسیدن failure count به threshold، upstream تا پایان cooldown از rotation خارج می‌شود. status فقط
نام، URL عمومی، state، تعداد خطا، error code و زمان آخرین موفقیت را نمایش می‌دهد.

## Offline mode

وجود `/data/control-plane/pypi-offline` هر outbound router را متوقف می‌کند. devpi همچنان metadata و
artifact کش‌شده را serve می‌کند. cache-miss عمداً پاسخ ناموفق می‌گیرد و به اینترنت نشت نمی‌کند.

## نتیجه chaos نهایی

با primary عمداً خراب، circuit باز و Liara انتخاب شد. artifact واقعی دانلود شد. پس از فعال‌کردن
offline mode، همان artifact موفق و یک artifact کش‌نشده ناموفق بود. تست خودکار DNS failure،
connect/read timeout، TCP reset، HTTP 503، recovery circuit و fallback را پوشش می‌دهد. checksum
نامعتبر پیش از exposure با `checksum_mismatch` رد، فایل موقت پاک و upstream بعدی انتخاب می‌شود.

Gate 4 در 2026-11-07 با ۴۶ تست کامل backend، Ruff و build تولیدی پنل بسته شد.
