# 18 — Operations Runbooks

این Runbookها متناظر با ruleهای `deploy/observability/prometheus-rules.yaml` و کارت‌های داخل
صفحه Observability هستند. قبل از هر mutation، Request ID، زمان رخداد و آخرین تغییر upstream را
ثبت کنید.

## Service down

1. liveness و readiness را جدا بررسی کنید؛ readiness ناموفق الزاماً به معنی crash نیست.
2. logهای container را با Request ID بررسی کنید و از restart loop یا پر شدن `/data` مطمئن شوید.
3. اگر rollback لازم شد فقط به image digest قبلی برگردید و همان `/data` را حفظ کنید.

## Registry unavailable

1. وضعیت npm و PyPI را جدا در Observability بررسی کنید.
2. از Upstreams، probe چهارمرحله‌ای DNS/TCP/TLS/HTTP را اجرا کنید.
3. اگر اینترنت قطع است cache-only را فعال کنید؛ ترتیب upstream را بدون شواهد تغییر ندهید.
4. cache-hit شناخته‌شده را با client واقعی آزمایش کنید.

## Storage pressure

1. صفحه Data lifecycle را باز و cleanup preview را با target مناسب اجرا کنید.
2. Pin و Quarantine را بازبینی کنید؛ این موارد نباید خودکار حذف شوند.
3. candidateها را از قدیمی‌ترین artifact بررسی و فقط با typed confirmation حذف کنید.
4. پس از عملیات Integrity Scan اجرا کنید.

## Offline mode

1. مشخص کنید offline mode عمدی است یا پس از incident باقی مانده است.
2. قبل از خروج از cache-only، upstream probe و TLS validation را اجرا کنید.
3. یک پکیج کم‌ریسک را revalidate و سپس client install را تست کنید.

## Failed jobs

1. error code و نوع job را در Jobs بررسی کنید؛ پیام‌های خام secret نمایش داده نمی‌شوند.
2. علت اصلی را رفع کنید و سپس Retry بزنید؛ retry متوالی بدون تغییر ممنوع است.
3. برای purge ناموفق، Pin، typed confirmation و دسترسی filesystem را بررسی کنید.
4. برای backup ناموفق، فضای آزاد، passphrase و Integrity Scan را بررسی کنید.

## Encrypted backup and offline restore

Restore یک عملیات آفلاین است و از داخل API یا پنل اجرا نمی‌شود. پنل فقط فایل را اعتبارسنجی
و plan یک‌ساعته می‌سازد. عبارت عبور در plan، دیتابیس، audit یا command تولیدشده ذخیره نمی‌شود.

1. در Data lifecycle یک backup رمزنگاری‌شده بسازید و passphrase را خارج از `/data` نگه دارید.
2. همان backup را Validate کنید و عبارت دقیق `RESTORE <backup-id>` را وارد کنید.
3. گزینه Prepare offline restore را اجرا و `plan id` و عبارت `APPLY <backup-id>` را ثبت کنید.
4. passphrase را در یک فایل موقت با دسترسی فقط مالک قرار دهید؛ آن را در history خط فرمان ننویسید.
5. سرویس اصلی را متوقف کنید و با `docker compose ps` مطمئن شوید container اصلی اجرا نمی‌شود.
6. CLI را با همان image و همان volume داده اجرا کنید؛ نمونه فرمان:

   ```sh
   docker compose run --rm --no-deps \
     -v "$PWD/restore-passphrase:/run/secrets/mrk-restore-passphrase:ro" \
     --entrypoint mrk-restore mrk-mirror apply \
     --plan '<plan-id>' \
     --passphrase-file /run/secrets/mrk-restore-passphrase \
     --confirmation 'APPLY <backup-id>' \
     --offline-confirm I_HAVE_STOPPED_MRK
   ```

7. receipt داخل `/data/control-plane/restore-receipts` و backup rollback داخل
   `/data/backups/restore-rollbacks` را بررسی کنید؛ سپس فایل passphrase موقت را امن حذف کنید.
8. سرویس را بالا بیاورید و readiness، ورود Owner، package catalog، Integrity Scan و نصب یک پکیج
   کش‌شده از هر رجیستری را بررسی کنید.

اگر `MRK_UPSTREAM_SECRET_KEY_FILE` تنظیم شده است، فایل کلید ۳۲‌بایتی جزو `/data` یا backup نیست.
پیش از بالا آوردن image جدید یا اجرای restore، همان نسخه کلید را از secret manager روی مسیر
فقط‌خواندنی مورد انتظار mount کنید. از چاپ، base64 کردن در command line یا قراردادن کلید در `.env`
خودداری کنید. نبودن فایل، regular-file نبودن آن یا طولی غیر از ۳۲ بایت عمداً credential store را
fail-closed می‌کند. گم‌شدن این کلید یعنی credentialهای upstream باید از پنل replace شوند.

CLI در صورت heartbeat تازه، plan منقضی، confirmation نادرست، schema migration ناسازگار، checksum
نامعتبر، symlink، path ناامن یا فضای ناکافی بدون اعمال تغییر متوقف می‌شود. در صورت failure هنگام
اعمال، فایل‌های جابه‌جا‌شده و snapshot دیتابیس تا حد ممکن به وضعیت پیشین برگردانده می‌شوند.
