# 18 — Operations Runbooks

این Runbookها متناظر با ruleهای `deploy/observability/prometheus-rules.yaml` و کارت‌های داخل
صفحه Observability هستند. قبل از هر mutation، Request ID، زمان رخداد و آخرین تغییر upstream را
ثبت کنید.

## Service down

1. liveness و readiness را جدا بررسی کنید؛ readiness ناموفق الزاماً به معنی crash نیست.
2. logهای container را با Request ID بررسی کنید و از restart loop یا پر شدن `/data` مطمئن شوید.
3. اگر rollback لازم شد فقط به image digest قبلی برگردید و همان `/data` را حفظ کنید.
4. اگر log پیام `mrk: program <name> is FATAL; stopping supervisord` دارد، یک سرویس داخلی پس از
   تلاش‌های مجدد بالا نیامده و container عمداً خارج شده تا restart policy عمل کند. خروج با کد 0 است،
   پس restart policy باید `unless-stopped` یا `always` باشد (نه `on-failure`). علت را در log همان
   سرویس پیدا کنید؛ restart پشت‌سرهم بدون رفع علت مشکل را حل نمی‌کند.
5. اگر container فقط unhealthy است و `component` برابر `pypi_registry` است، log برنامه
   `devpi-configure` را بررسی کنید (بخش PyPI bootstrap در ادامه).

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
     --entrypoint mrk-restore mrk-panel apply \
     --plan '<plan-id>' \
     --passphrase-file /run/secrets/mrk-restore-passphrase \
     --confirmation 'APPLY <backup-id>' \
     --offline-confirm I_HAVE_STOPPED_MRK
   ```

   در نصب جدا (سند 44) داده npm و PyPI روی volumeهای جدای `mrk-npm-data` و `mrk-pypi-data` است؛ چون
   بازگردانی آفلاین پوشه‌ها را با rename جابه‌جا می‌کند و rename از مرز mount رد نمی‌شود، این دو پوشه را
   رد می‌کند. پیش از بازگردانی آن‌ها، Stackهای `mrk-npm` و `mrk-pypi` را متوقف کنید و محتوای backup را با
   `docker run --rm -v mrk-npm-data:/v ...` در همان volume کپی کنید.
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

## PyPI bootstrap

- `devpi-start.sh` پیش از `devpi-init` فایل `.mrk-init-in-progress` را داخل همان
  `/data/pypi/server` می‌سازد و پس از موفقیت حذف می‌کند. اگر init قطع شود، شروع بعدی فقط محتوای همان
  پوشه را پاک و init را تکرار می‌کند. این فایل را دستی نسازید.
- پیام `Refusing to initialize non-empty devpi server directory` یعنی پوشه داده devpi دارد ولی
  `.nodeinfo` ندارد؛ هیچ چیز خودکار پاک نمی‌شود. پیش از هر اقدام از پوشه backup بگیرید.
- `devpi-configure.sh` ایندکس `root/pypi` را idempotent می‌سازد یا به‌روزرسانی می‌کند و تا
  `MRK_PYPI_CONFIGURE_ATTEMPTS` (پیش‌فرض 10) بار تلاش می‌کند. پس از شکست نهایی، container را
  restart کنید؛ تا فایل `/data/pypi/auth/upstream-configured` ساخته نشود PyPI ready نمی‌شود.
- مسیر artifact بزرگ: router کل فایل را spool و verify می‌کند و سپس به devpi می‌دهد؛ clientها برای
  پکیج‌های بزرگ timeout بالاتری لازم دارند (مثلاً `pip --timeout 900`).

## PostgreSQL

پنل از PostgreSQL استفاده می‌کند: در Docker سرویس `mrk-db` (داده در volume ‏`mrk-db-data`، یا پوشه
`MRK_HOST_DB_PATH`)، در نصب بومی PostgreSQL خود سیستم‌عامل. رمز را `mrk-db-init` یک بار می‌سازد
(volume ‏`mrk-db-secret`) و در هیچ `.env`ی نیست. autovacuum خود PostgreSQL روشن است؛ پنل هم دوره‌ای
`VACUUM (ANALYZE)` می‌زند.

پشتیبان مستقیم دیتابیس (کنار پشتیبان رمزنگاری‌شده پنل):

```sh
docker compose exec -T mrk-db pg_dump -U devassist -d devassist --format=custom > devassist.dump
```

بازگردانی همان فایل (پنل را اول متوقف کنید):

```sh
docker compose stop mrk-panel
docker compose exec -T mrk-db pg_restore -U devassist -d devassist --clean --if-exists < devassist.dump
docker compose start mrk-panel
```

ارتقای نسخه اصلی PostgreSQL (مثلاً 17 به 18) قالب پوشه داده را عوض می‌کند: اول با `pg_dump` پشتیبان
بگیرید، image را عوض کنید و روی volume تازه `pg_restore` کنید.
