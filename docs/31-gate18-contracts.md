# 31 — قراردادهای Gate 18 (سرویس S3، بکاپ سرور و دیتابیس، پیگیری آپدیت image)

وضعیت: **قرارداد مرجع پیاده‌سازی — 2026-11-08**. مشخصات کامل S3 در `docs/30-s3-object-storage-spec.md`.
هر تغییر باید هم‌زمان در backend و پنل اعمال شود.

## 1. مجوزها (auth.py)

| مجوز | owner | admin | operator | developer | viewer |
|---|---|---|---|---|---|
| `s3:read` (فهرست باکت/فایل، دانلود) | ✓ | ✓ | ✓ | ✓ | – |
| `s3:write` (آپلود، حذف فایل، پوشه، لینک اشتراک) | ✓ | ✓ | ✓ | – | – |
| `s3:admin` (باکت، identity، کلید، تنظیمات) | ✓ | ✓ | – | – | – |
| `backup:server:read` | ✓ | ✓ | ✓ | – | – |
| `backup:server:write` (مقصد، job، اجرا) | ✓ | ✓ | – | – | – |
| `updates:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `updates:write` (تنظیمات، بررسی دستی) | ✓ | ✓ | ✓ | – | – |

ساخت باکت «لینک‌شده به پوشه سرور» فقط برای owner (نیازمند `*`).

## 2. موتور S3 (`s3-engine`)

- process جدا زیر supervisord: `mrk-s3-engine` (console script در همان پکیج)، گوش روی `MRK_S3_LISTEN`
  (پیش‌فرض `0.0.0.0:9000`)؛ compose آن را روی `127.0.0.1:${MRK_S3_PORT:-9000}:9000` منتشر می‌کند (مثل npm/PyPI).
  دامنه: کاربر در Dokploy/Traefik یا Edge Gateway دامنه `s3.<domain>` (و `*.s3.<domain>` برای virtual-host) را به این
  پورت می‌دهد؛ Host اصلی باید حفظ شود.
- **پیکربندی:** موتور هیچ دسترسی به PGlite ندارد. Control Plane یک snapshot اتمیک در
  `/data/modules/s3/config.json` می‌نویسد؛ موتور با تغییر mtime (هر ۲ ثانیه) آن را بارگذاری می‌کند:
  ```json
  {"version": 1, "enabled": true, "region": "us-east-1", "public_endpoint": "https://s3.example.com",
   "virtual_host_suffix": "s3.example.com", "max_object_bytes": 5497558138880,
   "buckets": [{"name": "backups", "mode": "managed"|"linked", "link_path": "/mnt/links/files/a"|null,
                "link_mode": "rw"|"ro", "public_read": false, "quota_bytes": null, "created_at": 0}],
   "identities": [{"id": "..", "name": "..", "enabled": true, "system": false,
                   "policy": {"Version": "2012-10-17", "Statement": [..]},
                   "keys": [{"access_key_id": "MRK...", "secret_ref": "..", "enabled": true}]}]}
  ```
  secretها از `SecretStore(/data)` خوانده می‌شوند (همان کلید رمزنگاری). Control Plane یک identity سیستمی مخفی
  `__mrk_panel__` با دسترسی کامل می‌سازد تا خودش از طریق S3 API با موتور کار کند (فایل‌منیجر، presign).
- **ذخیره‌سازی:** managed در `/data/modules/s3/buckets/<bucket>/`؛ index اشیا در یک SQLite (WAL) per bucket متعلق
  به موتور؛ linked: فایل‌های واقعی در `link_path` (فقط زیر `/mnt/links`) با قواعد key↔path و ایمنی `docs/30 §3`.
- **API داخلی مدیریت** (فقط `127.0.0.1:9001`، توکن مشترک در `/data/modules/s3/admin.token` با mode 0600، هدر
  `X-MRK-Admin-Token`): `GET /admin/health`، `GET /admin/buckets/{b}/stats` → `{objects, bytes}`،
  `POST /admin/buckets/{b}/ensure`، `DELETE /admin/buckets/{b}?force=0|1` (برای linked هرگز فایل‌ها را پاک نمی‌کند،
  فقط index)، `GET /admin/links` → پوشه‌های mount‌شده زیر `/mnt/links`.
- **دامنه MVP S3:** طبق `docs/30 §1` و `§10` (MVP)، به‌خصوص سازگاری Dokploy (path-style، multipart، List/Head/Delete)
  و SigV4 header/query/chunked (signed، unsigned، trailer) با checksumهای جدید SDKها.

## 3. Control Plane — ماژول `s3` (`/api/v1/s3`)

- `GET /settings` (s3:read) و `PUT /settings` (s3:admin) → `{enabled, region, public_endpoint, virtual_host_suffix, max_object_bytes, default_quota_bytes}`
- `GET /status` (s3:read) → `{engine_reachable, buckets, objects, bytes, endpoint}`
- `GET /buckets` (s3:read) → `{items:[{name, mode, link_path, link_mode, public_read, quota_bytes, objects, bytes, created_at}]}`
- `POST /buckets` (s3:admin؛ linked فقط owner) `{name, mode, link_path?, link_mode?, public_read?, quota_bytes?}` → 201
- `PATCH /buckets/{name}` `{public_read?, quota_bytes?, link_mode?}`؛ `DELETE /buckets/{name}` `{confirmation: name, force?: bool}`
- `GET /links` (s3:admin) → `{items:[{path, writable, size_bytes?}], compose_hint}`
- فایل‌منیجر (s3:read برای خواندن، s3:write برای تغییر):
  - `GET /buckets/{name}/objects?prefix=&delimiter=/&continuation=&limit=` → `{prefixes:[..], objects:[{key, size, etag, last_modified, content_type}], next_continuation}`
  - `POST /buckets/{name}/objects?key=` (بدنه خام stream، `Content-Type` فایل) → `{key, size, etag}`
  - `GET /buckets/{name}/objects/download?key=` → stream با `Content-Disposition`
  - `DELETE /buckets/{name}/objects` `{keys:[..]}` → `{deleted, errors}`
  - `POST /buckets/{name}/folders` `{prefix}`؛ `POST /buckets/{name}/objects/move` `{from, to}`
  - `POST /buckets/{name}/share` `{key, expires_seconds}` (≤ 7 روز) → `{url, expires_at}`
- Identityها (s3:admin): `GET /identities` → `{items:[{id, name, enabled, policy_template, buckets, policy, keys:[{access_key_id, enabled, created_at, last_used_at}], created_at}]}`؛
  `POST /identities` `{name, policy_template:"read_only"|"read_write"|"admin"|"backup_client"|"custom", buckets:[..], policy?}`؛
  `PATCH /identities/{id}`؛ `DELETE /identities/{id}` `{confirmation: name}`؛
  `POST /identities/{id}/keys` → `{access_key_id, secret_access_key}` (secret فقط یک‌بار)؛ `PATCH|DELETE /identities/{id}/keys/{akid}`.
- `GET /connection` (s3:read) → `{endpoint, region, path_style: true, snippets: {aws_cli, rclone, mc, boto3, restic, dokploy}}`
- همه mutationها با CSRF و audit (بدون secret).

## 4. ماژول بکاپ سرور (`server_backups`، `/api/v1/server-backups`)

- مقصدها (`backup:server:*`): `GET/POST/PATCH/DELETE /destinations`
  `{name, kind:"local"|"s3"|"mrk_s3", config:{path? | endpoint, bucket, region, prefix, path_style, access_key_id, proxy_id?}, secret:{secret_access_key?}}`؛
  `POST /destinations/{id}/test` → `{ok, latency_ms, error_code?}`. `mrk_s3` = S3 بومی همین سیستم روی loopback (بدون خروج).
- jobها: `GET/POST/PATCH/DELETE /jobs`
  `{name, source:{kind:"volume"|"postgres"|"mysql"|"mariadb"|"mongo"|"redis", volume?, container?, database?}, destination_id, schedule:"<cron 5 field>", retention:{keep_last, keep_days}, enabled}`؛
  `POST /jobs/{id}/run` → 202 `{run_id}`؛ `GET /runs?job_id=&limit=` → `{items:[{id, job_id, state:"running"|"succeeded"|"failed", started_at, finished_at, bytes, object_key, error_code}]}`؛
  `GET /runs/{id}/download` (stream فایل بکاپ رمزنگاری‌شده) و `GET /sources` → volumeها و کانتینرهای دیتابیس کشف‌شده از Agent.
- رمزنگاری: MRKBKP2 با کلید job در SecretStore (هیچ passphrase در DB)؛ retention پس از هر اجرای موفق؛ رویداد
  `server_backup.failed` (error) و `server_backup.succeeded` (info).
- Host Agent (endpointهای جدید امضاشده): `GET /v1/backup/volumes/{name}/archive` → stream tar از volume
  (mount فقط‌خواندنی `/var/lib/docker/volumes:/host/volumes:ro`)؛ `POST /v1/backup/db/{container_id}/dump`
  `{engine, database?}` → stream dump با exec **allowlist‌شده با argv ثابت** (pg_dump/mysqldump/mariadb-dump/mongodump --archive/redis-cli --rdb)؛
  credential از env همان کانتینر داخل Agent خوانده می‌شود و هرگز به Control Plane نمی‌رسد. کانتینرهای Dokploy
  محافظت‌شده فقط خواندنی‌اند (dump مجاز است چون فقط‌خواندنی است، ولی ترجیح: بکاپ دیتابیس‌های Dokploy از خود Dokploy).

## 5. ماژول پیگیری آپدیت (`updates`، `/api/v1/updates`)

- `GET /images` (updates:read) → `{items:[{image, tag, registry, current_digest, latest_digest, update_available, checked_at, error_code, containers:[{name, protected}]}], last_run_at}`
- `POST /check` (updates:write) → 202؛ `GET/PUT /settings` `{enabled, interval_hours:12, ignore:["pattern"], include_stopped:false}`
- بررسی با `HEAD` manifest (Accept انواع manifest/index) و token anonymous رجیستری، از طریق `outbound.py`
  (پروکسی قابل‌تنظیم؛ ثبت provider در registry سرویس‌های خارجی با kind `registry`)؛ هرگز آپدیت خودکار.
- رویداد `update.available` (info، dedupe per image+digest).
