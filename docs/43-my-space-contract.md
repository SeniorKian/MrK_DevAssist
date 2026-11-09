# 43 — قرارداد «فضای من» (فضای کاری، بسته، مالکیت)

وضعیت: **قرارداد مرجع — 2026-11-09**. برنامه و تصمیم‌ها: `docs/42`. پژوهش: `docs/_research-tenancy.md`. هر سازنده تغییر شکل
را در §0 ثبت کند (0.1 بک‌اند، 0.2 پنل).

## 0. تغییرات نسبت به قرارداد اولیه

### 0.1 بک‌اند

مسیرها و شکل JSON دقیقاً همان‌طور که پیاده شده‌اند (همه زیر `/api/v1`). خطاها همان پوشش همیشگی
`{error:{code, message, request_id, fields?, ...extra}}` را دارند. هر تغییر (POST/PUT/PATCH/DELETE) با کوکی جلسه
هدر `X-CSRF-Token` می‌خواهد (کلید API نه).

**کلیات**
- `tenancy.enabled=false` ⇒ همه `/my/...` → 404 `tenancy_disabled`؛ مسیرهای `/admin/...` در دسترس‌اند (برای آماده‌سازی
  بسته‌ها پیش از روشن کردن).
- فضای جاری: هدر `X-Workspace: ws_…`؛ بدون آن فضای شخصی کاربر (اگر نباشد همان لحظه ساخته می‌شود). فضایی که عضوش نیستید → 404
  `not_found`. مسیرهای `/my/workspaces/{ws}/...` فضا را از مسیر می‌گیرند و هدر را نادیده می‌گیرند.
- منبع مال فضای دیگر یا ناموجود → **404 `not_found`** (یکسان، تا وجودش لو نرود). ترتیب بررسی: ورود → فضا → مالکیت منبع (404)
  → نقش/scope (403 `forbidden` با `required`) → suspended (423 `workspace_suspended`) → امکان (403 `feature_disabled` با
  `feature`) → سهمیه (409 `quota_exceeded` با `quota, limit, used`) → اعتبارسنجی (422).
- نقش‌های فضا: `owner` > `admin` > `member` > `viewer`. viewer فقط خواندن؛ member منابع را می‌سازد/تغییر می‌دهد؛ admin
  اعضا/کلیدهای API همه/تنظیم فضا؛ owner حذف فضا و ساخت owner دیگر. ارتقا بالاتر یا هم‌سطح خود → 403 `permission_escalation`.
- مجوزهای تازه سامانه: `tenancy:admin` (گروه people، نیاز به `user:read`) و `tenancy:impersonate_write` (نیاز به
  `tenancy:admin`)؛ نقش داخلی `admin` هر دو را دارد. نقش داخلی تازه `customer` هیچ مجوز مدیریتی ندارد (در فهرست نقش‌ها فقط
  وقتی `tenancy.enabled` روشن است دیده می‌شود).
- «دیدن به‌جای»: هدر `X-View-As: <token>` کنار جلسه خود مدیر. فقط‌خواندنی (نقش `viewer`)؛ با `write:true` نقش `admin`. هر
  درخواست `/my` در این حالت audit می‌شود (`tenancy.view_as.request`، با `workspace_id` و `on_behalf_of`=مالک فضا).
- audit: رویدادها دو ستون تازه دارند `workspace_id`, `on_behalf_of` (در `GET /audit-events` هم برمی‌گردند).

**اشیای مشترک**
- `Plan`: `{id, name_fa, name_en, description, default, builtin, features:{dns, dns_dnssec, dns_templates, s3,
  s3_public_links, s3_bucket_domains, npm, pypi, teams, api_tokens}, quotas:{workspaces_team, members, dns_zones,
  dns_records_per_zone, dns_record_types:[…], s3_buckets, s3_bytes, s3_objects, s3_keys, s3_bucket_domains, npm_bytes,
  pypi_bytes, api_tokens}, workspaces:int, created_at, updated_at}`؛ `null` = بی‌سقف. بسته‌های آماده: `basic` (پیش‌فرض)،
  `pro`، `unlimited` (`builtin:true`، قابل ویرایش، غیرقابل حذف).
- `Usage`: `{members, workspaces_team, dns_zones, s3_buckets, s3_bytes, s3_objects, s3_keys, s3_bucket_domains,
  npm_bytes, pypi_bytes, api_tokens}` (`s3_bytes/s3_objects` اگر موتور S3 در دسترس نباشد `null`).
- `Workspace` (در «فضای من»): `{id, slug, name, kind, status, role, plan:{id, name_fa, name_en}, limits:{features,
  quotas}, usage, created_at}` (`limits` = بسته + `quota_overrides`).
- `WorkspaceAdmin` (مدیر): همان + `{plan_id, quota_overrides, owner:{id, username, display_name}|null, members_count}`.

**API مدیریت** (`tenancy:admin`؛ «دیدن به‌جای» با نوشتن: `tenancy:impersonate_write`)
- `GET /admin/plans` → `{items:[Plan]}`؛ `POST /admin/plans {id?, name_fa, name_en, description?, default?, features,
  quotas}` → 201 Plan (کلید ناشناخته 422؛ شناسه `^[a-z0-9][a-z0-9_-]{1,31}$`)؛ `PUT /admin/plans/{id}` (همان بدنه، بخشی)
  → Plan؛ `DELETE /admin/plans/{id}` → `{deleted}` یا 409 `plan_in_use {workspaces}` / 409 `plan_builtin` /
  409 `plan_default`.
- `GET /admin/workspaces?query=&status=` → `{items:[WorkspaceAdmin]}`؛ `GET /admin/workspaces/{id}` → WorkspaceAdmin +
  `{members:[{user_id, username, display_name, email, role}], resources:[{kind, resource_id, created_by, created_at,
  meta}]}`؛ `PATCH /admin/workspaces/{id} {plan_id?, quota_overrides?, status?, name?}` → WorkspaceAdmin
  (`quota_overrides` فقط کلیدهای quotas؛ `null` یعنی حذف استثنا)؛ `DELETE /admin/workspaces/{id}?confirmation=<slug>&mode=
  delete|transfer` → `{deleted, mode, resources:{removed|transferred:int}}` (اشتباه بودن تأیید → 422
  `confirmation_mismatch`).
- `GET /admin/ownership?kind=&workspace_id=` → `{items:[{kind, resource_id, workspace_id, workspace_slug,
  created_by, created_at}]}`؛ `POST /admin/ownership/transfer {kind, resource_id, workspace_id|null}` → `{kind,
  resource_id, workspace_id}` (`null` = به سامانه). `kind` یکی از `dns_zone, s3_bucket, s3_identity, bucket_domain,
  npm_scope, pypi_index, api_token`.
- `POST /admin/workspaces/{id}/view-as {write?:bool}` → 201 `{token, expires_at, write, workspace:{id, slug, name}}`
  (30 دقیقه)؛ `DELETE /admin/view-as` با هدر `X-View-As` → `{ended:true}`.
- `GET /admin/signups?status=pending` → `{items:[{id, user:{id, username, display_name, email}, status, created_at,
  decided_at}]}`؛ `POST /admin/signups/{id}/approve {plan_id?}` → `{status:"approved", workspace_id}`؛
  `POST /admin/signups/{id}/reject` → `{status:"rejected"}` (حساب حذف می‌شود).
- `GET /admin/tenancy/settings` → `{enabled, signup, default_plan_id, verify_domains, admin_area_local_only}`؛
  `PUT` همان (بخشی). همین‌ها در registry هم هستند: `tenancy.enabled`, `tenancy.signup`, `tenancy.default_plan_id`,
  `tenancy.verify_domains`, `tenancy.admin_area_local_only` (گروه `people.security`).
- ثبت‌نام عمومی با `tenancy.enabled`: `GET /auth/registration-status` → `{enabled, mode}` (`mode` = `off|approval|open`؛ بی
  tenancy همان `{enabled}` قبلی). `POST /auth/register`: `open` → 201 مثل قبل با نقش `customer` و فضای شخصی؛
  `approval` → 202 `{status:"pending_approval"}` بدون جلسه؛ `off` → 409 `registration_rejected`.
- `tenancy.admin_area_local_only=true` ⇒ هر مسیر نیازمند مجوز مدیریتی فقط از loopback/شبکه خصوصی؛ وگرنه 403
  `admin_area_local_only`.

**«فضای من»** (`/my/...`)
- `GET /my/me` → `{user:{id, username, display_name, email, role}, workspaces:[Workspace], current:"ws_…",
  view_as:null|{workspace_id, write, expires_at, admin_user_id}}`.
- `GET /my/activity?before_id=&limit=` → `{items:[{id, actor_user_id, actor_username, on_behalf_of, action,
  object_type, object_id, result, occurred_at}], next_before_id}` (فقط رویدادهای همین فضا).
- فضاها: `POST /my/workspaces {name, slug?}` → 201 Workspace (`features.teams` + سهمیه `workspaces_team` از فضای شخصی
  سازنده؛ بسته همان بسته فضای شخصی)؛ `PATCH /my/workspaces/{ws} {name}` (admin+)؛ `DELETE /my/workspaces/{ws}
  {confirmation:<slug>}` (owner، فقط team؛ منابع حذف می‌شوند) → `{deleted:true}`.
- اعضا (فقط فضای team؛ شخصی → 409 `personal_workspace`): `GET /my/workspaces/{ws}/members` → `{items:[{user_id, username,
  display_name, email, role, created_at}]}`؛ `POST … {user:<username|email>, role}` → 201 عضو (کاربر ناموجود → 404
  `user_not_found`؛ سهمیه `members`)؛ `PATCH …/members/{user_id} {role}`؛ `DELETE …/members/{user_id}` (خروج خود هم
  مجاز؛ آخرین owner → 409 `last_owner`).
- دعوت‌نامه: `GET /my/workspaces/{ws}/invites` → `{items:[{id, email, role, created_at, expires_at}]}`؛ `POST … {email,
  role}` → 201 `{id, email, role, token, expires_at}` (توکن یک‌بار)؛ `DELETE …/invites/{id}`؛ `POST /my/invites/accept
  {token}` → `{workspace_id, role}` (ایمیل حساب باید همان ایمیل دعوت باشد، وگرنه 404). کسی که حساب ندارد از خود لینک
  حساب می‌سازد (§0.3).
- **DNS** (`features.dns`): `GET /my/dns/zones` → `{items:[Zone]}` که `Zone` = شیء موتور + `{status:"active"|
  "pending_verification", verified_at}`؛ `GET /my/dns/templates` → `{items:[{id, name, description, builtin,
  variables}], default_id}`؛ `POST /my/dns/zones {name, template_id?, variables?}` → 201 Zone + `{template}` (فقط primary؛
  `template_id` فقط با `dns_templates`، وگرنه قالب پیش‌فرض)؛ زون تداخلی → 409 `zone_unavailable`؛ `GET /my/dns/zones/{z}`؛
  `DELETE /my/dns/zones/{z} {confirmation:<z>}`؛ `GET …/{z}/verification` → `{methods:[{kind:"txt",
  name:"_devassist-verify.<z>", value:"devassist-verify=<token>"}, {kind:"ns", targets:[…]}], verified, status}`؛
  `POST …/{z}/verify` → `{verified, method:"txt"|"ns"|null, status}`؛ رکوردها: `GET …/{z}/records` → `{items}`،
  `POST …/{z}/records` (بدنه همان رکورد مدیریت بدون `view`؛ نوع باید در `dns_record_types` باشد → وگرنه 422
  `dns_record_type_not_allowed`؛ سهمیه `dns_records_per_zone`)، `PUT/DELETE …/{z}/records/{id}`؛
  `POST …/{z}/apply-template {template_id, variables?, replace_conflicts?}` (`dns_templates`)؛
  `GET …/{z}/dnssec`، `PUT …/{z}/dnssec {enabled:bool}` (`dns_dnssec`).
- **فضای فایل** (`features.s3`): `GET /my/s3/buckets` → `{items:[{name, public_read, created_at, objects, bytes}],
  suggested_prefix:"<slug>-"}`؛ `POST /my/s3/buckets {name, public_read?}` (`public_read` فقط با `s3_public_links`)؛
  `GET/PATCH /my/s3/buckets/{b} {public_read}`؛ `DELETE /my/s3/buckets/{b} {confirmation:<b>, force?}`؛ فایل‌ها دقیقاً مثل
  مدیریت: `GET …/{b}/objects?prefix=&delimiter=&continuation=&limit=`، `POST …/{b}/objects?key=` (بدنه خام)،
  `GET …/{b}/objects/download?key=`، `DELETE …/{b}/objects {keys}`، `POST …/{b}/folders {prefix}`،
  `POST …/{b}/objects/move {from, to}`، `POST …/{b}/share {key, expires_seconds}`؛ سقف حجم/تعداد در موتور →
  `QuotaExceeded` (پنل: `engine_error` با پیام موتور).
- کلیدهای S3: `GET /my/s3/keys` → `{items:[{id, name, access, buckets, enabled, access_key_id, created_at}]}`؛
  `POST /my/s3/keys {name, access:"read_only"|"read_write"|"admin", buckets:[…]}` → 201 همان + `{secret_access_key}`
  (یک‌بار؛ باکت غیرخودی → 404)؛ `PATCH /my/s3/keys/{id} {enabled?, access?, buckets?}`؛ `DELETE /my/s3/keys/{id}`.
  سیاست را DevAssist می‌سازد (بدون `PutBucketPolicy`/`DeleteBucket`/`CreateBucket`)؛ فیلد `policy` پذیرفته نمی‌شود (422).
- دامنه باکت (`s3_bucket_domains`): `GET /my/s3/buckets/{b}/domains` → `{items:[{host, verified, verification:{name,
  value}, route:{state, error_code}}]}`؛ `POST … {host}` → 201 همان شکل (زیر زون تأییدشده خود فضا ⇒ همان لحظه
  `verified:true` و مسیر ساخته می‌شود؛ host که برنامه‌ای در Dokploy دارد → 409 `domain_unavailable`)؛
  `POST …/domains/{host}/verify` → `{verified, route}`؛ `POST …/domains/{host}/route` → `{host, route}` (دوباره امتحان؛
  تأییدنشده → 409 `domain_not_verified`)؛ `DELETE …/domains/{host}` (مسیر هم برداشته می‌شود).
  `route.state` برای فضا: `ok | pending | manual | failed | conflict | off | unverified` (جزئیات سرور مثل پروژه Dokploy،
  درگاه یا مراحل دستی هیچ‌وقت به فضا نمی‌رسد).
- **بسته‌ها**: `GET /my/packages` → `{npm:{enabled, scope:"@<slug>", registry_url, publish_allowed, usage_bytes,
  packages:[{name, versions:[…], bytes}]}, pypi:{enabled, index:"<slug>/dev", index_url, publish_allowed,
  usage_bytes, packages:[{name, versions:[…]}]}}`؛ `GET /my/packages/tokens` → `{items:[{id, ecosystem, name,
  username, created_at}]}`؛ `POST /my/packages/tokens {ecosystem:"npm"|"pypi", name}` → 201 `{id, ecosystem, name,
  username, token, setup:{npmrc|pypirc}}` (یک‌بار)؛ `DELETE /my/packages/tokens/{id}`؛
  `DELETE /my/packages/{ecosystem}/{name}/versions/{version}`.
- **کلیدهای API من**: `GET /my/tokens` → `{items:[{id, name, scopes, workspace_id, created_by, expires_at, ip_allow,
  last_used_at, created_at}]}` (admin+ همه کلیدهای فضا را می‌بیند)؛ `POST /my/tokens {name, scopes,
  expires_in_seconds?, ip_allow?:[cidr]}` → 201 `{id, token, …}`؛ `DELETE /my/tokens/{id}`. scopes:
  `my.dns:read|write`, `my.s3:read|write`, `my.packages:read|write` و زیرمجموعه نقش سازنده (وگرنه 403
  `permission_escalation`). کلید فقط به فضای خودش و فقط `/my` دسترسی دارد (`Authorization: Bearer mrk_…`).

**تصمیم‌ها و محدودیت‌های پیاده‌سازی (بک‌اند)**
- لایه مشترک: `mrk_control_plane/tenancy.py` (`TenancyStore.resolve` → `WorkspaceContext.need`،
  `require_owned`، `claim` با شمارش سهمیه در همان تراکنش + قفل هر فضا). مسیرها: `modules/tenancy.py` (مدیر + هسته)،
  `my_dns.py`، `my_s3.py`، `my_packages.py`. جدول‌ها: migration `20261109_0014`.
- اعضا، کلیدهای API و خود فضا فقط با جلسه خود شخص (نه کلید API و نه «دیدن به‌جای») تغییر می‌کنند → 403 `forbidden`
  با `required:"session"`.
- کلید مدیریتی قدیمی (`/api/v1/tokens`) به `/my` راه ندارد (403)؛ کلیدهای فضا در فهرست کلیدهای مدیریت دیده نمی‌شوند.
- فایل‌منیجر `/my/s3` همان کد مدیریت است (`s3.add_file_routes`) با بررسی مالکیت باکت از مسیر.
- موتور S3: snapshot دو فیلد تازه دارد `quota_groups:[{id, buckets, bytes, objects}]` و `bucket_hosts:{host:
  bucket}` و روی باکت فضای تعلیق‌شده `frozen:true` (موتور هر نوشتن را `AccessDenied` می‌دهد).
- دامنه باکت در موتور S3 سرو می‌شود (Host → باکت). **مسیر عمومی** آن (`modules/bucket_routes.py`) دقیقاً مثل دامنه سرویس
  S3 ساخته می‌شود: همان روش اتصال (`domains.routing_mode`: Dokploy API / فایل Traefik / دستی)، همان مقصد (درگاه 9000 موتور
  S3 در همین کانتینر) و TLS با certResolver در Traefik. DevAssist هرگز 80/443 را نمی‌گیرد.
  - فقط دامنه **تأییدشده** مسیر می‌گیرد (افزودن زیر زون تأییدشده، `…/verify` موفق، یا «دوباره امتحان»). حذف دامنه، حذف باکت،
    حذف فضا (cleanup `bucket_domain`) مسیر را برمی‌دارد؛ انتقال مالکیت و تغییر فضا (`after_quota_change`) یک reconcile پس‌زمینه
    می‌زند و حلقه بررسی دامنه‌ها (هر ۵ دقیقه) هم reconcile می‌کند تا مسیر بی‌صاحب نماند.
  - وضعیت مسیر جدا از ردیف مالکیت در `system_settings["services.bucket_routes"]` (کلید = host) نگه داشته می‌شود تا پس از رفتن
    ردیف مالکیت هم برداشتنش ممکن باشد: `{bucket, workspace_id, mode, state, https, error_code, upstream_code,
    dokploy_domain_id, redeploy_required, conflict, updated_at}`. وضعیت‌ها: `ok`، `pending` (Dokploy Compose دامنه را دارد
    ولی تا Deploy بعدی مدیر فعال نیست؛ DevAssist خودش Deploy نمی‌کند — «دوباره امتحان» مدیر پس از Deploy آن را `ok` می‌کند)،
    `manual` (مراحل دستی فقط برای مدیر)، `failed` (برگشت داده شد)، `conflict` (هیچ تغییری داده نشد)، `stale` (برداشتن نیمه‌کاره)،
    `off`.
  - برگشت در خطا: Dokploy → اگر ثبت وضعیت بعد از `domain.create` شکست بخورد همان دامنه `domain.delete` می‌شود؛ فایل Traefik →
    اگر نوشتن شکست بخورد مسیر `failed` می‌شود و فایل بدون آن دوباره نوشته می‌شود. خطای مسیر هرگز خود دامنه/تأیید را برنمی‌گرداند.
  - در حالت فایل Traefik دامنه‌های باکت میزبان‌های اضافه همان ورودی `s3` فایل `mrk-domains.yml` هستند (Agent تغییری نکرد؛
    سقف `MAX_HOSTS=200` برای کل s3). یک router برای s3 است، پس اگر یک دامنه سرویس S3 بدون HTTPS باشد کل s3 بی‌HTTPS می‌شود.
  - تداخل: دامنه باکت با دامنه سرویس‌ها (`names_overlap`)، زون/دامنه باکت فضای دیگر و برنامه‌های Dokploy رد می‌شود؛ ساخت دامنه
    سرویس روی host یک دامنه باکت → 409 `domain_exists` با `owner:{kind:"bucket"}`. اگر تداخل بعداً پیدا شود وضعیت `conflict`.
  - تنظیم‌ها (registry، گروه server.apps): `domains.route_bucket_domains` (پیش‌فرض روشن؛ خاموش ⇒ همه مسیرها برداشته و
    `off`)، `domains.bucket_domains_https` (پیش‌فرض روشن؛ برای مسیرهای تازه).
  - باکت‌های «سامانه» (بی‌فضا) دامنه باکت ندارند؛ مدیر برای آن‌ها دامنه سرویس S3 + virtual-host را به کار می‌برد. مدیر برای
    دامنه یک فضا از «دیدن به‌جای» با نوشتن استفاده می‌کند.
  - API مدیر (زیر `/domains`، چون نحوه مسیردهی سرور را نشان می‌دهد): `GET /domains/bucket-routes` (`domains:read`) →
    `{items:[{host, bucket, verified, workspace_id, workspace_slug, route:{state, mode, error_code, upstream_code,
    redeploy_required, suggested_action, instructions, https, conflict, updated_at}}], enabled, mode, effective_mode}`؛
    `POST /domains/bucket-routes/{host}/retry` (`domains:write`) → همان آیتم؛ `POST /domains/bucket-routes/reconcile`
    (`domains:write`) → `{added, removed, items, …}`.
- سهمیه حجم npm/PyPI **پیش از ذخیره** سنجیده می‌شود (§0.3)؛ علاوه بر آن، فضایی که به سقف رسیده انتشارش بسته می‌شود تا
  نسخه حذف شود. scope npm اگر پیش‌تر بسته عمومی کش‌شده داشته باشد → 409 `scope_unavailable`.
- رد ثبت‌نام حساب در انتظار را حذف می‌کند؛ پذیرفتن آن را فعال و فضای شخصی (با `plan_id` اختیاری) می‌سازد.

### 0.2 پنل

پیاده‌سازی پنل (`apps/admin-ui`) بر پایه §0.1؛ هر جا با متن اولیه فرق دارد این‌جا آمده است.

**ساختار و مسیرها**
- بخش «فضای من» = مسیرهای `#/my/home|domains|files|packages|team|keys|activity` (`nav.ts MY_TABS`، کد در `src/my/`). منوی
  کناری در این بخش فقط زبانه‌های همان فضا را نشان می‌دهد (بر اساس `limits.features`) و انتخابگر فضا (شخصی/تیمی + «ساخت
  فضای تیمی» اگر `teams`) بالای منو است؛ روی گوشی/تبلت بالای صفحه و در برگه «بیشتر».
- کلید «مدیریت سرور / فضای من» در سربرگ (≥lg دکمه دوتایی، md آیکون، گوشی در منوی کاربر) فقط وقتی دیده می‌شود که کاربر مدیر
  است و `GET /my/me` جواب 200 بدهد (یعنی `tenancy.enabled`).
- حساب «فقط فضای من» = نقش `customer` یا نداشتن هیچ مجوز غیر `my.*`: هر مسیر دیگر به `#/my/home` می‌رود؛ زنگ اعلان، خلاصه
  خانه مدیریت، حالت ساده/پیشرفته، «همه تنظیمات» و «درباره» برایش نیست. نام نقش `customer` در پنل «کاربر» است.
- نقش `admin` فضا در متن‌ها «گرداننده» نامیده شده تا با «مدیر» سامانه قاطی نشود.
- فضای جاری در `localStorage` (`mrk-workspace:<userId>`) می‌ماند؛ `api.ts setMyScope/scopeHeaders` هدر `X-Workspace` (و در
  «دیدن به‌جای» `X-View-As`) را فقط روی `/api/v1/my/*` می‌فرستد؛ `X-View-As` روی `DELETE /admin/view-as` هم می‌رود.
- دعوت‌نامه: اگر `POST …/members {user}` با ایمیل → 404 `user_not_found`، پنل `POST …/invites {email, role}` می‌زند و لینک
  یک‌باره `#/my/team?accept=<token>` را نشان می‌دهد؛ باز کردن آن پس از ورود `POST /my/invites/accept` را صدا می‌زند.

**استفاده دوباره از اجزای موجود**
- DNS: `dns.ts`/`dnsFinal.ts` پایه API را از `dnsBase()` می‌خوانند و `<DnsApiScope base="/api/v1/my/dns">` (dnsUi.tsx) آن را
  برای «فضای من» عوض می‌کند. `RecordDialog` (DnsNames.tsx، حالا export با پراپ `types` = `dns_record_types`)،
  `TemplateChooser` و `ApplyTemplateDialog` همان‌اند. `fetchTemplates` حالا `default_id` را هم می‌فهمد. چون
  `/my/dns/templates` رکوردهای قالب و پیش‌نمایش ندارد، خلاصه «این رکوردها ساخته می‌شود» وقتی خالی است پنهان است.
- امضای امنیتی در «فضای من» کارت ساده خودش را دارد (`GET/PUT …/{z}/dnssec {enabled}` + نمایش DS برای ثبت‌کننده)، چون
  `ZoneSigningTab` مدیریت از `PATCH` زون و تعویض کلید استفاده می‌کند که در `/my` نیست.
- فایل‌ها: `S3FileManager` پراپ‌های `base`، `canShare`، `hideNoAccess`، `onChanged` گرفت؛ زیر `/my` دانلود با `fetch` + blob
  انجام می‌شود (لینک ساده هدر فضا را نمی‌فرستد). نمایش یک‌باره کلید S3 همان `KeySecretDialog` است.

**نقش‌ها و کلیدها**
- نقش‌های قابل دادن: owner همه؛ admin فقط member/viewer؛ admin روی owner و admin دیگر کاری نمی‌تواند (منو پنهان)؛ ردیف خود
  شخص «ترک این فضا» دارد.
- کلید برنامه: viewer هم می‌تواند کلید فقط‌خواندنی بسازد؛ scopeهای نوشتن برای viewer نشان داده نمی‌شوند؛ تیک «نوشتن» خواندن را
  هم می‌زند. انقضا: ۳۰/۹۰/۳۶۵ روز یا بی‌پایان → `expires_in_seconds`.
- بسته‌ها: کلید انتشار با نام خودکار `<ecosystem>-<YYYY-MM-DD>`؛ دستور pip با `username` پاسخ (پیش‌فرض `__token__`)؛
  نشانی آپلود twine = `index_url` بدون `+simple/`؛ فایل آماده `setup.npmrc|pypirc` اگر بیاید یک‌باره نشان داده می‌شود.

**خطاها** (`copy/errors.ts` + `copy/mySpace.ts planErrorSentence`)
- `quota_exceeded {quota, limit, used}` در همه پنل (نه فقط «فضای من») جمله «سقف «…» پر شده (x از y)» می‌سازد؛
  `feature_disabled {feature}` نام امکان را می‌گوید؛ `engine_error` با پیام `QuotaExceeded` = «حجم فایل‌ها پر شده».
- کدهای تازه کاتالوگ: `workspace_suspended`, `zone_unavailable`, `zone_not_verified`, `verification_failed`, `plan_in_use`,
  `plan_builtin`, `plan_default`, `plan_not_found`, `workspace_not_found`, `personal_workspace`, `permission_escalation`,
  `last_owner`, `already_member`, `user_not_found`, `tenancy_disabled`, `view_as_read_only`, `view_as_expired`,
  `dns_record_type_not_allowed`, `admin_area_local_only`, `signup_pending` و با دامنه `my:` (`forbidden`, `not_found`,
  `permission_escalation`).

**مدیریت (کاربران و دسترسی)**
- زبانه‌های تازه: «فضاهای کاری»، «بسته‌ها»، «ثبت‌نام‌های در انتظار»، «تنظیمات فضای من» (`tenancy:admin`؛ کد
  `src/tenancy/`). تنظیمات از `GET/PUT /admin/tenancy/settings` (نه registry). خاموش کردن اثبات دامنه تأیید می‌خواهد.
- استثنای یک فضا فقط عدد است (چون در PATCH مقدار `null` یعنی حذف استثنا)؛ «بی‌سقف» برای یک فضا = بسته بی‌سقف. استثنای
  خاموش‌شده با `null` فرستاده می‌شود؛ بسته فقط اگر عوض شده باشد فرستاده می‌شود.
- بسته `builtin` دکمه حذف ندارد. «دیدن به‌جای» از منوی هر فضا (تیک «اجازه تغییر» فقط با `tenancy:impersonate_write`)،
  با نوار هشدار ثابت بالای همه صفحه‌ها، پایان خودکار سر وقت و `DELETE /admin/view-as` هنگام پایان.
- انتقال مالکیت منابع فعلاً از پنجره جزئیات هر فضا (فهرست `resources`) است، نه از صفحه هر منبع در DNS/فضای فایل مدیریت.
- ثبت‌نام با تأیید (202 بدون جلسه): App.tsx آن را `signup_pending` برمی‌گرداند و فرم ثبت‌نام همان جمله را نشان می‌دهد
  («ثبت‌نام شما رسید و منتظر تأیید…»)؛ صفحه ورود/ثبت‌نام (Login/AuthShell/Setup) تغییر نکرد.
- مجوزهای `tenancy:admin` و `tenancy:impersonate_write` به `copy/roles.ts` اضافه شدند (نام ساده برای ماتریس نقش‌ها).

**مسیر دامنه پوشه**
- «فضای من › فضای فایل»: زیر هر دامنه تأییدشده یک برچسب وضعیت مسیر + یک جمله ساده (`MY_FILES.route_*`/`routeHint_*`)؛ در
  `failed` دکمه «دوباره امتحان کن» (`POST …/route`). جزئیات فنی (روش، مراحل دستی) به کاربر فضا نشان داده نمی‌شود.
- صفحه فضای فایل مدیر (زبانه پوشه‌ها، `S3BucketRoutes.tsx`): کارت «دامنه پوشه‌های فضای من» فقط با `domains:read` و وقتی
  دست‌کم یک دامنه هست؛ هر ردیف: host، پوشه و فضا، روش، وضعیت، دلیل خطا، راهنمای Deploy برای `pending` و «مراحل دستی»
  (همان `ManualSteps` صفحه سرویس‌ها) برای `manual`؛ «دوباره امتحان کن» و «بررسی دوباره همه» با `domains:write`.

### 0.3 بستن سه کمبود ساخت اول (سهمیه پیش از انتشار، ثبت‌نام با دعوت، devpi واقعی)

**سهمیه حجم npm پیش از انتشار**
- افزونه Verdaccio `deploy/verdaccio/plugins/verdaccio-mrk-quota` (middleware، بدون وابستگی). Verdaccio آن را بعد از
  body-parser و پیش از مسیرهای publish اجرا می‌کند، پس هیچ فایلی پیش از بررسی نوشته نمی‌شود. Dockerfile و
  `install-native.sh` آن را در `/opt/verdaccio/plugins` می‌گذارند (`MRK_NPM_PLUGINS_DIR` برای جای دیگر).
- `tenancy.json` حالا برای هر scope فیلد `quota_bytes` (عدد یا `null` = بی‌سقف) دارد. افزونه آن را با هر تغییر فایل
  دوباره می‌خواند؛ پس عوض کردن بسته/استثنا بدون راه‌اندازی دوباره Verdaccio اثر می‌کند.
- قاعده: `PUT` زیر scope سقف‌دار که tarball دارد (`_attachments` با base64 رمزگشایی‌شده، یا طول بدنه خام) وقتی
  `حجم فعلی پوشه scope + حجم تازه + انتشارهای هم‌زمان در جریان > سقف` → **413** با
  `{error:"quota_exceeded: …", code:"quota_exceeded", limit, used, incoming}` (npm متن `error` را چاپ می‌کند).
  به‌روزرسانی بدون tarball (unpublish، deprecate، dist-tag) هرگز بسته نمی‌شود.
- شکست بسته: اگر scope سقف داشته باشد و افزونه در دیسک نباشد، `verdaccio_runtime` انتشار آن scope را می‌بندد.

**سهمیه حجم PyPI پیش از آپلود**
- devpi قلاب «پیش از آپلود» ندارد؛ `mrk_control_plane.devpi_quota` یک tween در ورودی Pyramid اضافه می‌کند. devpi با
  `mrk-devpi-server` (= devpi-server با همین افزونه که همیشه ثبت می‌شود، نه از entry point) اجرا می‌شود
  (`devpi-start.sh`)، پس افزونه نمی‌تواند جا بماند.
- محدودیت‌ها در `pypi/quotas.json` (`{indexes:{"<slug>/dev": bytes|null}}`، مسیر `MRK_PYPI_QUOTA_FILE` یا
  `$MRK_DATA_DIR/pypi/quotas.json`). کنترل‌پلین آن را پیش از ساختن index، با هر تغییر بسته/استثنا (`after_quota_change`)،
  با حذف فضا و هنگام شروع می‌نویسد.
- قاعده: POST به index سقف‌دار با اعتبارنامه وقتی `+files/<slug>/dev + Content-Length + آپلودهای در جریان > سقف` →
  **413** با reason `quota_exceeded: …` (twine همین را نشان می‌دهد) و بدنه `{type:"error", code:"quota_exceeded",
  message}`؛ پیش از خواندن بدنه. بدون `Content-Length` → 411. `push` بین indexها به index سقف‌دار پذیرفته نمی‌شود (حجمش
  از پیش معلوم نیست). درخواست بی‌اعتبارنامه به devpi می‌رسد تا خودش 401 بدهد (حجم مصرف به ناشناس گفته نمی‌شود).
  فایل خراب: آخرین نسخه سالم، وگرنه همه آپلودهای دارای اعتبارنامه رد (شکست بسته).

**ثبت‌نام با لینک دعوت**
- تنظیم تازه `tenancy.invite_signup`: `follow` (پیش‌فرض = همان `tenancy.signup`)، `off`، `approval`، `open`. در پنل
  «تنظیمات فضای من» و registry.
- `POST /api/v1/auth/workspace-invite {token}` (بی‌جلسه) → `{email, role, expires_at, workspace:{name, slug},
  account_exists, signup:"off"|"approval"|"open", password_policy}`؛ توکن نادرست/مصرف‌شده/منقضی → 404.
- `POST /api/v1/auth/workspace-invite/register {token, display_name, password, password_confirmation}`: ایمیل همیشه از
  دعوت است (شخص نمی‌تواند ایمیل دیگری بگذارد). پیش از ساختن حساب: حساب موجود → 409 `account_exists` (باید وارد شود و
  بپذیرد)، حالت `off` → 403 `invite_signup_off`، سقف اعضا → 409 `quota_exceeded`. سیاست رمز و محدودیت تکرار همان
  ثبت‌نام عادی است. حالت `open` → 201 `{user, csrf_token, workspace_id, role, invite_error}` با جلسه و فضای شخصی؛
  `approval` → 202 `{status:"pending_approval", workspace_id, role}`: حساب غیرفعال است ولی عضویت همان لحظه ثبت می‌شود؛
  رد ثبت‌نام عضویت‌ها را هم پاک می‌کند. اگر پذیرفتن دعوت پس از ساختن حساب شکست بخورد (مثلاً تیم هم‌زمان پر شد) حساب
  می‌ماند و `invite_error` کد خطا را دارد.
- پنل: `#/my/team?accept=<token>` برای کسی که وارد نشده صفحه «دعوت به …» (`src/my/JoinTeamPage.tsx`، با همان
  `AuthShell`) را نشان می‌دهد: فرم نام + رمز، یا «با این ایمیل حساب دارید؛ وارد شوید»، یا «ساختن حساب با دعوت این‌جا
  ممکن نیست». «ورود با حسابی که دارم» صفحه ورود عادی را با همان لینک باز می‌کند تا پس از ورود «فضای من» دعوت را بپذیرد.

**آزمون devpi واقعی**
- `tests/test_devpi_integration.py` اگر `devpi-server` نصب باشد آن را در پوشه موقت با `mrk_control_plane.devpi_quota`
  بالا می‌آورد و از راه API پنل: ساخت index و کلید انتشار، آپلود، رد کلید فضای دیگر و ناشناس، رد سقف پیش از ذخیره
  (حجم `+files` تغییر نمی‌کند)، آپلود کوچک پس از آن، حذف نسخه. بدون devpi با دلیل روشن skip می‌شود.
- `tests/test_npm_quota.py`: پیکربندی Verdaccio (افزونه + شکست بسته)، منطق افزونه با node، و اگر node_modules
  Verdaccio پیدا شود (`MRK_TEST_VERDACCIO_DIR` یا `deploy/verdaccio`) یک publish واقعی که بالای سقف رد می‌شود.

## 1. مفاهیم

- **فضای کاری (workspace):** `{id:"ws_<12hex>", slug, name, kind:"personal"|"team", plan_id, quota_overrides, status:
  "active"|"suspended", created_at}`. هر کاربر هنگام ساخت یک فضای `personal` می‌گیرد (slug از نام کاربری). فضای `team` را
  کاربری می‌سازد که بسته‌اش اجازه دهد (`features.teams`) یا مدیر.
- **عضویت:** `{workspace_id, user_id, role:"owner"|"admin"|"member"|"viewer"}`. owner همه‌کار؛ admin همه جز حذف فضا و تغییر
  owner؛ member منابع را می‌سازد/تغییر می‌دهد؛ viewer فقط می‌بیند. **هیچ‌کس نقشی بالاتر یا هم‌سطح خودش نمی‌دهد** (فقط owner
  می‌تواند owner دیگر بسازد). دعوت به فضا با ایمیل/نام کاربری کاربر موجود یا دعوت‌نامه.
- **کاربر فقط-فضا:** نقش داخلی تازه `customer` بدون هیچ مجوز مدیریتی. مدیر/owner سامانه هر دو بخش را دارند.
- **بسته (plan):** `{id, name_fa, name_en, description, default:bool, features:{dns, dns_dnssec, dns_templates, s3,
  s3_public_links, s3_bucket_domains, npm, pypi, teams, api_tokens}, quotas:{workspaces_team, members, dns_zones,
  dns_records_per_zone, dns_record_types:[…], s3_buckets, s3_bytes, s3_objects, s3_keys, s3_bucket_domains, npm_bytes,
  pypi_bytes, api_tokens}}`. مقدار `null` در سهمیه = بی‌سقف. بسته‌های آماده: «پایه»، «حرفه‌ای»، «بدون محدودیت». هر فضای
  کاری یک بسته + `quota_overrides`.
- **مالکیت:** جدول `resource_owners {kind, resource_id, workspace_id, created_by, created_at}` برای `dns_zone`, `s3_bucket`,
  `s3_identity`, `bucket_domain`, `npm_scope`, `pypi_index`, `api_token`. منابع قدیمی مالک ندارند = مال «سامانه» (فقط مدیر).
  مدیر می‌تواند مالکیت را منتقل کند (`POST /api/v1/admin/ownership/transfer`).

## 2. API مدیریت (مجوز تازه `tenancy:admin`، گروه people)

- `GET/POST/PUT/DELETE /api/v1/admin/plans` (حذف بسته در حال استفاده → `plan_in_use` 409).
- `GET /api/v1/admin/workspaces?query=&status=` → فهرست با مصرف؛ `GET /…/{id}` (اعضا، منابع، مصرف)؛ `PATCH /…/{id}
  {plan_id?, quota_overrides?, status?, name?}`؛ `DELETE /…/{id}?confirmation=<slug>` (حذف منابع یا انتقال به سامانه طبق
  `mode=delete|transfer`).
- `POST /api/v1/admin/ownership/transfer {kind, resource_id, workspace_id|null}`.
- `POST /api/v1/admin/workspaces/{id}/view-as` → توکن جلسه کوتاه (30 دقیقه) «دیدن به‌جای»، **فقط‌خواندنی**؛ نوشتن فقط با
  `write:true` و مجوز `tenancy:impersonate_write`. همه درخواست‌های این جلسه در audit با `on_behalf_of`.
- تنظیمات (registry، runtime): `tenancy.enabled` (پیش‌فرض false تا مدیر روشن کند)، `tenancy.signup` = `off|approval|open`
  (پیش‌فرض off؛ ثبت‌نام عمومی فعلی به این نگاشت می‌شود)، `tenancy.default_plan_id`، `tenancy.verify_domains` (پیش‌فرض true)،
  `tenancy.admin_area_local_only` (پیش‌فرض false).
- ثبت‌نام‌های در انتظار: `GET /api/v1/admin/signups`، `POST /…/{id}/approve|reject`.

## 3. API فضای من (`/api/v1/my/...`)

قواعد مشترک (یک لایه سرویس `tenancy.py`):
- فضای جاری از هدر `X-Workspace: ws_…` یا مسیر؛ عضویت و نقش بررسی می‌شود؛ شناسه منبع **فقط** از مسیر، و مالکیتش در همان
  تراکنش بررسی می‌شود؛ منبع مال دیگری → **404** (نه 403، تا وجودش لو نرود).
- هر نوشتن: بررسی `features` و `quotas` بسته (خطای `quota_exceeded` 409 با `{quota, limit, used}`، `feature_disabled` 403).
- فضای suspended → فقط خواندن (`workspace_suspended` 423).
- audit با `workspace_id`؛ `GET /api/v1/my/activity` تاریخچه منابع فضا.

مسیرها:
- `GET /my/me` → `{user, workspaces:[{id, slug, name, kind, role, plan:{…}, usage:{…}, limits:{…}}], current}`.
- `POST /my/workspaces {name}` (team)، `PATCH /my/workspaces/{id}`، `DELETE` (owner، با تأیید slug)، اعضا:
  `GET/POST/PATCH/DELETE /my/workspaces/{id}/members`، دعوت‌ها.
- **DNS:** `GET/POST /my/dns/zones` (ساخت: نام + قالب + متغیرها؛ اگر `verify_domains` روشن است زون در حالت
  `pending_verification` ساخته می‌شود و فقط پس از اثبات فعال/پاسخ‌دهنده)، `GET /my/dns/zones/{z}/verification` →
  `{methods:[{kind:"txt", name:"_devassist-verify.<z>", value:"devassist-verify=<token>"}, {kind:"ns", targets:[…]}],
  verified}`، `POST …/verify`، رکوردها CRUD، اعمال قالب، امضای DNSSEC (اگر `dns_dnssec`)، `DELETE` زون. بررسی تداخل: زونی که
  زیر/بالای زون فضای دیگر یا نام‌های خود DevAssist است → `zone_unavailable` 409. انواع رکورد طبق `dns_record_types`.
  تنظیمات سراسری موتور (forwarder، فیلترینگ، …) در «فضای من» نیست.
- **فضای فایل:** باکت‌ها CRUD (نام سراسری یکتا؛ پیشنهاد پیشوند slug)، فایل‌ها (فهرست/آپلود/دانلود/حذف/پوشه، لینک موقت امضاشده)،
  کلیدها (identity + access key) با **سیاستی که DevAssist می‌سازد** از قالب‌های `read_only|read_write|admin` محدود به باکت‌های
  همان فضا (JSON سیاست از کاربر پذیرفته نمی‌شود)، دامنه باکت (با اثبات مالکیت همان سازوکار DNS یا زون‌های خود فضا)، لینک عمومی
  (اگر `s3_public_links`). سهمیه حجم/تعداد فایل در **موتور S3 هنگام نوشتن** اعمال می‌شود (`QuotaExceeded`).
- **بسته‌ها:** هر فضا یک scope npm (`@<slug>`) و یک index devpi (`<slug>/dev` با پایه mirror) اگر `npm`/`pypi` در بسته باشد؛
  توکن انتشار محدود به همان scope/index؛ فهرست بسته‌ها و نسخه‌ها؛ حذف نسخه. سهمیه حجم.
- **کلیدهای API من:** `GET/POST/DELETE /my/tokens {name, scopes:[…], workspace_id, expires_at?, ip_allow?}`؛ scopes زیرمجموعه
  نقش سازنده در همان فضا (`my.dns:read|write`, `my.s3:read|write`, `my.packages:read|write`)؛ هرگز مجوز مدیریتی.

## 4. پنل

- **تعویض بخش:** در سربرگ، کلید «مدیریت سرور / فضای من» برای مدیرها؛ کاربر `customer` فقط «فضای من» دارد (منو، مسیرهای
  `#/my/...`، خانه). انتخابگر فضای کاری (شخصی/تیم‌ها).
- **فضای من:** خانه (مصرف از بسته با نوارها و هشدار نزدیک سقف)، دامنه‌ها (افزودن با قالب، کارت اثبات مالکیت با گام‌های ساده و
  دکمه «بررسی کن»، رکوردها، امضا)، فضای فایل (باکت‌ها، مرورگر فایل با کشیدن‌ورها کردن، کلیدها با نمایش یک‌باره، دامنه باکت)،
  بسته‌ها (دستور آماده `npm config`/`pip` با توکن)، اعضای تیم، کلیدهای API، تاریخچه. ساده و فارسی؛ بدون اصطلاح مدیریتی.
- **مدیریت سرور › کاربران و دسترسی:** بسته‌ها، فضاهای کاری (مصرف، تغییر بسته/استثنا، تعلیق، حذف/انتقال)، ثبت‌نام‌های در
  انتظار، «دیدن به‌جای» با نوار هشدار ثابت در بالای صفحه، انتقال مالکیت منابع از صفحه هر منبع.
- همه متن‌ها در کاتالوگ، `check:copy` سبز، ریسپانسیو.

## 5. امنیت و پذیرش

- تست ایزوله‌سازی خودکار: برای **هر** مسیر `/my`، کاربر A با شناسه منابع کاربر B → 404؛ viewer → نوشتن 403؛ توکن با scope
  ناکافی → 403؛ عبور از سهمیه → 409؛ فضای suspended → 423.
- تست ارتقای نقش: دعوت/تغییر نقش بالاتر از خود → 403. تست «دیدن به‌جای» فقط‌خواندنی و audit.
- تست S3: کلید ساخته‌شده فقط به باکت‌های همان فضا دسترسی دارد (درخواست واقعی به موتور S3 در تست).
- اعتبارسنجی سخت نوع/مقدار رکورد پیش از موتور؛ escape داده کاربر (React پیش‌فرض؛ هیچ dangerouslySetInnerHTML).
- `tenancy.enabled=false` → هیچ تغییری در رفتار فعلی (همه تست‌های قبلی سبز).
- pytest کامل، ruff، validate_release؛ پنل build و check:copy.
