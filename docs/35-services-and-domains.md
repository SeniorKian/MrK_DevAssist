# 35 — «سرویس‌های من» و مدیریت دامنه هماهنگ با Dokploy

وضعیت: **پیاده‌سازی‌شده (بک‌اند) — 2026-11-08**. درخواست مالک: یک صفحه اول که همه سرویس‌ها را جدا نشان دهد
(وضعیت، روشن/خاموش، مصرف، دامنه‌های متصل)، و افزودن دامنه بدون تداخل با ترافیک Dokploy؛ چند دامنه برای یک سرویس.

کد: `modules/services.py` (API)، `services_catalog.py` (فهرست سرویس‌ها، وضعیت، مصرف)، `domains_hosts.py` (قواعد نام)،
`domains_routing.py` (تشخیص و سه روش)، `domains_verify.py` (بررسی‌ها)، `domains_settings.py` (تنظیمات)،
`agent/traefik.py` (فایل Traefik در Agent)، `process_control.py` (supervisorctl با فهرست مجاز)،
`middleware.py` (TrustedHost پویا)، جدول `service_domains` (migration `20261108_0012`).

## 0. تغییرات نسبت به قرارداد اولیه

- `state` یک مقدار بیشتر دارد: `unknown` (supervisor در دسترس نیست — مثلاً محیط توسعه — یا Agent/فایروال هنوز بررسی نشده).
- `available_modes` در `GET /domains/routing` **آرایه** نام روش‌های قابل استفاده است (مثلاً `["dokploy_api","manual"]`)، نه شیء.
- راهنما در `GET /domains/routing` به‌جای `guide` با نام **`guidance`** و به‌شکل آرایه کارت است (بخش 3.4).
- stop **و restart** هر دو `confirmation` = شناسه سرویس (`"npm"`, `"pypi"`, `"s3"`) می‌خواهند؛ start نه.
- پنل هیچ action ندارد (`actions: []`)؛ پایگاه‌داده در فهرست سرویس‌ها نیست و از پنل کنترل نمی‌شود.
- دامنه تکراری داخل MRK کد **`domain_exists`** دارد؛ `domain_in_use` فقط برای تداخل با Dokploy است. هر دو `error.owner` دارند.
- `POST /domains/{id}/verify` مجوز `domains:write` می‌خواهد (اتصال بیرونی می‌سازد).
- `virtual_host_suffix` در تنظیمات S3 فقط دامنه **اصلی** است؛ همه دامنه‌های S3 در `virtual_host_suffixes` (snapshot موتور) می‌روند و موتور همه را می‌پذیرد.
- `health` دامنه‌ای که هنوز بررسی نشده: `{dns:null, tls:null, reach:null, checked_at:null, problem_code:null, problems:[]}`.
- نام‌های audit: `services.action` (object_id = `<service>:<action>`)، `domain.create`، `domain.update`، `domain.delete`، `domain.verify`، `domains.routing.update`.

## 1. اصول

- MRK هرگز پورت 80/443 را نمی‌گیرد؛ ورودی سرور مال Traefik خود Dokploy است. MRK فقط به Dokploy/Traefik می‌گوید
  «این دامنه را به سرویس X روی پورت Y بفرست».
- پورت داخلی ثابت: پنل `8080`، npm `4873`، PyPI `3141`، S3 `9000`.
- چند دامنه برای هر سرویس، بدون محدودیت؛ دقیقاً یکی «اصلی» (اولین دامنه خودکار اصلی می‌شود؛ با حذف اصلی، قدیمی‌ترینِ بعدی اصلی می‌شود).
- نام دامنه canonical ذخیره می‌شود: IDNA/punycode، حروف کوچک، بدون نقطه انتها؛ پورت، wildcard، IP، scheme و مسیر رد می‌شوند.
  یکتا در کل MRK. `display_host` شکل یونیکد برای نمایش است.
- قبل از افزودن: بررسی تداخل با دامنه‌های MRK و Dokploy. اگر Dokploy در دسترس نباشد هشدار (`conflict_check:"skipped"`)، نه مسدود.
- MRK هیچ‌وقت خودش redeploy نمی‌کند؛ فقط `suggested_action` برمی‌گرداند.

## 2. سه روش مسیریابی (تشخیص خودکار، قابل تغییر)

| روش | شرط «در دسترس» | رفتار |
|---|---|---|
| `dokploy_api` | کانتینر خود MRK از طریق Host Agent پیدا شود (hostname = شناسه کانتینر، یا تنظیم `domains.self_container`)، label `com.docker.compose.project` (یا `com.docker.swarm.service.name`) با `appName` یک سرویس Compose/Application در Dokploy جور شود و اتصال Dokploy (کلید API) برقرار باشد | `domain.create` روی همان سرویس با پورت داخلی؛ `domain.update` برای تغییر https؛ `domain.delete` برای حذف. |
| `traefik_file` | تنظیم `domains.traefik_file_enabled = true` **و** Agent گزارش دهد پوشه `MRK_AGENT_TRAEFIK_DYNAMIC_DIR` قابل نوشتن است | Agent فقط `mrk-domains.yml` را در آن پوشه می‌نویسد/حذف می‌کند (بخش 2.2). |
| `manual` | همیشه | `instructions` گام‌به‌گام fa/en + `dokploy:{project, service, service_name, port, host, https, certificate_type}`. |

`auto` (پیش‌فرض) به ترتیب `dokploy_api` → `traefik_file` → `manual` را انتخاب می‌کند. اگر روش مشخص‌شده (در درخواست یا
`PUT routing`) در دسترس نباشد: 409 `routing_unavailable` (برای traefik_file: `traefik_dir_unavailable`) با `error.available_modes`.
هر دامنه `mode` خودش را نگه می‌دارد (تغییر روش، دامنه‌های قبلی را جابه‌جا نمی‌کند).

### 2.1 Dokploy v0.31.0 — فیلدهای تأییدشده از سورس

منابع: [`packages/server/src/db/schema/domain.ts`](https://github.com/Dokploy/dokploy/blob/v0.31.0/packages/server/src/db/schema/domain.ts)،
[`packages/server/src/db/validations/domain.ts`](https://github.com/Dokploy/dokploy/blob/v0.31.0/packages/server/src/db/validations/domain.ts)،
[`apps/dokploy/server/api/routers/domain.ts`](https://github.com/Dokploy/dokploy/blob/v0.31.0/apps/dokploy/server/api/routers/domain.ts)،
[`packages/server/src/services/domain.ts`](https://github.com/Dokploy/dokploy/blob/v0.31.0/packages/server/src/services/domain.ts)،
[`packages/server/src/utils/traefik/domain.ts`](https://github.com/Dokploy/dokploy/blob/v0.31.0/packages/server/src/utils/traefik/domain.ts)،
[`packages/server/src/setup/traefik-setup.ts`](https://github.com/Dokploy/dokploy/blob/v0.31.0/packages/server/src/setup/traefik-setup.ts)،
[`packages/server/src/constants/index.ts`](https://github.com/Dokploy/dokploy/blob/v0.31.0/packages/server/src/constants/index.ts).

- `apiCreateDomain` (mutation `POST /api/domain.create`): `host, path, port, customEntrypoint, https, applicationId,
  certificateType ("letsencrypt"|"none"|"custom"), customCertResolver, composeId, serviceName, domainType
  ("compose"|"application"|"preview"), previewDeploymentId, internalPath, stripPath, middlewares, forwardAuthEnabled`.
  قواعد: `https=true` بدون `certificateType` رد می‌شود؛ `custom` بدون `customCertResolver` رد می‌شود؛ برای compose
  `serviceName` لازم است؛ پورت 1..65535.
- `apiUpdateDomain` (`POST /api/domain.update`): همان فیلدها بدون شناسه سرویس + `domainId` (لازم) و `enabled`.
- `apiFindDomain` (`POST /api/domain.delete`، `GET domain.one`): `{domainId}`. `GET domain.byComposeId {composeId}`، `GET domain.byApplicationId {applicationId}`.
- بدنه‌ای که MRK می‌فرستد: `{host, path:"/", port:<8080|4873|3141|9000>, https, certificateType: https ? ("letsencrypt" | "custom"+customCertResolver) : "none", domainType:"compose", composeId, serviceName:<com.docker.compose.service, پیش‌فرض mrk-mirror>}`
  یا برای Application: `{…, domainType:"application", applicationId}`. شناسه از پاسخ `domainId`؛ اگر نبود با `domain.byComposeId` پیدا می‌شود.
- **redeploy:** برای Application، Dokploy در `createDomain` بلافاصله `manageDomain` را صدا می‌زند (فایل Traefik). برای Compose
  هیچ کار runtime انجام نمی‌شود («Compose domains are docker labels and only change on the next deployment»)؛ پس بعد از
  create/update/delete روی Compose: `applied.redeploy_required = true` و
  `applied.suggested_action = {kind:"dokploy_redeploy", service_type:"compose", service_id, method:"POST", endpoint:"/api/v1/dokploy/services/compose/<id>/redeploy"}`
  (همان endpoint موجود با مجوز `dokploy:deploy`؛ MRK خودش صدا نمی‌زند).
- Traefik دکپلوی: پوشه file provider `/etc/dokploy/traefik/dynamic` (watch)، entryPointها `web` (:80) و `websecure` (:443)،
  certResolver `letsencrypt` (فایل `acme.json` هم در همان پوشه است)، middleware `redirect-to-https` در `middlewares.yml`
  (ارجاع: `redirect-to-https@file`)، شبکه Docker `dokploy-network`.

### 2.2 فایل Traefik (Agent)

- Agent فقط وقتی `MRK_AGENT_TRAEFIK_DYNAMIC_DIR` (مسیر مطلق) تنظیم و mount جدای rw داده شده باشد فعال است؛ mountهای دیگر Agent read-only می‌مانند.
  snippet در `compose.yaml` و `deploy/appliance/compose.production.yaml` (کامنت‌شده) و در `guidance`.
- endpointهای امضاشده Agent: `GET /v1/traefik/status` → `{configured, writable, file_present}`؛
  `POST /v1/traefik/domains` بدنه ساخت‌یافته (هرگز YAML خام):
  `{target_host, entrypoints:{web, websecure}, cert_resolver, redirect_middleware|null, services:[{service: panel|npm|pypi|s3, hosts:[…], https}]}`
  → `{ok, file:"mrk-domains.yml", bytes}`؛ `POST /v1/traefik/domains/delete` → `{ok, removed}`. غیرفعال: 404 `traefik_disabled`؛
  بدنه نامعتبر: 422 `invalid_payload`؛ نوشتن ناموفق: 403 `traefik_dir_unwritable`. symlink رد می‌شود؛ نوشتن atomic (temp + rename).
- Agent خودش اعتبارسنجی و فایل را تولید می‌کند (JSON که YAML معتبر است): router `mrk-<service>-websecure` با
  ``Host(`a`) || Host(`b`)``، `entryPoints:[websecure]`، `tls.certResolver`؛ router `mrk-<service>-web` روی `web` با redirect؛
  سرویس `mrk-<service>` → `http://<target_host>:<port>` (`passHostHeader`). PyPI: یک router برای هر host با middleware
  `X-Outside-Url: https://<host>` تا devpi لینک همان دامنه را بسازد. پورت‌ها و نام سرویس‌ها ثابت‌اند.
- `target_host` = تنظیم `domains.target_host`، وگرنه نام کانتینر تشخیص‌داده‌شده، وگرنه `mrk-mirror`. کانتینر MRK باید عضو `dokploy-network` باشد.

## 3. API

مجوزها (گروه `server`): `services:read` (همه نقش‌ها)، `services:operate` (owner/admin/operator)، `domains:read` (همه نقش‌ها)،
`domains:write` (owner/admin). همه تغییرها CSRF و audit دارند. خطاها در قالب `{error:{code, message, request_id, fields?, field?, reason?, …extra}}`؛
فیلدهای اضافه (مثل `owner`، `available_modes`، `expected_confirmation`، `upstream_code`) **مستقیم زیر `error`** هستند (`error.owner`).

### 3.1 سرویس‌ها

`GET /api/v1/services` (services:read) →
```
{items:[{id: "panel"|"npm"|"pypi"|"s3"|"agent"|"firewall", name_fa, name_en, description_fa, description_en,
  state: "running"|"stopped"|"starting"|"degraded"|"not_installed"|"disabled"|"unknown",
  reason_code: null|"supervisor_unavailable"|"stopped_by_user"|"program_failed"|"partially_running"|"disabled_in_settings"
               |"agent_not_configured"|"agent_unreachable"|"firewall_not_configured"|"firewall_unreachable"|"not_checked_yet"|"module_unavailable",
  controllable: bool, actions: ["start","stop","restart"] (خالی اگر controllable=false),
  internal_port: 8080|4873|3141|9000|null,
  usage:{disk_bytes|null, disk_partial: bool, items|null, items_kind: "packages"|"buckets"|"users"|null, last_activity_at|null, requests_24h: null},
  domains:[{id, host, display_host, primary, https, health}],   // health = همان شیء /domains
  domains_supported: bool, public_url: "https://<primary>"|null, manage_route}],
 routing:{mode, effective_mode, detected:{…بخش 3.4}},
 supervisor_available: bool}
```
- وضعیت npm/PyPI/S3 از supervisord (`verdaccio`، `devpi`+`pypi-router`، `s3-engine`). بدون socket supervisor: از health محلی
  (`running` با `reason_code:"supervisor_unavailable"` یا `unknown`) و `controllable:false`. npm/PyPI خاموش در تنظیمات
  (`MRK_NPM_ENABLED`/`MRK_PYPI_ENABLED`) یا S3 با `enabled:false` → `disabled`. Agent/فایروال فقط از وضعیت ماژول خودشان (بدون probe).
- مصرف: حجم پوشه‌های داده (`npm`، `pypi`، `modules/s3`، `control-plane`+`database` برای پنل) با بودجه زمانی 3s و حافظه 60s
  (`disk_partial:true` یعنی ناقص)، `last_activity_at` = تازه‌ترین فایل، `items` = تعداد بسته‌ها/سطل‌ها/کاربران. `requests_24h` فعلاً `null`.

`POST /api/v1/services/{id}/actions {action: "start"|"stop"|"restart", confirmation?}` (services:operate، CSRF) →
`{id, action, state, reason_code}`. stop/restart: `confirmation` = شناسه سرویس. فقط npm، PyPI، S3.
خطاها: 404 `service_not_found`، 422 `confirmation_mismatch` (`expected_confirmation`)، 422 `service_action_not_allowed`
(action ناشناخته) / 409 `service_action_not_allowed` (`reason:"service_disabled"`)، 409 `service_not_controllable`
(پنل/Agent/فایروال، یا `reason:"supervisor_unavailable"`)، 409 `service_busy`، 502 `service_action_failed` (`upstream_code`).
سرویس خاموش‌شده در `data/control-plane/stopped-services.json` ثبت می‌شود: بعد از restart کانتینر دوباره خاموش می‌ماند و
`/health/ready` آن را نادیده می‌گیرد (کانتینر unhealthy نمی‌شود). start/restart آن را پاک می‌کند. pglite و control-plane هرگز کنترل نمی‌شوند.

### 3.2 دامنه‌ها

شیء دامنه: `{id, service_id, host, display_host, primary, https, mode, dokploy_domain_id, created_at, updated_at, created_by,
health:{dns:{ok, addresses[], expected[]}|null, tls:{ok, expires_at, issuer, hostname_match, days_left, error}|null, reach:{ok, status_code, matched_service}|null, checked_at, problem_code, problems[]}}`.

- `GET /api/v1/domains` (domains:read) → `{items:[domain]}` (مرتب: سرویس، اصلی اول، host).
- `POST /api/v1/domains {service_id: panel|npm|pypi|s3, host, https=true, primary?, mode="auto"}` (domains:write) → 201
  `{domain, applied:{mode, ok, error_code, conflict_check: "ok"|"partial"|"skipped", redeploy_required, suggested_action}, instructions?, sync}`
  (`instructions` فقط برای manual: `{steps_fa[], steps_en[], dokploy:{project, service, service_name, port, host, https, certificate_type}}`).
  بعد از افزودن، بررسی در پس‌زمینه شروع می‌شود.
- `PATCH /api/v1/domains/{id} {primary?, https?}` → `{domain, health, applied, sync, instructions?}`. `primary:false` روی دامنه اصلی، دامنه دیگری را اصلی می‌کند (اگر باشد).
- `DELETE /api/v1/domains/{id} {confirmation: host}` → `{deleted, applied, sync}`.
- `POST /api/v1/domains/{id}/verify` (domains:write) → `{domain, health}`.

خطاها: 422 `invalid_host` (`fields:[{field:"host", reason_code: required|invalid_type|too_long|invalid_format|wildcard_not_allowed|ip_not_allowed|port_not_allowed|reserved_name}]`)،
422 `invalid_service`، 422 `invalid_routing_mode`، 409 `domain_exists` (`owner:{kind:"mrk", name, service_id, domain_id}`)،
409 `domain_in_use` (`owner:{kind:"dokploy", name, project, service, service_type, service_id}`, `conflict_check`)،
409 `routing_unavailable` / `traefik_dir_unavailable` (`mode`, `available_modes[]`)، 502 `dokploy_domain_failed` (`upstream_code`
مثل `dokploy_rejected`/`dokploy_unreachable`)، 502 `traefik_write_failed` (`upstream_code`)، 404 `domain_not_found`،
422 `confirmation_mismatch` (`expected_confirmation`)، 502 `verify_failed`. در PATCH/DELETE روش traefik_file اگر فایل نوشته
نشود، تغییر ذخیره می‌ماند و `applied.ok=false, error_code:"traefik_write_failed"`.

### 3.3 بررسی (DNS / TLS / رسیدن)

- DNS: A/AAAA با تنظیم DNS خود MRK (netresolve). `expected` = `domains.server_public_ips` (`MRK_SERVER_PUBLIC_IPS`)؛ اگر خالی
  باشد فقط وجود رکورد بررسی می‌شود. نشانی loopback/link-local/multicast هرگز تماس گرفته نمی‌شود (`dns_wrong_ip`).
- TLS: اتصال به 443 همان IP با SNI؛ اعتبار زنجیره و نام، انقضا، صادرکننده. HTTP: درخواست مستقیم (بدون پروکسی خروجی)
  به همان IP با Host واقعی: پنل `GET /health/live` (header `X-MRK-Service: panel` که روی همه پاسخ‌های پنل است)، npm `GET /-/ping`
  (`X-Powered-By: verdaccio/…`)، PyPI `GET /+api` (`"apiconfig"`)، S3 `GET /` (`Server: MRK` + `x-amz-request-id`).
- `problem_code` (اولی برنده): `dns_missing`، `dns_wrong_ip`، `unreachable`، `tls_missing`، `tls_invalid`، `wrong_service`، `tls_expiring`
  (کمتر از `domains.tls_expiry_warning_days`، پیش‌فرض 14 روز).
- دوره‌ای: هر `domains.verify_interval_seconds` (پیش‌فرض 21600، صفر = خاموش؛ حلقه هر 5 دقیقه دامنه‌های کهنه را بررسی می‌کند).
- رویدادها: `domain.unhealthy` (warning، وقتی مشکل تازه پیدا شود)، `domain.cert_expiring` (warning)، `domain.healthy` (info، بازگشت)؛
  `details:{domain_id, host, service_id, problem_code, problems, expires_at?}`.

### 3.4 مسیریابی

`GET /api/v1/domains/routing[?refresh=true]` (domains:read) →
```
{mode: "auto"|"dokploy_api"|"traefik_file"|"manual", effective_mode, available_modes: ["dokploy_api"?, "traefik_file"?, "manual"],
 detected:{inside_dokploy, dokploy_connected, dokploy_project, dokploy_service, dokploy_service_type: "compose"|"application"|null,
   dokploy_service_id, compose_service, container_name, agent_connected, traefik_dir_available, traefik_file_enabled,
   on_dokploy_network, server_ips[], errors[]},
 settings:{traefik_file_enabled, cert_resolver, entrypoint_web, entrypoint_websecure, redirect_middleware, target_host,
   dokploy_network, verify_interval_seconds, server_public_ips},
 target_host, guidance:[{id, title_fa, title_en, body_fa, body_en, code, done}], sync|null}
```
کارت‌های `guidance`: `dokploy_compose_install`، `join_dokploy_network`، `agent_traefik_mount`. تشخیص 60 ثانیه cache می‌شود.

`PUT /api/v1/domains/routing {mode, traefik_file_enabled?}` (domains:write) → همان شیء GET. خطا: 422 `invalid_routing_mode`.

## 4. هماهنگ‌سازی خودکار (بعد از هر create/update/delete/تغییر اصلی و در شروع)

خروجی در `sync` پاسخ‌ها: `{panel, pypi, s3, npm, at}`.
- **پنل:** میزبان‌های مجاز = `MRK_TRUSTED_HOSTS` ∪ دامنه‌های پنل، بدون restart (`DynamicTrustedHostMiddleware`، `*` و `*.x` مثل قبل).
  `panel:{status: applied|disabled|unavailable, hosts[]}`. CORS/کوکی وابسته به host نیستند (پنل same-origin است).
- **PyPI:** `https://<دامنه اصلی>` در `<data>/pypi/outside-url`؛ `devpi-start.sh` اول `MRK_PYPI_OUTSIDE_URL` و بعد این فایل را
  می‌خواند (فقط `http(s)://host[:port]`). اگر تغییر کرد و supervisor هست: restart کنترل‌شده devpi.
  `pypi:{status: applied|unchanged|disabled|env_override, outside_url, restarted, restart_required}`.
- **S3:** `public_endpoint = https://<اصلی>` و `virtual_host_suffix = <اصلی>`، همه دامنه‌های S3 در `virtual_host_suffixes`؛ snapshot
  نوشته و موتور reload می‌شود. مقدار دستیِ صفحه S3 حفظ می‌شود (MRK آخرین مقدار خودش را نگه می‌دارد = `managed_by:"domains"`).
  `s3:{status: applied|manual_override|disabled|unavailable, managed_by, public_endpoint, virtual_host_suffix, virtual_host_suffixes[], manual_keys[]}`.
- **npm:** نیاز به تغییر ندارد: Verdaccio 6 آدرس tarballها را از `Host` و `X-Forwarded-Proto` می‌سازد (Traefik هر دو را می‌فرستد).
- **دستورهای اتصال:** `public_url` هر سرویس در `GET /api/v1/services` (UI در صورت وجود از آن استفاده کند، وگرنه از `registryEndpoints()`).
- **خانه:** قانون `domain_problem` (warning، `params:{host, problem_code, service_id}`، مسیر `#/services?domain=<id>`، مجوز
  `domains:read`)؛ `s3_public_endpoint_missing` و گام `set_public_address` با داشتن دامنه S3 برطرف می‌شوند؛ quick actionها
  `my_services` (`#/services`، services:read) و `add_domain` (`#/services?add=panel`، domains:write).
- **بکاپ پنل:** جدول `service_domains` خودکار در بکاپ منطقی هست (همه جدول‌ها شمرده می‌شوند).

## 5. تنظیمات (مرکز تنظیمات، گروه `server.apps`، ماژول `services`، خواندن `domains:read`، نوشتن `domains:write`)

تقدم: مقدار پنل > متغیر محیطی > پیش‌فرض.

| کلید | پیش‌فرض | env |
|---|---|---|
| `domains.routing_mode` | `auto` | `MRK_DOMAINS_ROUTING_MODE` |
| `domains.traefik_file_enabled` | `false` | `MRK_DOMAINS_TRAEFIK_FILE_ENABLED` |
| `domains.cert_resolver` | `letsencrypt` | `MRK_DOMAINS_CERT_RESOLVER` |
| `domains.entrypoint_web` / `domains.entrypoint_websecure` | `web` / `websecure` | — |
| `domains.redirect_middleware` | `redirect-to-https@file` | — |
| `domains.target_host` | `""` (تشخیص) | `MRK_DOMAINS_TARGET_HOST` |
| `domains.self_container` | `""` (hostname) | — |
| `domains.dokploy_network` | `dokploy-network` | — |
| `domains.verify_interval_seconds` | `21600` | `MRK_DOMAINS_VERIFY_INTERVAL_SECONDS` |
| `domains.tls_expiry_warning_days` | `14` | — |
| `domains.server_public_ips` | `[]` | `MRK_SERVER_PUBLIC_IPS` |
| `domains.conflict_check_budget` | `20` | — |
| `domains.sync_panel_trusted_hosts` / `domains.sync_pypi_outside_url` / `domains.sync_pypi_restart` / `domains.sync_s3_endpoint` | `true` | — |
| `agent_helper.traefik_dynamic_dir` (startup، کانتینر Agent) | `""` | `MRK_AGENT_TRAEFIK_DYNAMIC_DIR` |

## 6. محدودیت‌ها

- `requests_24h` هنوز اندازه‌گیری نمی‌شود (`null`).
- IP عمومی سرور خودکار کشف نمی‌شود؛ بدون `MRK_SERVER_PUBLIC_IPS`، `dns_wrong_ip` فقط برای نشانی‌های غیرقابل‌تماس است.
- بررسی تداخل Dokploy با بودجه `conflict_check_budget` و cache پنج‌دقیقه‌ای دامنه‌ها انجام می‌شود؛ اگر کامل نشود `conflict_check:"partial"`.
- تشخیص `dokploy_api` به Host Agent جفت‌شده نیاز دارد (برای خواندن label کانتینر خود MRK).
- دامنه موجود در Dokploy روی سرویس خود MRK «پذیرفته» (adopt) نمی‌شود؛ `domain_in_use` می‌دهد.
