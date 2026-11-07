# 05 — API، مدل داده و امنیت

## 1. Boundary سرویس‌ها

### Control Plane API

مسئول کاربران، role، upstream policy، health history، task orchestration، catalog projection، audit و تنظیمات است. فایل artifact را مستقیماً serve نمی‌کند.

در Appliance، state آن در SQLite با WAL و busy timeout زیر `/data/control-plane` ذخیره می‌شود. Repository adapter باید امکان PostgreSQL خارجی در نسخه scale-out را بدون تغییر API حفظ کند.

### npm Adapter

config و state Verdaccio را از طریق interface کنترل‌شده مدیریت می‌کند. reload باید atomic باشد و config خام از UI دریافت نشود.

### PyPI Adapter

indexهای devpi، upstream router و cache operations را مدیریت می‌کند. password یا root credential هرگز به browser نمی‌رود.

### Gateway

TLS، routing، request ID، rate limit و header normalization را انجام می‌دهد. تصمیم business-level package routing در adapter/policy engine باقی می‌ماند.

## 2. REST API اولیه

Base path: `/api/v1`

### Authentication

- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`
- `POST /tokens`
- `DELETE /tokens/{id}`

### Users/Roles

- `GET|POST /users`
- `GET|PATCH /users/{id}`
- `POST /users/{id}/disable`
- `GET /roles`
- `PUT /users/{id}/roles`

### Upstreams

- `GET|POST /upstreams`
- `GET|PATCH|DELETE /upstreams/{id}`
- `POST /upstreams/{id}/probe`
- `POST /upstreams/{id}/block`
- `POST /upstreams/{id}/unblock`
- `PUT /upstreams/reorder`
- `GET /upstreams/{id}/history`

### Packages/Cache

- `GET /packages`
- `GET /packages/{ecosystem}/{name}`
- `GET /packages/{ecosystem}/{name}/versions/{version}`
- `POST /cache/prefetch`
- `POST /cache/revalidate`
- `POST /cache/purge/preview`
- `POST /cache/purge`
- `POST /cache/pin`
- `POST /cache/unpin`

### Operations

- `GET /system/status`
- `GET /system/storage`
- `POST /system/offline-mode`
- `POST /system/maintenance-mode`
- `GET /tasks`
- `GET /tasks/{id}`
- `POST /tasks/{id}/cancel`
- `GET /audit-events`
- `GET /metrics` برای شبکه مدیریتی

### Backup

- `GET|POST /backups`
- `POST /backups/{id}/validate`
- `POST /restores/preview`
- `POST /restores` با confirmation token کوتاه‌عمر

## 3. Error Envelope

```json
{
  "error": {
    "code": "UPSTREAM_CONNECT_TIMEOUT",
    "message": "Primary upstream did not respond in time.",
    "correlation_id": "...",
    "details": {}
  }
}
```

message برای کاربر امن است؛ stack trace فقط در log داخلی قرار می‌گیرد.

## 4. مدل داده اولیه

### User

- id، username، email اختیاری
- password_hash یا identity_provider
- status، last_login_at، mfa_state
- created_at، updated_at

### Role / Permission / UserRole

- roleهای built-in immutable name دارند.
- custom role در فاز بعد قابل افزودن است.

### ApiToken

- id، owner_id، prefix، hash، scopes
- expires_at، last_used_at، revoked_at
- مقدار کامل token ذخیره نمی‌شود.

### Upstream

- id، name، ecosystem، base_url
- priority، enabled، manual_blocked
- connect_timeout، read_timeout، max_retries
- circuit settings، TLS profile، credential_ref

### UpstreamHealthSample

- upstream_id، checked_at، state
- dns_ms، connect_ms، tls_ms، first_byte_ms
- status_code، error_code

### Package / PackageVersion / Artifact

- ecosystem، normalized_name، display_name
- version، metadata، source_upstream_id
- artifact path، size، sha256، cache_state
- first_seen_at، cached_at، last_accessed_at
- pinned، quarantined، quarantine_reason

### Task

- type، state، progress، actor_id
- idempotency_key، input_safe_summary
- started_at، finished_at، error_code

### AuditEvent

- actor_type/id، action، object_type/id
- before/after redacted JSON
- source_ip، user_agent، correlation_id
- occurred_at، result

### Policy

- type، scope، priority، enabled
- validated configuration JSON
- version و effective_at

## 5. Secret Handling

- DB فقط `credential_ref` نگه می‌دارد.
- نصب compact به‌صورت پیش‌فرض یک file key با mode مالک‌محور داخل `/data/control-plane` می‌سازد تا backup/restore مستقل بماند؛ این حالت در برابر سرقت کامل volume مرز امنیتی جدا ایجاد نمی‌کند.
- production می‌تواند `MRK_UPSTREAM_SECRET_KEY_FILE` را به یک Docker/K8s/Vault-mounted file فقط‌خواندنی با دقیقاً ۳۲ بایت تصادفی اشاره دهد؛ فایل مفقود یا نامعتبر fail-closed است و برنامه هرگز آن را تولید یا overwrite نمی‌کند.
- secret در environment dump، exception، support bundle یا audit before/after قرار نمی‌گیرد.
- rotate operation مقدار قبلی را نمایش نمی‌دهد.
- در حالت external-key، کلید با DB/data backup در یک محل نگه‌داری نمی‌شود و custody/restore آن جدا تمرین می‌شود.

## 6. Permission Matrix خلاصه

| عملیات | Owner | Admin | Operator | Developer | Viewer |
|---|---:|---:|---:|---:|---:|
| مشاهده dashboard | ✓ | ✓ | ✓ | محدود | ✓ |
| مدیریت upstream | ✓ | ✓ | محدود | — | — |
| block/offline | ✓ | ✓ | ✓ | — | — |
| purge cache | ✓ | ✓ | محدود | — | — |
| publish private | ✓ | ✓ | — | با scope | — |
| user/role management | ✓ | ✓ | — | — | — |
| backup | ✓ | ✓ | محدود | — | — |
| restore | ✓ | — | — | — | — |
| audit export | ✓ | ✓ | محدود | — | read-only |

## 7. Threat Model اولیه

### T-01 Dependency Confusion

کنترل: namespace policy، private precedence، warning و allowlist.

### T-02 Malicious Upstream/Artifact

کنترل: hash verification، quarantine، immutable cache record و optional scanner integration.

### T-03 SSRF از URL upstream

کنترل: scheme/domain allowlist، resolve-and-validate، redirect validation و block شبکه‌های حساس.

### T-04 Secret Leakage

کنترل: external secret provider، redaction tests، no-secret API و support bundle scan.

### T-05 Cache Poisoning

کنترل: atomic write، checksum، content-addressed identity و عدم publish فایل ناقص.

### T-06 Admin Account Takeover

کنترل: MFA، rate limit، session revoke، audit، least privilege و break-glass procedure.

### T-07 Destructive Operator Error

کنترل: preview، typed confirmation، job queue، backup gate و audit.

## 8. License و Attribution

- license هر dependency در `THIRD_PARTY_NOTICES` ثبت می‌شود.
- Verdaccio، React Admin و FastAPI مجوزهای permissive دارند؛ متن مجوزها حفظ می‌شود.
- devpi و pluginهایش جداگانه در زمان pin نهایی بررسی می‌شوند.
- کد GPL وارد component proprietary بدون بررسی حقوقی نمی‌شود.
- انتشار binary یا ارائه تجاری قبل از release نیازمند license audit نهایی است.

## 9. محدودیت دسترسی Appliance

- container به Docker socket متصل نمی‌شود.
- فقط `/data` writable است؛ source و frontend bundle immutable هستند.
- تمام processها با UID/GID قابل تنظیم و پیش‌فرض non-root اجرا می‌شوند.
- Control Plane فقط adapterهای localhost را صدا می‌زند؛ endpoint مدیریتی engineها مستقیماً public نمی‌شود.
- SQLite، token store و configهای حساس permission حداقل `0600/0700` دارند.

## 10. مدل‌های ماژولار جدید

### Module / ModuleCapability

- `id` ثابت، نوع، display name و engine version
- manifest/schema version و capabilityهای فعال
- desired/observed state، health، readiness و restart count
- data root reference و backup contributor version

### DomainRoute

- hostname canonical، route kind و module id
- target id اختیاری برای status page
- tls mode، enabled، created/updated actor
- unique constraint روی hostname و route kind

### ServiceOperation

- module id، action، reason و requested actor
- desired deadline، observed result و failure code
- restart count/window و crash-loop state

### Uptime Projection

- monitor/status-page identity mapping و engine reference
- heartbeat summary، uptime windows و last check؛ raw history در engine می‌ماند
- incident/maintenance public projection
- notification secret فقط `credential_ref`

### DnsChangeSet

- engine id، base revision، risk، state و safe diff
- validation result، approval، idempotency key و apply result
- rollback snapshot reference؛ zone secret یا key خام در JSON ذخیره نمی‌شود

### DnsProjection

- zone/record summary، engine revision و last synchronized time
- resolver/listener/capability summary
- query aggregate؛ raw client IP فقط در store با retention/permission محدود

## 11. API namespaceهای جدید

- `/api/v1/modules` برای catalog، health و lifecycle jobها
- `/api/v1/routes` برای hostname mapping و validation
- `/api/v1/uptime/*` برای monitor، notification، incident، maintenance و status page
- `/api/v1/dns/*` برای projection، change set، apply/verify و engine status
- `/public/status/*` فقط داده publish‌شده و بدون reuse کردن schema مدیریتی

هیچ generic engine proxy یا endpoint دلخواه در Control Plane وجود ندارد. تمام operationها DTO، permission، validation و audit مشخص دارند.

## 12. Permissionهای جدید

- `module:read`، `module:operate`، `route:read`، `route:write`
- `uptime:monitor:*`، `uptime:notification:*`، `uptime:incident:*`، `uptime:status-page:*`
- `dns:zone:*`، `dns:record:*`، `dns:resolver:*`، `dns:dnssec:*`، `dns:operate`
- actionهای Critical DNS علاوه بر scope به step-up authentication نیاز دارند.
- permission engine-native هرگز مستقیماً به browser داده نمی‌شود.

## 13. مهاجرت و retention

- migration هر module نام‌فضای مستقل و dependency صریح به core revision دارد.
- uninstall داده را حذف نمی‌کند؛ purge نیازمند job و typed confirmation جداست.
- heartbeat و query log retention مستقل از audit است.
- backup manifest نسخه engine، module schema و adapter contract را ثبت می‌کند.

