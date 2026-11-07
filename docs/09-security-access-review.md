# 09 — بازبینی امنیت و دسترسی

تاریخ بازبینی: 2026-11-07  
وضعیت: Baseline پیش از پیاده‌سازی

## خلاصه تصمیم

سطح حمله محصول از سه بخش تشکیل می‌شود: endpointهای عمومی package، پنل/API مدیریتی و ارتباط outbound با upstreamها. این سه بخش نباید trust boundary مشترک یا credential مشترک داشته باشند. Control Plane نباید برای مدیریت سرویس‌ها به Docker socket، SSH host یا filesystem ریشه سرور دسترسی مستقیم داشته باشد.

## Trust Boundaryها

### Public Package Plane

- npm و PyPI download endpointها می‌توانند طبق policy anonymous read باشند.
- publish، delete، tag و mutation همیشه احراز هویت می‌خواهند.
- این plane به session cookie پنل دسترسی ندارد.
- rate limit دانلود از API مدیریتی جداست.

### Management Plane

- فقط HTTPS و ترجیحاً شبکه مدیریتی/VPN یا IP allowlist.
- cookie با Secure، HttpOnly و SameSite؛ mutationهای cookie-based دارای CSRF protection.
- CORS به originهای صریح محدود و wildcard همراه credential ممنوع.
- CSP، frame-ancestors، nosniff، Referrer-Policy و HSTS در production.

### Outbound Plane

- فقط upstreamهای تأییدشده روی 443/80 طبق policy.
- private، loopback، link-local، metadata و reserved IPها پیش‌فرض مسدود.
- DNS قبل و بعد از redirect resolve و اعتبارسنجی می‌شود تا DNS rebinding کنترل شود.
- redirect count محدود و تغییر scheme/host دوباره بررسی می‌شود.

## Access Matrix سخت‌گیرانه

| قابلیت | Owner | Admin | Operator | Publisher | Viewer |
|---|---:|---:|---:|---:|---:|
| تغییر تنظیمات امنیتی | ✓ | — | — | — | — |
| مدیریت کاربران و role | ✓ | محدود | — | — | — |
| ساخت/ویرایش upstream | ✓ | ✓ | محدود | — | — |
| مشاهده secret | هیچ‌کس؛ فقط replace | هیچ‌کس | — | — | — |
| offline/maintenance | ✓ | ✓ | ✓ | — | — |
| purge cache | ✓ | ✓ | با policy | — | — |
| publish private | ✓ | ✓ | — | namespace | — |
| delete private package | ✓ | با policy | — | — | — |
| restore production | ✓ | — | — | — | — |
| audit export | ✓ | ✓ | read | — | read |

## Authentication و Session

- password با Argon2id و policy حداقل طول؛ complexity نمایشی جایگزین طول نمی‌شود.
- login و reset دارای rate limit و پاسخ غیرقابل enumeration.
- MFA برای Owner و Admin در production اجباری می‌شود.
- refresh token rotation و revoke روی disable/reset/role downgrade.
- API token فقط hash‌شده، scopeدار، expiryدار و یک‌بار نمایش داده می‌شود.
- service account login تعاملی ندارد.
- break-glass account آفلاین، محدود و دوره‌ای آزمایش می‌شود.

## Authorization

- deny-by-default.
- check مجوز در backend؛ مخفی کردن button در UI کنترل امنیتی نیست.
- object-level permission برای namespace، upstream و عملیات cache.
- تغییر role و permission audit و sessionهای قدیمی revoke می‌شود.
- endpoint داخلی بدون auth فقط liveness است و اطلاعات نسخه/dependency افشا نمی‌کند.

## Secret Management

- secret در Git، Compose committed، frontend bundle، log، metric و audit ممنوع.
- محیط توسعه از `.env` محلی ignored استفاده می‌کند؛ `.env.example` فقط placeholder دارد.
- production برای credentialهای upstream از `MRK_UPSTREAM_SECRET_KEY_FILE` و فایل secret فقط‌خواندنی ۳۲‌بایتی Docker/Kubernetes/Vault استفاده می‌کند؛ نبود یا طول نادرست کلید fail-closed است.
- secret reference در DB ذخیره می‌شود، نه مقدار خام.
- در profile سخت‌گیرانه، encryption key از backup داده جدا نگه‌داری و همراه هر restore drill جداگانه بازیابی می‌شود؛ profile compact به‌صورت شفاف کلید محلی را داخل volume نگه می‌دارد و در برابر compromise کامل volume محافظت مستقل ندارد.
- rotate دو مرحله‌ای برای credential upstream و signing key.

## SSRF و Upstream Safety

- URL فقط `https` و در development با استثنای صریح `http`.
- userinfo در URL ممنوع؛ credential جدا ذخیره می‌شود.
- hostname normalization، IDNA validation و port allowlist.
- تمام IPهای A/AAAA بررسی می‌شوند، نه فقط اولین نتیجه.
- اتصال باید به IP اعتبارسنجی‌شده bind شود یا پس از resolve مجدد کنترل شود.
- redirect به IP/host ممنوع دوباره رد می‌شود.
- response size برای probe محدود است.
- probe و download timeout و max body دارند.

## Artifact Integrity و Cache Poisoning

- artifact ابتدا در temporary path و با محدودیت اندازه دریافت می‌شود.
- hash advertised در صورت وجود verify می‌شود؛ SHA-256 داخلی همیشه محاسبه می‌شود.
- metadata و binary به‌صورت atomic commit می‌شوند.
- فایل ناقص یا hash mismatch هرگز success یا cache-hit نمی‌شود.
- mismatch باعث quarantine، circuit signal و security event می‌شود.
- tar/zip در مسیر cache استخراج نمی‌شود؛ در صورت نیاز analysis در sandbox جداست.
- path traversal و symlink روی upload validation می‌شود.

## Web Security

- CSRF برای session mutation.
- CORS allowlist و preflight تست‌شده.
- output encoding و CSP؛ metadata پکیج untrusted تلقی می‌شود.
- filename و description قبل از render sanitize می‌شوند.
- file download با content-type و content-disposition امن.
- open redirect و javascript URL در فیلدهای قابل کلیک ممنوع.

## Container و Host Security

- non-root، `no-new-privileges` و capability drop تا حد ممکن.
- Docker socket، SSH key host و `/` هرگز mount نمی‌شوند.
- volume هر engine جدا و حداقل‌دسترسی است.
- root filesystem read-only برای Control Plane/UI و سرویس‌های سازگار.
- tmpfs محدود برای `/tmp`.
- egress network policy در production.
- resource limit، pids limit و log rotation.
- image با version و digest pin؛ SBOM و scan پیش از release.

## Database و Data Protection

- PostgreSQL accountهای migration و runtime جدا در production.
- runtime schema owner نیست و حداقل privilege دارد.
- connection TLS در deployment جدا از localhost.
- audit append-only از مسیر عادی برنامه؛ retention و export checksumدار.
- backup رمزگذاری، checksum و restore drill دارد.
- package metadata ممکن است حاوی نام/email ناشر باشد و باید data classification شود.

## Supply Chain

- release tag، commit و digest ثبت می‌شوند.
- `latest`، prerelease و branch build در production ممنوع.
- lockfile اجباری؛ update فقط PR و review.
- provenance/Trusted Publishing مزیت امتیازی است؛ نبود آن با hash و reproducible build جبران می‌شود.
- devpi maintainer concentration یک ریسک ثبت‌شده است؛ mirror source و exit plan الزامی است.
- React/Admin dependencyهای browser با SCA و lockfile کنترل می‌شوند.

## Audit Events اجباری

- login success/failure و MFA reset
- user/role/token create/revoke
- upstream create/edit/reorder/block
- secret replace بدون ثبت مقدار
- offline/maintenance mode
- cache purge/quarantine/release
- publish/delete package خصوصی
- backup/restore/upgrade
- policy و security setting change
- domain route create/edit/delete و TLS/trusted-proxy change
- module start/stop/restart/disable و crash-loop acknowledgement
- monitor/notification/status-page/incident/maintenance mutation
- DNS change-set validate/approve/apply/rollback
- zone/record/ACL/forwarder/DNSSEC/TSIG/listener mutation بدون secret value

## Domain Routing و Public Surface

- hostname allowlist و default-deny؛ route ناشناخته هرگز به engine یا پنل fallback نمی‌کند.
- forwarded header فقط از CIDR proxy مورد اعتماد پذیرفته می‌شود.
- admin، registry، public status و DoH security policy مستقل دارند.
- engine admin portها فقط loopback/Unix boundary هستند.
- wildcard route فقط Owner، step-up و impact preview.
- public status schema از DTO مدیریتی جدا و فاقد ID/secret داخلی است.

## Uptime Monitoring Threats

- monitorها یک SSRF primitive بالقوه‌اند؛ private network access پیش‌فرض deny و allowlist آن Owner-only است.
- redirect و resolve مجدد دوباره validate می‌شوند؛ metadata endpointها همیشه deny هستند.
- browser monitor sandbox، timeout، memory/process limit و download policy دارد.
- arbitrary shell/script monitor در فاز اول وجود ندارد.
- notification template و response sample untrusted هستند و encode/redact می‌شوند.
- Docker socket مستقیم mount نمی‌شود؛ فقط agent یا socket-proxy با API allowlist.
- push token و notification secret write-only و rotateable هستند.

## DNS Threats

- open recursion release blocker است؛ پیش‌فرض private ACL/default-deny.
- zone transfer و dynamic update پیش‌فرض deny و TSIG/ACL اجباری‌اند.
- تغییر NS/SOA/DNSSEC/TSIG/listener Critical و نیازمند step-up/typed confirmation است.
- query log شامل client IP است و data classification، retention و export audit دارد.
- DNS App فقط hash-pinned/allowlisted/license-reviewed؛ upload دلخواه ممنوع.
- DoH CORS بسته، rate limit فعال و admin API از مسیر DoH جداست.
- change-set قبل از apply snapshot و verification query دارد.

## Copyleft و توزیع

- Uptime Kuma MIT است و notice آن در artifact حفظ می‌شود.
- Technitium GPL-3.0 است؛ پیش از image عمومی Legal Gate الزامی است.
- binary متناظر با source دقیق، build information، copyright notice و source-offer همراه release نگه‌داری می‌شود.
- engine ترجیحاً بدون تغییر و process مستقل است؛ هر patch باید source کامل متناظر و ADR داشته باشد.
- نبود sign-off حقوقی باعث حذف DNS engine از release می‌شود، نه bypass کردن Gate.

## تصمیم‌های باز پیش از Production

- anonymous read فعال یا غیرفعال
- domain و network boundary پنل
- OIDC provider و MFA enforcement
- retention audit و package cache
- secret provider production
- مقصد backup و key custody
- egress allowlist نهایی
- license کد اختصاصی
- trusted proxy CIDR و hostname inventory production
- Legal sign-off و source-offer Technitium
- policy دسترسی monitor به شبکه خصوصی
- retention heartbeat و DNS query log

## Gate امنیتی Release

- threat model به‌روز
- critical/high finding بدون exception معتبر وجود ندارد
- secret scan و SBOM موفق
- dependency licenses تأیید
- restore drill موفق
- privilege و network policy تست‌شده
- session/CSRF/CORS/SSRF tests سبز
- incident و rollback runbook آماده

