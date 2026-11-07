# 20 — معماری Modular Appliance و مسیریابی دامنه

وضعیت: **مصوب برای طراحی؛ پیاده‌سازی و deploy هنوز شروع نشده است**  
تاریخ تصمیم: 2026-11-07  
دامنه تصمیم: تک‌ایمیج، چند ماژول، چند دامنه و قابلیت توسعه آینده

## 1. تصمیم معماری

خروجی production یک Docker Image و یک Compose service باقی می‌ماند، اما داخل آن چند process مستقل تحت یک supervisor اجرا می‌شوند. «یک image» به معنی «یک process بزرگ» نیست. مرزهای داده، پورت، policy، health و restart هر ماژول مستقل می‌ماند.

```text
Internet / Reverse Proxy
          │
          │ Host / X-Forwarded-Host (trusted proxy only)
          ▼
┌──────────────────── One Docker Appliance ────────────────────┐
│ Edge Gateway :8080                                            │
│  ├─ panel.domain.com ──> Admin UI + Control Plane API          │
│  ├─ npm.domain.com   ──> Verdaccio adapter                     │
│  ├─ pypi.domain.com  ──> devpi adapter                         │
│  ├─ status.domain.com ─> Public Status Portal                  │
│  └─ dns.domain.com/dns-query ─> DNS DoH endpoint               │
│                                                               │
│ Control Plane ──> Module Registry ──> Lifecycle/Policy/Audit   │
│ Supervisor     ├─ gateway                                     │
│                ├─ control-plane                               │
│                ├─ npm-engine                                  │
│                ├─ pypi-engine                                 │
│                ├─ uptime-engine                               │
│                └─ dns-engine                                  │
│                                                               │
│ Protocol listeners: npm :4873, PyPI :3141, DNS UDP/TCP :53    │
│                     DoT :853, optional DoQ :853/udp            │
└────────────────────────── /data ───────────────────────────────┘
```

## 2. قرارداد دامنه

### نگاشت نمونه

| hostname | نوع route | مقصد منطقی | عمومی؟ |
|---|---|---|---|
| `panel.domain.com` | HTTPS | Admin UI و `/api/v1` | فقط مدیران |
| `npm.domain.com` | HTTPS | npm registry | clientها |
| `pypi.domain.com` | HTTPS | PyPI simple/index | clientها |
| `status.domain.com` | HTTPS | status page منتخب | عمومی یا خصوصی |
| `dns.domain.com` | HTTPS | DoH و صفحه راهنمای resolver | طبق policy |

هر route شامل `hostname`، `module_id`، `route_kind`، `target_id` اختیاری، `tls_mode`، `enabled` و timestamps است. hostname با IDNA و lower-case canonicalize می‌شود. wildcard فقط برای Owner و پس از نمایش blast radius مجاز است.

### محدودیت DNS کلاسیک

DNS روی UDP/TCP پورت 53 مانند HTTP دارای Host header نیست؛ بنابراین `dns-a.domain.com` و `dns-b.domain.com` اگر به یک IP برسند، از روی نام دامنه قابل route به دو engine متفاوت نیستند. در Appliance فعلی یک DNS listener وجود دارد و zone داخل payload DNS مقصد را مشخص می‌کند. دامنه برای این موارد کاربرد دارد:

- آدرس مدیریتی DNS؛
- endpoint استاندارد DoH؛
- نام گواهی DoT/DoQ؛
- delegation و NS record.

## 3. Edge Gateway

Gateway تنها ورودی HTTP production است و باید:

- فقط hostnameهای ثبت‌شده و فعال را بپذیرد؛ hostname ناشناخته `421` یا `404` می‌گیرد؛
- `Host`، `X-Forwarded-Host`، `X-Forwarded-Proto` و client IP را فقط از CIDRهای trusted proxy قبول کند؛
- headerهای hop-by-hop و spoofable identity را حذف کند؛
- limitهای body، timeout و rate را per-route اعمال کند؛
- WebSocket/SSE و streaming package artifact را بدون buffer اجباری پشتیبانی کند؛
- route snapshot آخر سالم را atomic بارگذاری و در config نامعتبر fail-closed کند؛
- admin، registry، public status و DoH را با security header و CORS مستقل سرو کند؛
- endpoint داخلی engineها را هرگز به شکل catch-all منتشر نکند.

Gateway می‌تواند Caddy embedded/pinned یا یک gateway کوچک مبتنی بر کتابخانه بالغ باشد. انتخاب نهایی بعد از license، memory و dynamic-config PoC در ADR ثبت می‌شود.

## 4. Module Contract

هر module یک manifest نسخه‌دار دارد:

```yaml
apiVersion: mrk.io/v1
kind: Module
metadata:
  id: uptime
  displayName: Uptime Monitoring
spec:
  process: uptime-engine
  routes: [admin, public-status]
  capabilities: [monitor.read, monitor.write, incident.write]
  dataRoot: /data/modules/uptime
  health:
    live: /internal/health/live
    ready: /internal/health/ready
  migrations: true
  backup: true
```

قرارداد اجباری:

- `describe`: نسخه، capabilityها و schema version؛
- `health`: live/readiness/degraded با reason code؛
- `start/stop/restart`: asynchronous job با audit؛
- `backup/restore`: contributor به manifest مرکزی؛
- `upgrade/preflight`: compatibility و migration plan؛
- `metrics/logs`: نام‌گذاری و redaction استاندارد؛
- `permissions`: scopeهای module بدون استفاده از wildcard پنهان؛
- `routes`: انواع route قابل ثبت؛
- `events`: envelope مشترک، idempotency key و correlation ID.

ماژول آینده با ثبت manifest، migration، adapter و UI bundle اضافه می‌شود و نباید routing/auth/audit core را fork کند.

## 5. Process Supervision و مدیریت خرابی

وضعیت‌های استاندارد process:

`disabled → starting → ready → degraded → stopping → stopped`  
`starting/ready/degraded → failed → backoff → starting`  
`failed تکرارشونده → crash-loop`

قواعد:

- liveness فقط زنده‌بودن process و readiness توان پاسخ صحیح را می‌سنجد؛
- restart خودکار exponential backoff با jitter، سقف تلاش و پنجره زمانی دارد؛
- crash-loop پس از عبور از threshold متوقف و نیازمند اقدام Operator می‌شود؛
- restart دستی typed confirmation، reason، actor، زمان و نتیجه دارد؛
- stop/restart ماژول DNS impact warning جدی و optional maintenance window دارد؛
- supervisor هرگز database migration را در حلقه restart تکرار نمی‌کند؛
- processها حداقل privilege، UID مستقل در صورت امکان و filesystem محدود دارند؛
- Docker socket به هیچ module داده نمی‌شود؛ Docker monitoring فقط از agent/socket-proxy محدود استفاده می‌کند.

## 6. مدل داده و جداسازی

PGlite/PostgreSQL schema به namespaceهای منطقی تقسیم می‌شود:

- `core_*`: user، role، route، module، audit، task؛
- `registry_*`: catalog و upstream state؛
- `uptime_*`: monitor، heartbeat، incident، maintenance، status page؛
- `dns_*`: engine reference، change set، approval، snapshot و projectionهای لازم.

داده binary یا engine-native در `/data/modules/<module>` می‌ماند. Control Plane منبع حقیقت identity، permission، audit، route و lifecycle است. Engine منبع حقیقت داده تخصصی خودش است مگر ADR خلاف آن را مشخص کند.

## 7. Auth و مرز عمومی/خصوصی

- پنل مدیریتی تنها از session/token مرکزی MRK استفاده می‌کند.
- engine admin UI مستقیماً publish نمی‌شود.
- adapter با credential سرویسی کوتاه‌عمر یا Unix socket به engine متصل می‌شود.
- public status page هیچ endpoint مدیریتی یا شناسه داخلی را لو نمی‌دهد.
- status page خصوصی از signed access link یا login محدود استفاده می‌کند.
- routeهای registry auth policy مستقل از login پنل دارند.
- permissionها به شکل `<module>:<resource>:<action>` تعریف می‌شوند.

## 8. ذخیره‌سازی پیشنهادی

```text
/data/
├─ control-plane/
├─ database/
├─ modules/
│  ├─ registry/npm/
│  ├─ registry/pypi/
│  ├─ uptime/
│  └─ dns/
├─ gateway/
├─ logs/
├─ backups/
└─ tmp/
```

یک bind mount برای کاربر حفظ می‌شود، اما quota، backup policy و cleanup هر module جداست.

## 9. Backup، Upgrade و Rollback

- backup مرکزی manifest هر module و schema/version engine را ثبت می‌کند؛
- snapshot ناسازگار بدون adapter migration restore نمی‌شود؛
- upgrade ترتیب `preflight → backup → stop affected module → migrate → start → verify` دارد؛
- rollback فقط وقتی migration برگشت‌پذیر است خودکار نمایش داده می‌شود؛
- ارتقای یک module نباید engineهای دیگر را restart کند؛
- image با نسخه تمام engineها و source commit/digest در SBOM منتشر می‌شود.

## 10. تصمیم‌های امنیتی غیرقابل مذاکره

- default-deny برای hostname، route، permission و network access؛
- عدم expose پورت مدیریتی engineها؛
- عدم دریافت arbitrary executable/plugin از پنل در فاز اول؛
- عدم ذخیره secret خام در route، log، task payload یا support bundle؛
- DNS recursion پیش‌فرض فقط شبکه‌های مجاز و هرگز open resolver؛
- SSRF guard برای monitor HTTP/DNS و upstreamها با policy قابل مشاهده؛
- change preview و rollback snapshot برای DNS؛
- license notices و source-offer لازم برای componentهای GPL در artifact انتشار.

## 11. معیار پذیرش معماری

- سه دامنه نمونه پنل/npm/PyPI بدون پورت خارجی اضافه از یک entrypoint پاسخ صحیح دهند؛
- دامنه status به page انتخاب‌شده و دامنه DoH فقط به `/dns-query` route شود؛
- hostname ناشناخته و forwarded header از proxy غیرمجاز رد شود؛
- خرابی uptime-engine، npm/PyPI و پنل را قطع نکند؛
- restart یک module همراه audit و crash-loop protection باشد؛
- backup/restore module manifest را validate کند؛
- یک module آزمایشی بدون تغییر core routing/auth/audit ثبت شود؛
- هیچ engine admin port از خارج container قابل دسترس نباشد.

## 12. موارد نیازمند ADR پیش از پیاده‌سازی

1. انتخاب نهایی Edge Gateway و نحوه dynamic reload.
2. مرز fork و adapter برای Uptime Kuma.
3. تأیید حقوقی توزیع Technitium GPL-3.0 در image و شیوه source offer.
4. سیاست certificate: external reverse proxy یا ACME داخل Appliance.
5. پورت‌های publish پیش‌فرض DNS و DoH/DoT/DoQ.
6. مدل resource limits per-process داخل یک container.

