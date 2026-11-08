# 22 — طراحی ماژول DNS Management

> **به‌روزرسانی 2026-11-08:** طبق `docs/23` موتور خارجی اجرا نمی‌شود و این قابلیت‌ها به‌صورت موتور بومی MRK ساخته می‌شوند. بخش «تصمیم پایه» این سند منسوخ است؛ دامنه قابلیت‌ها همچنان معتبر است.

وضعیت: **Product/Architecture specification؛ پیاده‌سازی نشده**  
هدف: قابلیت‌های حرفه‌ای هم‌سطح Technitium با UX ساده‌تر و یکپارچه MRK

## 1. تصمیم پایه و مرز مجوز

کاندیدای engine، `TechnitiumSoftware/DnsServer` است:

- حدود 10k star و نزدیک 800 fork در snapshot تاریخ 2026-11-07؛
- authoritative و recursive DNS، DHCP، clustering، DNS Apps و transportهای امن؛
- Docker، release فعال و HTTP API کامل؛
- مجوز GPL-3.0.

تصمیم: engine به شکل process مستقل، version-pinned و تا حد امکان بدون تغییر اجرا می‌شود. Control Plane از HTTP API رسمی روی loopback/Unix boundary استفاده می‌کند و UI اصلی Technitium بیرون publish نمی‌شود. هر patch نیازمند ADR، انتشار source متناظر و license notice است. توزیع نهایی تک‌ایمیج پیش از release نیازمند تأیید حقوقی GPL و source-offer است.

منابع بررسی:

- <https://github.com/TechnitiumSoftware/DnsServer>
- <https://github.com/TechnitiumSoftware/DnsServer/releases>
- <https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md>
- <https://github.com/TechnitiumSoftware/DnsServer/blob/master/CHANGELOG.md>
- <https://technitium.com/dns/help.html>

## 2. قابلیت‌های هدف

### DNS Server

- authoritative و recursive resolver؛
- UDP/TCP، DoH، DoT و DoQ طبق قابلیت نسخه pin‌شده؛
- recursive policy، forwarder و conditional forwarder؛
- DNSSEC validation، QNAME minimization، serve-stale، prefetch و persistent cache؛
- cache inspect/flush، root hints و proxy؛
- ACL برای recursion، query، transfer و dynamic update؛
- rate limiting و protection در برابر amplification/open resolver.

### Zone Management

- Primary، Secondary، Stub، Forwarder و Secondary Forwarder؛
- Catalog Zone در Advanced Mode؛
- create/clone/enable/disable/delete با preview؛
- zone file import/export/editor؛
- AXFR/IXFR، NOTIFY، ZONEMD و transfer-over-TLS/QUIC در صورت پشتیبانی؛
- zone optionها، aging/expiry و change history؛
- bulk edit با dry-run و atomic change set.

### Record Management

- A، AAAA، CNAME، ANAME، NS، SOA، MX، TXT، PTR، SRV، CAA؛
- SVCB/HTTPS، TLSA، SSHFP، URI، NAPTR، DS/DNSKEY و recordهای engine؛
- wildcard، apex rules، TTL preset و comment؛
- validation context-aware برای hostname/IP/priority/weight؛
- duplicate/conflict detection؛
- undo با snapshot فقط وقتی engine state هنوز با revision مبنا برابر است.

### DNSSEC و Secretها

- sign/unsign zone، rollover و algorithm policy؛
- DS/DNSKEY workflow و هشدار expiry/rollover؛
- TSIG key create/rotate/revoke؛
- secret فقط یک بار نمایش، encrypted at rest و هرگز در audit payload؛
- typed confirmation برای unsign، key delete و trust-anchor change.

### Blocking، Apps و Query Visibility

- blocklist URL، update schedule، allow/bypass و regex policy؛
- blocking mode و custom response؛
- query log با retention، filter و redaction؛
- آمار query type، response code، client، zone و latency؛
- DNS App فقط از allowlist امضاشده و پس از license/security review؛
- arbitrary app upload از مرورگر در فاز اول ممنوع.

### DHCP و Cluster

- DHCP scope، reservation، lease و optionها در Advanced Mode؛
- DNS update integration و reverse-zone helper؛
- cluster member health، role، replication lag و safe failover در milestone جدا؛
- single-node Appliance نباید بدون member دوم ادعای HA کند.

## 3. Simple Mode

Simple Mode برای 90 درصد کارهای روزمره است:

- Dashboard: سلامت، query rate، top errors، cache hit و DNSSEC؛
- Zones: ساخت zone با wizard و template؛
- Records: جدول ساده، جست‌وجو، bulk select و inline validation؛
- Forwarders: presetهای Cloudflare/Google/Quad9/Custom با test latency؛
- Security: recursion فقط شبکه خصوصی، blocklist و DNSSEC validation؛
- Clients: آدرس‌های آماده UDP/TCP/DoH/DoT؛
- Changes: preview، apply، audit و rollback.

در Simple Mode گزینه خطرناک حذف نمی‌شود؛ به‌صورت summary read-only نشان داده می‌شود و برای تغییر، کاربر به Advanced Mode هدایت می‌گردد.

## 4. Advanced Mode

- تمام zone typeها و optionهای engine؛
- ACLهای ordered، TSIG، DNSSEC signing/rollover؛
- resolver concurrency/retry/cache policy؛
- transfer/notify/dynamic update؛
- DoH/DoT/DoQ certificate و protocol settings؛
- query logging و Apps؛
- DHCP و cluster؛
- raw zone editor با parse/validate/diff، نه save مستقیم؛
- نمایش mapping مستقیم هر field به API engine برای عیب‌یابی.

فعال‌سازی Advanced Mode preference کاربر است، اما actionهای حساس همچنان permission و confirmation جدا دارند.

## 5. Change Set و ایمنی عملیات

هیچ mutation مهمی مستقیم از فرم به engine ارسال نمی‌شود:

1. draft change set؛
2. schema و semantic validation؛
3. engine preflight در صورت امکان؛
4. diff خوانا و impact summary؛
5. permission/step-up/approval متناسب با ریسک؛
6. snapshot و revision مبنا؛
7. apply با idempotency key؛
8. query verification؛
9. audit و rollback eligibility.

سطح ریسک:

- Low: افزودن record غیرمتعارض؛
- Medium: تغییر TTL/forwarder/blocklist؛
- High: حذف zone، تغییر NS/SOA، recursion ACL، DNSSEC/TSIG؛
- Critical: open recursion، تغییر listener/certificate، cluster/failover.

Critical نیازمند Owner، step-up auth، typed confirmation و maintenance plan است. سیستم هرگز open recursion عمومی را preset یا پیش‌فرض نمی‌کند.

## 6. دامنه و پورت

- `panel.domain.com/dns/*`: مدیریت authenticated از gateway؛
- `dns.domain.com/dns-query`: DoH؛
- `dns.domain.com`: راهنمای client و status محدود، نه admin UI engine؛
- UDP/TCP `53`: listener DNS کلاسیک؛
- TCP `853`: DoT؛
- UDP `853`: DoQ در صورت فعال‌سازی.

دامنه‌های HTTP از پنل route می‌شوند. DNS کلاسیک از hostname ورودی آگاه نیست و route بر اساس domain HTTP ممکن نیست. برای چند tenant/instance مستقل به IP یا listener جدا نیاز است؛ این مورد خارج از Appliance تک‌نودی اولیه است.

## 7. Adapter و API

`DnsEngineAdapter` باید:

- version/capability discovery داشته باشد؛
- request/response engine را به DTO پایدار MRK تبدیل کند؛
- credential engine را از UI پنهان و rotate کند؛
- timeout/retry محدود و circuit breaker داشته باشد؛
- mutationها را idempotent و audit-correlated کند؛
- API breaking change را با contract test قبل از upgrade کشف کند؛
- endpointهای engine را allowlist کند و generic proxy نباشد؛
- secret fieldها را بر اساس schema redact کند.

## 8. lifecycle و self-healing

- process health، DNS probe واقعی روی loopback و readiness جدا؛
- metricهای QPS، latency، SERVFAIL، cache، memory و thread/event-loop؛
- graceful restart با drain برای TCP/DoH و هشدار برای UDP؛
- config backup و parse test پیش از restart؛
- restart خودکار با backoff و crash-loop protection؛
- restart دستی از پنل به‌صورت job، با reason و audit؛
- safe mode: engine با آخرین config سالم و mutation بسته؛
- خرابی DNS نباید panel/registry/uptime را از کار بیندازد.

## 9. امنیت شبکه

- recursion default: `AllowOnlyForPrivateNetworks` یا ACL صریح؛
- bind address و published port در preflight نمایش داده می‌شود؛
- DoH CORS پیش‌فرض بسته؛
- DNS rebinding protection و special-use zones؛
- rate/QPM limit per client/subnet؛
- query log دارای IP شخصی است و retention/access محدود دارد؛
- zone transfer و dynamic update پیش‌فرض deny؛
- TSIG/DNSSEC key در support bundle، log و backup manifest خام قرار نمی‌گیرد؛
- engine API فقط loopback و credential سرویس؛
- تغییر allowlist شبکه lockout preview دارد.

## 10. Backup و restore

- engine config، zoneها، keys به‌صورت encrypted payload، DHCP و app metadata؛
- manifest شامل engine version و schema/capability؛
- restore ابتدا در process ایزوله و روی پورت loopback تصادفی validate می‌شود؛
- zone parse، DNSSEC consistency و sample queryها اجرا می‌شوند؛
- restore production فقط offline و با rollback snapshot؛
- query log می‌تواند از backup عملیاتی حذف و retention جدا داشته باشد.

## 11. Gateهای تحویل

### D1 — Engine Baseline

- license/legal decision، source offer و pin دقیق؛
- process داخلی بدون expose admin port؛
- adapter discovery/health و backup اولیه.

### D2 — Simple DNS

- zones/records CRUD، forwarder، cache و query test؛
- Simple Mode و change preview؛
- audit و rollback snapshot.

### D3 — Advanced DNS

- همه zone typeها، transfer، ACL، TSIG و DNSSEC؛
- DoH/DoT/DoQ؛
- blocklist/query log.

### D4 — DHCP/Apps/Cluster

- DHCP؛
- allowlisted Apps؛
- cluster management با تست failover.

### D5 — Parity و Production

- ماتریس capability رسمی Technitium بدون gap P0/P1؛
- protocol conformance و load/soak؛
- backup/restore/upgrade؛
- penetration و open-resolver test.

## 12. تعریف parity

هم‌سطح Technitium به معنی پوشش API/capability و workflow قابل آزمون است، نه کپی پنل آن. برای هر release pin‌شده، endpointها و featureهای رسمی به وضعیت `native/adapted/mrk/deferred/not-applicable` نگاشت می‌شوند. هر gap در DNSSEC، zone data integrity، transfer یا access policy release blocker است.

## 13. موارد باز و blockerها

- تأیید حقوقی GPL-3.0 پیش از قرار دادن binary در image منتشرشده؛
- اندازه image چند-runtime و سیاست security patch .NET؛
- تصمیم expose پیش‌فرض پورت‌های 53/853 در Compose؛
- نیاز واقعی DHCP که به network capability و محیط host وابسته است؛
- cluster در یک image تک‌نودی معنا ندارد و به deployment چند instance نیاز دارد؛
- تعیین دقیق feature parity بر اساس version pin نهایی.

