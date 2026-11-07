# 04 — Roadmap و برنامه تحویل

## اصل تحویل

هر فاز باید یک خروجی قابل اجرا و قابل آزمون داشته باشد. عبور از هر Gate نیازمند demo، تست، مستندات و sign-off است. تاریخ‌ها پس از مشخص شدن ظرفیت تیم به Sprint تبدیل می‌شوند؛ ترتیب و dependencyها از هم‌اکنون قطعی‌اند.

## Phase 0 — Discovery و Baseline

خروجی‌ها:

- ثبت scorecard تمام ریپوهای کاندیدا
- pin کردن Verdaccio، devpi، React Admin و FastAPI
- ثبت ADRهای معماری، لایسنس و fork policy
- PoC نصب یک package از هر ecosystem
- PoC cache offline
- PoC failover به Liara

Gate:

- تمام P0های معماری اثبات شده باشند.
- هیچ prerelease یا latest در baseline نباشد.
- license review ثبت شده باشد.

## Phase 1 — Foundation

خروجی‌ها:

- ساختار monorepo
- Compose توسعه
- Control Plane skeleton و OpenAPI
- React Admin shell
- PostgreSQL migrations
- auth محلی و RBAC پایه
- CI: lint، unit، SAST، secret scan، SBOM

Gate:

- onboarding از clone تا اجرا مستند و قابل تکرار باشد.
- health endpoint همه سرویس‌ها سبز باشد.
- هیچ credential واقعی در repo نباشد.

## Phase 2 — Registry Core

خروجی‌ها:

- Verdaccio stable با multi-uplink npmjs/Liara
- devpi با upstream router PyPI/Liara
- client endpoints و نمونه config
- cache on-demand و offline mode
- package metadata catalog اولیه
- contract tests adapterها

Gate:

- npm/pnpm/yarn و pip/uv/poetry در E2E سبز باشند.
- قطع upstream اصلی باعث failover موفق شود.
- قطع کامل اینترنت package کش‌شده را مختل نکند.

## Phase 3 — Admin Experience

خروجی‌ها:

- Dashboard
- CRUD upstream و تست اتصال
- package search/detail
- cache purge/revalidate/pin
- task list و logs
- user/role/token management
- فارسی/انگلیسی و RTL/LTR

Gate:

- همه mutationها permission و audit داشته باشند.
- destructive UX تست شده باشد.
- UI هیچ secret یا mixed-content نداشته باشد.

## Phase 4 — Operations و Reliability

خروجی‌ها:

- Prometheus metrics و alert rules
- backup/restore automation
- storage policy و cleanup dry-run
- support bundle
- maintenance mode
- production Compose و runbookها

Gate:

- restore drill با نصب package نمونه موفق باشد.
- disk pressure و upstream outage تمرین شود.
- alertها actionable و بدون secret باشند.

## Phase 5 — Security Hardening

خروجی‌ها:

- MFA و OIDC اختیاری
- SSRF policy
- checksum/quarantine workflow
- rate limiting
- TLS/CA management
- image signing و provenance
- dependency review و penetration test

Gate:

- هیچ finding بحرانی باز بدون exception زمان‌دار نباشد.
- threat model و incident runbook تأیید شوند.

## Phase 6 — Production Release

خروجی‌ها:

- release candidate immutable
- migration و rollback rehearsal
- capacity test
- SLO dashboard
- operator/developer documentation
- go-live checklist و ownership

Gate:

- تمام Storyهای P0 Done باشند.
- backup سالم و rollback plan آماده باشد.
- owner پاسخ‌گو برای هر سرویس مشخص باشد.

## Phase 7 — Modular Edge و Domain Routing

خروجی‌ها:

- module registry و manifest contract
- Edge Gateway با hostname allowlist و trusted-proxy policy
- UI مدیریت domain route و conflict detection
- lifecycle manager، restart job، backoff و crash-loop detection
- backup/upgrade contributor contract برای moduleها

Gate:

- پنل، npm، PyPI و module آزمایشی از دامنه‌های جدا route شوند.
- hostname ناشناخته، Host spoof و forwarded header غیرمجاز fail-closed باشد.
- خرابی module آزمایشی سرویس‌های دیگر را قطع نکند.

## Phase 8 — Uptime Monitoring

خروجی‌ها:

- clone/pin و security/license baseline برای Uptime Kuma
- adapter و contract test
- monitor CRUD/test/history و Simple/Advanced form
- notification، incident و maintenance
- status page چندگانه با دامنه مستقل، badge و RSS
- backup/restore و lifecycle یکپارچه

Gate:

- gapهای P0/P1 ماتریس parity صفر باشد.
- SSRF، secret redaction، notification dedupe و public/private boundary تست شوند.
- outage/restart/upgrade بدون از دست‌رفتن configuration تمرین شود.

## Phase 9 — DNS Management

خروجی‌ها:

- Legal Gate برای Technitium GPL-3.0 و source-offer
- engine pin‌شده، adapter و admin-port isolation
- Simple Mode برای zone/record/forwarder/cache
- Advanced Mode برای ACL/transfer/TSIG/DNSSEC/DoH/DoT/DoQ
- change set، preview، approval، snapshot و rollback
- DHCP/Apps/Cluster در milestone مستقل

Gate:

- هیچ open resolver یا endpoint مدیریتی عمومی وجود نداشته باشد.
- zone integrity، DNSSEC، transfer، backup/restore و load test پاس باشند.
- gapهای P0/P1 ماتریس capability صفر باشد.

## Phase 10 — Unified Appliance Release

خروجی‌ها:

- یک image شامل moduleهای مصوب و یک bind mount
- SBOM/license/source-offer کامل برای تمام runtimeها
- resource profile و size budget
- upgrade/rollback rehearsal per-module
- عملیات و incident runbook یکپارچه

Gate:

- restart/خرابی هر module isolation واقعی داشته باشد.
- domain routing، DNS protocol listeners و TLS در محیط production-like پاس باشند.
- release فقط پس از sign-off امنیت، عملیات و مجوز منتشر شود.

## Milestoneها

| Milestone | نتیجه قابل نمایش |
|---|---|
| M1 | نصب npm و pip از endpoint محلی |
| M2 | failover و offline cache اثبات‌شده |
| M3 | مدیریت upstream از پنل |
| M4 | catalog، cache operations و audit |
| M5 | monitoring، backup و restore |
| M6 | production release |
| M7 | domain routing و module lifecycle |
| M8 | uptime monitoring و status page عمومی |
| M9 | DNS Simple/Advanced و secure resolver |
| M10 | unified modular appliance release |

## ترتیب Sprint پیشنهادی

### Sprint A

- US-001 تا US-005
- US-130 development subset
- US-140 contract harness

### Sprint B

- US-020 تا US-024
- US-030، US-031، US-040، US-041
- US-142 failover harness

### Sprint C

- US-010 تا US-014
- US-050، US-051
- US-060 تا US-063

### Sprint D

- US-025، US-026، US-052 تا US-055
- US-070 تا US-074

### Sprint E

- US-080 تا US-093
- US-122، US-130، US-132، US-134

### Sprint F

- US-100 تا US-105
- US-141، US-143، US-144
- Release Candidate

## Change Control

- تغییر موتور registry نیازمند ADR جدید است.
- اضافه کردن package format جدید خارج از MVP است.
- هر dependency جدید باید scorecard کوتاه داشته باشد.
- هر patch core باید exit plan داشته باشد.
- scope جدید بدون حذف یا جابه‌جایی scope قبلی وارد Sprint نمی‌شود.
- افزودن engine جدید فقط از Module Contract انجام می‌شود؛ اتصال مستقیم به core ممنوع است.
- component با copyleft پیش از قرار گرفتن در image عمومی Legal Gate اجباری دارد.
- عبارت feature parity باید با ماتریس و contract test اثبات شود، نه شباهت ظاهری.

