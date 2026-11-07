# 10 — Execution Plan آینده

Planهای اجرایی Gate 0 تا 10 پس از تکمیل Acceptance Criteria از این سند پاک شدند. وضعیت، تاریخ و
شواهد هر Story در `docs/03-user-stories.md` و شواهد عملیاتی Release در
`docs/19-production-release-gate.md` نگه‌داری می‌شود. این سند فقط کارهای اجرا‌نشده را نگه می‌دارد.

## سیاست پاک‌سازی Plan پس از پیاده‌سازی

پس از تکمیل هر Gate و ثبت شواهد:

1. وضعیت، تاریخ، release/gate و شواهد کوتاه به Storyهای متناظر منتقل می‌شود.
2. checklist، گزارش میانی و plan اجرایی تکمیل‌شده حذف می‌شود.
3. سند طراحی موقت فاقد ارزش عملیاتی حذف می‌شود.
4. Architecture Decision، قرارداد نهایی API/data، Runbook، security control، migration/rollback و release evidence حذف نمی‌شوند.
5. موارد Deferred، ریسک‌های باز و بدهی فنی تا زمان بسته‌شدن باقی می‌مانند.
6. حذف گروهی فقط در یک commit قابل‌بازیابی انجام می‌شود.

تا قبل از تکمیل Gate 14 و تأیید نهایی مالک، Planهای Gate 11 تا 14 و اسناد طراحی ماژول‌ها حذف
نخواهند شد.

## سیاست توقف

در صورت مشاهده یکی از موارد زیر Gate متوقف می‌شود:

- نیاز به secret واقعی
- عملیات destructive روی داده کاربر
- license مبهم یا ناسازگار
- vulnerability بحرانی بدون mitigation
- نیاز به دسترسی Docker socket/host root
- شکست integrity یا احتمال cache poisoning
- تغییر scope خارج از MVP بدون تأیید

## Deployment Contract قطعی

- artifact نهایی یک Docker Image است.
- production Compose فقط یک application service دارد.
- تنها volume اجباری `/data` است.
- یک HTTP entrypoint با route مبتنی بر hostname، به‌علاوه listenerهای منطقی npm/PyPI و پروتکل DNS از همان container ارائه می‌شوند.
- PostgreSQL/Redis برای نصب اولیه اجباری نیستند.
- image بدون mount باید fail امن باشد؛ production فقط با volume پایدار اجرا می‌شود.
- deploy روی Dokploy فقط پس از تأیید صریح مالک انجام می‌شود.

## Scope Expansion مصوب — 2026-11-07

در این مرحله فقط Product/Architecture/User Story به‌روزرسانی شده و هیچ engine جدیدی نصب، اجرا یا
deploy نشده است.

- معماری تک‌ایمیج با processهای ماژولار و دامنه‌های مستقل تأیید شد.
- Uptime Monitoring با Uptime Kuma به‌عنوان baseline مشروط و adapter/fork حداقلی وارد roadmap شد.
- DNS Management با Technitium به‌عنوان engine مشروط به GPL Legal Gate وارد roadmap شد.
- UI هر دو ماژول متعلق به MRK است؛ هدف capability parity است، نه کپی ظاهری.
- DNS کلاسیک UDP/TCP به دلیل نداشتن Host header با دامنه HTTP route نمی‌شود؛ DoH و پنل DNS دامنه مستقل دارند.
- اسناد تفصیلی: `docs/20-modular-appliance-and-domain-routing.md`، `docs/21-uptime-monitoring-module.md` و `docs/22-dns-management-module.md`.

## Gate 11 — Modular Edge و Domain Routing

- [ ] ADR انتخاب Edge Gateway
- [ ] module manifest/registry contract
- [ ] hostname route CRUD و conflict detection
- [ ] trusted proxy و Host security
- [ ] per-module lifecycle/restart/crash-loop
- [ ] failure-isolation test
- [ ] backup/upgrade contributor contract

## Gate 12 — Uptime Monitoring

- [ ] pin/security/license baseline Uptime Kuma
- [ ] adapter و contract tests
- [ ] monitor core و Simple/Advanced UI
- [ ] history/metrics/notifications
- [ ] incident/maintenance/status pages
- [ ] custom domains و public/private boundary
- [ ] parity matrix بدون gap P0/P1
- [ ] backup/restore/load/security rehearsal

## Gate 13 — DNS Management

- [ ] GPL Legal/Distribution Gate
- [ ] pin/security baseline Technitium
- [ ] adapter و engine admin-port isolation
- [ ] Simple Mode zones/records/forwarders/cache
- [ ] Advanced Mode ACL/transfer/TSIG/DNSSEC
- [ ] DoH/DoT/DoQ و protocol listeners
- [ ] change-set/preview/approval/rollback
- [ ] parity matrix بدون gap P0/P1
- [ ] backup/restore/load/open-resolver test

## Gate 14 — Unified Modular Appliance

- [ ] یک image و یک volume با تمام moduleهای مصوب
- [ ] resource/size budget و isolation
- [ ] SBOM/license/source-offer همه runtimeها
- [ ] upgrade/rollback per-module
- [ ] production-like domain/TLS/DNS E2E
- [ ] operations/security/legal sign-off

### ترتیب اجرای Scope جدید

1. Gate 11 قبل از هر engine جدید اجرا می‌شود تا moduleها از ابتدا روی قرارداد مشترک سوار شوند.
2. Gate 12 و Gate 13 پس از ثبات contract می‌توانند مستقل توسعه یابند.
3. Gate 14 فقط پس از Legal Gate Technitium و parity/security sign-off شروع می‌شود.
4. deploy روی Dokploy فقط با تأیید صریح مالک و پس از معماری/تصویر نهایی انجام می‌شود.
