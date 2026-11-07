# 07 — شروع پیاده‌سازی

## 1. ساختار پیشنهادی Monorepo

```text
mrk-package-mirror/
├─ apps/
│  ├─ control-plane/        # FastAPI
│  └─ admin-ui/             # React Admin
├─ services/
│  ├─ npm-registry/         # Verdaccio config/plugins only
│  ├─ pypi-registry/        # devpi config/plugins only
│  └─ upstream-router/      # protocol-aware failover adapters
├─ packages/
│  ├─ api-client/
│  ├─ policy-schema/
│  └─ observability/
├─ deploy/
│  ├─ appliance/            # Dockerfile واحد، supervisor و entrypoint
│  ├─ compose/              # یک service برای production
│  └─ development/          # پروفایل چندسرویسی فقط برای توسعه
├─ tests/
│  ├─ contract/
│  ├─ integration/
│  ├─ e2e/
│  └─ chaos/
├─ docs/
├─ scripts/
├─ THIRD_PARTY_NOTICES
└─ versions.lock.yaml
```

## 2. ریپوهایی که باید Pin شوند، نه Blind Fork

### npm engine

- Source: `https://github.com/verdaccio/verdaccio`
- انتخاب: آخرین stable از خط 6.x پس از بررسی changelog/security
- روش: image/package pin + plugin/config اختصاصی
- Fork فقط اگر API/plugin gap اثبات شود.

### PyPI engine

- Source: `https://github.com/devpi/devpi`
- انتخاب: release stable سازگار با Python مورد استفاده
- روش: image build reproducible + adapter بیرونی
- patch core فقط با contract test و upstream PR.

### Admin framework

- Source: `https://github.com/marmelab/react-admin`
- روش: package dependency؛ clone برای reference و contribution، نه کپی کامل source در محصول.

### API framework

- Source: `https://github.com/fastapi/fastapi`
- روش: package dependency pin‌شده.

## 3. کارهای اولین Commit

1. ایجاد monorepo و license policy.
2. افزودن `versions.lock.yaml` و scorecard.
3. ایجاد Compose توسعه با mock upstreamها.
4. ایجاد FastAPI با `/health/live`، `/health/ready` و `/api/v1/system/status`.
5. ایجاد React Admin shell با login placeholder.
6. افزودن PostgreSQL migration اولیه.
7. اجرای Verdaccio stable با storage مجزا.
8. اجرای devpi stable با storage مجزا.
9. افزودن correlation ID middleware.
10. CI شامل lint، tests، secret scan و dependency scan.

## 4. اولین Vertical Slice

سناریوی قابل تحویل:

1. مدیر وارد پنل می‌شود.
2. دو npm upstream و دو PyPI upstream را می‌بیند.
3. پنل health و latency را نشان می‌دهد.
4. کاربر `npm install` و `pip install` انجام می‌دهد.
5. درخواست اول از upstream و درخواست دوم از cache می‌آید.
6. upstream اصلی شبیه‌سازی‌شده قطع می‌شود.
7. درخواست uncached از upstream دوم دریافت می‌شود.
8. اینترنت هر دو upstream قطع می‌شود.
9. package کش‌شده همچنان نصب می‌شود.
10. تمام مراحل در metrics، trace و audit قابل مشاهده‌اند.

## 5. فایل version lock پیشنهادی

```yaml
reviewed_at: 2026-11-07
components:
  verdaccio:
    source: https://github.com/verdaccio/verdaccio
    release_line: 6.x
    version: TO_BE_PINNED_AFTER_SECURITY_REVIEW
    image_digest: TO_BE_RESOLVED
  devpi:
    source: https://github.com/devpi/devpi
    version: TO_BE_PINNED_AFTER_COMPATIBILITY_TEST
  react_admin:
    source: https://github.com/marmelab/react-admin
    version: TO_BE_PINNED
  fastapi:
    source: https://github.com/fastapi/fastapi
    version: TO_BE_PINNED
```

مقادیر عمداً هنوز نهایی نشده‌اند؛ pin نهایی فقط بعد از CVE scan، compatibility matrix و build test انجام می‌شود.

## 6. Pull Request Gates

- حداقل یک review
- unit و contract tests سبز
- بدون secret finding
- بدون critical vulnerability جدید
- migration review برای تغییر DB
- screenshot/UX review برای تغییر پنل
- ADR برای dependency یا معماری جدید
- changelog entry برای رفتار قابل مشاهده

## 7. اولین ADRها

- ADR-001: موتورهای جداگانه Verdaccio و devpi
- ADR-002: عدم Fork سنگین Core
- ADR-003: Control Plane با FastAPI
- ADR-004: پنل با React Admin
- ADR-005: PostgreSQL برای state مدیریتی
- ADR-006: failover بیرون از devpi core
- ADR-007: version pin و dependency scorecard

## 8. Environmentهای مورد نیاز

- local development
- CI ephemeral
- staging با DNS/TLS واقعی
- production
- restore-drill isolated

هیچ environment نباید credential محیط دیگر را reuse کند.

## 9. داده و Volumeهای Appliance

- `/data/control-plane`
- `/data/npm`
- `/data/pypi`
- `/data/logs`
- `/data/backups`
- `/data/tmp`

مسیر واقعی host در deployment تعیین می‌شود؛ داخل Git فقط placeholder قرار می‌گیرد.

نمونه استقرار هدف:

```yaml
services:
  mrk-mirror:
    image: mrk/package-mirror:<version>
    restart: unless-stopped
    volumes:
      - /path/on/host:/data
    ports:
      - "8080:8080"
      - "4873:4873"
      - "3141:3141"
```

## 10. تصمیم مورد نیاز پیش از Coding گسترده

- نام نهایی محصول و repository
- مجوز کد اختصاصی
- private-only یا open-source بودن Control Plane
- اندازه اولیه storage و retention
- anonymous read policy
- نیاز به package private در MVP
- دامنه‌های npm، PyPI و admin
- مقصد backup

این تصمیم‌ها مانع ساخت skeleton و PoC نیستند، اما قبل از production باید نهایی شوند.

