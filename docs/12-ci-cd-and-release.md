# CI/CD and GHCR Release

## CI

`.github/workflows/ci.yml` روی pull request و push شاخه `main` یا `master` اجرا می‌شود و این
gateها را دارد:

1. Ruff، pytest، migration downgrade/upgrade rehearsal، release policy و license inventory برای control plane؛
2. نصب deterministic با `npm ci`، audit مستقیم از npm رسمی، typecheck و build UI؛
3. build ایمیج با base imageهای digest-pinned و Trivy HIGH/CRITICAL gate؛
4. اجرای کانتینر hardened، probe واقعی readiness و clientهای online/offline؛
5. load gate محدود با keep-alive و threshold خطا/p95؛
6. چاپ log و حذف container/network/volume آزمایشی حتی در failure.

`soak.yml` نیز هفتگی یا دستی اجرا می‌شود، image را با همان Dockerfile می‌سازد، readiness را قبل و
بعد از soak کنترل و به‌طور پیش‌فرض ۱۰ دقیقه با concurrency 16 تست می‌کند. duration دستی حداکثر
۳۶۰۰ ثانیه و توسط خود probe اعتبارسنجی می‌شود.

## انتشار GHCR

`.github/workflows/publish-image.yml` فقط با tag مطابق `v*` یا اجرای دستی فعال می‌شود. قبل از
login و push، تست backend، audit و build UI دوباره اجرا می‌شوند. سپس ایمیج برای
`linux/amd64` و `linux/arm64` در آدرس زیر منتشر می‌شود:

```text
ghcr.io/<github-owner>/mrk-package-mirror:<version>
```

Workflow از `GITHUB_TOKEN` با permission محدود `packages: write` استفاده می‌کند؛ secret شخصی
نیاز ندارد. خروجی شامل SBOM، provenance attestation و digest در Job Summary است.

## Release flow

بعد از سبزشدن CI و review:

```bash
git tag -s v0.1.0 -m "MRK Package Mirror v0.1.0"
git push origin v0.1.0
```

برای production باید با digest deploy شود، نه tag شناور:

```yaml
services:
  mrk-mirror:
    image: ghcr.io/<github-owner>/mrk-package-mirror@sha256:<digest>
    volumes:
      - /opt/mirrors/pypi:/data
```

روی میزبان Linux مسیر volume باید قبل از اجرا با مالک `10001:10001` ساخته شود؛ entrypoint در هر
شروع mode آن و زیرپوشه‌های ثابت را `0750` می‌کند.
GitHub Actions به سرور production وصل نمی‌شود؛ CD فعلی artifact publication است. deploy خودکار
سرور فقط پس از تعریف environment protection، runner/credential و rollback policy اضافه می‌شود.
