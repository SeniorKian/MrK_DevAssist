# Gate 2 — npm Registry

## Runtime

- Verdaccio `6.11.1` روی Node `24.18.0` داخل همان appliance اجرا می‌شود.
- Supervisor `4.3.0` هم Verdaccio و هم control plane را مدیریت می‌کند.
- metadata، tarball و auth زیر `/data/npm` ذخیره می‌شوند.
- خواندن anonymous مجاز است؛ publish/unpublish فقط authenticated است.
- ساخت کاربر عمومی غیرفعال است (`max_users: -1`) تا Gate احراز هویت و RBAC تکمیل شود.

## Uplink order

ترتیب هر دو rule مربوط به scoped و unscoped package چنین است:

1. `https://registry.npmjs.org/`
2. `https://package-mirror.liara.ir/repository/npm/`

Timeout هر uplink هفت ثانیه و circuit-break window دو دقیقه است. TLS certificate validation
برای هر دو فعال است. تغییر URL از پنل تا زمان اضافه‌شدن validation ضد SSRF مجاز نیست.

## Client usage

پس از قرارگرفتن TLS در لایه PaaS/reverse proxy:

```bash
npm config set registry https://packages.example.com/npm/
pnpm config set registry https://packages.example.com/npm/
yarn config set npmRegistryServer https://packages.example.com/npm/
```

در deployment فعلی که پورت مستقیم استفاده می‌شود، endpoint داخلی npm پورت `4873` است.

## E2E evidence — 2026-11-07

- npm 11: دریافت `is-number@7.0.0` از uplink و ذخیره tarball موفق.
- offline: container روی Docker network از نوع `--internal` بدون اینترنت، همان tarball را به یک
  client تازه تحویل داد.
- failover: primary روی `127.0.0.1:9` عمداً `ECONNREFUSED` شد و metadata/tarball
  `is-odd@3.0.1` با HTTP 200 از Liara دریافت شد.
- scoped routing: `@colors/colors@1.6.0` از مسیر fallback موفق بود.
- pnpm `10.20.0`، Yarn Classic `1.22.22` و Yarn Berry `4.10.3` نصب واقعی را از mirror انجام دادند.
- image Gate 2 پس از اصلاح رندر پنل: `sha256:d77bde64cd2c...`.

## Accepted dependency risk

Audit رسمی npm برای Verdaccio 6.11.1 هیچ High/Critical ندارد، اما advisory
`GHSA-g3hv-75wg-m249` برای `minimatch@10.2.6` را به‌صورت Moderate گزارش می‌کند. الگوی glob در
این appliance ثابت و فقط از config immutable داخل image می‌آید؛ کاربر API نمی‌تواند pattern را
تزریق کند. override به minimatch 11 در E2E عملاً ناسازگار بود و E500 ایجاد کرد، بنابراین rollback
شد. این risk acceptance موقت است و در Gate 10 با release جدید upstream دوباره ارزیابی می‌شود.
