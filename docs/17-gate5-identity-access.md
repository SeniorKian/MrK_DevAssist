# Gate 5 — Identity and Access

تاریخ گزارش: 2026-11-07

## نتیجه فعلی

کنترل‌پلین اکنون یک مرز احراز هویت واقعی دارد. health endpointهای orchestration عمومی باقی مانده‌اند، اما status و تمام APIهای مدیریتی به session یا Bearer token معتبر نیاز دارند. پنل ورود و بخش Access Control نیز به API واقعی متصل‌اند.

## کنترل‌های پیاده‌شده

- First-Time Setup فقط وقتی جدول کاربران خالی است؛ نام، ایمیل و رمز را از فرم می‌گیرد و اولین Owner را اتمیک می‌سازد. هیچ رمز پیش‌فرض، کد راه‌اندازی یا bootstrap فایل‌محوری وجود ندارد.
- password hashing با Argon2id و پارامترهای memory/time صریح
- پیام خطای عمومی، dummy verification برای کاهش user enumeration و rate limit بر مبنای IP/username
- session تصادفی با token hash‌شده، TTL، rotation، revoke و cookie از نوع HttpOnly/SameSite=Strict
- Secure cookie به‌صورت پیش‌فرض در production؛ فقط preview محلی HTTP آن را خاموش می‌کند
- CSRF token برای تمام mutationهای session-based؛ Bearer token به CSRF وابسته نیست
- CORS محدود با credential و فهرست صریح method/header
- نقش‌های immutable و permission matrix در کد
- محافظت از آخرین Owner فعال
- revoke فوری session و API token هنگام disable یا تغییر role
- API token با scope، expiry و نمایش یک‌باره secret
- ثبت login success/failure/rate-limit، logout، refresh، user و token operations در Audit Log
- SQLite با WAL، foreign key، busy timeout و permission فایل `0600`
- ستون‌های migration-safe برای `identity_provider` و `mfa_enabled` و endpoint قابلیت‌ها؛ OIDC/MFA تا زمان پیاده‌سازی کامل fail-closed و غیرفعال گزارش می‌شوند

## سطح دسترسی

| نقش | خلاصه دسترسی |
|---|---|
| Owner | تمام permissionها و مدیریت Owner دیگر |
| Admin | تنظیمات عملیاتی، کاربر، token، audit و backup |
| Operator | عملیات upstream/cache/task و مشاهده audit |
| Developer | مشاهده سامانه و ساخت token محدود برای CI |
| Viewer | فقط مشاهده status، upstream، cache، task و audit |

## APIهای فعال

- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET|POST /api/v1/users`
- `PATCH /api/v1/users/{id}`
- `GET /api/v1/roles`
- `GET|POST /api/v1/tokens`
- `DELETE /api/v1/tokens/{id}`
- `GET /api/v1/audit-events`

## تست و شواهد

- 20 تست Python برای bootstrap، login، cookie، CSRF، refresh، logout، RBAC، last-owner protection، session revoke، token scope، token one-time display و revoke
- Ruff بدون خطا
- TypeScript بدون خطا
- Docker build و اجرای read-only/cap-drop/no-new-privileges موفق
- preview روی `http://localhost:8080` با داده پایدار Gateهای قبل اجرا شد

## موارد تکمیلی پس از Gate 5

- hardening دوره‌ای cleanup برای session/token منقضی‌شده
- تست browser کامل صفحه Access Control پس از ورود
