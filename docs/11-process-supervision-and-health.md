# Process Supervision and Health Contract

## هدف

نسخه نهایی appliance یک کانتینر است، اما چند process مستقل دارد: gateway، control plane، Verdaccio،
devpi، uptime engine، DNS engine و process supervisor. moduleهای جدید فقط از قرارداد manifest اضافه می‌شوند. وجود چند process
داخل کانتینر نباید مدیریت lifecycle، signal یا health را مبهم کند.

## Supervisor

Supervisor پروژه `Supervisor/supervisor` پس از pin و تست سازگاری Python 3.13 استفاده می‌شود.
تنظیمات اجباری:

- `supervisord` در foreground و PID 1؛
- بدون HTTP management listener؛
- Unix control socket فقط در `/data/control-plane/run` با mode `0600`؛
- هر program بدون shell interpolation و با آرایه فرمان ثابت؛
- `stopasgroup=true` و `killasgroup=true`؛
- timeout خاموش‌شدن محدود و ارسال `SIGTERM` پیش از `SIGKILL`؛
- stdout/stderr مستقیم به Docker log stream و بدون فایل log نامحدود؛
- اجرای همه child processها با UID/GID `10001`؛
- عدم restart بی‌نهایت برای خطای configuration؛ خطای پایدار باید container را unhealthy کند.

## ترتیب راه‌اندازی

1. entrypoint فقط schema و دسترسی `/data` را validate می‌کند؛ chown یا migration مخرب ندارد.
2. database/migration core و module manifestها validate می‌شوند.
3. devpi، Verdaccio و moduleهای enabled با dependency order راه‌اندازی می‌شوند.
4. control plane اجرا می‌شود و تا آماده‌شدن dependencyهای ضروری محلی، readiness برابر 503 است.
5. gateway آخرین route snapshot سالم را load می‌کند و سپس admin/public routeها را فعال می‌کند.

## Health semantics

| Probe | معنا | وابستگی به اینترنت |
|---|---|---|
| `/health/live` | process کنترل‌پلین event loop دارد | ندارد |
| `/health/ready` | data writable، Verdaccio و devpi محلی پاسخ می‌دهند | ندارد |
| `/api/v1/system/status` | وضعیت تفصیلی component و upstream | دارد، اما قطع upstream مساوی not-ready نیست |
| `/api/v1/modules` | health/readiness/lifecycle همه moduleها | probe خارجی فقط در deep status |

قطع npmjs/PyPI/Liara نباید readiness را fail کند، چون هدف appliance سرویس‌دهی از cache در
حالت آفلاین است. در این حالت component برابر `degraded` و cache برابر `available` گزارش می‌شود.
خرابی local registry یا unreadable بودن `/data` readiness را 503 می‌کند.

## Failure policy

- یک child process بعد از تعداد محدود retry در وضعیت fatal می‌ماند؛
- healthcheck تجمیعی علت را بدون secret/path داخلی گزارش می‌کند؛
- Docker/Paas درباره restart تصمیم می‌گیرد؛
- هیچ endpoint مدیریتی اجازه اجرای command دلخواه، دسترسی Docker socket یا SSH ندارد.

## Module lifecycle

- desired state فقط `enabled/disabled` و operationهای allowlist‌شده است؛ command خام وجود ندارد.
- restart دستی job پایدار با reason، actor، timeout و verification است.
- retry خودکار exponential backoff با jitter و سقف پنجره‌ای دارد.
- عبور از threshold، module را در `crash-loop` نگه می‌دارد تا Operator علت را بررسی کند.
- migration پیش از supervisor retry اجرا نمی‌شود تا حلقه خراب migration ایجاد نشود.
- health تجمیعی به‌صورت component-level است؛ خرابی optional module کل Appliance را unready نمی‌کند.
- خرابی gateway یا control-plane critical است؛ خرابی npm/PyPI/DNS/uptime فقط route همان module را degraded می‌کند مگر policy deployment خلاف آن باشد.

## Graceful operation

- uptime worker checkهای in-flight را drain یا با lease منقضی تعیین تکلیف می‌کند.
- DNS TCP/DoH connectionها drain می‌شوند؛ UDP drain تضمین‌شدنی نیست و impact در UI نمایش داده می‌شود.
- registry download/upload نیمه‌تمام success ثبت نمی‌شود.
- supervisor پس از stop timeout فقط همان process group را kill می‌کند.
