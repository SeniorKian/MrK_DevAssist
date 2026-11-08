# 23 — ADR: موتورهای بومی برای Uptime، DNS و Docker Registry و بودجه منابع

وضعیت: **پیشنهادی — منتظر تأیید مالک**  
تاریخ: 2026-11-08  
جایگزین: بخش «تصمیم پایه» در `docs/21` و `docs/22` و ردیف‌های Uptime Kuma/Technitium در `docs/02`

## 1. زمینه

هدف محصول یک Appliance کامپکت و بدون وابستگی به سرویس جانبی است. طرح قبلی Uptime Kuma (Node + SQLite
مستقل) و Technitium (runtime دات‌نت + مجوز GPL-3.0) را به‌صورت process داخلی اجرا می‌کرد. این کار:

- دو runtime کامل دیگر (Node دوم و .NET) و حدود چند صد مگابایت به image اضافه می‌کرد؛
- برای هر ماژول دیتابیس، auth و مدل داده جدا می‌ساخت که با Control Plane همگام نمی‌شد؛
- برای Technitium نیاز به Legal Gate، source offer و توزیع GPL داشت؛
- API مدیریتی Uptime Kuma رسماً ناپایدار و داخلی (Socket.IO) است و adapter روی آن شکننده بود.

مالک تصمیم گرفت سازوکار این سرویس‌ها **دقیقاً** و با کد خودمان داخل سیستم پیاده شود و از image، کد یا
ساختار آماده آن‌ها استفاده نشود. هم‌زمان یک ماژول جدید **Docker/OCI Registry** برای کمک به DevOps درخواست شد.

## 2. تصمیم

سه ماژول به‌صورت موتور بومی MRK و clean-room ساخته می‌شوند:

| ماژول | process | مشخصات فنی | مرجع رفتاری |
|---|---|---|---|
| Uptime Monitoring | `uptime-engine` (asyncio) | `docs/24-native-uptime-engine-spec.md` | رفتار Uptime Kuma 2.x (MIT) |
| DNS Management | `dns-engine` (asyncio + uvloop) | `docs/25-native-dns-engine-spec.md` | قابلیت‌های Technitium + RFCها |
| Docker/OCI Registry | `oci-engine` (uvicorn، `127.0.0.1:5000`) | `docs/26-oci-registry-module-spec.md` | OCI Distribution Spec v1.1 |

قواعد مشترک:

- هر سه روی Control Plane موجود سوار می‌شوند: همان users/roles/API token، audit، task queue، secret store،
  upstream store/probe، circuit breaker و الگوی spool-then-verify روتر PyPI.
- داده در PGlite/PostgreSQL مشترک با پیشوند `uptime_*`، `dns_*` و `oci_*`؛ داده باینری زیر
  `/data/modules/<module>`.
- UI هر سه داخل پنل MRK و با i18n فارسی/انگلیسی.
- هر سه پشت Edge Gateway (Gate 11) با route مبتنی بر hostname منتشر می‌شوند.

## 3. قواعد clean-room

- **Technitium (GPL-3.0):** هیچ کدی خوانده، کپی یا ترجمه نمی‌شود. فقط مستندات عمومی، APIDOCS، CHANGELOG و
  RFCها مرجع هستند. موارد نامطمئن با تست black-box روی نسخه رسمی بررسی می‌شوند، نه با خواندن source.
- **Uptime Kuma (MIT):** خواندن source برای استخراج رفتار مجاز است؛ کد کپی نمی‌شود و notice لازم نیست، چون
  پیاده‌سازی مستقل است. نام تجاری، UI و assetها کپی نمی‌شوند.
- **OCI Registry:** پیاده‌سازی مستقیم از روی spec باز OCI؛ هیچ binary از distribution، Harbor، Zot یا Nexus
  در image نیست. Trivy فقط به‌صورت scanner اختیاری بیرونی.
- کتابخانه‌های پایه با مجوز آزاد (dnspython/ISC، cryptography، aioquic/BSD، icmplib/LGPL بدون تغییر) مجازند؛
  این‌ها «ساختار آماده موتور» نیستند و منطق موتور را خودمان می‌نویسیم.

## 4. بودجه منابع (هدف، پیش از پیاده‌سازی با benchmark تأیید شود)

| process | RAM هدف (idle / peak) | CPU | توضیح |
|---|---|---|---|
| control-plane | 120 / 300 MB | 0.5 | فعلی |
| pglite | 150 / 512 MB | 0.5 | heap WASM با حجم داده رشد می‌کند |
| verdaccio | 120 / 400 MB | 0.5 | فعلی |
| devpi + pypi-router | 150 / 400 MB | 0.5 | فعلی |
| uptime-engine | 60 / 200 MB | 0.25 | تا 500 monitor با 60s interval |
| dns-engine | 80 / 300 MB | 0.5 | cache تا 100k رکورد؛ هدف 5k qps |
| oci-engine | 80 / 300 MB | 0.5 | streaming بدون buffer؛ throughput محدود به شبکه |

- سقف کل container پیشنهادی: **2 GB RAM** در حالت کامل. در compose با `mem_limit` و در supervisord با
  محدودیت per-process (cgroup v2 یا `ulimit -v` برای Node/Python) اعمال می‌شود.
- هدف اندازه image: افزایش حداکثر 60 MB نسبت به نسخه فعلی برای هر سه ماژول (فقط کد Python + کتابخانه‌ها).
- خرابی یا پرشدن حافظه یک ماژول نباید بقیه را از کار بیندازد؛ watchdog هر ماژول را جدا restart می‌کند.

## 5. محدودیت‌های container که باید حل شوند

- **ICMP ping** بدون `CAP_NET_RAW`: از socket بدون امتیاز ICMP (`SOCK_DGRAM`) با
  `sysctls: net.ipv4.ping_group_range="0 2147483647"` استفاده می‌شود؛ اجرای `/bin/ping` حذف می‌شود.
- **پورت 53** با UID 10001: `sysctls: net.ipv4.ip_unprivileged_port_start=53` (namespaced، بدون capability).
- **DHCP** نیازمند host network است و تا P2 خارج از scope می‌ماند.
- **Docker monitor** فقط از socket-proxy محدود؛ mount مستقیم Docker socket ممنوع می‌ماند.
- **Registry** نیاز به TLS دارد؛ TLS در Gateway terminate می‌شود و URLهای تولیدی از route config می‌آیند.

## 6. ریسک‌ها

| ریسک | کاهش |
|---|---|
| حجم کار بالا (DNS کامل + DNSSEC + Uptime + Registry) | فازبندی MVP/P1/P2 در هر spec؛ هر فاز Gate مستقل |
| PGlite تک‌اتصالی گلوگاه می‌شود (heartbeat، query log، HEAD های registry) | نوشتن batch، cache داخل process، query log روی فایل چرخشی؛ load test زودهنگام؛ PostgreSQL خارجی برای بار بالا |
| کارایی DNS در CPython | fast-path بایتی برای پاسخ cache؛ benchmark پیش از Gate؛ در صورت نیاز چند worker با `SO_REUSEPORT` |
| خطای storage به‌عنوان DOWN گزارش شود (باگ شناخته‌شده Uptime Kuma) | خطای داخلی هرگز وضعیت monitor را تغییر نمی‌دهد |
| رعایت نشدن clean-room برای Technitium | ثبت منابع هر قابلیت در spec؛ review قبل از merge |

## 7. ترتیب پیشنهادی اجرا

1. Gate 11 — Edge Gateway، route registry و module contract (پیش‌نیاز هر سه).
2. Gate 12 — Uptime MVP (کمترین ریسک، بیشترین استفاده روزانه).
3. Gate 15 — OCI Registry MVP: pull-through با failover بین Docker Hub و mirrorهای داخلی + push خصوصی.
4. Gate 13 — DNS MVP: authoritative + recursive + forwarder + DNSSEC validation.
5. Gate 14 — یکپارچه‌سازی، resource budget، backup/upgrade per-module و sign-off.

## 8. پیامدها

- Legal Gate مربوط به GPL Technitium حذف می‌شود.
- `docs/21`، `docs/22` و ردیف‌های مربوط در `docs/02` و `docs/01` باید با این ADR هم‌راستا شوند.
- non-goal «بازنویسی موتور DNS از صفر» در `docs/01` لغو می‌شود.
- تخمین کار: OCI Registry MVP حدود 7–9 هفته (از `docs/26`)؛ Uptime MVP حدود 4–6 هفته و DNS MVP حدود 8–10
  هفته کار یک مهندس (تخمین اولیه این ADR). همه پس از PoC به‌روزرسانی می‌شوند.
