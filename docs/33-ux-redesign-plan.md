# MRK admin panel: UX redesign plan (Simple for everyone, Advanced for everything)

Status: proposal · Date: 2026-11-08 · Scope: `apps/admin-ui/src/**` + supporting control-plane APIs
Sources audited: every `*.tsx` in `apps/admin-ui/src`, `i18n.ts`, `api.ts`, `uiMode.tsx`, `Dashboard.tsx`; `auth.py`
(`ROLE_PERMISSIONS`), `docs/27`, `docs/28`, `docs/29`, `docs/31`, `docs/32`, `README.md`, module settings code
(`netresolve.py`, `modules/dokploy.py`, `s3engine/settings.py`, `agent/*`, ...).

What the owner asked for: «بخش‌ها و دسترسی‌ها ساده و قابل‌فهم باشند تا هر کسی راحت کار کند؛ هر بخش جدا باشد؛ پنل
آن‌قدر ساده که یک بچه ۵ ساله هم بتواند؛ متن‌های ماشینی حذف شوند؛ بخش پیشرفته کامل باشد و ریزترین تنظیم هر سرویس را داشته باشد.»

Translated into design rules for this plan:

1. **Simple = task-first.** Every screen answers "what can I do here?" with 1–3 big verbs. No codes, no jargon, no English in Persian mode except product names.
2. **Advanced = complete.** Every tunable that exists (runtime or startup) is visible and searchable in one place, with its default, range, unit, source, and whether it needs a restart.
3. **One mental model.** About 7 groups, each one a separate "room". Inside a group, tabs are the separate sections.
4. **Permissions are people-shaped.** Users see role cards that say what someone "can / can't" do. Raw `scope:verb` strings appear only in the Advanced role editor.

---

## Current-state findings (summary)

| # | Finding | Evidence |
|---|---|---|
| F1 | 16 flat nav items today (19 once Gate 19 adds firewall, vuln and dbadmin). They are ordered by when they were built, not by what the user is trying to do. | `Dashboard.tsx:93-110` |
| F2 | "Network & Proxy" is gated by `upstream:read`, but it controls Telegram, email and webhook traffic too. "Monitoring" settings need `agent:write`. A permission's name doesn't match the page it unlocks. | `Dashboard.tsx:98`, docs/27 §9 |
| F3 | Two different pages share one word. «مانیتورینگ» = Observability and «پایش منابع» = Monitoring. «بروزرسانی» is used for both *refresh* and *update panel*, and «آپدیت‌ها» means image updates. | `i18n.ts:12,18,71,121,125` |
| F4 | About 370 Persian strings contain English tokens. "upstream" alone appears **162 times**. Permission IDs (`upstream:write`, `agent:write`, `s3:admin`, ...) are shown to users. | scan of all `labels/copy/text` dicts |
| F5 | Backend English `detail` is appended to Persian errors for 21 "detailed" codes, for 409 and for unknown codes. Raw `error_code`, `last_error` and task IDs are shown in `<code>`. | `api.ts:411,415,419`; `JobsPanel.tsx:242,268`; `ServerPanel.tsx:861,966,983`; `DokployPanel.tsx:311,354,751`; `UpdatesPanel.tsx:286,628`; `NotificationsPanel.tsx:1148`; `ServerBackupsPanel.tsx:895`; `LifecyclePanel.tsx:242` |
| F6 | Audit actions (`user.create`, `s3.bucket.delete`), results (`success`) and role names (`viewer`) are shown raw. | `AccessPanel.tsx:483,527,567,571,591,604`; `Dashboard.tsx:522`; `ObservabilityPanel.tsx:221` |
| F7 | Typed confirmations need Latin phrases (`PRUNE`, `DISCONNECT`, `PURGE pypi/requests`, and `ENFORCE` for the firewall). A Persian-keyboard user has to switch layout. | `DockerTools.tsx:481`, `DokployPanel.tsx:648`, `JobsPanel.tsx:75` |
| F8 | The password rule (6 characters) is hard-coded in the UI and ignores `MRK_PASSWORD_MIN_LENGTH`, `_REQUIRE_DIGITS` and `_REQUIRE_LETTERS`. | `AccessPanel.tsx:306`, `i18n.ts:97` |
| F9 | Advanced mode only expands accordions. Many tunables have no UI at all: dokploy tunables are partial, every env/startup value is missing, the S3 engine has none, notification retry is missing, and the docs/27 §6 "debt" constants are missing. | docs/27 §3, §6; `s3engine/settings.py:49-80` |
| F10 | Each panel owns a private copy dict with duplicated generic words («بروزرسانی», «انصراف», «ذخیره», «ناموفق بود» ×18, «نامعتبر است» ×21, «پذیرفته نشد» ×10). There is no glossary, so terms drift: «بکاپ» ×25 vs «پشتیبان» ×27; «وظیفه» vs «برنامه بکاپ» vs «job». | grep counts |
| F11 | The Overview page is an engineer's status board: "control plane", fallback order, non-root, read-only FS, commit. It has no "what needs me" list and no first-run guidance. | `Dashboard.tsx` overview, `i18n.ts:47-54` |
| F12 | Internal project vocabulary leaks out: "Enabled in the next project gate", «اپلاینس تک‌گره», «کنسول عملیات», «کنترل‌پلین». | `i18n.ts:41/180,113,114,32` |

---

## 1. Information architecture

### 1.1 New top-level groups (7) + utilities

| # | Group (fa / en) | Icon (MUI) | Who sees it (any of) | Sections (tabs) inside | Replaces today |
|---|---|---|---|---|---|
| 1 | **خانه** / Home | `HomeRounded` | everyone | (single page) Needs attention · Quick actions · Getting-started checklist · Health at a glance | overview |
| 2 | **بسته‌ها** / Packages | `Inventory2Rounded` | `cache:read`, `upstream:read`, `system:read` | **جست‌وجو و مدیریت** (search, pin, quarantine, remove, recycle bin, revalidate) · **پیش‌دریافت** (prefetch) · **منابع دریافت** (upstreams, health tests, offline mode, block) · **اتصال پروژه‌ها** (client setup commands and registry addresses: the old "Registries" page) | registries, packages, upstreams |
| 3 | **سرور و برنامه‌ها** / Server & apps | `DnsRounded` | `agent:read`, `metrics:read`, `dokploy:read`, `updates:read`, `db:read` | **نمای سرور** (host summary + containers + logs) · **مصرف منابع** (charts + resource alerts) · **برنامه‌های Dokploy** · **به‌روزرسانی نسخه‌ها** (image updates) · **پایگاه‌های داده** (dbadmin, Gate 19) · **ابزار Docker** (pull/prune; Advanced only) | server, monitoring, dokploy, updates, dbadmin |
| 4 | **فایل‌ها و پشتیبان** / Files & backups | `FolderRounded` | `s3:read`, `backup:server:read`, `backup:read`, `cache:read` | **فضای فایل** (S3 buckets + file manager + access keys + "how to connect") · **پشتیبان برنامه‌ها** (server backups: jobs, runs, destinations) · **پشتیبان پنل** (control-plane backup / validate / restore plan) · **نگهداری فضا** (cleanup preview, integrity check, storage use) | s3Storage, serverBackups, dataAndBackups |
| 5 | **امنیت و اینترنت** / Security & internet | `ShieldRounded` | `firewall:read`, `vuln:read`, `upstream:read` | **دیوار آتش** (firewall, Gate 19) · **بررسی آسیب‌پذیری** (vuln, Gate 19) · **اینترنت و پروکسی** (proxies + "which service uses which proxy") · **DNS و شبکه داخلی** (DNS settings + private-upstream policy; Advanced only) | network, firewall, vuln |
| 6 | **کاربران و دسترسی** / People & access | `GroupRounded` | `user:read`, `token:read`, `audit:read` | **افراد** (users, invite, enable/disable) · **نقش‌ها** (role cards; custom-role editor in Advanced) · **کلیدهای برنامه‌ها** (API tokens) · **ثبت‌نام عمومی** | access |
| 7 | **اعلان‌ها و تاریخچه** / Alerts & history | `NotificationsRounded` | `notification:read`, `task:read`, `audit:read`, `system:read` | **کانال‌های اعلان** (Telegram/Bale/email/webhook) · **قواعد اعلان** · **کارهای در حال انجام** (jobs) · **تاریخچه فعالیت** (audit + export) · **گزارش پشتیبانی** (support bundle, metrics endpoint; Advanced only) | notifications, jobs, observability |

Utilities, outside the 7 groups:

- **Top bar:** search (`Ctrl+K`, jumps to any page/tab/setting) · **activity tray** (spinner with a count of running jobs; opens a mini list; "see all" → Alerts & history › jobs) · **bell** (unacknowledged attention items) · Simple/Advanced switch · language · theme · user menu (profile, change password, my app keys, sign out).
- **⚙ همه تنظیمات / All settings** (nav footer). In Simple mode it shows only "Language, theme, display mode, my password". In Advanced mode it opens the schema-driven registry screen (§4.3). It requires no extra permission to open; each row is read-only unless the user holds that setting's write permission.
- **About / درباره سامانه** (footer link): version, commit, environment, components. This is the "engineer" data moved out of Home.

Merges and renames:

- *Registries* → becomes the tab "Connect your projects" under Packages (its content is mostly copy-paste commands and ports).
- *Upstreams* → "Package sources" tab. *Network & proxy* moves out of Packages to Security & internet, because it serves every outbound service.
- *Monitoring* and *Observability* split cleanly. Host/container charts go to Server › Resource use. Audit, jobs and support bundle go to Alerts & history.
- *Data & backups* (lifecycle) + *Server backups* + *S3* → one Files & backups group. Cleanup and integrity become "Keep storage healthy".
- *Jobs* stops being a primary destination. Its live state goes in the top-bar tray, and it gets a full list under Alerts & history.

Routing: keep hash routing. Use `#/<group>/<tab>` (`#/packages/sources`, `#/server/apps`) and keep the old hashes (`#upstreams`, `#s3`, ...) as redirects in a `LEGACY_ROUTES` map so bookmarks keep working. The nav config moves to `nav.ts` (data only), so permission gating and tab order are declared in one file:

```ts
type NavTab = { key: string; label: MessageKey; anyOf: string[]; advancedOnly?: boolean; load: () => Promise<...> };
type NavGroup = { key: GroupKey; label: MessageKey; icon: SvgIconComponent; tabs: NavTab[] }; // group visible if any tab visible
```

### 1.2 Home (خانه): "only what needs you"

Layout, top to bottom:

1. **Greeting + one-line verdict.** For example «سلام مریم، همه‌چیز رو به‌راه است ✓» or «۲ مورد به توجه شما نیاز دارد». It is green, amber or red, and it is never a percentage or a component name.
2. **Needs attention (توجه لازم)**. A list of `AttentionItem {severity, title, why, action:{label, route|handler}}`, sorted by severity and hidden entirely when empty. Each item is one sentence plus one button. Initial rules (client-side aggregation in phase 1, backend `/api/v1/home/summary` in phase 3):

   | Trigger (source) | Title (fa) | Button |
   |---|---|---|
   | a component `unavailable` (`/api/v1/system/status`) | «دریافت بسته‌های npm از کار افتاده» | «بررسی» → Packages › sources |
   | disk ≥ alert threshold (`storage.used_percent`, monitoring `disk_percent`) | «فضای دیسک رو به اتمام است (۸۷٪)» | «آزاد کردن فضا» → Files › keep healthy |
   | all upstreams of an ecosystem failing/blocked | «منبع دریافت PyPI جواب نمی‌دهد» | «امتحان دوباره» |
   | ecosystem offline mode on | «npm در حالت بدون اینترنت است» | «روشن کردن اینترنت» |
   | Agent not paired / unreachable | «دستیار سرور وصل نیست» | «وصل کردن» (wizard) |
   | last server-backup run failed, or no successful run in 2× its schedule | «پشتیبان "DB اصلی" دیشب انجام نشد» | «دوباره اجرا کن» |
   | no backup job at all (and `backup:server:write`) | «هنوز از برنامه‌ها پشتیبان نمی‌گیرید» | «ساخت پشتیبان» |
   | `update.available` count > 0 | «برای ۳ برنامه نسخه جدید آمده» | «دیدن» |
   | vuln critical/high count > 0 | «۲ مشکل امنیتی جدی در برنامه‌ها پیدا شد» | «دیدن» |
   | firewall `dry_run` for > 7 days | «دیوار آتش فقط در حال تمرین است» | «فعال کردن» |
   | no notification channel | «اگر مشکلی پیش بیاید خبردار نمی‌شوید» | «افزودن تلگرام/بله» |
   | failed jobs in last 24 h | «۱ کار ناتمام ماند» | «جزئیات» |
   | S3 `public_endpoint` not configured while buckets exist | «آدرس عمومی فضای فایل تنظیم نشده» | «تنظیم» |

3. **Quick actions** (big tiles, 2×3 grid, filtered by permission): «وصل کردن یک پروژه» (copy npm/pip command) · «جست‌وجوی بسته» · «پشتیبان‌گیری همین حالا» · «دعوت همکار» · «بررسی نسخه‌های جدید» · «دیدن مصرف سرور».
4. **Getting-started checklist** (راه‌اندازی در ۶ قدم). It is shown until done or dismissed, and progress is stored server-side per user in phase 3 (localStorage in phase 1). Steps: ✓ owner account → connect your first project (npm/pip) → add a notification channel → connect the server helper (Agent) → create the first backup → invite a teammate → (optional) set the public address / domain. Each step links into a wizard, not just a page.
5. **At a glance:** 3 small cards: «بسته‌ها» (npm/PyPI ready ✓, cached count, size), «سرور» (CPU/RAM/disk mini bars), «پشتیبان» (last success, relative time). Advanced mode adds "Recent activity" (humanized audit) and the old service-health grid.

Moved off Home: security posture (non-root/read-only FS go to About), commit/env (About), fallback order (Packages › sources).

### 1.3 Mobile layout (< 600 px)

- **Bottom navigation bar** with 5 slots: Home · Packages · Server · Files · «بیشتر» (More opens a sheet with Security, People, Alerts, Settings). The bar order follows RTL.
- Group tabs become a horizontally scrollable `Tabs variant="scrollable"` under a sticky compact `PageHeader`. The primary page action is a full-width sticky bottom button (above the bottom nav), not a header icon.
- Every table becomes a card list through a `ResponsiveList` (`DataListResponsive`) component: title, 1–2 meta lines, a status pill, and a `⋮` menu.
- Dialogs open full-screen (`fullScreen={isXs}`). Wizards use one step per screen with "Back / Next" at the bottom.
- Touch targets ≥ 44 px. Charts get a 24h/7d segmented control and no hover-only data.
- The top bar shrinks to: menu-less title · activity tray · bell · avatar. The mode, language and theme switches move to the avatar menu.

---

## 2. Plain-Persian writing guide (راهنمای نگارش)

### 2.1 Voice and tone
- Talk like a calm, competent colleague. Use the polite-informal register: «پشتیبان گرفته شد», «می‌خواهید ادامه دهید؟». Avoid stiff officialese («عملیات با موفقیت انجام گردید»).
- **Say what happened, why it matters, and what to do next.** Never just "failed".
- Short sentences: one idea per sentence, ≤ 15 words in Simple mode. Put details behind «چرا؟» or a HelpTip.
- Write in the active voice and name the subject: «MRK نتوانست به Dokploy وصل شود», not «اتصال برقرار نشد».
- Never blame the user. Write «این نام قبلاً گرفته شده؛ نام دیگری بنویسید», not «ورودی نامعتبر است».
- No internal project words: gate, control plane, appliance, snapshot, envelope, RBAC, payload, seed.

### 2.2 Words to use / avoid (generic)

| Avoid | Use | Note |
|---|---|---|
| عملیات انجام نشد / ناموفق بود | «نشد» + reason + next step: «ذخیره نشد؛ اینترنت سرور را بررسی کنید» | ban bare «ناموفق بود» |
| نامعتبر است / پذیرفته نشد | «باید … باشد» (state the rule): «پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد» | |
| بروزرسانی (for refresh) | **تازه کردن** (refresh) · **به‌روزرسانی** (update to a new version only) | fixes F3 |
| مجوز X:Y لازم است | «این کار فقط از دست «مدیر» برمی‌آید. از {owner} بخواهید.» | name the role, not the scope |
| در صف قرار گرفت: {id} | «شروع شد؛ پیشرفت را بالای صفحه ببینید» | IDs only in Advanced |
| وظیفه / job | **کار** (a background job) · **برنامه پشتیبان** (a backup schedule) | |
| بکاپ / Backup | **پشتیبان** everywhere (verb: «پشتیبان گرفتن») | one term |
| مانیتورینگ / پایش | **مصرف منابع** (charts) · **تاریخچه فعالیت** (audit) | |
| تست | **امتحان اتصال** / «امتحان کن» | |
| حذف دائمی | «پاک کردن برای همیشه» | |
| فعال/غیرفعال‌سازی | «روشن / خاموش» for features · «فعال / غیرفعال» for accounts | |
| ری‌استارت | «راه‌اندازی دوباره» | |
| کانفیگ / پیکربندی | «تنظیم» | |

### 2.3 Errors (no codes in Simple mode)
- Pattern: **[What happened] + [likely reason] + [one action button]**. For example: «به Dokploy وصل نشدیم. کلید دسترسی دیگر معتبر نیست.» [ساخت کلید جدید]
- Do not show `error_code`, HTTP status, request ID or backend `detail` in Simple mode. In Advanced mode they sit in a collapsed «جزئیات فنی» row (LTR `<code>`, with a copy button) so support can use them.
- Validation errors attach to the field (`helperText`), not a page-level Alert. This needs `error.field` from the backend (§7, BE4).
- Never concatenate the backend English `detail` into a Persian sentence (fixes `api.ts:411,415,419`). An unknown code falls back to «کاری که خواستید انجام نشد. دوباره امتحان کنید؛ اگر تکرار شد، جزئیات فنی را برای پشتیبانی بفرستید.»
- For network or server down: «سرور MRK جواب نمی‌دهد. اتصال اینترنت خودتان را بررسی کنید و چند لحظه بعد دوباره امتحان کنید.»

### 2.4 Numbers, units, dates
- In fa mode, digits are always Persian (`formatNumber`), including inside sentences, with the Persian thousands separator «٬». Codes, paths, URLs, hostnames and commands stay Latin and LTR inside `<bdi dir="ltr">`.
- Sizes: «۱٫۲ گیگابایت», «۳۵۰ مگابایت». Never "MiB/GiB" in Simple mode (show binary units only in Advanced).
- Durations: speak in human units: «۵ دقیقه», «۷ روز», «۸ ساعت» (not `28800`). Settings inputs take a number + a unit select.
- Dates: relative for recent events («۱۰ دقیقه پیش», «دیروز ساعت ۲۳:۱۰»), absolute Jalali in tooltips (`Intl` `fa-IR-u-ca-persian`). Advanced tables show absolute times.
- Percent: «۸۷٪». Thresholds read as «وقتی بیشتر از ۹۰٪ شد».
- Schedules: never show raw cron in Simple mode. Write «هر شب ساعت ۲»; the cron string appears only in Advanced "Custom".

### 2.5 Buttons and links
- Buttons are verbs naming the result: «ساخت پشتیبان», «وصل کن», «پاک کن», «ذخیره», «امتحان اتصال». Avoid «تأیید», «ارسال» and «OK» except in a generic confirm.
- One primary button per view. Destructive buttons are red and are never the default focus.
- In-progress label: «در حال ساخت…». Success toast: past tense + object: «پشتیبان "DB اصلی" ساخته شد».

### 2.6 Empty states
- Pattern: icon + «هنوز … ندارید» + one sentence on why it helps + primary button. For example: «هنوز کانال اعلانی ندارید. با افزودن تلگرام، اگر سرور مشکلی پیدا کند فوراً خبردار می‌شوید.» [افزودن تلگرام]
- Never write «داده‌ای یافت نشد» on its own. For search results: «چیزی با «react» پیدا نشد. املای نام را بررسی کنید یا آن را پیش‌دریافت کنید.»

### 2.7 Confirmations
- Title as a question with the object: «پشتیبان "DB اصلی" پاک شود؟». Body: what will happen, whether it can be undone, and who is affected. Buttons: «بله، پاک کن» / «نه، بماند».
- Severity ladder: (1) reversible → no confirm, offer an undo snackbar; (2) disruptive → simple confirm; (3) destructive or irreversible → typed confirm.
- **Typed confirmations use something the user can type in any keyboard**: the object's own name, or the Persian word «پاک کن» / «تأیید». The client maps it to the backend token (`PRUNE`, `DISCONNECT`, `ENFORCE`, `PURGE eco/name`). Typing is the safety step; the token is a transport detail. Keep the English token accepted for EN mode.

### 2.8 Glossary (technical → plain Persian)

Rule for English in parentheses: put the English term in parentheses **only the first time it appears on a page**, and only when the user may need to recognize it elsewhere (in an external tool, docs, or a CLI). Never parenthesize in buttons or status pills. In Advanced mode, setting rows always show the technical key (LTR, muted) under the plain name.

| Technical | Plain Persian (Simple) | Keep English in ( )? | Short explanation for HelpTip |
|---|---|---|---|
| upstream | **منبع دریافت** | yes, on the sources tab | جایی که MRK بسته‌ها را از آن می‌گیرد (مثل سایت اصلی npm) |
| registry (npm/PyPI) | **مخزن بسته** | first use | سرویسی که برنامه‌نویس‌ها بسته‌ها را از آن نصب می‌کنند |
| container registry / image registry | **مخزن نسخه‌های برنامه** (Docker Hub) | yes | |
| mirror | **نسخه آینه** / «منبع جایگزین نزدیک» | yes | کپی نزدیک‌تر یک مخزن که سریع‌تر جواب می‌دهد |
| cache | **ذخیره محلی** / «بسته‌های ذخیره‌شده» | no | |
| offline mode | **حالت بدون اینترنت** | no | |
| fallback | **جایگزین** («اگر اولی جواب نداد») | no | |
| priority | **ترتیب** | no | |
| proxy | **پروکسی** (familiar to Iranian users) | no | راه واسطه‌ای که ارتباط اینترنتی از آن عبور می‌کند |
| SOCKS5 / SOCKS5h / HTTP proxy types | «پروکسی SOCKS (نام‌ها را خود پروکسی پیدا می‌کند)» | type names stay Latin | |
| no_proxy | «بدون پروکسی برای این آدرس‌ها» | no | |
| DNS | **DNS (دفترچه تلفن اینترنت)** | keep "DNS" | |
| resolve | «پیدا کردن آدرس» | no | |
| endpoint | **آدرس** | Advanced only | |
| public endpoint | **آدرس عمومی** | first use | |
| bucket | **پوشه اصلی** / «سطل» → use **پوشه اصلی (باکت)** | yes, first use | |
| object / key (S3) | **فایل** / **مسیر فایل** | no | |
| access key / secret key | **کلید دسترسی** + **رمز کلید** | yes, first use (`Access Key`) | |
| identity (S3 user) | **کاربر فضای فایل** | no | |
| policy | **سطح دسترسی** (templates: «فقط خواندن», «خواندن و نوشتن», «مدیر», «برای پشتیبان‌گیری») | "policy" only in Advanced JSON | |
| quota | **سقف حجم** | no | |
| presigned link | **لینک اشتراک موقت** | no | |
| prune | **پاک‌سازی موارد بی‌استفاده** | no | |
| purge | **پاک کردن از ذخیره محلی** | no | |
| quarantine | **قرنطینه** (= «مسدود موقت برای همه») | no | |
| pin | **نگه‌داشتن** («هیچ‌وقت پاک نشود») | no | |
| revalidate | **دریافت دوباره از منبع** | no | |
| prefetch | **پیش‌دریافت** | no | |
| artifact | **فایل بسته** | no | |
| digest | **شناسه نسخه** | Advanced shows `sha256:` | |
| image | **نسخه برنامه (ایمیج)** | yes, first use | |
| tag | **برچسب نسخه** | no | |
| container | **کانتینر** (familiar) | no | |
| volume | **فضای داده کانتینر** | yes (Volume) | |
| deploy / redeploy | **انتشار** / «انتشار دوباره» | no | |
| host | **سرور** | no | |
| Host Agent | **دستیار سرور** | first use (Agent) | برنامه کوچکی کنار سرور که اطلاعات و کنترل Docker را به پنل می‌دهد |
| pairing key | **کد اتصال** | no | |
| token (API token) | **کلید برنامه** | first use (API token) | برای اسکریپت‌ها و CI؛ مثل رمز است |
| scope | **اجازه‌ها** | Advanced only | |
| role | **نقش** | no | |
| permission | **اجازه** | Advanced keys | |
| session | **ورود** («از همه دستگاه‌ها خارج شود») | no | |
| CSRF / session security token | never shown → «صفحه کهنه شده؛ یک بار صفحه را تازه کنید» | never | |
| audit log | **تاریخچه فعالیت** | no | |
| support bundle | **بسته گزارش برای پشتیبانی** | no | |
| metrics / scrape | **آمار** / «خواندن آمار با Prometheus» | Advanced | |
| job / task | **کار** | no | |
| schedule / cron | **زمان‌بندی** («هر شب ساعت ۲») | cron in Advanced | |
| retention | **مدت نگه‌داری** / «چند نسخه بماند» | no | |
| passphrase | **رمز پشتیبان** | no | |
| restore | **بازگردانی** | no | |
| dry run | **حالت تمرین** («فقط ثبت می‌کند، چیزی را نمی‌بندد») | no | |
| enforce | **حالت فعال** | no | |
| allowlist | **فهرست همیشه مجاز** | no | |
| ban / block | **مسدود کردن** | no | |
| CIDR | «محدوده IP» (with example) | CIDR in Advanced | |
| vulnerability / CVE | **مشکل امنیتی** («CVE-…» link in Advanced) | yes | |
| severity | **شدت** (بحرانی، زیاد، متوسط، کم) | no | |
| webhook | **وب‌هوک** (ارسال خودکار به یک آدرس) | keep | |
| chat id | **شناسه گفتگو** | no | |
| quiet hours | **ساعات سکوت** | no | |
| dedupe | «پیام تکراری فرستاده نشود» | no | |
| rate limit | «محدودیت تعداد درخواست» | no | |
| timeout | **حداکثر زمان انتظار** | no | |
| latency | **زمان پاسخ** | no | |
| TLS / HTTPS | «اتصال امن» | keep TLS in Advanced | |
| reverse proxy | «سرور جلویی (مثل Traefik)» | yes | |
| control plane | **سرور MRK** / «پنل» | never | |
| environment variable / env | **تنظیم شروع سرویس** (در فایل Compose) | Advanced shows `MRK_*` | |
| restart required | «پس از راه‌اندازی دوباره اعمال می‌شود» | no | |

Product and brand names (npm, PyPI, Docker, Dokploy, Telegram→«تلگرام», Bale→«بله», Gmail, Traefik, restic, rclone) stay as they are. Telegram and Bale are written in Persian.

---

## 3. Machine-like texts found in current code (with rewrites)

Legend: **L** = English leaking in fa · **J** = jargon in Simple mode · **C** = raw code/ID shown · **T** = translated-sounding/stiff · **I** = inconsistent term · **P** = permission ID shown.
All line numbers are in `apps/admin-ui/src/`.

### 3.1 Global (i18n.ts, api.ts, Dashboard.tsx)

| Location | Type | Current | Proposed fa | Proposed en |
|---|---|---|---|---|
| i18n.ts:5–6 | J | product «MRK Package Mirror» / «مرکز عملیات رجیستری‌ها» | «MRK» / «مدیریت سرور و بسته‌ها» | "MRK" / "Server & package manager" |
| i18n.ts:7 / 146 | I | «نمای کلی» / Overview | «خانه» | Home |
| i18n.ts:10 | L/J | «منابع بالادستی» | «منابع دریافت» | Package sources |
| i18n.ts:11 | I | «وظایف» | «کارها» | Jobs → "Background jobs" |
| i18n.ts:12 | I | observability «مانیتورینگ» | «تاریخچه و گزارش‌ها» | History & reports |
| i18n.ts:17 | T | «وضعیت زنده، ظرفیت ذخیره‌سازی و مسیرهای دریافت پکیج را از یک نقطه کنترل کنید.» | «چیزهایی که امروز به شما نیاز دارند، این‌جاست.» | "Here's what needs you today." |
| i18n.ts:18–20 | I | «بروزرسانی» (refresh) | «تازه کردن» / «در حال تازه کردن» / «آخرین بار:» | Refresh / Refreshing / Updated |
| i18n.ts:23 | T | «نیازمند بررسی» | «نیاز به توجه» | Needs attention |
| i18n.ts:28 | L | «مسیر سرویس‌دهی و ترتیب fallback هر اکوسیستم» | «هر مخزن بسته‌ها را به این ترتیب از منابع می‌گیرد» | "Where each registry gets packages, in order" |
| i18n.ts:31 | T | «پیکربندی نشده» | «هنوز تنظیم نشده» | Not set up yet |
| i18n.ts:32 / 171 | J | «کنترل‌پلین» / Control plane | «سرور MRK» | MRK server |
| i18n.ts:36 | J | «کش آفلاین» | «ذخیره محلی» | Local copies |
| i18n.ts:41 / 180 | J | «در مرحله‌ی بعدی پروژه فعال می‌شود» / "Enabled in the next project gate" | «به‌زودی» | Coming soon |
| i18n.ts:43 / 182 | L/J | «فضای واقعی فایل‌سیستم متصل به /data» | «فضای دیسکی که MRK استفاده می‌کند» (path → Advanced) | "Disk space used by MRK" |
| i18n.ts:48 | J | «آخرین پاسخ مستقیم کنترل‌پلین» | (remove; Advanced only) | — |
| i18n.ts:49–54 | J/L | «اجرای غیر root», «فایل‌سیستم فقط‌خواندنی», «بدون افزایش دسترسی» | move to About; rename «محافظت‌های داخلی سرویس» | "Built-in protections" |
| i18n.ts:56 | T | «آدرس‌ها از دامنه‌ی فعلی پنل استخراج شده‌اند؛ …» | «این آدرس‌ها از آدرس همین پنل ساخته شده‌اند. اگر مخزن‌ها دامنه جدا دارند، آن را جایگزین کنید.» | |
| i18n.ts:62 | P/T | «برای مشاهده‌ی رویدادها به مجوز لاگ ممیزی نیاز دارید.» | «دیدن تاریخچه فعالیت فقط برای مدیرها و مسئولان است.» | "Only admins and operators can see activity history." |
| i18n.ts:66 / 205 | J | «ارتباط با کنترل‌پلین برقرار نشد.» | «سرور MRK جواب نمی‌دهد. چند لحظه بعد دوباره امتحان کنید.» | "MRK isn't responding. Try again in a moment." |
| i18n.ts:69–71 | I | «نسخه‌ی جدید پنل آماده است» / «بروزرسانی پنل» | «نسخه تازه پنل آماده است» / «بارگذاری نسخه تازه» | "A new version of the panel is ready" / "Reload" |
| i18n.ts:97 | bug | «حداقل ۶ کاراکتر، شامل حرف و عدد.» (hard-coded) | generate from server password policy: «دست‌کم {n} نویسه، با حرف و عدد» | |
| i18n.ts:99 | L | «ذخیره‌سازی روی volume شما» | «اطلاعات روی دیسک خودتان می‌ماند» | "Your data stays on your disk" |
| i18n.ts:100 | T | «آماده توسعه ماژول‌های مدیریتی» | «هر وقت خواستید بخش تازه اضافه کنید» or drop | drop |
| i18n.ts:102 | L | «…با دسترسی مشاهده‌گر ساخته می‌شود.» | «…حساب تازه فقط می‌تواند ببیند و چیزی را تغییر نمی‌دهد.» | |
| i18n.ts:113–114 | J | «کنسول عملیات» / «اپلاینس تک‌گره» | drop both | drop |
| i18n.ts:120–125 | I | «سرور», «پایش منابع», «شبکه و پروکسی», «ذخیره‌ساز S3», «بکاپ سرور», «آپدیت‌ها» | per §1.1: «نمای سرور», «مصرف منابع», «اینترنت و پروکسی», «فضای فایل», «پشتیبان برنامه‌ها», «به‌روزرسانی نسخه‌ها» | |
| i18n.ts:133 | T | «برای تأیید، این عبارت را دقیقاً وارد کنید:» | «برای اطمینان، {phrase} را بنویسید:» | "To be sure, type {phrase}:" |
| i18n.ts:136 | L | «مسیریاب upstream پای‌پای» | «مسیریاب PyPI» (Advanced only) | "PyPI router" |
| i18n.ts:141 | J | «…در یک کنترل‌پلین امن و قابل توسعه.» | «همه کارهای سرور و بسته‌ها، در یک پنل ساده و امن.» | |
| api.ts:186 | J | «ارتباط با کنترل‌پلین برقرار نشد…» | «سرور MRK جواب نمی‌دهد. اتصال اینترنت خود را بررسی کنید.» | |
| api.ts:188 | P/T | «نقش شما اجازه این عملیات را ندارد.» | «نقش شما اجازه این کار را ندارد. از {یک مدیر} بخواهید.» | |
| api.ts:190 | T | «این عملیات با وضعیت فعلی سازگار نیست.» | «الان نمی‌شود؛ چیزی هم‌زمان تغییر کرده. صفحه را تازه کنید و دوباره امتحان کنید.» | |
| api.ts:192 | J | «خطای داخلی سرور رخ داد؛ لاگ‌ها را بررسی کنید.» | «مشکلی در سرور پیش آمد. دوباره امتحان کنید؛ اگر تکرار شد جزئیات فنی را برای پشتیبانی بفرستید.» | |
| api.ts:193 | T | «عملیات انجام نشد.» | «کاری که خواستید انجام نشد. دوباره امتحان کنید.» | |
| api.ts:194 | J | csrf «توکن امنیتی نشست معتبر نیست…» | «این صفحه کهنه شده. یک بار صفحه را تازه کنید.» | "This page is out of date. Please reload it." |
| api.ts:195 | T | «برخی مقادیر واردشده نامعتبر یا خارج از محدوده مجاز است.» | per-field message; fallback «چند خانه را باید درست کنید (با رنگ قرمز مشخص شده‌اند).» | |
| api.ts:196–197 | L | «تنظیمات upstream پذیرفته نشد», «حذف این upstream امن نیست (…)» | «این منبع ذخیره نشد: {reason_fa}», «این آخرین منبع فعال npm است؛ اول یک منبع دیگر اضافه کنید.» | |
| api.ts:199 | J | «اعتبارنامه نامعتبر است» | «نام کاربری یا رمز این منبع درست نیست.» | |
| api.ts:200 | J | «اکوسیستم پشتیبانی نمی‌شود.» | «فقط npm و PyPI پشتیبانی می‌شوند.» | |
| api.ts:204 | J | «توکن ساخته نشد» | «کلید برنامه ساخته نشد: {reason}» | |
| api.ts:207–208 | L | «Backup اعتبارسنجی نشد؛ passphrase…», «Restore plan ساخته نشد…» | «فایل پشتیبان باز نشد. رمز پشتیبان یا خود فایل را بررسی کنید.» / «آماده‌سازی بازگردانی انجام نشد. رمز پشتیبان و عبارت تأیید را بررسی کنید.» | |
| api.ts:214–217 | L/J | «Host Agent هنوز متصل (pair) نشده است.» … «سرویس mrk-agent را بررسی کنید» | «دستیار سرور هنوز وصل نشده.» [وصل کردن] / «دستیار سرور جواب نمی‌دهد؛ مطمئن شوید روی سرور روشن است.» / «اتصال دستیار از فایل Compose تنظیم شده و از این‌جا عوض نمی‌شود.» | |
| api.ts:220 | L | «Dokploy کلید API را نپذیرفت…» | «Dokploy این کلید را قبول نکرد. در Dokploy یک کلید تازه بسازید و این‌جا بگذارید.» | |
| api.ts:223 | T/L | plan_changed «وضعیت Docker پس از پیش‌نمایش تغییر کرد…» | «از وقتی فهرست را دیدید چیزهایی عوض شده. فهرست تازه را یک بار دیگر ببینید.» | |
| api.ts:226, 280 | L | «مرجع image نامعتبر است (مثال: …)» | «نام نسخه برنامه درست نیست. مثل nginx:1.27 بنویسید.» | |
| api.ts:228–239 | L | proxy type / host / npm-only-http / email-only-socks | «npm فقط با پروکسی HTTP یا HTTPS کار می‌کند؛ پروکسی دیگری انتخاب کنید.» etc. | |
| api.ts:247 | L | «…(پوشه سرور با دسترسی ro).» | «این پوشه فقط‌خواندنی است؛ نمی‌شود در آن فایل گذاشت.» | |
| api.ts:253 | L | «سیاست (policy) پذیرفته نشد» | «سطح دسترسی ذخیره نشد: {reason_fa}» | |
| api.ts:255 | L | «پسوند virtual-host نامعتبر است.» | (Advanced) «پسوند دامنه باید مثل s3.example.com باشد.» | |
| api.ts:262 | L | «مسیر پوشه مجاز نیست (فقط زیر ‎/mnt/links).» | «فقط پوشه‌هایی که زیر {root} به MRK داده شده‌اند قابل اتصال‌اند.» | |
| api.ts:270 | L | «زمان‌بندی (cron) نامعتبر است.» | «زمان‌بندی را نفهمیدیم. یکی از گزینه‌های آماده را انتخاب کنید.» | |
| api.ts:271–276 | T | «تنظیمات نگه‌داری نامعتبر است», «خواندن منبع بکاپ ناموفق بود», «S3 کلید دسترسی را نپذیرفت.» | «تعداد یا مدت نگه‌داری باید عدد مثبت باشد.» / «MRK نتوانست از {source} پشتیبان بخواند.» / «فضای فایل مقصد این کلید را قبول نکرد.» | |
| api.ts:411, 415, 419 | C/L | append backend English `detail` (`${known}: ${error.detail}`, `(${error.detail})`, `error.detail ‖ generic`) | never append in fa; map `detail` → `reason_fa` via a backend `hint_key`; raw detail → Advanced «جزئیات فنی» | |
| api.ts:143 | C | `HTTP ${status}` fallback message | localized generic | |
| Dashboard.tsx:522 | C | audit `item.action` (`user.create`) + `item.result` (`success`) | humanized sentence: «مریم یک کاربر تازه ساخت · ۵ دقیقه پیش» (action catalog, §6 `humanizeAudit`) | |

### 3.2 Per panel (selected; all similar occurrences follow the same rule)

| Location | Type | Current fa | Proposed fa | Proposed en |
|---|---|---|---|---|
| AccessPanel.tsx:81 | L | «توکن‌های API خود و کاربران سیستم را مدیریت کنید.» | «چه کسی وارد شود و چه کاری بکند.» | "Who can sign in, and what they can do." |
| AccessPanel.tsx:108–109 | L/J | «توکن‌های API من» / «برای CI، اسکریپت‌ها یا scrape کردن metrics…» | «کلیدهای برنامه من» / «برای اسکریپت‌ها و ابزارهای خودکار که باید بدون رمز شما وارد شوند.» | "My app keys" |
| AccessPanel.tsx:133, 135 | L | «…همه توکن‌های API فعال او لغو می‌شوند.» | «…از همه دستگاه‌ها خارج می‌شود و کلیدهای برنامه‌اش از کار می‌افتند.» | |
| AccessPanel.tsx:142, 145 | L | «…با نقش viewer ساخته می‌شوند», «…حساب viewer بسازد و … upstreamها …» | «…فقط می‌توانند ببینند (نقش «بیننده»).» / «هر کسی که به این پنل دسترسی دارد می‌تواند حسابی بسازد که فقط وضعیت و بسته‌ها را می‌بیند.» | |
| AccessPanel.tsx:147, 460 | P | «دامنه دسترسی»: `system:read · upstream:read …` | Simple: «فقط دیدن»; Advanced: chips with plain names (§5) | |
| AccessPanel.tsx:483, 527, 567, 571, 591 | C | role `item.name` / `item.role` raw (`viewer`, `operator`) | role card label «بیننده», «مسئول روزانه» … | |
| AccessPanel.tsx:604 | C | audit `item.action`, `item.result` raw | humanized (see Dashboard) | |
| ContainerLogsDialog.tsx:68 | P/L | «…Agent آفلاین باشد، دسترسی logs:read نداشته باشید…» | «لاگ زنده باز نشد. شاید دستیار سرور خاموش باشد یا نقش شما اجازه دیدن لاگ نداشته باشد.» | |
| ContainerLogsDialog.tsx:70 | L | «مشاهده لاگ در audit ثبت می‌شود و secretها پیش از نمایش پوشانده می‌شوند.» | «دیدن لاگ در تاریخچه ثبت می‌شود. رمزها پیش از نمایش پنهان می‌شوند.» | |
| DnsSettingsCard.tsx:36–37 | L | «DNS ارتباط با upstreamها» / «…resolve شوند…» | «DNS برای منابع دریافت» / «MRK آدرس منابع را با کدام DNS پیدا کند. تغییر فوراً اعمال می‌شود.» | |
| DnsSettingsCard.tsx:54 | L | «resolve ناموفق بود؛ هیچ آدرسی برگردانده نشد.» | «آدرسی برای این نام پیدا نشد.» | |
| DnsSettingsCard.tsx:56 | J | «…Verdaccio (npm) از DNS کانتینر…؛ … گزینه dns در Compose…» | «این تنظیم روی npm اثر ندارد؛ برای npm باید DNS را در فایل Compose عوض کنید.» [راهنما] | |
| DnsSettingsCard.tsx:57; NetworkPanel.tsx:59; UpstreamPolicyCard.tsx:20 | P | «…دسترسی upstream:write لازم است.» | «فقط «مدیر» می‌تواند این را عوض کند.» | |
| DockerTools.tsx:46 | L/T | «…{action} آن می‌تواند Dokploy، Traefik … از کار بیندازد … در audit ثبت می‌شود.» | «این کانتینر مال Dokploy است. اگر خاموشش کنید ممکن است برنامه‌ها یا سایت‌ها از دسترس خارج شوند. فقط اگر مطمئنید ادامه دهید.» | |
| DockerTools.tsx:48–55 | L | «دریافت Image», «…image را … pull می‌کند», «مرجع image» | «دریافت نسخه برنامه», «یک نسخه برنامه را روی سرور دانلود می‌کند؛ چیزی را اجرا یا عوض نمی‌کند.», «نام نسخه» | |
| DockerTools.tsx:60–68 | L/J | «Volumeها هرگز حذف نمی‌شوند…», «فقط بدون تگ (dangling)», «همه imageهای بی‌استفاده» | «فضای داده کانتینرها هیچ‌وقت پاک نمی‌شود…», «فقط نسخه‌های بی‌نام», «همه نسخه‌هایی که استفاده نمی‌شوند» | |
| DockerTools.tsx:481 | C | typed phrase `PRUNE` | type «پاک کن» (client sends `PRUNE`) | |
| DokployPanel.tsx:68 | L | «…ببینید و deploy کنید؛ فقط از طریق API رسمی Dokploy.» | «برنامه‌های Dokploy را ببینید و منتشر کنید.» | |
| DokployPanel.tsx:70; ServerPanel.tsx:94 | J | «ماژول … هنوز روی این نسخه سرور در دسترس نیست.» | «این بخش روی نسخه فعلی سرور نیست. MRK را به‌روز کنید.» | |
| DokployPanel.tsx:82 | P | «…به دسترسی dokploy:write نیاز دارد…» | «فقط «مدیر» می‌تواند Dokploy را وصل کند.» | |
| DokployPanel.tsx:89–99, 105–107 | L | «آخرین deploy», «هنوز deploy نشده», «تاریخچه deploy», «Deploy کامل…», «درخواست «{action}» … ارسال شد» | «آخرین انتشار», «هنوز منتشر نشده», «تاریخچه انتشار», «انتشار کامل (از اول ساخته می‌شود)», «{name} در حال انتشار است» | |
| DokployPanel.tsx:128 | J | «…(rate limit) و cache می‌شوند…» | Advanced only | |
| DokployPanel.tsx:311, 354, 751 | C | `HTTP ${status}`, `({error_code})`, `last_error` in `<code>` | sentence + Advanced «جزئیات فنی» | |
| DokployPanel.tsx:648 | C | typed `DISCONNECT` | type «قطع کن» | |
| JobsPanel.tsx:73–77 | C/L | «…(مثلاً PURGE pypi/requests)», «وظیفه دوباره در صف قرار گرفت: {id}» | «برای اطمینان، نام بسته (requests) را بنویسید.» / «دوباره شروع شد.» | |
| JobsPanel.tsx:242, 264, 268 | C | task `id`, `retry_of`, «کد خطا: {error_code}» | Simple: hide; show `failureReason(code)` sentence; Advanced: IDs | |
| LifecyclePanel.tsx:76, 80 | L | «…پکیج‌های Pin …», «فایل‌های cache را با checksum بررسی می‌کند…» | «…بسته‌های نگه‌داشته‌شده و قرنطینه کنار گذاشته می‌شوند.», «سالم بودن فایل‌های ذخیره‌شده را بررسی می‌کند؛ چیزی پاک نمی‌شود.» | |
| LifecyclePanel.tsx:84–86, 94–107 | L | «Passphrase…», «اعتبارسنجی و Restore آفلاین», «Restore plan آماده شد…» | «رمز پشتیبان (دست‌کم ۱۶ نویسه)…», «بازگردانی از پشتیبان», «آماده است. این دستور را بعد از خاموش کردن سرویس روی سرور اجرا کنید.» | |
| LifecyclePanel.tsx:242 | C | `(${task.error_code})` appended | sentence via `failureReason` | |
| MonitoringPanel.tsx:96 | J | «…(ممکن است cgroup روی میزبان در دسترس Agent نباشد).» | «آمار کانتینرها در دسترس نیست.» (reason → HelpTip) | |
| MonitoringPanel.tsx:121, 123 | P/L | «…agent:write نیاز دارد.», «…Agent را pair کنید.» | «فقط «مدیر» می‌تواند هشدارها را عوض کند.», «اول دستیار سرور را وصل کنید.» [وصل کردن] | |
| NetworkPanel.tsx:57 | L | «…(upstreamها، تلگرام، بله، ایمیل، webhook)… DNS و سیاست upstreamها هم این‌جاست.» | «اگر اینترنت سرور محدود است، یک پروکسی بسازید و برای هر سرویس روشنش کنید.» | |
| NetworkPanel.tsx:84 | J | «…به‌جای 127.0.0.1 از IP میزبان یا host.docker.internal…» | HelpTip only | |
| NetworkPanel.tsx:87–88 | J | «SOCKS5 — نام‌ها با DNS پنل resolve و IP تثبیت می‌شود…» | «SOCKS5: سرور آدرس‌ها را خودش پیدا می‌کند.» / «SOCKS5h: پروکسی آدرس‌ها را پیدا می‌کند؛ وقتی DNS فیلتر است این را بزنید.» | |
| NetworkPanel.tsx:133–139 | L | «خطای TLS», «مقصد خطای 5xx داد», «resolve نام ناموفق بود» | «اتصال امن برقرار نشد», «مقصد مشکل داشت», «آدرس پیدا نشد» | |
| NetworkPanel.tsx:313, 568 | C | falls back to raw `item.kind` | label map for every outbound kind (`registry`, `vuln_feed`, `server_backup_destination`, ...) | |
| NotificationsPanel.tsx:98 | L | «…یا webhook بفرستید.» | «وقتی اتفاق مهمی افتاد، در تلگرام، بله یا ایمیل خبردار شوید.» | |
| NotificationsPanel.tsx:144, 148, 156 | L/J | «…برای پراکسی یا Bot API محلی», «…POST و بدنه JSON … HMAC…», «هدرهای اضافه (هر خط: Name: value)» | Advanced only; Simple webhook = URL + «امتحان» | |
| NotificationsPanel.tsx:176, 180 | J | «…الگو مثل registry.* یا * است.» | Simple: checkbox list of event families («بسته‌ها», «پشتیبان», «سرور», «امنیت») + severity slider; pattern only in Advanced | |
| NotificationsPanel.tsx:198 | L | «منطقه زمانی (IANA)» | «منطقه زمانی» (picker, default «تهران») | |
| NotificationsPanel.tsx:1148, 1072 | C | `item.error_code` column / tooltip | `deliveryFailureReason(code)` | |
| ObservabilityPanel.tsx:65–71, 90–91 | L/P | «آخرین رویدادهای Audit», «ثبت append-only…», «دانلود Support Bundle», «…API Token دارای system:read…», «…مجوز audit:read…» | «تاریخچه فعالیت», «هیچ ردیفی پاک یا عوض نمی‌شود», «دانلود بسته گزارش برای پشتیبانی», Advanced: «برای Prometheus یک کلید برنامه «فقط دیدن» بسازید», «دیدن تاریخچه فقط برای مدیرها و مسئولان است» | |
| PackagesPanel.tsx:75, 83–98 | L | «محتوای واقعی cache…Pin کنید», «Pin شده», «برداشتن Pin», «حذف از cache…», «پکیجی در cache پیدا نشد» | «بسته‌هایی که روی این سرور ذخیره شده‌اند را پیدا کنید.», «نگه‌داشته‌شده», «دیگر نگه ندار», «پاک کردن از ذخیره…», «این بسته هنوز روی سرور ذخیره نشده.» [پیش‌دریافت] | |
| PackagesPanel.tsx:97 | T | «{artifacts} فایل ({size}) در قالب یک وظیفه حذف می‌شود.» | «{n} فایل ({size}) پاک می‌شود. تا ۷ روز در سطل بازیافت می‌ماند.» | |
| PackagesPanel.tsx:103 | L | «محتوای requirements.txt یا package-lock.json را وارد کنید تا … mirror دریافت و cache شوند.» | «فهرست بسته‌های پروژه را این‌جا بگذارید تا از قبل دانلود شوند.» (filenames as example chips) | |
| ProxyControls.tsx:55 | L | «نوع پروکسی پیش‌فرض ({type}) … پشتیبانی‌شده: {types}.» | «پروکسی پیش‌فرض برای این سرویس مناسب نیست؛ یک پروکسی دیگر انتخاب کنید.» | |
| ProxyControls.tsx:176 | C | raw `item.type` | type label | |
| RegistriesPanel.tsx:50–51 | J | «…HTTP ساده (۴۸۷۳ و ۳۱۴۱)…reverse proxy با HTTPS…», «…پورت داخلی دیتابیس هرگز publish نمی‌شود.» | Advanced/HelpTip; Simple: «برای استفاده از بیرون سرور، یک دامنه با HTTPS بدهید.» [راهنما] | |
| S3Access.tsx:74–84 | L/J | «سیاست سفارشی (JSON)», «مناسب restic/Dokploy…», «سیاست IAM دلخواه…», «…«Version» و آرایه «Statement»…» | Simple: 4 access-level cards; JSON only in Advanced | |
| S3Access.tsx:101 | C | «کلید {akid} حذف شود؟» | «کلید «…{last4}» پاک شود؟ برنامه‌هایی که از آن استفاده می‌کنند قطع می‌شوند.» | |
| S3Access.tsx:109 | L | «Secret فقط همین یک‌بار…» | «رمز کلید فقط همین یک بار نمایش داده می‌شود. همین حالا کپی کنید.» | |
| S3Access.tsx:122 | L | «Endpoint داخلی (از کانتینرهای همین سرور)» | «آدرس برای برنامه‌های همین سرور» | |
| S3FileManager.tsx:78 | L | «مسیر جدید (key)» | «نام یا مسیر تازه» | |
| S3FileManager.tsx:99; S3Panel.tsx:148 | P | «…دسترسی s3:write لازم است», «…به دسترسی s3:admin نیاز دارد.» | «نقش شما فقط اجازه دیدن فایل‌ها را دارد.» / «فقط «مدیر» می‌تواند پوشه اصلی بسازد.» | |
| S3Panel.tsx:77 | L | «فضای ذخیره‌سازی سازگار با S3 … (Dokploy، restic، rclone…).» | «یک فضای فایل روی سرور خودتان، مثل Google Drive، که برنامه‌ها هم می‌توانند در آن پشتیبان بگذارند.» | |
| S3Panel.tsx:113–115 | J | «بدون «..» و نه به شکل IP», «بدون پیشوند xn-- و پسوند -s3alias…» | one live validator line: «فقط حروف کوچک انگلیسی، عدد و خط تیره؛ ۳ تا ۶۳ نویسه.» | |
| S3Panel.tsx:123–124 | L/J | «…bind mount زیر {root}…», «…این خط را به سرویس MRK در compose اضافه…» | Advanced; Simple: «برای وصل کردن پوشه‌های سرور، راهنما را ببینید.» | |
| S3Panel.tsx:152–155 | L | «آدرس عمومی (Public endpoint)», «پسوند virtual-host» | «آدرس عمومی» (keep English once), virtual-host → Advanced | |
| ServerBackupsPanel.tsx:90 | L | «از volumeهای Docker و دیتابیس‌های اپ‌ها … بکاپ بگیرید.» | «از اطلاعات برنامه‌ها و دیتابیس‌ها خودکار و رمزدار پشتیبان بگیرید.» | |
| ServerBackupsPanel.tsx:93 | P | «…backup:server:write نیاز دارد.» | «فقط «مدیر» می‌تواند پشتیبان تازه بسازد.» | |
| ServerBackupsPanel.tsx:143–145 | L/J | «سفارشی (cron)», «عبارت cron (۵ بخشی)», «…(دقیقه ساعت روز ماه روزهفته).» | Simple presets only: «هر شب», «هر هفته», «هر ماه» + time picker; cron in Advanced | |
| ServerBackupsPanel.tsx:170, 177 | J | «Path-style (برای MinIO…)», «…با MRKBKP2 رمزنگاری می‌شوند…» | Advanced; «همه پشتیبان‌ها رمزدار ذخیره می‌شوند و کلیدش روی همین سرور امن نگه‌داری می‌شود.» | |
| ServerBackupsPanel.tsx:895 | C | ` · ${run.error_code}` | `backupFailureReason(code)` | |
| ServerPanel.tsx:92, 96–103 | L/J | «…از طریق Host Agent امن.», «Host Agent یک پل امن… Docker socket… (allowlist)…», «پروفایل agent را در Compose فعال کنید», «کلید pairing…» | «وضعیت سرور و برنامه‌هایش.» / wizard: «۱. دستیار سرور را روشن کنید (یک خط در Compose) ۲. کد اتصال را از لاگ آن کپی کنید ۳. این‌جا بچسبانید.» | |
| ServerPanel.tsx:126–127 | J | «…(قابلیت host_metrics غیرفعال است)», «…(قابلیت docker غیرفعال است)» | «دستیار سرور اجازه دیدن اطلاعات سرور را ندارد.» / «…اجازه دسترسی به Docker را ندارد.» [راهنما] | |
| ServerPanel.tsx:146 | L | «تنظیمات Agent با متغیرهای محیطی (env) مدیریت می‌شود…» | «این اتصال از فایل Compose تنظیم شده؛ برای تغییر، همان فایل را ویرایش کنید.» | |
| ServerPanel.tsx:167–171 | L | «Imageها», «Volumeها», «فضای مصرفی Docker» | «نسخه‌های برنامه», «فضاهای داده», «فضای اشغال‌شده توسط Docker» | |
| ServerPanel.tsx:581, 861, 966, 983 | C | tooltip `item.status`, `last_error`, `error_code` in `<code>` | localized status + Advanced «جزئیات فنی» | |
| UpdatesPanel.tsx:92–93 | L | «آپدیت imageها», «…imageهای در حال اجرا…» | «نسخه‌های تازه برنامه‌ها», «MRK فقط خبر می‌دهد؛ خودش چیزی را به‌روز نمی‌کند.» | |
| UpdatesPanel.tsx:114, 123–126 | L/J | «قفل digest», «Digest فعلی/جدید», «نوع manifest» | «نسخه قفل‌شده», Advanced: «شناسه نسخه فعلی/تازه» | |
| UpdatesPanel.tsx:121 | L | «…در Dokploy دوباره deploy (Redeploy) کنید…» | «برای به‌روزرسانی، این برنامه را در Dokploy دوباره منتشر کنید.» [باز کردن در Dokploy] | |
| UpdatesPanel.tsx:141–153 | L/J | «اگر HEAD پشتیبانی نشد از GET…», «Mirrorها», «رجیستری‌های HTTP/بدون TLS…» | Advanced section «منابع و روش بررسی»; Simple: only «هر چند ساعت بررسی شود» + «خبرم کن» | |
| UpdatesPanel.tsx:266, 286, 628 | C | `?? item.status`, `error_code`, `error_detail`, `last_error` | localized statuses and reasons | |
| UpstreamPolicyCard.tsx:12–17 | L/P | «upstreamهای خصوصی/شبکه داخلی», «…upstream:write…» | «اجازه منابع داخل شبکه خودتان (مثل Nexus)», «هر «مدیری» می‌تواند از این راه به سرویس‌های داخلی دسترسی بگیرد؛ فقط اگر به همه مدیرها اعتماد دارید روشن کنید.» | |
| UpstreamsPanel.tsx:66–79, 84, 106–138 | L | «…upstreamها…», «افزودن upstream», «upstream افزوده شد.», «حذف upstream…», «upstream ثبت نشده است.» | «منبع دریافت» everywhere: «افزودن منبع», «منبع اضافه شد», «پاک کردن منبع…», «هنوز منبعی ندارید» | |
| UpstreamsPanel.tsx:116, 124 | J | «سرویس npm (Verdaccio) برای اعمال تغییر یک‌بار ری‌استارت می‌شود.» | «npm چند ثانیه قطع و دوباره وصل می‌شود.» | |
| Setup.tsx / Login.tsx / AuthShell.tsx:62,109 | I | "MRK Package Mirror" / "Package Mirror" hard-coded in JSX | `t("product")` | |

Process rule: add a CI script `scripts/check-copy.mjs`. In Phase 2 it fails the build when a Persian string in a copy dict contains a Latin word that is not on an allowlist (product names, examples marked `{ex:…}`, or Advanced-only keys tagged `adv_`). It also fails when a scope regex `/\b[a-z]+:[a-z:]+\b/` appears in any fa string.

---

## 4. Simple vs Advanced per page, and the complete settings registry

### 4.1 Principles
- **Simple:** the everyday, safe and reversible actions, 1–3 primary buttons per tab, wizards for anything with more than 3 fields, presets instead of free numbers, no codes or IDs, destructive actions behind `⋮`.
- **Advanced:** all of Simple, plus extra columns, raw IDs and technical details, every tunable for that page inline (rendered by `SettingsForm` from the registry, filtered by `group`), danger-zone actions, and JSON/cron/regex editors.
- The mode stays a presentation preference only. RBAC, confirmations and audit are identical in both modes.

### 4.2 Per page

| Page / tab | Simple keeps | Moves to Advanced |
|---|---|---|
| Home | verdict, attention list, quick actions, checklist, 3 glance cards | recent activity, component grid, versions |
| Packages › search | search box, result cards (name, size, «نگه‌داشته»), actions: نگه‌دار / پاک کن (→ recycle bin) / بازگردانی from bin | quarantine with reason, revalidate, artifact list, purge preview details, permanent delete, file counts |
| Packages › prefetch | paste box + «دانلود از قبل» | per-file limits (500 items / 40 files: currently hard-coded, see debt) |
| Packages › sources | per ecosystem: status pill, «امتحان اتصال», «بدون اینترنت» switch, add-source wizard (URL → test → save) | priority reorder, timeout, credential, per-source proxy, block with duration, health history stages (dns→proxy→http), seed defaults info |
| Packages › connect projects | copy commands for npm / pip / uv / yarn (`everyday` clients) | all clients, ports, reverse-proxy notes, router info |
| Server › overview | host card (CPU/RAM/disk), container list with status + start/stop/restart (non-protected), «لاگ» | protected-container actions (typed), Agent connection/capabilities/last_error, Docker resources, unpair |
| Server › resource use | 24h/7d charts, «وقتی بیشتر از ۹۰٪ شد خبرم کن» toggle | interval, retention minute/hour, per-metric thresholds, duration |
| Server › Dokploy apps | project → apps list, status, «انتشار دوباره», «توقف» (confirm) | full deploy, deploy history/logs, connection settings + tunables, disconnect |
| Server › updates | list of apps with «نسخه تازه آمده», «بررسی همین حالا», link to Dokploy | digests, rate limits, all `updates.*` settings (mirrors, insecure, ignore, GET fallback, concurrency, proxies) |
| Server › databases (Gate 19) | connections list, browse tables read-only | write mode, query editor, export, every `dbadmin.*` limit |
| Server › Docker tools | — (hidden) | pull, prune with preview |
| Files › file space | buckets as folders, upload/download/share link, «ساخت پوشه اصلی» wizard (name → access level → done, shows key once), «اتصال ابزار» snippets for the 3 common tools | linked server folders (owner), custom JSON policy, quotas, region, vhost, max object size, all identities/keys, S3 engine startup settings |
| Files › app backups | «پشتیبان تازه» wizard (what → where → when [nightly/weekly/monthly] → keep [7 copies]) · run now · last result | cron, retention days, destinations editor (path-style, endpoint, region, prefix, proxy), key export, timezone, concurrency/part size |
| Files › panel backup | «پشتیبان از تنظیمات پنل» (config profile) + download | full profile, validate, restore plan, retention env |
| Files › keep healthy | disk bar + «آزاد کردن فضا» (preview → confirm) | integrity scan, catalog cache, trash retention |
| Security › firewall | mode as 3 cards («خاموش», «تمرین», «فعال»), blocked IP list with «رفع مسدودی», «همیشه مجاز کن» | rules (threshold/window/ban), sources paths, sensitive paths, limits, history retention, helper connection |
| Security › vulnerabilities | «۲ مشکل جدی» per app with «چه کار کنم؟» (update hint) | all findings, ignore rules, feeds, severities to notify, feed URL/proxy/max size |
| Security › internet & proxy | proxy list + add wizard (presets: «تونل محلی», «پروکسی HTTP»), per-service on/off switch | specific proxy per service, no-proxy lists, test URL, supported types |
| Security › DNS & internal network | — | DNS mode/servers/timeout/IPv4, DNS test, private-upstream policy |
| People › people | user cards with role badge, «دعوت همکار» (3 steps), disable/enable | change role, sessions info, source IP, IDs |
| People › roles | role cards (can / can't) | custom role editor (§5.3) |
| People › app keys | «ساخت کلید فقط-دیدنی» with expiry presets, revoke | custom scopes, last-used IP |
| Alerts › channels | add Telegram / Bale / email wizard + «پیام آزمایشی» | webhook headers/signing key, API base URL, parse mode, timeouts, per-channel proxy |
| Alerts › rules | event family checkboxes + «فقط موارد مهم / همه» | patterns, min severity per rule, quiet hours, dedupe, retry/backoff, retention |
| Alerts › jobs | running/finished list with plain names and progress, cancel/retry | IDs, retry_of, error codes |
| Alerts › history | humanized activity feed with filters (who / what / when) | raw action/object/request id, CSV export, support bundle, metrics endpoint |

### 4.3 "All settings" screen (Advanced) and the backend registry

UI: left column with group tree (mirrors the 7 groups + "System") · search box (matches fa/en names, keys and env names) · filter chips: «قابل تغییر از پنل» / «فقط از Compose» / «نیاز به راه‌اندازی دوباره» / «تغییر یافته از پیش‌فرض» / «خطرناک». Each row: plain name (fa) · technical key (LTR, muted) · control (generated) · default with a «بازگشت به پیش‌فرض» link · unit · source badge · restart badge · danger badge · HelpTip description.

- `source: runtime` rows are editable inline, with per-group «ذخیره تغییرات» (diff preview + confirm for `danger ≥ high`).
- `source: startup` rows are read-only and show the effective value (secrets → «تنظیم شده»). They offer a «کپی خط Compose» action that generates `MRK_X=value` for the user's compose file, plus "needs restart".
- `source: build` rows are read-only info.
- `source: constant` rows are hard-coded today (docs/27 §6 "debt"). They show «هنوز قابل تغییر نیست» so Advanced is honest about everything that exists.

**Schema** (`GET /api/v1/settings/registry`):

```jsonc
{
  "groups": [{ "key": "packages.sources", "label": {"fa": "...", "en": "..."}, "nav": "packages/sources" }],
  "items": [{
    "key": "monitoring.alerts.cpu_percent",      // stable dotted key
    "group": "server.resources",                  // nav group/tab
    "type": "int",                                // bool|int|float|string|enum|list<string>|duration|bytes|time|timezone|cidr_list|url|json|secret|map
    "default": 90, "min": 1, "max": 100, "step": 1, "enum": null,
    "unit": "percent",                            // percent|seconds|minutes|hours|days|ms|bytes|mb|count|per_second
    "source": "runtime",                          // runtime|startup|build|constant
    "env": null,                                  // e.g. "MRK_SESSION_TTL_SECONDS" for startup (or env override of a runtime default)
    "restart_required": false,
    "danger": "low",                              // none|low|medium|high|critical
    "requires": "agent:write",                    // write permission
    "depends_on": [{"key": "monitoring.alerts.enabled", "equals": true}],
    "label": {"fa": "آستانه هشدار CPU", "en": "CPU alert threshold"},
    "description": {"fa": "وقتی مصرف CPU بیشتر از این بماند خبر می‌دهیم.", "en": "..."},
    "value": 90, "overridden": false, "locked_by_env": false, "secret": false
  }]
}
```

`PATCH /api/v1/settings/values` `{ "changes": {"key": value, ...} }` dispatches to the existing module services (reusing their validators). It answers `{ results: {key: {ok, error_code?, field_message_fa?, field_message_en?}} }`, writes one audit row per module, and is all-or-nothing per module.

**Registry entries to create.** `R` = runtime (panel, no restart) · `S` = startup env (restart) · `B` = build · `K` = constant today (proposed to promote). Danger: n/l/m/h/c.

**A. General / system (group `system`)**

| Key | Src | Type | Default | Range / enum | Danger |
|---|---|---|---|---|---|
| system.env (`MRK_ENV`) | S | enum | production | production, development | m |
| system.data_dir (`MRK_DATA_DIR`) | S | path | /data | — | c |
| system.log_level (`MRK_LOG_LEVEL`) | S | enum | INFO | DEBUG, INFO, WARNING, ERROR | l |
| system.host / system.port (`MRK_HOST`, `MRK_PORT`) | S | string/int | 0.0.0.0 / 8080 | 1–65535 | h |
| system.admin_ui_dir (`MRK_ADMIN_UI_DIR`) | S | path | bundled | — | m |
| system.database_url (`MRK_DATABASE_URL`) | S | secret url | embedded PGlite | — | c |
| system.database_wait_seconds (`MRK_DATABASE_WAIT_SECONDS`) | S | duration | (code default) | — | l |
| system.db_vacuum_interval_hours (`MRK_DB_VACUUM_INTERVAL_HOURS`) | S→R | hours | 24 | 0 = off | l |
| system.healthcheck_attempts (`MRK_HEALTHCHECK_ATTEMPTS`) | S | int | (code) | — | l |
| system.fatal_ignore / fatal_marker / supervisor_socket | S | string | — | — | h |
| system.restore_engine_ports (`MRK_RESTORE_ENGINE_PORTS`) | S | list<int> | 4873,3141,3142,8080 | — | m |
| system.upstream_secret_key_file (`MRK_UPSTREAM_SECRET_KEY_FILE`) | S | path | — | — | c |
| system.upstream_config_file (`MRK_UPSTREAM_CONFIG_FILE`) | S | path | — | — | h |
| deploy.image / cpus / mem_limit / host_data_path (`MRK_IMAGE`, `MRK_CPUS`, `MRK_MEM_LIMIT`, `MRK_HOST_DATA_PATH`) | S (compose) | string | — | — | m |
| deploy.db_name / db_user / db_password (`MRK_DB_*`) | S | string/secret | — | — | c |
| build.npm_registry (`MRK_BUILD_NPM_REGISTRY` → `NPM_REGISTRY`) | B | url | lockfile hosts | — | l |
| build.pip_index_url (`MRK_BUILD_PIP_INDEX_URL`) | B | url | — | — | l |
| build.commit / build.date | B | info | — | — | n |

**B. Sign-in & security (group `people.security`)**

| Key | Src | Type | Default | Range | Danger |
|---|---|---|---|---|---|
| auth.registration.enabled | R | bool | false | — | h |
| auth.session_ttl_seconds (`MRK_SESSION_TTL_SECONDS`) | S→R (promote) | duration | 28800 (8 h) | 300–2592000 | m |
| auth.login_rate_limit.attempts (`MRK_LOGIN_RATE_LIMIT_ATTEMPTS`) | S→R | int | 5 | 1–100 | m |
| auth.login_rate_limit.window_seconds (`…_WINDOW_SECONDS`) | S→R | duration | 300 | 10–86400 | m |
| auth.password.min_length (`MRK_PASSWORD_MIN_LENGTH`) | S→R | int | (code) | — | m |
| auth.password.require_digits / require_letters | S→R | bool | true/true | — | m |
| auth.password_hash_concurrency (`MRK_PASSWORD_HASH_CONCURRENCY`) | S | int | 4 | 1–64 | m |
| auth.session_prune_age_seconds (`MRK_SESSION_PRUNE_AGE_SECONDS`) | S→R | duration | 604800 | 3600–31536000 | l |
| auth.audit_retention_days (`MRK_AUDIT_RETENTION_DAYS`) | S→R | days | 365 | 0 = forever | m |
| web.trusted_hosts (`MRK_TRUSTED_HOSTS`) | S | list | — | — | c |
| web.cors_origins (`MRK_CORS_ORIGINS`) | S | list | — | — | h |
| web.trusted_proxies (`MRK_TRUSTED_PROXIES`) | S | cidr_list | — | — | h |
| web.auth_cookie_secure (`MRK_AUTH_COOKIE_SECURE`) | S | bool | true | — | h |
| auth.argon2.time_cost / memory_cost / parallelism | K | int | 3 / 65536 / 2 | — | h |
| tokens.read_only_scopes (UI preset) | K | list | system/upstream/cache/task:read | — | l |

**C. Packages: npm registry (group `packages.npm`)**

| Key | Src | Type | Default | Range | Danger |
|---|---|---|---|---|---|
| npm.enabled (`MRK_NPM_ENABLED`) | S | bool | true | — | h |
| npm.primary_upstream / fallback_upstream (`MRK_NPM_*_UPSTREAM`) | S (seed once) | url | registry.npmjs.org / liara mirror | — | l |
| npm.offline | R | bool | false | — | m |
| npm.block_poll_seconds (`MRK_NPM_BLOCK_POLL_SECONDS`) | S | duration | 30 | 5–3600 | l |
| npm.health_host / health_port | S | string/int | — | — | m |
| npm.uplink_token.<id> (`MRK_NPM_UPLINK_TOKEN_*`) | S | secret | — | — | h |
| npm.uplink.max_fails / fail_timeout / maxage (Verdaccio) | K | int/duration | (generated) | — | m |

**D. Packages: PyPI (group `packages.pypi`)**

| Key | Src | Type | Default | Range | Danger |
|---|---|---|---|---|---|
| pypi.enabled | S | bool | true | — | h |
| pypi.primary_upstream / fallback_upstream | S (seed) | url | — | — | l |
| pypi.offline | R | bool | false | — | m |
| pypi.outside_url (`MRK_PYPI_OUTSIDE_URL`) | S | url | — | — | m |
| pypi.request_timeout (`MRK_PYPI_REQUEST_TIMEOUT`) | S | seconds | (devpi) | — | l |
| pypi.cache_expiry (`MRK_PYPI_CACHE_EXPIRY`) | S | seconds | (devpi) | — | l |
| pypi.threads (`MRK_PYPI_THREADS`) | S | int | (devpi) | — | l |
| pypi.port / health_host / health_port | S | int/string | 3141 | — | m |
| pypi.root_password_file / devpi_root_password_file | S | path | — | — | c |
| pypi.bootstrap_wait_seconds / configure_attempts | S | int | — | — | l |
| pypi.server_dir / client_dir / auth_dir / offline_file / bootstrap_state_file | S | path | — | — | h |
| pypi.revalidate_upstream_url (`MRK_PYPI_UPSTREAM_URL`) | S | url | http://127.0.0.1:3142/simple/ | — | l |
| pypi_router.connect_timeout / read_timeout | S | seconds | (code) | — | l |
| pypi_router.artifact_deadline | S | seconds | (code) | — | l |
| pypi_router.failure_threshold / cooldown | S | int/seconds | (code) | — | l |
| pypi_router.max_artifact_bytes | S | bytes | (code) | — | m |
| pypi_router.spool_dir | S | path | — | — | m |
| pypi_router.spool_reserve_bytes | K | bytes | 256 MB | — | m |
| pypi_router.allow_private (`MRK_PYPI_ROUTER_ALLOW_PRIVATE`) | S | bool | false | — | **c** |
| pypi_router.host / port / health_host | S | string/int | 3142 | — | m |

**E. Packages: sources, cache, lifecycle (groups `packages.sources`, `files.health`)**

| Key | Src | Type | Default | Range | Danger |
|---|---|---|---|---|---|
| upstreams[] (collection: name, ecosystem, url, priority, timeout_seconds 1–30, enabled, proxy_id, credential, block until/reason) | R | collection | seeded | — | m |
| network.allow_private_upstreams | R | bool | false | — | **h** |
| catalog.cache_seconds (`MRK_CATALOG_CACHE_SECONDS`) | S→R | seconds | 30 | — | l |
| integrity.full_rescan_days (`MRK_INTEGRITY_FULL_RESCAN_DAYS`) | S→R | days | 30 | — | l |
| purge.trash_retention_days (`MRK_PURGE_TRASH_RETENTION_DAYS`) | S→R | days | 7 | — | m |
| prefetch.max_items / max_files_per_version | K | int | 500 / 40 | — | l |
| backup.retain_count (`MRK_BACKUP_RETAIN_COUNT`) | S→R | int | 7 | 0 = unlimited | m |
| backup.retain_days (`MRK_BACKUP_RETAIN_DAYS`) | S→R | days | 30 | 0 = unlimited | m |
| backup.min_free_bytes (`MRK_BACKUP_MIN_FREE_BYTES`) | S→R | bytes | 1 GiB | — | m |
| backup.passphrase (`MRK_BACKUP_PASSPHRASE`) | S | secret | — | — | c |
| disk.alert_thresholds (Prometheus rules) | K | percent | (rules) | — | l |

**F. Internet: DNS & proxy (group `security.network`)**

| Key | Src | Type | Default | Range | Danger |
|---|---|---|---|---|---|
| network.dns.mode | R | enum | system | system, custom | m |
| network.dns.servers | R | list | [] | ≤ MAX_SERVERS (6), IP[:port] | m |
| network.dns.timeout_seconds | R | float s | 2.0 | 0.2–10 | l |
| network.dns.prefer_ipv4 | R | bool | true | — | l |
| network.proxies[] (name, type http/https/socks5/socks5h, host, port 1–65535, username, password, enabled, no_proxy ≤ 32) | R | collection | [] | — | m |
| network.default_proxy_id | R | ref | null | — | m |
| outbound.<kind>.<id>.proxy_id (per service: upstream, notification_channel, registry, vuln_feed, server_backup_destination) | R | ref | null (direct) | null/default/id | m |
| network.proxy_test_url | R (per test) | url | https://api.telegram.org | — | n |

**G. Server: Agent, Docker, logs (group `server.overview`)**

| Key | Src | Type | Default | Range | Danger |
|---|---|---|---|---|---|
| agent.url / agent.key (pairing) | R (or S `MRK_AGENT_URL` + `MRK_AGENT_KEY_FILE`, locks UI) | url/secret | — | — | h |
| agent.check_interval_seconds (`MRK_AGENT_CHECK_INTERVAL_SECONDS`) | S→R | seconds | 60 | — | l |
| logs.stream_max_seconds (`MRK_LOGS_STREAM_MAX_SECONDS`) | S | seconds | 600 | 10–600 | l |
| agent.job_max (`MRK_AGENT_JOB_MAX`) | S | int | 50 | 5–1000 | l |
| agent.job_ttl_seconds (`MRK_AGENT_JOB_TTL_SECONDS`) | S | seconds | 3600 | 60–86400 | l |
| agent_helper.listen (`MRK_AGENT_LISTEN`) | S (agent) | host:port | — | — | h |
| agent_helper.state_dir / docker_socket / host_proc / host_root / host_cgroup / host_volumes | S (agent) | path | /host/volumes … | — | h |
| agent_helper.docker_timeout_seconds | S (agent) | seconds | 5 | — | l |
| agent_helper.backup_max_seconds | S (agent) | seconds | 21600 | — | l |
| agent_helper.protected_name_regex / protected_label_prefixes / protected_compose_projects | S (agent) | string/list | Dokploy defaults | — | **c** |
| agent_helper.user / docker_gid (`MRK_AGENT_USER`, `MRK_DOCKER_GID`) | S | string/int | 10001 | — | h |
| logs.tail_max / search_max_chars | K | int | 5000 / 200 | — | n |
| agent.heartbeat_seconds / retention_hours | K | — | 5 s / 6 h | — | l |

**H. Server: resource use (group `server.resources`)**: all R, require `agent:write`

| Key | Default | Range |
|---|---|---|
| monitoring.enabled | true | — |
| monitoring.interval_seconds | 15 | 5–3600 |
| monitoring.minute_retention_days | 7 | 1–90 |
| monitoring.hour_retention_days | 90 | 1–3650, ≥ minute |
| monitoring.alerts.enabled | true | — |
| monitoring.alerts.cpu_percent / mem_percent / disk_percent | 90 / 90 / 85 | 1–100 |
| monitoring.alerts.duration_minutes | 5 | 1–1440 |
| monitoring.recovery_seconds | K 60 | — |
| monitoring.chart_max_points | K 500 | — |

**I. Server: Dokploy (group `server.apps`)**

| Key | Src | Default | Range |
|---|---|---|---|
| dokploy.url / dokploy.api_key | R (or S `MRK_DOKPLOY_URL`, `MRK_DOKPLOY_API_KEY_FILE`, locks UI) | — | — |
| dokploy.rate_limit_per_second | R (env default `MRK_DOKPLOY_RATE_LIMIT_PER_SECOND`) | 2.0 | 0.1–20 |
| dokploy.poll_interval_seconds | R (`MRK_DOKPLOY_POLL_SECONDS`) | 60 | 0–3600 |
| dokploy.cache_seconds | R (`MRK_DOKPLOY_CACHE_SECONDS`) | 15 | 0–600 |
| dokploy.concurrency (`MRK_DOKPLOY_CONCURRENCY`) | S→R | 2 | 1–8 |
| dokploy.timeout_seconds (`MRK_DOKPLOY_TIMEOUT_SECONDS`) | S→R | 15 | 1–120 |
| dokploy.max_queue_seconds (`MRK_DOKPLOY_MAX_QUEUE_SECONDS`) | S→R | 10 | 0–60 |
| dokploy.allow_loopback (`MRK_DOKPLOY_ALLOW_LOOPBACK`) | S | false | danger h |
| dokploy.domain_ttl_seconds / domain_fetch_budget / max_log_lines | K | 300 / 6 / 5000 | — |

**J. Server: image updates (group `server.updates`)**: all R, `updates:write`

| Key | Default | Range |
|---|---|---|
| updates.enabled | true | — |
| updates.interval_hours | 12 | 1–720 |
| updates.ignore | [] | ≤ 100 fnmatch |
| updates.include_stopped | false | — |
| updates.notify | true | — |
| updates.proxy_id | null | null/default/id |
| updates.registry_proxies | {} | map |
| updates.mirrors | {} | ≤ 5 per registry |
| updates.mirror_fallback | true | — |
| updates.insecure_registries | [] | not docker.io (danger h) |
| updates.allow_get_fallback | true | — |
| updates.timeout_seconds | 15 | 3–120 |
| updates.concurrency | 4 | 1–16 |
| updates.first_check_delay / retry_after_failure | K 60 s / 15 min | — |

**K. Server: databases (group `server.databases`)**: all R, `db:write`

| Key | Default | Range |
|---|---|---|
| dbadmin.connect_timeout_seconds | 5 | 1–60 |
| dbadmin.statement_timeout_ms | 15000 | 100–600000 |
| dbadmin.max_rows | 1000 | 1–1000 |
| dbadmin.max_cell_bytes | 65536 | 256–1 MiB |
| dbadmin.max_response_bytes | 5 MiB | 64 KiB–5 MiB |
| dbadmin.export_max_rows | 100000 | 1–5,000,000 |
| dbadmin.export_max_bytes | 100 MiB | 1 MiB–2 GiB |
| dbadmin.export_statement_timeout_ms | 300000 | 1 s–1 h |
| dbadmin.concurrency_per_connection | 2 | 1–2 |
| dbadmin.connections[] (engine, host, port, db, user, password, tls_mode) | collection | — |

**L. Files: S3 (group `files.space`)**

| Key | Src | Default | Range / note |
|---|---|---|---|
| s3.enabled | R | true | — |
| s3.region | R | us-east-1 | `[a-z0-9-]` 2–32 |
| s3.public_endpoint | R | null | http(s)://host[:port] |
| s3.virtual_host_suffix | R | null | hostname |
| s3.max_object_bytes | R | 5 TiB | 1 B–5 TiB |
| s3.default_quota_bytes | R | null | — |
| s3.share_link.default_expiry_seconds | K→R | 3600 | 1–604800 |
| s3.keys.max_active / max_total per identity | K | 2 / 10 | — |
| s3.engine_url / admin_url / links_root / url (`MRK_S3_ENGINE_URL`, `MRK_S3_ADMIN_URL`, `MRK_S3_LINKS_ROOT`, `MRK_S3_URL`) | S | :9000 / :9001 / /mnt/links | — |
| s3engine.listen / admin_listen / port | S | 0.0.0.0:9000 / 127.0.0.1:9001 | h |
| s3engine.data_dir / link_roots | S | — / /mnt/links | h |
| s3engine.config_poll_seconds | S | 2.0 | — |
| s3engine.clock_skew_seconds | S | 900 | — |
| s3engine.accept_any_region | S | true | — |
| s3engine.require_content_sha256 | S | true | m |
| s3engine.debug_signatures | S | false | h (leaks info) |
| s3engine.max_single_put_bytes / max_part_bytes | S | 5 GiB / 5 GiB | — |
| s3engine.multipart_min_part_bytes / multipart_max_parts / multipart_upload_ttl_days | S | 5 MiB / 10000 / 7 | — |
| s3engine.max_xml_body_bytes / max_header_bytes / max_user_metadata_bytes / max_chunk_bytes | S | 2 MiB / 16 KiB / 2 KiB / 16 MiB | — |
| s3engine.max_key_bytes / max_keys_per_list / max_delete_objects | K | 1024 / 1000 / 1000 | — |
| s3engine.idle_body_timeout_seconds | S | 120 | — |
| s3engine.fsync_policy | S | object | none/object/strict (m) |
| s3engine.gc_interval_seconds / tmp_ttl_seconds / trash_grace_seconds | S/S/K | 300 / 21600 / 60 | — |
| s3engine.disk_block_percent | S | 90 | 1–100 |
| s3engine.hash_rate_bytes / hash_max_file_bytes | S | 50 MiB / 1 GiB | — |
| s3engine.secret_cache_seconds | K | 300 | — |
| s3engine.trusted_proxies | S | — | h |

**M. Files: app backups (group `files.backups`)**

| Key | Src | Default | Range |
|---|---|---|---|
| server_backups.timezone | R | Asia/Tehran | IANA |
| server_backups.jobs[] (name, source kind/volume/container/database, destination, schedule cron, retention keep_last / keep_days, enabled) | R | — | — |
| server_backups.destinations[] (local path / s3 endpoint, bucket, region, prefix, path_style, keys, proxy / mrk_s3) | R | — | — |
| server_backups.concurrency (`MRK_SERVER_BACKUP_CONCURRENCY`) | S→R | 2 | 1–8 |
| server_backups.part_bytes (`MRK_SERVER_BACKUP_PART_BYTES`) | S | 8 MiB | ≥ 5 MiB |
| server_backups.scheduler_tick_seconds | K | 30 | — |
| server_backups.scrypt_n | K | 2^15 | — |

**N. Security: firewall (group `security.firewall`)**: R, `firewall:write`

| Key | Default | Range | Danger |
|---|---|---|---|
| firewall.mode | dry_run | off / dry_run / enforce | **c** (typed confirm) |
| firewall.allowlist | [] | ≤ 256 {cidr, note} | h |
| firewall.allowlist_private | true | — | h |
| firewall.allow_private_blocks | false | — | h |
| firewall.default_ban_seconds | 3600 | 60–max_ban | m |
| firewall.max_ban_seconds | 30 d | ≤ 365 d | m |
| firewall.max_blocks | 10000 | 1–65536 | m |
| firewall.poll_interval_seconds | 15 | 5–3600 | l |
| firewall.history_retention_days | 30 | 1–3650 | l |
| firewall.notify | true | — | l |
| firewall.sources.sshd.enabled / path | true / /host/log/system/auth.log | under /host/log/ | m |
| firewall.sources.traefik.enabled / path | false / /host/log/traefik/access.log | — | m |
| firewall.sources.mrk.enabled | true | — | l |
| firewall.sensitive_paths | 16 defaults | ≤ 100 | l |
| firewall.rules[] (threshold 1–100000, window 10–86400 s, ban 60 s–365 d) | collection | — | m |
| firewall.url / key_file (`MRK_FIREWALL_URL`, `MRK_FIREWALL_KEY_FILE`) | S | — | h |
| firewall_helper.listen / state_dir / log_root / nft / force_dry_run | S | unix socket / /var/lib/mrk-firewall / /host/log / /usr/sbin/nft / false | h |
| firewall.min_prefix / helper caps (1024 allow, 65536 block, 8 sources, 5000 signals, 2 MiB/poll, 16 KiB line) | K (intentional safety constants, show read-only) | — | — |

**O. Security: vulnerabilities (group `security.vuln`)**: R, `vuln:write`

| Key | Default | Range |
|---|---|---|
| vuln.enabled | true | — |
| vuln.interval_hours | 24 | 1–720 |
| vuln.ecosystems_extra | [] | Debian, Ubuntu, Alpine, Wolfi, Chainguard, AlmaLinux, Rocky Linux, npm, PyPI |
| vuln.feed_base_url | osv-vulnerabilities.storage.googleapis.com | url |
| vuln.severities_to_notify | [critical, high] | subset |
| vuln.include_stopped | false | — |
| vuln.proxy_id | null | — |
| vuln.feed_max_mb | 1024 | 16–4096 |
| vuln.feed_recheck_seconds / inventory_cache_days / max_images_per_scan / start_delay / retry_after_error / agent_file_caps / agent_timeout / max_ignores | K | 3600 / 7 / 300 / 120 s / 30 min / 8–40 MiB / 180 s / 500 |

**P. Alerts: notifications (group `alerts`)**: R, `notification:write`

| Key | Default | Range |
|---|---|---|
| notifications.quiet_hours.enabled | false | — |
| notifications.quiet_hours.start / end | 23:00 / 07:00 | HH:MM |
| notifications.quiet_hours.timezone | Asia/Tehran | IANA |
| notifications.quiet_hours.min_severity_during_quiet | critical | info/warning/error/critical |
| notifications.dedupe_window_seconds | 300 | 0 = off |
| notifications.max_attempts | 5 | 1–20 |
| notifications.retry_base_seconds / retry_max_seconds | 30 / 3600 | — |
| notifications.retention_days | 30 | — |
| notifications.channels[] (telegram/bale: chat_id, api_base_url, parse_mode, timeout 2–60 (15), bot_token, proxy; email: smtp_host, port, security starttls/tls/none, username, password, from, to[], timeout, proxy socks only; webhook: url, headers ≤ 20, signing_key, timeout, proxy) | collection | — |
| notifications.rules[] (pattern, min severity, channel) | collection | — |

Implementation note: the registry is **descriptive**. Each module exports `SETTINGS: list[SettingSpec]` next to its existing validator (`monitoring.py`, `updates_settings.py`, `vuln_settings.py`, `firewall.py`, `dbadmin.py`, `notifications.py`, `s3.py`, `server_backups.py`, `dokploy.py`, `netresolve.py`, `config.py` for env). A unit test asserts that every key a module's PUT accepts has a spec, and every `os.getenv("MRK_…")` in the code has a spec (grep-based test). That makes "no hidden constant" (docs/27 §1.5) enforceable in CI.

---

## 5. Permissions UX

### 5.1 Role cards (Simple)

| Role (key) | Card name fa / en | One-liner | Can ✓ | Can't ✗ |
|---|---|---|---|---|
| owner | **مالک** / Owner | «همه کارها، از جمله کارهای خیلی حساس» | everything; link server folders to file space; create other owners | — (only one person should have this) |
| admin | **مدیر** / Admin | «همه چیز را تنظیم می‌کند» | change every setting, add/remove people, connect Dokploy/Agent, firewall, databases, file space admin, backups setup, cleanup unused Docker items | link server folders; create an owner |
| operator | **مسئول روزانه** / Operator | «کارهای هر روز را انجام می‌دهد، تنظیمات اصلی را نه» | start/stop containers, publish apps, run backups, test/block sources, manage cached packages, upload files, check updates, scan for vulnerabilities, see logs and history | add people, change proxies/DNS, set up backups or Dokploy, firewall changes, databases, delete unused Docker items |
| developer | **برنامه‌نویس** / Developer | «بسته‌ها را استفاده می‌کند و وضعیت را می‌بیند» | see packages, sources, server charts, apps, files; make own app keys | change anything on the server, see logs, see history |
| viewer | **بیننده** / Viewer | «فقط می‌بیند» | see status, packages, sources, charts, updates, security findings | change anything |

The card UI shows a coloured avatar, the name, the one-liner, 3–5 "can" bullets, 2–3 "can't" bullets, and «دیدن همه اجازه‌ها» (opens the Advanced list read-only). Role dropdowns everywhere render these names, never keys.

### 5.2 Invite a teammate in 3 steps («دعوت همکار»)

1. **کیست؟** Name, username (auto-suggested from the name), and optional email.
2. **چه کاری بکند؟** Pick a role card. The default is «بیننده». «مدیر» shows an amber note: «می‌تواند افراد دیگر را هم اضافه کند».
3. **بفرستید.** The panel generates a strong one-time password, which it shows once with «کپی پیام دعوت». The ready-to-paste fa/en text includes the panel URL, username and temporary password, plus «در اولین ورود رمز را عوض کنید». Phase 3 replaces this with an invite link (`POST /api/v1/invites` → single-use token, 72 h) and forced password change on first login (`must_change_password`).

### 5.3 Advanced: custom-role editor

Layout: role name (fa/en) + description → "start from" (copy of an existing role) → permission matrix grouped by the new nav groups. Each group has a header switch ("none / view / full"), and each permission is a row with plain name, technical key (LTR, muted), and a «خطرناک» badge where relevant. Dependencies are auto-enforced: write ⇒ read, deploy ⇒ read, prune ⇒ operate, `backup:server:write` ⇒ `backup:server:read`. The editor shows a live "this role can" summary and a diff against the role it was copied from. Saving a role that grants `user:write` needs the owner. Custom roles can never hold `*`.

**Permission catalogue (every entry in `ROLE_PERMISSIONS`), grouped by new nav section:**

| Group | Key | Plain name (fa) | Plain name (en) | O | A | Op | D | V | Danger |
|---|---|---|---|---|---|---|---|---|---|
| خانه / system | `system:read` | دیدن وضعیت کلی سامانه | See system status | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| بسته‌ها | `cache:read` | دیدن بسته‌های ذخیره‌شده | See cached packages | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| بسته‌ها | `cache:write` | نگه‌داشتن، قرنطینه، پاک کردن و پیش‌دریافت بسته‌ها | Pin, quarantine, remove and prefetch packages | ✓ | ✓ | ✓ | – | – | m |
| بسته‌ها | `upstream:read` | دیدن منابع دریافت (و پروکسی/DNS) | See package sources (and proxy/DNS) | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| بسته‌ها | `upstream:operate` | امتحان، مسدود کردن و حالت بدون اینترنت منابع | Test, block and switch sources offline | ✓ | ✓ | ✓ | – | – | m |
| بسته‌ها | `upstream:write` | افزودن/تغییر منابع، پروکسی، DNS و منابع داخلی | Add/change sources, proxies, DNS, internal sources | ✓ | ✓ | – | – | – | h |
| سرور و برنامه‌ها | `agent:read` | دیدن سرور و کانتینرها | See server and containers | ✓ | ✓ | ✓ | – | – | – |
| سرور و برنامه‌ها | `agent:write` | وصل کردن دستیار سرور و تنظیم هشدارهای مصرف | Pair the server helper; set resource alerts | ✓ | ✓ | – | – | – | h |
| سرور و برنامه‌ها | `metrics:read` | دیدن نمودار مصرف منابع | See resource charts | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| سرور و برنامه‌ها | `logs:read` | دیدن لاگ کانتینرها | Read container logs | ✓ | ✓ | ✓ | – | – | m |
| سرور و برنامه‌ها | `docker:operate` | روشن/خاموش/راه‌اندازی دوباره کانتینر و دریافت نسخه | Start/stop/restart containers, pull images | ✓ | ✓ | ✓ | – | – | m |
| سرور و برنامه‌ها | `docker:prune` | پاک کردن موارد بی‌استفاده Docker | Clean up unused Docker items | ✓ | ✓ | – | – | – | h |
| سرور و برنامه‌ها | `dokploy:read` | دیدن برنامه‌های Dokploy | See Dokploy apps | ✓ | ✓ | ✓ | ✓ | – | – |
| سرور و برنامه‌ها | `dokploy:deploy` | انتشار، توقف و شروع برنامه‌های Dokploy | Deploy, stop and start Dokploy apps | ✓ | ✓ | ✓ | – | – | m |
| سرور و برنامه‌ها | `dokploy:write` | وصل/قطع کردن Dokploy و تنظیم آن | Connect/disconnect and tune Dokploy | ✓ | ✓ | – | – | – | h |
| سرور و برنامه‌ها | `updates:read` | دیدن نسخه‌های تازه برنامه‌ها | See available image updates | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| سرور و برنامه‌ها | `updates:write` | بررسی دستی و تنظیم بررسی نسخه‌ها | Check now; change update-check settings | ✓ | ✓ | ✓ | – | – | l |
| سرور و برنامه‌ها | `db:read` | دیدن دیتابیس‌ها و داده‌هایشان | Browse databases and data | ✓ | ✓ | – | – | – | **h** (data exposure) |
| سرور و برنامه‌ها | `db:write` | نوشتن در دیتابیس و مدیریت اتصال‌ها | Write to databases; manage connections | ✓ | ✓ | – | – | – | **c** |
| فایل‌ها و پشتیبان | `s3:read` | دیدن و دانلود فایل‌ها | See and download files | ✓ | ✓ | ✓ | ✓ | – | m |
| فایل‌ها و پشتیبان | `s3:write` | آپلود، پاک کردن و لینک اشتراک فایل | Upload, delete and share files | ✓ | ✓ | ✓ | – | – | m |
| فایل‌ها و پشتیبان | `s3:admin` | ساخت پوشه اصلی، کاربر و کلید فضای فایل | Manage buckets, file-space users and keys | ✓ | ✓ | – | – | – | h |
| فایل‌ها و پشتیبان | `backup:read` | دیدن پشتیبان‌های پنل | See panel backups | ✓ | ✓ | ✓ | – | – | – |
| فایل‌ها و پشتیبان | `backup:write` | ساخت پشتیبان پنل و آماده‌سازی بازگردانی | Create panel backups; prepare restore | ✓ | ✓ | – | – | – | h |
| فایل‌ها و پشتیبان | `backup:server:read` | دیدن پشتیبان برنامه‌ها | See app backups | ✓ | ✓ | ✓ | – | – | – |
| فایل‌ها و پشتیبان | `backup:server:write` | ساخت، اجرا و دانلود پشتیبان برنامه‌ها و گرفتن کلید | Create, run, download app backups; export keys | ✓ | ✓ | – | – | – | h |
| امنیت و اینترنت | `firewall:read` | دیدن وضعیت دیوار آتش و IPهای مسدود | See firewall and blocked IPs | ✓ | ✓ | ✓ | – | – | – |
| امنیت و اینترنت | `firewall:write` | تغییر حالت دیوار آتش، قواعد و مسدود کردن | Change firewall mode, rules and blocks | ✓ | ✓ | – | – | – | **c** |
| امنیت و اینترنت | `vuln:read` | دیدن مشکلات امنیتی برنامه‌ها | See vulnerability findings | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| امنیت و اینترنت | `vuln:write` | اسکن دستی، نادیده گرفتن و تنظیم بررسی امنیتی | Scan, ignore findings, change scan settings | ✓ | ✓ | ✓ | – | – | l |
| کاربران و دسترسی | `user:read` | دیدن افراد و نقش‌ها | See people and roles | ✓ | ✓ | – | – | – | – |
| کاربران و دسترسی | `user:write` | دعوت، غیرفعال کردن و تغییر نقش افراد | Invite, disable and change roles | ✓ | ✓ | – | – | – | **c** |
| کاربران و دسترسی | `token:read` | دیدن کلیدهای برنامه خود | See own app keys | ✓ | ✓ | – | ✓ | – | – |
| کاربران و دسترسی | `token:write` | ساخت و لغو کلید برنامه | Create and revoke app keys | ✓ | ✓ | – | ✓ | – | m |
| اعلان‌ها و تاریخچه | `notification:read` | دیدن کانال‌ها و قواعد اعلان | See alert channels and rules | ✓ | ✓ | ✓ | – | – | – |
| اعلان‌ها و تاریخچه | `notification:write` | افزودن/تغییر کانال و قواعد اعلان | Add/change alert channels and rules | ✓ | ✓ | – | – | – | m |
| اعلان‌ها و تاریخچه | `task:read` | دیدن کارهای در حال انجام | See background jobs | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| اعلان‌ها و تاریخچه | `task:write` | لغو یا تکرار کارها | Cancel or retry jobs | ✓ | ✓ | ✓ | – | – | l |
| اعلان‌ها و تاریخچه | `audit:read` | دیدن تاریخچه فعالیت | See activity history | ✓ | ✓ | ✓ | – | – | m |
| (owner only) | `*` | همه اجازه‌ها (فقط مالک) | All permissions (owner) | ✓ | – | – | – | – | **c** |

UX inconsistencies to fix while doing this (backend):
- Proxy/DNS management is gated by `upstream:write` but also controls notifications and backups traffic. Either rename it in the UI (as above, «… پروکسی، DNS») or add `network:write` later. Phase 3 should add `network:read/write` and keep `upstream:*` as an alias for one release.
- Monitoring settings need `agent:write`. Consider `metrics:write`.
- Token `scopes` ⊂ the user's permissions. The token wizard should offer presets: «فقط دیدن» (current `READ_ONLY_SCOPES`), «خواندن آمار برای Prometheus» (`system:read` + `metrics:read`), «برای CI: پیش‌دریافت بسته» (`cache:read`, `cache:write`), with custom scopes in Advanced.

---

## 6. Shared component kit (`src/kit/`)

| Component | Purpose / API sketch | Replaces |
|---|---|---|
| `AppShell` | layout: side nav (desktop), bottom nav (mobile), top bar, activity tray, attention bell; reads `nav.ts` | nav in `Dashboard.tsx` |
| `PageHeader` | `{title, subtitle?, icon?, primaryAction?, secondaryActions?, tabs?}`; sticky on mobile; one primary verb | ad-hoc headers in every panel |
| `GroupTabs` | hash-synced tabs `#/group/tab`, permission + advancedOnly filtering, scrollable on mobile | — |
| `SectionCard` | `{title, hint?, action?, status?, children, collapsible?, advanced?}`; `advanced` = renders only in Advanced or inside `AdvancedSection` | Card+CardContent repetition |
| `StatusPill` | `{tone: ok/warn/error/info/off, label}`; dot + text, never color alone; consistent wording table (`statusWords`) | `StatusChip`, many `Chip color=` |
| `AttentionList` / `AttentionItem` | Home + per-page "needs attention" strip | — |
| `QuickActionTile` | big icon + verb; permission-aware | — |
| `ChecklistCard` | getting-started steps with progress, dismiss, persisted | — |
| `EmptyState` | `{icon, title, body, action}` per §2.6 | `Alert severity="info"` empties |
| `ActionWizard` | stepper dialog: `steps:[{title, render, validate}]`, Back/Next/Finish, full-screen on xs, "test before save" step type | multi-field dialogs (add upstream, proxy, channel, backup job, bucket, agent pairing, Dokploy connect, invite) |
| `ConfirmDialog` / `useConfirm` (existing) | add `severity` ladder, `typedWord` that accepts a localized word or object name and maps to `backendToken`, `consequences: string[]`, `undo` hint | current `phrase` |
| `UndoSnackbar` | reversible actions (pin, toggle) show «برگرداندن» for 6 s | — |
| `HelpTip` | `(i)` popover with plain explanation + optional "learn more" link + glossary term | long hints in labels |
| `Term` | `<Term k="upstream"/>` renders the glossary word, first-use English in ( ), tooltip | inline jargon |
| `FriendlyError` | `{error}` → sentence + action + collapsed «جزئیات فنی» (Advanced: code, status, request id, copy) | `errorMessage` + `<code>` blocks |
| `TestResult` | uniform "امتحان اتصال" result: ok (latency in words) / fail (reason sentence) | 6 different test-result renders |
| `KeyValueList` | label/value rows, LTR `bdi` for technical values, copy buttons | ad-hoc `[label, value]` arrays |
| `CopyField` | read-only field + copy, with "copied" feedback | `copyText` usages |
| `SecretOnce` | shows a secret one time with forced acknowledge «کپی کردم» | S3 key, token, invite password, backup key |
| `ResponsiveList` | table on ≥ md, card list on xs; columns declare `advancedOnly` | tables in Access, Jobs, Notifications, S3, Backups |
| `RelativeTime`, `Bytes`, `Duration`, `Num` | formatting components over `format.ts` (Jalali, Persian digits) | scattered `formatX` |
| `DurationInput`, `BytesInput`, `PercentSlider`, `SchedulePicker` (presets + Advanced cron), `TimezonePicker`, `CidrListInput`, `ListInput` | typed inputs used by SettingsForm and wizards | free TextFields |
| `SettingsForm` | `{specs: SettingSpec[], values, onSave}` renders controls from registry schema: type→control, unit, min/max, enum labels, depends_on, restart/danger badges, reset-to-default, diff preview, per-field server errors | hand-built settings cards in Monitoring/Updates/Notifications/S3/Dokploy/DNS |
| `PermissionGate` | `<PermissionGate anyOf={[...]} fallback={<NoAccess role="مدیر"/>}>` with plain "who can" text | inline `hasPermission` + `noWrite` strings |
| `NoAccess` | «این کار فقط از دست «مدیر» برمی‌آید.» + who to ask | ~15 `noWrite/readOnly` strings |
| `AdvancedOnly`, `AdvancedSection` (existing) | unchanged API; `AdvancedSection` gets `danger` variant ("منطقه خطر") | — |
| `RoleCard`, `PermissionMatrix` | §5 | role list in Access |

Shared copy modules: `src/copy/common.ts` (generic words: save, cancel, refresh, retry, …), `src/copy/glossary.ts` (§2.8), `src/copy/errors.ts` (moved from `api.ts`, rewritten to §2.3, with `reasonFor(code, context)`), `src/copy/audit.ts` (action → sentence template: `user.create` → «{actor} کاربر {target} را ساخت»), `src/copy/kinds.ts` (job kinds, outbound kinds, statuses). Panels keep their own page-specific dicts but import the shared generic words.

---

## 7. Phased implementation plan

### Phase 0: foundations (1 agent, about 1–2 days, blocks the others)

**Agent A, "Kit & copy".** It owns: `src/kit/**` (new), `src/copy/**` (new), `ConfirmDialog.tsx`, `uiMode.tsx`, `format.ts`, `api.ts` (only `ERROR_TEXT`/`errorMessage` → delegate to `copy/errors.ts`; stop appending `detail` in fa), `polling.ts`, and `scripts/check-copy.mjs` (warning-only in Phase 0).
Deliverables: every component in §6 except `AppShell`, `RoleCard`, `PermissionMatrix`; the glossary; the errors rewrite; `SettingsForm` working against a static fixture of `SettingSpec[]` (the same TS type as BE1).
Exit check: `npm run typecheck && npm run build`, plus a kit demo route `#/__kit` (dev-only).

### Phase 1: parallel rework (4 frontend agents; disjoint files)

| Agent | Owns files (exclusive) | Work |
|---|---|---|
| **B: Shell & Home** | `Dashboard.tsx` → split into `AppShell.tsx` (kit), `nav.ts`, `HomePage.tsx`, `AboutPage.tsx`; `App.tsx`, `main.tsx`, `i18n.ts`, `Login.tsx`, `Setup.tsx`, `AuthShell.tsx`, `clients.ts`, `SettingsPage.tsx` (new, All settings screen using `SettingsForm` + registry API with a fixture fallback) | 7-group nav + legacy hash redirects, mobile bottom nav, Home (attention, quick actions, checklist, glance), top-bar tray/bell, server-driven password rule text, i18n rewrites §3.1 |
| **C: Packages + Security & internet** | `RegistriesPanel.tsx`, `PackagesPanel.tsx`, `UpstreamsPanel.tsx`, `UpstreamPolicyCard.tsx`, `NetworkPanel.tsx`, `DnsSettingsCard.tsx`, `ProxyControls.tsx`; new `PackagesPage.tsx` (tabs wrapper), `SecurityPage.tsx`, `FirewallPanel.tsx`, `VulnPanel.tsx` (Gate 19) | tabs per §1.1, wizards (add source, add proxy), Simple/Advanced split §4.2, copy rewrites §3.2, typed-confirm mapping |
| **D: Server & apps + Files & backups** | `ServerPanel.tsx`, `DockerTools.tsx`, `ContainerLogsDialog.tsx`, `MonitoringPanel.tsx`, `charts.tsx`, `DokployPanel.tsx`, `UpdatesPanel.tsx`, `S3Panel.tsx`, `S3Access.tsx`, `S3FileManager.tsx`, `ServerBackupsPanel.tsx`, `LifecyclePanel.tsx`; new `ServerPage.tsx`, `FilesPage.tsx`, `DbAdminPanel.tsx` (Gate 19) | agent-pairing wizard, backup wizard with schedule presets, bucket wizard + access-level cards, `SecretOnce`, `FriendlyError` replacing all `<code>{error_code}` blocks, settings sections via `SettingsForm` |
| **E: People + Alerts & history** | `AccessPanel.tsx` → split into `PeoplePanel.tsx`, `RolesPanel.tsx`, `AppKeysPanel.tsx`, `RegistrationCard.tsx`; `NotificationsPanel.tsx` (split into `ChannelsPanel.tsx`, `RulesPanel.tsx`, `DeliveriesPanel.tsx`); `JobsPanel.tsx`, `ObservabilityPanel.tsx` → `HistoryPanel.tsx`; new `PeoplePage.tsx`, `AlertsPage.tsx`, kit additions `RoleCard.tsx`, `PermissionMatrix.tsx` (inside `src/kit/people/`, owned by E) | role cards, 3-step invite, token presets, custom-role editor (behind a feature flag until BE2), channel wizards, event-family rules, humanized audit feed |

Conflict rules:
- Only B edits `i18n.ts`, `App.tsx` and `nav.ts`. Other agents register their page components by exporting `default` from their `*Page.tsx`. B wires the lazy imports from a list agreed up front (file names above are the contract).
- Only A edits `src/kit/**` and `src/copy/**` during Phase 0. In Phase 1, a needed kit change is a small PR to A, or a local component in the agent's own file (later promoted).
- Every agent removes jargon only in the files it owns. `check-copy.mjs` becomes blocking at the end of Phase 1.

### Phase 2: backend (parallel with Phase 1; Python agents)

| Task | Files | Detail |
|---|---|---|
| **BE1 Settings registry API** | new `settings_registry.py`; `SETTINGS` lists in `modules/{monitoring,updates_settings,vuln_settings,firewall,dbadmin,notifications,s3,server_backups,dokploy}.py`, `netresolve.py`, `config.py`, `auth.py`; routes in `main.py` | `SettingSpec` dataclass (schema §4.3); `GET /api/v1/settings/registry` (values filtered by the read permission of each group; secrets → `secret_configured`); `PATCH /api/v1/settings/values` dispatching to existing validators; startup values read from the effective config (redacted); tests: every PUT key + every `os.getenv("MRK_")` has a spec |
| **BE2 Custom roles** | migration `roles` table (`name` pk, `label_fa`, `label_en`, `description_fa/en`, `permissions` JSON, `builtin` bool, timestamps); `auth.py` (resolve `ROLE_PERMISSIONS` builtin ∪ DB roles, validation against `KNOWN_PERMISSIONS` frozenset, dependency closure, forbid `*`); `GET/POST/PATCH/DELETE /api/v1/roles` (`user:write`; roles granting `user:write` → owner only; delete → 409 if assigned); audit `role.create/update/delete`; sessions keep working (permissions computed per request) | |
| **BE3 Home summary** | new `modules/home.py` | `GET /api/v1/home/summary` → `{verdict, attention:[{id, severity, kind, params, route}], checklist:{steps, done}}` aggregated from existing stores; per-user checklist dismissal in `user_prefs` |
| **BE4 Error envelope** | `main.py` `_error_payload`, module routers | add `error.field` (for 422) and `error.reason` (stable machine sub-code, e.g. `last_enabled_upstream`) so the UI can localize without English `detail`; keep `message` for logs |
| **BE5 Promote env → runtime** | `auth.py`, `config.py`, `backup.py`, `catalog.py`, `tasks.py`, `modules/dokploy.py`, `modules/host_agent.py`, `modules/server_backups.py` | items marked `S→R` in §4.3 (session TTL, login rate limit, password policy, audit/session/backup/trash retention, catalog cache, integrity rescan, vacuum, dokploy concurrency/timeout/queue, agent check interval, backup concurrency); env stays as the default; panel value wins; audit |
| **BE6 Debt constants** | per docs/27 §6 + `K` rows | move to settings with the same defaults (Verdaccio uplink tuning, prefetch caps, spool reserve, heartbeat/retention, vuln constants except safety caps) |
| **BE7 Invites + must-change-password** | `auth.py`, `models.py`, migration, `main.py` | `POST /api/v1/invites`, `POST /api/v1/invites/{token}/accept`, `users.must_change_password` |
| **BE8 Permission split (optional)** | `auth.py` | `network:read/write`, `metrics:write`, with aliases |

### Phase 3: integration & polish (B + one QA agent)
- Wire `SettingsPage` and inline `SettingsForm`s to BE1. Turn on the custom-role editor (BE2), Home summary (BE3) and invite links (BE7).
- Make `check-copy.mjs` blocking. Add a Playwright smoke run at 375 px and 1280 px in fa and en. Run an RTL visual review of every page in both modes.
- Usability check with 3 non-technical users on 5 tasks: connect a project; add Telegram alerts; take a backup now; invite a teammate as viewer; find why npm is slow. Target: each finished in under 2 minutes with no help.
- Update docs: `docs/14-professional-admin-ui.md` (new IA), `docs/27` (registry is the source of truth), README screenshots.

Definition of done for each page: Simple mode has no Latin words except product names; no codes or IDs; every async action has a friendly success and failure message; empty states have an action; works at 375 px; every setting of that module is reachable in Advanced (inline or All settings); the RBAC "no access" text names a role.
