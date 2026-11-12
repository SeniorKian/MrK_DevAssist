/**
 * Friendly error catalog (docs/33 §2.3).
 *
 * Every backend `error.code` the panel can meet maps to one plain sentence in fa and en:
 * [what happened] + [likely reason / what to do]. An optional `action` names the one button
 * that helps (FriendlyError renders it). The backend English `message` is NEVER shown inside
 * a sentence; it is kept for the collapsed «جزئیات فنی» row in Advanced mode only.
 *
 * Use:
 *   errorSentence(language, error)            → string (toasts, Alerts)
 *   describeError(language, error)            → { message, action, field, technical }
 *   reasonFor(language, record.error_code)    → sentence for a stored failure code (jobs, runs, deliveries)
 *
 * Catalog sentences are context-neutral. When one module needs its own wording for a shared code,
 * add a scoped entry `"<scope>:<code>"` (e.g. `"firewall:invalid_rule"`) and pass the scope:
 * `describeError(language, error, "firewall")`, `errorSentence(…, "firewall")`, `<FriendlyError scope="firewall" />`.
 */
import type { Language } from "../i18n";
import type { Bi } from "./text";
import { planErrorSentence } from "./mySpace";

/** The single helpful next step for an error. FriendlyError turns it into a button. */
export type ErrorAction =
  | "retry"
  | "reload"
  | "signIn"
  | "askAdmin"
  | "pairAgent"
  | "connectDokploy"
  | "fixFields"
  | "refreshList";

export type ErrorEntry = Bi & {
  action?: ErrorAction;
  /** Form field the error belongs to, so pages can show it as helperText. */
  field?: string;
};

export const ERROR_ACTION_LABEL: Record<ErrorAction, Bi> = {
  retry: { fa: "دوباره امتحان کن", en: "Try again" },
  reload: { fa: "تازه کردن صفحه", en: "Reload the page" },
  signIn: { fa: "ورود دوباره", en: "Sign in again" },
  askAdmin: { fa: "چه کسی می‌تواند؟", en: "Who can do this?" },
  pairAgent: { fa: "وصل کردن دستیار سرور", en: "Connect the server helper" },
  connectDokploy: { fa: "وصل کردن Dokploy", en: "Connect Dokploy" },
  fixFields: { fa: "درست کردن خانه‌ها", en: "Fix the fields" },
  refreshList: { fa: "تازه کردن فهرست", en: "Refresh the list" }
};

/** Fallbacks by HTTP status / failure kind, used when a code is unknown. */
export const FALLBACK_ERRORS = {
  network: {
    fa: "سرور DevAssist جواب نمی‌دهد. اتصال اینترنت خودتان را بررسی کنید و چند لحظه بعد دوباره امتحان کنید.",
    en: "DevAssist isn't responding. Check your internet connection and try again in a moment.",
    action: "retry"
  },
  unauthorized: { fa: "زمان ورودتان تمام شده. لطفاً دوباره وارد شوید.", en: "Your sign-in has expired. Please sign in again.", action: "signIn" },
  forbidden: { fa: "نقش شما اجازه این کار را ندارد. از یک «مدیر» بخواهید.", en: "Your role can't do this. Ask an admin.", action: "askAdmin" },
  notFound: {
    fa: "این مورد پیدا نشد. شاید پاک شده باشد؛ صفحه را تازه کنید.",
    en: "We couldn't find this. It may have been removed; refresh the page.",
    action: "refreshList"
  },
  conflict: {
    fa: "الان نمی‌شود؛ چیزی هم‌زمان تغییر کرده. صفحه را تازه کنید و دوباره امتحان کنید.",
    en: "Not right now: something changed at the same time. Refresh and try again.",
    action: "refreshList"
  },
  validation: {
    fa: "چند خانه را باید درست کنید؛ با رنگ قرمز مشخص شده‌اند.",
    en: "A few fields need fixing; they're marked in red.",
    action: "fixFields"
  },
  tooLarge: { fa: "این فایل یا درخواست بیش از حد بزرگ است.", en: "This file or request is too large." },
  rateLimited: { fa: "درخواست‌ها زیاد شده. چند لحظه صبر کنید و دوباره امتحان کنید.", en: "Too many requests. Wait a moment and try again.", action: "retry" },
  server: {
    fa: "مشکلی در سرور پیش آمد. دوباره امتحان کنید؛ اگر باز هم نشد، به مدیر سامانه خبر دهید.",
    en: "Something went wrong on the server. Try again; if it keeps happening, tell your system admin.",
    action: "retry"
  },
  unavailable: {
    fa: "این بخش الان در دسترس نیست. چند لحظه بعد دوباره امتحان کنید.",
    en: "This part isn't available right now. Try again in a moment.",
    action: "retry"
  },
  generic: {
    fa: "کاری که خواستید انجام نشد. دوباره امتحان کنید؛ اگر باز هم نشد، به مدیر سامانه خبر دهید.",
    en: "That didn't work. Try again; if it keeps happening, tell your system admin.",
    action: "retry"
  }
} satisfies Record<string, ErrorEntry>;

/**
 * Backend error codes → sentences. Grouped by area. Keep sentences short, active and blame-free.
 * When adding a backend code, add it here too (check-copy does not verify this, code review does).
 */
export const ERROR_CATALOG: Record<string, ErrorEntry> = {
  // ── Sign-in, accounts, security ────────────────────────────────────────────
  csrf_failed: { fa: "این صفحه کهنه شده. یک بار صفحه را تازه کنید.", en: "This page is out of date. Please reload it.", action: "reload" },
  forbidden: FALLBACK_ERRORS.forbidden,
  http_error: FALLBACK_ERRORS.generic,
  internal_error: FALLBACK_ERRORS.server,
  validation_error: FALLBACK_ERRORS.validation,
  invalid_request: FALLBACK_ERRORS.validation,
  invalid_body: FALLBACK_ERRORS.validation,
  invalid_json: FALLBACK_ERRORS.validation,
  method_not_allowed: FALLBACK_ERRORS.generic,
  not_found: FALLBACK_ERRORS.notFound,
  not_allowed: { fa: "این کار این‌جا مجاز نیست.", en: "This isn't allowed here." },
  rate_limited: { fa: "چند بار پشت سر هم امتحان کردید. چند دقیقه صبر کنید و دوباره امتحان کنید.", en: "Too many attempts in a row. Wait a few minutes and try again.", action: "retry" },
  invalid_credentials: { fa: "نام کاربری یا رمز درست نیست.", en: "The username or password is wrong.", field: "password" },
  invalid_mfa_code: { fa: "این کد درست نیست. کد تازه برنامه را بنویسید.", en: "That code isn't right. Type the current code from the app.", field: "code" },
  mfa_challenge_invalid: { fa: "زمان ورود گذشت. دوباره نام کاربری و رمز را بنویسید.", en: "The sign-in timed out. Enter your username and password again." },
  mfa_enrollment_required: { fa: "پیش از ادامه، ورود دومرحله‌ای را روشن کنید.", en: "Turn on two-step sign-in before you continue." },
  mfa_already_enabled: { fa: "ورود دومرحله‌ای از قبل روشن است.", en: "Two-step sign-in is already on." },
  mfa_not_enabled: { fa: "ورود دومرحله‌ای خاموش است.", en: "Two-step sign-in is off." },
  mfa_enrollment_expired: { fa: "زمان راه‌اندازی گذشت. از اول شروع کنید.", en: "Setup timed out. Start again." },
  mfa_required_by_policy: { fa: "برای نقش شما ورود دومرحله‌ای لازم است و خاموش نمی‌شود.", en: "Your role requires two-step sign-in, so it can't be turned off." },
  mfa_unavailable: { fa: "ورود دومرحله‌ای روی این سرور در دسترس نیست.", en: "Two-step sign-in isn't available on this server." },
  reauthentication_required: { fa: "برای این کار یک بار خارج و دوباره وارد شوید.", en: "Sign out and in again to do this." },
  sso_required: { fa: "این حساب فقط با ورود یکپارچه سازمان وارد می‌شود.", en: "This account signs in with your organization's single sign-on only." },
  invalid_oidc_settings: { fa: "تنظیمات ورود یکپارچه کامل یا درست نیست.", en: "The single sign-on settings are incomplete or wrong." },
  invalid_mfa_policy: { fa: "دست‌کم یک نقش انتخاب کنید.", en: "Choose at least one role." },
  owner_only: { fa: "فقط مالک پنل می‌تواند این را عوض کند.", en: "Only the panel owner can change this." },
  use_sign_out: { fa: "برای این دستگاه از «خروج» استفاده کنید.", en: "Use Sign out for this device." },
  auth_failed: { fa: "نام کاربری یا رمز درست نیست.", en: "The username or password is wrong." },
  authentication_failed: { fa: "نام کاربری یا رمز درست نیست.", en: "The username or password is wrong." },
  password_mismatch: { fa: "دو رمزی که نوشتید یکی نیستند.", en: "The two passwords don't match.", field: "password_confirm" },
  weak_password: { fa: "این رمز ساده است. رمزی بلندتر با حرف و عدد انتخاب کنید.", en: "This password is too simple. Choose a longer one with letters and numbers.", field: "password" },
  invalid_secret_key: { fa: "این رمز کلید قابل قبول نیست. ۸ تا ۱۲۸ نویسه انگلیسی با حرف و عدد و بدون فاصله بنویسید.", en: "This secret can't be used. Use 8 to 128 English characters with letters and digits and no spaces.", field: "secret_access_key" },
  invalid_password: { fa: "این رمز قابل قبول نیست. رمزی بلندتر با حرف و عدد انتخاب کنید.", en: "This password can't be used. Choose a longer one with letters and numbers.", field: "password" },
  password_required: { fa: "رمز را بنویسید.", en: "Enter the password.", field: "password" },
  already_initialized: { fa: "حساب مالک قبلاً ساخته شده. با همان حساب وارد شوید.", en: "The owner account already exists. Sign in with it.", action: "signIn" },
  invalid_email: { fa: "نشانی ایمیل درست نیست؛ مثل name@example.com بنویسید.", en: "That email address isn't valid; write it like name@example.com.", field: "email" },
  invalid_name: { fa: "نام باید بین ۲ تا ۱۰۰ نویسه باشد.", en: "The name must be 2 to 100 characters.", field: "display_name" },
  invalid_username: { fa: "نام کاربری فقط می‌تواند حروف انگلیسی، عدد، نقطه، خط تیره و زیرخط داشته باشد.", en: "A username may only contain letters, digits, dots, dashes and underscores.", field: "username" },
  account_exists: { fa: "حسابی با این ایمیل از قبل هست. با همان وارد شوید.", en: "An account with this email already exists. Sign in with it.", field: "email" },
  setup_failed: { fa: "ساخت حساب مالک انجام نشد. دوباره امتحان کنید.", en: "Creating the owner account didn't work. Try again.", action: "retry" },
  setup_rejected: { fa: "ساخت حساب مالک پذیرفته نشد. خانه‌ها را بررسی کنید.", en: "The owner account couldn't be created. Check the fields.", action: "fixFields" },
  registration_failed: { fa: "ثبت‌نام انجام نشد. دوباره امتحان کنید.", en: "Sign-up didn't work. Try again.", action: "retry" },
  registration_rejected: { fa: "ثبت‌نام پذیرفته نشد. خانه‌ها را بررسی کنید.", en: "Sign-up wasn't accepted. Check the fields.", action: "fixFields" },
  invalid_user: { fa: "این حساب ساخته نشد. شاید این نام کاربری قبلاً گرفته شده باشد؛ نام دیگری بنویسید.", en: "This account wasn't created. The username may already be taken; try another.", field: "username" },
  invalid_user_update: { fa: "تغییر این حساب ذخیره نشد. خانه‌ها را بررسی کنید.", en: "The account change wasn't saved. Check the fields.", action: "fixFields" },
  invalid_token: { fa: "کلید برنامه ساخته نشد. نام و تاریخ انقضا را بررسی کنید.", en: "The app key wasn't created. Check its name and expiry.", action: "fixFields" },
  token_too_large: { fa: "این کلید بیش از حد بلند است.", en: "This key is too long." },
  confirmation_mismatch: { fa: "متن تأیید با چیزی که خواسته شده یکی نیست. دوباره بنویسید.", en: "The confirmation text doesn't match. Type it again.", field: "confirm" },
  confirmation_required: { fa: "برای اطمینان، نام همین مورد را در خانه تأیید بنویسید.", en: "To be sure, type this item's name in the confirmation box.", field: "confirm" },
  invalid_current_password: { fa: "رمز فعلی درست نیست.", en: "Your current password is wrong.", field: "current_password" },
  must_change_password: { fa: "پیش از ادامه، یک رمز تازه برای خودتان انتخاب کنید.", en: "Choose a new password before you continue.", field: "new_password" },
  invite_invalid: { fa: "این لینک دعوت درست نیست. از کسی که دعوتتان کرده لینک تازه بخواهید.", en: "This invite link isn't valid. Ask the person who invited you for a new one." },
  invite_expired: { fa: "مهلت این لینک دعوت تمام شده. از کسی که دعوتتان کرده لینک تازه بخواهید.", en: "This invite link has expired. Ask for a new one." },
  invite_used: { fa: "این لینک دعوت قبلاً استفاده شده. اگر حساب دارید، وارد شوید.", en: "This invite link was already used. If you have an account, sign in.", action: "signIn" },
  invite_pending: { fa: "برای این شخص یک دعوت باز وجود دارد.", en: "This person already has an open invite." },
  invalid_role: { fa: "این نقش ذخیره نشد. نام و اجازه‌های آن را بررسی کنید.", en: "This role wasn't saved. Check its name and permissions.", action: "fixFields" },
  unknown_role: { fa: "این نقش پیدا نشد. فهرست نقش‌ها را تازه کنید.", en: "This role wasn't found. Refresh the role list.", action: "refreshList" },
  role_name_exists: { fa: "نقش دیگری همین نام را دارد؛ نام دیگری بنویسید.", en: "Another role has this name; pick a different one.", field: "name" },
  builtin_role_immutable: { fa: "نقش‌های آماده عوض یا پاک نمی‌شوند. از روی آن یک نقش تازه بسازید.", en: "Built-in roles can't be changed or deleted. Make a copy instead." },
  role_in_use: { fa: "هنوز چند نفر این نقش را دارند. اول نقش آن‌ها را عوض کنید.", en: "Some people still have this role. Change their role first." },

  // ── Packages and package sources ──────────────────────────────────────────
  invalid_upstream: { fa: "این منبع دریافت ذخیره نشد. نشانی و ترتیب آن را بررسی کنید.", en: "This package source wasn't saved. Check its address and order.", action: "fixFields" },
  unsafe_upstream_delete: { fa: "این آخرین منبع فعال است. اول یک منبع دیگر اضافه یا روشن کنید.", en: "This is the last active source. Add or turn on another one first." },
  upstream_unavailable: { fa: "هیچ منبع دریافتی جواب نداد. اینترنت سرور یا پروکسی را بررسی کنید.", en: "No package source answered. Check the server's internet or proxy.", action: "retry" },
  invalid_credential: { fa: "نام کاربری یا رمز این منبع درست نیست.", en: "The username or password for this source is wrong.", field: "credential" },
  invalid_ecosystem: { fa: "فقط npm و PyPI پشتیبانی می‌شوند.", en: "Only npm and PyPI are supported." },
  ecosystem_unsupported: { fa: "فقط npm و PyPI پشتیبانی می‌شوند.", en: "Only npm and PyPI are supported." },
  invalid_package: { fa: "تغییر این بسته ذخیره نشد. نام و نسخه را بررسی کنید.", en: "The package change wasn't saved. Check the name and version.", action: "fixFields" },
  quarantine_reason_required: { fa: "بنویسید چرا این بسته را قرنطینه می‌کنید.", en: "Write why you're quarantining this package.", field: "reason" },
  package_pinned: { fa: "این بسته نگه‌داشته شده است. اول «دیگر نگه ندار» را بزنید.", en: "This package is kept. Choose “stop keeping” first." },
  package_quarantined: { fa: "این بسته در قرنطینه است. اول آن را از قرنطینه بیرون بیاورید.", en: "This package is quarantined. Release it first." },
  prefetch_failed: { fa: "پیش‌دریافت انجام نشد. اینترنت سرور یا منبع دریافت را بررسی کنید.", en: "The download-ahead didn't finish. Check the server's internet or the package source.", action: "retry" },
  refetch_failed: { fa: "دریافت دوباره از منبع انجام نشد. بعداً دوباره امتحان کنید.", en: "Fetching again from the source didn't work. Try again later.", action: "retry" },
  trash_delete_failed: { fa: "پاک کردن از سطل بازیافت انجام نشد. دوباره امتحان کنید.", en: "Removing it from the recycle bin didn't work. Try again.", action: "retry" },
  trash_restore_conflict: { fa: "بازگرداندن نشد؛ نسخه‌ای با همین نام دوباره ذخیره شده است.", en: "Couldn't restore: a copy with the same name was saved again." },
  checksum_mismatch: { fa: "فایل دریافتی خراب بود و کنار گذاشته شد. دوباره امتحان کنید.", en: "The downloaded file was damaged and was set aside. Try again.", action: "retry" },
  hash_mismatch: { fa: "فایل دریافتی خراب بود و کنار گذاشته شد. دوباره امتحان کنید.", en: "The downloaded file was damaged and was set aside. Try again.", action: "retry" },
  ssrf_rejected: { fa: "این نشانی به شبکه داخلی اشاره می‌کند و برای امنیت مسدود شد.", en: "This address points into the internal network and was blocked for safety." },

  // ── Network: DNS and proxies ──────────────────────────────────────────────
  invalid_dns_settings: { fa: "تنظیم DNS ذخیره نشد. نشانی سرورهای DNS را بررسی کنید؛ مثل 1.1.1.1", en: "The DNS setting wasn't saved. Check the DNS server addresses, like 1.1.1.1.", field: "servers" },
  dns_failed: { fa: "آدرس این نام پیدا نشد. املای نام یا تنظیم DNS را بررسی کنید.", en: "Couldn't find the address for this name. Check the spelling or the DNS setting." },
  invalid_proxy_name: { fa: "نام پروکسی باید کوتاه و بدون نویسه‌های خاص باشد.", en: "The proxy name should be short and plain.", field: "name" },
  invalid_proxy_type: { fa: "نوع پروکسی را از فهرست انتخاب کنید.", en: "Pick the proxy type from the list.", field: "type" },
  invalid_proxy_host: { fa: "نشانی پروکسی درست نیست؛ مثل 127.0.0.1 یا proxy.example.com بنویسید.", en: "The proxy address isn't valid; write it like 127.0.0.1 or proxy.example.com.", field: "host" },
  invalid_proxy_port: { fa: "پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد.", en: "The port must be a number from 1 to 65535.", field: "port" },
  invalid_port: { fa: "پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد.", en: "The port must be a number from 1 to 65535.", field: "port" },
  invalid_proxy_username: { fa: "نام کاربری پروکسی درست نیست.", en: "The proxy username isn't valid.", field: "username" },
  invalid_proxy_password: { fa: "رمز پروکسی درست نیست.", en: "The proxy password isn't valid.", field: "password" },
  invalid_no_proxy: { fa: "فهرست «بدون پروکسی» درست نیست. هر خط یک نشانی بنویسید.", en: "The “skip the proxy” list isn't valid. Write one address per line.", field: "no_proxy" },
  proxy_password_without_username: { fa: "برای رمز پروکسی، نام کاربری هم لازم است.", en: "A proxy password also needs a username.", field: "username" },
  proxy_name_taken: { fa: "پروکسی دیگری همین نام را دارد؛ نام دیگری بنویسید.", en: "Another proxy has this name; pick a different one.", field: "name" },
  too_many_proxies: { fa: "تعداد پروکسی‌ها به سقف رسیده. اول یکی را پاک کنید.", en: "You've reached the proxy limit. Remove one first." },
  proxy_credential_host_change: {
    fa: "وقتی نشانی پروکسی را عوض می‌کنید، رمزش را هم دوباره بنویسید. رمز قبلی برای امنیت به نشانی تازه فرستاده نمی‌شود.",
    en: "When you change the proxy address, enter its password again. For safety the old password isn't sent to a new address.",
    field: "password"
  },
  proxy_type_unsupported: { fa: "این سرویس با این نوع پروکسی کار نمی‌کند. پروکسی دیگری انتخاب کنید.", en: "This service doesn't work with that proxy type. Pick another proxy.", field: "proxy_id" },
  proxy_type_unsupported_for_npm: { fa: "npm فقط با پروکسی HTTP یا HTTPS کار می‌کند. پروکسی دیگری انتخاب کنید.", en: "npm only works with an HTTP or HTTPS proxy. Pick another proxy.", field: "proxy_id" },
  proxy_type_unsupported_for_email: { fa: "ایمیل فقط با پروکسی SOCKS کار می‌کند. پروکسی دیگری انتخاب کنید.", en: "Email only works through a SOCKS proxy. Pick another proxy.", field: "proxy_id" },
  proxy_in_use: { fa: "هنوز چند سرویس از این پروکسی استفاده می‌کنند. اول آن‌ها را به پروکسی دیگری ببرید.", en: "Some services still use this proxy. Move them to another one first." },
  proxy_not_found: { fa: "این پروکسی دیگر وجود ندارد. صفحه را تازه کنید.", en: "This proxy no longer exists. Refresh the page.", action: "refreshList" },
  proxy_unavailable: { fa: "پروکسی جواب نداد. روشن بودن و نشانی آن را بررسی کنید.", en: "The proxy didn't answer. Check that it's running and its address.", action: "retry" },
  no_default_proxy: { fa: "هنوز پروکسی پیش‌فرضی انتخاب نکرده‌اید.", en: "You haven't chosen a default proxy yet." },
  invalid_proxy_id: { fa: "پروکسی انتخاب‌شده دیگر وجود ندارد. یکی دیگر انتخاب کنید.", en: "The chosen proxy no longer exists. Pick another one.", field: "proxy_id" },
  connect_failed: { fa: "وصل نشدیم. نشانی، پورت و اینترنت سرور را بررسی کنید.", en: "Couldn't connect. Check the address, port and the server's internet.", action: "retry" },
  connect_timeout: { fa: "وصل شدن بیش از حد طول کشید. نشانی یا پروکسی را بررسی کنید.", en: "Connecting took too long. Check the address or proxy.", action: "retry" },
  read_timeout: { fa: "مقصد دیر جواب داد. چند لحظه بعد دوباره امتحان کنید.", en: "The other side answered too slowly. Try again in a moment.", action: "retry" },
  timeout: { fa: "بیش از حد طول کشید. چند لحظه بعد دوباره امتحان کنید.", en: "It took too long. Try again in a moment.", action: "retry" },
  invalid_url: { fa: "نشانی درست نیست؛ با https:// شروع کنید.", en: "That address isn't valid; start it with https://.", field: "url" },
  invalid_address: { fa: "نشانی درست نیست.", en: "That address isn't valid.", field: "address" },
  invalid_host: { fa: "نام یا نشانی سرور درست نیست.", en: "The server name or address isn't valid.", field: "host" },
  invalid_endpoint: { fa: "نشانی درست نیست؛ مثل https://s3.example.com بنویسید.", en: "That address isn't valid; write it like https://s3.example.com.", field: "endpoint" },
  invalid_timeout: { fa: "حداکثر زمان انتظار خارج از محدوده مجاز است.", en: "The maximum wait is outside the allowed range.", field: "timeout_seconds" },

  // ── Server helper (Agent) and Docker ──────────────────────────────────────
  agent_not_configured: { fa: "دستیار سرور هنوز وصل نشده.", en: "The server helper isn't connected yet.", action: "pairAgent" },
  agent_unreachable: { fa: "دستیار سرور جواب نمی‌دهد. مطمئن شوید روی سرور روشن است.", en: "The server helper isn't answering. Make sure it's running on the server.", action: "retry" },
  agent_unavailable: { fa: "دستیار سرور جواب نمی‌دهد. مطمئن شوید روی سرور روشن است.", en: "The server helper isn't answering. Make sure it's running on the server.", action: "retry" },
  agent_timeout: { fa: "دستیار سرور دیر جواب داد. چند لحظه بعد دوباره امتحان کنید.", en: "The server helper answered too slowly. Try again in a moment.", action: "retry" },
  agent_name_unresolved: { fa: "پنل نام دستیار سرور را پیدا نمی‌کند. پنل و دستیار باید در یک شبکه باشند («mrk-net» یا همان شبکه Dokploy)؛ نام سرویس و نام دیگرش در شبکه را هم بررسی کنید.", en: "The panel can't find the server helper by name. The panel and the helper must share the mrk-net network (or the same Dokploy network); check the service name/alias.", action: "retry" },
  agent_auth_failed: { fa: "دستیار سرور کد اتصال را قبول نکرد. کد تازه را از روی سرور بگیرید و دوباره وصل کنید.", en: "The server helper rejected the pairing code. Get a fresh code from the server and connect again.", action: "pairAgent" },
  agent_rejected: { fa: "دستیار سرور این درخواست را قبول نکرد.", en: "The server helper refused this request." },
  agent_key_required: { fa: "کد اتصال را بچسبانید.", en: "Paste the pairing code.", field: "key" },
  invalid_agent_key: { fa: "کد اتصال درست نیست. آن را دوباره از روی سرور کپی کنید.", en: "The pairing code isn't right. Copy it from the server again.", field: "key" },
  invalid_agent_url: { fa: "نشانی دستیار سرور درست نیست؛ مثل http://mrk-agent:8081 بنویسید.", en: "The server helper address isn't valid; write it like http://mrk-agent:8081.", field: "url" },
  invalid_agent_config: { fa: "تنظیم اتصال دستیار سرور ذخیره نشد. نشانی و کد اتصال را بررسی کنید.", en: "The server helper connection wasn't saved. Check the address and pairing code.", action: "fixFields" },
  agent_managed_by_env: { fa: "اتصال دستیار سرور در فایل Compose تنظیم شده و از این‌جا عوض نمی‌شود.", en: "The server helper connection is set in the Compose file and can't be changed here." },
  agent_managed_by_environment: { fa: "اتصال دستیار سرور در فایل Compose تنظیم شده و از این‌جا عوض نمی‌شود.", en: "The server helper connection is set in the Compose file and can't be changed here." },
  agent_not_found: { fa: "دستیار سرور این مورد را پیدا نکرد. فهرست را تازه کنید.", en: "The server helper couldn't find this. Refresh the list.", action: "refreshList" },
  agent_protocol_error: { fa: "پاسخ دستیار سرور ناقص بود. دوباره امتحان کنید.", en: "The server helper's answer was incomplete. Try again.", action: "retry" },
  agent_stream_incomplete: { fa: "ارسال داده از دستیار سرور نیمه‌کاره ماند. دوباره امتحان کنید.", en: "The data from the server helper stopped halfway. Try again.", action: "retry" },
  agent_stream_interrupted: { fa: "ارتباط با دستیار سرور وسط کار قطع شد. دوباره امتحان کنید.", en: "The connection to the server helper dropped midway. Try again.", action: "retry" },
  agent_docker_unavailable: { fa: "دستیار سرور به Docker دسترسی ندارد. تنظیم آن را روی سرور بررسی کنید.", en: "The server helper can't reach Docker. Check its setup on the server." },
  docker_unavailable: { fa: "Docker روی سرور جواب نمی‌دهد.", en: "Docker isn't answering on the server.", action: "retry" },
  docker_error: { fa: "Docker این کار را انجام نداد. دوباره امتحان کنید.", en: "Docker didn't do this. Try again.", action: "retry" },
  protected: { fa: "این کانتینر مال Dokploy است و برای امنیت از این‌جا خاموش یا پاک نمی‌شود.", en: "This container belongs to Dokploy and is protected from changes here." },
  container_protected: { fa: "این کانتینر مال Dokploy است و برای امنیت از این‌جا خاموش یا پاک نمی‌شود.", en: "This container belongs to Dokploy and is protected from changes here." },
  container_not_found: { fa: "این کانتینر دیگر وجود ندارد. فهرست را تازه کنید.", en: "This container no longer exists. Refresh the list.", action: "refreshList" },
  container_not_running: { fa: "این کانتینر روشن نیست. اول روشنش کنید.", en: "This container isn't running. Start it first." },
  invalid_container: { fa: "این کانتینر پیدا نشد. فهرست را تازه کنید.", en: "We couldn't find this container. Refresh the list.", action: "refreshList" },
  invalid_image: { fa: "نام نسخه برنامه درست نیست. مثل nginx:1.27 بنویسید.", en: "The image name isn't right. Write it like nginx:1.27.", field: "image" },
  invalid_reference: { fa: "نام نسخه برنامه درست نیست. مثل nginx:1.27 بنویسید.", en: "The image name isn't right. Write it like nginx:1.27.", field: "image" },
  image_not_found: { fa: "این نسخه برنامه پیدا نشد. فهرست را تازه کنید یا نام و برچسب نسخه را بررسی کنید.", en: "This image wasn't found. Refresh the list, or check the name and tag.", action: "refreshList" },
  pull_failed: { fa: "دریافت نسخه برنامه انجام نشد. اینترنت سرور یا نام نسخه را بررسی کنید.", en: "Downloading the image didn't work. Check the server's internet or the image name.", action: "retry" },
  pull_timeout: { fa: "دریافت نسخه برنامه بیش از حد طول کشید. بعداً دوباره امتحان کنید.", en: "Downloading the image took too long. Try again later.", action: "retry" },
  plan_changed: { fa: "از وقتی فهرست را دیدید چیزهایی عوض شده. فهرست تازه را یک بار دیگر ببینید.", en: "Things changed since you looked at the list. Review the fresh list once more." },
  images_mode: { fa: "نوع پاک‌سازی نسخه‌ها را از گزینه‌ها انتخاب کنید.", en: "Pick which images to clean up from the options." },
  targets: { fa: "دست‌کم یک مورد برای پاک‌سازی انتخاب کنید.", en: "Pick at least one thing to clean up." },
  volume_unsupported: { fa: "از این نوع فضای داده نمی‌شود پشتیبان گرفت.", en: "This kind of container data can't be backed up." },
  volume_unreadable: { fa: "این فضای داده خوانده نشد. دسترسی دستیار سرور به آن را بررسی کنید.", en: "This container data couldn't be read. Check the server helper's access to it." },
  invalid_volume: { fa: "این فضای داده پیدا نشد. فهرست را تازه کنید.", en: "This container data wasn't found. Refresh the list.", action: "refreshList" },
  invalid_query: { fa: "جست‌وجو درست نیست. عبارت کوتاه‌تری بنویسید.", en: "The search isn't valid. Try a shorter phrase.", field: "query" },
  invalid_search: { fa: "جست‌وجو درست نیست. عبارت کوتاه‌تری بنویسید.", en: "The search isn't valid. Try a shorter phrase.", field: "query" },
  invalid_limit: { fa: "تعداد خواسته‌شده خارج از محدوده مجاز است.", en: "The requested number is outside the allowed range.", field: "limit" },
  invalid_by: { fa: "مرتب‌سازی را از گزینه‌ها انتخاب کنید.", en: "Pick a sort option from the list." },
  invalid_range: { fa: "بازه زمانی را از گزینه‌ها انتخاب کنید.", en: "Pick a time range from the options." },
  body_too_large: FALLBACK_ERRORS.tooLarge,
  busy: { fa: "یک کار دیگر هم‌زمان در جریان است. کمی صبر کنید و دوباره امتحان کنید.", en: "Another job is running at the same time. Wait a little and try again.", action: "retry" },

  // ── Dokploy ───────────────────────────────────────────────────────────────
  dokploy_not_configured: { fa: "هنوز Dokploy را وصل نکرده‌اید.", en: "Dokploy isn't connected yet.", action: "connectDokploy" },
  dokploy_unreachable: { fa: "DevAssist نتوانست به Dokploy وصل شود. نشانی آن و روشن بودنش را بررسی کنید.", en: "DevAssist couldn't reach Dokploy. Check its address and that it's running.", action: "retry" },
  dokploy_unavailable: { fa: "Dokploy الان جواب نمی‌دهد. چند لحظه بعد دوباره امتحان کنید.", en: "Dokploy isn't answering right now. Try again in a moment.", action: "retry" },
  dokploy_timeout: { fa: "Dokploy دیر جواب داد. چند لحظه بعد دوباره امتحان کنید.", en: "Dokploy answered too slowly. Try again in a moment.", action: "retry" },
  dokploy_auth_failed: { fa: "Dokploy این کلید را قبول نکرد. در Dokploy یک کلید تازه بسازید و این‌جا بگذارید.", en: "Dokploy didn't accept this key. Create a new key in Dokploy and paste it here.", action: "connectDokploy" },
  dokploy_api_key_required: { fa: "کلید Dokploy را بچسبانید.", en: "Paste the Dokploy key.", field: "api_key" },
  invalid_dokploy_api_key: { fa: "کلید Dokploy درست نیست. آن را دوباره از Dokploy کپی کنید.", en: "The Dokploy key isn't right. Copy it from Dokploy again.", field: "api_key" },
  invalid_dokploy_url: { fa: "نشانی Dokploy درست نیست؛ مثل https://dokploy.example.com بنویسید.", en: "The Dokploy address isn't valid; write it like https://dokploy.example.com.", field: "url" },
  invalid_dokploy_config: { fa: "تنظیم Dokploy ذخیره نشد. نشانی و کلید را بررسی کنید.", en: "The Dokploy setting wasn't saved. Check the address and key.", action: "fixFields" },
  dokploy_forbidden: { fa: "Dokploy به این کلید اجازه این کار را نمی‌دهد. در Dokploy دسترسی کاربری را که این کلید را ساخته بررسی کنید.", en: "Dokploy doesn't let this key do that. Check the key owner's access in Dokploy." },
  dokploy_failed: { fa: "Dokploy نتوانست این کار را انجام دهد. چند لحظه بعد دوباره امتحان کنید یا وضعیت را در خود Dokploy ببینید.", en: "Dokploy couldn't do this. Try again in a moment, or check it in Dokploy itself.", action: "retry" },
  invalid_dokploy_public_url: { fa: "نشانی Dokploy در مرورگر درست نیست؛ مثل https://dokploy.example.com بنویسید یا خالی بگذارید.", en: "The Dokploy browser address isn't valid; write it like https://dokploy.example.com or leave it empty.", field: "public_url" },
  dokploy_rate_limited: { fa: "برای این‌که به Dokploy فشار نیاید، کمی صبر کنید و دوباره امتحان کنید.", en: "To go easy on Dokploy, wait a moment and try again.", action: "retry" },
  dokploy_rejected: { fa: "Dokploy این درخواست را قبول نکرد. وضعیت برنامه را در خود Dokploy ببینید.", en: "Dokploy refused this request. Check the app in Dokploy itself." },
  dokploy_not_found: { fa: "این مورد در Dokploy پیدا نشد. فهرست را تازه کنید.", en: "This wasn't found in Dokploy. Refresh the list.", action: "refreshList" },
  dokploy_service_not_found: { fa: "این برنامه در Dokploy پیدا نشد. شاید پاک شده باشد؛ فهرست را تازه کنید.", en: "This app wasn't found in Dokploy. It may have been removed; refresh the list.", action: "refreshList" },
  bucket_domain_route_failed: { fa: "مسیر این دامنه ساخته یا برداشته نشد. چند لحظه بعد دوباره امتحان کنید؛ وضعیت آن در «دامنه‌های اختصاصی باکت‌ها» دیده می‌شود.", en: "The route of this domain couldn't be updated. Try again in a moment; its state is shown under Custom bucket domains." },
  s3_dokploy_target_required: { fa: "اول سرویس Compose مربوط به فضای فایل را از فهرست انتخاب و ذخیره کنید.", en: "Choose and save the Compose service that runs S3 first." },
  dokploy_deployment_not_found: { fa: "این انتشار در Dokploy پیدا نشد. فهرست را تازه کنید.", en: "This deployment wasn't found in Dokploy. Refresh the list.", action: "refreshList" },
  dokploy_managed_by_environment: { fa: "اتصال Dokploy در فایل Compose تنظیم شده و از این‌جا عوض نمی‌شود.", en: "The Dokploy connection is set in the Compose file and can't be changed here." },
  invalid_service_type: { fa: "نوع برنامه در Dokploy شناخته نشد. فهرست را تازه کنید.", en: "Unknown Dokploy app type. Refresh the list.", action: "refreshList" },
  invalid_service_id: { fa: "این برنامه پیدا نشد. فهرست را تازه کنید.", en: "This app wasn't found. Refresh the list.", action: "refreshList" },
  invalid_deployment_id: { fa: "این انتشار پیدا نشد. فهرست را تازه کنید.", en: "This deployment wasn't found. Refresh the list.", action: "refreshList" },
  invalid_action: { fa: "این کار برای این مورد شناخته نشد.", en: "This action isn't available for this item." },

  // ── Image updates and registries ──────────────────────────────────────────
  auth_required: { fa: "مخزن نسخه‌ها برای این برنامه ورود می‌خواهد.", en: "The image registry needs a sign-in for this app." },
  digest_unavailable: { fa: "مخزن نسخه‌ها شناسه نسخه را نداد؛ بررسی این برنامه ممکن نشد.", en: "The registry didn't give a version fingerprint, so this app couldn't be checked." },
  digest_mismatch: { fa: "نسخه دریافتی با نسخه مورد انتظار یکی نیست.", en: "The downloaded version doesn't match the expected one." },
  manifest_too_large: { fa: "پاسخ مخزن نسخه‌ها بیش از حد بزرگ بود.", en: "The registry's answer was too large." },
  invalid_token_realm: { fa: "مخزن نسخه‌ها نشانی ورود نامعمولی داد و برای امنیت رد شد.", en: "The registry gave an unusual sign-in address and was refused for safety." },
  invalid_response: { fa: "پاسخ مقصد قابل فهم نبود. بعداً دوباره امتحان کنید.", en: "The answer couldn't be understood. Try again later.", action: "retry" },
  precondition_failed: { fa: "شرایط این کار دیگر برقرار نیست. فهرست را تازه کنید.", en: "This can't be done any more. Refresh the list.", action: "refreshList" },
  invalid_ignore: { fa: "الگوی نادیده‌گرفتن درست نیست؛ مثل nginx:* بنویسید.", en: "The ignore pattern isn't valid; write it like nginx:*.", field: "ignore" },

  // ── Panel backups and restore ─────────────────────────────────────────────
  backup_not_found: { fa: "این فایل پشتیبان دیگر روی سرور نیست. فهرست را تازه کنید.", en: "This backup file is no longer on the server. Refresh the list.", action: "refreshList" },
  backup_download_rejected: { fa: "این فایل پشتیبان قابل دانلود نیست؛ شاید خراب یا در حال ساخت باشد.", en: "This backup file can't be downloaded; it may be damaged or still being made." },
  backup_validation_failed: { fa: "فایل پشتیبان باز نشد. رمز پشتیبان یا خود فایل را بررسی کنید.", en: "The backup file couldn't be opened. Check the backup password or the file.", field: "passphrase" },
  restore_plan_rejected: { fa: "آماده‌سازی بازگردانی انجام نشد. رمز پشتیبان و متن تأیید را بررسی کنید.", en: "Preparing the restore didn't work. Check the backup password and confirmation text.", action: "fixFields" },
  backup_rejected: { fa: "این پشتیبان پذیرفته نشد. فایل را بررسی کنید.", en: "This backup wasn't accepted. Check the file." },
  backup_unavailable: { fa: "پشتیبان‌گیری از پنل الان ممکن نیست. فضای دیسک و رمز پشتیبان را بررسی کنید.", en: "A panel backup isn't possible right now. Check disk space and the backup password." },
  unknown_profile: { fa: "نوع پشتیبان شناخته نشد. یکی از گزینه‌ها را انتخاب کنید.", en: "Unknown backup type. Pick one of the options." },
  unknown_format: { fa: "این فایل، پشتیبان DevAssist نیست.", en: "This file isn't an DevAssist backup." },
  unsupported_kdf: { fa: "این پشتیبان با روشی ساخته شده که این نسخه DevAssist آن را نمی‌شناسد.", en: "This backup was made in a way this DevAssist version doesn't recognise." },
  corrupt: { fa: "فایل پشتیبان آسیب دیده است. فایل دیگری انتخاب کنید.", en: "The backup file is damaged. Pick another file." },
  invalid_archive: { fa: "فایل پشتیبان آسیب دیده یا ناقص است.", en: "The backup file is damaged or incomplete." },
  insufficient_space: { fa: "فضای دیسک کافی نیست. اول کمی فضا آزاد کنید.", en: "There isn't enough disk space. Free some space first." },
  storage_unavailable: { fa: "فضای ذخیره‌سازی در دسترس نیست.", en: "Storage isn't available." },

  // ── Background jobs ───────────────────────────────────────────────────────
  cleanup_target_required: { fa: "بگویید چه چیزی پاک شود: فهرست بسته‌ها یا اندازه فضایی که باید آزاد شود.", en: "Say what to clean up: a list of packages or how much space to free.", action: "fixFields" },
  nothing_to_clean: { fa: "چیزی برای پاک کردن نیست؛ فضای کافی دارید یا بسته‌ها نگه‌داشته شده‌اند.", en: "There's nothing to clean up; you have enough space or the packages are kept.", action: "refreshList" },
  "lifecycle:confirmation_mismatch": { fa: "فهرست بسته‌ها از وقتی آن را دیدید عوض شده. پیش‌نمایش تازه را ببینید و دوباره تأیید کنید.", en: "The package list changed since you looked. Review the fresh preview and confirm again.", action: "refreshList" },
  job_not_found: { fa: "این کار دیگر وجود ندارد. فهرست را تازه کنید.", en: "This job no longer exists. Refresh the list.", action: "refreshList" },
  job_running: { fa: "این کار همین حالا در حال انجام است. صبر کنید تا تمام شود.", en: "This is already running. Wait for it to finish." },
  too_many_jobs: { fa: "کارهای زیادی هم‌زمان در جریان است. کمی بعد دوباره امتحان کنید.", en: "Too many jobs are running at once. Try again shortly.", action: "retry" },
  cancelled: { fa: "این کار لغو شد.", en: "This job was cancelled." },
  interrupted: { fa: "این کار نیمه‌کاره ماند؛ احتمالاً سرویس وسط کار دوباره راه‌اندازی شد.", en: "This job stopped halfway, probably because the service restarted." },
  expired: { fa: "مهلت این مورد تمام شده است.", en: "This has expired." },
  backup_retry_unsupported: { fa: "این کار را نمی‌شود تکرار کرد؛ یک پشتیبان تازه بسازید.", en: "This job can't be retried; create a new backup instead." },

  // ── File space (S3) ───────────────────────────────────────────────────────
  // «فضای من» (docs/43 §3): the quota sentence with the limit's name and numbers is built by my/MyError.tsx.
  "my:quota_exceeded": { fa: "به سقف بسته‌تان رسیده‌اید. اول چیزی پاک کنید یا بسته بزرگ‌تری بخواهید.", en: "You've reached your plan's limit. Remove something first, or ask for a bigger plan." },
  feature_disabled: { fa: "این امکان در بسته شما نیست. برای داشتنش با مدیر سامانه صحبت کنید.", en: "This isn't in your plan. Talk to the system admin to get it." },
  workspace_suspended: { fa: "این فضا موقتاً بسته شده و فقط می‌شود دید. برای باز شدنش با مدیر سامانه صحبت کنید.", en: "This space is paused, so you can only look. Talk to the system admin to reopen it." },
  zone_unavailable: { fa: "این دامنه را نمی‌شود این‌جا آورد؛ یا مال فضای دیگری است یا بخشی از خود DevAssist است.", en: "This domain can't be added here: it belongs to another space or to DevAssist itself.", field: "name" },
  zone_not_verified: { fa: "مالکیت این دامنه هنوز ثابت نشده. رکورد را بگذارید و چند دقیقه بعد «بررسی کن» را بزنید.", en: "This domain isn't proven yet. Add the record and press “Check now” in a few minutes." },
  verification_failed: { fa: "رکورد اثبات هنوز پیدا نشد. اگر همین الان گذاشته‌اید، چند دقیقه بعد دوباره امتحان کنید.", en: "The proof record isn't visible yet. If you just added it, try again in a few minutes.", action: "retry" },
  plan_in_use: { fa: "این بسته هنوز به چند فضا داده شده. اول بسته آن‌ها را عوض کنید.", en: "Some workspaces still use this plan. Change their plan first." },
  plan_not_found: { fa: "این بسته پیدا نشد؛ شاید پاک شده باشد. فهرست را تازه کنید.", en: "That plan wasn't found; it may be gone. Refresh the list.", action: "refreshList" },
  workspace_not_found: { fa: "این فضا پیدا نشد؛ شاید پاک شده باشد. صفحه را تازه کنید.", en: "That space wasn't found; it may be gone. Refresh the page.", action: "refreshList" },
  not_a_member: { fa: "شما عضو این فضا نیستید. از صاحب فضا بخواهید دعوتتان کند.", en: "You're not a member of this space. Ask its owner to invite you." },
  role_escalation: { fa: "نمی‌توانید نقشی بالاتر از نقش خودتان بدهید.", en: "You can't give a role above your own.", field: "role" },
  last_owner: { fa: "این فضا دست‌کم یک صاحب لازم دارد. اول یک صاحب دیگر بگذارید.", en: "This space needs at least one owner. Make someone else owner first." },
  already_member: { fa: "این شخص همین حالا عضو این فضاست.", en: "This person is already a member.", field: "user" },
  user_not_found: { fa: "کسی با این ایمیل یا نام کاربری پیدا نشد. املایش را بررسی کنید.", en: "Nobody has that email or username. Check the spelling.", field: "user" },
  tenancy_disabled: { fa: "«فضای من» هنوز روشن نشده. از مدیر سامانه بخواهید روشنش کند.", en: "My space isn't turned on yet. Ask the system admin to turn it on." },
  view_as_read_only: { fa: "در حالت «دیدن به‌جای» فقط می‌شود دید؛ چیزی تغییر نمی‌کند.", en: "In view-as mode you can only look; nothing changes." },
  view_as_expired: { fa: "زمان «دیدن به‌جای» تمام شده. اگر لازم است دوباره شروع کنید.", en: "The view-as time is over. Start again if you need to." },
  scope_escalation: { fa: "کلید نمی‌تواند کاری بیشتر از نقش خودتان بکند.", en: "A key can't do more than your own role.", field: "scopes" },
  "my:permission_escalation": { fa: "نمی‌توانید نقش یا دسترسی‌ای بالاتر از نقش خودتان در این فضا بدهید.", en: "You can't give a role or access above your own in this space." },
  "my:forbidden": { fa: "نقش شما در این فضا اجازه این کار را نمی‌دهد. از صاحب فضا بخواهید.", en: "Your role in this space can't do this. Ask the space's owner." },
  "my:not_found": { fa: "این مورد پیدا نشد؛ شاید پاک شده یا مال فضای دیگری است. صفحه را تازه کنید.", en: "We couldn't find this; it may be gone or belong to another space. Refresh the page.", action: "refreshList" },
  permission_escalation: { fa: "نمی‌توانید نقش یا دسترسی‌ای بالاتر از نقش خودتان بدهید.", en: "You can't give a role or access above your own." },
  scope_unavailable: { fa: "این نام بسته در دسترس نیست؛ قبلاً بسته‌های عمومی با همین نام ذخیره شده. با مدیر سامانه صحبت کنید.", en: "This package scope isn't available: public packages with this name are already stored. Talk to the system admin." },
  personal_workspace: { fa: "فضای شخصی فقط مال خودتان است و عضو نمی‌پذیرد. برای کار گروهی یک فضای تیمی بسازید.", en: "A personal space is just for you. Make a team space to work with others." },
  plan_builtin: { fa: "بسته‌های آماده را نمی‌شود پاک کرد؛ فقط تغییرشان دهید.", en: "Ready-made plans can't be deleted; you can only edit them." },
  plan_default: { fa: "این بسته پیش‌فرض است. اول بسته دیگری را پیش‌فرض کنید.", en: "This is the default plan. Make another plan the default first." },
  dns_record_type_not_allowed: { fa: "بسته شما این نوع رکورد را اجازه نمی‌دهد. نوع دیگری انتخاب کنید.", en: "Your plan doesn't allow this record type. Pick another type.", field: "type" },
  admin_area_local_only: { fa: "بخش «مدیریت سرور» فقط از همین شبکه یا شبکه خصوصی باز می‌شود.", en: "Server admin only opens from this network or the private network (VPN)." },
  signup_pending: { fa: "ثبت‌نام شما رسید و منتظر تأیید مدیر سامانه است.", en: "Your sign-up arrived and is waiting for the system admin's approval." },
  bucket_exists: { fa: "پوشه اصلی دیگری همین نام را دارد؛ نام دیگری بنویسید.", en: "Another bucket has this name; pick a different one.", field: "name" },
  bucket_not_empty: { fa: "این پوشه اصلی خالی نیست. اگر مطمئنید، گزینه «پاک کردن با همه فایل‌ها» را بزنید.", en: "This bucket isn't empty. If you're sure, choose “delete with all files”." },
  bucket_not_found: { fa: "این پوشه اصلی پیدا نشد. فهرست را تازه کنید.", en: "This bucket wasn't found. Refresh the list.", action: "refreshList" },
  bucket_read_only: { fa: "این پوشه فقط‌خواندنی است؛ نمی‌شود در آن فایل گذاشت یا پاک کرد.", en: "This folder is read-only; files can't be added or removed." },
  invalid_bucket: { fa: "این پوشه اصلی پیدا نشد. فهرست را تازه کنید.", en: "This bucket wasn't found. Refresh the list.", action: "refreshList" },
  invalid_bucket_name: { fa: "نام پوشه اصلی فقط می‌تواند حروف کوچک انگلیسی، عدد و خط تیره داشته باشد؛ ۳ تا ۶۳ نویسه.", en: "A bucket name may only use lowercase letters, digits and dashes; 3 to 63 characters.", field: "name" },
  invalid_bucket_mode: { fa: "نوع پوشه اصلی را از گزینه‌ها انتخاب کنید.", en: "Pick the bucket type from the options.", field: "mode" },
  invalid_link_mode: { fa: "برای پوشه سرور، «فقط خواندن» یا «خواندن و نوشتن» را انتخاب کنید.", en: "For a server folder, choose “read only” or “read and write”.", field: "link_mode" },
  engine_unreachable: { fa: "فضای فایل الان جواب نمی‌دهد. چند لحظه بعد دوباره امتحان کنید.", en: "File space isn't answering right now. Try again in a moment.", action: "retry" },
  s3_name_unresolved: { fa: "پنل نام سرویس فضای فایل را پیدا نمی‌کند. پنل و آن باید در یک شبکه باشند («mrk-net» یا همان شبکه Dokploy)؛ نام سرویس و نام دیگرش در شبکه را هم بررسی کنید.", en: "The panel can't find the file space service by name. The panel and the service must share the mrk-net network (or the same Dokploy network); check the service name/alias.", action: "retry" },
  storage_not_ready: { fa: "پوشه‌هایی که برای داده‌ها انتخاب کرده‌اید آماده نیستند. در مرحله تنظیمات «بررسی پوشه‌ها» را بزنید و دستورهایی را که نشان می‌دهد روی سرور اجرا کنید.", en: "The folders you picked for the data aren't ready. In the settings step press “Check the folders” and run the commands it shows on the server.", action: "retry" },
  registry_name_unresolved: { fa: "پنل نام این مخزن را پیدا نمی‌کند. پنل و مخزن باید در یک شبکه باشند («mrk-net» یا همان شبکه Dokploy)؛ نام سرویس و نام دیگرش در شبکه را هم بررسی کنید.", en: "The panel can't find this registry by name. The panel and the registry must share the mrk-net network (or the same Dokploy network); check the service name/alias.", action: "retry" },
  registry_unreachable: { fa: "مخزن جواب نمی‌دهد. مطمئن شوید سرویس آن روشن است.", en: "The registry isn't answering. Make sure its service is running.", action: "retry" },
  registry_timeout: { fa: "مخزن دیر جواب داد؛ شاید سرش شلوغ است یا تازه روشن شده. چند لحظه بعد دوباره نگاه کنید.", en: "The registry answered too slowly; it may be busy or just starting. Look again in a moment.", action: "retry" },
  registry_bootstrapping: { fa: "مخزن PyPI هنوز در حال آماده شدن است.", en: "The PyPI registry is still getting ready." },
  engine_error: { fa: "فضای فایل این کار را انجام نداد. دوباره امتحان کنید.", en: "File space didn't do this. Try again.", action: "retry" },
  engine_access_denied: { fa: "فضای فایل اجازه این کار را نداد.", en: "File space didn't allow this." },
  engine_auth_failed: { fa: "فضای فایل کلید دسترسی را قبول نکرد.", en: "File space didn't accept the access key." },
  identity_exists: { fa: "کاربر فضای فایل دیگری همین نام را دارد؛ نام دیگری بنویسید.", en: "Another file-space user has this name; pick a different one.", field: "name" },
  identity_not_found: { fa: "این کاربر فضای فایل پیدا نشد. فهرست را تازه کنید.", en: "This file-space user wasn't found. Refresh the list.", action: "refreshList" },
  invalid_identity_name: { fa: "نام کاربر فقط می‌تواند حروف انگلیسی، عدد و خط تیره داشته باشد.", en: "The user name may only use letters, digits and dashes.", field: "name" },
  name_taken: { fa: "این نام قبلاً گرفته شده؛ نام دیگری بنویسید.", en: "This name is already taken; pick another.", field: "name" },
  invalid_policy: { fa: "سطح دسترسی ذخیره نشد. یکی از سطح‌های آماده را انتخاب کنید.", en: "The access level wasn't saved. Pick one of the ready-made levels.", field: "policy" },
  invalid_policy_template: { fa: "سطح دسترسی را از گزینه‌ها انتخاب کنید.", en: "Pick an access level from the options.", field: "policy" },
  invalid_public_endpoint: { fa: "آدرس عمومی درست نیست؛ مثل https://s3.example.com بنویسید.", en: "The public address isn't valid; write it like https://s3.example.com.", field: "public_endpoint" },
  public_endpoint_not_configured: { fa: "آدرس عمومی فضای فایل هنوز تنظیم نشده؛ لینک‌ها فقط داخل همین سرور کار می‌کنند.", en: "The file space public address isn't set, so links only work inside this server." },
  invalid_virtual_host_suffix: { fa: "پسوند دامنه باید مثل s3.example.com باشد.", en: "The domain suffix should look like s3.example.com.", field: "virtual_host_suffix" },
  invalid_region: { fa: "منطقه فقط می‌تواند حروف کوچک انگلیسی، عدد و خط تیره داشته باشد.", en: "The region may only use lowercase letters, digits and dashes.", field: "region" },
  invalid_quota: { fa: "سقف حجم باید عددی بزرگ‌تر از صفر باشد.", en: "The size limit must be greater than zero.", field: "quota_bytes" },
  invalid_object_key: { fa: "نام یا مسیر فایل درست نیست. نویسه‌های خاص و «..» را حذف کنید.", en: "The file name or path isn't valid. Remove special characters and “..”.", field: "key" },
  invalid_key: { fa: "نام یا مسیر فایل درست نیست.", en: "The file name or path isn't valid.", field: "key" },
  invalid_prefix: { fa: "مسیر پوشه درست نیست.", en: "The folder path isn't valid.", field: "prefix" },
  invalid_delimiter: { fa: "جداکننده پوشه‌ها درست نیست.", en: "The folder separator isn't valid." },
  invalid_move: { fa: "این جابه‌جایی ممکن نیست؛ نمی‌شود پوشه را به داخل خودش برد.", en: "This move isn't possible; a folder can't go inside itself." },
  invalid_expiry: { fa: "لینک اشتراک حداکثر ۷ روز اعتبار دارد.", en: "A share link can last at most 7 days.", field: "expires_in" },
  invalid_access_key: { fa: "کلید دسترسی درست نیست.", en: "The access key isn't valid.", field: "access_key" },
  key_not_found: { fa: "این کلید پیدا نشد. فهرست را تازه کنید.", en: "This key wasn't found. Refresh the list.", action: "refreshList" },
  key_limit_reached: { fa: "این کاربر به سقف تعداد کلید رسیده. اول یک کلید قدیمی را پاک کنید.", en: "This user has the maximum number of keys. Remove an old one first." },
  link_path_in_use: { fa: "این پوشه سرور قبلاً به پوشه اصلی دیگری وصل شده است.", en: "This server folder is already linked to another bucket.", field: "link_path" },
  link_path_invalid: { fa: "فقط پوشه‌هایی که در فایل Compose به DevAssist داده شده‌اند قابل اتصال‌اند.", en: "Only folders given to DevAssist in the Compose file can be linked.", field: "link_path" },
  linked_requires_owner: { fa: "فقط «مالک» می‌تواند پوشه‌های سرور را وصل کند.", en: "Only the owner can link server folders." },
  object_not_found: { fa: "این فایل پیدا نشد. فهرست را تازه کنید.", en: "This file wasn't found. Refresh the list.", action: "refreshList" },
  object_too_large: { fa: "این فایل از سقف حجم مجاز بزرگ‌تر است.", en: "This file is larger than the allowed size." },
  quota_exceeded: { fa: "سقف حجم این پوشه اصلی پر شده. اول چند فایل پاک کنید یا سقف را بیشتر کنید.", en: "This bucket's size limit is full. Remove some files or raise the limit." },
  too_many_objects: { fa: "تعداد موارد زیاد است؛ در چند دسته کوچک‌تر انجام دهید.", en: "Too many items; do it in smaller batches." },
  too_large: FALLBACK_ERRORS.tooLarge,
  upload_aborted: { fa: "آپلود نیمه‌کاره ماند. دوباره امتحان کنید.", en: "The upload stopped halfway. Try again.", action: "retry" },
  upload_not_found: { fa: "این آپلود دیگر وجود ندارد؛ از اول شروع کنید.", en: "This upload no longer exists; start again." },
  invalid_content_length: { fa: "حجم فایل مشخص نیست. دوباره آپلود کنید.", en: "The file size is unclear. Upload it again.", action: "retry" },
  s3_invalid_response: { fa: "پاسخ فضای فایل مقصد قابل فهم نبود.", en: "The destination file space gave an answer we couldn't understand." },
  s3_too_many_parts: { fa: "این فایل برای ارسال به فضای فایل مقصد بیش از حد بزرگ است.", en: "This file is too large to send to the destination file space." },
  s3_auth_failed: { fa: "فضای فایل مقصد این کلید را قبول نکرد. کلید دسترسی و رمز کلید را بررسی کنید.", en: "The destination file space didn't accept this key. Check the access key and secret.", field: "access_key" },
  s3_bucket_not_found: { fa: "پوشه اصلی مقصد پیدا نشد. نام آن را بررسی کنید.", en: "The destination bucket wasn't found. Check its name.", field: "bucket" },
  s3_object_not_found: { fa: "فایل در فضای فایل مقصد پیدا نشد.", en: "The file wasn't found in the destination file space." },
  s3_clock_skew: { fa: "ساعت سرور با فضای فایل مقصد فرق دارد. ساعت سرور را تنظیم کنید.", en: "The server clock is out of sync with the destination file space. Fix the server time." },
  clock_skew: { fa: "ساعت دستگاه با سرور فرق دارد. ساعت را تنظیم کنید.", en: "The device clock is out of sync with the server. Fix the time." },
  bad_signature: { fa: "امضای درخواست درست نبود. کلید دسترسی و رمز کلید را بررسی کنید.", en: "The request signature was wrong. Check the access key and secret." },
  replay: { fa: "این درخواست تکراری بود و برای امنیت رد شد.", en: "This request was a repeat and was refused for safety." },
  nonce_cache_full: FALLBACK_ERRORS.rateLimited,
  missing_headers: FALLBACK_ERRORS.generic,
  malformed_headers: FALLBACK_ERRORS.generic,
  invalid_header: FALLBACK_ERRORS.generic,

  // ── App backups (server backups) ──────────────────────────────────────────
  destination_in_use: { fa: "هنوز چند برنامه پشتیبان از این مقصد استفاده می‌کنند. اول آن‌ها را عوض کنید.", en: "Some backup schedules still use this destination. Change them first." },
  destination_not_found: { fa: "این مقصد پیدا نشد. فهرست را تازه کنید.", en: "This destination wasn't found. Refresh the list.", action: "refreshList" },
  invalid_destination: { fa: "مقصد پشتیبان ذخیره نشد. نشانی و کلیدها را بررسی کنید.", en: "The backup destination wasn't saved. Check the address and keys.", action: "fixFields" },
  destination_forbidden: { fa: "این مقصد برای امنیت مجاز نیست؛ مقصد دیگری انتخاب کنید.", en: "This destination isn't allowed for safety; pick another." },
  path_forbidden: { fa: "این پوشه مال خود DevAssist است؛ پوشه دیگری انتخاب کنید.", en: "This folder belongs to DevAssist itself; pick another folder.", field: "path" },
  path_not_writable: { fa: "DevAssist نمی‌تواند در این پوشه بنویسد. دسترسی پوشه را بررسی کنید.", en: "DevAssist can't write to this folder. Check its permissions.", field: "path" },
  invalid_path: { fa: "مسیر پوشه درست نیست.", en: "The folder path isn't valid.", field: "path" },
  invalid_schedule: { fa: "زمان‌بندی را نفهمیدیم. یکی از گزینه‌های آماده را انتخاب کنید.", en: "We couldn't understand the schedule. Pick one of the ready-made options.", field: "schedule" },
  invalid_retention: { fa: "تعداد یا مدت نگه‌داری باید عددی مثبت باشد.", en: "How many or how long to keep must be a positive number.", field: "retention" },
  invalid_source: { fa: "منبع پشتیبان پیدا نشد. فهرست برنامه‌ها را تازه کنید.", en: "The backup source wasn't found. Refresh the app list.", action: "refreshList" },
  invalid_source_path: { fa: "مسیر منبع پشتیبان درست نیست.", en: "The backup source path isn't valid.", field: "path" },
  invalid_kind: { fa: "نوع را از گزینه‌ها انتخاب کنید.", en: "Pick a type from the options.", field: "kind" },
  invalid_timezone: { fa: "منطقه زمانی را از فهرست انتخاب کنید.", en: "Pick a time zone from the list.", field: "timezone" },
  source_failed: { fa: "DevAssist نتوانست از منبع پشتیبان بخواند. روشن بودن برنامه را بررسی کنید.", en: "DevAssist couldn't read from the backup source. Check that the app is running." },
  dump_failed: { fa: "گرفتن خروجی از پایگاه داده انجام نشد. نام کاربری و رمز پایگاه داده را بررسی کنید.", en: "Exporting the database didn't work. Check the database username and password." },
  archive_failed: { fa: "بسته‌بندی فایل‌های پشتیبان انجام نشد. فضای دیسک را بررسی کنید.", en: "Packing the backup files didn't work. Check disk space." },
  credentials_unavailable: { fa: "نام کاربری و رمز پایگاه داده پیدا نشد. آن‌ها را در تنظیم پشتیبان بنویسید.", en: "The database username and password weren't found. Add them to the backup setup." },
  credentials_unsupported: { fa: "برای این نوع پایگاه داده پشتیبان‌گیری با رمز پشتیبانی نمی‌شود.", en: "Backups with a password aren't supported for this kind of database." },
  credentials_required: { fa: "نام کاربری و رمز لازم است.", en: "A username and password are needed.", field: "username" },
  key_unavailable: { fa: "کلید رمزگذاری این پشتیبان در دسترس نیست. کلید را از پشتیبان کلیدها بازگردانی کنید.", en: "This backup's encryption key isn't available. Restore it from your key backup." },
  artifact_unavailable: { fa: "این اجرا فایلی برای دانلود ندارد.", en: "This run has no file to download." },
  artifact_missing: { fa: "فایل این پشتیبان دیگر در جای نگه‌داری نیست.", en: "This backup's file is no longer at its storage place." },
  artifact_damaged: { fa: "فایل پشتیبان آسیب دیده یا با کلید دیگری رمز شده و باز نشد.", en: "The backup file is damaged or was encrypted with another key, so it couldn't be opened." },
  artifact_mismatch: { fa: "این فایل پشتیبان مال برنامه دیگری است.", en: "This backup file belongs to another schedule." },
  "server_backups:checksum_mismatch": { fa: "فایل پشتیبان بعد از ذخیره تغییر کرده است؛ به آن اعتماد نکنید.", en: "The backup file changed after it was saved; don't trust it." },
  unsafe_archive: { fa: "این پشتیبان فایل‌هایی دارد که می‌خواستند بیرون از پوشه بازگردانی نوشته شوند؛ برای امنیت کار متوقف شد.", en: "This backup has files that tried to write outside the restore folder; it was stopped for safety." },
  target_exists: { fa: "پوشه‌ای با این نام از قبل هست. نام دیگری بنویسید؛ چیزی رونویسی نمی‌شود.", en: "A folder with this name already exists. Pick another name; nothing is overwritten.", field: "target" },
  invalid_target: { fa: "نام پوشه فقط می‌تواند حرف و عدد انگلیسی و . _ - داشته باشد.", en: "The folder name can only have English letters, digits and . _ -", field: "target" },
  restore_running: { fa: "این پشتیبان همین حالا در حال بازگردانی است. صبر کنید تمام شود.", en: "This backup is already being restored. Wait for it to finish." },
  invalid_dump: { fa: "خروجی پایگاه داده در این پشتیبان قالب درستی ندارد.", en: "The database export in this backup isn't in the right format." },
  empty_dump: { fa: "خروجی پایگاه داده در این پشتیبان خالی است.", en: "The database export in this backup is empty." },
  send_failed: { fa: "ارسال به مقصد انجام نشد. اینترنت سرور و تنظیم مقصد را بررسی کنید.", en: "Sending to the destination didn't work. Check the server's internet and the destination.", action: "retry" },
  read_failed: { fa: "خواندن فایل انجام نشد.", en: "Reading the file didn't work." },
  rollback_failed: { fa: "برگرداندن تغییرات کامل انجام نشد. وضعیت را بررسی کنید.", en: "Undoing the changes didn't fully work. Check the current state." },
  symlink: { fa: "این مسیر یک میان‌بُر است و برای امنیت دنبال نمی‌شود.", en: "This path is a shortcut and isn't followed, for safety." },
  symlink_rejected: { fa: "این مسیر یک میان‌بُر است و برای امنیت دنبال نمی‌شود.", en: "This path is a shortcut and isn't followed, for safety." },
  truncated: { fa: "فقط بخشی از نتیجه نمایش داده شد.", en: "Only part of the result is shown." },
  client_closed: { fa: "ارتباط وسط کار قطع شد.", en: "The connection was closed midway." },

  // ── Alerts (notifications) ────────────────────────────────────────────────
  invalid_channel: { fa: "کانال اعلان ذخیره نشد. خانه‌ها را بررسی کنید.", en: "The alert channel wasn't saved. Check the fields.", action: "fixFields" },
  invalid_rule: { fa: "قاعده ذخیره نشد. خانه‌های آن را بررسی کنید.", en: "The rule wasn't saved. Check its fields.", action: "fixFields" },
  invalid_notification_settings: { fa: "تنظیم اعلان‌ها ذخیره نشد. خانه‌ها را بررسی کنید.", en: "The alert settings weren't saved. Check the fields.", action: "fixFields" },
  channel_name_taken: { fa: "کانال دیگری همین نام را دارد؛ نام دیگری بنویسید.", en: "Another channel has this name; pick a different one.", field: "name" },
  channel_deleted: { fa: "این کانال پاک شده است.", en: "This channel was removed." },
  channel_disabled: { fa: "این کانال خاموش است. اول روشنش کنید.", en: "This channel is turned off. Turn it on first." },
  kind_immutable: { fa: "نوع کانال بعد از ساخت عوض نمی‌شود. یک کانال تازه بسازید.", en: "A channel's type can't change after it's created. Make a new channel instead." },
  invalid_bot_token: { fa: "توکن ربات درست نیست. آن را دوباره از سازنده ربات کپی کنید.", en: "The bot token isn't right. Copy it again from the bot maker.", field: "bot_token" },
  invalid_chat_id: { fa: "شناسه گفتگو درست نیست. یک پیام به ربات بدهید و دوباره امتحان کنید.", en: "The chat ID isn't right. Send the bot a message and try again.", field: "chat_id" },
  invalid_channel_id: { fa: "این کانال پیدا نشد. فهرست را تازه کنید.", en: "This channel wasn't found. Refresh the list.", action: "refreshList" },
  invalid_api_base_url: { fa: "نشانی سرور ربات درست نیست؛ با https:// شروع کنید.", en: "The bot server address isn't valid; start it with https://.", field: "api_base_url" },
  invalid_parse_mode: { fa: "قالب پیام را از گزینه‌ها انتخاب کنید.", en: "Pick a message format from the options.", field: "parse_mode" },
  invalid_smtp_host: { fa: "نشانی سرور ایمیل درست نیست؛ مثل smtp.gmail.com بنویسید.", en: "The email server address isn't valid; write it like smtp.gmail.com.", field: "smtp_host" },
  invalid_smtp_port: { fa: "پورت سرور ایمیل باید عددی بین ۱ تا ۶۵۵۳۵ باشد؛ معمولاً ۵۸۷.", en: "The email server port must be 1 to 65535; usually 587.", field: "smtp_port" },
  invalid_smtp_security: { fa: "نوع اتصال امن ایمیل را از گزینه‌ها انتخاب کنید.", en: "Pick the email security option from the list.", field: "security" },
  invalid_smtp_username: { fa: "نام کاربری ایمیل درست نیست.", en: "The email username isn't valid.", field: "username" },
  invalid_from_address: { fa: "نشانی فرستنده درست نیست؛ مثل alerts@example.com بنویسید.", en: "The sender address isn't valid; write it like alerts@example.com.", field: "from_address" },
  invalid_to_addresses: { fa: "نشانی گیرنده‌ها درست نیست. هر خط یک ایمیل بنویسید.", en: "The recipient addresses aren't valid. Write one email per line.", field: "to_addresses" },
  insecure_smtp_auth: { fa: "برای ورود به سرور ایمیل، اتصال امن را روشن کنید.", en: "Turn on a secure connection to sign in to the email server.", field: "security" },
  smtp_auth_failed: { fa: "سرور ایمیل نام کاربری یا رمز را قبول نکرد. برای جیمیل از «رمز برنامه» استفاده کنید.", en: "The email server rejected the username or password. For Gmail, use an app password." },
  smtp_rejected: { fa: "سرور ایمیل پیام را قبول نکرد. نشانی فرستنده و گیرنده را بررسی کنید.", en: "The email server refused the message. Check the sender and recipient addresses." },
  invalid_headers: { fa: "سرآیندهای اضافه درست نیستند. هر خط به شکل «نام: مقدار» بنویسید.", en: "The extra headers aren't valid. Write one “Name: value” per line.", field: "headers" },
  invalid_signing_key: { fa: "کلید امضا درست نیست؛ دست‌کم ۱۶ نویسه بنویسید.", en: "The signing key isn't valid; use at least 16 characters.", field: "signing_key" },
  invalid_event_pattern: { fa: "نوع رویدادها را از فهرست انتخاب کنید.", en: "Pick event types from the list.", field: "pattern" },
  invalid_severity: { fa: "شدت را از گزینه‌ها انتخاب کنید.", en: "Pick a severity from the options.", field: "severity" },
  invalid_quiet_hours: { fa: "ساعات سکوت درست نیست؛ ساعت شروع و پایان را مثل ۲۳:۰۰ بنویسید.", en: "Quiet hours aren't valid; write start and end like 23:00.", field: "quiet_hours" },
  invalid_retry_max_seconds: { fa: "بیشترین فاصله تلاش دوباره باید از کمترین آن بزرگ‌تر باشد.", en: "The longest retry wait must be larger than the shortest.", field: "retry_max_seconds" },
  destination_not_allowed: { fa: "این نشانی به شبکه داخلی همین سرور اشاره می‌کند و برای امنیت مجاز نیست.", en: "This address points into this server's own network and isn't allowed, for safety.", field: "url" },
  secret_required: { fa: "رمز یا توکن را بنویسید.", en: "Enter the password or token.", field: "secret" },
  invalid_secret: { fa: "رمز یا توکن درست نیست.", en: "The password or token isn't valid.", field: "secret" },
  secret_unavailable: { fa: "رمز ذخیره‌شده در دسترس نیست؛ آن را دوباره بنویسید.", en: "The saved secret isn't available; enter it again.", field: "secret" },
  duplicate: { fa: "این پیام به‌تازگی فرستاده شده بود و تکرار نشد.", en: "This message was sent recently, so it wasn't repeated." },

  // ── Settings in general ───────────────────────────────────────────────────
  invalid_settings: { fa: "تنظیمات ذخیره نشد. خانه‌های قرمز را درست کنید.", en: "The settings weren't saved. Fix the fields in red.", action: "fixFields" },
  invalid_config: { fa: "تنظیمات ذخیره نشد. خانه‌های قرمز را درست کنید.", en: "The settings weren't saved. Fix the fields in red.", action: "fixFields" },
  invalid_enabled: { fa: "مقدار روشن/خاموش درست نیست.", en: "The on/off value isn't valid." },
  invalid_mode: { fa: "حالت را از گزینه‌ها انتخاب کنید.", en: "Pick a mode from the options.", field: "mode" },
  invalid_options: { fa: "گزینه‌های انتخاب‌شده با هم جور نیستند.", en: "The chosen options don't go together." },
  invalid_filter: { fa: "فیلتر درست نیست.", en: "The filter isn't valid." },
  invalid_sort: { fa: "مرتب‌سازی را از گزینه‌ها انتخاب کنید.", en: "Pick a sort option from the list." },
  invalid_state: { fa: "این مورد الان در وضعیتی نیست که این کار را بپذیرد.", en: "This item can't take that action in its current state." },
  invalid_status: { fa: "وضعیت انتخاب‌شده درست نیست.", en: "The chosen status isn't valid." },

  // ── Firewall ──────────────────────────────────────────────────────────────
  firewall_not_configured: { fa: "نگهبان دیوار آتش هنوز وصل نشده.", en: "The firewall helper isn't connected yet." },
  firewall_unreachable: { fa: "نگهبان دیوار آتش جواب نمی‌دهد. روشن بودن آن را روی سرور بررسی کنید.", en: "The firewall helper isn't answering. Check that it's running on the server.", action: "retry" },
  firewall_name_unresolved: { fa: "پنل نام نگهبان دیوار آتش را پیدا نمی‌کند. پنل و آن باید در یک شبکه باشند («mrk-net» یا همان شبکه Dokploy)؛ نام سرویس و نام دیگرش در شبکه را هم بررسی کنید.", en: "The panel can't find the firewall helper by name. The panel and the helper must share the mrk-net network (or the same Dokploy network); check the service name/alias.", action: "retry" },
  firewall_timeout: { fa: "نگهبان دیوار آتش دیر جواب داد. دوباره امتحان کنید.", en: "The firewall helper answered too slowly. Try again.", action: "retry" },
  firewall_auth_failed: { fa: "نگهبان دیوار آتش کد اتصال را قبول نکرد. کد تازه را از روی سرور بگیرید.", en: "The firewall helper rejected the pairing code. Get a fresh code from the server." },
  firewall_key_required: { fa: "کد اتصال نگهبان دیوار آتش را بچسبانید.", en: "Paste the firewall helper's pairing code.", field: "key" },
  invalid_firewall_key: { fa: "کد اتصال درست نیست. آن را دوباره از روی سرور کپی کنید.", en: "The pairing code isn't right. Copy it from the server again.", field: "key" },
  invalid_firewall_url: { fa: "نشانی نگهبان دیوار آتش درست نیست.", en: "The firewall helper address isn't valid.", field: "url" },
  firewall_managed_by_environment: { fa: "اتصال دیوار آتش در فایل Compose تنظیم شده و از این‌جا عوض نمی‌شود.", en: "The firewall connection is set in the Compose file and can't be changed here." },
  firewall_rejected: { fa: "نگهبان دیوار آتش این تغییر را قبول نکرد.", en: "The firewall helper refused this change." },
  nft_failed: { fa: "اعمال قاعده روی دیوار آتش سرور انجام نشد. دوباره امتحان کنید.", en: "Applying the rule to the server firewall didn't work. Try again.", action: "retry" },
  nft_unavailable: { fa: "دیوار آتش سرور در دسترس نیست؛ فعلاً فقط حالت تمرین ممکن است.", en: "The server firewall isn't available; only practice mode works for now." },
  already_blocked: { fa: "این نشانی همین حالا مسدود است.", en: "This address is already blocked." },
  max_blocks: { fa: "فهرست مسدودها پر شده. چند مورد قدیمی را آزاد کنید.", en: "The block list is full. Release some old entries." },
  max_blocks_reached: { fa: "فهرست مسدودها پر شده. چند مورد قدیمی را آزاد کنید.", en: "The block list is full. Release some old entries." },
  invalid_block: { fa: "نشانی یا محدوده IP درست نیست؛ مثل 203.0.113.7 بنویسید.", en: "The IP address or range isn't valid; write it like 203.0.113.7.", field: "address" },
  builtin_rule: { fa: "قواعد آماده پاک نمی‌شوند؛ فقط می‌توانید خاموششان کنید.", en: "Built-in rules can't be deleted, only turned off." },
  rule_name_taken: { fa: "قاعده دیگری همین نام را دارد؛ نام دیگری بنویسید.", en: "Another rule has this name; pick a different one.", field: "name" },
  requester_ip: { fa: "این نشانی خود شماست؛ مسدودش نمی‌کنیم تا از سرور بیرون نمانید.", en: "That's your own address; we won't block it so you don't get locked out." },
  host_address: { fa: "این نشانی مال خود سرور است و مسدود نمی‌شود.", en: "That address belongs to the server itself and can't be blocked." },
  private_range: { fa: "نشانی‌های داخلی شبکه مسدود نمی‌شوند. اگر لازم است، در حالت پیشرفته اجازه‌اش را بدهید.", en: "Internal network addresses aren't blocked. If you need to, allow it in Advanced mode." },
  allowlisted: { fa: "این نشانی در فهرست همیشه مجاز است. اول از آن فهرست برش دارید.", en: "This address is on the always-allowed list. Remove it from that list first." },
  prefix_too_broad: { fa: "این محدوده خیلی بزرگ است؛ یک محدوده کوچک‌تر بنویسید.", en: "This range is too large; write a smaller one." },
  loopback: { fa: "نشانی‌های داخلی خود سرور (مثل 127.0.0.1) مسدود نمی‌شوند.", en: "The server's own loopback addresses (like 127.0.0.1) can't be blocked." },
  reserved_address: { fa: "این نشانی رزروشده است و مسدود کردنش معنی ندارد.", en: "This is a reserved address; blocking it makes no sense." },
  "firewall:invalid_address": { fa: "نشانی درست نیست؛ مثل 203.0.113.7 یا 203.0.113.0/24 بنویسید.", en: "That address isn't valid; write it like 203.0.113.7 or 203.0.113.0/24.", field: "address" },
  "firewall:invalid_rule": { fa: "قاعده ذخیره نشد؛ نام، تعداد و مدت را بررسی کنید.", en: "The rule wasn't saved; check its name, count and period.", action: "fixFields" },
  ignore_not_found: { fa: "این مورد نادیده‌گرفته‌شده پیدا نشد. فهرست را تازه کنید.", en: "This ignore entry wasn't found. Refresh the list.", action: "refreshList" },

  // ── Security scan ─────────────────────────────────────────────────────────
  scan_failed: { fa: "بررسی امنیتی تمام نشد. بعداً دوباره امتحان کنید.", en: "The security check didn't finish. Try again later.", action: "retry" },
  feed_unavailable: { fa: "فهرست مشکلات امنیتی دریافت نشد. اینترنت سرور یا پروکسی را بررسی کنید.", en: "The security issue list couldn't be downloaded. Check the server's internet or proxy.", action: "retry" },
  feed_too_large: { fa: "فهرست مشکلات امنیتی از سقف حجم تعیین‌شده بزرگ‌تر است.", en: "The security issue list is larger than the set size limit." },
  "vuln:image_not_found": { fa: "این برنامه دیگر در فهرست نیست؛ فهرست را تازه کنید.", en: "This app isn't on the list anymore; refresh the list.", action: "refreshList" },
  "vuln:invalid_ignore": { fa: "قاعده ذخیره نشد؛ دست‌کم شناسه مشکل یا نام بسته و یک دلیل لازم است.", en: "The rule wasn't saved; it needs at least an issue id or a package name, and a reason.", action: "fixFields" },
  "vuln:invalid_settings": { fa: "تنظیمات ذخیره نشد؛ عددها را بررسی کنید.", en: "The settings weren't saved; check the numbers.", action: "fixFields" },
  "vuln:proxy_not_found": { fa: "این پروکسی دیگر وجود ندارد؛ یکی دیگر انتخاب کنید.", en: "That proxy no longer exists; pick another one." },
  feed_invalid_zip: { fa: "فایل فهرست مشکلات امنیتی خراب بود. بعداً دوباره امتحان کنید.", en: "The security issue list file was damaged. Try again later.", action: "retry" },

  // ── Databases ─────────────────────────────────────────────────────────────
  db_unreachable: { fa: "به پایگاه داده وصل نشدیم. نشانی و روشن بودن آن را بررسی کنید.", en: "Couldn't reach the database. Check its address and that it's running.", action: "retry" },
  db_unresolvable: { fa: "نشانی پایگاه داده پیدا نشد. نام سرور را بررسی کنید.", en: "Couldn't find the database address. Check the server name.", field: "host" },
  db_auth_failed: { fa: "پایگاه داده نام کاربری یا رمز را قبول نکرد.", en: "The database rejected the username or password.", field: "password" },
  db_timeout: { fa: "پایگاه داده دیر جواب داد. درخواست را ساده‌تر کنید یا بعداً امتحان کنید.", en: "The database answered too slowly. Simplify the request or try later.", action: "retry" },
  db_query_failed: { fa: "پایگاه داده این درخواست را اجرا نکرد. متن درخواست را بررسی کنید.", en: "The database didn't run this request. Check the request text.", field: "text" },
  connection_busy: { fa: "این اتصال الان مشغول است. صبر کنید کار قبلی تمام شود.", en: "This connection is busy. Wait for the previous request to finish.", action: "retry" },
  invalid_database: { fa: "نام پایگاه داده درست نیست.", en: "The database name isn't valid.", field: "database" },
  invalid_engine: { fa: "نوع پایگاه داده را از گزینه‌ها انتخاب کنید.", en: "Pick the database type from the options.", field: "engine" },
  invalid_tls_mode: { fa: "نوع اتصال امن را از گزینه‌ها انتخاب کنید.", en: "Pick a secure-connection option from the list.", field: "tls_mode" },
  invalid_table: { fa: "این جدول پیدا نشد.", en: "This table wasn't found.", field: "table" },
  table_not_found: { fa: "این جدول پیدا نشد. فهرست را تازه کنید.", en: "This table wasn't found. Refresh the list.", action: "refreshList" },
  schema_required: { fa: "اول پایگاه داده را از فهرست انتخاب کنید.", en: "Pick a database from the list first.", field: "schema" },
  engine_mismatch: { fa: "این کار برای این نوع پایگاه داده نیست.", en: "This isn't available for this kind of database." },
  unsupported_for_engine: { fa: "این کار برای این نوع پایگاه داده پشتیبانی نمی‌شود.", en: "This isn't supported for this kind of database." },
  read_only_violation: { fa: "این درخواست چیزی را تغییر می‌دهد؛ در حالت «فقط خواندن» اجرا نمی‌شود.", en: "This request changes data, so it can't run in read-only mode." },
  write_required: { fa: "برای این کار باید حالت نوشتن را روشن کنید.", en: "Turn on write mode for this." },
  dry_run_unsupported: { fa: "امتحان بدون اجرا برای این نوع پایگاه داده ممکن نیست.", en: "A dry run isn't possible for this kind of database." },
  export_invalid: { fa: "برای خروجی، فقط یکی از جدول یا درخواست را انتخاب کنید.", en: "For an export, pick either a table or a query, not both." },
  export_unsupported: { fa: "از این نوع داده نمی‌شود فایل خروجی گرفت.", en: "This kind of data can't be exported to a file." },
  unsupported_format: { fa: "این قالب فایل پشتیبانی نمی‌شود.", en: "This file format isn't supported." },
  query_invalid: { fa: "درخواست برای این نوع پایگاه داده درست نیست.", en: "The request doesn't fit this kind of database.", field: "text" },
  sql_empty: { fa: "متن درخواست خالی است.", en: "The request is empty.", field: "text" },
  sql_invalid: { fa: "متن درخواست SQL قابل فهم نیست. آن را بررسی کنید.", en: "The SQL request couldn't be understood. Check it.", field: "text" },
  sql_too_long: { fa: "متن درخواست بیش از حد بلند است.", en: "The request is too long.", field: "text" },
  sql_unterminated: { fa: "متن درخواست ناتمام است؛ یک نقل‌قول یا پرانتز بسته نشده.", en: "The request is unfinished; a quote or bracket isn't closed.", field: "text" },
  sql_executable_comment: { fa: "این نوع توضیح در متن درخواست برای امنیت مجاز نیست.", en: "This kind of comment isn't allowed in a request, for safety.", field: "text" },
  mongo_invalid: { fa: "متن درخواست MongoDB درست نیست.", en: "The MongoDB request isn't valid.", field: "text" },
  mongo_filter_required: { fa: "برای این کار در MongoDB یک فیلتر بنویسید.", en: "Write a filter for this MongoDB action.", field: "filter" },
  mongo_op_denied: { fa: "این دستور MongoDB برای امنیت مجاز نیست.", en: "This MongoDB command isn't allowed, for safety." },
  mongo_operator_denied: { fa: "این دستور MongoDB برای امنیت مجاز نیست.", en: "This MongoDB operator isn't allowed, for safety." },
  redis_command_denied: { fa: "این دستور Redis برای امنیت مجاز نیست.", en: "This Redis command isn't allowed, for safety." },
  redis_command_invalid: { fa: "دستور Redis شناخته نشد.", en: "Unknown Redis command.", field: "text" },
  redis_args_invalid: { fa: "ورودی‌های دستور Redis درست نیستند.", en: "The Redis command arguments aren't valid.", field: "text" },

  // ── Services and domains (docs/35) ────────────────────────────────────────
  service_not_found: { fa: "این سرویس پیدا نشد. صفحه را تازه کنید.", en: "This service wasn't found. Refresh the page.", action: "refreshList" },
  service_not_controllable: { fa: "این سرویس از پنل روشن و خاموش نمی‌شود؛ فقط وضعیتش را می‌بینید.", en: "This service can't be started or stopped from the panel; you can only see its status." },
  service_action_not_allowed: { fa: "این کار برای این سرویس ممکن نیست.", en: "This action isn't possible for this service." },
  action_not_allowed: { fa: "این کار برای این سرویس ممکن نیست.", en: "This action isn't possible for this service." },
  "services:invalid_action": { fa: "این کار شناخته نشد. صفحه را تازه کنید.", en: "This action isn't recognised. Reload the page.", action: "reload" },
  service_action_failed: { fa: "سرویس به دستور جواب نداد. چند لحظه بعد دوباره امتحان کنید.", en: "The service didn't respond to the command. Try again in a moment.", action: "retry" },
  service_busy: { fa: "این سرویس الان در حال روشن یا خاموش شدن است. چند لحظه صبر کنید.", en: "This service is starting or stopping right now. Wait a moment.", action: "retry" },
  "services:confirmation_mismatch": { fa: "نام سرویس درست نوشته نشد. دوباره بنویسید.", en: "The service name wasn't typed correctly. Type it again.", field: "confirm" },
  "services:confirmation_required": { fa: "برای اطمینان، نام سرویس را بنویسید.", en: "To be sure, type the service's name.", field: "confirm" },
  domain_in_use: { fa: "این دامنه قبلاً به جای دیگری وصل شده است.", en: "This domain is already attached somewhere else.", field: "host" },
  domain_exists: { fa: "این دامنه قبلاً اضافه شده است.", en: "This domain was already added.", field: "host" },
  domain_not_found: { fa: "این دامنه دیگر وجود ندارد. صفحه را تازه کنید.", en: "This domain no longer exists. Refresh the page.", action: "refreshList" },
  routing_unavailable: {
    fa: "الان DevAssist نمی‌تواند دامنه را خودش وصل کند. روش «دستی» را انتخاب کنید یا اتصال Dokploy را بررسی کنید.",
    en: "DevAssist can't attach the domain by itself right now. Pick the manual way, or check the Dokploy connection."
  },
  invalid_routing_mode: { fa: "این روش اتصال روی این سرور در دسترس نیست. یکی دیگر را انتخاب کنید.", en: "This routing method isn't available on this server. Pick another one." },
  "domains:invalid_mode": { fa: "این روش اتصال روی این سرور در دسترس نیست. یکی دیگر را انتخاب کنید.", en: "This routing method isn't available on this server. Pick another one." },
  dokploy_domain_failed: { fa: "Dokploy دامنه را ثبت نکرد. اتصال Dokploy را بررسی کنید و دوباره امتحان کنید.", en: "Dokploy didn't add the domain. Check the Dokploy connection and try again.", action: "retry" },
  dokploy_target_missing: {
    fa: "سرویسی که این دامنه باید به آن وصل شود در Dokploy پیدا نشد؛ شاید پاک یا دوباره ساخته شده باشد. اتصال Dokploy را بررسی کنید و دوباره امتحان کنید.",
    en: "The service this domain belongs to wasn't found in Dokploy; it may have been removed or created again. Check the Dokploy connection and try again.",
    action: "retry"
  },
  service_in_own_stack: {
    fa: "این سرویس در Compose جدای خودش در Dokploy اجرا می‌شود و DevAssist هنوز آن Compose را پیدا نکرده است. اتصال Dokploy را بررسی کنید، یا دامنه را خودتان در Dokploy روی همان Compose اضافه کنید.",
    en: "This service runs in its own Compose in Dokploy, and DevAssist hasn't found that Compose yet. Check the Dokploy connection, or add the domain yourself on that Compose in Dokploy."
  },
  routing_detection_failed: {
    fa: "Dokploy وصل است، ولی DevAssist نتوانست سرویس خودش را در آن پیدا کند. چند لحظه بعد دوباره امتحان کنید، یا روش «دستی» را انتخاب کنید.",
    en: "Dokploy is set up, but DevAssist couldn't find its own service there. Try again in a moment, or pick the manual way.",
    action: "retry"
  },
  panel_domain_in_use: {
    fa: "شما همین الان با این دامنه وارد پنل شده‌اید، یا این آخرین دامنه پنل است. برای برداشتن آن باید جداگانه تأیید کنید.",
    en: "You're using this domain right now, or it's the panel's last domain. Removing it needs a separate confirmation."
  },
  traefik_write_failed: { fa: "دستیار سرور نتوانست فایل Traefik را بنویسد. دسترسی پوشه Traefik را بررسی کنید.", en: "The server helper couldn't write the Traefik file. Check access to the Traefik folder.", action: "retry" },
  traefik_dir_unavailable: { fa: "پوشه تنظیمات Traefik در دسترس دستیار سرور نیست.", en: "The server helper can't reach the Traefik settings folder." },
  primary_required: { fa: "دست‌کم یک دامنه باید اصلی باشد. اول دامنه دیگری را اصلی کنید.", en: "At least one domain must be the main one. Make another domain main first." },
  verify_failed: { fa: "بررسی دامنه تمام نشد. چند لحظه بعد دوباره امتحان کنید.", en: "The domain check didn't finish. Try again in a moment.", action: "retry" },
  "domains:invalid_host": { fa: "این دامنه درست نوشته نشده؛ مثل npm.example.com بنویسید.", en: "This domain isn't written correctly; write it like npm.example.com.", field: "host" },
  "domains:confirmation_mismatch": { fa: "نام دامنه درست نوشته نشد. دوباره بنویسید.", en: "The domain name wasn't typed correctly. Type it again.", field: "confirm" },
  "domains:confirmation_required": { fa: "برای اطمینان، نام دامنه را بنویسید.", en: "To be sure, type the domain name.", field: "confirm" },

  // ── DevAssist DNS (docs/37 §4) ──────────────────────────────────────────────────
  dns_not_installed: { fa: "DNS هنوز روی این سرور راه نیفتاده است. از «راه‌اندازی» شروع کنید.", en: "DNS isn't set up on this server yet. Start from Set up." },
  dns_unreachable: { fa: "برنامه DNS جواب نمی‌دهد. مطمئن شوید روی سرور روشن است و دوباره امتحان کنید.", en: "The DNS program isn't answering. Make sure it's running on the server and try again.", action: "retry" },
  dns_config_conflict: {
    fa: "کس دیگری هم‌زمان تنظیمات DNS را تغییر داد. آخرین نسخه را بگیرید و تغییرتان را دوباره بزنید.",
    en: "Someone else changed the DNS settings at the same time. Load the latest version and make your change again.",
    action: "refreshList"
  },
  config_conflict: {
    fa: "کس دیگری هم‌زمان تنظیمات DNS را تغییر داد. آخرین نسخه را بگیرید و تغییرتان را دوباره بزنید.",
    en: "Someone else changed the DNS settings at the same time. Load the latest version and make your change again.",
    action: "refreshList"
  },
  dns_zone_exists: { fa: "این دامنه قبلاً در DNS اضافه شده است.", en: "This domain is already in DNS.", field: "name" },
  // docs/41: secondary zones, templates, TSIG, signing, blocking, backup
  zone_read_only: { fa: "این دامنه نسخه دوم است و رکوردهایش فقط از سرور اصلی تغییر می‌کند.", en: "This domain is a copy; its records change only on the main server." },
  dns_zone_read_only: { fa: "این دامنه نسخه دوم است و رکوردهایش فقط از سرور اصلی تغییر می‌کند.", en: "This domain is a copy; its records change only on the main server." },
  dns_zone_invalid: { fa: "چند خانه این دامنه درست نیست؛ با رنگ قرمز مشخص شده‌اند.", en: "A few fields of this domain need fixing; they're marked in red.", action: "fixFields" },
  dns_template_not_found: { fa: "این قالب دیگر وجود ندارد. فهرست را تازه کنید.", en: "This template no longer exists. Refresh the list.", action: "refreshList" },
  dns_template_invalid: { fa: "چند خانه این قالب درست نیست؛ نام، نوع و مقدار رکوردها را بررسی کنید.", en: "A few fields of this template need fixing; check the records' names, types and values.", action: "fixFields" },
  dns_template_builtin: { fa: "قالب‌های آماده تغییر نمی‌کنند؛ یک کپی بگیرید و کپی را تغییر دهید.", en: "Built-in templates don't change; copy one and edit the copy." },
  dns_template_exists: { fa: "قالبی با همین نام هست؛ نام دیگری بنویسید.", en: "A template with this name exists; pick another name.", field: "name" },
  dns_template_in_use: { fa: "این قالب پیش‌فرض است؛ اول قالب دیگری را پیش‌فرض کنید.", en: "This is the default template; make another one the default first." },
  dns_template_variable_missing: { fa: "چند پرسش قالب جواب نگرفته؛ خانه‌های لازم را پر کنید.", en: "Some of the template's questions aren't answered; fill in the needed fields.", action: "fixFields" },
  dns_template_conflict: { fa: "چند رکورد قالب با رکوردهای فعلی این دامنه جور نیست؛ چیزی تغییر نکرد.", en: "Some template records clash with this domain's records; nothing changed." },
  dns_tsig_not_found: { fa: "این کلید دیگر وجود ندارد. فهرست را تازه کنید.", en: "This key no longer exists. Refresh the list.", action: "refreshList" },
  dns_tsig_exists: { fa: "کلیدی با همین نام هست؛ نام دیگری بنویسید.", en: "A key with this name exists; pick another name.", field: "name" },
  dns_tsig_in_use: { fa: "یک یا چند دامنه از این کلید استفاده می‌کنند؛ اول آن‌ها را عوض کنید.", en: "One or more domains use this key; change them first." },
  dns_tsig_key_not_found: { fa: "این کلید دیگر وجود ندارد. فهرست را تازه کنید.", en: "This key no longer exists. Refresh the list.", action: "refreshList" },
  dns_tsig_key_exists: { fa: "کلیدی با همین نام هست؛ نام دیگری بنویسید.", en: "A key with this name exists; pick another name.", field: "name" },
  dns_tsig_key_in_use: { fa: "یک یا چند دامنه از این کلید استفاده می‌کنند؛ اول آن‌ها را عوض کنید.", en: "One or more domains use this key; change them first." },
  dns_rollover_in_progress: { fa: "یک تعویض کلید در جریان است؛ بعد از تمام شدن آن دوباره امتحان کنید.", en: "A key change is already in progress; try again after it finishes." },
  dns_tsig_invalid: { fa: "نام یا رمز این کلید درست نیست؛ رمز باید base64 باشد.", en: "This key's name or secret isn't valid; the secret must be base64.", action: "fixFields" },
  dns_secondary_only: { fa: "این کار فقط برای دامنه‌های نسخه دوم است.", en: "This works only for copied domains." },
  dns_dnssec_disabled: { fa: "امضای امنیتی این دامنه خاموش است؛ اول روشنش کنید.", en: "Security signing is off for this domain; turn it on first." },
  dns_dnssec_rollover_in_progress: { fa: "یک تعویض کلید در جریان است؛ بعد از تمام شدن آن دوباره امتحان کنید.", en: "A key change is already in progress; try again after it finishes." },
  dns_filter_list_invalid: { fa: "این فهرست پذیرفته نشد؛ نشانی باید HTTPS باشد و شکل فهرست درست انتخاب شود.", en: "This list wasn't accepted; the address must be HTTPS and the format must match.", action: "fixFields" },
  dns_filter_list_not_found: { fa: "این فهرست مسدودسازی دیگر وجود ندارد. صفحه را تازه کنید.", en: "This block list no longer exists. Refresh the page.", action: "refreshList" },
  dns_zone_type_mismatch: { fa: "این کار برای این نوع دامنه نیست؛ قالب فقط روی دامنه‌ای با رکوردهای خودتان اعمال می‌شود.", en: "This doesn't fit this kind of domain; templates apply only to domains with your own records." },
  dns_template_variables_invalid: { fa: "چند پرسش قالب جواب نگرفته یا درست نیست؛ خانه‌های قرمز را پر کنید.", en: "Some of the template's questions are empty or not right; fill in the fields in red.", action: "fixFields" },
  dns_template_replace_unsafe: { fa: "جایگزینی ممکن نیست چون رکوردی خاموش یا مخصوص یک گروه در این دامنه هست؛ آن را اول دستی تغییر دهید.", en: "Replacing isn't possible because a turned-off or group-only record is in this domain; change it by hand first." },
  dns_backup_failed: { fa: "پشتیبان DNS ساخته نشد. چند لحظه بعد دوباره امتحان کنید.", en: "The DNS backup wasn't made. Try again in a moment.", action: "retry" },
  dns_filtering_disabled: { fa: "مسدودسازی خاموش است؛ اول در «مسدودسازی» روشنش کنید.", en: "Blocking is off; turn it on under Blocking first." },
  restore_invalid: { fa: "این فایل پشتیبان پذیرفته نشد (خراب است یا مال نسخه دیگری است). چیزی تغییر نکرد.", en: "This backup file wasn't accepted (it's damaged or from another version). Nothing changed." },
  dns_restore_invalid: { fa: "این فایل پشتیبان پذیرفته نشد (خراب است یا مال نسخه دیگری است). چیزی تغییر نکرد.", en: "This backup file wasn't accepted (it's damaged or from another version). Nothing changed." },
  dns_zone_not_found: { fa: "این دامنه دیگر در DNS نیست. فهرست را تازه کنید.", en: "This domain is no longer in DNS. Refresh the list.", action: "refreshList" },
  dns_record_not_found: { fa: "این رکورد دیگر وجود ندارد. فهرست را تازه کنید.", en: "This record no longer exists. Refresh the list.", action: "refreshList" },
  dns_override_not_found: { fa: "این نام دیگر وجود ندارد. فهرست را تازه کنید.", en: "This name no longer exists. Refresh the list.", action: "refreshList" },
  dns_record_invalid: { fa: "چند خانه این رکورد درست نیست؛ با رنگ قرمز مشخص شده‌اند.", en: "A few fields of this record need fixing; they're marked in red.", action: "fixFields" },
  dns_cname_conflict: { fa: "نامی که «نام دیگر» دارد نمی‌تواند رکورد دیگری هم داشته باشد. یکی را بردارید.", en: "A name that is an alias can't have other records. Remove one of them.", field: "name" },
  invalid_zone_name: { fa: "نام دامنه را مثل example.com یا office.local بنویسید.", en: "Write the domain name like example.com or office.local.", field: "name" },
  dns_import_invalid: { fa: "متن فایل دامنه خوانده نشد. شکل آن را بررسی کنید.", en: "The zone text couldn't be read. Check its format.", field: "text" },
  dns_override_managed: { fa: "این نام را «سرویس‌های من» خودکار می‌سازد؛ دامنه را همان‌جا تغییر دهید.", en: "My services manages this name; change the domain there." },
  dns_sync_failed: { fa: "نام‌های «سرویس‌های من» به DNS منتقل نشد. چند لحظه بعد دوباره امتحان کنید.", en: "The My services names didn't reach DNS. Try again in a moment.", action: "retry" },
  "dns:confirmation_mismatch": { fa: "نام دامنه درست نوشته نشد. دوباره بنویسید.", en: "The domain name wasn't typed correctly. Type it again.", field: "confirmation" },
  "dns:invalid_settings": { fa: "این تنظیم ذخیره نشد؛ مقدار خانه قرمز را بررسی کنید.", en: "This setting wasn't saved; check the field in red.", action: "fixFields" },
  dns_version_not_found: { fa: "این نسخه دیگر در تاریخچه نیست. تاریخچه را تازه کنید.", en: "This version is no longer in the history. Refresh it.", action: "refreshList" },

  // ── DevAssist DNS D2: logs, monitoring, limits (docs/38 §4) ──────────────────────
  dns_limit_reached: { fa: "به بیشترین تعداد مجاز رسیده‌اید. اول چند مورد قدیمی را بردارید.", en: "You've reached the most allowed. Remove a few old ones first." },
  dns_not_found: { fa: "این مورد دیگر وجود ندارد. فهرست را تازه کنید.", en: "This item no longer exists. Refresh the list.", action: "refreshList" },
  dns_mitigation_not_found: { fa: "این محدودیت دیگر وجود ندارد؛ شاید وقتش تمام شده. فهرست را تازه کنید.", en: "This limit no longer exists; its time may be up. Refresh the list.", action: "refreshList" },
  dns_mitigation_invalid: { fa: "این محدودیت گذاشته نشد؛ نشانی یا نام را بررسی کنید.", en: "The limit wasn't set; check the address or name.", action: "fixFields" },
  dns_invalid_request: { fa: "درخواست کامل نبود. صفحه را تازه کنید و دوباره امتحان کنید.", en: "The request wasn't complete. Reload the page and try again.", action: "reload" },
  dns_querylog_disabled: { fa: "ثبت لاگ پرسش‌ها خاموش است. از «لاگ» در حالت پیشرفته روشنش کنید.", en: "The question log is off. Turn it on under Log in Advanced mode." },
  dns_query_invalid: { fa: "فیلترهای جست‌وجو درست نیست؛ زمان، نشانی یا نام را بررسی کنید.", en: "The search filters aren't right; check the time, address or name.", action: "fixFields" },
  dns_stream_limit: { fa: "الان نمایش‌های زنده زیادی باز است. یکی را ببندید و دوباره امتحان کنید.", en: "Too many live views are open. Close one and try again.", action: "retry" },
  // ── DevAssist DNS D4: root, DNSSEC, encrypted DNS (docs/40 §3, §5) ─────────────
  dns_settings_invalid: { fa: "تنظیمات DNS ذخیره نشد؛ خانه‌های قرمز را بررسی کنید.", en: "The DNS settings weren't saved; check the fields in red.", action: "fixFields" },
  certificate_required: { fa: "این اتصال رمزدار گواهی لازم دارد. اول در کارت «گواهی» یکی بسازید یا بارگذاری کنید.", en: "This encrypted connection needs a certificate. Make or upload one in the Certificate card first." },
  dns_certificate_required: { fa: "این اتصال رمزدار گواهی لازم دارد. اول در کارت «گواهی» یکی بسازید یا بارگذاری کنید.", en: "This encrypted connection needs a certificate. Make or upload one in the Certificate card first." },
  certificate_in_use: { fa: "این گواهی الان استفاده می‌شود. اول اتصال‌های رمزدار را خاموش کنید، بعد حذفش کنید.", en: "This certificate is in use. Turn off the encrypted connections first, then remove it." },
  dns_certificate_in_use: { fa: "این گواهی الان استفاده می‌شود. اول اتصال‌های رمزدار را خاموش کنید، بعد حذفش کنید.", en: "This certificate is in use. Turn off the encrypted connections first, then remove it." },
  tls_invalid: { fa: "این گواهی یا کلید پذیرفته نشد. فایل‌ها را بررسی کنید.", en: "This certificate or key wasn't accepted. Check the files." },
  dns_tls_invalid: { fa: "این گواهی یا کلید پذیرفته نشد. فایل‌ها را بررسی کنید.", en: "This certificate or key wasn't accepted. Check the files." },
  token_not_found: { fa: "این کلید دسترسی دیگر وجود ندارد. فهرست را تازه کنید.", en: "This access token no longer exists. Refresh the list.", action: "refreshList" },
  dns_token_not_found: { fa: "این کلید دسترسی دیگر وجود ندارد. فهرست را تازه کنید.", en: "This access token no longer exists. Refresh the list.", action: "refreshList" },
  listen_conflict: { fa: "این نشانی و پورت را بخش دیگری گرفته است؛ پورت دیگری بدهید.", en: "Another part already uses this address and port; pick another port.", action: "fixFields" },
  plain_doh_public: { fa: "بدون گواهی (پشت Traefik) فقط نشانی‌های داخلی مثل 127.0.0.1:8053 مجازند.", en: "Without a certificate (behind Traefik) only internal addresses like 127.0.0.1:8053 are allowed.", action: "fixFields" },
  token_invalid: { fa: "نام یا سقف این کلید درست نیست؛ نام ۱ تا ۶۴ نویسه و سقف ۱ تا ۱۰۰۰۰.", en: "This token's name or limit isn't valid; a name of 1 to 64 characters and a limit of 1 to 10000.", action: "fixFields" },
  dns_token_invalid: { fa: "نام یا سقف این کلید درست نیست؛ نام ۱ تا ۶۴ نویسه و سقف ۱ تا ۱۰۰۰۰.", en: "This token's name or limit isn't valid; a name of 1 to 64 characters and a limit of 1 to 10000.", action: "fixFields" },
  dns_doh_plain_disabled: { fa: "برای وصل کردن دامنه، اول در DNS › «اتصال رمزدار» گزینه «پشت Traefik» را روشن کنید.", en: "To connect a domain, first turn on “Behind Traefik” in DNS › Encrypted connections." },
  dns_profile_invalid: { fa: "پروفایل ساخته نشد؛ نشانی DNS رمزدار درست نیست.", en: "The profile wasn't made; the encrypted DNS address isn't valid." },
  "dns_logs:confirmation_mismatch": { fa: "کلمه تأیید درست نوشته نشد. دوباره بنویسید.", en: "The confirmation word wasn't typed correctly. Type it again.", field: "confirmation" }
};

// ── API ──────────────────────────────────────────────────────────────────────

/**
 * Stable sub-reasons the backend may send as `error.reason` next to `error.field` (docs/33 BE4).
 * When present they replace the generic code sentence with a field-specific one.
 */
export const REASON_CATALOG: Record<string, Bi> = {
  duplicate: { fa: "این مقدار قبلاً استفاده شده؛ مقدار دیگری بنویسید.", en: "This is already in use; try another." },
  reserved: { fa: "این نام رزرو شده است؛ نام دیگری بنویسید.", en: "This name is reserved; choose another." },
  too_long: { fa: "این متن بیش از حد بلند است؛ کوتاه‌ترش کنید.", en: "This is too long; shorten it." },
  too_short: { fa: "این متن بیش از حد کوتاه است.", en: "This is too short." },
  required: { fa: "این خانه را پر کنید.", en: "Fill in this field." },
  incorrect: { fa: "این مقدار درست نیست.", en: "This isn't correct." },
  same_as_current: { fa: "رمز تازه باید با رمز فعلی فرق داشته باشد.", en: "The new password must differ from the current one." },
  wildcard_forbidden: { fa: "یک نقش سفارشی نمی‌تواند «همه اجازه‌ها» را داشته باشد.", en: "A custom role can't hold every permission." },
  out_of_range: { fa: "این عدد خارج از محدوده مجاز است.", en: "This number is outside the allowed range." },
  last_enabled_upstream: { fa: "این آخرین منبع فعال است؛ اول یک منبع دیگر اضافه یا روشن کنید.", en: "This is the last active source; add or turn on another first." },
  missing_digit: { fa: "رمز باید دست‌کم یک عدد داشته باشد.", en: "The password needs at least one digit." },
  missing_letter: { fa: "رمز باید دست‌کم یک حرف داشته باشد.", en: "The password needs at least one letter." },
  invalid_characters: { fa: "این مقدار نویسه‌ای دارد که این‌جا پذیرفته نمی‌شود.", en: "This has a character that isn't accepted here." },
  needs_digit: { fa: "رمز باید دست‌کم یک عدد داشته باشد.", en: "The password needs at least one digit." },
  needs_letter: { fa: "رمز باید دست‌کم یک حرف داشته باشد.", en: "The password needs at least one letter." },
  unknown_permission: { fa: "یکی از اجازه‌ها شناخته نشد. صفحه را تازه کنید.", en: "One of the permissions isn't recognised. Reload the page." },
  local_address: { fa: "این نشانی به شبکه داخلی همین سرور اشاره می‌کند و مجاز نیست.", en: "This address points into this server's network and isn't allowed." }
};

/** Shape of `ApiError` from api.ts (duck-typed to avoid an import cycle). `field`/`reason` arrive with BE4. */
export type ApiErrorLike = { name: string; status: number; code: string; detail: string; field?: string; reason?: string; requestId?: string | null; extra?: Record<string, unknown> };

export function isApiErrorLike(error: unknown): error is ApiErrorLike {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { name?: unknown }).name === "ApiError" &&
    typeof (error as { status?: unknown }).status === "number"
  );
}

export type TechnicalDetails = {
  code?: string;
  status?: number;
  /** Backend English message. Advanced «جزئیات فنی» only, never inside a sentence. */
  detail?: string;
  reason?: string;
  /** Backend `error.request_id`, for support. */
  requestId?: string;
  /** For non-API errors (network, script errors). */
  raw?: string;
};

export type FriendlyErrorInfo = {
  message: string;
  action?: ErrorAction;
  field?: string;
  /** True when the code was found in the catalog (false = a fallback sentence was used). */
  known: boolean;
  technical: TechnicalDetails;
};

function fallbackForStatus(status: number): ErrorEntry {
  if (status === 401) return FALLBACK_ERRORS.unauthorized;
  if (status === 403) return FALLBACK_ERRORS.forbidden;
  if (status === 404) return FALLBACK_ERRORS.notFound;
  if (status === 409 || status === 412) return FALLBACK_ERRORS.conflict;
  if (status === 413) return FALLBACK_ERRORS.tooLarge;
  if (status === 400 || status === 422) return FALLBACK_ERRORS.validation;
  if (status === 429) return FALLBACK_ERRORS.rateLimited;
  if (status === 502 || status === 503 || status === 504) return FALLBACK_ERRORS.unavailable;
  if (status >= 500) return FALLBACK_ERRORS.server;
  return FALLBACK_ERRORS.generic;
}

const inCatalog = (key: string) => Object.prototype.hasOwnProperty.call(ERROR_CATALOG, key);

/** Look a code up in the catalog (the `"<scope>:<code>"` entry first when a scope is given). */
export function errorEntry(code: string | null | undefined, scope?: string): ErrorEntry | undefined {
  if (!code) return undefined;
  if (scope && inCatalog(`${scope}:${code}`)) return ERROR_CATALOG[`${scope}:${code}`];
  return inCatalog(code) ? ERROR_CATALOG[code] : undefined;
}

/** Full description of any thrown value: sentence + action + field + technical details. */
export function describeError(language: Language, error: unknown, scope?: string): FriendlyErrorInfo {
  if (isApiErrorLike(error)) {
    // docs/43 §3: plan limits name the limit and the numbers; plan features name the feature.
    const planSentence = planErrorSentence(language, error.code, error.extra, error.detail);
    if (planSentence) {
      return {
        message: planSentence,
        field: error.field,
        known: true,
        technical: { code: error.code || undefined, status: error.status, detail: error.detail || undefined, requestId: error.requestId || undefined }
      };
    }
    const entry = errorEntry(error.code, scope);
    const chosen = entry ?? fallbackForStatus(error.status);
    const reason = error.reason && Object.prototype.hasOwnProperty.call(REASON_CATALOG, error.reason) ? REASON_CATALOG[error.reason] : undefined;
    return {
      message: reason ? reason[language] : chosen[language],
      action: chosen.action,
      field: error.field || chosen.field,
      known: Boolean(entry || reason),
      technical: {
        code: error.code || undefined,
        status: error.status,
        detail: error.detail || undefined,
        reason: error.reason || undefined,
        requestId: error.requestId || undefined
      }
    };
  }
  if (error instanceof TypeError) {
    return {
      message: FALLBACK_ERRORS.network[language],
      action: FALLBACK_ERRORS.network.action,
      known: true,
      technical: { raw: error.message }
    };
  }
  const raw = error instanceof Error ? error.message : typeof error === "string" ? error : undefined;
  return { message: FALLBACK_ERRORS.generic[language], action: FALLBACK_ERRORS.generic.action, known: false, technical: { raw } };
}

/** Just the sentence (for toasts and Alerts). Never contains the backend English message. */
export function errorSentence(language: Language, error: unknown, scope?: string): string {
  return describeError(language, error, scope).message;
}

/**
 * Sentence for a failure code stored on a record (task `error_code`, backup run `error_code`,
 * delivery `error_code`, `last_error` codes). Unknown codes get a gentle generic sentence.
 */
export function reasonFor(language: Language, code: string | null | undefined, scope?: string): string {
  const entry = errorEntry(code, scope);
  if (entry) return entry[language];
  return language === "fa" ? "کار تمام نشد. دوباره امتحان کنید." : "It didn't finish. Try again.";
}

/** One-line technical summary for support (Advanced «جزئیات فنی» and the copy button). */
export function technicalSummary(details: TechnicalDetails): string {
  const parts: string[] = [];
  if (details.code) parts.push(`code=${details.code}`);
  if (details.status) parts.push(`status=${details.status}`);
  if (details.reason) parts.push(`reason=${details.reason}`);
  if (details.detail) parts.push(`message=${details.detail}`);
  if (details.requestId) parts.push(`request_id=${details.requestId}`);
  if (details.raw) parts.push(details.raw);
  return parts.join(" · ");
}
