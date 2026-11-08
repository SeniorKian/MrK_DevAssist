/**
 * Glossary: technical word → plain Persian (docs/33 §2.8).
 *
 * `english` controls the English term in parentheses on Persian pages:
 * - "first": show it the first time the word appears on a page (use <Term k="…" first />).
 * - "advanced": only Advanced mode may show the technical word.
 * - "never": never show the English word.
 * - "keep": the word itself is the common name (DNS, proxy) and stays.
 * Never put the English word in a button or a status pill.
 */
import type { Language } from "../i18n";
import type { Bi } from "./text";

export type GlossaryEntry = {
  /** Plain word (fa) and its everyday English equivalent (en). */
  word: Bi;
  /** The technical English term, as people meet it in docs and other tools. */
  term: string;
  english: "first" | "advanced" | "never" | "keep";
  /** One-sentence explanation for a HelpTip. */
  hint?: Bi;
};

export const GLOSSARY = {
  upstream: {
    word: { fa: "منبع دریافت", en: "package source" },
    term: "upstream",
    english: "first",
    hint: { fa: "جایی که MRK بسته‌ها را از آن می‌گیرد؛ مثل سایت اصلی npm.", en: "Where MRK fetches packages from, such as the official npm site." }
  },
  registry: {
    word: { fa: "مخزن بسته", en: "package registry" },
    term: "registry",
    english: "first",
    hint: { fa: "سرویسی که برنامه‌نویس‌ها بسته‌ها را از آن نصب می‌کنند.", en: "The service developers install packages from." }
  },
  imageRegistry: {
    word: { fa: "مخزن نسخه‌های برنامه", en: "image registry" },
    term: "container registry",
    english: "first",
    hint: { fa: "جایی مثل Docker Hub که نسخه‌های آماده برنامه‌ها در آن نگه‌داری می‌شود.", en: "A place such as Docker Hub that stores ready-to-run app images." }
  },
  mirror: {
    word: { fa: "منبع جایگزین نزدیک", en: "mirror" },
    term: "mirror",
    english: "first",
    hint: { fa: "کپی نزدیک‌تر یک مخزن که سریع‌تر جواب می‌دهد.", en: "A closer copy of a registry that answers faster." }
  },
  cache: { word: { fa: "ذخیره محلی", en: "local copies" }, term: "cache", english: "never" },
  offline: { word: { fa: "حالت بدون اینترنت", en: "offline mode" }, term: "offline mode", english: "never" },
  fallback: { word: { fa: "جایگزین", en: "fallback" }, term: "fallback", english: "never" },
  priority: { word: { fa: "ترتیب", en: "order" }, term: "priority", english: "never" },
  proxy: {
    word: { fa: "پروکسی", en: "proxy" },
    term: "proxy",
    english: "keep",
    hint: { fa: "راه واسطه‌ای که ارتباط اینترنتی سرور از آن عبور می‌کند.", en: "A middle route the server's internet traffic goes through." }
  },
  noProxy: { word: { fa: "بدون پروکسی برای این آدرس‌ها", en: "skip the proxy for these addresses" }, term: "no_proxy", english: "never" },
  dns: {
    word: { fa: "DNS", en: "DNS" },
    term: "DNS",
    english: "keep",
    hint: { fa: "دفترچه تلفن اینترنت؛ نام سایت‌ها را به آدرس عددی تبدیل می‌کند.", en: "The internet's phone book: turns site names into numeric addresses." }
  },
  resolve: { word: { fa: "پیدا کردن آدرس", en: "look up the address" }, term: "resolve", english: "never" },
  endpoint: { word: { fa: "آدرس", en: "address" }, term: "endpoint", english: "advanced" },
  publicEndpoint: {
    word: { fa: "آدرس عمومی", en: "public address" },
    term: "public endpoint",
    english: "first",
    hint: { fa: "آدرسی که برنامه‌های بیرون از این سرور با آن به فضای فایل وصل می‌شوند.", en: "The address apps outside this server use to reach file space." }
  },
  bucket: {
    word: { fa: "پوشه اصلی", en: "bucket" },
    term: "bucket",
    english: "first",
    hint: { fa: "بالاترین پوشه در فضای فایل؛ هر برنامه معمولاً یکی برای خودش دارد.", en: "The top-level folder in file space; each app usually gets its own." }
  },
  object: { word: { fa: "فایل", en: "file" }, term: "object", english: "never" },
  objectKey: { word: { fa: "مسیر فایل", en: "file path" }, term: "key", english: "never" },
  accessKey: {
    word: { fa: "کلید دسترسی", en: "access key" },
    term: "Access Key",
    english: "first",
    hint: { fa: "نام کاربری برنامه‌ها برای وصل شدن به فضای فایل. همراهش یک رمز کلید هم دارد.", en: "The username apps use to reach file space. It comes with a secret." }
  },
  secretKey: { word: { fa: "رمز کلید", en: "secret" }, term: "Secret Key", english: "first" },
  identity: { word: { fa: "کاربر فضای فایل", en: "file-space user" }, term: "identity", english: "never" },
  policy: { word: { fa: "سطح دسترسی", en: "access level" }, term: "policy", english: "advanced" },
  quota: { word: { fa: "سقف حجم", en: "size limit" }, term: "quota", english: "never" },
  presignedLink: { word: { fa: "لینک اشتراک موقت", en: "temporary share link" }, term: "presigned URL", english: "never" },
  prune: { word: { fa: "پاک‌سازی موارد بی‌استفاده", en: "clean up unused items" }, term: "prune", english: "never" },
  purge: { word: { fa: "پاک کردن از ذخیره محلی", en: "remove from local copies" }, term: "purge", english: "never" },
  quarantine: {
    word: { fa: "قرنطینه", en: "quarantine" },
    term: "quarantine",
    english: "never",
    hint: { fa: "بسته برای همه مسدود می‌شود تا وقتی که خودتان آزادش کنید.", en: "The package is blocked for everyone until you release it." }
  },
  pin: {
    word: { fa: "نگه‌داشتن", en: "keep" },
    term: "pin",
    english: "never",
    hint: { fa: "این بسته هیچ‌وقت در پاک‌سازی خودکار پاک نمی‌شود.", en: "This package is never removed by automatic cleanup." }
  },
  revalidate: { word: { fa: "دریافت دوباره از منبع", en: "fetch again from the source" }, term: "revalidate", english: "never" },
  prefetch: { word: { fa: "پیش‌دریافت", en: "download ahead" }, term: "prefetch", english: "never" },
  artifact: { word: { fa: "فایل بسته", en: "package file" }, term: "artifact", english: "never" },
  digest: { word: { fa: "شناسه نسخه", en: "version fingerprint" }, term: "digest", english: "advanced" },
  image: {
    word: { fa: "نسخه برنامه", en: "app image" },
    term: "image",
    english: "first",
    hint: { fa: "بسته آماده یک برنامه که Docker از روی آن کانتینر می‌سازد.", en: "A ready-made app package Docker runs containers from." }
  },
  tag: { word: { fa: "برچسب نسخه", en: "version tag" }, term: "tag", english: "never" },
  container: { word: { fa: "کانتینر", en: "container" }, term: "container", english: "never" },
  volume: { word: { fa: "فضای داده کانتینر", en: "container data" }, term: "Volume", english: "first" },
  deploy: { word: { fa: "انتشار", en: "deploy" }, term: "deploy", english: "never" },
  host: { word: { fa: "سرور", en: "server" }, term: "host", english: "never" },
  agent: {
    word: { fa: "دستیار سرور", en: "server helper" },
    term: "Agent",
    english: "first",
    hint: { fa: "برنامه کوچکی کنار سرور که اطلاعات و کنترل Docker را به پنل می‌دهد.", en: "A small program on the server that gives the panel Docker info and control." }
  },
  pairingKey: { word: { fa: "کد اتصال", en: "pairing code" }, term: "pairing key", english: "never" },
  apiToken: {
    word: { fa: "کلید برنامه", en: "app key" },
    term: "API token",
    english: "first",
    hint: { fa: "برای اسکریپت‌ها و ابزارهای خودکار؛ مثل رمز است و نباید به کسی داده شود.", en: "For scripts and automated tools. Treat it like a password." }
  },
  scope: { word: { fa: "اجازه‌ها", en: "permissions" }, term: "scope", english: "advanced" },
  role: { word: { fa: "نقش", en: "role" }, term: "role", english: "never" },
  permission: { word: { fa: "اجازه", en: "permission" }, term: "permission", english: "advanced" },
  session: { word: { fa: "ورود", en: "sign-in" }, term: "session", english: "never" },
  auditLog: { word: { fa: "تاریخچه فعالیت", en: "activity history" }, term: "audit log", english: "never" },
  supportBundle: { word: { fa: "بسته گزارش برای پشتیبانی", en: "support report" }, term: "support bundle", english: "never" },
  metrics: { word: { fa: "آمار", en: "statistics" }, term: "metrics", english: "advanced" },
  job: { word: { fa: "کار", en: "job" }, term: "job", english: "never" },
  schedule: { word: { fa: "زمان‌بندی", en: "schedule" }, term: "cron", english: "advanced" },
  retention: { word: { fa: "مدت نگه‌داری", en: "how long to keep" }, term: "retention", english: "never" },
  passphrase: { word: { fa: "رمز پشتیبان", en: "backup password" }, term: "passphrase", english: "never" },
  restore: { word: { fa: "بازگردانی", en: "restore" }, term: "restore", english: "never" },
  dryRun: {
    word: { fa: "حالت تمرین", en: "practice mode" },
    term: "dry run",
    english: "never",
    hint: { fa: "فقط ثبت می‌کند چه کسی را می‌بست؛ واقعاً چیزی را نمی‌بندد.", en: "Only records who would be blocked; nothing is actually blocked." }
  },
  enforce: { word: { fa: "حالت فعال", en: "active mode" }, term: "enforce", english: "never" },
  allowlist: { word: { fa: "فهرست همیشه مجاز", en: "always-allowed list" }, term: "allowlist", english: "never" },
  block: { word: { fa: "مسدود کردن", en: "block" }, term: "ban", english: "never" },
  cidr: { word: { fa: "محدوده IP", en: "IP range" }, term: "CIDR", english: "advanced" },
  vulnerability: { word: { fa: "مشکل امنیتی", en: "security issue" }, term: "CVE", english: "first" },
  severity: { word: { fa: "شدت", en: "severity" }, term: "severity", english: "never" },
  webhook: { word: { fa: "وب‌هوک", en: "webhook" }, term: "webhook", english: "keep", hint: { fa: "ارسال خودکار پیام به یک آدرس اینترنتی.", en: "Automatically sends a message to a web address." } },
  chatId: { word: { fa: "شناسه گفتگو", en: "chat ID" }, term: "chat id", english: "never" },
  quietHours: { word: { fa: "ساعات سکوت", en: "quiet hours" }, term: "quiet hours", english: "never" },
  dedupe: { word: { fa: "پیام تکراری فرستاده نشود", en: "don't repeat the same alert" }, term: "dedupe", english: "never" },
  rateLimit: { word: { fa: "محدودیت تعداد درخواست", en: "request limit" }, term: "rate limit", english: "never" },
  timeout: { word: { fa: "حداکثر زمان انتظار", en: "maximum wait" }, term: "timeout", english: "never" },
  latency: { word: { fa: "زمان پاسخ", en: "response time" }, term: "latency", english: "never" },
  tls: { word: { fa: "اتصال امن", en: "secure connection" }, term: "TLS", english: "advanced" },
  reverseProxy: { word: { fa: "سرور جلویی", en: "front server" }, term: "reverse proxy", english: "first", hint: { fa: "سروری مثل Traefik که جلوی پنل می‌نشیند و اتصال امن را برقرار می‌کند.", en: "A server such as Traefik that sits in front and handles secure connections." } },
  controlPlane: { word: { fa: "سرور MRK", en: "MRK server" }, term: "control plane", english: "never" },
  env: { word: { fa: "تنظیم شروع سرویس", en: "startup setting" }, term: "environment variable", english: "advanced", hint: { fa: "مقداری که در فایل Compose نوشته می‌شود و هنگام روشن شدن سرویس خوانده می‌شود.", en: "A value written in the Compose file and read when the service starts." } },
  restartRequired: { word: { fa: "پس از راه‌اندازی دوباره اعمال می‌شود", en: "applies after a restart" }, term: "restart required", english: "never" }
} satisfies Record<string, GlossaryEntry>;

export type GlossaryKey = keyof typeof GLOSSARY;

/** The plain word for a technical term. */
export function term(language: Language, key: GlossaryKey): string {
  return GLOSSARY[key].word[language];
}

/** The plain word plus the English technical term in parentheses (fa only, when the entry allows it). */
export function termWithEnglish(language: Language, key: GlossaryKey): string {
  const entry: GlossaryEntry = GLOSSARY[key];
  if (language !== "fa" || entry.english !== "first") return entry.word[language];
  return `${entry.word.fa} (${entry.term})`;
}

export function termHint(language: Language, key: GlossaryKey): string | undefined {
  const entry: GlossaryEntry = GLOSSARY[key];
  return entry.hint?.[language];
}
