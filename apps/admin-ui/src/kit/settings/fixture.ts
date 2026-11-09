/**
 * Static SettingSpec[] used until BE1 (`GET /api/v1/settings/registry`) ships, and by the kit demo.
 * Values are the documented defaults from docs/33 §4.3; they are NOT read from the server.
 * Covers every control type so SettingsForm can be exercised end to end.
 */
import type { SettingSpec, SettingsGroupInfo } from "./types";

export const SETTINGS_FIXTURE_GROUPS: SettingsGroupInfo[] = [
  { key: "server.resources", label: { fa: "مصرف منابع", en: "Resource use" }, nav: "server/resources" },
  { key: "security.network", label: { fa: "DNS و شبکه داخلی", en: "DNS & internal network" }, nav: "security/dns" },
  { key: "people.security", label: { fa: "ورود و امنیت", en: "Sign-in & security" }, nav: "people/people" },
  { key: "files.space", label: { fa: "فضای فایل", en: "File space" }, nav: "files/space" },
  { key: "security.firewall", label: { fa: "دیوار آتش", en: "Firewall" }, nav: "security/firewall" },
  { key: "alerts", label: { fa: "اعلان‌ها", en: "Alerts" }, nav: "alerts/rules" },
  { key: "system", label: { fa: "سامانه", en: "System" } }
];

export const SETTINGS_FIXTURE: SettingSpec[] = [
  // ── H. Resource use (runtime) ──────────────────────────────────────────────
  {
    key: "monitoring.enabled", group: "server.resources", type: "bool", default: true, value: true, source: "runtime", danger: "low", requires: "agent:write",
    label: { fa: "جمع‌آوری آمار مصرف", en: "Collect resource statistics" },
    description: { fa: "هر چند ثانیه مصرف پردازنده، حافظه و دیسک خوانده و نگه داشته می‌شود.", en: "CPU, memory and disk use are read and stored every few seconds." }
  },
  {
    key: "monitoring.interval_seconds", group: "server.resources", type: "duration", unit: "seconds", default: 15, value: 15, min: 5, max: 3600, source: "runtime", danger: "low", requires: "agent:write",
    depends_on: [{ key: "monitoring.enabled", equals: true }],
    label: { fa: "هر چند وقت یک بار خوانده شود", en: "How often to sample" },
    description: { fa: "فاصله کوتاه‌تر نمودار دقیق‌تری می‌دهد ولی فضای بیشتری می‌گیرد.", en: "Shorter gaps give finer charts but use more space." }
  },
  {
    key: "monitoring.minute_retention_days", group: "server.resources", type: "int", unit: "days", default: 7, value: 7, min: 1, max: 90, source: "runtime", danger: "low", requires: "agent:write",
    label: { fa: "نگه‌داری آمار دقیقه‌ای", en: "Keep per-minute data" },
    description: { fa: "آمار دقیق تا این چند روز می‌ماند.", en: "Detailed data is kept for this many days." }
  },
  {
    key: "monitoring.alerts.cpu_percent", group: "server.resources", type: "int", unit: "percent", default: 90, value: 85, overridden: true, min: 1, max: 100, source: "runtime", danger: "low", requires: "agent:write",
    depends_on: [{ key: "monitoring.alerts.enabled", equals: true }],
    label: { fa: "هشدار مصرف پردازنده", en: "CPU alert threshold" },
    description: { fa: "وقتی مصرف پردازنده بیشتر از این بماند خبرتان می‌کنیم.", en: "We tell you when CPU use stays above this." }
  },
  {
    key: "monitoring.alerts.enabled", group: "server.resources", type: "bool", default: true, value: true, source: "runtime", danger: "low", requires: "agent:write",
    label: { fa: "هشدار مصرف زیاد", en: "High-usage alerts" }
  },
  {
    key: "monitoring.alerts.duration_minutes", group: "server.resources", type: "duration", unit: "minutes", default: 5, value: 5, min: 1, max: 1440, source: "runtime", danger: "low", requires: "agent:write",
    depends_on: [{ key: "monitoring.alerts.enabled", equals: true }],
    label: { fa: "چه مدت بالا بماند تا هشدار بدهیم", en: "How long before alerting" }
  },
  {
    key: "monitoring.chart_max_points", group: "server.resources", type: "int", default: 500, value: 500, source: "constant", danger: "none",
    label: { fa: "بیشترین نقطه‌های هر نمودار", en: "Maximum points per chart" }
  },

  // ── F. DNS (runtime) ───────────────────────────────────────────────────────
  {
    key: "network.dns.mode", group: "security.network", type: "enum", default: "system", value: "system", source: "runtime", danger: "medium", requires: "upstream:write",
    enum: [
      { value: "system", label: { fa: "همان DNS سرور", en: "The server's DNS" } },
      { value: "custom", label: { fa: "DNS دلخواه", en: "Custom DNS" } }
    ],
    label: { fa: "پیدا کردن آدرس‌ها با", en: "Look up addresses with" },
    description: { fa: "DevAssist آدرس منابع دریافت را با کدام DNS پیدا کند. تغییر فوراً اعمال می‌شود.", en: "Which DNS DevAssist uses to find package sources. Applies at once." }
  },
  {
    key: "network.dns.servers", group: "security.network", type: "list", default: [], value: [], max_items: 6, source: "runtime", danger: "medium", requires: "upstream:write",
    depends_on: [{ key: "network.dns.mode", equals: "custom" }],
    label: { fa: "سرورهای DNS", en: "DNS servers" },
    description: { fa: "مثل 1.1.1.1 یا 8.8.8.8:53", en: "Like 1.1.1.1 or 8.8.8.8:53" }
  },
  {
    key: "network.dns.timeout_seconds", group: "security.network", type: "float", unit: "seconds", default: 2, value: 2, min: 0.2, max: 10, step: 0.1, source: "runtime", danger: "low", requires: "upstream:write",
    label: { fa: "حداکثر زمان انتظار برای DNS", en: "DNS timeout" }
  },
  {
    key: "network.allow_private_upstreams", group: "security.network", type: "bool", default: false, value: false, source: "runtime", danger: "high", requires: "upstream:write",
    label: { fa: "اجازه منابع داخل شبکه خودتان", en: "Allow sources inside your network" },
    description: { fa: "هر «مدیری» می‌تواند از این راه به سرویس‌های داخلی دسترسی بگیرد؛ فقط اگر به همه مدیرها اعتماد دارید روشن کنید.", en: "Any admin could reach internal services this way; turn on only if you trust every admin." }
  },

  // ── B. Sign-in (startup) ───────────────────────────────────────────────────
  {
    key: "auth.session_ttl_seconds", group: "people.security", type: "duration", unit: "seconds", default: 28800, value: 28800, min: 300, max: 2592000, source: "startup", env: "MRK_SESSION_TTL_SECONDS", restart_required: true, danger: "medium",
    label: { fa: "مدت اعتبار هر ورود", en: "Sign-in lasts for" },
    description: { fa: "بعد از این مدت باید دوباره وارد شوید.", en: "After this you need to sign in again." }
  },
  {
    key: "auth.login_rate_limit.attempts", group: "people.security", type: "int", default: 5, value: 5, min: 1, max: 100, source: "startup", env: "MRK_LOGIN_RATE_LIMIT_ATTEMPTS", restart_required: true, danger: "medium",
    label: { fa: "تعداد تلاش ورود پیش از توقف", en: "Sign-in attempts before a pause" }
  },
  {
    key: "auth.registration.enabled", group: "people.security", type: "bool", default: false, value: false, source: "runtime", danger: "high", requires: "user:write",
    label: { fa: "ثبت‌نام عمومی", en: "Public sign-up" },
    description: { fa: "هر کسی که به پنل دسترسی دارد می‌تواند حسابی بسازد که فقط می‌بیند.", en: "Anyone who can reach the panel can create a view-only account." }
  },
  {
    key: "web.trusted_proxies", group: "people.security", type: "cidr_list", default: [], value: ["10.0.0.0/8"], source: "startup", env: "MRK_TRUSTED_PROXIES", restart_required: true, danger: "high",
    label: { fa: "سرورهای جلویی مورد اعتماد", en: "Trusted front servers" }
  },
  {
    key: "auth.argon2.time_cost", group: "people.security", type: "int", default: 3, value: 3, source: "constant", danger: "high",
    label: { fa: "سختی رمزنگاری رمزها", en: "Password hashing cost" }
  },

  // ── L. File space ──────────────────────────────────────────────────────────
  {
    key: "s3.public_endpoint", group: "files.space", type: "url", default: null, value: null, source: "runtime", danger: "medium", requires: "s3:admin",
    label: { fa: "آدرس عمومی فضای فایل", en: "File space public address" },
    description: { fa: "آدرسی که برنامه‌های بیرون از این سرور با آن وصل می‌شوند؛ مثل https://s3.example.com", en: "The address apps outside this server use, like https://s3.example.com" }
  },
  {
    key: "s3.max_object_bytes", group: "files.space", type: "bytes", default: 5 * 1024 ** 4, value: 5 * 1024 ** 4, min: 1, max: 5 * 1024 ** 4, source: "runtime", danger: "low", requires: "s3:admin",
    label: { fa: "بزرگ‌ترین اندازه هر فایل", en: "Largest file size" }
  },
  {
    key: "s3.region", group: "files.space", type: "string", default: "us-east-1", value: "us-east-1", source: "runtime", danger: "low", requires: "s3:admin",
    label: { fa: "نام منطقه", en: "Region name" },
    description: { fa: "بیشتر برنامه‌ها همان مقدار پیش‌فرض را می‌خواهند.", en: "Most apps expect the default." }
  },
  {
    key: "s3engine.fsync_policy", group: "files.space", type: "enum", default: "object", value: "object", source: "startup", env: "MRK_S3_FSYNC_POLICY", restart_required: true, danger: "medium",
    enum: [
      { value: "none", label: { fa: "سریع‌ترین", en: "Fastest" } },
      { value: "object", label: { fa: "متعادل", en: "Balanced" } },
      { value: "strict", label: { fa: "امن‌ترین", en: "Safest" } }
    ],
    label: { fa: "اطمینان از نوشته شدن روی دیسک", en: "Disk write safety" }
  },

  // ── N. Firewall ────────────────────────────────────────────────────────────
  {
    key: "firewall.mode", group: "security.firewall", type: "enum", default: "dry_run", value: "dry_run", source: "runtime", danger: "critical", requires: "firewall:write",
    enum: [
      { value: "off", label: { fa: "خاموش", en: "Off" } },
      { value: "dry_run", label: { fa: "حالت تمرین", en: "Practice mode" }, description: { fa: "فقط ثبت می‌کند، چیزی را نمی‌بندد.", en: "Only records; blocks nothing." } },
      { value: "enforce", label: { fa: "حالت فعال", en: "Active" } }
    ],
    label: { fa: "حالت دیوار آتش", en: "Firewall mode" }
  },
  {
    key: "firewall.default_ban_seconds", group: "security.firewall", type: "duration", unit: "seconds", default: 3600, value: 3600, min: 60, max: 2592000, source: "runtime", danger: "medium", requires: "firewall:write",
    label: { fa: "مدت مسدودی پیش‌فرض", en: "Default block length" }
  },

  // ── P. Alerts ──────────────────────────────────────────────────────────────
  {
    key: "notifications.quiet_hours.enabled", group: "alerts", type: "bool", default: false, value: false, source: "runtime", danger: "none", requires: "notification:write",
    label: { fa: "ساعات سکوت", en: "Quiet hours" },
    description: { fa: "در این ساعت‌ها فقط پیام‌های خیلی مهم فرستاده می‌شود.", en: "Only very important messages are sent during these hours." }
  },
  {
    key: "notifications.quiet_hours.start", group: "alerts", type: "time", default: "23:00", value: "23:00", source: "runtime", danger: "none", requires: "notification:write",
    depends_on: [{ key: "notifications.quiet_hours.enabled", equals: true }],
    label: { fa: "شروع ساعات سکوت", en: "Quiet hours start" }
  },
  {
    key: "notifications.quiet_hours.timezone", group: "alerts", type: "timezone", default: "Asia/Tehran", value: "Asia/Tehran", source: "runtime", danger: "none", requires: "notification:write",
    label: { fa: "منطقه زمانی", en: "Time zone" }
  },
  {
    key: "notifications.max_attempts", group: "alerts", type: "int", unit: "count", default: 5, value: 5, min: 1, max: 20, source: "runtime", danger: "low", requires: "notification:write",
    label: { fa: "چند بار دوباره فرستاده شود", en: "Delivery attempts" }
  },

  // ── A. System (startup / build) ────────────────────────────────────────────
  {
    key: "system.log_level", group: "system", type: "enum", default: "INFO", value: "INFO", source: "startup", env: "MRK_LOG_LEVEL", restart_required: true, danger: "low",
    enum: [
      { value: "DEBUG", label: { fa: "همه جزئیات", en: "Everything" } },
      { value: "INFO", label: { fa: "معمولی", en: "Normal" } },
      { value: "WARNING", label: { fa: "فقط هشدارها", en: "Warnings only" } },
      { value: "ERROR", label: { fa: "فقط خطاها", en: "Errors only" } }
    ],
    label: { fa: "میزان جزئیات گزارش‌ها", en: "Log detail" }
  },
  {
    key: "system.database_url", group: "system", type: "secret", default: null, value: null, secret: true, secret_configured: true, source: "startup", env: "MRK_DATABASE_URL", restart_required: true, danger: "critical",
    label: { fa: "نشانی پایگاه داده پنل", en: "Panel database address" }
  },
  {
    key: "build.commit", group: "system", type: "string", default: null, value: "7bc1288", source: "build", danger: "none",
    label: { fa: "شناسه ساخت", en: "Build commit" }
  }
];
