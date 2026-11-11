/**
 * Roles and permissions in plain words (docs/33 §5).
 *
 * Users see role NAMES («مدیر», «بیننده») and permission NAMES («دیدن بسته‌های ذخیره‌شده»),
 * never `viewer` or `cache:read`. Raw permission ids are for the Advanced role editor only,
 * shown LTR and muted under the plain name.
 *
 * The same catalog lives in the backend (`auth.py` PERMISSION_CATALOG / BUILTIN_ROLE_INFO);
 * when the API returns labels, prefer them and fall back to this file.
 */
import type { Language } from "../i18n";
import type { Bi } from "./text";

export type RoleKey = "owner" | "admin" | "operator" | "developer" | "viewer";
export type Danger = "none" | "low" | "medium" | "high" | "critical";
export type PermissionGroup = "home" | "packages" | "server" | "dns" | "files" | "security" | "people" | "alerts";

export type RoleInfo = {
  name: Bi;
  oneLiner: Bi;
  can: { fa: string[]; en: string[] };
  cannot: { fa: string[]; en: string[] };
  note?: Bi;
  /** Avatar colour token (MUI palette key). */
  color: "error" | "warning" | "primary" | "secondary" | "info";
};

export const ROLES: Record<RoleKey, RoleInfo> = {
  owner: {
    name: { fa: "مالک", en: "Owner" },
    oneLiner: { fa: "همه کارها، از جمله کارهای خیلی حساس", en: "Everything, including the most sensitive actions" },
    can: {
      fa: ["همه کارها", "وصل کردن پوشه‌های سرور به فضای فایل", "ساختن مالک دیگر", "ساختن و تغییر نقش‌های سفارشی"],
      en: ["Everything", "Link server folders to file space", "Create other owners", "Create and edit custom roles"]
    },
    cannot: { fa: [], en: [] },
    note: { fa: "بهتر است فقط یک نفر این نقش را داشته باشد.", en: "Only one person should have this role." },
    color: "error"
  },
  admin: {
    name: { fa: "مدیر", en: "Admin" },
    oneLiner: { fa: "همه چیز را تنظیم می‌کند", en: "Sets everything up" },
    can: {
      fa: ["تغییر همه تنظیمات", "افزودن و برداشتن افراد", "وصل کردن Dokploy و دستیار سرور", "دیوار آتش، پایگاه‌های داده و فضای فایل", "تنظیم پشتیبان‌گیری"],
      en: ["Change every setting", "Add and remove people", "Connect Dokploy and the server helper", "Firewall, databases and file space", "Set up backups"]
    },
    cannot: {
      fa: ["وصل کردن پوشه‌های سرور به فضای فایل", "ساختن مالک"],
      en: ["Link server folders to file space", "Create an owner"]
    },
    note: { fa: "می‌تواند افراد دیگر را هم اضافه کند.", en: "Can add other people too." },
    color: "warning"
  },
  operator: {
    name: { fa: "مسئول روزانه", en: "Operator" },
    oneLiner: { fa: "کارهای هر روز را انجام می‌دهد، تنظیمات اصلی را نه", en: "Does the daily work, not the core setup" },
    can: {
      fa: ["روشن و خاموش کردن کانتینرها و انتشار برنامه‌ها", "اجرای پشتیبان‌گیری", "امتحان و مسدود کردن منابع و مدیریت بسته‌ها", "آپلود فایل", "افزودن و تغییر نام‌های DNS", "بررسی نسخه‌ها و مشکلات امنیتی، دیدن لاگ و تاریخچه"],
      en: ["Start/stop containers and deploy apps", "Run backups", "Test/block sources and manage cached packages", "Upload files", "Add and change DNS names", "Check updates and security issues; see logs and history"]
    },
    cannot: {
      fa: ["افزودن افراد", "تغییر پروکسی و تنظیمات DNS", "تنظیم پشتیبان‌گیری یا Dokploy", "دیوار آتش و پایگاه‌های داده"],
      en: ["Add people", "Change proxies or DNS settings", "Set up backups or Dokploy", "Firewall and databases"]
    },
    color: "primary"
  },
  developer: {
    name: { fa: "برنامه‌نویس", en: "Developer" },
    oneLiner: { fa: "بسته‌ها را استفاده می‌کند و وضعیت را می‌بیند", en: "Uses packages and sees the status" },
    can: {
      fa: ["دیدن بسته‌ها و منابع دریافت", "دیدن نمودار مصرف سرور و برنامه‌ها", "دیدن و دانلود فایل‌ها", "ساختن کلید برنامه برای خودش"],
      en: ["See packages and sources", "See server charts and apps", "See and download files", "Create their own app keys"]
    },
    cannot: {
      fa: ["تغییر چیزی روی سرور", "دیدن لاگ‌ها", "دیدن تاریخچه فعالیت"],
      en: ["Change anything on the server", "See logs", "See activity history"]
    },
    color: "secondary"
  },
  viewer: {
    name: { fa: "بیننده", en: "Viewer" },
    oneLiner: { fa: "فقط می‌بیند", en: "Can only look" },
    can: {
      fa: ["دیدن وضعیت و بسته‌ها", "دیدن منابع دریافت و نمودارها", "دیدن نسخه‌های تازه و مشکلات امنیتی"],
      en: ["See status and packages", "See sources and charts", "See updates and security findings"]
    },
    cannot: { fa: ["تغییر هر چیزی"], en: ["Change anything"] },
    color: "info"
  }
};

export type PermissionInfo = { group: PermissionGroup; name: Bi; danger: Danger; requires?: string[] };

/** Every permission in `ROLE_PERMISSIONS`, grouped by the new nav groups (docs/33 §5.3). */
export const PERMISSIONS: Record<string, PermissionInfo> = {
  "system:read": { group: "home", name: { fa: "دیدن وضعیت کلی سامانه", en: "See system status" }, danger: "none" },
  "cache:read": { group: "packages", name: { fa: "دیدن بسته‌های ذخیره‌شده", en: "See cached packages" }, danger: "none" },
  "cache:write": { group: "packages", name: { fa: "نگه‌داشتن، قرنطینه، پاک کردن و پیش‌دریافت بسته‌ها", en: "Keep, quarantine, remove and download packages ahead" }, danger: "medium", requires: ["cache:read"] },
  "upstream:read": { group: "packages", name: { fa: "دیدن منابع دریافت، پروکسی و DNS", en: "See package sources, proxies and DNS" }, danger: "none" },
  "upstream:operate": { group: "packages", name: { fa: "امتحان، مسدود کردن و حالت بدون اینترنت منابع", en: "Test, block and switch sources offline" }, danger: "medium", requires: ["upstream:read"] },
  "upstream:write": { group: "packages", name: { fa: "افزودن و تغییر منابع، پروکسی، DNS و منابع داخلی", en: "Add/change sources, proxies, DNS and internal sources" }, danger: "high", requires: ["upstream:read"] },
  "services:read": { group: "server", name: { fa: "دیدن سرویس‌ها و وضعیتشان", en: "See services and their status" }, danger: "none" },
  "services:operate": { group: "server", name: { fa: "روشن، خاموش و راه‌اندازی دوباره سرویس‌ها", en: "Start, stop and restart services" }, danger: "medium", requires: ["services:read"] },
  "domains:read": { group: "server", name: { fa: "دیدن دامنه‌ها و سلامت آن‌ها", en: "See domains and their health" }, danger: "none" },
  "domains:write": { group: "server", name: { fa: "افزودن، تغییر و برداشتن دامنه‌ها و روش اتصال آن‌ها", en: "Add, change and remove domains and how they're routed" }, danger: "high", requires: ["domains:read"] },
  "agent:read": { group: "server", name: { fa: "دیدن سرور و کانتینرها", en: "See the server and containers" }, danger: "none" },
  "agent:write": { group: "server", name: { fa: "وصل کردن دستیار سرور و تنظیم هشدارهای مصرف", en: "Connect the server helper; set resource alerts" }, danger: "high", requires: ["agent:read"] },
  "metrics:read": { group: "server", name: { fa: "دیدن نمودار مصرف منابع", en: "See resource charts" }, danger: "none" },
  "logs:read": { group: "server", name: { fa: "دیدن لاگ کانتینرها", en: "Read container logs" }, danger: "medium", requires: ["agent:read"] },
  "docker:operate": { group: "server", name: { fa: "روشن، خاموش و راه‌اندازی دوباره کانتینرها و دریافت نسخه", en: "Start/stop/restart containers and download images" }, danger: "medium", requires: ["agent:read"] },
  "docker:prune": { group: "server", name: { fa: "پاک کردن موارد بی‌استفاده Docker", en: "Clean up unused Docker items" }, danger: "high", requires: ["docker:operate"] },
  "dokploy:read": { group: "server", name: { fa: "دیدن برنامه‌های Dokploy", en: "See Dokploy apps" }, danger: "none" },
  "dokploy:deploy": { group: "server", name: { fa: "انتشار، توقف و شروع برنامه‌های Dokploy", en: "Deploy, stop and start Dokploy apps" }, danger: "medium", requires: ["dokploy:read"] },
  "dokploy:write": { group: "server", name: { fa: "وصل و قطع کردن Dokploy و تنظیم آن", en: "Connect, disconnect and tune Dokploy" }, danger: "high", requires: ["dokploy:read"] },
  "updates:read": { group: "server", name: { fa: "دیدن نسخه‌های تازه برنامه‌ها", en: "See available app updates" }, danger: "none" },
  "updates:write": { group: "server", name: { fa: "بررسی دستی و تنظیم بررسی نسخه‌ها", en: "Check now; change update-check settings" }, danger: "low", requires: ["updates:read"] },
  "db:read": { group: "server", name: { fa: "دیدن پایگاه‌های داده و داده‌هایشان", en: "Browse databases and their data" }, danger: "high" },
  "db:write": { group: "server", name: { fa: "نوشتن در پایگاه داده و مدیریت اتصال‌ها", en: "Write to databases; manage connections" }, danger: "critical", requires: ["db:read"] },
  "dns:read": { group: "dns", name: { fa: "دیدن وضعیت DNS، نام‌ها و دامنه‌های آن", en: "See DNS status, names and domains" }, danger: "none" },
  "dns:write": { group: "dns", name: { fa: "افزودن و تغییر نام‌ها و دامنه‌های DNS", en: "Add and change DNS names and domains" }, danger: "high", requires: ["dns:read"] },
  "dns:logs": { group: "dns", name: { fa: "دیدن پرسش‌های DNS (چه کسی چه چیزی پرسید)", en: "See DNS questions (who asked what)" }, danger: "medium", requires: ["dns:read"] },
  "dns:admin": { group: "dns", name: { fa: "تنظیمات DNS: کجا گوش بدهد، چه کسی بپرسد و DNS بیرونی", en: "DNS settings: where it listens, who may ask, outside DNS" }, danger: "critical", requires: ["dns:read", "dns:write"] },
  "s3:read": { group: "files", name: { fa: "دیدن و دانلود فایل‌ها", en: "See and download files" }, danger: "medium" },
  "s3:write": { group: "files", name: { fa: "آپلود، پاک کردن و لینک اشتراک فایل", en: "Upload, delete and share files" }, danger: "medium", requires: ["s3:read"] },
  "s3:admin": { group: "files", name: { fa: "ساخت پوشه اصلی، کاربر و کلید فضای فایل", en: "Manage buckets, file-space users and keys" }, danger: "high", requires: ["s3:read"] },
  "backup:read": { group: "files", name: { fa: "دیدن پشتیبان‌های پنل", en: "See panel backups" }, danger: "none" },
  "backup:write": { group: "files", name: { fa: "ساخت پشتیبان پنل و آماده‌سازی بازگردانی", en: "Create panel backups; prepare a restore" }, danger: "high", requires: ["backup:read"] },
  "backup:server:read": { group: "files", name: { fa: "دیدن پشتیبان برنامه‌ها", en: "See app backups" }, danger: "none" },
  "backup:server:write": { group: "files", name: { fa: "ساخت، اجرا و دانلود پشتیبان برنامه‌ها و گرفتن کلید", en: "Create, run and download app backups; export keys" }, danger: "high", requires: ["backup:server:read"] },
  "firewall:read": { group: "security", name: { fa: "دیدن وضعیت دیوار آتش و نشانی‌های مسدود", en: "See the firewall and blocked addresses" }, danger: "none" },
  "firewall:write": { group: "security", name: { fa: "تغییر حالت دیوار آتش، قواعد و مسدود کردن", en: "Change firewall mode, rules and blocks" }, danger: "critical", requires: ["firewall:read"] },
  "vuln:read": { group: "security", name: { fa: "دیدن مشکلات امنیتی برنامه‌ها", en: "See security issues in apps" }, danger: "none" },
  "vuln:write": { group: "security", name: { fa: "بررسی دستی، نادیده‌گرفتن و تنظیم بررسی امنیتی", en: "Scan, ignore findings, change scan settings" }, danger: "low", requires: ["vuln:read"] },
  "user:read": { group: "people", name: { fa: "دیدن افراد و نقش‌ها", en: "See people and roles" }, danger: "none" },
  "user:write": { group: "people", name: { fa: "دعوت، غیرفعال کردن و تغییر نقش افراد", en: "Invite, disable and change people's roles" }, danger: "critical", requires: ["user:read"] },
  "token:read": { group: "people", name: { fa: "دیدن کلیدهای برنامه خود", en: "See your own app keys" }, danger: "none" },
  "token:write": { group: "people", name: { fa: "ساخت و باطل کردن کلید برنامه", en: "Create and revoke app keys" }, danger: "medium", requires: ["token:read"] },
  "notification:read": { group: "alerts", name: { fa: "دیدن کانال‌ها و قواعد اعلان", en: "See alert channels and rules" }, danger: "none" },
  "notification:write": { group: "alerts", name: { fa: "افزودن و تغییر کانال‌ها و قواعد اعلان", en: "Add/change alert channels and rules" }, danger: "medium", requires: ["notification:read"] },
  "task:read": { group: "alerts", name: { fa: "دیدن کارهای در حال انجام", en: "See background jobs" }, danger: "none" },
  "task:write": { group: "alerts", name: { fa: "لغو یا تکرار کارها", en: "Cancel or retry jobs" }, danger: "low", requires: ["task:read"] },
  "audit:read": { group: "alerts", name: { fa: "دیدن تاریخچه فعالیت", en: "See activity history" }, danger: "medium" },
  "git:read": { group: "server", name: { fa: "دیدن مخزن‌های کد", en: "See code repositories" }, danger: "none" },
  "git:write": { group: "server", name: { fa: "ساختن و آینه کردن مخزن‌های کد", en: "Create and mirror code repositories" }, danger: "high", requires: ["git:read"] },
  "registry:read": { group: "server", name: { fa: "دیدن ایمیج‌های Docker", en: "See Docker images" }, danger: "none" },
  "registry:write": { group: "server", name: { fa: "مدیریت مخزن ایمیج Docker", en: "Manage the Docker image registry" }, danger: "high", requires: ["registry:read"] },
  "tenancy:admin": { group: "people", name: { fa: "مدیریت فضاهای کاری، بسته‌ها و ثبت‌نام‌ها", en: "Manage workspaces, plans and sign-ups" }, danger: "high", requires: ["user:read"] },
  "tenancy:impersonate_write": { group: "people", name: { fa: "تغییر دادن هنگام «دیدن به‌جای» کاربر", en: "Make changes while viewing as a user" }, danger: "critical", requires: ["tenancy:admin"] },
  "*": { group: "people", name: { fa: "همه اجازه‌ها (فقط مالک)", en: "All permissions (owner only)" }, danger: "critical" }
};

/** Built-in role → permissions (mirror of auth.py ROLE_PERMISSIONS, used for "who can" texts). */
export const ROLE_PERMISSIONS: Record<RoleKey, readonly string[]> = {
  owner: ["*"],
  admin: Object.keys(PERMISSIONS).filter((key) => key !== "*"),
  operator: [
    "system:read", "upstream:read", "upstream:operate", "cache:read", "cache:write", "task:read", "task:write",
    "audit:read", "backup:read", "notification:read", "agent:read", "metrics:read", "logs:read", "docker:operate",
    "dokploy:read", "dokploy:deploy", "s3:read", "s3:write", "backup:server:read", "updates:read", "updates:write",
    "firewall:read", "vuln:read", "vuln:write", "services:read", "services:operate", "domains:read",
    "dns:read", "dns:write", "git:read", "git:write", "registry:read", "registry:write"
  ],
  developer: [
    "system:read", "upstream:read", "cache:read", "task:read", "token:read", "token:write", "metrics:read",
    "dokploy:read", "s3:read", "updates:read", "vuln:read", "services:read", "domains:read", "dns:read", "git:read", "registry:read"
  ],
  viewer: ["system:read", "upstream:read", "cache:read", "task:read", "metrics:read", "updates:read", "vuln:read", "services:read", "domains:read", "dns:read"]
};

export const ROLE_ORDER: RoleKey[] = ["viewer", "developer", "operator", "admin", "owner"];

export const PERMISSION_GROUP_NAMES: Record<PermissionGroup, Bi> = {
  home: { fa: "خانه", en: "Home" },
  packages: { fa: "بسته‌ها", en: "Packages" },
  server: { fa: "سرور و برنامه‌ها", en: "Server & apps" },
  dns: { fa: "DNS", en: "DNS" },
  files: { fa: "فایل‌ها و پشتیبان", en: "Files & backups" },
  security: { fa: "امنیت و اینترنت", en: "Security & internet" },
  people: { fa: "کاربران و دسترسی", en: "People & access" },
  alerts: { fa: "اعلان‌ها و تاریخچه", en: "Alerts & history" }
};

export const DANGER_WORDS: Record<Danger, Bi> = {
  none: { fa: "بی‌خطر", en: "Safe" },
  low: { fa: "کم‌خطر", en: "Low risk" },
  medium: { fa: "حساس", en: "Sensitive" },
  high: { fa: "خطرناک", en: "Dangerous" },
  critical: { fa: "خیلی خطرناک", en: "Very dangerous" }
};

function isRoleKey(value: string): value is RoleKey {
  return Object.prototype.hasOwnProperty.call(ROLES, value);
}

/** Plain role name. Custom roles pass their own label; unknown keys fall back to a neutral word. */
export function roleName(language: Language, role: string, customLabel?: Bi | null): string {
  if (isRoleKey(role)) return ROLES[role].name[language];
  // docs/43 §1: a «فضای من»-only account, no admin permissions.
  if (role === "customer") return language === "fa" ? "کاربر" : "User";
  if (customLabel) return customLabel[language];
  return language === "fa" ? "نقش سفارشی" : "Custom role";
}

/** Plain permission name; unknown ids become a neutral phrase (never the raw id). */
export function permissionName(language: Language, permission: string): string {
  return PERMISSIONS[permission]?.name[language] ?? (language === "fa" ? "یک اجازه دیگر" : "Another permission");
}

/** The least powerful built-in role that holds the permission (for «فقط «مدیر» می‌تواند…» texts). */
export function lowestRoleWith(permission: string): RoleKey {
  for (const role of ROLE_ORDER) {
    const granted = ROLE_PERMISSIONS[role];
    if (granted.includes("*") || granted.includes(permission)) return role;
  }
  return "owner";
}

/**
 * «فقط «مدیر» و بالاتر می‌تواند این کار را بکند.» for a missing permission.
 * With `ask`, adds who to ask: «از {ask} بخواهید.»
 */
export function noAccessSentence(language: Language, permissions: string | readonly string[], ask?: string | null): string {
  const list = typeof permissions === "string" ? [permissions] : permissions;
  const roles = list.map(lowestRoleWith);
  const role = ROLE_ORDER.find((candidate) => roles.includes(candidate)) ?? "owner";
  const name = ROLES[role].name[language];
  const base =
    role === "owner"
      ? language === "fa" ? `این کار فقط از دست «${name}» برمی‌آید.` : `Only the ${name} can do this.`
      : language === "fa" ? `این کار از «${name}» به بالا برمی‌آید.` : `This needs the ${name} role or higher.`;
  if (!ask) return base;
  return language === "fa" ? `${base} از ${ask} بخواهید.` : `${base} Ask ${ask}.`;
}

/** Add required permissions (write ⇒ read, prune ⇒ operate, …) so a role is always consistent. */
export function withDependencies(permissions: Iterable<string>): Set<string> {
  const result = new Set(permissions);
  let changed = true;
  while (changed) {
    changed = false;
    for (const key of [...result]) {
      for (const needed of PERMISSIONS[key]?.requires ?? []) {
        if (!result.has(needed)) {
          result.add(needed);
          changed = true;
        }
      }
    }
  }
  return result;
}
