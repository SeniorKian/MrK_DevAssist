/**
 * Information architecture as data (docs/33 §1.1): 7 groups ("rooms"), each with tabs.
 *
 * - Routes are `#/<group>/<tab>` (`#/packages/sources`); `#/<group>` opens its first visible tab.
 * - A tab is visible when the user holds ANY permission in `anyOf` (empty = everyone) and, for
 *   `advancedOnly` tabs, when the display mode is Advanced. A group is visible when any tab is.
 * - Old hashes (`#upstreams`, `#s3`, …) redirect through LEGACY_ROUTES so bookmarks keep working;
 *   other spellings (`#/files/maintenance`, `#/access/people`) go through ROUTE_ALIASES.
 * - A `?query` after the route (`#/files/app-backups?new=1`) is kept when the route names a real tab
 *   (directly, through an alias or a legacy hash) and dropped when the tab falls back to another one;
 *   pages read it with `hashQuery()`.
 * - `panel` names the source file (`src/<panel>.tsx`) that renders the tab inside its group page
 *   (`NavGroup.page`); it documents the IA and helps search, the shell loads `page`.
 *
 * The shell (AppShell, owned by Phase 1 agent B) reads this file; pages never hard-code nav.
 */
import type { SvgIconComponent } from "@mui/icons-material";
import HomeRoundedIcon from "@mui/icons-material/HomeRounded";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import FolderRoundedIcon from "@mui/icons-material/FolderRounded";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";
import GroupRoundedIcon from "@mui/icons-material/GroupRounded";
import NotificationsRoundedIcon from "@mui/icons-material/NotificationsRounded";
import SettingsRoundedIcon from "@mui/icons-material/SettingsRounded";
import InfoRoundedIcon from "@mui/icons-material/InfoRounded";
import { hasPermission } from "./api";
import type { Language } from "./i18n";
import type { Bi } from "./copy/text";
import { normalizeTyped } from "./copy/text";

export type GroupKey = "home" | "packages" | "server" | "files" | "security" | "people" | "alerts";
export type UtilityKey = "settings" | "about";
export type DisplayMode = "simple" | "advanced";

/** Source files that render a tab (`src/<name>.tsx`), inside the group page. */
export type PanelKey =
  | "HomePage"
  | "PackagesPanel"
  | "UpstreamsPanel"
  | "RegistriesPanel"
  | "ServerPanel"
  | "MonitoringPanel"
  | "DokployPanel"
  | "UpdatesPanel"
  | "DbAdminPanel"
  | "S3Panel"
  | "ServerBackupsPanel"
  | "LifecyclePanel"
  | "FirewallPanel"
  | "VulnPanel"
  | "NetworkPanel"
  | "PeoplePanel"
  | "RolesPanel"
  | "AppKeysPanel"
  | "RegistrationCard"
  | "ChannelsPanel"
  | "RulesPanel"
  | "JobsPanel"
  | "HistoryPanel"
  | "SettingsPage"
  | "AboutPage";

export type NavTab = {
  key: string;
  label: Bi;
  /** One short sentence for search results and the page subtitle. */
  hint: Bi;
  anyOf: string[];
  advancedOnly?: boolean;
  panel: PanelKey;
  /** Extra words people may search for (fa and en), e.g. «آپستریم», "upstream". */
  keywords?: string[];
};

/** The page component (file name = default export) that renders a whole group with its tabs. */
export type GroupPageKey = "HomePage" | "PackagesPage" | "ServerPage" | "FilesPage" | "SecurityPage" | "PeoplePage" | "AlertsPage";

export type NavGroup = {
  key: GroupKey;
  label: Bi;
  icon: SvgIconComponent;
  /** Phase 1: each group is one page (`src/<page>.tsx`, default export) that renders its own tabs. */
  page: GroupPageKey;
  tabs: NavTab[];
};

export const NAV_GROUPS: NavGroup[] = [
  {
    key: "home",
    label: { fa: "خانه", en: "Home" },
    icon: HomeRoundedIcon,
    page: "HomePage",
    tabs: [
      {
        key: "overview",
        label: { fa: "خانه", en: "Home" },
        hint: { fa: "چیزهایی که امروز به شما نیاز دارند.", en: "What needs you today." },
        anyOf: [],
        panel: "HomePage"
      }
    ]
  },
  {
    key: "packages",
    label: { fa: "بسته‌ها", en: "Packages" },
    icon: Inventory2RoundedIcon,
    page: "PackagesPage",
    tabs: [
      {
        key: "search",
        label: { fa: "جست‌وجو و مدیریت", en: "Search & manage" },
        hint: { fa: "بسته‌های ذخیره‌شده روی این سرور را پیدا کنید، نگه دارید یا پاک کنید.", en: "Find, keep or remove packages stored on this server." },
        anyOf: ["cache:read"],
        panel: "PackagesPanel",
        keywords: ["پکیج", "package", "cache", "pin", "quarantine", "قرنطینه", "سطل بازیافت"]
      },
      {
        key: "prefetch",
        label: { fa: "پیش‌دریافت", en: "Download ahead" },
        hint: { fa: "بسته‌های یک پروژه را از قبل دانلود کنید تا بدون اینترنت هم نصب شوند.", en: "Download a project's packages in advance so they install even offline." },
        anyOf: ["cache:write"],
        panel: "PackagesPanel",
        keywords: ["prefetch", "requirements", "package-lock"]
      },
      {
        key: "sources",
        label: { fa: "منابع دریافت", en: "Package sources" },
        hint: { fa: "MRK بسته‌ها را از کجا و به چه ترتیبی بگیرد.", en: "Where MRK fetches packages from, and in what order." },
        anyOf: ["upstream:read"],
        panel: "UpstreamsPanel",
        keywords: ["upstream", "آپستریم", "mirror", "offline", "بدون اینترنت"]
      },
      {
        key: "connect",
        label: { fa: "اتصال پروژه‌ها", en: "Connect your projects" },
        hint: { fa: "دستورهای آماده برای این‌که npm و pip از این سرور نصب کنند.", en: "Ready commands so npm and pip install from this server." },
        anyOf: ["system:read"],
        panel: "RegistriesPanel",
        keywords: ["registry", "رجیستری", "npmrc", "pip.conf", "uv", "yarn"]
      }
    ]
  },
  {
    key: "server",
    label: { fa: "سرور و برنامه‌ها", en: "Server & apps" },
    icon: DnsRoundedIcon,
    page: "ServerPage",
    tabs: [
      {
        key: "overview",
        label: { fa: "نمای سرور", en: "Server" },
        hint: { fa: "وضعیت سرور و کانتینرهایش.", en: "The server and its containers." },
        anyOf: ["agent:read"],
        panel: "ServerPanel",
        keywords: ["agent", "دستیار سرور", "container", "کانتینر", "logs", "لاگ"]
      },
      {
        key: "resources",
        label: { fa: "مصرف منابع", en: "Resource use" },
        hint: { fa: "نمودار پردازنده، حافظه و دیسک، و هشدار وقتی پر شدند.", en: "CPU, memory and disk charts, with alerts when they fill up." },
        anyOf: ["metrics:read"],
        panel: "MonitoringPanel",
        keywords: ["monitoring", "پایش", "cpu", "ram", "disk", "دیسک"]
      },
      {
        key: "apps",
        label: { fa: "برنامه‌های Dokploy", en: "Dokploy apps" },
        hint: { fa: "برنامه‌های Dokploy را ببینید و دوباره منتشر کنید.", en: "See Dokploy apps and deploy them again." },
        anyOf: ["dokploy:read"],
        panel: "DokployPanel",
        keywords: ["dokploy", "deploy", "انتشار"]
      },
      {
        key: "updates",
        label: { fa: "به‌روزرسانی نسخه‌ها", en: "App updates" },
        hint: { fa: "برای کدام برنامه‌ها نسخه تازه آمده است.", en: "Which apps have a newer version." },
        anyOf: ["updates:read"],
        panel: "UpdatesPanel",
        keywords: ["update", "image", "آپدیت", "ایمیج"]
      },
      {
        key: "databases",
        label: { fa: "پایگاه‌های داده", en: "Databases" },
        hint: { fa: "داده‌های پایگاه‌های داده برنامه‌ها را ببینید.", en: "Browse your apps' databases." },
        anyOf: ["db:read"],
        panel: "DbAdminPanel",
        keywords: ["database", "dbadmin", "دیتابیس", "postgres", "mysql", "redis", "mongo"]
      },
      {
        key: "docker",
        label: { fa: "ابزار Docker", en: "Docker tools" },
        hint: { fa: "دانلود نسخه برنامه و پاک‌سازی موارد بی‌استفاده Docker.", en: "Pull images and clean up unused Docker items." },
        anyOf: ["docker:operate", "docker:prune"],
        advancedOnly: true,
        panel: "ServerPanel",
        keywords: ["prune", "pull", "پاک‌سازی"]
      }
    ]
  },
  {
    key: "files",
    label: { fa: "فایل‌ها و پشتیبان", en: "Files & backups" },
    icon: FolderRoundedIcon,
    page: "FilesPage",
    tabs: [
      {
        key: "space",
        label: { fa: "فضای فایل", en: "File space" },
        hint: { fa: "فضای فایل روی سرور خودتان؛ برای فایل‌ها و پشتیبان برنامه‌ها.", en: "File storage on your own server, for files and app backups." },
        anyOf: ["s3:read"],
        panel: "S3Panel",
        keywords: ["s3", "bucket", "باکت", "minio", "access key"]
      },
      {
        key: "app-backups",
        label: { fa: "پشتیبان برنامه‌ها", en: "App backups" },
        hint: { fa: "از اطلاعات برنامه‌ها و پایگاه‌های داده، خودکار و رمزدار پشتیبان بگیرید.", en: "Automatic, encrypted backups of your apps and databases." },
        anyOf: ["backup:server:read"],
        panel: "ServerBackupsPanel",
        keywords: ["backup", "بکاپ", "restic", "volume"]
      },
      {
        key: "panel-backup",
        label: { fa: "پشتیبان پنل", en: "Panel backup" },
        hint: { fa: "از تنظیمات خود پنل پشتیبان بگیرید یا آن را بازگردانی کنید.", en: "Back up or restore the panel's own settings." },
        anyOf: ["backup:read"],
        panel: "LifecyclePanel",
        keywords: ["restore", "بازگردانی", "بکاپ"]
      },
      {
        key: "health",
        label: { fa: "نگهداری فضا", en: "Keep storage healthy" },
        hint: { fa: "فضای دیسک را آزاد کنید و سالم بودن فایل‌ها را بررسی کنید.", en: "Free disk space and check stored files for damage." },
        anyOf: ["cache:read"],
        panel: "LifecyclePanel",
        keywords: ["cleanup", "integrity", "پاک‌سازی", "دیسک"]
      }
    ]
  },
  {
    key: "security",
    label: { fa: "امنیت و اینترنت", en: "Security & internet" },
    icon: ShieldRoundedIcon,
    page: "SecurityPage",
    tabs: [
      {
        key: "firewall",
        label: { fa: "دیوار آتش", en: "Firewall" },
        hint: { fa: "نشانی‌هایی که به سرور حمله می‌کنند خودکار مسدود می‌شوند.", en: "Addresses that attack the server are blocked automatically." },
        anyOf: ["firewall:read"],
        panel: "FirewallPanel",
        keywords: ["firewall", "فایروال", "ban", "مسدود"]
      },
      {
        key: "vuln",
        label: { fa: "بررسی امنیتی", en: "Security check" },
        hint: { fa: "مشکلات امنیتی شناخته‌شده در برنامه‌های شما.", en: "Known security issues in your apps." },
        anyOf: ["vuln:read"],
        panel: "VulnPanel",
        keywords: ["cve", "vulnerability", "آسیب‌پذیری"]
      },
      {
        key: "internet",
        label: { fa: "اینترنت و پروکسی", en: "Internet & proxy" },
        hint: { fa: "اگر اینترنت سرور محدود است، پروکسی بسازید و برای هر سرویس روشنش کنید.", en: "If the server's internet is limited, add a proxy and turn it on per service." },
        anyOf: ["upstream:read"],
        panel: "NetworkPanel",
        keywords: ["proxy", "پراکسی", "socks", "network", "شبکه"]
      },
      {
        key: "dns",
        label: { fa: "DNS و شبکه داخلی", en: "DNS & internal network" },
        hint: { fa: "MRK آدرس سایت‌ها را چطور پیدا کند و آیا به منابع داخل شبکه وصل شود.", en: "How MRK looks up addresses, and whether it may use internal sources." },
        anyOf: ["upstream:read"],
        advancedOnly: true,
        panel: "NetworkPanel",
        keywords: ["dns", "resolver", "private"]
      }
    ]
  },
  {
    key: "people",
    label: { fa: "کاربران و دسترسی", en: "People & access" },
    icon: GroupRoundedIcon,
    page: "PeoplePage",
    tabs: [
      {
        key: "people",
        label: { fa: "افراد", en: "People" },
        hint: { fa: "چه کسی وارد شود و چه کاری بکند.", en: "Who can sign in, and what they can do." },
        anyOf: ["user:read"],
        panel: "PeoplePanel",
        keywords: ["user", "کاربر", "invite", "دعوت"]
      },
      {
        key: "roles",
        label: { fa: "نقش‌ها", en: "Roles" },
        hint: { fa: "هر نقش چه کارهایی می‌تواند و چه کارهایی نمی‌تواند بکند.", en: "What each role can and can't do." },
        anyOf: ["user:read"],
        panel: "RolesPanel",
        keywords: ["role", "permission", "اجازه", "دسترسی"]
      },
      {
        key: "app-keys",
        label: { fa: "کلیدهای برنامه‌ها", en: "App keys" },
        hint: { fa: "کلید برای اسکریپت‌ها و ابزارهای خودکار که بدون رمز شما وارد می‌شوند.", en: "Keys for scripts and automated tools that sign in without your password." },
        anyOf: ["token:read"],
        panel: "AppKeysPanel",
        keywords: ["token", "توکن", "api", "ci"]
      },
      {
        key: "signup",
        label: { fa: "ثبت‌نام عمومی", en: "Public sign-up" },
        hint: { fa: "آیا هر کسی بتواند برای خودش حساب «بیننده» بسازد.", en: "Whether anyone can create a view-only account." },
        anyOf: ["user:read"],
        panel: "RegistrationCard",
        keywords: ["registration", "ثبت نام"]
      }
    ]
  },
  {
    key: "alerts",
    label: { fa: "اعلان‌ها و تاریخچه", en: "Alerts & history" },
    icon: NotificationsRoundedIcon,
    page: "AlertsPage",
    tabs: [
      {
        key: "channels",
        label: { fa: "کانال‌های اعلان", en: "Alert channels" },
        hint: { fa: "وقتی اتفاق مهمی افتاد، در تلگرام، بله یا ایمیل خبردار شوید.", en: "Get told on Telegram, Bale or email when something important happens." },
        anyOf: ["notification:read"],
        panel: "ChannelsPanel",
        keywords: ["telegram", "bale", "email", "webhook", "تلگرام", "بله", "ایمیل"]
      },
      {
        key: "rules",
        label: { fa: "قواعد اعلان", en: "Alert rules" },
        hint: { fa: "برای چه چیزهایی و به کدام کانال پیام بیاید.", en: "Which events send a message, and to which channel." },
        anyOf: ["notification:read"],
        panel: "RulesPanel",
        keywords: ["rule", "quiet hours", "ساعات سکوت"]
      },
      {
        key: "jobs",
        label: { fa: "کارهای در حال انجام", en: "Background jobs" },
        hint: { fa: "کارهایی که پنل در پس‌زمینه انجام می‌دهد و نتیجه آن‌ها.", en: "Work the panel does in the background, and how it went." },
        anyOf: ["task:read"],
        panel: "JobsPanel",
        keywords: ["job", "task", "وظیفه", "کار"]
      },
      {
        key: "history",
        label: { fa: "تاریخچه فعالیت", en: "Activity history" },
        hint: { fa: "چه کسی، چه زمانی، چه کاری کرد.", en: "Who did what, and when." },
        anyOf: ["audit:read"],
        panel: "HistoryPanel",
        keywords: ["audit", "log", "ممیزی", "لاگ"]
      },
      {
        key: "support",
        label: { fa: "گزارش پشتیبانی", en: "Support report" },
        hint: { fa: "یک بسته گزارش برای پشتیبانی دانلود کنید.", en: "Download a report bundle for support." },
        anyOf: ["system:read"],
        advancedOnly: true,
        panel: "HistoryPanel",
        keywords: ["support bundle", "metrics", "prometheus"]
      }
    ]
  }
];

/** Footer utilities outside the 7 groups. Route `#/settings`, `#/about`. */
export const NAV_UTILITIES: { key: UtilityKey; label: Bi; icon: SvgIconComponent; panel: PanelKey }[] = [
  { key: "settings", label: { fa: "همه تنظیمات", en: "All settings" }, icon: SettingsRoundedIcon, panel: "SettingsPage" },
  { key: "about", label: { fa: "درباره سامانه", en: "About" }, icon: InfoRoundedIcon, panel: "AboutPage" }
];

/** Phone bottom bar: these four + «بیشتر» (More) which opens a sheet with the rest. */
export const MOBILE_PRIMARY_GROUPS: GroupKey[] = ["home", "packages", "server", "files"];

/** Old flat hashes → new routes, so bookmarks keep working. */
export const LEGACY_ROUTES: Record<string, { group: GroupKey; tab: string }> = {
  overview: { group: "home", tab: "overview" },
  registries: { group: "packages", tab: "connect" },
  packages: { group: "packages", tab: "search" },
  upstreams: { group: "packages", tab: "sources" },
  network: { group: "security", tab: "internet" },
  jobs: { group: "alerts", tab: "jobs" },
  observability: { group: "alerts", tab: "history" },
  server: { group: "server", tab: "overview" },
  monitoring: { group: "server", tab: "resources" },
  dokploy: { group: "server", tab: "apps" },
  updates: { group: "server", tab: "updates" },
  s3: { group: "files", tab: "space" },
  serverBackups: { group: "files", tab: "app-backups" },
  notifications: { group: "alerts", tab: "channels" },
  access: { group: "people", tab: "people" },
  lifecycle: { group: "files", tab: "panel-backup" }
};

/**
 * Other spellings of a route (backend links, settings-registry `nav`, older drafts) → the real tab.
 * Keys are `group/tab` or a bare `group`.
 */
export const ROUTE_ALIASES: Record<string, { group: GroupKey; tab?: string }> = {
  access: { group: "people" },
  "access/people": { group: "people", tab: "people" },
  "access/roles": { group: "people", tab: "roles" },
  "access/tokens": { group: "people", tab: "app-keys" },
  "people/security": { group: "people", tab: "signup" },
  "people/signup": { group: "people", tab: "signup" },
  "people/registration": { group: "people", tab: "signup" },
  "people/tokens": { group: "people", tab: "app-keys" },
  "server/usage": { group: "server", tab: "resources" },
  "server/monitoring": { group: "server", tab: "resources" },
  "server/dokploy": { group: "server", tab: "apps" },
  "server/dbadmin": { group: "server", tab: "databases" },
  "files/storage": { group: "files", tab: "space" },
  "files/space": { group: "files", tab: "space" },
  "files/s3": { group: "files", tab: "space" },
  "files/backups": { group: "files", tab: "app-backups" },
  "files/server-backups": { group: "files", tab: "app-backups" },
  "files/maintenance": { group: "files", tab: "health" },
  "files/lifecycle": { group: "files", tab: "panel-backup" },
  "security/network": { group: "security", tab: "internet" },
  "security/proxy": { group: "security", tab: "internet" },
  "security/vulnerabilities": { group: "security", tab: "vuln" },
  "server/agent": { group: "server", tab: "overview" },
  "server/backups": { group: "files", tab: "app-backups" },
  "alerts/notifications": { group: "alerts", tab: "channels" },
  "alerts/audit": { group: "alerts", tab: "history" },
  "alerts/observability": { group: "alerts", tab: "history" }
};

export type Route =
  /** `query` (without `?`) is set only when the hash named this exact tab; a fallback tab drops it. */
  | { kind: "tab"; group: GroupKey; tab: string; query?: string }
  | { kind: "utility"; key: UtilityKey; query?: string }
  | { kind: "kit" };

const GROUP_INDEX = new Map(NAV_GROUPS.map((group) => [group.key, group]));

export function findGroup(key: string): NavGroup | undefined {
  return GROUP_INDEX.get(key as GroupKey);
}

export function routeHref(group: GroupKey, tab?: string): string {
  return tab ? `#/${group}/${tab}` : `#/${group}`;
}

export function utilityHref(key: UtilityKey): string {
  return `#/${key}`;
}

/** Split a hash into its path (`packages/sources`) and its query (`new=1`, without the `?`). */
export function splitHash(hash: string): { path: string; query: string } {
  const raw = hash.replace(/^#\/?/, "");
  const at = raw.indexOf("?");
  const path = (at >= 0 ? raw.slice(0, at) : raw).replace(/\/+$/, "");
  return { path, query: at >= 0 ? raw.slice(at + 1) : "" };
}

/**
 * Query parameters after the route in the hash: `#/files/app-backups?new=1` → `new=1`.
 * Pages read these to open a wizard or a filter straight away (Home links use them).
 */
export function hashQuery(hash: string = typeof window === "undefined" ? "" : window.location.hash): URLSearchParams {
  return new URLSearchParams(splitHash(hash).query);
}

/**
 * Parse a hash (`#/packages/sources`, `#upstreams`, `#/__kit`, `#/files/app-backups?new=1`). Unknown → null.
 * Does not check permissions. The `?query` is carried on the route only when the hash named a real
 * tab (directly, by alias or legacy name) or a utility, so a fallback tab never gets another tab's query.
 */
export function parseHash(hash: string): Route | null {
  const { path: raw, query } = splitHash(hash);
  if (!raw) return null;
  if (raw === "__kit") return { kind: "kit" };
  const withQuery = <T extends object>(route: T): T & { query?: string } => (query ? { ...route, query } : route);
  const legacy = LEGACY_ROUTES[raw];
  if (legacy) return withQuery({ kind: "tab" as const, ...legacy });
  const [first, second, ...rest] = raw.split("/");
  if (first === "settings" || first === "about") {
    const route = { kind: "utility" as const, key: first as UtilityKey };
    return second ? route : withQuery(route);
  }
  const alias = rest.length === 0 ? (second ? ROUTE_ALIASES[`${first}/${second}`] : ROUTE_ALIASES[first]) : undefined;
  if (alias) {
    const target = findGroup(alias.group)!;
    const route = { kind: "tab" as const, group: alias.group, tab: alias.tab ?? target.tabs[0].key };
    return alias.tab || !second ? withQuery(route) : route;
  }
  const group = findGroup(first) ?? (ROUTE_ALIASES[first] ? findGroup(ROUTE_ALIASES[first].group) : undefined);
  if (!group) return null;
  const exact = rest.length === 0 && Boolean(second) && group.tabs.some((item) => item.key === second) && group.key === first;
  const route = { kind: "tab" as const, group: group.key, tab: exact ? second : group.tabs[0].key };
  return exact || (!second && group.key === first) ? withQuery(route) : route;
}

export function isTabVisible(tab: NavTab, permissions: readonly string[], mode: DisplayMode): boolean {
  if (tab.advancedOnly && mode !== "advanced") return false;
  return tab.anyOf.length === 0 || tab.anyOf.some((permission) => hasPermission(permissions, permission));
}

export function visibleTabs(group: NavGroup, permissions: readonly string[], mode: DisplayMode): NavTab[] {
  return group.tabs.filter((tab) => isTabVisible(tab, permissions, mode));
}

/** Groups the user can open, each with its visible tabs only. */
export function visibleGroups(permissions: readonly string[], mode: DisplayMode): NavGroup[] {
  return NAV_GROUPS.map((group) => ({ ...group, tabs: visibleTabs(group, permissions, mode) })).filter((group) => group.tabs.length > 0);
}

export type ResolvedRoute = {
  route: Route;
  /** Canonical hash, keeping any `?query` when the requested tab was kept. */
  href: string;
  /** True when the hash had to change (legacy, alias, hidden tab, unknown, no permission). Use history.replaceState. */
  redirected: boolean;
};

/**
 * Turn any hash into a route the user may see. Hidden/forbidden tabs fall back to the group's
 * first visible tab, then to Home. The kit demo is only available in development builds.
 */
export function resolveRoute(hash: string, permissions: readonly string[], mode: DisplayMode): ResolvedRoute {
  const home: Route = { kind: "tab", group: "home", tab: "overview" };
  const parsed = parseHash(hash);
  const current = hash.startsWith("#") ? hash : `#${hash}`;
  const finish = (route: Route): ResolvedRoute => {
    const base = route.kind === "tab" ? routeHref(route.group, route.tab) : route.kind === "utility" ? utilityHref(route.key) : "#/__kit";
    const query = route.kind === "kit" ? undefined : route.query;
    const href = query ? `${base}?${query}` : base;
    return { route, href, redirected: href !== current };
  };
  if (!parsed) return finish(home);
  if (parsed.kind === "kit") return finish(import.meta.env.DEV ? parsed : home);
  if (parsed.kind === "utility") return finish(parsed);
  const group = findGroup(parsed.group);
  if (!group) return finish(home);
  const tabs = visibleTabs(group, permissions, mode);
  if (tabs.length === 0) return finish(home);
  const kept = tabs.find((item) => item.key === parsed.tab);
  return finish(kept ? parsed : { kind: "tab", group: group.key, tab: tabs[0].key });
}

export type NavSearchHit = { group: NavGroup; tab: NavTab; href: string; title: string; hint: string };

/** Ctrl+K search over group/tab names, hints and keywords (forgiving of ي/ی, spaces, case). */
export function searchNav(query: string, language: Language, permissions: readonly string[], mode: DisplayMode): NavSearchHit[] {
  const needle = normalizeTyped(query);
  if (!needle) return [];
  const hits: { hit: NavSearchHit; score: number }[] = [];
  for (const group of visibleGroups(permissions, mode)) {
    for (const tab of group.tabs) {
      const title = group.tabs.length > 1 ? `${group.label[language]} › ${tab.label[language]}` : tab.label[language];
      const fields = [tab.label.fa, tab.label.en, group.label.fa, group.label.en, ...(tab.keywords ?? [])].map(normalizeTyped);
      const hintFields = [tab.hint.fa, tab.hint.en].map(normalizeTyped);
      let score = 0;
      if (fields.some((field) => field.startsWith(needle))) score = 3;
      else if (fields.some((field) => field.includes(needle))) score = 2;
      else if (hintFields.some((field) => field.includes(needle))) score = 1;
      if (score > 0) hits.push({ hit: { group, tab, href: routeHref(group.key, tab.key), title, hint: tab.hint[language] }, score });
    }
  }
  return hits.sort((a, b) => b.score - a.score).map((item) => item.hit);
}
