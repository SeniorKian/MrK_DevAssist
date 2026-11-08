/**
 * Plain words for machine values that pages show: statuses, job states, severities,
 * outbound service kinds, ecosystems. Use these instead of printing `item.status`.
 *
 *   statusWord(language, "unavailable")  → { tone: "error", label: "از کار افتاده" }
 *   <StatusPill status="running" />       (kit) uses the same table
 */
import type { Language } from "../i18n";
import type { Bi } from "./text";

export type Tone = "ok" | "warn" | "error" | "info" | "off" | "busy";

/** One consistent wording table for every status pill (docs/33 §6 `statusWords`). */
export const STATUS_WORDS: Record<string, { tone: Tone; label: Bi }> = {
  // generic health
  ok: { tone: "ok", label: { fa: "رو به‌راه", en: "OK" } },
  ready: { tone: "ok", label: { fa: "آماده", en: "Ready" } },
  healthy: { tone: "ok", label: { fa: "سالم", en: "Healthy" } },
  online: { tone: "ok", label: { fa: "وصل", en: "Online" } },
  connected: { tone: "ok", label: { fa: "وصل", en: "Connected" } },
  reachable: { tone: "ok", label: { fa: "در دسترس", en: "Reachable" } },
  degraded: { tone: "warn", label: { fa: "کند یا ناقص", en: "Degraded" } },
  warning: { tone: "warn", label: { fa: "نیاز به توجه", en: "Needs attention" } },
  unhealthy: { tone: "error", label: { fa: "مشکل دارد", en: "Has a problem" } },
  unavailable: { tone: "error", label: { fa: "از کار افتاده", en: "Down" } },
  unreachable: { tone: "error", label: { fa: "جواب نمی‌دهد", en: "Not answering" } },
  offline: { tone: "off", label: { fa: "بدون اینترنت", en: "Offline" } },
  disconnected: { tone: "off", label: { fa: "وصل نیست", en: "Not connected" } },
  not_configured: { tone: "off", label: { fa: "هنوز تنظیم نشده", en: "Not set up yet" } },
  not_paired: { tone: "off", label: { fa: "وصل نشده", en: "Not connected" } },
  disabled: { tone: "off", label: { fa: "خاموش", en: "Off" } },
  enabled: { tone: "ok", label: { fa: "روشن", en: "On" } },
  blocked: { tone: "error", label: { fa: "مسدود", en: "Blocked" } },
  unknown: { tone: "off", label: { fa: "نامشخص", en: "Unknown" } },
  // jobs and runs
  pending: { tone: "info", label: { fa: "در نوبت", en: "Waiting" } },
  queued: { tone: "info", label: { fa: "در نوبت", en: "Waiting" } },
  running: { tone: "busy", label: { fa: "در حال انجام", en: "Running" } },
  succeeded: { tone: "ok", label: { fa: "انجام شد", en: "Done" } },
  success: { tone: "ok", label: { fa: "انجام شد", en: "Done" } },
  completed: { tone: "ok", label: { fa: "انجام شد", en: "Done" } },
  failed: { tone: "error", label: { fa: "انجام نشد", en: "Failed" } },
  failure: { tone: "error", label: { fa: "انجام نشد", en: "Failed" } },
  error: { tone: "error", label: { fa: "خطا", en: "Error" } },
  cancelled: { tone: "off", label: { fa: "لغو شد", en: "Cancelled" } },
  canceled: { tone: "off", label: { fa: "لغو شد", en: "Cancelled" } },
  interrupted: { tone: "warn", label: { fa: "نیمه‌کاره ماند", en: "Interrupted" } },
  skipped: { tone: "off", label: { fa: "رد شد", en: "Skipped" } },
  // containers
  created: { tone: "off", label: { fa: "ساخته شده", en: "Created" } },
  restarting: { tone: "busy", label: { fa: "در حال راه‌اندازی دوباره", en: "Restarting" } },
  paused: { tone: "warn", label: { fa: "مکث", en: "Paused" } },
  exited: { tone: "off", label: { fa: "خاموش", en: "Stopped" } },
  stopped: { tone: "off", label: { fa: "خاموش", en: "Stopped" } },
  dead: { tone: "error", label: { fa: "از کار افتاده", en: "Dead" } },
  removing: { tone: "busy", label: { fa: "در حال پاک شدن", en: "Removing" } },
  // deployments / updates
  done: { tone: "ok", label: { fa: "انجام شد", en: "Done" } },
  idle: { tone: "off", label: { fa: "بی‌کار", en: "Idle" } },
  update_available: { tone: "warn", label: { fa: "نسخه تازه آمده", en: "Update available" } },
  up_to_date: { tone: "ok", label: { fa: "به‌روز", en: "Up to date" } },
  // firewall
  off: { tone: "off", label: { fa: "خاموش", en: "Off" } },
  dry_run: { tone: "warn", label: { fa: "حالت تمرین", en: "Practice mode" } },
  enforce: { tone: "ok", label: { fa: "فعال", en: "Active" } },
  // package policy
  pinned: { tone: "info", label: { fa: "نگه‌داشته‌شده", en: "Kept" } },
  quarantined: { tone: "warn", label: { fa: "قرنطینه", en: "Quarantined" } },
  trashed: { tone: "off", label: { fa: "در سطل بازیافت", en: "In recycle bin" } }
};

export function statusWord(language: Language, status: string | null | undefined): { tone: Tone; label: string } {
  const entry = (status && STATUS_WORDS[status]) || STATUS_WORDS.unknown;
  return { tone: entry.tone, label: entry.label[language] };
}

export const SEVERITY_WORDS: Record<string, { tone: Tone; label: Bi }> = {
  critical: { tone: "error", label: { fa: "بحرانی", en: "Critical" } },
  high: { tone: "error", label: { fa: "زیاد", en: "High" } },
  error: { tone: "error", label: { fa: "مهم", en: "Important" } },
  medium: { tone: "warn", label: { fa: "متوسط", en: "Medium" } },
  moderate: { tone: "warn", label: { fa: "متوسط", en: "Medium" } },
  warning: { tone: "warn", label: { fa: "هشدار", en: "Warning" } },
  low: { tone: "info", label: { fa: "کم", en: "Low" } },
  info: { tone: "info", label: { fa: "اطلاع", en: "Info" } },
  unknown: { tone: "off", label: { fa: "نامشخص", en: "Unknown" } }
};

export function severityWord(language: Language, severity: string | null | undefined) {
  const entry = (severity && SEVERITY_WORDS[severity]) || SEVERITY_WORDS.unknown;
  return { tone: entry.tone, label: entry.label[language] };
}

/** Outbound service kinds (proxy assignments, "which service uses which proxy"). */
export const OUTBOUND_KIND_WORDS: Record<string, Bi> = {
  upstream: { fa: "منبع دریافت بسته", en: "Package source" },
  notification_channel: { fa: "کانال اعلان", en: "Alert channel" },
  registry: { fa: "مخزن نسخه‌های برنامه", en: "Image registry" },
  vuln_feed: { fa: "فهرست مشکلات امنیتی", en: "Security issue list" },
  server_backup_destination: { fa: "مقصد پشتیبان", en: "Backup destination" },
  updates: { fa: "بررسی نسخه‌های تازه", en: "Update checks" },
  dokploy: { fa: "Dokploy", en: "Dokploy" },
  telegram: { fa: "تلگرام", en: "Telegram" },
  bale: { fa: "بله", en: "Bale" },
  email: { fa: "ایمیل", en: "Email" },
  webhook: { fa: "وب‌هوک", en: "Webhook" }
};

export function outboundKindWord(language: Language, kind: string): string {
  return OUTBOUND_KIND_WORDS[kind]?.[language] ?? (language === "fa" ? "سرویس دیگر" : "Other service");
}

/** Notification channel kinds. */
export const CHANNEL_KIND_WORDS: Record<string, Bi> = {
  telegram: { fa: "تلگرام", en: "Telegram" },
  bale: { fa: "بله", en: "Bale" },
  email: { fa: "ایمیل", en: "Email" },
  webhook: { fa: "وب‌هوک", en: "Webhook" }
};

/** Ecosystem keys → product names (kept as-is per glossary). */
export const ECOSYSTEM_WORDS: Record<string, Bi> = {
  npm: { fa: "npm", en: "npm" },
  pypi: { fa: "PyPI", en: "PyPI" }
};

/** Proxy types: the Latin type name stays, the explanation is plain. */
export const PROXY_TYPE_WORDS: Record<string, Bi> = {
  http: { fa: "پروکسی HTTP", en: "HTTP proxy" },
  https: { fa: "پروکسی HTTPS", en: "HTTPS proxy" },
  socks5: { fa: "SOCKS5 (سرور آدرس‌ها را خودش پیدا می‌کند)", en: "SOCKS5 (the server looks up addresses)" },
  socks5h: { fa: "SOCKS5h (پروکسی آدرس‌ها را پیدا می‌کند؛ وقتی DNS فیلتر است)", en: "SOCKS5h (the proxy looks up addresses; use when DNS is filtered)" }
};

/** Event families for alert rules (Simple mode checkboxes instead of patterns). Each family maps to rule patterns. */
export const EVENT_FAMILY_WORDS: Record<string, { label: Bi; patterns: string[] }> = {
  packages: { label: { fa: "بسته‌ها و منابع دریافت", en: "Packages and sources" }, patterns: ["registry.*", "upstream.*"] },
  backups: { label: { fa: "پشتیبان‌گیری", en: "Backups" }, patterns: ["server_backup.*"] },
  server: { label: { fa: "سرور و مصرف منابع", en: "Server and resources" }, patterns: ["metrics.*", "agent.*", "docker.*"] },
  apps: { label: { fa: "برنامه‌ها و نسخه‌های تازه", en: "Apps and updates" }, patterns: ["update.*", "dokploy.*"] },
  security: { label: { fa: "امنیت", en: "Security" }, patterns: ["firewall.*", "vuln.*"] },
  jobs: { label: { fa: "کارهای پس‌زمینه", en: "Background jobs" }, patterns: ["task.*"] }
};
