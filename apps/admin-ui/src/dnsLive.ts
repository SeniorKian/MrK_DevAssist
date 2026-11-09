/**
 * DevAssist DNS phase D2 (contract docs/38 §4–§5): live monitoring, query log, mitigations.
 * Types, API calls and the plain words used by the «پایش» and «لاگ» tabs.
 *
 * Like dns.ts, every backend field is optional so an older server (no D2 endpoints, a bare 404)
 * or a partly filled answer never breaks a page. Panel API base: `/api/v1/dns`.
 */
import { getJson, mutateJson } from "./api";
import type { Language } from "./i18n";
import { fill, type Bi } from "./copy/text";
import { hitPercent, isCidr, isIPv4, isIPv6 } from "./dns";

const BASE = "/api/v1/dns";
const fresh = () => `_=${Date.now()}`;

type Tone = "ok" | "warn" | "error" | "off" | "busy" | "info";

// ── pressure ─────────────────────────────────────────────────────────────────

export type PressureLevel = "normal" | "warning" | "critical" | "emergency";
export type PressureReason = { metric: string; value?: number | null; threshold?: number | null };
export type HotItem = { name?: string | null; client?: string | null; qps?: number | null; count?: number | null };
export type DnsAttack = {
  parent?: string | null;
  unique_nxdomain_per_min?: number | null;
  top_clients?: Array<string | { client?: string; count?: number; qps?: number }> | null;
  since?: number | string | null;
  mitigation_id?: string | null;
};
export type DnsPressure = {
  level?: PressureLevel | string;
  since?: number | string | null;
  reasons?: PressureReason[] | null;
  metrics?: {
    cpu_percent?: number | null;
    memory_percent?: number | null;
    qps?: number | null;
    qps_percent?: number | null;
    inflight_upstream?: number | null;
    drops_1m?: number | null;
    host_cpu_percent?: number | null;
    host_memory_percent?: number | null;
    host_metrics_at?: number | string | null;
  } | null;
  active_actions?: string[] | null;
  hot?: {
    domains?: HotItem[] | number | null;
    clients?: HotItem[] | number | null;
    attacks?: DnsAttack[] | number | null;
    /** Without dns:logs the panel sends only counts (names/IPs hidden). */
    hidden?: boolean;
  } | null;
};

export const fetchPressure = (signal?: AbortSignal) => getJson<DnsPressure>(`${BASE}/pressure?${fresh()}`, signal);

/** `hot.*` may be a list or (without dns:logs) a bare count. */
export function hotList<T>(value: T[] | number | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}
export function hotCount(value: unknown[] | number | null | undefined): number {
  if (typeof value === "number") return value;
  return Array.isArray(value) ? value.length : 0;
}

export function pressureLevel(value: string | null | undefined): PressureLevel {
  return value === "warning" || value === "critical" || value === "emergency" ? value : "normal";
}

export const LEVEL_WORDS: Record<PressureLevel, { tone: Tone; label: Bi; color: "success" | "warning" | "error" }> = {
  normal: { tone: "ok", label: { fa: "آرام", en: "Calm" }, color: "success" },
  warning: { tone: "warn", label: { fa: "کمی شلوغ", en: "A bit busy" }, color: "warning" },
  critical: { tone: "error", label: { fa: "فشار زیاد", en: "Heavy load" }, color: "error" },
  emergency: { tone: "error", label: { fa: "فشار خیلی زیاد", en: "Overloaded" }, color: "error" }
};

const REASON_WORDS: Record<string, Bi> = {
  cpu: { fa: "پردازنده برنامه DNS {value}٪ مشغول است", en: "the DNS program's CPU is {value}% busy" },
  memory: { fa: "حافظه برنامه DNS {value}٪ پر است", en: "the DNS program's memory is {value}% full" },
  qps_percent: { fa: "پرسش‌ها به {value}٪ ظرفیت رسیده‌اند", en: "questions are at {value}% of capacity" },
  host_cpu: { fa: "پردازنده خود سرور {value}٪ مشغول است", en: "the server's own CPU is {value}% busy" },
  host_memory: { fa: "حافظه خود سرور {value}٪ پر است", en: "the server's own memory is {value}% full" },
  drops: { fa: "بعضی پرسش‌ها بی‌جواب مانده‌اند", en: "some questions went unanswered" },
  inflight_upstream: { fa: "پرسش‌های زیادی منتظر جواب DNS‌های بیرونی‌اند", en: "many questions are waiting for outside DNS servers" }
};
const REASON_ALIASES: Record<string, string> = {
  cpu_percent: "cpu",
  memory_percent: "memory",
  qps: "qps_percent",
  host_cpu_percent: "host_cpu",
  host_memory_percent: "host_memory",
  drops_1m: "drops"
};

export function reasonText(language: Language, reason: PressureReason): string {
  const key = REASON_ALIASES[reason.metric] ?? reason.metric;
  const entry = REASON_WORDS[key] ?? { fa: "یکی از سنجه‌ها از حد گذشته است", en: "one of the measurements is over its limit" };
  const value = typeof reason.value === "number" ? Math.round(reason.value) : "—";
  return fill(entry[language], { value }, language);
}

function joinWords(language: Language, parts: string[]): string {
  if (parts.length <= 1) return parts[0] ?? "";
  const and = language === "fa" ? " و " : " and ";
  const comma = language === "fa" ? "، " : ", ";
  return `${parts.slice(0, -1).join(comma)}${and}${parts[parts.length - 1]}`;
}

/** The big sentence at the top of «پایش». */
export function pressureSentence(language: Language, pressure: DnsPressure | null): string {
  const fa = language === "fa";
  if (!pressure) return fa ? "در حال بررسی…" : "Checking…";
  const level = pressureLevel(pressure.level);
  const reasons = (pressure.reasons ?? []).map((item) => reasonText(language, item));
  const because = reasons.length ? (fa ? ` چون ${joinWords(language, reasons)}` : ` because ${joinWords(language, reasons)}`) : "";
  switch (level) {
    case "warning":
      return fa ? `DNS کمی شلوغ است${because}.` : `DNS is a bit busy${because}.`;
    case "critical":
      return fa ? `فشار روی DNS زیاد است${because}.` : `DNS is under heavy load${because}.`;
    case "emergency":
      return fa ? `DNS زیر فشار خیلی زیاد است${because}. DevAssist فقط کارهای ضروری را انجام می‌دهد.` : `DNS is overloaded${because}. DevAssist is doing only what's essential.`;
    default:
      return fa ? "DNS آرام است و پرسش‌ها به‌موقع جواب می‌گیرند." : "DNS is calm and questions are answered on time.";
  }
}

export const ACTION_WORDS: Record<string, Bi> = {
  log_sampling: { fa: "فقط بخشی از پرسش‌ها در لاگ نوشته می‌شود تا DNS سبک‌تر بماند.", en: "Only some questions are written to the log so DNS stays light." },
  disable_prefetch: { fa: "تازه کردن زودهنگام نام‌های پرکاربرد موقتاً خاموش است.", en: "Early refresh of popular names is paused for now." },
  prefer_stale: { fa: "اگر لازم باشد، جواب ذخیره‌شده کمی قدیمی‌تر داده می‌شود تا کسی منتظر نماند.", en: "When needed, a slightly older stored answer is given so nobody waits." },
  tighten_client_qps: { fa: "سقف پرسش دستگاه‌های پرمصرف کمتر شده است.", en: "Heavy devices may ask fewer questions per second for now." },
  refuse_heavy_clients: { fa: "به دستگاه‌هایی که خیلی زیاد می‌پرسند موقتاً جواب داده نمی‌شود.", en: "Devices asking far too much are refused for now." },
  minimal_any: { fa: "به پرسش‌های «همه‌چیز» فقط جواب کوتاه داده می‌شود.", en: "“Everything” questions only get a short answer." }
};

export function actionText(language: Language, action: string): string {
  return ACTION_WORDS[action]?.[language] ?? (language === "fa" ? "یک کار محافظتی دیگر روشن است." : "Another protective step is on.");
}

// ── stats ────────────────────────────────────────────────────────────────────

export type StatsRange = "1h" | "6h" | "24h" | "7d" | "30d" | "1y";
export const ALL_RANGES: StatsRange[] = ["1h", "6h", "24h", "7d", "30d", "1y"];
export const SIMPLE_RANGES: StatsRange[] = ["1h", "24h", "7d", "30d", "1y"];

export type StatsPoint = {
  ts: number | string;
  queries?: number | null;
  qps?: number | null;
  p50_ms?: number | null;
  p95_ms?: number | null;
  p99_ms?: number | null;
  cache_hit_ratio?: number | null;
  by_rcode?: Record<string, number> | null;
  by_source?: Record<string, number> | null;
  /** docs/40 §4: validations in this bucket. */
  dnssec?: { secure?: number | null; insecure?: number | null; bogus?: number | null } | null;
};
export type TopName = { name: string; count?: number | null };
export type TopClient = { client: string; count?: number | null };
export type DnsStats = {
  range?: string;
  resolution_seconds?: number;
  points?: StatsPoint[];
  totals?: { queries?: number; by_rcode?: Record<string, number>; by_source?: Record<string, number>; by_qtype?: Record<string, number>; dnssec?: { secure?: number; insecure?: number; bogus?: number } | null } | null;
  top?: { domains?: TopName[]; clients?: TopClient[]; nxdomain?: TopName[]; refused_clients?: TopClient[] } | null;
  top_hidden?: boolean;
};

export const fetchStats = (range: StatsRange, signal?: AbortSignal) => getJson<DnsStats>(`${BASE}/stats?range=${range}&${fresh()}`, signal);

/** Share of answers that weren't "found" or "no such name" (server failures and refusals), 0–100. */
export function errorPercent(point: Pick<StatsPoint, "queries" | "by_rcode">): number | null {
  const byRcode = point.by_rcode ?? null;
  if (!byRcode) return null;
  // The codes add up to the answered questions; fall back to `queries` only when they don't.
  const total = Object.values(byRcode).reduce((sum, value) => sum + (value || 0), 0) || (typeof point.queries === "number" ? point.queries : 0);
  if (!total) return null;
  const fine = (byRcode.NOERROR ?? 0) + (byRcode.NXDOMAIN ?? 0);
  return Math.max(0, Math.min(100, ((total - fine) / total) * 100));
}

export function cachePercent(point: Pick<StatsPoint, "cache_hit_ratio">): number | null {
  return hitPercent(point.cache_hit_ratio);
}

// ── mitigations ──────────────────────────────────────────────────────────────

export type MitigationKind = "client" | "domain";
export type MitigationAction = "throttle" | "block" | "refuse";
export type Mitigation = {
  id: string;
  kind: MitigationKind | string;
  match: string;
  action: MitigationAction | string;
  qps?: number | null;
  created_at?: number | string | null;
  expires_at?: number | string | null;
  source?: "user" | "auto" | string;
  reason?: string | null;
  hits?: number | null;
};
export type MitigationInput = { kind: MitigationKind; match: string; action: MitigationAction; qps?: number; minutes: number; reason?: string };

function itemsOf<T>(payload: unknown): T[] {
  if (Array.isArray(payload)) return payload as T[];
  const items = (payload as { items?: unknown } | null)?.items;
  return Array.isArray(items) ? (items as T[]) : [];
}

export async function fetchMitigations(signal?: AbortSignal) {
  return itemsOf<Mitigation>(await getJson(`${BASE}/mitigations?${fresh()}`, signal));
}
export const createMitigation = (body: MitigationInput) => mutateJson<Mitigation>(`${BASE}/mitigations`, { method: "POST", body });
export const deleteMitigation = (id: string) => mutateJson(`${BASE}/mitigations/${encodeURIComponent(id)}`, { method: "DELETE" });

/** Duration choices offered next to «کند کن / مسدود کن». */
export const MITIGATION_MINUTES = [15, 60, 1440] as const;
/** The query rate «کند کن» allows (per second) unless Advanced changes it. */
export const DEFAULT_THROTTLE_QPS = 10;

export const MITIGATION_ACTION_WORDS: Record<string, Bi> = {
  throttle: { fa: "کند شده", en: "Slowed down" },
  block: { fa: "مسدود", en: "Blocked" },
  refuse: { fa: "بی‌جواب", en: "Refused" }
};
export const MITIGATION_KIND_WORDS: Record<string, Bi> = {
  client: { fa: "دستگاه", en: "Device" },
  domain: { fa: "نام", en: "Name" }
};

export function minutesWord(language: Language, minutes: number): string {
  const fa = language === "fa";
  const number = (value: number) => new Intl.NumberFormat(fa ? "fa-IR" : "en-US").format(value);
  if (minutes % 1440 === 0) return fa ? `${number(minutes / 1440)} روز` : `${number(minutes / 1440)} ${minutes === 1440 ? "day" : "days"}`;
  if (minutes % 60 === 0) return fa ? `${number(minutes / 60)} ساعت` : `${number(minutes / 60)} ${minutes === 60 ? "hour" : "hours"}`;
  return fa ? `${number(minutes)} دقیقه` : `${number(minutes)} min`;
}

// ── events ───────────────────────────────────────────────────────────────────

export type DnsEvent = { seq: number; ts?: number | string | null; type: string; severity?: string | null; data?: Record<string, unknown> | null };

/** Assumed panel endpoint mirroring the engine's `GET /v1/events?after` (docs/38 §3). */
export async function fetchDnsEvents(signal?: AbortSignal) {
  return itemsOf<DnsEvent>(await getJson(`${BASE}/events?${fresh()}`, signal));
}

export const DEGRADED_REASON_WORDS: Record<string, Bi> = {
  disk_low: { fa: "فضای خالی دیسک کم شده است", en: "free disk space is low" },
  low_disk: { fa: "فضای خالی دیسک کم شده است", en: "free disk space is low" },
  disk_full: { fa: "دیسک پر شده است", en: "the disk is full" },
  max_bytes: { fa: "لاگ به سقف حجمش رسیده است", en: "the log reached its size limit" },
  pressure: { fa: "DNS زیر فشار است", en: "DNS is under load" },
  write_error: { fa: "نوشتن روی دیسک انجام نشد", en: "writing to the disk failed" },
  buffer_full: { fa: "پرسش‌ها سریع‌تر از نوشتن می‌رسند", en: "questions arrive faster than they can be written" }
};

export function degradedReason(language: Language, reason: string | null | undefined): string {
  if (!reason) return "";
  return DEGRADED_REASON_WORDS[reason]?.[language] ?? (language === "fa" ? "مشکلی در نوشتن لاگ پیش آمده است" : "something is wrong with writing the log");
}

const LEVEL_EVENT: Record<PressureLevel, Bi> = {
  normal: { fa: "DNS دوباره آرام شد.", en: "DNS is calm again." },
  warning: { fa: "DNS کمی شلوغ شد.", en: "DNS got a bit busy." },
  critical: { fa: "DNS زیر فشار زیاد رفت.", en: "DNS came under heavy load." },
  emergency: { fa: "DNS زیر فشار خیلی زیاد رفت.", en: "DNS became overloaded." }
};

/** One line for an event of the timeline. */
export function eventText(language: Language, event: DnsEvent): string {
  const fa = language === "fa";
  const data = event.data ?? {};
  const text = (key: string) => (typeof data[key] === "string" || typeof data[key] === "number" ? String(data[key]) : "");
  switch (event.type) {
    case "pressure.level": {
      return LEVEL_EVENT[pressureLevel(text("level") || text("to"))][language];
    }
    case "attack.detected": {
      const parent = text("parent");
      return fa ? `الگوی حمله دیده شد${parent ? `: نام‌های ساختگی زیادی زیر «${parent}» پرسیده می‌شود` : ""}.` : `An attack pattern was seen${parent ? `: many made-up names under “${parent}”` : ""}.`;
    }
    case "mitigation.auto": {
      const match = text("match");
      const action = MITIGATION_ACTION_WORDS[text("action")]?.[language] ?? (fa ? "محدود" : "limited");
      return fa ? `DevAssist خودکار «${match || "یک مورد"}» را ${action} کرد.` : `DevAssist automatically ${action.toLowerCase()} “${match || "an item"}”.`;
    }
    case "mitigation.expired": {
      const match = text("match");
      return fa ? `وقت محدودیت «${match || "یک مورد"}» تمام شد.` : `The limit on “${match || "an item"}” ended.`;
    }
    case "querylog.degraded": {
      const reason = degradedReason(language, text("reason"));
      return fa ? `لاگ کامل موقتاً نوشته نمی‌شود${reason ? ` چون ${reason}` : ""}.` : `The full log is paused for now${reason ? ` because ${reason}` : ""}.`;
    }
    case "querylog.recovered":
      return fa ? "نوشتن لاگ به حالت عادی برگشت." : "Logging is back to normal.";
    // D4 (docs/40 §3)
    case "dnssec.trust_anchor_updated":
      return fa ? "کلید اعتماد ریشه اینترنت به‌روز شد." : "The internet's root trust key was updated.";
    case "dnssec.trust_anchor_failed":
      return fa ? "به‌روزرسانی کلید اعتماد ریشه انجام نشد؛ کلید قبلی نگه داشته شد." : "Updating the root trust key failed; the current key was kept.";
    case "dnssec.bogus_spike": {
      const count = text("count");
      return fa ? `جواب‌های زیادی با امضای خراب رسید${count ? ` (${count} در ۵ دقیقه)` : ""}؛ شاید کسی جواب‌ها را دست‌کاری می‌کند.` : `Many answers with broken signatures arrived${count ? ` (${count} in 5 minutes)` : ""}; someone may be tampering with answers.`;
    }
    case "tls.certificate_expiring": {
      const days = text("days_left");
      return fa ? `گواهی اتصال رمزدار${days ? ` ${days} روز دیگر` : " به‌زودی"} تمام می‌شود.` : `The encrypted connection's certificate ends${days ? ` in ${days} days` : " soon"}.`;
    }
    case "tls.certificate_expired":
      return fa ? "گواهی اتصال رمزدار تمام شد؛ دستگاه‌ها رمزدار وصل نمی‌شوند." : "The encrypted connection's certificate expired; devices can't connect encrypted.";
    case "resolution.priming_failed":
      return fa ? "DevAssist به سرورهای ریشه اینترنت نرسید." : "DevAssist couldn't reach the internet's root servers.";
    case "listener.failed": {
      const address = text("address");
      return fa ? `DNS نتوانست روی ${address || "یک نشانی"} گوش بدهد.` : `DNS couldn't listen on ${address || "an address"}.`;
    }
    default:
      return fa ? "یک رخداد دیگر ثبت شد." : "Another event was recorded.";
  }
}

// ── query log ────────────────────────────────────────────────────────────────

export type LogSource = "authoritative" | "override" | "cache" | "upstream" | "refused" | "rate_limited" | "mitigated" | "forwarder" | "recursive" | "blocked";
export type QueryLogEntry = {
  ts: number | string;
  client?: string | null;
  proto?: string | null;
  name?: string | null;
  qtype?: string | null;
  rcode?: string | number | null;
  source?: LogSource | string | null;
  upstream?: string | null;
  ms?: number | null;
  size?: number | null;
  flags?: { tc?: boolean; stale?: boolean; cached?: boolean } | null;
  /** docs/40 §4: "" = not checked. */
  dnssec?: "secure" | "insecure" | "bogus" | "" | string | null;
  /** DoH token id when the question came with a token. */
  token?: string | null;
};
export type QueryLogPage = { items: QueryLogEntry[]; next_cursor?: string | null; scanned_segments?: number; truncated?: boolean };
export type QueryLogStatus = {
  enabled?: boolean;
  mode?: string;
  mode_effective?: string;
  degraded_reason?: string | null;
  bytes?: number | null;
  segments?: number | null;
  oldest_ts?: number | string | null;
  written_total?: number | null;
  dropped_total?: number | null;
  disk_free_percent?: number | null;
};

export type LogFilters = {
  from?: number;
  to?: number;
  client?: string;
  name?: string;
  qtype?: string;
  rcode?: string;
  source?: string;
  blocked?: boolean;
  min_ms?: number;
  dnssec?: string;
  proto?: string;
};

export function logQuery(filters: LogFilters, extra: Record<string, string | number | undefined> = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries({ ...filters, ...extra })) {
    if (value === undefined || value === null || value === "" || value === false) continue;
    params.set(key, String(value));
  }
  return params.toString();
}

export async function fetchLogs(filters: LogFilters, cursor?: string | null, signal?: AbortSignal): Promise<QueryLogPage> {
  const payload = await getJson<Partial<QueryLogPage>>(`${BASE}/logs?${logQuery(filters, { limit: 100, cursor: cursor ?? undefined })}&${fresh()}`, signal);
  return { ...payload, items: Array.isArray(payload?.items) ? payload.items : [] };
}
export const fetchLogStatus = (signal?: AbortSignal) => getJson<QueryLogStatus>(`${BASE}/logs/status?${fresh()}`, signal);
export const logStreamUrl = (filters: LogFilters) => `${BASE}/logs/stream?${logQuery(filters)}`;
export const logExportUrl = (filters: LogFilters, format: "csv" | "ndjson") => `${BASE}/logs/export?${logQuery(filters, { format })}`;
export const deleteLogs = (body: { client?: string; before?: number; confirmation: string }) =>
  mutateJson<{ deleted_segments?: number; rewritten_segments?: number; deleted_rows?: number }>(`${BASE}/logs`, { method: "DELETE", body });

/** The search box: an IP/CIDR searches the client, anything else the name. */
export function searchFilter(text: string): Pick<LogFilters, "client" | "name"> {
  const value = text.trim();
  if (!value) return {};
  if (isIPv4(value) || isIPv6(value) || isCidr(value)) return { client: value };
  return { name: value.replace(/\.$/, "") };
}

export type ResultChip = "all" | "nxdomain" | "error" | "refused" | "blocked" | "bogus";
export const RESULT_CHIPS: ResultChip[] = ["all", "nxdomain", "error", "refused", "blocked", "bogus"];
export const RESULT_CHIP_WORDS: Record<ResultChip, Bi> = {
  bogus: { fa: "امضای خراب", en: "Broken signature" },
  all: { fa: "همه", en: "All" },
  nxdomain: { fa: "پیدا نشد", en: "Not found" },
  error: { fa: "خطا", en: "Errors" },
  refused: { fa: "رد شده", en: "Refused" },
  blocked: { fa: "مسدود", en: "Blocked" }
};
export function chipFilter(chip: ResultChip): Pick<LogFilters, "rcode" | "blocked" | "dnssec"> {
  if (chip === "bogus") return { dnssec: "bogus" };
  if (chip === "nxdomain") return { rcode: "NXDOMAIN" };
  if (chip === "error") return { rcode: "SERVFAIL" };
  if (chip === "refused") return { rcode: "REFUSED" };
  if (chip === "blocked") return { blocked: true };
  return {};
}

const RCODE_NUMBERS: Record<number, string> = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED" };
export function rcodeOf(value: string | number | null | undefined): string {
  if (typeof value === "number") return RCODE_NUMBERS[value] ?? String(value);
  return String(value ?? "NOERROR").toUpperCase() || "NOERROR";
}

/** The «نتیجه» cell: short plain word + tone. Blocking wins over the code. */
export function resultWord(language: Language, entry: Pick<QueryLogEntry, "rcode" | "source">): { tone: Tone; label: string } {
  const fa = language === "fa";
  if (entry.source === "mitigated") return { tone: "error", label: fa ? "مسدود" : "Blocked" };
  if (entry.source === "rate_limited") return { tone: "warn", label: fa ? "زیادی پرسید" : "Too many" };
  if (entry.source === "blocked") return { tone: "warn", label: fa ? "مسدود (فهرست)" : "Blocked (list)" };
  switch (rcodeOf(entry.rcode)) {
    case "NOERROR":
      return { tone: "ok", label: fa ? "پیدا شد" : "Found" };
    case "NXDOMAIN":
      return { tone: "info", label: fa ? "پیدا نشد" : "Not found" };
    case "REFUSED":
      return { tone: "warn", label: fa ? "رد شد" : "Refused" };
    case "SERVFAIL":
      return { tone: "error", label: fa ? "خطا" : "Error" };
    default:
      return { tone: "warn", label: fa ? "جواب دیگر" : "Other" };
  }
}

export const LOG_SOURCE_WORDS: Record<string, Bi> = {
  authoritative: { fa: "از دامنه‌های شما", en: "Your domains" },
  override: { fa: "از نام‌های شما", en: "Your names" },
  cache: { fa: "از حافظه", en: "From memory" },
  upstream: { fa: "از اینترنت", en: "From the internet" },
  forwarder: { fa: "از سرور دیگر", en: "From another server" },
  refused: { fa: "اجازه نداشت", en: "Not allowed" },
  rate_limited: { fa: "سقف پرسش", en: "Rate limit" },
  mitigated: { fa: "محدودسازی", en: "A limit" },
  recursive: { fa: "خودش از ریشه", en: "From the root" },
  // docs/41 §3.1: filtering (kept last in the list).
  blocked: { fa: "مسدودسازی", en: "Blocked" }
};
export function logSourceWord(language: Language, source: string | null | undefined): string {
  return (source && LOG_SOURCE_WORDS[source]?.[language]) || (language === "fa" ? "نامشخص" : "Unknown");
}

export const LOG_SOURCES = Object.keys(LOG_SOURCE_WORDS);

/** docs/40 §4: the DNSSEC column and filter (`none` = not checked). */
export const LOG_DNSSEC_WORDS: Record<string, { tone: Tone; label: Bi }> = {
  secure: { tone: "ok", label: { fa: "امضا درست", en: "Signed" } },
  insecure: { tone: "off", label: { fa: "بدون امضا", en: "Not signed" } },
  bogus: { tone: "error", label: { fa: "امضای خراب", en: "Broken" } },
  none: { tone: "off", label: { fa: "بررسی نشده", en: "Not checked" } }
};
export const LOG_DNSSEC = ["secure", "insecure", "bogus", "none"];
export const LOG_PROTOS = ["udp", "tcp", "dot", "doh", "doq"];
export const LOG_PROTO_WORDS: Record<string, Bi> = {
  udp: { fa: "معمولی (UDP)", en: "Plain (UDP)" },
  tcp: { fa: "معمولی (TCP)", en: "Plain (TCP)" },
  dot: { fa: "رمزدار با TLS", en: "Encrypted with TLS" },
  doh: { fa: "رمزدار با HTTPS", en: "Encrypted with HTTPS" },
  doq: { fa: "رمزدار سریع", en: "Encrypted, fast" }
};
export const LOG_RCODES = ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP"];
export const LOG_QTYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "PTR", "CAA", "SOA", "HTTPS", "SVCB", "ANY"];

/** Plain words for the common question types; the rest keep their technical name. */
export const QTYPE_WORDS: Record<string, Bi> = {
  A: { fa: "نشانی IPv4", en: "IPv4 address" },
  AAAA: { fa: "نشانی IPv6", en: "IPv6 address" },
  CNAME: { fa: "نام دیگر", en: "Alias" },
  MX: { fa: "سرور ایمیل", en: "Mail server" },
  TXT: { fa: "متن", en: "Text" },
  NS: { fa: "سرور نام", en: "Name server" },
  PTR: { fa: "نام یک نشانی", en: "Name of an address" },
  HTTPS: { fa: "مشخصات سایت", en: "Site details" },
  ANY: { fa: "همه‌چیز", en: "Everything" }
};

/** Keep the live list from growing without bound. */
export const LIVE_MAX_ROWS = 500;

// ── settings sections (docs/38 §2, inside the D1 settings object) ───────────

export type QueryLogSettings = {
  enabled: boolean;
  mode: "all" | "sample" | "errors_only" | "off" | string;
  sample_percent: number;
  max_age_days: number;
  max_bytes: number;
  min_free_disk_percent: number;
  client_ip: "full" | "mask" | "hash" | "none" | string;
  exclude_names: string[];
  exclude_clients: string[];
  stream_max_eps: number;
};
export type StatsSettings = { minute_retention_hours: number; hour_retention_days: number; day_retention_days: number; top_k: number };
export type Thresholds = { cpu: number; memory: number; qps_percent: number; host_cpu: number; host_memory: number };
export type PressureSettings = {
  enabled: boolean;
  capacity_qps: number;
  dwell_seconds: number;
  thresholds: { warning: Thresholds; critical: Thresholds; emergency: Thresholds };
  exit_margin_percent: number;
  actions: Record<string, boolean>;
  attack_detection: { mode: "off" | "suggest" | "auto" | string; nxdomain_unique_per_minute: number; mitigation_minutes: number };
};

export const DEFAULT_QUERYLOG: QueryLogSettings = {
  enabled: true, mode: "all", sample_percent: 100, max_age_days: 7, max_bytes: 2_147_483_648, min_free_disk_percent: 10,
  client_ip: "full", exclude_names: [], exclude_clients: [], stream_max_eps: 200
};
export const DEFAULT_STATS: StatsSettings = { minute_retention_hours: 48, hour_retention_days: 90, day_retention_days: 400, top_k: 100 };
export const DEFAULT_PRESSURE: PressureSettings = {
  enabled: true, capacity_qps: 50_000, dwell_seconds: 30,
  thresholds: {
    warning: { cpu: 70, memory: 75, qps_percent: 70, host_cpu: 85, host_memory: 90 },
    critical: { cpu: 85, memory: 85, qps_percent: 90, host_cpu: 92, host_memory: 95 },
    emergency: { cpu: 95, memory: 95, qps_percent: 110, host_cpu: 97, host_memory: 98 }
  },
  exit_margin_percent: 10,
  actions: { log_sampling: true, disable_prefetch: true, prefer_stale: true, tighten_client_qps: true, refuse_heavy_clients: true, minimal_any: true },
  attack_detection: { mode: "suggest", nxdomain_unique_per_minute: 500, mitigation_minutes: 30 }
};

/** Fill missing keys from the defaults (older engines, partial answers). */
export function withDefaults<T extends object>(value: unknown, defaults: T): T {
  if (!value || typeof value !== "object" || Array.isArray(value)) return JSON.parse(JSON.stringify(defaults)) as T;
  const result = { ...(JSON.parse(JSON.stringify(defaults)) as Record<string, unknown>) };
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const base = (defaults as Record<string, unknown>)[key];
    result[key] = base && typeof base === "object" && !Array.isArray(base) ? withDefaults(item, base as object) : item;
  }
  return result as T;
}
