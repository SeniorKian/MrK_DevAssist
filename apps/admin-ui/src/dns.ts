/**
 * MRK DNS (docs/36, contract docs/37 §4): types, API calls and the plain words used by the «DNS» pages.
 *
 * Every field from the backend is treated as optional so an older server (no DNS module) or a
 * partly filled answer never breaks a page. Panel API base: `/api/v1/dns`.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, apiGet, ensureOk, getJson, isAbortError, mutateJson } from "./api";
import type { Language } from "./i18n";
import { fill, type Bi } from "./copy/text";
import { fieldIssueMessage } from "./kit/people";
import { useVisibleInterval } from "./polling";

// ── types ────────────────────────────────────────────────────────────────────

export type DnsListener = { address: string; proto?: string; ok?: boolean; error?: string | null };
export type DnsUpstreamStatus = { id?: string; address: string; proto?: string; healthy?: boolean; rtt_ms?: number | null };

export type DnsEngineStatus = {
  version?: string;
  started_at?: number | string;
  uptime_s?: number;
  listeners?: DnsListener[];
  qps_1s?: number;
  qps_1m?: number;
  queries_total?: number;
  cache?: { entries?: number; bytes?: number; max_bytes?: number; hit_ratio?: number };
  upstreams?: DnsUpstreamStatus[];
  pressure?: string;
  memory_bytes?: number;
  goroutines?: number;
  config_version?: number | string;
};

export type DnsStatus = {
  installed?: boolean;
  reachable?: boolean;
  error_code?: string | null;
  engine?: DnsEngineStatus | null;
  setup_complete?: boolean;
};

export type DnsCommand = { id?: string; title_fa?: string; title_en?: string; code: string };
export type DnsSetupStep = {
  id: string;
  title_fa?: string;
  title_en?: string;
  state: "done" | "todo" | "warning" | "unknown" | string;
  detail_code?: string | null;
  params?: Record<string, unknown> | null;
  commands?: DnsCommand[] | null;
  revert?: DnsCommand[] | null;
};
export type DnsSetup = { steps: DnsSetupStep[] };

export type DnsListen = { address: string; udp: boolean; tcp: boolean };
export type DnsUpstream = { id?: string; address: string; enabled: boolean };
export type UpstreamStrategy = "fastest" | "parallel" | "in_order";

export type DnsSettings = {
  listen: DnsListen[];
  recursion: { enabled: boolean; allow: string[] };
  query_allow: string[];
  upstreams: DnsUpstream[];
  upstream_strategy: UpstreamStrategy | string;
  cache: {
    max_bytes: number;
    min_ttl: number;
    max_ttl: number;
    negative_max_ttl: number;
    serve_stale: boolean;
    stale_ttl: number;
    prefetch: boolean;
  };
  limits: {
    client_qps: number;
    client_burst: number;
    rrl_responses_per_second: number;
    rrl_slip: number;
    rrl_ipv4_prefix: number;
    rrl_ipv6_prefix: number;
    max_tcp_connections: number;
    tcp_idle_timeout_ms: number;
    udp_max_size: number;
    max_inflight_upstream: number;
  };
  minimal_any: boolean;
  refuse_any: boolean;
  rebinding_protection: boolean;
  overrides: { enabled: boolean };
  config_version?: number | string;
  /** Anything else the engine sends is kept and sent back untouched. */
  [key: string]: unknown;
};

export type ZoneType = "primary" | "forwarder";
export type DnsZone = {
  name: string;
  type: ZoneType | string;
  serial?: number | null;
  records?: number | null;
  disabled?: boolean;
  updated_at?: number | string | null;
  forwarders?: string[] | null;
};

export const RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "PTR", "CAA"] as const;
export type RecordType = (typeof RECORD_TYPES)[number];

export type DnsRecord = {
  id: string;
  name: string;
  type: RecordType | "SOA" | string;
  ttl?: number | null;
  data: Record<string, unknown>;
  disabled?: boolean;
  comment?: string | null;
};

export type DnsZoneVersion = {
  version: number | string;
  serial?: number | null;
  created_at?: number | string | null;
  records?: number | null;
  actor?: string | null;
  action?: string | null;
};

export type OverrideType = "A" | "AAAA" | "CNAME";
export type DnsOverride = {
  id: string;
  name: string;
  type: OverrideType | string;
  value: string;
  ttl?: number | null;
  source?: "user" | "services" | string;
  disabled?: boolean;
};

export type ResolveSource = "authoritative" | "override" | "cache" | "upstream" | "refused" | string;
export type DnsAnswer = { name: string; type: string; ttl?: number | null; data: unknown };
export type ResolveResult = {
  rcode?: string | number;
  answers?: DnsAnswer[];
  source?: ResolveSource;
  upstream?: string | null;
  rtt_ms?: number | null;
};

// ── API ──────────────────────────────────────────────────────────────────────

const BASE = "/api/v1/dns";
const zonePath = (zone: string) => `${BASE}/zones/${encodeURIComponent(zone)}`;
const fresh = () => `_=${Date.now()}`;

function itemsOf<T>(payload: unknown): T[] {
  if (Array.isArray(payload)) return payload as T[];
  const items = (payload as { items?: unknown } | null)?.items;
  return Array.isArray(items) ? (items as T[]) : [];
}

export const fetchDnsStatus = (signal?: AbortSignal) => getJson<DnsStatus>(`${BASE}/status?${fresh()}`, signal);

/** `refresh` asks the server to run every check again instead of using its short cache. */
export async function fetchDnsSetup(signal?: AbortSignal, refresh = false): Promise<DnsSetup> {
  const payload = await getJson<{ steps?: DnsSetupStep[] }>(`${BASE}/setup?${refresh ? "refresh=true&" : ""}${fresh()}`, signal);
  return { steps: Array.isArray(payload?.steps) ? payload.steps : [] };
}

/** Settings come either as the object itself or wrapped in `{settings, config_version}`. */
export async function fetchDnsSettings(signal?: AbortSignal): Promise<DnsSettings> {
  const payload = await getJson<Record<string, unknown>>(`${BASE}/settings?${fresh()}`, signal);
  if (payload && typeof payload.settings === "object" && payload.settings) {
    const inner = payload.settings as DnsSettings;
    return { ...inner, config_version: inner.config_version ?? (payload.config_version as number | string | undefined) };
  }
  return payload as DnsSettings;
}

export const saveDnsSettings = (settings: DnsSettings) =>
  mutateJson<DnsSettings | { settings?: DnsSettings }>(`${BASE}/settings`, { method: "PUT", body: settings });

export async function fetchZones(signal?: AbortSignal) {
  return itemsOf<DnsZone>(await getJson(`${BASE}/zones?${fresh()}`, signal));
}
export const createZone = (body: { name: string; type: ZoneType; forwarders?: string[] }) => mutateJson<DnsZone>(`${BASE}/zones`, { method: "POST", body });
export const patchZone = (zone: string, body: { disabled?: boolean; forwarders?: string[] }) => mutateJson<DnsZone>(zonePath(zone), { method: "PATCH", body });
/** The typed zone name goes along as `confirmation` (the server may ignore it). */
export const deleteZone = (zone: string) => mutateJson(zonePath(zone), { method: "DELETE", body: { confirmation: zone } });
export const fetchZone = (zone: string, signal?: AbortSignal) => getJson<DnsZone>(`${zonePath(zone)}?${fresh()}`, signal);

/** RFC 1035 zone text. Accepts `text/plain` or `{text}`. */
export async function exportZone(zone: string): Promise<string> {
  const response = await ensureOk(await apiGet(`${zonePath(zone)}/export?${fresh()}`));
  const type = response.headers.get("content-type") ?? "";
  if (type.includes("json")) {
    const payload = (await response.json()) as { text?: string; zone?: string } | string;
    return typeof payload === "string" ? payload : payload.text ?? payload.zone ?? "";
  }
  return response.text();
}
export const importZone = (zone: string, text: string, replace: boolean) =>
  mutateJson<{ added?: number; replaced?: number; records?: number }>(`${zonePath(zone)}/import`, { method: "POST", body: { text, replace } });
export async function fetchZoneHistory(zone: string, signal?: AbortSignal) {
  const payload = await getJson<unknown>(`${zonePath(zone)}/history?${fresh()}`, signal);
  const list = itemsOf<DnsZoneVersion>(payload);
  return list.length ? list : itemsOf<DnsZoneVersion>({ items: (payload as { versions?: unknown } | null)?.versions });
}
export const rollbackZone = (zone: string, version: number | string) => mutateJson(`${zonePath(zone)}/rollback`, { method: "POST", body: { version } });

export async function fetchRecords(zone: string, signal?: AbortSignal) {
  return itemsOf<DnsRecord>(await getJson(`${zonePath(zone)}/records?${fresh()}`, signal));
}
export type RecordInput = { name: string; type: string; ttl: number; data: Record<string, unknown>; disabled?: boolean; comment?: string };
export const createRecord = (zone: string, body: RecordInput) => mutateJson<DnsRecord>(`${zonePath(zone)}/records`, { method: "POST", body });
export const updateRecord = (zone: string, id: string, body: RecordInput) =>
  mutateJson<DnsRecord>(`${zonePath(zone)}/records/${encodeURIComponent(id)}`, { method: "PUT", body });
export const deleteRecord = (zone: string, id: string) => mutateJson(`${zonePath(zone)}/records/${encodeURIComponent(id)}`, { method: "DELETE" });

export async function fetchOverrides(signal?: AbortSignal) {
  return itemsOf<DnsOverride>(await getJson(`${BASE}/overrides?${fresh()}`, signal));
}
export type OverrideInput = { name: string; type: OverrideType; value: string; ttl: number; disabled?: boolean };
export const createOverride = (body: OverrideInput) => mutateJson<DnsOverride>(`${BASE}/overrides`, { method: "POST", body });
export const updateOverride = (id: string, body: OverrideInput) => mutateJson<DnsOverride>(`${BASE}/overrides/${encodeURIComponent(id)}`, { method: "PUT", body });
export const deleteOverride = (id: string) => mutateJson(`${BASE}/overrides/${encodeURIComponent(id)}`, { method: "DELETE" });

/** Panel-side DNS integration (`GET/PUT /api/v1/dns/integration`, dns:admin to change). */
export type DnsIntegrationSettings = {
  services_overrides: boolean;
  services_override_target: string;
  internal_zone_enabled: boolean;
  fallback_servers: string[];
};
export type DnsIntegration = {
  settings: DnsIntegrationSettings;
  effective_target?: string | null;
  internal_zone?: string | null;
  internal_names?: string[] | null;
  last_sync?: { status?: string; created?: number; updated?: number; deleted?: number; error_code?: string | null; at?: number } | null;
};
export const fetchDnsIntegration = (signal?: AbortSignal) => getJson<DnsIntegration>(`${BASE}/integration?${fresh()}`, signal);
export const saveDnsIntegration = (body: Partial<DnsIntegrationSettings>) => mutateJson<DnsIntegration>(`${BASE}/integration`, { method: "PUT", body });

export const resolveName = (body: { name: string; type: string; client_ip?: string }) => mutateJson<ResolveResult>(`${BASE}/resolve`, { method: "POST", body });
export const flushDnsCache = (name?: string) => mutateJson(`${BASE}/cache/flush`, { method: "POST", body: name ? { name } : {} });

/**
 * `GET /api/v1/dns/status`, polled while the tab is visible. `missing` = this server version has no
 * DNS module (a bare 404), so pages show a calm notice instead of an error.
 */
export function useDnsStatus(pollMs: number | null = 10_000) {
  const [status, setStatus] = useState<DnsStatus | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      const data = await fetchDnsStatus(current.signal);
      setStatus(data);
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);
  useVisibleInterval(() => void load(), pollMs);
  return { status, error, loading, reload: load };
}

/** The engine can answer changes only when it's installed and reachable. */
export function engineReady(status: DnsStatus | null): boolean {
  return Boolean(status?.installed && status?.reachable);
}

// ── validation ───────────────────────────────────────────────────────────────

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
export function isIPv4(value: string): boolean {
  return IPV4.test(value.trim());
}
export function isIPv6(value: string): boolean {
  const text = value.trim();
  if (!text.includes(":") || /[^0-9a-fA-F:.]/.test(text)) return false;
  try {
    new URL(`http://[${text}]/`);
    return true;
  } catch {
    return false;
  }
}
const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/i;
/** A DNS name like `git.example.com` (a trailing dot is fine). `relative` also allows `@` and a leading `*`. */
export function isDnsName(value: string, relative = false): boolean {
  const text = value.trim().replace(/\.$/, "");
  if (relative && (text === "@" || text === "*")) return true;
  if (!text || text.length > 253) return false;
  const labels = text.split(".");
  return labels.every((label, index) => (relative && index === 0 && label === "*") || LABEL.test(label));
}
export function isCidr(value: string): boolean {
  const [address, prefix, extra] = value.trim().split("/");
  if (extra !== undefined || prefix === undefined || !/^\d{1,3}$/.test(prefix)) return false;
  const bits = Number(prefix);
  if (isIPv4(address)) return bits <= 32;
  if (isIPv6(address)) return bits <= 128;
  return false;
}
/** `127.0.0.1:53` or `[::1]:53`. */
export function isListenAddress(value: string): boolean {
  const text = value.trim();
  const v6 = /^\[([^\]]+)\]:(\d{1,5})$/.exec(text);
  const v4 = /^([^:]+):(\d{1,5})$/.exec(text);
  const match = v6 ?? v4;
  if (!match) return false;
  const port = Number(match[2]);
  if (port < 1 || port > 65535) return false;
  return v6 ? isIPv6(match[1]) : isIPv4(match[1]);
}

/** The override type that fits a value: an IPv4 → A, an IPv6 → AAAA, a name → CNAME. */
export function overrideTypeFor(value: string): OverrideType | null {
  if (isIPv4(value)) return "A";
  if (isIPv6(value)) return "AAAA";
  if (isDnsName(value)) return "CNAME";
  return null;
}

export const TTL_MAX = 604_800;

// ── upstream addresses ───────────────────────────────────────────────────────

export type UpstreamProto = "udp" | "dot" | "doh";

/** `1.1.1.1:53` → udp, `tls://1.1.1.1:853#host` → dot, `https://…` → doh. */
export function upstreamProto(address: string): UpstreamProto {
  if (/^tls:\/\//i.test(address)) return "dot";
  if (/^https:\/\//i.test(address)) return "doh";
  return "udp";
}

/** Build the engine's address string from the parts the user typed. */
export function buildUpstreamAddress(proto: UpstreamProto, host: string, tlsName: string): string {
  const value = host.trim();
  if (proto === "doh") return /^https:\/\//i.test(value) ? value : `https://${value.replace(/^\/+/, "")}`;
  const withPort = (port: number) => (/:\d+$/.test(value) && !value.endsWith("]") ? value : `${isIPv6(value) ? `[${value}]` : value}:${port}`);
  if (proto === "dot") return `tls://${withPort(853)}${tlsName.trim() ? `#${tlsName.trim()}` : ""}`;
  return withPort(53);
}

export function upstreamAddressProblem(language: Language, address: string): string | null {
  const proto = upstreamProto(address);
  const fa = language === "fa";
  if (proto === "doh") {
    try {
      const url = new URL(address);
      return url.hostname ? null : fa ? "آدرس را مثل https://dns.google/dns-query بنویسید." : "Write the address like https://dns.google/dns-query.";
    } catch {
      return fa ? "آدرس را مثل https://dns.google/dns-query بنویسید." : "Write the address like https://dns.google/dns-query.";
    }
  }
  const body = proto === "dot" ? address.replace(/^tls:\/\//i, "").split("#")[0] : address;
  if (isListenAddress(body)) return null;
  return fa ? "نشانی را مثل 1.1.1.1 بنویسید." : "Write the address like 1.1.1.1.";
}

export type UpstreamPreset = { key: string; name: Bi; hint: Bi; addresses: string[]; iran?: boolean };

/**
 * Ready resolvers. Encrypted ones first; the Iranian ones are plain (they answer filtered names
 * and some sanctioned services from inside Iran).
 */
export const UPSTREAM_PRESETS: UpstreamPreset[] = [
  {
    key: "cloudflare",
    name: { fa: "Cloudflare", en: "Cloudflare" },
    hint: { fa: "سریع و رمزدار؛ گزینه خوب برای بیشتر سرورها.", en: "Fast and encrypted; a good choice for most servers." },
    addresses: ["tls://1.1.1.1:853#cloudflare-dns.com", "tls://1.0.0.1:853#cloudflare-dns.com"]
  },
  {
    key: "google",
    name: { fa: "Google", en: "Google" },
    hint: { fa: "رمزدار و پایدار.", en: "Encrypted and steady." },
    addresses: ["tls://8.8.8.8:853#dns.google", "https://dns.google/dns-query"]
  },
  {
    key: "quad9",
    name: { fa: "Quad9", en: "Quad9" },
    hint: { fa: "رمزدار؛ سایت‌های خطرناک را هم جواب نمی‌دهد.", en: "Encrypted; also refuses known dangerous sites." },
    addresses: ["tls://9.9.9.9:853#dns.quad9.net", "https://dns.quad9.net/dns-query"]
  },
  {
    key: "shecan",
    name: { fa: "شکن", en: "Shecan" },
    hint: { fa: "سرور ایرانی؛ برای باز شدن برخی سرویس‌های تحریمی.", en: "Iranian resolver; helps with some sanctioned services." },
    addresses: ["178.22.122.100:53", "185.51.200.2:53"],
    iran: true
  },
  {
    key: "403",
    name: { fa: "۴۰۳", en: "403" },
    hint: { fa: "سرور ایرانی؛ برای باز شدن برخی سرویس‌های تحریمی.", en: "Iranian resolver; helps with some sanctioned services." },
    addresses: ["10.202.10.202:53", "10.202.10.102:53"],
    iran: true
  },
  {
    key: "electro",
    name: { fa: "الکترو", en: "Electro" },
    hint: { fa: "سرور ایرانی؛ برای باز شدن برخی سرویس‌های تحریمی.", en: "Iranian resolver; helps with some sanctioned services." },
    addresses: ["78.157.42.100:53", "78.157.42.101:53"],
    iran: true
  }
];

export function presetFor(address: string): UpstreamPreset | undefined {
  return UPSTREAM_PRESETS.find((preset) => preset.addresses.includes(address));
}

// ── copy ─────────────────────────────────────────────────────────────────────

type Tone = "ok" | "warn" | "error" | "off" | "busy" | "info";

export const PROTO_WORDS: Record<UpstreamProto, Bi> = {
  udp: { fa: "معمولی (بدون رمز)", en: "Plain (not encrypted)" },
  dot: { fa: "رمزدار با TLS", en: "Encrypted with TLS" },
  doh: { fa: "رمزدار با HTTPS", en: "Encrypted with HTTPS" }
};

export const STRATEGY_WORDS: Record<UpstreamStrategy, { label: Bi; body: Bi }> = {
  fastest: { label: { fa: "سریع‌ترین", en: "Fastest" }, body: { fa: "از سرعت جواب‌ها یاد می‌گیرد و سریع‌ترین را می‌پرسد.", en: "Learns which one answers fastest and asks that one." } },
  parallel: { label: { fa: "همه با هم", en: "All at once" }, body: { fa: "از همه می‌پرسد و اولین جواب را برمی‌دارد. سریع ولی پرمصرف‌تر.", en: "Asks all of them and takes the first answer. Fast, but uses more traffic." } },
  in_order: { label: { fa: "به ترتیب", en: "In order" }, body: { fa: "اول اولی را می‌پرسد؛ اگر جواب نداد، بعدی را.", en: "Asks the first; if it doesn't answer, the next one." } }
};

export const ZONE_TYPE_WORDS: Record<ZoneType, { label: Bi; body: Bi }> = {
  primary: {
    label: { fa: "دامنه با رکوردهای خودم", en: "My own records" },
    body: { fa: "همه نام‌های این دامنه را خودتان اینجا می‌نویسید و MRK جواب می‌دهد.", en: "You write every name of this domain here and MRK answers." }
  },
  forwarder: {
    label: { fa: "فرستادن به سرور دیگر", en: "Send to another server" },
    body: { fa: "پرسش‌های این دامنه به سرورهای DNS که می‌گویید فرستاده می‌شود؛ مثلاً DNS شبکه شرکت.", en: "Questions for this domain go to the DNS servers you name, like your office network's DNS." }
  }
};

export function zoneTypeWord(language: Language, type: string): string {
  return ZONE_TYPE_WORDS[type as ZoneType]?.label[language] ?? (language === "fa" ? "نوع دیگر" : "Another type");
}

export const SOURCE_WORDS: Record<string, { label: Bi; body: Bi; tone: Tone }> = {
  override: { label: { fa: "از نام‌های شما", en: "From your names" }, body: { fa: "این جواب را خودتان در «نام‌ها» نوشته‌اید.", en: "You wrote this answer yourself under Names." }, tone: "ok" },
  authoritative: { label: { fa: "از دامنه‌های شما", en: "From your domains" }, body: { fa: "این نام در یکی از دامنه‌هایی است که MRK خودش جواب می‌دهد.", en: "This name is in one of the domains MRK answers for itself." }, tone: "ok" },
  cache: { label: { fa: "از جواب‌های ذخیره‌شده", en: "From stored answers" }, body: { fa: "MRK این را قبلاً پرسیده بود و جواب را نگه داشته بود؛ برای همین سریع بود.", en: "MRK asked this before and kept the answer, so it was quick." }, tone: "ok" },
  upstream: { label: { fa: "از اینترنت", en: "From the internet" }, body: { fa: "MRK این را از یک DNS بیرونی پرسید.", en: "MRK asked an outside DNS server." }, tone: "info" },
  refused: { label: { fa: "جواب داده نشد", en: "Refused" }, body: { fa: "این نشانی اجازه پرسیدن ندارد، یا پرسیدن از اینترنت خاموش است.", en: "This address isn't allowed to ask, or asking the internet is turned off." }, tone: "warn" }
};

export function sourceWord(language: Language, source: string | null | undefined) {
  const entry = source ? SOURCE_WORDS[source] : undefined;
  return entry
    ? { label: entry.label[language], body: entry.body[language], tone: entry.tone }
    : { label: language === "fa" ? "نامشخص" : "Unknown", body: "", tone: "off" as Tone };
}

const RCODE_WORDS: Record<string, Bi> = {
  NOERROR: { fa: "پیدا شد", en: "Found" },
  NXDOMAIN: { fa: "چنین نامی وجود ندارد", en: "No such name" },
  SERVFAIL: { fa: "سرور نتوانست جواب بدهد", en: "The server couldn't answer" },
  REFUSED: { fa: "جواب داده نشد", en: "Refused" },
  FORMERR: { fa: "پرسش درست نبود", en: "The question wasn't valid" },
  NOTIMP: { fa: "این نوع پرسش پشتیبانی نمی‌شود", en: "This kind of question isn't supported" }
};
const RCODE_NUMBERS: Record<number, string> = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED" };

export function rcodeName(rcode: string | number | null | undefined): string {
  if (typeof rcode === "number") return RCODE_NUMBERS[rcode] ?? String(rcode);
  return String(rcode ?? "").toUpperCase();
}
export function rcodeWord(language: Language, rcode: string | number | null | undefined): string {
  return RCODE_WORDS[rcodeName(rcode)]?.[language] ?? (language === "fa" ? "جواب دیگری آمد" : "Another answer");
}

/** One sentence for `status.error_code` when the engine is installed but not answering. */
const STATUS_REASONS: Record<string, Bi> = {
  dns_unreachable: { fa: "برنامه DNS روی سرور هست ولی جواب نمی‌دهد. شاید خاموش شده یا در حال روشن شدن است.", en: "The DNS program is on the server but isn't answering. It may be stopped or still starting." },
  dns_not_installed: { fa: "برنامه DNS هنوز روی این سرور روشن نشده است.", en: "The DNS program hasn't been started on this server yet." },
  token_missing: { fa: "پنل کلید اتصال به DNS را پیدا نکرد. برنامه DNS را یک بار دوباره راه‌اندازی کنید.", en: "The panel couldn't find the DNS connection key. Restart the DNS program once." },
  unauthorized: { fa: "کلید اتصال پنل به DNS قبول نشد. برنامه DNS و پنل را دوباره راه‌اندازی کنید.", en: "The DNS program didn't accept the panel's key. Restart DNS and the panel." },
  timeout: { fa: "برنامه DNS خیلی دیر جواب داد. شاید زیر فشار است.", en: "The DNS program answered too slowly. It may be under heavy load." }
};

export function statusReason(language: Language, code: string | null | undefined): string {
  const entry = code ? STATUS_REASONS[code] : undefined;
  return (entry ?? STATUS_REASONS.dns_unreachable)[language];
}

/** The one sentence at the top of «وضعیت». */
export function dnsVerdict(language: Language, status: DnsStatus | null): { tone: Tone; label: string; sentence: string } {
  const fa = language === "fa";
  if (!status) return { tone: "off", label: fa ? "نامشخص" : "Unknown", sentence: fa ? "در حال بررسی…" : "Checking…" };
  if (!status.installed) {
    return { tone: "off", label: fa ? "راه نیفتاده" : "Not set up", sentence: fa ? "DNS هنوز روی این سرور راه نیفتاده است." : "DNS isn't set up on this server yet." };
  }
  if (!status.reachable) return { tone: "error", label: fa ? "جواب نمی‌دهد" : "Not answering", sentence: statusReason(language, status.error_code) };
  const listeners = status.engine?.listeners ?? [];
  const failing = listeners.filter((item) => item.ok === false);
  const upstreams = status.engine?.upstreams ?? [];
  const sick = upstreams.length > 0 && upstreams.every((item) => item.healthy === false);
  if (failing.length) {
    return {
      tone: "warn",
      label: fa ? "نیاز به توجه" : "Needs attention",
      sentence: fa ? "DNS کار می‌کند، ولی روی بعضی نشانی‌ها نمی‌تواند گوش بدهد." : "DNS works, but it can't listen on some addresses."
    };
  }
  if (sick) {
    return {
      tone: "warn",
      label: fa ? "نیاز به توجه" : "Needs attention",
      sentence: fa ? "DNS جواب نام‌های خودتان را می‌دهد، ولی به هیچ DNS بیرونی نمی‌رسد." : "DNS answers your own names, but can't reach any outside DNS server."
    };
  }
  return { tone: "ok", label: fa ? "روشن" : "Running", sentence: fa ? "DNS روشن است و به پرسش‌ها جواب می‌دهد." : "DNS is running and answering questions." };
}

// ── setup steps ──────────────────────────────────────────────────────────────

export const SETUP_STEP_WORDS: Record<string, { title: Bi; why: Bi }> = {
  port_53_free: {
    title: { fa: "آزاد کردن پورت ۵۳", en: "Free port 53" },
    why: { fa: "DNS روی پورت ۵۳ جواب می‌دهد. اگر برنامه دیگری آن را گرفته باشد، اول باید آزادش کنید.", en: "DNS answers on port 53. If another program holds it, free it first." }
  },
  engine_running: {
    title: { fa: "روشن کردن برنامه DNS", en: "Start the DNS program" },
    why: { fa: "DNS یک کانتینر جدا کنار MRK است تا اگر زیر فشار رفت، پنل و بقیه سرویس‌ها سالم بمانند.", en: "DNS runs in its own container next to MRK, so the panel and other services stay healthy under load." }
  },
  host_resolver: {
    title: { fa: "استفاده خود سرور از این DNS", en: "Make the server itself use it" },
    why: { fa: "تا خود سرور هم نام‌ها را از MRK بپرسد. یک DNS پشتیبان هم کنارش می‌ماند تا اینترنت سرور قطع نشود.", en: "So the server itself asks MRK. A backup DNS stays next to it so the server never loses the internet." }
  },
  docker_daemon: {
    title: { fa: "استفاده کانتینرها از این DNS", en: "Make containers use it" },
    why: { fa: "تا برنامه‌های داخل Docker هم نام‌ها را از MRK بپرسند.", en: "So the apps inside Docker ask MRK too." }
  },
  verify_from_host: {
    title: { fa: "بررسی از روی سرور", en: "Check from the server" },
    why: { fa: "پنل یک پرسش آزمایشی از خود سرور می‌فرستد.", en: "The panel sends a test question from the server itself." }
  },
  verify_from_container: {
    title: { fa: "بررسی از داخل یک کانتینر", en: "Check from a container" },
    why: { fa: "پنل یک پرسش آزمایشی از داخل یک کانتینر می‌فرستد.", en: "The panel sends a test question from inside a container." }
  }
};

export function setupStepTitle(language: Language, id: string, step?: Pick<DnsSetupStep, "title_fa" | "title_en">): string {
  const fromServer = language === "fa" ? step?.title_fa : step?.title_en;
  return SETUP_STEP_WORDS[id]?.title[language] ?? fromServer ?? (language === "fa" ? "یک قدم دیگر" : "Another step");
}

export const SETUP_STATE_WORDS: Record<string, { tone: Tone; label: Bi }> = {
  done: { tone: "ok", label: { fa: "انجام شده", en: "Done" } },
  todo: { tone: "info", label: { fa: "مانده", en: "To do" } },
  warning: { tone: "warn", label: { fa: "نیاز به توجه", en: "Needs attention" } },
  unknown: { tone: "off", label: { fa: "بررسی نشد", en: "Not checked" } }
};

export function setupStateWord(language: Language, state: string) {
  const entry = SETUP_STATE_WORDS[state] ?? SETUP_STATE_WORDS.unknown;
  return { tone: entry.tone, label: entry.label[language] };
}

const AGENT_WORDS: Bi = {
  fa: "دستیار سرور وصل نیست یا جواب نمی‌دهد، پس MRK این را خودش نمی‌تواند بررسی کند. دستورها را اجرا کنید و بعد «دوباره بررسی کن» را بزنید.",
  en: "The server helper isn't connected or isn't answering, so MRK can't check this itself. Run the commands, then press Check again."
};

/**
 * Plain sentences for `detail_code` (codes from `dns_setup.py`). A `"<step>:<code>"` entry wins
 * over the bare code. Placeholders come from `params`: {process}, {address}, {nameservers}, {dns},
 * {fallback}, {gateway}, {name}. Unknown codes fall back to a sentence for the step's state.
 */
const DETAIL_WORDS: Record<string, Bi> = {
  // generic
  ok: { fa: "درست است.", en: "All good." },
  agent_not_configured: AGENT_WORDS,
  agent_unreachable: AGENT_WORDS,
  agent_unsupported: { fa: "دستیار سرور قدیمی است و این بررسی را بلد نیست. آن را به‌روز کنید، یا دستورها را اجرا کنید و ادامه دهید.", en: "The server helper is too old for this check. Update it, or run the commands and carry on." },
  agent_unavailable: AGENT_WORDS,
  host_proc_unavailable: { fa: "دستیار سرور به فهرست برنامه‌های سرور دسترسی ندارد، پس پورت ۵۳ بررسی نشد.", en: "The server helper can't see the server's programs, so port 53 wasn't checked." },
  host_root_unavailable: { fa: "دستیار سرور به فایل‌های تنظیم سرور دسترسی ندارد، پس این قدم بررسی نشد.", en: "The server helper can't read the server's settings files, so this step wasn't checked." },
  unknown: { fa: "MRK نتوانست این را بررسی کند. اگر دستورها را اجرا کرده‌اید، به قدم بعد بروید.", en: "MRK couldn't check this. If you ran the commands, go on to the next step." },
  // engine_running
  running: { fa: "برنامه DNS روشن است و جواب می‌دهد.", en: "The DNS program is running and answering." },
  not_installed: { fa: "برنامه DNS هنوز روشن نیست. دستور زیر را روی سرور اجرا کنید.", en: "The DNS program isn't running yet. Run the command below on the server." },
  engine_unreachable: { fa: "برنامه DNS هست ولی به پنل جواب نمی‌دهد. یک بار آن را دوباره راه‌اندازی کنید.", en: "The DNS program is there but doesn't answer the panel. Restart it once." },
  listener_failed: { fa: "برنامه DNS روشن است ولی نمی‌تواند روی {address} گوش بدهد. معمولاً یعنی برنامه دیگری پورت ۵۳ را گرفته؛ قدم بعد را ببینید.", en: "The DNS program runs but can't listen on {address}. Usually another program holds port 53; see the next step." },
  // port_53_free
  free: { fa: "پورت ۵۳ آزاد است.", en: "Port 53 is free." },
  held_by_mrk: { fa: "پورت ۵۳ دست خود MRK است.", en: "MRK itself holds port 53." },
  "port_53_free:systemd_resolved_stub": {
    fa: "برنامه DNS خود لینوکس پورت ۵۳ را گرفته. دستور زیر فقط شنیدنش روی پورت ۵۳ را خاموش می‌کند؛ اینترنت سرور قطع نمی‌شود.",
    en: "Linux's own DNS helper holds port 53. The command below only stops it listening on port 53; the server keeps its internet."
  },
  port_in_use: { fa: "برنامه «{process}» پورت ۵۳ را گرفته. اول آن را خاموش کنید یا به پورت دیگری ببرید.", en: "The program “{process}” holds port 53. Stop it or move it to another port first." },
  // host_resolver
  uses_mrk: { fa: "نام‌ها از MRK پرسیده می‌شوند و یک DNS پشتیبان هم هست.", en: "Names are asked from MRK, with a backup DNS too." },
  no_fallback: { fa: "نام‌ها از MRK پرسیده می‌شوند ولی DNS پشتیبان ندارد. اگر MRK بیفتد، اینترنت هم می‌افتد. دستور زیر یک پشتیبان ({fallback}) اضافه می‌کند.", en: "Names are asked from MRK, but there's no backup DNS. If MRK goes down, so does the internet. The command below adds a backup ({fallback})." },
  "host_resolver:systemd_resolved_stub": { fa: "خود سرور هنوز از برنامه DNS لینوکس می‌پرسد. دستور زیر آن را به MRK و یک DNS پشتیبان می‌فرستد.", en: "The server still asks Linux's own DNS helper. The command below points it at MRK plus a backup DNS." },
  resolved_stub_forwarding: { fa: "خود سرور از برنامه DNS لینوکس می‌پرسد و آن هم به MRK می‌فرستد. کار می‌کند، ولی دستور زیر مستقیم‌ترش می‌کند.", en: "The server asks Linux's DNS helper, which forwards to MRK. It works, but the command below makes it direct." },
  mrk_not_first: { fa: "MRK در فهرست هست ولی اول نیست، پس بیشتر پرسش‌ها جای دیگری می‌روند. دستور زیر MRK را اول می‌گذارد.", en: "MRK is listed but not first, so most questions go elsewhere. The command below puts MRK first." },
  "host_resolver:uses_other_dns": { fa: "خود سرور الان از {nameservers} می‌پرسد. دستور زیر MRK را اول و یک DNS پشتیبان را بعدش می‌گذارد.", en: "The server currently asks {nameservers}. The command below puts MRK first with a backup DNS after it." },
  static_resolv_conf: { fa: "فایل DNS سرور دستی نوشته شده و از {nameservers} می‌پرسد. دستور زیر MRK و یک DNS پشتیبان را در آن می‌نویسد.", en: "The server's DNS file is written by hand and asks {nameservers}. The command below writes MRK plus a backup DNS into it." },
  // docker_daemon
  daemon_json_missing: { fa: "فایل تنظیم Docker هنوز وجود ندارد؛ دستور زیر آن را با DNS درست می‌سازد.", en: "Docker's settings file doesn't exist yet; the command below creates it with the right DNS." },
  daemon_json_invalid: { fa: "فایل تنظیم Docker خراب است و خوانده نمی‌شود. اول آن را درست کنید، بعد DNS را اضافه کنید.", en: "Docker's settings file is broken and can't be read. Fix it first, then add the DNS." },
  dns_not_set: { fa: "در تنظیم Docker هنوز DNS نوشته نشده؛ کانتینرها از DNS دیگری می‌پرسند.", en: "Docker's settings don't list a DNS yet; containers ask another DNS." },
  "docker_daemon:uses_other_dns": { fa: "Docker الان به کانتینرها {dns} را می‌دهد. دستور زیر {gateway} را اول می‌گذارد.", en: "Docker currently gives containers {dns}. The command below puts {gateway} first." },
  "docker_daemon:uses_mrk": { fa: "Docker به کانتینرها همین DNS را می‌دهد و یک پشتیبان هم دارد.", en: "Docker gives containers this DNS, with a backup too." },
  // verify
  "verify_from_host:ok": { fa: "پرسش آزمایشی از روی سرور جواب درست گرفت.", en: "The test question from the server got the right answer." },
  "verify_from_container:ok": { fa: "پرسش آزمایشی از داخل کانتینر جواب درست گرفت.", en: "The test question from a container got the right answer." },
  engine_not_running: { fa: "تا برنامه DNS روشن نشود، این بررسی ممکن نیست. اول قدم اول را انجام دهید.", en: "This can't be checked until the DNS program runs. Do the first step first." },
  resolve_failed: { fa: "پرسش آزمایشی جواب نگرفت. قدم‌های قبلی را بررسی کنید.", en: "The test question got no answer. Check the earlier steps." },
  engine_ok_host_unknown: { fa: "DNS جواب می‌دهد، ولی MRK نمی‌داند خود سرور از آن می‌پرسد یا نه. با دستور زیر خودتان امتحان کنید.", en: "DNS answers, but MRK can't tell whether the server itself uses it. Try it yourself with the command below." },
  engine_ok_host_not_using: { fa: "DNS جواب می‌دهد، ولی خود سرور هنوز از آن نمی‌پرسد. قدم «استفاده خود سرور از این DNS» را انجام دهید.", en: "DNS answers, but the server itself doesn't use it yet. Do the “Make the server itself use it” step." },
  docker_dns_not_set: { fa: "کانتینرها هنوز از این DNS نمی‌پرسند. قدم «استفاده کانتینرها از این DNS» را انجام دهید.", en: "Containers don't ask this DNS yet. Do the “Make containers use it” step." },
  gateway_not_listening: { fa: "DNS روی نشانی شبکه Docker ({gateway}) گوش نمی‌دهد. آن را در تنظیمات DNS به نشانی‌ها اضافه کنید.", en: "DNS isn't listening on the Docker network address ({gateway}). Add it to the addresses in DNS settings." },
  manual_check: { fa: "این را MRK خودش نمی‌تواند بررسی کند. دستور زیر را روی سرور اجرا کنید؛ اگر نشانی آمد، درست است.", en: "MRK can't check this by itself. Run the command below on the server; if an address comes back, it works." }
};

const STATE_FALLBACK: Record<string, Bi> = {
  done: DETAIL_WORDS.ok,
  todo: { fa: "این قدم هنوز انجام نشده. دستور زیر را روی سرور اجرا کنید.", en: "This step isn't done yet. Run the command below on the server." },
  warning: { fa: "این قدم انجام شده ولی کامل نیست. توضیح و دستور زیر را ببینید.", en: "This step is done but not complete. See the note and command below." },
  unknown: DETAIL_WORDS.unknown
};

function paramText(language: Language, value: unknown): string {
  if (Array.isArray(value)) return value.map(String).join(language === "fa" ? "، " : ", ");
  return value === null || value === undefined ? "" : String(value);
}

export function setupDetail(language: Language, step: DnsSetupStep): string {
  const params = step.params ?? {};
  const code = step.detail_code ?? "";
  const entry = DETAIL_WORDS[`${step.id}:${code}`] ?? DETAIL_WORDS[code] ?? STATE_FALLBACK[step.state] ?? DETAIL_WORDS.unknown;
  const values: Record<string, string> = {};
  for (const [key, value] of Object.entries(params)) values[key] = paramText(language, value);
  const fallbackWord = language === "fa" ? "DNS دیگری" : "another DNS server";
  values.process ||= language === "fa" ? "دیگری" : "another program";
  values.nameservers ||= fallbackWord;
  values.dns ||= fallbackWord;
  values.fallback ||= "1.1.1.1";
  values.gateway ||= "172.17.0.1";
  values.address ||= language === "fa" ? "یکی از نشانی‌ها" : "one of its addresses";
  return fill(entry[language], values, language);
}

export function commandTitle(language: Language, command: DnsCommand, index: number): string {
  const title = language === "fa" ? command.title_fa || command.title_en : command.title_en || command.title_fa;
  if (title) return title;
  return language === "fa" ? `دستور ${new Intl.NumberFormat("fa-IR").format(index + 1)}` : `Command ${index + 1}`;
}

// ── record types ─────────────────────────────────────────────────────────────

export type FieldKind = "ipv4" | "ipv6" | "name" | "int" | "text" | "choice";
export type RecordFieldSpec = {
  key: string;
  label: Bi;
  kind: FieldKind;
  min?: number;
  max?: number;
  placeholder?: string;
  hint?: Bi;
  options?: { value: string; label: Bi }[];
  multiline?: boolean;
  defaultValue?: string | number;
};

export type RecordTypeSpec = { label: Bi; hint: Bi; fields: RecordFieldSpec[] };

const TARGET_HINT: Bi = { fa: "یک نام کامل، مثل mail.example.com", en: "A full name, like mail.example.com" };

/**
 * Field names of `data` for each type (docs/37 §2: "named fields", e.g. MX `{preference, exchange}`).
 * Assumed names for the rest; keep them in sync with the backend.
 */
export const RECORD_SPECS: Record<RecordType, RecordTypeSpec> = {
  A: {
    label: { fa: "نشانی IPv4", en: "IPv4 address" },
    hint: { fa: "این نام به این نشانی IP برود.", en: "This name goes to this IP address." },
    fields: [{ key: "address", label: { fa: "نشانی IP", en: "IP address" }, kind: "ipv4", placeholder: "192.168.1.10" }]
  },
  AAAA: {
    label: { fa: "نشانی IPv6", en: "IPv6 address" },
    hint: { fa: "این نام به این نشانی IPv6 برود.", en: "This name goes to this IPv6 address." },
    fields: [{ key: "address", label: { fa: "نشانی IPv6", en: "IPv6 address" }, kind: "ipv6", placeholder: "2001:db8::10" }]
  },
  CNAME: {
    label: { fa: "نام دیگر", en: "Alias" },
    hint: { fa: "این نام همان نام دیگری است؛ هر جا آن رفت، این هم برود.", en: "This name is another name for something else; it goes wherever that one goes." },
    fields: [{ key: "target", label: { fa: "نام اصلی", en: "Real name" }, kind: "name", placeholder: "app.example.com", hint: TARGET_HINT }]
  },
  MX: {
    label: { fa: "سرور ایمیل", en: "Mail server" },
    hint: { fa: "ایمیل‌های این دامنه به کدام سرور برود.", en: "Which server receives this domain's email." },
    fields: [
      { key: "preference", label: { fa: "اولویت (عدد کمتر = اول)", en: "Priority (lower goes first)" }, kind: "int", min: 0, max: 65535, defaultValue: 10 },
      { key: "exchange", label: { fa: "سرور ایمیل", en: "Mail server" }, kind: "name", placeholder: "mail.example.com", hint: TARGET_HINT }
    ]
  },
  TXT: {
    label: { fa: "متن", en: "Text" },
    hint: { fa: "یک متن دلخواه؛ معمولاً برای تأیید مالکیت دامنه یا تنظیم ایمیل.", en: "Any text; usually to prove you own the domain or to set up email." },
    fields: [{ key: "text", label: { fa: "متن", en: "Text" }, kind: "text", multiline: true, placeholder: "v=spf1 -all" }]
  },
  SRV: {
    label: { fa: "آدرس یک سرویس", en: "Service location" },
    hint: { fa: "یک سرویس خاص (مثل تماس یا چت) روی کدام سرور و پورت است.", en: "Which server and port run a specific service (like calls or chat)." },
    fields: [
      { key: "priority", label: { fa: "اولویت", en: "Priority" }, kind: "int", min: 0, max: 65535, defaultValue: 10 },
      { key: "weight", label: { fa: "وزن", en: "Weight" }, kind: "int", min: 0, max: 65535, defaultValue: 5 },
      { key: "port", label: { fa: "پورت", en: "Port" }, kind: "int", min: 0, max: 65535 },
      { key: "target", label: { fa: "سرور", en: "Server" }, kind: "name", placeholder: "sip.example.com", hint: TARGET_HINT }
    ]
  },
  NS: {
    label: { fa: "سرور نام", en: "Name server" },
    hint: { fa: "کدام سرور DNS جواب این بخش از دامنه را می‌دهد.", en: "Which DNS server answers for this part of the domain." },
    fields: [{ key: "nameserver", label: { fa: "سرور DNS", en: "DNS server" }, kind: "name", placeholder: "ns1.example.com", hint: TARGET_HINT }]
  },
  PTR: {
    label: { fa: "نام برای یک نشانی", en: "Name for an address" },
    hint: { fa: "برعکس نشانی: این نشانی IP چه نامی دارد.", en: "The reverse: which name an IP address has." },
    fields: [{ key: "target", label: { fa: "نام", en: "Name" }, kind: "name", placeholder: "host.example.com", hint: TARGET_HINT }]
  },
  CAA: {
    label: { fa: "صادرکننده گواهی", en: "Certificate issuer" },
    hint: { fa: "فقط کدام شرکت حق دارد برای این دامنه گواهی HTTPS بدهد.", en: "Which company may issue HTTPS certificates for this domain." },
    fields: [
      { key: "flags", label: { fa: "پرچم", en: "Flags" }, kind: "int", min: 0, max: 255, defaultValue: 0 },
      {
        key: "tag",
        label: { fa: "نوع", en: "Kind" },
        kind: "choice",
        defaultValue: "issue",
        options: [
          { value: "issue", label: { fa: "گواهی معمولی", en: "Regular certificates" } },
          { value: "issuewild", label: { fa: "گواهی همه زیردامنه‌ها", en: "Wildcard certificates" } },
          { value: "iodef", label: { fa: "گزارش تخلف به", en: "Report problems to" } }
        ]
      },
      { key: "value", label: { fa: "صادرکننده", en: "Issuer" }, kind: "text", placeholder: "letsencrypt.org" }
    ]
  }
};

export function isRecordType(value: string): value is RecordType {
  return (RECORD_TYPES as readonly string[]).includes(value);
}

export function recordTypeLabel(language: Language, type: string): string {
  if (isRecordType(type)) return RECORD_SPECS[type].label[language];
  if (type === "SOA") return language === "fa" ? "مشخصات دامنه (خودکار)" : "Zone details (automatic)";
  return type;
}

/** The record's value in one line (`10 mail.example.com`). Unknown shapes print their values. */
export function recordValue(record: Pick<DnsRecord, "type" | "data">): string {
  const data = record.data ?? {};
  if (isRecordType(record.type)) {
    const parts = RECORD_SPECS[record.type].fields.map((field) => data[field.key]).filter((value) => value !== undefined && value !== null && value !== "");
    if (parts.length) return parts.map((value) => (record.type === "TXT" || (record.type === "CAA" && value === data.value) ? JSON.stringify(String(value)) : String(value))).join(" ");
  }
  return Object.values(data).map((value) => (typeof value === "object" ? JSON.stringify(value) : String(value))).join(" ");
}

export function answerValue(answer: DnsAnswer): string {
  if (answer.data === null || answer.data === undefined) return "";
  if (typeof answer.data === "string" || typeof answer.data === "number") return String(answer.data);
  if (typeof answer.data === "object") return recordValue({ type: answer.type, data: answer.data as Record<string, unknown> });
  return String(answer.data);
}

/** A plain sentence for a field value, or null when it's fine. */
export function fieldProblem(language: Language, field: RecordFieldSpec, raw: string): string | null {
  const value = raw.trim();
  const fa = language === "fa";
  if (!value) return field.kind === "int" && field.defaultValue !== undefined ? null : fa ? "این خانه را پر کنید." : "Fill in this field.";
  switch (field.kind) {
    case "ipv4":
      return isIPv4(value) ? null : fa ? "نشانی را مثل 192.168.1.10 بنویسید." : "Write the address like 192.168.1.10.";
    case "ipv6":
      return isIPv6(value) ? null : fa ? "نشانی را مثل 2001:db8::10 بنویسید." : "Write the address like 2001:db8::10.";
    case "name":
      return isDnsName(value) ? null : fa ? "نام را مثل mail.example.com بنویسید." : "Write the name like mail.example.com.";
    case "int": {
      const number = Number(value.replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit))));
      const min = field.min ?? 0;
      const max = field.max ?? 65535;
      if (!Number.isInteger(number) || number < min || number > max) {
        return fill(fa ? "یک عدد بین {min} تا {max} بنویسید." : "Write a number from {min} to {max}.", { min, max }, language);
      }
      return null;
    }
    case "text":
      return value.length > 4000 ? (fa ? "این متن خیلی بلند است." : "This text is too long.") : null;
    default:
      return null;
  }
}

/** Field reason codes the DNS backend may send in `fields`, in plain words. */
const DNS_FIELD_REASONS: Record<string, Bi> = {
  invalid_ip: { fa: "این نشانی IP درست نیست.", en: "This IP address isn't valid." },
  invalid_ipv4: { fa: "نشانی را مثل 192.168.1.10 بنویسید.", en: "Write the address like 192.168.1.10." },
  invalid_ipv6: { fa: "نشانی را مثل 2001:db8::10 بنویسید.", en: "Write the address like 2001:db8::10." },
  invalid_name: { fa: "این نام درست نیست؛ فقط حروف انگلیسی، عدد، خط تیره و نقطه.", en: "This name isn't valid; use letters, digits, dashes and dots." },
  invalid_cidr: { fa: "محدوده را مثل 192.168.0.0/16 بنویسید.", en: "Write the range like 192.168.0.0/16." },
  invalid_address: { fa: "این نشانی درست نیست.", en: "This address isn't valid." },
  invalid_ttl: { fa: "مدت نگه‌داری باید بین ۰ ثانیه تا ۷ روز باشد.", en: "The time to keep must be between 0 seconds and 7 days." },
  ttl_out_of_range: { fa: "مدت نگه‌داری باید بین ۰ ثانیه تا ۷ روز باشد.", en: "The time to keep must be between 0 seconds and 7 days." },
  out_of_range: { fa: "این عدد خارج از محدوده مجاز است.", en: "This number is outside the allowed range." },
  cname_conflict: { fa: "نامی که «نام دیگر» دارد نمی‌تواند رکورد دیگری هم داشته باشد.", en: "A name that is an alias can't have any other record." },
  dns_cname_conflict: { fa: "نامی که «نام دیگر» دارد نمی‌تواند رکورد دیگری هم داشته باشد.", en: "A name that is an alias can't have any other record." },
  duplicate: { fa: "همین مورد قبلاً اضافه شده است.", en: "This already exists." },
  cname_at_apex: { fa: "خود دامنه (@) نمی‌تواند «نام دیگر» باشد؛ از نشانی IP استفاده کنید.", en: "The domain itself (@) can't be an alias; use an IP address." },
  self_reference: { fa: "یک نام نمی‌تواند به خودش اشاره کند.", en: "A name can't point to itself." },
  soa_managed: { fa: "مشخصات دامنه خودکار ساخته می‌شود.", en: "Zone details are made automatically." },
  soa_apex_only: { fa: "مشخصات دامنه فقط برای خود دامنه است.", en: "Zone details belong to the domain itself." },
  greater_than_max: { fa: "کمترین مقدار باید از بیشترین کمتر باشد.", en: "The smallest value must be less than the largest." },
  invalid_choice: { fa: "یکی از گزینه‌ها را انتخاب کنید.", en: "Pick one of the options." },
  incorrect: { fa: "درست نوشته نشد؛ دوباره بنویسید.", en: "That isn't right; type it again." },
  outside_zone: { fa: "این نام بیرون از این دامنه است.", en: "This name is outside this domain." },
  too_long: { fa: "این متن بیش از حد بلند است؛ کوتاه‌ترش کنید.", en: "This is too long; shorten it." },
  required: { fa: "این خانه را پر کنید.", en: "Fill in this field." }
};

/**
 * `{field: sentence}` from a DNS error. Field names like `data.exchange` become `exchange`;
 * `ttl`, `name`, `value`, `type` stay as they are.
 */
export function dnsFieldMessages(language: Language, error: unknown): Record<string, string> {
  const result: Record<string, string> = {};
  if (!(error instanceof ApiError)) return result;
  for (const issue of error.fields) {
    const key = issue.field.replace(/^(data|body|record|override)\./, "");
    if (result[key]) continue;
    const words = DNS_FIELD_REASONS[issue.reason_code];
    result[key] = words ? words[language] : fieldIssueMessage(language, issue);
  }
  return result;
}

// ── numbers ──────────────────────────────────────────────────────────────────

export function formatQps(language: Language, value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US", { maximumFractionDigits: value < 10 ? 1 : 0 }).format(value);
}

/** `hit_ratio` may be 0..1 or already a percentage. */
export function hitPercent(ratio: number | null | undefined): number | null {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) return null;
  return ratio <= 1 ? ratio * 100 : ratio;
}

export function download(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}
