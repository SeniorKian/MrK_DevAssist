/**
 * DNS final phase (contract docs/41): types, API calls and plain words for
 * - domain templates (§5): list / create / edit / delete, preview, apply, default template;
 * - zones (§2): secondary status and refresh, transfer / NOTIFY / dynamic update, TSIG keys, zone signing;
 * - policy (§3): filtering lists, allow / block, "why was this blocked?", client groups;
 * - backup and restore (§4).
 *
 * The backend is built to the same contract in parallel, so every field is optional and every
 * list accepts `[...]` or `{items: [...]}`. Panel API base: `/api/v1/dns`.
 */
import { apiGet, apiMutate, ensureOk, getCsrfToken, getJson, mutateJson, refreshCsrf, toApiError } from "./api";
import type { Language } from "./i18n";
import { fill, pick, type Bi } from "./copy/text";
import { dnsBase, fetchDnsSettings, recordTypeLabel, type DnsZone } from "./dns";

const fresh = () => `_=${Date.now()}`;
const zonePath = (zone: string) => `${dnsBase()}/zones/${encodeURIComponent(zone)}`;

function itemsOf<T>(payload: unknown, ...keys: string[]): T[] {
  if (Array.isArray(payload)) return payload as T[];
  if (!payload || typeof payload !== "object") return [];
  for (const key of ["items", ...keys]) {
    const value = (payload as Record<string, unknown>)[key];
    if (Array.isArray(value)) return value as T[];
  }
  return [];
}

/** Seconds or milliseconds or an ISO text → something RelativeTime understands. */
export function toTime(value: number | string | null | undefined): number | string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") return value < 1e12 ? value * 1000 : value;
  return value;
}

// ── templates (§5) ───────────────────────────────────────────────────────────

export type TemplateRecord = {
  name: string;
  type: string;
  ttl?: number | null;
  /** Named fields like a record (`{address: "{server_ipv4}"}`); a plain text is accepted too. */
  data: Record<string, unknown> | string;
  comment?: string | null;
};
export type TemplateVariable = { key: string; label_fa?: string | null; label_en?: string | null; default?: string | null; required?: boolean };
export type TemplateZone = {
  ttl?: number | null;
  soa?: { hostmaster?: string | null; refresh?: number | null; retry?: number | null; expire?: number | null; minimum?: number | null } | null;
  ns?: string[] | null;
};
export type DnsTemplate = {
  id: string;
  name: string;
  name_fa?: string | null;
  name_en?: string | null;
  description?: string | null;
  description_fa?: string | null;
  description_en?: string | null;
  builtin?: boolean;
  is_default?: boolean;
  default?: boolean;
  zone?: TemplateZone | null;
  records: TemplateRecord[];
  variables: TemplateVariable[];
  updated_at?: number | string | null;
};
export type TemplateInput = Omit<DnsTemplate, "id" | "builtin" | "is_default" | "default" | "updated_at" | "name_fa" | "name_en" | "description_fa" | "description_en">;

/** The variables Pishkar fills by itself (§5): never asked in Simple mode. */
export const AUTO_VARIABLES = ["domain", "domain_dashed", "server_ipv4", "server_ipv6"] as const;
export const isAutoVariable = (key: string) => (AUTO_VARIABLES as readonly string[]).includes(key);

/** Known variable names in plain words (the template's own labels win). */
export const VARIABLE_WORDS: Record<string, { label: Bi; hint?: Bi }> = {
  domain: { label: { fa: "نام دامنه", en: "Domain name" } },
  domain_dashed: { label: { fa: "نام دامنه با خط تیره", en: "Domain name with dashes" } },
  server_ipv4: { label: { fa: "نشانی IPv4 سرور", en: "Server IPv4 address" }, hint: { fa: "خالی بگذارید تا پیشکار خودش پیدا کند.", en: "Leave empty and Pishkar finds it." } },
  server_ipv6: { label: { fa: "نشانی IPv6 سرور", en: "Server IPv6 address" }, hint: { fa: "خالی بگذارید تا پیشکار خودش پیدا کند.", en: "Leave empty and Pishkar finds it." } },
  mail_host: { label: { fa: "سرور ایمیل", en: "Mail server" }, hint: { fa: "نام سروری که ایمیل‌ها را می‌گیرد، مثل mail.example.com", en: "The server that receives email, like mail.example.com" } },
  dkim_value: { label: { fa: "کلید امضای ایمیل", en: "Email signing key" }, hint: { fa: "متنی که سرویس ایمیل شما داده است؛ با v=DKIM1 شروع می‌شود.", en: "The text your email service gave you; it starts with v=DKIM1." } }
};

export function templateName(language: Language, template: Pick<DnsTemplate, "name" | "name_fa" | "name_en">): string {
  return (language === "fa" ? template.name_fa : template.name_en) || template.name || "—";
}
export function templateDescription(language: Language, template: Pick<DnsTemplate, "description" | "description_fa" | "description_en">): string {
  return (language === "fa" ? template.description_fa : template.description_en) || template.description || "";
}
export function variableLabel(language: Language, variable: TemplateVariable): string {
  const own = language === "fa" ? variable.label_fa : variable.label_en;
  return own || (VARIABLE_WORDS[variable.key] ? pick(language, VARIABLE_WORDS[variable.key].label) : variable.key);
}

function normalizeTemplate(raw: Partial<DnsTemplate> & Record<string, unknown>): DnsTemplate {
  return {
    ...(raw as DnsTemplate),
    id: String(raw.id ?? raw.name ?? ""),
    name: String(raw.name ?? raw.id ?? ""),
    records: Array.isArray(raw.records) ? raw.records : [],
    variables: Array.isArray(raw.variables) ? raw.variables : []
  };
}

export type TemplateList = { items: DnsTemplate[]; defaultId: string | null };

/**
 * `GET /api/v1/dns/templates`. The default comes from `default_template_id` on the list, an
 * `is_default` / `default` flag on one item, or (older answers) the first built-in one.
 */
export async function fetchTemplates(signal?: AbortSignal): Promise<TemplateList> {
  const payload = await getJson<unknown>(`${dnsBase()}/templates?${fresh()}`, signal);
  const items = itemsOf<Partial<DnsTemplate> & Record<string, unknown>>(payload, "templates").map(normalizeTemplate).filter((item) => item.id);
  // `default_template_id` (admin) or `default_id` («فضای من», docs/43 §0.1).
  const body = payload && typeof payload === "object" && !Array.isArray(payload) ? (payload as { default_template_id?: unknown; default_id?: unknown }) : null;
  const fromList = body ? body.default_template_id ?? body.default_id : null;
  const flagged = items.find((item) => item.is_default || item.default);
  const defaultId = (typeof fromList === "string" && fromList) || flagged?.id || null;
  return { items, defaultId };
}
export const createTemplate = (body: TemplateInput) => mutateJson<DnsTemplate>(`${dnsBase()}/templates`, { method: "POST", body });
export const updateTemplate = (id: string, body: TemplateInput) => mutateJson<DnsTemplate>(`${dnsBase()}/templates/${encodeURIComponent(id)}`, { method: "PUT", body });
export const deleteTemplate = (id: string) => mutateJson(`${dnsBase()}/templates/${encodeURIComponent(id)}`, { method: "DELETE" });

/**
 * §5 default template: `PUT /api/v1/dns/templates/default {template_id|null}` (docs/41 §0.3); an older
 * server without it gets the runtime setting `dns.default_template_id` instead.
 */
export async function setDefaultTemplate(id: string | null) {
  const response = await apiMutate(`${dnsBase()}/templates/default`, { method: "PUT", body: { template_id: id } });
  if (response.ok) return;
  if (response.status !== 404 && response.status !== 405) throw await toApiError(response);
  const fallback = await apiMutate(`/api/v1/settings/registry/${encodeURIComponent("dns.default_template_id")}`, { method: "PUT", body: { value: id ?? "" } });
  if (!fallback.ok) throw await toApiError(fallback);
}

export type PreviewStatus = "new" | "duplicate" | "conflict" | "skipped";
export type PreviewRecord = TemplateRecord & {
  status?: PreviewStatus | string;
  /** `record` | `ns` | `soa` (docs/41 §0.3). */
  source?: string;
  conflicts?: unknown[];
  reason?: string | null;
  /** The empty variable that made a record `skipped`. */
  variable?: string | null;
};
export type PreviewSummary = { new?: number; duplicate?: number; conflict?: number; skipped?: number };
export type TemplatePreview = {
  records: PreviewRecord[];
  variables: Record<string, string>;
  missing: string[];
  summary: PreviewSummary | null;
  canApply: boolean | null;
  warnings: string[];
  replaceEffects: { removes?: number; comments_dropped?: number; blocked?: { disabled?: number; view?: number } } | null;
};

const warningCode = (item: unknown) => (typeof item === "string" ? item : item && typeof item === "object" ? String((item as { code?: unknown }).code ?? "") : "");

/**
 * docs/41 §0.3: `{items:[{index, source, status, record, conflicts, reason?, variable?}], variables, summary, can_apply,
 * replace_effects, warnings}`. Also accepts flat `{records:[{…, status}]}` or `{new:[…], duplicate:[…], conflict:[…]}`.
 */
function normalizePreview(payload: unknown): TemplatePreview {
  const body = (payload && typeof payload === "object" ? payload : {}) as Record<string, unknown>;
  let records = itemsOf<PreviewRecord & { record?: TemplateRecord }>(body, "records").map((item) =>
    item.record && typeof item.record === "object" ? { ...item.record, status: item.status, source: item.source, conflicts: item.conflicts, reason: item.reason, variable: item.variable } : item
  ) as PreviewRecord[];
  if (!records.length) {
    for (const status of ["new", "duplicate", "conflict"] as const) {
      const group = body[status] ?? body[`${status}s`];
      if (Array.isArray(group)) records = records.concat((group as PreviewRecord[]).map((item) => ({ ...item, status })));
    }
  }
  const variables = body.variables && typeof body.variables === "object" && !Array.isArray(body.variables) ? (body.variables as Record<string, string>) : {};
  const missing = Array.isArray(body.missing) ? (body.missing as string[]) : Array.isArray(body.missing_variables) ? (body.missing_variables as string[]) : [];
  const summary = body.summary && typeof body.summary === "object" ? (body.summary as PreviewSummary) : null;
  const warnings = Array.isArray(body.warnings) ? body.warnings.map(warningCode).filter(Boolean) : [];
  const replaceEffects = body.replace_effects && typeof body.replace_effects === "object" ? (body.replace_effects as TemplatePreview["replaceEffects"]) : null;
  return { records, variables, missing, summary, canApply: typeof body.can_apply === "boolean" ? body.can_apply : null, warnings, replaceEffects };
}
export async function previewTemplate(id: string, zone: string, variables: Record<string, string>, signal?: AbortSignal) {
  return normalizePreview(await mutateJson(`${dnsBase()}/templates/${encodeURIComponent(id)}/preview`, { method: "POST", body: { zone, variables }, signal }));
}
export type ApplyResult = { applied?: boolean; mode?: "add" | "replace" | null; added?: number; replaced?: number; summary?: PreviewSummary; version?: number | string; warnings?: unknown[]; error?: { code?: string; message?: string } | null };
export const applyTemplate = (zone: string, templateId: string, variables: Record<string, string>, replaceConflicts = false) =>
  mutateJson<ApplyResult>(`${zonePath(zone)}/apply-template`, { method: "POST", body: { template_id: templateId, variables, ...(replaceConflicts ? { replace_conflicts: true } : {}) } });

const PLACEHOLDER = /\{([a-z0-9_]+)\}/gi;

/** Every `{name}` the template uses, declared or not, in order of first use. */
export function usedVariables(template: Pick<DnsTemplate, "records" | "zone">): string[] {
  const found = new Set<string>();
  const scan = (value: unknown) => {
    if (typeof value === "string") for (const match of value.matchAll(PLACEHOLDER)) found.add(match[1].toLowerCase());
    else if (value && typeof value === "object") Object.values(value).forEach(scan);
  };
  template.records.forEach((record) => { scan(record.name); scan(record.data); });
  scan(template.zone ?? null);
  return [...found];
}

/** The variables a person is asked for: declared + used-but-undeclared, minus the automatic ones. */
export function askedVariables(template: DnsTemplate, includeAuto = false): TemplateVariable[] {
  const declared = new Map(template.variables.map((item) => [item.key, item]));
  for (const key of usedVariables(template)) if (!declared.has(key)) declared.set(key, { key, required: !isAutoVariable(key) });
  return [...declared.values()].filter((item) => includeAuto ? item.key !== "domain" : !isAutoVariable(item.key));
}

export function initialVariables(template: DnsTemplate | null): Record<string, string> {
  const values: Record<string, string> = {};
  if (!template) return values;
  for (const item of askedVariables(template, true)) values[item.key] = item.default ?? "";
  return values;
}

/** The required variables still empty. */
export function missingVariables(template: DnsTemplate | null, values: Record<string, string>): string[] {
  if (!template) return [];
  return askedVariables(template).filter((item) => item.required && !(values[item.key] ?? "").trim()).map((item) => item.key);
}

/** Only the filled values travel; Pishkar fills the automatic ones. */
export function cleanVariables(values: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(values).map(([key, value]) => [key, value.trim()]).filter(([, value]) => value));
}

function expandText(text: string, values: Record<string, string>, fallback?: string): string {
  return text.replace(PLACEHOLDER, (match, key: string) => values[key.toLowerCase()] || (fallback ?? match));
}

/** Replace the variables in a template record (unknown ones stay as `{name}`, or become `fallback`). */
export function expandRecord(record: TemplateRecord, values: Record<string, string>, fallback?: string): TemplateRecord {
  const data = typeof record.data === "string"
    ? expandText(record.data, values, fallback)
    : Object.fromEntries(Object.entries(record.data ?? {}).map(([key, value]) => [key, typeof value === "string" ? expandText(value, values, fallback) : value]));
  return { ...record, name: expandText(record.name || "@", values, fallback), data };
}

/** A record value in one line, whether `data` is named fields or plain text. */
export function templateValue(record: Pick<TemplateRecord, "type" | "data">): string {
  if (typeof record.data === "string") return record.data;
  const data = record.data ?? {};
  const order: Record<string, string[]> = {
    A: ["address"], AAAA: ["address"], CNAME: ["target"], NS: ["nameserver"], PTR: ["target"], TXT: ["text"],
    MX: ["preference", "exchange"], SRV: ["priority", "weight", "port", "target"], CAA: ["flags", "tag", "value"]
  };
  const keys = order[record.type] ?? Object.keys(data);
  const parts = keys.map((key) => data[key]).filter((value) => value !== undefined && value !== null && value !== "");
  return (parts.length ? parts : Object.values(data)).map((value) => (typeof value === "object" ? JSON.stringify(value) : String(value))).join(" ");
}

function field(record: TemplateRecord, key: string): string {
  if (typeof record.data === "string") return record.data;
  const value = record.data?.[key];
  return value === undefined || value === null ? "" : String(value);
}

/** The full name a template record lands on. */
export function recordHost(name: string, zone: string): string {
  const clean = (name || "@").replace(/\.$/, "");
  if (clean === "@") return zone || "@";
  if (zone && clean.toLowerCase().endsWith(`.${zone.toLowerCase()}`)) return clean;
  return zone ? `${clean}.${zone}` : clean;
}

const SENTENCES = {
  address: { fa: "«{host}» به نشانی {value} می‌رود", en: "“{host}” goes to the address {value}" },
  wildcardAddress: { fa: "هر نام دیگر زیر «{zone}» به نشانی {value} می‌رود", en: "Any other name under “{zone}” goes to the address {value}" },
  alias: { fa: "«{host}» همان «{value}» است", en: "“{host}” is the same as “{value}”" },
  mail: { fa: "ایمیل‌های «{host}» به سرور «{value}» می‌رود", en: "Email for “{host}” goes to the server “{value}”" },
  spf: { fa: "فقط سرورهای مجاز از طرف «{host}» ایمیل بفرستند", en: "Only allowed servers may send email as “{host}”" },
  spfNone: { fa: "هیچ سروری از طرف «{host}» ایمیل نفرستد", en: "No server may send email as “{host}”" },
  dmarc: { fa: "ایمیل‌های جعلی به نام «{zone}» رد شوند", en: "Fake email in the name of “{zone}” is rejected" },
  dkim: { fa: "کلید امضای ایمیل‌های «{zone}» منتشر شود", en: "The email signing key of “{zone}” is published" },
  verify: { fa: "مالکیت «{host}» برای یک سرویس بیرونی تأیید شود", en: "Ownership of “{host}” is proven to an outside service" },
  text: { fa: "روی «{host}» این متن گذاشته شود: {value}", en: "This text is put on “{host}”: {value}" },
  caa: { fa: "فقط «{value}» برای «{host}» گواهی HTTPS بدهد", en: "Only “{value}” may issue HTTPS certificates for “{host}”" },
  ns: { fa: "جواب «{host}» را سرور «{value}» می‌دهد", en: "The server “{value}” answers for “{host}”" },
  srv: { fa: "سرویس «{host}» روی «{value}» است", en: "The service “{host}” runs on “{value}”" },
  other: { fa: "«{host}»: {type} {value}", en: "“{host}”: {type} {value}" }
} satisfies Record<string, Bi>;

/** One plain sentence for a (variables-filled) template record: what will be created. */
export function templateRecordSentence(language: Language, record: TemplateRecord, zone: string): string {
  const host = recordHost(record.name, zone);
  const value = templateValue(record);
  const params = { host, zone: zone || host, value, type: recordTypeLabel(language, record.type) };
  const say = (text: Bi) => fill(pick(language, text), params, language);
  switch (record.type) {
    case "A":
    case "AAAA":
      return say(record.name === "*" || record.name.startsWith("*.") ? SENTENCES.wildcardAddress : SENTENCES.address);
    case "CNAME":
      return say(SENTENCES.alias);
    case "MX":
      return fill(pick(language, SENTENCES.mail), { ...params, value: field(record, "exchange") || value }, language);
    case "TXT": {
      const text = field(record, "text").trim();
      if (/^v=spf1/i.test(text)) return say(/^v=spf1\s+-all$/i.test(text) ? SENTENCES.spfNone : SENTENCES.spf);
      if (/^v=dmarc1/i.test(text)) return say(SENTENCES.dmarc);
      if (/^v=dkim1/i.test(text) || /_domainkey/i.test(record.name)) return say(SENTENCES.dkim);
      if (/verification|verify|^ms=/i.test(text)) return say(SENTENCES.verify);
      return say(SENTENCES.text);
    }
    case "CAA":
      return fill(pick(language, SENTENCES.caa), { ...params, value: field(record, "value") || value }, language);
    case "NS":
      return say(SENTENCES.ns);
    case "SRV":
      return say(SENTENCES.srv);
    default:
      return say(SENTENCES.other);
  }
}

/** Whether a value still holds `{name}` (the variable wasn't filled; Pishkar fills the automatic ones). */
export const hasPlaceholder = (text: string) => /\{[a-z0-9_]+\}/i.test(text);

// ── zones (§2) ───────────────────────────────────────────────────────────────

export type ZoneSecondaryStatus = {
  serial?: number | null;
  last_refresh?: number | string | null;
  last_success?: number | string | null;
  next_refresh?: number | string | null;
  expires_at?: number | string | null;
  error?: string | null;
  state?: string | null;
  loaded?: boolean;
  expired?: boolean;
  primary?: string | null;
  last_transfer?: "axfr" | "ixfr" | string | null;
};
export type ZoneTransfer = { allow: string[]; tsig_key?: string | null };
export type ZoneNotify = { targets: string[]; enabled: boolean; tsig_key?: string | null };
export type ZoneUpdate = { enabled: boolean; allow: string[]; tsig_key?: string | null; require_tsig: boolean };
export type DnssecAlgorithm = "ECDSAP256SHA256" | "ED25519";
export type ZoneDnssecSettings = {
  enabled: boolean;
  algorithm: DnssecAlgorithm | string;
  denial: "nsec" | "nsec3" | string;
  nsec3: { iterations: number; salt: string; opt_out: boolean };
  signature_validity_days: number;
  refresh_days: number;
};

export const DEFAULT_TRANSFER: ZoneTransfer = { allow: [], tsig_key: null };
export const DEFAULT_NOTIFY: ZoneNotify = { targets: [], enabled: false };
export const DEFAULT_UPDATE: ZoneUpdate = { enabled: false, allow: [], tsig_key: null, require_tsig: true };
export const DEFAULT_ZONE_DNSSEC: ZoneDnssecSettings = {
  enabled: false,
  algorithm: "ECDSAP256SHA256",
  denial: "nsec",
  nsec3: { iterations: 0, salt: "", opt_out: false },
  signature_validity_days: 14,
  refresh_days: 3
};

export const fetchZoneDetail = (zone: string, signal?: AbortSignal) => getJson<DnsZone>(`${zonePath(zone)}?${fresh()}`, signal);
export const refreshSecondary = (zone: string) => mutateJson(`${zonePath(zone)}/refresh`, { method: "POST", body: {} });

export type DnssecKey = { tag?: number | string; role?: "ksk" | "zsk" | "csk" | string; algorithm?: string; created?: number | string | null; state?: string };
export type DsRecord = { digest_type?: number | string; digest?: string; text?: string; key_tag?: number | string; algorithm?: number | string };
export type ZoneDnssecStatus = { enabled?: boolean; keys?: DnssecKey[]; ds?: DsRecord[]; next_resign?: number | string | null; error?: string | null };
export const fetchZoneDnssec = (zone: string, signal?: AbortSignal) => getJson<ZoneDnssecStatus>(`${zonePath(zone)}/dnssec?${fresh()}`, signal);
export const rolloverZoneKey = (zone: string, role: "zsk" | "ksk") => mutateJson(`${zonePath(zone)}/dnssec/rollover`, { method: "POST", body: { role } });

export const DIGEST_WORDS: Record<string, Bi> = {
  "1": { fa: "SHA-1 (قدیمی)", en: "SHA-1 (old)" },
  "2": { fa: "SHA-256 (پیشنهادی)", en: "SHA-256 (recommended)" },
  "4": { fa: "SHA-384", en: "SHA-384" }
};

export const KEY_STATE_WORDS: Record<string, { tone: "ok" | "warn" | "off" | "info"; label: Bi }> = {
  active: { tone: "ok", label: { fa: "در حال کار", en: "Active" } },
  published: { tone: "info", label: { fa: "منتشر شده، هنوز امضا نمی‌کند", en: "Published, not signing yet" } },
  ready: { tone: "info", label: { fa: "آماده", en: "Ready" } },
  retired: { tone: "off", label: { fa: "بازنشسته", en: "Retired" } },
  removed: { tone: "off", label: { fa: "برداشته شده", en: "Removed" } },
  pending: { tone: "warn", label: { fa: "در انتظار", en: "Pending" } }
};

/** TSIG keys (§2.3). `secret` comes back only once, when the key is made. */
export type TsigKey = { name: string; algorithm?: "hmac-sha256" | "hmac-sha512" | string; secret?: string | null; created_at?: number | string | null };
export const TSIG_ALGORITHMS = ["hmac-sha256", "hmac-sha512"] as const;
export async function fetchTsigKeys(signal?: AbortSignal) {
  return itemsOf<TsigKey>(await getJson(`${dnsBase()}/tsig?${fresh()}`, signal), "keys");
}
export const createTsigKey = (body: { name: string; algorithm: string; secret?: string }) => mutateJson<TsigKey>(`${dnsBase()}/tsig`, { method: "POST", body });
export const deleteTsigKey = (name: string) => mutateJson(`${dnsBase()}/tsig/${encodeURIComponent(name)}`, { method: "DELETE" });

/** `ip`, `ip:port` or `[v6]:port` (for primaries, NOTIFY targets). */
export function isHostPort(value: string): boolean {
  const text = value.trim();
  const v6 = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(text);
  const v4 = /^([0-9.]+)(?::(\d{1,5}))?$/.exec(text);
  const host = v6 ? v6[1] : v4 ? v4[1] : text;
  const port = v6 ? v6[2] : v4 ? v4[2] : undefined;
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) return false;
  const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(host);
  if (ipv4) return true;
  if (!host.includes(":") || /[^0-9a-fA-F:.]/.test(host)) return false;
  try {
    new URL(`http://[${host}]/`);
    return true;
  } catch {
    return false;
  }
}

// ── filtering and client groups (§3) ─────────────────────────────────────────

export type FilterFormat = "hosts" | "domains" | "adblock" | "rpz";
export const FILTER_FORMATS: FilterFormat[] = ["hosts", "domains", "adblock", "rpz"];
export type FilterList = { id: string; name: string; url: string; format: FilterFormat | string; enabled: boolean; update_hours: number };
export type FilterAction = "nxdomain" | "null_ip" | "refuse";
export type FilteringSettings = {
  enabled: boolean;
  lists: FilterList[];
  allow: string[];
  block: string[];
  action: FilterAction | string;
  safe_search: boolean;
};
export const DEFAULT_FILTERING: FilteringSettings = { enabled: false, lists: [], allow: [], block: [], action: "nxdomain", safe_search: false };

export type GroupFiltering = "inherit" | "on" | "off";
export type ClientGroup = {
  id: string;
  name: string;
  networks: string[];
  filtering: GroupFiltering | string;
  lists?: string[];
  upstreams?: string[];
  blocked_services?: string[];
};

export type FilterListStatus = {
  id: string; name?: string; enabled?: boolean; entries?: number | null; updated_at?: number | string | null; next_update_at?: number | string | null;
  updating?: boolean; error?: string | null; error_detail?: string | null;
};
export type FilteringStatus = { enabled?: boolean; lists?: FilterListStatus[]; total_entries?: number | null; blocked_1h?: number | null; memory_bytes?: number | null };
export const fetchFilteringStatus = (signal?: AbortSignal) => getJson<FilteringStatus>(`${dnsBase()}/filtering/status?${fresh()}`, signal);
export const refreshFiltering = () => mutateJson(`${dnsBase()}/filtering/refresh`, { method: "POST", body: {} });
/** docs/41 §0.2: `reason` = list | custom_block | service | allow_list | safe_search | not_listed | filtering_off. */
export type FilterCheck = {
  name?: string;
  blocked?: boolean;
  list_id?: string | null;
  rule?: string | null;
  reason?: string | null;
  service?: string | null;
  group?: string | null;
  rewrite?: string | null;
  filtering?: boolean | null;
  allowed?: boolean;
  source?: string | null;
};
export const checkFiltering = (name: string, client_ip?: string) => mutateJson<FilterCheck>(`${dnsBase()}/filtering/check`, { method: "POST", body: client_ip ? { name, client_ip } : { name } });

export type SuggestedList = { key: string; name: Bi; hint: Bi; list: Omit<FilterList, "name" | "enabled"> };

/** §3.1: suggestions only, off until the person adds them. Free and widely used. */
export const SUGGESTED_LISTS: SuggestedList[] = [
  {
    key: "ads",
    name: { fa: "تبلیغات و ردیاب‌ها", en: "Ads and trackers" },
    hint: { fa: "فهرست رایگان و شناخته‌شده «StevenBlack»؛ بیشتر تبلیغ‌ها و ردیاب‌ها را می‌بندد.", en: "The free, well-known StevenBlack list; blocks most ads and trackers." },
    list: { id: "ads", url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", format: "hosts", update_hours: 24 }
  },
  {
    key: "malware",
    name: { fa: "بدافزار و کلاهبرداری", en: "Malware and scams" },
    hint: { fa: "فهرست رایگان «URLhaus»؛ نشانی‌هایی که بدافزار پخش می‌کنند را می‌بندد.", en: "The free URLhaus list; blocks addresses that spread malware." },
    list: { id: "malware", url: "https://urlhaus.abuse.ch/downloads/hostfile/", format: "hosts", update_hours: 12 }
  }
];

export const FILTER_ACTION_WORDS: Record<FilterAction, { label: Bi; body: Bi }> = {
  nxdomain: { label: { fa: "«چنین نامی نیست»", en: "“No such name”" }, body: { fa: "دستگاه فکر می‌کند این سایت وجود ندارد. پیشنهادی.", en: "The device thinks the site doesn't exist. Recommended." } },
  null_ip: { label: { fa: "نشانی خالی", en: "Empty address" }, body: { fa: "نشانی 0.0.0.0 برمی‌گردد؛ صفحه باز نمی‌شود.", en: "Returns 0.0.0.0; the page doesn't open." } },
  refuse: { label: { fa: "جواب نده", en: "Refuse" }, body: { fa: "پرسش رد می‌شود؛ بعضی برنامه‌ها چند بار دوباره می‌پرسند.", en: "The question is refused; some apps ask again a few times." } }
};

export const FORMAT_WORDS: Record<FilterFormat, Bi> = {
  hosts: { fa: "فایل «hosts»", en: "hosts file" },
  domains: { fa: "یک نام در هر خط", en: "One name per line" },
  adblock: { fa: "قاعده‌های «Adblock»", en: "Adblock rules" },
  rpz: { fa: "منطقه «RPZ»", en: "RPZ zone" }
};

export const GROUP_FILTERING_WORDS: Record<GroupFiltering, Bi> = {
  inherit: { fa: "مثل بقیه", en: "Same as everyone" },
  on: { fa: "همیشه روشن", en: "Always on" },
  off: { fa: "خاموش", en: "Off" }
};

export function newId(base: string, taken: string[]): string {
  const slug = base.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32) || "item";
  let id = slug;
  for (let index = 2; taken.includes(id); index++) id = `${slug}-${index}`;
  return id;
}

/** A name in a block / allow list: `example.com` or `*.example.com`. */
export function isFilterName(value: string): boolean {
  const text = value.trim().toLowerCase().replace(/\.$/, "").replace(/^\*\./, "");
  if (!text || text.length > 253) return false;
  return text.split(".").every((label) => /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/.test(label));
}

// ── backup and restore (§4) ──────────────────────────────────────────────────

/** `GET /api/v1/dns/backup`: downloads the tar.gz the server sends. */
export async function downloadDnsBackup(): Promise<string> {
  const response = await ensureOk(await apiGet(`${dnsBase()}/backup?${fresh()}`));
  const disposition = response.headers.get("content-disposition") ?? "";
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition);
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const filename = match ? decodeURIComponent(match[1]) : `mrk-dns-backup-${stamp}.tar.gz`;
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 2_000);
  return filename;
}

export type RestoreResult = { restored?: boolean | string[] | null; files?: number | null; zones?: number | null; config_version?: number | string; backup_created_at?: number | string | null; restart_required?: boolean; restart_for?: string[] | null };

/**
 * `POST /api/v1/dns/restore`: the same file as the request body (`application/gzip`).
 * The server checks it fully before changing anything; `restore_invalid` (422) says why.
 */
export async function restoreDnsBackup(file: File): Promise<RestoreResult> {
  const response = await apiMutateRaw(`${dnsBase()}/restore?confirmation=RESTORE`, file, "application/gzip");
  const ok = await ensureOk(response);
  const text = await ok.text();
  return (text ? JSON.parse(text) : {}) as RestoreResult;
}

async function apiMutateRaw(path: string, body: Blob, contentType: string): Promise<Response> {
  const send = () => fetch(path, { method: "POST", headers: { Accept: "application/json", "Content-Type": contentType, "X-CSRF-Token": getCsrfToken() }, body, cache: "no-store" });
  let response = await send();
  if (response.status === 403) {
    const code = await response.clone().json().then((payload: { error?: { code?: string } }) => payload.error?.code, () => null);
    if (code === "csrf_failed" && (await refreshCsrf())) response = await send();
  }
  return response;
}

/** Client groups live in the engine settings (`client_groups`, dns:admin to read). */
export async function fetchClientGroups(signal?: AbortSignal): Promise<ClientGroup[]> {
  const settings = await fetchDnsSettings(signal);
  return Array.isArray(settings.client_groups) ? (settings.client_groups as ClientGroup[]) : [];
}
