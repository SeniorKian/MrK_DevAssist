/**
 * DevAssist DNS phase D4 (contract docs/40): finding names from the root, DNSSEC and encrypted DNS.
 * Types, API calls and the plain words used by the settings cards, the «اتصال رمزدار» tab,
 * the test tab (DNSSEC badge + full path) and the log/monitor additions.
 *
 * Like dns.ts, every backend field is optional so an older server (no D4 endpoints, a bare 404)
 * or a partly filled answer never breaks a page. Panel API base: `/api/v1/dns` (docs/40 §5).
 */
import { ApiError, apiMutate, ensureOk, getJson, mutateJson } from "./api";
import type { Language } from "./i18n";
import { fill, type Bi } from "./copy/text";

const BASE = "/api/v1/dns";
const fresh = () => `_=${Date.now()}`;

type Tone = "ok" | "warn" | "error" | "off" | "busy" | "info";

// ── settings sections (docs/40 §2) ───────────────────────────────────────────

export type ResolutionMode = "forward" | "recursive" | "forward_then_recursive";
export type RootHint = { name: string; ipv4?: string; ipv6?: string };
export type ResolutionSettings = {
  mode: ResolutionMode | string;
  qname_minimization: "off" | "relaxed" | "strict" | string;
  ip_versions: "ipv4" | "ipv6" | "both" | string;
  case_randomization: boolean;
  root_hints: RootHint[];
  allow_private_ns: boolean;
  max_referrals: number;
  max_queries_per_resolution: number;
  max_ns_per_zone: number;
  query_timeout_ms: number;
  resolve_timeout_ms: number;
  infra_cache_entries: number;
};

export type DnssecMode = "off" | "validate" | "log_only";
export type NegativeTrustAnchor = { domain: string; reason?: string; expires_at?: string | null };
export type DnssecSettings = {
  mode: DnssecMode | string;
  trust_anchor_auto_update: boolean;
  negative_trust_anchors: NegativeTrustAnchor[];
  auto_insecure_local: boolean;
  aggressive_nsec: boolean;
  nsec3_max_iterations: number;
  bogus_ttl: number;
  sig_skew_seconds: number;
};

export type EncryptedSettings = {
  dot: { enabled: boolean; listen: string[] };
  doq: { enabled: boolean; listen: string[] };
  doh: { enabled: boolean; listen: string[]; tls: boolean; path: string; allow_get: boolean; trusted_proxies: string[] };
  allow: string[] | null;
  max_connections: number;
  max_connections_per_client: number;
  idle_timeout_ms: number;
  max_streams_per_connection: number;
  handshake_timeout_ms: number;
};

export const DEFAULT_RESOLUTION: ResolutionSettings = {
  mode: "forward", qname_minimization: "relaxed", ip_versions: "ipv4", case_randomization: true, root_hints: [], allow_private_ns: false,
  max_referrals: 30, max_queries_per_resolution: 100, max_ns_per_zone: 13, query_timeout_ms: 1500, resolve_timeout_ms: 4000, infra_cache_entries: 10_000
};
export const DEFAULT_DNSSEC: DnssecSettings = {
  mode: "validate", trust_anchor_auto_update: true, negative_trust_anchors: [], auto_insecure_local: true, aggressive_nsec: true,
  nsec3_max_iterations: 150, bogus_ttl: 60, sig_skew_seconds: 3600
};
export const DOH_PUBLIC_LISTEN = ["0.0.0.0:443"];
/** The panel's default for «پشت Traefik» (docs/40 §2.3). */
export const DOH_BEHIND_PROXY_LISTEN = ["127.0.0.1:8053", "172.17.0.1:8053"];
export const DEFAULT_ENCRYPTED: EncryptedSettings = {
  dot: { enabled: false, listen: ["0.0.0.0:853"] },
  doq: { enabled: false, listen: ["0.0.0.0:853"] },
  doh: {
    enabled: false, listen: DOH_PUBLIC_LISTEN, tls: true, path: "/dns-query", allow_get: true,
    trusted_proxies: ["127.0.0.0/8", "::1/128", "172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"]
  },
  allow: null,
  max_connections: 2000, max_connections_per_client: 50, idle_timeout_ms: 30_000, max_streams_per_connection: 100, handshake_timeout_ms: 5000
};

/** Ranges from docs/40 §2 (also used for the inputs' min/max). */
export const RANGES = {
  max_referrals: [1, 64], max_queries_per_resolution: [10, 500], max_ns_per_zone: [1, 32], query_timeout_ms: [200, 10_000],
  resolve_timeout_ms: [1000, 30_000], infra_cache_entries: [100, 1_000_000], root_hints: [1, 26],
  nsec3_max_iterations: [0, 2500], bogus_ttl: [0, 3600], sig_skew_seconds: [0, 86_400], negative_trust_anchors: [0, 500],
  max_connections: [10, 100_000], max_connections_per_client: [1, 10_000], idle_timeout_ms: [1000, 600_000],
  max_streams_per_connection: [1, 1000], handshake_timeout_ms: [500, 30_000]
} as const;

/** Settings PUT may answer `warnings:[{code}]` next to the saved settings (docs/40 §5). */
export type SettingsWarning = { code: string; params?: Record<string, unknown> | null };
export function warningsOf(result: unknown): SettingsWarning[] {
  if (!result || typeof result !== "object") return [];
  const list = (result as { warnings?: unknown }).warnings;
  if (!Array.isArray(list)) return [];
  return list
    .map((item) => (typeof item === "string" ? { code: item } : item && typeof item === "object" && typeof (item as SettingsWarning).code === "string" ? (item as SettingsWarning) : null))
    .filter((item): item is SettingsWarning => item !== null);
}

const WARNING_WORDS: Record<string, Bi> = {
  recursive_needs_outbound_53: {
    fa: "برای پیدا کردن مستقیم نشانی‌ها، سرور باید بتواند به پورت ۵۳ سرورهای اینترنت وصل شود (UDP و TCP). اگر دیوار آتش یا شرکت میزبان این را بسته، پرسش‌ها جواب نمی‌گیرند.",
    en: "To find addresses directly, the server must be able to reach port 53 on internet servers (UDP and TCP). If a firewall or your host blocks it, questions won't get answers."
  },
  doh_public_needs_token: {
    fa: "DNS رمزدار روی اینترنت باز است، ولی فقط شبکه‌های خودتان اجازه دارند. برای گوشی‌ای که بیرون از این شبکه‌هاست، یک کلید دسترسی (token) در «اتصال رمزدار» بسازید.",
    en: "Encrypted DNS is open to the internet, but only your own networks may ask. For a phone outside them, make an access token under Encrypted connection."
  },
  self_signed_certificate: {
    fa: "گواهی فعلی خودامضاست. بیشتر گوشی‌ها و مرورگرها به آن اعتماد نمی‌کنند؛ برای کار بی‌دردسر، از «از دامنه با Traefik» استفاده کنید یا گواهی معتبر بارگذاری کنید.",
    en: "The current certificate is self-signed. Most phones and browsers won't trust it; for a smooth setup use “Via a domain with Traefik” or upload a trusted certificate."
  }
};
export function warningText(language: Language, warning: SettingsWarning): string {
  return WARNING_WORDS[warning.code]?.[language] ?? (language === "fa" ? "تنظیمات ذخیره شد، ولی یک نکته هست که بهتر است بررسی کنید." : "The settings were saved, but there is something worth checking.");
}

// ── status additions (docs/40 §3 GET /v1/status) ─────────────────────────────

export type TrustAnchorState = "valid" | "pending" | "revoked" | "missing";
export type TrustAnchor = { key_tag: number; algorithm?: number; state: TrustAnchorState | string; since?: string | number | null; builtin?: boolean };
export type DnssecCounters = { secure?: number; insecure?: number; bogus?: number; indeterminate?: number };
export type DnsD4Status = {
  resolution?: { mode?: string; root_priming?: { ok?: boolean; at?: string | number | null; servers_reachable?: number; error?: string | null } | null; infra_cache_entries?: number } | null;
  dnssec?: { mode?: string; trust_anchors?: TrustAnchor[]; trust_anchor_updated_at?: string | number | null; trust_anchor_error?: string | null; counters?: DnssecCounters } | null;
  encrypted?: {
    connections?: { dot?: number; doh?: number; doq?: number } | null;
    certificate?: { present?: boolean; not_after?: string | number | null; self_signed?: boolean; days_left?: number | null } | null;
  } | null;
};

// ── DNSSEC (GET dnssec, POST dnssec/refresh) ─────────────────────────────────

export type DnssecView = {
  mode?: string;
  trust_anchors?: TrustAnchor[];
  updated_at?: string | number | null;
  error?: string | null;
  negative_trust_anchors?: NegativeTrustAnchor[];
  counters?: DnssecCounters;
};
export const fetchDnssec = (signal?: AbortSignal) => getJson<DnssecView>(`${BASE}/dnssec?${fresh()}`, signal);
export const refreshDnssec = () => mutateJson<DnssecView>(`${BASE}/dnssec/refresh`, { method: "POST", body: {} });

export const ANCHOR_STATE_WORDS: Record<string, { tone: Tone; label: Bi }> = {
  valid: { tone: "ok", label: { fa: "معتبر", en: "Valid" } },
  pending: { tone: "info", label: { fa: "در انتظار (۳۰ روز)", en: "Waiting (30 days)" } },
  revoked: { tone: "off", label: { fa: "باطل‌شده", en: "Revoked" } },
  missing: { tone: "warn", label: { fa: "دیگر دیده نمی‌شود", en: "No longer seen" } }
};

/** One sentence about the root trust anchor for the DNSSEC card. */
export function anchorSentence(language: Language, view: DnssecView | null): { tone: Tone; text: string } {
  const fa = language === "fa";
  if (!view) return { tone: "off", text: fa ? "در حال بررسی…" : "Checking…" };
  const valid = (view.trust_anchors ?? []).filter((item) => item.state === "valid").length;
  if (!valid) {
    return {
      tone: "error",
      text: fa
        ? "کلید اعتماد ریشه اینترنت پیدا نشد؛ بررسی امضا نمی‌تواند درست کار کند. «به‌روزرسانی» را بزنید."
        : "No valid root trust key was found, so signature checks can't work properly. Press Update."
    };
  }
  if (view.error) {
    return {
      tone: "warn",
      text: fa
        ? "کلید اعتماد ریشه سالم است، ولی آخرین به‌روزرسانی خودکار انجام نشد. DevAssist همان کلید قبلی را نگه داشته و بعداً دوباره امتحان می‌کند."
        : "The root trust key is fine, but the last automatic update didn't work. DevAssist keeps the current key and will try again later."
    };
  }
  return {
    tone: "ok",
    text: fa ? "کلید اعتماد ریشه اینترنت سالم است و خودکار به‌روز می‌ماند." : "The internet's root trust key is fine and stays up to date by itself."
  };
}

// ── resolve with DNSSEC / trace (POST resolve) ───────────────────────────────

export type DnssecStatus = "secure" | "insecure" | "bogus" | "indeterminate";
export type Ede = { code: number; text?: string | null };
export type TraceStep = {
  step?: number;
  zone?: string;
  server?: string;
  server_name?: string | null;
  qname?: string;
  qtype?: string;
  rcode?: string | number;
  rtt_ms?: number | null;
  referral?: string[] | null;
  dnssec?: DnssecStatus | string | null;
  error?: string | null;
};
export type ResolveExtras = {
  dnssec?: { status?: DnssecStatus | string; reason?: string | null } | null;
  ede?: Ede[] | null;
  trace?: TraceStep[] | null;
};

export const DNSSEC_STATUS_WORDS: Record<string, { tone: Tone; label: Bi; body: Bi }> = {
  secure: {
    tone: "ok",
    label: { fa: "امضا درست است", en: "Signature checks out" },
    body: { fa: "صاحب این دامنه جواب را امضا کرده و امضا درست بود؛ یعنی جواب دست‌کاری نشده.", en: "The domain's owner signed this answer and the signature was right, so it wasn't tampered with." }
  },
  insecure: {
    tone: "info",
    label: { fa: "بدون امضا", en: "Not signed" },
    body: { fa: "این دامنه امضای امنیتی ندارد. جواب عادی است، فقط نمی‌شود ثابت کرد دست‌کاری نشده.", en: "This domain has no security signature. The answer is normal; it just can't be proven untouched." }
  },
  bogus: {
    tone: "error",
    label: { fa: "امضا خراب است", en: "Signature is broken" },
    body: { fa: "امضای این جواب درست نبود؛ ممکن است جعلی یا دست‌کاری‌شده باشد. DevAssist برای امنیت جواب را نداد.", en: "This answer's signature didn't check out; it may be fake or tampered with. DevAssist held it back to keep you safe." }
  },
  indeterminate: {
    tone: "off",
    label: { fa: "بررسی نشد", en: "Couldn't check" },
    body: { fa: "DevAssist نتوانست امضا را بررسی کند (مثلاً DNS بیرونی امضاها را حذف می‌کند). جواب مثل «بدون امضا» داده شد.", en: "DevAssist couldn't check the signature (for example, the outside DNS strips signatures). The answer was given as “not signed”." }
  }
};

/** Plain reason for `dnssec.reason` (docs/40 §0.1). */
const DNSSEC_REASON_WORDS: Record<string, Bi> = {
  validation_off: { fa: "بررسی امضا در تنظیمات خاموش است.", en: "Signature checking is off in settings." },
  negative_trust_anchor: { fa: "این دامنه در فهرست استثناهای بررسی امضا است.", en: "This domain is on the signature-check exceptions list." },
  local_zone: { fa: "این نام مال شبکه یا دامنه‌های خودتان است و بررسی امضا لازم ندارد.", en: "This name belongs to your own network or domains and needs no signature check." },
  unsigned_zone: { fa: "صاحب این دامنه امضای امنیتی نگذاشته است.", en: "The domain's owner hasn't set up a security signature." },
  rrsigs_missing: { fa: "امضا باید همراه جواب می‌آمد ولی نیامد.", en: "A signature should have come with the answer, but didn't." },
  signature_expired: { fa: "تاریخ امضا گذشته است؛ صاحب دامنه باید امضا را تازه کند (یا ساعت سرور اشتباه است).", en: "The signature has expired; the domain's owner must renew it (or the server's clock is wrong)." },
  signature_not_yet_valid: { fa: "امضا هنوز شروع نشده؛ احتمالاً ساعت سرور یا سرور آن دامنه اشتباه است.", en: "The signature isn't valid yet; the server's clock or the domain's server is probably wrong." },
  signature_invalid: { fa: "امضا با جواب جور درنمی‌آید؛ ممکن است جواب دست‌کاری شده باشد.", en: "The signature doesn't match the answer; the answer may have been tampered with." },
  dnskey_missing: { fa: "کلید امضای دامنه پیدا نشد.", en: "The domain's signing key couldn't be found." },
  ds_mismatch: { fa: "کلید دامنه با چیزی که دامنه بالاتر ثبت کرده جور نیست؛ معمولاً اشتباه صاحب دامنه است.", en: "The domain's key doesn't match what the parent domain has on record; usually the owner's mistake." },
  denial_proof_failed: { fa: "سرور گفت «این نام نیست» ولی نتوانست آن را با امضا ثابت کند.", en: "The server said “no such name” but couldn't prove it with a signature." },
  unsupported_algorithm: { fa: "این دامنه از روش امضایی استفاده می‌کند که DevAssist نمی‌شناسد؛ مثل «بدون امضا» با آن رفتار شد.", en: "This domain uses a signing method DevAssist doesn't know; it was treated as not signed." },
  unsupported_digest: { fa: "این دامنه از روش امضایی استفاده می‌کند که DevAssist نمی‌شناسد؛ مثل «بدون امضا» با آن رفتار شد.", en: "This domain uses a signing method DevAssist doesn't know; it was treated as not signed." },
  nsec3_iterations: { fa: "امضای این دامنه بیش از حد سنگین است؛ برای ایمنی سرور مثل «بدون امضا» با آن رفتار شد.", en: "This domain's signature is too heavy to check; to protect the server it was treated as not signed." },
  nsec3_opt_out: { fa: "این بخش از دامنه عمداً بدون امضا مانده است.", en: "This part of the domain is deliberately left unsigned." },
  no_reachable_authority: { fa: "سرورهای این دامنه جواب ندادند، پس امضا بررسی نشد.", en: "The domain's servers didn't answer, so the signature couldn't be checked." },
  trust_anchor_unavailable: { fa: "کلید اعتماد ریشه در دسترس نبود (شاید DNS بیرونی امضاها را حذف می‌کند).", en: "The root trust key wasn't available (the outside DNS may strip signatures)." },
  signer_mismatch: { fa: "امضاکننده با صاحب واقعی دامنه یکی نیست.", en: "The signer isn't the domain's real owner." },
  validation_budget: { fa: "بررسی این امضا بیش از حد کار می‌برد و برای ایمنی سرور نیمه‌کاره ماند.", en: "Checking this signature took too much work and was stopped to protect the server." }
};

/** Plain words for EDE codes (RFC 8914) when no `dnssec.reason` came. */
const EDE_WORDS: Record<number, Bi> = {
  1: DNSSEC_REASON_WORDS.unsupported_algorithm,
  2: DNSSEC_REASON_WORDS.unsupported_digest,
  3: { fa: "اینترنت در دسترس نبود و جواب ذخیره‌شده قدیمی داده شد.", en: "The internet wasn't reachable, so an older stored answer was given." },
  6: { fa: "امضای جواب درست نبود؛ ممکن است جعلی باشد.", en: "The answer's signature didn't check out; it may be fake." },
  7: DNSSEC_REASON_WORDS.signature_expired,
  8: DNSSEC_REASON_WORDS.signature_not_yet_valid,
  9: DNSSEC_REASON_WORDS.dnskey_missing,
  10: DNSSEC_REASON_WORDS.rrsigs_missing,
  15: { fa: "این نام به‌خاطر یک محدودیت در «پایش» مسدود است.", en: "This name is blocked by a limit under Monitor." },
  18: { fa: "این نشانی اجازه پرسیدن ندارد.", en: "This address isn't allowed to ask." },
  22: DNSSEC_REASON_WORDS.no_reachable_authority
};

export function dnssecReasonText(language: Language, reason: string | null | undefined, ede: Ede[] | null | undefined): string {
  if (reason && DNSSEC_REASON_WORDS[reason]) return DNSSEC_REASON_WORDS[reason][language];
  for (const item of ede ?? []) if (EDE_WORDS[item.code]) return EDE_WORDS[item.code][language];
  return "";
}

export function edeText(language: Language, item: Ede): string {
  return EDE_WORDS[item.code]?.[language] ?? (language === "fa" ? "توضیح دیگری از سرور آمد." : "The server sent another note.");
}

export type TraceLevel = "root" | "tld" | "domain" | "validator" | "forwarder";

/** Where a step sits: «ریشه» → «پسوند» → «دامنه», or the signature check / a forwarder. */
export function traceLevel(step: TraceStep, forwardMode: boolean): TraceLevel {
  if (step.server === "validator") return "validator";
  const zone = (step.zone ?? "").replace(/\.$/, "");
  if (!zone) return forwardMode ? "forwarder" : "root";
  return zone.includes(".") ? "domain" : "tld";
}

export const TRACE_LEVEL_WORDS: Record<TraceLevel, Bi> = {
  root: { fa: "ریشه اینترنت", en: "Internet root" },
  tld: { fa: "پسوند", en: "Ending" },
  domain: { fa: "دامنه", en: "Domain" },
  validator: { fa: "بررسی امضا", en: "Signature check" },
  forwarder: { fa: "DNS بیرونی", en: "Outside DNS" }
};

/** One sentence for what came back at a step. */
export function traceOutcome(language: Language, step: TraceStep): string {
  const fa = language === "fa";
  const names = (step.referral ?? []).map((item) => item.replace(/\.$/, ""));
  if (step.error) return fa ? "این قدم جواب نگرفت." : "This step got no answer.";
  if (names.length) {
    const list = names.slice(0, 3).join(fa ? "، " : ", ") + (names.length > 3 ? (fa ? " و…" : ", …") : "");
    return fill(fa ? "گفت: «برو از این‌ها بپرس»: {list}" : "It said: “ask these instead”: {list}", { list }, language);
  }
  const rcode = typeof step.rcode === "number" ? ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"][step.rcode] ?? String(step.rcode) : String(step.rcode ?? "NOERROR").toUpperCase();
  if (rcode === "NXDOMAIN") return fa ? "گفت: «چنین نامی وجود ندارد»." : "It said: “no such name”.";
  if (rcode === "NOERROR" || !rcode) return fa ? "جواب داد." : "It answered.";
  if (rcode === "REFUSED") return fa ? "جواب نداد (رد کرد)." : "It refused to answer.";
  return fa ? "نتوانست جواب بدهد." : "It couldn't answer.";
}

// ── TLS certificate (GET/PUT/DELETE tls, POST tls/self-signed) ────────────────

export type TlsInfo = {
  present?: boolean;
  source?: "uploaded" | "self_signed" | null | string;
  subject?: string | null;
  names?: string[] | null;
  issuer?: string | null;
  not_before?: string | number | null;
  not_after?: string | number | null;
  fingerprint_sha256?: string | null;
  self_signed?: boolean;
  key_type?: string | null;
};
export const fetchTls = (signal?: AbortSignal) => getJson<TlsInfo>(`${BASE}/tls?${fresh()}`, signal);
export const uploadTls = (body: { cert_pem: string; key_pem: string }) => mutateJson<TlsInfo>(`${BASE}/tls`, { method: "PUT", body });
export const createSelfSigned = (names: string[]) => mutateJson<TlsInfo>(`${BASE}/tls/self-signed`, { method: "POST", body: { names } });
export const deleteTls = () => mutateJson(`${BASE}/tls`, { method: "DELETE" });

export function toMillis(value: string | number | null | undefined): number | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") return value < 1e12 ? value * 1000 : value;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}
export function daysLeft(notAfter: string | number | null | undefined): number | null {
  const ms = toMillis(notAfter);
  return ms === null ? null : Math.floor((ms - Date.now()) / 86_400_000);
}

const TLS_REASON_WORDS: Record<string, Bi> = {
  bad_pem: { fa: "فایل گواهی یا کلید خوانده نشد. باید متنی باشد که با «-----BEGIN» شروع می‌شود.", en: "The certificate or key couldn't be read. It must be text starting with “-----BEGIN”." },
  key_mismatch: { fa: "این کلید مال این گواهی نیست. کلید همان گواهی را بگذارید.", en: "This key doesn't belong to this certificate. Use the certificate's own key." },
  expired: { fa: "تاریخ این گواهی گذشته است. یک گواهی تازه بگیرید.", en: "This certificate has expired. Get a fresh one." },
  weak_key: { fa: "کلید این گواهی ضعیف است. از کلیدی قوی‌تر استفاده کنید (مثلاً RSA دست‌کم ۲۰۴۸ بیتی).", en: "This certificate's key is too weak. Use a stronger one (for example RSA of at least 2048 bits)." },
  no_names: { fa: "این گواهی هیچ نامی ندارد؛ گواهی‌ای بگیرید که نام دامنه داشته باشد.", en: "This certificate has no names; get one that lists your domain." },
  too_large: { fa: "فایل خیلی بزرگ است (بیشتر از ۶۴ کیلوبایت).", en: "The file is too large (over 64 KB)." }
};
/** Plain sentence for a `tls_invalid` error's reason (error.reason or the first field reason). */
export function tlsErrorText(language: Language, error: unknown): string | null {
  if (!(error instanceof ApiError)) return null;
  const fromExtra = typeof error.extra.reason_code === "string" ? error.extra.reason_code : "";
  const reason = fromExtra || error.fields[0]?.reason_code || error.reason || "";
  return TLS_REASON_WORDS[reason]?.[language] ?? null;
}

// ── DoH tokens ───────────────────────────────────────────────────────────────

export type DohToken = { id: string; name: string; qps?: number | null; created_at?: string | number | null; last_used_at?: string | number | null; queries?: number | null };
export type DohTokenCreated = DohToken & { token: string; urls?: { doh?: string | null } | null };
export async function fetchDohTokens(signal?: AbortSignal): Promise<DohToken[]> {
  const payload = await getJson<{ items?: DohToken[] } | DohToken[]>(`${BASE}/doh/tokens?${fresh()}`, signal);
  if (Array.isArray(payload)) return payload;
  return Array.isArray(payload?.items) ? payload.items : [];
}
export const createDohToken = (body: { name: string; qps?: number }) => mutateJson<DohTokenCreated>(`${BASE}/doh/tokens`, { method: "POST", body });
export const patchDohToken = (id: string, body: { name?: string; qps?: number }) => mutateJson<DohToken>(`${BASE}/doh/tokens/${encodeURIComponent(id)}`, { method: "PATCH", body });
export const deleteDohToken = (id: string) => mutateJson(`${BASE}/doh/tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
export const DOH_TOKEN_DEFAULT_QPS = 50;
export const DOH_TOKEN_MAX = 200;

// ── device guides (GET encrypted/clients, POST encrypted/apple-profile) ──────

export type GuideId = "android" | "ios" | "windows" | "macos" | "linux" | "firefox" | "chrome";
export const GUIDE_IDS: GuideId[] = ["android", "ios", "macos", "windows", "firefox", "chrome", "linux"];
export type EncryptedClients = {
  doh_url?: string | null;
  dot_name?: string | null;
  doq_name?: string | null;
  ip?: string | null;
  certificate?: { trusted?: boolean; present?: boolean; self_signed?: boolean } | null;
  guides?: Array<{ id: GuideId | string; available?: boolean; reason?: string | null }> | null;
};
export const fetchEncryptedClients = (signal?: AbortSignal) => getJson<EncryptedClients>(`${BASE}/encrypted/clients?${fresh()}`, signal);

/** Download the unsigned Apple profile (`.mobileconfig`). */
export async function downloadAppleProfile(body: { doh_url?: string; dot_name?: string; name?: string }) {
  const response = await ensureOk(await apiMutate(`${BASE}/encrypted/apple-profile`, { method: "POST", body }));
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "mrk-dns.mobileconfig";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export const GUIDE_WORDS: Record<GuideId, { title: Bi; needs: "dot" | "doh" | "profile" | "linux" }> = {
  android: { title: { fa: "گوشی Android", en: "Android phone" }, needs: "dot" },
  ios: { title: { fa: "iPhone و iPad", en: "iPhone and iPad" }, needs: "profile" },
  macos: { title: { fa: "Mac", en: "Mac" }, needs: "profile" },
  windows: { title: { fa: "Windows 11", en: "Windows 11" }, needs: "doh" },
  firefox: { title: { fa: "مرورگر Firefox", en: "Firefox browser" }, needs: "doh" },
  chrome: { title: { fa: "مرورگر Chrome یا Edge", en: "Chrome or Edge browser" }, needs: "doh" },
  linux: { title: { fa: "Linux", en: "Linux" }, needs: "linux" }
};

/** Short steps per device; {dot}, {doh}, {ip} come from GET encrypted/clients. */
export const GUIDE_STEPS: Record<GuideId, Bi[]> = {
  android: [
    { fa: "تنظیمات گوشی را باز کنید و به «شبکه و اینترنت» بروید.", en: "Open the phone's Settings and go to “Network & internet”." },
    { fa: "«DNS خصوصی» را بزنید و «نام میزبان ارائه‌دهنده DNS خصوصی» را انتخاب کنید.", en: "Tap “Private DNS” and choose “Private DNS provider hostname”." },
    { fa: "این نام را بنویسید و «ذخیره» را بزنید: {dot}", en: "Type this name and tap Save: {dot}" }
  ],
  ios: [
    { fa: "روی همین گوشی دکمه «دریافت پروفایل» را بزنید.", en: "On this phone, tap “Get the profile”." },
    { fa: "تنظیمات را باز کنید؛ بالای صفحه «پروفایل دانلود شد» را بزنید و «نصب» کنید.", en: "Open Settings; tap “Profile Downloaded” at the top and Install it." },
    { fa: "در «عمومی › VPN و مدیریت دستگاه › DNS» مطمئن شوید DevAssist انتخاب شده است.", en: "Under “General › VPN & Device Management › DNS”, make sure DevAssist is selected." }
  ],
  macos: [
    { fa: "دکمه «دریافت پروفایل» را بزنید و فایل را باز کنید.", en: "Press “Get the profile” and open the file." },
    { fa: "در «تنظیمات سیستم › حریم خصوصی و امنیت › پروفایل‌ها» آن را نصب کنید.", en: "Install it under “System Settings › Privacy & Security › Profiles”." }
  ],
  windows: [
    { fa: "«تنظیمات › شبکه و اینترنت» را باز کنید و Wi-Fi یا Ethernet خودتان را بزنید.", en: "Open “Settings › Network & internet” and pick your Wi-Fi or Ethernet." },
    { fa: "کنار «تخصیص سرور DNS» دکمه «ویرایش» را بزنید و «دستی» را انتخاب کنید.", en: "Next to “DNS server assignment”, press Edit and choose Manual." },
    { fa: "IPv4 را روشن کنید، این نشانی را بنویسید: {ip}", en: "Turn on IPv4 and type this address: {ip}" },
    { fa: "«DNS روی HTTPS» را «روشن (الگوی دستی)» کنید و این نشانی را بنویسید: {doh}", en: "Set “DNS over HTTPS” to “On (manual template)” and type: {doh}" }
  ],
  firefox: [
    { fa: "در Firefox به «تنظیمات › حریم خصوصی و امنیت» بروید و تا «DNS روی HTTPS» پایین بیایید.", en: "In Firefox go to “Settings › Privacy & Security” and scroll to “DNS over HTTPS”." },
    { fa: "«بیشترین محافظت» را انتخاب کنید و ارائه‌دهنده را «سفارشی» بگذارید.", en: "Choose “Max Protection” and set the provider to Custom." },
    { fa: "این نشانی را بنویسید: {doh}", en: "Type this address: {doh}" }
  ],
  chrome: [
    { fa: "در مرورگر به «تنظیمات › حریم خصوصی و امنیت › امنیت» بروید.", en: "In the browser go to “Settings › Privacy and security › Security”." },
    { fa: "«استفاده از DNS امن» را روشن کنید و «سفارشی» را انتخاب کنید.", en: "Turn on “Use secure DNS” and choose Custom." },
    { fa: "این نشانی را بنویسید: {doh}", en: "Type this address: {doh}" }
  ],
  linux: [
    { fa: "این دستور را روی رایانه Linux اجرا کنید (برای سیستم‌هایی که «systemd-resolved» دارند، مثل Ubuntu).", en: "Run this command on the Linux computer (for systems with systemd-resolved, like Ubuntu)." },
    { fa: "با «resolvectl status» ببینید که «DNSOverTLS» روشن است.", en: "Check with “resolvectl status” that DNSOverTLS is on." }
  ]
};

/** The systemd-resolved drop-in for the Linux guide. */
export function linuxCommand(ip: string, dotName: string): string {
  return [
    "sudo mkdir -p /etc/systemd/resolved.conf.d",
    `printf '[Resolve]\\nDNS=${ip}#${dotName}\\nDNSOverTLS=yes\\n' | sudo tee /etc/systemd/resolved.conf.d/mrk-dns.conf`,
    "sudo systemctl restart systemd-resolved"
  ].join("\n");
}

const GUIDE_REASON_WORDS: Record<string, Bi> = {
  dot_disabled: { fa: "اول «رمزدار با TLS» را در بالا روشن کنید.", en: "Turn on “Encrypted with TLS” above first." },
  doh_disabled: { fa: "اول «رمزدار با HTTPS» را در بالا روشن کنید.", en: "Turn on “Encrypted with HTTPS” above first." },
  no_name: { fa: "برای این دستگاه یک نام دامنه لازم است؛ از «از دامنه با Traefik» یک دامنه وصل کنید.", en: "This device needs a domain name; connect one via “Via a domain with Traefik”." },
  no_domain: { fa: "برای این دستگاه یک نام دامنه لازم است؛ از «از دامنه با Traefik» یک دامنه وصل کنید.", en: "This device needs a domain name; connect one via “Via a domain with Traefik”." },
  certificate_untrusted: { fa: "این دستگاه به گواهی خودامضا اعتماد نمی‌کند؛ گواهی معتبر لازم است.", en: "This device doesn't trust a self-signed certificate; a trusted one is needed." },
  no_certificate: { fa: "اول در کارت «گواهی» یک گواهی بسازید یا بارگذاری کنید.", en: "First make or upload a certificate in the Certificate card." },
  disabled: { fa: "اول اتصال رمزدار لازم را در بالا روشن کنید.", en: "Turn on the needed encrypted connection above first." },
  encrypted_disabled: { fa: "هنوز هیچ اتصال رمزداری روشن نیست؛ یکی را در بالا روشن کنید.", en: "No encrypted connection is on yet; turn one on above." },
  no_hostname: { fa: "برای این دستگاه یک نام دامنه لازم است؛ از «از دامنه با Traefik» یک دامنه وصل کنید.", en: "This device needs a domain name; connect one via “Via a domain with Traefik”." },
  no_doh_url: { fa: "هنوز نشانی رمزدار با HTTPS آماده نیست؛ اول آن را روشن کنید و یک دامنه وصل کنید.", en: "The HTTPS address isn't ready yet; turn it on and connect a domain first." },
  no_ip: { fa: "نشانی IP سرور پیدا نشد؛ از «راه‌اندازی» وضعیت سرور را بررسی کنید.", en: "The server's IP address wasn't found; check the server in Setup." }
};
export function guideReason(language: Language, reason: string | null | undefined): string {
  return (reason && GUIDE_REASON_WORDS[reason]?.[language]) || (language === "fa" ? "این راهنما هنوز آماده نیست؛ تنظیمات بالا را کامل کنید." : "This guide isn't ready yet; finish the settings above.");
}
