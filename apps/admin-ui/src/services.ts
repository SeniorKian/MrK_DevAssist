/**
 * «سرویس‌های من» (docs/35): types, API calls, a small shared store for `GET /api/v1/services`,
 * and the plain words for service states, routing modes and domain problems.
 *
 * The store is shared so other pages (connection commands in clients.ts, Home) can use each
 * service's `public_url` without fetching again. Every field from the backend is treated as
 * optional so an older server (no services API, or fewer fields) never breaks a page.
 */
import { useEffect, useSyncExternalStore } from "react";
import { getJson, mutateJson } from "./api";
import type { Language } from "./i18n";
import { formatAbsolute } from "./kit/formatters";
import { fill, type Bi } from "./copy/text";

// ── types ────────────────────────────────────────────────────────────────────

export type ServiceId = "panel" | "npm" | "pypi" | "s3" | "agent" | "firewall" | string;
export type ServiceState = "running" | "stopped" | "starting" | "degraded" | "not_installed" | "disabled" | string;
export type ServiceAction = "start" | "stop" | "restart";
export type RoutingMode = "dokploy_api" | "traefik_file" | "manual";
export type RoutingChoice = RoutingMode | "auto";

export type DomainProblemCode =
  | "dns_missing" | "dns_wrong_ip" | "tls_missing" | "tls_expiring" | "tls_invalid" | "unreachable" | "wrong_service" | string;

export type DomainHealth = {
  dns?: { ok?: boolean | null; addresses?: string[] | null; expected?: string[] | null } | null;
  tls?: { ok?: boolean | null; expires_at?: number | string | null; issuer?: string | null } | null;
  reach?: { ok?: boolean | null; status_code?: number | null; matched_service?: string | boolean | null } | null;
  checked_at?: number | string | null;
  problem_code?: DomainProblemCode | null;
  /** Some servers send a one-word summary instead of the full object. */
  state?: string | null;
};

/** A domain as listed inside a service (`GET /api/v1/services`). `health` may be the full object or a word. */
export type ServiceDomainRef = {
  id: string;
  host: string;
  primary?: boolean;
  https?: boolean;
  health?: DomainHealth | string | null;
};

export type ServiceUsage = {
  disk_bytes?: number | null;
  items?: number | null;
  last_activity_at?: number | string | null;
  requests_24h?: number | null;
};

export type ServiceInfo = {
  id: ServiceId;
  name_fa?: string;
  name_en?: string;
  description_fa?: string;
  description_en?: string;
  state: ServiceState;
  reason_code?: string | null;
  controllable?: boolean;
  actions?: string[];
  internal_port?: number | null;
  usage?: ServiceUsage | null;
  domains?: ServiceDomainRef[];
  public_url?: string | null;
  manage_route?: string | null;
  /** Set while the panel is bringing a crashed service back (state "crashed"). */
  recovery?: ServiceRecovery | null;
};

export type ServiceRecovery = {
  since?: number | null;
  attempts?: number | null;
  next_retry_at?: number | null;
  last_attempt_at?: number | null;
  programs?: string[];
  last_error?: string | null;
};

export type RoutingDetected = {
  inside_dokploy?: boolean | null;
  dokploy_connected?: boolean | null;
  dokploy_project?: string | null;
  dokploy_service?: string | null;
  traefik_dir_available?: boolean | null;
  on_dokploy_network?: boolean | null;
  server_ips?: string[] | null;
};

export type RoutingSummary = { mode?: RoutingChoice | string | null; effective_mode?: RoutingMode | string | null; detected?: RoutingDetected | null };

export type ServicesPayload = { items: ServiceInfo[]; routing?: RoutingSummary | null };

export type DomainRecord = {
  id: string;
  service_id: ServiceId;
  host: string;
  primary?: boolean;
  https?: boolean;
  mode?: RoutingMode | string | null;
  created_at?: number | string | null;
  dokploy_domain_id?: string | null;
  health?: DomainHealth | null;
};

export type ManualInstructions = {
  steps_fa?: string[] | null;
  steps_en?: string[] | null;
  dokploy?: { project?: string | null; service?: string | null; port?: number | null; host?: string | null } | null;
};

export type CreateDomainResult = {
  domain?: DomainRecord | null;
  applied?: { mode?: RoutingMode | string | null; ok?: boolean | null; error_code?: string | null } | null;
  instructions?: ManualInstructions | null;
};

/** One copyable guidance snippet from `GET /api/v1/domains/routing`. */
export type RoutingSnippet = { key: string; title?: Bi | null; hint?: Bi | null; content: string };

export type RoutingInfo = RoutingSummary & {
  available_modes?: string[] | null;
  snippets: RoutingSnippet[];
};

// ── API ──────────────────────────────────────────────────────────────────────

export const SERVICE_ACTIONS: ServiceAction[] = ["start", "restart", "stop"];

export async function fetchServices(signal?: AbortSignal): Promise<ServicesPayload> {
  const payload = await getJson<ServicesPayload>(`/api/v1/services?_=${Date.now()}`, signal);
  const data = { items: Array.isArray(payload?.items) ? payload.items : [], routing: payload?.routing ?? null };
  setServicesState({ data, loadedAt: Date.now() });
  return data;
}

export async function fetchDomains(signal?: AbortSignal): Promise<DomainRecord[]> {
  const payload = await getJson<{ items?: DomainRecord[] }>(`/api/v1/domains?_=${Date.now()}`, signal);
  return Array.isArray(payload?.items) ? payload.items : [];
}

/**
 * The token sent with a confirmed action. The user types the service's name; the server gets the
 * service id (docs/35 §3: `confirmation?`).
 */
export function serviceActionConfirmation(service: Pick<ServiceInfo, "id">): string {
  return String(service.id);
}

export function runServiceAction(service: ServiceInfo, action: ServiceAction, confirmed: boolean) {
  const body: Record<string, unknown> = { action };
  if (confirmed) body.confirmation = serviceActionConfirmation(service);
  return mutateJson(`/api/v1/services/${encodeURIComponent(String(service.id))}/actions`, { method: "POST", body });
}

export function createDomain(body: { service_id: string; host: string; https: boolean; primary?: boolean; mode: RoutingChoice }) {
  return mutateJson<CreateDomainResult>("/api/v1/domains", { method: "POST", body });
}

export function updateDomain(id: string, body: { primary?: boolean; https?: boolean }) {
  return mutateJson<DomainRecord | { domain?: DomainRecord }>(`/api/v1/domains/${encodeURIComponent(id)}`, { method: "PATCH", body });
}

export function deleteDomain(id: string, host: string) {
  return mutateJson(`/api/v1/domains/${encodeURIComponent(id)}`, { method: "DELETE", body: { confirmation: host } });
}

export function verifyDomain(id: string) {
  return mutateJson<DomainRecord | { domain?: DomainRecord; health?: DomainHealth }>(`/api/v1/domains/${encodeURIComponent(id)}/verify`, { method: "POST" });
}

export function setRoutingMode(mode: RoutingChoice) {
  return mutateJson("/api/v1/domains/routing", { method: "PUT", body: { mode } });
}

function asBi(fa: unknown, en: unknown): Bi | null {
  const faText = typeof fa === "string" ? fa : "";
  const enText = typeof en === "string" ? en : "";
  if (!faText && !enText) return null;
  return { fa: faText || enText, en: enText || faText };
}

/**
 * `GET /api/v1/domains/routing`. The guidance block may come as a list of snippets
 * (`[{key|id, title_fa, title_en, content|snippet|text}]`) or as a map (`{key: "text"}` or
 * `{key: {title_fa, content}}`); both are normalised to `RoutingSnippet[]`.
 */
export async function fetchRouting(signal?: AbortSignal): Promise<RoutingInfo> {
  const raw = await getJson<Record<string, unknown>>(`/api/v1/domains/routing?_=${Date.now()}`, signal);
  const snippets: RoutingSnippet[] = [];
  const pushSnippet = (key: string, value: unknown) => {
    if (typeof value === "string") {
      if (value.trim()) snippets.push({ key, content: value });
      return;
    }
    if (!value || typeof value !== "object") return;
    const item = value as Record<string, unknown>;
    const content = [item.content, item.snippet, item.text, item.yaml, item.value].find((candidate) => typeof candidate === "string") as string | undefined;
    if (!content?.trim()) return;
    snippets.push({
      key: String(item.key ?? item.id ?? key),
      title: asBi(item.title_fa, item.title_en),
      hint: asBi(item.description_fa ?? item.hint_fa, item.description_en ?? item.hint_en),
      content
    });
  };
  const guidance = raw.guidance ?? raw.snippets ?? raw.guides;
  if (Array.isArray(guidance)) guidance.forEach((item, index) => pushSnippet(`snippet_${index}`, item));
  else if (guidance && typeof guidance === "object") for (const [key, value] of Object.entries(guidance)) pushSnippet(key, value);
  return {
    mode: (raw.mode as string | null | undefined) ?? null,
    effective_mode: (raw.effective_mode as string | null | undefined) ?? null,
    detected: (raw.detected as RoutingDetected | null | undefined) ?? null,
    available_modes: Array.isArray(raw.available_modes) ? (raw.available_modes as string[]) : null,
    snippets
  };
}

// ── shared store ─────────────────────────────────────────────────────────────

type StoreState = { data: ServicesPayload | null; loadedAt: number | null };
let storeState: StoreState = { data: null, loadedAt: null };
const listeners = new Set<() => void>();
let inFlight: Promise<void> | null = null;

function setServicesState(next: Partial<StoreState>) {
  storeState = { ...storeState, ...next };
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Load the services list once for pages that only need `public_url` (errors are ignored: old servers, no permission). */
function ensureServicesLoaded(maxAgeMs: number) {
  if (inFlight) return;
  if (storeState.loadedAt && Date.now() - storeState.loadedAt < maxAgeMs) return;
  inFlight = fetchServices()
    .then(() => undefined)
    .catch(() => {
      setServicesState({ loadedAt: Date.now() });
    })
    .finally(() => {
      inFlight = null;
    });
}

/** Forget the cached list (sign-out). */
export function resetServices() {
  storeState = { data: null, loadedAt: null };
  listeners.forEach((listener) => listener());
}

export type PublicUrls = Partial<Record<"panel" | "npm" | "pypi" | "s3", string>>;

/** `public_url` of each service that has one (from the shared store). */
export function publicUrlsFrom(data: ServicesPayload | null): PublicUrls {
  const result: PublicUrls = {};
  for (const item of data?.items ?? []) {
    const url = typeof item.public_url === "string" ? item.public_url.trim() : "";
    if (url && (item.id === "panel" || item.id === "npm" || item.id === "pypi" || item.id === "s3")) result[item.id] = url;
  }
  return result;
}

/**
 * Public addresses of the services, for connection commands. Loads `GET /api/v1/services` in the
 * background when nothing is cached (or the cache is older than a minute). Empty until then, or
 * when the server has no services API: callers fall back to addresses built from the page URL.
 */
export function usePublicServiceUrls(): PublicUrls {
  const snapshot = useSyncExternalStore(subscribe, () => storeState);
  useEffect(() => {
    ensureServicesLoaded(60_000);
  }, []);
  return publicUrlsFrom(snapshot.data);
}

// ── copy ─────────────────────────────────────────────────────────────────────

/** Fallback names when the server sends none (it normally sends name_fa / name_en). */
export const SERVICE_NAMES: Record<string, { name: Bi; description: Bi }> = {
  panel: {
    name: { fa: "پنل مدیریت", en: "Admin panel" },
    description: { fa: "همین صفحه‌ای که الان می‌بینید.", en: "The page you're looking at right now." }
  },
  npm: {
    name: { fa: "مخزن npm", en: "npm registry" },
    description: { fa: "بسته‌های جاوااسکریپت را برای پروژه‌ها نگه می‌دارد.", en: "Keeps JavaScript packages for your projects." }
  },
  pypi: {
    name: { fa: "مخزن PyPI", en: "PyPI registry" },
    description: { fa: "بسته‌های پایتون را برای پروژه‌ها نگه می‌دارد.", en: "Keeps Python packages for your projects." }
  },
  s3: {
    name: { fa: "فضای فایل", en: "File space" },
    description: { fa: "فایل‌ها و پشتیبان برنامه‌ها روی سرور خودتان.", en: "Files and app backups on your own server." }
  },
  agent: {
    name: { fa: "دستیار سرور", en: "Server helper" },
    description: { fa: "به پنل کمک می‌کند سرور و کانتینرها را ببیند.", en: "Lets the panel see the server and its containers." }
  },
  firewall: {
    name: { fa: "دیوار آتش", en: "Firewall" },
    description: { fa: "نشانی‌هایی را که به سرور حمله می‌کنند مسدود می‌کند.", en: "Blocks addresses that attack the server." }
  },
  dns: {
    name: { fa: "DNS", en: "DNS" },
    description: { fa: "نام‌ها را برای سرور، کانتینرها و شبکه شما به آدرس تبدیل می‌کند.", en: "Turns names into addresses for the server, its containers and your network." }
  }
};

export function serviceName(language: Language, service: Pick<ServiceInfo, "id" | "name_fa" | "name_en">): string {
  const fromServer = language === "fa" ? service.name_fa || service.name_en : service.name_en || service.name_fa;
  return fromServer || SERVICE_NAMES[service.id]?.name[language] || String(service.id);
}

export function serviceDescription(language: Language, service: ServiceInfo): string {
  const fromServer = language === "fa" ? service.description_fa || service.description_en : service.description_en || service.description_fa;
  return fromServer || SERVICE_NAMES[service.id]?.description[language] || "";
}

export type ServiceTone = "ok" | "warn" | "error" | "off" | "busy" | "info";

export const SERVICE_STATE_WORDS: Record<string, { tone: ServiceTone; label: Bi; why: Bi }> = {
  running: { tone: "ok", label: { fa: "روشن", en: "Running" }, why: { fa: "کار می‌کند و جواب می‌دهد.", en: "It's working and answering." } },
  stopped: { tone: "off", label: { fa: "خاموش", en: "Stopped" }, why: { fa: "خاموش است و به برنامه‌ها جواب نمی‌دهد.", en: "It's off and won't answer your apps." } },
  starting: { tone: "busy", label: { fa: "در حال روشن شدن", en: "Starting" }, why: { fa: "چند لحظه صبر کنید.", en: "Give it a moment." } },
  degraded: { tone: "warn", label: { fa: "کند یا ناقص", en: "Degraded" }, why: { fa: "کار می‌کند، ولی یک بخشش مشکل دارد.", en: "It works, but part of it has a problem." } },
  not_installed: { tone: "off", label: { fa: "نصب نشده", en: "Not installed" }, why: { fa: "این بخش روی این سرور نصب نیست.", en: "This part isn't installed on this server." } },
  disabled: { tone: "off", label: { fa: "غیرفعال", en: "Turned off" }, why: { fa: "در تنظیمات خاموش شده است.", en: "It's turned off in the settings." } },
  crashed: { tone: "error", label: { fa: "از کار افتاده", en: "Crashed" }, why: { fa: "این سرویس از کار افتاد. پنل و بقیه سرویس‌ها روشن مانده‌اند.", en: "This service crashed. The panel and the other services are still up." } }
};

/** Plain reasons for `reason_code` (unknown codes fall back to the state's own sentence). */
export const SERVICE_REASONS: Record<string, Bi> = {
  agent_not_paired: { fa: "دستیار سرور هنوز وصل نشده؛ اول آن را وصل کنید.", en: "The server helper isn't connected yet; connect it first." },
  agent_unreachable: { fa: "دستیار سرور جواب نمی‌دهد؛ مطمئن شوید روشن است.", en: "The server helper isn't answering; make sure it's running." },
  not_paired: { fa: "هنوز به پنل وصل نشده است.", en: "It isn't connected to the panel yet." },
  unreachable: { fa: "جواب نمی‌دهد؛ مطمئن شوید روی سرور روشن است.", en: "It isn't answering; make sure it's running on the server." },
  not_configured: { fa: "هنوز تنظیم نشده است.", en: "It isn't set up yet." },
  disabled_by_config: { fa: "در تنظیمات سرور خاموش شده است.", en: "It's turned off in the server settings." },
  disabled_by_operator: { fa: "یک نفر آن را از همین پنل خاموش کرده است.", en: "Someone turned it off from this panel." },
  stopped_by_operator: { fa: "یک نفر آن را از همین پنل خاموش کرده است.", en: "Someone turned it off from this panel." },
  process_exited: { fa: "برنامه‌اش متوقف شد؛ راه‌اندازی دوباره را امتحان کنید.", en: "Its program stopped; try restarting it." },
  crashed: { fa: "برنامه‌اش متوقف شد؛ راه‌اندازی دوباره را امتحان کنید.", en: "Its program stopped; try restarting it." },
  health_check_failed: { fa: "روشن است ولی درست جواب نمی‌دهد.", en: "It's on but isn't answering properly." },
  unhealthy: { fa: "روشن است ولی درست جواب نمی‌دهد.", en: "It's on but isn't answering properly." },
  upstreams_failing: { fa: "به منبع‌های دریافت بسته در اینترنت نمی‌رسد.", en: "It can't reach its package sources on the internet." },
  offline_mode: { fa: "در حالت بدون اینترنت است؛ فقط بسته‌های ذخیره‌شده نصب می‌شوند.", en: "It's in offline mode; only stored packages install." },
  dry_run: { fa: "فقط در حالت تمرین است و جلوی حمله‌ها را نمی‌گیرد.", en: "It's only in practice mode and doesn't block attacks." },
  disk_full: { fa: "فضای دیسک پر است.", en: "The disk is full." },
  module_missing: { fa: "این بخش در این نسخه از سرور نیست.", en: "This part isn't in this server version." },
  starting: { fa: "در حال روشن شدن است.", en: "It's starting up." },
  stopped_by_user: { fa: "یک نفر آن را از همین پنل خاموش کرده است.", en: "Someone turned it off from this panel." },
  program_failed: { fa: "برنامه‌اش متوقف شد؛ راه‌اندازی دوباره را امتحان کنید.", en: "Its program stopped; try restarting it." },
  partially_running: { fa: "فقط بخشی از آن روشن است؛ راه‌اندازی دوباره را امتحان کنید.", en: "Only part of it is running; try restarting it." },
  supervisor_unavailable: { fa: "در این حالت اجرا، روشن و خاموش کردن از پنل ممکن نیست.", en: "In this setup it can't be turned on or off from the panel." },
  disabled_in_settings: { fa: "در تنظیمات خاموش شده است.", en: "It's turned off in the settings." },
  module_unavailable: { fa: "این بخش در این نسخه از سرور نیست.", en: "This part isn't in this server version." },
  agent_not_configured: { fa: "دستیار سرور هنوز وصل نشده؛ اول آن را وصل کنید.", en: "The server helper isn't connected yet; connect it first." },
  firewall_not_configured: { fa: "دیوار آتش هنوز وصل نشده است.", en: "The firewall isn't connected yet." },
  firewall_unreachable: { fa: "دیوار آتش جواب نمی‌دهد؛ مطمئن شوید روشن است.", en: "The firewall isn't answering; make sure it's running." },
  crashed_retrying: { fa: "از کار افتاد؛ پنل خودش با فاصله دوباره روشنش می‌کند. می‌توانید همین حالا «راه‌اندازی دوباره» را بزنید.", en: "It crashed; the panel keeps retrying with growing waits. You can press Restart right now." },
  doh_plain_disabled: { fa: "برای وصل کردن دامنه، اول در DNS › «اتصال رمزدار» گزینه «پشت Traefik» را روشن کنید.", en: "To connect a domain, first turn on “Behind Traefik” in DNS › Encrypted connections." },
  crashed_no_auto_restart: { fa: "از کار افتاد و روشن کردن خودکار خاموش است؛ «راه‌اندازی دوباره» را بزنید.", en: "It crashed and automatic restart is off; press Restart." },
  not_checked_yet: { fa: "هنوز بررسی نشده؛ چند لحظه صبر کنید.", en: "Not checked yet; give it a moment." },
  dns_not_installed: { fa: "DNS هنوز روی این سرور راه نیفتاده؛ از صفحه DNS، «راه‌اندازی» را باز کنید.", en: "DNS isn't set up on this server yet; open Set up on the DNS page." },
  dns_unreachable: { fa: "برنامه DNS روی سرور هست ولی جواب نمی‌دهد.", en: "The DNS program is on the server but isn't answering." },
  dns_setup_incomplete: { fa: "DNS روشن است، ولی راه‌اندازی هنوز تمام نشده.", en: "DNS is running, but setup isn't finished yet." },
  setup_incomplete: { fa: "روشن است، ولی راه‌اندازی هنوز تمام نشده.", en: "It's running, but setup isn't finished yet." },
  separate_container: { fa: "در کانتینر جدای خودش اجرا می‌شود و از پنل روشن و خاموش نمی‌شود.", en: "It runs in its own container and isn't started or stopped from the panel." },
  listener_failed: { fa: "روی بعضی نشانی‌ها نمی‌تواند گوش بدهد.", en: "It can't listen on some addresses." },
  upstreams_unreachable: { fa: "به هیچ DNS بیرونی نمی‌رسد؛ فقط نام‌های خودتان جواب داده می‌شود.", en: "It can't reach any outside DNS; only your own names get answers." }
};

export function serviceStateText(language: Language, service: Pick<ServiceInfo, "state" | "reason_code">) {
  const entry = SERVICE_STATE_WORDS[service.state] ?? { tone: "off" as ServiceTone, label: { fa: "نامشخص", en: "Unknown" }, why: { fa: "وضعیتش معلوم نیست.", en: "Its state isn't known." } };
  const reason = service.reason_code ? SERVICE_REASONS[service.reason_code] : undefined;
  return { tone: entry.tone, label: entry.label[language], why: (reason ?? entry.why)[language] };
}

export const ACTION_WORDS: Record<ServiceAction, { button: Bi; busy: Bi; done: Bi }> = {
  start: { button: { fa: "روشن کن", en: "Start" }, busy: { fa: "در حال روشن کردن…", en: "Starting…" }, done: { fa: "«{name}» روشن شد.", en: "“{name}” was started." } },
  stop: { button: { fa: "خاموش کن", en: "Stop" }, busy: { fa: "در حال خاموش کردن…", en: "Stopping…" }, done: { fa: "«{name}» خاموش شد.", en: "“{name}” was stopped." } },
  restart: { button: { fa: "راه‌اندازی دوباره", en: "Restart" }, busy: { fa: "در حال راه‌اندازی دوباره…", en: "Restarting…" }, done: { fa: "«{name}» دوباره راه‌اندازی شد.", en: "“{name}” was restarted." } }
};

export const ROUTING_MODE_WORDS: Record<RoutingChoice, { label: Bi; body: Bi }> = {
  auto: {
    label: { fa: "انتخاب خودکار", en: "Pick automatically" },
    body: { fa: "DevAssist بهترین روشی را که روی این سرور کار می‌کند خودش انتخاب می‌کند.", en: "DevAssist picks the best way that works on this server." }
  },
  dokploy_api: {
    label: { fa: "Dokploy خودکار", en: "Dokploy, automatic" },
    body: { fa: "DevAssist دامنه را خودش در Dokploy ثبت می‌کند و گواهی HTTPS هم خودکار گرفته می‌شود.", en: "DevAssist adds the domain in Dokploy itself, and the HTTPS certificate is issued automatically." }
  },
  traefik_file: {
    label: { fa: "فایل Traefik", en: "Traefik file" },
    body: { fa: "دستیار سرور فقط یک فایل جدا برای Traefik می‌نویسد؛ به بقیه تنظیمات Dokploy دست نمی‌زند.", en: "The server helper writes one separate file for Traefik and leaves the rest of Dokploy alone." }
  },
  manual: {
    label: { fa: "دستی", en: "Manual" },
    body: { fa: "پنل قدم‌به‌قدم می‌گوید در Dokploy چه چیزی ثبت کنید؛ بعد خودش بررسی می‌کند.", en: "The panel tells you step by step what to add in Dokploy, then checks it." }
  }
};

export function routingModeWord(language: Language, mode: string | null | undefined): string {
  const entry = mode ? ROUTING_MODE_WORDS[mode as RoutingChoice] : undefined;
  return entry ? entry.label[language] : language === "fa" ? "نامشخص" : "Unknown";
}

/**
 * The mode a new domain will actually use: the configured one, or (for «auto») the best
 * mode the detection allows (docs/35 §2).
 */
export function effectiveMode(routing: RoutingSummary | null | undefined): RoutingMode {
  const configured = routing?.effective_mode ?? routing?.mode;
  if (configured === "dokploy_api" || configured === "traefik_file" || configured === "manual") return configured;
  const detected = routing?.detected ?? {};
  if (detected.inside_dokploy && detected.dokploy_connected) return "dokploy_api";
  if (detected.traefik_dir_available && detected.on_dokploy_network) return "traefik_file";
  return "manual";
}

/** Which modes the detection allows (manual and auto always). */
export function modeAvailable(mode: RoutingChoice, detected: RoutingDetected | null | undefined, available?: string[] | null): boolean {
  if (mode === "auto" || mode === "manual") return true;
  if (available && available.length) return available.includes(mode);
  if (mode === "dokploy_api") return Boolean(detected?.inside_dokploy && detected?.dokploy_connected);
  return Boolean(detected?.traefik_dir_available && detected?.on_dokploy_network);
}

/** What each domain problem means and what to do about it. */
export const DOMAIN_PROBLEMS: Record<string, { title: Bi; fix: Bi; tone: "warn" | "error" }> = {
  dns_missing: {
    title: { fa: "این دامنه هنوز به هیچ سروری اشاره نمی‌کند", en: "This domain doesn't point to any server yet" },
    fix: {
      fa: "در پنل ثبت دامنه، یک رکورد A بسازید که به نشانی {expected} اشاره کند. چند دقیقه تا چند ساعت طول می‌کشد.",
      en: "Where you bought the domain, add an A record pointing to {expected}. It can take a few minutes to a few hours."
    },
    tone: "error"
  },
  dns_wrong_ip: {
    title: { fa: "این دامنه به سرور دیگری اشاره می‌کند", en: "This domain points to a different server" },
    fix: {
      fa: "الان به {addresses} اشاره می‌کند. رکورد A را در پنل ثبت دامنه به {expected} تغییر دهید.",
      en: "It points to {addresses} now. Change the A record where you bought the domain to {expected}."
    },
    tone: "error"
  },
  tls_missing: {
    title: { fa: "هنوز گواهی HTTPS ندارد", en: "There's no HTTPS certificate yet" },
    fix: {
      fa: "اگر DNS تازه درست شده، چند دقیقه صبر کنید و دوباره بررسی کنید. اگر نشد، باز بودن پورت ۸۰ و ۴۴۳ سرور را بررسی کنید.",
      en: "If DNS was just fixed, wait a few minutes and check again. If not, make sure ports 80 and 443 are open on the server."
    },
    tone: "error"
  },
  tls_expiring: {
    title: { fa: "گواهی HTTPS به‌زودی تمام می‌شود", en: "The HTTPS certificate expires soon" },
    fix: {
      fa: "معمولاً خودکار تمدید می‌شود. اگر تا {expires} تمدید نشد، DNS و باز بودن پورت ۸۰ را بررسی کنید.",
      en: "It usually renews by itself. If it hasn't renewed by {expires}, check DNS and that port 80 is open."
    },
    tone: "warn"
  },
  tls_invalid: {
    title: { fa: "گواهی HTTPS این دامنه درست نیست", en: "This domain's HTTPS certificate isn't valid" },
    fix: {
      fa: "شاید گواهی مال دامنه دیگری است یا منقضی شده. در Dokploy گواهی را دوباره بگیرید و بعد بررسی کنید.",
      en: "It may belong to another domain or have expired. Request the certificate again in Dokploy, then check."
    },
    tone: "error"
  },
  unreachable: {
    title: { fa: "از اینترنت به این دامنه نمی‌رسیم", en: "This domain can't be reached from the internet" },
    fix: {
      fa: "باز بودن پورت ۸۰ و ۴۴۳ سرور و روشن بودن Dokploy را بررسی کنید.",
      en: "Check that ports 80 and 443 are open on the server and that Dokploy is running."
    },
    tone: "error"
  },
  wrong_service: {
    title: { fa: "این دامنه به سرویس دیگری می‌رسد", en: "This domain reaches a different service" },
    fix: {
      fa: "در Dokploy ببینید این دامنه به کدام برنامه وصل است. باید به همین سرویس و پورت {port} وصل باشد.",
      en: "In Dokploy, see which app this domain is attached to. It must go to this service on port {port}."
    },
    tone: "error"
  }
};

export const UNKNOWN_DOMAIN_PROBLEM = {
  title: { fa: "این دامنه مشکلی دارد", en: "This domain has a problem" },
  fix: { fa: "دوباره بررسی کنید؛ اگر ماند، جزئیات را در حالت پیشرفته ببینید.", en: "Check again; if it stays, see the details in Advanced mode." },
  tone: "error" as const
};

export type DomainHealthSummary = { tone: "ok" | "warn" | "error" | "off"; label: string; problem?: string | null };

function looksLikeHealth(value: unknown): value is DomainHealth {
  return Boolean(value) && typeof value === "object";
}

/** One status for a domain chip or row: ok / problem / not checked yet. */
export function domainHealthSummary(language: Language, health: DomainHealth | string | null | undefined): DomainHealthSummary {
  const fa = language === "fa";
  const unchecked: DomainHealthSummary = { tone: "off", label: fa ? "هنوز بررسی نشده" : "Not checked yet" };
  if (!health) return unchecked;
  if (typeof health === "string") {
    if (health === "ok" || health === "healthy") return { tone: "ok", label: fa ? "سالم" : "Healthy" };
    if (health === "pending" || health === "unknown" || health === "unchecked") return unchecked;
    if (health === "tls_expiring" || health === "warning") return { tone: "warn", label: fa ? "نیاز به توجه" : "Needs attention", problem: health };
    return { tone: "error", label: fa ? "مشکل دارد" : "Has a problem", problem: DOMAIN_PROBLEMS[health] ? health : null };
  }
  if (!looksLikeHealth(health)) return unchecked;
  const problem = health.problem_code ?? null;
  if (problem) {
    const tone = DOMAIN_PROBLEMS[problem]?.tone ?? "error";
    return { tone, label: tone === "warn" ? (fa ? "نیاز به توجه" : "Needs attention") : fa ? "مشکل دارد" : "Has a problem", problem };
  }
  if (!health.checked_at && health.dns?.ok == null && health.reach?.ok == null) return unchecked;
  const failed = [health.dns?.ok, health.tls?.ok, health.reach?.ok].some((value) => value === false);
  if (failed) return { tone: "error", label: fa ? "مشکل دارد" : "Has a problem" };
  return { tone: "ok", label: fa ? "سالم" : "Healthy" };
}

function listWords(language: Language, values: string[] | null | undefined): string {
  const list = (values ?? []).filter(Boolean);
  if (!list.length) return language === "fa" ? "نشانی این سرور" : "this server's address";
  return list.join(language === "fa" ? "، " : ", ");
}

/** Plain «what's wrong + what to do» for a domain problem. */
export function domainProblemText(
  language: Language,
  code: string | null | undefined,
  context: { health?: DomainHealth | null; port?: number | null; expectedIps?: string[] | null } = {}
): { title: string; fix: string; tone: "warn" | "error" } {
  const entry = (code && DOMAIN_PROBLEMS[code]) || UNKNOWN_DOMAIN_PROBLEM;
  const health = context.health ?? null;
  const expires = health?.tls?.expires_at;
  const params = {
    expected: listWords(language, health?.dns?.expected?.length ? health.dns.expected : context.expectedIps),
    addresses: listWords(language, health?.dns?.addresses),
    port: typeof context.port === "number" ? String(context.port) : language === "fa" ? "درست" : "the right one",
    expires: expires ? formatAbsolute(typeof expires === "number" && expires < 1e12 ? expires * 1000 : expires, language) : language === "fa" ? "چند روز دیگر" : "a few days"
  };
  return { title: entry.title[language], fix: fill(entry.fix[language], params, language), tone: entry.tone };
}

/** Normalise a timestamp from the API (seconds or milliseconds or ISO) to something kit formatters accept. */
export function apiTime(value: number | string | null | undefined): number | string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") return value < 1e12 ? value * 1000 : value;
  return value;
}
