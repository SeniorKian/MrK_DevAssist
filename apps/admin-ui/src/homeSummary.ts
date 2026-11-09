/**
 * Home summary (docs/34 §1): one shared store for `GET /api/v1/home`, used by HomePage and by
 * the shell's bell, plus the plain-language sentence for every attention rule, quick action and
 * checklist step. Rule ids are stable backend ids; each maps to one sentence + one button.
 */
import { useEffect, useSyncExternalStore } from "react";
import { getJson, mutateJson } from "./api";
import type { Language } from "./i18n";
import { formatRelative } from "./kit/formatters";
import { formatNumber } from "./format";
import { ECOSYSTEM_WORDS } from "./copy/kinds";
import { reasonFor } from "./copy/errors";
import { fill, type Bi } from "./copy/text";
import { domainProblemText } from "./services";

export type HomeSeverity = "critical" | "error" | "warning" | "info";

export type HomeAttention = {
  id: string;
  rule: string;
  severity: HomeSeverity;
  title_key?: string;
  params?: Record<string, unknown>;
  action?: { kind?: string; route?: string };
};

export type HomeChecklistStep = { id: string; done: boolean; route?: string; optional?: boolean; detected?: boolean | null };

export type HomeSummary = {
  verdict: { level: "ok" | "attention" | "problem"; count: number };
  attention: HomeAttention[];
  quick_actions: { id: string; route: string }[];
  checklist: HomeChecklistStep[];
  checklist_progress?: { done: number; total: number };
  checklist_dismissed?: boolean;
  generated_at?: number;
  must_change_password?: boolean;
};

// ── store ────────────────────────────────────────────────────────────────────

type State = { data: HomeSummary | null; error: unknown; loading: boolean; loadedAt: number | null };

let state: State = { data: null, error: null, loading: false, loadedAt: null };
const listeners = new Set<() => void>();
let inFlight: Promise<void> | null = null;

function setState(next: Partial<State>) {
  state = { ...state, ...next };
  listeners.forEach((listener) => listener());
}

/** Fetch the summary now (concurrent callers share one request). */
export function refreshHome(): Promise<void> {
  if (inFlight) return inFlight;
  setState({ loading: true });
  inFlight = (async () => {
    try {
      const data = await getJson<HomeSummary>(`/api/v1/home?_=${Date.now()}`);
      setState({ data, error: null, loadedAt: Date.now() });
    } catch (error) {
      setState({ error });
    } finally {
      setState({ loading: false });
      inFlight = null;
    }
  })();
  return inFlight;
}

/** Forget everything (sign-out, another user). */
export function resetHome() {
  state = { data: null, error: null, loading: false, loadedAt: null };
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/**
 * Current summary. With `pollMs`, refreshes on mount, on an interval while the tab is visible,
 * and when the tab becomes visible again.
 */
export function useHomeSummary(pollMs?: number) {
  const snapshot = useSyncExternalStore(subscribe, () => state);
  useEffect(() => {
    if (!pollMs) return;
    if (!state.loadedAt || Date.now() - state.loadedAt > 5_000) void refreshHome();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void refreshHome();
    }, pollMs);
    const onVisible = () => {
      if (document.visibilityState === "visible" && (!state.loadedAt || Date.now() - state.loadedAt > 30_000)) void refreshHome();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [pollMs]);
  return snapshot;
}

/** `PATCH /api/v1/home/checklist`, then refresh. */
export async function updateChecklist(body: { dismissed?: boolean; steps?: Record<string, boolean> }) {
  await mutateJson("/api/v1/home/checklist", { method: "PATCH", body });
  if (state.data) {
    const data = { ...state.data };
    if (body.dismissed !== undefined) data.checklist_dismissed = body.dismissed;
    if (body.steps) data.checklist = data.checklist.map((step) => (step.id in body.steps! ? { ...step, done: step.done || body.steps![step.id] } : step));
    setState({ data });
  }
  void refreshHome();
}

// ── copy ─────────────────────────────────────────────────────────────────────

const COMPONENT_WORDS: Record<string, Bi> = {
  npm_registry: { fa: "مخزن npm", en: "The npm registry" },
  pypi_registry: { fa: "مخزن PyPI", en: "The PyPI registry" },
  pypi_upstream_router: { fa: "مسیریاب PyPI", en: "The PyPI router" },
  database: { fa: "پایگاه داده پنل", en: "The panel's database" },
  control_plane: { fa: "سرور DevAssist", en: "The DevAssist server" },
  s3_engine: { fa: "فضای فایل", en: "File space" },
  s3: { fa: "فضای فایل", en: "File space" },
  dns: { fa: "DNS سرور", en: "The server's DNS" },
  dns_engine: { fa: "DNS سرور", en: "The server's DNS" }
};

/** Plain name of a system component («مخزن npm»). Unknown → «یکی از بخش‌های DevAssist». */
export function componentWord(language: Language, component: string): string {
  return COMPONENT_WORDS[component]?.[language] ?? (language === "fa" ? "یکی از بخش‌های DevAssist" : "Part of DevAssist");
}

function ecosystemWord(language: Language, value: unknown): string {
  const key = String(value ?? "");
  return ECOSYSTEM_WORDS[key]?.[language] ?? (key === "pypi" ? "PyPI" : key === "npm" ? "npm" : key);
}

type RuleCopy = { title: Bi; why?: Bi; button: Bi };

const RULES: Record<string, RuleCopy> = {
  component_unavailable: {
    title: { fa: "{component} از کار افتاده است", en: "{component} has stopped working" },
    why: { fa: "تا درست نشود، این بخش به برنامه‌ها جواب نمی‌دهد.", en: "Until it's fixed, this part won't answer your apps." },
    button: { fa: "بررسی", en: "Check" }
  },
  disk_almost_full: {
    title: { fa: "فضای دیسک رو به اتمام است ({percent}٪ پر شده)", en: "The disk is almost full ({percent}% used)" },
    why: { fa: "وقتی دیسک از {threshold}٪ بیشتر پر شود خبرتان می‌کنیم.", en: "We warn you once the disk passes {threshold}%." },
    button: { fa: "آزاد کردن فضا", en: "Free up space" }
  },
  upstreams_all_failing: {
    title: { fa: "منبع دریافت {ecosystem} جواب نمی‌دهد", en: "The {ecosystem} package source isn't answering" },
    why: { fa: "بسته‌های تازه دانلود نمی‌شوند؛ فقط بسته‌های ذخیره‌شده نصب می‌شوند.", en: "New packages can't be downloaded; only stored ones install." },
    button: { fa: "دوباره امتحان کن", en: "Try again" }
  },
  ecosystem_offline: {
    title: { fa: "{ecosystem} در حالت بدون اینترنت است", en: "{ecosystem} is in offline mode" },
    why: { fa: "فقط بسته‌هایی نصب می‌شوند که قبلاً روی سرور ذخیره شده‌اند.", en: "Only packages already stored on the server can install." },
    button: { fa: "روشن کردن اینترنت", en: "Go back online" }
  },
  agent_not_paired: {
    title: { fa: "دستیار سرور هنوز وصل نیست", en: "The server helper isn't connected yet" },
    why: { fa: "بدون آن، وضعیت سرور و کانتینرها را نمی‌بینید.", en: "Without it you can't see the server or its containers." },
    button: { fa: "وصل کردن", en: "Connect" }
  },
  agent_unreachable: {
    title: { fa: "دستیار سرور جواب نمی‌دهد", en: "The server helper isn't answering" },
    why: { fa: "مطمئن شوید روی سرور روشن است.", en: "Make sure it's running on the server." },
    button: { fa: "بررسی", en: "Check" }
  },
  backup_failed: {
    title: { fa: "پشتیبان «{job_name}» انجام نشد", en: "Backup “{job_name}” didn't finish" },
    button: { fa: "دیدن و اجرای دوباره", en: "See and run again" }
  },
  backup_overdue: {
    title: { fa: "مدتی است از «{job_name}» پشتیبان گرفته نشده", en: "“{job_name}” hasn't been backed up for a while" },
    button: { fa: "بررسی پشتیبان", en: "Check the backup" }
  },
  no_backup_jobs: {
    title: { fa: "هنوز از برنامه‌ها پشتیبان نمی‌گیرید", en: "Your apps aren't being backed up yet" },
    why: { fa: "اگر مشکلی پیش بیاید، اطلاعات برنامه‌ها برنمی‌گردد.", en: "If something breaks, your apps' data can't be brought back." },
    button: { fa: "ساخت پشتیبان", en: "Set up a backup" }
  },
  updates_available: {
    title: { fa: "برای {count} برنامه نسخه تازه آمده است", en: "{count} apps have a newer version" },
    button: { fa: "دیدن", en: "See them" }
  },
  vulnerabilities_found: {
    title: { fa: "{count} مشکل امنیتی جدی در برنامه‌ها پیدا شد", en: "{count} serious security issues were found in your apps" },
    why: { fa: "بهتر است زودتر برنامه‌های گفته‌شده را به‌روز کنید.", en: "It's best to update the affected apps soon." },
    button: { fa: "دیدن", en: "See them" }
  },
  firewall_dry_run: {
    title: { fa: "دیوار آتش {days} روز است فقط در حالت تمرین است", en: "The firewall has been in practice mode for {days} days" },
    why: { fa: "حمله‌ها ثبت می‌شوند ولی جلویشان گرفته نمی‌شود.", en: "Attacks are logged but not blocked." },
    button: { fa: "فعال کردن", en: "Turn it on" }
  },
  no_notification_channel: {
    title: { fa: "اگر مشکلی پیش بیاید خبردار نمی‌شوید", en: "You won't hear about problems" },
    why: { fa: "یک کانال تلگرام، بله یا ایمیل اضافه کنید.", en: "Add a Telegram, Bale or email channel." },
    button: { fa: "افزودن کانال", en: "Add a channel" }
  },
  jobs_failed: {
    title: { fa: "{count} کار در یک روز گذشته ناتمام ماند", en: "{count} background jobs didn't finish in the last day" },
    button: { fa: "جزئیات", en: "Details" }
  },
  s3_public_endpoint_missing: {
    title: { fa: "آدرس عمومی فضای فایل تنظیم نشده", en: "The file space has no public address yet" },
    why: { fa: "برنامه‌های بیرون از این سرور نمی‌توانند به فایل‌ها وصل شوند.", en: "Apps outside this server can't reach your files." },
    button: { fa: "تنظیم", en: "Set it up" }
  },
  dns_unreachable: {
    title: { fa: "DNS سرور جواب نمی‌دهد", en: "The server's DNS isn't answering" },
    why: { fa: "تا درست نشود، برنامه‌هایی که از این DNS می‌پرسند نام‌ها را پیدا نمی‌کنند.", en: "Until it's fixed, apps that ask this DNS can't find names." },
    button: { fa: "بررسی DNS", en: "Check DNS" }
  },
  dns_under_pressure: {
    title: { fa: "DNS سرور زیر فشار است", en: "The server's DNS is under load" },
    why: { fa: "DevAssist خودکار کارهای کم‌اهمیت را کم کرده تا پرسش‌ها جواب بگیرند. ببینید چه کسی بیشتر می‌پرسد.", en: "DevAssist has cut back less important work so questions still get answers. See who is asking the most." },
    button: { fa: "دیدن پایش", en: "See monitor" }
  },
  dns_attack_detected: {
    title: { fa: "حمله‌ای به DNS سرور دیده شد", en: "An attack on the server's DNS was seen" },
    why: { fa: "کسی تعداد زیادی نام ساختگی می‌پرسد تا DNS را خسته کند. با یک دکمه جلویش را بگیرید.", en: "Someone is asking lots of made-up names to wear DNS out. Stop it with one button." },
    button: { fa: "جلویش را بگیر", en: "Stop it" }
  },
  dns_certificate_expiring: {
    title: { fa: "گواهی اتصال رمزدار DNS رو به اتمام است", en: "DNS's encrypted connection certificate is ending" },
    why: { fa: "اگر تمام شود، گوشی‌ها و لپ‌تاپ‌ها دیگر رمزدار به DNS وصل نمی‌شوند. گواهی را تمدید یا جایگزین کنید.", en: "When it ends, phones and laptops can no longer connect to DNS encrypted. Renew or replace the certificate." },
    button: { fa: "دیدن گواهی", en: "See the certificate" }
  },
  dns_trust_anchor_problem: {
    title: { fa: "کلید اعتماد ریشه DNS مشکل دارد", en: "DNS's root trust key has a problem" },
    why: { fa: "تا درست نشود، بررسی امضای امنیتی جواب‌ها ممکن است درست کار نکند. در تنظیمات DNS «به‌روزرسانی» را بزنید.", en: "Until it's fixed, checking answers' security signatures may not work right. Press Update in DNS settings." },
    button: { fa: "بررسی امضای امنیتی", en: "Check signatures" }
  },
  dns_secondary_problem: {
    title: { fa: "نسخه دوم دامنه {zone} به‌روز نمی‌شود", en: "The copy of the domain {zone} isn't updating" },
    why: { fa: "DevAssist نمی‌تواند رکوردها را از سرور اصلی بگیرد. اگر مدت زیادی بماند، این دامنه دیگر جواب نمی‌گیرد.", en: "DevAssist can't copy the records from the main server. If it lasts too long, this domain stops getting answers." },
    button: { fa: "بررسی دامنه", en: "Check the domain" }
  },
  dns_signing_problem: {
    title: { fa: "امضای امنیتی دامنه {zone} مشکل دارد", en: "Security signing for the domain {zone} has a problem" },
    why: { fa: "اگر امضاها تمدید نشوند، دامنه برای خیلی از کاربران باز نمی‌شود. وضعیت امضا را ببینید.", en: "If the signatures aren't renewed, the domain stops opening for many people. See the signing state." },
    button: { fa: "دیدن امضا", en: "See signing" }
  },
  domain_problem: {
    title: { fa: "دامنه {host} مشکل دارد", en: "The domain {host} has a problem" },
    why: { fa: "تا درست نشود، این دامنه از بیرون باز نمی‌شود.", en: "Until it's fixed, this domain won't open from outside." },
    button: { fa: "بررسی دامنه", en: "Check the domain" }
  }
};

const UNKNOWN_RULE: RuleCopy = {
  title: { fa: "یک مورد تازه به توجه شما نیاز دارد", en: "Something new needs your attention" },
  button: { fa: "دیدن", en: "See it" }
};

const DNS_MONITOR_RULES = new Set(["dns_under_pressure", "dns_attack_detected"]);

/** docs/41 §6: open the domain (and its tab) the item names. */
function zoneRoute(zone: unknown, tab: "records" | "signing"): string {
  if (typeof zone !== "string" || !zone) return "#/dns/names";
  return `#/dns/names?zone=${encodeURIComponent(zone)}${tab === "records" ? "" : `&ztab=${tab}`}`;
}

export type AttentionText = { title: string; why?: string; button: string; severity: "critical" | "warning" | "info"; route?: string };

function lastSuccess(language: Language, value: unknown): string {
  if (typeof value !== "number" || !value) return language === "fa" ? "تا حالا هیچ پشتیبان موفقی گرفته نشده." : "No backup has succeeded yet.";
  const when = formatRelative(value * 1000, language);
  return language === "fa" ? `آخرین پشتیبان موفق: ${when}.` : `Last good backup: ${when}.`;
}

/** One plain sentence + one button for an attention item. */
export function attentionText(language: Language, item: HomeAttention): AttentionText {
  const copy = RULES[item.rule] ?? UNKNOWN_RULE;
  const params = item.params ?? {};
  const values = {
    component: componentWord(language, String(params.component ?? "")),
    ecosystem: ecosystemWord(language, params.ecosystem),
    percent: typeof params.percent === "number" ? params.percent : null,
    threshold: typeof params.threshold === "number" ? params.threshold : null,
    job_name: String(params.job_name ?? (language === "fa" ? "بی‌نام" : "unnamed")),
    count: typeof params.count === "number" ? params.count : null,
    days: typeof params.days === "number" ? params.days : null,
    buckets: typeof params.buckets === "number" ? params.buckets : null,
    host: typeof params.host === "string" && params.host ? params.host : language === "fa" ? "یکی از سرویس‌ها" : "for one of your services",
    zone: typeof params.zone === "string" && params.zone ? params.zone : ""
  };
  let why = copy.why ? fill(copy.why[language], values, language) : undefined;
  if (item.rule === "backup_failed") {
    const reason = params.error_code ? reasonFor(language, String(params.error_code)) : "";
    why = [reason, lastSuccess(language, params.last_success_at)].filter(Boolean).join(" ");
  }
  if (item.rule === "backup_overdue") why = lastSuccess(language, params.last_success_at);
  if (item.rule === "domain_problem" && typeof params.problem_code === "string") {
    const problem = domainProblemText(language, params.problem_code);
    why = `${problem.title}. ${problem.fix}`;
  }
  if (item.rule === "dns_under_pressure" && params.level === "emergency") {
    why = language === "fa"
      ? "فشار خیلی زیاد است و DevAssist فقط کارهای ضروری را انجام می‌دهد. ببینید چه کسی بیشتر می‌پرسد."
      : "The load is very heavy and DevAssist is doing only what's essential. See who is asking the most.";
  }
  if (item.rule === "dns_attack_detected" && typeof params.parent === "string" && params.parent) {
    why = language === "fa"
      ? `کسی تعداد زیادی نام ساختگی زیر «${params.parent}» می‌پرسد تا DNS را خسته کند. با یک دکمه جلویش را بگیرید.`
      : `Someone is asking lots of made-up names under “${params.parent}” to wear DNS out. Stop it with one button.`;
  }
  if (item.rule === "dns_certificate_expiring" && typeof params.days_left === "number") {
    const days = formatNumber(params.days_left, language);
    why = params.days_left <= 0
      ? (language === "fa" ? "گواهی تمام شده و دستگاه‌ها رمزدار وصل نمی‌شوند. گواهی را تمدید یا جایگزین کنید." : "The certificate has ended and devices can't connect encrypted. Renew or replace it.")
      : (language === "fa" ? `گواهی ${days} روز دیگر تمام می‌شود. پیش از آن تمدید یا جایگزینش کنید.` : `The certificate ends in ${days} days. Renew or replace it before then.`);
  }
  if (item.rule === "dns_secondary_problem" && params.expired === true) {
    why = language === "fa"
      ? "نسخه دوم از اعتبار افتاده و DevAssist برای این دامنه جواب خطا می‌دهد. سرور اصلی را بررسی کنید."
      : "The copy has run out and DevAssist answers this domain with an error. Check the main server.";
  }
  if (item.rule === "agent_unreachable" && typeof params.since === "number") {
    const when = formatRelative(params.since * 1000, language);
    why = language === "fa" ? `آخرین بار ${when} جواب داد. مطمئن شوید روی سرور روشن است.` : `It last answered ${when}. Make sure it's running on the server.`;
  }
  const severity = item.severity === "critical" || item.severity === "error" ? "critical" : item.severity === "warning" ? "warning" : "info";
  const route = item.action?.route ?? (item.rule === "domain_problem" ? "#/services" : item.rule === "dns_unreachable" ? "#/dns/status" : DNS_MONITOR_RULES.has(item.rule) ? "#/dns/monitor"
    : item.rule === "dns_certificate_expiring" ? "#/dns/encrypted" : item.rule === "dns_trust_anchor_problem" ? "#/dns/settings"
    : item.rule === "dns_secondary_problem" ? zoneRoute(params.zone, "records") : item.rule === "dns_signing_problem" ? zoneRoute(params.zone, "signing") : undefined);
  return { title: fill(copy.title[language], values, language), why, button: copy.button[language], severity, route };
}

export const QUICK_ACTION_COPY: Record<string, { label: Bi; hint: Bi }> = {
  connect_project: { label: { fa: "وصل کردن یک پروژه", en: "Connect a project" }, hint: { fa: "دستور آماده برای npm و pip", en: "Ready commands for npm and pip" } },
  search_package: { label: { fa: "جست‌وجوی بسته", en: "Find a package" }, hint: { fa: "ببینید چه بسته‌هایی ذخیره شده", en: "See which packages are stored" } },
  backup_now: { label: { fa: "پشتیبان‌گیری همین حالا", en: "Back up now" }, hint: { fa: "یک پشتیبان تازه از برنامه‌ها", en: "A fresh backup of your apps" } },
  invite_teammate: { label: { fa: "دعوت همکار", en: "Invite a teammate" }, hint: { fa: "با یک لینک ساده", en: "With a simple link" } },
  check_updates: { label: { fa: "بررسی نسخه‌های تازه", en: "Check for new versions" }, hint: { fa: "کدام برنامه‌ها نسخه تازه دارند", en: "Which apps have a newer version" } },
  view_server_usage: { label: { fa: "دیدن مصرف سرور", en: "See server use" }, hint: { fa: "پردازنده، حافظه و دیسک", en: "CPU, memory and disk" } },
  my_services: { label: { fa: "سرویس‌های من", en: "My services" }, hint: { fa: "وضعیت، روشن و خاموش، دامنه‌ها", en: "Status, start/stop, domains" } },
  add_domain: { label: { fa: "افزودن دامنه", en: "Add a domain" }, hint: { fa: "یک آدرس اینترنتی برای سرویس‌ها", en: "A web address for your services" } },
};

export const CHECKLIST_COPY: Record<string, Bi> = {
  owner_account: { fa: "ساخت حساب مالک", en: "Create the owner account" },
  connect_project: { fa: "وصل کردن اولین پروژه به npm یا pip", en: "Connect your first project to npm or pip" },
  add_notification_channel: { fa: "افزودن یک کانال اعلان (تلگرام، بله یا ایمیل)", en: "Add an alert channel (Telegram, Bale or email)" },
  connect_agent: { fa: "وصل کردن دستیار سرور", en: "Connect the server helper" },
  create_backup: { fa: "ساخت اولین پشتیبان", en: "Create your first backup" },
  invite_teammate: { fa: "دعوت یک همکار", en: "Invite a teammate" },
  set_public_address: { fa: "تنظیم آدرس عمومی فضای فایل", en: "Set the file space's public address" },
  setup_dns: { fa: "راه‌اندازی DNS خود سرور (اختیاری)", en: "Set up the server's own DNS (optional)" }
};
