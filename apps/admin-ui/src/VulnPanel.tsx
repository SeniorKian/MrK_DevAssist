import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Box, Button, Card, CardContent, Checkbox, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel,
  FormGroup, Grid, InputAdornment, Link, MenuItem, Stack, Switch, TextField, Typography, useMediaQuery, useTheme
} from "@mui/material";
import GppGoodRoundedIcon from "@mui/icons-material/GppGoodRounded";
import GppMaybeRoundedIcon from "@mui/icons-material/GppMaybeRounded";
import GppBadRoundedIcon from "@mui/icons-material/GppBadRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import VisibilityOffRoundedIcon from "@mui/icons-material/VisibilityOffRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { pick, reasonFor, say, severityWord, termWithEnglish, type Bi, type Tone } from "./copy";
import {
  Bytes, EmptyState, FriendlyError, HelpTip, Ltr, NoAccess, Notice, NumberInput, RelativeTime, ResponsiveList, SectionCard, StatGrid,
  StatTile, StatusPill, useConfirmAction, useKit, useUndoSnackbar, RegistrySettings
} from "./kit";
import { ProxyPicker, PROXY_TYPES, choiceFromApi, choiceToApi, useProxyList } from "./ProxyControls";
import { formatNumber } from "./format";
import type { Language } from "./i18n";

/**
 * Security › «بررسی امنیتی» (docs/32 §4.1, docs/33 §4.2).
 * Simple: one verdict, one card per app (image) with secure / needs attention / critical and
 * «چه کار کنم؟» in plain words, the issues of an app, and «نادیده بگیر» with a reason and an end date.
 * Advanced: CVE ids, versions, scores, every finding filter, ignore rules, feed status and all settings.
 */

type Severity = "critical" | "high" | "medium" | "low" | "unknown";
type Counts = Record<Severity, number>;
type ImageStatus = "critical" | "warning" | "secure" | "error" | "unsupported";
type Summary = {
  enabled: boolean;
  agent_configured: boolean;
  images: number;
  counts: Counts;
  fixable: number;
  ignored: number;
  images_by_status: Record<ImageStatus, number>;
  feeds_ready: boolean;
  running: boolean;
  phase: string | null;
  last_run_at: number | null;
  last_attempt_at: number | null;
  last_error: string | null;
  next_run_at: number | null;
};
type ImageRecord = {
  image_id: string;
  image: string;
  digest: string | null;
  os: { id?: string; version_id?: string; name?: string; ecosystem?: string } | null;
  packages_scanned: number;
  ecosystems: string[];
  counts: Counts;
  status: ImageStatus;
  fixable: number;
  ignored: number;
  containers: { id: string; name: string; state: string; protected: boolean }[];
  scanned_at: number | null;
  errors: { code: string; feed?: string }[];
};
type Finding = {
  id: string;
  aliases: string[];
  package: string;
  binaries: string[];
  installed: string;
  fixed: string | null;
  severity: Severity;
  score: number | null;
  summary: string | null;
  ecosystem: string;
  location: string | null;
  first_seen: number | null;
  ignored: boolean;
  ignore_id: string | null;
};
type IgnoreRule = { id: string; advisory: string | null; package: string | null; image: string | null; reason: string; expires_at: number | null; created_at: number; expired: boolean };
type Feed = { ecosystem: string; needed: boolean; url: string; updated_at: number | null; checked_at: number | null; records: number | null; size: number | null; status: "ok" | "error" | "pending"; error: string | null };
type VulnSettings = { enabled: boolean; interval_hours: number; ecosystems_extra: string[]; feed_base_url: string; severities_to_notify: string[]; include_stopped: boolean; proxy_id: string | null; feed_max_mb: number };

const API = "/api/v1/vuln";
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "unknown"];
const EXTRA_ECOSYSTEMS = ["Debian", "Ubuntu", "Alpine", "Wolfi", "Chainguard", "AlmaLinux", "Rocky Linux", "npm", "PyPI"];
const STATUS_ORDER: Record<ImageStatus, number> = { critical: 0, warning: 1, error: 2, unsupported: 3, secure: 4 };

const COPY = {
  unavailable: { fa: "بررسی امنیتی روی نسخه فعلی سرور نیست. MRK را به‌روز کنید.", en: "Security checks aren't on this server version. Update MRK." },
  // verdict
  verdictTitle: { fa: "وضعیت امنیت برنامه‌ها", en: "Your apps' security" },
  off: { fa: "بررسی امنیتی خاموش است.", en: "Security checks are off." },
  offBody: { fa: "در حالت پیشرفته، بخش «تنظیمات بررسی» را روشن کنید.", en: "Turn it on under “Check settings” in Advanced mode." },
  noAgent: { fa: "برای بررسی برنامه‌ها، اول دستیار سرور را وصل کنید.", en: "To check your apps, connect the server helper first." },
  connectAgent: { fa: "وصل کردن دستیار سرور", en: "Connect the server helper" },
  critical: { fa: "{n} مشکل امنیتی بحرانی در برنامه‌ها پیدا شد.", en: "{n} critical security issues were found in your apps." },
  high: { fa: "{n} مشکل امنیتی جدی در برنامه‌ها پیدا شد.", en: "{n} serious security issues were found in your apps." },
  medium: { fa: "مشکل جدی نیست، ولی {n} مورد متوسط هست.", en: "Nothing serious, but there are {n} medium issues." },
  clean: { fa: "مشکل امنیتی شناخته‌شده‌ای پیدا نشد.", en: "No known security issues were found." },
  notYet: { fa: "هنوز بررسی‌ای انجام نشده.", en: "No check has run yet." },
  fixableLine: { fa: "{n} مورد با به‌روز کردن درست می‌شود.", en: "{n} can be fixed by updating." },
  lastRun: { fa: "آخرین بررسی", en: "Last check" },
  nextRun: { fa: "بررسی بعدی", en: "Next check" },
  running: { fa: "در حال بررسی…", en: "Checking…" },
  feedsNotReady: { fa: "فهرست مشکلات امنیتی هنوز کامل دانلود نشده؛ نتیجه ممکن است ناقص باشد.", en: "The security issue list isn't fully downloaded yet; results may be incomplete." },
  lastError: { fa: "آخرین بررسی کامل نشد: {reason}", en: "The last check didn't finish: {reason}" },
  scanNow: { fa: "بررسی همین حالا", en: "Check now" },
  scanFresh: { fa: "بررسی با فهرست تازه بسته‌ها", en: "Check with a fresh package list" },
  scanStarted: { fa: "بررسی شروع شد؛ چند دقیقه طول می‌کشد.", en: "The check has started; it takes a few minutes." },
  scanBusy: { fa: "یک بررسی همین حالا در جریان است.", en: "A check is already running." },
  statCritical: { fa: "بحرانی", en: "Critical" },
  statHigh: { fa: "زیاد", en: "High" },
  statMedium: { fa: "متوسط", en: "Medium" },
  statLow: { fa: "کم", en: "Low" },
  statFixable: { fa: "قابل رفع", en: "Fixable" },
  statIgnored: { fa: "نادیده‌گرفته", en: "Ignored" },
  // apps
  appsTitle: { fa: "برنامه‌ها", en: "Apps" },
  appsHint: { fa: "هر کارت یک نسخه برنامه (ایمیج) است که روی سرور اجرا می‌شود.", en: "Each card is an app image running on the server." },
  appsEmpty: { fa: "هنوز برنامه‌ای بررسی نشده.", en: "No app has been checked yet." },
  appsEmptyBody: { fa: "بعد از اولین بررسی، وضعیت هر برنامه این‌جا دیده می‌شود.", en: "After the first check, each app's status shows up here." },
  sSecure: { fa: "امن", en: "Secure" },
  sWarning: { fa: "نیاز به توجه", en: "Needs attention" },
  sCritical: { fa: "بحرانی", en: "Critical" },
  sError: { fa: "بررسی نشد", en: "Not checked" },
  sUnsupported: { fa: "قابل بررسی نیست", en: "Can't be checked" },
  issues: { fa: "{n} مشکل", en: "{n} issues" },
  usedBy: { fa: "اجرا در: {names}", en: "Running as: {names}" },
  whatToDo: { fa: "چه کار کنم؟", en: "What should I do?" },
  doFix: { fa: "{n} مورد با نسخه تازه‌تر درست می‌شود. نسخه پایه برنامه (ایمیج) را به‌روز کنید و برنامه را دوباره منتشر کنید.", en: "{n} can be fixed with a newer version. Update the base image and redeploy the app." },
  doWait: { fa: "هنوز نسخه اصلاح‌شده‌ای نیامده. خودکار دوباره بررسی می‌شود؛ تا آن موقع اگر برنامه رو به اینترنت است، دسترسی به آن را محدود کنید.", en: "No fixed version exists yet. It'll be checked again automatically; meanwhile, limit access if the app faces the internet." },
  doError: { fa: "این برنامه بررسی نشد: {reason}", en: "This app wasn't checked: {reason}" },
  doUnsupported: { fa: "MRK نتوانست فهرست بسته‌های این برنامه را بخواند؛ معمولاً برای برنامه‌های خیلی کوچک یا ساخته‌شده از صفر این‌طور است.", en: "MRK couldn't read this app's package list; this is usual for very small or from-scratch images." },
  doNothing: { fa: "کاری لازم نیست. مشکل شناخته‌شده‌ای پیدا نشد.", en: "Nothing to do. No known issues were found." },
  seeIssues: { fa: "دیدن مشکل‌ها", en: "See issues" },
  redeploy: { fa: "انتشار دوباره در Dokploy", en: "Redeploy in Dokploy" },
  checkUpdates: { fa: "دیدن نسخه‌های تازه", en: "See new versions" },
  // findings
  findingsTitle: { fa: "مشکل‌های «{image}»", en: "Issues in “{image}”" },
  findingsHint: { fa: "هر ردیف یک مشکل امنیتی در یکی از بسته‌های این برنامه است.", en: "Each row is a security issue in one of this app's packages." },
  closeFindings: { fa: "بستن", en: "Close" },
  search: { fa: "جست‌وجوی بسته یا شناسه", en: "Search package or id" },
  showIgnored: { fa: "نمایش نادیده‌گرفته‌ها", en: "Show ignored" },
  package: { fa: "بسته", en: "Package" },
  severity: { fa: "شدت", en: "Severity" },
  installed: { fa: "نسخه فعلی", en: "Installed" },
  fixedIn: { fa: "درست می‌شود در", en: "Fixed in" },
  notFixed: { fa: "هنوز اصلاح نشده", en: "No fix yet" },
  advisory: { fa: "شناسه", en: "Advisory" },
  score: { fa: "امتیاز", en: "Score" },
  summary: { fa: "خلاصه", en: "Summary" },
  firstSeen: { fa: "اولین بار", en: "First seen" },
  location: { fa: "محل", en: "Location" },
  ignoredPill: { fa: "نادیده‌گرفته", en: "Ignored" },
  findingsEmpty: { fa: "با این فیلترها مشکلی پیدا نشد.", en: "No issues match these filters." },
  findingsEmptyBody: { fa: "فیلتر شدت را بازتر کنید یا جست‌وجو را پاک کنید.", en: "Widen the severity filter or clear the search." },
  more: { fa: "{n} مورد دیگر هم هست؛ فیلتر را دقیق‌تر کنید.", en: "{n} more exist; narrow the filters." },
  ignore: { fa: "نادیده بگیر…", en: "Ignore…" },
  unignore: { fa: "دیگر نادیده نگیر", en: "Stop ignoring" },
  unignored: { fa: "این مشکل دوباره شمرده می‌شود.", en: "This issue counts again." },
  // ignore dialog
  ignoreTitle: { fa: "نادیده گرفتن یک مشکل", en: "Ignore an issue" },
  ignoreBody: { fa: "مشکل نادیده‌گرفته‌شده در شمارش‌ها و هشدارها حساب نمی‌شود. حتماً دلیلش را بنویسید.", en: "An ignored issue isn't counted or alerted on. Always write why." },
  ignoreAdvisory: { fa: "شناسه مشکل (مثل CVE-2024-1234 یا CVE-2024-*)", en: "Issue id (like CVE-2024-1234 or CVE-2024-*)" },
  ignorePackage: { fa: "نام بسته (مثل «openssl» یا «lib*»)", en: "Package name (like openssl or lib*)" },
  ignoreImage: { fa: "برنامه (مثل nginx:*)؛ خالی یعنی همه برنامه‌ها", en: "App (like nginx:*); empty means every app" },
  ignoreReason: { fa: "چرا؟ (مثلاً «این بخش در برنامه ما استفاده نمی‌شود»)", en: "Why? (for example “we don't use this part”)" },
  ignoreUntil: { fa: "تا کی؟", en: "Until when?" },
  days30: { fa: "۳۰ روز", en: "30 days" },
  days90: { fa: "۹۰ روز", en: "90 days" },
  year1: { fa: "۱ سال", en: "1 year" },
  never: { fa: "همیشه", en: "Forever" },
  ignoreYes: { fa: "نادیده بگیر", en: "Ignore" },
  ignoreDone: { fa: "این مشکل نادیده گرفته شد.", en: "This issue is now ignored." },
  needReason: { fa: "دلیل را بنویسید.", en: "Write the reason." },
  needTarget: { fa: "دست‌کم شناسه مشکل یا نام بسته را بنویسید.", en: "Write at least the issue id or the package name." },
  cancel: { fa: "انصراف", en: "Cancel" },
  // ignore rules (Advanced)
  ignoresTitle: { fa: "مشکل‌های نادیده‌گرفته", en: "Ignored issues" },
  ignoresHint: { fa: "قاعده‌هایی که می‌گویند کدام مشکل‌ها شمرده نشوند.", en: "Rules that say which issues aren't counted." },
  ignoresEmpty: { fa: "هیچ مشکلی نادیده گرفته نشده.", en: "No issue is being ignored." },
  ignoresEmptyBody: { fa: "از فهرست مشکل‌های یک برنامه می‌توانید یکی را با دلیل نادیده بگیرید.", en: "From an app's issue list you can ignore one, with a reason." },
  any: { fa: "همه", en: "Any" },
  until: { fa: "تا", en: "Until" },
  expired: { fa: "تمام شده", en: "Ended" },
  active: { fa: "فعال", en: "Active" },
  removeIgnoreTitle: { fa: "این قاعده نادیده گرفتن پاک شود؟", en: "Delete this ignore rule?" },
  removeIgnoreBody: { fa: "مشکل‌هایی که با آن پنهان شده بودند دوباره شمرده می‌شوند.", en: "Issues it hid will count again." },
  remove: { fa: "پاک کن", en: "Delete" },
  // feeds (Advanced)
  feedsTitle: { fa: "فهرست‌های مشکلات امنیتی", en: "Security issue lists" },
  feedsHint: { fa: "MRK این فهرست‌ها را از OSV دانلود و روی همین سرور نگه می‌دارد.", en: "MRK downloads these lists from OSV and keeps them on this server." },
  feed: { fa: "فهرست", en: "List" },
  records: { fa: "تعداد مورد", en: "Entries" },
  size: { fa: "حجم", en: "Size" },
  updated: { fa: "به‌روز شده", en: "Updated" },
  checked: { fa: "آخرین بررسی", en: "Checked" },
  needed: { fa: "لازم", en: "Needed" },
  fOk: { fa: "آماده", en: "Ready" },
  fError: { fa: "مشکل دارد", en: "Has a problem" },
  fPending: { fa: "در نوبت", en: "Waiting" },
  // settings (Advanced)
  settingsTitle: { fa: "تنظیمات بررسی", en: "Check settings" },
  settingsHint: { fa: "کی و چطور برنامه‌ها بررسی شوند و برای چه چیزهایی خبرتان کنیم.", en: "When and how apps are checked, and what you're told about." },
  enabled: { fa: "بررسی خودکار روشن باشد", en: "Automatic checks are on" },
  interval: { fa: "هر چند ساعت یک بار بررسی شود", en: "Check every so many hours" },
  hours: { fa: "ساعت", en: "hours" },
  notify: { fa: "برای این شدت‌ها خبرم کن", en: "Tell me about these severities" },
  includeStopped: { fa: "برنامه‌های خاموش هم بررسی شوند", en: "Also check stopped apps" },
  extra: { fa: "این فهرست‌ها همیشه دانلود شوند (حتی اگر لازم نباشند)", en: "Always download these lists (even if not needed)" },
  feedUrl: { fa: "آدرس دانلود فهرست‌ها", en: "List download address" },
  feedMax: { fa: "بیشترین حجم هر فهرست", en: "Largest size per list" },
  mb: { fa: "مگابایت", en: "MB" },
  proxyLabel: { fa: "دانلود فهرست‌ها از پروکسی", en: "Download the lists through a proxy" },
  save: { fa: "ذخیره", en: "Save" },
  saved: { fa: "تنظیمات بررسی ذخیره شد.", en: "Check settings were saved." },
  moreSettings: { fa: "سقف‌ها و زمان‌بندی‌های داخلی", en: "Internal limits and timings" },
  moreSettingsHint: { fa: "مقدارهایی که فعلاً ثابت‌اند.", en: "Values that are fixed for now." },
  readOnly: { fa: "نقش شما فقط اجازه دیدن نتیجه‌ها را دارد.", en: "Your role can only view the results." }
} satisfies Record<string, Bi>;

/** Errors on this page use the catalog with this module's wording (copy/errors.ts `vuln:<code>`). */
function ErrorBox({ error, onClose, onRetry }: { error: unknown; onClose?: () => void; onRetry?: () => void }) {
  return <FriendlyError error={error} onClose={onClose} onRetry={onRetry} scope="vuln" />;
}

function statusInfo(language: Language, status: ImageStatus): { tone: Tone; label: string; icon: typeof GppGoodRoundedIcon } {
  if (status === "critical") return { tone: "error", label: pick(language, COPY.sCritical), icon: GppBadRoundedIcon };
  if (status === "warning") return { tone: "warn", label: pick(language, COPY.sWarning), icon: GppMaybeRoundedIcon };
  if (status === "error") return { tone: "error", label: pick(language, COPY.sError), icon: GppMaybeRoundedIcon };
  if (status === "unsupported") return { tone: "off", label: pick(language, COPY.sUnsupported), icon: GppMaybeRoundedIcon };
  return { tone: "ok", label: pick(language, COPY.sSecure), icon: GppGoodRoundedIcon };
}

function totalIssues(counts: Counts) {
  return SEVERITIES.reduce((sum, key) => sum + (counts[key] ?? 0), 0);
}

function advice(language: Language, image: ImageRecord) {
  if (image.status === "error") return say(language, COPY.doError, { reason: reasonFor(language, image.errors[0]?.code ?? null) });
  if (image.status === "unsupported") return pick(language, COPY.doUnsupported);
  if (image.status === "secure") return pick(language, COPY.doNothing);
  if (image.fixable > 0) return say(language, COPY.doFix, { n: formatNumber(image.fixable, language) });
  return pick(language, COPY.doWait);
}

function SeverityPill({ severity }: { severity: string }) {
  const { language } = useKit();
  const word = severityWord(language, severity);
  return <StatusPill tone={word.tone} label={word.label} />;
}

function advisoryHref(id: string) {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

// ── page ────────────────────────────────────────────────────────────────────

export default function VulnPanel({ permissions }: { permissions: readonly string[] }) {
  const { language, isAdvanced, c } = useKit();
  const canWrite = hasPermission(permissions, "vuln:write");
  const { notify, snackbar } = useUndoSnackbar();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [images, setImages] = useState<ImageRecord[]>([]);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [selected, setSelected] = useState<ImageRecord | null>(null);
  const [ignoreDraft, setIgnoreDraft] = useState<{ advisory: string; package: string; image: string } | null>(null);
  const [ignoresKey, setIgnoresKey] = useState(0);
  const [findingsKey, setFindingsKey] = useState(0);
  const [scanning, setScanning] = useState(false);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      const [nextSummary, nextImages] = await Promise.all([
        getJson<Summary>(`${API}/summary`, signal),
        getJson<{ items: ImageRecord[] }>(`${API}/images`, signal)
      ]);
      setSummary(nextSummary);
      setImages([...nextImages.items].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || totalIssues(b.counts) - totalIssues(a.counts)));
      setUnavailable(false);
      setLoadError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      if (caught instanceof ApiError && caught.status === 404) setUnavailable(true);
      else setLoadError(caught);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  // While a check runs, look again every 10 seconds.
  useEffect(() => {
    if (!summary?.running) return;
    const timer = window.setInterval(() => void load(), 10_000);
    return () => window.clearInterval(timer);
  }, [summary?.running, load]);

  const scan = async (fresh: boolean) => {
    setScanning(true);
    setActionError(null);
    try {
      const result = await mutateJson<{ started: boolean; running: boolean }>(`${API}/scan`, { method: "POST", body: fresh ? { refresh_inventory: true } : {} });
      notify({ message: pick(language, result?.started === false ? COPY.scanBusy : COPY.scanStarted), tone: result?.started === false ? "info" : "success" });
      await load();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    } finally {
      setScanning(false);
    }
  };

  if (unavailable) return <Notice>{pick(language, COPY.unavailable)}</Notice>;
  if (loadError !== null && !summary) return <FriendlyError error={loadError} onRetry={() => void load()} />;
  if (!summary) return <Stack sx={{ py: 4 }} alignItems="center"><CircularProgress /></Stack>;

  const counts = summary.counts;
  const verdict = (() => {
    if (!summary.enabled) return { tone: "off" as Tone, text: pick(language, COPY.off), icon: GppMaybeRoundedIcon };
    if (!summary.last_run_at && !summary.running) return { tone: "info" as Tone, text: pick(language, COPY.notYet), icon: GppMaybeRoundedIcon };
    if (counts.critical > 0) return { tone: "error" as Tone, text: say(language, COPY.critical, { n: counts.critical }), icon: GppBadRoundedIcon };
    if (counts.high > 0) return { tone: "error" as Tone, text: say(language, COPY.high, { n: counts.high }), icon: GppBadRoundedIcon };
    if (counts.medium > 0) return { tone: "warn" as Tone, text: say(language, COPY.medium, { n: counts.medium }), icon: GppMaybeRoundedIcon };
    return { tone: "ok" as Tone, text: pick(language, COPY.clean), icon: GppGoodRoundedIcon };
  })();
  const VerdictIcon = verdict.icon;
  const verdictColor = verdict.tone === "error" ? "error.main" : verdict.tone === "warn" ? "warning.main" : verdict.tone === "ok" ? "success.main" : "text.secondary";

  return (
    <Stack spacing={2.5}>
      {actionError !== null && <ErrorBox error={actionError} onClose={() => setActionError(null)} />}

      {/* ── verdict ── */}
      <SectionCard
        title={pick(language, COPY.verdictTitle)}
        status={summary.running ? <StatusPill tone="busy" label={pick(language, COPY.running)} /> : undefined}
        action={<Button size="small" onClick={() => void load()} disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} sx={{ minHeight: 44 }}>{c.refresh}</Button>}
      >
        <Stack spacing={2}>
          <Stack direction="row" spacing={1.5} alignItems="center">
            <VerdictIcon sx={{ color: verdictColor, fontSize: 40 }} aria-hidden />
            <Box>
              <Typography variant="h6" component="p" sx={{ fontWeight: 760, lineHeight: 1.5 }}>{verdict.text}</Typography>
              {summary.fixable > 0 && <Typography variant="body2" color="text.secondary">{say(language, COPY.fixableLine, { n: summary.fixable })}</Typography>}
              <Typography variant="caption" color="text.secondary">
                {pick(language, COPY.lastRun)}: <RelativeTime value={summary.last_run_at} />
                {summary.next_run_at ? <> · {pick(language, COPY.nextRun)}: <RelativeTime value={summary.next_run_at} relativeAlways /></> : null}
              </Typography>
            </Box>
          </Stack>
          {!summary.enabled && <Notice>{pick(language, COPY.offBody)}</Notice>}
          {!summary.agent_configured && (
            <Notice tone="warning" action={<Button color="inherit" size="small" href="#/server/overview?connect=agent">{pick(language, COPY.connectAgent)}</Button>}>
              {pick(language, COPY.noAgent)}
            </Notice>
          )}
          {summary.enabled && !summary.feeds_ready && <Notice>{pick(language, COPY.feedsNotReady)}</Notice>}
          {summary.last_error && <Notice tone="warning">{say(language, COPY.lastError, { reason: reasonFor(language, summary.last_error) })}</Notice>}
          <StatGrid>
            <StatTile label={pick(language, COPY.statCritical)} value={formatNumber(counts.critical, language)} tone={counts.critical ? "error" : undefined} />
            <StatTile label={pick(language, COPY.statHigh)} value={formatNumber(counts.high, language)} tone={counts.high ? "error" : undefined} />
            <StatTile label={pick(language, COPY.statMedium)} value={formatNumber(counts.medium, language)} tone={counts.medium ? "warn" : undefined} />
            {isAdvanced && <StatTile label={pick(language, COPY.statLow)} value={formatNumber(counts.low, language)} />}
            <StatTile label={pick(language, COPY.statFixable)} value={formatNumber(summary.fixable, language)} />
            {isAdvanced && <StatTile label={pick(language, COPY.statIgnored)} value={formatNumber(summary.ignored, language)} />}
          </StatGrid>
          {canWrite ? (
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
              <Button variant="contained" size="large" startIcon={scanning || summary.running ? <CircularProgress size={18} color="inherit" /> : <PlayArrowRoundedIcon />} disabled={scanning || summary.running || !summary.agent_configured} onClick={() => void scan(false)} sx={{ minHeight: 48 }}>
                {summary.running ? pick(language, COPY.running) : pick(language, COPY.scanNow)}
              </Button>
              {isAdvanced && (
                <Button variant="outlined" disabled={scanning || summary.running || !summary.agent_configured} onClick={() => void scan(true)} sx={{ minHeight: 48 }}>
                  {pick(language, COPY.scanFresh)}
                </Button>
              )}
            </Stack>
          ) : (
            <NoAccess needs="vuln:write" />
          )}
        </Stack>
      </SectionCard>

      {/* ── apps ── */}
      <SectionCard title={pick(language, COPY.appsTitle)} hint={pick(language, COPY.appsHint)} action={<HelpTip term="vulnerability" />}>
        {images.length === 0 ? (
          <EmptyState compact icon={GppGoodRoundedIcon} title={pick(language, COPY.appsEmpty)} body={pick(language, COPY.appsEmptyBody)} />
        ) : (
          <Grid container spacing={1.5}>
            {images.map((image) => {
              const info = statusInfo(language, image.status);
              const Icon = info.icon;
              const total = totalIssues(image.counts);
              return (
                <Grid key={image.image_id} size={{ xs: 12, md: 6, xl: 4 }}>
                  <Card variant="outlined" sx={{ height: "100%", borderInlineStartWidth: 4, borderInlineStartStyle: "solid", borderInlineStartColor: info.tone === "error" ? "error.main" : info.tone === "warn" ? "warning.main" : info.tone === "ok" ? "success.main" : "divider" }}>
                    <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={1}>
                        <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                          <Icon aria-hidden sx={{ color: info.tone === "error" ? "error.main" : info.tone === "warn" ? "warning.main" : info.tone === "ok" ? "success.main" : "text.disabled" }} />
                          <Typography fontWeight={760} noWrap title={image.image}><Ltr>{image.image}</Ltr></Typography>
                        </Stack>
                        <StatusPill tone={info.tone} label={info.label} />
                      </Stack>
                      {image.containers.length > 0 && (
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
                          {say(language, COPY.usedBy, { names: image.containers.map((item) => item.name).join("، ") })}
                        </Typography>
                      )}
                      {total > 0 && (
                        <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
                          {SEVERITIES.filter((key) => image.counts[key] > 0 && (isAdvanced || key !== "unknown")).map((key) => (
                            <Chip key={key} size="small" variant="outlined" label={`${severityWord(language, key).label}: ${formatNumber(image.counts[key], language)}`} />
                          ))}
                        </Stack>
                      )}
                      <Box sx={{ mt: 1.5, p: 1.25, borderRadius: 1, bgcolor: "action.hover" }}>
                        <Typography variant="caption" sx={{ fontWeight: 760 }}>{pick(language, COPY.whatToDo)}</Typography>
                        <Typography variant="body2" sx={{ lineHeight: 1.8 }}>{advice(language, image)}</Typography>
                      </Box>
                      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 1.5 }}>
                        {total > 0 && <Button size="small" variant="contained" onClick={() => setSelected(image)} sx={{ minHeight: 40 }}>{pick(language, COPY.seeIssues)}</Button>}
                        {image.fixable > 0 && <Button size="small" href="#/server/apps" sx={{ minHeight: 40 }}>{pick(language, COPY.redeploy)}</Button>}
                        {image.fixable > 0 && <Button size="small" href="#/server/updates" sx={{ minHeight: 40 }}>{pick(language, COPY.checkUpdates)}</Button>}
                      </Stack>
                      {isAdvanced && (
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                          <Ltr mono>{image.image_id.slice(0, 19)}</Ltr> · {image.os?.name ?? image.os?.id ?? "—"} · {formatNumber(image.packages_scanned, language)} · <RelativeTime value={image.scanned_at} />
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              );
            })}
          </Grid>
        )}
      </SectionCard>

      {selected && (
        <FindingsCard
          key={`${selected.image_id}-${findingsKey}`}
          image={selected}
          canWrite={canWrite}
          onClose={() => setSelected(null)}
          onIgnore={(finding) => setIgnoreDraft({ advisory: finding.id, package: finding.package, image: selected.image })}
          onChanged={() => {
            setIgnoresKey((value) => value + 1);
            void load();
          }}
        />
      )}

      {isAdvanced && (
        <IgnoresCard
          key={ignoresKey}
          canWrite={canWrite}
          onAdd={() => setIgnoreDraft({ advisory: "", package: "", image: "" })}
          onChanged={() => {
            setFindingsKey((value) => value + 1);
            void load();
          }}
        />
      )}
      {isAdvanced && <FeedsCard />}
      {isAdvanced && <VulnSettingsCard canWrite={canWrite} onSaved={() => { notify({ message: pick(language, COPY.saved) }); void load(); }} />}
      <RegistrySettings
        groups={["security.vuln"]}
        exclude={["vuln.enabled", "vuln.interval_hours", "vuln.ecosystems_extra", "vuln.feed_base_url", "vuln.severities_to_notify", "vuln.include_stopped", "vuln.proxy_id", "vuln.feed_max_mb"]}
        permissions={permissions}
        title={pick(language, COPY.moreSettings)}
        hint={pick(language, COPY.moreSettingsHint)}
      />

      {ignoreDraft && (
        <IgnoreDialog
          draft={ignoreDraft}
          onClose={() => setIgnoreDraft(null)}
          onDone={() => {
            setIgnoreDraft(null);
            notify({ message: pick(language, COPY.ignoreDone) });
            setIgnoresKey((value) => value + 1);
            setFindingsKey((value) => value + 1);
            void load();
          }}
        />
      )}
      {snackbar}
    </Stack>
  );
}

// ── findings of one app ─────────────────────────────────────────────────────

function FindingsCard({ image, canWrite, onClose, onIgnore, onChanged }: { image: ImageRecord; canWrite: boolean; onClose: () => void; onIgnore: (finding: Finding) => void; onChanged: () => void }) {
  const { language, isAdvanced } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const [severities, setSeverities] = useState<Severity[]>(["critical", "high", "medium"]);
  const [query, setQuery] = useState("");
  const [showIgnored, setShowIgnored] = useState(false);
  const [items, setItems] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    const timer = window.setTimeout(() => {
      const params = new URLSearchParams({ limit: "500" });
      if (severities.length && severities.length < SEVERITIES.length) params.set("severity", severities.join(","));
      if (query.trim()) params.set("q", query.trim());
      if (showIgnored) params.set("include_ignored", "1");
      void getJson<{ total: number; items: Finding[] }>(`${API}/images/${encodeURIComponent(image.image_id)}/findings?${params}`, controller.signal)
        .then((payload) => {
          setItems(payload.items);
          setTotal(payload.total);
          setError(null);
        })
        .catch((caught) => {
          if (!isAbortError(caught)) setError(caught);
        })
        .finally(() => {
          if (!controller.signal.aborted) setLoading(false);
        });
    }, 250);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [image.image_id, severities, query, showIgnored, tick]);

  const unignore = async (finding: Finding) => {
    if (!finding.ignore_id) return;
    try {
      await mutateJson(`${API}/ignores/${encodeURIComponent(finding.ignore_id)}`, { method: "DELETE" });
      notify({ message: pick(language, COPY.unignored) });
      setTick((value) => value + 1);
      onChanged();
    } catch (caught) {
      setError(caught);
    }
  };

  const toggleSeverity = (severity: Severity) =>
    setSeverities((current) => (current.includes(severity) ? current.filter((item) => item !== severity) : [...current, severity]));

  return (
    <SectionCard
      title={say(language, COPY.findingsTitle, { image: image.image })}
      hint={pick(language, COPY.findingsHint)}
      flush
      action={<Button size="small" onClick={onClose} sx={{ minHeight: 44 }}>{pick(language, COPY.closeFindings)}</Button>}
    >
      <Stack spacing={1.5} sx={{ p: 2, pb: 0 }}>
        <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} alignItems={{ md: "center" }}>
          <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
            {SEVERITIES.filter((key) => isAdvanced || key !== "unknown").map((key) => (
              <Chip
                key={key}
                clickable
                color={severities.includes(key) ? "primary" : "default"}
                variant={severities.includes(key) ? "filled" : "outlined"}
                label={severityWord(language, key).label}
                onClick={() => toggleSeverity(key)}
                aria-pressed={severities.includes(key)}
                sx={{ minHeight: 36 }}
              />
            ))}
          </Stack>
          <TextField
            size="small"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            label={pick(language, COPY.search)}
            slotProps={{ htmlInput: { dir: "ltr", maxLength: 200 }, input: { startAdornment: <InputAdornment position="start"><SearchRoundedIcon fontSize="small" /></InputAdornment> } }}
            sx={{ minWidth: { md: 240 } }}
          />
          <FormControlLabel control={<Switch checked={showIgnored} onChange={(_event, value) => setShowIgnored(value)} />} label={pick(language, COPY.showIgnored)} />
        </Stack>
        {error !== null && <ErrorBox error={error} onRetry={() => setTick((value) => value + 1)} />}
        {loading && <CircularProgress size={20} />}
      </Stack>
      <ResponsiveList<Finding>
        label={say(language, COPY.findingsTitle, { image: image.image })}
        rows={items}
        rowKey={(row) => `${row.id}:${row.package}:${row.installed}`}
        columns={[
          { key: "package", header: pick(language, COPY.package), render: (row) => <Ltr>{row.package}</Ltr> },
          { key: "severity", header: pick(language, COPY.severity), render: (row) => <Stack direction="row" spacing={0.5}><SeverityPill severity={row.severity} />{row.ignored && <StatusPill tone="off" label={pick(language, COPY.ignoredPill)} />}</Stack> },
          { key: "installed", header: pick(language, COPY.installed), render: (row) => <Ltr mono>{row.installed}</Ltr>, advancedOnly: true },
          { key: "fixed", header: pick(language, COPY.fixedIn), render: (row) => (row.fixed ? <Ltr mono>{row.fixed}</Ltr> : pick(language, COPY.notFixed)) },
          { key: "advisory", header: pick(language, COPY.advisory), render: (row) => (
            <Stack spacing={0.25}>
              <Link href={advisoryHref(row.id)} target="_blank" rel="noopener noreferrer"><Ltr mono>{row.id}</Ltr></Link>
              {row.aliases.filter((alias) => alias !== row.id).slice(0, 2).map((alias) => <Typography key={alias} variant="caption" color="text.secondary"><Ltr mono>{alias}</Ltr></Typography>)}
            </Stack>
          ), advancedOnly: true },
          { key: "score", header: pick(language, COPY.score), render: (row) => (row.score === null ? "—" : formatNumber(row.score, language, { maximumFractionDigits: 1 })), advancedOnly: true },
          { key: "summary", header: pick(language, COPY.summary), render: (row) => <Box component="span" dir="ltr" sx={{ display: "block", maxWidth: 360 }}>{row.summary ?? "—"}</Box>, advancedOnly: true, hideOnCard: true },
          { key: "location", header: pick(language, COPY.location), render: (row) => <Ltr mono>{row.location ?? row.ecosystem}</Ltr>, advancedOnly: true, hideOnCard: true },
          { key: "first", header: pick(language, COPY.firstSeen), render: (row) => <RelativeTime value={row.first_seen} />, advancedOnly: true }
        ]}
        card={{
          title: (row) => <Ltr>{row.package}</Ltr>,
          meta: (row) => (row.fixed ? <>{pick(language, COPY.fixedIn)}: <Ltr mono>{row.fixed}</Ltr></> : pick(language, COPY.notFixed)),
          status: (row) => <SeverityPill severity={row.severity} />
        }}
        actions={canWrite ? [
          { key: "ignore", label: pick(language, COPY.ignore), icon: VisibilityOffRoundedIcon, onClick: onIgnore, hidden: (row) => row.ignored },
          { key: "unignore", label: pick(language, COPY.unignore), icon: VisibilityRoundedIcon, onClick: (row) => void unignore(row), hidden: (row) => !row.ignored || !row.ignore_id }
        ] : undefined}
        empty={loading ? undefined : <EmptyState compact icon={SearchRoundedIcon} title={pick(language, COPY.findingsEmpty)} body={pick(language, COPY.findingsEmptyBody)} />}
      />
      {total > items.length && <Box sx={{ p: 2 }}><Notice>{say(language, COPY.more, { n: total - items.length })}</Notice></Box>}
      {snackbar}
    </SectionCard>
  );
}

// ── ignore an issue ─────────────────────────────────────────────────────────

const DAY = 86400;

function IgnoreDialog({ draft, onClose, onDone }: { draft: { advisory: string; package: string; image: string }; onClose: () => void; onDone: () => void }) {
  const { language, isAdvanced } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [advisory, setAdvisory] = useState(draft.advisory);
  const [pkg, setPkg] = useState(draft.package);
  const [image, setImage] = useState(draft.image);
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState<number | "never">(90);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const prefilled = Boolean(draft.advisory || draft.package);
  const editable = isAdvanced || !prefilled;

  const submit = async () => {
    if (!advisory.trim() && !pkg.trim()) return setProblem(pick(language, COPY.needTarget));
    if (!reason.trim()) return setProblem(pick(language, COPY.needReason));
    setProblem(null);
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = { reason: reason.trim() };
      if (advisory.trim()) body.advisory = advisory.trim();
      if (pkg.trim()) body.package = pkg.trim();
      if (image.trim()) body.image = image.trim();
      if (until !== "never") body.expires_at = Math.floor(Date.now() / 1000) + until * DAY;
      await mutateJson(`${API}/ignores`, { method: "POST", body });
      onDone();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onClose} fullWidth maxWidth="sm" fullScreen={fullScreen} aria-labelledby="mrk-vuln-ignore-title">
      <DialogTitle id="mrk-vuln-ignore-title">{pick(language, COPY.ignoreTitle)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <Typography variant="body2" color="text.secondary">{pick(language, COPY.ignoreBody)}</Typography>
          {!editable && (
            <Typography variant="body2"><Ltr mono>{draft.package}</Ltr> · <Ltr mono>{draft.advisory}</Ltr></Typography>
          )}
          {editable && (
            <>
              <TextField fullWidth label={pick(language, COPY.ignoreAdvisory)} value={advisory} onChange={(event) => setAdvisory(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
              <TextField fullWidth label={pick(language, COPY.ignorePackage)} value={pkg} onChange={(event) => setPkg(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
              <TextField fullWidth label={pick(language, COPY.ignoreImage)} value={image} onChange={(event) => setImage(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
            </>
          )}
          <TextField fullWidth required multiline minRows={2} label={pick(language, COPY.ignoreReason)} value={reason} onChange={(event) => setReason(event.target.value)} slotProps={{ htmlInput: { maxLength: 500, dir: "auto" } }} />
          <TextField select fullWidth label={pick(language, COPY.ignoreUntil)} value={until} onChange={(event) => setUntil(event.target.value === "never" ? "never" : Number(event.target.value))}>
            <MenuItem value={30}>{pick(language, COPY.days30)}</MenuItem>
            <MenuItem value={90}>{pick(language, COPY.days90)}</MenuItem>
            <MenuItem value={365}>{pick(language, COPY.year1)}</MenuItem>
            <MenuItem value="never">{pick(language, COPY.never)}</MenuItem>
          </TextField>
          {problem && <Notice tone="error">{problem}</Notice>}
          {error !== null && <ErrorBox error={error} />}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
        <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, COPY.cancel)}</Button>
        <Button variant="contained" disabled={busy} onClick={() => void submit()} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : <VisibilityOffRoundedIcon />} sx={{ minHeight: 44 }}>
          {pick(language, COPY.ignoreYes)}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Advanced: ignore rules ──────────────────────────────────────────────────

function IgnoresCard({ canWrite, onAdd, onChanged }: { canWrite: boolean; onAdd: () => void; onChanged: () => void }) {
  const { language } = useKit();
  const { ask, dialog } = useConfirmAction();
  const [items, setItems] = useState<IgnoreRule[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    try {
      setItems((await getJson<{ items: IgnoreRule[] }>(`${API}/ignores`)).items);
      setError(null);
    } catch (caught) {
      setError(caught);
    }
  }, []);
  useEffect(() => void load(), [load]);

  const remove = async (rule: IgnoreRule) => {
    const accepted = await ask({ title: pick(language, COPY.removeIgnoreTitle), body: pick(language, COPY.removeIgnoreBody), severity: "destructive", undoable: false, confirmLabel: pick(language, COPY.remove) });
    if (!accepted) return;
    try {
      await mutateJson(`${API}/ignores/${encodeURIComponent(rule.id)}`, { method: "DELETE" });
      await load();
      onChanged();
    } catch (caught) {
      setError(caught);
    }
  };

  return (
    <SectionCard
      title={pick(language, COPY.ignoresTitle)}
      hint={pick(language, COPY.ignoresHint)}
      flush
      collapsible
      action={canWrite ? <Button size="small" startIcon={<VisibilityOffRoundedIcon />} onClick={onAdd} sx={{ minHeight: 44 }}>{pick(language, COPY.ignore)}</Button> : undefined}
    >
      {error !== null && <Box sx={{ p: 2 }}><ErrorBox error={error} onRetry={() => void load()} /></Box>}
      <ResponsiveList<IgnoreRule>
        label={pick(language, COPY.ignoresTitle)}
        rows={items ?? []}
        rowKey={(row) => row.id}
        columns={[
          { key: "advisory", header: pick(language, COPY.advisory), render: (row) => (row.advisory ? <Ltr mono>{row.advisory}</Ltr> : pick(language, COPY.any)) },
          { key: "package", header: pick(language, COPY.package), render: (row) => (row.package ? <Ltr mono>{row.package}</Ltr> : pick(language, COPY.any)) },
          { key: "image", header: pick(language, COPY.appsTitle), render: (row) => (row.image ? <Ltr mono>{row.image}</Ltr> : pick(language, COPY.any)) },
          { key: "reason", header: pick(language, COPY.summary), render: (row) => <Box component="span" dir="auto">{row.reason}</Box> },
          { key: "until", header: pick(language, COPY.until), render: (row) => (row.expires_at ? <RelativeTime value={row.expires_at} relativeAlways /> : pick(language, COPY.never)) },
          { key: "state", header: pick(language, COPY.severity), render: (row) => <StatusPill tone={row.expired ? "off" : "ok"} label={pick(language, row.expired ? COPY.expired : COPY.active)} /> }
        ]}
        card={{
          title: (row) => <Ltr mono>{row.advisory ?? row.package ?? "*"}</Ltr>,
          meta: (row) => <Box component="span" dir="auto">{row.reason}</Box>,
          status: (row) => <StatusPill tone={row.expired ? "off" : "ok"} label={pick(language, row.expired ? COPY.expired : COPY.active)} />
        }}
        actions={canWrite ? [{ key: "delete", label: pick(language, COPY.remove), icon: DeleteOutlineRoundedIcon, onClick: (row) => void remove(row), danger: true }] : undefined}
        empty={<EmptyState compact icon={VisibilityRoundedIcon} title={pick(language, COPY.ignoresEmpty)} body={pick(language, COPY.ignoresEmptyBody)} />}
      />
      {dialog}
    </SectionCard>
  );
}

// ── Advanced: feeds ─────────────────────────────────────────────────────────

function FeedsCard() {
  const { language } = useKit();
  const [feeds, setFeeds] = useState<Feed[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    void getJson<{ items: Feed[] }>(`${API}/feeds`).then((payload) => setFeeds(payload.items), setError);
  }, []);
  const pill = (feed: Feed) =>
    feed.status === "ok" ? <StatusPill tone="ok" label={pick(language, COPY.fOk)} />
      : feed.status === "error" ? <StatusPill tone="error" label={pick(language, COPY.fError)} />
        : <StatusPill tone="info" label={pick(language, COPY.fPending)} />;
  return (
    <SectionCard title={pick(language, COPY.feedsTitle)} hint={pick(language, COPY.feedsHint)} flush collapsible defaultCollapsed>
      {error !== null && <Box sx={{ p: 2 }}><FriendlyError error={error} /></Box>}
      <ResponsiveList<Feed>
        label={pick(language, COPY.feedsTitle)}
        rows={feeds ?? []}
        rowKey={(row) => row.ecosystem}
        columns={[
          { key: "eco", header: pick(language, COPY.feed), render: (row) => <Ltr>{row.ecosystem}</Ltr> },
          { key: "needed", header: pick(language, COPY.needed), render: (row) => (row.needed ? "✓" : "—") },
          { key: "records", header: pick(language, COPY.records), render: (row) => formatNumber(row.records, language) },
          { key: "size", header: pick(language, COPY.size), render: (row) => <Bytes value={row.size} /> },
          { key: "updated", header: pick(language, COPY.updated), render: (row) => <RelativeTime value={row.updated_at} /> },
          { key: "checked", header: pick(language, COPY.checked), render: (row) => <RelativeTime value={row.checked_at} /> },
          { key: "state", header: pick(language, COPY.severity), render: (row) => <Stack spacing={0.25}>{pill(row)}{row.error && <Typography variant="caption" color="text.secondary">{reasonFor(language, row.error)}</Typography>}</Stack> }
        ]}
        card={{ title: (row) => <Ltr>{row.ecosystem}</Ltr>, meta: (row) => <RelativeTime value={row.updated_at} />, status: pill }}
      />
    </SectionCard>
  );
}

// ── Advanced: settings ──────────────────────────────────────────────────────

function VulnSettingsCard({ canWrite, onSaved }: { canWrite: boolean; onSaved: () => void }) {
  const { language } = useKit();
  const { list: proxyList, failed: proxyFailed } = useProxyList();
  const [settings, setSettings] = useState<VulnSettings | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    void getJson<VulnSettings>(`${API}/settings`).then(setSettings, setError);
  }, []);
  const patch = (next: Partial<VulnSettings>) => setSettings((current) => (current ? { ...current, ...next } : current));
  const valid = useMemo(() => Boolean(settings && settings.interval_hours >= 1 && settings.interval_hours <= 720 && settings.feed_max_mb >= 16 && settings.feed_max_mb <= 4096), [settings]);

  const save = async () => {
    if (!settings || !valid) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await mutateJson<VulnSettings>(`${API}/settings`, { method: "PUT", body: settings });
      if (saved) setSettings(saved);
      onSaved();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const toggle = (list: string[], value: string) => (list.includes(value) ? list.filter((item) => item !== value) : [...list, value]);
  const disabled = !canWrite || busy;

  return (
    <SectionCard title={pick(language, COPY.settingsTitle)} hint={pick(language, COPY.settingsHint)} collapsible>
      {error !== null && <ErrorBox error={error} onClose={() => setError(null)} />}
      {settings && (
        <Stack spacing={2}>
          <FormControlLabel control={<Switch checked={settings.enabled} disabled={disabled} onChange={(_event, value) => patch({ enabled: value })} />} label={pick(language, COPY.enabled)} />
          <Box sx={{ maxWidth: 320 }}>
            <NumberInput label={pick(language, COPY.interval)} value={settings.interval_hours} onChange={(value) => patch({ interval_hours: value ?? 0 })} min={1} max={720} integer unit={pick(language, COPY.hours)} disabled={disabled} />
          </Box>
          <Box>
            <Typography variant="body2" sx={{ fontWeight: 650 }}>{pick(language, COPY.notify)}</Typography>
            <FormGroup row>
              {(["critical", "high", "medium", "low"] as const).map((severity) => (
                <FormControlLabel key={severity} control={<Checkbox checked={settings.severities_to_notify.includes(severity)} disabled={disabled} onChange={() => patch({ severities_to_notify: toggle(settings.severities_to_notify, severity) })} />} label={severityWord(language, severity).label} />
              ))}
            </FormGroup>
          </Box>
          <FormControlLabel control={<Switch checked={settings.include_stopped} disabled={disabled} onChange={(_event, value) => patch({ include_stopped: value })} />} label={pick(language, COPY.includeStopped)} />
          <Box>
            <Typography variant="body2" sx={{ fontWeight: 650 }}>{pick(language, COPY.extra)}</Typography>
            <FormGroup row>
              {EXTRA_ECOSYSTEMS.map((eco) => (
                <FormControlLabel key={eco} control={<Checkbox checked={settings.ecosystems_extra.includes(eco)} disabled={disabled} onChange={() => patch({ ecosystems_extra: toggle(settings.ecosystems_extra, eco) })} />} label={<Ltr>{eco}</Ltr>} />
              ))}
            </FormGroup>
          </Box>
          <TextField fullWidth label={pick(language, COPY.feedUrl)} value={settings.feed_base_url} disabled={disabled} onChange={(event) => patch({ feed_base_url: event.target.value })} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
          <Box sx={{ maxWidth: 320 }}>
            <NumberInput label={pick(language, COPY.feedMax)} value={settings.feed_max_mb} onChange={(value) => patch({ feed_max_mb: value ?? 0 })} min={16} max={4096} integer unit={pick(language, COPY.mb)} disabled={disabled} />
          </Box>
          {!proxyFailed && (
            <Box>
              <Typography variant="body2" sx={{ fontWeight: 650, mb: 1 }}>{pick(language, COPY.proxyLabel)}</Typography>
              <ProxyPicker language={language} list={proxyList} value={choiceFromApi(settings.proxy_id)} onChange={(value) => patch({ proxy_id: choiceToApi(value) })} supported={PROXY_TYPES} advanced disabled={disabled} size="medium" />
            </Box>
          )}
          {!canWrite && <NoAccess needs="vuln:write" />}
          <Box>
            <Button variant="contained" disabled={disabled || !valid} onClick={() => void save()} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
              {pick(language, COPY.save)}
            </Button>
          </Box>
          <Typography variant="caption" color="text.secondary">{termWithEnglish(language, "vulnerability")}</Typography>
        </Stack>
      )}
    </SectionCard>
  );
}
