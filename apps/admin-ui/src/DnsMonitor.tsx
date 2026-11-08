/**
 * «DNS › پایش» (#/dns/monitor, dns:read; contract docs/38 §4–§5).
 *
 * - One big sentence in the pressure level's colour with the reasons in plain words, plus what MRK
 *   is doing about it right now (`GET pressure`, every 5 s).
 * - Live charts (questions per second, slow answers, answered from memory, errors) over a range.
 * - Busiest names / devices / "not found" names with «کند کن / مسدود کن» (names need dns:logs).
 * - Detected attacks with «جلویش را بگیر», active limits with «برداشتن», recent events.
 * - Advanced: load levels, automatic steps and attack detection (saved into the DNS settings).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Box, Button, CircularProgress, Divider, FormControlLabel, LinearProgress, Paper, Stack, Switch, ToggleButton, ToggleButtonGroup, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";
import SpeedRoundedIcon from "@mui/icons-material/SpeedRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import VisibilityOffRoundedIcon from "@mui/icons-material/VisibilityOffRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import { ApiError, hasPermission, isAbortError } from "./api";
import { errorSentence, pick, say, severityWord, type Bi } from "./copy";
import { LineChart, type ChartWords } from "./charts";
import { formatDateTime, formatNumber, formatPercent, toUnixSeconds } from "./format";
import {
  ChoiceCards, DurationInput, EmptyState, FriendlyError, KeyValueList, Ltr, NoAccess, Notice, NumberInput, RangeToggle, RelativeTime, ResponsiveList,
  SectionCard, StatusPill, helperProblem, useConfirmAction, useKit, useUndoSnackbar, type ListColumn
} from "./kit";
import { useVisibleInterval } from "./polling";
import { DnsAvailability } from "./DnsPage";
import { engineReady, formatQps, useDnsStatus } from "./dns";
import {
  ACTION_WORDS, ALL_RANGES, DEFAULT_PRESSURE, LEVEL_WORDS, MITIGATION_ACTION_WORDS, MITIGATION_KIND_WORDS, SIMPLE_RANGES, actionText, cachePercent,
  createMitigation, deleteMitigation, errorPercent, eventText, fetchDnsEvents, fetchMitigations, fetchPressure, fetchStats, hotCount, hotList, minutesWord,
  pressureLevel, pressureSentence, type DnsAttack, type DnsEvent, type DnsPressure, type DnsStats, type Mitigation, type PressureSettings, type StatsRange,
  type Thresholds
} from "./dnsLive";
import { MitigateDialog, type MitigateTarget } from "./DnsMitigate";
import { DnsSectionSettings } from "./DnsSectionSettings";

const COPY = {
  // pressure
  pressureTitle: { fa: "حال DNS همین الان", en: "How DNS is doing right now" },
  since: { fa: "از {when}", en: "Since {when}" },
  doing: { fa: "کاری که MRK الان برای سبک ماندن DNS می‌کند:", en: "What MRK is doing right now to keep DNS light:" },
  nothingToDo: { fa: "نیازی به کار خاصی نیست.", en: "Nothing special is needed." },
  pressureFailed: { fa: "حال DNS خوانده نشد.", en: "DNS load didn't load." },
  notSupported: { fa: "برنامه DNS روی سرور هنوز پایش را ندارد. MRK و برنامه DNS را به‌روز کنید.", en: "The DNS program on the server doesn't have monitoring yet. Update MRK and the DNS program." },
  hotHidden: { fa: "{domains} نام و {clients} دستگاه الان خیلی پرسش می‌فرستند. برای دیدن نام‌ها و نشانی‌ها، اجازه «دیدن پرسش‌های DNS» لازم است.", en: "{domains} names and {clients} devices are very busy right now. Seeing which ones needs the “See DNS questions” permission." },
  technical: { fa: "عددهای فنی", en: "Technical numbers" },
  mCpu: { fa: "پردازنده برنامه DNS", en: "DNS program CPU" },
  mMemory: { fa: "حافظه برنامه DNS", en: "DNS program memory" },
  mQps: { fa: "پرسش در ثانیه", en: "Questions per second" },
  mQpsPercent: { fa: "نسبت به ظرفیت", en: "Of capacity" },
  mInflight: { fa: "پرسش‌های منتظر DNS بیرونی", en: "Waiting for outside DNS" },
  mDrops: { fa: "بی‌جواب در دقیقه گذشته", en: "Unanswered in the last minute" },
  mHostCpu: { fa: "پردازنده سرور", en: "Server CPU" },
  mHostMemory: { fa: "حافظه سرور", en: "Server memory" },
  mHostAt: { fa: "آخرین خبر از دستیار سرور", en: "Last report from the server helper" },
  // charts
  chartsTitle: { fa: "پرسش‌ها در طول زمان", en: "Questions over time" },
  rangeLabel: { fa: "بازه زمانی", en: "Time range" },
  qps: { fa: "پرسش در ثانیه", en: "Questions per second" },
  p95: { fa: "زمان جواب (کندترین‌ها)", en: "Answer time (slowest)" },
  p95Hint: { fa: "۹۵ درصد پرسش‌ها زودتر از این جواب گرفتند.", en: "95 out of 100 questions were answered faster than this." },
  hit: { fa: "جواب از حافظه", en: "Answered from memory" },
  hitHint: { fa: "هر چه بیشتر، سریع‌تر.", en: "Higher is faster." },
  errors: { fa: "خطا یا رد شده", en: "Errors or refused" },
  errorsHint: { fa: "پرسش‌هایی که جواب درست نگرفتند.", en: "Questions that didn't get a proper answer." },
  noData: { fa: "هنوز آماری در این بازه نیست", en: "No numbers in this range yet" },
  statsFailed: { fa: "آمار DNS خوانده نشد.", en: "DNS numbers didn't load." },
  totalInRange: { fa: "در این بازه {count} پرسش جواب داده شد.", en: "{count} questions were answered in this range." },
  // top
  topTitle: { fa: "پرمصرف‌ترین‌ها", en: "Busiest" },
  topHint: { fa: "در بازه‌ای که بالا انتخاب کرده‌اید.", en: "In the range you picked above." },
  topDomains: { fa: "نام‌ها", en: "Names" },
  topClients: { fa: "دستگاه‌ها", en: "Devices" },
  topNx: { fa: "«پیدا نشد»ها", en: "“Not found”" },
  topNxHint: { fa: "نام‌هایی که زیاد پرسیده شدند ولی وجود ندارند؛ اگر خیلی زیاد و عجیب باشند، شاید حمله است.", en: "Names asked a lot that don't exist; if there are many odd ones, it may be an attack." },
  topHidden: { fa: "این فهرست نشان می‌دهد چه کسی چه چیزی پرسیده، پس فقط با اجازه «دیدن پرسش‌های DNS» دیده می‌شود.", en: "This list shows who asked what, so it needs the “See DNS questions” permission." },
  topEmpty: { fa: "هنوز چیزی برای نشان دادن نیست.", en: "Nothing to show yet." },
  times: { fa: "{count} بار", en: "{count} times" },
  throttle: { fa: "کند کن", en: "Slow down" },
  block: { fa: "مسدود کن", en: "Block" },
  name: { fa: "نام", en: "Name" },
  device: { fa: "دستگاه", en: "Device" },
  count: { fa: "تعداد", en: "Count" },
  limited: { fa: "محدود شده", en: "Limited" },
  // attacks
  attacksTitle: { fa: "حمله‌های دیده‌شده", en: "Attacks seen" },
  attacksHint: { fa: "وقتی کسی تعداد زیادی نام ساختگی می‌پرسد تا DNS را خسته کند.", en: "When someone asks lots of made-up names to wear DNS out." },
  noAttacks: { fa: "هیچ حمله‌ای دیده نشده است.", en: "No attacks have been seen." },
  attackLine: { fa: "در هر دقیقه {count} نام ساختگی تازه زیر این نام پرسیده می‌شود.", en: "{count} new made-up names under this name are asked every minute." },
  attackFrom: { fa: "بیشتر از:", en: "Mostly from:" },
  attackHiddenCount: { fa: "{count} حمله دیده شده. برای دیدن نام‌ها، اجازه «دیدن پرسش‌های DNS» لازم است.", en: "Attacks seen: {count}. Seeing the names needs the “See DNS questions” permission." },
  stopIt: { fa: "جلویش را بگیر", en: "Stop it" },
  stopped: { fa: "جلویش گرفته شده", en: "Being stopped" },
  stopTitle: { fa: "جلوی حمله به «{name}» گرفته شود؟", en: "Stop the attack on “{name}”?" },
  stopBody: { fa: "تا {minutes} همه نام‌های زیر «{name}» جواب «چنین نامی نیست» می‌گیرند و به اینترنت فرستاده نمی‌شوند. اگر خود این نام برایتان مهم است، به‌جای این کار دستگاه حمله‌کننده را مسدود کنید.", en: "For {minutes}, every name under “{name}” gets “no such name” and isn't sent to the internet. If this name matters to you, block the attacking device instead." },
  stopYes: { fa: "بله، جلویش را بگیر", en: "Yes, stop it" },
  stoppedToast: { fa: "جلوی حمله به «{name}» گرفته شد.", en: "The attack on “{name}” is being stopped." },
  // mitigations
  limitsTitle: { fa: "محدودسازی‌های فعال", en: "Active limits" },
  limitsHint: { fa: "دستگاه‌ها و نام‌هایی که الان کند یا مسدود شده‌اند؛ وقتشان که تمام شود خودکار برداشته می‌شوند.", en: "Devices and names slowed down or blocked right now; they're removed automatically when their time is up." },
  limitsEmpty: { fa: "الان هیچ دستگاه یا نامی محدود نشده است.", en: "Nothing is limited right now." },
  limitsFailed: { fa: "فهرست محدودسازی‌ها خوانده نشد.", en: "The list of limits didn't load." },
  what: { fa: "چه چیزی", en: "What" },
  how: { fa: "چه شده", en: "How" },
  bySource: { fa: "توسط", en: "By" },
  byUser: { fa: "شما", en: "You" },
  byAuto: { fa: "MRK خودکار", en: "MRK, automatically" },
  until: { fa: "تا", en: "Until" },
  hits: { fa: "جلوگیری‌شده", en: "Stopped" },
  perSecond: { fa: "{qps} در ثانیه", en: "{qps} per second" },
  reason: { fa: "یادداشت", en: "Note" },
  remove: { fa: "برداشتن", en: "Remove" },
  removeTitle: { fa: "محدودیت «{name}» برداشته شود؟", en: "Remove the limit on “{name}”?" },
  removeBody: { fa: "از همین حالا دوباره عادی جواب می‌گیرد.", en: "It gets normal answers again right away." },
  removeYes: { fa: "بله، بردار", en: "Yes, remove" },
  removed: { fa: "محدودیت «{name}» برداشته شد.", en: "The limit on “{name}” was removed." },
  added: { fa: "محدودیت «{name}» گذاشته شد.", en: "A limit was set on “{name}”." },
  // events
  eventsTitle: { fa: "رخدادهای اخیر", en: "Recent events" },
  eventsEmpty: { fa: "هنوز رخدادی ثبت نشده است.", en: "No events yet." },
  // settings
  settingsTitle: { fa: "سطح‌های فشار و کارهای خودکار", en: "Load levels and automatic steps" },
  settingsHint: { fa: "MRK از روی این عددها می‌فهمد DNS کی شلوغ است و چه کاری خودکار انجام دهد.", en: "MRK uses these numbers to tell when DNS is busy and what to do automatically." },
  enabled: { fa: "پایش فشار روشن باشد", en: "Watch the load" },
  capacity: { fa: "ظرفیت این سرور (پرسش در ثانیه)", en: "This server's capacity (questions per second)" },
  capacityHint: { fa: "بیشترین پرسشی که این سرور راحت جواب می‌دهد؛ درصدهای پایین از روی همین حساب می‌شوند.", en: "The most questions this server answers comfortably; the percentages below are based on it." },
  dwell: { fa: "دست‌کم این مدت در هر سطح بماند", en: "Stay in each level at least" },
  dwellHint: { fa: "تا سطح فشار مدام بالا و پایین نشود.", en: "So the level doesn't flip back and forth." },
  exitMargin: { fa: "برای برگشتن، چند درصد پایین‌تر از حد", en: "To go back, this many percent under the limit" },
  levelsTitle: { fa: "از چه وقت هر سطح شروع شود (درصد)", en: "When each level starts (percent)" },
  tCpu: { fa: "پردازنده DNS", en: "DNS CPU" },
  tMemory: { fa: "حافظه DNS", en: "DNS memory" },
  tQps: { fa: "پرسش‌ها از ظرفیت", en: "Questions of capacity" },
  tHostCpu: { fa: "پردازنده سرور", en: "Server CPU" },
  tHostMemory: { fa: "حافظه سرور", en: "Server memory" },
  order: { fa: "عدد هر سطح باید از سطح قبلی بیشتر باشد.", en: "Each level's number must be higher than the one before." },
  actionsTitle: { fa: "کارهایی که MRK زیر فشار خودکار انجام دهد", en: "Steps MRK may take automatically under load" },
  attackTitle: { fa: "تشخیص حمله", en: "Attack detection" },
  modeOff: { fa: "خاموش", en: "Off" },
  modeOffBody: { fa: "حمله‌ها تشخیص داده نمی‌شوند.", en: "Attacks aren't detected." },
  modeSuggest: { fa: "فقط خبرم کن", en: "Just tell me" },
  modeSuggestBody: { fa: "پیشنهاد ما: خبر می‌دهد و شما با یک دکمه جلویش را می‌گیرید.", en: "Our suggestion: it tells you and you stop it with one button." },
  modeAuto: { fa: "خودکار جلویش را بگیر", en: "Stop it automatically" },
  modeAutoBody: { fa: "MRK خودش برای مدتی جلوی حمله را می‌گیرد و خبرتان می‌کند.", en: "MRK stops it for a while by itself and tells you." },
  nxPerMinute: { fa: "حمله یعنی بیش از این تعداد نام ساختگی تازه در دقیقه", en: "An attack means more than this many new made-up names a minute" },
  mitigationMinutes: { fa: "جلوگیری خودکار تا چه مدت", en: "Stop automatically for" }
} satisfies Record<string, Bi>;

const WORDS: Record<"fa" | "en", ChartWords> = {
  fa: { now: "الان", lowest: "کمترین", average: "میانگین", highest: "بیشترین", separator: "؛ " },
  en: { now: "now", lowest: "lowest", average: "average", highest: "highest", separator: "; " }
};
const RANGE_WORDS: Record<StatsRange, Bi> = {
  "1h": { fa: "۱ ساعت", en: "1 hour" },
  "6h": { fa: "۶ ساعت", en: "6 hours" },
  "24h": { fa: "۲۴ ساعت", en: "24 hours" },
  "7d": { fa: "۷ روز", en: "7 days" },
  "30d": { fa: "۳۰ روز", en: "30 days" },
  "1y": { fa: "۱ سال", en: "1 year" }
};
const POLL_MS: Record<StatsRange, number> = { "1h": 15_000, "6h": 30_000, "24h": 60_000, "7d": 300_000, "30d": 300_000, "1y": 600_000 };
const COLORS = { qps: "#3b82f6", p95: "#8b5cf6", hit: "#10b981", errors: "#ef4444" };
const RANGE_KEY = "mrk-dns-range";

function readRange(allowed: StatsRange[]): StatsRange {
  try {
    const value = window.localStorage.getItem(RANGE_KEY) as StatsRange | null;
    if (value && allowed.includes(value)) return value;
  } catch {
    // storage unavailable
  }
  return "24h";
}

function isMissing(error: unknown) {
  return error instanceof ApiError && error.status === 404 && (!error.code || error.code === "not_found");
}

/** Poll a loader while the tab is visible; keeps the last good value on errors. */
function usePolled<T>(loader: (signal: AbortSignal) => Promise<T>, pollMs: number | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      setData(await loader(current.signal));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
    // `loader` is rebuilt from `deps`.
  }, deps);
  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);
  useVisibleInterval(() => void load(), pollMs);
  return { data, error, loading, reload: load, setData };
}

// ── pressure ─────────────────────────────────────────────────────────────────

function PressureCard({ pressure, error, onRetry }: { pressure: DnsPressure | null; error: unknown; onRetry: () => void }) {
  const { language, isAdvanced } = useKit();
  const theme = useTheme();
  if (error && !pressure) {
    if (isMissing(error) || helperProblem(error) === "module_missing") return <Notice tone="info">{pick(language, COPY.notSupported)}</Notice>;
    return <FriendlyError error={error} title={pick(language, COPY.pressureFailed)} onRetry={onRetry} scope="dns" />;
  }
  const level = pressureLevel(pressure?.level);
  const words = LEVEL_WORDS[level];
  const color = theme.palette[words.color].main;
  const actions = pressure?.active_actions ?? [];
  const metrics = pressure?.metrics ?? {};
  const hidden = Boolean(pressure?.hot?.hidden) || typeof pressure?.hot?.domains === "number" || typeof pressure?.hot?.clients === "number";
  const busyDomains = hotCount(pressure?.hot?.domains ?? null);
  const busyClients = hotCount(pressure?.hot?.clients ?? null);
  const pct = (value: number | null | undefined) => (typeof value === "number" ? formatPercent(value, language) : "—");

  return (
    <Paper
      variant="outlined"
      sx={{ p: { xs: 2, sm: 2.5 }, borderColor: alpha(color, 0.5), borderInlineStartWidth: 6, bgcolor: alpha(color, theme.palette.mode === "dark" ? 0.12 : 0.06) }}
      aria-live="polite"
    >
      <Stack spacing={1.5}>
        <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap" justifyContent="space-between">
          <Typography variant="subtitle2" color="text.secondary" sx={{ fontWeight: 700 }}>{pick(language, COPY.pressureTitle)}</Typography>
          {pressure ? <StatusPill tone={words.tone} label={pick(language, words.label)} size="medium" /> : <CircularProgress size={18} aria-hidden />}
        </Stack>
        <Typography variant="h5" component="p" sx={{ fontWeight: 760, lineHeight: 1.7, color: level === "normal" ? "text.primary" : color, fontSize: { xs: "1.2rem", sm: "1.5rem" } }}>
          {pressureSentence(language, pressure)}
        </Typography>
        {pressure && level !== "normal" && pressure.since ? (
          <Typography variant="caption" color="text.secondary">
            {pick(language, { fa: "از", en: "Since" })} <RelativeTime value={pressure.since} relativeAlways />
          </Typography>
        ) : null}
        {pressure && (level !== "normal" || actions.length > 0) ? (
          <Box>
            <Typography variant="body2" sx={{ fontWeight: 700, mb: 0.5 }}>{pick(language, COPY.doing)}</Typography>
            {actions.length ? (
              <Stack component="ul" spacing={0.5} sx={{ m: 0, ps: 2.5 }}>
                {actions.map((action) => (
                  <Typography component="li" variant="body2" key={action} sx={{ lineHeight: 1.8 }}>{actionText(language, action)}</Typography>
                ))}
              </Stack>
            ) : (
              <Typography variant="body2" color="text.secondary">{pick(language, COPY.nothingToDo)}</Typography>
            )}
          </Box>
        ) : null}
        {hidden && (busyDomains || busyClients) && level !== "normal" ? (
          <Stack direction="row" gap={1} alignItems="flex-start">
            <VisibilityOffRoundedIcon fontSize="small" color="action" aria-hidden sx={{ mt: 0.25 }} />
            <Typography variant="body2" color="text.secondary">{say(language, COPY.hotHidden, { domains: busyDomains, clients: busyClients })}</Typography>
          </Stack>
        ) : null}
        {isAdvanced && pressure ? (
          <>
            <Divider />
            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{pick(language, COPY.technical)}</Typography>
            <KeyValueList
              dense
              items={[
                { label: pick(language, COPY.mCpu), value: pct(metrics.cpu_percent) },
                { label: pick(language, COPY.mMemory), value: pct(metrics.memory_percent) },
                { label: pick(language, COPY.mQps), value: formatQps(language, metrics.qps) },
                { label: pick(language, COPY.mQpsPercent), value: pct(metrics.qps_percent) },
                { label: pick(language, COPY.mInflight), value: formatNumber(metrics.inflight_upstream, language) },
                { label: pick(language, COPY.mDrops), value: formatNumber(metrics.drops_1m, language) },
                ...(typeof metrics.host_cpu_percent === "number" ? [{ label: pick(language, COPY.mHostCpu), value: pct(metrics.host_cpu_percent) }] : []),
                ...(typeof metrics.host_memory_percent === "number" ? [{ label: pick(language, COPY.mHostMemory), value: pct(metrics.host_memory_percent) }] : []),
                ...(metrics.host_metrics_at ? [{ label: pick(language, COPY.mHostAt), value: <RelativeTime value={metrics.host_metrics_at} relativeAlways /> }] : [])
              ]}
            />
          </>
        ) : null}
      </Stack>
    </Paper>
  );
}

// ── charts ───────────────────────────────────────────────────────────────────

function ChartsCard({ stats, error, loading, range, ranges, onRange, onRetry }: {
  stats: DnsStats | null; error: unknown; loading: boolean; range: StatsRange; ranges: StatsRange[]; onRange: (range: StatsRange) => void; onRetry: () => void;
}) {
  const { language } = useKit();
  const points = useMemo(() => (stats?.points ?? []).map((point) => ({ ...point, t: toUnixSeconds(point.ts) })).filter((point) => point.t !== null), [stats]);
  const times = useMemo(() => points.map((point) => point.t as number), [points]);
  const short = range === "1h" || range === "6h" || range === "24h";
  const formatX = (ts: number) => formatDateTime(ts, language, short ? { hour: "2-digit", minute: "2-digit" } : range === "1y" ? { month: "short" } : { month: "short", day: "numeric" });
  const formatTooltipX = (ts: number) => formatDateTime(ts, language, { dateStyle: "medium", timeStyle: "short" });
  const pct = (value: number) => formatPercent(value, language);
  const ms = (value: number) => `${formatNumber(value, language, { maximumFractionDigits: value < 10 ? 1 : 0 })} ${language === "fa" ? "میلی‌ثانیه" : "ms"}`;
  const common = { times, formatX, formatTooltipX, emptyText: pick(language, COPY.noData), height: 180, words: WORDS[language], showSummary: true };
  const label = pick(language, RANGE_WORDS[range]);
  const total = stats?.totals?.queries;

  const charts = [
    { key: "qps", title: COPY.qps, hint: null, color: COLORS.qps, values: points.map((point) => point.qps ?? null), format: (value: number) => formatQps(language, value), yMax: undefined },
    { key: "p95", title: COPY.p95, hint: COPY.p95Hint, color: COLORS.p95, values: points.map((point) => point.p95_ms ?? null), format: ms, yMax: undefined },
    { key: "hit", title: COPY.hit, hint: COPY.hitHint, color: COLORS.hit, values: points.map((point) => cachePercent(point)), format: pct, yMax: 100 },
    { key: "errors", title: COPY.errors, hint: COPY.errorsHint, color: COLORS.errors, values: points.map((point) => errorPercent(point)), format: pct, yMax: undefined }
  ];

  return (
    <SectionCard
      title={pick(language, COPY.chartsTitle)}
      hint={typeof total === "number" ? say(language, COPY.totalInRange, { count: formatNumber(total, language) }) : undefined}
    >
      <Stack spacing={2}>
        <Box sx={{ maxWidth: "100%", overflowX: "auto" }}>
          <RangeToggle value={range} options={ranges} labelOf={(value) => pick(language, RANGE_WORDS[value])} onChange={onRange} label={pick(language, COPY.rangeLabel)} />
        </Box>
        {loading && !stats ? <LinearProgress /> : null}
        {error ? <FriendlyError error={error} title={pick(language, COPY.statsFailed)} onRetry={onRetry} severity={stats ? "warning" : "error"} scope="dns" /> : null}
        <Box sx={{ display: "grid", gap: 3, gridTemplateColumns: { xs: "minmax(0, 1fr)", md: "repeat(2, minmax(0, 1fr))" } }}>
          {charts.map((chart) => (
            <Box key={chart.key} sx={{ minWidth: 0 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, chart.title)}</Typography>
              {chart.hint ? <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 0.5 }}>{pick(language, chart.hint)}</Typography> : null}
              <LineChart
                {...common}
                title={`${pick(language, chart.title)} · ${label}`}
                series={[{ label: pick(language, chart.title), color: chart.color, values: chart.values }]}
                yMax={chart.yMax}
                formatY={chart.format}
              />
            </Box>
          ))}
        </Box>
      </Stack>
    </SectionCard>
  );
}

// ── busiest ──────────────────────────────────────────────────────────────────

type TopRow = { key: string; kind: "client" | "domain"; label: string; count: number | null };
type TopTab = "domains" | "clients" | "nxdomain";

function TopCard({ stats, canWrite, limited, onMitigate }: { stats: DnsStats | null; canWrite: boolean; limited: Set<string>; onMitigate: (target: MitigateTarget) => void }) {
  const { language } = useKit();
  const [tab, setTab] = useState<TopTab>("domains");
  const top = stats?.top ?? {};
  const rows: TopRow[] = tab === "clients"
    ? (top.clients ?? []).map((item) => ({ key: item.client, kind: "client", label: item.client, count: item.count ?? null }))
    : ((tab === "nxdomain" ? top.nxdomain : top.domains) ?? []).map((item) => ({ key: item.name, kind: "domain", label: item.name, count: item.count ?? null }));
  const shown = rows.slice(0, 20);
  const columns: ListColumn<TopRow>[] = [
    { key: "label", header: pick(language, tab === "clients" ? COPY.device : COPY.name), render: (row) => <Ltr mono>{row.label}</Ltr>, hideOnCard: true },
    { key: "count", header: pick(language, COPY.count), render: (row) => (row.count === null ? "—" : formatNumber(row.count, language)), hideOnCard: true },
    {
      key: "act",
      header: "",
      hideOnCard: true,
      align: "end",
      render: (row) => <RowButtons row={row} canWrite={canWrite} limited={limited.has(row.label)} onMitigate={onMitigate} />
    }
  ];

  return (
    <SectionCard title={pick(language, COPY.topTitle)} hint={pick(language, tab === "nxdomain" ? COPY.topNxHint : COPY.topHint)}>
      <Stack spacing={2}>
        <ToggleButtonGroup exclusive size="small" value={tab} onChange={(_event, next: TopTab | null) => { if (next) setTab(next); }} aria-label={pick(language, COPY.topTitle)} sx={{ flexWrap: "wrap" }}>
          <ToggleButton value="domains" sx={{ minHeight: 40, textTransform: "none" }}>{pick(language, COPY.topDomains)}</ToggleButton>
          <ToggleButton value="clients" sx={{ minHeight: 40, textTransform: "none" }}>{pick(language, COPY.topClients)}</ToggleButton>
          <ToggleButton value="nxdomain" sx={{ minHeight: 40, textTransform: "none" }}>{pick(language, COPY.topNx)}</ToggleButton>
        </ToggleButtonGroup>
        {stats?.top_hidden ? (
          <Stack direction="row" gap={1} alignItems="flex-start">
            <VisibilityOffRoundedIcon fontSize="small" color="action" aria-hidden sx={{ mt: 0.25 }} />
            <Box>
              <Typography variant="body2" color="text.secondary">{pick(language, COPY.topHidden)}</Typography>
              <NoAccess needs="dns:logs" />
            </Box>
          </Stack>
        ) : (
          <ResponsiveList
            rows={shown}
            rowKey={(row) => row.key}
            columns={columns}
            dense
            label={pick(language, COPY.topTitle)}
            card={{
              title: (row) => <Ltr mono>{row.label}</Ltr>,
              meta: (row) => (row.count === null ? null : say(language, COPY.times, { count: formatNumber(row.count, language) })),
              status: (row) => <RowButtons row={row} canWrite={canWrite} limited={limited.has(row.label)} onMitigate={onMitigate} />
            }}
            empty={<Typography variant="body2" color="text.secondary">{pick(language, COPY.topEmpty)}</Typography>}
          />
        )}
      </Stack>
    </SectionCard>
  );
}

function RowButtons({ row, canWrite, limited, onMitigate }: { row: TopRow; canWrite: boolean; limited: boolean; onMitigate: (target: MitigateTarget) => void }) {
  const { language } = useKit();
  if (limited) return <StatusPill tone="warn" label={pick(language, COPY.limited)} />;
  if (!canWrite) return null;
  return (
    <Stack direction="row" gap={0.5} flexWrap="wrap" justifyContent="flex-end">
      <Button size="small" startIcon={<SpeedRoundedIcon />} onClick={() => onMitigate({ kind: row.kind, match: row.label, action: "throttle" })} sx={{ minHeight: 40 }}>
        {pick(language, COPY.throttle)}
      </Button>
      <Button size="small" color="error" startIcon={<BlockRoundedIcon />} onClick={() => onMitigate({ kind: row.kind, match: row.label, action: "block" })} sx={{ minHeight: 40 }}>
        {pick(language, COPY.block)}
      </Button>
    </Stack>
  );
}

// ── attacks ──────────────────────────────────────────────────────────────────

function attackClients(attack: DnsAttack): string[] {
  return (attack.top_clients ?? []).map((item) => (typeof item === "string" ? item : item.client ?? "")).filter(Boolean).slice(0, 3);
}

function AttacksCard({ pressure, canWrite, onStop }: { pressure: DnsPressure | null; canWrite: boolean; onStop: (attack: DnsAttack) => Promise<void> }) {
  const { language } = useKit();
  const [busy, setBusy] = useState<string | null>(null);
  const raw = pressure?.hot?.attacks ?? null;
  const attacks = hotList<DnsAttack>(raw).filter((item) => item.parent);
  const hiddenCount = typeof raw === "number" ? raw : 0;
  if (!pressure) return null;
  return (
    <SectionCard title={pick(language, COPY.attacksTitle)} hint={pick(language, COPY.attacksHint)} status={attacks.length || hiddenCount ? <StatusPill tone="error" label={formatNumber(attacks.length || hiddenCount, language)} /> : undefined}>
      {hiddenCount ? (
        <Typography variant="body2">{say(language, COPY.attackHiddenCount, { count: formatNumber(hiddenCount, language) })}</Typography>
      ) : attacks.length ? (
        <Stack divider={<Divider flexItem />} spacing={1.5}>
          {attacks.map((attack) => {
            const parent = attack.parent as string;
            const clients = attackClients(attack);
            return (
              <Stack key={parent} direction={{ xs: "column", sm: "row" }} gap={1.5} alignItems={{ xs: "stretch", sm: "center" }} justifyContent="space-between">
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="body1" sx={{ fontWeight: 720, wordBreak: "break-all" }}><Ltr mono>{`*.${parent}`}</Ltr></Typography>
                  <Typography variant="body2" color="text.secondary">
                    {say(language, COPY.attackLine, { count: formatNumber(attack.unique_nxdomain_per_min ?? null, language) })}
                    {attack.since ? <> · <RelativeTime value={attack.since} relativeAlways /></> : null}
                  </Typography>
                  {clients.length ? (
                    <Typography variant="caption" color="text.secondary" component="p">
                      {pick(language, COPY.attackFrom)} <Ltr mono>{clients.join(", ")}</Ltr>
                    </Typography>
                  ) : null}
                </Box>
                {attack.mitigation_id ? (
                  <StatusPill tone="ok" label={pick(language, COPY.stopped)} />
                ) : canWrite ? (
                  <Button
                    variant="contained"
                    color="error"
                    startIcon={busy === parent ? <CircularProgress size={16} color="inherit" /> : <ShieldRoundedIcon />}
                    disabled={busy !== null}
                    onClick={async () => {
                      setBusy(parent);
                      try {
                        await onStop(attack);
                      } finally {
                        setBusy(null);
                      }
                    }}
                    sx={{ minHeight: 44, flexShrink: 0 }}
                  >
                    {pick(language, COPY.stopIt)}
                  </Button>
                ) : (
                  <NoAccess needs="dns:write" />
                )}
              </Stack>
            );
          })}
        </Stack>
      ) : (
        <Typography variant="body2" color="text.secondary">{pick(language, COPY.noAttacks)}</Typography>
      )}
    </SectionCard>
  );
}

// ── active limits ────────────────────────────────────────────────────────────

function LimitsCard({ items, error, loading, onRetry, onRemove }: { items: Mitigation[] | null; error: unknown; loading: boolean; onRetry: () => void; onRemove: (item: Mitigation) => void }) {
  const { language } = useKit();
  const actionLabel = (item: Mitigation) => {
    const word = MITIGATION_ACTION_WORDS[item.action] ? pick(language, MITIGATION_ACTION_WORDS[item.action]) : item.action;
    return item.action === "throttle" && typeof item.qps === "number" ? `${word} (${say(language, COPY.perSecond, { qps: formatNumber(item.qps, language) })})` : word;
  };
  const sourceLabel = (item: Mitigation) => pick(language, item.source === "auto" ? COPY.byAuto : COPY.byUser);
  const columns: ListColumn<Mitigation>[] = [
    { key: "match", header: pick(language, COPY.what), render: (item) => <Ltr mono>{item.match}</Ltr>, hideOnCard: true },
    { key: "kind", header: pick(language, { fa: "نوع", en: "Kind" }), render: (item) => (MITIGATION_KIND_WORDS[item.kind] ? pick(language, MITIGATION_KIND_WORDS[item.kind]) : item.kind) },
    { key: "action", header: pick(language, COPY.how), render: (item) => <StatusPill tone={item.action === "throttle" ? "warn" : "error"} label={actionLabel(item)} />, hideOnCard: true },
    { key: "source", header: pick(language, COPY.bySource), render: sourceLabel },
    { key: "until", header: pick(language, COPY.until), render: (item) => <RelativeTime value={item.expires_at} relativeAlways /> },
    { key: "hits", header: pick(language, COPY.hits), render: (item) => formatNumber(item.hits ?? 0, language) },
    { key: "reason", header: pick(language, COPY.reason), render: (item) => item.reason || "—", advancedOnly: true }
  ];
  return (
    <SectionCard title={pick(language, COPY.limitsTitle)} hint={pick(language, COPY.limitsHint)} flush={Boolean(items?.length)}>
      {error ? <FriendlyError error={error} title={pick(language, COPY.limitsFailed)} onRetry={onRetry} severity="warning" scope="dns" /> : null}
      {loading && !items ? <LinearProgress /> : null}
      {items ? (
        <ResponsiveList
          rows={items}
          rowKey={(item) => item.id}
          columns={columns}
          label={pick(language, COPY.limitsTitle)}
          actions={[{ key: "remove", label: pick(language, COPY.remove), icon: DeleteOutlineRoundedIcon, danger: true, onClick: onRemove }]}
          card={{
            title: (item) => <Ltr mono>{item.match}</Ltr>,
            status: (item) => <StatusPill tone={item.action === "throttle" ? "warn" : "error"} label={actionLabel(item)} />
          }}
          empty={<Typography variant="body2" color="text.secondary">{pick(language, COPY.limitsEmpty)}</Typography>}
        />
      ) : null}
    </SectionCard>
  );
}

// ── events ───────────────────────────────────────────────────────────────────

function EventsCard() {
  const { language, isAdvanced } = useKit();
  const { data, error } = usePolled<DnsEvent[]>((signal) => fetchDnsEvents(signal), 30_000);
  if (error && !data) return null; // an older server has no events endpoint; nothing to show
  const items = [...(data ?? [])].sort((a, b) => b.seq - a.seq).slice(0, isAdvanced ? 50 : 10);
  return (
    <SectionCard title={pick(language, COPY.eventsTitle)}>
      {items.length ? (
        <Stack component="ol" spacing={1.25} sx={{ listStyle: "none", m: 0, p: 0 }}>
          {items.map((event) => {
            const severity = severityWord(language, event.severity ?? "info");
            return (
              <Stack component="li" key={event.seq} direction="row" gap={1.25} alignItems="flex-start">
                <HistoryRoundedIcon fontSize="small" color="action" aria-hidden sx={{ mt: 0.25 }} />
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography variant="body2" sx={{ lineHeight: 1.8 }}>{eventText(language, event)}</Typography>
                  <Typography variant="caption" color="text.secondary"><RelativeTime value={event.ts} relativeAlways /></Typography>
                </Box>
                {event.severity && event.severity !== "info" ? <StatusPill tone={severity.tone} label={severity.label} /> : null}
              </Stack>
            );
          })}
        </Stack>
      ) : (
        <Typography variant="body2" color="text.secondary">{pick(language, COPY.eventsEmpty)}</Typography>
      )}
    </SectionCard>
  );
}

// ── settings (Advanced) ──────────────────────────────────────────────────────

const LEVELS = ["warning", "critical", "emergency"] as const;
const METRICS: Array<{ key: keyof Thresholds; label: Bi; max: number }> = [
  { key: "cpu", label: COPY.tCpu, max: 100 },
  { key: "memory", label: COPY.tMemory, max: 100 },
  { key: "qps_percent", label: COPY.tQps, max: 500 },
  { key: "host_cpu", label: COPY.tHostCpu, max: 100 },
  { key: "host_memory", label: COPY.tHostMemory, max: 100 }
];
type PressureDraft = { pressure: PressureSettings };
const PRESSURE_DEFAULTS: PressureDraft = { pressure: DEFAULT_PRESSURE };

function validatePressure(language: "fa" | "en") {
  return (draft: PressureDraft) => {
    const problems: Record<string, string> = {};
    const thresholds = draft.pressure.thresholds;
    for (const metric of METRICS) {
      const values = LEVELS.map((level) => thresholds[level]?.[metric.key] ?? 0);
      if (!(values[0] < values[1] && values[1] < values[2])) problems[`thresholds.${metric.key}`] = pick(language, COPY.order);
    }
    return problems;
  };
}

function PressureSettingsCard({ permissions }: { permissions: readonly string[] }) {
  const { language } = useKit();
  const validate = useMemo(() => validatePressure(language), [language]);
  return (
    <DnsSectionSettings<PressureDraft>
      title={pick(language, COPY.settingsTitle)}
      hint={pick(language, COPY.settingsHint)}
      permissions={permissions}
      defaults={PRESSURE_DEFAULTS}
      validate={validate}
      collapsible
      defaultCollapsed
    >
      {({ draft, update, problems, serverFields }) => {
        const pressure = draft.pressure;
        return (
          <Stack spacing={2.5}>
            <FormControlLabel control={<Switch checked={pressure.enabled !== false} onChange={(event) => update((next) => { next.pressure.enabled = event.target.checked; })} />} label={pick(language, COPY.enabled)} />
            <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" } }}>
              <NumberInput label={pick(language, COPY.capacity)} value={pressure.capacity_qps} onChange={(value) => update((next) => { next.pressure.capacity_qps = value ?? 0; })} min={100} max={10_000_000} integer helperText={pick(language, COPY.capacityHint)} error={serverFields["pressure.capacity_qps"] ?? null} />
              <DurationInput label={pick(language, COPY.dwell)} value={pressure.dwell_seconds} onChange={(value) => update((next) => { next.pressure.dwell_seconds = value ?? 0; })} min={0} max={3600} units={["seconds", "minutes"]} helperText={pick(language, COPY.dwellHint)} />
              <NumberInput label={pick(language, COPY.exitMargin)} value={pressure.exit_margin_percent} onChange={(value) => update((next) => { next.pressure.exit_margin_percent = value ?? 0; })} min={0} max={50} integer unit="٪" />
            </Box>

            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.levelsTitle)}</Typography>
            <Stack spacing={1.5}>
              {METRICS.map((metric) => (
                <Box key={metric.key}>
                  <Typography variant="body2" sx={{ fontWeight: 650, mb: 0.75 }}>{pick(language, metric.label)}</Typography>
                  <Box sx={{ display: "grid", gap: 1, gridTemplateColumns: { xs: "repeat(3, minmax(0, 1fr))" } }}>
                    {LEVELS.map((level) => (
                      <NumberInput
                        key={level}
                        label={pick(language, LEVEL_WORDS[level].label)}
                        value={pressure.thresholds[level]?.[metric.key] ?? null}
                        onChange={(value) => update((next) => { next.pressure.thresholds[level][metric.key] = value ?? 0; })}
                        min={1}
                        max={metric.max}
                        integer
                        error={serverFields[`pressure.thresholds.${level}.${metric.key}`] ?? null}
                      />
                    ))}
                  </Box>
                  {problems[`thresholds.${metric.key}`] ? <Typography variant="caption" color="error">{problems[`thresholds.${metric.key}`]}</Typography> : null}
                </Box>
              ))}
            </Stack>

            <Divider />
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.actionsTitle)}</Typography>
            <Stack spacing={0.5}>
              {Object.keys(ACTION_WORDS).map((key) => (
                <FormControlLabel
                  key={key}
                  control={<Switch checked={pressure.actions?.[key] !== false} onChange={(event) => update((next) => { next.pressure.actions = { ...(next.pressure.actions ?? {}), [key]: event.target.checked }; })} />}
                  label={pick(language, ACTION_WORDS[key])}
                  sx={{ alignItems: "flex-start", "& .MuiFormControlLabel-label": { pt: 1, lineHeight: 1.7 } }}
                />
              ))}
            </Stack>

            <Divider />
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.attackTitle)}</Typography>
            <ChoiceCards<"off" | "suggest" | "auto">
              label={pick(language, COPY.attackTitle)}
              value={(["off", "suggest", "auto"].includes(pressure.attack_detection.mode) ? pressure.attack_detection.mode : "suggest") as "off" | "suggest" | "auto"}
              onChange={(value) => update((next) => { next.pressure.attack_detection.mode = value; })}
              options={[
                { key: "off", title: pick(language, COPY.modeOff), body: pick(language, COPY.modeOffBody) },
                { key: "suggest", title: pick(language, COPY.modeSuggest), body: pick(language, COPY.modeSuggestBody) },
                { key: "auto", title: pick(language, COPY.modeAuto), body: pick(language, COPY.modeAutoBody), tone: "warning" }
              ]}
            />
            {pressure.attack_detection.mode !== "off" ? (
              <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" } }}>
                <NumberInput label={pick(language, COPY.nxPerMinute)} value={pressure.attack_detection.nxdomain_unique_per_minute} onChange={(value) => update((next) => { next.pressure.attack_detection.nxdomain_unique_per_minute = value ?? 0; })} min={10} max={1_000_000} integer />
                <DurationInput label={pick(language, COPY.mitigationMinutes)} value={(pressure.attack_detection.mitigation_minutes ?? 30) * 60} onChange={(value) => update((next) => { next.pressure.attack_detection.mitigation_minutes = Math.max(1, Math.round((value ?? 0) / 60)); })} min={60} max={7 * 86_400} units={["minutes", "hours", "days"]} />
              </Box>
            ) : null}
          </Stack>
        );
      }}
    </DnsSectionSettings>
  );
}

// ── tab ──────────────────────────────────────────────────────────────────────

export default function DnsMonitorTab({ permissions }: { permissions: readonly string[] }) {
  const { language, isAdvanced } = useKit();
  const canWrite = hasPermission(permissions, "dns:write");
  const { status, error: statusError, reload: reloadStatus } = useDnsStatus(30_000);
  const ranges = isAdvanced ? ALL_RANGES : SIMPLE_RANGES;
  const [range, setRange] = useState<StatsRange>(() => readRange(ALL_RANGES));
  const effectiveRange = ranges.includes(range) ? range : "24h";
  const pressure = usePolled<DnsPressure>((signal) => fetchPressure(signal), 5_000);
  const stats = usePolled<DnsStats>((signal) => fetchStats(effectiveRange, signal), POLL_MS[effectiveRange], [effectiveRange]);
  const limits = usePolled<Mitigation[]>((signal) => fetchMitigations(signal), canWrite ? 15_000 : null, [canWrite]);
  const [target, setTarget] = useState<MitigateTarget | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();

  const limited = useMemo(() => new Set((limits.data ?? []).map((item) => item.match)), [limits.data]);
  const ready = engineReady(status);

  const changeRange = (next: StatsRange) => {
    setRange(next);
    try {
      window.localStorage.setItem(RANGE_KEY, next);
    } catch {
      // storage unavailable
    }
  };

  const stopAttack = async (attack: DnsAttack) => {
    const name = attack.parent as string;
    const minutes = 30;
    const ok = await ask({
      title: say(language, COPY.stopTitle, { name }),
      body: say(language, COPY.stopBody, { name, minutes: minutesWord(language, minutes) }),
      severity: "disruptive",
      confirmLabel: pick(language, COPY.stopYes)
    });
    if (!ok) return;
    try {
      await createMitigation({ kind: "domain", match: name, action: "block", minutes, reason: "attack" });
      notify({ message: say(language, COPY.stoppedToast, { name }), tone: "success" });
      void pressure.reload();
      void limits.reload();
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
  };

  const removeLimit = async (item: Mitigation) => {
    const ok = await ask({
      title: say(language, COPY.removeTitle, { name: item.match }),
      body: pick(language, COPY.removeBody),
      severity: "disruptive",
      confirmLabel: pick(language, COPY.removeYes)
    });
    if (!ok) return;
    try {
      await deleteMitigation(item.id);
      limits.setData((current) => (current ?? []).filter((entry) => entry.id !== item.id));
      notify({ message: say(language, COPY.removed, { name: item.match }), tone: "success" });
      void limits.reload();
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
  };

  if (status && !ready) {
    return (
      <Stack spacing={2.5}>
        <DnsAvailability status={status} error={statusError} onRetry={() => void reloadStatus()} />
        <SectionCard>
          <EmptyState icon={SpeedRoundedIcon} title={pick(language, { fa: "پایش وقتی DNS روشن است کار می‌کند", en: "Monitoring works once DNS is running" })} body={pick(language, { fa: "اول DNS را از «راه‌اندازی» روشن کنید.", en: "Turn DNS on from Set up first." })} />
        </SectionCard>
      </Stack>
    );
  }

  return (
    <Stack spacing={2.5}>
      <DnsAvailability status={status} error={statusError} onRetry={() => void reloadStatus()} />
      <PressureCard pressure={pressure.data} error={pressure.error} onRetry={() => void pressure.reload()} />
      <ChartsCard stats={stats.data} error={stats.error} loading={stats.loading} range={effectiveRange} ranges={ranges} onRange={changeRange} onRetry={() => void stats.reload()} />
      <AttacksCard pressure={pressure.data} canWrite={canWrite} onStop={stopAttack} />
      <TopCard stats={stats.data} canWrite={canWrite} limited={limited} onMitigate={setTarget} />
      {canWrite ? (
        <LimitsCard items={limits.data} error={limits.error} loading={limits.loading} onRetry={() => void limits.reload()} onRemove={(item) => void removeLimit(item)} />
      ) : (
        <SectionCard title={pick(language, COPY.limitsTitle)} hint={pick(language, COPY.limitsHint)}>
          <NoAccess needs="dns:write" />
        </SectionCard>
      )}
      <EventsCard />
      {isAdvanced ? <PressureSettingsCard permissions={permissions} /> : null}
      {target ? (
        <MitigateDialog
          key={`${target.kind}:${target.match}`}
          target={target}
          onClose={() => setTarget(null)}
          onDone={() => {
            notify({ message: say(language, COPY.added, { name: target.match }), tone: "success" });
            setTarget(null);
            void limits.reload();
          }}
        />
      ) : null}
      {dialog}
      {snackbar}
    </Stack>
  );
}
