/**
 * Server › Resource use (docs/33 §4.2): plain usage tiles, 24h/7d charts with a text summary, one
 * "tell me when it fills up" switch, and per-container use. Advanced adds every range, load and
 * network charts, top lists, raw timestamps and every monitoring setting (RegistrySettings).
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Box, Button, Chip, CircularProgress, FormControlLabel, Grid, LinearProgress, Stack, Switch, Tooltip, Typography } from "@mui/material";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import MemoryRoundedIcon from "@mui/icons-material/MemoryRounded";
import SpeedRoundedIcon from "@mui/icons-material/SpeedRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import LinkRoundedIcon from "@mui/icons-material/LinkRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { LineChart, Sparkline, seriesStats, type ChartSeries, type ChartWords } from "./charts";
import { formatBytes, formatDateTime, formatNumber, formatPercent, formatRate } from "./format";
import type { Language } from "./i18n";
import { useVisibleInterval } from "./polling";
import {
  EmptyState, FriendlyError, HelpTip, Ltr, NoAccess, Notice, ResponsiveList, SectionCard, StatGrid, StatTile, useKit, useUndoSnackbar,
  RegistrySettings, RangeToggle, helperProblem, PAIR_AGENT_HREF, type ListColumn
} from "./kit";
import { pick, say, type Bi } from "./copy";

type Range = "1h" | "6h" | "24h" | "7d" | "30d";
const ALL_RANGES: Range[] = ["1h", "6h", "24h", "7d", "30d"];
const SIMPLE_RANGES: Range[] = ["24h", "7d"];
// Coarser ranges change slowly; poll them less often.
const POLL_MS: Record<Range, number> = { "1h": 30_000, "6h": 60_000, "24h": 120_000, "7d": 600_000, "30d": 600_000 };

type HostPoint = {
  ts: number;
  cpu_percent: number | null;
  mem_percent: number | null;
  disk_percent: number | null;
  load1: number | null;
  net_rx_bps: number | null;
  net_tx_bps: number | null;
  mem_used_bytes?: number | null;
  mem_total_bytes?: number | null;
  disk_used_bytes?: number | null;
  disk_total_bytes?: number | null;
};
/** Newest absolute values (docs/34 §4); `null` when there's no sample in the last 10 minutes. */
type HostLatest = {
  ts?: number;
  source?: "agent" | "minute";
  cpu_percent?: number | null;
  mem_total_bytes?: number | null;
  mem_used_bytes?: number | null;
  mem_percent?: number | null;
  disk_path?: string | null;
  disk_total_bytes?: number | null;
  disk_used_bytes?: number | null;
  disk_percent?: number | null;
};
type HostMetrics = { resolution: "minute" | "hour"; points: HostPoint[]; latest?: HostLatest | null };
type TopItem = { name: string; cpu_percent: number | null; mem_bytes: number | null };
type ContainerMetric = {
  name: string;
  protected: boolean;
  latest: { cpu_percent: number | null; mem_bytes: number | null; mem_limit_bytes: number | null } | null;
  points: Array<{ ts: number; cpu_percent: number | null; mem_bytes: number | null }>;
};
type MetricsSettings = {
  enabled: boolean;
  interval_seconds: number;
  minute_retention_days: number;
  hour_retention_days: number;
  alerts: { enabled: boolean; cpu_percent: number; mem_percent: number; disk_percent: number; duration_minutes: number };
};

type Props = { language: Language; permissions: string[]; onUnauthorized: () => void };

const BASE = "/api/v1/metrics";
const COLORS = { cpu: "#3b82f6", mem: "#8b5cf6", disk: "#f59e0b", rx: "#10b981", tx: "#ec4899", load: "#f97316" };
const PAIR_HREF = PAIR_AGENT_HREF;

const T = {
  rangeLabel: { fa: "بازه زمانی", en: "Time range" },
  ranges: {
    "1h": { fa: "۱ ساعت گذشته", en: "Last hour" },
    "6h": { fa: "۶ ساعت گذشته", en: "Last 6 hours" },
    "24h": { fa: "۲۴ ساعت گذشته", en: "Last 24 hours" },
    "7d": { fa: "۷ روز گذشته", en: "Last 7 days" },
    "30d": { fa: "۳۰ روز گذشته", en: "Last 30 days" }
  } satisfies Record<Range, Bi>,
  nowTitle: { fa: "همین حالا", en: "Right now" },
  nowHint: { fa: "سرور الان چقدر سرش شلوغ است.", en: "How busy the server is right now." },
  cpu: { fa: "پردازنده", en: "Processor (CPU)" },
  memory: { fa: "حافظه", en: "Memory" },
  disk: { fa: "دیسک", en: "Disk" },
  network: { fa: "شبکه", en: "Network" },
  rx: { fa: "دریافت", en: "Received" },
  tx: { fa: "ارسال", en: "Sent" },
  load: { fa: "بار سرور (میانگین ۱ دقیقه)", en: "Server load (1-minute average)" },
  cpuValue: { fa: "{value} مشغول", en: "{value} busy" },
  memValue: { fa: "{value} پر", en: "{value} used" },
  diskValue: { fa: "{value} پر", en: "{value} full" },
  ofTotal: { fa: "{used} از {total}", en: "{used} of {total}" },
  calm: { fa: "خیالتان راحت؛ جای کافی هست.", en: "All good; plenty of room." },
  busy: { fa: "کمی شلوغ است.", en: "A bit busy." },
  full: { fa: "نزدیک پر شدن است.", en: "Almost full." },
  chartsTitle: { fa: "در طول زمان", en: "Over time" },
  chartsHint: { fa: "خط بالاتر یعنی سرور مشغول‌تر بوده است.", en: "A higher line means the server was busier." },
  noData: { fa: "هنوز آماری جمع نشده. چند دقیقه دیگر سر بزنید.", en: "No statistics yet. Check back in a few minutes." },
  words: { fa: { now: "الان", lowest: "کمترین", average: "میانگین", highest: "بیشترین", separator: "؛ " }, en: { now: "now", lowest: "lowest", average: "average", highest: "highest", separator: "; " } },
  alertTitle: { fa: "خبرم کن", en: "Tell me" },
  alertSwitch: { fa: "وقتی بیشتر از {cpu}٪ شد خبرم کن", en: "Tell me when it goes over {cpu}%" },
  alertCaption: {
    fa: "اگر پردازنده از {cpu}٪، حافظه از {mem}٪ یا دیسک از {disk}٪ بیشتر شد و {minutes} دقیقه همان‌طور ماند، پیام می‌گیرید.",
    en: "You get a message when CPU passes {cpu}%, memory {mem}% or disk {disk}% for {minutes} minutes."
  },
  alertOn: { fa: "از این به بعد وقتی سرور پر شد خبرتان می‌کنیم.", en: "We'll tell you when the server fills up." },
  alertOff: { fa: "هشدار پر شدن سرور خاموش شد.", en: "Full-server alerts are off." },
  alertChannelHint: { fa: "پیام از راه کانال‌های اعلان (مثل تلگرام) می‌رسد.", en: "Messages arrive through your alert channels (such as Telegram)." },
  containersTitle: { fa: "مصرف هر کانتینر", en: "Use per container" },
  containersHint: { fa: "کدام برنامه بیشتر از پردازنده و حافظه استفاده می‌کند.", en: "Which app uses the most processor and memory." },
  containersEmpty: { fa: "آمار کانتینرها در دسترس نیست.", en: "Container statistics aren't available." },
  containersWhy: {
    fa: "دستیار سرور نمی‌تواند مصرف تک‌تک کانتینرها را بخواند. معمولاً یعنی به اطلاعات Docker روی سرور دسترسی ندارد. راهنمای نصب دستیار سرور را ببینید.",
    en: "The server helper can't read per-container use. Usually it has no access to Docker's data on the host. See the server helper setup guide."
  },
  name: { fa: "نام", en: "Name" },
  cpuNow: { fa: "پردازنده الان", en: "CPU now" },
  cpuTrend: { fa: "روند پردازنده", en: "CPU trend" },
  memNow: { fa: "حافظه الان", en: "Memory now" },
  memTrend: { fa: "روند حافظه", en: "Memory trend" },
  cardMeta: { fa: "پردازنده {cpu} · حافظه {mem}", en: "CPU {cpu} · memory {mem}" },
  topCpu: { fa: "پرمصرف‌ترین‌ها از نظر پردازنده", en: "Top containers by CPU" },
  topMem: { fa: "پرمصرف‌ترین‌ها از نظر حافظه", en: "Top containers by memory" },
  resolution_minute: { fa: "هر نقطه = یک دقیقه", en: "Each point = one minute" },
  resolution_hour: { fa: "هر نقطه = یک ساعت", en: "Each point = one hour" },
  lastUpdated: { fa: "آخرین بار تازه شد: {time}", en: "Last refreshed: {time}" },
  advancedTitle: { fa: "جزئیات بیشتر", en: "More detail" },
  advancedHint: { fa: "بار سرور، شبکه و پرمصرف‌ترین کانتینرها.", en: "Server load, network and the busiest containers." },
  settingsTitle: { fa: "تنظیمات جمع‌آوری آمار و هشدار", en: "Collection and alert settings" },
  settingsHint: { fa: "هر چند وقت آمار خوانده شود، چقدر بماند و از چه حدی هشدار بدهد.", en: "How often to sample, how long to keep it and when to alert." },
  unavailable: { fa: "این بخش روی نسخه فعلی سرور نیست. MRK را به‌روز کنید.", en: "This section isn't on the current server version. Update MRK." },
  notPairedTitle: { fa: "اول دستیار سرور را وصل کنید.", en: "Connect the server helper first." },
  notPairedBody: { fa: "دستیار سرور (Agent) مصرف پردازنده، حافظه و دیسک را برای این صفحه می‌خواند.", en: "The server helper (Agent) reads CPU, memory and disk use for this page." },
  pair: { fa: "وصل کردن دستیار سرور", en: "Connect the server helper" },
  loadFailed: { fa: "آمار مصرف خوانده نشد.", en: "Couldn't read usage." },
  saveFailed: { fa: "هشدار ذخیره نشد.", en: "The alert wasn't saved." }
};

function readRange(allowed: Range[], fallback: Range): Range {
  try {
    const stored = window.localStorage.getItem("mrk-metrics-range") as Range | null;
    return stored && allowed.includes(stored) ? stored : fallback;
  } catch {
    return fallback;
  }
}

function lastNumber(values: Array<number | null>) {
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const value = values[index];
    if (value !== null && Number.isFinite(value)) return value;
  }
  return null;
}

function lastPoint(points: HostPoint[]) {
  return points.length ? points[points.length - 1] : null;
}

type Level = "ok" | "warn" | "error";
function levelOf(value: number | null, threshold: number): Level {
  if (value === null) return "ok";
  if (value >= threshold) return "error";
  if (value >= threshold - 15) return "warn";
  return "ok";
}

function isNotPaired(error: unknown) {
  return helperProblem(error) === "not_paired";
}
function isMissing(error: unknown) {
  return helperProblem(error) === "module_missing";
}
function isQuiet(error: unknown) {
  return isAbortError(error) || (error instanceof ApiError && error.status === 401);
}

function ChartBox({ title, latest, children }: { title: string; latest: string; children: ReactNode }) {
  return (
    <Box sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: { xs: 1.5, sm: 2 }, height: "100%" }}>
      <Stack direction="row" justifyContent="space-between" alignItems="baseline" spacing={1} sx={{ mb: 1 }}>
        <Typography variant="subtitle1" component="h3" fontWeight={760}>{title}</Typography>
        <Typography variant="body2" fontWeight={760} color="text.secondary">{latest}</Typography>
      </Stack>
      {children}
    </Box>
  );
}

function TopList({ title, items, value, language, emptyText }: { title: string; items: TopItem[] | null; value: (item: TopItem) => string; language: Language; emptyText: string }) {
  return (
    <Box sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: { xs: 1.5, sm: 2 }, height: "100%" }}>
      <Typography variant="subtitle1" component="h3" fontWeight={760}>{title}</Typography>
      {items === null ? <LinearProgress sx={{ mt: 2 }} /> : items.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1.5 }}>{emptyText}</Typography>
      ) : (
        <Stack component="ol" sx={{ mt: 1, mb: 0, p: 0, listStyle: "none" }}>
          {items.map((item, index) => (
            <Stack component="li" key={item.name} direction="row" justifyContent="space-between" alignItems="center" spacing={1} sx={{ py: 0.75, minWidth: 0 }}>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                <Typography variant="body2" color="text.secondary" sx={{ width: 20, flexShrink: 0 }}>{formatNumber(index + 1, language)}</Typography>
                <Typography variant="body2" fontWeight={680} noWrap title={item.name}><Ltr>{item.name.replace(/^\//, "")}</Ltr></Typography>
              </Stack>
              <Typography variant="body2" fontWeight={760} sx={{ flexShrink: 0 }}>{value(item)}</Typography>
            </Stack>
          ))}
        </Stack>
      )}
    </Box>
  );
}

function ContainersCard({ range }: { range: Range }) {
  const { language } = useKit();
  const [items, setItems] = useState<ContainerMetric[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      const payload = await getJson<{ items: ContainerMetric[] }>(`${BASE}/containers?range=${range}`, current.signal);
      setItems(payload.items ?? []);
      setError(null);
    } catch (caught) {
      if (isQuiet(caught)) return;
      setError(caught);
    }
  }, [range]);

  useEffect(() => {
    setItems(null);
    void load();
    return () => controller.current?.abort();
  }, [load]);
  useVisibleInterval(() => void load(), POLL_MS[range]);

  const sorted = useMemo(() => [...(items ?? [])].sort((a, b) => (b.latest?.cpu_percent ?? 0) - (a.latest?.cpu_percent ?? 0)), [items]);
  const nameOf = (item: ContainerMetric) => item.name.replace(/^\//, "");
  const memText = (item: ContainerMetric) => {
    const used = formatBytes(item.latest?.mem_bytes ?? null, language);
    const limit = item.latest?.mem_limit_bytes ?? null;
    return limit ? say(language, T.ofTotal, { used, total: formatBytes(limit, language) }) : used;
  };
  const columns: ListColumn<ContainerMetric>[] = [
    {
      key: "name",
      header: pick(language, T.name),
      render: (item) => (
        <Stack direction="row" spacing={0.75} alignItems="center" sx={{ minWidth: 0 }}>
          <Typography variant="body2" fontWeight={680} noWrap title={nameOf(item)}><Ltr>{nameOf(item)}</Ltr></Typography>
          {item.protected && <Chip size="small" variant="outlined" color="secondary" icon={<LockRoundedIcon />} label="Dokploy" />}
        </Stack>
      )
    },
    { key: "cpu", header: pick(language, T.cpuNow), render: (item) => formatPercent(item.latest?.cpu_percent ?? null, language) },
    {
      key: "cpuTrend",
      header: pick(language, T.cpuTrend),
      hideOnCard: true,
      render: (item) => <Sparkline values={item.points.map((point) => point.cpu_percent)} color={COLORS.cpu} label={`${pick(language, T.cpuTrend)} · ${nameOf(item)}`} />
    },
    { key: "mem", header: pick(language, T.memNow), render: memText },
    {
      key: "memTrend",
      header: pick(language, T.memTrend),
      hideOnCard: true,
      render: (item) => <Sparkline values={item.points.map((point) => point.mem_bytes)} color={COLORS.mem} label={`${pick(language, T.memTrend)} · ${nameOf(item)}`} max={item.latest?.mem_limit_bytes ?? undefined} />
    }
  ];

  return (
    <SectionCard title={pick(language, T.containersTitle)} hint={pick(language, T.containersHint)} flush={sorted.length > 0}>
      {error !== null && <FriendlyError error={error} title={pick(language, T.loadFailed)} onRetry={() => void load()} severity="warning" />}
      {items === null && error === null && <LinearProgress />}
      {items !== null && (
        <ResponsiveList
          rows={sorted}
          rowKey={(item) => item.name}
          label={pick(language, T.containersTitle)}
          columns={columns}
          card={{
            title: (item) => <Ltr>{nameOf(item)}</Ltr>,
            meta: (item) => say(language, T.cardMeta, { cpu: formatPercent(item.latest?.cpu_percent ?? null, language), mem: memText(item) })
          }}
          empty={
            <Stack direction="row" spacing={0.5} alignItems="center" sx={{ p: 2 }}>
              <Typography variant="body2" color="text.secondary">{pick(language, T.containersEmpty)}</Typography>
              <HelpTip>{pick(language, T.containersWhy)}</HelpTip>
            </Stack>
          }
        />
      )}
    </SectionCard>
  );
}

function AlertSwitch({ canWrite }: { canWrite: boolean }) {
  const { language } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const [settings, setSettings] = useState<MetricsSettings | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    getJson<MetricsSettings>(`${BASE}/settings`, controller.signal).then(setSettings, (caught) => {
      if (!isQuiet(caught)) setError(caught);
    });
    return () => controller.abort();
  }, []);

  const apply = useCallback(async (enabled: boolean, undo = false) => {
    setSaving(true);
    setError(null);
    try {
      const saved = await mutateJson<MetricsSettings | null>(`${BASE}/settings`, { method: "PUT", body: { alerts: { enabled } } });
      setSettings((current) => saved ?? (current ? { ...current, alerts: { ...current.alerts, enabled } } : current));
      if (!undo) notify({ message: pick(language, enabled ? T.alertOn : T.alertOff), onUndo: () => void apply(!enabled, true) });
    } catch (caught) {
      if (!isQuiet(caught)) setError(caught);
    } finally {
      setSaving(false);
    }
  }, [language, notify]);

  if (!settings) return error ? <FriendlyError error={error} severity="warning" inline /> : null;
  const alerts = settings.alerts;
  const params = { cpu: alerts.cpu_percent, mem: alerts.mem_percent, disk: alerts.disk_percent, minutes: alerts.duration_minutes };
  return (
    <Stack spacing={0.5}>
      <FormControlLabel
        control={<Switch checked={alerts.enabled} disabled={!canWrite || saving} onChange={(event) => void apply(event.target.checked)} />}
        label={say(language, T.alertSwitch, params)}
      />
      <Typography variant="body2" color="text.secondary">{say(language, T.alertCaption, params)} {pick(language, T.alertChannelHint)}</Typography>
      {!canWrite && <NoAccess needs="agent:write" />}
      {error !== null && <FriendlyError error={error} title={pick(language, T.saveFailed)} />}
      {snackbar}
    </Stack>
  );
}

export function MonitoringPanel({ permissions }: Props) {
  const { language, isAdvanced, c } = useKit();
  const canWrite = hasPermission(permissions, "agent:write");
  const ranges = isAdvanced ? ALL_RANGES : SIMPLE_RANGES;
  const [range, setRange] = useState<Range>(() => readRange(ALL_RANGES, "24h"));
  const effectiveRange: Range = ranges.includes(range) ? range : "24h";
  const [host, setHost] = useState<HostMetrics | null>(null);
  const [topCpu, setTopCpu] = useState<TopItem[] | null>(null);
  const [topMem, setTopMem] = useState<TopItem[] | null>(null);
  const [thresholds, setThresholds] = useState({ cpu: 90, mem: 90, disk: 85 });
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async (background = false) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    if (!background) setLoading(true);
    try {
      const [hostResult, cpuResult, memResult] = await Promise.allSettled([
        getJson<HostMetrics>(`${BASE}/host?range=${effectiveRange}`, current.signal),
        getJson<{ items: TopItem[] }>(`${BASE}/top?by=cpu&limit=5`, current.signal),
        getJson<{ items: TopItem[] }>(`${BASE}/top?by=mem&limit=5`, current.signal)
      ]);
      if (current.signal.aborted) return;
      if (hostResult.status === "rejected") throw hostResult.reason;
      setHost(hostResult.value);
      setTopCpu(cpuResult.status === "fulfilled" ? cpuResult.value.items ?? [] : []);
      setTopMem(memResult.status === "fulfilled" ? memResult.value.items ?? [] : []);
      setError(null);
      setUpdatedAt(new Date());
    } catch (caught) {
      if (isQuiet(caught)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, [effectiveRange]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  useEffect(() => {
    const ctrl = new AbortController();
    getJson<MetricsSettings>(`${BASE}/settings`, ctrl.signal).then(
      (value) => value.alerts && setThresholds({ cpu: value.alerts.cpu_percent, mem: value.alerts.mem_percent, disk: value.alerts.disk_percent }),
      () => undefined
    );
    return () => ctrl.abort();
  }, []);

  const blocked = isNotPaired(error) || isMissing(error);
  useVisibleInterval(() => void load(true), blocked ? null : POLL_MS[effectiveRange]);

  const changeRange = (next: Range | null) => {
    if (!next) return;
    setRange(next);
    try {
      window.localStorage.setItem("mrk-metrics-range", next);
    } catch {
      // storage unavailable
    }
  };

  const points = host?.points ?? [];
  const times = useMemo(() => points.map((point) => point.ts), [points]);
  const series = useCallback((key: keyof HostPoint) => points.map((point) => (point[key] as number | null | undefined) ?? null), [points]);
  const short = effectiveRange === "1h" || effectiveRange === "6h" || effectiveRange === "24h";
  const formatX = (ts: number) => formatDateTime(ts, language, short ? { hour: "2-digit", minute: "2-digit" } : { month: "short", day: "numeric" });
  const formatTooltipX = (ts: number) => formatDateTime(ts, language, { dateStyle: "medium", timeStyle: "short" });
  const pct = (value: number) => formatPercent(value, language);
  const words: ChartWords = T.words[language];

  const charts = useMemo(() => {
    const make = (label: Bi, color: string, key: keyof HostPoint): ChartSeries => ({ label: pick(language, label), color, values: series(key) });
    return {
      cpu: [make(T.cpu, COLORS.cpu, "cpu_percent")],
      mem: [make(T.memory, COLORS.mem, "mem_percent")],
      disk: [make(T.disk, COLORS.disk, "disk_percent")],
      net: [make(T.rx, COLORS.rx, "net_rx_bps"), make(T.tx, COLORS.tx, "net_tx_bps")],
      load: [make(T.load, COLORS.load, "load1")]
    };
  }, [language, series]);

  if (isMissing(error)) return <Notice>{pick(language, T.unavailable)}</Notice>;
  if (isNotPaired(error)) {
    return (
      <SectionCard>
        <EmptyState
          icon={LinkRoundedIcon}
          title={pick(language, T.notPairedTitle)}
          body={pick(language, T.notPairedBody)}
          action={<Button variant="contained" href={PAIR_HREF}>{pick(language, T.pair)}</Button>}
        />
      </SectionCard>
    );
  }

  const point = lastPoint(points);
  const live = host?.latest ?? null;
  const latest = {
    cpu_percent: live?.cpu_percent ?? point?.cpu_percent ?? null,
    mem_percent: live?.mem_percent ?? point?.mem_percent ?? null,
    disk_percent: live?.disk_percent ?? point?.disk_percent ?? null,
    mem_used_bytes: live?.mem_used_bytes ?? point?.mem_used_bytes ?? null,
    mem_total_bytes: live?.mem_total_bytes ?? point?.mem_total_bytes ?? null,
    disk_used_bytes: live?.disk_used_bytes ?? point?.disk_used_bytes ?? null,
    disk_total_bytes: live?.disk_total_bytes ?? point?.disk_total_bytes ?? null
  };
  const cpuNow = latest.cpu_percent ?? lastNumber(charts.cpu[0].values);
  const memNow = latest.mem_percent ?? lastNumber(charts.mem[0].values);
  const diskNow = latest.disk_percent ?? lastNumber(charts.disk[0].values);
  const caption = (level: Level, extra?: string) => {
    const word = pick(language, level === "error" ? T.full : level === "warn" ? T.busy : T.calm);
    return extra ? `${extra} · ${word}` : word;
  };
  const memLevel = levelOf(memNow, thresholds.mem);
  const diskLevel = levelOf(diskNow, thresholds.disk);
  const cpuLevel = levelOf(cpuNow, thresholds.cpu);
  const memAmount = latest.mem_used_bytes && latest.mem_total_bytes
    ? say(language, T.ofTotal, { used: formatBytes(latest.mem_used_bytes, language), total: formatBytes(latest.mem_total_bytes, language) })
    : undefined;
  const diskAmount = latest.disk_used_bytes && latest.disk_total_bytes
    ? say(language, T.ofTotal, { used: formatBytes(latest.disk_used_bytes, language), total: formatBytes(latest.disk_total_bytes, language) })
    : undefined;
  const rangeLabel = pick(language, T.ranges[effectiveRange]);
  const chartProps = { times, formatX, formatTooltipX, emptyText: pick(language, T.noData), height: 190, words, showSummary: true };
  const nowText = (values: Array<number | null>) => `${words.now}: ${pct(seriesStats(values)?.latest ?? NaN)}`;

  const refreshButton = (
    <Tooltip title={c.refresh}>
      <span>
        <Button variant="outlined" aria-label={c.refresh} onClick={() => void load()} disabled={loading} sx={{ minWidth: 44, minHeight: 40, px: 1 }}>
          {loading ? <CircularProgress size={18} /> : <RefreshRoundedIcon />}
        </Button>
      </span>
    </Tooltip>
  );

  return (
    <Stack spacing={3}>
      {error !== null && <FriendlyError error={error} title={pick(language, T.loadFailed)} onRetry={() => void load()} />}
      {loading && !host && error === null && <LinearProgress />}

      {host && (
        <SectionCard title={pick(language, T.nowTitle)} hint={pick(language, T.nowHint)} action={refreshButton}>
          <StatGrid columns={3}>
            <StatTile
              icon={SpeedRoundedIcon}
              label={pick(language, T.cpu)}
              value={say(language, T.cpuValue, { value: formatPercent(cpuNow, language) })}
              meter={cpuNow}
              tone={cpuLevel}
              caption={caption(cpuLevel)}
            />
            <StatTile
              icon={MemoryRoundedIcon}
              label={pick(language, T.memory)}
              value={memAmount ?? say(language, T.memValue, { value: formatPercent(memNow, language) })}
              meter={memNow}
              tone={memLevel}
              caption={caption(memLevel, memAmount ? say(language, T.memValue, { value: formatPercent(memNow, language) }) : undefined)}
            />
            <StatTile
              icon={StorageRoundedIcon}
              label={pick(language, T.disk)}
              value={say(language, T.diskValue, { value: formatPercent(diskNow, language) })}
              meter={diskNow}
              tone={diskLevel}
              caption={caption(diskLevel, [diskAmount, isAdvanced ? live?.disk_path : null].filter(Boolean).join(" · ") || undefined)}
            />
          </StatGrid>
          {isAdvanced && updatedAt && (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1.5 }}>
              {say(language, T.lastUpdated, { time: formatDateTime(updatedAt, language, { hour: "2-digit", minute: "2-digit", second: "2-digit" }) })}
            </Typography>
          )}
        </SectionCard>
      )}

      {host && (
        <SectionCard
          title={pick(language, T.chartsTitle)}
          hint={pick(language, T.chartsHint)}
          action={
            <RangeToggle value={effectiveRange} options={ranges} labelOf={(value) => pick(language, T.ranges[value])} onChange={changeRange} label={pick(language, T.rangeLabel)} />
          }
        >
          {isAdvanced && (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
              {pick(language, host.resolution === "hour" ? T.resolution_hour : T.resolution_minute)}
            </Typography>
          )}
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, lg: 6 }}>
              <ChartBox title={pick(language, T.cpu)} latest={nowText(charts.cpu[0].values)}>
                <LineChart {...chartProps} title={`${pick(language, T.cpu)} · ${rangeLabel}`} series={charts.cpu} yMax={100} formatY={pct} />
              </ChartBox>
            </Grid>
            <Grid size={{ xs: 12, lg: 6 }}>
              <ChartBox title={pick(language, T.memory)} latest={nowText(charts.mem[0].values)}>
                <LineChart {...chartProps} title={`${pick(language, T.memory)} · ${rangeLabel}`} series={charts.mem} yMax={100} formatY={pct} />
              </ChartBox>
            </Grid>
            <Grid size={{ xs: 12, lg: 6 }}>
              <ChartBox title={pick(language, T.disk)} latest={nowText(charts.disk[0].values)}>
                <LineChart {...chartProps} title={`${pick(language, T.disk)} · ${rangeLabel}`} series={charts.disk} yMax={100} formatY={pct} />
              </ChartBox>
            </Grid>
            {isAdvanced && (
              <Grid size={{ xs: 12, lg: 6 }}>
                <ChartBox
                  title={pick(language, T.network)}
                  latest={`↓ ${formatRate(lastNumber(charts.net[0].values), language)} · ↑ ${formatRate(lastNumber(charts.net[1].values), language)}`}
                >
                  <LineChart {...chartProps} title={`${pick(language, T.network)} · ${rangeLabel}`} series={charts.net} area={false} formatY={(value) => formatRate(value, language)} />
                </ChartBox>
              </Grid>
            )}
          </Grid>
        </SectionCard>
      )}

      {host && (
        <SectionCard title={pick(language, T.alertTitle)}>
          <AlertSwitch canWrite={canWrite} />
        </SectionCard>
      )}

      {host && <ContainersCard range={effectiveRange} />}

      {host && (
        <SectionCard advanced title={pick(language, T.advancedTitle)} hint={pick(language, T.advancedHint)}>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, lg: 6 }}>
              <ChartBox title={pick(language, T.load)} latest={`${words.now}: ${formatNumber(lastNumber(charts.load[0].values), language, { maximumFractionDigits: 2 })}`}>
                <LineChart {...chartProps} title={`${pick(language, T.load)} · ${rangeLabel}`} series={charts.load} formatY={(value) => formatNumber(value, language, { maximumFractionDigits: 2 })} />
              </ChartBox>
            </Grid>
            <Grid size={{ xs: 12, sm: 6, lg: 3 }}>
              <TopList title={pick(language, T.topCpu)} items={topCpu} language={language} emptyText={pick(language, T.containersEmpty)} value={(item) => formatPercent(item.cpu_percent, language)} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, lg: 3 }}>
              <TopList title={pick(language, T.topMem)} items={topMem} language={language} emptyText={pick(language, T.containersEmpty)} value={(item) => formatBytes(item.mem_bytes, language)} />
            </Grid>
          </Grid>
        </SectionCard>
      )}

      {isAdvanced && !blocked && (
        <RegistrySettings groups={["server.resources"]} permissions={permissions} title={pick(language, T.settingsTitle)} hint={pick(language, T.settingsHint)} />
      )}
    </Stack>
  );
}
