/**
 * Server › overview dashboard: what the machine is (facts) and what it is doing now
 * (live gauges, charts with 15-minute / 24-hour history, per-core heat map, disks,
 * network, temperatures and the busiest containers).
 *
 * Data: GET /api/v1/agent/host/facts (cached by the agent) and
 *       GET /api/v1/agent/host/live (the panel samples the agent every 2 s while this
 *       page is open, every 5 s otherwise, and keeps the history in memory).
 * Polling runs only while the browser tab is visible (useVisibleInterval).
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Box, Card, Chip, Stack, Typography, useTheme } from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import DeveloperBoardRoundedIcon from "@mui/icons-material/DeveloperBoardRounded";
import MemoryRoundedIcon from "@mui/icons-material/MemoryRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import ScheduleRoundedIcon from "@mui/icons-material/ScheduleRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import SpeedRoundedIcon from "@mui/icons-material/SpeedRounded";
import ViewInArRoundedIcon from "@mui/icons-material/ViewInArRounded";
import ComputerRoundedIcon from "@mui/icons-material/ComputerRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import { ApiError, getJson, isAbortError } from "./api";
import { useVisibleInterval } from "./polling";
import { HelpTip, Ltr, Notice, RangeToggle, SectionCard, StatusPill, formatClock, formatDuration, useKit } from "./kit";
import { pick, say, type Bi } from "./copy";
import type { Tone } from "./copy/kinds";
import type { Language } from "./i18n";
import { formatBytes, formatDateTime, formatNumber, formatPercent, formatRate } from "./format";
import { LineChart, Sparkline, type ChartSeries, type ChartWords } from "./charts";
import { CoreHeatMap, Gauge, LiveDot, StackedBar, UsageBar, thresholdTone, toneColor, useSeriesColors, type Segment } from "./serverViz";

const BASE = "/api/v1/agent/host";
const LIVE_MS = 2000;
const DAY_MS = 60_000;
const FACTS_MS = 5 * 60_000;
const FINE_SECONDS = 15 * 60;
const HEAT_COLUMNS = 90;

// ── Types (mirror modules/server_live.py and agent/host_facts.py) ─────────────────

type Sensor = { chip: string; label: string; celsius: number; high: number | null; critical: number | null };
type Filesystem = { device: string; mountpoint: string; fstype: string; total_bytes: number | null; used_bytes: number | null; free_bytes: number | null };
type BlockDevice = { name: string; size_bytes: number; model: string | null; vendor: string | null; rotational: boolean | null; removable: boolean; kind: string };
type NetInterface = { name: string; speed_mbps: number | null; state: string | null; mtu: number | null; ipv4: string[]; ipv6: string[] };

export type HostFacts = {
  available: boolean;
  hostname: string | null;
  os: { pretty_name: string | null; id: string | null; version_id: string | null };
  kernel: string | null;
  architecture: string | null;
  machine: { vendor: string | null; product: string | null; board: string | null; virtualization: "vm" | "bare_metal" | "unknown"; technology: string | null };
  cpu: {
    model: string | null; vendor: string | null; sockets: number | null; cores: number | null; threads: number | null; mhz: number | null;
    max_mhz: number | null; cache_text: string | null; caches: Array<{ level: string; size_bytes: number }>; virtualization_flags: string[];
  };
  memory: { total_bytes: number | null; swap_total_bytes: number | null };
  filesystems: Filesystem[];
  block_devices: BlockDevice[];
  interfaces: NetInterface[];
  temperatures: Sensor[];
  sensors_available: boolean;
  loadavg: number[] | null;
  uptime_seconds: number | null;
  docker: { version: string; api_version: string; containers_running: number | null; containers_total: number | null } | null;
  agent_version?: string;
};

type Point = {
  t: number; cpu: number | null; user: number | null; system: number | null; iowait: number | null; steal: number | null;
  cores: Array<number | null>; mem_used: number | null; mem_cache: number | null; mem_buffers: number | null; mem_available: number | null;
  swap_used: number | null; load1: number | null; rx: number | null; tx: number | null; dr: number | null; dw: number | null; temp: number | null;
  net: Record<string, [number, number]>; disk: Record<string, [number, number, number, number, number]>;
};
type DayPoint = Pick<Point, "t" | "cpu" | "iowait" | "steal" | "mem_used" | "mem_cache" | "swap_used" | "load1" | "rx" | "tx" | "dr" | "dw" | "temp"> & { cpu_max: number | null };
type ContainerLive = { id: string; name: string; protected: boolean; cpu: number | null; mem_bytes: number | null; mem_limit_bytes: number | null };
type Latest = Point & {
  interval: number;
  memory: { total: number | null; free: number | null; available: number | null; used: number | null; buffers: number | null; cache: number | null; shared: number | null; swap_total: number | null; swap_used: number | null };
  loadavg: number[] | null; uptime_seconds: number | null; tasks_total: number | null; procs_running: number | null; procs_blocked: number | null;
  cpu_mhz: number | null; temperatures: Sensor[]; containers: ContainerLive[] | null;
};
type LiveResponse<P> = { window: "15m" | "24h"; available: boolean | null; error_code: string | null; interval: number; latest: Latest | null; points: P[] };
type Window = "15m" | "24h";

// ── Copy ─────────────────────────────────────────────────────────────────────

const T = {
  thisMachine: { fa: "این سرور", en: "This machine" },
  vm: { fa: "سرور مجازی", en: "Virtual machine" },
  bareMetal: { fa: "سرور فیزیکی", en: "Physical server" },
  unknownMachine: { fa: "نوع ماشین نامشخص", en: "Machine type unknown" },
  processor: { fa: "پردازنده", en: "Processor" },
  coresLine: { fa: "{cores} هسته · {threads} رشته پردازشی", en: "{cores} cores · {threads} threads" },
  socketsLine: { fa: "{n} سوکت", en: "{n} sockets" },
  memory: { fa: "حافظه", en: "Memory" },
  swapLine: { fa: "حافظه جایگزین {n}", en: "{n} swap" },
  noSwap: { fa: "بدون حافظه جایگزین", en: "No swap" },
  storage: { fa: "فضای ذخیره", en: "Storage" },
  disksLine: { fa: "{n} دیسک", en: "{n} disks" },
  hardware: { fa: "سخت‌افزار", en: "Hardware" },
  system: { fa: "سیستم‌عامل", en: "Operating system" },
  kernelWord: { fa: "هسته لینوکس", en: "Linux kernel" },
  uptime: { fa: "روشن بوده", en: "Up for" },
  uptimeSince: { fa: "از آخرین راه‌اندازی", en: "Since the last boot" },
  containers: { fa: "کانتینرها", en: "Containers" },
  containersLine: { fa: "{running} روشن از {total}", en: "{running} running of {total}" },
  load: { fa: "بار سیستم", en: "System load" },
  loadLine: { fa: "۱، ۵ و ۱۵ دقیقه", en: "1, 5 and 15 min" },
  cache: { fa: "حافظه نهان", en: "Cache" },

  cpu: { fa: "پردازنده", en: "CPU" },
  ram: { fa: "حافظه", en: "Memory" },
  disk: { fa: "دیسک اصلی", en: "Main disk" },
  temperature: { fa: "دما", en: "Temperature" },
  stateOk: { fa: "عادی", en: "Normal" },
  stateWarn: { fa: "بالا", en: "High" },
  stateError: { fa: "بحرانی", en: "Critical" },
  stateNone: { fa: "نامشخص", en: "Unknown" },
  coresCaption: { fa: "{n} هسته · {mhz}", en: "{n} cores · {mhz}" },
  ofTotal: { fa: "{used} از {total}", en: "{used} of {total}" },
  freeLeft: { fa: "{free} خالی", en: "{free} free" },
  noSensors: { fa: "این سرور حسگر دما ندارد", en: "No sensors on this server" },
  hottest: { fa: "داغ‌ترین: {label}", en: "Hottest: {label}" },

  live: { fa: "زنده", en: "Live" },
  liveEvery: { fa: "هر {n} ثانیه", en: "every {n} s" },
  paused: { fa: "مکث (تب پنهان است)", en: "Paused (tab hidden)" },
  history: { fa: "روند مصرف", en: "Usage over time" },
  historyHint: { fa: "داده‌های ۱۵ دقیقه اخیر هر ۲ ثانیه و ۲۴ ساعت اخیر میانگین هر دقیقه است.", en: "The last 15 minutes every 2 seconds; the last 24 hours as one-minute averages." },
  range15m: { fa: "۱۵ دقیقه", en: "15 min" },
  range24h: { fa: "۲۴ ساعت", en: "24 hours" },
  rangeLabel: { fa: "بازه نمودارها", en: "Chart range" },
  busy: { fa: "مشغول", en: "Busy" },
  busyMax: { fa: "بیشترین در دقیقه", en: "Peak per minute" },
  iowait: { fa: "انتظار دیسک", en: "Disk wait" },
  steal: { fa: "سهم گرفته‌شده", en: "Steal" },
  stealHelp: {
    fa: "زمانی که سرور مجازی آماده کار بود ولی میزبان، پردازنده را به ماشین دیگری داده بود. اگر مدام بالای ۱۰٪ است، سرور شما با همسایه‌های پرمصرف شریک است.",
    en: "Time this virtual machine was ready to run but the host gave the CPU to another machine. Constantly above 10% means noisy neighbours."
  },
  used: { fa: "در استفاده برنامه‌ها", en: "Used by apps" },
  usedShort: { fa: "در استفاده", en: "Used" },
  buffers: { fa: "بافر", en: "Buffers" },
  free: { fa: "آزاد", en: "Free" },
  swap: { fa: "حافظه جایگزین", en: "Swap" },
  network: { fa: "شبکه", en: "Network" },
  received: { fa: "دریافت", en: "Received" },
  sent: { fa: "ارسال", en: "Sent" },
  diskIo: { fa: "خواندن و نوشتن دیسک", en: "Disk read & write" },
  read: { fa: "خواندن", en: "Read" },
  write: { fa: "نوشتن", en: "Write" },
  noData: { fa: "هنوز داده‌ای جمع نشده؛ چند ثانیه صبر کنید.", en: "No data yet; give it a few seconds." },
  now: { fa: "الان", en: "Now" },
  words: { fa: { now: "الان", lowest: "کمترین", average: "میانگین", highest: "بیشترین", separator: "؛ " }, en: { now: "now", lowest: "lowest", average: "average", highest: "highest", separator: "; " } },

  coresTitle: { fa: "هسته‌های پردازنده", en: "CPU cores" },
  coresHint: { fa: "هر ردیف یک هسته است و هر خانه دو ثانیه؛ رنگ پررنگ‌تر یعنی مشغول‌تر.", en: "Each row is a core and each cell two seconds; darker means busier." },
  coreN: { fa: "هسته {n}", en: "Core {n}" },
  coreCell: { fa: "هسته {n} · {time}: {p}", en: "Core {n} · {time}: {p}" },
  coresSummary: { fa: "میانگین هسته‌ها الان {avg}؛ مشغول‌ترین هسته {n} با {max}.", en: "Cores now average {avg}; busiest is core {n} at {max}." },
  idle: { fa: "بیکار", en: "Idle" },
  full: { fa: "پر", en: "Full" },
  userTime: { fa: "برنامه‌ها", en: "Apps" },
  systemTime: { fa: "سیستم", en: "System" },
  clock: { fa: "فرکانس", en: "Clock" },
  maxClock: { fa: "تا {mhz}", en: "up to {mhz}" },
  processes: { fa: "فرایندها", en: "Processes" },
  processesLine: { fa: "{running} در حال اجرا از {total}", en: "{running} running of {total}" },

  memoryTitle: { fa: "جزئیات حافظه", en: "Memory breakdown" },
  memoryHint: { fa: "حافظه نهان را لینوکس هر وقت لازم باشد آزاد می‌کند؛ «در دسترس» یعنی چقدر واقعاً برای برنامه‌ها جا هست.", en: "Linux frees the cache whenever needed; “available” is what apps can really still use." },
  available: { fa: "در دسترس", en: "Available" },

  disksTitle: { fa: "دیسک‌ها", en: "Disks" },
  disksHint: { fa: "فضای هر بخش دیسک و سرعت خواندن و نوشتن هر دستگاه.", en: "Space per file system and read/write speed per device." },
  filesystems: { fa: "بخش‌های دیسک", en: "File systems" },
  devices: { fa: "دستگاه‌ها", en: "Devices" },
  virtualDisk: { fa: "دیسک مجازی", en: "Virtual disk" },
  raid: { fa: "آرایه دیسک", en: "Disk array" },
  memoryCard: { fa: "کارت حافظه", en: "Memory card" },
  unknownKind: { fa: "نوع نامشخص", en: "Unknown type" },
  ops: { fa: "{r} خواندن و {w} نوشتن در ثانیه", en: "{r} reads and {w} writes per second" },
  busyTime: { fa: "{p} مشغول", en: "{p} busy" },
  notVisible: { fa: "دستیار سرور این بخش را نمی‌بیند", en: "Not visible to the server helper" },

  interfacesTitle: { fa: "کارت‌های شبکه", en: "Network interfaces" },
  interfacesHint: { fa: "کارت‌های شبکه واقعی سرور؛ شبکه‌های داخلی Docker نشان داده نمی‌شوند.", en: "The server's real network interfaces; Docker's internal networks are left out." },
  speed: { fa: "سرعت پورت", en: "Link speed" },
  stateUp: { fa: "وصل", en: "Up" },
  stateDown: { fa: "قطع", en: "Down" },
  noInterfaces: { fa: "کارت شبکه‌ای پیدا نشد.", en: "No network interfaces found." },

  sensorsTitle: { fa: "دمای قطعات", en: "Temperatures" },
  sensorsHint: { fa: "دمای خوانده‌شده از حسگرهای خود سخت‌افزار.", en: "Read from the hardware's own sensors." },
  noSensorsBody: {
    fa: "این سرور حسگر دما ندارد یا آن را به سیستم‌عامل نشان نمی‌دهد. بیشتر سرورهای مجازی همین‌طورند و دمای سخت‌افزار را فقط ارائه‌دهنده می‌بیند.",
    en: "This server has no temperature sensors, or doesn't expose them. Most virtual servers are like this; only the provider sees the hardware's temperature."
  },
  highAt: { fa: "هشدار از {c}", en: "high at {c}" },
  critAt: { fa: "بحرانی از {c}", en: "critical at {c}" },

  topTitle: { fa: "پرمصرف‌ترین کانتینرها", en: "Busiest containers" },
  topHint: { fa: "سهم هر کانتینر از کل پردازنده و حافظه این سرور، همین حالا.", en: "Each container's share of this server's CPU and memory, right now." },
  byCpu: { fa: "بر اساس پردازنده", en: "By CPU" },
  byMem: { fa: "بر اساس حافظه", en: "By memory" },
  noContainerStats: { fa: "آمار کانتینرها در دسترس نیست.", en: "Container statistics aren't available." },
  locked: { fa: "قفل Dokploy", en: "Dokploy lock" },

  outdated: { fa: "دستیار سرور قدیمی‌تر از پنل است؛ برای دیدن جزئیات سخت‌افزار و نمودارهای زنده آن را به‌روز کنید.", en: "The server helper is older than the panel; update it to see hardware details and live charts." },
  noHostAccess: { fa: "دستیار سرور اجازه دیدن اطلاعات سرور را ندارد.", en: "The server helper isn't allowed to read server information." },
  liveProblem: { fa: "داده زنده از دستیار سرور نرسید؛ دوباره تلاش می‌شود.", en: "Live data didn't arrive from the server helper; retrying." }
} satisfies Record<string, Bi | Record<Language, ChartWords>>;

type CopyKey = { [K in keyof typeof T]: (typeof T)[K] extends Bi ? K : never }[keyof typeof T];
const tr = (language: Language, key: CopyKey, params?: Record<string, string | number>) => (params ? say(language, T[key] as Bi, params) : pick(language, T[key] as Bi));

// ── Formatting ───────────────────────────────────────────────────────────────

function formatMhz(mhz: number | null | undefined, language: Language) {
  if (mhz === null || mhz === undefined || !Number.isFinite(mhz) || mhz <= 0) return "—";
  if (mhz >= 1000) return `${formatNumber(mhz / 1000, language, { maximumFractionDigits: 2 })} ${language === "fa" ? "گیگاهرتز" : "GHz"}`;
  return `${formatNumber(mhz, language, { maximumFractionDigits: 0 })} ${language === "fa" ? "مگاهرتز" : "MHz"}`;
}

function formatCelsius(value: number | null | undefined, language: Language) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return `${formatNumber(value, language, { maximumFractionDigits: 0 })}°`;
}

function formatLinkSpeed(mbps: number | null, language: Language) {
  if (!mbps) return "—";
  if (mbps >= 1000) return `${formatNumber(mbps / 1000, language, { maximumFractionDigits: 1 })} ${language === "fa" ? "گیگابیت" : "Gb/s"}`;
  return `${formatNumber(mbps, language)} ${language === "fa" ? "مگابیت" : "Mb/s"}`;
}

const pct = (value: number | null | undefined, language: Language) => formatPercent(value === null || value === undefined ? null : Math.round(value * 10) / 10, language);

function stateWord(language: Language, tone: Tone) {
  if (tone === "ok") return tr(language, "stateOk");
  if (tone === "warn") return tr(language, "stateWarn");
  if (tone === "error") return tr(language, "stateError");
  return tr(language, "stateNone");
}

function lastOf<P>(points: P[], read: (point: P) => number | null | undefined): number | null {
  for (let index = points.length - 1; index >= 0; index -= 1) {
    const value = read(points[index]);
    if (value !== null && value !== undefined && Number.isFinite(value)) return value;
  }
  return null;
}

// ── Data hooks ─────────────────────────────────────────────────────────────────

function useFacts() {
  const [facts, setFacts] = useState<HostFacts | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      setFacts(await getJson<HostFacts>(`${BASE}/facts`, signal));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    }
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);
  useVisibleInterval(() => void load(), FACTS_MS);
  return { facts, error };
}

function useLive(window: Window) {
  const [fine, setFine] = useState<Point[]>([]);
  const [day, setDay] = useState<DayPoint[]>([]);
  const [latest, setLatest] = useState<Latest | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [failed, setFailed] = useState<unknown>(null);
  const [visible, setVisible] = useState(() => document.visibilityState === "visible");
  const lastT = useRef<number | null>(null);
  const inFlight = useRef(false);

  const pull = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const since = lastT.current;
      const data = await getJson<LiveResponse<Point>>(`${BASE}/live?window=15m${since ? `&since=${since}` : ""}`);
      setErrorCode(data.error_code);
      setFailed(null);
      if (data.latest) setLatest(data.latest);
      if (data.points.length) {
        lastT.current = data.points[data.points.length - 1].t;
        setFine((current) => {
          const merged = since ? [...current, ...data.points] : data.points;
          const cutoff = merged[merged.length - 1].t - FINE_SECONDS;
          return merged.filter((point) => point.t >= cutoff);
        });
      }
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setFailed(caught);
    } finally {
      inFlight.current = false;
    }
  }, []);

  const pullDay = useCallback(async () => {
    try {
      const data = await getJson<LiveResponse<DayPoint>>(`${BASE}/live?window=24h`);
      setDay(data.points);
    } catch {
      // the 15-minute feed reports problems
    }
  }, []);

  useEffect(() => { void pull(); }, [pull]);
  useEffect(() => { if (window === "24h") void pullDay(); }, [window, pullDay]);
  useVisibleInterval(() => void pull(), LIVE_MS);
  useVisibleInterval(() => void pullDay(), window === "24h" ? DAY_MS : null);
  useEffect(() => {
    const onVisibility = () => setVisible(document.visibilityState === "visible");
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, []);
  return { fine, day, latest, errorCode, failed, visible };
}

// ── Pieces ───────────────────────────────────────────────────────────────────

function FactItem({ icon: Icon, label, value, detail }: { icon: SvgIconComponent; label: string; value: ReactNode; detail?: ReactNode }) {
  return (
    <Stack direction="row" spacing={1.5} sx={{ minWidth: 0, alignItems: "flex-start" }}>
      <Box sx={{ width: 36, height: 36, borderRadius: 2, display: "grid", placeItems: "center", bgcolor: "action.hover", color: "primary.main", flexShrink: 0 }}>
        <Icon fontSize="small" aria-hidden />
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 650, display: "block" }}>{label}</Typography>
        <Typography variant="body2" sx={{ fontWeight: 720, overflowWrap: "anywhere", lineHeight: 1.6 }}>{value}</Typography>
        {detail && <Typography variant="caption" color="text.secondary" sx={{ display: "block", overflowWrap: "anywhere", lineHeight: 1.6 }}>{detail}</Typography>}
      </Box>
    </Stack>
  );
}

function MachineCard({ facts, latest, language }: { facts: HostFacts; latest: Latest | null; language: Language }) {
  const theme = useTheme();
  const machine = facts.machine;
  const cpu = facts.cpu;
  const kind = machine.virtualization === "vm" ? tr(language, "vm") : machine.virtualization === "bare_metal" ? tr(language, "bareMetal") : tr(language, "unknownMachine");
  const hardware = [machine.vendor, machine.product].filter(Boolean).join(" · ");
  const storageTotal = facts.block_devices.reduce((sum, item) => sum + item.size_bytes, 0);
  const uptime = latest?.uptime_seconds ?? facts.uptime_seconds;
  const load = latest?.loadavg ?? facts.loadavg;
  const caches = cpu.caches.filter((item) => item.level === "L2" || item.level === "L3");
  const docker = facts.docker;
  return (
    <Card component="section" aria-label={tr(language, "thisMachine")} sx={{ overflow: "hidden" }}>
      <Box sx={{
        px: { xs: 2, sm: 3 }, py: { xs: 2, sm: 2.5 },
        background: theme.palette.mode === "dark"
          ? "linear-gradient(135deg, rgba(57,135,229,.16), rgba(94,234,212,.06) 60%, transparent)"
          : "linear-gradient(135deg, rgba(42,120,214,.10), rgba(15,118,110,.05) 60%, transparent)",
        borderBottom: 1, borderColor: "divider"
      }}>
        <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ xs: "flex-start", sm: "center" }} justifyContent="space-between">
          <Stack direction="row" spacing={1.75} alignItems="center" sx={{ minWidth: 0 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2.5, display: "grid", placeItems: "center", bgcolor: "primary.main", color: "primary.contrastText", flexShrink: 0 }}>
              <DnsRoundedIcon aria-hidden />
            </Box>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 650 }}>{tr(language, "thisMachine")}</Typography>
              <Typography component="h2" variant="h5" sx={{ fontWeight: 800, lineHeight: 1.25, overflowWrap: "anywhere" }}><Ltr>{facts.hostname ?? "—"}</Ltr></Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.25 }}><Ltr>{facts.os.pretty_name ?? "Linux"}</Ltr></Typography>
            </Box>
          </Stack>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            <Chip size="small" icon={<ComputerRoundedIcon />} label={kind} color={machine.virtualization === "bare_metal" ? "success" : "default"} variant="outlined" />
            {machine.technology && <Chip size="small" label={<Ltr>{machine.technology.toUpperCase()}</Ltr>} variant="outlined" />}
            {facts.architecture && <Chip size="small" label={<Ltr>{facts.architecture}</Ltr>} variant="outlined" />}
            {docker && <Chip size="small" icon={<ViewInArRoundedIcon />} label={<Ltr>{`Docker ${docker.version}`}</Ltr>} variant="outlined" />}
          </Stack>
        </Stack>
      </Box>
      <Box sx={{ px: { xs: 2, sm: 3 }, py: 2.5, display: "grid", gap: 2.25, gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))", lg: "repeat(4, minmax(0, 1fr))" } }}>
        <FactItem
          icon={DeveloperBoardRoundedIcon}
          label={tr(language, "processor")}
          value={<Ltr>{cpu.model ?? "—"}</Ltr>}
          detail={[
            tr(language, "coresLine", { cores: formatNumber(cpu.cores, language), threads: formatNumber(cpu.threads, language) }),
            cpu.sockets && cpu.sockets > 1 ? tr(language, "socketsLine", { n: formatNumber(cpu.sockets, language) }) : null,
            formatMhz(latest?.cpu_mhz ?? cpu.max_mhz ?? cpu.mhz, language),
            caches.length ? `${tr(language, "cache")} ${caches.map((item) => `${item.level} ${formatBytes(item.size_bytes, language)}`).join("، ")}` : null
          ].filter(Boolean).join(" · ")}
        />
        <FactItem
          icon={MemoryRoundedIcon}
          label={tr(language, "memory")}
          value={formatBytes(facts.memory.total_bytes, language)}
          detail={facts.memory.swap_total_bytes ? tr(language, "swapLine", { n: formatBytes(facts.memory.swap_total_bytes, language) }) : tr(language, "noSwap")}
        />
        <FactItem
          icon={StorageRoundedIcon}
          label={tr(language, "storage")}
          value={storageTotal ? formatBytes(storageTotal, language) : "—"}
          detail={facts.block_devices.length ? `${tr(language, "disksLine", { n: formatNumber(facts.block_devices.length, language) })} · ${facts.block_devices.map((item) => kindLabel(language, item.kind)).join("، ")}` : undefined}
        />
        <FactItem
          icon={ScheduleRoundedIcon}
          label={tr(language, "uptime")}
          value={uptime ? formatDuration(uptime, language) : "—"}
          detail={tr(language, "uptimeSince")}
        />
        <FactItem
          icon={ComputerRoundedIcon}
          label={tr(language, "hardware")}
          value={hardware ? <Ltr>{hardware}</Ltr> : kind}
          detail={machine.board ? <Ltr>{machine.board}</Ltr> : undefined}
        />
        <FactItem
          icon={TerminalRoundedIcon}
          label={tr(language, "system")}
          value={<Ltr>{facts.os.pretty_name ?? "Linux"}</Ltr>}
          detail={facts.kernel ? <>{tr(language, "kernelWord")} <Ltr>{facts.kernel}</Ltr></> : undefined}
        />
        <FactItem
          icon={SpeedRoundedIcon}
          label={tr(language, "load")}
          // Not wrapped in Ltr: in Persian the 1-minute value reads first, from the right.
          value={load ? load.map((value) => formatNumber(value, language, { minimumFractionDigits: 2, maximumFractionDigits: 2 })).join("  ·  ") : "—"}
          detail={tr(language, "loadLine")}
        />
        <FactItem
          icon={ViewInArRoundedIcon}
          label={tr(language, "containers")}
          value={docker && docker.containers_total !== null ? tr(language, "containersLine", { running: formatNumber(docker.containers_running, language), total: formatNumber(docker.containers_total, language) }) : "—"}
          detail={docker ? <Ltr>{`Docker ${docker.version} · API ${docker.api_version}`}</Ltr> : undefined}
        />
      </Box>
    </Card>
  );
}

function kindLabel(language: Language, kind: string) {
  switch (kind) {
    case "nvme": return "NVMe";
    case "ssd": return "SSD";
    case "hdd": return "HDD";
    case "virtual": return tr(language, "virtualDisk");
    case "raid": return tr(language, "raid");
    case "mmc": return tr(language, "memoryCard");
    default: return tr(language, "unknownKind");
  }
}

function GaugesCard({ facts, latest, language }: { facts: HostFacts | null; latest: Latest | null; language: Language }) {
  const cpu = latest?.cpu ?? null;
  const cpuTone = thresholdTone(cpu, 75, 90);
  const memory = latest?.memory;
  const memTotal = memory?.total ?? facts?.memory.total_bytes ?? null;
  const memUsed = memTotal !== null && memory?.available !== null && memory?.available !== undefined ? memTotal - memory.available : null;
  const memPercent = memTotal && memUsed !== null ? (memUsed / memTotal) * 100 : null;
  const memTone = thresholdTone(memPercent, 80, 90);
  const root = facts?.filesystems.find((item) => item.mountpoint === "/" && item.total_bytes) ?? facts?.filesystems.find((item) => item.total_bytes);
  const diskPercent = root && root.total_bytes && root.used_bytes !== null ? (root.used_bytes / root.total_bytes) * 100 : null;
  const diskTone = thresholdTone(diskPercent, 80, 90);
  const sensors = latest?.temperatures ?? facts?.temperatures ?? [];
  const hottest = sensors.reduce<Sensor | null>((best, item) => (best === null || item.celsius > best.celsius ? item : best), null);
  const tempLimit = hottest?.critical ?? 100;
  const tempWarn = hottest?.high ?? Math.min(80, tempLimit - 10);
  const tempTone = hottest ? thresholdTone(hottest.celsius, tempWarn, hottest.critical ?? 95) : "off";
  const cores = facts?.cpu.threads ?? latest?.cores.length ?? null;
  return (
    <Card component="section" aria-label={tr(language, "now")}>
      <Box sx={{ p: { xs: 1.5, sm: 2.5 }, display: "grid", gap: { xs: 1.5, sm: 2 }, gridTemplateColumns: { xs: "repeat(2, minmax(0, 1fr))", md: "repeat(4, minmax(0, 1fr))" } }}>
        <Gauge
          label={tr(language, "cpu")}
          valueText={cpu === null ? "—" : pct(Math.round(cpu), language)}
          percent={cpu}
          tone={cpuTone}
          statusText={stateWord(language, cpuTone)}
          marks={[75, 90]}
          caption={cores ? tr(language, "coresCaption", { n: formatNumber(cores, language), mhz: formatMhz(latest?.cpu_mhz ?? facts?.cpu.mhz, language) }) : undefined}
        />
        <Gauge
          label={tr(language, "ram")}
          valueText={memPercent === null ? "—" : pct(Math.round(memPercent), language)}
          percent={memPercent}
          tone={memTone}
          statusText={stateWord(language, memTone)}
          marks={[80, 90]}
          caption={memTotal && memUsed !== null ? tr(language, "ofTotal", { used: formatBytes(memUsed, language), total: formatBytes(memTotal, language) }) : undefined}
        />
        <Gauge
          label={tr(language, "disk")}
          valueText={diskPercent === null ? "—" : pct(Math.round(diskPercent), language)}
          percent={diskPercent}
          tone={diskTone}
          statusText={stateWord(language, diskTone)}
          marks={[80, 90]}
          caption={root && root.total_bytes ? `${tr(language, "ofTotal", { used: formatBytes(root.used_bytes, language), total: formatBytes(root.total_bytes, language) })} · ${tr(language, "freeLeft", { free: formatBytes(root.free_bytes, language) })}` : undefined}
        />
        <Gauge
          label={tr(language, "temperature")}
          valueText={hottest ? formatCelsius(hottest.celsius, language) : "—"}
          percent={hottest ? (hottest.celsius / tempLimit) * 100 : null}
          tone={tempTone}
          statusText={hottest ? stateWord(language, tempTone) : tr(language, "stateNone")}
          marks={hottest ? [(tempWarn / tempLimit) * 100] : []}
          caption={hottest ? tr(language, "hottest", { label: hottest.label }) : tr(language, "noSensors")}
        />
      </Box>
    </Card>
  );
}

function ChartBlock({ title, now, help, children }: { title: string; now?: string; help?: ReactNode; children: ReactNode }) {
  return (
    <Box sx={{ minWidth: 0 }}>
      <Stack direction="row" alignItems="baseline" justifyContent="space-between" flexWrap="wrap" useFlexGap columnGap={1} sx={{ mb: 0.75 }}>
        <Stack direction="row" alignItems="center" spacing={0.5}>
          <Typography variant="subtitle2" sx={{ fontWeight: 740 }}>{title}</Typography>
          {help}
        </Stack>
        {now && <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 700 }}>{now}</Typography>}
      </Stack>
      {children}
    </Box>
  );
}

function HistoryCard({ fine, day, window, onWindow, live, interval, memTotal, language }: {
  fine: Point[]; day: DayPoint[]; window: Window; onWindow: (value: Window) => void; live: boolean; interval: number; memTotal: number | null; language: Language;
}) {
  const colors = useSeriesColors();
  const theme = useTheme();
  const words = T.words[language];
  const short = window === "15m";
  const points: Array<Point | DayPoint> = short ? fine : day;
  const times = points.map((point) => point.t);
  const col = (read: (point: Point | DayPoint) => number | null | undefined) => points.map((point) => read(point) ?? null);
  const cpuSeries: ChartSeries[] = [
    { label: tr(language, "busy"), color: colors.blue, values: col((point) => point.cpu) },
    ...(short ? [] : [{ label: tr(language, "busyMax"), color: colors.violet, values: col((point) => (point as DayPoint).cpu_max) }]),
    { label: tr(language, "iowait"), color: colors.orange, values: col((point) => point.iowait) },
    { label: tr(language, "steal"), color: colors.magenta, values: col((point) => point.steal) }
  ];
  const memSeries: ChartSeries[] = [
    { label: tr(language, "usedShort"), color: colors.blue, values: col((point) => point.mem_used) },
    { label: tr(language, "cache"), color: colors.aqua, values: col((point) => point.mem_cache) },
    { label: tr(language, "swap"), color: colors.orange, values: col((point) => point.swap_used) }
  ];
  const netSeries: ChartSeries[] = [
    { label: tr(language, "received"), color: colors.aqua, values: col((point) => point.rx) },
    { label: tr(language, "sent"), color: colors.violet, values: col((point) => point.tx) }
  ];
  const diskSeries: ChartSeries[] = [
    { label: tr(language, "read"), color: colors.blue, values: col((point) => point.dr) },
    { label: tr(language, "write"), color: colors.orange, values: col((point) => point.dw) }
  ];
  const formatX = (ts: number) => formatClock(ts * 1000, language);
  const formatTooltipX = (ts: number) => formatDateTime(ts, language, short ? { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false } : { dateStyle: "medium", timeStyle: "short" });
  const common = { times, formatX, formatTooltipX, emptyText: tr(language, "noData"), height: 180, words };
  const nowCpu = lastOf(points, (point) => point.cpu);
  const nowMem = lastOf(points, (point) => point.mem_used);
  const nowRx = lastOf(points, (point) => point.rx);
  const nowTx = lastOf(points, (point) => point.tx);
  const nowRead = lastOf(points, (point) => point.dr);
  const nowWrite = lastOf(points, (point) => point.dw);
  return (
    <SectionCard
      title={tr(language, "history")}
      hint={tr(language, "historyHint")}
      status={
        <Stack direction="row" spacing={0.75} alignItems="center" role="status">
          <LiveDot active={live} color={theme.palette.success.main} />
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 650 }}>
            {live ? `${tr(language, "live")} · ${tr(language, "liveEvery", { n: formatNumber(interval, language) })}` : tr(language, "paused")}
          </Typography>
        </Stack>
      }
      action={<RangeToggle<Window> value={window} options={["15m", "24h"]} labelOf={(value) => tr(language, value === "15m" ? "range15m" : "range24h")} onChange={onWindow} label={tr(language, "rangeLabel")} />}
    >
      <Box sx={{ display: "grid", gap: 3, gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" } }}>
        <ChartBlock title={tr(language, "cpu")} now={`${words.now}: ${pct(nowCpu, language)}`} help={<HelpTip>{tr(language, "stealHelp")}</HelpTip>}>
          <LineChart {...common} title={tr(language, "cpu")} series={cpuSeries} yMax={100} formatY={(value) => pct(value, language)} />
        </ChartBlock>
        <ChartBlock title={tr(language, "memory")} now={`${words.now}: ${formatBytes(nowMem, language)}`}>
          <LineChart {...common} title={tr(language, "memory")} series={memSeries} yMax={memTotal ?? undefined} formatY={(value) => formatBytes(value, language)} />
        </ChartBlock>
        <ChartBlock title={tr(language, "network")} now={`↓ ${formatRate(nowRx, language)}  ↑ ${formatRate(nowTx, language)}`}>
          <LineChart {...common} title={tr(language, "network")} series={netSeries} area={false} formatY={(value) => formatRate(value, language)} />
        </ChartBlock>
        <ChartBlock title={tr(language, "diskIo")} now={`${tr(language, "read")} ${formatRate(nowRead, language)} · ${tr(language, "write")} ${formatRate(nowWrite, language)}`}>
          <LineChart {...common} title={tr(language, "diskIo")} series={diskSeries} area={false} formatY={(value) => formatRate(value, language)} />
        </ChartBlock>
      </Box>
    </SectionCard>
  );
}

function CoresCard({ fine, latest, facts, language }: { fine: Point[]; latest: Latest | null; facts: HostFacts | null; language: Language }) {
  const recent = fine.slice(-HEAT_COLUMNS);
  const coreCount = latest?.cores.length ?? recent[recent.length - 1]?.cores.length ?? 0;
  const rows = useMemo(
    () => Array.from({ length: coreCount }, (_, core) => recent.map((point) => point.cores[core] ?? null)),
    [recent, coreCount]
  );
  const current = latest?.cores ?? [];
  const numbers = current.filter((value): value is number => value !== null);
  const avg = numbers.length ? numbers.reduce((sum, value) => sum + value, 0) / numbers.length : null;
  const maxIndex = numbers.length ? current.indexOf(Math.max(...numbers)) : -1;
  const summary = avg === null ? tr(language, "noData") : tr(language, "coresSummary", { avg: pct(avg, language), n: formatNumber(maxIndex, language), max: pct(current[maxIndex], language) });
  const split = latest;
  return (
    <SectionCard title={tr(language, "coresTitle")} hint={tr(language, "coresHint")}>
      {coreCount > 0 ? (
        <CoreHeatMap
          rows={rows}
          title={tr(language, "coresTitle")}
          summary={summary}
          rowLabel={(index) => formatNumber(index, language)}
          cellText={(row, column, value) => tr(language, "coreCell", { n: formatNumber(row, language), time: formatClock((recent[column]?.t ?? 0) * 1000, language), p: pct(value, language) })}
          legendLow={tr(language, "idle")}
          legendHigh={tr(language, "full")}
        />
      ) : (
        <Typography variant="body2" color="text.secondary">{tr(language, "noData")}</Typography>
      )}
      <Box sx={{ display: "grid", gap: 1.5, gridTemplateColumns: { xs: "repeat(2, minmax(0, 1fr))", sm: "repeat(3, minmax(0, 1fr))" } }}>
        <MiniStat label={tr(language, "userTime")} value={pct(split?.user, language)} />
        <MiniStat label={tr(language, "systemTime")} value={pct(split?.system, language)} />
        <MiniStat label={tr(language, "iowait")} value={pct(split?.iowait, language)} />
        <MiniStat label={tr(language, "steal")} value={pct(split?.steal, language)} help={<HelpTip>{tr(language, "stealHelp")}</HelpTip>} />
        <MiniStat label={tr(language, "clock")} value={formatMhz(latest?.cpu_mhz ?? facts?.cpu.mhz, language)} detail={facts?.cpu.max_mhz ? tr(language, "maxClock", { mhz: formatMhz(facts.cpu.max_mhz, language) }) : undefined} />
        <MiniStat label={tr(language, "processes")} value={latest?.tasks_total !== null && latest?.tasks_total !== undefined ? tr(language, "processesLine", { running: formatNumber(latest.procs_running, language), total: formatNumber(latest.tasks_total, language) }) : "—"} />
      </Box>
    </SectionCard>
  );
}

function MiniStat({ label, value, detail, help }: { label: string; value: ReactNode; detail?: string; help?: ReactNode }) {
  return (
    <Box sx={{ p: 1.25, borderRadius: 2, bgcolor: "action.hover", minWidth: 0 }}>
      <Stack direction="row" alignItems="center" spacing={0.25}>
        <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 650 }}>{label}</Typography>
        {help}
      </Stack>
      <Typography variant="body2" sx={{ fontWeight: 760, overflowWrap: "anywhere" }}>{value}</Typography>
      {detail && <Typography variant="caption" color="text.secondary">{detail}</Typography>}
    </Box>
  );
}

function MemoryCard({ latest, language }: { latest: Latest | null; language: Language }) {
  const colors = useSeriesColors();
  const theme = useTheme();
  const memory = latest?.memory;
  if (!memory || !memory.total) {
    return <SectionCard title={tr(language, "memoryTitle")}><Typography variant="body2" color="text.secondary">{tr(language, "noData")}</Typography></SectionCard>;
  }
  const total = memory.total;
  const segments: Segment[] = [
    { key: "used", label: tr(language, "used"), value: memory.used ?? 0, color: colors.blue, valueText: formatBytes(memory.used, language) },
    { key: "buffers", label: tr(language, "buffers"), value: memory.buffers ?? 0, color: colors.violet, valueText: formatBytes(memory.buffers, language) },
    { key: "cache", label: tr(language, "cache"), value: memory.cache ?? 0, color: colors.aqua, valueText: formatBytes(memory.cache, language) },
    { key: "free", label: tr(language, "free"), value: memory.free ?? 0, color: theme.palette.action.hover, valueText: formatBytes(memory.free, language) }
  ];
  const swapPercent = memory.swap_total ? ((memory.swap_used ?? 0) / memory.swap_total) * 100 : null;
  const availablePercent = memory.available !== null ? (memory.available / total) * 100 : null;
  return (
    <SectionCard title={tr(language, "memoryTitle")} hint={tr(language, "memoryHint")}>
      <StackedBar segments={segments} total={total} label={tr(language, "memoryTitle")} />
      <Box sx={{ display: "grid", gap: 1.5, gridTemplateColumns: "repeat(2, minmax(0, 1fr))" }}>
        <MiniStat label={tr(language, "available")} value={formatBytes(memory.available, language)} detail={pct(availablePercent, language)} />
        <MiniStat label={tr(language, "memory")} value={formatBytes(total, language)} />
      </Box>
      <Box>
        <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.5 }}>
          <Typography variant="body2" sx={{ fontWeight: 700 }}>{tr(language, "swap")}</Typography>
          <Typography variant="body2" color="text.secondary">
            {memory.swap_total ? tr(language, "ofTotal", { used: formatBytes(memory.swap_used, language), total: formatBytes(memory.swap_total, language) }) : tr(language, "noSwap")}
          </Typography>
        </Stack>
        {memory.swap_total ? <UsageBar percent={swapPercent} tone={thresholdTone(swapPercent, 50, 80)} label={tr(language, "swap")} /> : null}
      </Box>
    </SectionCard>
  );
}

function DisksCard({ facts, fine, latest, language }: { facts: HostFacts; fine: Point[]; latest: Latest | null; language: Language }) {
  const colors = useSeriesColors();
  const io = latest?.disk ?? {};
  return (
    <SectionCard title={tr(language, "disksTitle")} hint={tr(language, "disksHint")}>
      <Box sx={{ display: "grid", gap: 3, gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" } }}>
        <Stack spacing={1.75}>
          <Typography variant="subtitle2" sx={{ fontWeight: 740 }}>{tr(language, "filesystems")}</Typography>
          {facts.filesystems.map((item) => {
            const percent = item.total_bytes && item.used_bytes !== null ? (item.used_bytes / item.total_bytes) * 100 : null;
            const tone = thresholdTone(percent, 80, 90);
            return (
              <Box key={item.device}>
                <Stack direction="row" justifyContent="space-between" spacing={1} sx={{ mb: 0.5 }}>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="body2" sx={{ fontWeight: 720 }}><Ltr mono>{item.mountpoint}</Ltr></Typography>
                    <Typography variant="caption" color="text.secondary"><Ltr mono>{`${item.device} · ${item.fstype}`}</Ltr></Typography>
                  </Box>
                  <Box sx={{ textAlign: "end", flexShrink: 0 }}>
                    <Typography variant="body2" sx={{ fontWeight: 760 }}>{percent === null ? "—" : pct(percent, language)}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.total_bytes ? tr(language, "ofTotal", { used: formatBytes(item.used_bytes, language), total: formatBytes(item.total_bytes, language) }) : tr(language, "notVisible")}
                    </Typography>
                  </Box>
                </Stack>
                {item.total_bytes ? <UsageBar percent={percent} tone={tone} label={`${item.mountpoint} ${pct(percent, language)}`} /> : null}
              </Box>
            );
          })}
        </Stack>
        <Stack spacing={1.5}>
          <Typography variant="subtitle2" sx={{ fontWeight: 740 }}>{tr(language, "devices")}</Typography>
          {facts.block_devices.map((device) => {
            const rates = io[device.name];
            return (
              <Box key={device.name} sx={{ p: 1.5, borderRadius: 2, border: 1, borderColor: "divider" }}>
                <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between" flexWrap="wrap" useFlexGap>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                    <StorageRoundedIcon fontSize="small" color="action" aria-hidden />
                    <Typography variant="body2" sx={{ fontWeight: 760 }}><Ltr mono>{device.name}</Ltr></Typography>
                    <Chip size="small" label={kindLabel(language, device.kind)} color={device.kind === "nvme" || device.kind === "ssd" ? "primary" : "default"} variant="outlined" />
                  </Stack>
                  <Typography variant="body2" sx={{ fontWeight: 720 }}>{formatBytes(device.size_bytes, language)}</Typography>
                </Stack>
                {(device.vendor || device.model) && <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}><Ltr>{[device.vendor, device.model].filter(Boolean).join(" ")}</Ltr></Typography>}
                <Box sx={{ display: "grid", gap: 1, gridTemplateColumns: "minmax(0, 1fr) auto", alignItems: "center", mt: 1 }}>
                  <Sparkline values={fine.slice(-90).map((point) => (point.disk[device.name] ? point.disk[device.name][0] + point.disk[device.name][1] : null))} color={colors.blue} label={`${device.name} ${tr(language, "diskIo")}`} />
                  <Typography variant="caption" color="text.secondary" sx={{ textAlign: "end", whiteSpace: "nowrap" }}>
                    {rates ? `${tr(language, "read")} ${formatRate(rates[0], language)} · ${tr(language, "write")} ${formatRate(rates[1], language)}` : "—"}
                  </Typography>
                </Box>
                {rates && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                    {tr(language, "ops", { r: formatNumber(rates[2], language, { maximumFractionDigits: 1 }), w: formatNumber(rates[3], language, { maximumFractionDigits: 1 }) })} · {tr(language, "busyTime", { p: pct(rates[4], language) })}
                  </Typography>
                )}
              </Box>
            );
          })}
        </Stack>
      </Box>
    </SectionCard>
  );
}

function NetworkCard({ facts, fine, latest, language }: { facts: HostFacts; fine: Point[]; latest: Latest | null; language: Language }) {
  const colors = useSeriesColors();
  return (
    <SectionCard title={tr(language, "interfacesTitle")} hint={tr(language, "interfacesHint")}>
      {facts.interfaces.length === 0 && <Typography variant="body2" color="text.secondary">{tr(language, "noInterfaces")}</Typography>}
      {facts.interfaces.map((item) => {
        const rates = latest?.net[item.name];
        const up = item.state === "up" || item.state === "unknown" || item.state === null;
        return (
          <Box key={item.name} sx={{ p: 1.5, borderRadius: 2, border: 1, borderColor: "divider" }}>
            <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between" flexWrap="wrap" useFlexGap>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="body2" sx={{ fontWeight: 760 }}><Ltr mono>{item.name}</Ltr></Typography>
                {item.state && <StatusPill tone={up ? "ok" : "off"} label={up ? tr(language, "stateUp") : tr(language, "stateDown")} />}
              </Stack>
              {item.speed_mbps ? <Typography variant="caption" color="text.secondary">{tr(language, "speed")}: {formatLinkSpeed(item.speed_mbps, language)}</Typography> : null}
            </Stack>
            {[...item.ipv4, ...item.ipv6].length > 0 && (
              <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap sx={{ mt: 0.75 }}>
                {[...item.ipv4, ...item.ipv6].map((address) => <Chip key={address} size="small" variant="outlined" label={<Ltr mono>{address}</Ltr>} />)}
              </Stack>
            )}
            <Box sx={{ display: "grid", gap: 1, gridTemplateColumns: "repeat(2, minmax(0, 1fr))", mt: 1 }}>
              <Box>
                <Typography variant="caption" color="text.secondary">↓ {tr(language, "received")} <Box component="span" sx={{ fontWeight: 760, color: "text.primary" }}>{formatRate(rates?.[0], language)}</Box></Typography>
                <Sparkline values={fine.slice(-90).map((point) => point.net[item.name]?.[0] ?? null)} color={colors.aqua} label={`${item.name} ${tr(language, "received")}`} />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">↑ {tr(language, "sent")} <Box component="span" sx={{ fontWeight: 760, color: "text.primary" }}>{formatRate(rates?.[1], language)}</Box></Typography>
                <Sparkline values={fine.slice(-90).map((point) => point.net[item.name]?.[1] ?? null)} color={colors.violet} label={`${item.name} ${tr(language, "sent")}`} />
              </Box>
            </Box>
          </Box>
        );
      })}
    </SectionCard>
  );
}

function SensorsCard({ sensors, language }: { sensors: Sensor[]; language: Language }) {
  const theme = useTheme();
  return (
    <SectionCard title={tr(language, "sensorsTitle")} hint={sensors.length ? tr(language, "sensorsHint") : undefined}>
      {sensors.length === 0 ? (
        <Notice tone="info">{tr(language, "noSensorsBody")}</Notice>
      ) : (
        <Stack spacing={1.5}>
          {sensors.map((sensor, index) => {
            const limit = sensor.critical ?? 100;
            const warn = sensor.high ?? Math.min(80, limit - 10);
            const tone = thresholdTone(sensor.celsius, warn, sensor.critical ?? 95);
            return (
              <Box key={`${sensor.chip}-${sensor.label}-${index}`}>
                <Stack direction="row" justifyContent="space-between" spacing={1} sx={{ mb: 0.5 }}>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="body2" sx={{ fontWeight: 700 }}><Ltr>{sensor.label}</Ltr></Typography>
                    <Typography variant="caption" color="text.secondary">
                      <Ltr mono>{sensor.chip}</Ltr>
                      {sensor.high ? ` · ${tr(language, "highAt", { c: formatCelsius(sensor.high, language) })}` : ""}
                      {sensor.critical ? ` · ${tr(language, "critAt", { c: formatCelsius(sensor.critical, language) })}` : ""}
                    </Typography>
                  </Box>
                  <Stack direction="row" spacing={0.75} alignItems="center" sx={{ flexShrink: 0 }}>
                    <Box aria-hidden sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: toneColor(theme, tone) }} />
                    <Typography variant="body2" sx={{ fontWeight: 780 }}>{formatCelsius(sensor.celsius, language)}</Typography>
                    <Typography variant="caption" color="text.secondary">{stateWord(language, tone)}</Typography>
                  </Stack>
                </Stack>
                <UsageBar percent={(sensor.celsius / limit) * 100} tone={tone} label={`${sensor.label} ${formatCelsius(sensor.celsius, language)}`} height={6} />
              </Box>
            );
          })}
        </Stack>
      )}
    </SectionCard>
  );
}

function TopContainersCard({ latest, memTotal, language }: { latest: Latest | null; memTotal: number | null; language: Language }) {
  const items = latest?.containers;
  const colors = useSeriesColors();
  if (!items) {
    return <SectionCard title={tr(language, "topTitle")}><Typography variant="body2" color="text.secondary">{tr(language, "noContainerStats")}</Typography></SectionCard>;
  }
  const byCpu = [...items].sort((a, b) => (b.cpu ?? 0) - (a.cpu ?? 0)).slice(0, 6);
  const byMem = [...items].sort((a, b) => (b.mem_bytes ?? 0) - (a.mem_bytes ?? 0)).slice(0, 6);
  const maxCpu = Math.max(1, ...byCpu.map((item) => item.cpu ?? 0));
  const list = (rows: ContainerLive[], kind: "cpu" | "mem") => (
    <Stack spacing={1.25}>
      <Typography variant="subtitle2" sx={{ fontWeight: 740 }}>{tr(language, kind === "cpu" ? "byCpu" : "byMem")}</Typography>
      {rows.map((item) => {
        const value = kind === "cpu" ? item.cpu : item.mem_bytes;
        const share = kind === "cpu" ? ((item.cpu ?? 0) / maxCpu) * 100 : memTotal && item.mem_bytes ? (item.mem_bytes / memTotal) * 100 : 0;
        const text = kind === "cpu" ? pct(value, language) : `${formatBytes(value, language)}${memTotal && item.mem_bytes ? ` · ${pct((item.mem_bytes / memTotal) * 100, language)}` : ""}`;
        return (
          <Box key={item.id}>
            <Stack direction="row" justifyContent="space-between" spacing={1} sx={{ mb: 0.4 }}>
              <Stack direction="row" spacing={0.5} alignItems="center" sx={{ minWidth: 0 }}>
                {item.protected && <LockRoundedIcon sx={{ fontSize: 14, color: "text.secondary" }} aria-label={tr(language, "locked")} />}
                <Typography variant="body2" noWrap sx={{ fontWeight: 650 }}><Ltr>{item.name}</Ltr></Typography>
              </Stack>
              <Typography variant="body2" sx={{ fontWeight: 760, whiteSpace: "nowrap" }}>{text}</Typography>
            </Stack>
            <Box sx={{ height: 6, borderRadius: 3, bgcolor: "action.hover", overflow: "hidden" }} aria-hidden>
              <Box sx={{ width: `${Math.max(Math.min(share, 100), value ? 1 : 0)}%`, height: "100%", borderRadius: 3, bgcolor: kind === "cpu" ? colors.blue : colors.aqua, transition: "width .6s" }} />
            </Box>
          </Box>
        );
      })}
    </Stack>
  );
  return (
    <SectionCard title={tr(language, "topTitle")} hint={tr(language, "topHint")}>
      <Box sx={{ display: "grid", gap: 3, gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" } }}>
        {list(byCpu, "cpu")}
        {list(byMem, "mem")}
      </Box>
    </SectionCard>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

/**
 * The live server dashboard. `fallback` is shown when the agent is too old for
 * `/v1/host/facts` (the classic tiles from /status still work then).
 */
export function ServerOverview({ fallback }: { fallback?: ReactNode }) {
  const { language } = useKit();
  const [window, setWindow] = useState<Window>("15m");
  const { facts, error: factsError } = useFacts();
  const { fine, day, latest, errorCode, failed, visible } = useLive(window);
  const outdated = (factsError instanceof ApiError && factsError.code === "agent_outdated") || errorCode === "agent_outdated";
  if (outdated) {
    return (
      <Stack spacing={2}>
        <Notice tone="warning">{tr(language, "outdated")}</Notice>
        {fallback}
      </Stack>
    );
  }
  if (facts && facts.available === false) {
    return <Notice>{tr(language, "noHostAccess")}</Notice>;
  }
  const sensors = latest?.temperatures ?? facts?.temperatures ?? [];
  const live = visible && !failed && errorCode === null && latest !== null;
  return (
    <Stack spacing={2.5}>
      {facts && <MachineCard facts={facts} latest={latest} language={language} />}
      {(failed !== null || (errorCode && errorCode !== "agent_not_configured")) && <Notice tone="warning">{tr(language, "liveProblem")}</Notice>}
      <GaugesCard facts={facts} latest={latest} language={language} />
      <HistoryCard fine={fine} day={day} window={window} onWindow={setWindow} live={live} interval={latest?.interval ?? LIVE_MS / 1000} memTotal={latest?.memory.total ?? facts?.memory.total_bytes ?? null} language={language} />
      <Box sx={{ display: "grid", gap: 2.5, gridTemplateColumns: { xs: "1fr", lg: "repeat(2, minmax(0, 1fr))" }, alignItems: "start" }}>
        <CoresCard fine={fine} latest={latest} facts={facts} language={language} />
        <MemoryCard latest={latest} language={language} />
      </Box>
      {facts && <DisksCard facts={facts} fine={fine} latest={latest} language={language} />}
      <Box sx={{ display: "grid", gap: 2.5, gridTemplateColumns: { xs: "1fr", lg: "repeat(2, minmax(0, 1fr))" }, alignItems: "start" }}>
        {facts && <NetworkCard facts={facts} fine={fine} latest={latest} language={language} />}
        <SensorsCard sensors={sensors} language={language} />
      </Box>
      <TopContainersCard latest={latest} memTotal={latest?.memory.total ?? facts?.memory.total_bytes ?? null} language={language} />
    </Stack>
  );
}

export default ServerOverview;
