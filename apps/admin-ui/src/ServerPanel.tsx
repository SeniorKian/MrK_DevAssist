/**
 * Server › overview (host summary, containers, logs) and Server › Docker tools (Advanced only).
 * Talks to the server helper (Host Agent) through `/api/v1/agent/*`. ServerPage provides the page header.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Box, Button, CircularProgress, InputAdornment, MenuItem, Stack, TextField, Typography } from "@mui/material";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import MemoryRoundedIcon from "@mui/icons-material/MemoryRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import SpeedRoundedIcon from "@mui/icons-material/SpeedRounded";
import ScheduleRoundedIcon from "@mui/icons-material/ScheduleRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import LinkRoundedIcon from "@mui/icons-material/LinkRounded";
import LinkOffRoundedIcon from "@mui/icons-material/LinkOffRounded";
import NetworkCheckRoundedIcon from "@mui/icons-material/NetworkCheckRounded";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import StopRoundedIcon from "@mui/icons-material/StopRounded";
import RestartAltRoundedIcon from "@mui/icons-material/RestartAltRounded";
import ArticleRoundedIcon from "@mui/icons-material/ArticleRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import DeveloperBoardRoundedIcon from "@mui/icons-material/DeveloperBoardRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { Language } from "./i18n";
import { useVisibleInterval } from "./polling";
import {
  ActionWizard, CopyField, DangerZone, EmptyState, FriendlyError, HelpTip, KeyValueList, Ltr, NoAccess, Notice, RelativeTime,
  ResponsiveList, SectionCard, StatGrid, StatTile, StatusPill, TestResult, useConfirmAction, useKit, useUndoSnackbar, formatDuration,
  formatSize, RegistrySettings, HelperNotice, helperProblem, helperSentence, type KeyValueItem, type ListColumn, type RowAction,
  type TestOutcome
} from "./kit";
import { CONFIRM_WORDS, pick, say, statusWord, type Bi } from "./copy";
import { formatNumber, formatPercent } from "./format";
import { ContainerLogsDialog } from "./ContainerLogsDialog";
import { DockerToolsSection, actionLabel, cleanName, isRunning, useContainerActions } from "./DockerTools";
import { ServerOverview } from "./ServerOverview";
import type { Tone } from "./copy/kinds";

type AgentStatus = {
  configured: boolean;
  source: "panel" | "env" | null;
  url: string | null;
  reachable: boolean;
  last_checked_at: number | null;
  last_error: string | null;
  version: string | null;
  capabilities: { docker: boolean; host_metrics: boolean; firewall: boolean } | null;
  docker: { version: string; api_version: string; containers_running: number; containers_total: number } | null;
  host: {
    hostname: string;
    kernel: string;
    uptime_seconds: number;
    cpu_count: number;
    loadavg: number[];
    memory: { total_bytes: number; available_bytes: number } | null;
    disks: Array<{ path: string; total_bytes: number; free_bytes: number }>;
  } | null;
};
type Container = {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
  created: number | string | null;
  ports: unknown;
  labels_subset: Record<string, string> | null;
  protected: boolean;
  /** healthy / unhealthy / starting when the image has a health check (newer agents). */
  health?: "healthy" | "unhealthy" | "starting" | null;
};
type AgentTest = { ok: boolean; latency_ms: number; error_code?: string | null };

type Props = { language: Language; permissions: string[]; onUnauthorized?: () => void; section?: "overview" | "docker" };

const BASE = "/api/v1/agent";
const DEFAULT_URL = "http://mrk-agent:7070";
// Run in the folder (or Dokploy/Coolify stack) where the agent was deployed.
const LOG_COMMAND = "docker compose logs mrk-agent | grep pairing";
const INTERVALS = [15, 30, 60, 0] as const;

const COPY = {
  refresh: { fa: "تازه کردن", en: "Refresh" },

  connectTitle: { fa: "دستیار سرور را وصل کنید", en: "Connect the server helper" },
  connectBody: {
    fa: "دستیار سرور (Agent) برنامه کوچکی کنار سرور است. با آن وضعیت سرور و کانتینرها را این‌جا می‌بینید و می‌توانید آن‌ها را روشن و خاموش کنید.",
    en: "The server helper (Agent) is a small program next to the server. With it you can see the server and its containers here, and start or stop them."
  },
  connectSafe: { fa: "کانتینرهای Dokploy همیشه محافظت می‌شوند و بی‌اجازه شما دست نمی‌خورند.", en: "Dokploy's containers are always protected and never touched without your say-so." },
  connectButton: { fa: "وصل کردن دستیار سرور", en: "Connect the server helper" },
  wizardTitle: { fa: "وصل کردن دستیار سرور", en: "Connect the server helper" },
  repairTitle: { fa: "وصل کردن دوباره یا عوض کردن کد اتصال", en: "Reconnect or change the pairing code" },
  step1: { fa: "روشن کردن", en: "Turn on" },
  step1Hint: { fa: "این دستور را در پوشه DevAssist روی سرور اجرا کنید تا دستیار سرور روشن شود.", en: "Run this in the DevAssist folder on the server to turn the helper on." },
  step1Label: { fa: "دستور روشن کردن", en: "Command to turn it on" },
  step1Wizard: {
    fa: "دستیار را از «سرویس‌های من ← افزودن سرویس» نصب کنید؛ آن‌جا کلید اتصال خودکار ساخته و وصل می‌شود. این مسیر فقط برای وصل کردن دستیاری است که از قبل نصب شده.",
    en: "Install the agent from My services → Add a service; it creates the key and connects by itself. This path is only for an agent that is already installed."
  },
  step1WizardButton: { fa: "افزودن سرویس", en: "Add a service" },
  step1Note: { fa: "دستیار سرور از قبل در فایل Compose هست؛ فقط باید روشنش کنید.", en: "The helper is already in the Compose file; you only need to turn it on." },
  step2: { fa: "کپی کد", en: "Copy the code" },
  step2Hint: { fa: "این دستور را اجرا کنید. در خروجی، کد اتصال را پیدا و کپی کنید.", en: "Run this command. Find the pairing code in the output and copy it." },
  step2Label: { fa: "دستور دیدن کد اتصال", en: "Command to show the pairing code" },
  step3: { fa: "چسباندن کد", en: "Paste the code" },
  step3Hint: { fa: "کد اتصالی را که کپی کردید این‌جا بچسبانید.", en: "Paste the pairing code you copied here." },
  keyLabel: { fa: "کد اتصال", en: "Pairing code" },
  keyKeep: { fa: "اگر خالی بماند، همان کد قبلی می‌ماند.", en: "Leave it empty to keep the current code." },
  keyNeeded: { fa: "کد اتصال را بچسبانید.", en: "Paste the pairing code." },
  urlLabel: { fa: "نشانی دستیار سرور", en: "Server helper address" },
  urlHint: { fa: "معمولاً همین مقدار پیش‌فرض درست است.", en: "The default is usually right." },
  urlRule: { fa: "نشانی باید با http یا https شروع شود.", en: "The address must start with http or https." },
  pair: { fa: "وصل کن", en: "Connect" },
  saveConnection: { fa: "ذخیره اتصال", en: "Save connection" },
  pairedDone: { fa: "دستیار سرور وصل شد.", en: "The server helper is connected." },
  savedDone: { fa: "اتصال دستیار سرور ذخیره شد.", en: "The server helper connection was saved." },
  pairedCheck: { fa: "برای اطمینان، اتصال یک بار امتحان شد:", en: "We tested the connection once to be sure:" },

  offlineTitle: { fa: "دستیار سرور جواب نمی‌دهد", en: "The server helper isn't answering" },
  offlineBody: { fa: "پنل به دستیار سرور نرسید. مطمئن شوید سرویس آن روی سرور روشن است.", en: "The panel couldn't reach the server helper. Make sure its service is running on the server." },
  lastCheck: { fa: "آخرین بررسی", en: "Last checked" },
  online: { fa: "وصل است", en: "Connected" },

  hostTitle: { fa: "وضعیت سرور", en: "Server at a glance" },
  cpu: { fa: "پردازنده", en: "CPU" },
  cpuBusy: { fa: "{p} مشغول", en: "{p} busy" },
  cores: { fa: "{n} هسته", en: "{n} cores" },
  memory: { fa: "حافظه", en: "Memory" },
  filled: { fa: "{p} پر", en: "{p} full" },
  ofTotal: { fa: "{used} از {total}", en: "{used} of {total}" },
  disk: { fa: "دیسک", en: "Disk" },
  freeLeft: { fa: "{free} خالی مانده", en: "{free} free" },
  uptime: { fa: "روشن بوده", en: "Up for" },
  uptimeCaption: { fa: "از آخرین راه‌اندازی دوباره", en: "Since the last restart" },
  noHost: { fa: "دستیار سرور اجازه دیدن اطلاعات سرور را ندارد.", en: "The server helper isn't allowed to read server information." },
  noHostHelp: { fa: "در فایل Compose، دسترسی خواندن اطلاعات سرور برای دستیار سرور خاموش است. راهنمای نصب را ببینید.", en: "Reading server information is turned off for the helper in the Compose file. See the setup guide." },
  noDocker: { fa: "دستیار سرور اجازه دسترسی به Docker را ندارد.", en: "The server helper isn't allowed to use Docker." },
  noDockerHelp: { fa: "در فایل Compose، دسترسی Docker برای دستیار سرور خاموش است. راهنمای نصب را ببینید.", en: "Docker access is turned off for the helper in the Compose file. See the setup guide." },

  containers: { fa: "کانتینرها", en: "Containers" },
  containersHint: { fa: "برنامه‌هایی که روی این سرور اجرا می‌شوند. کانتینرهای Dokploy قفل‌اند.", en: "The apps running on this server. Dokploy's containers are locked." },
  containersSummary: { fa: "{running} روشن از {total}", en: "{running} running of {total}" },
  search: { fa: "جست‌وجوی نام کانتینر", en: "Search container names" },
  noContainers: { fa: "هنوز کانتینری روی این سرور نیست.", en: "There are no containers on this server yet." },
  noContainersBody: { fa: "وقتی برنامه‌ای را با Dokploy منتشر کنید، کانتینرش این‌جا دیده می‌شود.", en: "When you deploy an app with Dokploy, its container shows up here." },
  noMatch: { fa: "کانتینری با «{q}» پیدا نشد. نام را بررسی کنید.", en: "No container matches “{q}”. Check the name." },
  clearSearch: { fa: "پاک کردن جست‌وجو", en: "Clear search" },
  containersError: { fa: "فهرست کانتینرها نیامد.", en: "The container list didn't load." },
  colName: { fa: "نام", en: "Name" },
  colState: { fa: "وضعیت", en: "State" },
  colImage: { fa: "نسخه برنامه", en: "Image" },
  colPorts: { fa: "پورت‌ها", en: "Ports" },
  colCreated: { fa: "ساخته‌شده", en: "Created" },
  colId: { fa: "شناسه", en: "ID" },
  colLabels: { fa: "برچسب‌ها", en: "Labels" },
  locked: { fa: "قفل Dokploy", en: "Dokploy lock" },
  lockedHint: { fa: "این کانتینر مال Dokploy است. فقط در حالت پیشرفته و با نوشتن نامش می‌شود آن را خاموش یا راه‌اندازی دوباره کرد.", en: "This container belongs to Dokploy. It can only be stopped or restarted in Advanced mode, by typing its name." },
  logs: { fa: "لاگ", en: "Logs" },
  stateOn: { fa: "روشن", en: "Running" },
  stateOnHealthy: { fa: "روشن · سالم", en: "Running · healthy" },
  stateOnUnhealthy: { fa: "روشن · مشکل دارد", en: "Running · unhealthy" },
  stateOnStarting: { fa: "روشن · در حال آماده شدن", en: "Running · starting" },
  stateRestarting: { fa: "در حال راه‌اندازی دوباره", en: "Restarting" },
  stateWorking: { fa: "در حال انجام", en: "Working…" },
  noOperate: { fa: "روشن و خاموش کردن کانتینرها", en: "Starting and stopping containers" },

  advancedTitle: { fa: "اتصال دستیار سرور", en: "Server helper connection" },
  advancedHint: { fa: "جزئیات فنی اتصال، قابلیت‌ها و آزمایش آن.", en: "Technical details of the connection, its capabilities and a test." },
  url: { fa: "نشانی", en: "Address" },
  source: { fa: "از کجا تنظیم شده", en: "Set from" },
  sourcePanel: { fa: "همین پنل", en: "This panel" },
  sourceEnv: { fa: "فایل Compose", en: "The Compose file" },
  envManaged: { fa: "این اتصال از فایل Compose تنظیم شده؛ برای تغییر، همان فایل را ویرایش کنید.", en: "This connection is set in the Compose file; edit that file to change it." },
  version: { fa: "نسخه دستیار", en: "Helper version" },
  capabilities: { fa: "قابلیت‌ها", en: "Capabilities" },
  capDocker: { fa: "Docker", en: "Docker" },
  capHost: { fa: "اطلاعات سرور", en: "Server info" },
  capFirewall: { fa: "دیوار آتش", en: "Firewall" },
  capOn: { fa: "روشن", en: "on" },
  capOff: { fa: "خاموش", en: "off" },
  hostname: { fa: "نام سرور", en: "Hostname" },
  kernel: { fa: "هسته لینوکس", en: "Kernel" },
  loadavg: { fa: "میانگین بار (۱، ۵ و ۱۵ دقیقه)", en: "Load average (1/5/15 min)" },
  dockerVersion: { fa: "نسخه Docker", en: "Docker version" },
  lastError: { fa: "آخرین مشکل اتصال", en: "Last connection problem" },
  test: { fa: "امتحان اتصال", en: "Test connection" },
  testing: { fa: "در حال امتحان…", en: "Testing…" },
  repair: { fa: "عوض کردن کد اتصال", en: "Change pairing code" },
  interval: { fa: "هر چند وقت تازه شود", en: "Auto-refresh every" },
  seconds: { fa: "{n} ثانیه", en: "{n} seconds" },
  never: { fa: "خودکار تازه نشود", en: "Don't auto-refresh" },
  noWrite: { fa: "وصل کردن دستیار سرور", en: "Connecting the server helper" },

  unpair: { fa: "قطع اتصال دستیار سرور", en: "Disconnect the server helper" },
  unpairButton: { fa: "قطع کن", en: "Disconnect" },
  unpairTitle: { fa: "اتصال دستیار سرور قطع شود؟", en: "Disconnect the server helper?" },
  unpairBody: { fa: "پنل دیگر به دستیار سرور وصل نمی‌شود و این صفحه تا اتصال دوباره خالی می‌ماند. خود دستیار روی سرور خاموش نمی‌شود.", en: "The panel stops talking to the helper and this page stays empty until you connect again. The helper itself keeps running on the server." },
  unpaired: { fa: "اتصال دستیار سرور قطع شد.", en: "The server helper was disconnected." },

  resources: { fa: "فضای اشغال‌شده توسط Docker", en: "Space used by Docker" },
  images: { fa: "نسخه‌های برنامه", en: "Images" },
  volumes: { fa: "فضاهای داده", en: "Volumes" },
  networks: { fa: "شبکه‌ها", en: "Networks" },
  containersCount: { fa: "کانتینرها", en: "Containers" },
  buildCache: { fa: "حافظه موقت ساخت", en: "Build cache" },
  total: { fa: "مجموع", en: "Total" },
  dockerToolsNeedsAgent: { fa: "برای ابزار Docker اول دستیار سرور باید وصل و روشن باشد.", en: "Docker tools need the server helper connected and running first." },
  dockerToolsNoAccess: { fa: "دانلود نسخه برنامه یا پاک‌سازی Docker", en: "Downloading images or cleaning up Docker" },
  settingsTitle: { fa: "همه تنظیمات سرور و دستیار", en: "Every server and helper setting" }
} satisfies Record<string, Bi>;

const t = (language: Language, key: keyof typeof COPY, params?: Record<string, string | number>) => (params ? say(language, COPY[key], params) : pick(language, COPY[key]));

function AgentError({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return <HelperNotice error={error} onRetry={onRetry} noPairAction />;
}

function formatPorts(ports: unknown): string {
  if (!ports) return "";
  if (typeof ports === "string") return ports;
  if (!Array.isArray(ports)) return "";
  return ports
    .map((item) => {
      if (typeof item === "string") return item;
      if (item && typeof item === "object") {
        const port = item as { PublicPort?: number; PrivatePort?: number; Type?: string; public_port?: number; private_port?: number; type?: string };
        const pub = port.PublicPort ?? port.public_port;
        const priv = port.PrivatePort ?? port.private_port;
        const type = port.Type ?? port.type ?? "tcp";
        return pub ? `${pub}→${priv}/${type}` : `${priv}/${type}`;
      }
      return "";
    })
    .filter(Boolean)
    .join(", ");
}

function createdTime(value: Container["created"]): number | null {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed / 1000;
  }
  return null;
}

/** A container's state as a pill: running is "on" (not a busy spinner), with Docker's health if any. */
function containerPill(language: Language, row: Container, busy: boolean): { tone: Tone; label: string } {
  if (busy) return { tone: "busy", label: t(language, "stateWorking") };
  if (row.state === "running") {
    if (row.health === "unhealthy") return { tone: "error", label: t(language, "stateOnUnhealthy") };
    if (row.health === "starting") return { tone: "warn", label: t(language, "stateOnStarting") };
    if (row.health === "healthy") return { tone: "ok", label: t(language, "stateOnHealthy") };
    return { tone: "ok", label: t(language, "stateOn") };
  }
  if (row.state === "restarting") return { tone: "warn", label: t(language, "stateRestarting") };
  const known = statusWord(language, row.state || "unknown");
  return { tone: known.tone === "busy" ? "warn" : known.tone, label: known.label };
}

function ContainerStatePill({ row, busy }: { row: Container; busy: boolean }) {
  const { language } = useKit();
  const pill = containerPill(language, row, busy);
  return <StatusPill tone={pill.tone} label={pill.label} />;
}

function meterTone(percent: number | null): "ok" | "warn" | "error" | "info" {
  if (percent === null) return "info";
  if (percent >= 90) return "error";
  if (percent >= 80) return "warn";
  return "ok";
}

/** Turn a stored `last_error` into something FriendlyError can explain (codes → sentence; text → details). */
function lastErrorAsApiError(text: string) {
  const code = /^[a-z][a-z0-9_]*$/.test(text) ? text : "agent_unreachable";
  return new ApiError(502, code, text);
}

// ── Pairing wizard ──────────────────────────────────────────────────────────

function PairWizard({ open, hasKey, initialUrl, onClose, onPaired }: { open: boolean; hasKey: boolean; initialUrl: string; onClose: () => void; onPaired: () => void }) {
  const { language, isAdvanced } = useKit();
  const [url, setUrl] = useState(initialUrl);
  const [key, setKey] = useState("");
  const [outcome, setOutcome] = useState<TestOutcome>({ state: "idle" });
  const [finished, setFinished] = useState(false);
  const urlOk = /^https?:\/\/\S+$/i.test(url.trim());

  useEffect(() => {
    if (open) {
      setUrl(initialUrl);
      setKey("");
      setOutcome({ state: "idle" });
      setFinished(false);
    }
    // Reset only when the wizard opens; a status refresh after pairing must not clear the result.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const finish = async () => {
    const body: { url: string; key?: string } = { url: url.trim() };
    if (key.trim()) body.key = key.trim();
    await mutateJson(`${BASE}/config`, { method: "PUT", body });
    setFinished(true);
    onPaired();
    setOutcome({ state: "running" });
    try {
      const result = await mutateJson<AgentTest>(`${BASE}/test`, { method: "POST" });
      setOutcome(result.ok ? { state: "ok", latencyMs: result.latency_ms } : { state: "fail", code: result.error_code ?? "agent_unreachable" });
    } catch (caught) {
      setOutcome({ state: "fail", error: caught });
    }
  };

  return (
    <ActionWizard
      open={open}
      title={hasKey ? t(language, "repairTitle") : t(language, "wizardTitle")}
      onClose={onClose}
      onFinish={finish}
      finishLabel={hasKey ? t(language, "saveConnection") : t(language, "pair")}
      done={finished ? (
        <Stack spacing={1.5}>
          <Notice tone="success">{hasKey ? t(language, "savedDone") : t(language, "pairedDone")}</Notice>
          <Typography variant="body2" color="text.secondary">{t(language, "pairedCheck")}</Typography>
          <TestResult outcome={outcome} />
        </Stack>
      ) : undefined}
      steps={[
        {
          key: "start",
          title: t(language, "step1"),
          hint: t(language, "step1Hint"),
          render: () => (
            <Stack spacing={1.5}>
              <Notice tone="info">{t(language, "step1Wizard")}</Notice>
              <Box>
                <Button variant="contained" href="#/services/add" sx={{ minHeight: 44 }}>{t(language, "step1WizardButton")}</Button>
              </Box>
              <Typography variant="body2" color="text.secondary">{t(language, "step1Note")}</Typography>
            </Stack>
          )
        },
        {
          key: "code",
          title: t(language, "step2"),
          hint: t(language, "step2Hint"),
          render: () => <CopyField label={t(language, "step2Label")} value={LOG_COMMAND} multiline />
        },
        {
          key: "paste",
          title: t(language, "step3"),
          hint: t(language, "step3Hint"),
          validate: () => {
            if (!hasKey && !key.trim()) return t(language, "keyNeeded");
            if (!urlOk) return t(language, "urlRule");
            return null;
          },
          render: () => (
            <Stack spacing={2}>
              <TextField
                fullWidth
                autoFocus
                type="password"
                label={t(language, "keyLabel")}
                value={key}
                helperText={hasKey ? t(language, "keyKeep") : " "}
                onChange={(event) => setKey(event.target.value)}
                slotProps={{ htmlInput: { dir: "ltr", autoComplete: "new-password", spellCheck: false } }}
              />
              {(isAdvanced || hasKey) && (
                <TextField
                  fullWidth
                  label={t(language, "urlLabel")}
                  value={url}
                  error={url.length > 0 && !urlOk}
                  helperText={url.length > 0 && !urlOk ? t(language, "urlRule") : t(language, "urlHint")}
                  onChange={(event) => setUrl(event.target.value)}
                  slotProps={{ htmlInput: { dir: "ltr", autoComplete: "off", spellCheck: false } }}
                />
              )}
            </Stack>
          )
        }
      ]}
    />
  );
}

// ── Host tiles ──────────────────────────────────────────────────────────────

function HostTiles({ status }: { status: AgentStatus }) {
  const { language, isAdvanced } = useKit();
  const host = status.host;
  if (!host) {
    return (
      <Notice action={<HelpTip>{t(language, "noHostHelp")}</HelpTip>}>{t(language, "noHost")}</Notice>
    );
  }
  const memory = host.memory;
  const memUsed = memory && memory.total_bytes > 0 ? memory.total_bytes - memory.available_bytes : null;
  const memPercent = memory && memUsed !== null ? (memUsed / memory.total_bytes) * 100 : null;
  const load1 = host.loadavg?.[0];
  const cpuPercent = load1 !== undefined && host.cpu_count > 0 ? Math.min(100, (load1 / host.cpu_count) * 100) : null;
  const pct = (value: number | null) => formatPercent(value === null ? null : Math.round(value), language);
  return (
    <StatGrid columns={4}>
      <StatTile
        icon={SpeedRoundedIcon}
        label={t(language, "cpu")}
        value={cpuPercent === null ? "—" : t(language, "cpuBusy", { p: pct(cpuPercent) })}
        caption={t(language, "cores", { n: host.cpu_count })}
        meter={cpuPercent}
        tone={meterTone(cpuPercent)}
      />
      <StatTile
        icon={MemoryRoundedIcon}
        label={t(language, "memory")}
        value={memPercent === null ? "—" : t(language, "filled", { p: pct(memPercent) })}
        caption={memory ? t(language, "ofTotal", { used: formatSize(memUsed, language), total: formatSize(memory.total_bytes, language) }) : undefined}
        meter={memPercent}
        tone={meterTone(memPercent)}
      />
      {host.disks.map((diskItem) => {
        const used = diskItem.total_bytes - diskItem.free_bytes;
        const percent = diskItem.total_bytes > 0 ? (used / diskItem.total_bytes) * 100 : null;
        return (
          <StatTile
            key={diskItem.path}
            icon={StorageRoundedIcon}
            label={isAdvanced || host.disks.length > 1 ? `${t(language, "disk")} · ${diskItem.path}` : t(language, "disk")}
            value={percent === null ? "—" : t(language, "filled", { p: pct(percent) })}
            caption={diskItem.total_bytes > 0
              ? `${t(language, "ofTotal", { used: formatSize(used, language), total: formatSize(diskItem.total_bytes, language) })} · ${t(language, "freeLeft", { free: formatSize(diskItem.free_bytes, language) })}`
              : t(language, "freeLeft", { free: formatSize(diskItem.free_bytes, language) })}
            meter={percent}
            tone={meterTone(percent)}
          />
        );
      })}
      <StatTile
        icon={ScheduleRoundedIcon}
        label={t(language, "uptime")}
        value={host.uptime_seconds > 0 ? formatDuration(host.uptime_seconds, language) : "—"}
        caption={t(language, "uptimeCaption")}
      />
    </StatGrid>
  );
}

// ── Containers ──────────────────────────────────────────────────────────────

function ContainersSection({
  status,
  containers,
  error,
  canOperate,
  canLogs,
  onRetry,
  onLogs,
  onActionDone,
  onActionError
}: {
  status: AgentStatus;
  containers: Container[] | null;
  error: unknown;
  canOperate: boolean;
  canLogs: boolean;
  onRetry: () => void;
  onLogs: (container: Container) => void;
  onActionDone: (message: string) => void;
  onActionError: (error: unknown) => void;
}) {
  const { language, isAdvanced, c } = useKit();
  const [query, setQuery] = useState("");
  const { run, busy, dialog } = useContainerActions({ onDone: onActionDone, onError: onActionError });
  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const list = [...(containers ?? [])].sort((a, b) => (a.state === b.state ? a.name.localeCompare(b.name) : a.state === "running" ? -1 : b.state === "running" ? 1 : 0));
    return needle ? list.filter((item) => item.name.toLowerCase().includes(needle) || item.image.toLowerCase().includes(needle)) : list;
  }, [containers, query]);

  if (status.capabilities?.docker === false) {
    return (
      <SectionCard title={t(language, "containers")}>
        <Notice action={<HelpTip>{t(language, "noDockerHelp")}</HelpTip>}>{t(language, "noDocker")}</Notice>
      </SectionCard>
    );
  }

  // Protected containers: actions only in Advanced mode (typed name). Simple shows the lock.
  const canAct = (row: Container) => canOperate && (!row.protected || isAdvanced) && busy === null;
  const columns: ListColumn<Container>[] = [
    { key: "name", header: t(language, "colName"), render: (row) => <Typography variant="body2" fontWeight={700}><Ltr>{cleanName(row.name)}</Ltr></Typography> },
    {
      key: "state",
      header: t(language, "colState"),
      render: (row) => (
        <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
          <ContainerStatePill row={row} busy={busy === row.id} />
          {row.protected && <LockBadge />}
        </Stack>
      )
    },
    { key: "image", header: t(language, "colImage"), render: (row) => <Ltr mono>{row.image}</Ltr>, ltr: true, advancedOnly: true },
    { key: "ports", header: t(language, "colPorts"), render: (row) => <Ltr mono>{formatPorts(row.ports) || "—"}</Ltr>, advancedOnly: true },
    { key: "created", header: t(language, "colCreated"), render: (row) => <RelativeTime value={createdTime(row.created)} />, advancedOnly: true },
    { key: "id", header: t(language, "colId"), render: (row) => <Ltr mono>{row.id.slice(0, 12)}</Ltr>, advancedOnly: true },
    {
      key: "labels",
      header: t(language, "colLabels"),
      advancedOnly: true,
      hideOnCard: true,
      render: (row) => {
        const entries = Object.entries(row.labels_subset ?? {});
        if (entries.length === 0) return "—";
        return (
          <Box sx={{ fontSize: 12, maxWidth: 360 }}>
            {entries.map(([key, value]) => <Box key={key} sx={{ overflowWrap: "anywhere" }}><Ltr mono>{`${key}=${value}`}</Ltr></Box>)}
          </Box>
        );
      }
    }
  ];
  const actions: RowAction<Container>[] = [
    { key: "logs", label: t(language, "logs"), icon: ArticleRoundedIcon, onClick: onLogs, hidden: () => !canLogs },
    { key: "start", label: actionLabel(language, "start"), icon: PlayArrowRoundedIcon, onClick: (row) => void run(row, "start"), hidden: (row) => !canAct(row) || isRunning(row.state) },
    { key: "restart", label: actionLabel(language, "restart"), icon: RestartAltRoundedIcon, onClick: (row) => void run(row, "restart"), hidden: (row) => !canAct(row) || !isRunning(row.state) },
    { key: "stop", label: actionLabel(language, "stop"), icon: StopRoundedIcon, danger: true, onClick: (row) => void run(row, "stop"), hidden: (row) => !canAct(row) || !isRunning(row.state) }
  ];
  const docker = status.docker;
  const summary = docker ? t(language, "containersSummary", { running: docker.containers_running, total: docker.containers_total }) : undefined;

  return (
    <SectionCard
      title={t(language, "containers")}
      hint={t(language, "containersHint")}
      status={summary ? <Typography variant="body2" color="text.secondary">{summary}</Typography> : undefined}
      flush
    >
      <Box sx={{ px: 2, pb: 1.5 }}>
        <TextField
          size="small"
          fullWidth
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={t(language, "search")}
          slotProps={{
            htmlInput: { "aria-label": t(language, "search") },
            input: { startAdornment: <InputAdornment position="start"><SearchRoundedIcon fontSize="small" /></InputAdornment> }
          }}
          sx={{ maxWidth: { sm: 360 } }}
        />
      </Box>
      {error !== null && <Box sx={{ px: 2, pb: 1.5 }}><AgentError error={error} onRetry={onRetry} /></Box>}
      {containers === null && error === null ? (
        <Box sx={{ p: 3, textAlign: "center" }}><CircularProgress size={24} aria-label={c.loading} /></Box>
      ) : (
        <ResponsiveList
          label={t(language, "containers")}
          rows={rows}
          rowKey={(row) => row.id}
          columns={columns}
          card={{
            title: (row) => <Ltr>{cleanName(row.name)}</Ltr>,
            meta: (row) => (isAdvanced ? <Ltr mono>{row.image}</Ltr> : row.protected ? t(language, "locked") : undefined),
            status: (row) => <ContainerStatePill row={row} busy={busy === row.id} />
          }}
          actions={actions}
          empty={
            query.trim()
              ? <EmptyState compact title={t(language, "noMatch", { q: query.trim() })} action={<Button onClick={() => setQuery("")}>{t(language, "clearSearch")}</Button>} />
              : <EmptyState compact title={t(language, "noContainers")} body={t(language, "noContainersBody")} action={<Button href="#/server/apps">{pick(language, { fa: "دیدن برنامه‌های Dokploy", en: "See Dokploy apps" })}</Button>} />
          }
        />
      )}
      {!canOperate && <Box sx={{ px: 2, pb: 2 }}><NoAccess needs="docker:operate" /></Box>}
      {dialog}
    </SectionCard>
  );
}

function LockBadge() {
  const { language } = useKit();
  return (
    <Stack direction="row" spacing={0.25} alignItems="center" sx={{ color: "text.secondary" }}>
      <LockRoundedIcon sx={{ fontSize: 16 }} aria-hidden />
      <Typography variant="caption">{t(language, "locked")}</Typography>
      <HelpTip>{t(language, "lockedHint")}</HelpTip>
    </Stack>
  );
}

// ── Advanced: Docker space ───────────────────────────────────────────────────

const USAGE_WORDS: Record<string, keyof typeof COPY> = {
  images: "images",
  images_bytes: "images",
  volumes: "volumes",
  volumes_bytes: "volumes",
  containers: "containersCount",
  containers_bytes: "containersCount",
  build_cache: "buildCache",
  build_cache_bytes: "buildCache",
  total: "total",
  total_bytes: "total"
};

function DockerSpaceCard() {
  const { language } = useKit();
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback((signal?: AbortSignal) => {
    setError(null);
    getJson<Record<string, unknown>>(`${BASE}/summary`, signal).then(setSummary, (caught) => {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const countOf = (value: unknown): number | null => {
    if (typeof value === "number") return value;
    if (Array.isArray(value)) return value.length;
    if (value && typeof value === "object") {
      const record = value as Record<string, unknown>;
      for (const key of ["count", "total"]) if (typeof record[key] === "number") return record[key] as number;
    }
    return null;
  };
  const usage = summary?.disk_usage;
  const usageItems: KeyValueItem[] =
    typeof usage === "number"
      ? [{ label: t(language, "total"), value: formatSize(usage, language) }]
      : usage && typeof usage === "object"
        ? Object.entries(usage as Record<string, unknown>)
          .filter(([, value]) => typeof value === "number")
          .map(([key, value]) => ({
            label: USAGE_WORDS[key] ? t(language, USAGE_WORDS[key]) : key,
            value: formatSize(value as number, language),
            hint: USAGE_WORDS[key] ? undefined : key
          }))
        : [];

  return (
    <SectionCard title={t(language, "resources")} advanced>
      {error !== null && <AgentError error={error} onRetry={() => load()} />}
      {summary === null && error === null && <CircularProgress size={22} />}
      {summary && (
        <Stack spacing={2}>
          <StatGrid columns={3}>
            <StatTile label={t(language, "images")} value={formatNumber(countOf(summary.images), language)} />
            <StatTile label={t(language, "volumes")} value={formatNumber(countOf(summary.volumes), language)} />
            <StatTile label={t(language, "networks")} value={formatNumber(countOf(summary.networks), language)} />
          </StatGrid>
          {usageItems.length > 0 && <KeyValueList items={usageItems} dense />}
        </Stack>
      )}
    </SectionCard>
  );
}

// ── Advanced: connection ─────────────────────────────────────────────────────

function readInterval(): number {
  try {
    const raw = window.localStorage.getItem("mrk-agent-refresh");
    const stored = Number(raw);
    return raw !== null && (INTERVALS as readonly number[]).includes(stored) ? stored : 30;
  } catch {
    return 30;
  }
}

function ConnectionCard({
  status,
  canWrite,
  interval,
  onInterval,
  onRepair,
  onUnpair
}: {
  status: AgentStatus;
  canWrite: boolean;
  interval: number;
  onInterval: (value: number) => void;
  onRepair: () => void;
  onUnpair: () => void;
}) {
  const { language } = useKit();
  const [outcome, setOutcome] = useState<TestOutcome>({ state: "idle" });
  const envManaged = status.source === "env";
  const host = status.host;
  const docker = status.docker;

  const test = async () => {
    setOutcome({ state: "running" });
    try {
      const result = await mutateJson<AgentTest>(`${BASE}/test`, { method: "POST" });
      setOutcome(result.ok ? { state: "ok", latencyMs: result.latency_ms } : { state: "fail", code: result.error_code ?? "agent_unreachable" });
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) return;
      setOutcome({ state: "fail", error: caught });
    }
  };

  const cap = (on: boolean | undefined) => (on ? t(language, "capOn") : t(language, "capOff"));
  const items: KeyValueItem[] = [
    { label: t(language, "url"), value: status.url ?? "—", ltr: true, copy: Boolean(status.url) },
    { label: t(language, "source"), value: status.source === "env" ? t(language, "sourceEnv") : status.source === "panel" ? t(language, "sourcePanel") : "—" },
    { label: t(language, "version"), value: status.version ?? "—", ltr: true },
    {
      label: t(language, "capabilities"),
      value: (
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
          <StatusPill tone={status.capabilities?.docker ? "ok" : "off"} label={`${t(language, "capDocker")}: ${cap(status.capabilities?.docker)}`} />
          <StatusPill tone={status.capabilities?.host_metrics ? "ok" : "off"} label={`${t(language, "capHost")}: ${cap(status.capabilities?.host_metrics)}`} />
          <StatusPill tone={status.capabilities?.firewall ? "ok" : "off"} label={`${t(language, "capFirewall")}: ${cap(status.capabilities?.firewall)}`} />
        </Stack>
      )
    },
    { label: t(language, "lastCheck"), value: <RelativeTime value={status.last_checked_at} /> }
  ];
  if (host) {
    items.push(
      { label: t(language, "hostname"), value: host.hostname, ltr: true },
      { label: t(language, "kernel"), value: host.kernel, ltr: true },
      { label: t(language, "loadavg"), value: (host.loadavg ?? []).map((value) => formatNumber(value, language, { maximumFractionDigits: 2 })).join(" / ") }
    );
  }
  if (docker) items.push({ label: t(language, "dockerVersion"), value: `${docker.version} · API ${docker.api_version}`, ltr: true });

  return (
    <SectionCard title={t(language, "advancedTitle")} hint={t(language, "advancedHint")} advanced>
      <Stack spacing={2}>
        {envManaged && <Notice>{t(language, "envManaged")}</Notice>}
        <KeyValueList items={items} />
        {status.last_error && (
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 0.5 }}>{t(language, "lastError")}</Typography>
            <FriendlyError error={lastErrorAsApiError(status.last_error)} severity="warning" noAction />
          </Box>
        )}
        <Stack direction="row" gap={1} flexWrap="wrap">
          <Button variant="outlined" startIcon={outcome.state === "running" ? <CircularProgress size={16} /> : <NetworkCheckRoundedIcon />} disabled={outcome.state === "running"} onClick={() => void test()} sx={{ minHeight: 40 }}>
            {outcome.state === "running" ? t(language, "testing") : t(language, "test")}
          </Button>
          {canWrite && !envManaged && <Button startIcon={<LinkRoundedIcon />} onClick={onRepair} sx={{ minHeight: 40 }}>{t(language, "repair")}</Button>}
        </Stack>
        <TestResult outcome={outcome} />
        {!canWrite && <NoAccess needs="agent:write" />}
        <TextField select size="small" label={t(language, "interval")} value={interval} onChange={(event) => onInterval(Number(event.target.value))} sx={{ maxWidth: 260 }}>
          {INTERVALS.map((value) => (
            <MenuItem key={value} value={value}>{value === 0 ? t(language, "never") : t(language, "seconds", { n: value })}</MenuItem>
          ))}
        </TextField>
      </Stack>
      {canWrite && !envManaged && (
        <Box sx={{ mt: 2 }}>
          <DangerZone
            items={[{
              title: t(language, "unpair"),
              description: t(language, "unpairBody"),
              action: <Button color="error" variant="outlined" startIcon={<LinkOffRoundedIcon />} onClick={onUnpair}>{t(language, "unpairButton")}</Button>
            }]}
          />
        </Box>
      )}
    </SectionCard>
  );
}

// ── Panel ───────────────────────────────────────────────────────────────────

function wantsConnectWizard() {
  const query = window.location.hash.split("?")[1] ?? "";
  return new URLSearchParams(query).get("connect") === "agent";
}

export function ServerPanel({ language, permissions, section = "overview" }: Props) {
  const { isAdvanced } = useKit();
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canWrite = hasPermission(permissions, "agent:write");
  const canOperate = hasPermission(permissions, "docker:operate");
  const canPrune = hasPermission(permissions, "docker:prune");
  const canLogs = hasPermission(permissions, "logs:read");
  const [logsTarget, setLogsTarget] = useState<{ id: string; name: string } | null>(null);
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [containers, setContainers] = useState<Container[] | null>(null);
  const [containersError, setContainersError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [wizard, setWizard] = useState<"pair" | "repair" | null>(null);
  const [interval, setIntervalSeconds] = useState<number>(readInterval);
  const controller = useRef<AbortController | null>(null);
  const autoOpened = useRef(false);

  const load = useCallback(async (background = false) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    if (!background) setLoading(true);
    try {
      const payload = await getJson<AgentStatus>(`${BASE}/status`, current.signal);
      setStatus(payload);
      setUnavailable(false);
      setLoadError(null);
      if (section === "overview" && payload.configured && payload.reachable && payload.capabilities?.docker !== false) {
        try {
          const list = await getJson<{ items: Container[] }>(`${BASE}/containers`, current.signal);
          setContainers(list.items);
          setContainersError(null);
        } catch (caught) {
          if (isAbortError(caught)) throw caught;
          if (!(caught instanceof ApiError && caught.status === 401)) setContainersError(caught);
        }
      }
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      if (helperProblem(caught) === "module_missing") setUnavailable(true);
      else setLoadError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, [section]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);
  useVisibleInterval(() => void load(true), section === "overview" && !unavailable && status?.configured && interval > 0 ? interval * 1000 : null);

  // Home's «وصل کردن» links to #/server/overview?connect=agent.
  useEffect(() => {
    if (autoOpened.current || !status || status.configured || !canWrite) return;
    if (wantsConnectWizard()) {
      autoOpened.current = true;
      setWizard("pair");
    }
  }, [status, canWrite]);

  const changeInterval = (value: number) => {
    setIntervalSeconds(value);
    try {
      window.localStorage.setItem("mrk-agent-refresh", String(value));
    } catch {
      // storage unavailable
    }
  };

  const unpair = async () => {
    const ok = await ask({
      title: pick(language, COPY.unpairTitle),
      body: pick(language, COPY.unpairBody),
      severity: "destructive",
      undoable: true,
      typed: CONFIRM_WORDS.disconnect,
      confirmLabel: pick(language, COPY.unpairButton)
    });
    if (!ok) return;
    setActionError(null);
    try {
      // The agent endpoint expects the UNPAIR token; the user typed «قطع کن».
      await mutateJson(`${BASE}/config`, { method: "DELETE", body: { confirmation: CONFIRM_WORDS.unpair.token } });
      notify({ message: pick(language, COPY.unpaired), tone: "info" });
      setContainers(null);
      await load(true);
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const onPaired = () => {
    setContainers(null);
    void load();
  };

  const header = (
    <Stack direction="row" spacing={1.5} alignItems="center" justifyContent="flex-end" flexWrap="wrap" useFlexGap>
      {status?.configured && (
        <Stack direction="row" spacing={1} alignItems="center" role="status">
          <StatusPill tone={status.reachable ? "ok" : "error"} label={status.reachable ? pick(language, COPY.online) : statusWord(language, "unreachable").label} />
          {status.last_checked_at && <Typography variant="caption" color="text.secondary">{pick(language, COPY.lastCheck)}: <RelativeTime value={status.last_checked_at} /></Typography>}
        </Stack>
      )}
      <Button variant="outlined" startIcon={loading ? <CircularProgress size={16} /> : <RefreshRoundedIcon />} onClick={() => void load()} disabled={loading} sx={{ minHeight: 40 }}>
        {pick(language, COPY.refresh)}
      </Button>
    </Stack>
  );

  const pairWizard = (
    <PairWizard
      open={wizard !== null}
      hasKey={wizard === "repair"}
      initialUrl={status?.url ?? DEFAULT_URL}
      onClose={() => setWizard(null)}
      onPaired={onPaired}
    />
  );

  const common = (
    <>
      {unavailable && <Notice>{helperSentence(language, "module_missing")}</Notice>}
      {loadError !== null && <AgentError error={loadError} onRetry={() => void load()} />}
      {actionError !== null && <FriendlyError error={actionError} onClose={() => setActionError(null)} />}
      {loading && !status && !unavailable && loadError === null && <Box sx={{ textAlign: "center", py: 3 }}><CircularProgress size={26} /></Box>}
    </>
  );

  const notConnected = status && !status.configured && !unavailable && (
    <SectionCard title={pick(language, COPY.connectTitle)} hint={pick(language, COPY.connectBody)} action={<HelpTip term="agent" />}>
      <Stack spacing={2} alignItems="flex-start">
        <Stack direction="row" spacing={1} alignItems="center">
          <DeveloperBoardRoundedIcon color="primary" aria-hidden />
          <Typography variant="body2" color="text.secondary">{pick(language, COPY.connectSafe)}</Typography>
        </Stack>
        {canWrite
          ? <Button variant="contained" size="large" startIcon={<LinkRoundedIcon />} onClick={() => setWizard("pair")}>{pick(language, COPY.connectButton)}</Button>
          : <NoAccess needs="agent:write" variant="card" />}
      </Stack>
    </SectionCard>
  );

  if (section === "docker") {
    const ready = status?.configured && status.reachable && status.capabilities?.docker !== false;
    return (
      <Stack spacing={2.5}>
        {header}
        {common}
        {notConnected}
        {status?.configured && !ready && <Notice tone="warning">{pick(language, COPY.dockerToolsNeedsAgent)}</Notice>}
        {ready && (canOperate || canPrune
          ? <DockerToolsSection canOperate={canOperate} canPrune={canPrune} />
          : <NoAccess needs={["docker:operate", "docker:prune"]} variant="card" />)}
        {pairWizard}
        {dialog}
        {snackbar}
      </Stack>
    );
  }

  return (
    <Stack spacing={2.5}>
      {header}
      {common}
      {notConnected}

      {status?.configured && (
        <>
          {!status.reachable && (
            <Notice tone="warning" action={<Button color="inherit" size="small" onClick={() => void load()}>{pick(language, COPY.refresh)}</Button>}>
              <strong>{pick(language, COPY.offlineTitle)}.</strong> {pick(language, COPY.offlineBody)}
            </Notice>
          )}
          {status.reachable && (
            status.host
              ? <ServerOverview fallback={<SectionCard title={pick(language, COPY.hostTitle)}><HostTiles status={status} /></SectionCard>} />
              : <SectionCard title={pick(language, COPY.hostTitle)}><HostTiles status={status} /></SectionCard>
          )}
          {status.reachable && (
            <ContainersSection
              status={status}
              containers={containers}
              error={containersError}
              canOperate={canOperate}
              canLogs={canLogs}
              onRetry={() => void load()}
              onLogs={(item) => setLogsTarget({ id: item.id, name: cleanName(item.name) })}
              onActionDone={(message) => { notify({ message, tone: "success" }); setActionError(null); void load(true); }}
              onActionError={(caught) => { setActionError(caught); void load(true); }}
            />
          )}
          {isAdvanced && (
            <ConnectionCard
              status={status}
              canWrite={canWrite}
              interval={interval}
              onInterval={changeInterval}
              onRepair={() => setWizard("repair")}
              onUnpair={() => void unpair()}
            />
          )}
          {isAdvanced && status.reachable && status.capabilities?.docker !== false && <DockerSpaceCard />}
        </>
      )}
      {isAdvanced && <RegistrySettings groups={["server.overview"]} permissions={permissions} title={pick(language, COPY.settingsTitle)} />}
      {pairWizard}
      {logsTarget && <ContainerLogsDialog container={logsTarget} language={language} onClose={() => setLogsTarget(null)} />}
      {dialog}
      {snackbar}
    </Stack>
  );
}

export default ServerPanel;
