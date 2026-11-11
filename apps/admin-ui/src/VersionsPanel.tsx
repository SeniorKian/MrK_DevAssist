/**
 * «نسخه‌ها و به‌روزرسانی» / Versions & updates. Which release the panel runs, whether a newer one is
 * out, and how to move the panel and every installed service to it (panel first, then services).
 *
 * Data: `GET /api/v1/releases/status` (services:read): current version, the latest published one
 * (checked every 12 hours, `POST /api/v1/releases/check` checks now), how the panel itself can be
 * updated, and each service's deployed image vs. the image this panel ships with.
 *
 * Actions:
 * - panel: `POST /api/v1/releases/panel/upgrade {version, confirmation:"UPDATE"}` when the panel runs
 *   as a Dokploy compose (it restarts); otherwise ready commands to copy;
 * - services the panel deployed through Dokploy/Coolify: `POST /api/v1/releases/services/{id}/upgrade`,
 *   followed with `GET /api/v1/releases/jobs/{job}`; only the image line changes, pairing keys stay;
 * - other services: `GET /api/v1/releases/services/{id}/manual` (new compose.yaml, the one env line,
 *   steps per tool) and `POST /api/v1/releases/services/{id}/mark-updated` once done.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, LinearProgress, Link,
  Skeleton, Stack, Tab, Tabs, Typography, useMediaQuery, useTheme
} from "@mui/material";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import SystemUpdateAltRoundedIcon from "@mui/icons-material/SystemUpdateAltRounded";
import MenuBookRoundedIcon from "@mui/icons-material/MenuBookRounded";
import NewReleasesRoundedIcon from "@mui/icons-material/NewReleasesRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { CONFIRM_WORDS, pick, say, type Bi } from "./copy";
import { CodeBlock, serviceName } from "./AddServicePanel";
import { CopyField, FriendlyError, Ltr, Notice, RelativeTime, SectionCard, StatusPill, useConfirmAction, useKit } from "./kit";
import type { Language } from "./i18n";
import { routeHref } from "./nav";

// ── API types ────────────────────────────────────────────────────────────────

type Command = { title_fa: string; title_en: string; command: string };
type PanelMethod = "dokploy" | "compose" | "native";
type Connection = "connected" | "unreachable" | "not_connected" | "unavailable";
type ServiceRow = {
  id: string;
  image: string | null;
  deployed_image: string | null;
  installed: boolean;
  target: "dokploy" | "coolify" | null;
  can_auto: boolean;
  needs_update: boolean;
  connection: Connection;
};
type Status = {
  current: { version: string; image_tag: string; runtime: "docker" | "native" };
  latest: { version: string | null; checked_at: number | null; error_code: string | null; notes_url: string | null; checking?: boolean };
  update_available: boolean;
  panel: { method: PanelMethod; can_auto: boolean; commands: Command[] };
  services: ServiceRow[];
};
type Job = {
  id: string;
  status: "running" | "succeeded" | "failed";
  phase: string;
  error_code: string | null;
  connection: Connection | null;
};
type Step = { fa: string; en: string };
type Manual = {
  id: string;
  image: string;
  compose: string;
  env_change: string | null;
  steps: Record<"dokploy" | "coolify" | "compose", Step[]>;
  commands: string[];
};

/** Same extra permission as installing the service (install.py WRITE_PERMISSION). */
const WRITE_PERMISSION: Record<string, string> = {
  agent: "agent:write", firewall: "firewall:write", dns: "dns:write", s3: "s3:admin",
  npm: "upstream:write", pypi: "upstream:write", git: "git:write", registry: "registry:write"
};

// ── copy ─────────────────────────────────────────────────────────────────────

const COPY = {
  loadFailed: { fa: "وضعیت نسخه‌ها باز نشد.", en: "The version status didn't load." },
  currentTitle: { fa: "نسخه فعلی", en: "Current version" },
  currentBody: { fa: "این پنل نسخه {version} است.", en: "This panel runs version {version}." },
  runtimeDocker: { fa: "در Docker", en: "In Docker" },
  runtimeNative: { fa: "مستقیم روی سرور", en: "Directly on the server" },
  newVersion: { fa: "نسخه {version} آمده است.", en: "Version {version} is out." },
  upToDate: { fa: "پنل تازه‌ترین نسخه را دارد.", en: "The panel is on the latest version." },
  neverChecked: { fa: "هنوز بررسی نشده که نسخه تازه‌ای آمده یا نه.", en: "Not checked yet for a new version." },
  checkFailed: { fa: "بررسی نسخه تازه انجام نشد: {reason}", en: "Couldn't check for a new version: {reason}" },
  checkedAt: { fa: "آخرین بررسی:", en: "Last checked:" },
  checkAgain: { fa: "بررسی دوباره", en: "Check again" },
  notes: { fa: "چه چیزهایی تازه است", en: "What's new" },
  order: {
    fa: "اول پنل را به‌روز کنید، بعد سرویس‌ها را؛ هر سرویس با نسخه‌ای کار می‌کند که پنل همراه خودش دارد.",
    en: "Update the panel first, then the services; each service runs the version the panel ships with."
  },
  panelTitle: { fa: "به‌روزرسانی پنل", en: "Update the panel" },
  panelDokploy: { fa: "پنل در Dokploy اجرا می‌شود و می‌تواند خودش را به‌روز کند.", en: "The panel runs in Dokploy and can update itself." },
  panelDokployManual: { fa: "پنل در Dokploy اجرا می‌شود؛ برای به‌روزرسانی از اینجا، Dokploy باید وصل باشد.", en: "The panel runs in Dokploy; to update it from here, Dokploy must be connected." },
  panelCompose: { fa: "پنل با Docker Compose اجرا می‌شود. این دستورها را روی سرور اجرا کنید:", en: "The panel runs with Docker Compose. Run these on the server:" },
  panelNative: { fa: "پنل بدون Docker روی سرور نصب شده است. این دستور را روی سرور اجرا کنید:", en: "The panel is installed on the server without Docker. Run this on the server:" },
  panelButton: { fa: "به‌روزرسانی پنل به {version}", en: "Update the panel to {version}" },
  panelNoPermission: { fa: "به‌روزرسانی خود پنل فقط از مدیر کامل برمی‌آید.", en: "Only a full administrator can update the panel itself." },
  panelConfirmTitle: { fa: "پنل به نسخه {version} به‌روز شود؟", en: "Update the panel to {version}?" },
  panelConfirmBody: {
    fa: "پنل برای چند ثانیه تا چند دقیقه در دسترس نیست و بعد با نسخه تازه برمی‌گردد. تنظیمات و داده‌ها می‌مانند.",
    en: "The panel goes away for a few seconds to a few minutes and comes back with the new version. Settings and data stay."
  },
  panelStarted: { fa: "به‌روزرسانی شروع شد. پنل چند لحظه قطع می‌شود؛ بعد این صفحه را دوباره باز کنید.", en: "The update started. The panel will be away for a moment; then reload this page." },
  panelLatest: { fa: "پنل تازه‌ترین نسخه را دارد؛ کاری لازم نیست.", en: "The panel is on the latest version; nothing to do." },
  servicesTitle: { fa: "سرویس‌ها", en: "Services" },
  servicesHint: { fa: "هر سرویسی که نصب کرده‌اید و نسخه‌ای که با این پنل جور است.", en: "Every service you installed and the version that matches this panel." },
  noServices: { fa: "هنوز سرویسی از «افزودن سرویس» نصب نکرده‌اید.", en: "You haven't installed any service from “Add a service” yet." },
  notInstalled: { fa: "نصب نشده", en: "Not installed" },
  needsUpdate: { fa: "نسخه تازه دارد", en: "Update available" },
  current: { fa: "به‌روز", en: "Up to date" },
  unknownImage: { fa: "معلوم نیست", en: "Unknown" },
  deployed: { fa: "الان:", en: "Now:" },
  target: { fa: "نسخه تازه:", en: "New:" },
  via: { fa: "نصب‌شده با {tool}", en: "Installed with {tool}" },
  viaManual: { fa: "نصب دستی", en: "Installed by hand" },
  update: { fa: "به‌روزرسانی", en: "Update" },
  guide: { fa: "راهنمای به‌روزرسانی", en: "How to update" },
  updated: { fa: "به‌روز شد.", en: "Updated." },
  updateFailed: { fa: "به‌روزرسانی انجام نشد.", en: "The update didn't finish." },
  noOperate: { fa: "برای به‌روزرسانی سرویس‌ها اجازه «روشن و خاموش کردن سرویس‌ها» لازم است.", en: "Updating services needs the “start and stop services” permission." },
  manualTitle: { fa: "به‌روزرسانی «{name}»", en: "Update “{name}”" },
  manualIntro: { fa: "فایل compose.yaml تازه را جایگزین کنید و در تنظیمات فقط یک خط را عوض کنید. کلید اتصال و بقیه مقدارها همان می‌مانند.", en: "Replace compose.yaml with the new one and change one line of the settings. The pairing key and every other value stay as they are." },
  manualNoEnv: { fa: "این سرویس ایمیج ثابت خودش را دارد؛ فقط فایل compose.yaml را عوض کنید.", en: "This service pins its own image; only replace compose.yaml." },
  envLine: { fa: "خطی که در تنظیمات عوض می‌شود", en: "The settings line to change" },
  composeFile: { fa: "فایل compose.yaml تازه", en: "New compose.yaml" },
  commandsLabel: { fa: "دستورها", en: "Commands" },
  markDone: { fa: "به‌روزرسانی را انجام دادم", en: "I've updated it" },
  close: { fa: "بستن", en: "Close" },
  chip: { fa: "نسخه تازه {version}", en: "New version {version}" }
} satisfies Record<string, Bi>;

const TOOL_TAB: Record<"dokploy" | "coolify" | "compose", Bi> = {
  dokploy: { fa: "Dokploy", en: "Dokploy" },
  coolify: { fa: "Coolify", en: "Coolify" },
  compose: { fa: "Docker Compose", en: "Docker Compose" }
};

const PHASES: Record<string, Bi> = {
  preparing: { fa: "آماده‌سازی", en: "Preparing" },
  configuring: { fa: "گذاشتن فایل‌های تازه", en: "Putting the new files in place" },
  deploying: { fa: "بالا آوردن نسخه تازه", en: "Starting the new version" },
  waiting: { fa: "صبر تا آماده شود", en: "Waiting until it's ready" },
  connecting: { fa: "بررسی اتصال به پنل", en: "Checking the connection to the panel" },
  done: { fa: "تمام شد", en: "Done" }
};

const CHECK_ERRORS: Record<string, Bi> = {
  unreachable: { fa: "مخزن ایمیج‌ها در دسترس نبود", en: "the image registry couldn't be reached" },
  proxy_unavailable: { fa: "پروکسی تنظیم‌شده کار نمی‌کند", en: "the configured proxy doesn't work" },
  auth_required: { fa: "مخزن ایمیج‌ها اجازه دیدن نسخه‌ها را نداد", en: "the image registry didn't allow listing versions" },
  not_found: { fa: "ایمیج پنل در مخزن پیدا نشد", en: "the panel image wasn't found in the registry" },
  rate_limited: { fa: "مخزن ایمیج‌ها گفت کمی بعد دوباره امتحان کنید", en: "the image registry asked to try again later" },
  no_release: { fa: "هنوز نسخه منتشرشده‌ای نیست", en: "there is no published release yet" }
};

const JOB_ERRORS: Record<string, Bi> = {
  deploy_failed: { fa: "نسخه تازه بالا نیامد؛ گزارش استقرار را در همان ابزار ببینید.", en: "The new version didn't start; see the deployment log in that tool." },
  deploy_timeout: { fa: "بالا آمدن نسخه تازه بیش از حد طول کشید.", en: "Starting the new version took too long." },
  connect_failed: { fa: "نسخه تازه بالا آمد ولی هنوز به پنل جواب نمی‌دهد؛ کمی بعد دوباره نگاه کنید.", en: "The new version is up but doesn't answer the panel yet; look again in a moment." },
  service_missing: { fa: "این سرویس دیگر در آن ابزار پیدا نمی‌شود.", en: "This service can't be found in that tool any more." }
};

function title(language: Language, command: Command) {
  return language === "fa" ? command.title_fa || command.title_en : command.title_en || command.title_fa;
}

function errorCode(error: unknown) {
  return error instanceof ApiError ? error.code : "";
}

// ── «new version» chip (services page header) ───────────────────────────────

/** Small chip that links to this tab when a newer release is out; renders nothing otherwise. */
export function NewReleaseChip() {
  const { language } = useKit();
  const [latest, setLatest] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    getJson<{ latest: string | null; update_available: boolean }>("/api/v1/releases/summary", controller.signal)
      .then((summary) => setLatest(summary.update_available ? summary.latest : null))
      .catch(() => setLatest(null));
    return () => controller.abort();
  }, []);
  if (!latest) return null;
  return (
    <Chip
      component="a"
      href={routeHref("services", "versions")}
      clickable
      color="info"
      size="small"
      icon={<NewReleasesRoundedIcon />}
      label={say(language, COPY.chip, { version: latest })}
    />
  );
}

// ── manual dialog ────────────────────────────────────────────────────────────

function ManualDialog({ serviceId, canMark, onClose, onDone }: { serviceId: string; canMark: boolean; onClose: () => void; onDone: () => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [manual, setManual] = useState<Manual | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tool, setTool] = useState<"dokploy" | "coolify" | "compose">("dokploy");
  const [marking, setMarking] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    getJson<Manual>(`/api/v1/releases/services/${serviceId}/manual`, controller.signal)
      .then(setManual)
      .catch((caught) => { if (!isAbortError(caught)) setError(caught); });
    return () => controller.abort();
  }, [serviceId]);
  const name = serviceName(language, serviceId);
  const mark = async () => {
    setMarking(true);
    try {
      await mutateJson(`/api/v1/releases/services/${serviceId}/mark-updated`, { method: "POST" });
      onDone();
    } catch (caught) {
      setError(caught);
    } finally {
      setMarking(false);
    }
  };
  return (
    <Dialog open onClose={onClose} fullScreen={fullScreen} maxWidth="md" fullWidth>
      <DialogTitle>{say(language, COPY.manualTitle, { name })}</DialogTitle>
      <DialogContent dividers>
        {error ? <FriendlyError error={error} /> : null}
        {!manual && !error ? <Skeleton variant="rounded" height={240} /> : null}
        {manual ? (
          <Stack spacing={2}>
            <Typography>{pick(language, manual.env_change ? COPY.manualIntro : COPY.manualNoEnv)}</Typography>
            {manual.env_change ? <CopyField label={pick(language, COPY.envLine)} value={manual.env_change} /> : null}
            <CodeBlock title={pick(language, COPY.composeFile)} value={manual.compose} fileName="compose.yaml" />
            <Tabs value={tool} onChange={(_event, next: "dokploy" | "coolify" | "compose") => setTool(next)} variant="scrollable" allowScrollButtonsMobile>
              {(["dokploy", "coolify", "compose"] as const).map((key) => (
                <Tab key={key} value={key} label={pick(language, TOOL_TAB[key])} />
              ))}
            </Tabs>
            <Box component="ol" sx={{ m: 0, ps: 3, "& li": { mb: 1 } }}>
              {manual.steps[tool].map((step) => (
                <li key={step.en}>
                  <Typography>{(language === "fa" ? step.fa : step.en).replace("{id}", manual.id)}</Typography>
                </li>
              ))}
            </Box>
            {tool === "compose" ? <CopyField label={pick(language, COPY.commandsLabel)} value={manual.commands.join("\n")} multiline /> : null}
          </Stack>
        ) : null}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{pick(language, COPY.close)}</Button>
        {canMark && manual ? (
          <Button variant="contained" onClick={() => void mark()} disabled={marking} startIcon={marking ? <CircularProgress size={14} color="inherit" /> : undefined}>
            {pick(language, COPY.markDone)}
          </Button>
        ) : null}
      </DialogActions>
    </Dialog>
  );
}

// ── service row ──────────────────────────────────────────────────────────────

function ServiceItem({ row, permissions, onChanged, onGuide }: { row: ServiceRow; permissions: readonly string[]; onChanged: () => void; onGuide: (id: string) => void }) {
  const { language } = useKit();
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState<unknown>(null);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const extra = WRITE_PERMISSION[row.id];
  const canOperate = hasPermission(permissions, "services:operate") && (!extra || hasPermission(permissions, extra))
    && (row.target !== "dokploy" || hasPermission(permissions, "dokploy:deploy"));

  const follow = useCallback((id: string) => {
    const tick = async () => {
      try {
        const next = await getJson<Job>(`/api/v1/releases/jobs/${id}`);
        setJob(next);
        if (next.status === "running") timer.current = window.setTimeout(() => void tick(), 1500);
        else onChanged();
      } catch (caught) {
        setError(caught);
      }
    };
    void tick();
  }, [onChanged]);

  const start = async () => {
    setError(null);
    try {
      const started = await mutateJson<Job>(`/api/v1/releases/services/${row.id}/upgrade`, { method: "POST" });
      setJob(started);
      follow(started.id);
    } catch (caught) {
      if (errorCode(caught) === "manual_upgrade") onGuide(row.id);
      else setError(caught);
    }
  };

  const running = job?.status === "running";
  const pill = !row.installed
    ? <StatusPill tone="off" label={pick(language, COPY.notInstalled)} />
    : row.needs_update
      ? <StatusPill tone="warn" label={pick(language, COPY.needsUpdate)} />
      : <StatusPill tone="ok" label={pick(language, COPY.current)} />;
  const tool = row.target === "dokploy" ? "Dokploy" : row.target === "coolify" ? "Coolify" : null;
  const jobError = job?.error_code ? JOB_ERRORS[job.error_code] : undefined;
  return (
    <Box sx={{ py: 1.5, borderBottom: 1, borderColor: "divider", "&:last-child": { borderBottom: 0 } }}>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ xs: "stretch", sm: "center" }}>
        <Stack spacing={0.5} sx={{ flex: 1, minWidth: 0 }}>
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <Typography fontWeight={650}>{serviceName(language, row.id)}</Typography>
            {pill}
            {row.installed ? (
              <Typography variant="body2" color="text.secondary">
                {tool ? say(language, COPY.via, { tool }) : pick(language, COPY.viaManual)}
              </Typography>
            ) : null}
          </Stack>
          {row.installed ? (
            <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: "anywhere" }}>
              {pick(language, COPY.deployed)} {row.deployed_image ? <Ltr mono>{row.deployed_image}</Ltr> : pick(language, COPY.unknownImage)}
              {row.needs_update && row.image ? <>{" · "}{pick(language, COPY.target)} <Ltr mono>{row.image}</Ltr></> : null}
            </Typography>
          ) : null}
        </Stack>
        {row.installed && row.needs_update ? (
          row.can_auto ? (
            <Button variant="contained" onClick={() => void start()} disabled={!canOperate || running} startIcon={running ? <CircularProgress size={14} color="inherit" /> : <SystemUpdateAltRoundedIcon />}>
              {pick(language, COPY.update)}
            </Button>
          ) : (
            <Button variant="outlined" onClick={() => onGuide(row.id)} startIcon={<MenuBookRoundedIcon />}>
              {pick(language, COPY.guide)}
            </Button>
          )
        ) : null}
      </Stack>
      {job ? (
        <Box sx={{ mt: 1 }}>
          {running ? (
            <Stack spacing={0.5}>
              <LinearProgress />
              <Typography variant="body2" color="text.secondary">{pick(language, PHASES[job.phase] ?? PHASES.preparing)}</Typography>
            </Stack>
          ) : job.status === "succeeded" ? (
            <Notice tone="success">{pick(language, COPY.updated)}</Notice>
          ) : (
            <Notice tone={job.error_code === "connect_failed" ? "warning" : "error"}>{pick(language, jobError ?? COPY.updateFailed)}</Notice>
          )}
        </Box>
      ) : null}
      {error ? <Box sx={{ mt: 1 }}><FriendlyError error={error} inline /></Box> : null}
    </Box>
  );
}

// ── panel ────────────────────────────────────────────────────────────────────

export function VersionsPanel({ permissions }: { permissions: readonly string[] }) {
  const { language } = useKit();
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<unknown>(null);
  const [panelBusy, setPanelBusy] = useState(false);
  const [panelError, setPanelError] = useState<unknown>(null);
  const [panelStarted, setPanelStarted] = useState(false);
  const [guide, setGuide] = useState<string | null>(null);
  const { ask, dialog } = useConfirmAction();

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      setStatus(await getJson<Status>("/api/v1/releases/status", signal));
      setError(null);
    } catch (caught) {
      if (!isAbortError(caught)) setError(caught);
    }
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);
  const reload = useCallback(() => { void load(); }, [load]);

  const check = async () => {
    setChecking(true);
    setCheckError(null);
    try {
      await mutateJson("/api/v1/releases/check", { method: "POST" });
      await load();
    } catch (caught) {
      setCheckError(caught);
    } finally {
      setChecking(false);
    }
  };

  const canOperate = hasPermission(permissions, "services:operate");
  const canPanel = canOperate && hasPermission(permissions, "dokploy:deploy") && hasPermission(permissions, "user:write");

  const upgradePanel = async (version: string) => {
    const ok = await ask({
      title: say(language, COPY.panelConfirmTitle, { version }),
      body: pick(language, COPY.panelConfirmBody),
      typed: CONFIRM_WORDS.updatePanel,
      confirmLabel: say(language, COPY.panelButton, { version })
    });
    if (!ok) return;
    setPanelBusy(true);
    setPanelError(null);
    try {
      await mutateJson("/api/v1/releases/panel/upgrade", { method: "POST", body: { version, confirmation: CONFIRM_WORDS.updatePanel.token } });
      setPanelStarted(true);
    } catch (caught) {
      setPanelError(caught);
    } finally {
      setPanelBusy(false);
    }
  };

  if (error && !status) return <FriendlyError error={error} title={pick(language, COPY.loadFailed)} onRetry={reload} />;
  if (!status) {
    return (
      <Stack spacing={2}>
        <Skeleton variant="rounded" height={120} />
        <Skeleton variant="rounded" height={220} />
      </Stack>
    );
  }

  const { current, latest, panel } = status;
  const target = latest.version ?? current.version;
  const reason = latest.error_code ? pick(language, CHECK_ERRORS[latest.error_code] ?? CHECK_ERRORS.unreachable) : "";
  const checkButton = (
    <Button size="small" onClick={() => void check()} disabled={checking} startIcon={checking ? <CircularProgress size={14} color="inherit" /> : <RefreshRoundedIcon />}>
      {pick(language, COPY.checkAgain)}
    </Button>
  );
  const installed = status.services.filter((row) => row.installed);

  return (
    <Stack spacing={2.5}>
      <SectionCard
        title={pick(language, COPY.currentTitle)}
        status={<StatusPill tone="info" label={pick(language, current.runtime === "native" ? COPY.runtimeNative : COPY.runtimeDocker)} />}
        action={checkButton}
      >
        <Stack spacing={1.5}>
          <Typography>{say(language, COPY.currentBody, { version: current.version })}</Typography>
          {status.update_available && latest.version ? (
            <Notice
              tone="info"
              action={latest.notes_url ? (
                <Button size="small" component={Link} href={latest.notes_url} target="_blank" rel="noopener noreferrer">{pick(language, COPY.notes)}</Button>
              ) : undefined}
            >
              {say(language, COPY.newVersion, { version: latest.version })}
            </Notice>
          ) : latest.error_code && latest.error_code !== "no_release" ? (
            <Notice tone="warning">{say(language, COPY.checkFailed, { reason })}</Notice>
          ) : latest.checked_at ? (
            <Notice tone="success">{pick(language, COPY.upToDate)}</Notice>
          ) : (
            <Typography color="text.secondary">{pick(language, COPY.neverChecked)}</Typography>
          )}
          {latest.checked_at ? (
            <Typography variant="body2" color="text.secondary">
              {pick(language, COPY.checkedAt)} <RelativeTime value={new Date(latest.checked_at * 1000)} />
            </Typography>
          ) : null}
          {checkError ? <FriendlyError error={checkError} inline /> : null}
        </Stack>
      </SectionCard>

      {status.update_available ? <Notice tone="info">{pick(language, COPY.order)}</Notice> : null}

      <SectionCard title={pick(language, COPY.panelTitle)}>
        <Stack spacing={1.5}>
          {!status.update_available ? <Typography color="text.secondary">{pick(language, COPY.panelLatest)}</Typography> : null}
          {status.update_available && panel.method === "dokploy" && panel.can_auto ? (
            <>
              <Typography>{pick(language, COPY.panelDokploy)}</Typography>
              {panelStarted ? <Notice tone="success">{pick(language, COPY.panelStarted)}</Notice> : (
                <Box>
                  <Button variant="contained" onClick={() => void upgradePanel(target)} disabled={!canPanel || panelBusy} startIcon={panelBusy ? <CircularProgress size={14} color="inherit" /> : <SystemUpdateAltRoundedIcon />}>
                    {say(language, COPY.panelButton, { version: target })}
                  </Button>
                </Box>
              )}
              {!canPanel ? <Typography variant="body2" color="text.secondary">{pick(language, COPY.panelNoPermission)}</Typography> : null}
              {panelError ? <FriendlyError error={panelError} inline /> : null}
            </>
          ) : null}
          {status.update_available && !(panel.method === "dokploy" && panel.can_auto) ? (
            <>
              <Typography>
                {pick(language, panel.method === "native" ? COPY.panelNative : panel.method === "dokploy" ? COPY.panelDokployManual : COPY.panelCompose)}
              </Typography>
              {panel.commands.map((command) => (
                command.command
                  ? <CopyField key={command.command} label={title(language, command)} value={command.command} />
                  : <Typography key={command.title_en} variant="body2">{title(language, command)}</Typography>
              ))}
            </>
          ) : null}
        </Stack>
      </SectionCard>

      <SectionCard title={pick(language, COPY.servicesTitle)} hint={pick(language, COPY.servicesHint)}>
        {installed.length === 0 ? (
          <Typography color="text.secondary">{pick(language, COPY.noServices)}</Typography>
        ) : (
          <Box>
            {installed.map((row) => (
              <ServiceItem key={row.id} row={row} permissions={permissions} onChanged={reload} onGuide={setGuide} />
            ))}
          </Box>
        )}
        {!canOperate && installed.some((row) => row.needs_update) ? (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{pick(language, COPY.noOperate)}</Typography>
        ) : null}
      </SectionCard>

      {guide ? (
        <ManualDialog
          serviceId={guide}
          canMark={canOperate && (!WRITE_PERMISSION[guide] || hasPermission(permissions, WRITE_PERMISSION[guide]))}
          onClose={() => setGuide(null)}
          onDone={() => { setGuide(null); reload(); }}
        />
      ) : null}
      {dialog}
    </Stack>
  );
}
