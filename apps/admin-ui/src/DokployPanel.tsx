/**
 * Server › Dokploy apps (docs/33 §4.2). Simple: connect wizard, projects → apps with
 * «انتشار دوباره» and «توقف». Advanced: full deploy, history and logs, connection details,
 * disconnect and every Dokploy setting. ServerPage provides the page header and tabs.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Box,
  Button,
  CircularProgress,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  LinearProgress,
  Link,
  Stack,
  TextField,
  Typography,
  useMediaQuery,
  useTheme
} from "@mui/material";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import RocketLaunchRoundedIcon from "@mui/icons-material/RocketLaunchRounded";
import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import StopRoundedIcon from "@mui/icons-material/StopRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import ArticleRoundedIcon from "@mui/icons-material/ArticleRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import LinkRoundedIcon from "@mui/icons-material/LinkRounded";
import LinkOffRoundedIcon from "@mui/icons-material/LinkOffRounded";
import NetworkCheckRoundedIcon from "@mui/icons-material/NetworkCheckRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import AppsRoundedIcon from "@mui/icons-material/AppsRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { Language } from "./i18n";
import { useVisibleInterval } from "./polling";
import {
  ActionWizard, DangerZone, EmptyState, FriendlyError, KeyValueList, Ltr, NoAccess, Notice, RelativeTime, ResponsiveList, SectionCard,
  StatusPill, TestResult, useConfirmAction, useKit, useUndoSnackbar, RegistrySettings, helperProblem, type TestOutcome
} from "./kit";
import { CONFIRM_WORDS, pick, reasonFor, say, type Bi } from "./copy";

type DokployConfig = {
  configured: boolean;
  url: string | null;
  source: "panel" | "env" | null;
  last_error: string | null;
  /** The Dokploy web panel (docs/34 §4), for «باز کردن در Dokploy». */
  panel_url?: string | null;
};

/** Dokploy's own page for a project (`<panel>/dashboard/project/<id>`). */
function dokployProjectHref(panelUrl: string | null | undefined, projectId: string): string | null {
  if (!panelUrl) return null;
  return `${panelUrl.replace(/\/+$/, "")}/dashboard/project/${encodeURIComponent(projectId)}`;
}

function OpenInDokploy({ href, label }: { href: string; label: string }) {
  return (
    <Button size="small" href={href} target="_blank" rel="noopener noreferrer" endIcon={<OpenInNewRoundedIcon fontSize="small" />} sx={{ minHeight: 40, whiteSpace: "nowrap" }}>
      {label}
    </Button>
  );
}
type ServiceType = "application" | "compose" | "postgres" | "mysql" | "mariadb" | "mongo" | "redis";
type LastDeployment = { status: string; created_at: string | number | null; title?: string | null };
type Service = { id: string; type: ServiceType; name: string; status: string | null; domains: string[] | null; last_deployment: LastDeployment | null };
type Project = { id: string; name: string; description: string | null; services: Service[] };
type Deployment = { id: string; status: string; title: string | null; created_at: string | number | null; finished_at: string | number | null };
type ServiceDetail = Service & { deployments?: Deployment[] };
type DokployTest = { ok: boolean; latency_ms: number; version?: string | null; error_code?: string | null };
type ServiceAction = "deploy" | "redeploy" | "start" | "stop";

type Props = { language: Language; permissions: string[]; onUnauthorized: () => void };

const BASE = "/api/v1/dokploy";
const POLL_MS = 30_000;

const T = {
  openInDokploy: { fa: "باز کردن در Dokploy", en: "Open in Dokploy" },
  unavailable: { fa: "این بخش روی نسخه فعلی سرور نیست. پیشکار را به‌روز کنید.", en: "This section isn't on this server version. Update Pishkar." },
  refresh: { fa: "تازه کردن", en: "Refresh" },
  appsTitle: { fa: "برنامه‌های Dokploy", en: "Dokploy apps" },
  appsHint: { fa: "هر برنامه را با یک دکمه دوباره منتشر کنید.", en: "Deploy any app again with one button." },
  connected: { fa: "وصل", en: "Connected" },
  problem: { fa: "اتصال مشکل دارد", en: "Connection problem" },
  staleData: { fa: "Dokploy الان جواب نمی‌دهد؛ شاید فهرست قدیمی باشد.", en: "Dokploy isn't answering right now; the list may be out of date." },
  emptyTitle: { fa: "هنوز Dokploy را وصل نکرده‌اید", en: "Dokploy isn't connected yet" },
  emptyBody: { fa: "با وصل کردن Dokploy، برنامه‌هایتان را همین‌جا می‌بینید و با یک دکمه دوباره منتشر می‌کنید.", en: "Connect Dokploy to see your apps here and deploy them again with one button." },
  connect: { fa: "وصل کردن Dokploy", en: "Connect Dokploy" },
  noProjects: { fa: "هنوز پروژه‌ای در Dokploy ندارید", en: "No projects in Dokploy yet" },
  noProjectsBody: { fa: "وقتی در Dokploy پروژه بسازید، این‌جا نشان داده می‌شود.", en: "Projects you create in Dokploy will show up here." },
  noServices: { fa: "این پروژه هنوز برنامه‌ای ندارد.", en: "This project has no apps yet." },
  appsCount: { fa: "{projects} پروژه · {apps} برنامه", en: "{projects} projects · {apps} apps" },
  colName: { fa: "برنامه", en: "App" },
  colKind: { fa: "نوع", en: "Type" },
  colStatus: { fa: "وضعیت", en: "Status" },
  colLast: { fa: "آخرین انتشار", en: "Last deploy" },
  colDomains: { fa: "نشانی‌ها", en: "Addresses" },
  colAction: { fa: "کار اصلی", en: "Main action" },
  colId: { fa: "شناسه", en: "ID" },
  never: { fa: "هنوز منتشر نشده", en: "Never deployed" },
  redeploy: { fa: "انتشار دوباره", en: "Redeploy" },
  deploy: { fa: "انتشار کامل (از اول ساخته می‌شود)", en: "Full deploy (built from scratch)" },
  start: { fa: "روشن کردن", en: "Start" },
  stop: { fa: "توقف", en: "Stop" },
  history: { fa: "تاریخچه انتشار", en: "Deploy history" },
  noHistory: { fa: "هنوز انتشاری برای این برنامه ثبت نشده است.", en: "No deploys recorded for this app yet." },
  viewLog: { fa: "دیدن لاگ", en: "View log" },
  logTitle: { fa: "لاگ انتشار", en: "Deploy log" },
  logUnavailable: { fa: "Dokploy لاگ این انتشار را در اختیار پیشکار نمی‌گذارد. آن را در خود Dokploy ببینید.", en: "Dokploy doesn't share this deploy's log with Pishkar. See it in Dokploy itself." },
  logEmpty: { fa: "لاگ این انتشار خالی است.", en: "This deploy's log is empty." },
  close: { fa: "بستن", en: "Close" },
  started: { fa: "شروع", en: "Started" },
  took: { fa: "مدت: {seconds} ثانیه", en: "Took {seconds} s" },
  stopTitle: { fa: "برنامه «{name}» متوقف شود؟", en: "Stop “{name}”?" },
  stopBody: { fa: "تا وقتی دوباره روشنش نکنید، این برنامه از دسترس خارج می‌شود.", en: "The app stays unavailable until you start it again." },
  deployTitle: { fa: "«{name}» از اول ساخته و منتشر شود؟", en: "Build and deploy “{name}” from scratch?" },
  deployBody: { fa: "کد برنامه دوباره دریافت و ساخته می‌شود. این کار از «انتشار دوباره» کندتر است.", en: "The app's code is fetched and built again. This is slower than Redeploy." },
  redeployDone: { fa: "«{name}» در حال انتشار است.", en: "“{name}” is deploying." },
  deployDone: { fa: "«{name}» از اول در حال ساخت و انتشار است.", en: "“{name}” is being built and deployed from scratch." },
  startDone: { fa: "«{name}» در حال روشن شدن است.", en: "“{name}” is starting." },
  stopDone: { fa: "«{name}» متوقف شد.", en: "“{name}” was stopped." },
  noDeploy: { fa: "انتشار برنامه‌ها", en: "deploying apps" },
  // connection wizard
  wizardTitle: { fa: "وصل کردن Dokploy", en: "Connect Dokploy" },
  wizardEditTitle: { fa: "تغییر نشانی یا کلید Dokploy", en: "Change Dokploy address or key" },
  stepAddress: { fa: "نشانی", en: "Address" },
  stepKey: { fa: "کلید", en: "Key" },
  stepTest: { fa: "امتحان", en: "Test" },
  addressHint: { fa: "نشانی‌ای که با آن وارد Dokploy می‌شوید.", en: "The address you use to open Dokploy." },
  url: { fa: "نشانی Dokploy", en: "Dokploy address" },
  urlExample: { fa: "مثلاً https://dokploy.example.com یا http://dokploy:3000", en: "For example https://dokploy.example.com or http://dokploy:3000" },
  urlRule: { fa: "نشانی باید با http:// یا https:// شروع شود.", en: "The address must start with http:// or https://." },
  keyHint: { fa: "یک کلید دسترسی در Dokploy بسازید و این‌جا بچسبانید.", en: "Create an access key in Dokploy and paste it here." },
  keyStep1: { fa: "وارد Dokploy شوید و به «Settings» و بعد «Profile» بروید.", en: "Sign in to Dokploy and open “Settings”, then “Profile”." },
  keyStep2: { fa: "در بخش «API/CLI» دکمه «Generate» را بزنید و کلید را کپی کنید.", en: "Under “API/CLI”, press “Generate” and copy the key." },
  apiKey: { fa: "کلید دسترسی Dokploy", en: "Dokploy access key" },
  keyKeep: { fa: "برای نگه‌داشتن کلید فعلی خالی بگذارید.", en: "Leave empty to keep the current key." },
  keyRequired: { fa: "کلید را از Dokploy کپی کنید و این‌جا بچسبانید.", en: "Copy the key from Dokploy and paste it here." },
  saveAndTest: { fa: "ذخیره و امتحان اتصال", en: "Save and test" },
  safety: { fa: "پیشکار فقط از راه رسمی Dokploy کار می‌کند و به فایل‌ها و تنظیمات خود Dokploy دست نمی‌زند. کلید رمزدار نگه‌داری می‌شود.", en: "Pishkar only uses Dokploy's official interface and never touches Dokploy's own files or settings. The key is stored encrypted." },
  testHint: { fa: "اگر وصل نشد، برگردید و نشانی یا کلید را درست کنید.", en: "If it doesn't connect, go back and fix the address or key." },
  versionLine: { fa: "نسخه Dokploy: {version}", en: "Dokploy version: {version}" },
  wizardDone: { fa: "Dokploy وصل شد.", en: "Dokploy is connected." },
  noWrite: { fa: "وصل کردن Dokploy", en: "connecting Dokploy" },
  // advanced connection card
  connection: { fa: "اتصال Dokploy", en: "Dokploy connection" },
  connectionHint: { fa: "پیشکار برای این‌که به Dokploy فشار نیاید، درخواست‌ها را محدود و موقتاً ذخیره می‌کند.", en: "Pishkar limits and briefly caches requests so Dokploy isn't put under extra load." },
  source: { fa: "از کجا تنظیم شده", en: "Set from" },
  sourcePanel: { fa: "همین پنل", en: "This panel" },
  sourceEnv: { fa: "فایل Compose", en: "Compose file" },
  envManaged: { fa: "این اتصال از فایل Compose تنظیم شده؛ برای تغییر، همان فایل را ویرایش کنید.", en: "This connection is set in the Compose file; edit that file to change it." },
  lastProblem: { fa: "آخرین مشکل", en: "Last problem" },
  technical: { fa: "جزئیات فنی", en: "Technical details" },
  test: { fa: "امتحان اتصال", en: "Test connection" },
  edit: { fa: "تغییر نشانی یا کلید", en: "Change address or key" },
  disconnect: { fa: "قطع اتصال", en: "Disconnect" },
  disconnectTitle: { fa: "اتصال Dokploy قطع شود؟", en: "Disconnect Dokploy?" },
  disconnectBody: { fa: "کلید از پیشکار پاک می‌شود. خود Dokploy و برنامه‌هایش هیچ تغییری نمی‌کنند.", en: "The key is removed from Pishkar. Dokploy and its apps don't change at all." },
  disconnected: { fa: "اتصال Dokploy قطع شد.", en: "Dokploy was disconnected." },
  settingsTitle: { fa: "همه تنظیمات Dokploy", en: "Every Dokploy setting" }
} satisfies Record<string, Bi>;

const KIND_WORDS: Record<string, Bi> = {
  application: { fa: "برنامه", en: "Application" },
  compose: { fa: "Compose", en: "Compose" },
  postgres: { fa: "PostgreSQL", en: "PostgreSQL" },
  mysql: { fa: "MySQL", en: "MySQL" },
  mariadb: { fa: "MariaDB", en: "MariaDB" },
  mongo: { fa: "MongoDB", en: "MongoDB" },
  redis: { fa: "Redis", en: "Redis" }
};

/** Dokploy's own status words → our status table. */
function serviceStatus(status: string | null | undefined): string {
  if (!status) return "unknown";
  if (status === "done") return "running";
  if (status === "idle") return "stopped";
  if (status === "deploying") return "running";
  return status;
}

/** A bare 404 (no specific code) means the module isn't on this server. */
function isMissingModule(error: unknown) {
  return helperProblem(error) === "module_missing";
}

/** Only http(s) links; a bare host becomes https://host. */
function domainHref(domain: string): string | null {
  const value = domain.trim();
  if (!value) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(value) ? value : `https://${value}`;
  try {
    const url = new URL(candidate);
    return url.protocol === "http:" || url.protocol === "https:" ? url.toString() : null;
  } catch {
    return null;
  }
}

function canStart(status: string | null) {
  return !status || ["idle", "stopped", "exited", "error"].includes(status);
}

function canStop(status: string | null) {
  return !status || !["idle", "stopped", "exited"].includes(status);
}

function testOutcome(result: DokployTest, language: Language): TestOutcome {
  if (result.ok) return { state: "ok", latencyMs: result.latency_ms, message: result.version ? say(language, T.versionLine, { version: result.version }) : undefined };
  return { state: "fail", code: result.error_code ?? null, message: result.error_code ? reasonFor(language, result.error_code) : undefined };
}

async function runTest(language: Language): Promise<TestOutcome> {
  try {
    return testOutcome(await mutateJson<DokployTest>(`${BASE}/test`, { method: "POST" }), language);
  } catch (caught) {
    return { state: "fail", error: caught };
  }
}

// ── Connection wizard ─────────────────────────────────────────────────────────

function ConnectWizard({ open, initialUrl, hasKey, onClose, onSaved }: { open: boolean; initialUrl: string; hasKey: boolean; onClose: () => void; onSaved: () => void }) {
  const { language } = useKit();
  const [url, setUrl] = useState(initialUrl);
  const [key, setKey] = useState("");
  const [outcome, setOutcome] = useState<TestOutcome>({ state: "idle" });

  useEffect(() => {
    if (!open) return;
    setUrl(initialUrl);
    setKey("");
    setOutcome({ state: "idle" });
  }, [open, initialUrl]);

  const urlOk = /^https?:\/\/[^\s/]+/i.test(url.trim());

  const save = async () => {
    const body: { url: string; api_key?: string } = { url: url.trim().replace(/\/+$/, "") };
    if (key.trim()) body.api_key = key.trim();
    await mutateJson(`${BASE}/config`, { method: "PUT", body });
    setKey("");
    onSaved();
    setOutcome({ state: "running" });
    setOutcome(await runTest(language));
  };

  return (
    <ActionWizard
      open={open}
      title={pick(language, hasKey ? T.wizardEditTitle : T.wizardTitle)}
      onClose={onClose}
      onFinish={() => undefined}
      finishLabel={pick(language, T.close)}
      steps={[
        {
          key: "address",
          title: pick(language, T.stepAddress),
          hint: pick(language, T.addressHint),
          validate: () => (urlOk ? null : pick(language, T.urlRule)),
          render: () => (
            <Stack spacing={2}>
              <TextField
                autoFocus
                fullWidth
                label={pick(language, T.url)}
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                error={url.length > 0 && !urlOk}
                helperText={pick(language, T.urlExample)}
                slotProps={{ htmlInput: { dir: "ltr", autoComplete: "off", spellCheck: false } }}
              />
              <Typography variant="body2" color="text.secondary">{pick(language, T.safety)}</Typography>
            </Stack>
          )
        },
        {
          key: "key",
          title: pick(language, T.stepKey),
          hint: pick(language, T.keyHint),
          nextLabel: pick(language, T.saveAndTest),
          validate: () => (hasKey || key.trim() ? null : pick(language, T.keyRequired)),
          onNext: save,
          render: () => (
            <Stack spacing={2}>
              <Stack component="ol" spacing={0.75} sx={{ m: 0, ps: 2.5 }}>
                <Typography component="li" variant="body2">{pick(language, T.keyStep1)}</Typography>
                <Typography component="li" variant="body2">{pick(language, T.keyStep2)}</Typography>
              </Stack>
              <TextField
                autoFocus
                fullWidth
                type="password"
                label={pick(language, T.apiKey)}
                value={key}
                onChange={(event) => setKey(event.target.value)}
                helperText={hasKey ? pick(language, T.keyKeep) : " "}
                slotProps={{ htmlInput: { dir: "ltr", autoComplete: "new-password" } }}
              />
            </Stack>
          )
        },
        {
          key: "test",
          title: pick(language, T.stepTest),
          hint: pick(language, T.testHint),
          render: () => (
            <Stack spacing={2}>
              <TestResult outcome={outcome} />
              <Box>
                <Button variant="outlined" startIcon={<NetworkCheckRoundedIcon />} disabled={outcome.state === "running"} onClick={() => void (async () => { setOutcome({ state: "running" }); setOutcome(await runTest(language)); })()}>
                  {pick(language, T.test)}
                </Button>
              </Box>
            </Stack>
          )
        }
      ]}
    />
  );
}

// ── Deploy history and log ────────────────────────────────────────────────────

function DeploymentLogDialog({ deployment, onClose }: { deployment: Deployment; onClose: () => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [state, setState] = useState<{ available: boolean; lines: string[] } | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const payload = await getJson<{ available: boolean; lines?: unknown[] }>(`${BASE}/deployments/${encodeURIComponent(deployment.id)}/log`, controller.signal);
        const lines = (payload.lines ?? []).map((line) => (typeof line === "string" ? line : line && typeof line === "object" && "text" in line ? String((line as { text: unknown }).text) : JSON.stringify(line)));
        setState({ available: Boolean(payload.available), lines });
      } catch (caught) {
        if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
        setError(caught);
      }
    })();
    return () => controller.abort();
  }, [deployment.id]);

  const dark = theme.palette.mode === "dark";
  return (
    <Dialog open onClose={onClose} fullScreen={fullScreen} fullWidth maxWidth="lg" aria-labelledby="mrk-deploy-log-title" slotProps={{ paper: { sx: { height: fullScreen ? "100%" : "85vh" } } }}>
      <DialogTitle id="mrk-deploy-log-title" sx={{ pr: 7 }}>
        {pick(language, T.logTitle)}{deployment.title ? <> · <Box component="span" dir="auto">{deployment.title}</Box></> : null}
        <IconButton aria-label={pick(language, T.close)} onClick={onClose} sx={{ position: "absolute", insetInlineEnd: 12, top: 12, width: 44, height: 44 }}><CloseRoundedIcon /></IconButton>
      </DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", minHeight: 0 }}>
        {error !== null && <FriendlyError error={error} />}
        {state === null && error === null && <LinearProgress />}
        {state && !state.available && <Notice>{pick(language, T.logUnavailable)}</Notice>}
        {state && state.available && (
          <Box
            dir="ltr"
            role="log"
            tabIndex={0}
            aria-label={pick(language, T.logTitle)}
            sx={{ flex: 1, minHeight: 200, overflow: "auto", p: 1.25, borderRadius: 1, border: 1, borderColor: "divider", bgcolor: dark ? "#050b12" : "#f6f8fa", fontFamily: 'ui-monospace, "SFMono-Regular", Consolas, monospace', fontSize: 12.5, lineHeight: 1.55, whiteSpace: "pre-wrap", overflowWrap: "anywhere", textAlign: "start" }}
          >
            {state.lines.length === 0 ? pick(language, T.logEmpty) : state.lines.join("\n")}
          </Box>
        )}
      </DialogContent>
    </Dialog>
  );
}

function DeploymentHistoryDialog({ service, onClose, onLog }: { service: Service; onClose: () => void; onLog: (deployment: Deployment) => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [deployments, setDeployments] = useState<Deployment[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const detail = await getJson<ServiceDetail>(`${BASE}/services/${encodeURIComponent(service.type)}/${encodeURIComponent(service.id)}`, controller.signal);
        const stamp = (value: string | number | null) => (value === null ? 0 : typeof value === "number" ? value : Date.parse(value) / 1000 || 0);
        setDeployments([...(detail.deployments ?? [])].sort((a, b) => stamp(b.created_at) - stamp(a.created_at)).slice(0, 50));
      } catch (caught) {
        if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
        setError(caught);
      }
    })();
    return () => controller.abort();
  }, [service.id, service.type]);

  const seconds = (deployment: Deployment) => {
    const toSec = (value: string | number | null) => (value === null ? null : typeof value === "number" ? (value > 1e12 ? value / 1000 : value) : Date.parse(value) / 1000 || null);
    const start = toSec(deployment.created_at);
    const end = toSec(deployment.finished_at);
    return start && end && end >= start ? Math.round(end - start) : null;
  };

  return (
    <Dialog open onClose={onClose} fullScreen={fullScreen} fullWidth maxWidth="md" aria-labelledby="mrk-deploy-history-title">
      <DialogTitle id="mrk-deploy-history-title" sx={{ pr: 7 }}>
        {pick(language, T.history)} · <Box component="span" dir="auto">{service.name}</Box>
        <IconButton aria-label={pick(language, T.close)} onClick={onClose} sx={{ position: "absolute", insetInlineEnd: 12, top: 12, width: 44, height: 44 }}><CloseRoundedIcon /></IconButton>
      </DialogTitle>
      <DialogContent>
        {error !== null && <FriendlyError error={error} />}
        {deployments === null && error === null && <LinearProgress />}
        {deployments !== null && (
          <ResponsiveList
            label={pick(language, T.history)}
            rows={deployments}
            rowKey={(row) => row.id}
            dense
            columns={[
              { key: "status", header: pick(language, T.colStatus), render: (row) => <StatusPill status={serviceStatus(row.status)} /> },
              { key: "title", header: pick(language, T.colName), render: (row) => <Box component="span" dir="auto">{row.title || "—"}</Box> },
              { key: "started", header: pick(language, T.started), render: (row) => <RelativeTime value={row.created_at} /> },
              { key: "took", header: "", render: (row) => { const value = seconds(row); return value === null ? "—" : say(language, T.took, { seconds: value }); } },
              { key: "id", header: pick(language, T.colId), render: (row) => <Ltr mono>{row.id}</Ltr>, ltr: true, hideOnCard: true }
            ]}
            card={{ title: (row) => <Box component="span" dir="auto">{row.title || "—"}</Box>, meta: (row) => <RelativeTime value={row.created_at} />, status: (row) => <StatusPill status={serviceStatus(row.status)} /> }}
            actions={[{ key: "log", label: pick(language, T.viewLog), icon: ArticleRoundedIcon, onClick: onLog }]}
            empty={<Typography variant="body2" color="text.secondary">{pick(language, T.noHistory)}</Typography>}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

// ── One project ───────────────────────────────────────────────────────────────

function ProjectCard({ project, canDeploy, busy, onAction, onHistory, panelUrl }: {
  project: Project;
  panelUrl?: string | null;
  canDeploy: boolean;
  busy: { id: string; action: ServiceAction } | null;
  onAction: (service: Service, action: ServiceAction) => void;
  onHistory: (service: Service) => void;
}) {
  const { language } = useKit();
  const kind = (type: string) => pick(language, KIND_WORDS[type] ?? { fa: type, en: type });
  const domains = (service: Service) => (service.domains ?? []).map((domain) => ({ domain, href: domainHref(domain) })).filter((item) => item.href);

  return (
    <SectionCard
      title={project.name}
      hint={project.description ?? undefined}
      flush
      action={(() => {
        const href = dokployProjectHref(panelUrl, project.id);
        return href ? <OpenInDokploy href={href} label={pick(language, T.openInDokploy)} /> : undefined;
      })()}
    >
      <ResponsiveList
        label={project.name}
        rows={project.services}
        rowKey={(row) => `${row.type}:${row.id}`}
        columns={[
          { key: "name", header: pick(language, T.colName), render: (row) => <Typography variant="body2" fontWeight={700} dir="auto">{row.name}</Typography> },
          { key: "kind", header: pick(language, T.colKind), render: (row) => kind(row.type), hideOnCard: true },
          { key: "status", header: pick(language, T.colStatus), render: (row) => <StatusPill status={serviceStatus(row.status)} />, hideOnCard: true },
          {
            key: "last",
            header: pick(language, T.colLast),
            render: (row) => (row.last_deployment ? <Stack direction="row" spacing={0.75} alignItems="center"><StatusPill status={serviceStatus(row.last_deployment.status)} size="small" /><RelativeTime value={row.last_deployment.created_at} /></Stack> : pick(language, T.never))
          },
          {
            key: "domains",
            header: pick(language, T.colDomains),
            render: (row) => {
              const list = domains(row);
              if (!list.length) return "—";
              return (
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {list.map((item) => (
                    <Link key={item.domain} href={item.href!} target="_blank" rel="noopener noreferrer" variant="caption" dir="ltr" underline="hover" sx={{ display: "inline-flex", alignItems: "center", gap: 0.25 }}>
                      {item.domain.replace(/^https?:\/\//, "")}<OpenInNewRoundedIcon sx={{ fontSize: 12 }} aria-hidden />
                    </Link>
                  ))}
                </Stack>
              );
            }
          },
          { key: "id", header: pick(language, T.colId), render: (row) => <Ltr mono>{row.id}</Ltr>, advancedOnly: true, ltr: true },
          ...(canDeploy
            ? [{
                key: "redeploy",
                header: pick(language, T.colAction),
                render: (row: Service) => (
                  <Button
                    size="small"
                    variant="contained"
                    disabled={busy !== null}
                    startIcon={busy?.id === row.id && busy.action === "redeploy" ? <CircularProgress size={14} color="inherit" /> : <ReplayRoundedIcon fontSize="small" />}
                    onClick={(event) => { event.stopPropagation(); onAction(row, "redeploy"); }}
                    aria-label={`${pick(language, T.redeploy)} · ${row.name}`}
                    sx={{ minHeight: 36, whiteSpace: "nowrap" }}
                  >
                    {pick(language, T.redeploy)}
                  </Button>
                )
              }]
            : [])
        ]}
        card={{
          title: (row) => <Box component="span" dir="auto">{row.name}</Box>,
          meta: (row) => <>{kind(row.type)}{row.last_deployment ? <> · <RelativeTime value={row.last_deployment.created_at} /></> : null}</>,
          status: (row) => <StatusPill status={serviceStatus(row.status)} />
        }}
        actions={[
          ...(canDeploy
            ? [
                { key: "start", label: pick(language, T.start), icon: PlayArrowRoundedIcon, onClick: (row: Service) => onAction(row, "start"), hidden: (row: Service) => !canStart(row.status), disabled: () => busy !== null },
                { key: "stop", label: pick(language, T.stop), icon: StopRoundedIcon, danger: true, onClick: (row: Service) => onAction(row, "stop"), hidden: (row: Service) => !canStop(row.status), disabled: () => busy !== null },
                { key: "deploy", label: pick(language, T.deploy), icon: RocketLaunchRoundedIcon, advancedOnly: true, onClick: (row: Service) => onAction(row, "deploy"), disabled: () => busy !== null }
              ]
            : []),
          { key: "history", label: pick(language, T.history), icon: HistoryRoundedIcon, advancedOnly: true, onClick: onHistory }
        ]}
        empty={<Typography variant="body2" color="text.secondary" sx={{ p: 2 }}>{pick(language, T.noServices)}</Typography>}
      />
    </SectionCard>
  );
}

// ── Panel ─────────────────────────────────────────────────────────────────────

export function DokployPanel({ language, permissions }: Props) {
  const { isAdvanced } = useKit();
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canWrite = hasPermission(permissions, "dokploy:write");
  const canDeploy = hasPermission(permissions, "dokploy:deploy");
  const [config, setConfig] = useState<DokployConfig | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [projectsError, setProjectsError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState<{ id: string; action: ServiceAction } | null>(null);
  const [test, setTest] = useState<TestOutcome>({ state: "idle" });
  const [wizardOpen, setWizardOpen] = useState(false);
  const [historyFor, setHistoryFor] = useState<Service | null>(null);
  const [logDeployment, setLogDeployment] = useState<Deployment | null>(null);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async (background = false) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    if (!background) setLoading(true);
    try {
      const nextConfig = await getJson<DokployConfig>(`${BASE}/config`, current.signal);
      setConfig(nextConfig);
      setUnavailable(false);
      setLoadError(null);
      if (nextConfig.configured) {
        try {
          const payload = await getJson<{ items: Project[] }>(`${BASE}/projects`, current.signal);
          setProjects(payload.items ?? []);
          setProjectsError(null);
        } catch (caught) {
          if (isAbortError(caught)) throw caught;
          if (caught instanceof ApiError && caught.status === 401) return;
          if (caught instanceof ApiError && caught.code === "dokploy_not_configured") {
            setConfig({ ...nextConfig, configured: false });
            setProjects(null);
          } else setProjectsError(caught);
        }
      } else {
        setProjects(null);
      }
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      if (isMissingModule(caught)) setUnavailable(true);
      else setLoadError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);
  useVisibleInterval(() => void load(true), !unavailable && config?.configured ? POLL_MS : null);

  const runAction = async (service: Service, action: ServiceAction) => {
    if (action === "stop") {
      const ok = await ask({ title: say(language, T.stopTitle, { name: service.name }), body: pick(language, T.stopBody), severity: "disruptive", undoable: true, confirmLabel: pick(language, T.stop) });
      if (!ok) return;
    } else if (action === "deploy") {
      const ok = await ask({ title: say(language, T.deployTitle, { name: service.name }), body: pick(language, T.deployBody), severity: "disruptive", confirmLabel: pick(language, T.deploy) });
      if (!ok) return;
    }
    setBusy({ id: service.id, action });
    setActionError(null);
    try {
      await mutateJson(`${BASE}/services/${encodeURIComponent(service.type)}/${encodeURIComponent(service.id)}/${action}`, {
        method: "POST",
        body: action === "stop" ? { confirmation: service.name } : {}
      });
      const done = action === "redeploy" ? T.redeployDone : action === "deploy" ? T.deployDone : action === "start" ? T.startDone : T.stopDone;
      notify({ message: say(language, done, { name: service.name }), tone: "success" });
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    } finally {
      setBusy(null);
      void load(true);
    }
  };

  const testConnection = async () => {
    setTest({ state: "running" });
    setTest(await runTest(language));
  };

  const disconnect = async () => {
    const ok = await ask({ title: pick(language, T.disconnectTitle), body: pick(language, T.disconnectBody), severity: "destructive", typed: CONFIRM_WORDS.disconnect, confirmLabel: pick(language, T.disconnect) });
    if (!ok) return;
    setActionError(null);
    try {
      await mutateJson(`${BASE}/config`, { method: "DELETE", body: { confirmation: CONFIRM_WORDS.disconnect.token } });
      notify({ message: pick(language, T.disconnected), tone: "success" });
      setProjects(null);
      setTest({ state: "idle" });
      await load(true);
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const configured = Boolean(config?.configured);
  const envManaged = config?.source === "env";
  const healthy = configured && !config?.last_error && projectsError === null;
  const serviceCount = (projects ?? []).reduce((sum, project) => sum + project.services.length, 0);
  const refreshButton = (
    <Button size="small" startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} onClick={() => void load()} disabled={loading} sx={{ minHeight: 40 }}>
      {pick(language, T.refresh)}
    </Button>
  );

  if (unavailable) return <Notice>{pick(language, T.unavailable)}</Notice>;

  return (
    <Stack spacing={3}>
      {loadError !== null && <FriendlyError error={loadError} onRetry={() => void load()} />}
      {actionError !== null && <FriendlyError error={actionError} onClose={() => setActionError(null)} onRetry={() => void load()} />}
      {loading && !config && loadError === null && <LinearProgress />}

      {config && !configured && (
        <SectionCard title={pick(language, T.appsTitle)}>
          <EmptyState
            icon={AppsRoundedIcon}
            title={pick(language, T.emptyTitle)}
            body={pick(language, T.emptyBody)}
            action={canWrite ? <Button variant="contained" startIcon={<LinkRoundedIcon />} onClick={() => setWizardOpen(true)} sx={{ minHeight: 44 }}>{pick(language, T.connect)}</Button> : undefined}
          />
          {!canWrite && <NoAccess needs="dokploy:write" variant="card" />}
        </SectionCard>
      )}

      {config && configured && (
        <>
          <SectionCard
            title={pick(language, T.appsTitle)}
            hint={projects ? `${pick(language, T.appsHint)} ${say(language, T.appsCount, { projects: projects.length, apps: serviceCount })}` : pick(language, T.appsHint)}
            status={<StatusPill tone={healthy ? "ok" : "warn"} label={pick(language, healthy ? T.connected : T.problem)} />}
            action={
              <Stack direction="row" spacing={0.5} alignItems="center">
                {config.panel_url && <OpenInDokploy href={config.panel_url} label={pick(language, T.openInDokploy)} />}
                {refreshButton}
              </Stack>
            }
          >
            {projectsError !== null && <FriendlyError error={projectsError} severity="warning" onRetry={() => void load()} />}
            {projectsError === null && config.last_error && <Notice tone="warning">{pick(language, T.staleData)}</Notice>}
            {projects === null && projectsError === null && <LinearProgress />}
            {projects !== null && projects.length === 0 && <EmptyState icon={AppsRoundedIcon} title={pick(language, T.noProjects)} body={pick(language, T.noProjectsBody)} action={refreshButton} compact />}
            {!canDeploy && projects !== null && projects.length > 0 && <NoAccess needs="dokploy:deploy" />}
          </SectionCard>

          {projects?.map((project) => (
            <ProjectCard key={project.id} project={project} canDeploy={canDeploy} busy={busy} onAction={(service, action) => void runAction(service, action)} onHistory={setHistoryFor} panelUrl={config.panel_url} />
          ))}

          <SectionCard advanced title={pick(language, T.connection)} hint={pick(language, T.connectionHint)}>
            <Stack spacing={2}>
              {envManaged && <Notice>{pick(language, T.envManaged)}</Notice>}
              <KeyValueList
                items={[
                  { label: pick(language, T.url), value: <Ltr>{config.url ?? "—"}</Ltr>, copy: config.url ?? undefined },
                  { label: pick(language, T.source), value: config.source === "env" ? pick(language, T.sourceEnv) : config.source === "panel" ? pick(language, T.sourcePanel) : "—" },
                  ...(config.last_error
                    ? [
                        { label: pick(language, T.lastProblem), value: reasonFor(language, config.last_error) },
                        { label: pick(language, T.technical), value: <Ltr mono>{config.last_error}</Ltr> }
                      ]
                    : [])
                ]}
              />
              <TestResult outcome={test} />
              <Stack direction="row" gap={1} flexWrap="wrap">
                <Button variant="outlined" startIcon={<NetworkCheckRoundedIcon />} disabled={test.state === "running"} onClick={() => void testConnection()} sx={{ minHeight: 44 }}>{pick(language, T.test)}</Button>
                {canWrite && !envManaged && <Button startIcon={<LinkRoundedIcon />} onClick={() => setWizardOpen(true)} sx={{ minHeight: 44 }}>{pick(language, T.edit)}</Button>}
              </Stack>
              {!canWrite && <NoAccess needs="dokploy:write" />}
            </Stack>
          </SectionCard>

          {canWrite && !envManaged && (
            <DangerZone
              items={[{
                title: pick(language, T.disconnect),
                description: pick(language, T.disconnectBody),
                action: <Button color="error" variant="outlined" startIcon={<LinkOffRoundedIcon />} onClick={() => void disconnect()}>{pick(language, T.disconnect)}</Button>
              }]}
            />
          )}
        </>
      )}

      {isAdvanced && config && <RegistrySettings groups={["server.apps"]} permissions={permissions} title={pick(language, T.settingsTitle)} />}

      <ConnectWizard open={wizardOpen} initialUrl={config?.url ?? ""} hasKey={configured} onClose={() => { setWizardOpen(false); void load(true); }} onSaved={() => void load(true)} />
      {historyFor && <DeploymentHistoryDialog service={historyFor} onClose={() => setHistoryFor(null)} onLog={setLogDeployment} />}
      {logDeployment && <DeploymentLogDialog deployment={logDeployment} onClose={() => setLogDeployment(null)} />}
      {dialog}
      {snackbar}
    </Stack>
  );
}
