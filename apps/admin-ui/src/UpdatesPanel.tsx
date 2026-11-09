/**
 * Server › App updates (docs/33 §4.2). Simple: which apps have a newer version, «بررسی همین
 * حالا», how to update (redeploy in Dokploy), and two plain settings. Advanced: version
 * fingerprints (digests), registry rate limits, the full check settings (mirrors, proxies,
 * insecure registries, ignore patterns …) and every `updates.*` setting.
 * ServerPage provides the page header and tabs.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  Box,
  Button,
  CircularProgress,
  Divider,
  FormControlLabel,
  Grid,
  IconButton,
  LinearProgress,
  MenuItem,
  Stack,
  Switch,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography
} from "@mui/material";
import TravelExploreRoundedIcon from "@mui/icons-material/TravelExploreRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import NewReleasesRoundedIcon from "@mui/icons-material/NewReleasesRounded";
import TaskAltRoundedIcon from "@mui/icons-material/TaskAltRounded";
import AppsRoundedIcon from "@mui/icons-material/AppsRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { Language } from "./i18n";
import { useVisibleInterval } from "./polling";
import { PROXY_TYPES, ProxyPicker, choiceFromApi, choiceToApi, useProxyList } from "./ProxyControls";
import {
  EmptyState, FriendlyError, Ltr, NoAccess, Notice, NumberInput, RelativeTime, ResponsiveList, SectionCard, StatusPill, useKit,
  useUndoSnackbar, RegistrySettings, helperProblem, PAIR_AGENT_HREF
} from "./kit";
import { pick, reasonFor, say, type Bi } from "./copy";

type Props = { language: Language; permissions: string[]; onUnauthorized: () => void };
type ImageStatus = "up_to_date" | "update_available" | "pinned" | "ignored" | "unknown" | "error";
type ImageItem = {
  image: string;
  tag: string | null;
  registry: string;
  repository?: string;
  reference?: string;
  current_digest: string | null;
  latest_digest: string | null;
  update_available: boolean;
  status: ImageStatus;
  checked_at: number | string | null;
  error_code: string | null;
  error_detail?: string | null;
  endpoint?: string | null;
  media_type?: string | null;
  containers: Array<{
    name: string;
    protected: boolean;
    state?: string;
    dokploy_url?: string | null;
    dokploy_service?: { type?: string; id?: string; name?: string; project_id?: string } | null;
  }>;
  /** Deep link to the matching Dokploy service (best effort; null without `dokploy:read`). */
  dokploy_url?: string | null;
};
type RateLimit = { limit: number | null; remaining: number | null; window_seconds: number | null; source?: string | null; checked_at?: number | string | null };
type ImagesPayload = {
  items: ImageItem[];
  last_run_at: number | string | null;
  last_attempt_at?: number | string | null;
  last_error?: string | null;
  running?: boolean;
  next_run_at?: number | string | null;
  rate_limits?: Record<string, RateLimit>;
  summary?: { total: number; update_available: number; errors: number };
  dokploy?: { configured: boolean; panel_url: string | null; matched?: number; error_code?: string | null } | null;
};
type UpdateSettings = {
  enabled: boolean;
  interval_hours: number;
  ignore: string[];
  include_stopped: boolean;
  notify: boolean;
  proxy_id: string | null;
  registry_proxies: Record<string, string | null>;
  mirrors: Record<string, string[]>;
  mirror_fallback: boolean;
  insecure_registries: string[];
  allow_get_fallback: boolean;
  timeout_seconds: number;
  concurrency: number;
};

const BASE = "/api/v1/updates";

const T = {
  unavailable: { fa: "این بخش روی نسخه فعلی سرور نیست. DevAssist را به‌روز کنید.", en: "This section isn't on this server version. Update DevAssist." },
  notPaired: { fa: "برای دیدن نسخه‌های تازه، اول دستیار سرور را وصل کنید.", en: "Connect the server helper first to see new versions." },
  pairAgent: { fa: "وصل کردن دستیار سرور", en: "Connect the server helper" },
  title: { fa: "نسخه‌های تازه برنامه‌ها", en: "New app versions" },
  hint: { fa: "DevAssist فقط خبر می‌دهد؛ خودش چیزی را به‌روز نمی‌کند.", en: "DevAssist only tells you; it never updates anything itself." },
  check: { fa: "بررسی همین حالا", en: "Check now" },
  checking: { fa: "در حال بررسی…", en: "Checking…" },
  checkStarted: { fa: "بررسی شروع شد؛ نتیجه چند لحظه بعد این‌جا می‌آید.", en: "The check started; results will appear here shortly." },
  someUpdates: { fa: "برای {n} برنامه نسخه تازه آمده", en: "{n} apps have a new version" },
  allGood: { fa: "همه برنامه‌ها به‌روزند", en: "Every app is up to date" },
  lastRun: { fa: "آخرین بررسی", en: "Last check" },
  nextRun: { fa: "بررسی بعدی", en: "Next check" },
  never: { fa: "هنوز بررسی نشده", en: "Not checked yet" },
  lastProblem: { fa: "آخرین بررسی کامل نشد: {reason}", en: "The last check didn't finish: {reason}" },
  technical: { fa: "جزئیات فنی", en: "Technical details" },
  // what to update
  todoTitle: { fa: "چه چیزی را به‌روز کنم؟", en: "What should I update?" },
  howTo: { fa: "برای به‌روزرسانی، این برنامه را در Dokploy دوباره منتشر کنید.", en: "To update, deploy this app again in Dokploy." },
  openApps: { fa: "رفتن به برنامه‌های Dokploy", en: "Go to Dokploy apps" },
  openInDokploy: { fa: "باز کردن در Dokploy", en: "Open in Dokploy" },
  colDokploy: { fa: "در Dokploy", en: "In Dokploy" },
  todoEmptyTitle: { fa: "فعلاً چیزی برای به‌روزرسانی نیست", en: "Nothing to update right now" },
  todoEmptyBody: { fa: "وقتی نسخه تازه‌ای بیاید، همین‌جا نشانتان می‌دهیم.", en: "When a new version comes out, it shows up here." },
  noImagesTitle: { fa: "هنوز برنامه‌ای پیدا نشده", en: "No apps found yet" },
  noImagesBody: { fa: "یک بار بررسی کنید تا فهرست برنامه‌های در حال اجرا ساخته شود.", en: "Run a check once to build the list of running apps." },
  colApp: { fa: "برنامه", en: "App" },
  colImage: { fa: "نسخه برنامه (ایمیج)", en: "Image" },
  colTag: { fa: "برچسب نسخه", en: "Tag" },
  colStatus: { fa: "وضعیت", en: "Status" },
  colChecked: { fa: "زمان بررسی", en: "Checked" },
  colRegistry: { fa: "مخزن نسخه‌ها", en: "Registry" },
  colCurrent: { fa: "شناسه نسخه فعلی", en: "Current digest" },
  colLatest: { fa: "شناسه نسخه تازه", en: "Latest digest" },
  colEndpoint: { fa: "نشانی بررسی", en: "Endpoint" },
  colMedia: { fa: "نوع فهرست نسخه", en: "Manifest type" },
  colProblem: { fa: "مشکل", en: "Problem" },
  sameTagNewer: { fa: "برای همین برچسب، نسخه تازه‌تری منتشر شده است.", en: "A newer build was published under the same tag." },
  noContainers: { fa: "هیچ کانتینری از آن استفاده نمی‌کند", en: "No container uses it" },
  dokployOwned: { fa: "مال Dokploy", en: "Dokploy's" },
  pinned: { fa: "نسخه قفل‌شده", en: "Pinned version" },
  ignored: { fa: "نادیده گرفته می‌شود", en: "Ignored" },
  // all apps
  allTitle: { fa: "همه برنامه‌های بررسی‌شده", en: "Every checked app" },
  all: { fa: "همه", en: "All" },
  onlyUpdates: { fa: "نسخه تازه دارند", en: "Have an update" },
  onlyErrors: { fa: "بررسی نشدند", en: "Couldn't check" },
  noneFiltered: { fa: "موردی با این انتخاب نیست.", en: "Nothing matches this choice." },
  // simple settings
  simpleSettings: { fa: "هر چند وقت بررسی شود", en: "How often to check" },
  everyHours: { fa: "هر {n} ساعت", en: "Every {n} hours" },
  daily: { fa: "روزی یک بار", en: "Once a day" },
  weekly: { fa: "هفته‌ای یک بار", en: "Once a week" },
  autoCheck: { fa: "خودکار بررسی شود", en: "Check automatically" },
  notifyMe: { fa: "وقتی نسخه تازه آمد خبرم کن", en: "Tell me when a new version comes out" },
  saved: { fa: "تنظیمات بررسی ذخیره شد.", en: "Check settings saved." },
  // advanced settings
  rateLimits: { fa: "سهمیه درخواست مخزن‌های نسخه", en: "Registry rate limits" },
  rlRemaining: { fa: "باقی‌مانده از سقف", en: "Remaining of limit" },
  rlWindow: { fa: "بازه", en: "Window" },
  rlSource: { fa: "منبع عدد", en: "Source" },
  hours: { fa: "{n} ساعت", en: "{n} h" },
  methodTitle: { fa: "منابع و روش بررسی", en: "Sources and how to check" },
  methodHint: { fa: "این تنظیمات معمولاً لازم نیست؛ برای اینترنت محدود یا مخزن‌های خصوصی است.", en: "Usually not needed; for limited internet or private registries." },
  includeStopped: { fa: "کانتینرهای خاموش هم بررسی شوند", en: "Also check stopped containers" },
  allowGet: { fa: "اگر روش سبک بررسی جواب نداد، با روش کامل بررسی شود (از سهمیه Docker Hub کم می‌کند)", en: "If the light check isn't supported, fall back to a full request (uses Docker Hub quota)" },
  mirrorFallback: { fa: "اگر نسخه آینه جواب نداد، مخزن اصلی امتحان شود", en: "Try the original registry if the mirrors fail" },
  interval: { fa: "فاصله بررسی", en: "Check interval" },
  timeout: { fa: "حداکثر زمان انتظار هر درخواست", en: "Timeout per request" },
  concurrency: { fa: "چند بررسی هم‌زمان", en: "Checks at the same time" },
  ignore: { fa: "برنامه‌هایی که بررسی نشوند (هر خط یکی، مثل «postgres:*» یا «ghcr.io/org/*»)", en: "Apps to skip (one per line, e.g. postgres:* or ghcr.io/org/*)" },
  insecure: { fa: "مخزن‌هایی که اتصال امن ندارند (هر خط یکی)", en: "Registries without a secure connection (one per line)" },
  proxy: { fa: "پروکسی برای بررسی نسخه‌ها", en: "Proxy for update checks" },
  registryProxies: { fa: "پروکسی جدا برای هر مخزن", en: "A separate proxy per registry" },
  mirrors: { fa: "نسخه‌های آینه (منبع جایگزین نزدیک)", en: "Mirrors" },
  mirrorsHint: { fa: "برای هر مخزن، نسخه‌های آینه به ترتیب امتحان می‌شوند. با ویرگول جدا کنید.", en: "Mirrors are tried in order for each registry. Separate them with commas." },
  registry: { fa: "مخزن", en: "Registry" },
  mirrorList: { fa: "نشانی آینه‌ها", en: "Mirror addresses" },
  addRow: { fa: "افزودن", en: "Add" },
  removeRow: { fa: "پاک کردن", en: "Remove" },
  suggestArvan: { fa: "پیشنهاد: docker.io ← docker.arvancloud.ir", en: "Suggestion: docker.io → docker.arvancloud.ir" },
  save: { fa: "ذخیره", en: "Save" },
  allSettings: { fa: "همه تنظیمات بررسی نسخه‌ها", en: "Every update-check setting" }
} satisfies Record<string, Bi>;

const INTERVAL_PRESETS = [6, 12, 24, 48, 168];

function shortDigest(digest: string | null) {
  if (!digest) return "—";
  return `sha256:${digest.replace(/^sha256:/, "").slice(0, 12)}`;
}

function isMissingModule(error: unknown) {
  return helperProblem(error) === "module_missing";
}

function referenceOf(item: ImageItem) {
  return item.reference || (item.tag ? `${item.image}:${item.tag}` : item.image);
}

function appName(item: ImageItem) {
  const names = item.containers.map((container) => container.name.replace(/^\//, ""));
  if (names.length) return names.join("، ");
  const base = item.image.split("/").pop() ?? item.image;
  return base;
}

function ImageStatusPill({ item }: { item: ImageItem }) {
  const { language } = useKit();
  if (item.status === "pinned") return <StatusPill tone="info" label={pick(language, T.pinned)} />;
  if (item.status === "ignored") return <StatusPill tone="off" label={pick(language, T.ignored)} />;
  if (item.status === "error") return <StatusPill tone="error" label={pick(language, T.onlyErrors)} />;
  return <StatusPill status={item.status} />;
}

function dokployUrlOf(item: ImageItem): string | null {
  return item.dokploy_url ?? item.containers.find((container) => container.dokploy_url)?.dokploy_url ?? null;
}

/** «باز کردن در Dokploy» (new tab). Nothing when there is no matching service. */
function DokployLink({ url }: { url: string | null }) {
  const { language } = useKit();
  if (!url) return <>—</>;
  return (
    <Button size="small" href={url} target="_blank" rel="noopener noreferrer" endIcon={<OpenInNewRoundedIcon fontSize="small" />} sx={{ minHeight: 36, whiteSpace: "nowrap" }}>
      {pick(language, T.openInDokploy)}
    </Button>
  );
}

function Containers({ item }: { item: ImageItem }) {
  const { language } = useKit();
  if (item.containers.length === 0) return <Typography variant="caption" color="text.secondary">{pick(language, T.noContainers)}</Typography>;
  return (
    <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
      {item.containers.map((container) => (
        <Stack key={container.name} direction="row" spacing={0.25} alignItems="center">
          {container.protected && (
            <Tooltip title={pick(language, T.dokployOwned)}>
              <LockRoundedIcon sx={{ fontSize: 14, color: "secondary.main" }} aria-label={pick(language, T.dokployOwned)} />
            </Tooltip>
          )}
          <Typography variant="body2"><Ltr>{container.name.replace(/^\//, "")}</Ltr></Typography>
        </Stack>
      ))}
    </Stack>
  );
}

// ── Simple settings: how often + tell me ──────────────────────────────────────

function SimpleSettings({ canWrite }: { canWrite: boolean }) {
  const { language } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const [settings, setSettings] = useState<UpdateSettings | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        setSettings(await getJson<UpdateSettings>(`${BASE}/settings`, controller.signal));
      } catch (caught) {
        if (!isAbortError(caught) && !(caught instanceof ApiError && caught.status === 401)) setError(caught);
      }
    })();
    return () => controller.abort();
  }, []);

  const save = async (patch: Partial<UpdateSettings>) => {
    if (!settings || !canWrite) return;
    const previous = settings;
    const body = { ...settings, ...patch };
    setSettings(body);
    setBusy(true);
    setError(null);
    try {
      const saved = await mutateJson<UpdateSettings | null>(`${BASE}/settings`, { method: "PUT", body });
      setSettings(saved ?? body);
      notify({ message: pick(language, T.saved), tone: "success" });
    } catch (caught) {
      setSettings(previous);
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const presetLabel = (hours: number) => (hours === 24 ? pick(language, T.daily) : hours === 168 ? pick(language, T.weekly) : say(language, T.everyHours, { n: hours }));
  const presets = settings && !INTERVAL_PRESETS.includes(settings.interval_hours) ? [...INTERVAL_PRESETS, settings.interval_hours].sort((a, b) => a - b) : INTERVAL_PRESETS;

  return (
    <SectionCard title={pick(language, T.simpleSettings)}>
      {error !== null && <FriendlyError error={error} onClose={() => setError(null)} />}
      {settings === null && error === null && <LinearProgress />}
      {settings && (
        <Stack spacing={1}>
          <FormControlLabel control={<Switch checked={settings.enabled} disabled={!canWrite || busy} onChange={(event) => void save({ enabled: event.target.checked })} />} label={pick(language, T.autoCheck)} />
          <TextField
            select
            size="small"
            label={pick(language, T.simpleSettings)}
            value={settings.interval_hours}
            disabled={!canWrite || busy || !settings.enabled}
            onChange={(event) => void save({ interval_hours: Number(event.target.value) })}
            sx={{ maxWidth: 280 }}
          >
            {presets.map((hours) => <MenuItem key={hours} value={hours}>{presetLabel(hours)}</MenuItem>)}
          </TextField>
          <FormControlLabel control={<Switch checked={settings.notify !== false} disabled={!canWrite || busy} onChange={(event) => void save({ notify: event.target.checked })} />} label={pick(language, T.notifyMe)} />
          {!canWrite && <NoAccess needs="updates:write" />}
        </Stack>
      )}
      {snackbar}
    </SectionCard>
  );
}

// ── Advanced: sources and how to check ───────────────────────────────────────

type Row = { registry: string; value: string };

function AdvancedSettingsCard({ canWrite }: { canWrite: boolean }) {
  const { language } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const { list: proxyList, failed: proxyFailed } = useProxyList();
  const [settings, setSettings] = useState<UpdateSettings | null>(null);
  const [draft, setDraft] = useState({ enabled: true, interval: 12, include_stopped: false, notify: true, timeout: 10, concurrency: 4, allow_get_fallback: false, mirror_fallback: true, ignore: "", insecure: "", proxy: "" });
  const [mirrors, setMirrors] = useState<Row[]>([]);
  const [registryProxies, setRegistryProxies] = useState<Row[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const adopt = (next: UpdateSettings) => {
    setSettings(next);
    setDraft({
      enabled: next.enabled,
      interval: next.interval_hours ?? 12,
      include_stopped: Boolean(next.include_stopped),
      notify: next.notify !== false,
      timeout: next.timeout_seconds ?? 10,
      concurrency: next.concurrency ?? 4,
      allow_get_fallback: Boolean(next.allow_get_fallback),
      mirror_fallback: next.mirror_fallback !== false,
      ignore: (next.ignore ?? []).join("\n"),
      insecure: (next.insecure_registries ?? []).join("\n"),
      proxy: choiceFromApi(next.proxy_id)
    });
    setMirrors(Object.entries(next.mirrors ?? {}).map(([registry, list]) => ({ registry, value: (list ?? []).join(", ") })));
    setRegistryProxies(Object.entries(next.registry_proxies ?? {}).map(([registry, proxy]) => ({ registry, value: choiceFromApi(proxy) })));
  };

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        adopt(await getJson<UpdateSettings>(`${BASE}/settings`, controller.signal));
      } catch (caught) {
        if (!isAbortError(caught) && !(caught instanceof ApiError && caught.status === 401)) setError(caught);
      }
    })();
    return () => controller.abort();
  }, []);

  const ranges = { interval: [1, 168], timeout: [1, 120], concurrency: [1, 32] } as const;
  const inRange = (value: number, [min, max]: readonly [number, number]) => Number.isFinite(value) && value >= min && value <= max;
  const valid = inRange(draft.interval, ranges.interval) && inRange(draft.timeout, ranges.timeout) && inRange(draft.concurrency, ranges.concurrency);
  const lines = (text: string) => text.split(/\n+/).map((item) => item.trim()).filter(Boolean);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite || !valid || busy) return;
    setBusy(true);
    setSaveError(null);
    const body: UpdateSettings = {
      enabled: draft.enabled,
      interval_hours: draft.interval,
      ignore: lines(draft.ignore),
      include_stopped: draft.include_stopped,
      notify: draft.notify,
      proxy_id: choiceToApi(draft.proxy),
      registry_proxies: Object.fromEntries(registryProxies.filter((row) => row.registry.trim()).map((row) => [row.registry.trim(), choiceToApi(row.value)])),
      mirrors: Object.fromEntries(mirrors.filter((row) => row.registry.trim()).map((row) => [row.registry.trim(), row.value.split(/[,،\s]+/).map((item) => item.trim()).filter(Boolean)])),
      mirror_fallback: draft.mirror_fallback,
      insecure_registries: lines(draft.insecure),
      allow_get_fallback: draft.allow_get_fallback,
      timeout_seconds: draft.timeout,
      concurrency: draft.concurrency
    };
    try {
      const saved = await mutateJson<UpdateSettings | null>(`${BASE}/settings`, { method: "PUT", body });
      adopt(saved ?? body);
      notify({ message: pick(language, T.saved), tone: "success" });
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setSaveError(caught);
    } finally {
      setBusy(false);
    }
  };

  const disabled = !canWrite || busy;
  const switchField = (key: "include_stopped" | "allow_get_fallback" | "mirror_fallback", label: Bi) => (
    <FormControlLabel control={<Switch checked={draft[key]} disabled={disabled} onChange={(event) => setDraft((value) => ({ ...value, [key]: event.target.checked }))} />} label={pick(language, label)} />
  );
  const rowsEditor = (rows: Row[], setRows: (rows: Row[]) => void, kind: "mirrors" | "proxies") => (
    <Stack spacing={1}>
      {rows.map((row, index) => (
        <Stack key={index} direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ sm: "center" }}>
          <TextField size="small" label={pick(language, T.registry)} value={row.registry} disabled={disabled} onChange={(event) => setRows(rows.map((item, position) => (position === index ? { ...item, registry: event.target.value } : item)))} sx={{ minWidth: 200 }} slotProps={{ htmlInput: { dir: "ltr" } }} />
          <Box sx={{ flex: 1 }}>
            {kind === "mirrors"
              ? <TextField fullWidth size="small" label={pick(language, T.mirrorList)} value={row.value} disabled={disabled} onChange={(event) => setRows(rows.map((item, position) => (position === index ? { ...item, value: event.target.value } : item)))} slotProps={{ htmlInput: { dir: "ltr" } }} />
              : <ProxyPicker language={language} list={proxyList} value={row.value} onChange={(value) => setRows(rows.map((item, position) => (position === index ? { ...item, value } : item)))} supported={PROXY_TYPES} advanced disabled={disabled} label={row.registry} />}
          </Box>
          <IconButton aria-label={`${pick(language, T.removeRow)} · ${row.registry}`} disabled={disabled} onClick={() => setRows(rows.filter((_item, position) => position !== index))} sx={{ width: 44, height: 44 }}><DeleteOutlineRoundedIcon fontSize="small" /></IconButton>
        </Stack>
      ))}
      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        <Button size="small" startIcon={<AddRoundedIcon />} disabled={disabled} onClick={() => setRows([...rows, { registry: "", value: "" }])}>{pick(language, T.addRow)}</Button>
        {kind === "mirrors" && !rows.some((row) => row.registry.trim() === "docker.io") && (
          <Button size="small" variant="outlined" disabled={disabled} onClick={() => setRows([...rows, { registry: "docker.io", value: "docker.arvancloud.ir" }])}>{pick(language, T.suggestArvan)}</Button>
        )}
      </Stack>
    </Stack>
  );

  return (
    <SectionCard advanced title={pick(language, T.methodTitle)} hint={pick(language, T.methodHint)} collapsible>
      {error !== null && <FriendlyError error={error} />}
      {settings === null && error === null && <LinearProgress />}
      {settings && (
        <Box component="form" onSubmit={submit} noValidate>
          {!canWrite && <Box sx={{ mb: 1.5 }}><NoAccess needs="updates:write" /></Box>}
          <Stack>
            {switchField("include_stopped", T.includeStopped)}
            {switchField("allow_get_fallback", T.allowGet)}
            {switchField("mirror_fallback", T.mirrorFallback)}
          </Stack>
          <Grid container spacing={1.5} sx={{ mt: 1 }}>
            <Grid size={{ xs: 12, sm: 4 }}>
              <NumberInput label={pick(language, T.interval)} value={draft.interval} onChange={(value) => setDraft((current) => ({ ...current, interval: value ?? NaN }))} min={ranges.interval[0]} max={ranges.interval[1]} integer unit="hours" disabled={disabled} />
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <NumberInput label={pick(language, T.timeout)} value={draft.timeout} onChange={(value) => setDraft((current) => ({ ...current, timeout: value ?? NaN }))} min={ranges.timeout[0]} max={ranges.timeout[1]} integer unit="seconds" disabled={disabled} />
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <NumberInput label={pick(language, T.concurrency)} value={draft.concurrency} onChange={(value) => setDraft((current) => ({ ...current, concurrency: value ?? NaN }))} min={ranges.concurrency[0]} max={ranges.concurrency[1]} integer disabled={disabled} />
            </Grid>
            {!proxyFailed && (
              <Grid size={{ xs: 12, md: 6 }}>
                <Typography variant="subtitle2" sx={{ mb: 0.75 }}>{pick(language, T.proxy)}</Typography>
                <ProxyPicker language={language} list={proxyList} value={draft.proxy} onChange={(value) => setDraft((current) => ({ ...current, proxy: value }))} supported={PROXY_TYPES} advanced disabled={disabled} />
              </Grid>
            )}
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField fullWidth size="small" multiline minRows={3} label={pick(language, T.ignore)} value={draft.ignore} disabled={disabled} onChange={(event) => setDraft((value) => ({ ...value, ignore: event.target.value }))} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField fullWidth size="small" multiline minRows={3} label={pick(language, T.insecure)} value={draft.insecure} disabled={disabled} onChange={(event) => setDraft((value) => ({ ...value, insecure: event.target.value }))} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
            </Grid>
          </Grid>
          <Divider sx={{ my: 2 }} />
          <Typography variant="subtitle2">{pick(language, T.mirrors)}</Typography>
          <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>{pick(language, T.mirrorsHint)}</Typography>
          {rowsEditor(mirrors, setMirrors, "mirrors")}
          {!proxyFailed && (
            <>
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle2" sx={{ mb: 1 }}>{pick(language, T.registryProxies)}</Typography>
              {rowsEditor(registryProxies, setRegistryProxies, "proxies")}
            </>
          )}
          {saveError !== null && <Box sx={{ mt: 2 }}><FriendlyError error={saveError} onClose={() => setSaveError(null)} /></Box>}
          {canWrite && <Button type="submit" variant="contained" sx={{ mt: 2, minHeight: 44 }} disabled={!valid || busy} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined}>{pick(language, T.save)}</Button>}
        </Box>
      )}
      {snackbar}
    </SectionCard>
  );
}

function RateLimits({ limits }: { limits: Record<string, RateLimit> }) {
  const { language } = useKit();
  const entries = Object.entries(limits).map(([endpoint, limit]) => ({ endpoint, ...limit }));
  if (!entries.length) return null;
  const n = (value: number | null) => (value === null ? "—" : value.toLocaleString(language === "fa" ? "fa-IR" : "en-US"));
  return (
    <SectionCard advanced title={pick(language, T.rateLimits)} flush>
      <ResponsiveList
        label={pick(language, T.rateLimits)}
        rows={entries}
        rowKey={(row) => row.endpoint}
        dense
        columns={[
          { key: "endpoint", header: pick(language, T.colRegistry), render: (row) => <Ltr>{row.endpoint}</Ltr>, ltr: true },
          { key: "remaining", header: pick(language, T.rlRemaining), render: (row) => `${n(row.remaining)} / ${n(row.limit)}` },
          { key: "window", header: pick(language, T.rlWindow), render: (row) => (row.window_seconds ? say(language, T.hours, { n: Math.round((row.window_seconds / 3600) * 10) / 10 }) : "—") },
          { key: "source", header: pick(language, T.rlSource), render: (row) => <Ltr>{row.source ?? "—"}</Ltr> },
          { key: "checked", header: pick(language, T.colChecked), render: (row) => <RelativeTime value={row.checked_at ?? null} /> }
        ]}
        card={{ title: (row) => <Ltr>{row.endpoint}</Ltr>, meta: (row) => `${n(row.remaining)} / ${n(row.limit)}` }}
      />
    </SectionCard>
  );
}

// ── Panel ─────────────────────────────────────────────────────────────────────

export function UpdatesPanel({ language, permissions }: Props) {
  const { isAdvanced } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const canWrite = hasPermission(permissions, "updates:write");
  const [data, setData] = useState<ImagesPayload | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [starting, setStarting] = useState(false);
  const [filter, setFilter] = useState<"all" | "updates" | "errors">("all");
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async (background = false) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    if (!background) setLoading(true);
    try {
      setData(await getJson<ImagesPayload>(`${BASE}/images`, current.signal));
      setUnavailable(false);
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      if (isMissingModule(caught)) setUnavailable(true);
      else setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);
  useVisibleInterval(() => void load(true), unavailable ? null : data?.running ? 5_000 : 60_000);

  const check = async () => {
    setStarting(true);
    setActionError(null);
    try {
      await mutateJson(`${BASE}/check`, { method: "POST" });
      notify({ message: pick(language, T.checkStarted), tone: "info" });
      setData((current) => (current ? { ...current, running: true } : current));
      window.setTimeout(() => void load(true), 1500);
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    } finally {
      setStarting(false);
    }
  };

  const items = data?.items ?? [];
  const updates = useMemo(() => items.filter((item) => item.status === "update_available" || item.update_available).sort((a, b) => a.image.localeCompare(b.image)), [items]);
  const summaryUpdates = data?.summary?.update_available ?? updates.length;
  const visible = useMemo(() => {
    const sorted = [...items].sort((a, b) => {
      const rank = (item: ImageItem) => (item.status === "update_available" ? 0 : item.status === "error" ? 1 : 2);
      return rank(a) - rank(b) || a.image.localeCompare(b.image);
    });
    if (filter === "updates") return sorted.filter((item) => item.status === "update_available");
    if (filter === "errors") return sorted.filter((item) => item.status === "error");
    return sorted;
  }, [filter, items]);
  const running = Boolean(data?.running);
  const notPaired = helperProblem(error) === "not_paired";

  if (unavailable) return <Notice>{pick(language, T.unavailable)}</Notice>;
  if (notPaired) {
    return (
      <SectionCard title={pick(language, T.title)}>
        <EmptyState icon={AppsRoundedIcon} title={pick(language, T.notPaired)} action={<Button variant="contained" href={PAIR_AGENT_HREF} sx={{ minHeight: 44 }}>{pick(language, T.pairAgent)}</Button>} />
      </SectionCard>
    );
  }

  const checkButton = canWrite ? (
    <Button variant="contained" startIcon={running || starting ? <CircularProgress size={16} color="inherit" /> : <TravelExploreRoundedIcon />} disabled={running || starting} onClick={() => void check()} sx={{ minHeight: 40 }}>
      {running ? pick(language, T.checking) : pick(language, T.check)}
    </Button>
  ) : undefined;

  const statusColumns = [
    { key: "app", header: pick(language, T.colApp), render: (row: ImageItem) => <Containers item={row} /> },
    { key: "image", header: pick(language, T.colImage), render: (row: ImageItem) => <Ltr>{row.image}</Ltr>, ltr: true },
    { key: "tag", header: pick(language, T.colTag), render: (row: ImageItem) => <Ltr mono>{row.tag ?? "—"}</Ltr>, ltr: true }
  ];

  return (
    <Stack spacing={3}>
      {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
      {actionError !== null && <FriendlyError error={actionError} onClose={() => setActionError(null)} />}
      {loading && !data && error === null && <LinearProgress />}

      {data && (
        <>
          <SectionCard
            title={pick(language, T.title)}
            hint={pick(language, T.hint)}
            status={summaryUpdates > 0 ? <StatusPill tone="warn" label={say(language, T.someUpdates, { n: summaryUpdates })} /> : items.length > 0 ? <StatusPill tone="ok" label={pick(language, T.allGood)} /> : undefined}
            action={checkButton}
          >
            <Stack spacing={1.5}>
              <Stack direction={{ xs: "column", sm: "row" }} spacing={{ xs: 0.5, sm: 3 }}>
                <Typography variant="body2" color="text.secondary">
                  {pick(language, T.lastRun)}: {data.last_run_at ? <RelativeTime value={data.last_run_at} /> : pick(language, T.never)}
                </Typography>
                {data.next_run_at && <Typography variant="body2" color="text.secondary">{pick(language, T.nextRun)}: <RelativeTime value={data.next_run_at} /></Typography>}
              </Stack>
              {running && <LinearProgress aria-label={pick(language, T.checking)} />}
              {data.last_error && (
                <Notice tone="warning">
                  {say(language, T.lastProblem, { reason: reasonFor(language, data.last_error) })}
                  {isAdvanced && <Box component="div" sx={{ mt: 0.5 }}>{pick(language, T.technical)}: <Ltr mono>{data.last_error}</Ltr></Box>}
                </Notice>
              )}
              {!canWrite && <NoAccess needs="updates:write" />}
            </Stack>
          </SectionCard>

          <SectionCard title={pick(language, T.todoTitle)} flush>
            {updates.length > 0 && (
              <Box sx={{ p: 2, pb: 0 }}>
                <Notice
                  tone="info"
                  action={
                    data.dokploy?.panel_url ? (
                      <Button color="inherit" size="small" href={data.dokploy.panel_url} target="_blank" rel="noopener noreferrer" endIcon={<OpenInNewRoundedIcon fontSize="small" />} sx={{ whiteSpace: "nowrap" }}>{pick(language, T.openInDokploy)}</Button>
                    ) : (
                      <Button color="inherit" size="small" href="#/server/apps" sx={{ whiteSpace: "nowrap" }}>{pick(language, T.openApps)}</Button>
                    )
                  }
                >
                  {pick(language, T.howTo)}
                </Notice>
              </Box>
            )}
            <ResponsiveList
              label={pick(language, T.todoTitle)}
              rows={updates}
              rowKey={(row) => `${row.registry}/${referenceOf(row)}`}
              columns={[
                ...statusColumns,
                { key: "status", header: pick(language, T.colStatus), render: (row) => <ImageStatusPill item={row} />, hideOnCard: true },
                { key: "dokploy", header: pick(language, T.colDokploy), render: (row) => <DokployLink url={dokployUrlOf(row)} /> },
                { key: "checked", header: pick(language, T.colChecked), render: (row) => <RelativeTime value={row.checked_at} /> },
                { key: "current", header: pick(language, T.colCurrent), render: (row) => <Tooltip title={row.current_digest ?? ""}><span><Ltr mono>{shortDigest(row.current_digest)}</Ltr></span></Tooltip>, advancedOnly: true, ltr: true },
                { key: "latest", header: pick(language, T.colLatest), render: (row) => <Tooltip title={row.latest_digest ?? ""}><span><Ltr mono>{shortDigest(row.latest_digest)}</Ltr></span></Tooltip>, advancedOnly: true, ltr: true }
              ]}
              card={{
                title: (row) => <Box component="span" dir="auto">{appName(row)}</Box>,
                meta: (row) => <><Ltr>{referenceOf(row)}</Ltr><Typography variant="caption" color="text.secondary" display="block">{pick(language, T.sameTagNewer)}</Typography></>,
                status: (row) => <ImageStatusPill item={row} />
              }}
              empty={<EmptyState compact icon={items.length ? TaskAltRoundedIcon : NewReleasesRoundedIcon} title={pick(language, items.length ? T.todoEmptyTitle : T.noImagesTitle)} body={pick(language, items.length ? T.todoEmptyBody : T.noImagesBody)} action={items.length ? undefined : checkButton} />}
            />
          </SectionCard>

          {items.length > 0 && (
            <SectionCard
              title={pick(language, T.allTitle)}
              collapsible
              defaultCollapsed={!isAdvanced}
              flush
              action={isAdvanced ? (
                <ToggleButtonGroup size="small" exclusive value={filter} onChange={(_event, value: "all" | "updates" | "errors" | null) => value && setFilter(value)} aria-label={pick(language, T.allTitle)}>
                  <ToggleButton value="all" sx={{ px: 1.5 }}>{pick(language, T.all)}</ToggleButton>
                  <ToggleButton value="updates" sx={{ px: 1.5 }}>{pick(language, T.onlyUpdates)}</ToggleButton>
                  <ToggleButton value="errors" sx={{ px: 1.5 }}>{pick(language, T.onlyErrors)}</ToggleButton>
                </ToggleButtonGroup>
              ) : undefined}
            >
              <ResponsiveList
                label={pick(language, T.allTitle)}
                rows={isAdvanced ? visible : [...items].sort((a, b) => a.image.localeCompare(b.image))}
                rowKey={(row) => `${row.registry}/${referenceOf(row)}`}
                dense
                columns={[
                  ...statusColumns,
                  { key: "status", header: pick(language, T.colStatus), render: (row) => <ImageStatusPill item={row} />, hideOnCard: true },
                  { key: "problem", header: pick(language, T.colProblem), render: (row) => (row.status === "error" ? <Typography variant="caption" color="error.main">{reasonFor(language, row.error_code)}</Typography> : "—") },
                  { key: "checked", header: pick(language, T.colChecked), render: (row) => <RelativeTime value={row.checked_at} />, hideOnCard: true },
                  { key: "registry", header: pick(language, T.colRegistry), render: (row) => <Ltr>{row.registry}</Ltr>, advancedOnly: true, ltr: true },
                  { key: "current", header: pick(language, T.colCurrent), render: (row) => <Tooltip title={row.current_digest ?? ""}><span><Ltr mono>{shortDigest(row.current_digest)}</Ltr></span></Tooltip>, advancedOnly: true, ltr: true },
                  { key: "latest", header: pick(language, T.colLatest), render: (row) => <Tooltip title={row.latest_digest ?? ""}><span><Ltr mono>{shortDigest(row.latest_digest)}</Ltr></span></Tooltip>, advancedOnly: true, ltr: true },
                  { key: "endpoint", header: pick(language, T.colEndpoint), render: (row) => <Ltr>{row.endpoint ?? "—"}</Ltr>, advancedOnly: true, ltr: true },
                  { key: "media", header: pick(language, T.colMedia), render: (row) => <Ltr mono>{row.media_type ?? "—"}</Ltr>, advancedOnly: true, ltr: true },
                  { key: "technical", header: pick(language, T.technical), render: (row) => (row.error_code || row.error_detail ? <Ltr mono>{[row.error_code, row.error_detail].filter(Boolean).join(" · ")}</Ltr> : "—"), advancedOnly: true, ltr: true }
                ]}
                card={{
                  title: (row) => <Box component="span" dir="auto">{appName(row)}</Box>,
                  meta: (row) => <Ltr>{referenceOf(row)}</Ltr>,
                  status: (row) => <ImageStatusPill item={row} />
                }}
                empty={<Typography variant="body2" color="text.secondary" sx={{ p: 2 }}>{pick(language, T.noneFiltered)}</Typography>}
              />
            </SectionCard>
          )}

          <SimpleSettings canWrite={canWrite} />

          {isAdvanced && data.rate_limits && <RateLimits limits={data.rate_limits} />}
          {isAdvanced && <AdvancedSettingsCard canWrite={canWrite} />}
          {isAdvanced && <RegistrySettings groups={["server.updates"]} permissions={permissions} title={pick(language, T.allSettings)} />}
        </>
      )}
      {snackbar}
    </Stack>
  );
}
