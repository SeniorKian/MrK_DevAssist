import { useCallback, useEffect, useRef, useState } from "react";
import {
  Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Grid, MenuItem, Stack, Switch,
  TextField, ToggleButton, ToggleButtonGroup, Typography, useMediaQuery, useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import NetworkCheckRoundedIcon from "@mui/icons-material/NetworkCheckRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import LockOpenRoundedIcon from "@mui/icons-material/LockOpenRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import CloudSyncRoundedIcon from "@mui/icons-material/CloudSyncRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { nameConfirmation, pick, say, termWithEnglish, type Bi } from "./copy";
import {
  ActionWizard, ConfirmAction, EmptyState, FriendlyError, HelpTip, Ltr, NoAccess, Notice, NumberInput, RelativeTime, ResponsiveList,
  SectionCard, StatusPill, TestResult, useConfirmAction, useKit, useUndoSnackbar, RegistrySettings, type TestOutcome, type WizardStep
} from "./kit";
import { ProxyPicker, choiceFromApi, choiceToApi, supportedTypesFor, useProxyList, type ProxyChoice } from "./ProxyControls";
import { formatMs, formatNumber } from "./format";
import type { Language } from "./i18n";

/**
 * Packages › «منابع دریافت» (docs/33 §4.2).
 * Simple: per-ecosystem status, «امتحان اتصال», offline switch, «افزودن منبع» wizard.
 * Advanced: order, timeout, password, proxy per source, block for a while, health history, delete,
 * and every packages setting from the registry.
 */

type Ecosystem = "npm" | "pypi";

type UpstreamRecord = {
  id: string;
  name: string;
  ecosystem: Ecosystem;
  url: string;
  priority: number;
  timeout_seconds: number;
  enabled: boolean;
  blocked_until: number | null;
  blocked_reason: string | null;
  credential_configured: boolean;
  credential_type?: "bearer" | "basic" | null;
  credential_updated_at?: number | null;
  proxy_id?: string | null;
};

type ProbeStage = { name: string; status: "ok" | "failed"; latency_ms: number; detail?: string };
type ProbeResult = { ok?: boolean; stages?: ProbeStage[]; total_latency_ms?: number };
type HealthCheck = { id: number; upstream_id: string; ok: boolean; stages: ProbeStage[]; total_latency_ms: number; checked_at: number };

const PRIORITY_RANGE = { min: 1, max: 10000 };
const TIMEOUT_RANGE = { min: 1, max: 300 };
const FOREVER = 2147483647;
const ECOSYSTEM_NAME: Record<Ecosystem, string> = { npm: "npm", pypi: "PyPI" };

const COPY = {
  intro: { fa: "DevAssist بسته‌ها را از این منابع می‌گیرد؛ اگر اولی جواب نداد، سراغ بعدی می‌رود.", en: "DevAssist fetches packages from these sources; if the first doesn't answer, it tries the next." },
  add: { fa: "افزودن منبع", en: "Add a source" },
  refresh: { fa: "تازه کردن", en: "Refresh" },
  // ecosystem card
  ecoHint: { fa: "{n} منبع، به این ترتیب: {names}", en: "{n} sources, in this order: {names}" },
  ecoNone: { fa: "هنوز منبعی ندارد.", en: "No sources yet." },
  ready: { fa: "آماده", en: "Ready" },
  noSource: { fa: "منبعی ندارد", en: "No source" },
  allBlocked: { fa: "همه منابع مسدود یا خاموش‌اند", en: "All sources are blocked or off" },
  offline: { fa: "بدون اینترنت", en: "Offline" },
  testAll: { fa: "امتحان اتصال", en: "Test connection" },
  offlineLabel: { fa: "حالت بدون اینترنت", en: "Offline mode" },
  offlineHint: { fa: "فقط بسته‌هایی که قبلاً ذخیره شده‌اند داده می‌شوند و DevAssist به اینترنت نمی‌رود.", en: "Only packages already stored are served, and DevAssist doesn't go to the internet." },
  offlineOnTitle: { fa: "{eco} بدون اینترنت شود؟", en: "Switch {eco} to offline mode?" },
  offlineOnBody: { fa: "تا وقتی خاموشش نکنید، بسته‌ای که روی سرور نیست نصب نمی‌شود.", en: "Until you turn it off, packages that aren't stored here won't install." },
  offlineOffTitle: { fa: "{eco} دوباره به اینترنت وصل شود؟", en: "Reconnect {eco} to the internet?" },
  offlineOffBody: { fa: "DevAssist دوباره از منابع دریافت بسته می‌گیرد.", en: "DevAssist fetches from the package sources again." },
  npmRestart: { fa: "npm چند ثانیه قطع و دوباره وصل می‌شود.", en: "npm pauses for a few seconds and comes back." },
  turnOn: { fa: "بله، روشن کن", en: "Yes, turn on" },
  turnOff: { fa: "بله، وصل کن", en: "Yes, reconnect" },
  offlineOnDone: { fa: "{eco} حالا بدون اینترنت کار می‌کند.", en: "{eco} now works offline." },
  offlineOffDone: { fa: "{eco} دوباره به اینترنت وصل شد.", en: "{eco} is back on the internet." },
  // list
  listTitle: { fa: "همه منابع", en: "All sources" },
  name: { fa: "نام", en: "Name" },
  kind: { fa: "برای", en: "For" },
  address: { fa: "آدرس", en: "Address" },
  order: { fa: "ترتیب", en: "Order" },
  timeout: { fa: "حداکثر زمان انتظار", en: "Timeout" },
  password: { fa: "رمز", en: "Password" },
  hasPassword: { fa: "دارد", en: "Set" },
  noPassword: { fa: "ندارد", en: "None" },
  proxy: { fa: "پروکسی", en: "Proxy" },
  direct: { fa: "مستقیم", en: "Direct" },
  viaDefault: { fa: "پیش‌فرض", en: "Default" },
  state: { fa: "وضعیت", en: "State" },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  blocked: { fa: "مسدود", en: "Blocked" },
  blockedUntil: { fa: "مسدود تا {time}", en: "Blocked until {time}" },
  blockedForever: { fa: "مسدود تا وقتی آزادش کنید", en: "Blocked until you unblock it" },
  empty: { fa: "هنوز منبعی ندارید.", en: "You don't have a source yet." },
  emptyBody: { fa: "بدون منبع، DevAssist نمی‌تواند بسته تازه بگیرد. یک منبع مثل سایت اصلی npm اضافه کنید.", en: "Without a source, DevAssist can't fetch new packages. Add one, such as the official npm site." },
  readOnly: { fa: "نقش شما فقط اجازه دیدن منابع را دارد.", en: "Your role can only view sources." },
  // actions
  test: { fa: "امتحان اتصال", en: "Test connection" },
  history: { fa: "تاریخچه امتحان‌ها", en: "Test history" },
  edit: { fa: "ویرایش", en: "Edit" },
  credential: { fa: "رمز منبع", en: "Source password" },
  block: { fa: "مسدود کردن موقت…", en: "Block for a while…" },
  unblock: { fa: "آزاد کن", en: "Unblock" },
  remove: { fa: "پاک کن", en: "Delete" },
  testOk: { fa: "«{name}» وصل شد.", en: "“{name}” connected." },
  testFail: { fa: "«{name}» وصل نشد.", en: "“{name}” didn't connect." },
  stageFailed: { fa: "در مرحله «{stage}» گیر کرد.", en: "It got stuck at “{stage}”." },
  // wizard
  wizardTitle: { fa: "افزودن منبع دریافت", en: "Add a package source" },
  stepEco: { fa: "برای چه؟", en: "For what?" },
  stepEcoHint: { fa: "این منبع بسته‌های کدام نوع پروژه را می‌دهد؟", en: "Which kind of project's packages does this source provide?" },
  ecoNpm: { fa: "npm (جاوااسکریپت)", en: "npm (JavaScript)" },
  ecoPypi: { fa: "PyPI (پایتون)", en: "PyPI (Python)" },
  stepAddress: { fa: "آدرس", en: "Address" },
  stepAddressHint: { fa: "آدرس کامل منبع را بنویسید و یک نام برایش بگذارید.", en: "Type the source's full address and give it a name." },
  url: { fa: "آدرس منبع", en: "Source address" },
  urlHint: { fa: "مثل https://registry.npmjs.org", en: "Like https://registry.npmjs.org" },
  needUrl: { fa: "آدرس باید با https:// یا http:// شروع شود.", en: "The address must start with https:// or http://." },
  needName: { fa: "نام دست‌کم ۲ نویسه باشد؛ مثلاً «آینه دانشگاه».", en: "The name needs at least 2 characters, like “University mirror”." },
  sourceName: { fa: "نام", en: "Name" },
  stepTest: { fa: "امتحان", en: "Test" },
  stepTestHint: { fa: "پیش از ذخیره، ببینیم DevAssist به این منبع می‌رسد یا نه.", en: "Before saving, let's check that DevAssist can reach this source." },
  runTest: { fa: "امتحان اتصال", en: "Test connection" },
  testOptional: { fa: "اگر الان وصل نشد هم می‌توانید ذخیره کنید؛ بعداً دوباره امتحان می‌شود.", en: "You can save even if it doesn't connect now; it will be retried later." },
  stepMore: { fa: "جزئیات", en: "Details" },
  stepMoreHint: { fa: "این‌ها را معمولاً لازم نیست عوض کنید.", en: "You usually don't need to change these." },
  orderHelp: { fa: "عدد کمتر یعنی زودتر امتحان شود.", en: "A smaller number is tried first." },
  seconds: { fa: "ثانیه", en: "seconds" },
  save: { fa: "ذخیره منبع", en: "Save source" },
  created: { fa: "منبع «{name}» اضافه شد.", en: "The source “{name}” was added." },
  saved: { fa: "تغییرات «{name}» ذخیره شد.", en: "Changes to “{name}” were saved." },
  enabledLabel: { fa: "این منبع روشن باشد", en: "This source is on" },
  editTitle: { fa: "ویرایش «{name}»", en: "Edit “{name}”" },
  saveChanges: { fa: "ذخیره تغییرات", en: "Save changes" },
  // credential
  credentialTitle: { fa: "رمز منبع «{name}»", en: "Password for “{name}”" },
  credentialHint: { fa: "فقط برای منبع‌های خصوصی لازم است.", en: "Only needed for private sources." },
  credentialSet: { fa: "برای این منبع رمز ذخیره شده است.", en: "A password is saved for this source." },
  credentialNone: { fa: "این منبع رمز ندارد.", en: "This source has no password." },
  credentialType: { fa: "نوع ورود", en: "Sign-in type" },
  bearer: { fa: "کلید دسترسی (توکن)", en: "Access key (token)" },
  basic: { fa: "نام کاربری و رمز", en: "Username and password" },
  token: { fa: "کلید دسترسی", en: "Access key" },
  username: { fa: "نام کاربری", en: "Username" },
  passwordField: { fa: "رمز", en: "Password" },
  saveCredential: { fa: "ذخیره رمز", en: "Save password" },
  removeCredential: { fa: "رمز را پاک کن", en: "Remove password" },
  removeCredentialTitle: { fa: "رمز «{name}» پاک شود؟", en: "Remove the password of “{name}”?" },
  removeCredentialBody: { fa: "اگر منبع خصوصی باشد، دریافت بسته از آن متوقف می‌شود.", en: "If the source is private, downloads from it will stop." },
  credentialSaved: { fa: "رمز «{name}» ذخیره شد.", en: "The password for “{name}” was saved." },
  credentialRemoved: { fa: "رمز «{name}» پاک شد.", en: "The password for “{name}” was removed." },
  cancel: { fa: "انصراف", en: "Cancel" },
  // block
  blockTitle: { fa: "«{name}» موقتاً مسدود شود؟", en: "Block “{name}” for a while?" },
  blockBody: { fa: "تا پایان این مدت، DevAssist سراغ این منبع نمی‌رود و از منبع بعدی می‌گیرد.", en: "Until then, DevAssist skips this source and uses the next one." },
  duration: { fa: "تا کی؟", en: "For how long?" },
  oneHour: { fa: "۱ ساعت", en: "1 hour" },
  oneDay: { fa: "۲۴ ساعت", en: "24 hours" },
  oneWeek: { fa: "۷ روز", en: "7 days" },
  indefinite: { fa: "تا وقتی خودم آزادش کنم", en: "Until I unblock it" },
  reason: { fa: "دلیل (دست‌کم ۳ نویسه)", en: "Reason (at least 3 characters)" },
  defaultReason: { fa: "مسدود کردن دستی از پنل", en: "Blocked by hand from the panel" },
  blockYes: { fa: "مسدود کن", en: "Block" },
  blockedDone: { fa: "«{name}» مسدود شد.", en: "“{name}” was blocked." },
  unblockedDone: { fa: "«{name}» آزاد شد.", en: "“{name}” was unblocked." },
  // delete
  removeTitle: { fa: "منبع «{name}» پاک شود؟", en: "Delete the source “{name}”?" },
  removeBody: { fa: "این منبع و رمزش برای همیشه پاک می‌شوند.", en: "This source and its password are deleted for good." },
  removed: { fa: "منبع «{name}» پاک شد.", en: "The source “{name}” was deleted." },
  // history
  historyTitle: { fa: "تاریخچه امتحان «{name}»", en: "Test history of “{name}”" },
  historyEmpty: { fa: "هنوز امتحانی ثبت نشده. «امتحان اتصال» را بزنید.", en: "No test has been recorded yet. Choose “Test connection”." },
  passed: { fa: "وصل شد", en: "Connected" },
  failed: { fa: "وصل نشد", en: "Didn't connect" },
  close: { fa: "بستن", en: "Close" },
  // settings
  settingsTitle: { fa: "همه تنظیمات بسته‌ها", en: "Every package setting" },
  settingsHint: { fa: "تنظیمات مخزن‌های npm و PyPI و نگهداری ذخیره محلی.", en: "Settings for the npm and PyPI registries and local copies upkeep." }
} satisfies Record<string, Bi>;

/** Probe stage keys → plain words. */
const STAGE_WORDS: Record<string, Bi> = {
  dns: { fa: "پیدا کردن آدرس", en: "Finding the address" },
  resolve: { fa: "پیدا کردن آدرس", en: "Finding the address" },
  proxy: { fa: "پروکسی", en: "Proxy" },
  tcp: { fa: "اتصال", en: "Connecting" },
  connect: { fa: "اتصال", en: "Connecting" },
  tls: { fa: "اتصال امن", en: "Secure connection" },
  http: { fa: "پاسخ منبع", en: "Source answer" },
  request: { fa: "پاسخ منبع", en: "Source answer" },
  policy: { fa: "اجازه آدرس", en: "Address allowed" }
};

function stageWord(language: Language, name: string) {
  return STAGE_WORDS[name] ? pick(language, STAGE_WORDS[name]) : name;
}

function probeOutcome(language: Language, stages: ProbeStage[] | undefined, ok: boolean | undefined, total?: number): TestOutcome {
  const list = stages ?? [];
  const failed = list.find((stage) => stage.status !== "ok");
  if ((ok ?? !failed) && !failed) {
    const latency = total ?? list.reduce((sum, stage) => sum + (stage.latency_ms || 0), 0);
    return { state: "ok", latencyMs: latency || null };
  }
  return { state: "fail", message: failed ? say(language, COPY.stageFailed, { stage: stageWord(language, failed.name) }) : undefined };
}

function inRange(value: number | null, range: { min: number; max: number }) {
  return value !== null && Number.isInteger(value) && value >= range.min && value <= range.max;
}

type Props = { permissions: readonly string[] };

export function SourcesTab({ permissions }: Props) {
  const { language, isAdvanced, c } = useKit();
  const canWrite = hasPermission(permissions, "upstream:write");
  const canOperate = hasPermission(permissions, "upstream:operate");
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [items, setItems] = useState<UpstreamRecord[]>([]);
  const [offline, setOffline] = useState({ npm: false, pypi: false });
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [outcomes, setOutcomes] = useState<Record<string, TestOutcome>>({});
  const [wizardOpen, setWizardOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<UpstreamRecord | null>(null);
  const [credentialTarget, setCredentialTarget] = useState<UpstreamRecord | null>(null);
  const [blockTarget, setBlockTarget] = useState<UpstreamRecord | null>(null);
  const [historyTarget, setHistoryTarget] = useState<UpstreamRecord | null>(null);
  const [proxyRefresh, setProxyRefresh] = useState(0);
  const { list: proxyList, failed: proxyFailed } = useProxyList(proxyRefresh);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      const payload = await getJson<{ items: UpstreamRecord[]; offline: { npm: boolean; pypi: boolean } }>("/api/v1/upstreams", current.signal);
      setItems([...payload.items].sort((a, b) => a.priority - b.priority));
      setOffline(payload.offline);
      setLoadError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setLoadError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const now = Math.floor(Date.now() / 1000);
  const isBlocked = (item: UpstreamRecord) => item.blocked_until !== null && item.blocked_until > now;

  const testSource = async (item: UpstreamRecord) => {
    setOutcomes((current) => ({ ...current, [item.id]: { state: "running" } }));
    try {
      const result = await mutateJson<ProbeResult>("/api/v1/upstreams/test", { method: "POST", body: { upstream_id: item.id } });
      setOutcomes((current) => ({ ...current, [item.id]: probeOutcome(language, result.stages, result.ok, result.total_latency_ms) }));
    } catch (caught) {
      setOutcomes((current) => ({ ...current, [item.id]: { state: "fail", error: caught } }));
    }
  };

  const testEcosystem = async (ecosystem: Ecosystem) => {
    for (const item of items.filter((source) => source.ecosystem === ecosystem && source.enabled)) await testSource(item);
  };

  const toggleOffline = async (ecosystem: Ecosystem, value: boolean) => {
    const eco = ECOSYSTEM_NAME[ecosystem];
    const accepted = await ask({
      title: say(language, value ? COPY.offlineOnTitle : COPY.offlineOffTitle, { eco }),
      body: pick(language, value ? COPY.offlineOnBody : COPY.offlineOffBody),
      consequences: ecosystem === "npm" ? [pick(language, COPY.npmRestart)] : undefined,
      undoable: true,
      confirmLabel: pick(language, value ? COPY.turnOn : COPY.turnOff)
    });
    if (!accepted) return;
    setActionError(null);
    try {
      await mutateJson(`/api/v1/ecosystems/${ecosystem}/offline`, { method: "PUT", body: { offline: value } });
      setOffline((current) => ({ ...current, [ecosystem]: value }));
      notify({ message: say(language, value ? COPY.offlineOnDone : COPY.offlineOffDone, { eco }) });
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const unblock = async (item: UpstreamRecord) => {
    setActionError(null);
    try {
      await mutateJson(`/api/v1/upstreams/${encodeURIComponent(item.id)}/unblock`, { method: "POST" });
      notify({ message: say(language, COPY.unblockedDone, { name: item.name }) });
      await load();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const remove = async (item: UpstreamRecord) => {
    const accepted = await ask({
      title: say(language, COPY.removeTitle, { name: item.name }),
      body: pick(language, COPY.removeBody),
      severity: "destructive",
      undoable: false,
      typed: nameConfirmation(item.name, item.name)
    });
    if (!accepted) return;
    setActionError(null);
    try {
      await mutateJson(`/api/v1/upstreams/${encodeURIComponent(item.id)}`, { method: "DELETE", body: { confirmation: item.name } });
      notify({ message: say(language, COPY.removed, { name: item.name }) });
      await load();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const proxyLabel = (item: UpstreamRecord) => {
    if (!item.proxy_id) return pick(language, COPY.direct);
    if (item.proxy_id === "default") return pick(language, COPY.viaDefault);
    return proxyList?.items.find((proxy) => proxy.id === item.proxy_id)?.name ?? item.proxy_id;
  };

  const statePill = (item: UpstreamRecord) => {
    if (isBlocked(item)) return <StatusPill tone="error" label={pick(language, COPY.blocked)} />;
    return <StatusPill tone={item.enabled ? "ok" : "off"} label={pick(language, item.enabled ? COPY.on : COPY.off)} />;
  };

  const ecosystemCard = (ecosystem: Ecosystem) => {
    const sources = items.filter((item) => item.ecosystem === ecosystem);
    const usable = sources.filter((item) => item.enabled && !isBlocked(item));
    const pill = offline[ecosystem]
      ? <StatusPill tone="off" label={pick(language, COPY.offline)} />
      : sources.length === 0
        ? <StatusPill tone="error" label={pick(language, COPY.noSource)} />
        : usable.length === 0
          ? <StatusPill tone="error" label={pick(language, COPY.allBlocked)} />
          : <StatusPill tone="ok" label={pick(language, COPY.ready)} />;
    const running = sources.some((item) => outcomes[item.id]?.state === "running");
    return (
      <SectionCard
        title={ECOSYSTEM_NAME[ecosystem]}
        status={pill}
        hint={sources.length ? say(language, COPY.ecoHint, { n: formatNumber(sources.length, language), names: sources.map((item) => item.name).join("، ") }) : pick(language, COPY.ecoNone)}
      >
        <Stack spacing={1.5}>
          {sources.filter((item) => outcomes[item.id] && outcomes[item.id].state !== "idle").map((item) => (
            <Box key={item.id}>
              <Typography variant="caption" color="text.secondary" dir="auto">{item.name}</Typography>
              <TestResult outcome={outcomes[item.id]} />
            </Box>
          ))}
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }} justifyContent="space-between">
            <Button
              variant="outlined"
              startIcon={running ? <CircularProgress size={16} /> : <NetworkCheckRoundedIcon />}
              disabled={running || usable.length === 0 || !canWrite}
              onClick={() => void testEcosystem(ecosystem)}
              sx={{ minHeight: 44 }}
            >
              {pick(language, COPY.testAll)}
            </Button>
            <Stack direction="row" alignItems="center" spacing={0.5}>
              <FormControlLabel
                control={<Switch checked={offline[ecosystem]} disabled={!canOperate} onChange={(_event, value) => void toggleOffline(ecosystem, value)} />}
                label={pick(language, COPY.offlineLabel)}
                sx={{ mr: 0 }}
              />
              <HelpTip>{pick(language, COPY.offlineHint)}</HelpTip>
            </Stack>
          </Stack>
        </Stack>
      </SectionCard>
    );
  };

  return (
    <Stack spacing={2.5}>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }} justifyContent="space-between">
        <Stack direction="row" spacing={0.5} alignItems="center">
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{pick(language, COPY.intro)}</Typography>
          <HelpTip term="upstream" />
        </Stack>
        <Stack direction="row" spacing={1} sx={{ flexShrink: 0 }}>
          <Button onClick={() => void load()} disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} sx={{ minHeight: 44 }}>{c.refresh}</Button>
          {canWrite && <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setWizardOpen(true)} sx={{ minHeight: 44 }}>{pick(language, COPY.add)}</Button>}
        </Stack>
      </Stack>

      {loadError !== null && <FriendlyError error={loadError} onRetry={() => void load()} />}
      {actionError !== null && <FriendlyError error={actionError} onClose={() => setActionError(null)} />}
      {!canWrite && !canOperate && <NoAccess needs="upstream:operate" />}

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>{ecosystemCard("npm")}</Grid>
        <Grid size={{ xs: 12, md: 6 }}>{ecosystemCard("pypi")}</Grid>
      </Grid>

      <SectionCard title={termWithEnglish(language, "upstream")} hint={pick(language, COPY.listTitle)} flush>
        <ResponsiveList<UpstreamRecord>
          label={pick(language, COPY.listTitle)}
          rows={items}
          rowKey={(row) => row.id}
          columns={[
            { key: "name", header: pick(language, COPY.name), render: (row) => <Box component="span" dir="auto">{row.name}</Box> },
            { key: "eco", header: pick(language, COPY.kind), render: (row) => ECOSYSTEM_NAME[row.ecosystem] ?? row.ecosystem },
            { key: "url", header: pick(language, COPY.address), render: (row) => <Ltr>{row.url}</Ltr>, hideOnCard: true },
            { key: "order", header: pick(language, COPY.order), render: (row) => formatNumber(row.priority, language), advancedOnly: true },
            { key: "timeout", header: pick(language, COPY.timeout), render: (row) => `${formatNumber(row.timeout_seconds, language)} ${pick(language, COPY.seconds)}`, advancedOnly: true },
            { key: "password", header: pick(language, COPY.password), render: (row) => pick(language, row.credential_configured ? COPY.hasPassword : COPY.noPassword), advancedOnly: true },
            { key: "proxy", header: pick(language, COPY.proxy), render: (row) => proxyLabel(row), advancedOnly: true },
            { key: "state", header: pick(language, COPY.state), render: (row) => statePill(row) }
          ]}
          card={{
            title: (row) => <Box component="span" dir="auto">{row.name}</Box>,
            meta: (row) => <>{ECOSYSTEM_NAME[row.ecosystem]} · <Ltr>{row.url}</Ltr></>,
            status: (row) => statePill(row)
          }}
          actions={[
            ...(canWrite ? [{ key: "test", label: pick(language, COPY.test), icon: NetworkCheckRoundedIcon, onClick: (row: UpstreamRecord) => void testSource(row) }] : []),
            { key: "history", label: pick(language, COPY.history), icon: HistoryRoundedIcon, onClick: (row: UpstreamRecord) => setHistoryTarget(row), advancedOnly: true },
            ...(canWrite ? [
              { key: "edit", label: pick(language, COPY.edit), icon: EditRoundedIcon, onClick: (row: UpstreamRecord) => setEditTarget(row), advancedOnly: true },
              { key: "credential", label: pick(language, COPY.credential), icon: KeyRoundedIcon, onClick: (row: UpstreamRecord) => setCredentialTarget(row), advancedOnly: true }
            ] : []),
            ...(canOperate ? [
              { key: "block", label: pick(language, COPY.block), icon: BlockRoundedIcon, onClick: (row: UpstreamRecord) => setBlockTarget(row), hidden: (row: UpstreamRecord) => isBlocked(row), advancedOnly: true },
              { key: "unblock", label: pick(language, COPY.unblock), icon: LockOpenRoundedIcon, onClick: (row: UpstreamRecord) => void unblock(row), hidden: (row: UpstreamRecord) => !isBlocked(row) }
            ] : []),
            ...(canWrite ? [{ key: "delete", label: pick(language, COPY.remove), icon: DeleteOutlineRoundedIcon, onClick: (row: UpstreamRecord) => void remove(row), danger: true, advancedOnly: true }] : [])
          ]}
          empty={
            <EmptyState
              icon={CloudSyncRoundedIcon}
              title={pick(language, COPY.empty)}
              body={pick(language, COPY.emptyBody)}
              action={canWrite ? <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setWizardOpen(true)}>{pick(language, COPY.add)}</Button> : undefined}
            />
          }
        />
        {isAdvanced && items.some(isBlocked) && (
          <Box sx={{ p: 2 }}>
            {items.filter(isBlocked).map((item) => (
              <Typography key={item.id} variant="caption" color="text.secondary" display="block">
                {item.name}: {item.blocked_until !== null && item.blocked_until >= FOREVER ? pick(language, COPY.blockedForever) : say(language, COPY.blockedUntil, { time: "" })}
                {item.blocked_until !== null && item.blocked_until < FOREVER && <RelativeTime value={item.blocked_until} />}
                {item.blocked_reason ? ` · ${item.blocked_reason}` : ""}
              </Typography>
            ))}
          </Box>
        )}
      </SectionCard>

      <RegistrySettings
        groups={["packages.sources", "packages.npm", "packages.pypi"]}
        exclude={["network.allow_private_upstreams"]}
        permissions={permissions}
        title={pick(language, COPY.settingsTitle)}
        hint={pick(language, COPY.settingsHint)}
      />

      {wizardOpen && (
        <SourceWizard
          proxyList={proxyFailed ? null : proxyList}
          onClose={() => setWizardOpen(false)}
          onDone={(message) => {
            setWizardOpen(false);
            setProxyRefresh((value) => value + 1);
            notify({ message });
            void load();
          }}
        />
      )}
      {editTarget && (
        <EditSource
          item={editTarget}
          proxyList={proxyFailed ? null : proxyList}
          onClose={() => setEditTarget(null)}
          onDone={(message) => {
            setEditTarget(null);
            setProxyRefresh((value) => value + 1);
            notify({ message });
            void load();
          }}
        />
      )}
      {credentialTarget && (
        <CredentialDialog
          item={credentialTarget}
          onClose={() => setCredentialTarget(null)}
          onDone={(message) => {
            setCredentialTarget(null);
            notify({ message });
            void load();
          }}
        />
      )}
      {blockTarget && (
        <BlockDialog
          item={blockTarget}
          onClose={() => setBlockTarget(null)}
          onDone={(message) => {
            setBlockTarget(null);
            notify({ message });
            void load();
          }}
        />
      )}
      {historyTarget && <HistoryDialog item={historyTarget} onClose={() => setHistoryTarget(null)} />}
      {dialog}
      {snackbar}
    </Stack>
  );
}

// ── Add a source (wizard) ────────────────────────────────────────────────────

type ProxyListValue = ReturnType<typeof useProxyList>["list"];

function SourceWizard({ proxyList, onClose, onDone }: { proxyList: ProxyListValue; onClose: () => void; onDone: (message: string) => void }) {
  const { language, isAdvanced } = useKit();
  const [ecosystem, setEcosystem] = useState<Ecosystem>("npm");
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [priority, setPriority] = useState<number | null>(30);
  const [timeout, setTimeoutValue] = useState<number | null>(30);
  const [proxy, setProxy] = useState<ProxyChoice>("");
  const [outcome, setOutcome] = useState<TestOutcome>({ state: "idle" });

  const runTest = async () => {
    setOutcome({ state: "running" });
    try {
      const result = await mutateJson<ProbeResult>("/api/v1/upstreams/test", {
        method: "POST",
        body: { url: url.trim(), timeout_seconds: Math.min(Math.max(timeout ?? 30, 1), 30), ...(proxy ? { proxy_id: choiceToApi(proxy) } : {}) }
      });
      setOutcome(probeOutcome(language, result.stages, result.ok, result.total_latency_ms));
    } catch (caught) {
      setOutcome({ state: "fail", error: caught });
    }
  };

  const steps: WizardStep[] = [
    {
      key: "eco",
      title: pick(language, COPY.stepEco),
      hint: pick(language, COPY.stepEcoHint),
      render: () => (
        <ToggleButtonGroup orientation="vertical" fullWidth exclusive value={ecosystem} onChange={(_event, value: Ecosystem | null) => value && setEcosystem(value)} sx={{ "& .MuiToggleButton-root": { minHeight: 56, justifyContent: "flex-start", textTransform: "none", fontWeight: 700 } }}>
          <ToggleButton value="npm">{pick(language, COPY.ecoNpm)}</ToggleButton>
          <ToggleButton value="pypi">{pick(language, COPY.ecoPypi)}</ToggleButton>
        </ToggleButtonGroup>
      )
    },
    {
      key: "address",
      title: pick(language, COPY.stepAddress),
      hint: pick(language, COPY.stepAddressHint),
      validate: () => {
        if (!/^https?:\/\/\S{3,}$/i.test(url.trim())) return pick(language, COPY.needUrl);
        if (name.trim().length < 2) return pick(language, COPY.needName);
        return null;
      },
      render: () => (
        <Stack spacing={2}>
          <TextField fullWidth autoFocus label={pick(language, COPY.url)} helperText={pick(language, COPY.urlHint)} value={url} onChange={(event) => setUrl(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", maxLength: 2048, spellCheck: false, inputMode: "url" } }} />
          <TextField fullWidth label={pick(language, COPY.sourceName)} value={name} onChange={(event) => setName(event.target.value)} slotProps={{ htmlInput: { maxLength: 80, dir: "auto" } }} />
        </Stack>
      )
    },
    {
      key: "test",
      title: pick(language, COPY.stepTest),
      hint: pick(language, COPY.stepTestHint),
      render: () => (
        <Stack spacing={1.5}>
          <Box>
            <Button variant="outlined" startIcon={<NetworkCheckRoundedIcon />} onClick={() => void runTest()} disabled={outcome.state === "running"} sx={{ minHeight: 44 }}>{pick(language, COPY.runTest)}</Button>
          </Box>
          <TestResult outcome={outcome} />
          <Typography variant="caption" color="text.secondary">{pick(language, COPY.testOptional)}</Typography>
        </Stack>
      )
    },
    ...(isAdvanced ? [{
      key: "more",
      title: pick(language, COPY.stepMore),
      hint: pick(language, COPY.stepMoreHint),
      validate: () => (inRange(priority, PRIORITY_RANGE) && inRange(timeout, TIMEOUT_RANGE) ? null : pick(language, COPY.orderHelp)),
      render: () => (
        <Stack spacing={2}>
          <NumberInput label={pick(language, COPY.order)} value={priority} onChange={setPriority} min={PRIORITY_RANGE.min} max={PRIORITY_RANGE.max} integer helperText={pick(language, COPY.orderHelp)} />
          <NumberInput label={pick(language, COPY.timeout)} value={timeout} onChange={setTimeoutValue} min={TIMEOUT_RANGE.min} max={TIMEOUT_RANGE.max} integer unit={pick(language, COPY.seconds)} />
          {proxyList && <ProxyPicker language={language} list={proxyList} value={proxy} onChange={setProxy} supported={supportedTypesFor(ecosystem)} advanced size="medium" />}
        </Stack>
      )
    } satisfies WizardStep] : [])
  ];

  const finish = async () => {
    const body: Record<string, unknown> = { name: name.trim(), ecosystem, url: url.trim(), priority: priority ?? 30, timeout_seconds: timeout ?? 30 };
    if (proxy) body.proxy_id = choiceToApi(proxy);
    await mutateJson("/api/v1/upstreams", { method: "POST", body });
    onDone(say(language, COPY.created, { name: name.trim() }));
  };

  return <ActionWizard open title={pick(language, COPY.wizardTitle)} steps={steps} finishLabel={pick(language, COPY.save)} onFinish={finish} onClose={onClose} />;
}

// ── Edit (Advanced) ──────────────────────────────────────────────────────────

function EditSource({ item, proxyList, onClose, onDone }: { item: UpstreamRecord; proxyList: ProxyListValue; onClose: () => void; onDone: (message: string) => void }) {
  const { language } = useKit();
  const [name, setName] = useState(item.name);
  const [url, setUrl] = useState(item.url);
  const [priority, setPriority] = useState<number | null>(item.priority);
  const [timeout, setTimeoutValue] = useState<number | null>(item.timeout_seconds);
  const [enabled, setEnabled] = useState(item.enabled);
  const [proxy, setProxy] = useState<ProxyChoice>(choiceFromApi(item.proxy_id));

  const save = async () => {
    // Send only what changed: every npm change restarts the npm service.
    const changes: Record<string, unknown> = {};
    if (name.trim() !== item.name) changes.name = name.trim();
    if (url.trim() !== item.url) changes.url = url.trim();
    if (priority !== item.priority) changes.priority = priority;
    if (timeout !== item.timeout_seconds) changes.timeout_seconds = timeout;
    if (enabled !== item.enabled) changes.enabled = enabled;
    if (proxy !== choiceFromApi(item.proxy_id)) changes.proxy_id = choiceToApi(proxy);
    if (Object.keys(changes).length) await mutateJson(`/api/v1/upstreams/${encodeURIComponent(item.id)}`, { method: "PATCH", body: changes });
    onDone(say(language, COPY.saved, { name: name.trim() }));
  };

  return (
    <ActionWizard
      open
      title={say(language, COPY.editTitle, { name: item.name })}
      finishLabel={pick(language, COPY.saveChanges)}
      onFinish={save}
      onClose={onClose}
      steps={[{
        key: "edit",
        title: pick(language, COPY.edit),
        hint: item.ecosystem === "npm" ? pick(language, COPY.npmRestart) : undefined,
        validate: () => {
          if (name.trim().length < 2) return pick(language, COPY.needName);
          if (!/^https?:\/\/\S{3,}$/i.test(url.trim())) return pick(language, COPY.needUrl);
          if (!inRange(priority, PRIORITY_RANGE) || !inRange(timeout, TIMEOUT_RANGE)) return pick(language, COPY.orderHelp);
          return null;
        },
        render: () => (
          <Stack spacing={2}>
            <TextField fullWidth label={pick(language, COPY.sourceName)} value={name} onChange={(event) => setName(event.target.value)} slotProps={{ htmlInput: { maxLength: 80, dir: "auto" } }} />
            <TextField fullWidth label={pick(language, COPY.url)} value={url} onChange={(event) => setUrl(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", maxLength: 2048, spellCheck: false } }} />
            <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
              <NumberInput label={pick(language, COPY.order)} value={priority} onChange={setPriority} min={PRIORITY_RANGE.min} max={PRIORITY_RANGE.max} integer helperText={pick(language, COPY.orderHelp)} />
              <NumberInput label={pick(language, COPY.timeout)} value={timeout} onChange={setTimeoutValue} min={TIMEOUT_RANGE.min} max={TIMEOUT_RANGE.max} integer unit={pick(language, COPY.seconds)} />
            </Stack>
            {proxyList && <ProxyPicker language={language} list={proxyList} value={proxy} onChange={setProxy} supported={supportedTypesFor(item.ecosystem)} advanced size="medium" />}
            <FormControlLabel control={<Switch checked={enabled} onChange={(_event, value) => setEnabled(value)} />} label={pick(language, COPY.enabledLabel)} />
          </Stack>
        )
      }]}
    />
  );
}

// ── Source password (Advanced) ───────────────────────────────────────────────

function CredentialDialog({ item, onClose, onDone }: { item: UpstreamRecord; onClose: () => void; onDone: (message: string) => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const { ask, dialog } = useConfirmAction();
  const [type, setType] = useState<"bearer" | "basic">(item.ecosystem === "npm" ? "bearer" : item.credential_type ?? "bearer");
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const valid = type === "bearer" ? Boolean(token) : Boolean(username && password);

  const save = async () => {
    if (!valid) return;
    setBusy(true);
    setError(null);
    try {
      const body = type === "bearer" ? { credential_type: "bearer", token } : { credential_type: "basic", username, password };
      await mutateJson(`/api/v1/upstreams/${encodeURIComponent(item.id)}/credential`, { method: "PUT", body });
      onDone(say(language, COPY.credentialSaved, { name: item.name }));
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const removeCredential = async () => {
    const accepted = await ask({
      title: say(language, COPY.removeCredentialTitle, { name: item.name }),
      body: pick(language, COPY.removeCredentialBody),
      severity: "destructive",
      undoable: false,
      confirmLabel: pick(language, COPY.removeCredential)
    });
    if (!accepted) return;
    setBusy(true);
    try {
      await mutateJson(`/api/v1/upstreams/${encodeURIComponent(item.id)}/credential`, { method: "DELETE" });
      onDone(say(language, COPY.credentialRemoved, { name: item.name }));
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onClose} fullWidth maxWidth="sm" fullScreen={fullScreen} aria-labelledby="mrk-credential-title">
      <DialogTitle id="mrk-credential-title">{say(language, COPY.credentialTitle, { name: item.name })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <Typography variant="body2" color="text.secondary">{pick(language, COPY.credentialHint)} {pick(language, item.credential_configured ? COPY.credentialSet : COPY.credentialNone)}</Typography>
          <TextField select fullWidth label={pick(language, COPY.credentialType)} value={type} disabled={item.ecosystem === "npm"} onChange={(event) => setType(event.target.value as "bearer" | "basic")}>
            <MenuItem value="bearer">{pick(language, COPY.bearer)}</MenuItem>
            {item.ecosystem !== "npm" && <MenuItem value="basic">{pick(language, COPY.basic)}</MenuItem>}
          </TextField>
          {type === "bearer" ? (
            <TextField fullWidth type="password" autoComplete="new-password" label={pick(language, COPY.token)} value={token} onChange={(event) => setToken(event.target.value)} slotProps={{ htmlInput: { dir: "ltr" } }} />
          ) : (
            <>
              <TextField fullWidth autoComplete="username" label={pick(language, COPY.username)} value={username} onChange={(event) => setUsername(event.target.value)} slotProps={{ htmlInput: { dir: "ltr" } }} />
              <TextField fullWidth type="password" autoComplete="new-password" label={pick(language, COPY.passwordField)} value={password} onChange={(event) => setPassword(event.target.value)} slotProps={{ htmlInput: { dir: "ltr" } }} />
            </>
          )}
          {error !== null && <FriendlyError error={error} noAction />}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2, gap: 1, flexWrap: "wrap" }}>
        {item.credential_configured && <Button color="error" disabled={busy} onClick={() => void removeCredential()}>{pick(language, COPY.removeCredential)}</Button>}
        <Box sx={{ flex: 1 }} />
        <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, COPY.cancel)}</Button>
        <Button variant="contained" disabled={!valid || busy} onClick={() => void save()} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
          {pick(language, COPY.saveCredential)}
        </Button>
      </DialogActions>
      {dialog}
    </Dialog>
  );
}

// ── Block for a while (Advanced) ─────────────────────────────────────────────

function BlockDialog({ item, onClose, onDone }: { item: UpstreamRecord; onClose: () => void; onDone: (message: string) => void }) {
  const { language } = useKit();
  const [duration, setDuration] = useState<number | "forever">(3600);
  const [reason, setReason] = useState(pick(language, COPY.defaultReason));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await mutateJson(`/api/v1/upstreams/${encodeURIComponent(item.id)}/block`, {
        method: "POST",
        body: { reason: reason.trim(), duration_seconds: duration === "forever" ? null : duration }
      });
      onDone(say(language, COPY.blockedDone, { name: item.name }));
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <ConfirmAction
      open
      title={say(language, COPY.blockTitle, { name: item.name })}
      body={pick(language, COPY.blockBody)}
      consequences={item.ecosystem === "npm" ? [pick(language, COPY.npmRestart)] : undefined}
      undoable
      confirmLabel={pick(language, COPY.blockYes)}
      busy={busy}
      error={error}
      confirmDisabled={reason.trim().length < 3}
      onConfirm={() => void submit()}
      onClose={onClose}
    >
      <TextField select fullWidth label={pick(language, COPY.duration)} value={duration} onChange={(event) => setDuration(event.target.value === "forever" ? "forever" : Number(event.target.value))}>
        <MenuItem value={3600}>{pick(language, COPY.oneHour)}</MenuItem>
        <MenuItem value={86400}>{pick(language, COPY.oneDay)}</MenuItem>
        <MenuItem value={604800}>{pick(language, COPY.oneWeek)}</MenuItem>
        <MenuItem value="forever">{pick(language, COPY.indefinite)}</MenuItem>
      </TextField>
      <TextField fullWidth required label={pick(language, COPY.reason)} value={reason} onChange={(event) => setReason(event.target.value)} slotProps={{ htmlInput: { minLength: 3, maxLength: 256, dir: "auto" } }} />
    </ConfirmAction>
  );
}

// ── Health history (Advanced) ────────────────────────────────────────────────

function HistoryDialog({ item, onClose }: { item: UpstreamRecord; onClose: () => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [checks, setChecks] = useState<HealthCheck[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    void (async () => {
      try {
        const payload = await getJson<{ items: HealthCheck[] }>(`/api/v1/upstreams/${encodeURIComponent(item.id)}/health?limit=20`);
        setChecks(payload.items);
      } catch (caught) {
        setError(caught);
      }
    })();
  }, [item.id]);

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm" fullScreen={fullScreen} aria-labelledby="mrk-history-title">
      <DialogTitle id="mrk-history-title">{say(language, COPY.historyTitle, { name: item.name })}</DialogTitle>
      <DialogContent>
        {error !== null && <FriendlyError error={error} noAction />}
        {checks === null && error === null && <CircularProgress size={20} />}
        {checks && checks.length === 0 && <Notice>{pick(language, COPY.historyEmpty)}</Notice>}
        <Stack spacing={1.5}>
          {checks?.map((check) => (
            <Box key={check.id} sx={{ pb: 1.25, borderBottom: 1, borderColor: "divider" }}>
              <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={1}>
                <StatusPill tone={check.ok ? "ok" : "error"} label={pick(language, check.ok ? COPY.passed : COPY.failed)} />
                <Typography variant="caption" color="text.secondary"><RelativeTime value={check.checked_at} /></Typography>
              </Stack>
              <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 1 }}>
                {check.stages.map((stage) => (
                  <Typography key={`${check.id}-${stage.name}`} variant="caption" sx={{ px: 1, py: 0.25, borderRadius: 1, border: 1, borderColor: stage.status === "ok" ? "success.main" : "error.main" }}>
                    {stageWord(language, stage.name)} · {formatMs(stage.latency_ms, language)}
                    {stage.detail ? <> · <Ltr>{stage.detail}</Ltr></> : null}
                  </Typography>
                ))}
              </Stack>
            </Box>
          ))}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ minHeight: 44 }}>{pick(language, COPY.close)}</Button>
      </DialogActions>
    </Dialog>
  );
}

/** Legacy entry point (old `#upstreams` page); the shell now mounts PackagesPage. */
export function UpstreamsPanel({ permissions }: { language?: Language; permissions: string[]; onUnauthorized?: () => void }) {
  return <SourcesTab permissions={permissions} />;
}
