import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Box, Button, Checkbox, CircularProgress, Divider, FormControlLabel, Grid, LinearProgress, MenuItem, Stack, Switch, TextField,
  ToggleButton, ToggleButtonGroup, Typography
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import NetworkCheckRoundedIcon from "@mui/icons-material/NetworkCheckRounded";
import StarRoundedIcon from "@mui/icons-material/StarRounded";
import StarBorderRoundedIcon from "@mui/icons-material/StarBorderRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import VpnLockRoundedIcon from "@mui/icons-material/VpnLockRounded";
import { ApiError, apiMutate, getJson, hasPermission, isAbortError, mutateJson, toApiError } from "./api";
import { nameConfirmation, outboundKindWord, pick, PROXY_TYPE_WORDS, say, type Bi } from "./copy";
import {
  ActionWizard, EmptyState, FriendlyError, HelpTip, ListInput, Ltr, NoAccess, Notice, RelativeTime, ResponsiveList, SectionCard,
  StatusPill, TestResult, useConfirmAction, useKit, useUndoSnackbar, RegistrySettings, type TestOutcome, type WizardStep
} from "./kit";
import { DnsSettingsCard } from "./DnsSettingsCard";
import { UpstreamPolicyCard } from "./UpstreamPolicyCard";
import { formatNumber } from "./format";
import type { Language } from "./i18n";
import { PROXY_TYPES, PROXY_TYPE_SHORT, ProxyPicker, choiceFromApi, choiceToApi, type ProxyList, type ProxyRecord, type ProxyType, type ProxyUsage } from "./ProxyControls";

/**
 * Security & internet › «اینترنت و پروکسی» and «DNS و شبکه داخلی» (docs/33 §1.1, §4.2).
 * Simple: proxy list, «افزودن پروکسی» wizard (presets), one switch per service.
 * Advanced: a specific proxy per service, no-proxy lists, test address, default, edit, delete.
 */

type ServiceGroup = "npm" | "pypi" | "telegram" | "bale" | "email" | "webhook" | string;
type OutboundService = { kind: string; id: string; name: string; group: ServiceGroup; proxy_id: string | null; supported_proxy_types: ProxyType[] };
type ProxyTest = { ok: boolean; status_code?: number | null; latency_ms: number; error_code?: string | null };

const BASE = "/api/v1/settings/proxies";
const SERVICES = "/api/v1/settings/outbound-services";
const GROUP_ORDER = ["npm", "pypi", "telegram", "bale", "email", "webhook"];
const DEFAULT_TEST_URL = "https://api.telegram.org";

const COPY = {
  proxies: { fa: "پروکسی‌ها", en: "Proxies" },
  proxiesHint: { fa: "اگر اینترنت سرور محدود است، یک پروکسی بسازید و برای هر سرویس روشنش کنید.", en: "If the server's internet is limited, add a proxy and turn it on per service." },
  add: { fa: "افزودن پروکسی", en: "Add a proxy" },
  empty: { fa: "هنوز پروکسی ندارید.", en: "You don't have a proxy yet." },
  emptyBody: { fa: "با یک پروکسی، سرور می‌تواند حتی با اینترنت محدود بسته بگیرد و پیام بفرستد.", en: "With a proxy, the server can fetch packages and send messages even on limited internet." },
  name: { fa: "نام", en: "Name" },
  address: { fa: "آدرس", en: "Address" },
  type: { fa: "نوع", en: "Type" },
  state: { fa: "وضعیت", en: "State" },
  usage: { fa: "استفاده", en: "Used by" },
  updated: { fa: "آخرین تغییر", en: "Last change" },
  usedBy: { fa: "{n} سرویس", en: "{n} services" },
  notUsed: { fa: "هنوز هیچ سرویسی", en: "No service yet" },
  isDefault: { fa: "پیش‌فرض", en: "Default" },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  test: { fa: "امتحان اتصال", en: "Test connection" },
  testOf: { fa: "امتحان «{name}»", en: "Testing “{name}”" },
  setDefault: { fa: "پیش‌فرض کن", en: "Make default" },
  clearDefault: { fa: "دیگر پیش‌فرض نباشد", en: "Stop being default" },
  defaultSet: { fa: "«{name}» پروکسی پیش‌فرض شد.", en: "“{name}” is now the default proxy." },
  defaultCleared: { fa: "دیگر پروکسی پیش‌فرضی ندارید.", en: "You no longer have a default proxy." },
  edit: { fa: "ویرایش", en: "Edit" },
  remove: { fa: "پاک کن", en: "Delete" },
  removeTitle: { fa: "پروکسی «{name}» پاک شود؟", en: "Delete the proxy “{name}”?" },
  removeBody: { fa: "این پروکسی برای همیشه پاک می‌شود.", en: "This proxy is deleted for good." },
  removed: { fa: "پروکسی «{name}» پاک شد.", en: "The proxy “{name}” was deleted." },
  inUse: { fa: "این سرویس‌ها هنوز از آن استفاده می‌کنند؛ اول آن‌ها را به پروکسی دیگری ببرید:", en: "These services still use it; move them to another proxy first:" },
  viaDefault: { fa: "از راه پیش‌فرض", en: "via the default" },
  listLabel: { fa: "فهرست پروکسی‌ها", en: "Proxy list" },
  readOnly: { fa: "نقش شما فقط اجازه دیدن دارد.", en: "Your role can only view this." },
  unavailable: { fa: "مدیریت پروکسی روی نسخه فعلی سرور نیست. DevAssist را به‌روز کنید.", en: "Proxy management isn't on this server version. Update DevAssist." },
  // services
  services: { fa: "کدام سرویس از پروکسی رد شود؟", en: "Which services go through a proxy?" },
  servicesHint: { fa: "روشن کردن کلید یعنی این سرویس از پروکسی پیش‌فرض استفاده کند.", en: "Switching on means this service uses the default proxy." },
  servicesHintAdvanced: { fa: "برای هر سرویس می‌توانید یک پروکسی مشخص هم انتخاب کنید.", en: "You can also pick a specific proxy for each service." },
  noServices: { fa: "هنوز سرویسی که به اینترنت وصل شود ندارید.", en: "No service talks to the internet yet." },
  serviceSaved: { fa: "تنظیم پروکسی «{name}» ذخیره شد.", en: "Proxy setting for “{name}” saved." },
  supported: { fa: "انواع مناسب: {types}", en: "Suitable types: {types}" },
  groupTelegram: { fa: "تلگرام", en: "Telegram" },
  groupBale: { fa: "بله", en: "Bale" },
  groupEmail: { fa: "ایمیل", en: "Email" },
  groupWebhook: { fa: "وب‌هوک", en: "Webhook" },
  groupOther: { fa: "سرویس‌های دیگر", en: "Other services" },
  // wizard
  wizardTitle: { fa: "افزودن پروکسی", en: "Add a proxy" },
  editTitle: { fa: "ویرایش پروکسی «{name}»", en: "Edit the proxy “{name}”" },
  stepKind: { fa: "چه پروکسی‌ای؟", en: "Which kind?" },
  stepKindHint: { fa: "یکی را انتخاب کنید؛ بعداً می‌شود عوضش کرد.", en: "Pick one; you can change it later." },
  presetTunnel: { fa: "تونل روی همین سرور", en: "A tunnel on this server" },
  presetTunnelHint: { fa: "برنامه‌ای مثل یک تونل امن که روی سرور اجرا می‌شود (SOCKS5h، پورت ۱۰۸۰).", en: "A tunnel app running on the server (SOCKS5h, port 1080)." },
  presetHttp: { fa: "پروکسی HTTP", en: "An HTTP proxy" },
  presetHttpHint: { fa: "پروکسی معمولی که آدرس و پورتش را دارید (پورت رایج ۳۱۲۸).", en: "A regular proxy you have an address and port for (usually 3128)." },
  presetCustom: { fa: "تنظیم دستی", en: "Set it up myself" },
  presetCustomHint: { fa: "نوع، آدرس و پورت را خودتان بنویسید.", en: "Type the kind, address and port yourself." },
  stepAddress: { fa: "آدرس", en: "Address" },
  stepAddressHint: { fa: "پروکسی کجاست؟", en: "Where is the proxy?" },
  host: { fa: "آدرس پروکسی", en: "Proxy address" },
  hostHint: { fa: "فقط نام یا IP، بدون http://", en: "Only the name or IP, without http://" },
  hostHelp: {
    fa: "اگر تونل روی خود سرور (بیرون از کانتینر DevAssist) اجرا می‌شود، به جای 127.0.0.1 بنویسید host.docker.internal یا IP سرور.",
    en: "If the tunnel runs on the server itself (outside the DevAssist container), use host.docker.internal or the server's IP instead of 127.0.0.1."
  },
  port: { fa: "پورت", en: "Port" },
  stepLogin: { fa: "ورود", en: "Sign-in" },
  stepLoginHint: { fa: "اگر پروکسی نام کاربری و رمز می‌خواهد بنویسید؛ وگرنه از این قدم بگذرید.", en: "If the proxy needs a username and password, type them; otherwise skip this step." },
  username: { fa: "نام کاربری", en: "Username" },
  password: { fa: "رمز", en: "Password" },
  passwordKeep: { fa: "رمز ذخیره شده؛ برای نگه داشتن، خالی بگذارید.", en: "A password is saved; leave empty to keep it." },
  clearPassword: { fa: "رمز ذخیره‌شده پاک شود", en: "Remove the saved password" },
  stepFinish: { fa: "ذخیره", en: "Save" },
  stepFinishHint: { fa: "بعد از ذخیره، اتصال پروکسی خودکار امتحان می‌شود.", en: "After saving, the proxy is tested automatically." },
  makeDefault: { fa: "این پروکسی پیش‌فرض باشد", en: "Make this the default proxy" },
  enabled: { fa: "روشن باشد", en: "Turned on" },
  noProxy: { fa: "بدون پروکسی برای این آدرس‌ها", en: "Skip the proxy for these addresses" },
  noProxyHelp: { fa: "مثل «localhost» یا 10.0.0.0/8؛ هر کدام را بنویسید و Enter بزنید.", en: "Like localhost or 10.0.0.0/8; type each and press Enter." },
  testUrl: { fa: "آدرس امتحان", en: "Test address" },
  save: { fa: "ذخیره پروکسی", en: "Save proxy" },
  created: { fa: "پروکسی «{name}» اضافه شد.", en: "The proxy “{name}” was added." },
  saved: { fa: "تغییرات «{name}» ذخیره شد.", en: "Changes to “{name}” were saved." },
  needName: { fa: "یک نام بنویسید؛ مثلاً «تونل دفتر».", en: "Type a name, for example “Office tunnel”." },
  needHost: { fa: "آدرس پروکسی را بنویسید.", en: "Type the proxy address." },
  badHost: { fa: "فقط نام یا IP بنویسید، بدون http:// و فاصله.", en: "Write only the name or IP, without http:// or spaces." },
  badPort: { fa: "پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد.", en: "The port must be a number from 1 to 65535." },
  passwordNeedsUser: { fa: "برای رمز، نام کاربری هم لازم است.", en: "A password needs a username too." },
  nameExample: { fa: "مثلاً «تونل دفتر»", en: "For example “Office tunnel”" },
  testAfterSave: { fa: "نتیجه امتحان اتصال:", en: "Connection test result:" },
  // test failures
  fail_destination_not_allowed: { fa: "این آدرس امتحان مجاز نیست.", en: "This test address isn't allowed." },
  fail_proxy_error: { fa: "پروکسی خطا داد؛ نام کاربری، رمز یا تنظیمش را بررسی کنید.", en: "The proxy returned an error; check its username, password or settings." },
  fail_connect_failed: { fa: "به پروکسی وصل نشدیم؛ آدرس و پورت را بررسی کنید.", en: "We couldn't reach the proxy; check the address and port." },
  fail_timeout: { fa: "پروکسی دیر جواب داد.", en: "The proxy took too long to answer." },
  fail_tls_error: { fa: "اتصال امن برقرار نشد.", en: "A secure connection couldn't be made." },
  fail_http_5xx: { fa: "مقصد مشکل داشت؛ کمی بعد دوباره امتحان کنید.", en: "The destination had a problem; try again a bit later." },
  fail_dns_failed: { fa: "آدرس پیدا نشد.", en: "The address couldn't be found." },
  // dns tab
  dnsMore: { fa: "تنظیمات بیشتر شبکه", en: "More network settings" },
  dnsMoreHint: { fa: "همه تنظیمات شبکه که این‌جا تغییر می‌کنند.", en: "Every network setting that can be changed here." }
} satisfies Record<string, Bi>;

type ProxyForm = { name: string; type: ProxyType; host: string; port: string; username: string; password: string; clearPassword: boolean; enabled: boolean; noProxy: string[]; makeDefault: boolean };

function emptyForm(makeDefault: boolean): ProxyForm {
  return { name: "", type: "socks5h", host: "127.0.0.1", port: "1080", username: "", password: "", clearPassword: false, enabled: true, noProxy: [], makeDefault };
}

function formFromProxy(proxy: ProxyRecord): ProxyForm {
  return { name: proxy.name, type: proxy.type, host: proxy.host, port: String(proxy.port), username: proxy.username ?? "", password: "", clearPassword: false, enabled: proxy.enabled, noProxy: proxy.no_proxy ?? [], makeDefault: proxy.is_default };
}

/** apiMutate that keeps `error.used_by` from a proxy_in_use 409. */
async function mutateProxy<T>(path: string, method: "POST" | "PUT" | "PATCH" | "DELETE", body?: unknown): Promise<T> {
  const response = await apiMutate(path, { method, body });
  if (!response.ok) {
    let usedBy: ProxyUsage[] = [];
    try {
      const payload = (await response.clone().json()) as { error?: { used_by?: ProxyUsage[] }; used_by?: ProxyUsage[] };
      usedBy = payload.error?.used_by ?? payload.used_by ?? [];
    } catch {
      // non-JSON body
    }
    throw Object.assign(await toApiError(response), { usedBy });
  }
  if (response.status === 204) return null as T;
  const text = await response.text();
  return (text ? JSON.parse(text) : null) as T;
}

function usedByOf(error: unknown): ProxyUsage[] {
  const list = (error as { usedBy?: unknown } | null)?.usedBy;
  return Array.isArray(list) ? (list as ProxyUsage[]) : [];
}

function testOutcome(result: ProxyTest, language: Language): TestOutcome {
  if (result.ok) return { state: "ok", latencyMs: result.latency_ms };
  const key = `fail_${result.error_code ?? ""}` as keyof typeof COPY;
  return { state: "fail", code: result.error_code ?? null, message: key in COPY ? pick(language, COPY[key]) : undefined };
}

function groupLabel(group: string, language: Language) {
  if (group === "npm") return "npm";
  if (group === "pypi") return "PyPI";
  if (group === "telegram") return pick(language, COPY.groupTelegram);
  if (group === "bale") return pick(language, COPY.groupBale);
  if (group === "email") return pick(language, COPY.groupEmail);
  if (group === "webhook") return pick(language, COPY.groupWebhook);
  return pick(language, COPY.groupOther);
}

// ── Proxy wizard (add + edit) ────────────────────────────────────────────────

type Preset = "tunnel" | "http" | "custom";

function ProxyWizard({ editing, defaultExists, onClose, onDone }: { editing: ProxyRecord | null; defaultExists: boolean; onClose: () => void; onDone: (message: string) => void }) {
  const { language, isAdvanced } = useKit();
  const [form, setForm] = useState<ProxyForm>(() => (editing ? formFromProxy(editing) : emptyForm(!defaultExists)));
  const [preset, setPreset] = useState<Preset>("tunnel");
  const [testUrl, setTestUrl] = useState(DEFAULT_TEST_URL);
  const [outcome, setOutcome] = useState<TestOutcome>({ state: "idle" });
  const [doneMessage, setDoneMessage] = useState("");
  const patch = (next: Partial<ProxyForm>) => setForm((current) => ({ ...current, ...next }));
  const stored = Boolean(editing?.secret_configured);

  const choosePreset = (value: Preset) => {
    setPreset(value);
    if (value === "tunnel") patch({ type: "socks5h", host: form.host || "127.0.0.1", port: "1080" });
    if (value === "http") patch({ type: "http", port: "3128" });
  };

  const addressProblem = () => {
    if (!form.name.trim()) return pick(language, COPY.needName);
    const host = form.host.trim();
    if (!host) return pick(language, COPY.needHost);
    if (/[\s/]|:\/\//.test(host)) return pick(language, COPY.badHost);
    const port = Number(form.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return pick(language, COPY.badPort);
    return null;
  };
  const loginProblem = () => {
    const willHavePassword = Boolean(form.password) || (stored && !form.clearPassword);
    return willHavePassword && !form.username.trim() ? pick(language, COPY.passwordNeedsUser) : null;
  };

  const save = async () => {
    const port = Number(form.port);
    let id = editing?.id ?? null;
    if (editing) {
      const changes: Record<string, unknown> = {};
      if (form.name.trim() !== editing.name) changes.name = form.name.trim();
      if (form.type !== editing.type) changes.type = form.type;
      if (form.host.trim() !== editing.host) changes.host = form.host.trim();
      if (port !== editing.port) changes.port = port;
      if (form.username.trim() !== (editing.username ?? "")) changes.username = form.username.trim() || null;
      if (form.clearPassword) changes.password = "";
      else if (form.password) changes.password = form.password;
      if (form.enabled !== editing.enabled) changes.enabled = form.enabled;
      if (form.noProxy.join("\n") !== (editing.no_proxy ?? []).join("\n")) changes.no_proxy = form.noProxy;
      if (Object.keys(changes).length) await mutateProxy(`${BASE}/${encodeURIComponent(editing.id)}`, "PATCH", changes);
      setDoneMessage(say(language, COPY.saved, { name: form.name.trim() }));
    } else {
      const body: Record<string, unknown> = { name: form.name.trim(), type: form.type, host: form.host.trim(), port, enabled: form.enabled, no_proxy: form.noProxy };
      if (form.username.trim()) body.username = form.username.trim();
      if (form.password) body.password = form.password;
      const created = await mutateProxy<ProxyRecord | null>(BASE, "POST", body);
      id = created?.id ?? null;
      if (form.makeDefault && id) await mutateProxy(`${BASE}/default`, "PUT", { proxy_id: id });
      setDoneMessage(say(language, COPY.created, { name: form.name.trim() }));
    }
    if (id) {
      setOutcome({ state: "running" });
      try {
        const url = isAdvanced && testUrl.trim() && testUrl.trim() !== DEFAULT_TEST_URL ? testUrl.trim() : undefined;
        const result = await mutateJson<ProxyTest>(`${BASE}/${encodeURIComponent(id)}/test`, { method: "POST", body: url ? { url } : {} });
        setOutcome(testOutcome(result, language));
      } catch (caught) {
        setOutcome({ state: "fail", error: caught });
      }
    }
  };

  const presetButton = (value: Preset, title: Bi, hint: Bi) => (
    <ToggleButton value={value} sx={{ justifyContent: "flex-start", textAlign: "start", textTransform: "none", py: 1.5, px: 2, minHeight: 64 }}>
      <Box>
        <Typography fontWeight={720}>{pick(language, title)}</Typography>
        <Typography variant="body2" color="text.secondary">{pick(language, hint)}</Typography>
      </Box>
    </ToggleButton>
  );

  const addressStep: WizardStep = {
    key: "address",
    title: pick(language, COPY.stepAddress),
    hint: pick(language, COPY.stepAddressHint),
    validate: addressProblem,
    render: () => (
      <Grid container spacing={1.5}>
        <Grid size={12}>
          <TextField fullWidth label={pick(language, COPY.name)} placeholder={pick(language, COPY.nameExample)} value={form.name} onChange={(event) => patch({ name: event.target.value })} slotProps={{ htmlInput: { maxLength: 64, dir: "auto" } }} />
        </Grid>
        {(preset === "custom" || editing) && (
          <Grid size={12}>
            <TextField select fullWidth label={pick(language, COPY.type)} value={form.type} onChange={(event) => patch({ type: event.target.value as ProxyType })}>
              {PROXY_TYPES.map((type) => <MenuItem key={type} value={type}>{pick(language, PROXY_TYPE_WORDS[type])}</MenuItem>)}
            </TextField>
          </Grid>
        )}
        <Grid size={{ xs: 8, sm: 9 }}>
          <Stack direction="row" spacing={0.5} alignItems="flex-start">
            <TextField fullWidth label={pick(language, COPY.host)} helperText={pick(language, COPY.hostHint)} value={form.host} onChange={(event) => patch({ host: event.target.value })} slotProps={{ htmlInput: { dir: "ltr", autoComplete: "off", spellCheck: false } }} />
            <Box sx={{ pt: 1 }}><HelpTip>{pick(language, COPY.hostHelp)}</HelpTip></Box>
          </Stack>
        </Grid>
        <Grid size={{ xs: 4, sm: 3 }}>
          <TextField fullWidth label={pick(language, COPY.port)} value={form.port} onChange={(event) => patch({ port: event.target.value.replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit))) })} slotProps={{ htmlInput: { dir: "ltr", inputMode: "numeric" } }} />
        </Grid>
      </Grid>
    )
  };

  const loginStep: WizardStep = {
    key: "login",
    title: pick(language, COPY.stepLogin),
    hint: pick(language, COPY.stepLoginHint),
    optional: true,
    validate: loginProblem,
    render: () => (
      <Stack spacing={1.5}>
        <TextField fullWidth label={pick(language, COPY.username)} value={form.username} onChange={(event) => patch({ username: event.target.value })} slotProps={{ htmlInput: { dir: "ltr", autoComplete: "off" } }} />
        <TextField
          fullWidth
          type="password"
          label={pick(language, COPY.password)}
          value={form.password}
          disabled={form.clearPassword}
          helperText={stored ? pick(language, COPY.passwordKeep) : " "}
          onChange={(event) => patch({ password: event.target.value })}
          slotProps={{ htmlInput: { dir: "ltr", autoComplete: "new-password" } }}
        />
        {stored && <FormControlLabel control={<Checkbox checked={form.clearPassword} onChange={(event) => patch({ clearPassword: event.target.checked, password: "" })} />} label={pick(language, COPY.clearPassword)} />}
      </Stack>
    )
  };

  const finishStep: WizardStep = {
    key: "finish",
    title: pick(language, COPY.stepFinish),
    hint: pick(language, COPY.stepFinishHint),
    render: () => (
      <Stack spacing={1.5}>
        {!editing && <FormControlLabel control={<Checkbox checked={form.makeDefault} onChange={(event) => patch({ makeDefault: event.target.checked })} />} label={pick(language, COPY.makeDefault)} />}
        {isAdvanced && (
          <>
            <FormControlLabel control={<Switch checked={form.enabled} onChange={(event) => patch({ enabled: event.target.checked })} />} label={pick(language, COPY.enabled)} />
            <ListInput label={pick(language, COPY.noProxy)} value={form.noProxy} onChange={(value) => patch({ noProxy: value })} max={32} helperText={pick(language, COPY.noProxyHelp)} />
            <TextField fullWidth size="small" label={pick(language, COPY.testUrl)} value={testUrl} onChange={(event) => setTestUrl(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
          </>
        )}
      </Stack>
    )
  };

  const steps: WizardStep[] = editing
    ? [addressStep, loginStep, finishStep]
    : [
        {
          key: "kind",
          title: pick(language, COPY.stepKind),
          hint: pick(language, COPY.stepKindHint),
          render: () => (
            <ToggleButtonGroup orientation="vertical" exclusive fullWidth value={preset} onChange={(_event, value: Preset | null) => value && choosePreset(value)}>
              {presetButton("tunnel", COPY.presetTunnel, COPY.presetTunnelHint)}
              {presetButton("http", COPY.presetHttp, COPY.presetHttpHint)}
              {presetButton("custom", COPY.presetCustom, COPY.presetCustomHint)}
            </ToggleButtonGroup>
          )
        },
        addressStep,
        loginStep,
        finishStep
      ];

  return (
    <ActionWizard
      open
      title={editing ? say(language, COPY.editTitle, { name: editing.name }) : pick(language, COPY.wizardTitle)}
      steps={steps}
      finishLabel={pick(language, COPY.save)}
      onFinish={save}
      onClose={() => (doneMessage ? onDone(doneMessage) : onClose())}
      done={
        <Stack spacing={1.5}>
          <Notice tone="success">{doneMessage}</Notice>
          <Typography variant="body2" color="text.secondary">{pick(language, COPY.testAfterSave)}</Typography>
          <TestResult outcome={outcome} />
        </Stack>
      }
    />
  );
}

// ── Internet & proxy tab ─────────────────────────────────────────────────────

export type SecurityTabProps = { permissions: readonly string[] };

export function InternetTab({ permissions }: SecurityTabProps) {
  const { language, isAdvanced, c } = useKit();
  const canWrite = hasPermission(permissions, "upstream:write");
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [list, setList] = useState<ProxyList | null>(null);
  const [services, setServices] = useState<OutboundService[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [wizard, setWizard] = useState<{ editing: ProxyRecord | null } | null>(null);
  const [testing, setTesting] = useState<{ proxy: ProxyRecord; outcome: TestOutcome } | null>(null);
  const [serviceBusy, setServiceBusy] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async (background = false) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    if (!background) setLoading(true);
    try {
      const [proxies, outbound] = await Promise.all([
        getJson<ProxyList>(BASE, current.signal),
        getJson<{ items: OutboundService[]; default_proxy_id: string | null }>(SERVICES, current.signal)
      ]);
      setList(proxies);
      setServices(outbound.items ?? []);
      setUnavailable(false);
      setLoadError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      if (caught instanceof ApiError && caught.status === 404) setUnavailable(true);
      else setLoadError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const test = async (proxy: ProxyRecord) => {
    setTesting({ proxy, outcome: { state: "running" } });
    try {
      const result = await mutateJson<ProxyTest>(`${BASE}/${encodeURIComponent(proxy.id)}/test`, { method: "POST", body: {} });
      setTesting({ proxy, outcome: testOutcome(result, language) });
    } catch (caught) {
      setTesting({ proxy, outcome: { state: "fail", error: caught } });
    }
  };

  const setDefault = async (proxy: ProxyRecord, makeDefault: boolean) => {
    setActionError(null);
    try {
      await mutateProxy(`${BASE}/default`, "PUT", { proxy_id: makeDefault ? proxy.id : null });
      notify({ message: makeDefault ? say(language, COPY.defaultSet, { name: proxy.name }) : pick(language, COPY.defaultCleared) });
      await load(true);
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const remove = async (proxy: ProxyRecord) => {
    const accepted = await ask({
      title: say(language, COPY.removeTitle, { name: proxy.name }),
      body: pick(language, COPY.removeBody),
      severity: "destructive",
      undoable: false,
      typed: nameConfirmation(proxy.name, proxy.name),
      consequences: proxy.used_by.length ? proxy.used_by.map((item) => `${item.name} · ${outboundKindWord(language, item.kind)}`) : undefined
    });
    if (!accepted) return;
    setActionError(null);
    try {
      await mutateProxy(`${BASE}/${encodeURIComponent(proxy.id)}`, "DELETE", { confirmation: proxy.name });
      notify({ message: say(language, COPY.removed, { name: proxy.name }) });
      await load(true);
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const changeService = async (service: OutboundService, value: string) => {
    const key = `${service.kind}:${service.id}`;
    setServiceBusy(key);
    setActionError(null);
    try {
      const updated = await mutateJson<OutboundService | null>(`${SERVICES}/${encodeURIComponent(service.kind)}/${encodeURIComponent(service.id)}`, { method: "PUT", body: { proxy_id: choiceToApi(value) } });
      const entry = updated ?? { ...service, proxy_id: choiceToApi(value) };
      setServices((current) => (current ?? []).map((item) => (item.kind === entry.kind && item.id === entry.id ? { ...item, ...entry } : item)));
      notify({ message: say(language, COPY.serviceSaved, { name: service.name }) });
      void load(true);
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    } finally {
      setServiceBusy(null);
    }
  };

  const grouped = useMemo(() => {
    const result = new Map<string, OutboundService[]>();
    for (const service of services ?? []) {
      const group = GROUP_ORDER.includes(service.group) ? service.group : "other";
      result.set(group, [...(result.get(group) ?? []), service]);
    }
    return [...GROUP_ORDER, "other"].filter((group) => result.has(group)).map((group) => [group, result.get(group)!] as const);
  }, [services]);

  const proxies = list?.items ?? [];
  const actionUsage = usedByOf(actionError);

  if (unavailable) return <Notice>{pick(language, COPY.unavailable)}</Notice>;

  return (
    <Stack spacing={2.5}>
      {loadError !== null && <FriendlyError error={loadError} onRetry={() => void load()} />}
      {actionError !== null && (
        <Box>
          <FriendlyError error={actionError} onClose={() => setActionError(null)} />
          {actionUsage.length > 0 && (
            <Notice tone="warning">
              {pick(language, COPY.inUse)}{" "}
              {actionUsage.map((item) => `${item.name} (${outboundKindWord(language, item.kind)}${item.via_default ? ` · ${pick(language, COPY.viaDefault)}` : ""})`).join("، ")}
            </Notice>
          )}
        </Box>
      )}
      {!canWrite && <NoAccess needs="upstream:write" />}
      {loading && !list && <LinearProgress />}

      {list && (
        <SectionCard
          title={pick(language, COPY.proxies)}
          hint={pick(language, COPY.proxiesHint)}
          flush
          action={
            <Stack direction="row" spacing={1}>
              <Button size="small" onClick={() => void load()} disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} sx={{ minHeight: 44 }}>{c.refresh}</Button>
              {canWrite && proxies.length > 0 && <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setWizard({ editing: null })} sx={{ minHeight: 44 }}>{pick(language, COPY.add)}</Button>}
            </Stack>
          }
        >
          {testing && (
            <Box sx={{ px: 2, pt: 2 }}>
              <Typography variant="body2" sx={{ fontWeight: 650, mb: 0.5 }}>{say(language, COPY.testOf, { name: testing.proxy.name })}</Typography>
              <TestResult outcome={testing.outcome} />
            </Box>
          )}
          <ResponsiveList<ProxyRecord>
            label={pick(language, COPY.listLabel)}
            rows={proxies}
            rowKey={(row) => row.id}
            columns={[
              { key: "name", header: pick(language, COPY.name), render: (row) => (
                <Stack direction="row" spacing={0.75} alignItems="center">
                  <Box component="span" dir="auto">{row.name}</Box>
                  {row.is_default && <StatusPill tone="info" label={pick(language, COPY.isDefault)} />}
                </Stack>
              ) },
              { key: "address", header: pick(language, COPY.address), render: (row) => <Ltr mono>{`${row.host}:${row.port}`}</Ltr> },
              { key: "type", header: pick(language, COPY.type), render: (row) => PROXY_TYPE_SHORT[row.type] ?? row.type },
              { key: "usage", header: pick(language, COPY.usage), render: (row) => (row.used_by.length ? say(language, COPY.usedBy, { n: formatNumber(row.used_by.length, language) }) : pick(language, COPY.notUsed)) },
              { key: "noProxy", header: pick(language, COPY.noProxy), render: (row) => <Ltr mono>{(row.no_proxy ?? []).join(", ") || "—"}</Ltr>, advancedOnly: true },
              { key: "updated", header: pick(language, COPY.updated), render: (row) => <RelativeTime value={row.updated_at} />, advancedOnly: true },
              { key: "state", header: pick(language, COPY.state), render: (row) => <StatusPill tone={row.enabled ? "ok" : "off"} label={pick(language, row.enabled ? COPY.on : COPY.off)} /> }
            ]}
            card={{
              title: (row) => <Box component="span" dir="auto">{row.name}</Box>,
              meta: (row) => <><Ltr mono>{`${row.host}:${row.port}`}</Ltr> · {PROXY_TYPE_SHORT[row.type]}{row.is_default ? ` · ${pick(language, COPY.isDefault)}` : ""}</>,
              status: (row) => <StatusPill tone={row.enabled ? "ok" : "off"} label={pick(language, row.enabled ? COPY.on : COPY.off)} />
            }}
            actions={[
              { key: "test", label: pick(language, COPY.test), icon: NetworkCheckRoundedIcon, onClick: (row) => void test(row) },
              ...(canWrite ? [
                { key: "default", label: pick(language, COPY.setDefault), icon: StarRoundedIcon, onClick: (row: ProxyRecord) => void setDefault(row, true), hidden: (row: ProxyRecord) => row.is_default },
                { key: "undefault", label: pick(language, COPY.clearDefault), icon: StarBorderRoundedIcon, onClick: (row: ProxyRecord) => void setDefault(row, false), hidden: (row: ProxyRecord) => !row.is_default, advancedOnly: true },
                { key: "edit", label: pick(language, COPY.edit), icon: EditRoundedIcon, onClick: (row: ProxyRecord) => setWizard({ editing: row }), advancedOnly: true },
                { key: "delete", label: pick(language, COPY.remove), icon: DeleteOutlineRoundedIcon, onClick: (row: ProxyRecord) => void remove(row), danger: true, advancedOnly: true }
              ] : [])
            ]}
            empty={
              <EmptyState
                icon={VpnLockRoundedIcon}
                title={pick(language, COPY.empty)}
                body={pick(language, COPY.emptyBody)}
                action={canWrite ? <Button variant="contained" size="large" startIcon={<AddRoundedIcon />} onClick={() => setWizard({ editing: null })}>{pick(language, COPY.add)}</Button> : undefined}
              />
            }
          />
        </SectionCard>
      )}

      {list && (
        <SectionCard title={pick(language, COPY.services)} hint={`${pick(language, COPY.servicesHint)}${isAdvanced ? ` ${pick(language, COPY.servicesHintAdvanced)}` : ""}`}>
          {services !== null && services.length === 0 && <Typography variant="body2" color="text.secondary">{pick(language, COPY.noServices)}</Typography>}
          <Stack spacing={2}>
            {grouped.map(([group, items]) => (
              <Box key={group} component="section" aria-label={groupLabel(group, language)}>
                <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 760 }}>{groupLabel(group, language)}</Typography>
                <Stack divider={<Divider flexItem />} sx={{ border: 1, borderColor: "divider", borderRadius: 1 }}>
                  {items.map((service) => {
                    const key = `${service.kind}:${service.id}`;
                    return (
                      <Stack key={key} direction={{ xs: isAdvanced ? "column" : "row", sm: "row" }} alignItems={{ xs: isAdvanced ? "stretch" : "center", sm: "center" }} justifyContent="space-between" spacing={1.5} sx={{ px: 1.75, py: 1, minHeight: 56 }}>
                        <Box sx={{ minWidth: 0 }}>
                          <Typography variant="body2" fontWeight={700} dir="auto" noWrap title={service.name}>{service.name}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {outboundKindWord(language, service.kind)}
                            {isAdvanced && service.supported_proxy_types?.length ? ` · ${say(language, COPY.supported, { types: service.supported_proxy_types.map((type) => PROXY_TYPE_SHORT[type] ?? type).join("، ") })}` : ""}
                          </Typography>
                        </Box>
                        <Stack direction="row" alignItems="center" spacing={1} sx={{ flexShrink: 0, minWidth: isAdvanced ? { sm: 260 } : undefined }}>
                          {serviceBusy === key && <CircularProgress size={16} aria-hidden />}
                          <Box sx={{ flex: 1 }}>
                            <ProxyPicker
                              language={language}
                              list={list}
                              value={choiceFromApi(service.proxy_id)}
                              onChange={(value) => void changeService(service, value)}
                              supported={service.supported_proxy_types?.length ? service.supported_proxy_types : PROXY_TYPES}
                              advanced={isAdvanced}
                              disabled={!canWrite || serviceBusy === key}
                              label={service.name}
                              hideLabel={!isAdvanced}
                            />
                          </Box>
                        </Stack>
                      </Stack>
                    );
                  })}
                </Stack>
              </Box>
            ))}
          </Stack>
        </SectionCard>
      )}

      {wizard && (
        <ProxyWizard
          editing={wizard.editing}
          defaultExists={Boolean(list?.default_proxy_id)}
          onClose={() => setWizard(null)}
          onDone={(message) => {
            setWizard(null);
            notify({ message });
            void load(true);
          }}
        />
      )}
      {dialog}
      {snackbar}
    </Stack>
  );
}

// ── DNS & internal network tab (Advanced) ────────────────────────────────────

const DNS_KEYS = ["network.dns.mode", "network.dns.servers", "network.dns.timeout_seconds", "network.dns.prefer_ipv4", "network.allow_private_upstreams", "network.proxies", "network.default_proxy_id"];

export function DnsTab({ permissions }: SecurityTabProps) {
  const { language } = useKit();
  const canWrite = hasPermission(permissions, "upstream:write");
  return (
    <Stack spacing={2.5}>
      <DnsSettingsCard canWrite={canWrite} />
      <UpstreamPolicyCard canWrite={canWrite} />
      <RegistrySettings groups={["security.network"]} exclude={DNS_KEYS} permissions={permissions} title={pick(language, COPY.dnsMore)} hint={pick(language, COPY.dnsMoreHint)} />
    </Stack>
  );
}

/** Legacy entry point (old `#network` page); the shell now mounts SecurityPage. */
export function NetworkPanel({ permissions }: { language?: Language; permissions: string[]; onUnauthorized?: () => void }) {
  const { isAdvanced } = useKit();
  return (
    <Stack spacing={3}>
      <InternetTab permissions={permissions} />
      {isAdvanced && <DnsTab permissions={permissions} />}
    </Stack>
  );
}
