import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Box, Button, ButtonBase, Card, CardContent, Grid, Stack, TextField, Typography } from "@mui/material";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import QueryStatsRoundedIcon from "@mui/icons-material/QueryStatsRounded";
import CloudDownloadRoundedIcon from "@mui/icons-material/CloudDownloadRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import type { SvgIconComponent } from "@mui/icons-material";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { AuthUser } from "./App";
import {
  ActionWizard, DateTime, DurationInput, EmptyState, FriendlyError, HelpTip, Ltr, NoAccess, OneTimeSecret, RelativeTime,
  ResponsiveList, SectionCard, StatusPill, useConfirmAction, useKit, useUndoSnackbar, type WizardStep
} from "./kit";
import { PermissionMatrix, covers, fieldMessages, indexCatalog, permissionLabel, usePermissionCatalog } from "./kit/people";
import { errorSentence, pick, say, type Bi } from "./copy";

type TokenRecord = {
  id: number;
  name: string;
  scopes: string[];
  created_at: number;
  expires_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
};

type PresetKey = "readonly" | "monitoring" | "ci" | "custom";

const PRESETS: { key: Exclude<PresetKey, "custom">; icon: SvgIconComponent; scopes: string[]; label: Bi; hint: Bi; name: Bi }[] = [
  {
    key: "readonly",
    icon: VisibilityRoundedIcon,
    scopes: ["system:read", "upstream:read", "cache:read", "task:read"],
    label: { fa: "فقط دیدن", en: "View only" },
    hint: { fa: "برای اسکریپتی که فقط وضعیت و بسته‌ها را می‌خواند و چیزی را عوض نمی‌کند.", en: "For a script that only reads status and packages and changes nothing." },
    name: { fa: "کلید فقط دیدنی", en: "View-only key" }
  },
  {
    key: "monitoring",
    icon: QueryStatsRoundedIcon,
    scopes: ["system:read", "metrics:read"],
    label: { fa: "برای ابزار پایش", en: "For monitoring" },
    hint: { fa: "ابزاری مثل Prometheus آمار سرور را با آن می‌خواند. فقط دیدنی است.", en: "A tool like Prometheus reads server stats with it. View only." },
    name: { fa: "کلید ابزار پایش", en: "Monitoring key" }
  },
  {
    key: "ci",
    icon: CloudDownloadRoundedIcon,
    scopes: ["system:read", "cache:read", "cache:write", "task:read"],
    label: { fa: "برای CI: دانلود بسته‌ها از قبل", en: "For CI: download packages ahead" },
    hint: { fa: "CI می‌تواند بسته‌های پروژه را از قبل روی سرور دانلود کند تا نصب سریع‌تر شود.", en: "CI can download a project's packages onto the server ahead of time, so installs are faster." },
    name: { fa: "کلید CI", en: "CI key" }
  }
];

const EXPIRY: { seconds: number; label: Bi }[] = [
  { seconds: 86400, label: { fa: "۱ روز", en: "1 day" } },
  { seconds: 7 * 86400, label: { fa: "۱ هفته", en: "1 week" } },
  { seconds: 30 * 86400, label: { fa: "۱ ماه", en: "1 month" } },
  { seconds: 90 * 86400, label: { fa: "۳ ماه", en: "3 months" } },
  { seconds: 31536000, label: { fa: "۱ سال", en: "1 year" } }
];

const T = {
  title: { fa: "کلیدهای برنامه من", en: "My app keys" },
  hint: { fa: "برای اسکریپت‌ها و ابزارهای خودکار که باید بدون رمز شما وارد شوند. هر کلید مثل یک رمز است.", en: "For scripts and automated tools that must sign in without your password. Each key works like a password." },
  create: { fa: "ساخت کلید برنامه", en: "Create an app key" },
  emptyTitle: { fa: "هنوز کلید برنامه‌ای ندارید", en: "You don't have any app keys yet" },
  emptyBody: { fa: "اگر یک اسکریپت یا CI باید به پیشکار وصل شود، برایش یک کلید جدا بسازید. هر وقت خواستید باطلش کنید.", en: "If a script or CI needs to reach Pishkar, give it its own key. You can revoke it any time." },
  colName: { fa: "نام", en: "Name" },
  colPurpose: { fa: "برای چه", en: "Purpose" },
  colStatus: { fa: "وضعیت", en: "Status" },
  colExpires: { fa: "تا کی", en: "Expires" },
  colUsed: { fa: "آخرین استفاده", en: "Last used" },
  colScopes: { fa: "اجازه‌ها", en: "Permissions" },
  colCreated: { fa: "ساخته شده", en: "Created" },
  colId: { fa: "شناسه", en: "ID" },
  neverUsed: { fa: "هنوز استفاده نشده", en: "Not used yet" },
  customPurpose: { fa: "اجازه‌های سفارشی", en: "Custom permissions" },
  active: { fa: "فعال", en: "Active" },
  expiringSoon: { fa: "به‌زودی تمام می‌شود", en: "Expiring soon" },
  expired: { fa: "تاریخش گذشته", en: "Expired" },
  revoked: { fa: "باطل شده", en: "Revoked" },
  revoke: { fa: "باطل کردن", en: "Revoke" },
  revokeTitle: { fa: "کلید «{name}» باطل شود؟", en: "Revoke the key “{name}”?" },
  revokeBody: { fa: "هر اسکریپت یا ابزاری که از این کلید استفاده می‌کند همین حالا قطع می‌شود.", en: "Any script or tool using this key is cut off right away." },
  revokedToast: { fa: "کلید «{name}» باطل شد.", en: "“{name}” was revoked." },
  readOnly: { fa: "نقش شما فقط اجازه دیدن کلیدهای خودتان را دارد.", en: "Your role can only see your own keys." },
  // wizard
  stepWhat: { fa: "برای چه؟", en: "What for?" },
  stepWhatHint: { fa: "بگویید این کلید قرار است چه کاری بکند. کمترین اجازه‌ی لازم را انتخاب کنید.", en: "Say what this key is for. Pick the smallest permission it needs." },
  custom: { fa: "سفارشی", en: "Custom" },
  customHint: { fa: "خودتان دقیقاً انتخاب کنید کلید چه اجازه‌هایی داشته باشد.", en: "Choose exactly which permissions the key has." },
  notAllowed: { fa: "نقش شما این اجازه‌ها را ندارد.", en: "Your role doesn't have these permissions." },
  name: { fa: "نام کلید (برای این‌که بعداً بشناسیدش)", en: "Key name (so you recognise it later)" },
  nameRule: { fa: "نام کلید باید بین ۳ تا ۸۰ نویسه باشد.", en: "The key name must be 3 to 80 characters." },
  pickPreset: { fa: "یکی از گزینه‌ها را انتخاب کنید.", en: "Pick one of the options." },
  pickScopes: { fa: "دست‌کم یک اجازه را تیک بزنید.", en: "Tick at least one permission." },
  stepWhen: { fa: "تا کی کار کند؟", en: "How long should it work?" },
  stepWhenHint: { fa: "بعد از این مدت، کلید خودبه‌خود از کار می‌افتد. کوتاه‌تر امن‌تر است.", en: "After this, the key stops working by itself. Shorter is safer." },
  customExpiry: { fa: "مدت دلخواه", en: "Custom length" },
  expiryRule: { fa: "مدت باید بین ۱۵ دقیقه و ۱ سال باشد.", en: "The length must be between 15 minutes and 1 year." },
  finish: { fa: "ساخت کلید", en: "Create key" },
  secretTitle: { fa: "کلید «{name}» ساخته شد", en: "“{name}” is ready" },
  secretBody: { fa: "این کلید مثل رمز است. آن را فقط در جای امن بگذارید، مثلاً در تنظیمات مخفی CI.", en: "This key works like a password. Keep it somewhere safe, such as your CI's secret settings." },
  secretLabel: { fa: "کلید برنامه", en: "App key" },
  usage: { fa: "نمونه استفاده", en: "Example use" },
  createdToast: { fa: "کلید «{name}» ساخته شد.", en: "“{name}” was created." },
  scopesHelp: { fa: "کلید هیچ‌وقت بیشتر از نقش شما اجازه ندارد.", en: "A key never has more permissions than your role." }
} satisfies Record<string, Bi>;

function presetOf(scopes: string[]) {
  const set = [...scopes].sort().join(",");
  return PRESETS.find((preset) => [...preset.scopes].sort().join(",") === set);
}

function ChoiceCard({ selected, disabled, onClick, icon: Icon, title, hint, reason }: { selected: boolean; disabled?: boolean; onClick: () => void; icon: SvgIconComponent; title: string; hint: string; reason?: string | null }) {
  return (
    <Card variant="outlined" sx={{ height: "100%", borderColor: selected ? "primary.main" : undefined, borderWidth: selected ? 2 : 1, opacity: disabled ? 0.55 : 1 }}>
      <ButtonBase role="radio" aria-checked={selected} disabled={disabled} onClick={onClick} sx={{ display: "block", width: "100%", height: "100%", textAlign: "start" }}>
        <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
          <Stack direction="row" spacing={1.25} alignItems="flex-start">
            <Icon color={selected ? "primary" : "action"} aria-hidden />
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography sx={{ fontWeight: 760 }}>{title}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>{hint}</Typography>
              {reason && <Typography variant="caption" color="text.secondary">{reason}</Typography>}
            </Box>
            {selected && <CheckCircleRoundedIcon color="primary" fontSize="small" aria-hidden />}
          </Stack>
        </CardContent>
      </ButtonBase>
    </Card>
  );
}

export type AppKeysPanelProps = {
  user: AuthUser;
  /** Increment to open the create wizard (the page's primary button). */
  createRequest?: number;
};

export function AppKeysPanel({ user, createRequest = 0 }: AppKeysPanelProps) {
  const { language, isAdvanced } = useKit();
  const { ask, dialog: confirmDialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canRead = hasPermission(user.permissions, "token:read");
  const canWrite = hasPermission(user.permissions, "token:write");
  const { catalog } = usePermissionCatalog();
  const index = useMemo(() => indexCatalog(catalog), [catalog]);
  const [tokens, setTokens] = useState<TokenRecord[] | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const controller = useRef<AbortController | null>(null);

  const [open, setOpen] = useState(false);
  const [preset, setPreset] = useState<PresetKey>("readonly");
  const [customScopes, setCustomScopes] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const [expiry, setExpiry] = useState(30 * 86400);
  const [customExpiry, setCustomExpiry] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [issued, setIssued] = useState<{ name: string; token: string; preset: PresetKey } | null>(null);

  const load = useCallback(async () => {
    if (!canRead) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      const payload = await getJson<{ items: TokenRecord[] }>("/api/v1/tokens", current.signal);
      setTokens(payload.items ?? []);
      setLoadError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setLoadError(caught);
    }
  }, [canRead]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const presetAllowed = (scopes: string[]) => covers(user.permissions, scopes);
  const firstAllowed = PRESETS.find((item) => presetAllowed(item.scopes))?.key ?? "custom";

  const openWizard = useCallback(() => {
    setPreset(firstAllowed);
    setCustomScopes([]);
    const first = PRESETS.find((item) => item.key === firstAllowed);
    setName(first ? pick(language, first.name) : "");
    setNameTouched(false);
    setExpiry(30 * 86400);
    setCustomExpiry(false);
    setFieldErrors({});
    setOpen(true);
  }, [firstAllowed, language]);

  useEffect(() => {
    if (createRequest > 0 && canWrite) openWizard();
  }, [createRequest, canWrite, openWizard]);

  const choosePreset = (key: PresetKey) => {
    setPreset(key);
    if (!nameTouched) {
      const found = PRESETS.find((item) => item.key === key);
      setName(found ? pick(language, found.name) : "");
    }
  };

  const scopesFor = (key: PresetKey) => (key === "custom" ? customScopes : PRESETS.find((item) => item.key === key)?.scopes ?? []);
  const now = Math.floor(Date.now() / 1000);

  const status = (item: TokenRecord): { tone: "ok" | "warn" | "off"; label: string } => {
    if (item.revoked_at) return { tone: "off", label: pick(language, T.revoked) };
    if (item.expires_at <= now) return { tone: "off", label: pick(language, T.expired) };
    if (item.expires_at - now < 7 * 86400) return { tone: "warn", label: pick(language, T.expiringSoon) };
    return { tone: "ok", label: pick(language, T.active) };
  };
  const purpose = (item: TokenRecord) => {
    const found = presetOf(item.scopes);
    return found ? pick(language, found.label) : pick(language, T.customPurpose);
  };

  const revoke = async (item: TokenRecord) => {
    const ok = await ask({ title: say(language, T.revokeTitle, { name: item.name }), body: pick(language, T.revokeBody), severity: "destructive", undoable: false, confirmLabel: pick(language, T.revoke) });
    if (!ok) return;
    try {
      await mutateJson(`/api/v1/tokens/${item.id}`, { method: "DELETE" });
      notify({ message: say(language, T.revokedToast, { name: item.name }) });
      await load();
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
  };

  const steps: WizardStep[] = [
    {
      key: "what",
      title: pick(language, T.stepWhat),
      hint: pick(language, T.stepWhatHint),
      validate: () => {
        const trimmed = name.trim();
        if (trimmed.length < 3 || trimmed.length > 80) return pick(language, T.nameRule);
        if (preset !== "custom" && !presetAllowed(scopesFor(preset))) return pick(language, T.pickPreset);
        if (scopesFor(preset).length === 0) return pick(language, T.pickScopes);
        return null;
      },
      render: () => (
        <Stack spacing={2}>
          <Grid container spacing={1.5} role="radiogroup" aria-label={pick(language, T.stepWhat)}>
            {PRESETS.map((item) => {
              const allowed = presetAllowed(item.scopes);
              return (
                <Grid key={item.key} size={{ xs: 12 }}>
                  <ChoiceCard
                    selected={preset === item.key}
                    disabled={!allowed}
                    onClick={() => choosePreset(item.key)}
                    icon={item.icon}
                    title={pick(language, item.label)}
                    hint={pick(language, item.hint)}
                    reason={allowed ? null : pick(language, T.notAllowed)}
                  />
                </Grid>
              );
            })}
            {isAdvanced && (
              <Grid size={{ xs: 12 }}>
                <ChoiceCard selected={preset === "custom"} onClick={() => choosePreset("custom")} icon={TuneRoundedIcon} title={pick(language, T.custom)} hint={pick(language, T.customHint)} />
              </Grid>
            )}
          </Grid>
          {preset === "custom" && (
            <Box>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>{pick(language, T.scopesHelp)}</Typography>
              <PermissionMatrix catalog={catalog} value={customScopes} onChange={setCustomScopes} grantable={user.permissions} />
            </Box>
          )}
          <TextField
            fullWidth
            label={pick(language, T.name)}
            value={name}
            onChange={(event) => { setName(event.target.value); setNameTouched(true); setFieldErrors(({ name: _drop, ...rest }) => rest); }}
            error={Boolean(fieldErrors.name)}
            helperText={fieldErrors.name ?? " "}
            slotProps={{ htmlInput: { maxLength: 80 } }}
          />
        </Stack>
      )
    },
    {
      key: "when",
      title: pick(language, T.stepWhen),
      hint: pick(language, T.stepWhenHint),
      validate: () => (expiry < 900 || expiry > 31536000 ? pick(language, T.expiryRule) : null),
      render: () => (
        <Stack spacing={2}>
          <Grid container spacing={1} role="radiogroup" aria-label={pick(language, T.stepWhen)}>
            {EXPIRY.map((item) => (
              <Grid key={item.seconds} size={{ xs: 6, sm: 4 }}>
                <Button
                  fullWidth
                  role="radio"
                  aria-checked={!customExpiry && expiry === item.seconds}
                  variant={!customExpiry && expiry === item.seconds ? "contained" : "outlined"}
                  onClick={() => { setCustomExpiry(false); setExpiry(item.seconds); }}
                  sx={{ minHeight: 48 }}
                >
                  {pick(language, item.label)}
                </Button>
              </Grid>
            ))}
            {isAdvanced && (
              <Grid size={{ xs: 6, sm: 4 }}>
                <Button fullWidth role="radio" aria-checked={customExpiry} variant={customExpiry ? "contained" : "outlined"} onClick={() => setCustomExpiry(true)} sx={{ minHeight: 48 }}>
                  {pick(language, T.customExpiry)}
                </Button>
              </Grid>
            )}
          </Grid>
          {customExpiry && (
            <DurationInput label={pick(language, T.customExpiry)} value={expiry} onChange={(value) => setExpiry(value ?? 0)} min={900} max={31536000} units={["minutes", "hours", "days"]} />
          )}
          {fieldErrors.expires_in_seconds && <Typography role="alert" color="error.main" variant="body2">{fieldErrors.expires_in_seconds}</Typography>}
          {fieldErrors.scopes && <Typography role="alert" color="error.main" variant="body2">{fieldErrors.scopes}</Typography>}
        </Stack>
      )
    }
  ];

  const finish = async () => {
    setFieldErrors({});
    try {
      const payload = await mutateJson<{ id: number; token: string }>("/api/v1/tokens", {
        method: "POST",
        body: { name: name.trim(), scopes: scopesFor(preset), expires_in_seconds: Math.round(expiry) }
      });
      setIssued({ name: name.trim(), token: payload.token, preset });
      notify({ message: say(language, T.createdToast, { name: name.trim() }) });
      void load();
    } catch (caught) {
      setFieldErrors(fieldMessages(language, caught));
      throw caught;
    }
  };

  if (!canRead) return <NoAccess needs="token:read" variant="card" />;

  const usage = issued
    ? issued.preset === "monitoring"
      ? `# prometheus.yml\nscrape_configs:\n  - job_name: mrk\n    metrics_path: /metrics\n    authorization:\n      credentials: ${issued.token}\n    static_configs:\n      - targets: ["${window.location.host}"]`
      : `curl -H "Authorization: Bearer ${issued.token}" ${window.location.origin}/api/v1/system/status`
    : "";

  return (
    <SectionCard
      title={pick(language, T.title)}
      hint={pick(language, T.hint)}
      action={<HelpTip term="apiToken" />}
      flush
    >
      <Stack spacing={1.5}>
        {loadError !== null && <Box sx={{ px: 2.5, pt: 1 }}><FriendlyError error={loadError} onRetry={() => void load()} /></Box>}
        {!canWrite && <Box sx={{ px: 2.5 }}><NoAccess needs="token:write" /></Box>}
        <ResponsiveList
          label={pick(language, T.title)}
          rows={tokens ?? []}
          rowKey={(row) => row.id}
          columns={[
            { key: "name", header: pick(language, T.colName), render: (row) => <Typography sx={{ fontWeight: 700 }}>{row.name}</Typography> },
            { key: "purpose", header: pick(language, T.colPurpose), render: (row) => purpose(row) },
            { key: "status", header: pick(language, T.colStatus), render: (row) => <StatusPill tone={status(row).tone} label={status(row).label} />, hideOnCard: true },
            { key: "expires", header: pick(language, T.colExpires), render: (row) => <RelativeTime value={row.revoked_at ?? row.expires_at} /> },
            { key: "used", header: pick(language, T.colUsed), render: (row) => (row.last_used_at ? <RelativeTime value={row.last_used_at} /> : pick(language, T.neverUsed)) },
            { key: "scopes", header: pick(language, T.colScopes), advancedOnly: true, render: (row) => (
              <Stack spacing={0.25}>
                {row.scopes.map((scope) => (
                  <Typography key={scope} variant="caption" display="block">{permissionLabel(language, scope, index)} <Box component="span" sx={{ color: "text.disabled" }}><Ltr mono>{scope}</Ltr></Box></Typography>
                ))}
              </Stack>
            ) },
            { key: "created", header: pick(language, T.colCreated), advancedOnly: true, render: (row) => <DateTime value={row.created_at} /> },
            { key: "id", header: pick(language, T.colId), advancedOnly: true, ltr: true, render: (row) => <Ltr mono>{String(row.id)}</Ltr> }
          ]}
          card={{
            title: (row) => row.name,
            meta: (row) => <>{purpose(row)} · {row.last_used_at ? <RelativeTime value={row.last_used_at} /> : pick(language, T.neverUsed)}</>,
            status: (row) => <StatusPill tone={status(row).tone} label={status(row).label} />
          }}
          actions={canWrite ? [{
            key: "revoke",
            label: pick(language, T.revoke),
            icon: BlockRoundedIcon,
            danger: true,
            hidden: (row) => Boolean(row.revoked_at) || row.expires_at <= now,
            onClick: (row) => void revoke(row)
          }] : undefined}
          empty={tokens === null ? undefined : (
            <EmptyState
              icon={KeyRoundedIcon}
              title={pick(language, T.emptyTitle)}
              body={pick(language, T.emptyBody)}
              action={canWrite ? <Button variant="contained" startIcon={<KeyRoundedIcon />} onClick={openWizard} sx={{ minHeight: 44 }}>{pick(language, T.create)}</Button> : undefined}
              compact
            />
          )}
        />
      </Stack>

      <ActionWizard open={open} title={pick(language, T.create)} steps={steps} finishLabel={pick(language, T.finish)} onFinish={finish} onClose={() => setOpen(false)} />

      {issued && (
        <OneTimeSecret
          open
          title={say(language, T.secretTitle, { name: issued.name })}
          body={pick(language, T.secretBody)}
          items={[{ label: pick(language, T.secretLabel), value: issued.token, ltr: true }]}
          message={{ label: pick(language, T.usage), value: usage }}
          onClose={() => setIssued(null)}
        />
      )}
      {confirmDialog}
      {snackbar}
    </SectionCard>
  );
}

export default AppKeysPanel;
