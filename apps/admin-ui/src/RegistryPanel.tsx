/**
 * «ایمیج‌های Docker» / Docker images (group `code`, tab `registry`). A Docker registry on our own
 * server (Zot): a private place for your images, and an on-demand mirror of Docker Hub, ghcr.io and
 * quay.io, each with fallback addresses (e.g. a domestic mirror).
 *
 * - Status card + «How to use» ready commands (docker login, pull through the mirror, push, daemon.json).
 * - Mirror sources: an ordered address list per source (first is tried first), on/off, anonymous pull.
 * - Images and their tags; registry users (pull / push) with a one-time password.
 *
 * Data: `/api/v1/registry/*` (registry:read; changes need registry:write). A server without this part
 * (404) or without Zot (`connected: false`) gets a friendly empty state.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem,
  Stack, Switch, TextField, Typography, useMediaQuery, useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import ArrowUpwardRoundedIcon from "@mui/icons-material/ArrowUpwardRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import LayersRoundedIcon from "@mui/icons-material/LayersRounded";
import LocalOfferRoundedIcon from "@mui/icons-material/LocalOfferRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import PersonAddRoundedIcon from "@mui/icons-material/PersonAddRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import { ApiError, getJson, mutateJson } from "./api";
import { pick, say, type Bi } from "./copy";
import {
  ActionWizard, CopyField, EmptyState, FriendlyError, KeyValueList, ListInput, Ltr, NoAccess, Num, Notice, OneTimeSecret, RelativeTime,
  ResponsiveList, SectionCard, StatusPill, useCan, useConfirmAction, useKit, useUndoSnackbar
} from "./kit";
import { useVisibleInterval } from "./polling";
import type { CodePanelProps } from "./GitPanel";

type RegistryStatus = {
  connected?: boolean;
  reachable?: boolean;
  url?: string | null;
  public_url?: string | null;
  endpoint?: string | null;
};

type Upstream = { id: string; name: string; destination: string; urls: string[]; enabled: boolean };
type RegistrySettings = { anonymous_pull: boolean; upstreams: Upstream[] };
type ImageRepo = { name: string; tags?: number | null };
type RegistryUser = { name: string; access: "pull" | "push"; created_at?: number };
type HelpPayload = { endpoint?: string; docker_login?: string; daemon_mirror_json?: string; examples?: { title_fa?: string; title_en?: string; command?: string }[] };

const API = "/api/v1/registry";
const USER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const URL_RE = /^https?:\/\/[^\s/]+\S*$/i;

const T = {
  missingTitle: { fa: "مخزن ایمیج هنوز روی این سرور نصب نیست", en: "The image registry isn't installed on this server yet" },
  missingBody: {
    fa: "با آن ایمیج‌های خصوصی‌تان روی سرور خودتان می‌ماند و ایمیج‌های Docker Hub یک بار دانلود و بعد از همین‌جا برداشته می‌شوند. اول سرویس Zot را اضافه کنید.",
    en: "It keeps your private images on your own server, and Docker Hub images are downloaded once and then served from here. Add the Zot service first."
  },
  oldServerTitle: { fa: "این نسخه از سرور هنوز بخش ایمیج‌ها را ندارد", en: "This server version has no image section yet" },
  oldServerBody: { fa: "بعد از به‌روزرسانی DevAssist دوباره سر بزنید.", en: "Come back after updating DevAssist." },
  addService: { fa: "افزودن سرویس", en: "Add a service" },
  statusTitle: { fa: "مخزن ایمیج Docker", en: "Docker image registry" },
  statusHint: { fa: "ایمیج‌های خصوصی شما، و نسخه‌ای از Docker Hub که روی همین سرور می‌ماند.", en: "Your private images, and a copy of Docker Hub that stays on this server." },
  notAnswering: { fa: "مخزن ایمیج نصب است ولی الان جواب نمی‌دهد. چند دقیقه بعد دوباره نگاه کنید یا آن را در «سرویس‌های من» بررسی کنید.", en: "The registry is installed but isn't answering right now. Look again in a few minutes, or check it under My services." },
  endpoint: { fa: "نشانی برای Docker", en: "Address for Docker" },
  endpointHint: { fa: "همین نشانی را در دستورهای Docker می‌نویسید.", en: "You write this address in Docker commands." },
  publicUrl: { fa: "نشانی عمومی", en: "Public address" },
  internalUrl: { fa: "نشانی داخلی", en: "Internal address" },
  open: { fa: "باز کردن", en: "Open" },
  helpTitle: { fa: "طرز استفاده", en: "How to use it" },
  helpHint: { fa: "این دستورها را روی رایانه یا سروری که Docker دارد اجرا کنید.", en: "Run these commands on a computer or server that has Docker." },
  helpLogin: { fa: "وارد شدن به مخزن", en: "Sign in to the registry" },
  helpPullHub: { fa: "دریافت ایمیج Docker Hub از راه این سرور", en: "Pull a Docker Hub image through this server" },
  helpPush: { fa: "فرستادن ایمیج خصوصی خودتان", en: "Push your own private image" },
  helpDaemon: { fa: "استفاده خودکار برای همه ایمیج‌های Docker Hub", en: "Use it automatically for every Docker Hub image" },
  helpDaemonHint: { fa: "این را در فایل /etc/docker/daemon.json بگذارید و Docker را دوباره راه‌اندازی کنید.", en: "Put this in /etc/docker/daemon.json and restart Docker." },
  // Settings
  settingsTitle: { fa: "منبع‌های آینه", en: "Mirror sources" },
  settingsHint: {
    fa: "وقتی ایمیجی اینجا نیست، از این منبع‌ها گرفته و نگه داشته می‌شود. نشانی اول اول امتحان می‌شود؛ بقیه پشتیبان‌اند، مثلاً یک آینه داخلی.",
    en: "When an image isn't here yet, it's fetched from these sources and kept. The first address is tried first; the rest are fallbacks, such as a domestic mirror."
  },
  anonymous: { fa: "دریافت بدون ورود", en: "Pull without signing in" },
  anonymousHint: { fa: "هر کسی که به سرور دسترسی دارد بتواند ایمیج بگیرد، بدون نام کاربری.", en: "Anyone who can reach the server can pull images, without a username." },
  anonymousWarning: { fa: "با روشن بودن این گزینه، ایمیج‌های خصوصی شما هم برای همه قابل دریافت است. فقط روی شبکه داخلی روشنش کنید.", en: "With this on, your private images can be pulled by anyone too. Turn it on only on an internal network." },
  sourceOn: { fa: "روشن", en: "On" },
  destination: { fa: "مسیر روی این سرور", en: "Path on this server" },
  addresses: { fa: "نشانی‌ها به ترتیب", en: "Addresses, in order" },
  addressesHelp: { fa: "نشانی را بنویسید و Enter بزنید.", en: "Type an address and press Enter." },
  urlRule: { fa: "نشانی باید با https:// یا http:// شروع شود.", en: "The address must start with https:// or http://." },
  tryOrder: { fa: "ترتیب امتحان:", en: "Order of trying:" },
  first: { fa: "اول", en: "first" },
  fallback: { fa: "پشتیبان", en: "fallback" },
  moveUp: { fa: "بالا بردن «{name}»", en: "Move “{name}” up" },
  noAddresses: { fa: "این منبع نشانی ندارد و استفاده نمی‌شود.", en: "This source has no address and won't be used." },
  removeSource: { fa: "حذف این منبع", en: "Remove this source" },
  addSource: { fa: "افزودن منبع", en: "Add a source" },
  sourceName: { fa: "نام منبع", en: "Source name" },
  newSource: { fa: "منبع تازه", en: "New source" },
  saveSettings: { fa: "ذخیره منبع‌ها", en: "Save sources" },
  saved: { fa: "منبع‌های آینه ذخیره شد.", en: "Mirror sources were saved." },
  unsaved: { fa: "تغییرهای ذخیره‌نشده دارید.", en: "You have unsaved changes." },
  discard: { fa: "برگرداندن تغییرها", en: "Discard changes" },
  emptySources: { fa: "هنوز منبع آینه‌ای ندارید", en: "You have no mirror sources yet" },
  emptySourcesBody: { fa: "بدون منبع، فقط ایمیج‌هایی که خودتان می‌فرستید اینجا هست.", en: "Without a source, only images you push yourself are here." },
  // Images
  imagesTitle: { fa: "ایمیج‌ها", en: "Images" },
  imagesHint: { fa: "ایمیج‌هایی که فرستاده‌اید یا از منبع‌ها گرفته و نگه داشته شده‌اند.", en: "Images you pushed, or that were fetched from a source and kept." },
  emptyImages: { fa: "هنوز ایمیجی اینجا نیست", en: "There are no images here yet" },
  emptyImagesBody: { fa: "یک ایمیج بفرستید یا از راه این سرور یکی بگیرید؛ دستورهایش در «طرز استفاده» هست.", en: "Push an image or pull one through this server; the commands are under How to use it." },
  colImage: { fa: "ایمیج", en: "Image" },
  colTags: { fa: "تعداد نسخه", en: "Tags" },
  showTags: { fa: "دیدن نسخه‌ها", en: "See tags" },
  tagsTitle: { fa: "نسخه‌های «{name}»", en: "Tags of “{name}”" },
  noTags: { fa: "این ایمیج نسخه‌ای ندارد.", en: "This image has no tags." },
  pullCommand: { fa: "دستور دریافت", en: "Pull command" },
  // Users
  usersTitle: { fa: "کاربران مخزن", en: "Registry users" },
  usersHint: { fa: "هر برنامه یا هم‌تیمی با نام کاربری خودش وارد می‌شود.", en: "Each app or teammate signs in with their own username." },
  newUser: { fa: "کاربر تازه", en: "New user" },
  emptyUsers: { fa: "هنوز کاربری ندارید", en: "You have no users yet" },
  emptyUsersBody: { fa: "برای هر سرور یا هم‌تیمی یک کاربر بسازید تا بتوانید دسترسی را جدا جدا بگیرید.", en: "Create one user per server or teammate, so you can take access back one by one." },
  colName: { fa: "نام کاربری", en: "Username" },
  colAccess: { fa: "دسترسی", en: "Access" },
  colCreated: { fa: "ساخته‌شده", en: "Created" },
  accessPull: { fa: "فقط دریافت", en: "Pull only" },
  accessPush: { fa: "دریافت و فرستادن", en: "Pull and push" },
  accessPullHint: { fa: "برای سرورهایی که فقط برنامه را اجرا می‌کنند.", en: "For servers that only run apps." },
  accessPushHint: { fa: "برای ساختن و فرستادن ایمیج، مثلاً در CI.", en: "For building and pushing images, such as in CI." },
  userStep: { fa: "مشخصات", en: "Details" },
  userStepHint: { fa: "رمز ورود خودکار ساخته می‌شود و فقط یک بار نشان داده می‌شود.", en: "A password is made automatically and shown only once." },
  nameRule: { fa: "نام فقط حروف انگلیسی، عدد، نقطه، خط تیره و زیرخط باشد و با حرف یا عدد شروع شود.", en: "Use only letters, digits, dots, dashes and underscores, starting with a letter or digit." },
  createUser: { fa: "ساخت کاربر", en: "Create user" },
  secretTitle: { fa: "کاربر «{name}» ساخته شد", en: "User “{name}” was created" },
  secretBody: { fa: "این رمز را جای امنی نگه دارید؛ با دستور زیر وارد شوید.", en: "Keep this password somewhere safe; sign in with the command below." },
  password: { fa: "رمز ورود", en: "Password" },
  loginCommand: { fa: "دستور ورود", en: "Sign-in command" },
  removeUser: { fa: "پاک کردن", en: "Delete" },
  removeTitle: { fa: "کاربر «{name}» پاک شود؟", en: "Delete user “{name}”?" },
  removeBody: { fa: "هر سرور یا برنامه‌ای که با این کاربر وارد شده، دیگر نمی‌تواند ایمیج بگیرد یا بفرستد.", en: "Any server or app signed in as this user can no longer pull or push images." },
  removed: { fa: "کاربر «{name}» پاک شد.", en: "User “{name}” was deleted." },
  writeNeeded: { fa: "برای تغییر منبع‌ها و کاربران مخزن", en: "to change the registry's sources and users" }
} satisfies Record<string, Bi>;

function isMissing(error: unknown) {
  return error instanceof ApiError && (error.status === 404 || error.status === 405);
}

/** `library/nginx` → `library/nginx` with each segment encoded. */
function encodePath(name: string) {
  return name.split("/").map(encodeURIComponent).join("/");
}

function normalizeSettings(value: Partial<RegistrySettings> | null | undefined): RegistrySettings {
  return {
    anonymous_pull: Boolean(value?.anonymous_pull),
    upstreams: (value?.upstreams ?? []).map((item, index) => ({
      id: item?.id ?? `source-${index}`,
      name: item?.name ?? "",
      destination: item?.destination ?? "/",
      urls: Array.isArray(item?.urls) ? item.urls : [],
      enabled: item?.enabled !== false
    }))
  };
}

export function RegistryPanel({ permissions }: CodePanelProps) {
  const { language } = useKit();
  const can = useCan(permissions);
  const canWrite = can("registry:write");
  const { notify, snackbar } = useUndoSnackbar();
  const [status, setStatus] = useState<RegistryStatus | null>(null);
  const [statusError, setStatusError] = useState<unknown>(null);

  const loadStatus = useCallback(() => {
    getJson<RegistryStatus>(`${API}/status`).then(
      (value) => {
        setStatus(value ?? {});
        setStatusError(null);
      },
      (error) => setStatusError(error)
    );
  }, []);
  useEffect(() => loadStatus(), [loadStatus]);
  useVisibleInterval(loadStatus, 15000);

  if (statusError && !status) {
    if (isMissing(statusError)) {
      return <SectionCard><EmptyState icon={LayersRoundedIcon} title={pick(language, T.oldServerTitle)} body={pick(language, T.oldServerBody)} /></SectionCard>;
    }
    return <FriendlyError error={statusError} onRetry={loadStatus} />;
  }
  if (!status) return null;
  if (!status.connected) {
    return (
      <SectionCard>
        <EmptyState
          icon={LayersRoundedIcon}
          title={pick(language, T.missingTitle)}
          body={pick(language, T.missingBody)}
          action={<Button variant="contained" href="#/services/add" startIcon={<AddRoundedIcon />}>{pick(language, T.addService)}</Button>}
        />
      </SectionCard>
    );
  }

  const toast = (bi: Bi, name = "") => notify({ message: say(language, bi, { name }) });
  return (
    <Stack spacing={2}>
      <StatusCard status={status} />
      <HelpSection endpoint={status.endpoint ?? null} />
      <SettingsSection canWrite={canWrite} notify={toast} />
      <ImagesSection endpoint={status.endpoint ?? null} />
      <UsersSection canWrite={canWrite} endpoint={status.endpoint ?? null} notify={toast} />
      {!canWrite && <NoAccess needs="registry:write" ask={pick(language, T.writeNeeded)} />}
      {snackbar}
    </Stack>
  );
}

type Notify = (bi: Bi, name?: string) => void;

function StatusCard({ status }: { status: RegistryStatus }) {
  const { language } = useKit();
  const reachable = status.reachable !== false;
  return (
    <SectionCard
      title={pick(language, T.statusTitle)}
      hint={pick(language, T.statusHint)}
      status={<StatusPill status={reachable ? "connected" : "unreachable"} />}
      action={status.public_url ? (
        <Button variant="outlined" href={status.public_url} target="_blank" rel="noopener noreferrer" endIcon={<OpenInNewRoundedIcon />}>{pick(language, T.open)}</Button>
      ) : undefined}
    >
      <Stack spacing={1.5}>
        {!reachable && <Notice tone="warning">{pick(language, T.notAnswering)}</Notice>}
        {status.endpoint && <CopyField label={pick(language, T.endpoint)} value={status.endpoint} helperText={pick(language, T.endpointHint)} />}
        <KeyValueList
          items={[
            { label: pick(language, T.publicUrl), value: status.public_url ? <Ltr>{status.public_url}</Ltr> : "—", advancedOnly: true },
            { label: pick(language, T.internalUrl), value: status.url ? <Ltr>{status.url}</Ltr> : "—", advancedOnly: true }
          ]}
        />
      </Stack>
    </SectionCard>
  );
}

// ── How to use ───────────────────────────────────────────────────────────────

/** Commands built here when the server has no `/help` (older versions). */
function fallbackHelp(endpoint: string): HelpPayload {
  return {
    endpoint,
    docker_login: `docker login ${endpoint}`,
    daemon_mirror_json: JSON.stringify({ "registry-mirrors": [`https://${endpoint}`] }, null, 2),
    examples: [
      { title_fa: T.helpPullHub.fa, title_en: T.helpPullHub.en, command: `docker pull ${endpoint}/library/nginx:latest` },
      { title_fa: T.helpPush.fa, title_en: T.helpPush.en, command: `docker tag my-app:1.0 ${endpoint}/my-app:1.0\ndocker push ${endpoint}/my-app:1.0` }
    ]
  };
}

function HelpSection({ endpoint }: { endpoint: string | null }) {
  const { language } = useKit();
  const [help, setHelp] = useState<HelpPayload | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => {
    getJson<HelpPayload>(`${API}/help`).then(
      (value) => {
        setHelp(value ?? {});
        setError(null);
      },
      (caught) => {
        if (isMissing(caught) && endpoint) setHelp(fallbackHelp(endpoint));
        else setError(caught);
      }
    );
  }, [endpoint]);
  useEffect(() => load(), [load]);

  return (
    <SectionCard title={pick(language, T.helpTitle)} hint={pick(language, T.helpHint)} collapsible>
      {error ? <FriendlyError error={error} onRetry={load} /> : help === null ? null : (
        <Stack spacing={2}>
          {help.docker_login && <CopyField label={pick(language, T.helpLogin)} value={help.docker_login} />}
          {(help.examples ?? []).filter((item) => item.command).map((item, index) => (
            <CopyField
              key={`${index}-${item.command}`}
              label={(language === "fa" ? item.title_fa : item.title_en) || item.title_en || item.title_fa || pick(language, T.helpPullHub)}
              value={item.command ?? ""}
              multiline={(item.command ?? "").includes("\n")}
            />
          ))}
          {help.daemon_mirror_json && (
            <CopyField label={pick(language, T.helpDaemon)} value={help.daemon_mirror_json} multiline helperText={pick(language, T.helpDaemonHint)} />
          )}
        </Stack>
      )}
    </SectionCard>
  );
}

// ── Mirror sources ───────────────────────────────────────────────────────────

function SettingsSection({ canWrite, notify }: { canWrite: boolean; notify: Notify }) {
  const { language, isAdvanced, c } = useKit();
  const { ask, dialog } = useConfirmAction();
  const [saved, setSaved] = useState<RegistrySettings | null>(null);
  const [draft, setDraft] = useState<RegistrySettings | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    getJson<RegistrySettings>(`${API}/settings`).then(
      (value) => {
        const next = normalizeSettings(value);
        setSaved(next);
        setDraft(next);
        setError(null);
      },
      (caught) => setError(caught)
    );
  }, []);
  useEffect(() => load(), [load]);

  const dirty = useMemo(() => Boolean(saved && draft && JSON.stringify(saved) !== JSON.stringify(draft)), [saved, draft]);
  const update = (id: string, patch: Partial<Upstream>) =>
    setDraft((current) => current && { ...current, upstreams: current.upstreams.map((item) => (item.id === id ? { ...item, ...patch } : item)) });

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    setSaveError(null);
    try {
      const result = await mutateJson<RegistrySettings>(`${API}/settings`, { method: "PUT", body: draft });
      const next = normalizeSettings(result ?? draft);
      setSaved(next);
      setDraft(next);
      notify(T.saved);
    } catch (caught) {
      setSaveError(caught);
    } finally {
      setSaving(false);
    }
  };

  const toggleAnonymous = async (checked: boolean) => {
    if (checked && !(await ask({ title: pick(language, T.anonymous), body: pick(language, T.anonymousWarning), severity: "disruptive" }))) return;
    setDraft((current) => current && { ...current, anonymous_pull: checked });
  };

  const addSource = () =>
    setDraft((current) => current && {
      ...current,
      upstreams: [...current.upstreams, { id: `new-${Date.now()}`, name: pick(language, T.newSource), destination: "/", urls: [], enabled: true }]
    });

  if (error) return <SectionCard title={pick(language, T.settingsTitle)}><FriendlyError error={error} onRetry={load} /></SectionCard>;
  if (!draft) return null;
  const disabled = !canWrite || saving;
  return (
    <SectionCard title={pick(language, T.settingsTitle)} hint={pick(language, T.settingsHint)} action={isAdvanced && canWrite ? <Button startIcon={<AddRoundedIcon />} onClick={addSource}>{pick(language, T.addSource)}</Button> : undefined}>
      <Stack spacing={2}>
        <Box>
          <FormControlLabel
            control={<Switch checked={draft.anonymous_pull} disabled={disabled} onChange={(event) => void toggleAnonymous(event.target.checked)} />}
            label={pick(language, T.anonymous)}
          />
          <Typography variant="caption" color="text.secondary" component="p">{pick(language, T.anonymousHint)}</Typography>
          {draft.anonymous_pull && <Box sx={{ mt: 1 }}><Notice tone="warning">{pick(language, T.anonymousWarning)}</Notice></Box>}
        </Box>
        {draft.upstreams.length === 0 ? (
          <EmptyState
            compact
            icon={LayersRoundedIcon}
            title={pick(language, T.emptySources)}
            body={pick(language, T.emptySourcesBody)}
            action={canWrite ? <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={addSource}>{pick(language, T.addSource)}</Button> : undefined}
          />
        ) : draft.upstreams.map((source) => (
          <UpstreamEditor
            key={source.id}
            source={source}
            disabled={disabled}
            onChange={(patch) => update(source.id, patch)}
            onRemove={isAdvanced ? () => setDraft((current) => current && { ...current, upstreams: current.upstreams.filter((item) => item.id !== source.id) }) : undefined}
          />
        ))}
        {saveError ? <FriendlyError error={saveError} onClose={() => setSaveError(null)} /> : null}
        {canWrite && (
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <Button variant="contained" disabled={!dirty || saving} onClick={() => void save()} startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
              {saving ? c.saving : pick(language, T.saveSettings)}
            </Button>
            {dirty && <Button disabled={saving} onClick={() => setDraft(saved)} sx={{ minHeight: 44 }}>{pick(language, T.discard)}</Button>}
            {dirty && <Typography variant="body2" color="text.secondary">{pick(language, T.unsaved)}</Typography>}
          </Stack>
        )}
      </Stack>
      {dialog}
    </SectionCard>
  );
}

function UpstreamEditor({ source, disabled, onChange, onRemove }: { source: Upstream; disabled: boolean; onChange: (patch: Partial<Upstream>) => void; onRemove?: () => void }) {
  const { language, isAdvanced } = useKit();
  const moveUp = (index: number) => {
    if (index <= 0) return;
    const urls = [...source.urls];
    [urls[index - 1], urls[index]] = [urls[index], urls[index - 1]];
    onChange({ urls });
  };
  return (
    <Box sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: 2, opacity: source.enabled ? 1 : 0.75 }}>
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          {isAdvanced && !disabled ? (
            <TextField size="small" label={pick(language, T.sourceName)} value={source.name} onChange={(event) => onChange({ name: event.target.value })} sx={{ flex: 1, minWidth: 180 }} />
          ) : (
            <Typography variant="subtitle1" sx={{ fontWeight: 700, flex: 1 }}>{source.name || "—"}</Typography>
          )}
          <FormControlLabel control={<Switch checked={source.enabled} disabled={disabled} onChange={(event) => onChange({ enabled: event.target.checked })} />} label={pick(language, T.sourceOn)} />
          {onRemove && !disabled && (
            <IconButton aria-label={pick(language, T.removeSource)} onClick={onRemove} sx={{ width: 44, height: 44 }}><DeleteOutlineRoundedIcon /></IconButton>
          )}
        </Stack>
        {isAdvanced && (
          disabled ? (
            <Typography variant="body2" color="text.secondary">{pick(language, T.destination)}: <Ltr mono>{source.destination}</Ltr></Typography>
          ) : (
            <TextField size="small" label={pick(language, T.destination)} value={source.destination} onChange={(event) => onChange({ destination: event.target.value.trim() })} slotProps={{ htmlInput: { dir: "ltr" } }} sx={{ maxWidth: 320 }} />
          )
        )}
        <ListInput
          label={pick(language, T.addresses)}
          value={source.urls}
          onChange={(urls) => onChange({ urls })}
          validate={(item) => (URL_RE.test(item) ? null : pick(language, T.urlRule))}
          helperText={pick(language, T.addressesHelp)}
          placeholder="https://registry-1.docker.io"
          disabled={disabled}
        />
        {source.urls.length === 0 ? (
          <Typography variant="body2" color="warning.main">{pick(language, T.noAddresses)}</Typography>
        ) : source.urls.length > 1 ? (
          <Box>
            <Typography variant="caption" color="text.secondary">{pick(language, T.tryOrder)}</Typography>
            <Stack component="ol" spacing={0.5} sx={{ m: 0, ps: 3 }}>
              {source.urls.map((url, index) => (
                <Box component="li" key={url}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Box sx={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}><Ltr mono>{url}</Ltr></Box>
                    <Chip size="small" variant="outlined" label={pick(language, index === 0 ? T.first : T.fallback)} />
                    {index > 0 && !disabled && (
                      <IconButton size="small" aria-label={say(language, T.moveUp, { name: url })} onClick={() => moveUp(index)}><ArrowUpwardRoundedIcon fontSize="small" /></IconButton>
                    )}
                  </Stack>
                </Box>
              ))}
            </Stack>
          </Box>
        ) : null}
      </Stack>
    </Box>
  );
}

// ── Images ───────────────────────────────────────────────────────────────────

function ImagesSection({ endpoint }: { endpoint: string | null }) {
  const { language, c } = useKit();
  const [rows, setRows] = useState<ImageRepo[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(() => {
    getJson<{ items?: ImageRepo[] }>(`${API}/repos`).then(
      (value) => {
        setRows(value?.items ?? []);
        setError(null);
      },
      (caught) => setError(caught)
    );
  }, []);
  useEffect(() => load(), [load]);

  return (
    <SectionCard
      title={pick(language, T.imagesTitle)}
      hint={pick(language, T.imagesHint)}
      action={<Button startIcon={<RefreshRoundedIcon />} onClick={load}>{c.refresh}</Button>}
    >
      {error ? <FriendlyError error={error} onRetry={load} /> : rows === null ? null : (
        <ResponsiveList<ImageRepo>
          label={pick(language, T.imagesTitle)}
          rows={rows}
          rowKey={(row) => row.name}
          onRowClick={(row) => setOpen(row.name)}
          columns={[
            { key: "name", header: pick(language, T.colImage), render: (row) => <Ltr mono>{row.name}</Ltr> },
            { key: "tags", header: pick(language, T.colTags), render: (row) => (typeof row.tags === "number" ? <Num value={row.tags} /> : "—") }
          ]}
          card={{ title: (row) => <Ltr mono>{row.name}</Ltr>, meta: (row) => (typeof row.tags === "number" ? <>{pick(language, T.colTags)}: <Num value={row.tags} /></> : null) }}
          actions={[{ key: "tags", label: pick(language, T.showTags), icon: LocalOfferRoundedIcon, onClick: (row) => setOpen(row.name) }]}
          empty={<EmptyState compact icon={LayersRoundedIcon} title={pick(language, T.emptyImages)} body={pick(language, T.emptyImagesBody)} action={<Button onClick={load}>{c.refresh}</Button>} />}
        />
      )}
      {open && <TagsDialog name={open} endpoint={endpoint} onClose={() => setOpen(null)} />}
    </SectionCard>
  );
}

function TagsDialog({ name, endpoint, onClose }: { name: string; endpoint: string | null; onClose: () => void }) {
  const { language, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [tags, setTags] = useState<string[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => {
    setError(null);
    getJson<{ tags?: string[] }>(`${API}/repos/${encodePath(name)}/tags`).then((value) => setTags(value?.tags ?? []), setError);
  }, [name]);
  useEffect(() => load(), [load]);
  const image = endpoint ? `${endpoint}/${name}` : name;
  return (
    <Dialog open onClose={onClose} fullScreen={fullScreen} fullWidth maxWidth="sm">
      <DialogTitle sx={{ fontWeight: 760 }}>{say(language, T.tagsTitle, { name })}</DialogTitle>
      <DialogContent>
        {error ? <FriendlyError error={error} onRetry={load} /> : tags === null ? (
          <Box sx={{ display: "grid", placeItems: "center", py: 4 }}><CircularProgress size={28} aria-hidden /></Box>
        ) : tags.length === 0 ? (
          <Typography color="text.secondary">{pick(language, T.noTags)}</Typography>
        ) : (
          <Stack spacing={1.5} sx={{ pt: 1 }}>
            {tags.map((tag) => <CopyField key={tag} label={`${pick(language, T.pullCommand)} · ${tag}`} value={`docker pull ${image}:${tag}`} />)}
          </Stack>
        )}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ minHeight: 44 }}>{c.close}</Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Users ────────────────────────────────────────────────────────────────────

function UsersSection({ canWrite, endpoint, notify }: { canWrite: boolean; endpoint: string | null; notify: Notify }) {
  const { language } = useKit();
  const { ask, dialog } = useConfirmAction();
  const [rows, setRows] = useState<RegistryUser[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [access, setAccess] = useState<"pull" | "push">("pull");
  const [secret, setSecret] = useState<{ name: string; password: string } | null>(null);

  const load = useCallback(() => {
    getJson<{ items?: RegistryUser[] }>(`${API}/users`).then(
      (value) => {
        setRows(value?.items ?? []);
        setError(null);
      },
      (caught) => setError(caught)
    );
  }, []);
  useEffect(() => load(), [load]);

  const start = () => {
    setName("");
    setAccess("pull");
    setOpen(true);
  };

  const remove = async (row: RegistryUser) => {
    const ok = await ask({ title: say(language, T.removeTitle, { name: row.name }), body: pick(language, T.removeBody), severity: "destructive", undoable: false });
    if (!ok) return;
    setActionError(null);
    try {
      await mutateJson(`${API}/users/${encodeURIComponent(row.name)}`, { method: "DELETE" });
      notify(T.removed, row.name);
      load();
    } catch (caught) {
      setActionError(caught);
    }
  };

  const accessLabel = (value: string) => pick(language, value === "push" ? T.accessPush : T.accessPull);
  return (
    <SectionCard
      title={pick(language, T.usersTitle)}
      hint={pick(language, T.usersHint)}
      action={canWrite ? <Button variant="outlined" startIcon={<PersonAddRoundedIcon />} onClick={start}>{pick(language, T.newUser)}</Button> : undefined}
      collapsible
    >
      {actionError ? <Box sx={{ mb: 1.5 }}><FriendlyError error={actionError} onClose={() => setActionError(null)} /></Box> : null}
      {error ? <FriendlyError error={error} onRetry={load} /> : rows === null ? null : (
        <ResponsiveList<RegistryUser>
          label={pick(language, T.usersTitle)}
          rows={rows}
          rowKey={(row) => row.name}
          columns={[
            { key: "name", header: pick(language, T.colName), render: (row) => <Ltr>{row.name}</Ltr> },
            { key: "access", header: pick(language, T.colAccess), render: (row) => accessLabel(row.access) },
            { key: "created", header: pick(language, T.colCreated), render: (row) => <RelativeTime value={row.created_at} /> }
          ]}
          card={{ title: (row) => <Ltr>{row.name}</Ltr>, meta: (row) => <RelativeTime value={row.created_at} />, status: (row) => <StatusPill tone={row.access === "push" ? "warn" : "ok"} label={accessLabel(row.access)} /> }}
          actions={canWrite ? [{ key: "delete", label: pick(language, T.removeUser), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (row) => void remove(row) }] : undefined}
          empty={<EmptyState compact title={pick(language, T.emptyUsers)} body={pick(language, T.emptyUsersBody)} action={canWrite ? <Button variant="contained" onClick={start}>{pick(language, T.newUser)}</Button> : undefined} />}
        />
      )}
      <ActionWizard
        open={open}
        title={pick(language, T.newUser)}
        finishLabel={pick(language, T.createUser)}
        onClose={() => setOpen(false)}
        steps={[
          {
            key: "details",
            title: pick(language, T.userStep),
            hint: pick(language, T.userStepHint),
            validate: () => (USER_RE.test(name.trim()) ? null : pick(language, T.nameRule)),
            render: () => (
              <Stack spacing={2}>
                <TextField autoFocus label={pick(language, T.colName)} value={name} onChange={(event) => setName(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", autoComplete: "off" } }} fullWidth />
                <TextField
                  select
                  label={pick(language, T.colAccess)}
                  value={access}
                  onChange={(event) => setAccess(event.target.value === "push" ? "push" : "pull")}
                  helperText={pick(language, access === "push" ? T.accessPushHint : T.accessPullHint)}
                  fullWidth
                >
                  <MenuItem value="pull">{pick(language, T.accessPull)}</MenuItem>
                  <MenuItem value="push">{pick(language, T.accessPush)}</MenuItem>
                </TextField>
              </Stack>
            )
          }
        ]}
        onFinish={async () => {
          const result = await mutateJson<{ name?: string; access?: string; password?: string }>(`${API}/users`, { method: "POST", body: { name: name.trim(), access } });
          const created = result?.name ?? name.trim();
          if (result?.password) setSecret({ name: created, password: result.password });
          else notify(T.secretTitle, created);
          load();
        }}
      />
      <OneTimeSecret
        open={secret !== null}
        title={say(language, T.secretTitle, { name: secret?.name ?? "" })}
        body={pick(language, T.secretBody)}
        items={secret ? [
          { label: pick(language, T.colName), value: secret.name, ltr: true },
          { label: pick(language, T.password), value: secret.password, ltr: true },
          ...(endpoint ? [{ label: pick(language, T.loginCommand), value: `docker login ${endpoint} -u ${secret.name}`, ltr: true }] : [])
        ] : []}
        onClose={() => setSecret(null)}
      />
      {dialog}
    </SectionCard>
  );
}
