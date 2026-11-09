/**
 * «انتقال و همگام‌سازی» of one domain (contract docs/41 §2.1–§2.4, §7; Advanced).
 *
 * - Secondary domains: where the copy comes from (main servers, key, who may announce changes),
 *   the copy's state (serial, last success, next check, when it runs out) and «همین حالا بگیر».
 * - Primary domains: who may copy this domain (transfer), whom to tell after each change (NOTIFY),
 *   and changes from other programs (dynamic update, RFC 2136).
 * - TSIG keys used by all of the above (dns:admin); the secret is shown once.
 */
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Box, Button, CircularProgress, FormControlLabel, MenuItem, Stack, Switch, TextField, Typography } from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import SyncRoundedIcon from "@mui/icons-material/SyncRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import { hasPermission } from "./api";
import { errorSentence, pick, say, type Bi } from "./copy";
import {
  EmptyState, FriendlyError, KeyValueList, ListInput, Ltr, NoAccess, Notice, OneTimeSecret, RelativeTime, ResponsiveList, SectionCard, StatusPill,
  useConfirmAction, useKit, useUndoSnackbar, type ListColumn, type RowAction
} from "./kit";
import { isCidr, patchZone, type DnsZone } from "./dns";
import {
  DEFAULT_NOTIFY, DEFAULT_TRANSFER, DEFAULT_UPDATE, TSIG_ALGORITHMS, createTsigKey, deleteTsigKey, fetchTsigKeys, fetchZoneDetail, isHostPort,
  refreshSecondary, toTime, type TsigKey, type ZoneNotify, type ZoneSecondaryStatus, type ZoneTransfer, type ZoneUpdate
} from "./dnsFinal";
import { FormDialog, Loading, isMissingEndpoint, ltrInput, useList, useLoader } from "./dnsUi";

const COPY = {
  // secondary
  copyTitle: { fa: "نسخه دوم", en: "Copy" },
  copyHint: { fa: "پیشکار رکوردهای این دامنه را از سرور اصلی می‌گیرد و خودکار به‌روز نگه می‌دارد.", en: "Pishkar takes this domain's records from the main server and keeps them up to date by itself." },
  copyOk: { fa: "به‌روز است", en: "Up to date" },
  copyFailing: { fa: "گرفتن نسخه انجام نشد", en: "Copying failed" },
  copyExpired: { fa: "نسخه از اعتبار افتاده", en: "The copy ran out" },
  copyWaiting: { fa: "هنوز گرفته نشده", en: "Not copied yet" },
  copyExpiredBody: { fa: "مدتی است سرور اصلی جواب نمی‌دهد و نسخه از اعتبار افتاده؛ تا درست نشود، پیشکار برای این دامنه جواب خطا می‌دهد.", en: "The main server hasn't answered for a while and the copy ran out; until it's fixed, Pishkar answers this domain with an error." },
  serial: { fa: "شماره نسخه", en: "Serial" },
  lastSuccess: { fa: "آخرین گرفتن موفق", en: "Last good copy" },
  lastTry: { fa: "آخرین تلاش", en: "Last try" },
  nextRefresh: { fa: "بررسی بعدی", en: "Next check" },
  expiresAt: { fa: "اعتبار نسخه تا", en: "Copy valid until" },
  problem: { fa: "مشکل", en: "Problem" },
  refreshNow: { fa: "همین حالا بگیر", en: "Copy now" },
  refreshed: { fa: "درخواست گرفتن نسخه تازه فرستاده شد.", en: "Asked for a fresh copy." },
  sourceTitle: { fa: "از کجا گرفته شود", en: "Where to copy from" },
  sourceHint: { fa: "سرورهای اصلی و کلیدی که برای گرفتن نسخه لازم است.", en: "The main servers and the key needed to copy." },
  primaries: { fa: "سرورهای اصلی", en: "Main servers" },
  primariesHint: { fa: "مثل 203.0.113.5 یا 203.0.113.5:53", en: "Like 203.0.113.5 or 203.0.113.5:53" },
  notifyAllow: { fa: "چه کسانی می‌توانند خبر تغییر بدهند", en: "Who may announce changes" },
  notifyAllowHint: { fa: "جز سرورهای اصلی؛ مثل 10.0.0.0/8", en: "Besides the main servers; like 10.0.0.0/8" },
  // primary
  transferTitle: { fa: "چه کسانی می‌توانند این دامنه را کپی کنند", en: "Who may copy this domain" },
  transferHint: { fa: "سرورهای DNS دوم (مثلاً یک سرور پشتیبان) از این محدوده‌ها همه رکوردها را می‌گیرند. خالی = هیچ‌کس (امن‌ترین).", en: "Second DNS servers (like a backup server) in these ranges get every record. Empty = nobody (safest)." },
  transferAllow: { fa: "محدوده‌های مجاز", en: "Allowed ranges" },
  rangeHint: { fa: "مثل 203.0.113.0/24 یا 198.51.100.7/32", en: "Like 203.0.113.0/24 or 198.51.100.7/32" },
  transferClosed: { fa: "بسته؛ هیچ سروری نمی‌تواند کپی بگیرد.", en: "Closed; no server can copy it." },
  notifyTitle: { fa: "خبر دادن بعد از هر تغییر", en: "Announce each change" },
  notifyHint: { fa: "بعد از هر تغییر، پیشکار به این سرورها خبر می‌دهد تا همان لحظه نسخه تازه بگیرند.", en: "After each change, Pishkar tells these servers so they copy the new version right away." },
  notifyOn: { fa: "خبر بده", en: "Announce changes" },
  notifyTargets: { fa: "سرورهایی که خبر می‌گیرند", en: "Servers to tell" },
  updateTitle: { fa: "تغییر از برنامه‌های دیگر", en: "Changes from other programs" },
  updateHint: { fa: "برنامه‌هایی مثل گرفتن خودکار گواهی یا پخش خودکار نشانی در شبکه می‌توانند رکوردها را خودشان تغییر دهند. هر تغییر در «تاریخچه» می‌ماند.", en: "Programs like automatic certificates or DHCP can change records themselves. Every change stays in History." },
  updateOn: { fa: "اجازه تغییر بده", en: "Allow changes" },
  updateAllow: { fa: "از این محدوده‌ها", en: "From these ranges" },
  requireTsig: { fa: "فقط با کلید امضا (پیشنهادی)", en: "Only with a signing key (recommended)" },
  requireTsigOff: { fa: "بدون کلید، هر دستگاهی در این محدوده‌ها می‌تواند رکوردها را تغییر دهد. فقط در شبکه‌ای که کاملاً به آن اعتماد دارید.", en: "Without a key, any device in these ranges can change records. Only on a network you fully trust." },
  updateOpenNoRange: { fa: "دست‌کم یک محدوده یا یک کلید بدهید؛ وگرنه هیچ تغییری پذیرفته نمی‌شود.", en: "Give at least one range or a key; otherwise no change is accepted." },
  tsigKey: { fa: "کلید امضا (TSIG)", en: "Signing key (TSIG)" },
  targetsNeeded: { fa: "دست‌کم یک سرور بنویسید یا خبر دادن را خاموش کنید.", en: "Write at least one server, or turn announcing off." },
  keyNeeded: { fa: "برای «فقط با کلید امضا» یک کلید انتخاب کنید (یا آن را در کارت پایین بسازید).", en: "For “Only with a signing key”, pick a key (or make one in the card below)." },
  tsigNone: { fa: "بدون کلید", en: "No key" },
  save: { fa: "ذخیره", en: "Save" },
  saved: { fa: "ذخیره شد و همین حالا اعمال شد.", en: "Saved and applied right away." },
  badRange: { fa: "محدوده را مثل 203.0.113.0/24 بنویسید.", en: "Write the range like 203.0.113.0/24." },
  badHostPort: { fa: "نشانی را مثل 203.0.113.5 یا 203.0.113.5:53 بنویسید.", en: "Write the address like 203.0.113.5 or 203.0.113.5:53." },
  primariesNeeded: { fa: "دست‌کم یک سرور اصلی لازم است.", en: "At least one main server is needed." },
  loadFailed: { fa: "تنظیمات انتقال این دامنه خوانده نشد.", en: "This domain's transfer settings didn't load." },
  notSupported: { fa: "برنامه DNS روی سرور هنوز این بخش را ندارد. آن را به‌روز کنید.", en: "The DNS program on the server doesn't have this yet. Update it." },
  // tsig
  tsigTitle: { fa: "کلیدهای امضای انتقال (TSIG)", en: "Transfer signing keys (TSIG)" },
  tsigHint: { fa: "یک رمز مشترک بین دو سرور تا فقط سرور واقعی بتواند کپی بگیرد، خبر بدهد یا رکورد تغییر دهد. برای همه دامنه‌ها مشترک است.", en: "A shared secret between two servers so only the real server can copy, announce or change records. Shared by all domains." },
  addKey: { fa: "ساخت کلید", en: "Make a key" },
  emptyKeys: { fa: "هنوز کلیدی نساخته‌اید", en: "No keys yet" },
  emptyKeysBody: { fa: "برای انتقال امن بین دو سرور یک کلید بسازید و همان را روی سرور دیگر هم بگذارید.", en: "Make a key for safe transfers between two servers and put the same one on the other server." },
  keyName: { fa: "نام کلید", en: "Key name" },
  keyNameHint: { fa: "مثل «transfer-key»؛ روی هر دو سرور باید یکسان باشد.", en: "Like transfer-key; it must be the same on both servers." },
  badKeyName: { fa: "فقط حروف انگلیسی، عدد، نقطه و خط تیره؛ مثل «transfer-key»", en: "Letters, digits, dots and dashes only; like transfer-key" },
  algorithm: { fa: "نوع رمز", en: "Algorithm" },
  ownSecret: { fa: "رمز آماده دارم (اختیاری)", en: "I have a secret already (optional)" },
  ownSecretHint: { fa: "اگر سرور دیگر رمز را ساخته، همان را بگذارید؛ وگرنه خالی بگذارید تا پیشکار یک رمز قوی بسازد.", en: "If the other server made the secret, paste it; otherwise leave it empty and Pishkar makes a strong one." },
  makeKey: { fa: "ساخت کلید", en: "Make key" },
  keyMade: { fa: "کلید «{name}» ساخته شد", en: "The key “{name}” was made" },
  keyMadeBody: { fa: "این رمز را روی سرور دیگر هم بگذارید. بعد از بستن این پنجره دیگر نمایش داده نمی‌شود.", en: "Put this secret on the other server too. It won't be shown again after you close this window." },
  secret: { fa: "رمز", en: "Secret" },
  configSnippet: { fa: "تنظیم آماده برای سرور دیگر", en: "Ready setting for the other server" },
  removeKey: { fa: "پاک کردن", en: "Delete" },
  removeKeyTitle: { fa: "کلید «{name}» پاک شود؟", en: "Delete the key “{name}”?" },
  removeKeyBody: { fa: "هر دامنه‌ای که از این کلید استفاده می‌کند دیگر نمی‌تواند با آن کپی بگیرد یا تغییر بپذیرد.", en: "Every domain using this key can no longer copy or accept changes with it." },
  keyRemoved: { fa: "کلید «{name}» پاک شد.", en: "The key “{name}” was deleted." },
  keysFailed: { fa: "فهرست کلیدها خوانده نشد.", en: "The list of keys didn't load." },
  colName: { fa: "نام", en: "Name" },
  colAlgorithm: { fa: "نوع رمز", en: "Algorithm" },
  colCreated: { fa: "ساخته شده", en: "Made" }
} satisfies Record<string, Bi>;

const rangeProblem = (language: "fa" | "en") => (value: string) => (isCidr(value) ? null : pick(language, COPY.badRange));
const hostPortProblem = (language: "fa" | "en") => (value: string) => (isHostPort(value) ? null : pick(language, COPY.badHostPort));

/** The copy's state in one pill. */
export function secondaryState(status: ZoneSecondaryStatus | null | undefined): { tone: "ok" | "warn" | "error" | "off"; label: Bi } {
  if (!status) return { tone: "off", label: COPY.copyWaiting };
  const expires = toTime(status.expires_at);
  if (status.expired || status.state === "expired" || (typeof expires === "number" && expires < Date.now())) return { tone: "error", label: COPY.copyExpired };
  if (status.error) return { tone: "warn", label: COPY.copyFailing };
  if (!status.last_success) return { tone: "off", label: COPY.copyWaiting };
  return { tone: "ok", label: COPY.copyOk };
}

export function SecondaryStatusCard({ zone, canWrite, onRefreshed }: { zone: DnsZone; canWrite: boolean; onRefreshed: () => void }) {
  const { language } = useKit();
  const loader = useCallback((signal: AbortSignal) => fetchZoneDetail(zone.name, signal), [zone.name]);
  const { data, error, reload } = useLoader<DnsZone>(loader);
  const [busy, setBusy] = useState(false);
  const { notify, snackbar } = useUndoSnackbar();
  const status = data?.secondary ?? zone.secondary ?? null;
  const state = secondaryState(status);
  const when = (value: number | string | null | undefined) => (value ? <RelativeTime value={toTime(value)} /> : "—");

  const refresh = async () => {
    setBusy(true);
    try {
      await refreshSecondary(zone.name);
      notify({ message: pick(language, COPY.refreshed), tone: "success" });
      window.setTimeout(() => { void reload(); onRefreshed(); }, 1_500);
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard
      title={pick(language, COPY.copyTitle)}
      hint={pick(language, COPY.copyHint)}
      status={<StatusPill tone={state.tone} label={pick(language, state.label)} />}
      action={canWrite ? (
        <Button variant="outlined" startIcon={busy ? <CircularProgress size={14} /> : <SyncRoundedIcon />} disabled={busy} onClick={() => void refresh()} sx={{ minHeight: 44 }}>
          {pick(language, COPY.refreshNow)}
        </Button>
      ) : undefined}
    >
      <Stack spacing={1.5}>
        {state.tone === "error" ? <Notice tone="error">{pick(language, COPY.copyExpiredBody)}</Notice> : null}
        {error && !data ? <FriendlyError error={error} onRetry={() => void reload()} severity="warning" /> : null}
        <KeyValueList
          items={[
            { label: pick(language, COPY.lastSuccess), value: when(status?.last_success) },
            { label: pick(language, COPY.nextRefresh), value: when(status?.next_refresh) },
            { label: pick(language, COPY.expiresAt), value: when(status?.expires_at) },
            ...(typeof status?.serial === "number" ? [{ label: pick(language, COPY.serial), value: String(status.serial), ltr: true }] : []),
            ...(status?.last_refresh ? [{ label: pick(language, COPY.lastTry), value: when(status.last_refresh) }] : []),
            ...(status?.error ? [{ label: pick(language, COPY.problem), value: <Ltr mono>{status.error}</Ltr> }] : [])
          ]}
        />
      </Stack>
      {snackbar}
    </SectionCard>
  );
}

/** One card that edits one part of the zone and saves it with PATCH. */
function ZonePartCard<T extends object>({ title, hint, initial, canWrite, validate, onSave, children }: {
  title: string; hint: string; initial: T; canWrite: boolean; validate?: (draft: T) => string | null;
  onSave: (draft: T) => Promise<void>; children: (draft: T, set: (next: T) => void) => ReactNode;
}) {
  const { language } = useKit();
  const [draft, setDraft] = useState<T>(initial);
  const [saved, setSaved] = useState<T>(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const { notify, snackbar } = useUndoSnackbar();
  const initialKey = JSON.stringify(initial);
  useEffect(() => {
    setDraft(JSON.parse(initialKey) as T);
    setSaved(JSON.parse(initialKey) as T);
  }, [initialKey]);
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved);
  const problem = validate?.(draft) ?? null;
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSave(draft);
      setSaved(draft);
      notify({ message: pick(language, COPY.saved), tone: "success" });
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };
  return (
    <SectionCard title={title} hint={hint}>
      <Stack spacing={2}>
        <Box component="fieldset" disabled={!canWrite || busy} sx={{ border: 0, p: 0, m: 0, minWidth: 0 }}>
          <Stack spacing={2}>{children(draft, setDraft)}</Stack>
        </Box>
        {problem && dirty ? <Typography variant="body2" color="warning.main">{problem}</Typography> : null}
        {error ? <FriendlyError error={error} scope="dns" onClose={() => setError(null)} /> : null}
        {canWrite && dirty ? (
          <Stack direction="row" gap={1} justifyContent="flex-end">
            <Button onClick={() => setDraft(saved)} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, { fa: "دور انداختن تغییرات", en: "Discard changes" })}</Button>
            <Button variant="contained" onClick={() => void save()} disabled={busy || Boolean(problem)} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>{pick(language, COPY.save)}</Button>
          </Stack>
        ) : null}
      </Stack>
      {snackbar}
    </SectionCard>
  );
}

function TsigSelect({ value, onChange, keys }: { value: string | null | undefined; onChange: (value: string | null) => void; keys: string[] }) {
  const { language } = useKit();
  const current = value ?? "";
  return (
    <TextField select size="small" label={pick(language, COPY.tsigKey)} value={current} onChange={(event) => onChange(event.target.value || null)} fullWidth>
      <MenuItem value="">{pick(language, COPY.tsigNone)}</MenuItem>
      {keys.map((key) => <MenuItem key={key} value={key}><Ltr mono>{key}</Ltr></MenuItem>)}
      {current && !keys.includes(current) ? <MenuItem value={current}><Ltr mono>{current}</Ltr></MenuItem> : null}
    </TextField>
  );
}

function SwitchLine({ label, checked, onChange, color }: { label: string; checked: boolean; onChange: (value: boolean) => void; color?: "warning" }) {
  return <FormControlLabel control={<Switch checked={checked} color={color} onChange={(event) => onChange(event.target.checked)} />} label={label} />;
}

// ── TSIG keys ────────────────────────────────────────────────────────────────

const KEY_NAME = /^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/i;

function snippet(key: TsigKey): string {
  return `key "${key.name}" {\n  algorithm ${key.algorithm ?? "hmac-sha256"};\n  secret "${key.secret ?? ""}";\n};`;
}

function TsigDialog({ onClose, onMade }: { onClose: () => void; onMade: (key: TsigKey) => void }) {
  const { language } = useKit();
  const [name, setName] = useState("");
  const [algorithm, setAlgorithm] = useState<string>("hmac-sha256");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const clean = name.trim();
  const problem = clean && !KEY_NAME.test(clean) ? pick(language, COPY.badKeyName) : null;
  const save = async () => {
    if (!clean || problem) return;
    setBusy(true);
    setError(null);
    try {
      const made = await createTsigKey({ name: clean, algorithm, ...(secret.trim() ? { secret: secret.trim() } : {}) });
      onMade({ algorithm, ...(made ?? {}), name: made?.name ?? clean, secret: made?.secret ?? (secret.trim() || null) });
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };
  return (
    <FormDialog title={pick(language, COPY.addKey)} hint={pick(language, COPY.tsigHint)} submitLabel={pick(language, COPY.makeKey)} busy={busy} error={error} disabled={!clean || Boolean(problem)} onSubmit={() => void save()} onClose={onClose}>
      <TextField label={pick(language, COPY.keyName)} value={name} onChange={(event) => setName(event.target.value)} error={Boolean(problem)} helperText={problem ?? pick(language, COPY.keyNameHint)} autoFocus fullWidth slotProps={ltrInput} />
      <TextField select label={pick(language, COPY.algorithm)} value={algorithm} onChange={(event) => setAlgorithm(event.target.value)} fullWidth>
        {TSIG_ALGORITHMS.map((item) => <MenuItem key={item} value={item}><Ltr mono>{item}</Ltr></MenuItem>)}
      </TextField>
      <TextField label={pick(language, COPY.ownSecret)} value={secret} onChange={(event) => setSecret(event.target.value)} helperText={pick(language, COPY.ownSecretHint)} fullWidth slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoComplete: "off" } }} />
    </FormDialog>
  );
}

export function TsigKeysCard({ permissions }: { permissions: readonly string[] }) {
  const { language } = useKit();
  const canAdmin = hasPermission(permissions, "dns:admin");
  const loader = useCallback((signal: AbortSignal) => fetchTsigKeys(signal), []);
  const { items, error, loading, reload } = useList<TsigKey>(loader);
  const [creating, setCreating] = useState<number | null>(null);
  const [made, setMade] = useState<TsigKey | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const rows = items ?? [];

  const remove = async (key: TsigKey) => {
    const ok = await ask({ title: say(language, COPY.removeKeyTitle, { name: key.name }), body: pick(language, COPY.removeKeyBody), severity: "destructive", confirmLabel: pick(language, COPY.removeKey) });
    if (!ok) return;
    try {
      await deleteTsigKey(key.name);
      notify({ message: say(language, COPY.keyRemoved, { name: key.name }), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
    void reload();
  };

  const columns: ListColumn<TsigKey>[] = [
    { key: "name", header: pick(language, COPY.colName), hideOnCard: true, render: (row) => <Ltr mono>{row.name}</Ltr> },
    { key: "algorithm", header: pick(language, COPY.colAlgorithm), render: (row) => <Ltr mono>{row.algorithm ?? "—"}</Ltr> },
    { key: "created", header: pick(language, COPY.colCreated), render: (row) => (row.created_at ? <RelativeTime value={toTime(row.created_at)} /> : "—") }
  ];
  const actions: RowAction<TsigKey>[] = canAdmin ? [{ key: "delete", label: pick(language, COPY.removeKey), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (row) => void remove(row) }] : [];
  const addButton = canAdmin ? (
    <Button variant={rows.length ? "outlined" : "contained"} startIcon={<AddRoundedIcon />} onClick={() => setCreating(Date.now())} sx={{ minHeight: 44 }}>{pick(language, COPY.addKey)}</Button>
  ) : null;

  return (
    <SectionCard title={pick(language, COPY.tsigTitle)} hint={pick(language, COPY.tsigHint)} action={rows.length ? addButton : undefined}>
      <Stack spacing={2}>
        {error && !items ? (isMissingEndpoint(error) ? <Notice tone="info">{pick(language, COPY.notSupported)}</Notice> : <FriendlyError error={error} title={pick(language, COPY.keysFailed)} onRetry={() => void reload()} />) : null}
        {items === null && loading ? <Loading /> : null}
        {items !== null ? (
          <ResponsiveList
            rows={rows}
            rowKey={(row) => row.name}
            columns={columns}
            label={pick(language, COPY.tsigTitle)}
            card={{ title: (row) => <Ltr mono>{row.name}</Ltr>, meta: (row) => <Ltr mono>{row.algorithm ?? ""}</Ltr> }}
            actions={actions}
            empty={<EmptyState compact icon={KeyRoundedIcon} title={pick(language, COPY.emptyKeys)} body={pick(language, COPY.emptyKeysBody)} action={addButton} />}
          />
        ) : null}
        {!canAdmin ? <NoAccess needs="dns:admin" /> : null}
      </Stack>
      {creating ? (
        <TsigDialog
          key={creating}
          onClose={() => setCreating(null)}
          onMade={(key) => {
            setCreating(null);
            setMade(key);
            void reload();
          }}
        />
      ) : null}
      <OneTimeSecret
        open={Boolean(made)}
        title={made ? say(language, COPY.keyMade, { name: made.name }) : ""}
        body={pick(language, COPY.keyMadeBody)}
        items={made?.secret ? [{ label: pick(language, COPY.secret), value: made.secret }, { label: pick(language, COPY.configSnippet), value: snippet(made), multiline: true }] : []}
        onClose={() => setMade(null)}
      />
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

// ── the tab ──────────────────────────────────────────────────────────────────

export function ZoneSyncTab({ zone, permissions, onChanged }: { zone: DnsZone; permissions: readonly string[]; onChanged: () => void }) {
  const { language } = useKit();
  const canWrite = hasPermission(permissions, "dns:write");
  const isSecondary = zone.type === "secondary";
  const loader = useCallback((signal: AbortSignal) => fetchZoneDetail(zone.name, signal), [zone.name]);
  const { data, error, reload } = useLoader<DnsZone>(loader);
  const keysLoader = useCallback((signal: AbortSignal) => fetchTsigKeys(signal).catch(() => [] as TsigKey[]), []);
  const { items: keyItems } = useList<TsigKey>(keysLoader);
  const keys = (keyItems ?? []).map((item) => item.name);
  const detail = data ?? zone;

  const patch = async (body: Parameters<typeof patchZone>[1]) => {
    await patchZone(zone.name, body);
    void reload();
    onChanged();
  };

  if (error && !data && !isMissingEndpoint(error)) return <FriendlyError error={error} title={pick(language, COPY.loadFailed)} onRetry={() => void reload()} />;
  if (!data && !error) return <Loading />;

  return (
    <Stack spacing={2.5}>
      {isSecondary ? (
        <ZonePartCard
          title={pick(language, COPY.sourceTitle)}
          hint={pick(language, COPY.sourceHint)}
          canWrite={canWrite}
          initial={{ primaries: detail.primaries ?? [], tsig_key: detail.tsig_key ?? null, notify_allow: detail.notify_allow ?? [] }}
          validate={(draft) => (draft.primaries.length ? null : pick(language, COPY.primariesNeeded))}
          onSave={(draft) => patch({ primaries: draft.primaries, tsig_key: draft.tsig_key, notify_allow: draft.notify_allow })}
        >
          {(draft, set) => (
            <>
              <ListInput label={pick(language, COPY.primaries)} value={draft.primaries} onChange={(value) => set({ ...draft, primaries: value })} validate={hostPortProblem(language)} helperText={pick(language, COPY.primariesHint)} max={8} />
              <TsigSelect value={draft.tsig_key} onChange={(value) => set({ ...draft, tsig_key: value })} keys={keys} />
              <ListInput label={pick(language, COPY.notifyAllow)} value={draft.notify_allow} onChange={(value) => set({ ...draft, notify_allow: value })} validate={rangeProblem(language)} helperText={pick(language, COPY.notifyAllowHint)} max={16} />
            </>
          )}
        </ZonePartCard>
      ) : (
        <>
          <ZonePartCard<ZoneTransfer>
            title={pick(language, COPY.transferTitle)}
            hint={pick(language, COPY.transferHint)}
            canWrite={canWrite}
            initial={{ ...DEFAULT_TRANSFER, ...(detail.transfer ?? {}) }}
            onSave={(draft) => patch({ transfer: draft })}
          >
            {(draft, set) => (
              <>
                <ListInput label={pick(language, COPY.transferAllow)} value={draft.allow ?? []} onChange={(value) => set({ ...draft, allow: value })} validate={rangeProblem(language)} helperText={pick(language, COPY.rangeHint)} max={32} />
                {!(draft.allow ?? []).length ? <Typography variant="caption" color="text.secondary">{pick(language, COPY.transferClosed)}</Typography> : null}
                <TsigSelect value={draft.tsig_key} onChange={(value) => set({ ...draft, tsig_key: value })} keys={keys} />
              </>
            )}
          </ZonePartCard>
          <ZonePartCard<ZoneNotify>
            title={pick(language, COPY.notifyTitle)}
            hint={pick(language, COPY.notifyHint)}
            canWrite={canWrite}
            initial={{ ...DEFAULT_NOTIFY, ...(detail.notify ?? {}) }}
            validate={(draft) => (draft.enabled && !(draft.targets ?? []).length ? pick(language, COPY.targetsNeeded) : null)}
            onSave={(draft) => patch({ notify: draft })}
          >
            {(draft, set) => (
              <>
                <SwitchLine label={pick(language, COPY.notifyOn)} checked={Boolean(draft.enabled)} onChange={(value) => set({ ...draft, enabled: value })} />
                {draft.enabled ? (
                  <>
                    <ListInput label={pick(language, COPY.notifyTargets)} value={draft.targets ?? []} onChange={(value) => set({ ...draft, targets: value })} validate={hostPortProblem(language)} helperText={pick(language, COPY.primariesHint)} max={16} />
                    <TsigSelect value={draft.tsig_key} onChange={(value) => set({ ...draft, tsig_key: value })} keys={keys} />
                  </>
                ) : null}
              </>
            )}
          </ZonePartCard>
          <ZonePartCard<ZoneUpdate>
            title={pick(language, COPY.updateTitle)}
            hint={pick(language, COPY.updateHint)}
            canWrite={canWrite}
            initial={{ ...DEFAULT_UPDATE, ...(detail.update ?? {}) }}
            validate={(draft) => {
              if (!draft.enabled) return null;
              if (draft.require_tsig !== false && !draft.tsig_key) return pick(language, COPY.keyNeeded);
              return !(draft.allow ?? []).length && !draft.tsig_key ? pick(language, COPY.updateOpenNoRange) : null;
            }}
            onSave={(draft) => patch({ update: draft })}
          >
            {(draft, set) => (
              <>
                <SwitchLine label={pick(language, COPY.updateOn)} checked={Boolean(draft.enabled)} onChange={(value) => set({ ...draft, enabled: value })} />
                {draft.enabled ? (
                  <>
                    <ListInput label={pick(language, COPY.updateAllow)} value={draft.allow ?? []} onChange={(value) => set({ ...draft, allow: value })} validate={rangeProblem(language)} helperText={pick(language, COPY.rangeHint)} max={32} />
                    <TsigSelect value={draft.tsig_key} onChange={(value) => set({ ...draft, tsig_key: value })} keys={keys} />
                    <SwitchLine label={pick(language, COPY.requireTsig)} checked={draft.require_tsig !== false} color="warning" onChange={(value) => set({ ...draft, require_tsig: value })} />
                    {draft.require_tsig === false ? <Notice tone="warning">{pick(language, COPY.requireTsigOff)}</Notice> : null}
                  </>
                ) : null}
              </>
            )}
          </ZonePartCard>
        </>
      )}
      <TsigKeysCard permissions={permissions} />
    </Stack>
  );
}
