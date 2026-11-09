import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Box, Button, CircularProgress, InputAdornment, Stack, TextField, ToggleButton, ToggleButtonGroup, Typography } from "@mui/material";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import PushPinRoundedIcon from "@mui/icons-material/PushPinRounded";
import GppBadRoundedIcon from "@mui/icons-material/GppBadRounded";
import GppGoodRoundedIcon from "@mui/icons-material/GppGoodRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import CloudDownloadRoundedIcon from "@mui/icons-material/CloudDownloadRounded";
import SyncRoundedIcon from "@mui/icons-material/SyncRounded";
import RestoreFromTrashRoundedIcon from "@mui/icons-material/RestoreFromTrashRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { CONFIRM_TOKENS, deleteConfirmation, errorSentence, pick, say, type Bi } from "./copy";
import {
  Bytes, ConfirmAction, EmptyState, FriendlyError, Ltr, NoAccess, Notice, RelativeTime, ResponsiveList, SectionCard, StatusPill,
  useConfirmAction, useKit, useUndoSnackbar
} from "./kit";
import type { Language } from "./i18n";
import { formatBytes, formatNumber } from "./format";

/**
 * Packages › «جست‌وجو و مدیریت» and «پیش‌دریافت» (docs/33 §4.2).
 * Simple: search, keep / stop keeping (undo), remove to the recycle bin, restore from the bin.
 * Advanced: quarantine with a reason, fetch again from the source, file counts, delete forever.
 */

type Ecosystem = "npm" | "pypi";

type PackageRecord = {
  name: string;
  ecosystem: Ecosystem;
  versions: string[];
  artifact_count: number;
  size_bytes: number;
  latest_mtime: number;
  pinned: boolean;
  quarantined: boolean;
  quarantine_reason: string | null;
};

type TrashRecord = { trash_id: string; ecosystem: string; name: string; trashed_at: number; size_bytes: number; expires_at: number | null };

type PurgePreview = { ecosystem: Ecosystem; name: string; artifact_count: number; size_bytes: number; blocked_by_pin: boolean; confirmation: string };

const SEARCH_LIMIT = 100;

const COPY = {
  search: { fa: "نام بسته را بنویسید", en: "Type a package name" },
  all: { fa: "همه", en: "All" },
  results: { fa: "{count} بسته", en: "{count} packages" },
  truncated: { fa: "فقط {count} بسته اول نشان داده شده؛ نام را دقیق‌تر بنویسید.", en: "Only the first {count} packages are shown; type a more exact name." },
  name: { fa: "نام بسته", en: "Package" },
  kind: { fa: "نوع", en: "Type" },
  versions: { fa: "نسخه‌ها", en: "Versions" },
  size: { fa: "حجم", en: "Size" },
  files: { fa: "تعداد فایل", en: "Files" },
  lastChange: { fa: "آخرین تغییر", en: "Last change" },
  state: { fa: "وضعیت", en: "State" },
  stored: { fa: "ذخیره‌شده", en: "Stored" },
  keep: { fa: "نگه دار", en: "Keep" },
  stopKeeping: { fa: "دیگر نگه ندار", en: "Stop keeping" },
  kept: { fa: "«{name}» نگه داشته می‌شود و هیچ‌وقت خودکار پاک نمی‌شود.", en: "“{name}” will be kept and never removed automatically." },
  unkept: { fa: "«{name}» دیگر نگه داشته نمی‌شود.", en: "“{name}” is no longer kept." },
  remove: { fa: "پاک کن", en: "Remove" },
  removeTitle: { fa: "«{name}» از ذخیره محلی پاک شود؟", en: "Remove “{name}” from local copies?" },
  removeBody: {
    fa: "{files} فایل ({size}) پاک می‌شود. تا چند روز در سطل بازیافت می‌ماند و می‌توانید برش گردانید.",
    en: "{files} files ({size}) will be removed. They stay in the recycle bin for a few days, so you can bring them back."
  },
  removeConsequence: { fa: "اگر پروژه‌ای دوباره این بسته را بخواهد، پیشکار آن را از منبع دریافت می‌کند.", en: "If a project asks for it again, Pishkar fetches it from the source." },
  removeBlocked: { fa: "این بسته نگه‌داشته‌شده است. اول «دیگر نگه ندار» را بزنید.", en: "This package is kept. Choose “Stop keeping” first." },
  removeStarted: { fa: "پاک کردن «{name}» شروع شد.", en: "Removing “{name}” has started." },
  quarantine: { fa: "قرنطینه…", en: "Quarantine…" },
  quarantineTitle: { fa: "«{name}» قرنطینه شود؟", en: "Quarantine “{name}”?" },
  quarantineBody: { fa: "تا وقتی قرنطینه است، هیچ پروژه‌ای نمی‌تواند آن را نصب کند.", en: "While quarantined, no project can install it." },
  quarantineReason: { fa: "چرا؟ (دست‌کم ۳ نویسه)", en: "Why? (at least 3 characters)" },
  quarantineYes: { fa: "قرنطینه کن", en: "Quarantine" },
  quarantined: { fa: "«{name}» قرنطینه شد.", en: "“{name}” was quarantined." },
  release: { fa: "از قرنطینه درآور", en: "Release" },
  released: { fa: "«{name}» از قرنطینه درآمد.", en: "“{name}” was released." },
  revalidate: { fa: "دریافت دوباره از منبع", en: "Fetch again from source" },
  revalidateStarted: { fa: "دریافت دوباره «{name}» شروع شد.", en: "Fetching “{name}” again has started." },
  seeJobs: { fa: "دیدن پیشرفت", en: "See progress" },
  emptyAll: { fa: "هنوز بسته‌ای روی این سرور ذخیره نشده.", en: "No packages are stored on this server yet." },
  emptyAllBody: { fa: "وقتی پروژه‌ها از این سرور نصب کنند، بسته‌ها این‌جا دیده می‌شوند.", en: "Once projects install from this server, their packages show up here." },
  connect: { fa: "اتصال یک پروژه", en: "Connect a project" },
  emptyQuery: { fa: "چیزی با «{query}» پیدا نشد.", en: "Nothing matches “{query}”." },
  emptyQueryBody: { fa: "املای نام را بررسی کنید یا آن را از قبل دانلود کنید.", en: "Check the spelling, or download it ahead of time." },
  prefetchIt: { fa: "پیش‌دریافت", en: "Download ahead" },
  readOnly: { fa: "نقش شما فقط اجازه دیدن بسته‌ها را دارد.", en: "Your role can only view packages." },
  listLabel: { fa: "بسته‌های ذخیره‌شده", en: "Stored packages" },
  // recycle bin
  trash: { fa: "سطل بازیافت", en: "Recycle bin" },
  trashHint: { fa: "بسته‌های پاک‌شده تا زمان مشخص‌شده این‌جا می‌مانند و برمی‌گردند.", en: "Removed packages wait here until their time runs out, and can be brought back." },
  trashEmpty: { fa: "سطل بازیافت خالی است.", en: "The recycle bin is empty." },
  trashEmptyBody: { fa: "بسته‌ای که پاک کنید، چند روز این‌جا می‌ماند.", en: "A package you remove stays here for a few days." },
  trashUnavailable: { fa: "سطل بازیافت روی نسخه فعلی سرور نیست.", en: "The recycle bin isn't available on this server version." },
  removedAt: { fa: "پاک‌شده", en: "Removed" },
  goneAt: { fa: "پاک شدن برای همیشه", en: "Deleted for good" },
  restore: { fa: "برگردان", en: "Restore" },
  restoreTitle: { fa: "«{name}» برگردانده شود؟", en: "Bring back “{name}”?" },
  restoreBody: { fa: "فایل‌های این بسته دوباره در ذخیره محلی قرار می‌گیرند.", en: "This package's files go back into local copies." },
  restoreYes: { fa: "بله، برگردان", en: "Yes, restore" },
  restored: { fa: "«{name}» برگردانده شد.", en: "“{name}” was restored." },
  deleteForever: { fa: "پاک کردن برای همیشه…", en: "Delete forever…" },
  deleteTitle: { fa: "«{name}» برای همیشه پاک شود؟", en: "Delete “{name}” forever?" },
  deleteBody: { fa: "فایل‌ها برای همیشه پاک می‌شوند و دیگر برنمی‌گردند.", en: "The files are erased and can't be brought back." },
  deleted: { fa: "«{name}» برای همیشه پاک شد.", en: "“{name}” was deleted forever." },
  // prefetch
  prefetchTitle: { fa: "دانلود بسته‌ها از قبل", en: "Download packages ahead" },
  prefetchHint: {
    fa: "فهرست بسته‌های پروژه را این‌جا بگذارید تا از قبل دانلود شوند و بعداً بدون اینترنت هم نصب شوند.",
    en: "Paste your project's package list so the packages are downloaded now and install later even without internet."
  },
  fileKind: { fa: "این فهرست از کدام فایل است؟", en: "Which file is this list from?" },
  pythonFile: { fa: "پایتون", en: "Python" },
  nodeFile: { fa: "جاوااسکریپت", en: "JavaScript" },
  manifest: { fa: "محتوای فایل", en: "File content" },
  manifestHelpPy: { fa: "محتوای فایل requirements.txt را بچسبانید.", en: "Paste the content of requirements.txt." },
  manifestHelpNpm: { fa: "محتوای فایل package-lock.json را بچسبانید.", en: "Paste the content of package-lock.json." },
  enqueue: { fa: "دانلود از قبل", en: "Download ahead" },
  enqueuing: { fa: "در حال شروع…", en: "Starting…" },
  prefetchStarted: { fa: "دانلود بسته‌ها شروع شد.", en: "Downloading the packages has started." },
  prefetchLimits: {
    fa: "هر بار حداکثر ۵۰۰ بسته و برای هر نسخه حداکثر ۴۰ فایل دانلود می‌شود.",
    en: "Each run downloads at most 500 packages and at most 40 files per version."
  },
  noTasks: { fa: "نقش شما اجازه شروع کارهای پس‌زمینه را ندارد.", en: "Your role can't start background jobs." }
} satisfies Record<string, Bi>;

const ECOSYSTEM_LABEL: Record<string, string> = { npm: "npm", pypi: "PyPI" };

const packagePath = (item: { ecosystem: string; name: string }) => `/api/v1/packages/${item.ecosystem}/${encodeURIComponent(item.name)}`;

function useJobsNotice() {
  const { language } = useKit();
  return (message: string) => ({ message, action: <Button color="inherit" size="small" href="#/alerts/jobs">{pick(language, COPY.seeJobs)}</Button> });
}

// ── Search & manage ──────────────────────────────────────────────────────────

export type PackagesTabProps = { permissions: readonly string[] };

export function SearchTab({ permissions }: PackagesTabProps) {
  const { language, isAdvanced } = useKit();
  const canWrite = hasPermission(permissions, "cache:write");
  const canRunTasks = hasPermission(permissions, "task:write");
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const jobsNotice = useJobsNotice();
  const [items, setItems] = useState<PackageRecord[]>([]);
  const [count, setCount] = useState(0);
  const [query, setQuery] = useState("");
  const [ecosystem, setEcosystem] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [jobNotice, setJobNotice] = useState<{ message: string; action: ReactNode } | null>(null);
  const [quarantineTarget, setQuarantineTarget] = useState<PackageRecord | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [trashKey, setTrashKey] = useState(0);
  const loadController = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    loadController.current?.abort();
    const controller = new AbortController();
    loadController.current = controller;
    setLoading(true);
    try {
      const params = new URLSearchParams({ q: query, limit: String(SEARCH_LIMIT) });
      if (ecosystem) params.set("ecosystem", ecosystem);
      const payload = await getJson<{ items: PackageRecord[]; count?: number }>(`/api/v1/packages?${params}`, controller.signal);
      if (controller.signal.aborted) return;
      setItems(payload.items);
      setCount(payload.count ?? payload.items.length);
      setLoadError(null);
    } catch (caught) {
      if (isAbortError(caught) || controller.signal.aborted || (caught instanceof ApiError && caught.status === 401)) return;
      setLoadError(caught);
    } finally {
      if (loadController.current === controller) {
        loadController.current = null;
        setLoading(false);
      }
    }
  }, [ecosystem, query]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 250);
    return () => window.clearTimeout(timer);
  }, [load]);
  useEffect(() => () => loadController.current?.abort(), []);

  const run = async (action: () => Promise<void>) => {
    setActionError(null);
    try {
      await action();
      return true;
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
      return false;
    }
  };

  const setPinned = async (item: PackageRecord, pinned: boolean, undoable = true) => {
    const ok = await run(async () => {
      await mutateJson(`${packagePath(item)}/policy`, { method: "PUT", body: { pinned } });
    });
    if (!ok) return;
    await load();
    notify({
      message: say(language, pinned ? COPY.kept : COPY.unkept, { name: item.name }),
      onUndo: undoable ? () => void setPinned(item, !pinned, false) : undefined
    });
  };

  const remove = async (item: PackageRecord) => {
    let preview: PurgePreview | null = null;
    const ok = await run(async () => {
      preview = await mutateJson<PurgePreview>(`${packagePath(item)}/purge-preview`, { method: "POST" });
    });
    const target = preview as PurgePreview | null;
    if (!ok || !target) return;
    if (target.blocked_by_pin) {
      notify({ message: pick(language, COPY.removeBlocked), tone: "info" });
      return;
    }
    const accepted = await ask({
      title: say(language, COPY.removeTitle, { name: item.name }),
      body: say(language, COPY.removeBody, { files: formatNumber(target.artifact_count, language), size: formatBytes(target.size_bytes, language) }),
      consequences: [pick(language, COPY.removeConsequence)],
      undoable: true,
      severity: "disruptive",
      confirmLabel: pick(language, COPY.remove)
    });
    if (!accepted) return;
    const done = await run(async () => {
      await mutateJson(`${packagePath(item)}/purge`, { method: "POST", body: { confirmation: target.confirmation || CONFIRM_TOKENS.purge(item.ecosystem, item.name) } });
    });
    if (done) {
      setJobNotice(jobsNotice(say(language, COPY.removeStarted, { name: item.name })));
      setTrashKey((value) => value + 1);
    }
  };

  const revalidate = async (item: PackageRecord) => {
    const ok = await run(async () => {
      await mutateJson(`${packagePath(item)}/revalidate`, { method: "POST" });
    });
    if (ok) setJobNotice(jobsNotice(say(language, COPY.revalidateStarted, { name: item.name })));
  };

  const release = async (item: PackageRecord) => {
    const ok = await run(async () => {
      await mutateJson(`${packagePath(item)}/policy`, { method: "PUT", body: { quarantined: false, quarantine_reason: null } });
    });
    if (ok) {
      notify({ message: say(language, COPY.released, { name: item.name }) });
      await load();
    }
  };

  const submitQuarantine = async () => {
    if (!quarantineTarget || reason.trim().length < 3) return;
    setBusy(true);
    const target = quarantineTarget;
    const ok = await run(async () => {
      await mutateJson(`${packagePath(target)}/policy`, { method: "PUT", body: { quarantined: true, quarantine_reason: reason.trim() } });
    });
    setBusy(false);
    if (!ok) return;
    setQuarantineTarget(null);
    notify({ message: say(language, COPY.quarantined, { name: target.name }) });
    await load();
  };

  const trimmed = query.trim();
  const formattedCount = formatNumber(count, language);

  return (
    <Stack spacing={2.5}>
      <SectionCard>
        <Stack spacing={1.5}>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
            <TextField
              fullWidth
              autoFocus
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              label={pick(language, COPY.search)}
              slotProps={{
                htmlInput: { maxLength: 200, dir: "auto" },
                input: {
                  startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment>,
                  endAdornment: loading ? <CircularProgress size={18} aria-label={pick(language, COPY.search)} /> : null
                }
              }}
            />
            <ToggleButtonGroup exclusive size="small" value={ecosystem} onChange={(_event, value: string | null) => setEcosystem(value ?? "")} sx={{ flexShrink: 0, "& .MuiToggleButton-root": { minHeight: 44, px: 2 } }}>
              <ToggleButton value="">{pick(language, COPY.all)}</ToggleButton>
              <ToggleButton value="npm">npm</ToggleButton>
              <ToggleButton value="pypi">PyPI</ToggleButton>
            </ToggleButtonGroup>
          </Stack>
          <Typography variant="caption" color="text.secondary" role="status">
            {count >= SEARCH_LIMIT ? say(language, COPY.truncated, { count: formattedCount }) : say(language, COPY.results, { count: formattedCount })}
          </Typography>
        </Stack>
      </SectionCard>

      {loadError !== null && <FriendlyError error={loadError} onRetry={() => void load()} />}
      {actionError !== null && <FriendlyError error={actionError} onClose={() => setActionError(null)} />}
      {jobNotice && <Notice tone="success" action={jobNotice.action}>{jobNotice.message}</Notice>}
      {!canWrite && <NoAccess needs="cache:write" />}

      <SectionCard flush>
        <ResponsiveList<PackageRecord>
          label={pick(language, COPY.listLabel)}
          rows={items}
          rowKey={(row) => `${row.ecosystem}:${row.name}`}
          columns={[
            { key: "name", header: pick(language, COPY.name), render: (row) => <Ltr>{row.name}</Ltr> },
            { key: "eco", header: pick(language, COPY.kind), render: (row) => ECOSYSTEM_LABEL[row.ecosystem] ?? row.ecosystem },
            { key: "versions", header: pick(language, COPY.versions), render: (row) => <Ltr>{row.versions.slice(0, isAdvanced ? 8 : 3).join("، ") || "—"}</Ltr>, hideOnCard: true },
            { key: "size", header: pick(language, COPY.size), render: (row) => <Bytes value={row.size_bytes} /> },
            { key: "files", header: pick(language, COPY.files), render: (row) => formatNumber(row.artifact_count, language), advancedOnly: true },
            { key: "mtime", header: pick(language, COPY.lastChange), render: (row) => <RelativeTime value={row.latest_mtime} />, advancedOnly: true },
            { key: "state", header: pick(language, COPY.state), render: (row) => <PackageState row={row} /> }
          ]}
          card={{
            title: (row) => <Ltr>{row.name}</Ltr>,
            meta: (row) => (
              <>
                {ECOSYSTEM_LABEL[row.ecosystem]} · <Bytes value={row.size_bytes} />
              </>
            ),
            status: (row) => <PackageState row={row} />
          }}
          actions={canWrite ? [
            { key: "keep", label: pick(language, COPY.keep), icon: PushPinRoundedIcon, onClick: (row) => void setPinned(row, true), hidden: (row) => row.pinned },
            { key: "unkeep", label: pick(language, COPY.stopKeeping), icon: PushPinRoundedIcon, onClick: (row) => void setPinned(row, false), hidden: (row) => !row.pinned },
            { key: "revalidate", label: pick(language, COPY.revalidate), icon: SyncRoundedIcon, onClick: (row) => void revalidate(row), advancedOnly: true, disabled: (row) => !canRunTasks || row.pinned },
            { key: "quarantine", label: pick(language, COPY.quarantine), icon: GppBadRoundedIcon, onClick: (row) => { setReason(""); setQuarantineTarget(row); }, advancedOnly: true, hidden: (row) => row.quarantined },
            { key: "release", label: pick(language, COPY.release), icon: GppGoodRoundedIcon, onClick: (row) => void release(row), advancedOnly: true, hidden: (row) => !row.quarantined },
            { key: "remove", label: pick(language, COPY.remove), icon: DeleteOutlineRoundedIcon, onClick: (row) => void remove(row), danger: true, disabled: () => !canRunTasks }
          ] : undefined}
          empty={
            loading ? undefined : trimmed ? (
              <EmptyState
                icon={SearchRoundedIcon}
                title={say(language, COPY.emptyQuery, { query: trimmed })}
                body={pick(language, COPY.emptyQueryBody)}
                action={hasPermission(permissions, "cache:write") ? <Button variant="contained" href="#/packages/prefetch" startIcon={<CloudDownloadRoundedIcon />}>{pick(language, COPY.prefetchIt)}</Button> : undefined}
              />
            ) : (
              <EmptyState
                icon={Inventory2RoundedIcon}
                title={pick(language, COPY.emptyAll)}
                body={pick(language, COPY.emptyAllBody)}
                action={<Button variant="contained" href="#/packages/connect">{pick(language, COPY.connect)}</Button>}
              />
            )
          }
        />
      </SectionCard>

      <RecycleBin key={trashKey} permissions={permissions} onChanged={() => void load()} />

      <ConfirmAction
        open={quarantineTarget !== null}
        title={quarantineTarget ? say(language, COPY.quarantineTitle, { name: quarantineTarget.name }) : ""}
        body={pick(language, COPY.quarantineBody)}
        undoable
        severity="destructive"
        confirmLabel={pick(language, COPY.quarantineYes)}
        busy={busy}
        error={quarantineTarget ? actionError : null}
        confirmDisabled={reason.trim().length < 3}
        onConfirm={() => void submitQuarantine()}
        onClose={() => setQuarantineTarget(null)}
      >
        <TextField fullWidth required label={pick(language, COPY.quarantineReason)} value={reason} onChange={(event) => setReason(event.target.value)} slotProps={{ htmlInput: { minLength: 3, maxLength: 500, dir: "auto" } }} />
      </ConfirmAction>
      {dialog}
      {snackbar}
    </Stack>
  );
}

function PackageState({ row }: { row: PackageRecord }) {
  const { language } = useKit();
  if (row.quarantined) return <StatusPill status="quarantined" />;
  if (row.pinned) return <StatusPill status="pinned" />;
  return <StatusPill tone="ok" label={pick(language, COPY.stored)} />;
}

// ── Recycle bin ──────────────────────────────────────────────────────────────

function RecycleBin({ permissions, onChanged }: { permissions: readonly string[]; onChanged: () => void }) {
  const { language, c } = useKit();
  const canWrite = hasPermission(permissions, "cache:write");
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [items, setItems] = useState<TrashRecord[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const payload = await getJson<{ items: TrashRecord[] }>("/api/v1/packages/trash");
      setItems(payload.items);
      setError(null);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) return;
      if (caught instanceof ApiError && (caught.status === 404 || caught.status === 405)) setUnavailable(true);
      else setError(caught);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => void load(), [load]);

  const restore = async (item: TrashRecord) => {
    const accepted = await ask({ title: say(language, COPY.restoreTitle, { name: item.name }), body: pick(language, COPY.restoreBody), confirmLabel: pick(language, COPY.restoreYes) });
    if (!accepted) return;
    try {
      await mutateJson(`/api/v1/packages/trash/${encodeURIComponent(item.trash_id)}/restore`, { method: "POST" });
      notify({ message: say(language, COPY.restored, { name: item.name }) });
      await load();
      onChanged();
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
  };

  const deleteForever = async (item: TrashRecord) => {
    const token = CONFIRM_TOKENS.trashDelete(item.trash_id);
    const accepted = await ask({
      title: say(language, COPY.deleteTitle, { name: item.name }),
      body: pick(language, COPY.deleteBody),
      undoable: false,
      severity: "destructive",
      typed: deleteConfirmation(token)
    });
    if (!accepted) return;
    try {
      await mutateJson(`/api/v1/packages/trash/${encodeURIComponent(item.trash_id)}`, { method: "DELETE", body: { confirmation: token } });
      notify({ message: say(language, COPY.deleted, { name: item.name }) });
      await load();
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
  };

  if (unavailable) return null;
  return (
    <SectionCard
      title={pick(language, COPY.trash)}
      hint={pick(language, COPY.trashHint)}
      collapsible
      defaultCollapsed={!items || items.length === 0}
      flush
      action={
        <Button size="small" onClick={() => void load()} disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} sx={{ minHeight: 44 }}>
          {c.refresh}
        </Button>
      }
    >
      {error !== null && <Box sx={{ p: 2 }}><FriendlyError error={error} onRetry={() => void load()} /></Box>}
      <ResponsiveList<TrashRecord>
        label={pick(language, COPY.trash)}
        rows={items ?? []}
        rowKey={(row) => row.trash_id}
        columns={[
          { key: "name", header: pick(language, COPY.name), render: (row) => <Ltr>{row.name}</Ltr> },
          { key: "eco", header: pick(language, COPY.kind), render: (row) => ECOSYSTEM_LABEL[row.ecosystem] ?? row.ecosystem },
          { key: "size", header: pick(language, COPY.size), render: (row) => <Bytes value={row.size_bytes} /> },
          { key: "at", header: pick(language, COPY.removedAt), render: (row) => <RelativeTime value={row.trashed_at} /> },
          { key: "expires", header: pick(language, COPY.goneAt), render: (row) => <RelativeTime value={row.expires_at} /> },
          { key: "id", header: "ID", render: (row) => <Ltr mono>{row.trash_id}</Ltr>, advancedOnly: true }
        ]}
        card={{
          title: (row) => <Ltr>{row.name}</Ltr>,
          meta: (row) => <><Bytes value={row.size_bytes} /> · <RelativeTime value={row.expires_at} /></>
        }}
        actions={canWrite ? [
          { key: "restore", label: pick(language, COPY.restore), icon: RestoreFromTrashRoundedIcon, onClick: (row) => void restore(row) },
          { key: "delete", label: pick(language, COPY.deleteForever), icon: DeleteOutlineRoundedIcon, onClick: (row) => void deleteForever(row), danger: true, advancedOnly: true }
        ] : undefined}
        empty={<EmptyState compact icon={RestoreFromTrashRoundedIcon} title={pick(language, COPY.trashEmpty)} body={pick(language, COPY.trashEmptyBody)} />}
      />
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

// ── Download ahead (prefetch) ────────────────────────────────────────────────

export function PrefetchTab({ permissions }: PackagesTabProps) {
  const { language, isAdvanced } = useKit();
  const canRun = hasPermission(permissions, "task:write") && hasPermission(permissions, "cache:write");
  const jobsNotice = useJobsNotice();
  const [ecosystem, setEcosystem] = useState<Ecosystem>("pypi");
  const [manifest, setManifest] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<{ message: string; action: ReactNode } | null>(null);

  const submit = async () => {
    if (!manifest.trim()) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await mutateJson<{ task_id: string }>("/api/v1/packages/prefetch", { method: "POST", body: { ecosystem, content: manifest } });
      setManifest("");
      setNotice(jobsNotice(pick(language, COPY.prefetchStarted)));
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard title={pick(language, COPY.prefetchTitle)} hint={pick(language, COPY.prefetchHint)}>
      <Stack spacing={2}>
        <Box>
          <Typography variant="body2" sx={{ mb: 1, fontWeight: 650 }}>{pick(language, COPY.fileKind)}</Typography>
          <ToggleButtonGroup exclusive value={ecosystem} onChange={(_event, value: Ecosystem | null) => value && setEcosystem(value)} sx={{ "& .MuiToggleButton-root": { minHeight: 44, px: 2.5, textTransform: "none" } }}>
            <ToggleButton value="pypi">{pick(language, COPY.pythonFile)} · <Ltr>requirements.txt</Ltr></ToggleButton>
            <ToggleButton value="npm">{pick(language, COPY.nodeFile)} · <Ltr>package-lock.json</Ltr></ToggleButton>
          </ToggleButtonGroup>
        </Box>
        <TextField
          fullWidth
          multiline
          minRows={5}
          maxRows={14}
          label={pick(language, COPY.manifest)}
          helperText={pick(language, ecosystem === "pypi" ? COPY.manifestHelpPy : COPY.manifestHelpNpm)}
          value={manifest}
          onChange={(event) => setManifest(event.target.value)}
          disabled={!canRun}
          slotProps={{ htmlInput: { dir: "ltr", maxLength: 1_000_000, spellCheck: false } }}
        />
        {isAdvanced && <Notice>{pick(language, COPY.prefetchLimits)}</Notice>}
        {error !== null && <FriendlyError error={error} onClose={() => setError(null)} />}
        {notice && <Notice tone="success" action={notice.action}>{notice.message}</Notice>}
        {!canRun && <NoAccess needs={["task:write", "cache:write"]} />}
        <Box>
          <Button
            variant="contained"
            size="large"
            startIcon={busy ? <CircularProgress size={18} color="inherit" /> : <CloudDownloadRoundedIcon />}
            disabled={!canRun || busy || !manifest.trim()}
            onClick={() => void submit()}
            sx={{ minHeight: 48 }}
          >
            {busy ? pick(language, COPY.enqueuing) : pick(language, COPY.enqueue)}
          </Button>
        </Box>
      </Stack>
    </SectionCard>
  );
}

/** Legacy entry point (old `#packages` page); the shell now mounts PackagesPage. */
export function PackagesPanel({ permissions }: { language?: Language; permissions: string[]; onUnauthorized?: () => void }) {
  return (
    <Stack spacing={3}>
      <SearchTab permissions={permissions} />
      <PrefetchTab permissions={permissions} />
    </Stack>
  );
}

