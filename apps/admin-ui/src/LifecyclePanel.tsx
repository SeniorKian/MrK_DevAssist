/**
 * Files › Panel backup and Files › Keep storage healthy (docs/33 §4.2).
 * - section "backup": encrypted backup of the panel's own settings. Simple: settings-only backup +
 *   list. Advanced: full profile, validate in isolation, offline restore plan (typed confirmation),
 *   and the panel-backup retention settings.
 * - section "health": disk use + «آزاد کردن فضا» (preview → confirm → purge the oldest unused,
 *   unpinned packages). Advanced: target slider, candidate list, integrity scan, cache/recycle-bin settings.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Box, Button, CircularProgress, FormControlLabel, LinearProgress, MenuItem, Stack, Switch, TextField, Typography } from "@mui/material";
import FactCheckRoundedIcon from "@mui/icons-material/FactCheckRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import BackupRoundedIcon from "@mui/icons-material/BackupRounded";
import CleaningServicesRoundedIcon from "@mui/icons-material/CleaningServicesRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import RestoreRoundedIcon from "@mui/icons-material/RestoreRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import { ApiError, apiGet, ensureOk, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { Language } from "./i18n";
import {
  Bytes, ConfirmAction, CopyField, EmptyState, FriendlyError, HelpTip, Ltr, NoAccess, Notice, PercentSlider, Percent,
  RegistrySettings, RelativeTime, ResponsiveList, SectionCard, StatGrid, StatTile, StatusPill, useConfirmAction, useKit,
  useUndoSnackbar, formatSize
} from "./kit";
import { deleteConfirmation, reasonFor, say, type Bi, type ConfirmWord } from "./copy";

type Candidate = { ecosystem: string; name: string; size_bytes: number; latest_mtime: number; frees_space_immediately?: boolean };
type Preview = {
  target_percent: number;
  current_percent: number;
  total_bytes?: number;
  used_bytes?: number;
  free_bytes?: number;
  required_reclaim_bytes: number;
  candidate_reclaim_bytes: number;
  candidates: Candidate[];
  truncated: boolean;
  trash_bytes?: number;
  dry_run: boolean;
  /** Token the clean-up endpoint expects (`CLEANUP <n> PACKAGES`). */
  confirmation?: string;
};
type BackupProfile = "config" | "full";
type BackupRecord = { backup_id?: string; filename?: string; created_at?: number; size_bytes: number; profile?: string; format?: number | string; cipher?: string; invalid?: boolean };
type TaskSnapshot = { id: string; state: string; progress: number; error_code: string | null };
type CleanupResult = {
  purged?: unknown[];
  purged_count?: number;
  skipped?: { reason?: string }[];
  failed?: { error_code?: string | null }[];
  reclaimed_bytes?: number;
  cancelled?: boolean;
};
type CleanupTask = TaskSnapshot & { result?: CleanupResult | null; total?: number };
type CleanupSummary = { purged: number; skipped: number; failed: number; reclaimed: number; cancelled: boolean; firstFailure: string | null };

type Props = {
  language: Language;
  permissions: string[];
  onUnauthorized: () => void;
  /** "backup" = panel backup tab, "health" = keep storage healthy tab; omit for both. */
  section?: "backup" | "health";
};

const CANDIDATE_LIMIT = 25;
const TASK_POLL_MS = 3000;
const SIMPLE_TARGET = 75;
const MIN_PASSPHRASE = 16;
const JOBS_HREF = "#/alerts/jobs";
const BACKUP_SETTING_KEYS = ["backup.retain_count", "backup.retain_days"];
const HEALTH_SETTING_KEYS = ["catalog.cache_seconds", "integrity.full_rescan_days", "purge.trash_retention_days", "purge.trash_expiry_interval_seconds"];

const T = {
  // backup
  backupTitle: { fa: "پشتیبان از تنظیمات پنل", en: "Back up the panel's settings" },
  backupHint: { fa: "کاربران، منابع دریافت، قواعد و تنظیمات پنل در یک فایل رمزدار ذخیره می‌شوند.", en: "Users, package sources, rules and panel settings are saved in one encrypted file." },
  passphrase: { fa: "رمز پشتیبان", en: "Backup password" },
  passphraseRule: { fa: "دست‌کم ۱۶ نویسه. این رمز جایی ذخیره نمی‌شود؛ آن را جای امنی بنویسید.", en: "At least 16 characters. It isn't stored anywhere; write it down somewhere safe." },
  passphraseShort: { fa: "رمز باید دست‌کم ۱۶ نویسه باشد.", en: "The password must be at least 16 characters." },
  passphraseAgain: { fa: "تکرار رمز پشتیبان", en: "Repeat the backup password" },
  passphraseMismatch: { fa: "دو رمز یکی نیستند.", en: "The two passwords don't match." },
  profile: { fa: "چه چیزی در پشتیبان باشد؟", en: "What goes into the backup?" },
  profileConfig: { fa: "فقط تنظیمات (پیشنهادی)", en: "Settings only (recommended)" },
  profileConfigHint: { fa: "کوچک و سریع. بسته‌های ذخیره‌شده در آن نیستند و بعداً دوباره دریافت می‌شوند.", en: "Small and fast. Stored packages aren't included; they download again later." },
  profileFull: { fa: "کامل، همراه بسته‌های ذخیره‌شده", en: "Full, with stored packages" },
  profileFullHint: { fa: "همه بسته‌های ذخیره‌شده هم می‌آیند؛ ممکن است خیلی بزرگ و طولانی شود.", en: "Includes every stored package; can be very large and slow." },
  createBackup: { fa: "ساخت پشتیبان", en: "Create backup" },
  backupQueued: { fa: "ساخت پشتیبان شروع شد…", en: "The backup started…" },
  backupRunning: { fa: "در حال ساخت پشتیبان…", en: "Creating the backup…" },
  backupCreated: { fa: "پشتیبان رمزدار پنل ساخته شد.", en: "The encrypted panel backup was created." },
  backupFailed: { fa: "پشتیبان ساخته نشد. {reason}", en: "The backup wasn't created. {reason}" },
  viewJobs: { fa: "دیدن پیشرفت", en: "See progress" },
  noBackupsTitle: { fa: "هنوز از پنل پشتیبان نگرفته‌اید", en: "No panel backups yet" },
  noBackupsBody: { fa: "با یک پشتیبان، اگر سرور عوض شود یا اشتباهی پیش بیاید، تنظیمات را برمی‌گردانید.", en: "With a backup you can bring the settings back after a mistake or on a new server." },
  listTitle: { fa: "پشتیبان‌های پنل", en: "Panel backups" },
  colDate: { fa: "زمان", en: "When" },
  colContent: { fa: "محتوا", en: "Contents" },
  colSize: { fa: "حجم", en: "Size" },
  colFile: { fa: "فایل", en: "File" },
  colCipher: { fa: "روش رمز", en: "Cipher" },
  damaged: { fa: "خراب", en: "Damaged" },
  healthy: { fa: "سالم", en: "OK" },
  storedOnServer: { fa: "فایل‌های پشتیبان در پوشه داده همین سرور نگه داشته می‌شوند. برای اطمینان، یک نسخه را بیرون از سرور هم نگه دارید.", en: "Backup files are kept in this server's data folder. Keep a copy outside the server too." },
  // restore
  restoreTitle: { fa: "بازگردانی از پشتیبان", en: "Restore from a backup" },
  restoreHint: { fa: "اول پشتیبان بدون دست زدن به داده‌های فعلی بررسی می‌شود؛ بعد دستور بازگردانی آماده می‌شود.", en: "The backup is checked first without touching current data; then the restore command is prepared." },
  pickBackup: { fa: "کدام پشتیبان؟", en: "Which backup?" },
  validate: { fa: "بررسی پشتیبان", en: "Check the backup" },
  checking: { fa: "در حال بررسی…", en: "Checking…" },
  valid: { fa: "پشتیبان سالم است و رمزش درست است.", en: "The backup is intact and the password is right." },
  prepare: { fa: "آماده کردن بازگردانی", en: "Prepare the restore" },
  restoreConfirmTitle: { fa: "بازگردانی پشتیبان {date} آماده شود؟", en: "Prepare restoring the backup from {date}?" },
  restoreConfirmBody: { fa: "بعد از اجرای دستور، تنظیمات فعلی پنل با این پشتیبان عوض می‌شوند.", en: "Once you run the command, the panel's current settings are replaced by this backup." },
  restoreConsequence1: { fa: "دستور فقط وقتی کار می‌کند که سرویس پیشکار کاملاً خاموش باشد.", en: "The command only works while the Pishkar service is fully stopped." },
  restoreConsequence2: { fa: "رمز پشتیبان در این طرح ذخیره نمی‌شود.", en: "The backup password isn't stored in the plan." },
  restoreWord: { fa: "بازگردانی کن", en: "RESTORE" },
  planReady: { fa: "آماده است. سرویس را خاموش کنید و این دستور را روی سرور اجرا کنید.", en: "Ready. Stop the service, then run this command on the server." },
  applyCommand: { fa: "دستور بازگردانی", en: "Restore command" },
  noValidBackups: { fa: "پشتیبان سالمی برای بازگردانی نیست.", en: "There's no intact backup to restore." },
  // health
  diskTitle: { fa: "فضای دیسک", en: "Disk space" },
  diskHint: { fa: "فضایی که بسته‌های ذخیره‌شده و پشتیبان‌ها روی این سرور گرفته‌اند.", en: "Space used on this server by stored packages and backups." },
  used: { fa: "پر شده", en: "Used" },
  usedOf: { fa: "{used} از {total}", en: "{used} of {total}" },
  free: { fa: "خالی", en: "Free" },
  trash: { fa: "در سطل بازیافت", en: "In the recycle bin" },
  trashHint: { fa: "بسته‌های پاک‌شده npm مدتی این‌جا می‌مانند و بعد خودکار پاک می‌شوند.", en: "Deleted npm packages wait here for a while, then go away automatically." },
  freeUp: { fa: "آزاد کردن فضا", en: "Free up space" },
  freeing: { fa: "سرور در حال پاک کردن {total} بسته قدیمی است…", en: "The server is removing {total} old packages…" },
  enoughSpace: { fa: "فضای کافی دارید؛ فعلاً لازم نیست چیزی پاک شود.", en: "You have enough space; nothing needs to go right now." },
  freeTitle: { fa: "{count} بسته قدیمی پاک شود؟", en: "Remove {count} old packages?" },
  freeBody: { fa: "حدود {size} آزاد می‌شود. بسته‌هایی که مدت‌ها استفاده نشده‌اند اول پاک می‌شوند.", en: "About {size} will be freed. Packages unused for the longest go first." },
  freeConsequence1: { fa: "بسته‌های نگه‌داشته‌شده و قرنطینه دست نمی‌خورند.", en: "Kept and quarantined packages aren't touched." },
  freeConsequence2: { fa: "بسته‌های npm اول به سطل بازیافت می‌روند و تا چند روز برمی‌گردند.", en: "npm packages go to the recycle bin first and can come back for a few days." },
  freeConsequence3: { fa: "بسته‌های PyPI فوراً پاک می‌شوند؛ اگر لازم شوند دوباره از اینترنت دریافت می‌شوند.", en: "PyPI packages go right away; they download again if needed." },
  freeDone: { fa: "{count} بسته پاک شد و حدود {size} آزاد شد.", en: "{count} packages were removed, freeing about {size}." },
  freeCancelled: { fa: "پاک‌سازی نیمه‌کاره لغو شد؛ تا آن لحظه {count} بسته پاک شد ({size}).", en: "The clean-up was cancelled; {count} packages were removed by then ({size})." },
  freeSkipped: { fa: "{count} بسته دست نخورد (نگه‌داشته‌شده، قرنطینه یا دیگر لازم نبود).", en: "{count} packages were left alone (kept, quarantined or no longer needed)." },
  freeSomeFailed: { fa: "{failed} بسته پاک نشد. {reason}", en: "{failed} packages weren't removed. {reason}" },
  freeFailed: { fa: "فضا آزاد نشد. {reason}", en: "No space was freed. {reason}" },
  download: { fa: "دانلود", en: "Download" },
  downloading: { fa: "در حال آماده کردن فایل…", en: "Preparing the file…" },
  downloaded: { fa: "فایل پشتیبان دانلود شد. رمز آن همان رمز پشتیبان است.", en: "The backup file was downloaded. It opens with the backup password." },
  // advanced health
  cleanupTitle: { fa: "پیش‌نمایش پاک‌سازی", en: "Clean-up preview" },
  cleanupHint: { fa: "فقط پیش‌نمایش است؛ تا «آزاد کردن فضا» را نزنید چیزی پاک نمی‌شود.", en: "Preview only; nothing is removed until you press “Free up space”." },
  target: { fa: "هدف: دیسک تا این اندازه پر باشد", en: "Goal: keep the disk at most this full" },
  reclaim: { fa: "باید آزاد شود", en: "Needs freeing" },
  candidate: { fa: "با این بسته‌ها آزاد می‌شود", en: "These packages free" },
  noCandidates: { fa: "با این هدف لازم نیست چیزی پاک شود.", en: "Nothing needs to go at this goal." },
  more: { fa: "و {count} مورد دیگر", en: "and {count} more" },
  colPackage: { fa: "بسته", en: "Package" },
  colEco: { fa: "نوع", en: "Kind" },
  colLastUse: { fa: "آخرین استفاده", en: "Last used" },
  integrityTitle: { fa: "بررسی سالم بودن فایل‌ها", en: "Check stored files for damage" },
  integrityHint: { fa: "سالم بودن فایل‌های ذخیره‌شده بررسی می‌شود؛ چیزی پاک نمی‌شود.", en: "Stored files are checked for damage; nothing is removed." },
  integrityFull: { fa: "همه فایل‌ها از اول بررسی شوند (کندتر)", en: "Check every file from scratch (slower)" },
  integrityRun: { fa: "شروع بررسی", en: "Start the check" },
  integrityStarted: { fa: "بررسی شروع شد. پیشرفت را در «کارها» ببینید.", en: "The check started. Follow it under Jobs." },
  settingsBackup: { fa: "تنظیمات نگه‌داری پشتیبان‌های پنل", en: "Panel backup retention settings" },
  settingsHealth: { fa: "تنظیمات نگهداری فضا", en: "Storage upkeep settings" }
} satisfies Record<string, Bi>;

type Key = keyof typeof T;

const ECOSYSTEM_NAMES: Record<string, string> = { npm: "npm", pypi: "PyPI" };

function backupFile(backup: BackupRecord) {
  return backup.filename ?? (backup.backup_id ? `${backup.backup_id}.mrkbak` : "");
}

function isUnauthorized(error: unknown) {
  return error instanceof ApiError && error.status === 401;
}

// ─────────────────────────── panel backup ───────────────────────────

function PanelBackupSection({ permissions }: { permissions: string[] }) {
  const { language, isAdvanced, c } = useKit();
  const t = (key: Key) => T[key][language];
  const { notify, snackbar } = useUndoSnackbar();
  const canRead = hasPermission(permissions, "backup:read");
  const canWrite = hasPermission(permissions, "backup:write");
  const [backups, setBackups] = useState<BackupRecord[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [passphrase, setPassphrase] = useState("");
  const [again, setAgain] = useState("");
  const [profile, setProfile] = useState<BackupProfile>("config");
  const [busy, setBusy] = useState(false);
  const [task, setTask] = useState<TaskSnapshot | null>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    if (!canRead) return;
    try {
      const payload = await getJson<{ items: BackupRecord[] }>("/api/v1/backups", signal);
      setBackups([...(payload.items ?? [])].sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0)));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || isUnauthorized(caught)) return;
      setError(caught);
    }
  }, [canRead]);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  // Follow the queued backup job until it finishes, then refresh the list.
  const taskId = task?.id ?? null;
  useEffect(() => {
    if (!taskId) return;
    let stopped = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const payload = await getJson<{ items: TaskSnapshot[] }>("/api/v1/tasks?limit=50");
        const found = payload.items.find((item) => item.id === taskId);
        if (stopped) return;
        if (found) {
          setTask(found);
          if (found.state === "succeeded") {
            notify({ message: T.backupCreated[language], tone: "success" });
            setTask(null);
            void load();
            return;
          }
          if (found.state === "failed" || found.state === "cancelled") {
            setActionError(say(language, T.backupFailed, { reason: reasonFor(language, found.error_code) }));
            setTask(null);
            return;
          }
        }
      } catch {
        // transient polling failure: try again on the next tick
      }
      if (!stopped) timer = window.setTimeout(() => void poll(), TASK_POLL_MS);
    };
    timer = window.setTimeout(() => void poll(), TASK_POLL_MS);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [taskId, language, load, notify]);

  const download = async (backup: BackupRecord) => {
    const id = backup.filename ?? backup.backup_id;
    if (!id) return;
    setActionError(null);
    notify({ message: t("downloading") });
    try {
      const response = await ensureOk(await apiGet(`/api/v1/backups/${encodeURIComponent(id)}/download`));
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = backupFile(backup) || "mrk-panel-backup.mrkbak";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 30_000);
      notify({ message: t("downloaded"), tone: "success" });
    } catch (caught) {
      if (!isUnauthorized(caught)) setActionError(caught);
    }
  };

  const passphraseError = passphrase.length > 0 && passphrase.length < MIN_PASSPHRASE ? t("passphraseShort") : null;
  const againError = again.length > 0 && again !== passphrase ? t("passphraseMismatch") : null;
  const ready = passphrase.length >= MIN_PASSPHRASE && again === passphrase && !busy && !task;

  const create = async () => {
    if (!ready) return;
    setBusy(true);
    setActionError(null);
    try {
      const payload = await mutateJson<{ task_id?: string }>("/api/v1/backups", { method: "POST", body: { passphrase, profile: isAdvanced ? profile : "config" } });
      if (payload?.task_id) {
        setTask({ id: payload.task_id, state: "pending", progress: 0, error_code: null });
      } else {
        notify({ message: t("backupCreated"), tone: "success" });
        await load();
      }
      setPassphrase("");
      setAgain("");
    } catch (caught) {
      if (!isUnauthorized(caught)) setActionError(caught);
    } finally {
      setBusy(false);
    }
  };

  if (!canRead) return <NoAccess needs="backup:read" variant="card" />;

  return (
    <Stack spacing={2.5}>
      <SectionCard
        title={t("backupTitle")}
        hint={t("backupHint")}
        action={<HelpTip term="passphrase" />}
      >
        {!canWrite ? <NoAccess needs="backup:write" variant="card" /> : (
          <Box component="form" onSubmit={(event) => { event.preventDefault(); void create(); }}>
            <Stack spacing={1.5}>
              {isAdvanced ? (
                <TextField select fullWidth size="small" label={t("profile")} value={profile} onChange={(event) => setProfile(event.target.value as BackupProfile)} helperText={profile === "config" ? t("profileConfigHint") : t("profileFullHint")}>
                  <MenuItem value="config">{t("profileConfig")}</MenuItem>
                  <MenuItem value="full">{t("profileFull")}</MenuItem>
                </TextField>
              ) : (
                <Typography variant="body2" color="text.secondary">{t("profileConfigHint")}</Typography>
              )}
              <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
                <TextField fullWidth size="small" type="password" autoComplete="new-password" label={t("passphrase")} value={passphrase} onChange={(event) => setPassphrase(event.target.value)} error={Boolean(passphraseError)} helperText={passphraseError ?? t("passphraseRule")} slotProps={{ htmlInput: { maxLength: 1024, dir: "ltr" } }} />
                <TextField fullWidth size="small" type="password" autoComplete="new-password" label={t("passphraseAgain")} value={again} onChange={(event) => setAgain(event.target.value)} error={Boolean(againError)} helperText={againError ?? " "} slotProps={{ htmlInput: { maxLength: 1024, dir: "ltr" } }} />
              </Stack>
              <Box>
                <Button type="submit" variant="contained" disabled={!ready} startIcon={busy || task ? <CircularProgress size={16} color="inherit" /> : <BackupRoundedIcon />}>{t("createBackup")}</Button>
              </Box>
              {task && (
                <Box role="status">
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="body2" color="text.secondary">{task.state === "running" ? t("backupRunning") : t("backupQueued")}</Typography>
                    <Button size="small" href={JOBS_HREF}>{t("viewJobs")}</Button>
                  </Stack>
                  <LinearProgress variant={task.progress > 0 ? "determinate" : "indeterminate"} value={task.progress} aria-label={t("backupRunning")} sx={{ mt: 0.5, height: 6, borderRadius: 1 }} />
                </Box>
              )}
              {actionError !== null && (typeof actionError === "string" ? <Notice tone="error">{actionError}</Notice> : <FriendlyError error={actionError} onClose={() => setActionError(null)} noAction />)}
            </Stack>
          </Box>
        )}
      </SectionCard>

      <SectionCard
        title={t("listTitle")}
        hint={t("storedOnServer")}
        flush
        action={<Button aria-label={c.refresh} onClick={() => void load()} sx={{ minWidth: 44, minHeight: 44 }}><RefreshRoundedIcon /></Button>}
      >
        {error !== null && <Box sx={{ px: 2, pb: 2 }}><FriendlyError error={error} onRetry={() => void load()} /></Box>}
        {backups === null && error === null && <LinearProgress aria-label={c.loading} />}
        {backups !== null && (
          <ResponsiveList
            label={t("listTitle")}
            rows={backups}
            rowKey={(backup) => backupFile(backup) || String(backup.created_at)}
            columns={[
              { key: "date", header: t("colDate"), render: (backup) => <RelativeTime value={backup.created_at ?? null} /> },
              { key: "content", header: t("colContent"), render: (backup) => (backup.profile === "full" ? t("profileFull") : t("profileConfig")) },
              { key: "size", header: t("colSize"), render: (backup) => <Bytes value={backup.size_bytes} /> },
              { key: "state", header: c.details, render: (backup) => <StatusPill tone={backup.invalid ? "error" : "ok"} label={backup.invalid ? t("damaged") : t("healthy")} /> },
              { key: "file", header: t("colFile"), advancedOnly: true, ltr: true, render: (backup) => <Ltr mono>{backupFile(backup)}</Ltr> },
              { key: "cipher", header: t("colCipher"), advancedOnly: true, ltr: true, render: (backup) => <Ltr mono>{[backup.cipher, backup.format].filter(Boolean).join(" · ") || "—"}</Ltr> }
            ]}
            card={{
              title: (backup) => <RelativeTime value={backup.created_at ?? null} />,
              meta: (backup) => <>{backup.profile === "full" ? t("profileFull") : t("profileConfig")} · <Bytes value={backup.size_bytes} /></>,
              status: (backup) => <StatusPill tone={backup.invalid ? "error" : "ok"} label={backup.invalid ? t("damaged") : t("healthy")} />
            }}
            actions={canWrite ? [{ key: "download", label: t("download"), icon: DownloadRoundedIcon, onClick: (backup) => void download(backup), hidden: (backup) => !(backup.filename ?? backup.backup_id) }] : undefined}
            empty={<EmptyState compact icon={BackupRoundedIcon} title={t("noBackupsTitle")} body={t("noBackupsBody")} />}
          />
        )}
      </SectionCard>

      {isAdvanced && canWrite && backups && <RestoreCard backups={backups.filter((item) => !item.invalid && backupFile(item))} />}
      {isAdvanced && <RegistrySettings keys={BACKUP_SETTING_KEYS} permissions={permissions} title={t("settingsBackup")} />}
      {snackbar}
    </Stack>
  );
}

function RestoreCard({ backups }: { backups: BackupRecord[] }) {
  const { language } = useKit();
  const t = (key: Key) => T[key][language];
  const [selected, setSelected] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [validated, setValidated] = useState<{ filename: string; confirmation: string; date: number | undefined } | null>(null);
  const [command, setCommand] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [confirming, setConfirming] = useState(false);
  const [confirmError, setConfirmError] = useState<unknown>(null);
  const filename = selected || (backups[0] ? backupFile(backups[0]) : "");
  const chosen = backups.find((backup) => backupFile(backup) === filename);

  const validate = async () => {
    if (!filename || passphrase.length < MIN_PASSPHRASE) return;
    setBusy(true);
    setError(null);
    setValidated(null);
    setCommand("");
    try {
      const payload = await mutateJson<{ confirmation: string }>(`/api/v1/backups/${encodeURIComponent(filename)}/validate`, { method: "POST", body: { passphrase } });
      // Keep the passphrase: the restore plan needs it again.
      setValidated({ filename, confirmation: payload.confirmation, date: chosen?.created_at });
    } catch (caught) {
      if (!isUnauthorized(caught)) setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const prepare = async () => {
    if (!validated) return;
    setBusy(true);
    setConfirmError(null);
    try {
      const payload = await mutateJson<{ apply_command: string }>(`/api/v1/backups/${encodeURIComponent(validated.filename)}/restore-plan`, { method: "POST", body: { passphrase, confirmation: validated.confirmation } });
      setCommand(payload.apply_command);
      setPassphrase("");
      setConfirming(false);
    } catch (caught) {
      setConfirmError(caught);
    } finally {
      setBusy(false);
    }
  };

  const typed: ConfirmWord | undefined = validated ? { word: { fa: T.restoreWord.fa, en: validated.confirmation }, token: validated.confirmation } : undefined;
  const dateText = validated?.date ? new Intl.DateTimeFormat(language === "fa" ? "fa-IR-u-ca-persian" : "en-GB", { dateStyle: "medium", timeStyle: "short" }).format(new Date(validated.date * 1000)) : "";

  return (
    <SectionCard title={t("restoreTitle")} hint={t("restoreHint")} tone="warning" action={<HelpTip term="restore" />}>
      {backups.length === 0 ? <Notice>{t("noValidBackups")}</Notice> : (
        <Stack spacing={1.5}>
          <Box component="form" onSubmit={(event) => { event.preventDefault(); void validate(); }}>
            <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} alignItems={{ md: "flex-start" }}>
              <TextField select fullWidth size="small" label={t("pickBackup")} value={filename} onChange={(event) => { setSelected(event.target.value); setValidated(null); setCommand(""); }}>
                {backups.map((backup) => (
                  <MenuItem key={backupFile(backup)} value={backupFile(backup)}>
                    <RelativeTime value={backup.created_at ?? null} relativeAlways />&nbsp;· <Bytes value={backup.size_bytes} />
                  </MenuItem>
                ))}
              </TextField>
              <TextField fullWidth size="small" type="password" autoComplete="off" label={T.passphrase[language]} value={passphrase} onChange={(event) => setPassphrase(event.target.value)} helperText={passphrase.length > 0 && passphrase.length < MIN_PASSPHRASE ? t("passphraseShort") : " "} slotProps={{ htmlInput: { maxLength: 1024, dir: "ltr" } }} />
              <Button type="submit" variant="outlined" disabled={busy || passphrase.length < MIN_PASSPHRASE} startIcon={busy && !validated ? <CircularProgress size={16} /> : <FactCheckRoundedIcon />} sx={{ flexShrink: 0 }}>{busy && !validated ? t("checking") : t("validate")}</Button>
            </Stack>
          </Box>
          {error !== null && <FriendlyError error={error} noAction />}
          {validated && !command && (
            <Notice tone="success" action={<Button color="warning" variant="contained" startIcon={<RestoreRoundedIcon />} onClick={() => setConfirming(true)}>{t("prepare")}</Button>}>
              {t("valid")}
            </Notice>
          )}
          {command && (
            <Stack spacing={1}>
              <Notice tone="success">{t("planReady")}</Notice>
              <CopyField label={t("applyCommand")} value={command} multiline />
            </Stack>
          )}
        </Stack>
      )}
      {validated && typed && (
        <ConfirmAction
          open={confirming}
          title={say(language, T.restoreConfirmTitle, { date: dateText })}
          body={t("restoreConfirmBody")}
          consequences={[t("restoreConsequence1"), t("restoreConsequence2")]}
          severity="destructive"
          typed={typed}
          confirmLabel={t("prepare")}
          busy={busy}
          error={confirmError}
          onConfirm={() => void prepare()}
          onClose={() => setConfirming(false)}
        />
      )}
    </SectionCard>
  );
}

// ─────────────────────────── keep storage healthy ───────────────────────────

function HealthSection({ permissions }: { permissions: string[] }) {
  const { language, isAdvanced, c } = useKit();
  const t = (key: Key) => T[key][language];
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canRead = hasPermission(permissions, "cache:read");
  const canPurge = hasPermission(permissions, "task:write") && hasPermission(permissions, "cache:write");
  const canScan = hasPermission(permissions, "task:write");
  const [target, setTarget] = useState(SIMPLE_TARGET);
  const [committed, setCommitted] = useState(SIMPLE_TARGET);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [cleanup, setCleanup] = useState<CleanupTask | null>(null);
  const [cleanupResult, setCleanupResult] = useState<CleanupSummary | null>(null);
  const [scanFull, setScanFull] = useState(false);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanStarted, setScanStarted] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const effectiveTarget = isAdvanced ? committed : SIMPLE_TARGET;

  const load = useCallback(async () => {
    if (!canRead) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      setPreview(await getJson<Preview>(`/api/v1/lifecycle/cleanup-preview?target_percent=${effectiveTarget}`, current.signal));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || isUnauthorized(caught)) return;
      setError(caught);
    }
  }, [canRead, effectiveTarget]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  // Follow the server-side clean-up job, then report what happened in plain words.
  const cleanupId = cleanup?.id ?? null;
  useEffect(() => {
    if (!cleanupId) return;
    let stopped = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const payload = await getJson<{ items: CleanupTask[] }>("/api/v1/tasks?limit=50");
        const found = payload.items.find((item) => item.id === cleanupId);
        if (stopped) return;
        if (found) {
          setCleanup((current) => (current ? { ...current, ...found } : current));
          if (found.state === "succeeded" || found.state === "failed" || found.state === "cancelled") {
            const result = found.result ?? {};
            const purged = result.purged_count ?? result.purged?.length ?? 0;
            const skipped = result.skipped?.length ?? 0;
            const failed = result.failed?.length ?? 0;
            if (found.state === "failed" && purged === 0) {
              setActionError(say(language, T.freeFailed, { reason: reasonFor(language, found.error_code) }));
            } else {
              setCleanupResult({ purged, skipped, failed, reclaimed: result.reclaimed_bytes ?? 0, cancelled: found.state === "cancelled" || Boolean(result.cancelled), firstFailure: result.failed?.[0]?.error_code ?? null });
            }
            setCleanup(null);
            void load();
            return;
          }
        }
      } catch {
        // transient polling failure: try again on the next tick
      }
      if (!stopped) timer = window.setTimeout(() => void poll(), TASK_POLL_MS);
    };
    timer = window.setTimeout(() => void poll(), TASK_POLL_MS);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [cleanupId, language, load]);

  const freeUp = async () => {
    if (!preview || preview.candidates.length === 0) return;
    const candidates = preview.candidates;
    const token = preview.confirmation ?? `CLEANUP ${candidates.length} PACKAGES`;
    const ok = await ask({
      title: say(language, T.freeTitle, { count: candidates.length }),
      body: say(language, T.freeBody, { size: formatSize(preview.candidate_reclaim_bytes, language) }),
      consequences: [t("freeConsequence1"), t("freeConsequence2"), t("freeConsequence3")],
      severity: "destructive",
      typed: deleteConfirmation(token),
      confirmLabel: t("freeUp")
    });
    if (!ok) return;
    setActionError(null);
    setCleanupResult(null);
    try {
      const queued = await mutateJson<{ task_id: string; candidate_count?: number; skipped?: unknown[] }>("/api/v1/lifecycle/cleanup", {
        method: "POST",
        body: { candidates: candidates.map((item) => ({ ecosystem: item.ecosystem, name: item.name })), confirmation: token }
      });
      setCleanup({ id: queued.task_id, state: "pending", progress: 0, error_code: null, total: queued.candidate_count ?? candidates.length });
    } catch (caught) {
      if (!isUnauthorized(caught)) setActionError(caught);
      void load();
    }
  };

  const scan = async () => {
    setScanBusy(true);
    setActionError(null);
    try {
      await mutateJson<{ task_id: string }>(`/api/v1/lifecycle/integrity-scan${scanFull ? "?full=true" : ""}`, { method: "POST" });
      setScanStarted(true);
    } catch (caught) {
      if (!isUnauthorized(caught)) setActionError(caught);
    } finally {
      setScanBusy(false);
    }
  };

  if (!canRead) return <NoAccess needs="cache:read" variant="card" />;

  const used = preview?.current_percent ?? null;
  const tone = used === null ? "off" : used >= 90 ? "error" : used >= 80 ? "warn" : "ok";
  const needsCleanup = Boolean(preview && preview.required_reclaim_bytes > 0 && preview.candidates.length > 0);
  const remaining = Math.max(0, (preview?.candidates.length ?? 0) - CANDIDATE_LIMIT);

  return (
    <Stack spacing={2.5}>
      <SectionCard
        title={t("diskTitle")}
        hint={t("diskHint")}
        action={<Button aria-label={c.refresh} onClick={() => void load()} sx={{ minWidth: 44, minHeight: 44 }}><RefreshRoundedIcon /></Button>}
      >
        {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
        {!preview && error === null && <LinearProgress aria-label={c.loading} />}
        {preview && (
          <Stack spacing={2}>
            <StatGrid>
              <StatTile
                icon={StorageRoundedIcon}
                label={t("used")}
                value={<Percent value={used} />}
                meter={used}
                tone={tone}
                caption={preview.used_bytes !== undefined && preview.total_bytes !== undefined ? say(language, T.usedOf, { used: formatSize(preview.used_bytes, language), total: formatSize(preview.total_bytes, language) }) : undefined}
              />
              {preview.free_bytes !== undefined && <StatTile label={t("free")} value={<Bytes value={preview.free_bytes} />} />}
              {preview.trash_bytes !== undefined && <StatTile label={t("trash")} value={<Bytes value={preview.trash_bytes} />} caption={t("trashHint")} />}
            </StatGrid>
            {cleanup ? (
              <Box role="status">
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography variant="body2" color="text.secondary">{say(language, T.freeing, { total: cleanup.total ?? 0 })}</Typography>
                  <Button size="small" href={JOBS_HREF}>{t("viewJobs")}</Button>
                </Stack>
                <LinearProgress variant={cleanup.progress > 0 ? "determinate" : "indeterminate"} value={cleanup.progress} aria-label={t("freeUp")} sx={{ mt: 0.5, height: 6, borderRadius: 1 }} />
              </Box>
            ) : needsCleanup ? (
              <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
                <Button variant="contained" startIcon={<CleaningServicesRoundedIcon />} disabled={!canPurge} onClick={() => void freeUp()}>{t("freeUp")}</Button>
                {!canPurge && <NoAccess needs={["cache:write", "task:write"]} />}
              </Stack>
            ) : (
              <Notice tone="success">{t("enoughSpace")}</Notice>
            )}
            {cleanupResult && (
              <Notice tone={cleanupResult.failed > 0 ? "warning" : "success"}>
                {say(language, cleanupResult.cancelled ? T.freeCancelled : T.freeDone, { count: cleanupResult.purged, size: formatSize(cleanupResult.reclaimed, language) })}
                {cleanupResult.skipped > 0 && <> {say(language, T.freeSkipped, { count: cleanupResult.skipped })}</>}
                {cleanupResult.failed > 0 && <> {say(language, T.freeSomeFailed, { failed: cleanupResult.failed, reason: reasonFor(language, cleanupResult.firstFailure) })}</>}
              </Notice>
            )}
            {actionError !== null && (typeof actionError === "string" ? <Notice tone="error">{actionError}</Notice> : <FriendlyError error={actionError} onClose={() => setActionError(null)} onRetry={() => void load()} scope="lifecycle" />)}
          </Stack>
        )}
      </SectionCard>

      {isAdvanced && preview && (
        <SectionCard title={t("cleanupTitle")} hint={t("cleanupHint")} flush>
          <Box sx={{ px: { xs: 2, sm: 2.5 }, pb: 1.5 }}>
            <PercentSlider label={t("target")} value={target} min={20} max={90} step={5} onChange={(value) => { setTarget(value); setCommitted(value); }} />
            <Stack direction="row" spacing={3} flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
              <Typography variant="body2">{t("reclaim")}: <b><Bytes value={preview.required_reclaim_bytes} /></b></Typography>
              <Typography variant="body2">{t("candidate")}: <b><Bytes value={preview.candidate_reclaim_bytes} /></b></Typography>
            </Stack>
          </Box>
          <ResponsiveList
            label={t("cleanupTitle")}
            rows={preview.candidates.slice(0, CANDIDATE_LIMIT)}
            rowKey={(item) => `${item.ecosystem}:${item.name}`}
            columns={[
              { key: "name", header: t("colPackage"), ltr: true, render: (item) => <Ltr>{item.name}</Ltr> },
              { key: "eco", header: t("colEco"), render: (item) => ECOSYSTEM_NAMES[item.ecosystem] ?? item.ecosystem },
              { key: "size", header: t("colSize"), render: (item) => <Bytes value={item.size_bytes} /> },
              { key: "last", header: t("colLastUse"), render: (item) => <RelativeTime value={item.latest_mtime} /> }
            ]}
            card={{ title: (item) => <Ltr>{item.name}</Ltr>, meta: (item) => <>{ECOSYSTEM_NAMES[item.ecosystem] ?? item.ecosystem} · <Bytes value={item.size_bytes} /></> }}
            empty={<EmptyState compact title={t("noCandidates")} />}
          />
          {(remaining > 0 || preview.truncated) && <Typography variant="caption" color="text.secondary" sx={{ display: "block", px: 2.5, pb: 2 }}>{say(language, T.more, { count: remaining })}</Typography>}
        </SectionCard>
      )}

      {isAdvanced && (
        <SectionCard title={t("integrityTitle")} hint={t("integrityHint")} action={<FactCheckRoundedIcon color="primary" aria-hidden />}>
          {!canScan ? <NoAccess needs="task:write" variant="card" /> : (
            <Stack spacing={1} alignItems="flex-start">
              <FormControlLabel control={<Switch checked={scanFull} onChange={(event) => setScanFull(event.target.checked)} />} label={t("integrityFull")} />
              <Button variant="outlined" disabled={scanBusy} startIcon={scanBusy ? <CircularProgress size={16} /> : <FactCheckRoundedIcon />} onClick={() => void scan()}>{t("integrityRun")}</Button>
              {scanStarted && <Notice tone="success" action={<Button size="small" href={JOBS_HREF}>{t("viewJobs")}</Button>}>{t("integrityStarted")}</Notice>}
            </Stack>
          )}
        </SectionCard>
      )}

      {isAdvanced && <RegistrySettings keys={HEALTH_SETTING_KEYS} permissions={permissions} title={t("settingsHealth")} />}
      {dialog}
      {snackbar}
    </Stack>
  );
}

export function LifecyclePanel({ permissions, section }: Props) {
  return (
    <Stack spacing={3}>
      {section !== "health" && <PanelBackupSection permissions={permissions} />}
      {section !== "backup" && <HealthSection permissions={permissions} />}
    </Stack>
  );
}
