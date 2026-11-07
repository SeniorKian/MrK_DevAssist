import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Grid,
  LinearProgress,
  Slider,
  Stack,
  TextField,
  Typography
} from "@mui/material";
import FactCheckRoundedIcon from "@mui/icons-material/FactCheckRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import type { Language } from "./i18n";

type Candidate = { ecosystem: string; name: string; size_bytes: number; latest_mtime: number };
type Preview = {
  target_percent: number;
  current_percent: number;
  required_reclaim_bytes: number;
  candidate_reclaim_bytes: number;
  candidates: Candidate[];
  truncated: boolean;
  dry_run: boolean;
};
type BackupRecord = {
  backup_id?: string;
  filename: string;
  created_at?: number;
  size_bytes: number;
  cipher?: string;
  invalid?: boolean;
};

type Props = {
  language: Language;
  csrf: string;
  permissions: string[];
  onUnauthorized: () => void;
};

const labels = {
  fa: {
    title: "چرخه عمر داده",
    hint: "ظرفیت، پاک‌سازی آزمایشی و یکپارچگی cache را بدون حذف ناخواسته مدیریت کنید.",
    target: "هدف مصرف فضای ذخیره‌سازی",
    current: "مصرف فعلی",
    reclaim: "فضای موردنیاز برای آزادسازی",
    candidate: "فضای قابل آزادسازی از گزینه‌ها",
    preview: "گزینه‌های پیشنهادی پاک‌سازی",
    dryRun: "فقط پیش‌نمایش؛ هیچ فایلی حذف نشده است.",
    empty: "در آستانه فعلی نیازی به پاک‌سازی نیست.",
    refresh: "محاسبه مجدد",
    scan: "اجرای Integrity Scan",
    queued: "Integrity Scan در صف قرار گرفت",
    error: "دریافت یا اجرای عملیات چرخه عمر ناموفق بود.",
    readOnly: "نقش شما فقط اجازه مشاهده دارد.",
    protected: "پکیج‌های Pin و Quarantine از گزینه‌ها حذف می‌شوند.",
    backups: "پشتیبان‌های رمزگذاری‌شده",
    backupHint: "Passphrase فقط در حافظه درخواست استفاده می‌شود و ذخیره نخواهد شد.",
    passphrase: "Passphrase حداقل ۱۶ کاراکتر",
    createBackup: "ساخت Backup",
    validateBackup: "اعتبارسنجی ایزوله",
    backupCreated: "Backup رمزگذاری‌شده ساخته شد",
    backupValid: "Backup بدون استخراج روی داده فعال، معتبر است",
    noBackups: "هنوز Backup ساخته نشده است.",
    restorePrepare: "آماده‌سازی Restore آفلاین",
    restoreConfirmation: "عبارت تأیید Restore",
    restoreWarning: "Restore فقط بعد از توقف کامل سرویس و با CLI آفلاین اعمال می‌شود. Passphrase در plan ذخیره نمی‌شود.",
    restorePlanReady: "Restore plan آماده شد؛ دستور زیر را فقط پس از توقف سرویس اجرا کنید."
  },
  en: {
    title: "Data lifecycle",
    hint: "Manage capacity, cleanup previews, and cache integrity without accidental deletion.",
    target: "Storage usage target",
    current: "Current usage",
    reclaim: "Required reclaim",
    candidate: "Candidate reclaim",
    preview: "Suggested cleanup candidates",
    dryRun: "Preview only; no files were removed.",
    empty: "No cleanup is required at the current threshold.",
    refresh: "Recalculate",
    scan: "Run integrity scan",
    queued: "Integrity scan was queued",
    error: "Could not load or run lifecycle operation.",
    readOnly: "Your role has view-only access.",
    protected: "Pinned and quarantined packages are excluded from candidates.",
    backups: "Encrypted backups",
    backupHint: "The passphrase is used only in request memory and is never persisted.",
    passphrase: "Passphrase (16+ characters)",
    createBackup: "Create backup",
    validateBackup: "Validate in isolation",
    backupCreated: "Encrypted backup was created",
    backupValid: "Backup is valid without extracting over active data",
    noBackups: "No backups have been created yet.",
    restorePrepare: "Prepare offline restore",
    restoreConfirmation: "Restore confirmation phrase",
    restoreWarning: "Restore is applied only by the offline CLI after the service is fully stopped. The passphrase is never stored in the plan.",
    restorePlanReady: "The restore plan is ready. Run this command only after stopping the service."
  }
} as const;

function bytes(value: number) {
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  return `${(value / 1024 ** 3).toFixed(1)} GB`;
}

export function LifecyclePanel({ language, csrf, permissions, onUnauthorized }: Props) {
  const copy = labels[language];
  const canRun = permissions.includes("*") || permissions.includes("task:write");
  const canBackupRead = permissions.includes("*") || permissions.includes("backup:read");
  const canBackupWrite = permissions.includes("*") || permissions.includes("backup:write");
  const [target, setTarget] = useState(75);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [backups, setBackups] = useState<BackupRecord[]>([]);
  const [passphrase, setPassphrase] = useState("");
  const [validatedRestore, setValidatedRestore] = useState<{ filename: string; confirmation: string } | null>(null);
  const [restoreConfirmation, setRestoreConfirmation] = useState("");
  const [restoreCommand, setRestoreCommand] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [response, backupResponse] = await Promise.all([
        fetch(`/api/v1/lifecycle/cleanup-preview?target_percent=${target}`, { cache: "no-store" }),
        canBackupRead ? fetch("/api/v1/backups", { cache: "no-store" }) : Promise.resolve(null)
      ]);
      if (response.status === 401 || backupResponse?.status === 401) return onUnauthorized();
      if (!response.ok || (backupResponse && !backupResponse.ok)) throw new Error("preview failed");
      setPreview((await response.json()) as Preview);
      setBackups(backupResponse ? ((await backupResponse.json()) as { items: BackupRecord[] }).items : []);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [canBackupRead, onUnauthorized, target]);

  useEffect(() => { void load(); }, [load]);

  const scan = async () => {
    setLoading(true);
    try {
      const response = await fetch("/api/v1/lifecycle/integrity-scan", { method: "POST", headers: { "X-CSRF-Token": csrf } });
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("scan failed");
      const payload = (await response.json()) as { task_id: string };
      setNotice(`${copy.queued}: ${payload.task_id}`);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  const backupAction = async (filename?: string) => {
    if (passphrase.length < 16) return;
    setLoading(true);
    try {
      const response = await fetch(filename ? `/api/v1/backups/${encodeURIComponent(filename)}/validate` : "/api/v1/backups", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ passphrase })
      });
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("backup operation failed");
      const payload = (await response.json()) as { confirmation?: string };
      if (filename && payload.confirmation) {
        setValidatedRestore({ filename, confirmation: payload.confirmation });
        setRestoreConfirmation("");
        setRestoreCommand("");
      }
      setNotice(filename ? copy.backupValid : copy.backupCreated);
      setPassphrase("");
      await load();
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  const prepareRestore = async () => {
    if (!validatedRestore || passphrase.length < 16) return;
    setLoading(true);
    try {
      const response = await fetch(`/api/v1/backups/${encodeURIComponent(validatedRestore.filename)}/restore-plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ passphrase, confirmation: restoreConfirmation })
      });
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("restore plan failed");
      const payload = (await response.json()) as { apply_command: string };
      setRestoreCommand(payload.apply_command);
      setPassphrase("");
      setNotice(copy.restorePlanReady);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "flex-end" }} spacing={2}><Box><Typography variant="h4" component="h1">{copy.title}</Typography><Typography color="text.secondary" sx={{ mt: 0.8 }}>{copy.hint}</Typography></Box><Stack direction="row" spacing={1}><Button variant="outlined" startIcon={<RefreshRoundedIcon />} disabled={loading} onClick={() => void load()}>{copy.refresh}</Button><Button variant="contained" startIcon={loading ? <CircularProgress size={16} /> : <FactCheckRoundedIcon />} disabled={!canRun || loading} onClick={() => void scan()}>{copy.scan}</Button></Stack></Stack>
      {error && <Alert severity="error">{copy.error}</Alert>}
      {!canRun && <Alert severity="info">{copy.readOnly}</Alert>}
      {notice && <Alert severity="success" onClose={() => setNotice(null)}>{notice}</Alert>}
      <Alert severity="info">{copy.dryRun} {copy.protected}</Alert>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, lg: 5 }}><Card sx={{ height: "100%" }}><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Typography fontWeight={760}>{copy.target}: {target}%</Typography><Slider value={target} min={20} max={90} step={5} valueLabelDisplay="auto" onChange={(_event, value) => setTarget(value as number)} sx={{ mt: 2 }} /><Divider sx={{ my: 2 }} /><Stack spacing={1.5}><Stack direction="row" justifyContent="space-between"><Typography color="text.secondary" variant="body2">{copy.current}</Typography><Typography fontWeight={720}>{preview?.current_percent ?? 0}%</Typography></Stack><LinearProgress variant="determinate" value={preview?.current_percent ?? 0} color={(preview?.current_percent ?? 0) > target ? "warning" : "primary"} sx={{ height: 7, borderRadius: 1 }} /><Stack direction="row" justifyContent="space-between"><Typography color="text.secondary" variant="body2">{copy.reclaim}</Typography><Typography fontWeight={720}>{bytes(preview?.required_reclaim_bytes ?? 0)}</Typography></Stack><Stack direction="row" justifyContent="space-between"><Typography color="text.secondary" variant="body2">{copy.candidate}</Typography><Typography fontWeight={720}>{bytes(preview?.candidate_reclaim_bytes ?? 0)}</Typography></Stack></Stack></CardContent></Card></Grid>
        <Grid size={{ xs: 12, lg: 7 }}><Card sx={{ height: "100%" }}><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Typography fontWeight={760}>{copy.preview}</Typography><Stack divider={<Divider flexItem />} sx={{ mt: 1.5 }}>{preview?.candidates.length === 0 && <Alert severity="success">{copy.empty}</Alert>}{preview?.candidates.slice(0, 25).map((item) => <Stack key={`${item.ecosystem}:${item.name}`} direction="row" alignItems="center" spacing={1} sx={{ py: 1, minWidth: 0 }}><Chip size="small" label={item.ecosystem} /><Typography dir="ltr" noWrap sx={{ minWidth: 0, flex: 1 }}>{item.name}</Typography><Typography variant="body2" color="text.secondary" sx={{ flexShrink: 0 }}>{bytes(item.size_bytes)}</Typography></Stack>)}</Stack></CardContent></Card></Grid>
      </Grid>

      {canBackupRead && <Card><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Typography fontWeight={760}>{copy.backups}</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: 0.6 }}>{copy.backupHint}</Typography><Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ mt: 2 }}><TextField fullWidth type="password" autoComplete="new-password" label={copy.passphrase} value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /><Button variant="contained" disabled={!canBackupWrite || loading || passphrase.length < 16} onClick={() => void backupAction()} sx={{ flexShrink: 0 }}>{copy.createBackup}</Button></Stack><Stack divider={<Divider flexItem />} sx={{ mt: 2 }}>{backups.length === 0 && <Alert severity="info">{copy.noBackups}</Alert>}{backups.map((backup) => <Stack key={backup.filename} direction={{ xs: "column", sm: "row" }} alignItems={{ sm: "center" }} spacing={1} sx={{ py: 1.2, minWidth: 0 }}><Box sx={{ minWidth: 0, flex: 1 }}><Typography dir="ltr" noWrap fontWeight={700}>{backup.filename}</Typography><Typography variant="caption" color="text.secondary" dir="ltr">{backup.cipher ?? "invalid"} · {bytes(backup.size_bytes)}</Typography></Box><Button size="small" variant="outlined" disabled={!canBackupWrite || loading || passphrase.length < 16 || backup.invalid} onClick={() => void backupAction(backup.filename)}>{copy.validateBackup}</Button></Stack>)}</Stack>{validatedRestore && <Alert severity="warning" sx={{ mt: 2 }}><Typography variant="body2" fontWeight={700}>{copy.restoreWarning}</Typography><Stack direction={{ xs: "column", md: "row" }} spacing={1.5} sx={{ mt: 1.5 }}><TextField fullWidth label={`${copy.restoreConfirmation}: ${validatedRestore.confirmation}`} value={restoreConfirmation} onChange={(event) => setRestoreConfirmation(event.target.value)} inputProps={{ dir: "ltr" }} /><Button variant="outlined" color="warning" disabled={loading || passphrase.length < 16 || restoreConfirmation !== validatedRestore.confirmation} onClick={() => void prepareRestore()} sx={{ flexShrink: 0 }}>{copy.restorePrepare}</Button></Stack></Alert>}{restoreCommand && <Alert severity="success" sx={{ mt: 2 }}><Typography variant="body2">{copy.restorePlanReady}</Typography><Typography component="code" dir="ltr" sx={{ display: "block", mt: 1, overflowWrap: "anywhere" }}>{restoreCommand}</Typography></Alert>}</CardContent></Card>}
    </Stack>
  );
}
