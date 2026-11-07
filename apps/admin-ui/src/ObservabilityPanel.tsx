import { useCallback, useEffect, useMemo, useState } from "react";
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
  Paper,
  Stack,
  Tooltip,
  Typography
} from "@mui/material";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import MonitorHeartRoundedIcon from "@mui/icons-material/MonitorHeartRounded";
import SecurityRoundedIcon from "@mui/icons-material/SecurityRounded";
import TaskAltRoundedIcon from "@mui/icons-material/TaskAltRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import type { Language } from "./i18n";

type AuditEvent = {
  id: number;
  actor_user_id: number | null;
  action: string;
  object_type: string;
  object_id: string | null;
  result: string;
  source_ip: string | null;
  request_id: string | null;
  occurred_at: number;
};

type TaskRecord = { state: "pending" | "running" | "succeeded" | "failed" | "cancelled" };
type Status = {
  uptime_seconds: number;
  storage: { total_bytes: number; used_bytes: number; free_bytes: number; used_percent: number };
  components: Record<string, string>;
};

type Props = {
  language: Language;
  permissions: string[];
  onUnauthorized: () => void;
};

const labels = {
  fa: {
    title: "مانیتورینگ و رویدادها",
    hint: "سلامت سرویس، وظایف، ظرفیت و رویدادهای امنیتی را از یک نقطه بررسی کنید.",
    refresh: "بروزرسانی",
    error: "دریافت اطلاعات مانیتورینگ ناموفق بود.",
    health: "سلامت مؤلفه‌ها",
    storage: "مصرف فضای ذخیره‌سازی",
    jobs: "وضعیت وظایف",
    audit: "آخرین رویدادهای Audit",
    auditHint: "ثبت append-only عملیات مدیریتی و امنیتی",
    exportAudit: "دانلود CSV",
    supportBundle: "دانلود Support Bundle",
    supportNotice: "Support Bundle شامل تنظیمات امن، وضعیت، وظایف و audit است؛ لاگ خام و credential عمداً حذف شده‌اند.",
    metrics: "Prometheus metrics",
    metricsHint: "برای scrape از API Token دارای system:read استفاده کنید.",
    ready: "آماده",
    unavailable: "خارج از دسترس",
    notConfigured: "پیکربندی نشده",
    empty: "هنوز رویدادی ثبت نشده است.",
    actor: "کاربر",
    request: "Request ID",
    pending: "در صف",
    running: "در حال اجرا",
    succeeded: "موفق",
    failed: "ناموفق",
    cancelled: "لغوشده",
    runbooks: "راهنمای واکنش",
    registryRunbook: "رجیستری خارج از دسترس",
    registryAction: "ابتدا probe منبع بالادستی و سپس حالت cache-only را بررسی کنید.",
    storageRunbook: "ظرفیت بالاتر از ۸۵٪",
    storageAction: "قبل از پاک‌سازی، dry-run و وضعیت Pin پکیج‌ها را بازبینی کنید.",
    jobsRunbook: "وظایف ناموفق",
    jobsAction: "error code را بررسی و فقط پس از رفع علت از Retry استفاده کنید."
  },
  en: {
    title: "Observability and events",
    hint: "Inspect service health, jobs, capacity, and security events from one place.",
    refresh: "Refresh",
    error: "Could not load observability data.",
    health: "Component health",
    storage: "Storage usage",
    jobs: "Job status",
    audit: "Recent audit events",
    auditHint: "Append-only administrative and security activity",
    exportAudit: "Download CSV",
    supportBundle: "Download support bundle",
    supportNotice: "The support bundle includes safe configuration, status, jobs, and audit data; raw logs and credentials are deliberately excluded.",
    metrics: "Prometheus metrics",
    metricsHint: "Use an API token with system:read for scraping.",
    ready: "Ready",
    unavailable: "Unavailable",
    notConfigured: "Not configured",
    empty: "No events have been recorded yet.",
    actor: "Actor",
    request: "Request ID",
    pending: "Pending",
    running: "Running",
    succeeded: "Succeeded",
    failed: "Failed",
    cancelled: "Cancelled",
    runbooks: "Response guides",
    registryRunbook: "Registry unavailable",
    registryAction: "Check the upstream probe first, then verify cache-only mode.",
    storageRunbook: "Capacity above 85%",
    storageAction: "Review cleanup dry-run and package pins before removing data.",
    jobsRunbook: "Failed jobs",
    jobsAction: "Inspect the error code and retry only after resolving its cause."
  }
} as const;

function bytes(value: number) {
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  return `${(value / 1024 ** 3).toFixed(1)} GB`;
}

export function ObservabilityPanel({ language, permissions, onUnauthorized }: Props) {
  const copy = labels[language];
  const canAudit = permissions.includes("*") || permissions.includes("audit:read");
  const [status, setStatus] = useState<Status | null>(null);
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [statusResponse, tasksResponse, auditResponse] = await Promise.all([
        fetch("/api/v1/system/status", { cache: "no-store" }),
        fetch("/api/v1/tasks?limit=100", { cache: "no-store" }),
        canAudit ? fetch("/api/v1/audit-events?limit=50", { cache: "no-store" }) : Promise.resolve(null)
      ]);
      if (statusResponse.status === 401 || tasksResponse.status === 401 || auditResponse?.status === 401) return onUnauthorized();
      if (!statusResponse.ok || !tasksResponse.ok || (auditResponse && !auditResponse.ok)) throw new Error("observability load failed");
      setStatus((await statusResponse.json()) as Status);
      setTasks(((await tasksResponse.json()) as { items: TaskRecord[] }).items);
      setAudit(auditResponse ? ((await auditResponse.json()) as { items: AuditEvent[] }).items : []);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [canAudit, onUnauthorized]);

  useEffect(() => { void load(); }, [load]);

  const taskCounts = useMemo(() => {
    const counts = { pending: 0, running: 0, succeeded: 0, failed: 0, cancelled: 0 };
    tasks.forEach((task) => { counts[task.state] += 1; });
    return counts;
  }, [tasks]);

  const formatTime = (value: number) => new Intl.DateTimeFormat(language === "fa" ? "fa-IR" : "en-US", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value * 1000));
  const componentLabel = (state: string) => state === "ready" ? copy.ready : state === "unavailable" ? copy.unavailable : copy.notConfigured;
  const componentColor = (state: string) => state === "ready" ? "success" : state === "unavailable" ? "error" : "default";

  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "flex-end" }} spacing={2}>
        <Box><Typography variant="h4" component="h1">{copy.title}</Typography><Typography color="text.secondary" sx={{ mt: 0.8 }}>{copy.hint}</Typography></Box>
        <Button variant="outlined" startIcon={loading ? <CircularProgress size={16} /> : <RefreshRoundedIcon />} disabled={loading} onClick={() => void load()}>{copy.refresh}</Button>
      </Stack>
      {error && <Alert severity="error">{copy.error}</Alert>}

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, lg: 4 }}><Card sx={{ height: "100%" }}><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Stack direction="row" alignItems="center" spacing={1}><MonitorHeartRoundedIcon color="primary" /><Typography fontWeight={760}>{copy.health}</Typography></Stack><Stack divider={<Divider flexItem />} sx={{ mt: 1.5 }}>{Object.entries(status?.components ?? {}).map(([name, state]) => <Stack key={name} direction="row" justifyContent="space-between" alignItems="center" sx={{ py: 1 }}><Tooltip title={name}><Typography variant="body2" dir="ltr" noWrap sx={{ maxWidth: 170 }}>{name.replaceAll("_", " ")}</Typography></Tooltip><Chip size="small" color={componentColor(state)} label={componentLabel(state)} /></Stack>)}</Stack></CardContent></Card></Grid>
        <Grid size={{ xs: 12, lg: 4 }}><Card sx={{ height: "100%" }}><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Stack direction="row" alignItems="center" spacing={1}><StorageRoundedIcon color="secondary" /><Typography fontWeight={760}>{copy.storage}</Typography></Stack><Typography variant="h4" sx={{ mt: 2 }}>{status?.storage.used_percent ?? 0}%</Typography><LinearProgress variant="determinate" value={status?.storage.used_percent ?? 0} color={(status?.storage.used_percent ?? 0) >= 85 ? "warning" : "primary"} sx={{ mt: 1.3, height: 7, borderRadius: 1 }} /><Typography variant="body2" color="text.secondary" dir="ltr" sx={{ mt: 1.2 }}>{status ? `${bytes(status.storage.used_bytes)} / ${bytes(status.storage.total_bytes)}` : "—"}</Typography></CardContent></Card></Grid>
        <Grid size={{ xs: 12, lg: 4 }}><Card sx={{ height: "100%" }}><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Stack direction="row" alignItems="center" spacing={1}><TaskAltRoundedIcon color="success" /><Typography fontWeight={760}>{copy.jobs}</Typography></Stack><Grid container spacing={1} sx={{ mt: 1 }}>{Object.entries(taskCounts).map(([state, count]) => <Grid key={state} size={{ xs: 6 }}><Paper variant="outlined" sx={{ p: 1.2, bgcolor: "transparent" }}><Typography variant="h6">{count}</Typography><Typography variant="caption" color="text.secondary">{copy[state as keyof typeof taskCounts]}</Typography></Paper></Grid>)}</Grid></CardContent></Card></Grid>
      </Grid>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, lg: 7 }}><Card sx={{ height: "100%" }}><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" spacing={1}><Box><Typography fontWeight={760}>{copy.audit}</Typography><Typography variant="body2" color="text.secondary">{copy.auditHint}</Typography></Box>{canAudit && <Button size="small" startIcon={<DownloadRoundedIcon />} href="/api/v1/audit-events/export.csv">{copy.exportAudit}</Button>}</Stack><Stack divider={<Divider flexItem />} sx={{ mt: 1.5 }}>{audit.length === 0 && <Alert severity="info">{copy.empty}</Alert>}{audit.map((item) => <Stack key={item.id} direction={{ xs: "column", sm: "row" }} justifyContent="space-between" spacing={1} sx={{ py: 1.25, minWidth: 0 }}><Box sx={{ minWidth: 0 }}><Typography variant="body2" fontWeight={700} dir="ltr" noWrap>{item.action}</Typography><Typography variant="caption" color="text.secondary" dir="ltr" noWrap>{item.object_type}{item.object_id ? ` · ${item.object_id}` : ""}</Typography></Box><Box sx={{ textAlign: { sm: "end" }, flexShrink: 0 }}><Chip size="small" color={item.result === "success" ? "success" : "error"} label={item.result} /><Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>{formatTime(item.occurred_at)}</Typography></Box></Stack>)}</Stack></CardContent></Card></Grid>
        <Grid size={{ xs: 12, lg: 5 }}><Stack spacing={2}><Card><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Stack direction="row" alignItems="center" spacing={1}><SecurityRoundedIcon color="primary" /><Typography fontWeight={760}>{copy.supportBundle}</Typography></Stack><Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{copy.supportNotice}</Typography><Button fullWidth variant="outlined" startIcon={<DownloadRoundedIcon />} href="/api/v1/support-bundle" disabled={!canAudit} sx={{ mt: 2 }}>{copy.supportBundle}</Button></CardContent></Card><Card><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Typography fontWeight={760}>{copy.metrics}</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: 0.7 }}>{copy.metricsHint}</Typography><Paper variant="outlined" sx={{ mt: 1.5, p: 1.2, bgcolor: "transparent" }}><Typography component="code" dir="ltr" variant="body2">GET /metrics</Typography></Paper></CardContent></Card></Stack></Grid>
      </Grid>

      <Card><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Typography fontWeight={760}>{copy.runbooks}</Typography><Grid container spacing={1.5} sx={{ mt: 0.5 }}>{[[copy.registryRunbook, copy.registryAction], [copy.storageRunbook, copy.storageAction], [copy.jobsRunbook, copy.jobsAction]].map(([title, action]) => <Grid key={title} size={{ xs: 12, md: 4 }}><Paper variant="outlined" sx={{ p: 1.6, bgcolor: "transparent", height: "100%" }}><Typography variant="body2" fontWeight={720}>{title}</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.7 }}>{action}</Typography></Paper></Grid>)}</Grid></CardContent></Card>
    </Stack>
  );
}
