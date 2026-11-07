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
  InputAdornment,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography
} from "@mui/material";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import PushPinRoundedIcon from "@mui/icons-material/PushPinRounded";
import GppBadRoundedIcon from "@mui/icons-material/GppBadRounded";
import DeleteSweepRoundedIcon from "@mui/icons-material/DeleteSweepRounded";
import CloudDownloadRoundedIcon from "@mui/icons-material/CloudDownloadRounded";
import SyncRoundedIcon from "@mui/icons-material/SyncRounded";
import type { Language } from "./i18n";

type PackageRecord = {
  name: string;
  ecosystem: "npm" | "pypi";
  versions: string[];
  artifact_count: number;
  size_bytes: number;
  latest_mtime: number;
  pinned: boolean;
  quarantined: boolean;
  quarantine_reason: string | null;
};

type Props = {
  language: Language;
  csrf: string;
  permissions: string[];
  onUnauthorized: () => void;
};

type PurgePreview = {
  ecosystem: "npm" | "pypi";
  name: string;
  artifact_count: number;
  size_bytes: number;
  blocked_by_pin: boolean;
  confirmation: string;
};

const labels = {
  fa: {
    title: "کاتالوگ پکیج‌ها",
    hint: "محتوای واقعی cache در npm و PyPI را جست‌وجو و سیاست‌های نگه‌داری را مدیریت کنید.",
    search: "جست‌وجوی نام پکیج",
    all: "همه اکوسیستم‌ها",
    versions: "نسخه‌ها",
    artifacts: "فایل",
    size: "حجم",
    pin: "Pin",
    unpin: "Unpin",
    quarantine: "قرنطینه",
    release: "رفع قرنطینه",
    preview: "پیش‌نمایش حذف",
    reason: "دلیل قرنطینه",
    empty: "پکیجی در cache پیدا نشد.",
    error: "دریافت یا تغییر اطلاعات پکیج ناموفق بود.",
    readOnly: "نقش شما اجازه تغییر سیاست cache را ندارد.",
    purgeTitle: "پیش‌نمایش عملیات حذف",
    blocked: "به‌علت Pin امکان حذف ندارد",
    confirmation: "عبارت تأیید",
    executePurge: "اجرای حذف",
    revalidate: "بازاعتبارسنجی",
    taskQueued: "وظیفه با موفقیت در صف قرار گرفت",
    prefetchTitle: "دریافت از قبل",
    prefetchHint: "محتوای requirements.txt یا package-lock.json را وارد کنید تا پکیج‌ها از مسیر همین mirror دریافت و cache شوند.",
    manifest: "محتوای فایل",
    enqueue: "افزودن به صف",
    taskOnly: "نقش شما اجازه اجرای وظایف عملیاتی را ندارد.",
    confirmationMismatch: "عبارت تأیید را دقیقاً وارد کنید."
  },
  en: {
    title: "Package catalog",
    hint: "Search real npm and PyPI cache content and manage retention policies.",
    search: "Search package name",
    all: "All ecosystems",
    versions: "Versions",
    artifacts: "artifacts",
    size: "Size",
    pin: "Pin",
    unpin: "Unpin",
    quarantine: "Quarantine",
    release: "Release",
    preview: "Purge preview",
    reason: "Quarantine reason",
    empty: "No cached packages were found.",
    error: "Could not load or update package data.",
    readOnly: "Your role cannot change cache policies.",
    purgeTitle: "Purge operation preview",
    blocked: "Purge is blocked because this package is pinned",
    confirmation: "Confirmation phrase",
    executePurge: "Execute purge",
    revalidate: "Revalidate",
    taskQueued: "The job was queued successfully",
    prefetchTitle: "Prefetch packages",
    prefetchHint: "Paste requirements.txt or package-lock.json content to download and cache packages through this mirror.",
    manifest: "File content",
    enqueue: "Add to queue",
    taskOnly: "Your role cannot run operational jobs.",
    confirmationMismatch: "Enter the confirmation phrase exactly."
  }
} as const;

function bytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  return `${(value / 1024 ** 3).toFixed(1)} GB`;
}

export function PackagesPanel({ language, csrf, permissions, onUnauthorized }: Props) {
  const copy = labels[language];
  const canWrite = permissions.includes("*") || permissions.includes("cache:write");
  const canRunTasks = permissions.includes("*") || permissions.includes("task:write");
  const [items, setItems] = useState<PackageRecord[]>([]);
  const [query, setQuery] = useState("");
  const [ecosystem, setEcosystem] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [reason, setReason] = useState("manual security review");
  const [preview, setPreview] = useState<PurgePreview | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [taskNotice, setTaskNotice] = useState<string | null>(null);
  const [operationPending, setOperationPending] = useState(false);
  const [prefetchEcosystem, setPrefetchEcosystem] = useState<"npm" | "pypi">("pypi");
  const [manifest, setManifest] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ q: query });
      if (ecosystem) params.set("ecosystem", ecosystem);
      const response = await fetch(`/api/v1/packages?${params}`, { cache: "no-store" });
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("load failed");
      const payload = (await response.json()) as { items: PackageRecord[] };
      setItems(payload.items);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [ecosystem, onUnauthorized, query]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 250);
    return () => window.clearTimeout(timer);
  }, [load]);

  const policy = async (item: PackageRecord, body: object) => {
    try {
      const response = await fetch(
        `/api/v1/packages/${item.ecosystem}/${encodeURIComponent(item.name)}/policy`,
        {
          method: "PUT",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf
          },
          body: JSON.stringify(body)
        }
      );
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("policy failed");
      await load();
    } catch {
      setError(true);
    }
  };

  const purgePreview = async (item: PackageRecord) => {
    try {
      const response = await fetch(
        `/api/v1/packages/${item.ecosystem}/${encodeURIComponent(item.name)}/purge-preview`,
        { method: "POST", headers: { "X-CSRF-Token": csrf } }
      );
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("preview failed");
      setPreview((await response.json()) as PurgePreview);
      setConfirmation("");
    } catch {
      setError(true);
    }
  };

  const queuePackageTask = async (item: PackageRecord, action: "purge" | "revalidate") => {
    if (action === "purge" && (!preview || confirmation !== preview.confirmation)) {
      setError(true);
      return;
    }
    setOperationPending(true);
    setError(false);
    try {
      const response = await fetch(
        `/api/v1/packages/${item.ecosystem}/${encodeURIComponent(item.name)}/${action}`,
        {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf
          },
          body: action === "purge" ? JSON.stringify({ confirmation }) : undefined
        }
      );
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("task enqueue failed");
      const payload = (await response.json()) as { task_id: string };
      setTaskNotice(`${copy.taskQueued}: ${payload.task_id}`);
      setPreview(null);
      setConfirmation("");
    } catch {
      setError(true);
    } finally {
      setOperationPending(false);
    }
  };

  const queuePrefetch = async () => {
    if (!manifest.trim()) return;
    setOperationPending(true);
    setError(false);
    try {
      const response = await fetch("/api/v1/packages/prefetch", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf
        },
        body: JSON.stringify({ ecosystem: prefetchEcosystem, content: manifest })
      });
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("prefetch enqueue failed");
      const payload = (await response.json()) as { task_id: string };
      setTaskNotice(`${copy.taskQueued}: ${payload.task_id}`);
      setManifest("");
    } catch {
      setError(true);
    } finally {
      setOperationPending(false);
    }
  };

  return (
    <Stack spacing={3}>
      <Box><Typography variant="h4" component="h1">{copy.title}</Typography><Typography color="text.secondary" sx={{ mt: 0.8 }}>{copy.hint}</Typography></Box>
      {error && <Alert severity="error">{copy.error}</Alert>}
      {!canWrite && <Alert severity="info">{copy.readOnly}</Alert>}
      {!canRunTasks && <Alert severity="info">{copy.taskOnly}</Alert>}
      {taskNotice && <Alert severity="success" onClose={() => setTaskNotice(null)}><Typography sx={{ overflowWrap: "anywhere" }}>{taskNotice}</Typography></Alert>}
      {preview && <Alert severity={preview.blocked_by_pin ? "warning" : "info"}><Typography fontWeight={750}>{copy.purgeTitle}</Typography><Typography variant="body2" sx={{ mt: 0.5 }}>{preview.artifact_count} {copy.artifacts} · {bytes(preview.size_bytes)}</Typography>{preview.blocked_by_pin ? <Typography variant="body2">{copy.blocked}</Typography> : <Stack spacing={1.2} sx={{ mt: 1.2 }}><Typography component="code" dir="ltr" variant="body2" sx={{ overflowWrap: "anywhere" }}>{preview.confirmation}</Typography><TextField size="small" label={copy.confirmation} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} error={confirmation.length > 0 && confirmation !== preview.confirmation} helperText={confirmation.length > 0 && confirmation !== preview.confirmation ? copy.confirmationMismatch : " "} inputProps={{ dir: "ltr" }} /><Button color="error" variant="contained" disabled={!canRunTasks || operationPending || confirmation !== preview.confirmation} onClick={() => { const item = items.find((entry) => entry.ecosystem === preview.ecosystem && entry.name === preview.name); if (item) void queuePackageTask(item, "purge"); }}>{copy.executePurge}</Button></Stack>}</Alert>}

      <Card><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Grid container spacing={2}><Grid size={{ xs: 12, md: 8 }}><TextField fullWidth value={query} onChange={(event) => setQuery(event.target.value)} label={copy.search} slotProps={{ input: { startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment>, endAdornment: loading ? <CircularProgress size={18} /> : null } }} /></Grid><Grid size={{ xs: 12, md: 4 }}><TextField select fullWidth value={ecosystem} onChange={(event) => setEcosystem(event.target.value)} label={copy.all}><MenuItem value="">{copy.all}</MenuItem><MenuItem value="npm">npm</MenuItem><MenuItem value="pypi">PyPI</MenuItem></TextField></Grid></Grid>{canWrite && <TextField fullWidth size="small" label={copy.reason} value={reason} onChange={(event) => setReason(event.target.value)} sx={{ mt: 2 }} />}</CardContent></Card>

      <Card><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Stack direction="row" spacing={1} alignItems="center"><CloudDownloadRoundedIcon color="primary" /><Box><Typography fontWeight={760}>{copy.prefetchTitle}</Typography><Typography variant="body2" color="text.secondary">{copy.prefetchHint}</Typography></Box></Stack><Grid container spacing={2} sx={{ mt: 0.5 }}><Grid size={{ xs: 12, md: 3 }}><TextField select fullWidth label={copy.all} value={prefetchEcosystem} onChange={(event) => setPrefetchEcosystem(event.target.value as "npm" | "pypi")}><MenuItem value="pypi">requirements.txt</MenuItem><MenuItem value="npm">package-lock.json</MenuItem></TextField></Grid><Grid size={{ xs: 12, md: 9 }}><TextField fullWidth multiline minRows={3} maxRows={9} label={copy.manifest} value={manifest} onChange={(event) => setManifest(event.target.value)} inputProps={{ dir: "ltr" }} /></Grid></Grid><Stack direction="row" justifyContent="flex-end" sx={{ mt: 1.5 }}><Button variant="contained" startIcon={<CloudDownloadRoundedIcon />} disabled={!canRunTasks || operationPending || !manifest.trim()} onClick={() => void queuePrefetch()}>{copy.enqueue}</Button></Stack></CardContent></Card>

      <Grid container spacing={2}>{items.length === 0 && !loading && <Grid size={12}><Alert severity="info">{copy.empty}</Alert></Grid>}{items.map((item) => <Grid key={`${item.ecosystem}:${item.name}`} size={{ xs: 12, lg: 6 }}><Card sx={{ height: "100%" }}><CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}><Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}><Box sx={{ minWidth: 0 }}><Stack direction="row" spacing={1} alignItems="center"><Tooltip title={item.name}><Typography variant="h6" noWrap sx={{ maxWidth: 300 }}>{item.name}</Typography></Tooltip><Chip size="small" label={item.ecosystem} /></Stack><Tooltip title={item.versions.join(", ")}><Typography variant="body2" color="text.secondary" noWrap dir="ltr" sx={{ mt: 0.8 }}>{copy.versions}: {item.versions.slice(0, 4).join(", ") || "—"}</Typography></Tooltip></Box><Stack direction="row" spacing={0.7}>{item.pinned && <Chip size="small" color="primary" label={copy.pin} />}{item.quarantined && <Chip size="small" color="error" label={copy.quarantine} />}</Stack></Stack><Divider sx={{ my: 2 }} /><Stack direction="row" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={1}><Typography variant="body2">{item.artifact_count} {copy.artifacts} · {bytes(item.size_bytes)}</Typography>{canWrite && <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap><Button size="small" startIcon={<PushPinRoundedIcon />} onClick={() => void policy(item, { pinned: !item.pinned })}>{item.pinned ? copy.unpin : copy.pin}</Button><Button size="small" color={item.quarantined ? "success" : "error"} startIcon={<GppBadRoundedIcon />} onClick={() => void policy(item, { quarantined: !item.quarantined, quarantine_reason: item.quarantined ? null : reason })}>{item.quarantined ? copy.release : copy.quarantine}</Button><Button size="small" disabled={!canRunTasks || operationPending || item.pinned} startIcon={<SyncRoundedIcon />} onClick={() => void queuePackageTask(item, "revalidate")}>{copy.revalidate}</Button><Button size="small" color="warning" disabled={!canRunTasks || operationPending} startIcon={<DeleteSweepRoundedIcon />} onClick={() => void purgePreview(item)}>{copy.preview}</Button></Stack>}</Stack></CardContent></Card></Grid>)}</Grid>
    </Stack>
  );
}
