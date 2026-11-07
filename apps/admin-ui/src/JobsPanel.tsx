import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  LinearProgress,
  Stack,
  Typography
} from "@mui/material";
import CancelRoundedIcon from "@mui/icons-material/CancelRounded";
import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import type { Language } from "./i18n";

type TaskRecord = {
  id: string;
  kind: string;
  state: "pending" | "running" | "succeeded" | "failed" | "cancelled";
  progress: number;
  error_code: string | null;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
  retry_of: string | null;
  result: Record<string, unknown> | null;
};

type Props = {
  language: Language;
  csrf: string;
  permissions: string[];
  onUnauthorized: () => void;
};

const labels = {
  fa: { title: "وظایف", hint: "عملیات طولانی و حساس را پیگیری، لغو یا دوباره اجرا کنید.", refresh: "بروزرسانی", empty: "هنوز وظیفه‌ای ثبت نشده است.", cancel: "لغو", retry: "اجرای مجدد", error: "دریافت وظایف ناموفق بود.", pending: "در صف", running: "در حال اجرا", succeeded: "موفق", failed: "ناموفق", cancelled: "لغوشده", readOnly: "نقش شما فقط اجازه مشاهده وظایف را دارد." },
  en: { title: "Jobs", hint: "Track, cancel, or retry long-running and sensitive operations.", refresh: "Refresh", empty: "No jobs have been recorded yet.", cancel: "Cancel", retry: "Retry", error: "Could not load jobs.", pending: "Pending", running: "Running", succeeded: "Succeeded", failed: "Failed", cancelled: "Cancelled", readOnly: "Your role can only view jobs." }
} as const;

const colors = { pending: "default", running: "info", succeeded: "success", failed: "error", cancelled: "warning" } as const;

export function JobsPanel({ language, csrf, permissions, onUnauthorized }: Props) {
  const copy = labels[language];
  const canWrite = permissions.includes("*") || permissions.includes("task:write");
  const [items, setItems] = useState<TaskRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const load = useCallback(async (background = false) => {
    if (!background) setLoading(true);
    try {
      const response = await fetch("/api/v1/tasks?limit=100", { cache: "no-store" });
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("task load failed");
      setItems(((await response.json()) as { items: TaskRecord[] }).items);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [onUnauthorized]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(true), 3000);
    return () => window.clearInterval(timer);
  }, [load]);

  const mutate = async (taskId: string, action: "cancel" | "retry") => {
    const response = await fetch(`/api/v1/tasks/${taskId}/${action}`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf }
    });
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) setError(true);
    await load();
  };

  const formatTime = (value: number | null) => value ? new Intl.DateTimeFormat(language === "fa" ? "fa-IR" : "en-US", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value * 1000)) : "—";

  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "flex-end" }} spacing={2}><Box><Typography variant="h4" component="h1">{copy.title}</Typography><Typography color="text.secondary" sx={{ mt: 0.8 }}>{copy.hint}</Typography></Box><Button variant="outlined" startIcon={loading ? <CircularProgress size={16} /> : <RefreshRoundedIcon />} disabled={loading} onClick={() => void load()}>{copy.refresh}</Button></Stack>
      {error && <Alert severity="error">{copy.error}</Alert>}
      {!canWrite && <Alert severity="info">{copy.readOnly}</Alert>}
      {!loading && items.length === 0 && <Alert severity="info">{copy.empty}</Alert>}
      <Stack spacing={1.5}>{items.map((item) => <Card key={item.id}><CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}><Stack direction={{ xs: "column", md: "row" }} alignItems={{ md: "center" }} spacing={2}><Box sx={{ minWidth: 0, flex: 1 }}><Stack direction="row" alignItems="center" spacing={1}><Typography fontWeight={750}>{item.kind}</Typography><Chip size="small" color={colors[item.state]} label={copy[item.state]} /></Stack><Typography variant="caption" color="text.secondary" dir="ltr" display="block" noWrap sx={{ mt: 0.6 }}>{item.id}{item.retry_of ? ` · retry of ${item.retry_of}` : ""}</Typography><LinearProgress variant="determinate" value={item.state === "pending" ? 0 : item.progress} sx={{ mt: 1.3, height: 6, borderRadius: 1 }} /></Box><Stack sx={{ minWidth: 170 }}><Typography variant="caption" color="text.secondary">{formatTime(item.created_at)}</Typography>{item.error_code && <Typography variant="caption" color="error.main" dir="ltr">{item.error_code}</Typography>}</Stack>{canWrite && <Stack direction="row" spacing={0.5}>{["pending", "running"].includes(item.state) && <Button size="small" color="warning" startIcon={<CancelRoundedIcon />} onClick={() => void mutate(item.id, "cancel")}>{copy.cancel}</Button>}{["failed", "cancelled"].includes(item.state) && <Button size="small" startIcon={<ReplayRoundedIcon />} onClick={() => void mutate(item.id, "retry")}>{copy.retry}</Button>}</Stack>}</Stack></CardContent></Card>)}</Stack>
    </Stack>
  );
}
