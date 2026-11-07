import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  Grid,
  MenuItem,
  Stack,
  Switch,
  TextField,
  Typography
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import NetworkCheckRoundedIcon from "@mui/icons-material/NetworkCheckRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import type { Language } from "./i18n";

type UpstreamRecord = {
  id: string;
  name: string;
  ecosystem: "npm" | "pypi";
  url: string;
  priority: number;
  timeout_seconds: number;
  enabled: boolean;
  blocked_until: number | null;
  blocked_reason: string | null;
  credential_configured: boolean;
  credential_type?: "bearer" | "basic" | null;
  credential_updated_at?: number | null;
};

type ProbeStage = {
  name: string;
  status: "ok" | "failed";
  latency_ms: number;
  detail?: string;
};

type HealthCheck = {
  id: number;
  upstream_id: string;
  ok: boolean;
  stages: ProbeStage[];
  total_latency_ms: number;
  checked_at: number;
};

type Props = {
  language: Language;
  csrf: string;
  permissions: string[];
  onUnauthorized: () => void;
};

const labels = {
  fa: {
    title: "منابع بالادستی",
    hint: "ترتیب failover، سلامت اتصال و حالت آفلاین را بدون restart مدیریت کنید.",
    add: "افزودن upstream",
    name: "نام",
    ecosystem: "اکوسیستم",
    url: "آدرس HTTPS",
    priority: "اولویت",
    timeout: "مهلت (ثانیه)",
    create: "افزودن",
    test: "تست اتصال",
    testSaved: "تست اکنون",
    history: "تاریخچه سلامت",
    hideHistory: "بستن تاریخچه",
    noHistory: "هنوز تستی برای این upstream ثبت نشده است.",
    healthy: "موفق",
    unhealthy: "ناموفق",
    credential: "اعتبارنامه خصوصی",
    credentialConfigured: "اعتبارنامه تنظیم شده",
    credentialEmpty: "بدون اعتبارنامه",
    credentialType: "نوع اعتبارنامه",
    bearer: "Bearer token",
    basic: "نام کاربری و رمز",
    token: "Token",
    username: "نام کاربری",
    password: "رمز عبور",
    replaceCredential: "ذخیره/جایگزینی",
    removeCredential: "حذف اعتبارنامه",
    cancel: "انصراف",
    edit: "ویرایش",
    save: "ذخیره تغییرات",
    delete: "حذف upstream",
    deleteConfirmation: "برای حذف، نام دقیق upstream را وارد کنید.",
    confirmation: "تأیید نام",
    testing: "در حال تست…",
    refresh: "بروزرسانی",
    pypiOffline: "حالت آفلاین PyPI",
    npmOffline: "حالت آفلاین npm",
    offlineHint: "هیچ درخواست خروجی ارسال نمی‌شود و فقط کش و پکیج خصوصی پاسخ می‌دهد.",
    enabled: "فعال",
    disabled: "غیرفعال",
    block: "مسدودسازی",
    unblock: "رفع مسدودی",
    error: "عملیات upstream ناموفق بود.",
    empty: "upstream ثبت نشده است.",
    readOnly: "نقش شما اجازه تغییر upstreamها را ندارد."
  },
  en: {
    title: "Upstreams",
    hint: "Manage failover order, connection health, and offline mode without a restart.",
    add: "Add upstream",
    name: "Name",
    ecosystem: "Ecosystem",
    url: "HTTPS URL",
    priority: "Priority",
    timeout: "Timeout (seconds)",
    create: "Add",
    test: "Test connection",
    testSaved: "Test now",
    history: "Health history",
    hideHistory: "Hide history",
    noHistory: "No health check has been recorded for this upstream yet.",
    healthy: "Passed",
    unhealthy: "Failed",
    credential: "Private credential",
    credentialConfigured: "Credential configured",
    credentialEmpty: "No credential",
    credentialType: "Credential type",
    bearer: "Bearer token",
    basic: "Username and password",
    token: "Token",
    username: "Username",
    password: "Password",
    replaceCredential: "Save / replace",
    removeCredential: "Remove credential",
    cancel: "Cancel",
    edit: "Edit",
    save: "Save changes",
    delete: "Delete upstream",
    deleteConfirmation: "Type the exact upstream name to delete it.",
    confirmation: "Name confirmation",
    testing: "Testing…",
    refresh: "Refresh",
    pypiOffline: "PyPI offline mode",
    npmOffline: "npm offline mode",
    offlineHint: "No outbound request is made; only cache and private packages are served.",
    enabled: "Enabled",
    disabled: "Disabled",
    block: "Block",
    unblock: "Unblock",
    error: "The upstream operation failed.",
    empty: "No upstreams are configured.",
    readOnly: "Your role cannot change upstreams."
  }
} as const;

export function UpstreamsPanel({ language, csrf, permissions, onUnauthorized }: Props) {
  const copy = labels[language];
  const canWrite = permissions.includes("*") || permissions.includes("upstream:write");
  const canOperate = permissions.includes("*") || permissions.includes("upstream:operate");
  const [items, setItems] = useState<UpstreamRecord[]>([]);
  const [offline, setOfflineState] = useState({ npm: false, pypi: false });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [name, setName] = useState("");
  const [ecosystem, setEcosystem] = useState<"npm" | "pypi">("pypi");
  const [url, setUrl] = useState("");
  const [priority, setPriority] = useState(30);
  const [timeout, setTimeoutValue] = useState(30);
  const [testing, setTesting] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [probe, setProbe] = useState<ProbeStage[]>([]);
  const [history, setHistory] = useState<Record<string, HealthCheck[]>>({});
  const [visibleHistory, setVisibleHistory] = useState<string | null>(null);
  const [credentialTarget, setCredentialTarget] = useState<UpstreamRecord | null>(null);
  const [credentialType, setCredentialType] = useState<"bearer" | "basic">("bearer");
  const [credentialToken, setCredentialToken] = useState("");
  const [credentialUsername, setCredentialUsername] = useState("");
  const [credentialPassword, setCredentialPassword] = useState("");
  const [editTarget, setEditTarget] = useState<UpstreamRecord | null>(null);
  const [editName, setEditName] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editPriority, setEditPriority] = useState(1);
  const [editTimeout, setEditTimeout] = useState(30);
  const [editEnabled, setEditEnabled] = useState(true);
  const [deleteConfirmation, setDeleteConfirmation] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch("/api/v1/upstreams", { cache: "no-store" });
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("load failed");
      const payload = (await response.json()) as {
        items: UpstreamRecord[];
        offline: { npm: boolean; pypi: boolean };
      };
      setItems(payload.items);
      setOfflineState(payload.offline);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [onUnauthorized]);

  useEffect(() => void load(), [load]);

  const request = async (path: string, method: string, body?: object) => {
    const response = await fetch(path, {
      method,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: body ? JSON.stringify(body) : undefined
    });
    if (response.status === 401) onUnauthorized();
    if (!response.ok) throw new Error("request failed");
    return response;
  };

  const create = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      await request("/api/v1/upstreams", "POST", {
        name,
        ecosystem,
        url,
        priority,
        timeout_seconds: timeout
      });
      setName("");
      setUrl("");
      await load();
    } catch {
      setError(true);
    }
  };

  const testConnection = async () => {
    setTesting(true);
    setProbe([]);
    try {
      const response = await request("/api/v1/upstreams/test", "POST", {
        url,
        timeout_seconds: Math.min(timeout, 30)
      });
      const payload = (await response.json()) as { stages: ProbeStage[] };
      setProbe(payload.stages);
    } catch {
      setError(true);
    } finally {
      setTesting(false);
    }
  };

  const loadHistory = async (upstreamId: string) => {
    const response = await fetch(`/api/v1/upstreams/${upstreamId}/health?limit=20`, {
      cache: "no-store"
    });
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) throw new Error("history failed");
    const payload = (await response.json()) as { items: HealthCheck[] };
    setHistory((current) => ({ ...current, [upstreamId]: payload.items }));
  };

  const testSavedUpstream = async (item: UpstreamRecord) => {
    setTestingId(item.id);
    try {
      await request("/api/v1/upstreams/test", "POST", { upstream_id: item.id });
      await loadHistory(item.id);
      setVisibleHistory(item.id);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setTestingId(null);
    }
  };

  const toggleHistory = async (upstreamId: string) => {
    if (visibleHistory === upstreamId) {
      setVisibleHistory(null);
      return;
    }
    try {
      await loadHistory(upstreamId);
      setVisibleHistory(upstreamId);
      setError(false);
    } catch {
      setError(true);
    }
  };

  const toggleOffline = async (ecosystemName: "npm" | "pypi", value: boolean) => {
    try {
      await request(`/api/v1/ecosystems/${ecosystemName}/offline`, "PUT", { offline: value });
      setOfflineState((current) => ({ ...current, [ecosystemName]: value }));
    } catch {
      setError(true);
    }
  };

  const openCredential = (item: UpstreamRecord) => {
    setCredentialTarget(item);
    setCredentialType(item.ecosystem === "npm" ? "bearer" : item.credential_type ?? "bearer");
    setCredentialToken("");
    setCredentialUsername("");
    setCredentialPassword("");
  };

  const closeCredential = () => {
    setCredentialTarget(null);
    setCredentialToken("");
    setCredentialUsername("");
    setCredentialPassword("");
  };

  const saveCredential = async () => {
    if (!credentialTarget) return;
    try {
      const body = credentialType === "bearer"
        ? { credential_type: "bearer", token: credentialToken }
        : {
            credential_type: "basic",
            username: credentialUsername,
            password: credentialPassword
          };
      await request(`/api/v1/upstreams/${credentialTarget.id}/credential`, "PUT", body);
      closeCredential();
      await load();
      setError(false);
    } catch {
      setError(true);
    }
  };

  const removeCredential = async () => {
    if (!credentialTarget) return;
    try {
      await request(`/api/v1/upstreams/${credentialTarget.id}/credential`, "DELETE");
      closeCredential();
      await load();
      setError(false);
    } catch {
      setError(true);
    }
  };

  const openEdit = (item: UpstreamRecord) => {
    setEditTarget(item);
    setEditName(item.name);
    setEditUrl(item.url);
    setEditPriority(item.priority);
    setEditTimeout(item.timeout_seconds);
    setEditEnabled(item.enabled);
    setDeleteConfirmation("");
  };

  const closeEdit = () => {
    setEditTarget(null);
    setDeleteConfirmation("");
  };

  const saveEdit = async () => {
    if (!editTarget) return;
    try {
      await request(`/api/v1/upstreams/${editTarget.id}`, "PATCH", {
        name: editName,
        url: editUrl,
        priority: editPriority,
        timeout_seconds: editTimeout,
        enabled: editEnabled
      });
      closeEdit();
      await load();
      setError(false);
    } catch {
      setError(true);
    }
  };

  const deleteUpstream = async () => {
    if (!editTarget) return;
    try {
      await request(`/api/v1/upstreams/${editTarget.id}`, "DELETE", {
        confirmation: deleteConfirmation
      });
      closeEdit();
      await load();
      setError(false);
    } catch {
      setError(true);
    }
  };

  const toggleBlock = async (item: UpstreamRecord) => {
    try {
      await request(
        `/api/v1/upstreams/${item.id}/${item.blocked_until ? "unblock" : "block"}`,
        "POST",
        item.blocked_until ? undefined : { reason: "manual operation from admin panel" }
      );
      await load();
    } catch {
      setError(true);
    }
  };

  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "flex-end" }} spacing={2}>
        <Box><Typography variant="h4" component="h1">{copy.title}</Typography><Typography color="text.secondary" sx={{ mt: 0.8 }}>{copy.hint}</Typography></Box>
        <Button variant="outlined" startIcon={loading ? <CircularProgress size={16} /> : <RefreshRoundedIcon />} onClick={() => void load()} disabled={loading}>{copy.refresh}</Button>
      </Stack>
      {error && <Alert severity="error">{copy.error}</Alert>}
      {!canWrite && !canOperate && <Alert severity="info">{copy.readOnly}</Alert>}

      {canWrite && <Card><CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}><Typography variant="h6">{copy.add}</Typography><Box component="form" onSubmit={(event) => void create(event)} sx={{ mt: 2 }}><Grid container spacing={2}><Grid size={{ xs: 12, md: 2 }}><TextField fullWidth required label={copy.name} value={name} onChange={(event) => setName(event.target.value)} /></Grid><Grid size={{ xs: 12, md: 2 }}><TextField select fullWidth label={copy.ecosystem} value={ecosystem} onChange={(event) => setEcosystem(event.target.value as "npm" | "pypi")}><MenuItem value="pypi">PyPI</MenuItem><MenuItem value="npm">npm</MenuItem></TextField></Grid><Grid size={{ xs: 12, md: 4 }}><TextField fullWidth required dir="ltr" label={copy.url} value={url} onChange={(event) => setUrl(event.target.value)} /></Grid><Grid size={{ xs: 6, md: 1.5 }}><TextField fullWidth type="number" label={copy.priority} value={priority} onChange={(event) => setPriority(Number(event.target.value))} /></Grid><Grid size={{ xs: 6, md: 1.5 }}><TextField fullWidth type="number" label={copy.timeout} value={timeout} onChange={(event) => setTimeoutValue(Number(event.target.value))} /></Grid><Grid size={{ xs: 12, md: 1 }}><Button fullWidth type="submit" variant="contained" sx={{ minHeight: 56 }}><AddRoundedIcon /></Button></Grid></Grid></Box><Button sx={{ mt: 1.5 }} disabled={!url || testing} startIcon={testing ? <CircularProgress size={16} /> : <NetworkCheckRoundedIcon />} onClick={() => void testConnection()}>{testing ? copy.testing : copy.test}</Button>{probe.length > 0 && <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 1.5 }}>{probe.map((stage) => <Chip key={stage.name} color={stage.status === "ok" ? "success" : "error"} variant="outlined" label={`${stage.name}: ${stage.latency_ms} ms${stage.detail ? ` · ${stage.detail}` : ""}`} />)}</Stack>}</CardContent></Card>}

      <Grid container spacing={2}>
        {(["npm", "pypi"] as const).map((ecosystemName) => (
          <Grid key={ecosystemName} size={{ xs: 12, md: 6 }}>
            <Card sx={{ height: "100%" }}>
              <CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}>
                <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={2}>
                  <Box>
                    <Typography variant="h6">{ecosystemName === "npm" ? copy.npmOffline : copy.pypiOffline}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 0.4 }}>{copy.offlineHint}</Typography>
                  </Box>
                  <Switch checked={offline[ecosystemName]} disabled={!canOperate} onChange={(_event, value) => void toggleOffline(ecosystemName, value)} />
                </Stack>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={2}>
        {items.length === 0 && <Grid size={12}><Alert severity="info">{copy.empty}</Alert></Grid>}
        {items.map((item) => {
          const itemHistory = history[item.id] ?? [];
          const isHistoryVisible = visibleHistory === item.id;
          return (
            <Grid key={item.id} size={{ xs: 12, lg: 6 }}>
              <Card sx={{ height: "100%" }}>
                <CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
                    <Box sx={{ minWidth: 0, flex: 1 }}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography variant="h6">{item.name}</Typography>
                        <Chip size="small" label={item.ecosystem} />
                      </Stack>
                      <Typography variant="body2" color="text.secondary" dir="ltr" noWrap title={item.url} sx={{ mt: 0.8 }}>{item.url}</Typography>
                    </Box>
                    <Chip size="small" color={item.blocked_until ? "warning" : item.enabled ? "success" : "default"} label={item.blocked_until ? copy.block : item.enabled ? copy.enabled : copy.disabled} />
                  </Stack>
                  <Divider sx={{ my: 2 }} />
                  <Stack direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ sm: "center" }}>
                    <Typography variant="body2" sx={{ flex: 1 }}>{copy.priority}: {item.priority}</Typography>
                    <Typography variant="body2" sx={{ flex: 1 }}>{copy.timeout}: {item.timeout_seconds}</Typography>
                    {canWrite && <Button size="small" startIcon={testingId === item.id ? <CircularProgress size={14} /> : <NetworkCheckRoundedIcon />} disabled={testingId === item.id} onClick={() => void testSavedUpstream(item)}>{copy.testSaved}</Button>}
                    {canWrite && <Button size="small" color={item.credential_configured ? "success" : "inherit"} onClick={() => openCredential(item)}>{item.credential_configured ? copy.credentialConfigured : copy.credential}</Button>}
                    {canWrite && <Button size="small" onClick={() => openEdit(item)}>{copy.edit}</Button>}
                    <Button size="small" onClick={() => void toggleHistory(item.id)}>{isHistoryVisible ? copy.hideHistory : copy.history}</Button>
                    {canOperate && <Button size="small" color={item.blocked_until ? "success" : "warning"} onClick={() => void toggleBlock(item)}>{item.blocked_until ? copy.unblock : copy.block}</Button>}
                  </Stack>
                  {isHistoryVisible && <Box sx={{ mt: 2 }}>
                    <Divider sx={{ mb: 1.5 }} />
                    {itemHistory.length === 0
                      ? <Typography variant="body2" color="text.secondary">{copy.noHistory}</Typography>
                      : <Stack spacing={1}>{itemHistory.map((check) => <Box key={check.id} sx={{ py: 1, borderBottom: "1px solid", borderColor: "divider" }}><Stack direction="row" justifyContent="space-between" gap={1}><Chip size="small" color={check.ok ? "success" : "error"} variant="outlined" label={check.ok ? copy.healthy : copy.unhealthy} /><Typography variant="caption" color="text.secondary" dir="ltr">{new Date(check.checked_at * 1000).toLocaleString(language === "fa" ? "fa-IR" : "en-US")}</Typography></Stack><Stack direction="row" flexWrap="wrap" gap={0.75} sx={{ mt: 1 }}>{check.stages.map((stage) => <Chip key={`${check.id}-${stage.name}`} size="small" variant="outlined" color={stage.status === "ok" ? "success" : "error"} label={`${stage.name} · ${stage.latency_ms} ms`} title={stage.detail} />)}</Stack></Box>)}</Stack>}
                  </Box>}
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>
      <Dialog open={credentialTarget !== null} onClose={closeCredential} fullWidth maxWidth="sm">
        <DialogTitle>{copy.credential}{credentialTarget ? ` · ${credentialTarget.name}` : ""}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Alert severity="info">{credentialTarget?.credential_configured ? copy.credentialConfigured : copy.credentialEmpty}</Alert>
            <TextField select fullWidth label={copy.credentialType} value={credentialType} disabled={credentialTarget?.ecosystem === "npm"} onChange={(event) => setCredentialType(event.target.value as "bearer" | "basic")}>
              <MenuItem value="bearer">{copy.bearer}</MenuItem>
              {credentialTarget?.ecosystem !== "npm" && <MenuItem value="basic">{copy.basic}</MenuItem>}
            </TextField>
            {credentialType === "bearer"
              ? <TextField fullWidth required type="password" autoComplete="new-password" label={copy.token} value={credentialToken} onChange={(event) => setCredentialToken(event.target.value)} />
              : <><TextField fullWidth required autoComplete="username" label={copy.username} value={credentialUsername} onChange={(event) => setCredentialUsername(event.target.value)} /><TextField fullWidth required type="password" autoComplete="new-password" label={copy.password} value={credentialPassword} onChange={(event) => setCredentialPassword(event.target.value)} /></>}
          </Stack>
        </DialogContent>
        <DialogActions>
          {credentialTarget?.credential_configured && <Button color="error" onClick={() => void removeCredential()}>{copy.removeCredential}</Button>}
          <Box sx={{ flex: 1 }} />
          <Button onClick={closeCredential}>{copy.cancel}</Button>
          <Button variant="contained" disabled={credentialType === "bearer" ? !credentialToken : !credentialUsername || !credentialPassword} onClick={() => void saveCredential()}>{copy.replaceCredential}</Button>
        </DialogActions>
      </Dialog>
      <Dialog open={editTarget !== null} onClose={closeEdit} fullWidth maxWidth="sm">
        <DialogTitle>{copy.edit}{editTarget ? ` · ${editTarget.name}` : ""}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <TextField fullWidth required label={copy.name} value={editName} onChange={(event) => setEditName(event.target.value)} />
            <TextField fullWidth required dir="ltr" label={copy.url} value={editUrl} onChange={(event) => setEditUrl(event.target.value)} />
            <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
              <TextField fullWidth required type="number" label={copy.priority} value={editPriority} onChange={(event) => setEditPriority(Number(event.target.value))} />
              <TextField fullWidth required type="number" label={copy.timeout} value={editTimeout} onChange={(event) => setEditTimeout(Number(event.target.value))} />
            </Stack>
            <FormControlLabel control={<Switch checked={editEnabled} onChange={(_event, value) => setEditEnabled(value)} />} label={copy.enabled} />
            <Divider />
            <Alert severity="warning">{copy.deleteConfirmation}</Alert>
            <TextField fullWidth label={copy.confirmation} value={deleteConfirmation} onChange={(event) => setDeleteConfirmation(event.target.value)} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button color="error" disabled={!editTarget || deleteConfirmation !== editTarget.name} onClick={() => void deleteUpstream()}>{copy.delete}</Button>
          <Box sx={{ flex: 1 }} />
          <Button onClick={closeEdit}>{copy.cancel}</Button>
          <Button variant="contained" disabled={!editName || !editUrl || editPriority < 1 || editTimeout < 1} onClick={() => void saveEdit()}>{copy.save}</Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
