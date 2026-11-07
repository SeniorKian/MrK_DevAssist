import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert, AppBar, Avatar, Box, Button, Card, CardContent, Chip, CircularProgress,
  Divider, Drawer, Grid, IconButton, LinearProgress, List, ListItemButton,
  ListItemIcon, ListItemText, Paper, Skeleton, Stack, Tab, Tabs, Toolbar,
  Tooltip, Typography, useMediaQuery, useTheme
} from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import DashboardRoundedIcon from "@mui/icons-material/DashboardRounded";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import CloudSyncRoundedIcon from "@mui/icons-material/CloudSyncRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import TaskAltRoundedIcon from "@mui/icons-material/TaskAltRounded";
import MonitorHeartRoundedIcon from "@mui/icons-material/MonitorHeartRounded";
import ManageAccountsRoundedIcon from "@mui/icons-material/ManageAccountsRounded";
import SettingsRoundedIcon from "@mui/icons-material/SettingsRounded";
import MenuRoundedIcon from "@mui/icons-material/MenuRounded";
import LightModeRoundedIcon from "@mui/icons-material/LightModeRounded";
import DarkModeRoundedIcon from "@mui/icons-material/DarkModeRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import ScheduleRoundedIcon from "@mui/icons-material/ScheduleRounded";
import HubRoundedIcon from "@mui/icons-material/HubRounded";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import ArrowForwardRoundedIcon from "@mui/icons-material/ArrowForwardRounded";
import UpdateRoundedIcon from "@mui/icons-material/UpdateRounded";
import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import packageMetadata from "../package.json";
import type { AuthUser } from "./App";
import { translate, type Language, type MessageKey } from "./i18n";

const AccessPanel = lazy(() => import("./AccessPanel").then((module) => ({ default: module.AccessPanel })));
const UpstreamsPanel = lazy(() => import("./UpstreamsPanel").then((module) => ({ default: module.UpstreamsPanel })));
const PackagesPanel = lazy(() => import("./PackagesPanel").then((module) => ({ default: module.PackagesPanel })));
const JobsPanel = lazy(() => import("./JobsPanel").then((module) => ({ default: module.JobsPanel })));
const ObservabilityPanel = lazy(() => import("./ObservabilityPanel").then((module) => ({ default: module.ObservabilityPanel })));
const LifecyclePanel = lazy(() => import("./LifecyclePanel").then((module) => ({ default: module.LifecyclePanel })));
const RegistriesPanel = lazy(() => import("./RegistriesPanel").then((module) => ({ default: module.RegistriesPanel })));

const DRAWER_WIDTH = 268;
const UI_COMMIT = import.meta.env.VITE_BUILD_COMMIT || "unknown";

type ComponentState = "ready" | "unavailable" | "not_configured";
type SystemStatus = {
  status: string;
  version: string;
  environment: string;
  uptime_seconds: number;
  build: { commit: string; built_at: string; ui_version: string };
  storage: { total_bytes: number; used_bytes: number; free_bytes: number; used_percent: number };
  components: Record<string, ComponentState>;
};

type DashboardProps = {
  language: Language;
  mode: "dark" | "light";
  user: AuthUser;
  csrf: string;
  onUnauthorized: () => void;
  onLogout: () => void;
  onLanguageChange: () => void;
  onModeChange: () => void;
};

type PageKey = "overview" | "registries" | "packages" | "upstreams" | "jobs" | "observability" | "access" | "lifecycle";
type NavItem = { label: MessageKey; icon: SvgIconComponent; page?: PageKey };
const navItems: NavItem[] = [
  { label: "overview", icon: DashboardRoundedIcon, page: "overview" },
  { label: "registries", icon: DnsRoundedIcon, page: "registries" },
  { label: "packages", icon: Inventory2RoundedIcon, page: "packages" },
  { label: "upstreams", icon: CloudSyncRoundedIcon, page: "upstreams" },
  { label: "jobs", icon: TaskAltRoundedIcon, page: "jobs" },
  { label: "observability", icon: MonitorHeartRoundedIcon, page: "observability" },
  { label: "access", icon: ManageAccountsRoundedIcon, page: "access" },
  { label: "settings", icon: SettingsRoundedIcon, page: "lifecycle" }
];
const pageKeys = new Set<PageKey>(navItems.flatMap((item) => item.page ? [item.page] : []));

function formatBytes(value: number, language: Language): string {
  if (!Number.isFinite(value) || value <= 0) return "0 GB";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US", { maximumFractionDigits: 1 }).format(value / 1024 ** exponent)} ${units[exponent]}`;
}

function formatUptime(seconds: number, language: Language, t: (key: MessageKey) => string): string {
  if (!seconds) return t("justNow");
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const number = (value: number) => new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(value);
  if (days) return `${number(days)} ${t("daysShort")} ${number(hours)} ${t("hoursShort")}`;
  if (hours) return `${number(hours)} ${t("hoursShort")} ${number(minutes)} ${t("minutesShort")}`;
  return `${number(Math.max(1, minutes))} ${t("minutesShort")}`;
}

function statusLabel(state: ComponentState, t: (key: MessageKey) => string): string {
  if (state === "ready") return t("ready");
  if (state === "unavailable") return t("unavailable");
  return t("notConfigured");
}

function StatusChip({ state, t }: { state: ComponentState; t: (key: MessageKey) => string }) {
  const color = state === "ready" ? "success" : state === "unavailable" ? "error" : "warning";
  return (
    <Chip
      size="small"
      color={color}
      variant="outlined"
      label={
        <Stack component="span" direction="row" alignItems="center" spacing={0.65}>
          <Box component="span" sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: `${color}.main`, flexShrink: 0 }} />
          <Box component="span">{statusLabel(state, t)}</Box>
        </Stack>
      }
      sx={{ height: 24, fontWeight: 700, flexShrink: 0, "& .MuiChip-label": { px: 1 } }}
    />
  );
}

function SectionTitle({ title, hint }: { title: string; hint: string }) {
  return <Box><Typography variant="h6">{title}</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: 0.4 }}>{hint}</Typography></Box>;
}

function MetricCard({ label, value, hint, icon: Icon, color, valueDir }: { label: string; value: string; hint: string; icon: SvgIconComponent; color: string; valueDir?: "ltr" | "rtl" }) {
  return (
    <Card sx={{ height: "100%", position: "relative", overflow: "hidden" }}>
      <Box sx={{ position: "absolute", insetInlineStart: 0, top: 0, bottom: 0, width: 3, bgcolor: color }} />
      <CardContent sx={{ p: 2.5, "&:last-child": { pb: 2.5 } }}>
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
          <Box><Typography variant="body2" color="text.secondary" fontWeight={620}>{label}</Typography><Typography variant="h5" dir={valueDir} sx={{ mt: 1, fontWeight: 780 }}>{value}</Typography><Typography variant="caption" color="text.secondary">{hint}</Typography></Box>
          <Avatar sx={{ width: 42, height: 42, color, bgcolor: `${color}18` }}><Icon fontSize="small" /></Avatar>
        </Stack>
      </CardContent>
    </Card>
  );
}

function Brand() {
  return (
    <Stack direction="row" alignItems="center" spacing={1.75}>
      <Box aria-hidden sx={{ width: 38, height: 38, borderRadius: 1.25, display: "grid", placeItems: "center", fontSize: 13, fontWeight: 850, color: "#042f2e", background: "linear-gradient(145deg, #99f6e4, #38bdf8)", flexShrink: 0 }}>MRK</Box>
      <Box sx={{ minWidth: 0 }}><Typography fontWeight={780} lineHeight={1.35} noWrap>Package Mirror</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.25 }} noWrap>Operations Console</Typography></Box>
    </Stack>
  );
}

export function Dashboard({
  language,
  mode,
  user,
  csrf,
  onUnauthorized,
  onLogout,
  onLanguageChange,
  onModeChange
}: DashboardProps) {
  const theme = useTheme();
  const compact = useMediaQuery(theme.breakpoints.down("md"));
  const [mobileOpen, setMobileOpen] = useState(false);
  const [page, setPage] = useState<PageKey>(() => {
    const candidate = window.location.hash.replace(/^#\/?/, "") as PageKey;
    return pageKeys.has(candidate) ? candidate : "overview";
  });
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [setupTab, setSetupTab] = useState(0);
  const [copied, setCopied] = useState(false);
  const [updateState, setUpdateState] = useState<"none" | "updating" | "failed">("none");
  const t = useCallback((key: MessageKey) => translate(language, key), [language]);

  const navigateTo = useCallback((target: PageKey) => {
    setPage(target);
    window.history.replaceState(null, "", `#/${target}`);
  }, []);

  useEffect(() => {
    const onHashChange = () => {
      const candidate = window.location.hash.replace(/^#\/?/, "") as PageKey;
      if (pageKeys.has(candidate)) setPage(candidate);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const forceReload = useCallback((commit: string) => {
    const url = new URL(window.location.href);
    url.searchParams.set("_ui", commit.slice(0, 12));
    window.location.replace(url.toString());
  }, []);

  const checkBuild = useCallback((nextStatus: SystemStatus) => {
    const serverCommit = nextStatus.build.commit;
    const versionMismatch = nextStatus.build.ui_version !== packageMetadata.version;
    const commitMismatch = serverCommit !== "unknown" && serverCommit !== UI_COMMIT;
    if (!versionMismatch && !commitMismatch) return;
    const reloadKey = `mrk-ui-reload:${serverCommit}:${nextStatus.build.ui_version}`;
    if (window.sessionStorage.getItem(reloadKey) !== "attempted") {
      window.sessionStorage.setItem(reloadKey, "attempted");
      setUpdateState("updating");
      window.setTimeout(() => forceReload(serverCommit || nextStatus.build.ui_version), 900);
    } else {
      setUpdateState("failed");
    }
  }, [forceReload]);

  const loadStatus = useCallback(async (background = false) => {
    if (!background) setLoading(true);
    try {
      const response = await fetch(`/api/v1/system/status?_=${Date.now()}`, { headers: { Accept: "application/json" }, cache: "no-store" });
      if (response.status === 401) {
        onUnauthorized();
        return;
      }
      if (!response.ok) throw new Error("status request failed");
      const payload = (await response.json()) as SystemStatus;
      setStatus(payload);
      setLastUpdated(new Date());
      setError(false);
      checkBuild(payload);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [checkBuild, onUnauthorized]);

  useEffect(() => {
    void loadStatus();
    const interval = window.setInterval(() => void loadStatus(true), 60_000);
    const onVisible = () => document.visibilityState === "visible" && void loadStatus(true);
    document.addEventListener("visibilitychange", onVisible);
    return () => { window.clearInterval(interval); document.removeEventListener("visibilitychange", onVisible); };
  }, [loadStatus]);

  const readyCount = useMemo(() => [status?.components.npm_registry, status?.components.pypi_registry].filter((value) => value === "ready").length, [status]);
  const setupClients = [
    { label: "npm", command: "npm config set registry https://packages.example.com/npm/" },
    { label: "pnpm", command: "pnpm config set registry https://packages.example.com/npm/" },
    { label: "Yarn", command: "yarn config set npmRegistryServer https://packages.example.com/npm/" },
    { label: "pip", command: "pip config set global.index-url https://pypi.example.com/root/pypi/+simple/" },
    { label: "uv", command: "uv pip install <package> --index-url https://pypi.example.com/root/pypi/+simple/" },
    { label: "Poetry", command: "poetry source add --priority=primary mrk https://pypi.example.com/root/pypi/+simple/" }
  ];
  const handleCopy = async () => {
    await navigator.clipboard.writeText(setupClients[setupTab].command);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };

  const drawer = (
    <Box dir={language === "fa" ? "rtl" : "ltr"} sx={{ height: "100%", px: 2, py: 2.25, display: "flex", flexDirection: "column" }}>
      <Box sx={{ px: 0.75, py: 1 }}><Brand /></Box><Divider sx={{ my: 2.25 }} />
      <List sx={{ px: 0, direction: language === "fa" ? "rtl" : "ltr" }}>
        {navItems.map(({ label, icon: Icon, page: targetPage }) => {
          const active = targetPage === page;
          return (
          <ListItemButton key={label} selected={active} disabled={!targetPage} onClick={() => { if (targetPage) navigateTo(targetPage); if (compact) setMobileOpen(false); }} sx={{ mb: 0.6, minHeight: 42, px: 1.5, gap: 1.25, borderRadius: 1, opacity: targetPage ? 1 : 0.58, "&.Mui-selected": { bgcolor: "rgba(45,212,191,.11)", color: "primary.main" }, "&.Mui-selected:hover": { bgcolor: "rgba(45,212,191,.15)" } }}>
            <ListItemIcon sx={{ minWidth: 24, width: 24, justifyContent: "center", color: "inherit" }}><Icon fontSize="small" /></ListItemIcon>
            <ListItemText sx={{ m: 0, textAlign: language === "fa" ? "right" : "left" }} primary={t(label)} primaryTypographyProps={{ noWrap: true, fontSize: 14, fontWeight: active ? 720 : 570 }} />
            {!targetPage && <Chip label={t("comingSoon")} size="small" sx={{ height: 20, maxWidth: 54, fontSize: 9, flexShrink: 0 }} />}
          </ListItemButton>
        );})}
      </List>
      <Box sx={{ mt: "auto", px: 1.5, py: 1.25, border: 1, borderColor: "divider", borderRadius: 1.25, bgcolor: "transparent" }}>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ minWidth: 0 }}>
          <Avatar sx={{ width: 28, height: 28, fontSize: 12, bgcolor: "primary.main", color: "primary.contrastText" }}>{user.username.slice(0, 2).toUpperCase()}</Avatar>
          <Box sx={{ minWidth: 0, flex: 1 }}><Typography variant="caption" fontWeight={700} display="block" noWrap>{user.username}</Typography><Typography variant="caption" color="text.secondary" display="block" noWrap>{user.role}</Typography></Box>
          <Tooltip title={t("logout")}><IconButton size="small" aria-label={t("logout")} onClick={onLogout}><LogoutRoundedIcon fontSize="small" /></IconButton></Tooltip>
        </Stack>
        <Divider sx={{ my: 1.2 }} />
        <Stack direction="row" alignItems="center" spacing={1}><CheckCircleRoundedIcon color="success" sx={{ fontSize: 18 }} /><Typography variant="caption" fontWeight={700}>{t("operational")}</Typography></Stack>
        <Typography variant="caption" color="text.secondary" display="block" noWrap sx={{ mt: 0.6 }}>{t("version")} {status?.version ?? packageMetadata.version}{status?.build.commit && status.build.commit !== "unknown" ? ` · ${status.build.commit.slice(0, 7)}` : ""}</Typography>
      </Box>
    </Box>
  );

  const componentRows: Array<[MessageKey, string]> = [["controlPlane", "control_plane"], ["npmRegistry", "npm_registry"], ["pypiRegistry", "pypi_registry"]];

  return (
    <Box sx={{ display: "flex", minHeight: "100vh", background: mode === "dark" ? "radial-gradient(circle at 62% -10%, rgba(20,184,166,.09), transparent 32%), #071019" : "radial-gradient(circle at 62% -10%, rgba(13,148,136,.08), transparent 32%), #f4f7fa" }}>
      <AppBar position="fixed" color="transparent" elevation={0} sx={{ width: { md: `calc(100% - ${DRAWER_WIDTH}px)` }, insetInlineStart: { md: `${DRAWER_WIDTH}px` }, borderBottom: 1, borderColor: "divider", bgcolor: mode === "dark" ? "rgba(7,16,25,.82)" : "rgba(244,247,250,.82)", backdropFilter: "blur(18px)" }}>
        <Toolbar sx={{ minHeight: "68px !important", gap: 1 }}>
          {compact && <IconButton aria-label={t("menu")} onClick={() => setMobileOpen(true)}><MenuRoundedIcon /></IconButton>}
          <Box sx={{ flex: 1 }}><Typography variant="body2" fontWeight={730}>{t("dashboard")}</Typography>{!compact && <Typography variant="caption" color="text.secondary">{t("subtitle")}</Typography>}</Box>
          <Tooltip title={t("refresh")}><span><IconButton aria-label={t("refresh")} disabled={loading} onClick={() => void loadStatus()}>{loading ? <CircularProgress size={19} /> : <RefreshRoundedIcon />}</IconButton></span></Tooltip>
          <Tooltip title={t("switchTheme")}><IconButton aria-label={t("switchTheme")} onClick={onModeChange}>{mode === "dark" ? <LightModeRoundedIcon /> : <DarkModeRoundedIcon />}</IconButton></Tooltip>
          <Button variant="outlined" size="small" onClick={onLanguageChange} sx={{ minWidth: 68 }}>{t("language")}</Button>
        </Toolbar>
      </AppBar>

      <Box component="nav" aria-label={t("menu")} sx={{ width: { md: DRAWER_WIDTH }, flexShrink: { md: 0 } }}>
        <Drawer variant="temporary" open={mobileOpen} onClose={() => setMobileOpen(false)} ModalProps={{ keepMounted: true }} anchor={language === "fa" ? "right" : "left"} sx={{ display: { xs: "block", md: "none" }, "& .MuiDrawer-paper": { width: DRAWER_WIDTH } }}>{drawer}</Drawer>
        <Drawer variant="permanent" anchor={language === "fa" ? "right" : "left"} sx={{ display: { xs: "none", md: "block" }, "& .MuiDrawer-paper": { width: DRAWER_WIDTH, borderColor: "divider" } }} open>{drawer}</Drawer>
      </Box>

      <Box component="main" sx={{ flexGrow: 1, width: { md: `calc(100% - ${DRAWER_WIDTH}px)` }, minWidth: 0 }}>
        <Toolbar sx={{ minHeight: "68px !important" }} />
        <Box sx={{ p: { xs: 2, sm: 3, xl: 4 }, maxWidth: 1560, mx: "auto" }}>
          {updateState !== "none" && <Alert severity={updateState === "updating" ? "info" : "warning"} icon={<UpdateRoundedIcon />} action={updateState === "failed" ? <Button color="inherit" size="small" onClick={() => forceReload(status?.build.commit ?? "latest")}>{t("updateNow")}</Button> : undefined} sx={{ mb: 2.5 }}><Typography fontWeight={750}>{t("updateAvailable")}</Typography><Typography variant="body2">{t(updateState === "updating" ? "updating" : "updateFailed")}</Typography></Alert>}
          {error && <Alert severity="error" action={<Button color="inherit" size="small" onClick={() => void loadStatus()}>{t("retry")}</Button>} sx={{ mb: 2.5 }}>{t("connectionError")}</Alert>}

          <Suspense fallback={<LinearProgress sx={{ mt: 1 }} />}>
          {page === "access" ? (
            <AccessPanel
              language={language}
              csrf={csrf}
              permissions={user.permissions}
              canWrite={user.permissions.includes("*") || user.permissions.includes("user:write")}
              onUnauthorized={onUnauthorized}
            />
          ) : page === "registries" ? (
            <RegistriesPanel
              language={language}
              onUnauthorized={onUnauthorized}
            />
          ) : page === "upstreams" ? (
            <UpstreamsPanel
              language={language}
              csrf={csrf}
              permissions={user.permissions}
              onUnauthorized={onUnauthorized}
            />
          ) : page === "packages" ? (
            <PackagesPanel
              language={language}
              csrf={csrf}
              permissions={user.permissions}
              onUnauthorized={onUnauthorized}
            />
          ) : page === "jobs" ? (
            <JobsPanel
              language={language}
              csrf={csrf}
              permissions={user.permissions}
              onUnauthorized={onUnauthorized}
            />
          ) : page === "observability" ? (
            <ObservabilityPanel
              language={language}
              permissions={user.permissions}
              onUnauthorized={onUnauthorized}
            />
          ) : page === "lifecycle" ? (
            <LifecyclePanel
              language={language}
              csrf={csrf}
              permissions={user.permissions}
              onUnauthorized={onUnauthorized}
            />
          ) : (
          <>

          <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "flex-end" }} spacing={2} sx={{ mb: 3 }}>
            <Box><Typography variant="h4" component="h1">{t("dashboard")}</Typography><Typography color="text.secondary" sx={{ mt: 0.8, maxWidth: 720 }}>{t("dashboardHint")}</Typography></Box>
            <Typography variant="caption" color="text.secondary">{t("lastUpdated")}: {lastUpdated ? new Intl.DateTimeFormat(language === "fa" ? "fa-IR" : "en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(lastUpdated) : "—"}</Typography>
          </Stack>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid size={{ xs: 12, sm: 6, xl: 3 }}>{loading && !status ? <Skeleton variant="rounded" height={142} /> : <MetricCard label={t("systemHealth")} value={error ? t("degraded") : t("operational")} hint={t("controlPlane")} icon={MonitorHeartRoundedIcon} color={error ? "#fb7185" : "#34d399"} />}</Grid>
            <Grid size={{ xs: 12, sm: 6, xl: 3 }}><MetricCard label={t("registriesReady")} value={`${readyCount} / 2`} valueDir="ltr" hint={`${t("npmRegistry")} + ${t("pypiRegistry")}`} icon={HubRoundedIcon} color="#60a5fa" /></Grid>
            <Grid size={{ xs: 12, sm: 6, xl: 3 }}><MetricCard label={t("storageUsed")} value={status ? `${status.storage.used_percent}%` : "—"} hint={status ? `${formatBytes(status.storage.used_bytes, language)} / ${formatBytes(status.storage.total_bytes, language)}` : t("unknown")} icon={StorageRoundedIcon} color="#a78bfa" /></Grid>
            <Grid size={{ xs: 12, sm: 6, xl: 3 }}><MetricCard label={t("uptime")} value={status ? formatUptime(status.uptime_seconds, language, t) : "—"} hint={`${t("environment")}: ${status?.environment ?? "—"}`} icon={ScheduleRoundedIcon} color="#fbbf24" /></Grid>
          </Grid>

          <Grid container spacing={3}>
            <Grid size={{ xs: 12, xl: 8 }}>
              <Card><CardContent sx={{ p: { xs: 2.2, sm: 3 }, "&:last-child": { pb: 3 } }}>
                <SectionTitle title={t("registryStatus")} hint={t("registryStatusHint")} />
                <Grid container spacing={2} sx={{ mt: 1 }}>
                  {[
                    { name: "npm", title: t("npmRegistry"), state: status?.components.npm_registry ?? "not_configured", port: "4873", upstreams: ["registry.npmjs.org", "package-mirror.liara.ir/repository/npm"], pending: false },
                    { name: "PyPI", title: t("pypiRegistry"), state: status?.components.pypi_registry ?? "not_configured", port: "3141", upstreams: ["pypi.org", "package-mirror.liara.ir"], pending: false }
                  ].map((registry) => (
                    <Grid key={registry.name} size={{ xs: 12, md: 6 }}><Paper variant="outlined" sx={{ p: 2.25, borderRadius: 1.25, bgcolor: "transparent", height: "100%", minWidth: 0 }}>
                      <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={1}><Stack direction="row" alignItems="center" spacing={1.3}><Avatar sx={{ width: 38, height: 38, bgcolor: "action.hover", color: "primary.main", fontWeight: 800, fontSize: 13 }}>{registry.name}</Avatar><Box><Typography fontWeight={760}>{registry.title}</Typography><Typography variant="caption" color="text.secondary">{t("port")} {registry.port}</Typography></Box></Stack><StatusChip state={registry.state} t={t} /></Stack>
                      <Divider sx={{ my: 2 }} />
                      <Stack spacing={1.2}><Stack direction="row" justifyContent="space-between"><Typography variant="body2" color="text.secondary">{t("cache")}</Typography><Typography variant="body2" fontWeight={700}>{t("enabled")}</Typography></Stack><Typography variant="body2" color="text.secondary">{t("upstreamOrder")}</Typography>
                        {registry.upstreams.map((upstream, index) => <Stack key={upstream} direction="row" alignItems="center" spacing={1} sx={{ minWidth: 0 }}><Chip size="small" label={index + 1} sx={{ width: 26, height: 24, flexShrink: 0 }} /><Tooltip title={upstream} placement="top"><Typography component="span" variant="body2" dir="ltr" sx={{ minWidth: 0, flex: 1, display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", textAlign: language === "fa" ? "right" : "left" }}>{upstream}</Typography></Tooltip><Typography variant="caption" color="text.secondary" noWrap sx={{ flexShrink: 0, minWidth: 48, textAlign: "end" }}>{t(index === 0 ? "primary" : "fallback")}</Typography></Stack>)}
                      </Stack>
                      {registry.pending && <Alert severity="info" variant="outlined" sx={{ mt: 2, py: 0, "& .MuiAlert-message": { fontSize: 12 } }}>{t("pypiPending")}</Alert>}
                    </Paper></Grid>
                  ))}
                </Grid>
              </CardContent></Card>
            </Grid>

            <Grid size={{ xs: 12, xl: 4 }}><Stack spacing={3}>
              <Card><CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}><SectionTitle title={t("storage")} hint={t("storageHint")} /><Box sx={{ mt: 2.5 }}><Stack direction="row" justifyContent="space-between" alignItems="baseline"><Typography variant="h5" fontWeight={780}>{status ? `${status.storage.used_percent}%` : "—"}</Typography><Typography variant="body2" color="text.secondary">{t("used")}</Typography></Stack><LinearProgress variant="determinate" value={status?.storage.used_percent ?? 0} sx={{ mt: 1.4, height: 8, borderRadius: 99 }} /><Grid container spacing={1} sx={{ mt: 1.5 }}>{[["used", status?.storage.used_bytes], ["free", status?.storage.free_bytes], ["total", status?.storage.total_bytes]].map(([key, value]) => <Grid key={key as string} size={4}><Typography variant="caption" color="text.secondary">{t(key as MessageKey)}</Typography><Typography variant="body2" fontWeight={700}>{formatBytes(Number(value ?? 0), language)}</Typography></Grid>)}</Grid></Box></CardContent></Card>
              <Card><CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}><SectionTitle title={t("serviceHealth")} hint={t("serviceHealthHint")} /><Stack divider={<Divider flexItem />} sx={{ mt: 1.5 }}>{componentRows.map(([label, key]) => { const state = status?.components[key] ?? "not_configured"; return <Stack key={key} direction="row" justifyContent="space-between" alignItems="center" sx={{ py: 1.25 }}><Typography variant="body2" fontWeight={650}>{t(label)}</Typography><StatusChip state={state} t={t} /></Stack>; })}</Stack></CardContent></Card>
            </Stack></Grid>

            <Grid size={{ xs: 12, lg: 7 }}><Card sx={{ height: "100%" }}><CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}><Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}><SectionTitle title={t("quickSetup")} hint={t("quickSetupHint")} /><TerminalRoundedIcon color="primary" /></Stack><Tabs variant="fullWidth" value={setupTab} onChange={(_event, value: number) => setSetupTab(value)} sx={{ mt: 2, minHeight: 40, p: 0.5, border: 1, borderColor: "divider", borderRadius: 1, bgcolor: "action.hover", "& .MuiTabs-indicator": { display: "none" }, "& .MuiTab-root": { minWidth: 0, minHeight: 34, px: 0.75, py: 0.6, borderRadius: 0.75, color: "text.secondary", fontSize: 12 }, "& .MuiTab-root.Mui-selected": { color: "text.primary", bgcolor: "background.paper", boxShadow: "0 1px 4px rgba(0,0,0,.14)" } }}>{setupClients.map((client) => <Tab key={client.label} label={client.label} />)}</Tabs><Paper variant="outlined" sx={{ mt: 1.5, p: 1.5, bgcolor: mode === "dark" ? "#071019" : "#eef3f5", borderRadius: 1 }}><Stack direction="row" alignItems="center" spacing={1} sx={{ minWidth: 0 }}><Tooltip title={setupClients[setupTab].command} placement="top"><Typography component="code" dir="ltr" sx={{ minWidth: 0, flex: 1, fontFamily: 'ui-monospace, "SFMono-Regular", Consolas, monospace', fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{setupClients[setupTab].command}</Typography></Tooltip><Button size="small" startIcon={copied ? <CheckCircleRoundedIcon /> : <ContentCopyRoundedIcon />} onClick={() => void handleCopy()} sx={{ flexShrink: 0 }}>{t(copied ? "copied" : "copy")}</Button></Stack></Paper></CardContent></Card></Grid>

            <Grid size={{ xs: 12, lg: 5 }}><Card sx={{ height: "100%" }}><CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}><Stack direction="row" justifyContent="space-between"><SectionTitle title={t("security")} hint={t("securityHint")} /><ShieldRoundedIcon color="success" /></Stack><Grid container spacing={1.2} sx={{ mt: 1.5 }}>{["nonRoot", "readOnly", "noPrivileges", "registrationClosed"].map((key) => <Grid key={key} size={{ xs: 12, sm: 6 }}><Paper variant="outlined" sx={{ p: 1.4, borderRadius: 1, bgcolor: "transparent" }}><Stack direction="row" alignItems="center" spacing={1}><CheckCircleRoundedIcon color="success" sx={{ fontSize: 18, flexShrink: 0 }} /><Typography variant="body2" fontWeight={620}>{t(key as MessageKey)}</Typography></Stack></Paper></Grid>)}</Grid></CardContent></Card></Grid>

            <Grid size={12}><Card><CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}><SectionTitle title={t("activity")} hint={t("activityHint")} /><Stack alignItems="center" textAlign="center" sx={{ py: 4 }}><Avatar sx={{ bgcolor: "action.hover", color: "text.secondary" }}><ScheduleRoundedIcon /></Avatar><Typography fontWeight={680} sx={{ mt: 1.5 }}>{t("noActivity")}</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: 0.4 }}>{t("auditLater")}</Typography></Stack></CardContent></Card></Grid>
          </Grid>

          <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" spacing={1} sx={{ py: 3 }}><Typography variant="caption" color="text.secondary">{t("version")} {status?.version ?? packageMetadata.version} · {t("environment")} {status?.environment ?? "—"}</Typography><Typography variant="caption" color="text.secondary" dir="ltr">{t("commit")}: {status?.build.commit && status.build.commit !== "unknown" ? status.build.commit.slice(0, 12) : t("unknown")} <ArrowForwardRoundedIcon sx={{ fontSize: 12, verticalAlign: "middle" }} /></Typography></Stack>
          </>
          )}
          </Suspense>
        </Box>
      </Box>
    </Box>
  );
}
