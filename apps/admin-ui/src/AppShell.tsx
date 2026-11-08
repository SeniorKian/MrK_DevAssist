/**
 * AppShell (docs/33 §1.1, §1.3, §6): the frame around every signed-in page.
 *
 * - Desktop (≥ md): permanent side nav with the 7 groups + footer links (All settings, About).
 * - Tablet (sm–md): the same nav in a drawer behind a menu button.
 * - Phone (< sm): bottom bar with Home · Packages · Server · Files · «بیشتر» (a sheet with the rest);
 *   the top bar shrinks to brand · search · bell · avatar, and mode/language/theme move into the avatar menu.
 * - Top bar: search (Ctrl+K), Simple/Advanced switch, language, theme, the attention bell (Home count),
 *   and the user menu (change password, sign out).
 * - Routes are `#/<group>/<tab>` from nav.ts; old hashes redirect. Each group is one lazy page that
 *   renders its own tabs with GroupTabs/useGroupTab.
 */
import {
  Component, lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState,
  type ComponentType, type ErrorInfo, type LazyExoticComponent, type ReactNode
} from "react";
import {
  Alert, AppBar, Avatar, Badge, Box, BottomNavigation, BottomNavigationAction, Button, Dialog, DialogContent, Divider, Drawer,
  IconButton, InputAdornment, LinearProgress, List, ListItemButton, ListItemIcon, ListItemText, Menu, MenuItem,
  Paper, Popover, Stack, TextField, Toolbar, Tooltip, Typography, useMediaQuery, useTheme
} from "@mui/material";
import MenuRoundedIcon from "@mui/icons-material/MenuRounded";
import LightModeRoundedIcon from "@mui/icons-material/LightModeRounded";
import DarkModeRoundedIcon from "@mui/icons-material/DarkModeRounded";
import NotificationsNoneRoundedIcon from "@mui/icons-material/NotificationsNoneRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import TranslateRoundedIcon from "@mui/icons-material/TranslateRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import MoreHorizRoundedIcon from "@mui/icons-material/MoreHorizRounded";
import UpdateRoundedIcon from "@mui/icons-material/UpdateRounded";
import ErrorRoundedIcon from "@mui/icons-material/ErrorRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import InfoRoundedIcon from "@mui/icons-material/InfoRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import packageMetadata from "../package.json";
import type { AuthUser } from "./App";
import { apiGet } from "./api";
import { translate, type Language, type MessageKey } from "./i18n";
import {
  MOBILE_PRIMARY_GROUPS, NAV_UTILITIES, findGroup, resolveRoute, routeHref, searchNav, utilityHref, visibleGroups,
  type GroupKey, type GroupPageKey, type NavGroup, type Route, type UtilityKey
} from "./nav";
import { UiModeToggle, useUiMode } from "./uiMode";
import { useUndoSnackbar } from "./kit";
import { roleName } from "./copy/roles";
import { pick } from "./copy/text";
import { attentionText, useHomeSummary, type HomeAttention } from "./homeSummary";
import { ChangePasswordDialog, passwordChangedText } from "./ChangePasswordPage";

// ── Pages ────────────────────────────────────────────────────────────────────

/** Props every group page receives. Pages may ignore any of them. */
export type ShellPageProps = {
  user: AuthUser;
  language: Language;
  permissions: string[];
  /** The current tab key of this group (same as `useGroupTab`). */
  tab: string;
  onUnauthorized: () => void;
};

type LazyPage = LazyExoticComponent<ComponentType<ShellPageProps>>;

// Each group page is a separate file with a default export (docs/33 §7 Phase 1 contract).
const GROUP_PAGES: Record<GroupPageKey, LazyPage> = {
  HomePage: lazy(() => import("./HomePage")) as unknown as LazyPage,
  PackagesPage: lazy(() => import("./PackagesPage")) as unknown as LazyPage,
  ServerPage: lazy(() => import("./ServerPage")) as unknown as LazyPage,
  FilesPage: lazy(() => import("./FilesPage")) as unknown as LazyPage,
  SecurityPage: lazy(() => import("./SecurityPage")) as unknown as LazyPage,
  PeoplePage: lazy(() => import("./PeoplePage")) as unknown as LazyPage,
  AlertsPage: lazy(() => import("./AlertsPage")) as unknown as LazyPage
};

type UtilityPageProps = ShellPageProps & {
  colorMode: "dark" | "light";
  onLanguageChange: () => void;
  onColorModeChange: () => void;
  onChangePassword: () => void;
};

const UTILITY_PAGES: Record<UtilityKey, LazyExoticComponent<ComponentType<UtilityPageProps>>> = {
  settings: lazy(() => import("./SettingsPage")),
  about: lazy(() => import("./AboutPage"))
};

const KitDemo = lazy(() => import("./kit/KitDemo"));

const DRAWER_WIDTH = 264;
const BOTTOM_NAV_HEIGHT = 64;
const UI_COMMIT = import.meta.env.VITE_BUILD_COMMIT || "unknown";

const COPY = {
  pageFailed: { fa: "این بخش باز نشد", en: "This section didn't open" },
  pageFailedBody: {
    fa: "شاید نسخه تازه‌ای از پنل آمده باشد. یک بار صفحه را تازه کنید.",
    en: "A new version of the panel may have arrived. Reload the page once."
  },
  reload: { fa: "تازه کردن صفحه", en: "Reload the page" },
  nav: { fa: "بخش‌های پنل", en: "Panel sections" },
  attentionCount: { fa: "{n} مورد نیاز به توجه دارد", en: "{n} things need attention" },
  searchNothing: { fa: "بخشی با این نام پیدا نشد.", en: "No section matches that." },
  searchTip: { fa: "نام یک بخش یا کار را بنویسید؛ مثلاً «پشتیبان» یا «پروکسی».", en: "Type a section or task, for example “backup” or “proxy”." }
};

// ── Small pieces ─────────────────────────────────────────────────────────────

class PageErrorBoundary extends Component<{ language: Language; resetKey: string; children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    console.error("page failed to render", error, info.componentStack);
  }

  componentDidUpdate(previous: { resetKey: string }) {
    if (previous.resetKey !== this.props.resetKey && this.state.failed) this.setState({ failed: false });
  }

  render() {
    if (!this.state.failed) return this.props.children;
    const { language } = this.props;
    return (
      <Alert
        severity="warning"
        action={<Button color="inherit" onClick={() => window.location.reload()}>{pick(language, COPY.reload)}</Button>}
      >
        <Typography fontWeight={720}>{pick(language, COPY.pageFailed)}</Typography>
        <Typography variant="body2">{pick(language, COPY.pageFailedBody)}</Typography>
      </Alert>
    );
  }
}

function Brand({ language, compact = false }: { language: Language; compact?: boolean }) {
  return (
    <Stack direction="row" alignItems="center" spacing={1.5} sx={{ minWidth: 0 }}>
      <Box
        aria-hidden
        sx={{
          width: compact ? 32 : 38, height: compact ? 32 : 38, borderRadius: 1.25, display: "grid", placeItems: "center",
          fontSize: 12, fontWeight: 850, color: "#042f2e", background: "linear-gradient(145deg, #99f6e4, #38bdf8)", flexShrink: 0
        }}
      >
        MRK
      </Box>
      {!compact && (
        <Box sx={{ minWidth: 0 }}>
          <Typography fontWeight={780} lineHeight={1.35} noWrap>{translate(language, "product")}</Typography>
          <Typography variant="caption" color="text.secondary" display="block" noWrap>{translate(language, "subtitle")}</Typography>
        </Box>
      )}
    </Stack>
  );
}

function initials(user: AuthUser) {
  const source = (user.display_name || user.username || "?").trim();
  const parts = source.split(/\s+/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : source.slice(0, 2);
  return letters.toUpperCase();
}

function isMac() {
  return typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
}

// ── Status poll (new panel version) ──────────────────────────────────────────

type SystemBuild = { build?: { commit?: string; ui_version?: string } };

function safeSessionGet(key: string) {
  try {
    return window.sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeSessionSet(key: string, value: string) {
  try {
    window.sessionStorage.setItem(key, value);
  } catch {
    // storage may be unavailable
  }
}

/** Reload once when the server runs a newer panel build; then offer a manual reload. */
function useBuildCheck() {
  const [updateState, setUpdateState] = useState<"none" | "updating" | "failed">("none");
  const [offline, setOffline] = useState(false);
  const target = useRef("latest");
  const forceReload = useCallback((commit: string) => {
    const url = new URL(window.location.href);
    url.searchParams.set("_ui", commit.slice(0, 12));
    window.location.replace(url.toString());
  }, []);
  const check = useCallback(async () => {
    try {
      const response = await apiGet(`/api/v1/system/status?_=${Date.now()}`);
      // 401 is handled by the session; 403 means this role can't read the status (nothing to check).
      if (response.status === 401 || response.status === 403) return;
      if (!response.ok) throw new Error("status");
      const payload = (await response.json()) as SystemBuild;
      setOffline(false);
      const commit = payload.build?.commit ?? "unknown";
      const uiVersion = payload.build?.ui_version ?? packageMetadata.version;
      if (uiVersion === packageMetadata.version && (commit === "unknown" || commit === UI_COMMIT)) return;
      target.current = commit !== "unknown" ? commit : uiVersion;
      const reloadKey = `mrk-ui-reload:${commit}:${uiVersion}`;
      if (safeSessionGet(reloadKey) !== "attempted") {
        safeSessionSet(reloadKey, "attempted");
        setUpdateState("updating");
        window.setTimeout(() => forceReload(target.current), 900);
      } else {
        setUpdateState("failed");
      }
    } catch {
      setOffline(true);
    }
  }, [forceReload]);
  useEffect(() => {
    void check();
    const timer = window.setInterval(() => void check(), 60_000);
    const onVisible = () => document.visibilityState === "visible" && void check();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [check]);
  return { updateState, offline, retry: check, reloadNow: () => forceReload(target.current) };
}

// ── Shell ────────────────────────────────────────────────────────────────────

type AppShellProps = {
  language: Language;
  colorMode: "dark" | "light";
  user: AuthUser;
  onUnauthorized: () => void;
  onLogout: () => void;
  onLanguageChange: () => void;
  onColorModeChange: () => void;
  onUserChange: (user: AuthUser | null) => void;
};

export function AppShell({ language, colorMode, user, onUnauthorized, onLogout, onLanguageChange, onColorModeChange, onUserChange }: AppShellProps) {
  const theme = useTheme();
  const isDesktop = useMediaQuery(theme.breakpoints.up("md"));
  const isPhone = useMediaQuery(theme.breakpoints.down("sm"));
  const { mode } = useUiMode();
  const t = useCallback((key: MessageKey) => translate(language, key), [language]);
  const permissions = user.permissions;
  const groups = useMemo(() => visibleGroups(permissions, mode), [permissions, mode]);

  // ── routing
  const [route, setRoute] = useState<Route>(() => resolveRoute(window.location.hash, permissions, mode).route);
  const sync = useCallback(() => {
    const resolved = resolveRoute(window.location.hash, permissions, mode);
    if (resolved.redirected) window.history.replaceState(null, "", resolved.href);
    setRoute(resolved.route);
  }, [permissions, mode]);
  useEffect(() => {
    sync();
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, [sync]);
  const go = useCallback((href: string) => {
    if (window.location.hash === href) sync();
    else window.location.hash = href;
  }, [sync]);

  // Back to the top when the group or utility changes (not when a tab changes).
  const routeKey = route.kind === "tab" ? `g:${route.group}` : route.kind === "utility" ? `u:${route.key}` : "kit";
  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [routeKey]);

  // ── layout bits
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [bellAnchor, setBellAnchor] = useState<HTMLElement | null>(null);
  const [userAnchor, setUserAnchor] = useState<HTMLElement | null>(null);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const { notify, snackbar } = useUndoSnackbar();
  const build = useBuildCheck();
  const home = useHomeSummary(60_000);
  const attention = home.data?.attention ?? [];

  useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--mrk-bottom-nav-height", isPhone ? `${BOTTOM_NAV_HEIGHT}px` : "0px");
    return () => {
      root.style.removeProperty("--mrk-bottom-nav-height");
    };
  }, [isPhone]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const activeGroup: GroupKey | null = route.kind === "tab" ? route.group : null;
  const activeUtility: UtilityKey | null = route.kind === "utility" ? route.key : null;
  const currentTitle =
    route.kind === "tab" ? findGroup(route.group)?.label[language] ?? "" :
    route.kind === "utility" ? NAV_UTILITIES.find((item) => item.key === route.key)?.label[language] ?? "" : "";

  useEffect(() => {
    document.title = currentTitle ? `${currentTitle} · ${t("product")}` : t("product");
  }, [currentTitle, t]);

  const navigate = (href: string) => {
    setDrawerOpen(false);
    setMoreOpen(false);
    go(href);
  };

  // ── side nav
  const navList = (
    <Box dir={language === "fa" ? "rtl" : "ltr"} sx={{ height: "100%", px: 1.5, py: 2, display: "flex", flexDirection: "column" }}>
      <Box sx={{ px: 1, py: 0.5 }}><Brand language={language} /></Box>
      <Divider sx={{ my: 2 }} />
      <List component="nav" aria-label={pick(language, COPY.nav)} sx={{ px: 0 }}>
        {groups.map((group) => (
          <NavItem
            key={group.key}
            group={group}
            language={language}
            active={group.key === activeGroup}
            badge={group.key === "home" ? attention.length : 0}
            onClick={() => navigate(routeHref(group.key))}
          />
        ))}
      </List>
      <Box sx={{ mt: "auto" }}>
        <Divider sx={{ my: 1.5 }} />
        <List sx={{ px: 0 }}>
          {NAV_UTILITIES.map((item) => {
            const Icon = item.icon;
            const active = activeUtility === item.key;
            return (
              <ListItemButton
                key={item.key}
                selected={active}
                aria-current={active ? "page" : undefined}
                onClick={() => navigate(utilityHref(item.key))}
                sx={{ minHeight: 44, gap: 1.25, px: 1.5, mb: 0.5 }}
              >
                <ListItemIcon sx={{ minWidth: 24, color: "inherit" }}><Icon fontSize="small" /></ListItemIcon>
                <ListItemText primary={item.label[language]} slotProps={{ primary: { noWrap: true, fontSize: 14, fontWeight: active ? 720 : 560 } }} />
              </ListItemButton>
            );
          })}
        </List>
        <Typography variant="caption" color="text.secondary" display="block" sx={{ px: 1.5, mt: 1 }}>
          {t("version")} <bdi dir="ltr">{packageMetadata.version}</bdi>
        </Typography>
      </Box>
    </Box>
  );

  // ── bottom nav (phones)
  const primary = MOBILE_PRIMARY_GROUPS.map((key) => groups.find((group) => group.key === key)).filter(Boolean) as NavGroup[];
  const others = groups.filter((group) => !primary.includes(group));
  const bottomValue = activeGroup && primary.some((group) => group.key === activeGroup) ? activeGroup : "more";

  // ── page
  let page: ReactNode = null;
  const pageProps: ShellPageProps = { user, language, permissions, tab: route.kind === "tab" ? route.tab : "", onUnauthorized };
  if (route.kind === "tab") {
    const group = findGroup(route.group)!;
    const Page = GROUP_PAGES[group.page];
    page = <Page {...pageProps} />;
  } else if (route.kind === "utility") {
    const Page = UTILITY_PAGES[route.key];
    page = (
      <Page
        {...pageProps}
        colorMode={colorMode}
        onLanguageChange={onLanguageChange}
        onColorModeChange={onColorModeChange}
        onChangePassword={() => setPasswordOpen(true)}
      />
    );
  } else {
    page = <KitDemo permissions={permissions} />;
  }

  const bellCount = attention.length;
  const bellLabel = bellCount
    ? pick(language, COPY.attentionCount).replace("{n}", new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(bellCount))
    : t("notificationsBell");

  const themeButton = (
    <Tooltip title={t("switchTheme")}>
      <IconButton aria-label={t("switchTheme")} onClick={onColorModeChange}>
        {colorMode === "dark" ? <LightModeRoundedIcon /> : <DarkModeRoundedIcon />}
      </IconButton>
    </Tooltip>
  );

  return (
    <Box
      dir={language === "fa" ? "rtl" : "ltr"}
      sx={{
        display: "flex",
        minHeight: "100vh",
        background:
          colorMode === "dark"
            ? "radial-gradient(circle at 62% -10%, rgba(20,184,166,.09), transparent 32%), #071019"
            : "radial-gradient(circle at 62% -10%, rgba(13,148,136,.08), transparent 32%), #f4f7fa"
      }}
    >
      <Box
        component="a"
        href="#mrk-main"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("mrk-main")?.focus();
        }}
        sx={{
          position: "absolute", insetInlineStart: 8, top: -48, zIndex: theme.zIndex.tooltip, px: 2, py: 1, borderRadius: 1,
          bgcolor: "background.paper", color: "text.primary", "&:focus": { top: 8 }
        }}
      >
        {t("skipToContent")}
      </Box>

      <AppBar
        position={isPhone ? "absolute" : "fixed"}
        color="transparent"
        elevation={0}
        sx={{
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          insetInlineStart: { md: `${DRAWER_WIDTH}px` },
          borderBottom: 1,
          borderColor: "divider",
          bgcolor: colorMode === "dark" ? "rgba(7,16,25,.86)" : "rgba(244,247,250,.86)",
          backdropFilter: "blur(18px)"
        }}
      >
        <Toolbar sx={{ minHeight: { xs: "56px !important", sm: "64px !important" }, gap: 0.5, px: { xs: 1, sm: 2 } }}>
          {!isDesktop && !isPhone && (
            <IconButton aria-label={t("menu")} onClick={() => setDrawerOpen(true)}>
              <MenuRoundedIcon />
            </IconButton>
          )}
          {isPhone ? (
            <Box sx={{ flex: 1, minWidth: 0, px: 0.5 }}><Brand language={language} compact /></Box>
          ) : (
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Button
                onClick={() => setSearchOpen(true)}
                startIcon={<SearchRoundedIcon />}
                color="inherit"
                sx={{
                  justifyContent: "flex-start", width: "100%", maxWidth: 380, minHeight: 40, px: 1.5, color: "text.secondary",
                  border: 1, borderColor: "divider", bgcolor: "action.hover", fontWeight: 500
                }}
              >
                <Box component="span" sx={{ flex: 1, textAlign: "start" }}>{t("searchHint")}</Box>
                <Box component="kbd" dir="ltr" sx={{ fontFamily: "inherit", fontSize: 12, opacity: 0.8 }}>{isMac() ? "⌘K" : "Ctrl+K"}</Box>
              </Button>
            </Box>
          )}
          {isPhone && (
            <IconButton aria-label={t("search")} onClick={() => setSearchOpen(true)}>
              <SearchRoundedIcon />
            </IconButton>
          )}
          {!isPhone && <Box sx={{ mx: 0.5 }}><UiModeToggle /></Box>}
          {!isPhone && themeButton}
          {!isPhone && (
            <Button variant="outlined" size="small" onClick={onLanguageChange} lang={language === "fa" ? "en" : "fa"} sx={{ minWidth: 72, minHeight: 36, mx: 0.5 }}>
              {t("language")}
            </Button>
          )}
          <Tooltip title={bellLabel}>
            <IconButton aria-label={bellLabel} onClick={(event) => setBellAnchor(event.currentTarget)}>
              <Badge badgeContent={bellCount} color={attention.some((item) => item.severity === "critical" || item.severity === "error") ? "error" : "warning"} max={99}>
                <NotificationsNoneRoundedIcon />
              </Badge>
            </IconButton>
          </Tooltip>
          <Tooltip title={t("userMenu")}>
            <IconButton aria-label={t("userMenu")} onClick={(event) => setUserAnchor(event.currentTarget)} sx={{ p: 0.5 }}>
              <Avatar sx={{ width: 34, height: 34, fontSize: 13, bgcolor: "primary.main", color: "primary.contrastText" }}>{initials(user)}</Avatar>
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>

      {!isPhone && (
        <Box sx={{ width: { md: DRAWER_WIDTH }, flexShrink: { md: 0 } }}>
          {/* anchor="left" is logical: MUI mirrors it to the right edge when the theme is RTL. */}
          {isDesktop ? (
            <Drawer variant="permanent" anchor="left" open sx={{ "& .MuiDrawer-paper": { width: DRAWER_WIDTH, borderColor: "divider" } }}>
              {navList}
            </Drawer>
          ) : (
            <Drawer variant="temporary" anchor="left" open={drawerOpen} onClose={() => setDrawerOpen(false)} ModalProps={{ keepMounted: true }} sx={{ "& .MuiDrawer-paper": { width: DRAWER_WIDTH } }}>
              {navList}
            </Drawer>
          )}
        </Box>
      )}

      <Box
        component="main"
        id="mrk-main"
        tabIndex={-1}
        sx={{
          flexGrow: 1,
          minWidth: 0,
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          outline: "none",
          pb: isPhone ? `calc(${BOTTOM_NAV_HEIGHT + 88}px + env(safe-area-inset-bottom, 0px))` : 4
        }}
      >
        <Toolbar sx={{ minHeight: { xs: "56px !important", sm: "64px !important" } }} />
        <Box sx={{ px: { xs: 2, sm: 3, xl: 4 }, pt: { xs: 1.5, sm: 3 }, maxWidth: 1480, mx: "auto" }}>
          {build.updateState !== "none" && (
            <Alert
              severity={build.updateState === "updating" ? "info" : "warning"}
              icon={<UpdateRoundedIcon />}
              action={build.updateState === "failed" ? <Button color="inherit" size="small" onClick={build.reloadNow}>{t("updateNow")}</Button> : undefined}
              sx={{ mb: 2.5 }}
            >
              <Typography fontWeight={750}>{t("updateAvailable")}</Typography>
              <Typography variant="body2">{t(build.updateState === "updating" ? "updating" : "updateFailed")}</Typography>
            </Alert>
          )}
          {build.offline && (
            <Alert severity="error" action={<Button color="inherit" size="small" onClick={() => void build.retry()}>{t("retry")}</Button>} sx={{ mb: 2.5 }}>
              {t("connectionError")}
            </Alert>
          )}
          <PageErrorBoundary language={language} resetKey={routeKey}>
            <Suspense fallback={<LinearProgress sx={{ mt: 1 }} aria-label={t("refreshing")} />}>{page}</Suspense>
          </PageErrorBoundary>
        </Box>
      </Box>

      {isPhone && (
        <Paper
          elevation={8}
          component="nav"
          aria-label={pick(language, COPY.nav)}
          sx={{ position: "fixed", left: 0, right: 0, bottom: 0, zIndex: theme.zIndex.appBar, pb: "env(safe-area-inset-bottom, 0px)", borderTop: 1, borderColor: "divider" }}
        >
          <BottomNavigation
            showLabels
            value={bottomValue}
            onChange={(_event, value: string) => {
              if (value === "more") setMoreOpen(true);
              else navigate(routeHref(value as GroupKey));
            }}
            sx={{ height: BOTTOM_NAV_HEIGHT, bgcolor: "transparent", "& .MuiBottomNavigationAction-root": { minWidth: 0, px: 0.5 } }}
          >
            {primary.map((group) => {
              const Icon = group.icon;
              return (
                <BottomNavigationAction
                  key={group.key}
                  value={group.key}
                  label={group.label[language]}
                  icon={group.key === "home" && attention.length ? <Badge variant="dot" color="warning"><Icon /></Badge> : <Icon />}
                  sx={{ "& .MuiBottomNavigationAction-label": { fontSize: 11, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "100%" } }}
                />
              );
            })}
            <BottomNavigationAction value="more" label={t("more")} icon={<MoreHorizRoundedIcon />} />
          </BottomNavigation>
        </Paper>
      )}

      <Drawer anchor="bottom" open={moreOpen} onClose={() => setMoreOpen(false)} sx={{ "& .MuiDrawer-paper": { borderTopLeftRadius: 16, borderTopRightRadius: 16, pb: "env(safe-area-inset-bottom, 0px)" } }}>
        <Box dir={language === "fa" ? "rtl" : "ltr"} sx={{ py: 1 }}>
          <Box aria-hidden sx={{ width: 40, height: 4, borderRadius: 2, bgcolor: "divider", mx: "auto", mb: 1 }} />
          <List>
            {others.map((group) => (
              <NavItem key={group.key} group={group} language={language} active={group.key === activeGroup} onClick={() => navigate(routeHref(group.key))} />
            ))}
            {others.length > 0 && <Divider sx={{ my: 1 }} />}
            {NAV_UTILITIES.map((item) => {
              const Icon = item.icon;
              return (
                <ListItemButton key={item.key} selected={activeUtility === item.key} onClick={() => navigate(utilityHref(item.key))} sx={{ minHeight: 52, gap: 1.5, px: 2.5 }}>
                  <ListItemIcon sx={{ minWidth: 24, color: "inherit" }}><Icon /></ListItemIcon>
                  <ListItemText primary={item.label[language]} />
                </ListItemButton>
              );
            })}
          </List>
        </Box>
      </Drawer>

      <BellPopover
        anchor={bellAnchor}
        language={language}
        onClose={() => setBellAnchor(null)}
        attention={attention}
        onNavigate={(href) => {
          setBellAnchor(null);
          navigate(href);
        }}
      />

      <Menu
        anchorEl={userAnchor}
        open={Boolean(userAnchor)}
        onClose={() => setUserAnchor(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: language === "fa" ? "left" : "right" }}
        transformOrigin={{ vertical: "top", horizontal: language === "fa" ? "left" : "right" }}
        slotProps={{ paper: { sx: { minWidth: 260 } } }}
      >
        <Box sx={{ px: 2, py: 1.25 }}>
          <Typography fontWeight={720} noWrap>{user.display_name || user.username}</Typography>
          <Typography variant="body2" color="text.secondary" noWrap>{roleName(language, user.role)}</Typography>
          {user.email && <Typography variant="caption" color="text.secondary" display="block" noWrap component="bdi" dir="ltr">{user.email}</Typography>}
        </Box>
        <Divider />
        {isPhone && (
          <Box sx={{ px: 2, py: 1.25 }}>
            <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
              <TuneRoundedIcon fontSize="small" color="action" />
              <Typography variant="body2" fontWeight={650}>{t("uiMode")}</Typography>
            </Stack>
            <UiModeToggle />
          </Box>
        )}
        {isPhone && (
          <MenuItem onClick={() => { setUserAnchor(null); onLanguageChange(); }} sx={{ minHeight: 48 }}>
            <ListItemIcon><TranslateRoundedIcon fontSize="small" /></ListItemIcon>
            <ListItemText lang={language === "fa" ? "en" : "fa"}>{t("language")}</ListItemText>
          </MenuItem>
        )}
        {isPhone && (
          <MenuItem onClick={() => { setUserAnchor(null); onColorModeChange(); }} sx={{ minHeight: 48 }}>
            <ListItemIcon>{colorMode === "dark" ? <LightModeRoundedIcon fontSize="small" /> : <DarkModeRoundedIcon fontSize="small" />}</ListItemIcon>
            <ListItemText>{`${t("theme")}: ${t(colorMode === "dark" ? "themeLight" : "themeDark")}`}</ListItemText>
          </MenuItem>
        )}
        {isPhone && <Divider />}
        <MenuItem onClick={() => { setUserAnchor(null); setPasswordOpen(true); }} sx={{ minHeight: 48 }}>
          <ListItemIcon><KeyRoundedIcon fontSize="small" /></ListItemIcon>
          <ListItemText>{t("changePassword")}</ListItemText>
        </MenuItem>
        {NAV_UTILITIES.filter((item) => item.key === "settings").map((item) => {
          const Icon = item.icon;
          return (
            <MenuItem key={item.key} onClick={() => { setUserAnchor(null); navigate(utilityHref(item.key)); }} sx={{ minHeight: 48 }}>
              <ListItemIcon><Icon fontSize="small" /></ListItemIcon>
              <ListItemText>{item.label[language]}</ListItemText>
            </MenuItem>
          );
        })}
        <Divider />
        <MenuItem onClick={() => { setUserAnchor(null); onLogout(); }} sx={{ minHeight: 48 }}>
          <ListItemIcon><LogoutRoundedIcon fontSize="small" /></ListItemIcon>
          <ListItemText>{t("logout")}</ListItemText>
        </MenuItem>
      </Menu>

      <SearchDialog
        open={searchOpen}
        language={language}
        permissions={permissions}
        mode={mode}
        onClose={() => setSearchOpen(false)}
        onPick={(href) => {
          setSearchOpen(false);
          navigate(href);
        }}
      />

      <ChangePasswordDialog
        open={passwordOpen}
        language={language}
        onClose={() => setPasswordOpen(false)}
        onChanged={(next) => {
          onUserChange(next);
          notify({ message: passwordChangedText(language), tone: "success" });
        }}
      />
      {snackbar}
    </Box>
  );
}

function NavItem({ group, language, active, badge = 0, onClick }: { group: NavGroup; language: Language; active: boolean; badge?: number; onClick: () => void }) {
  const Icon = group.icon;
  return (
    <ListItemButton
      selected={active}
      aria-current={active ? "page" : undefined}
      onClick={onClick}
      sx={{
        mb: 0.5, minHeight: 46, px: 1.5, gap: 1.25, borderRadius: 1,
        "&.Mui-selected": { bgcolor: "rgba(45,212,191,.11)", color: "primary.main" },
        "&.Mui-selected:hover": { bgcolor: "rgba(45,212,191,.15)" }
      }}
    >
      <ListItemIcon sx={{ minWidth: 24, width: 24, justifyContent: "center", color: "inherit" }}>
        <Badge variant="dot" color="warning" invisible={!badge}><Icon fontSize="small" /></Badge>
      </ListItemIcon>
      <ListItemText primary={group.label[language]} slotProps={{ primary: { noWrap: true, fontSize: 14.5, fontWeight: active ? 720 : 570 } }} />
    </ListItemButton>
  );
}

function BellPopover({
  anchor, language, onClose, attention, onNavigate
}: {
  anchor: HTMLElement | null;
  language: Language;
  onClose: () => void;
  attention: HomeAttention[];
  onNavigate: (href: string) => void;
}) {
  const items = attention.map((item) => ({ item, text: attentionText(language, item) }));
  return (
    <Popover
      open={Boolean(anchor)}
      anchorEl={anchor}
      onClose={onClose}
      anchorOrigin={{ vertical: "bottom", horizontal: language === "fa" ? "left" : "right" }}
      transformOrigin={{ vertical: "top", horizontal: language === "fa" ? "left" : "right" }}
      slotProps={{ paper: { sx: { width: 360, maxWidth: "calc(100vw - 24px)" } } }}
    >
      <Box dir={language === "fa" ? "rtl" : "ltr"}>
        <Typography component="h2" fontWeight={760} sx={{ px: 2, pt: 1.75, pb: 1 }}>{translate(language, "notificationsBell")}</Typography>
        {items.length === 0 ? (
          <Stack direction="row" spacing={1} alignItems="center" sx={{ px: 2, pb: 2 }}>
            <CheckCircleRoundedIcon color="success" fontSize="small" />
            <Typography variant="body2">{translate(language, "nothingNeedsYou")}</Typography>
          </Stack>
        ) : (
          <List dense disablePadding sx={{ maxHeight: 360, overflowY: "auto" }}>
            {items.map(({ item, text }) => {
              const Icon = text.severity === "critical" ? ErrorRoundedIcon : text.severity === "warning" ? WarningAmberRoundedIcon : InfoRoundedIcon;
              const color = text.severity === "critical" ? "error" : text.severity === "warning" ? "warning" : "info";
              return (
                <ListItemButton key={item.id} onClick={() => onNavigate(text.route ?? "#/home")} sx={{ alignItems: "flex-start", gap: 1.25, py: 1.25, px: 2 }}>
                  <Icon color={color} fontSize="small" sx={{ mt: 0.25 }} aria-hidden />
                  <ListItemText primary={text.title} secondary={text.why} slotProps={{ primary: { fontWeight: 650, fontSize: 14 } }} />
                </ListItemButton>
              );
            })}
          </List>
        )}
        <Divider />
        <Box sx={{ p: 1 }}>
          <Button fullWidth onClick={() => onNavigate("#/home")} sx={{ minHeight: 44 }}>{translate(language, "seeAll")}</Button>
        </Box>
      </Box>
    </Popover>
  );
}

function SearchDialog({
  open, language, permissions, mode, onClose, onPick
}: {
  open: boolean;
  language: Language;
  permissions: string[];
  mode: "simple" | "advanced";
  onClose: () => void;
  onPick: (href: string) => void;
}) {
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  useEffect(() => {
    if (open) {
      setQuery("");
      setIndex(0);
    }
  }, [open]);
  const hits = useMemo(() => searchNav(query, language, permissions, mode).slice(0, 12), [language, mode, permissions, query]);
  const utilityHits = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return [];
    return NAV_UTILITIES.filter((item) => item.label.fa.includes(query.trim()) || item.label.en.toLowerCase().includes(needle)).map((item) => ({
      href: utilityHref(item.key),
      title: item.label[language],
      hint: ""
    }));
  }, [language, query]);
  const all = [...hits.map((hit) => ({ href: hit.href, title: hit.title, hint: hit.hint })), ...utilityHits];
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm" fullScreen={fullScreen} aria-label={translate(language, "search")}>
      <DialogContent sx={{ p: 0 }} dir={language === "fa" ? "rtl" : "ltr"}>
        <Box sx={{ p: 2, pb: 1 }}>
          <TextField
            autoFocus
            fullWidth
            value={query}
            placeholder={translate(language, "searchHint")}
            onChange={(event) => {
              setQuery(event.target.value);
              setIndex(0);
            }}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown") {
                event.preventDefault();
                setIndex((value) => Math.min(value + 1, Math.max(all.length - 1, 0)));
              } else if (event.key === "ArrowUp") {
                event.preventDefault();
                setIndex((value) => Math.max(value - 1, 0));
              } else if (event.key === "Enter" && all[index]) {
                event.preventDefault();
                onPick(all[index].href);
              }
            }}
            slotProps={{
              htmlInput: { "aria-label": translate(language, "search") },
              input: { startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment> }
            }}
          />
        </Box>
        {query.trim() === "" ? (
          <Typography variant="body2" color="text.secondary" sx={{ px: 2.5, pb: 2.5 }}>{pick(language, COPY.searchTip)}</Typography>
        ) : all.length === 0 ? (
          <Typography variant="body2" color="text.secondary" sx={{ px: 2.5, pb: 2.5 }}>{pick(language, COPY.searchNothing)}</Typography>
        ) : (
          <List sx={{ pb: 1 }}>
            {all.map((hit, position) => (
              <ListItemButton key={hit.href} selected={position === index} onClick={() => onPick(hit.href)} sx={{ minHeight: 52, px: 2.5 }}>
                <ListItemText primary={hit.title} secondary={hit.hint || undefined} slotProps={{ primary: { fontWeight: 650 } }} />
              </ListItemButton>
            ))}
          </List>
        )}
        {fullScreen && (
          <Box sx={{ p: 2 }}>
            <Button fullWidth variant="outlined" onClick={onClose} sx={{ minHeight: 48 }}>{language === "fa" ? "بستن" : "Close"}</Button>
          </Box>
        )}
      </DialogContent>
    </Dialog>
  );
}
