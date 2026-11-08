import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Alert, Box, Button, CircularProgress, CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { CacheProvider } from "@emotion/react";
import createCache from "@emotion/cache";
import { prefixer } from "stylis";
import rtlPlugin from "stylis-plugin-rtl";
import { apiMutate, refreshCsrf, refreshSession, setCsrfToken, setUnauthorizedHandler } from "./api";
import { ConfirmProvider } from "./ConfirmDialog";
import { AppShell } from "./AppShell";
import { UiModeProvider } from "./uiMode";
import { Login } from "./Login";
import { Setup, type SetupValues } from "./Setup";
import { DEFAULT_PASSWORD_POLICY, readAuthFailure, readPasswordPolicy, type AuthFailure, type PasswordPolicy } from "./AuthShell";
import ChangePasswordPage from "./ChangePasswordPage";
import InvitePage, { inviteTokenFromHash } from "./InvitePage";
import { resetHome } from "./homeSummary";
import { translate, type Language } from "./i18n";

type ColorMode = "dark" | "light";
export type AuthUser = {
  id: number;
  username: string;
  role: string;
  permissions: string[];
  display_name?: string | null;
  email?: string | null;
  /** Invited accounts must choose their own password before anything else works. */
  must_change_password?: boolean;
};

function storedValue<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const value = window.localStorage.getItem(key);
    return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : fallback;
  } catch {
    return fallback;
  }
}

function storeValue(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // storage may be unavailable (private mode, blocked site data)
  }
}

const rtlCache = createCache({ key: "muirtl", stylisPlugins: [prefixer, rtlPlugin] });
const ltrCache = createCache({ key: "muiltr", stylisPlugins: [prefixer] });

export function App() {
  const [language, setLanguage] = useState<Language>(() => storedValue<Language>("mrk-language", ["fa", "en"], "fa"));
  const [mode, setMode] = useState<ColorMode>(() => storedValue<ColorMode>("mrk-theme", ["dark", "light"], "dark"));
  const [user, setUser] = useState<AuthUser | null>(null);
  const [setupRequired, setSetupRequired] = useState(false);
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicy>(DEFAULT_PASSWORD_POLICY);
  const [registrationEnabled, setRegistrationEnabled] = useState(false);
  const [authView, setAuthView] = useState<"login" | "register">("login");
  const [authLoading, setAuthLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const [inviteToken, setInviteToken] = useState<string | null>(() => inviteTokenFromHash(window.location.hash));

  const setCsrf = useCallback((token: string) => setCsrfToken(token), []);

  const handleUnauthorized = useCallback(() => {
    setSessionExpired(true);
    setUser(null);
    setCsrfToken("");
    resetHome();
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(handleUnauthorized);
  }, [handleUnauthorized]);

  useEffect(() => {
    storeValue("mrk-language", language);
    document.documentElement.lang = language;
    document.documentElement.dir = language === "fa" ? "rtl" : "ltr";
  }, [language]);

  useEffect(() => storeValue("mrk-theme", mode), [mode]);

  // The public invite link (#/invite/<token>) can be opened at any time, signed in or not.
  useEffect(() => {
    const onHash = () => setInviteToken(inviteTokenFromHash(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const loadSession = useCallback(async () => {
    setAuthLoading(true);
    setConnectionError(false);
    try {
      const setupResponse = await fetch("/api/v1/auth/setup-status", {
        headers: { Accept: "application/json" },
        cache: "no-store"
      });
      if (setupResponse.ok) {
        const setup = (await setupResponse.json()) as { required: boolean; password_policy?: unknown };
        setPasswordPolicy(readPasswordPolicy(setup));
        setSetupRequired(setup.required);
        if (setup.required) return;
      }
      const registrationResponse = await fetch("/api/v1/auth/registration-status", {
        headers: { Accept: "application/json" },
        cache: "no-store"
      });
      if (registrationResponse.ok) {
        const registration = (await registrationResponse.json()) as { enabled: boolean };
        setRegistrationEnabled(registration.enabled);
      }
      const response = await fetch("/api/v1/auth/me", {
        headers: { Accept: "application/json" },
        cache: "no-store"
      });
      if (!response.ok) return;
      const payload = (await response.json()) as { user: AuthUser; csrf_token: string };
      setUser(payload.user);
      setCsrf(payload.csrf_token);
    } catch {
      setConnectionError(true);
    } finally {
      setAuthLoading(false);
    }
  }, [setCsrf]);

  useEffect(() => void loadSession(), [loadSession]);

  // Sessions have a fixed TTL; rotate the session while the operator is active so
  // long working sessions are not cut off (and unsaved forms lost) mid-task.
  const lastActivity = useRef(Date.now());
  const lastRefresh = useRef(Date.now());
  const userId = user?.id ?? null;
  useEffect(() => {
    if (userId === null) return;
    lastRefresh.current = Date.now();
    const markActive = () => {
      lastActivity.current = Date.now();
    };
    const maybeRefresh = () => {
      const now = Date.now();
      const active = now - lastActivity.current < 30 * 60_000;
      if (document.visibilityState !== "visible" || !active || now - lastRefresh.current < 25 * 60_000) return;
      lastRefresh.current = now;
      void refreshSession();
    };
    const events = ["pointerdown", "keydown"] as const;
    events.forEach((name) => window.addEventListener(name, markActive, { passive: true }));
    document.addEventListener("visibilitychange", maybeRefresh);
    const timer = window.setInterval(maybeRefresh, 60_000);
    return () => {
      events.forEach((name) => window.removeEventListener(name, markActive));
      document.removeEventListener("visibilitychange", maybeRefresh);
      window.clearInterval(timer);
    };
  }, [userId]);

  const adoptSession = useCallback(
    (payload: { user: AuthUser; csrf_token: string; must_change_password?: boolean }) => {
      resetHome();
      setUser({ ...payload.user, must_change_password: payload.user.must_change_password ?? payload.must_change_password });
      setCsrf(payload.csrf_token);
      setSessionExpired(false);
    },
    [setCsrf]
  );

  const login = async (username: string, password: string): Promise<true | AuthFailure> => {
    const response = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    if (!response.ok) return readAuthFailure(response);
    adoptSession((await response.json()) as { user: AuthUser; csrf_token: string; must_change_password?: boolean });
    return true;
  };

  const createAccount = async (path: string, values: SetupValues): Promise<true | AuthFailure> => {
    const response = await fetch(path, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        display_name: values.displayName,
        email: values.email,
        password: values.password,
        password_confirmation: values.passwordConfirmation
      })
    });
    if (!response.ok) return readAuthFailure(response);
    adoptSession((await response.json()) as { user: AuthUser; csrf_token: string });
    return true;
  };

  const setup = async (values: SetupValues) => {
    const result = await createAccount("/api/v1/auth/setup", values);
    if (result === true) setSetupRequired(false);
    return result;
  };

  const register = async (values: SetupValues) => {
    const result = await createAccount("/api/v1/auth/register", values);
    if (result === true) setAuthView("login");
    return result;
  };

  const leaveInvite = useCallback(() => {
    setInviteToken(null);
    window.history.replaceState(null, "", "#/");
  }, []);

  const logout = useCallback(async () => {
    try {
      const options = { silentUnauthorized: true, retryOnForbidden: false } as const;
      const response = await apiMutate("/api/v1/auth/logout", options);
      // A stale CSRF token (or transient failure) gets one retry after refreshing the token.
      if (!response.ok && response.status !== 401 && (await refreshCsrf())) {
        await apiMutate("/api/v1/auth/logout", options);
      }
    } catch {
      // network failure: still clear local state below
    } finally {
      setUser(null);
      setCsrfToken("");
      setSessionExpired(false);
      setAuthView("login");
      resetHome();
    }
  }, []);

  /** Merge a fresh user payload (e.g. after a password change). */
  const onUserChange = useCallback((next: AuthUser | null) => {
    setUser((current) => (current ? { ...current, ...(next ?? {}), must_change_password: next?.must_change_password ?? false } : current));
  }, []);

  const toggleLanguage = useCallback(() => setLanguage((value) => (value === "fa" ? "en" : "fa")), []);
  const toggleMode = useCallback(() => setMode((value) => (value === "dark" ? "light" : "dark")), []);
  const onLogout = useCallback(() => void logout(), [logout]);

  const theme = useMemo(() => {
    const dark = mode === "dark";
    return createTheme({
      direction: language === "fa" ? "rtl" : "ltr",
      palette: {
        mode,
        primary: { main: dark ? "#5eead4" : "#0f766e" },
        secondary: { main: dark ? "#60a5fa" : "#2563eb" },
        success: { main: dark ? "#34d399" : "#059669" },
        warning: { main: dark ? "#fbbf24" : "#d97706" },
        error: { main: dark ? "#fb7185" : "#e11d48" },
        background: {
          default: dark ? "#071019" : "#f4f7fa",
          paper: dark ? "#0d1924" : "#ffffff"
        },
        text: {
          primary: dark ? "#edf6f7" : "#12242c",
          secondary: dark ? "#91a7b2" : "#5c7079"
        },
        divider: dark ? "rgba(148, 183, 194, .14)" : "rgba(30, 64, 75, .12)"
      },
      shape: { borderRadius: 8 },
      typography: {
        fontFamily:
          language === "fa"
            ? '"Vazirmatn Variable", "Inter Variable", sans-serif'
            : '"Inter Variable", "Vazirmatn Variable", sans-serif',
        h4: { fontWeight: 780, letterSpacing: language === "fa" ? 0 : "-0.035em" },
        h6: { fontWeight: 720 },
        button: { fontWeight: 650, textTransform: "none" }
      },
      components: {
        MuiCard: {
          styleOverrides: {
            root: {
              backgroundImage: "none",
              borderRadius: 10,
              border: `1px solid ${dark ? "rgba(148,183,194,.13)" : "rgba(30,64,75,.10)"}`,
              boxShadow: dark ? "0 10px 30px rgba(0,0,0,.10)" : "0 8px 24px rgba(27,59,69,.05)"
            }
          }
        },
        MuiPaper: {
          styleOverrides: {
            root: { backgroundImage: "none" },
            outlined: { borderRadius: 10 }
          }
        },
        MuiButton: {
          defaultProps: { disableElevation: true },
          styleOverrides: { root: { borderRadius: 7 } }
        },
        MuiChip: {
          styleOverrides: {
            root: { maxWidth: "100%", borderRadius: 6 },
            label: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }
          }
        },
        MuiListItemButton: {
          styleOverrides: { root: { borderRadius: 8 } }
        },
        MuiAlert: {
          styleOverrides: { root: { borderRadius: 8 } }
        },
        MuiTooltip: { defaultProps: { arrow: true } }
      }
    });
  }, [language, mode]);

  const centered = (children: ReactNode) => (
    <Box dir={language === "fa" ? "rtl" : "ltr"} sx={{ minHeight: "100vh", display: "grid", placeItems: "center", p: 2 }}>
      {children}
    </Box>
  );

  let content: ReactNode;
  if (inviteToken) {
    content = (
      <InvitePage
        language={language}
        token={inviteToken}
        onLanguageChange={toggleLanguage}
        onAccepted={(acceptedUser, csrf) => {
          adoptSession({ user: { ...acceptedUser, must_change_password: false }, csrf_token: csrf });
          setSetupRequired(false);
          leaveInvite();
        }}
        onGoToSignIn={() => {
          leaveInvite();
          void loadSession();
        }}
      />
    );
  } else if (authLoading) {
    content = centered(<CircularProgress size={30} aria-label={translate(language, "refreshing")} />);
  } else if (connectionError && !user) {
    content = centered(
      <Alert
        severity="error"
        action={<Button color="inherit" size="small" onClick={() => void loadSession()}>{translate(language, "retry")}</Button>}
        sx={{ maxWidth: 520, width: "100%" }}
      >
        {translate(language, "connectionError")}
      </Alert>
    );
  } else if (setupRequired) {
    content = <Setup language={language} onSetup={setup} onLanguageChange={toggleLanguage} passwordPolicy={passwordPolicy} />;
  } else if (!user && authView === "register" && registrationEnabled) {
    content = (
      <Setup
        language={language}
        variant="public"
        onSetup={register}
        onBack={() => setAuthView("login")}
        onLanguageChange={toggleLanguage}
        passwordPolicy={passwordPolicy}
      />
    );
  } else if (user?.must_change_password) {
    content = (
      <ChangePasswordPage
        language={language}
        onLanguageChange={toggleLanguage}
        onChanged={(next) => onUserChange(next)}
        onSignOut={onLogout}
      />
    );
  } else if (user) {
    content = (
      <UiModeProvider userId={user.id} language={language}>
        <ConfirmProvider>
          <AppShell
            language={language}
            colorMode={mode}
            user={user}
            onUnauthorized={handleUnauthorized}
            onLogout={onLogout}
            onLanguageChange={toggleLanguage}
            onColorModeChange={toggleMode}
            onUserChange={onUserChange}
          />
        </ConfirmProvider>
      </UiModeProvider>
    );
  } else {
    content = (
      <Login
        language={language}
        expired={sessionExpired}
        onLogin={login}
        registrationEnabled={registrationEnabled}
        onRegister={() => setAuthView("register")}
        onLanguageChange={toggleLanguage}
      />
    );
  }

  return (
    <CacheProvider value={language === "fa" ? rtlCache : ltrCache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        {content}
      </ThemeProvider>
    </CacheProvider>
  );
}
