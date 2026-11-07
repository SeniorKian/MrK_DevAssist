import { useCallback, useEffect, useMemo, useState } from "react";
import { Box, CircularProgress, CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { Dashboard } from "./Dashboard";
import { Login } from "./Login";
import { Setup, type SetupValues } from "./Setup";
import type { Language } from "./i18n";

type ColorMode = "dark" | "light";
export type AuthUser = {
  id: number;
  username: string;
  role: string;
  permissions: string[];
  display_name?: string | null;
  email?: string | null;
};

function storedValue<T extends string>(key: string, fallback: T): T {
  const value = window.localStorage.getItem(key);
  return (value as T | null) ?? fallback;
}

export function App() {
  const [language, setLanguage] = useState<Language>(() => storedValue("mrk-language", "fa"));
  const [mode, setMode] = useState<ColorMode>(() => storedValue("mrk-theme", "dark"));
  const [user, setUser] = useState<AuthUser | null>(null);
  const [setupRequired, setSetupRequired] = useState(false);
  const [registrationEnabled, setRegistrationEnabled] = useState(false);
  const [authView, setAuthView] = useState<"login" | "register">("login");
  const [csrf, setCsrf] = useState("");
  const [authLoading, setAuthLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);

  useEffect(() => {
    window.localStorage.setItem("mrk-language", language);
    document.documentElement.lang = language;
    document.documentElement.dir = language === "fa" ? "rtl" : "ltr";
  }, [language]);

  useEffect(() => window.localStorage.setItem("mrk-theme", mode), [mode]);

  const loadSession = useCallback(async () => {
    try {
      const setupResponse = await fetch("/api/v1/auth/setup-status", {
        headers: { Accept: "application/json" },
        cache: "no-store"
      });
      if (setupResponse.ok) {
        const setup = (await setupResponse.json()) as { required: boolean };
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
    } finally {
      setAuthLoading(false);
    }
  }, []);

  useEffect(() => void loadSession(), [loadSession]);

  const login = async (username: string, password: string) => {
    const response = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    if (!response.ok) return false;
    const payload = (await response.json()) as { user: AuthUser; csrf_token: string };
    setUser(payload.user);
    setCsrf(payload.csrf_token);
    setSessionExpired(false);
    return true;
  };

  const setup = async (values: SetupValues) => {
    const response = await fetch("/api/v1/auth/setup", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        display_name: values.displayName,
        email: values.email,
        password: values.password,
        password_confirmation: values.passwordConfirmation
      })
    });
    if (!response.ok) return false;
    const payload = (await response.json()) as { user: AuthUser; csrf_token: string };
    setUser(payload.user);
    setCsrf(payload.csrf_token);
    setSetupRequired(false);
    setSessionExpired(false);
    return true;
  };

  const register = async (values: SetupValues) => {
    const response = await fetch("/api/v1/auth/register", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        display_name: values.displayName,
        email: values.email,
        password: values.password,
        password_confirmation: values.passwordConfirmation
      })
    });
    if (!response.ok) return false;
    const payload = (await response.json()) as { user: AuthUser; csrf_token: string };
    setUser(payload.user);
    setCsrf(payload.csrf_token);
    setAuthView("login");
    setSessionExpired(false);
    return true;
  };

  const logout = async () => {
    await fetch("/api/v1/auth/logout", {
      method: "POST",
      headers: { Accept: "application/json", "X-CSRF-Token": csrf }
    });
    setUser(null);
    setCsrf("");
    setAuthView("login");
  };

  const handleUnauthorized = () => {
    setSessionExpired(true);
    setUser(null);
    setCsrf("");
  };

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

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {authLoading ? (
        <Box sx={{ minHeight: "100vh", display: "grid", placeItems: "center" }}>
          <CircularProgress size={30} />
        </Box>
      ) : setupRequired ? (
        <Setup
          language={language}
          onSetup={setup}
          onLanguageChange={() => setLanguage((value) => (value === "fa" ? "en" : "fa"))}
        />
      ) : authView === "register" && registrationEnabled ? (
        <Setup
          language={language}
          variant="public"
          onSetup={register}
          onBack={() => setAuthView("login")}
          onLanguageChange={() => setLanguage((value) => (value === "fa" ? "en" : "fa"))}
        />
      ) : user ? (
        <Dashboard
          language={language}
          mode={mode}
          user={user}
          csrf={csrf}
          onUnauthorized={handleUnauthorized}
          onLogout={() => void logout()}
          onLanguageChange={() => setLanguage((value) => (value === "fa" ? "en" : "fa"))}
          onModeChange={() => setMode((value) => (value === "dark" ? "light" : "dark"))}
        />
      ) : (
        <Login
          language={language}
          expired={sessionExpired}
          onLogin={login}
          registrationEnabled={registrationEnabled}
          onRegister={() => setAuthView("register")}
          onLanguageChange={() => setLanguage((value) => (value === "fa" ? "en" : "fa"))}
        />
      )}
    </ThemeProvider>
  );
}
