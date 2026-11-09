import { useState, type FormEvent } from "react";
import { Alert, Box, Button, CircularProgress, Stack, TextField } from "@mui/material";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import { AuthHeading, AuthShell, PasswordField, failureMessages, type AuthFailure } from "./AuthShell";
import type { Language, MessageKey } from "./i18n";
import { translate } from "./i18n";

type LoginProps = {
  language: Language;
  expired: boolean;
  /** Resolves `true` on success, or the failure (status, code, field problems). */
  onLogin: (username: string, password: string) => Promise<true | AuthFailure>;
  onLanguageChange: () => void;
  registrationEnabled: boolean;
  onRegister: () => void;
};

const FIELDS = ["username", "password"] as const;

export function Login({ language, expired, onLogin, onLanguageChange, registrationEnabled, onRegister }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [general, setGeneral] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const t = (key: MessageKey) => translate(language, key);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const missing: Record<string, string> = {};
    const fillIn = language === "fa" ? "این خانه را پر کنید." : "Please fill this in.";
    if (!username.trim()) missing.username = fillIn;
    if (!password) missing.password = fillIn;
    setFieldErrors(missing);
    setGeneral(null);
    if (Object.keys(missing).length) return;
    setSubmitting(true);
    try {
      const result = await onLogin(username.trim(), password);
      if (result !== true) {
        if (result.code === "invalid_credentials" || result.status === 401) {
          setGeneral(t("invalidCredentials"));
        } else {
          const messages = failureMessages(language, result, FIELDS);
          setFieldErrors(messages.fields);
          setGeneral(messages.general);
        }
      }
    } catch {
      setGeneral(t("connectionError"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell language={language} onLanguageChange={onLanguageChange}>
      <AuthHeading icon={<LockRoundedIcon fontSize="small" />} title={t("signIn")} hint={t("signInHint")} />

      {general ? (
        <Alert severity="error" sx={{ mt: 2.5 }} role="alert">
          {general}
        </Alert>
      ) : expired ? (
        <Alert severity="info" sx={{ mt: 2.5 }}>
          {t("sessionExpired")}
        </Alert>
      ) : null}

      <Box component="form" noValidate onSubmit={(event) => void submit(event)} sx={{ mt: 3.5 }}>
        <Stack spacing={2}>
          <TextField
            label={language === "fa" ? "ایمیل یا نام کاربری" : "Email or username"}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            slotProps={{ htmlInput: { dir: "ltr" } }}
            error={Boolean(fieldErrors.username)}
            helperText={fieldErrors.username}
            required
            autoFocus
          />
          <PasswordField
            language={language}
            label={t("password")}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            error={Boolean(fieldErrors.password)}
            helperText={fieldErrors.password}
            required
          />
          <Button type="submit" variant="contained" size="large" disabled={submitting} sx={{ minHeight: 48 }}>
            {submitting ? (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={18} color="inherit" />
                <span>{t("loggingIn")}</span>
              </Stack>
            ) : (
              t("login")
            )}
          </Button>
          {registrationEnabled && (
            <Button type="button" variant="outlined" size="large" onClick={onRegister} sx={{ minHeight: 48 }}>
              {t("register")}
            </Button>
          )}
        </Stack>
      </Box>
    </AuthShell>
  );
}
