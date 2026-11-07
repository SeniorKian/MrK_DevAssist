import { useState, type FormEvent } from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Stack,
  TextField,
  Typography
} from "@mui/material";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import { AuthShell } from "./AuthShell";
import type { Language, MessageKey } from "./i18n";
import { translate } from "./i18n";

type LoginProps = {
  language: Language;
  expired: boolean;
  onLogin: (username: string, password: string) => Promise<boolean>;
  onLanguageChange: () => void;
  registrationEnabled: boolean;
  onRegister: () => void;
};

export function Login({ language, expired, onLogin, onLanguageChange, registrationEnabled, onRegister }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [failed, setFailed] = useState(false);
  const t = (key: MessageKey) => translate(language, key);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setFailed(false);
    try {
      setFailed(!(await onLogin(username, password)));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell language={language} onLanguageChange={onLanguageChange}>
      <Box
        aria-hidden
        sx={{
          width: 44,
          height: 44,
          borderRadius: 1.25,
          display: "grid",
          placeItems: "center",
          color: "primary.contrastText",
          bgcolor: "primary.main"
        }}
      >
        <LockRoundedIcon fontSize="small" />
      </Box>
      <Typography variant="h4" component="h1" sx={{ mt: 2.5 }}>
        {t("signIn")}
      </Typography>
      <Typography color="text.secondary" sx={{ mt: 1, lineHeight: 1.8 }}>
        {t("signInHint")}
      </Typography>

      {(failed || expired) && (
        <Alert severity="error" sx={{ mt: 2.5 }}>
          {t(expired ? "sessionExpired" : "invalidCredentials")}
        </Alert>
      )}

      <Box component="form" onSubmit={(event) => void submit(event)} sx={{ mt: 3 }}>
        <Stack spacing={2}>
          <TextField
            label={`${t("email")} / ${t("username")}`}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            inputProps={{ dir: "ltr" }}
            required
            autoFocus
          />
          <TextField
            label={t("password")}
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
          />
          <Button type="submit" variant="contained" size="large" disabled={submitting} sx={{ minHeight: 46 }}>
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
            <Button type="button" variant="outlined" size="large" onClick={onRegister}>
              {t("register")}
            </Button>
          )}
        </Stack>
      </Box>
    </AuthShell>
  );
}
