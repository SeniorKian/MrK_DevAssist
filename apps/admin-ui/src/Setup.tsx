import { useMemo, useState, type FormEvent } from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  LinearProgress,
  Stack,
  TextField,
  Typography
} from "@mui/material";
import PersonAddAltRoundedIcon from "@mui/icons-material/PersonAddAltRounded";
import { AuthShell } from "./AuthShell";
import type { Language, MessageKey } from "./i18n";
import { translate } from "./i18n";

export type SetupValues = {
  displayName: string;
  email: string;
  password: string;
  passwordConfirmation: string;
};

type SetupProps = {
  language: Language;
  onSetup: (values: SetupValues) => Promise<boolean>;
  onLanguageChange: () => void;
  variant?: "owner" | "public";
  onBack?: () => void;
};

export function Setup({ language, onSetup, onLanguageChange, variant = "owner", onBack }: SetupProps) {
  const [values, setValues] = useState<SetupValues>({
    displayName: "",
    email: "",
    password: "",
    passwordConfirmation: ""
  });
  const [submitting, setSubmitting] = useState(false);
  const [failed, setFailed] = useState(false);
  const [mismatch, setMismatch] = useState(false);
  const t = (key: MessageKey) => translate(language, key);
  const strength = useMemo(() => Math.min(100, (values.password.length / 20) * 100), [values.password]);
  const set = (key: keyof SetupValues, value: string) =>
    setValues((current) => ({ ...current, [key]: value }));

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const passwordsDiffer = values.password !== values.passwordConfirmation;
    setMismatch(passwordsDiffer);
    setFailed(false);
    if (passwordsDiffer) return;
    setSubmitting(true);
    try {
      setFailed(!(await onSetup(values)));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell language={language} onLanguageChange={onLanguageChange}>
      <Box
        aria-hidden
        sx={{ width: 44, height: 44, display: "grid", placeItems: "center", borderRadius: 1.25, bgcolor: "primary.main", color: "primary.contrastText" }}
      >
        <PersonAddAltRoundedIcon fontSize="small" />
      </Box>
      <Typography variant="h4" component="h1" sx={{ mt: 2.5 }}>
        {t(variant === "owner" ? "firstRunTitle" : "publicRegisterTitle")}
      </Typography>
      <Typography color="text.secondary" sx={{ mt: 1, lineHeight: 1.8 }}>
        {t(variant === "owner" ? "firstRunHint" : "publicRegisterHint")}
      </Typography>

      {(failed || mismatch) && (
        <Alert severity="error" sx={{ mt: 2.5 }}>
          {t(mismatch ? "passwordMismatch" : "setupFailed")}
        </Alert>
      )}

      <Box component="form" onSubmit={(event) => void submit(event)} sx={{ mt: 3 }}>
        <Stack spacing={2}>
          <TextField
            label={t("displayName")}
            value={values.displayName}
            onChange={(event) => set("displayName", event.target.value)}
            autoComplete="name"
            required
            autoFocus
          />
          <TextField
            label={t("email")}
            type="email"
            value={values.email}
            onChange={(event) => set("email", event.target.value)}
            autoComplete="email"
            inputProps={{ dir: "ltr" }}
            required
          />
          <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
            <TextField
              label={t("password")}
              type="password"
              value={values.password}
              onChange={(event) => set("password", event.target.value)}
              autoComplete="new-password"
              inputProps={{ minLength: 14 }}
              required
              fullWidth
            />
            <TextField
              label={t("passwordConfirm")}
              type="password"
              value={values.passwordConfirmation}
              onChange={(event) => set("passwordConfirmation", event.target.value)}
              autoComplete="new-password"
              inputProps={{ minLength: 14 }}
              required
              fullWidth
            />
          </Stack>
          <Box>
            <LinearProgress variant="determinate" value={strength} color={strength >= 70 ? "success" : "warning"} sx={{ height: 4 }} />
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.8, display: "block" }}>
              {t("passwordRule")}
            </Typography>
          </Box>
          <Button type="submit" variant="contained" size="large" disabled={submitting} sx={{ minHeight: 46 }}>
            {submitting ? (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={18} color="inherit" />
                <span>{t("creatingOwner")}</span>
              </Stack>
            ) : (
              t(variant === "owner" ? "createOwner" : "createAccount")
            )}
          </Button>
          {variant === "public" && onBack && (
            <Button variant="text" onClick={onBack}>{t("backToLogin")}</Button>
          )}
        </Stack>
      </Box>
    </AuthShell>
  );
}
