import { useMemo, useState, type FormEvent } from "react";
import { Alert, Box, Button, CircularProgress, LinearProgress, Stack, TextField, Typography } from "@mui/material";
import PersonAddAltRoundedIcon from "@mui/icons-material/PersonAddAltRounded";
import {
  AuthHeading, AuthShell, DEFAULT_PASSWORD_POLICY, PasswordField, failureMessages, passwordProblem, passwordRuleText,
  type AuthFailure, type PasswordPolicy
} from "./AuthShell";
import type { Language, MessageKey } from "./i18n";
import { translate } from "./i18n";
import type { Bi } from "./copy/text";

export type SetupValues = {
  displayName: string;
  email: string;
  password: string;
  passwordConfirmation: string;
};

type SetupProps = {
  language: Language;
  /** Resolves `true` on success, or the failure (status, code, field problems). */
  onSetup: (values: SetupValues) => Promise<true | AuthFailure>;
  onLanguageChange: () => void;
  variant?: "owner" | "public";
  onBack?: () => void;
  /** The server's password rule (from setup-status); the default rule is used until it arrives. */
  passwordPolicy?: PasswordPolicy;
};

/** Backend field names → form fields. */
const FIELD_MAP: Record<string, keyof SetupValues> = {
  display_name: "displayName",
  email: "email",
  password: "password",
  password_confirmation: "passwordConfirmation"
};

const GENERAL_ERRORS: Record<string, Bi> = {
  already_initialized: { fa: "حساب مالک قبلاً ساخته شده است. صفحه را تازه کنید و وارد شوید.", en: "The owner account already exists. Reload the page and sign in." },
  account_exists: { fa: "حسابی با این ایمیل از قبل هست. اگر مال شماست، وارد شوید.", en: "An account with this email already exists. If it's yours, sign in." },
  registration_disabled: { fa: "ثبت‌نام همین حالا بسته شد. از مدیر پنل بخواهید شما را دعوت کند.", en: "Sign-up was just closed. Ask the panel's admin to invite you." }
};

export function Setup({ language, onSetup, onLanguageChange, variant = "owner", onBack, passwordPolicy = DEFAULT_PASSWORD_POLICY }: SetupProps) {
  const [values, setValues] = useState<SetupValues>({ displayName: "", email: "", password: "", passwordConfirmation: "" });
  const [submitting, setSubmitting] = useState(false);
  const [general, setGeneral] = useState<string | null>(null);
  const [errors, setErrors] = useState<Partial<Record<keyof SetupValues, string>>>({});
  const t = (key: MessageKey) => translate(language, key);
  const rule = passwordRuleText(language, passwordPolicy);
  const strength = useMemo(() => {
    const target = Math.max(passwordPolicy.min_length, 12);
    let score = Math.min(1, values.password.length / target) * 70;
    if (/\p{L}/u.test(values.password)) score += 15;
    if (/\p{Nd}/u.test(values.password)) score += 15;
    return Math.min(100, score);
  }, [passwordPolicy.min_length, values.password]);
  const set = (key: keyof SetupValues, value: string) => {
    setValues((current) => ({ ...current, [key]: value }));
    if (errors[key]) setErrors((current) => ({ ...current, [key]: undefined }));
  };

  const validate = (): Partial<Record<keyof SetupValues, string>> => {
    const result: Partial<Record<keyof SetupValues, string>> = {};
    const fillIn = language === "fa" ? "این خانه را پر کنید." : "Please fill this in.";
    const name = values.displayName.trim();
    if (!name) result.displayName = fillIn;
    else if (name.length < 2) result.displayName = language === "fa" ? "نام باید دست‌کم ۲ نویسه باشد." : "The name needs at least 2 characters.";
    if (!values.email.trim()) result.email = fillIn;
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email.trim()))
      result.email = language === "fa" ? "ایمیل باید مثل name@example.com باشد." : "The email should look like name@example.com.";
    const problem = passwordProblem(language, passwordPolicy, values.password);
    if (!values.password) result.password = fillIn;
    else if (problem) result.password = problem;
    if (!result.password && values.password !== values.passwordConfirmation) result.passwordConfirmation = t("passwordMismatch");
    return result;
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const local = validate();
    setErrors(local);
    setGeneral(null);
    if (Object.keys(local).length) return;
    setSubmitting(true);
    try {
      const result = await onSetup({ ...values, displayName: values.displayName.trim(), email: values.email.trim() });
      if (result !== true) {
        const messages = failureMessages(language, result, Object.keys(FIELD_MAP), GENERAL_ERRORS);
        const mapped: Partial<Record<keyof SetupValues, string>> = {};
        for (const [field, text] of Object.entries(messages.fields)) mapped[FIELD_MAP[field]] = text;
        setErrors(mapped);
        setGeneral(messages.general ?? (Object.keys(mapped).length ? null : t("setupFailed")));
      }
    } catch {
      setGeneral(t("connectionError"));
    } finally {
      setSubmitting(false);
    }
  };

  const owner = variant === "owner";

  return (
    <AuthShell language={language} onLanguageChange={onLanguageChange}>
      <AuthHeading
        icon={<PersonAddAltRoundedIcon fontSize="small" />}
        title={t(owner ? "firstRunTitle" : "publicRegisterTitle")}
        hint={t(owner ? "firstRunHint" : "publicRegisterHint")}
      />

      {general && (
        <Alert severity="error" sx={{ mt: 2.5 }} role="alert">
          {general}
        </Alert>
      )}

      <Box component="form" noValidate onSubmit={(event) => void submit(event)} sx={{ mt: 3 }}>
        <Stack spacing={2}>
          <TextField
            label={t("displayName")}
            value={values.displayName}
            onChange={(event) => set("displayName", event.target.value)}
            autoComplete="name"
            slotProps={{ htmlInput: { maxLength: 100 } }}
            error={Boolean(errors.displayName)}
            helperText={errors.displayName}
            required
            autoFocus
          />
          <TextField
            label={t("email")}
            type="email"
            value={values.email}
            onChange={(event) => set("email", event.target.value)}
            autoComplete="email"
            slotProps={{ htmlInput: { dir: "ltr" } }}
            error={Boolean(errors.email)}
            helperText={errors.email ?? (owner ? (language === "fa" ? "با همین ایمیل وارد پنل می‌شوید." : "You'll sign in with this email.") : undefined)}
            required
          />
          <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
            <PasswordField
              language={language}
              label={t("password")}
              value={values.password}
              onChange={(event) => set("password", event.target.value)}
              autoComplete="new-password"
              error={Boolean(errors.password)}
              helperText={errors.password}
              required
              fullWidth
            />
            <PasswordField
              language={language}
              label={t("passwordConfirm")}
              value={values.passwordConfirmation}
              onChange={(event) => set("passwordConfirmation", event.target.value)}
              autoComplete="new-password"
              error={Boolean(errors.passwordConfirmation)}
              helperText={errors.passwordConfirmation}
              required
              fullWidth
            />
          </Stack>
          <Box>
            <LinearProgress
              variant="determinate"
              value={strength}
              color={strength >= 85 ? "success" : "warning"}
              aria-hidden
              sx={{ height: 4, borderRadius: 2 }}
            />
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.8, display: "block" }}>
              {rule}
            </Typography>
          </Box>
          <Button type="submit" variant="contained" size="large" disabled={submitting} sx={{ minHeight: 48 }}>
            {submitting ? (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={18} color="inherit" />
                <span>{t("creatingOwner")}</span>
              </Stack>
            ) : (
              t(owner ? "createOwner" : "createAccount")
            )}
          </Button>
          {!owner && onBack && (
            <Button variant="text" onClick={onBack} sx={{ minHeight: 44 }}>
              {t("backToLogin")}
            </Button>
          )}
        </Stack>
      </Box>
    </AuthShell>
  );
}
