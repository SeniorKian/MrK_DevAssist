/**
 * Change my password (docs/34 §2: POST /api/v1/auth/change-password {current_password, new_password}).
 *
 * - `ChangePasswordDialog`: from the user menu and the Settings page.
 * - `ChangePasswordPage` (default): full page shown when the account must change its password
 *   (an invited person who signed in with a one-time password). Nothing else works until it is done.
 */
import { useEffect, useState, type FormEvent } from "react";
import {
  Alert, Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Typography, useMediaQuery, useTheme
} from "@mui/material";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import { apiMutate } from "./api";
import {
  AuthHeading, AuthShell, DEFAULT_PASSWORD_POLICY, PasswordField, failureMessages, passwordProblem, passwordRuleText, readAuthFailure,
  readPasswordPolicy, type PasswordPolicy
} from "./AuthShell";
import type { AuthUser } from "./App";
import type { Language } from "./i18n";
import { translate } from "./i18n";
import { pick, type Bi } from "./copy/text";

const COPY = {
  title: { fa: "تغییر رمز", en: "Change your password" },
  forcedTitle: { fa: "یک رمز تازه برای خودتان بگذارید", en: "Choose your own password" },
  forcedHint: {
    fa: "با رمز یک‌بار مصرف وارد شده‌اید. پیش از ادامه، رمزی بگذارید که فقط خودتان بدانید.",
    en: "You signed in with a one-time password. Before you continue, choose a password only you know."
  },
  dialogHint: { fa: "پس از تغییر، از دستگاه‌های دیگر خارج می‌شوید.", en: "After the change, your other devices are signed out." },
  current: { fa: "رمز فعلی", en: "Current password" },
  currentForced: { fa: "رمز یک‌بار مصرف", en: "One-time password" },
  next: { fa: "رمز تازه", en: "New password" },
  repeat: { fa: "تکرار رمز تازه", en: "Repeat the new password" },
  save: { fa: "ذخیره رمز تازه", en: "Save the new password" },
  saving: { fa: "در حال ذخیره…", en: "Saving…" },
  done: { fa: "رمز شما عوض شد.", en: "Your password was changed." },
  signOut: { fa: "خروج", en: "Sign out" },
  cancel: { fa: "انصراف", en: "Cancel" },
  fillIn: { fa: "این خانه را پر کنید.", en: "Please fill this in." },
  same: { fa: "رمز تازه باید با رمز فعلی فرق داشته باشد.", en: "The new password must be different from the current one." }
} satisfies Record<string, Bi>;

const FIELD_MAP: Record<string, "current" | "next" | "repeat"> = {
  current_password: "current",
  new_password: "next",
  password: "next",
  password_confirmation: "repeat"
};

/** The server's password rule, read once from setup-status. */
export function usePasswordPolicy(): PasswordPolicy {
  const [policy, setPolicy] = useState<PasswordPolicy>(DEFAULT_PASSWORD_POLICY);
  useEffect(() => {
    let alive = true;
    fetch("/api/v1/auth/setup-status", { headers: { Accept: "application/json" }, cache: "no-store" })
      .then((response) => (response.ok ? response.json() : null))
      .then((payload) => {
        if (alive && payload) setPolicy(readPasswordPolicy(payload));
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);
  return policy;
}

type FormProps = {
  language: Language;
  forced?: boolean;
  onDone: (user: AuthUser | null) => void;
  onCancel?: () => void;
  /** Render the buttons in a DialogActions bar. */
  inDialog?: boolean;
};

function ChangePasswordForm({ language, forced, onDone, onCancel, inDialog }: FormProps) {
  const policy = usePasswordPolicy();
  const [values, setValues] = useState({ current: "", next: "", repeat: "" });
  const [errors, setErrors] = useState<Partial<Record<keyof typeof values, string>>>({});
  const [general, setGeneral] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const say = (bi: Bi) => pick(language, bi);

  const set = (key: keyof typeof values, value: string) => {
    setValues((current) => ({ ...current, [key]: value }));
    if (errors[key]) setErrors((current) => ({ ...current, [key]: undefined }));
  };

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    const local: Partial<Record<keyof typeof values, string>> = {};
    if (!values.current) local.current = say(COPY.fillIn);
    const problem = values.next ? passwordProblem(language, policy, values.next) : say(COPY.fillIn);
    if (problem) local.next = problem;
    else if (values.next === values.current) local.next = say(COPY.same);
    else if (values.next !== values.repeat) local.repeat = translate(language, "passwordMismatch");
    setErrors(local);
    setGeneral(null);
    if (Object.keys(local).length) return;
    setBusy(true);
    try {
      const response = await apiMutate("/api/v1/auth/change-password", {
        body: { current_password: values.current, new_password: values.next },
        silentUnauthorized: forced
      });
      if (response.ok) {
        const payload = (await response.json().catch(() => null)) as { user?: AuthUser } | null;
        onDone(payload?.user ?? null);
        return;
      }
      const failure = await readAuthFailure(response);
      const messages = failureMessages(language, failure, Object.keys(FIELD_MAP));
      const mapped: Partial<Record<keyof typeof values, string>> = {};
      for (const [field, text] of Object.entries(messages.fields)) mapped[FIELD_MAP[field]] = text;
      if (failure.code === "invalid_current_password" && !mapped.current) {
        mapped.current = forced
          ? language === "fa" ? "رمز یک‌بار مصرف درست نیست." : "The one-time password is wrong."
          : language === "fa" ? "رمز فعلی درست نیست." : "Your current password is wrong.";
      }
      setErrors(mapped);
      setGeneral(Object.keys(mapped).length ? null : messages.general);
    } catch {
      setGeneral(translate(language, "connectionError"));
    } finally {
      setBusy(false);
    }
  };

  const fields = (
    <Stack spacing={2} sx={{ mt: inDialog ? 1 : 3 }}>
      {general && <Alert severity="error" role="alert">{general}</Alert>}
      <PasswordField
        language={language}
        label={say(forced ? COPY.currentForced : COPY.current)}
        value={values.current}
        onChange={(event) => set("current", event.target.value)}
        autoComplete="current-password"
        error={Boolean(errors.current)}
        helperText={errors.current}
        autoFocus
        fullWidth
      />
      <PasswordField
        language={language}
        label={say(COPY.next)}
        value={values.next}
        onChange={(event) => set("next", event.target.value)}
        autoComplete="new-password"
        error={Boolean(errors.next)}
        helperText={errors.next ?? passwordRuleText(language, policy)}
        fullWidth
      />
      <PasswordField
        language={language}
        label={say(COPY.repeat)}
        value={values.repeat}
        onChange={(event) => set("repeat", event.target.value)}
        autoComplete="new-password"
        error={Boolean(errors.repeat)}
        helperText={errors.repeat}
        fullWidth
      />
    </Stack>
  );

  const submitButton = (
    <Button type="submit" variant="contained" size="large" disabled={busy} sx={{ minHeight: 48 }}>
      {busy ? (
        <Stack direction="row" spacing={1} alignItems="center">
          <CircularProgress size={18} color="inherit" />
          <span>{say(COPY.saving)}</span>
        </Stack>
      ) : (
        say(COPY.save)
      )}
    </Button>
  );

  if (inDialog) {
    return (
      <Box component="form" noValidate onSubmit={(event) => void submit(event)}>
        <DialogContent>
          <Typography variant="body2" color="text.secondary">{say(COPY.dialogHint)}</Typography>
          {fields}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2.5, gap: 1 }}>
          <Button onClick={onCancel} sx={{ minHeight: 44 }}>{say(COPY.cancel)}</Button>
          {submitButton}
        </DialogActions>
      </Box>
    );
  }
  return (
    <Box component="form" noValidate onSubmit={(event) => void submit(event)}>
      {fields}
      <Stack spacing={1.5} sx={{ mt: 2.5 }}>
        {submitButton}
        {onCancel && (
          <Button variant="text" onClick={onCancel} sx={{ minHeight: 44 }}>
            {say(COPY.signOut)}
          </Button>
        )}
      </Stack>
    </Box>
  );
}

/** Dialog version (user menu, Settings). Calls `onChanged` after a successful change. */
export function ChangePasswordDialog({ open, language, onClose, onChanged }: { open: boolean; language: Language; onClose: () => void; onChanged?: (user: AuthUser | null) => void }) {
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="xs" fullScreen={fullScreen} aria-labelledby="mrk-change-password-title">
      <DialogTitle id="mrk-change-password-title" sx={{ fontWeight: 760 }}>{pick(language, COPY.title)}</DialogTitle>
      {open && (
        <ChangePasswordForm
          language={language}
          inDialog
          onCancel={onClose}
          onDone={(user) => {
            onChanged?.(user);
            onClose();
          }}
        />
      )}
    </Dialog>
  );
}

/** Success line for toasts after a password change. */
export function passwordChangedText(language: Language) {
  return pick(language, COPY.done);
}

/** Forced full-page flow while `must_change_password` is set. */
export default function ChangePasswordPage({
  language,
  onLanguageChange,
  onChanged,
  onSignOut
}: {
  language: Language;
  onLanguageChange: () => void;
  onChanged: (user: AuthUser | null) => void;
  onSignOut: () => void;
}) {
  return (
    <AuthShell language={language} onLanguageChange={onLanguageChange}>
      <AuthHeading icon={<KeyRoundedIcon fontSize="small" />} title={pick(language, COPY.forcedTitle)} hint={pick(language, COPY.forcedHint)} />
      <ChangePasswordForm language={language} forced onDone={onChanged} onCancel={onSignOut} />
    </AuthShell>
  );
}
