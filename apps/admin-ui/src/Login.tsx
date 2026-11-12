import { useEffect, useState, type FormEvent } from "react";
import { Alert, Box, Button, Checkbox, CircularProgress, Divider, FormControlLabel, Stack, TextField } from "@mui/material";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import PhonelinkLockRoundedIcon from "@mui/icons-material/PhonelinkLockRounded";
import { AuthHeading, AuthShell, PasswordField, failureMessages, type AuthFailure } from "./AuthShell";
import type { Language, MessageKey } from "./i18n";
import { translate } from "./i18n";
import { errorEntry } from "./copy/errors";
import { fill, pick, type Bi } from "./copy/text";

/** What the password step answered: signed in, a second step is needed, or a failure. */
export type LoginOutcome = true | { mfa: string | null } | AuthFailure;

export type SsoOption = { enabled: boolean; display_name?: string | null; start_url?: string | null };

type LoginProps = {
  language: Language;
  expired: boolean;
  onLogin: (username: string, password: string, remember: boolean) => Promise<LoginOutcome>;
  /** Second step; `challenge` null means the server keeps it in a cookie (after single sign-on). */
  onSecondStep: (challenge: string | null, value: { code?: string; recovery_code?: string }, remember: boolean) => Promise<true | AuthFailure>;
  onLanguageChange: () => void;
  registrationEnabled: boolean;
  onRegister: () => void;
  sso?: SsoOption | null;
  /** From the address after the single sign-on round trip: an error code, or "mfa". */
  ssoResult?: { error?: string | null; mfa?: boolean } | null;
};

const FIELDS = ["username", "password"] as const;

const COPY = {
  remember: { fa: "مرا به خاطر بسپار", en: "Keep me signed in" },
  rememberHint: { fa: "روی رایانه شخصی روشن بماند؛ روی رایانه مشترک خاموشش کنید.", en: "Leave on for your own computer; turn off on a shared one." },
  or: { fa: "یا", en: "or" },
  ssoButton: { fa: "ورود با {name}", en: "Sign in with {name}" },
  stepTitle: { fa: "ورود دومرحله‌ای", en: "Two-step sign-in" },
  stepHint: { fa: "کد ۶ رقمی برنامه احراز هویت گوشی‌تان را بنویسید.", en: "Type the 6-digit code from your authenticator app." },
  recoveryHint: { fa: "یکی از کدهای پشتیبانی را که هنگام راه‌اندازی ذخیره کردید بنویسید. هر کد فقط یک بار کار می‌کند.", en: "Type one of the backup codes you saved during setup. Each works once." },
  code: { fa: "کد ورود", en: "Sign-in code" },
  recovery: { fa: "کد پشتیبانی", en: "Backup code" },
  useRecovery: { fa: "به گوشی دسترسی ندارم؛ کد پشتیبانی دارم", en: "I can't use my phone; I have a backup code" },
  useApp: { fa: "استفاده از کد برنامه", en: "Use the app code" },
  verify: { fa: "تأیید و ورود", en: "Verify and sign in" },
  back: { fa: "بازگشت به ورود", en: "Back to sign-in" },
  fillIn: { fa: "این خانه را پر کنید.", en: "Please fill this in." },
  ssoFailed: { fa: "ورود یکپارچه انجام نشد.", en: "Single sign-on didn't work." }
} satisfies Record<string, Bi>;

const SSO_ERRORS: Record<string, Bi> = {
  sso_no_account: { fa: "حسابی با این ایمیل در پنل نیست. از مدیر پنل بخواهید شما را دعوت کند.", en: "No panel account has this email. Ask the panel admin to invite you." },
  sso_email_unverified: { fa: "ایمیل شما نزد سازمان تأیید نشده است.", en: "Your email isn't verified with your organization." },
  sso_email_missing: { fa: "سازمان ایمیل شما را نفرستاد.", en: "Your organization didn't send your email." },
  sso_domain_not_allowed: { fa: "ایمیل این دامنه اجازه ورود ندارد.", en: "Emails of this domain may not sign in." },
  sso_account_disabled: { fa: "این حساب غیرفعال است.", en: "This account is deactivated." },
  sso_account_conflict: { fa: "این حساب به حساب دیگری از همین سازمان وصل است.", en: "This account is linked to another identity of the same organization." },
  sso_state_invalid: { fa: "زمان ورود گذشت یا صفحه عوض شد. دوباره امتحان کنید.", en: "The sign-in timed out or the page changed. Try again." },
  sso_disabled: { fa: "ورود یکپارچه خاموش است.", en: "Single sign-on is off." },
  sso_unreachable: { fa: "پنل به سرور ورود سازمان وصل نشد.", en: "The panel couldn't reach your organization's sign-in server." },
  sso_idp_error: { fa: "سرور ورود سازمان ورود را نپذیرفت.", en: "Your organization's sign-in server refused the sign-in." }
};

export function Login({ language, expired, onLogin, onSecondStep, onLanguageChange, registrationEnabled, onRegister, sso, ssoResult }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [general, setGeneral] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  // Second step: undefined = not needed; string = challenge; null = kept by the server (SSO).
  const [challenge, setChallenge] = useState<string | null | undefined>(ssoResult?.mfa ? null : undefined);
  const [useRecovery, setUseRecovery] = useState(false);
  const [code, setCode] = useState("");
  const t = (key: MessageKey) => translate(language, key);
  const say = (bi: Bi) => pick(language, bi);

  useEffect(() => {
    if (ssoResult?.error) setGeneral(say(SSO_ERRORS[ssoResult.error] ?? COPY.ssoFailed));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ssoResult?.error]);

  const failureText = (result: AuthFailure) => {
    const entry = errorEntry(result.code);
    return entry ? pick(language, entry) : failureMessages(language, result, FIELDS).general;
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const missing: Record<string, string> = {};
    if (!username.trim()) missing.username = say(COPY.fillIn);
    if (!password) missing.password = say(COPY.fillIn);
    setFieldErrors(missing);
    setGeneral(null);
    if (Object.keys(missing).length) return;
    setSubmitting(true);
    try {
      const result = await onLogin(username.trim(), password, remember);
      if (result === true) return;
      if ("mfa" in result) {
        setChallenge(result.mfa);
        setCode("");
        setUseRecovery(false);
        return;
      }
      if (result.code === "invalid_credentials" || result.status === 401) {
        setGeneral(t("invalidCredentials"));
      } else if (result.code === "sso_required" || result.code === "rate_limited") {
        setGeneral(failureText(result));
      } else {
        const messages = failureMessages(language, result, FIELDS);
        setFieldErrors(messages.fields);
        setGeneral(messages.general);
      }
    } catch {
      setGeneral(t("connectionError"));
    } finally {
      setSubmitting(false);
    }
  };

  const submitCode = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setGeneral(null);
    const value = code.trim();
    if (!value) {
      setFieldErrors({ code: say(COPY.fillIn) });
      return;
    }
    setFieldErrors({});
    setSubmitting(true);
    try {
      const result = await onSecondStep(challenge ?? null, useRecovery ? { recovery_code: value } : { code: value }, remember);
      if (result === true) return;
      if (result.code === "mfa_challenge_invalid") {
        setChallenge(undefined);
        setPassword("");
      }
      setGeneral(failureText(result));
    } catch {
      setGeneral(t("connectionError"));
    } finally {
      setSubmitting(false);
    }
  };

  const busyLabel = (label: string) =>
    submitting ? (
      <Stack direction="row" spacing={1} alignItems="center">
        <CircularProgress size={18} color="inherit" />
        <span>{t("loggingIn")}</span>
      </Stack>
    ) : (
      label
    );

  const alert = general ? (
    <Alert severity="error" sx={{ mt: 2.5 }} role="alert">{general}</Alert>
  ) : expired && challenge === undefined ? (
    <Alert severity="info" sx={{ mt: 2.5 }}>{t("sessionExpired")}</Alert>
  ) : null;

  if (challenge !== undefined) {
    return (
      <AuthShell language={language} onLanguageChange={onLanguageChange}>
        <AuthHeading icon={<PhonelinkLockRoundedIcon fontSize="small" />} title={say(COPY.stepTitle)} hint={say(useRecovery ? COPY.recoveryHint : COPY.stepHint)} />
        {alert}
        <Box component="form" noValidate onSubmit={(event) => void submitCode(event)} sx={{ mt: 3.5 }}>
          <Stack spacing={2}>
            <TextField
              key={useRecovery ? "recovery" : "code"}
              label={say(useRecovery ? COPY.recovery : COPY.code)}
              value={code}
              onChange={(event) => setCode(useRecovery ? event.target.value : event.target.value.replace(/[^0-9۰-۹]/g, "").replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit))).slice(0, 6))}
              autoComplete="one-time-code"
              slotProps={{ htmlInput: useRecovery ? { dir: "ltr", spellCheck: false } : { dir: "ltr", inputMode: "numeric", pattern: "[0-9]*", maxLength: 6 } }}
              error={Boolean(fieldErrors.code)}
              helperText={fieldErrors.code}
              autoFocus
              required
            />
            <Button type="submit" variant="contained" size="large" disabled={submitting} sx={{ minHeight: 48 }}>
              {busyLabel(say(COPY.verify))}
            </Button>
            <Button type="button" variant="text" onClick={() => { setUseRecovery((value) => !value); setCode(""); setFieldErrors({}); }} sx={{ minHeight: 44 }}>
              {say(useRecovery ? COPY.useApp : COPY.useRecovery)}
            </Button>
            <Button type="button" variant="text" color="inherit" onClick={() => { setChallenge(undefined); setGeneral(null); }} sx={{ minHeight: 44 }}>
              {say(COPY.back)}
            </Button>
          </Stack>
        </Box>
      </AuthShell>
    );
  }

  const ssoName = sso?.display_name || "SSO";
  return (
    <AuthShell language={language} onLanguageChange={onLanguageChange}>
      <AuthHeading icon={<LockRoundedIcon fontSize="small" />} title={t("signIn")} hint={t("signInHint")} />
      {alert}

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
          <FormControlLabel
            control={<Checkbox checked={remember} onChange={(event) => setRemember(event.target.checked)} />}
            label={say(COPY.remember)}
            title={say(COPY.rememberHint)}
            sx={{ m: 0 }}
          />
          <Button type="submit" variant="contained" size="large" disabled={submitting} sx={{ minHeight: 48 }}>
            {busyLabel(t("login"))}
          </Button>
          {sso?.enabled && sso.start_url && (
            <>
              <Divider>{say(COPY.or)}</Divider>
              <Button
                type="button"
                variant="outlined"
                size="large"
                sx={{ minHeight: 48 }}
                onClick={() => {
                  window.location.href = `${sso.start_url}?remember=${remember ? "1" : "0"}`;
                }}
              >
                {fill(say(COPY.ssoButton), { name: ssoName }, language)}
              </Button>
            </>
          )}
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
