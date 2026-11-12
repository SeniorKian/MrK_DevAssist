/**
 * Public invite link `#/invite/<token>` (docs/34 §2):
 * GET /api/v1/auth/invite/{token} → who is invited + password rule;
 * POST /api/v1/auth/invite/{token}/accept {password} → signs the person in.
 */
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Alert, Box, Button, CircularProgress, Stack, Typography } from "@mui/material";
import HandshakeRoundedIcon from "@mui/icons-material/HandshakeRounded";
import {
  AuthHeading, AuthShell, PasswordField, failureMessages, passwordProblem, passwordRuleText, readAuthFailure, readPasswordPolicy,
  type AuthFailure, type PasswordPolicy
} from "./AuthShell";
import type { AuthUser } from "./App";
import type { Language } from "./i18n";
import { translate } from "./i18n";
import { formatRelative } from "./kit/formatters";
import { errorEntry } from "./copy/errors";
import { fill, pick, type Bi } from "./copy/text";

const COPY = {
  loading: { fa: "در حال باز کردن دعوت…", en: "Opening your invite…" },
  title: { fa: "به DevAssist خوش آمدید", en: "Welcome to DevAssist" },
  titleNamed: { fa: "{name}، به DevAssist خوش آمدید", en: "Welcome to DevAssist, {name}" },
  hint: { fa: "شما را به این پنل دعوت کرده‌اند. فقط یک رمز برای خودتان بگذارید و وارد شوید.", en: "You've been invited to this panel. Just choose a password and you're in." },
  signInAs: { fa: "با این حساب وارد می‌شوید:", en: "You'll sign in as:" },
  expires: { fa: "این دعوت {when} تمام می‌شود.", en: "This invite expires {when}." },
  password: { fa: "رمز تازه", en: "New password" },
  repeat: { fa: "تکرار رمز", en: "Repeat the password" },
  accept: { fa: "ذخیره رمز و ورود", en: "Save password and sign in" },
  accepting: { fa: "در حال ورود…", en: "Signing in…" },
  fillIn: { fa: "این خانه را پر کنید.", en: "Please fill this in." },
  toSignIn: { fa: "رفتن به صفحه ورود", en: "Go to sign in" },
  retry: { fa: "دوباره امتحان کن", en: "Try again" },
  brokenTitle: { fa: "این لینک دعوت کار نمی‌کند", en: "This invite link doesn't work" }
} satisfies Record<string, Bi>;

type InviteDetails = { display_name?: string | null; email?: string | null; username?: string | null; expires_at?: number | null };

const INVITE_ERRORS: Record<string, Bi> = {
  invite_invalid: { fa: "این لینک دعوت درست نیست. از کسی که دعوتتان کرده لینک تازه بخواهید.", en: "This invite link isn't valid. Ask the person who invited you for a new one." },
  invite_expired: { fa: "مهلت این لینک دعوت تمام شده. از کسی که دعوتتان کرده لینک تازه بخواهید.", en: "This invite link has expired. Ask the person who invited you for a new one." },
  invite_used: { fa: "این لینک قبلاً استفاده شده. اگر رمزتان را گذاشته‌اید، از صفحه ورود وارد شوید.", en: "This link was already used. If you've set your password, sign in from the sign-in page." }
};

function inviteProblem(language: Language, failure: AuthFailure): string {
  const own = INVITE_ERRORS[failure.code];
  if (own) return own[language];
  if (failure.status === 404) return INVITE_ERRORS.invite_invalid[language];
  if (failure.status === 410) return INVITE_ERRORS.invite_expired[language];
  const entry = errorEntry(failure.code);
  if (entry) return entry[language];
  return translate(language, "connectionError");
}

/** Token from `#/invite/<token>`, or null. */
export function inviteTokenFromHash(hash: string): string | null {
  const match = /^#\/?invite\/([^/?#]+)/.exec(hash);
  return match ? decodeURIComponent(match[1]) : null;
}

type InvitePageProps = {
  language: Language;
  token: string;
  onLanguageChange: () => void;
  onAccepted: (user: AuthUser, csrfToken: string) => void;
  onGoToSignIn: () => void;
};

export default function InvitePage({ language, token, onLanguageChange, onAccepted, onGoToSignIn }: InvitePageProps) {
  const say = (bi: Bi, params?: Record<string, string | number | null>) => fill(pick(language, bi), params, language);
  const [details, setDetails] = useState<InviteDetails | null>(null);
  const [policy, setPolicy] = useState<PasswordPolicy | null>(null);
  const [loadProblem, setLoadProblem] = useState<{ text: string; fatal: boolean } | null>(null);
  const [values, setValues] = useState({ password: "", repeat: "" });
  const [errors, setErrors] = useState<{ password?: string; repeat?: string }>({});
  const [general, setGeneral] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoadProblem(null);
    try {
      const response = await fetch(`/api/v1/auth/invite/${encodeURIComponent(token)}`, { headers: { Accept: "application/json" }, cache: "no-store" });
      if (!response.ok) {
        const failure = await readAuthFailure(response);
        setLoadProblem({ text: inviteProblem(language, failure), fatal: failure.status === 404 || failure.status === 410 });
        return;
      }
      const payload = (await response.json()) as InviteDetails & { password_policy?: unknown };
      setDetails(payload);
      setPolicy(readPasswordPolicy(payload));
    } catch {
      setLoadProblem({ text: translate(language, "connectionError"), fatal: false });
    }
  }, [language, token]);

  useEffect(() => void load(), [load]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!policy) return;
    const local: { password?: string; repeat?: string } = {};
    const problem = values.password ? passwordProblem(language, policy, values.password) : say(COPY.fillIn);
    if (problem) local.password = problem;
    else if (values.password !== values.repeat) local.repeat = translate(language, "passwordMismatch");
    setErrors(local);
    setGeneral(null);
    if (Object.keys(local).length) return;
    setBusy(true);
    try {
      const response = await fetch(`/api/v1/auth/invite/${encodeURIComponent(token)}/accept`, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ password: values.password, password_confirmation: values.repeat })
      });
      if (response.ok) {
        const payload = (await response.json()) as { user?: AuthUser; csrf_token?: string; status?: string };
        // Two-step sign-in is on for this account: the password is saved; sign in with it and the code.
        if (payload.status === "mfa_required" || !payload.user || !payload.csrf_token) {
          onGoToSignIn();
          return;
        }
        onAccepted(payload.user, payload.csrf_token);
        return;
      }
      const failure = await readAuthFailure(response);
      if (failure.code in INVITE_ERRORS || failure.status === 404 || failure.status === 410) {
        setLoadProblem({ text: inviteProblem(language, failure), fatal: true });
        return;
      }
      const messages = failureMessages(language, failure, ["password", "password_confirmation"]);
      setErrors({ password: messages.fields.password, repeat: messages.fields.password_confirmation });
      setGeneral(messages.general);
    } catch {
      setGeneral(translate(language, "connectionError"));
    } finally {
      setBusy(false);
    }
  };

  const name = details?.display_name?.trim();
  const account = details?.email || details?.username;

  return (
    <AuthShell language={language} onLanguageChange={onLanguageChange}>
      <AuthHeading
        icon={<HandshakeRoundedIcon fontSize="small" />}
        title={loadProblem?.fatal ? say(COPY.brokenTitle) : name ? say(COPY.titleNamed, { name }) : say(COPY.title)}
        hint={loadProblem?.fatal ? undefined : say(COPY.hint)}
      />

      {loadProblem ? (
        <Stack spacing={2} sx={{ mt: 3 }}>
          <Alert severity={loadProblem.fatal ? "warning" : "error"} role="alert">{loadProblem.text}</Alert>
          {loadProblem.fatal ? (
            <Button variant="contained" size="large" onClick={onGoToSignIn} sx={{ minHeight: 48 }}>{say(COPY.toSignIn)}</Button>
          ) : (
            <Button variant="contained" size="large" onClick={() => void load()} sx={{ minHeight: 48 }}>{say(COPY.retry)}</Button>
          )}
        </Stack>
      ) : !details || !policy ? (
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mt: 3 }} role="status">
          <CircularProgress size={20} />
          <Typography color="text.secondary">{say(COPY.loading)}</Typography>
        </Stack>
      ) : (
        <Box component="form" noValidate onSubmit={(event) => void submit(event)} sx={{ mt: 3 }}>
          <Stack spacing={2}>
            {account && (
              <Box sx={{ p: 1.5, border: 1, borderColor: "divider", borderRadius: 1.25 }}>
                <Typography variant="body2" color="text.secondary">{say(COPY.signInAs)}</Typography>
                <Typography fontWeight={700} component="bdi" dir="ltr">{account}</Typography>
                {details.expires_at ? (
                  <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
                    {say(COPY.expires, { when: formatRelative(details.expires_at * 1000, language) })}
                  </Typography>
                ) : null}
              </Box>
            )}
            {general && <Alert severity="error" role="alert">{general}</Alert>}
            <PasswordField
              language={language}
              label={say(COPY.password)}
              value={values.password}
              onChange={(event) => setValues((current) => ({ ...current, password: event.target.value }))}
              autoComplete="new-password"
              error={Boolean(errors.password)}
              helperText={errors.password ?? passwordRuleText(language, policy)}
              autoFocus
              fullWidth
            />
            <PasswordField
              language={language}
              label={say(COPY.repeat)}
              value={values.repeat}
              onChange={(event) => setValues((current) => ({ ...current, repeat: event.target.value }))}
              autoComplete="new-password"
              error={Boolean(errors.repeat)}
              helperText={errors.repeat}
              fullWidth
            />
            <Button type="submit" variant="contained" size="large" disabled={busy} sx={{ minHeight: 48 }}>
              {busy ? (
                <Stack direction="row" spacing={1} alignItems="center">
                  <CircularProgress size={18} color="inherit" />
                  <span>{say(COPY.accepting)}</span>
                </Stack>
              ) : (
                say(COPY.accept)
              )}
            </Button>
            <Button variant="text" onClick={onGoToSignIn} sx={{ minHeight: 44 }}>{say(COPY.toSignIn)}</Button>
          </Stack>
        </Box>
      )}
    </AuthShell>
  );
}
