/**
 * Team invite link for someone who is not signed in (`#/my/team?accept=<token>`, docs/43 §0.1):
 * POST /api/v1/auth/workspace-invite {token} → who is invited where + whether an account can be made;
 * POST /api/v1/auth/workspace-invite/register {token, display_name, password, password_confirmation}
 *   → 201 signs the person in (already a member), 202 waits for the admin's approval.
 * A person who already has an account signs in instead; «My space» then accepts the invite.
 */
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Alert, Box, Button, CircularProgress, Stack, TextField, Typography } from "@mui/material";
import GroupAddRoundedIcon from "@mui/icons-material/GroupAddRounded";
import {
  AuthHeading, AuthShell, PasswordField, failureMessages, passwordProblem, passwordRuleText, readAuthFailure, readPasswordPolicy,
  type PasswordPolicy
} from "../AuthShell";
import type { AuthUser } from "../App";
import type { Language } from "../i18n";
import { translate } from "../i18n";
import { formatRelative } from "../kit/formatters";
import { workspaceRoleName } from "../copy/mySpace";
import { fill, pick, type Bi } from "../copy/text";

const COPY = {
  loading: { fa: "در حال باز کردن دعوت…", en: "Opening your invite…" },
  title: { fa: "دعوت به «{team}»", en: "Invite to “{team}”" },
  hint: { fa: "شما را با نقش «{role}» به این تیم دعوت کرده‌اند.", en: "You've been invited to this team as “{role}”." },
  email: { fa: "ایمیل حساب شما", en: "Your account email" },
  expires: { fa: "این دعوت {when} تمام می‌شود.", en: "This invite expires {when}." },
  hasAccount: { fa: "با این ایمیل از قبل حساب دارید. وارد شوید تا به تیم بپیوندید.", en: "You already have an account with this email. Sign in to join the team." },
  noSignup: { fa: "این‌جا نمی‌شود با لینک دعوت حساب ساخت. از مدیر سامانه بخواهید برایتان حساب بسازد، بعد با همین لینک وارد شوید.", en: "Accounts can't be created from invite links here. Ask the system admin to create your account, then open this link again and sign in." },
  approvalNote: { fa: "پس از ساختن حساب، مدیر سامانه باید آن را تأیید کند. بعد از تأیید وارد می‌شوید و در تیم هستید.", en: "After you create the account, the system admin has to approve it. Once approved, you sign in and you're in the team." },
  name: { fa: "نام شما", en: "Your name" },
  nameHint: { fa: "همان نامی که هم‌تیمی‌ها می‌بینند.", en: "The name your teammates see." },
  password: { fa: "رمز تازه", en: "New password" },
  repeat: { fa: "تکرار رمز", en: "Repeat the password" },
  create: { fa: "ساختن حساب و پیوستن", en: "Create account and join" },
  creating: { fa: "در حال ساختن حساب…", en: "Creating your account…" },
  fillIn: { fa: "این خانه را پر کنید.", en: "Please fill this in." },
  nameShort: { fa: "نام باید دست‌کم ۲ نویسه باشد.", en: "The name needs at least 2 characters." },
  signIn: { fa: "ورود با حسابی که دارم", en: "Sign in with my account" },
  retry: { fa: "دوباره امتحان کن", en: "Try again" },
  brokenTitle: { fa: "این لینک دعوت کار نمی‌کند", en: "This invite link doesn't work" },
  broken: { fa: "این لینک دعوت درست نیست، استفاده شده یا مهلتش تمام شده. از کسی که دعوتتان کرده لینک تازه بخواهید.", en: "This invite link isn't valid, was already used, or has expired. Ask the person who invited you for a new one." },
  pendingTitle: { fa: "حساب شما ساخته شد", en: "Your account was created" },
  pending: { fa: "حساب شما منتظر تأیید مدیر سامانه است. پس از تأیید با همین ایمیل و رمز وارد شوید؛ عضو تیم هستید.", en: "Your account is waiting for the system admin's approval. Once approved, sign in with this email and password; you're already in the team." },
  teamFull: { fa: "این تیم به سقف اعضایش رسیده. به کسی که دعوتتان کرده بگویید.", en: "This team has reached its member limit. Tell the person who invited you." }
} satisfies Record<string, Bi>;

type Preview = {
  email: string;
  role: string;
  expires_at?: number | null;
  workspace?: { name?: string | null } | null;
  account_exists: boolean;
  signup: "off" | "approval" | "open";
};

const SPECIFIC: Record<string, Bi> = {
  invite_signup_off: COPY.noSignup,
  account_exists: COPY.hasAccount,
  quota_exceeded: COPY.teamFull
};

/** Invite token from `#/my/team?accept=<token>`, or null. */
export function joinTokenFromHash(hash: string): string | null {
  const match = /^#\/?my\/team\?(?:[^#]*&)?accept=([^&#]+)/.exec(hash);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

type JoinTeamPageProps = {
  language: Language;
  token: string;
  onLanguageChange: () => void;
  /** Account created and joined: sign the person in. */
  onJoined: (user: AuthUser, csrfToken: string) => void;
  /** Show the normal sign-in page (the link stays, so «My space» accepts it after sign-in). */
  onSignIn: () => void;
};

export default function JoinTeamPage({ language, token, onLanguageChange, onJoined, onSignIn }: JoinTeamPageProps) {
  const say = (bi: Bi, params?: Record<string, string | number | null>) => fill(pick(language, bi), params, language);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [policy, setPolicy] = useState<PasswordPolicy | null>(null);
  const [problem, setProblem] = useState<{ text: string; fatal: boolean } | null>(null);
  const [values, setValues] = useState({ name: "", password: "", repeat: "" });
  const [errors, setErrors] = useState<{ name?: string; password?: string; repeat?: string }>({});
  const [general, setGeneral] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState(false);

  const load = useCallback(async () => {
    setProblem(null);
    try {
      const response = await fetch("/api/v1/auth/workspace-invite", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
        cache: "no-store"
      });
      if (!response.ok) {
        const failure = await readAuthFailure(response);
        const fatal = failure.status === 404 || failure.status === 422;
        setProblem({ text: fatal ? say(COPY.broken) : translate(language, "connectionError"), fatal });
        return;
      }
      const payload = (await response.json()) as Preview & { password_policy?: unknown };
      setPreview(payload);
      setPolicy(readPasswordPolicy(payload));
    } catch {
      setProblem({ text: translate(language, "connectionError"), fatal: false });
    }
  }, [language, token]);

  useEffect(() => void load(), [load]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!policy) return;
    const local: { name?: string; password?: string; repeat?: string } = {};
    const name = values.name.trim();
    if (!name) local.name = say(COPY.fillIn);
    else if (name.length < 2) local.name = say(COPY.nameShort);
    const passwordIssue = values.password ? passwordProblem(language, policy, values.password) : say(COPY.fillIn);
    if (passwordIssue) local.password = passwordIssue;
    else if (values.password !== values.repeat) local.repeat = translate(language, "passwordMismatch");
    setErrors(local);
    setGeneral(null);
    if (Object.keys(local).length) return;
    setBusy(true);
    try {
      const response = await fetch("/api/v1/auth/workspace-invite/register", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ token, display_name: name, password: values.password, password_confirmation: values.repeat })
      });
      if (response.status === 202) {
        setPending(true);
        return;
      }
      if (response.ok) {
        const payload = (await response.json()) as { user: AuthUser; csrf_token: string };
        onJoined(payload.user, payload.csrf_token);
        return;
      }
      const failure = await readAuthFailure(response);
      if (failure.status === 404) {
        setProblem({ text: say(COPY.broken), fatal: true });
        return;
      }
      const messages = failureMessages(language, failure, ["display_name", "password", "password_confirmation"], SPECIFIC);
      setErrors({ name: messages.fields.display_name, password: messages.fields.password, repeat: messages.fields.password_confirmation });
      setGeneral(messages.general);
    } catch {
      setGeneral(translate(language, "connectionError"));
    } finally {
      setBusy(false);
    }
  };

  const team = preview?.workspace?.name?.trim() || "";
  const canCreate = preview && !preview.account_exists && preview.signup !== "off";
  let title = say(COPY.loading);
  if (problem?.fatal) title = say(COPY.brokenTitle);
  else if (pending) title = say(COPY.pendingTitle);
  else if (preview) title = say(COPY.title, { team });

  return (
    <AuthShell language={language} onLanguageChange={onLanguageChange}>
      <AuthHeading
        icon={<GroupAddRoundedIcon fontSize="small" />}
        title={title}
        hint={preview && !problem?.fatal && !pending ? say(COPY.hint, { role: workspaceRoleName(language, preview.role) }) : undefined}
      />

      {problem ? (
        <Stack spacing={2} sx={{ mt: 3 }}>
          <Alert severity={problem.fatal ? "warning" : "error"} role="alert">{problem.text}</Alert>
          {problem.fatal ? (
            <Button variant="contained" size="large" onClick={onSignIn} sx={{ minHeight: 48 }}>{say(COPY.signIn)}</Button>
          ) : (
            <Button variant="contained" size="large" onClick={() => void load()} sx={{ minHeight: 48 }}>{say(COPY.retry)}</Button>
          )}
        </Stack>
      ) : pending ? (
        <Stack spacing={2} sx={{ mt: 3 }}>
          <Alert severity="success" role="status">{say(COPY.pending)}</Alert>
          <Button variant="contained" size="large" onClick={onSignIn} sx={{ minHeight: 48 }}>{say(COPY.signIn)}</Button>
        </Stack>
      ) : !preview || !policy ? (
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mt: 3 }} role="status">
          <CircularProgress size={20} />
          <Typography color="text.secondary">{say(COPY.loading)}</Typography>
        </Stack>
      ) : (
        <Box component="form" noValidate onSubmit={(event) => void submit(event)} sx={{ mt: 3 }}>
          <Stack spacing={2}>
            <Box sx={{ p: 1.5, border: 1, borderColor: "divider", borderRadius: 1.25 }}>
              <Typography variant="body2" color="text.secondary">{say(COPY.email)}</Typography>
              <Typography fontWeight={700} component="bdi" dir="ltr">{preview.email}</Typography>
              {preview.expires_at ? (
                <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
                  {say(COPY.expires, { when: formatRelative(preview.expires_at * 1000, language) })}
                </Typography>
              ) : null}
            </Box>
            {preview.account_exists ? <Alert severity="info">{say(COPY.hasAccount)}</Alert> : null}
            {!preview.account_exists && preview.signup === "off" ? <Alert severity="info">{say(COPY.noSignup)}</Alert> : null}
            {canCreate && preview.signup === "approval" ? <Alert severity="info">{say(COPY.approvalNote)}</Alert> : null}
            {general && <Alert severity="error" role="alert">{general}</Alert>}
            {canCreate ? (
              <>
                <TextField
                  label={say(COPY.name)}
                  value={values.name}
                  onChange={(event) => setValues((current) => ({ ...current, name: event.target.value }))}
                  autoComplete="name"
                  error={Boolean(errors.name)}
                  helperText={errors.name ?? say(COPY.nameHint)}
                  inputProps={{ maxLength: 100 }}
                  autoFocus
                  fullWidth
                />
                <PasswordField
                  language={language}
                  label={say(COPY.password)}
                  value={values.password}
                  onChange={(event) => setValues((current) => ({ ...current, password: event.target.value }))}
                  autoComplete="new-password"
                  error={Boolean(errors.password)}
                  helperText={errors.password ?? passwordRuleText(language, policy)}
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
                      <span>{say(COPY.creating)}</span>
                    </Stack>
                  ) : (
                    say(COPY.create)
                  )}
                </Button>
                <Button variant="text" onClick={onSignIn} sx={{ minHeight: 44 }}>{say(COPY.signIn)}</Button>
              </>
            ) : (
              <Button variant="contained" size="large" onClick={onSignIn} sx={{ minHeight: 48 }}>{say(COPY.signIn)}</Button>
            )}
          </Stack>
        </Box>
      )}
    </AuthShell>
  );
}
