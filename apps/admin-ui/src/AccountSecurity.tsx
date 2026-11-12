/**
 * My sign-in security: two-step sign-in with an authenticator app (TOTP) and my open sessions.
 *
 * - `AccountSecurityDialog`: from the user menu.
 * - `ForcedTwoStepPage`: full page while the two-step policy covers the account and it is not set up.
 * - `SignInPolicyCards`: people management: who must use two-step sign-in, and single sign-on (OIDC).
 * API: /api/v1/auth/mfa*, /api/v1/auth/sessions*, /api/v1/auth/mfa/policy, /api/v1/auth/oidc/settings.
 */
import { useCallback, useEffect, useState } from "react";
import {
  Alert, Box, Button, Checkbox, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Divider, FormControlLabel,
  List, ListItem, ListItemText, MenuItem, Stack, Switch, TextField, Typography, useMediaQuery, useTheme
} from "@mui/material";
import PhonelinkLockRoundedIcon from "@mui/icons-material/PhonelinkLockRounded";
import { ApiError, apiMutate, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { AuthUser } from "./App";
import { AuthHeading, AuthShell, PasswordField } from "./AuthShell";
import { CopyField, FriendlyError, NoAccess, OneTimeSecret, QrCode, RelativeTime, SectionCard, StatusPill, useKit } from "./kit";
import { roleTitle } from "./kit/people";
import { errorSentence, pick, type Bi } from "./copy";
import type { Language } from "./i18n";

const T = {
  title: { fa: "امنیت ورود من", en: "My sign-in security" },
  twoStep: { fa: "ورود دومرحله‌ای", en: "Two-step sign-in" },
  twoStepHint: { fa: "بعد از رمز، یک کد از برنامه احراز هویت گوشی هم لازم است؛ مثل Google Authenticator یا Microsoft Authenticator.", en: "After your password you also type a code from an authenticator app, such as Google Authenticator or Microsoft Authenticator." },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  required: { fa: "برای نقش شما لازم است", en: "Required for your role" },
  turnOn: { fa: "روشن کردن", en: "Turn on" },
  turnOff: { fa: "خاموش کردن", en: "Turn off" },
  newCodes: { fa: "ساخت کدهای پشتیبانی تازه", en: "Make new backup codes" },
  codesLeft: { fa: "{n} کد پشتیبانی باقی مانده است.", en: "{n} backup codes left." },
  password: { fa: "رمز فعلی", en: "Current password" },
  next: { fa: "ادامه", en: "Continue" },
  scan: { fa: "این تصویر را با برنامه احراز هویت گوشی بخوانید. اگر نشد، کلید زیر را دستی وارد کنید.", en: "Scan this picture with your authenticator app. If you can't, type the key below by hand." },
  key: { fa: "کلید", en: "Key" },
  code: { fa: "کد ۶ رقمی برنامه", en: "6-digit code from the app" },
  confirm: { fa: "تأیید و روشن کردن", en: "Confirm and turn on" },
  codeOrBackup: { fa: "کد برنامه یا کد پشتیبانی", en: "App code or a backup code" },
  codesTitle: { fa: "کدهای پشتیبانی", en: "Backup codes" },
  codesBody: { fa: "اگر گوشی در دسترس نبود، با هر کدام از این‌ها یک بار می‌توانید وارد شوید.", en: "If your phone isn't at hand, each of these signs you in once." },
  sessions: { fa: "دستگاه‌هایی که وارد شده‌اند", en: "Where you're signed in" },
  thisDevice: { fa: "همین دستگاه", en: "This device" },
  remembered: { fa: "به خاطر سپرده شده", en: "Remembered" },
  lastSeen: { fa: "آخرین استفاده", en: "Last used" },
  endsAt: { fa: "پایان", en: "Ends" },
  signOut: { fa: "خروج", en: "Sign out" },
  signOutOthers: { fa: "خروج از همه دستگاه‌های دیگر", en: "Sign out all other devices" },
  close: { fa: "بستن", en: "Close" },
  cancel: { fa: "انصراف", en: "Cancel" },
  forcedTitle: { fa: "ورود دومرحله‌ای را روشن کنید", en: "Turn on two-step sign-in" },
  forcedHint: { fa: "مدیر پنل ورود دومرحله‌ای را برای نقش شما لازم کرده است. پیش از ادامه آن را راه بیندازید.", en: "The panel admin requires two-step sign-in for your role. Set it up before you continue." },
  logout: { fa: "خروج", en: "Sign out" },
  done: { fa: "انجام شد.", en: "Done." }
} satisfies Record<string, Bi>;

type MfaStatus = { enabled: boolean; required: boolean; recovery_codes_left: number; password_required: boolean; available: boolean };
type Enrollment = { secret: string; otpauth_uri: string; account: string };
type SessionItem = { id: number; current: boolean; created_at: number; last_seen_at: number; expires_at: number; remember: boolean; method: string; source_ip?: string | null; user_agent?: string | null };

const sayIn = (language: Language, bi: Bi, params?: Record<string, string | number>) => {
  let text = pick(language, bi);
  for (const [key, value] of Object.entries(params ?? {})) text = text.replace(`{${key}}`, String(value));
  return text;
};

/** The enrolment steps: password (when the account has one) → QR + key → code → backup codes. */
function TwoStepSetup({ language, passwordRequired, onEnabled }: { language: Language; passwordRequired: boolean; onEnabled: (codes: string[]) => void }) {
  const [password, setPassword] = useState("");
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const say = (bi: Bi) => pick(language, bi);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      setEnrollment(await mutateJson<Enrollment>("/api/v1/auth/mfa/totp/start", { body: passwordRequired ? { current_password: password } : {} }));
    } catch (caught) {
      setError(errorSentence(language, caught));
    } finally {
      setBusy(false);
    }
  };
  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await mutateJson<{ recovery_codes: string[] }>("/api/v1/auth/mfa/totp/confirm", { body: { code } });
      onEnabled(result.recovery_codes);
    } catch (caught) {
      setError(errorSentence(language, caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack spacing={2}>
      {error && <Alert severity="error" role="alert">{error}</Alert>}
      {!enrollment ? (
        <Box component="form" noValidate onSubmit={(event) => { event.preventDefault(); void start(); }}>
          <Stack spacing={2}>
            {passwordRequired && (
              <PasswordField language={language} label={say(T.password)} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" fullWidth autoFocus />
            )}
            <Button type="submit" variant="contained" disabled={busy || (passwordRequired && !password)} sx={{ minHeight: 44 }}>
              {busy ? <CircularProgress size={18} color="inherit" /> : say(T.next)}
            </Button>
          </Stack>
        </Box>
      ) : (
        <Box component="form" noValidate onSubmit={(event) => { event.preventDefault(); void confirm(); }}>
          <Stack spacing={2} alignItems="stretch">
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{say(T.scan)}</Typography>
            <Box sx={{ display: "flex", justifyContent: "center", bgcolor: "#fff", p: 1, borderRadius: 1 }}>
              <QrCode value={enrollment.otpauth_uri} label={say(T.twoStep)} />
            </Box>
            <CopyField label={say(T.key)} value={enrollment.secret.replace(/(.{4})/g, "$1 ").trim()} />
            <TextField
              label={say(T.code)}
              value={code}
              onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
              autoComplete="one-time-code"
              slotProps={{ htmlInput: { dir: "ltr", inputMode: "numeric", pattern: "[0-9]*", maxLength: 6 } }}
              autoFocus
            />
            <Button type="submit" variant="contained" disabled={busy || code.length !== 6} sx={{ minHeight: 44 }}>
              {busy ? <CircularProgress size={18} color="inherit" /> : say(T.confirm)}
            </Button>
          </Stack>
        </Box>
      )}
    </Stack>
  );
}

function BackupCodes({ language, codes, onClose }: { language: Language; codes: string[] | null; onClose: () => void }) {
  return (
    <OneTimeSecret
      open={Boolean(codes)}
      title={pick(language, T.codesTitle)}
      body={pick(language, T.codesBody)}
      items={[{ label: pick(language, T.codesTitle), value: (codes ?? []).join("\n"), ltr: true, multiline: true }]}
      onClose={onClose}
    />
  );
}

/** A code-or-proof form used to turn off two-step sign-in or make new backup codes. */
function ProofForm({ language, needPassword, action, onDone, onCancel }: { language: Language; needPassword: boolean; action: "disable" | "codes"; onDone: (codes?: string[]) => void; onCancel: () => void }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const say = (bi: Bi) => pick(language, bi);
  const submit = async () => {
    setBusy(true);
    setError(null);
    const value = code.trim();
    const proof = /^\d{6}$/.test(value) ? { code: value } : { recovery_code: value };
    try {
      if (action === "disable") {
        await mutateJson("/api/v1/auth/mfa/disable", { body: { ...proof, current_password: needPassword ? password : undefined } });
        onDone();
      } else {
        const result = await mutateJson<{ recovery_codes: string[] }>("/api/v1/auth/mfa/recovery-codes", { body: proof });
        onDone(result.recovery_codes);
      }
    } catch (caught) {
      setError(errorSentence(language, caught));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Box component="form" noValidate onSubmit={(event) => { event.preventDefault(); void submit(); }}>
      <Stack spacing={2}>
        {error && <Alert severity="error" role="alert">{error}</Alert>}
        {action === "disable" && needPassword && (
          <PasswordField language={language} label={say(T.password)} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" fullWidth autoFocus />
        )}
        <TextField label={say(T.codeOrBackup)} value={code} onChange={(event) => setCode(event.target.value)} autoComplete="one-time-code" slotProps={{ htmlInput: { dir: "ltr" } }} />
        <Stack direction="row" spacing={1} justifyContent="flex-end">
          <Button onClick={onCancel} sx={{ minHeight: 44 }}>{say(T.cancel)}</Button>
          <Button type="submit" variant="contained" color={action === "disable" ? "error" : "primary"} disabled={busy || !code.trim()} sx={{ minHeight: 44 }}>
            {busy ? <CircularProgress size={18} color="inherit" /> : say(action === "disable" ? T.turnOff : T.newCodes)}
          </Button>
        </Stack>
      </Stack>
    </Box>
  );
}

export function AccountSecurityDialog({ open, language, onClose }: { open: boolean; language: Language; onClose: () => void }) {
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [mode, setMode] = useState<"idle" | "setup" | "disable" | "codes">("idle");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const say = (bi: Bi) => pick(language, bi);

  const load = useCallback(async () => {
    try {
      const [mfa, list] = await Promise.all([
        getJson<MfaStatus>("/api/v1/auth/mfa"),
        getJson<{ items: SessionItem[] }>("/api/v1/auth/sessions")
      ]);
      setStatus(mfa);
      setSessions(list.items);
      setError(null);
    } catch (caught) {
      if (!isAbortError(caught)) setError(caught);
    }
  }, []);

  useEffect(() => {
    if (open) {
      setMode("idle");
      void load();
    }
  }, [open, load]);

  const endSession = async (id: number | "others") => {
    try {
      if (id === "others") await mutateJson("/api/v1/auth/sessions/revoke-others", {});
      else await mutateJson(`/api/v1/auth/sessions/${id}`, { method: "DELETE" });
      await load();
    } catch (caught) {
      setError(caught);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm" fullScreen={fullScreen} aria-labelledby="mrk-account-security-title">
      <DialogTitle id="mrk-account-security-title" sx={{ fontWeight: 760 }}>{say(T.title)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2.5}>
          {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
          {!status ? (
            error === null && <CircularProgress size={24} />
          ) : (
            <Stack spacing={1.5}>
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                <Typography fontWeight={720}>{say(T.twoStep)}</Typography>
                <StatusPill tone={status.enabled ? "ok" : "warn"} label={say(status.enabled ? T.on : T.off)} />
                {status.required && <Chip size="small" label={say(T.required)} />}
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{say(T.twoStepHint)}</Typography>
              {status.enabled && <Typography variant="body2">{sayIn(language, T.codesLeft, { n: status.recovery_codes_left })}</Typography>}
              {mode === "setup" && (
                <TwoStepSetup language={language} passwordRequired={status.password_required} onEnabled={(next) => { setCodes(next); setMode("idle"); void load(); }} />
              )}
              {(mode === "disable" || mode === "codes") && (
                <ProofForm
                  language={language}
                  needPassword={status.password_required}
                  action={mode}
                  onCancel={() => setMode("idle")}
                  onDone={(next) => { if (next) setCodes(next); setMode("idle"); void load(); }}
                />
              )}
              {mode === "idle" && status.available && (
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {!status.enabled && <Button variant="contained" startIcon={<PhonelinkLockRoundedIcon />} onClick={() => setMode("setup")} sx={{ minHeight: 44 }}>{say(T.turnOn)}</Button>}
                  {status.enabled && <Button variant="outlined" onClick={() => setMode("codes")} sx={{ minHeight: 44 }}>{say(T.newCodes)}</Button>}
                  {status.enabled && !status.required && <Button color="error" onClick={() => setMode("disable")} sx={{ minHeight: 44 }}>{say(T.turnOff)}</Button>}
                </Stack>
              )}
            </Stack>
          )}
          <Divider />
          <Stack spacing={1}>
            <Typography fontWeight={720}>{say(T.sessions)}</Typography>
            <List dense disablePadding>
              {sessions.map((item) => (
                <ListItem
                  key={item.id}
                  disableGutters
                  secondaryAction={!item.current ? <Button size="small" onClick={() => void endSession(item.id)}>{say(T.signOut)}</Button> : undefined}
                >
                  <ListItemText
                    primary={
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                        <Typography variant="body2" component="bdi" dir="ltr" noWrap sx={{ maxWidth: 260 }}>{(item.user_agent || item.source_ip || "—").slice(0, 60)}</Typography>
                        {item.current && <Chip size="small" color="primary" label={say(T.thisDevice)} />}
                        {item.remember && <Chip size="small" variant="outlined" label={say(T.remembered)} />}
                      </Stack>
                    }
                    secondary={<>{say(T.lastSeen)}: <RelativeTime value={item.last_seen_at} /> · {say(T.endsAt)}: <RelativeTime value={item.expires_at} /></>}
                  />
                </ListItem>
              ))}
            </List>
            {sessions.length > 1 && (
              <Box><Button color="warning" onClick={() => void endSession("others")} sx={{ minHeight: 44 }}>{say(T.signOutOthers)}</Button></Box>
            )}
          </Stack>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2.5 }}>
        <Button onClick={onClose} sx={{ minHeight: 44 }}>{say(T.close)}</Button>
      </DialogActions>
      <BackupCodes language={language} codes={codes} onClose={() => setCodes(null)} />
    </Dialog>
  );
}

/** Full page while the two-step policy covers this account and it is not set up yet. */
export function ForcedTwoStepPage({ language, onLanguageChange, onDone, onSignOut }: { language: Language; onLanguageChange: () => void; onDone: () => void; onSignOut: () => void }) {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  useEffect(() => {
    getJson<MfaStatus>("/api/v1/auth/mfa").then(setStatus).catch(() => setStatus({ enabled: false, required: true, recovery_codes_left: 0, password_required: true, available: true }));
  }, []);
  return (
    <AuthShell language={language} onLanguageChange={onLanguageChange}>
      <AuthHeading icon={<PhonelinkLockRoundedIcon fontSize="small" />} title={pick(language, T.forcedTitle)} hint={pick(language, T.forcedHint)} />
      <Box sx={{ mt: 3 }}>
        {status ? <TwoStepSetup language={language} passwordRequired={status.password_required} onEnabled={setCodes} /> : <CircularProgress size={24} />}
        <Button variant="text" onClick={onSignOut} sx={{ mt: 1.5, minHeight: 44 }} fullWidth>{pick(language, T.logout)}</Button>
      </Box>
      <BackupCodes language={language} codes={codes} onClose={() => { setCodes(null); onDone(); }} />
    </AuthShell>
  );
}

// ── People management ─────────────────────────────────────────────────────────

const P = {
  policyTitle: { fa: "ورود دومرحله‌ای برای همه", en: "Two-step sign-in for everyone" },
  policyHint: { fa: "چه کسانی باید ورود دومرحله‌ای داشته باشند. کسی که هنوز ندارد، بعد از ورود اول آن را راه می‌اندازد.", en: "Who must use two-step sign-in. Anyone who doesn't have it yet sets it up right after signing in." },
  modeOff: { fa: "اختیاری", en: "Optional" },
  modeAll: { fa: "برای همه لازم", en: "Required for everyone" },
  modeRoles: { fa: "برای نقش‌های انتخاب‌شده لازم", en: "Required for chosen roles" },
  save: { fa: "ذخیره", en: "Save" },
  saved: { fa: "ذخیره شد.", en: "Saved." },
  ssoTitle: { fa: "ورود یکپارچه سازمان", en: "Organization single sign-on" },
  ssoHint: { fa: "افراد با حساب سازمانی خود وارد شوند؛ مثل Google، Microsoft، Keycloak یا Authentik.", en: "People sign in with their organization account, such as Google, Microsoft, Keycloak or Authentik." },
  enabled: { fa: "روشن باشد", en: "Turned on" },
  displayName: { fa: "نام روی دکمه ورود", en: "Name on the sign-in button" },
  issuer: { fa: "نشانی صادرکننده", en: "Issuer address" },
  clientId: { fa: "شناسه برنامه", en: "Client ID" },
  clientSecret: { fa: "رمز برنامه", en: "Client secret" },
  secretSet: { fa: "ذخیره شده است؛ برای عوض کردن، مقدار تازه بنویسید.", en: "Saved; type a new value to replace it." },
  redirect: { fa: "نشانی بازگشت (در تنظیمات سرور ورود سازمان بگذارید)", en: "Redirect address (add it in your sign-in provider)" },
  domains: { fa: "دامنه‌های ایمیل مجاز (با فاصله جدا کنید؛ خالی یعنی همه)", en: "Allowed email domains (separate with spaces; empty means any)" },
  autoCreate: { fa: "برای افراد تازه خودکار حساب بساز", en: "Make accounts for new people automatically" },
  defaultRole: { fa: "نقش حساب‌های تازه", en: "Role of new accounts" },
  ssoOnly: { fa: "جز مالک، همه فقط با ورود یکپارچه وارد شوند", en: "Everyone except owners signs in with single sign-on only" },
  trustMfa: { fa: "ورود دومرحله‌ای سازمان کافی است", en: "The organization's two-step check is enough" },
  verified: { fa: "فقط ایمیل‌های تأییدشده پذیرفته شوند", en: "Accept verified emails only" },
  test: { fa: "آزمایش اتصال", en: "Test connection" },
  testOk: { fa: "اتصال برقرار است.", en: "The connection works." },
  testFailed: { fa: "اتصال برقرار نشد: {code}", en: "Couldn't connect: {code}" },
  ownerOnly: { fa: "فقط مالک پنل این بخش را عوض می‌کند.", en: "Only the panel owner changes this." }
} satisfies Record<string, Bi>;

type Policy = { mode: "off" | "all" | "roles"; roles: string[] };
type Sso = {
  enabled: boolean; display_name: string; issuer: string; client_id: string; client_secret_set: boolean; redirect_uri: string;
  allowed_domains: string[]; auto_create: boolean; default_role: string; sso_only: boolean; trust_idp_mfa: boolean;
  require_email_verified: boolean; roles: string[];
};

export function SignInPolicyCards({ user }: { user: AuthUser }) {
  const { language } = useKit();
  const canRead = hasPermission(user.permissions, "user:read");
  const canWrite = hasPermission(user.permissions, "user:write");
  const isOwner = user.role === "owner";
  const say = (bi: Bi) => pick(language, bi);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [sso, setSso] = useState<Sso | null>(null);
  const [secret, setSecret] = useState("");
  const [domains, setDomains] = useState("");
  const [message, setMessage] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const [ssoMessage, setSsoMessage] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const roles = ["admin", "operator", "developer", "viewer", "customer"];

  const load = useCallback(async () => {
    try {
      const [nextPolicy, nextSso] = await Promise.all([getJson<Policy>("/api/v1/auth/mfa/policy"), getJson<Sso>("/api/v1/auth/oidc/settings")]);
      setPolicy(nextPolicy);
      setSso(nextSso);
      setDomains(nextSso.allowed_domains.join(" "));
      setError(null);
    } catch (caught) {
      if (!isAbortError(caught) && !(caught instanceof ApiError && caught.status === 401)) setError(caught);
    }
  }, []);
  useEffect(() => {
    if (canRead) void load();
  }, [canRead, load]);

  if (!canRead) return <NoAccess needs="user:read" variant="card" />;

  const savePolicy = async () => {
    if (!policy) return;
    try {
      setPolicy(await mutateJson<Policy>("/api/v1/auth/mfa/policy", { method: "PUT", body: policy }));
      setMessage({ tone: "success", text: say(P.saved) });
    } catch (caught) {
      setMessage({ tone: "error", text: errorSentence(language, caught) });
    }
  };
  const saveSso = async () => {
    if (!sso) return;
    try {
      const body = {
        enabled: sso.enabled, display_name: sso.display_name, issuer: sso.issuer, client_id: sso.client_id,
        allowed_domains: domains.split(/[\s,]+/).filter(Boolean), auto_create: sso.auto_create, default_role: sso.default_role,
        sso_only: sso.sso_only, trust_idp_mfa: sso.trust_idp_mfa, require_email_verified: sso.require_email_verified,
        ...(secret ? { client_secret: secret } : {})
      };
      const next = await mutateJson<Sso>("/api/v1/auth/oidc/settings", { method: "PUT", body });
      setSso(next);
      setSecret("");
      setSsoMessage({ tone: "success", text: say(P.saved) });
    } catch (caught) {
      setSsoMessage({ tone: "error", text: errorSentence(language, caught) });
    }
  };
  const testSso = async () => {
    try {
      const response = await apiMutate("/api/v1/auth/oidc/test");
      const result = (await response.json()) as { ok: boolean; code?: string };
      setSsoMessage(result.ok ? { tone: "success", text: say(P.testOk) } : { tone: "error", text: sayIn(language, P.testFailed, { code: result.code ?? "" }) });
    } catch (caught) {
      setSsoMessage({ tone: "error", text: errorSentence(language, caught) });
    }
  };
  const ssoEditable = canWrite && isOwner;
  const flag = (key: "enabled" | "auto_create" | "sso_only" | "trust_idp_mfa" | "require_email_verified", label: Bi) => (
    <FormControlLabel
      control={<Switch checked={Boolean(sso?.[key])} disabled={!ssoEditable} onChange={(_event, value) => setSso((current) => (current ? { ...current, [key]: value } : current))} />}
      label={say(label)}
      sx={{ m: 0 }}
    />
  );

  return (
    <Stack spacing={2.5}>
      {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
      <SectionCard title={say(P.policyTitle)} hint={say(P.policyHint)}>
        {policy && (
          <Stack spacing={2}>
            <TextField select label={say(P.policyTitle)} value={policy.mode} disabled={!canWrite} onChange={(event) => setPolicy({ ...policy, mode: event.target.value as Policy["mode"] })}>
              <MenuItem value="off">{say(P.modeOff)}</MenuItem>
              <MenuItem value="all">{say(P.modeAll)}</MenuItem>
              <MenuItem value="roles">{say(P.modeRoles)}</MenuItem>
            </TextField>
            {policy.mode === "roles" && (
              <Stack direction="row" flexWrap="wrap" useFlexGap>
                {roles.map((role) => (
                  <FormControlLabel
                    key={role}
                    control={<Checkbox checked={policy.roles.includes(role)} disabled={!canWrite} onChange={(_event, checked) => setPolicy({ ...policy, roles: checked ? [...policy.roles, role] : policy.roles.filter((item) => item !== role) })} />}
                    label={roleTitle(language, role)}
                  />
                ))}
              </Stack>
            )}
            {message && <Alert severity={message.tone}>{message.text}</Alert>}
            {canWrite && <Box><Button variant="contained" onClick={() => void savePolicy()} sx={{ minHeight: 44 }}>{say(P.save)}</Button></Box>}
          </Stack>
        )}
      </SectionCard>
      <SectionCard title={say(P.ssoTitle)} hint={say(P.ssoHint)} status={sso ? <StatusPill tone={sso.enabled ? "ok" : "warn"} label={say(sso.enabled ? T.on : T.off)} /> : undefined}>
        {sso && (
          <Stack spacing={2}>
            {!isOwner && <Alert severity="info">{say(P.ownerOnly)}</Alert>}
            {flag("enabled", P.enabled)}
            <TextField label={say(P.displayName)} value={sso.display_name} disabled={!ssoEditable} onChange={(event) => setSso({ ...sso, display_name: event.target.value })} />
            <TextField label={say(P.issuer)} value={sso.issuer} disabled={!ssoEditable} placeholder="https://accounts.google.com" slotProps={{ htmlInput: { dir: "ltr" } }} onChange={(event) => setSso({ ...sso, issuer: event.target.value })} />
            <TextField label={say(P.clientId)} value={sso.client_id} disabled={!ssoEditable} slotProps={{ htmlInput: { dir: "ltr" } }} onChange={(event) => setSso({ ...sso, client_id: event.target.value })} />
            <TextField label={say(P.clientSecret)} type="password" value={secret} disabled={!ssoEditable} helperText={sso.client_secret_set ? say(P.secretSet) : undefined} autoComplete="new-password" slotProps={{ htmlInput: { dir: "ltr" } }} onChange={(event) => setSecret(event.target.value)} />
            <CopyField label={say(P.redirect)} value={sso.redirect_uri} />
            <TextField label={say(P.domains)} value={domains} disabled={!ssoEditable} slotProps={{ htmlInput: { dir: "ltr" } }} onChange={(event) => setDomains(event.target.value)} />
            {flag("require_email_verified", P.verified)}
            {flag("auto_create", P.autoCreate)}
            {sso.auto_create && (
              <TextField select label={say(P.defaultRole)} value={sso.default_role} disabled={!ssoEditable} onChange={(event) => setSso({ ...sso, default_role: event.target.value })}>
                {sso.roles.map((role) => <MenuItem key={role} value={role}>{roleTitle(language, role)}</MenuItem>)}
              </TextField>
            )}
            {flag("trust_idp_mfa", P.trustMfa)}
            {flag("sso_only", P.ssoOnly)}
            {ssoMessage && <Alert severity={ssoMessage.tone}>{ssoMessage.text}</Alert>}
            {ssoEditable && (
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Button variant="contained" onClick={() => void saveSso()} sx={{ minHeight: 44 }}>{say(P.save)}</Button>
                <Button variant="outlined" onClick={() => void testSso()} sx={{ minHeight: 44 }}>{say(P.test)}</Button>
              </Stack>
            )}
          </Stack>
        )}
      </SectionCard>
    </Stack>
  );
}
