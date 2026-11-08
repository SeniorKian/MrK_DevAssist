import { useCallback, useEffect, useState } from "react";
import { Box, FormControlLabel, Skeleton, Stack, Switch, Typography } from "@mui/material";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { AuthUser } from "./App";
import { FriendlyError, NoAccess, Notice, RegistrySettings, SectionCard, StatusPill, useConfirmAction, useKit, useUndoSnackbar } from "./kit";
import { roleTitle } from "./kit/people";
import { errorSentence, pick, say, type Bi } from "./copy";

const T = {
  title: { fa: "ثبت‌نام عمومی", en: "Public sign-up" },
  hint: { fa: "آیا هر کسی که صفحه ورود این پنل را باز می‌کند، بتواند برای خودش حساب بسازد؟", en: "Can anyone who opens this panel's sign-in page make their own account?" },
  explainOn: { fa: "روشن است: هر کسی می‌تواند حساب بسازد. حساب تازه نقش «{role}» می‌گیرد و فقط می‌تواند ببیند؛ چیزی را عوض نمی‌کند.", en: "On: anyone can make an account. New accounts get the “{role}” role and can only look; they can't change anything." },
  explainOff: { fa: "خاموش است: فقط شما و مدیرها می‌توانید افراد تازه را دعوت کنید. این امن‌ترین حالت است.", en: "Off: only you and other admins can invite new people. This is the safest choice." },
  switchLabel: { fa: "اجازه بده هر کسی حساب بسازد", en: "Let anyone make an account" },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  confirmTitle: { fa: "ثبت‌نام عمومی روشن شود؟", en: "Turn on public sign-up?" },
  confirmBody: { fa: "هر کسی که به این پنل دسترسی شبکه دارد می‌تواند حسابی بسازد که وضعیت سرور، منابع دریافت و بسته‌ها را می‌بیند.", en: "Anyone who can reach this panel on the network can make an account that sees server status, package sources and packages." },
  confirmEffect1: { fa: "حساب‌های تازه نمی‌توانند چیزی را عوض کنند.", en: "New accounts can't change anything." },
  confirmEffect2: { fa: "اگر پنل روی اینترنت باز است، بهتر است خاموش بماند.", en: "If the panel is open to the internet, keep this off." },
  confirmYes: { fa: "بله، روشن کن", en: "Yes, turn on" },
  turnedOn: { fa: "ثبت‌نام عمومی روشن شد.", en: "Public sign-up is on." },
  turnedOff: { fa: "ثبت‌نام عمومی خاموش شد.", en: "Public sign-up is off." },
  undoHint: { fa: "حساب‌هایی که تا حالا ساخته شده‌اند می‌مانند؛ از بخش «افراد» می‌توانید غیرفعالشان کنید.", en: "Accounts already made stay; you can deactivate them under People." },
  securityTitle: { fa: "ورود و امنیت حساب‌ها", en: "Sign-in & account security" },
  securityHint: { fa: "مدت ماندن در پنل، قانون رمزها و محدودیت تلاش‌های ورود.", en: "How long sign-ins last, password rules and sign-in attempt limits." }
} satisfies Record<string, Bi>;

export function RegistrationCard({ user }: { user: AuthUser }) {
  const { language } = useKit();
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canRead = hasPermission(user.permissions, "user:read");
  const canWrite = hasPermission(user.permissions, "user:write");
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [defaultRole, setDefaultRole] = useState("viewer");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const payload = await getJson<{ enabled: boolean; default_role?: string }>("/api/v1/settings/registration", signal);
      setEnabled(Boolean(payload.enabled));
      if (payload.default_role) setDefaultRole(payload.default_role);
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    }
  }, []);

  useEffect(() => {
    if (!canRead) return;
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [canRead, load]);

  const change = async (next: boolean) => {
    if (next) {
      const ok = await ask({
        title: pick(language, T.confirmTitle),
        body: pick(language, T.confirmBody),
        consequences: [pick(language, T.confirmEffect1), pick(language, T.confirmEffect2)],
        confirmLabel: pick(language, T.confirmYes)
      });
      if (!ok) return;
    }
    setBusy(true);
    try {
      const payload = await mutateJson<{ enabled: boolean }>("/api/v1/settings/registration", { method: "PATCH", body: { enabled: next } });
      setEnabled(Boolean(payload?.enabled ?? next));
      notify({
        message: pick(language, next ? T.turnedOn : T.turnedOff),
        onUndo: () => void change(!next)
      });
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  if (!canRead) return <NoAccess needs="user:read" variant="card" />;
  const role = roleTitle(language, defaultRole);

  return (
    <SectionCard
      title={pick(language, T.title)}
      hint={pick(language, T.hint)}
      status={enabled === null ? undefined : <StatusPill tone={enabled ? "warn" : "ok"} label={pick(language, enabled ? T.on : T.off)} />}
    >
      <Stack spacing={2}>
        {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
        {enabled === null && error === null ? (
          <Skeleton variant="rounded" height={64} />
        ) : enabled !== null ? (
          <>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              {enabled ? say(language, T.explainOn, { role }) : pick(language, T.explainOff)}
            </Typography>
            <Box>
              <FormControlLabel
                control={<Switch checked={enabled} disabled={!canWrite || busy} onChange={(_event, value) => void change(value)} />}
                label={pick(language, T.switchLabel)}
                sx={{ m: 0, "& .MuiFormControlLabel-label": { fontWeight: 650 } }}
              />
            </Box>
            {enabled && <Notice tone="info">{pick(language, T.undoHint)}</Notice>}
            {!canWrite && <NoAccess needs="user:write" />}
          </>
        ) : null}
      </Stack>
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

/** Advanced: every sign-in & security setting (registry group `people.security`). */
export function SignInSecuritySettings({ user }: { user: AuthUser }) {
  const { language } = useKit();
  return (
    <RegistrySettings
      groups={["people.security"]}
      permissions={user.permissions}
      title={pick(language, T.securityTitle)}
      hint={pick(language, T.securityHint)}
    />
  );
}

export default RegistrationCard;
