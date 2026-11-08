import { useEffect, useState } from "react";
import { FormControlLabel, Stack, Switch, Typography } from "@mui/material";
import { ApiError, getJson, isAbortError, mutateJson } from "./api";
import { pick, type Bi } from "./copy";
import { FriendlyError, NoAccess, Notice, SectionCard, StatusPill, useConfirmAction, useKit, useUndoSnackbar } from "./kit";
import type { Language } from "./i18n";

/** Security › DNS & internal network: may package sources point at addresses inside your own network? */

type UpstreamPolicy = { allow_private_upstreams: boolean };

const COPY = {
  title: { fa: "منابع داخل شبکه خودتان", en: "Sources inside your own network" },
  hint: {
    fa: "به‌طور پیش‌فرض MRK فقط از آدرس‌های عمومی اینترنت بسته می‌گیرد تا کسی نتواند از راه پنل به سرویس‌های داخلی برسد.",
    en: "By default MRK only fetches packages from public internet addresses, so nobody can reach internal services through the panel."
  },
  label: { fa: "اجازه منابع داخل شبکه خودتان (مثل Nexus)", en: "Allow sources inside your network (such as Nexus)" },
  warning: {
    fa: "وقتی روشن است، هر «مدیری» می‌تواند از این راه به سرویس‌های داخلی شبکه دسترسی بگیرد. فقط اگر به همه مدیرها اعتماد دارید روشن کنید.",
    en: "When this is on, any admin can use it to reach services inside your network. Turn it on only if you trust every admin."
  },
  confirmTitle: { fa: "منابع داخل شبکه مجاز شوند؟", en: "Allow sources inside your network?" },
  confirmBody: {
    fa: "فقط وقتی روشن کنید که یک مخزن داخلی مطمئن (مثل Nexus) دارید.",
    en: "Turn this on only if you run a trusted internal registry (such as Nexus)."
  },
  consequence: { fa: "منابع دریافت می‌توانند به آدرس‌هایی مثل 192.168.x یا 10.x اشاره کنند.", en: "Package sources may point at addresses such as 192.168.x or 10.x." },
  allow: { fa: "بله، روشن کن", en: "Yes, turn on" },
  savedOn: { fa: "منابع داخل شبکه مجاز شدند.", en: "Sources inside your network are now allowed." },
  savedOff: { fa: "فقط منابع عمومی اینترنت مجازند.", en: "Only public internet sources are allowed." },
  on: { fa: "مجاز", en: "Allowed" },
  off: { fa: "فقط اینترنت", en: "Internet only" }
} satisfies Record<string, Bi>;

export function UpstreamPolicyCard({ canWrite }: { language?: Language; canWrite: boolean }) {
  const { language } = useKit();
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [policy, setPolicy] = useState<UpstreamPolicy | null>(null);
  const [unsupported, setUnsupported] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        setPolicy(await getJson<UpstreamPolicy>("/api/v1/settings/network/upstream-policy", controller.signal));
      } catch (caught) {
        if (isAbortError(caught)) return;
        if (caught instanceof ApiError && (caught.status === 404 || caught.status === 405)) {
          setUnsupported(true);
          return;
        }
        if (caught instanceof ApiError && caught.status === 401) return;
        setError(caught);
      }
    })();
    return () => controller.abort();
  }, []);

  if (unsupported) return null;

  const update = async (allow: boolean) => {
    if (allow) {
      const accepted = await ask({
        title: pick(language, COPY.confirmTitle),
        body: pick(language, COPY.confirmBody),
        consequences: [pick(language, COPY.consequence), pick(language, COPY.warning)],
        severity: "destructive",
        undoable: true,
        confirmLabel: pick(language, COPY.allow)
      });
      if (!accepted) return;
    }
    setSaving(true);
    setError(null);
    try {
      const payload = await mutateJson<UpstreamPolicy>("/api/v1/settings/network/upstream-policy", { method: "PUT", body: { allow_private_upstreams: allow } });
      setPolicy(payload && typeof payload.allow_private_upstreams === "boolean" ? payload : { allow_private_upstreams: allow });
      notify({ message: pick(language, allow ? COPY.savedOn : COPY.savedOff) });
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setSaving(false);
    }
  };

  const allowed = Boolean(policy?.allow_private_upstreams);
  return (
    <SectionCard
      title={pick(language, COPY.title)}
      hint={pick(language, COPY.hint)}
      status={policy ? <StatusPill tone={allowed ? "warn" : "ok"} label={pick(language, allowed ? COPY.on : COPY.off)} /> : undefined}
    >
      <Stack spacing={1.5}>
        {error !== null && <FriendlyError error={error} onClose={() => setError(null)} />}
        {policy && (
          <FormControlLabel
            control={<Switch checked={allowed} disabled={!canWrite || saving} onChange={(_event, value) => void update(value)} />}
            label={<Typography variant="body2" sx={{ fontWeight: 650 }}>{pick(language, COPY.label)}</Typography>}
          />
        )}
        <Notice tone="warning">{pick(language, COPY.warning)}</Notice>
        {!canWrite && <NoAccess needs="upstream:write" />}
      </Stack>
      {dialog}
      {snackbar}
    </SectionCard>
  );
}
