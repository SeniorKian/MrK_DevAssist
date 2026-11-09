/**
 * About (docs/33 §1.1 utilities): the "engineer's glance" moved off Home.
 * Version and build, how long Pishkar has been running, the state of each part, and the built-in protections.
 */
import { useCallback, useEffect, useState } from "react";
import { Box, Button, Skeleton, Stack, Typography } from "@mui/material";
import InfoRoundedIcon from "@mui/icons-material/InfoRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import packageMetadata from "../package.json";
import type { AuthUser } from "./App";
import { getJson, hasPermission } from "./api";
import { COMPONENT_LABELS, translate } from "./i18n";
import {
  FriendlyError, KeyValueList, Ltr, NoAccess, PageHeader, SectionCard, StatusPill, formatDuration, useKit, type KeyValueItem
} from "./kit";
import { pick, type Bi } from "./copy/text";
import { componentWord } from "./homeSummary";

type ComponentState = "ready" | "unavailable" | "not_configured" | "offline" | string;

type SystemStatus = {
  status?: string;
  version?: string;
  environment?: string;
  uptime_seconds?: number;
  build?: { commit?: string; built_at?: string; ui_version?: string };
  components?: Record<string, ComponentState>;
};

const COPY = {
  title: { fa: "درباره سامانه", en: "About" },
  subtitle: { fa: "نسخه، بخش‌های پیشکار و محافظت‌هایی که همیشه روشن‌اند.", en: "Version, the parts of Pishkar, and the protections that are always on." },
  versionCard: { fa: "نسخه و ساخت", en: "Version and build" },
  serverVersion: { fa: "نسخه سرور", en: "Server version" },
  panelVersion: { fa: "نسخه این پنل", en: "This panel's version" },
  runningFor: { fa: "مدت روشن بودن", en: "Running for" },
  builtAt: { fa: "زمان ساخت", en: "Built at" },
  partsCard: { fa: "بخش‌های پیشکار", en: "Parts of Pishkar" },
  partsHint: { fa: "آخرین وضعیتی که هر بخش گزارش داده است.", en: "The latest status each part reported." },
  protectionsCard: { fa: "محافظت‌های داخلی", en: "Built-in protections" },
  refresh: { fa: "تازه کردن", en: "Refresh" },
  registration: { fa: "ثبت‌نام عمومی", en: "Public sign-up" },
  registrationOpenHint: { fa: "هر کسی می‌تواند حساب «بیننده» بسازد. اگر لازم نیست، از بخش کاربران ببندید.", en: "Anyone can create a view-only account. Close it in People if you don't need it." }
} satisfies Record<string, Bi>;

const STATE_TO_STATUS: Record<string, string> = {
  ready: "ready",
  unavailable: "unavailable",
  offline: "offline",
  not_configured: "not_configured"
};

export default function AboutPage({ user }: { user: AuthUser }) {
  const { language, isAdvanced } = useKit();
  const say = (bi: Bi) => pick(language, bi);
  const canRead = hasPermission(user.permissions, "system:read");
  const canUsers = hasPermission(user.permissions, "user:read");
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [registrationOpen, setRegistrationOpen] = useState<boolean | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    if (!canRead) return;
    setError(null);
    try {
      setStatus(await getJson<SystemStatus>(`/api/v1/system/status?_=${Date.now()}`));
    } catch (problem) {
      setError(problem);
    }
    if (canUsers) {
      try {
        const payload = await getJson<{ enabled: boolean }>("/api/v1/settings/registration");
        setRegistrationOpen(Boolean(payload.enabled));
      } catch {
        setRegistrationOpen(null);
      }
    }
  }, [canRead, canUsers]);

  useEffect(() => void load(), [load]);

  const header = (
    <PageHeader
      title={say(COPY.title)}
      subtitle={say(COPY.subtitle)}
      icon={InfoRoundedIcon}
      secondaryActions={canRead ? <Button onClick={() => void load()} sx={{ minHeight: 40 }}>{say(COPY.refresh)}</Button> : undefined}
    />
  );

  if (!canRead) {
    return (
      <>
        {header}
        <SectionCard title={say(COPY.versionCard)}>
          <KeyValueList items={[{ label: say(COPY.panelVersion), value: <Ltr>{packageMetadata.version}</Ltr> }]} />
        </SectionCard>
        <Box sx={{ mt: 2 }}><NoAccess needs="system:read" variant="card" /></Box>
      </>
    );
  }

  const commit = status?.build?.commit && status.build.commit !== "unknown" ? status.build.commit.slice(0, 12) : null;
  const versionItems: KeyValueItem[] = [
    { label: say(COPY.serverVersion), value: <Ltr>{status?.version ?? "—"}</Ltr> },
    { label: say(COPY.panelVersion), value: <Ltr>{packageMetadata.version}</Ltr> },
    { label: say(COPY.runningFor), value: status?.uptime_seconds ? formatDuration(status.uptime_seconds, language) : translate(language, "justNow") },
    { label: translate(language, "environment"), value: <Ltr>{status?.environment ?? "—"}</Ltr>, advancedOnly: true },
    { label: translate(language, "commit"), value: <Ltr mono>{commit ?? "—"}</Ltr>, copy: commit ?? undefined, advancedOnly: true },
    { label: say(COPY.builtAt), value: <Ltr>{status?.build?.built_at ?? "—"}</Ltr>, advancedOnly: true }
  ];

  const components = Object.entries(status?.components ?? {});
  const knownOrder = Object.keys(COMPONENT_LABELS);
  components.sort(([a], [b]) => (knownOrder.indexOf(a) + 1 || 99) - (knownOrder.indexOf(b) + 1 || 99));

  const protections: { label: string; good: boolean; hint?: string }[] = [
    { label: translate(language, "nonRoot"), good: true },
    { label: translate(language, "readOnly"), good: true },
    { label: translate(language, "noPrivileges"), good: true }
  ];
  if (registrationOpen !== null) {
    protections.push({
      label: translate(language, registrationOpen ? "registrationOpen" : "registrationClosed"),
      good: !registrationOpen,
      hint: registrationOpen ? say(COPY.registrationOpenHint) : undefined
    });
  }

  return (
    <>
      {header}
      {error ? <Box sx={{ mb: 2 }}><FriendlyError error={error} onRetry={() => void load()} /></Box> : null}
      <Stack spacing={2.5}>
        <SectionCard title={say(COPY.versionCard)}>
          {status || error ? <KeyValueList items={versionItems} /> : <Skeleton variant="rounded" height={96} />}
        </SectionCard>

        <SectionCard title={say(COPY.partsCard)} hint={say(COPY.partsHint)}>
          {!status ? (
            <Skeleton variant="rounded" height={120} />
          ) : (
            <Stack divider={<Box sx={{ borderTop: 1, borderColor: "divider" }} />}>
              {components.map(([key, state]) => (
                <Stack key={key} direction="row" alignItems="center" justifyContent="space-between" spacing={1.5} sx={{ py: 1.25, minHeight: 44 }}>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="body2" fontWeight={650}>
                      {COMPONENT_LABELS[key] ? translate(language, COMPONENT_LABELS[key]) : componentWord(language, key)}
                    </Typography>
                    {isAdvanced && <Typography variant="caption" color="text.secondary"><Ltr mono>{key}</Ltr></Typography>}
                  </Box>
                  <StatusPill status={STATE_TO_STATUS[state] ?? state} />
                </Stack>
              ))}
            </Stack>
          )}
        </SectionCard>

        <SectionCard title={say(COPY.protectionsCard)} hint={translate(language, "securityHint")}>
          <Stack component="ul" spacing={1.25} sx={{ m: 0, p: 0, listStyle: "none" }}>
            {protections.map((item) => (
              <Stack component="li" key={item.label} direction="row" spacing={1.25} alignItems="flex-start">
                {item.good ? <CheckCircleRoundedIcon color="success" sx={{ fontSize: 20, mt: 0.2 }} aria-hidden /> : <WarningAmberRoundedIcon color="warning" sx={{ fontSize: 20, mt: 0.2 }} aria-hidden />}
                <Box>
                  <Typography variant="body2" fontWeight={620}>{item.label}</Typography>
                  {item.hint && <Typography variant="caption" color="text.secondary">{item.hint}</Typography>}
                </Box>
              </Stack>
            ))}
          </Stack>
        </SectionCard>
      </Stack>
    </>
  );
}
