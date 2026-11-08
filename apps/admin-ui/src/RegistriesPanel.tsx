import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Box, Button, CircularProgress, Grid, Stack, Typography } from "@mui/material";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import { ApiError, getJson, isAbortError } from "./api";
import { clientCommands } from "./clients";
import { usePublicServiceUrls } from "./services";
import { pick, say, type Bi } from "./copy";
import { CopyField, FriendlyError, HelpTip, KeyValueList, Ltr, Notice, SectionCard, StatusPill, useKit } from "./kit";
import type { Language } from "./i18n";

/**
 * Packages › «اتصال پروژه‌ها» (docs/33 §1.1, §4.2): copy-paste commands so npm, pip and uv install
 * from this server. Simple = the everyday clients; Advanced = every client, ports and network notes.
 */

type ComponentState = "ready" | "unavailable" | "not_configured" | "offline";
type RegistryStatus = { components: Record<string, ComponentState> };

const COPY = {
  intro: {
    fa: "این دستورها را یک بار در ترمینال پروژه یا سیستم خودتان اجرا کنید. از آن به بعد بسته‌ها از همین سرور نصب می‌شوند.",
    en: "Run these commands once in your project or on your computer. From then on, packages install from this server."
  },
  address: { fa: "آدرس مخزن", en: "Registry address" },
  commandFor: { fa: "دستور برای {client}", en: "Command for {client}" },
  oneTime: { fa: "فقط یک بار لازم است.", en: "You only need to do this once." },
  moreClients: { fa: "ابزارهای دیگر را در حالت پیشرفته ببینید.", en: "Other tools are listed in Advanced mode." },
  npmHint: { fa: "برای پروژه‌های جاوااسکریپت و تایپ‌اسکریپت.", en: "For JavaScript and TypeScript projects." },
  pypiHint: { fa: "برای پروژه‌های پایتون.", en: "For Python projects." },
  stateReady: { fa: "آماده", en: "Ready" },
  stateDown: { fa: "از کار افتاده", en: "Down" },
  stateOffline: { fa: "بدون اینترنت", en: "Offline" },
  stateNotSet: { fa: "هنوز تنظیم نشده", en: "Not set up yet" },
  offlineNote: {
    fa: "این مخزن در حالت بدون اینترنت است؛ فقط بسته‌هایی که قبلاً ذخیره شده‌اند نصب می‌شوند.",
    en: "This registry is in offline mode; only packages already stored here will install."
  },
  downNote: {
    fa: "این مخزن الان جواب نمی‌دهد. «منابع دریافت» را بررسی کنید.",
    en: "This registry isn't answering right now. Check “Package sources”."
  },
  openSources: { fa: "منابع دریافت", en: "Package sources" },
  portNote: {
    fa: "این آدرس‌ها بدون اتصال امن کار می‌کنند. برای استفاده از بیرون سرور، یک دامنه با HTTPS بدهید.",
    en: "These addresses don't use a secure connection. To use them from outside the server, give them a domain with HTTPS."
  },
  networkTitle: { fa: "پورت‌ها و شبکه", en: "Ports and network" },
  networkHint: { fa: "برای کسی که سرور جلویی (مثل Traefik) را تنظیم می‌کند.", en: "For whoever sets up the front server (such as Traefik)." },
  npmPort: { fa: "پورت npm", en: "npm port" },
  pypiPort: { fa: "پورت PyPI", en: "PyPI port" },
  panelPort: { fa: "پورت پنل", en: "Panel port" },
  derived: {
    fa: "آدرس‌ها از آدرس همین پنل ساخته شده‌اند. اگر مخزن‌ها دامنه جدا دارند، آن را جایگزین کنید.",
    en: "These addresses are built from this panel's address. If the registries have their own domains, use those instead."
  },
  proxyNote: {
    fa: "در سرور جلویی (reverse proxy) فقط پورت‌های ۸۰۸۰، ۴۸۷۳ و ۳۱۴۱ را به دامنه‌های عمومی وصل کنید. پورت پایگاه داده هیچ‌وقت بیرون داده نمی‌شود.",
    en: "In your reverse proxy, connect only ports 8080, 4873 and 3141 to public domains. The database port is never exposed."
  },
  allClients: { fa: "همه ابزارها", en: "All tools" },
  helpRegistry: {
    fa: "مخزن بسته جایی است که npm یا pip بسته‌ها را از آن نصب می‌کنند. با این دستورها، آن‌ها به جای اینترنت از این سرور نصب می‌کنند.",
    en: "A registry is where npm or pip install packages from. These commands make them install from this server instead of the internet."
  }
} satisfies Record<string, Bi>;

function statePill(state: ComponentState | undefined, language: Language) {
  if (state === "ready") return <StatusPill tone="ok" label={pick(language, COPY.stateReady)} />;
  if (state === "unavailable") return <StatusPill tone="error" label={pick(language, COPY.stateDown)} />;
  if (state === "offline") return <StatusPill tone="off" label={pick(language, COPY.stateOffline)} />;
  return <StatusPill tone="off" label={pick(language, COPY.stateNotSet)} />;
}

/** The «اتصال پروژه‌ها» tab. */
export function ConnectTab() {
  const { language, isAdvanced, c } = useKit();
  const [status, setStatus] = useState<RegistryStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      setStatus(await getJson<RegistryStatus>("/api/v1/system/status", current.signal));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const publicUrls = usePublicServiceUrls();
  const { endpoints, commands } = useMemo(() => clientCommands(publicUrls), [publicUrls.npm, publicUrls.pypi]); // eslint-disable-line react-hooks/exhaustive-deps
  const registries = [
    { key: "npm_registry", ecosystem: "npm" as const, name: "npm", endpoint: endpoints.npm, hint: COPY.npmHint },
    { key: "pypi_registry", ecosystem: "pypi" as const, name: "PyPI", endpoint: endpoints.pypi, hint: COPY.pypiHint }
  ];

  return (
    <Stack spacing={2.5}>
      <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
        <Stack direction="row" spacing={0.5} alignItems="center">
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{pick(language, COPY.intro)}</Typography>
          <HelpTip>{pick(language, COPY.helpRegistry)}</HelpTip>
        </Stack>
        <Button size="small" onClick={() => void load()} disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} sx={{ flexShrink: 0, minHeight: 44 }}>
          {c.refresh}
        </Button>
      </Stack>

      {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
      {endpoints.portBased && <Notice tone="warning">{pick(language, COPY.portNote)}</Notice>}

      <Grid container spacing={2}>
        {registries.map((registry) => {
          const state = status?.components[registry.key];
          const visible = commands.filter((command) => command.ecosystem === registry.ecosystem && (isAdvanced || command.everyday));
          return (
            <Grid key={registry.key} size={{ xs: 12, lg: 6 }}>
              <SectionCard title={registry.name} hint={pick(language, registry.hint)} status={statePill(state, language)}>
                <Stack spacing={1.5}>
                  {state === "offline" && <Notice>{pick(language, COPY.offlineNote)}</Notice>}
                  {state === "unavailable" && (
                    <Notice tone="error" action={<Button color="inherit" size="small" href="#/packages/sources">{pick(language, COPY.openSources)}</Button>}>
                      {pick(language, COPY.downNote)}
                    </Notice>
                  )}
                  <CopyField label={pick(language, COPY.address)} value={registry.endpoint} />
                  {visible.map((command) => (
                    <CopyField
                      key={command.label}
                      label={say(language, COPY.commandFor, { client: command.label })}
                      value={command.command}
                      multiline={command.command.length > 70}
                    />
                  ))}
                  <Typography variant="caption" color="text.secondary">
                    {pick(language, COPY.oneTime)} {!isAdvanced && pick(language, COPY.moreClients)}
                  </Typography>
                </Stack>
              </SectionCard>
            </Grid>
          );
        })}
      </Grid>

      <SectionCard advanced title={pick(language, COPY.networkTitle)} hint={pick(language, COPY.networkHint)}>
        <Stack spacing={1.5}>
          <KeyValueList
            items={[
              { label: pick(language, COPY.npmPort), value: <Ltr mono>4873</Ltr> },
              { label: pick(language, COPY.pypiPort), value: <Ltr mono>3141</Ltr> },
              { label: pick(language, COPY.panelPort), value: <Ltr mono>8080</Ltr> }
            ]}
          />
          {!publicUrls.npm && !publicUrls.pypi && <Notice>{pick(language, COPY.derived)}</Notice>}
          <Notice>{pick(language, COPY.proxyNote)}</Notice>
        </Stack>
      </SectionCard>
    </Stack>
  );
}

/** Legacy entry point (old `#registries` page); the shell now mounts PackagesPage. */
export function RegistriesPanel(_props: { language?: Language; onUnauthorized?: () => void }) {
  return <ConnectTab />;
}
