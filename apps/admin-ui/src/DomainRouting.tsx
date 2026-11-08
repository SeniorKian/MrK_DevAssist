/**
 * «مسیریابی دامنه» (docs/35 §2): how domains reach MRK's services through Dokploy/Traefik.
 * Advanced only. Shows what was detected on this server, the current mode, lets an admin change it,
 * and lists the copyable guidance snippets from `GET /api/v1/domains/routing`.
 */
import { useCallback, useEffect, useState } from "react";
import { Box, Button, CircularProgress, Stack, Typography } from "@mui/material";
import { hasPermission } from "./api";
import { pick, say, type Bi } from "./copy";
import { ChoiceCards, CopyField, FriendlyError, KeyValueList, Ltr, NoAccess, Notice, SectionCard, StatusPill, useKit, type ChoiceCardOption } from "./kit";
import {
  ROUTING_MODE_WORDS, effectiveMode, fetchRouting, modeAvailable, routingModeWord, setRoutingMode,
  type RoutingChoice, type RoutingInfo, type RoutingSummary
} from "./services";

const COPY = {
  title: { fa: "مسیریابی دامنه", en: "Domain routing" },
  hint: {
    fa: "دامنه‌ها از راه Dokploy به سرویس‌ها می‌رسند. این‌جا می‌بینید MRK روی این سرور چه چیزی پیدا کرده و از چه روشی استفاده می‌کند.",
    en: "Domains reach your services through Dokploy. Here you see what MRK found on this server and which way it uses."
  },
  detectedTitle: { fa: "چیزهایی که روی این سرور پیدا شد", en: "What was found on this server" },
  insideDokploy: { fa: "MRK داخل Dokploy نصب است", en: "MRK runs inside Dokploy" },
  dokployConnected: { fa: "اتصال Dokploy برقرار است", en: "Dokploy is connected" },
  dokployProject: { fa: "پروژه MRK در Dokploy", en: "MRK's Dokploy project" },
  dokployService: { fa: "سرویس MRK در Dokploy", en: "MRK's Dokploy service" },
  traefikDir: { fa: "پوشه تنظیمات Traefik در دسترس است", en: "The Traefik settings folder is reachable" },
  onNetwork: { fa: "MRK عضو شبکه «dokploy-network» است", en: "MRK is on the \"dokploy-network\" network" },
  serverIps: { fa: "نشانی‌های این سرور", en: "This server's addresses" },
  yes: { fa: "بله", en: "Yes" },
  no: { fa: "نه", en: "No" },
  unknown: { fa: "نامشخص", en: "Unknown" },
  currentMode: { fa: "روش فعلی", en: "Current way" },
  autoNow: { fa: "{mode} (الان: {effective})", en: "{mode} (now: {effective})" },
  changeTitle: { fa: "تغییر روش", en: "Change the way" },
  changeLabel: { fa: "روش اتصال دامنه‌ها", en: "How domains connect" },
  notAvailable: { fa: "روی این سرور در دسترس نیست", en: "Not available on this server" },
  save: { fa: "ذخیره روش", en: "Save the way" },
  saved: { fa: "روش اتصال دامنه‌ها ذخیره شد. دامنه‌های تازه با این روش وصل می‌شوند.", en: "Saved. New domains will connect this way." },
  existingNote: { fa: "دامنه‌هایی که قبلاً اضافه شده‌اند همان روش قبلی خود را نگه می‌دارند.", en: "Domains added before keep the way they were added with." },
  guidesTitle: { fa: "راهنمای آماده‌سازی", en: "Setup guides" },
  guidesHint: { fa: "اگر می‌خواهید روش خودکارتری در دسترس باشد، این تکه‌ها را در فایل Compose بگذارید.", en: "To make a more automatic way available, put these pieces in your Compose file." },
  guideFallback: { fa: "راهنما {n}", en: "Guide {n}" },
  noGuides: { fa: "راهنمای دیگری لازم نیست.", en: "No extra setup is needed." }
} satisfies Record<string, Bi>;

const SNIPPET_TITLES: Record<string, Bi> = {
  network: { fa: "پیوستن به شبکه Dokploy", en: "Join the Dokploy network" },
  join_network: { fa: "پیوستن به شبکه Dokploy", en: "Join the Dokploy network" },
  dokploy_network: { fa: "پیوستن به شبکه Dokploy", en: "Join the Dokploy network" },
  traefik_mount: { fa: "دسترسی دستیار سرور به پوشه Traefik", en: "Give the server helper the Traefik folder" },
  mount: { fa: "دسترسی دستیار سرور به پوشه Traefik", en: "Give the server helper the Traefik folder" },
  traefik_dir: { fa: "دسترسی دستیار سرور به پوشه Traefik", en: "Give the server helper the Traefik folder" },
  compose_template: { fa: "نصب MRK به‌صورت Compose داخل Dokploy", en: "Install MRK as a Compose project in Dokploy" },
  dokploy_compose: { fa: "نصب MRK به‌صورت Compose داخل Dokploy", en: "Install MRK as a Compose project in Dokploy" },
  install: { fa: "نصب MRK به‌صورت Compose داخل Dokploy", en: "Install MRK as a Compose project in Dokploy" }
};

const MODES: RoutingChoice[] = ["auto", "dokploy_api", "traefik_file", "manual"];

export type DomainRoutingProps = {
  permissions: readonly string[];
  /** The routing block from `GET /api/v1/services` (used until the full routing info loads). */
  summary: RoutingSummary | null;
  onChanged: () => void;
  /** Lets the page share `available_modes` with the add-domain wizard. */
  onLoaded?: (info: RoutingInfo) => void;
};

export function DomainRouting({ permissions, summary, onChanged, onLoaded }: DomainRoutingProps) {
  const { language } = useKit();
  const canRead = hasPermission(permissions, "domains:read");
  const canWrite = hasPermission(permissions, "domains:write");
  const [info, setInfo] = useState<RoutingInfo | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [choice, setChoice] = useState<RoutingChoice | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [savedNote, setSavedNote] = useState(false);

  const load = useCallback(async () => {
    if (!canRead) return;
    try {
      const next = await fetchRouting();
      setInfo(next);
      setError(null);
      onLoaded?.(next);
    } catch (caught) {
      setError(caught);
    }
  }, [canRead, onLoaded]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!canRead) {
    return (
      <SectionCard advanced title={pick(language, COPY.title)}>
        <NoAccess needs="domains:read" variant="card" />
      </SectionCard>
    );
  }

  const routing: RoutingSummary = info ?? summary ?? {};
  const detected = routing.detected ?? {};
  const configured = (routing.mode ?? "auto") as RoutingChoice;
  const effective = effectiveMode(routing);
  const selected = choice ?? (MODES.includes(configured) ? configured : "auto");

  const flag = (value: boolean | null | undefined) =>
    value === true ? <StatusPill tone="ok" label={pick(language, COPY.yes)} /> : value === false ? <StatusPill tone="off" label={pick(language, COPY.no)} /> : <StatusPill tone="off" label={pick(language, COPY.unknown)} />;

  const options: ChoiceCardOption<RoutingChoice>[] = MODES.map((key) => {
    const available = modeAvailable(key, detected, info?.available_modes);
    return {
      key,
      title: pick(language, ROUTING_MODE_WORDS[key].label),
      body: pick(language, ROUTING_MODE_WORDS[key].body),
      disabled: !available || !canWrite,
      badges: available ? undefined : <StatusPill tone="off" label={pick(language, COPY.notAvailable)} />
    };
  });

  const save = async () => {
    setSaving(true);
    setSaveError(null);
    setSavedNote(false);
    try {
      await setRoutingMode(selected);
      setChoice(null);
      setSavedNote(true);
      await load();
      onChanged();
    } catch (caught) {
      setSaveError(caught);
    } finally {
      setSaving(false);
    }
  };

  const ips = (detected.server_ips ?? []).filter(Boolean);
  const snippets = info?.snippets ?? [];

  return (
    <SectionCard advanced title={pick(language, COPY.title)} hint={pick(language, COPY.hint)}>
      <Stack spacing={2.5} id="mrk-domain-routing">
        {error !== null ? <FriendlyError error={error} scope="domains" onRetry={() => void load()} /> : null}

        <Box>
          <Typography variant="subtitle2" sx={{ fontWeight: 760, mb: 1 }}>{pick(language, COPY.detectedTitle)}</Typography>
          <KeyValueList
            dense
            items={[
              { label: pick(language, COPY.insideDokploy), value: flag(detected.inside_dokploy) },
              { label: pick(language, COPY.dokployConnected), value: flag(detected.dokploy_connected) },
              ...(detected.dokploy_project ? [{ label: pick(language, COPY.dokployProject), value: detected.dokploy_project, ltr: true, copy: true }] : []),
              ...(detected.dokploy_service ? [{ label: pick(language, COPY.dokployService), value: detected.dokploy_service, ltr: true, copy: true }] : []),
              { label: pick(language, COPY.traefikDir), value: flag(detected.traefik_dir_available) },
              { label: pick(language, COPY.onNetwork), value: flag(detected.on_dokploy_network) },
              ...(ips.length ? [{ label: pick(language, COPY.serverIps), value: <Ltr mono>{ips.join(", ")}</Ltr>, copy: ips.join(", ") }] : [])
            ]}
          />
        </Box>

        <KeyValueList
          items={[
            {
              label: pick(language, COPY.currentMode),
              value:
                configured === "auto"
                  ? say(language, COPY.autoNow, { mode: routingModeWord(language, "auto"), effective: routingModeWord(language, effective) })
                  : routingModeWord(language, configured)
            }
          ]}
        />

        <Box>
          <Typography variant="subtitle2" sx={{ fontWeight: 760, mb: 1 }}>{pick(language, COPY.changeTitle)}</Typography>
          <ChoiceCards options={options} value={selected} onChange={(key) => { setChoice(key); setSavedNote(false); }} label={pick(language, COPY.changeLabel)} />
          <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 1 }}>{pick(language, COPY.existingNote)}</Typography>
          {canWrite ? (
            <Box sx={{ mt: 1.5 }}>
              <Button
                variant="contained"
                onClick={() => void save()}
                disabled={saving || selected === configured}
                startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined}
                sx={{ minHeight: 44 }}
              >
                {pick(language, COPY.save)}
              </Button>
            </Box>
          ) : (
            <Box sx={{ mt: 1 }}><NoAccess needs="domains:write" /></Box>
          )}
          {saveError !== null ? <Box sx={{ mt: 1.5 }}><FriendlyError error={saveError} scope="domains" noAction /></Box> : null}
          {savedNote ? <Box sx={{ mt: 1.5 }}><Notice tone="success">{pick(language, COPY.saved)}</Notice></Box> : null}
        </Box>

        <Box>
          <Typography variant="subtitle2" sx={{ fontWeight: 760, mb: 0.5 }}>{pick(language, COPY.guidesTitle)}</Typography>
          {snippets.length ? (
            <Stack spacing={1.5}>
              <Typography variant="body2" color="text.secondary">{pick(language, COPY.guidesHint)}</Typography>
              {snippets.map((snippet, index) => {
                const title = snippet.title ?? SNIPPET_TITLES[snippet.key] ?? null;
                return (
                  <CopyField
                    key={snippet.key}
                    label={title ? pick(language, title) : say(language, COPY.guideFallback, { n: index + 1 })}
                    value={snippet.content}
                    multiline
                    helperText={snippet.hint ? pick(language, snippet.hint) : undefined}
                  />
                );
              })}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">{pick(language, COPY.noGuides)}</Typography>
          )}
        </Box>
      </Stack>
    </SectionCard>
  );
}
