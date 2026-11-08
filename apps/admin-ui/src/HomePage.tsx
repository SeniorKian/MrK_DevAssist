/**
 * Home (docs/33 §1.2): "only what needs you".
 * Greeting + verdict · needs attention (from GET /api/v1/home) · quick actions · getting-started
 * checklist (dismiss via PATCH /api/v1/home/checklist) · two small "at a glance" tiles.
 * The engineer's view (versions, components, protections) lives on About.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Skeleton, Stack, Tab, Tabs, Typography, useMediaQuery, useTheme
} from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import BackupRoundedIcon from "@mui/icons-material/BackupRounded";
import PersonAddAltRoundedIcon from "@mui/icons-material/PersonAddAltRounded";
import SystemUpdateAltRoundedIcon from "@mui/icons-material/SystemUpdateAltRounded";
import QueryStatsRoundedIcon from "@mui/icons-material/QueryStatsRounded";
import AppsRoundedIcon from "@mui/icons-material/AppsRounded";
import LanguageRoundedIcon from "@mui/icons-material/LanguageRounded";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import InfoRoundedIcon from "@mui/icons-material/InfoRounded";
import type { AuthUser } from "./App";
import { getJson, hasPermission } from "./api";
import { clientCommands } from "./clients";
import { usePublicServiceUrls } from "./services";
import type { Language } from "./i18n";
import {
  AttentionList, ChecklistCard, CopyField, FriendlyError, Notice, QuickActionGrid, QuickActionTile, SectionCard, StatGrid, StatTile, Verdict,
  formatSize, formatWithUnit, useKit, type AttentionItem, type ChecklistStep
} from "./kit";
import { fill, pick, type Bi } from "./copy/text";
import { CHECKLIST_COPY, QUICK_ACTION_COPY, attentionText, refreshHome, updateChecklist, useHomeSummary } from "./homeSummary";

const COPY = {
  hello: { fa: "سلام {name}", en: "Hi {name}" },
  helloPlain: { fa: "سلام", en: "Hi" },
  allGood: { fa: "همه‌چیز خوب است ✓", en: "Everything is fine ✓" },
  needsYou: { fa: "{n} مورد نیاز به توجه دارد", en: "{n} things need your attention" },
  needsYouOne: { fa: "یک مورد نیاز به توجه دارد", en: "One thing needs your attention" },
  checking: { fa: "در حال بررسی وضعیت…", en: "Checking how things are…" },
  attentionTitle: { fa: "نیاز به توجه", en: "Needs attention" },
  quickTitle: { fa: "کارهای سریع", en: "Quick actions" },
  glanceTitle: { fa: "یک نگاه", en: "At a glance" },
  packagesTile: { fa: "مخزن‌های بسته", en: "Package registries" },
  packagesReady: { fa: "{ready} از {total} آماده", en: "{ready} of {total} ready" },
  packagesAllReady: { fa: "npm و PyPI آماده‌اند", en: "npm and PyPI are ready" },
  packagesSomeDown: { fa: "یکی از مخزن‌ها کار نمی‌کند", en: "One registry isn't working" },
  diskTile: { fa: "فضای دیسک", en: "Disk space" },
  diskCaption: { fa: "{used} از {total} پر شده", en: "{used} of {total} used" },
  showChecklist: { fa: "نمایش دوباره فهرست راه‌اندازی", en: "Show the setup checklist again" },
  checklistTitle: { fa: "راه‌اندازی در {n} قدم", en: "Set up in {n} steps" },
  checklistSaveFailed: { fa: "پنهان کردن فهرست ذخیره نشد. دوباره امتحان کنید.", en: "Hiding the checklist wasn't saved. Try again." },
  history: { fa: "تاریخچه فعالیت", en: "Activity history" },
  historyHint: { fa: "چه کسی، چه زمانی، چه کاری کرد.", en: "Who did what, and when." },
  about: { fa: "جزئیات فنی سامانه", en: "Technical details" },
  aboutHint: { fa: "نسخه، بخش‌ها و محافظت‌های داخلی.", en: "Version, parts and built-in protections." },
  connectTitle: { fa: "وصل کردن یک پروژه", en: "Connect a project" },
  connectHint: {
    fa: "این دستور را یک بار در پروژه یا رایانه خودتان اجرا کنید تا بسته‌ها از همین سرور نصب شوند.",
    en: "Run this once in your project or on your computer so packages install from this server."
  },
  connectMore: { fa: "دستورهای بیشتر", en: "More commands" },
  close: { fa: "بستن", en: "Close" },
  command: { fa: "دستور", en: "Command" }
} satisfies Record<string, Bi>;

const QUICK_ICONS: Record<string, SvgIconComponent> = {
  connect_project: TerminalRoundedIcon,
  search_package: SearchRoundedIcon,
  backup_now: BackupRoundedIcon,
  invite_teammate: PersonAddAltRoundedIcon,
  check_updates: SystemUpdateAltRoundedIcon,
  view_server_usage: QueryStatsRoundedIcon,
  my_services: AppsRoundedIcon,
  add_domain: LanguageRoundedIcon
};

type SystemStatus = {
  storage?: { total_bytes: number; used_bytes: number; free_bytes: number; used_percent: number };
  components?: Record<string, string>;
};

function useSystemStatus(enabled: boolean) {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const load = useCallback(async () => {
    if (!enabled) return;
    try {
      setStatus(await getJson<SystemStatus>(`/api/v1/system/status?_=${Date.now()}`));
    } catch {
      setStatus(null);
    }
  }, [enabled]);
  useEffect(() => {
    void load();
    if (!enabled) return;
    const timer = window.setInterval(() => document.visibilityState === "visible" && void load(), 60_000);
    return () => window.clearInterval(timer);
  }, [enabled, load]);
  return status;
}

function ConnectDialog({ open, language, onClose }: { open: boolean; language: Language; onClose: () => void }) {
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const publicUrls = usePublicServiceUrls();
  const { commands } = useMemo(() => clientCommands(publicUrls), [publicUrls.npm, publicUrls.pypi]); // eslint-disable-line react-hooks/exhaustive-deps
  const everyday = commands.filter((item) => item.everyday);
  const [index, setIndex] = useState(0);
  const current = everyday[Math.min(index, everyday.length - 1)];
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm" fullScreen={fullScreen} aria-labelledby="mrk-connect-title">
      <DialogTitle id="mrk-connect-title" sx={{ fontWeight: 760 }}>{pick(language, COPY.connectTitle)}</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{pick(language, COPY.connectHint)}</Typography>
        <Tabs value={index} onChange={(_event, value: number) => setIndex(value)} variant="fullWidth" sx={{ mb: 2, minHeight: 44 }}>
          {everyday.map((client) => <Tab key={client.label} label={client.label} sx={{ minHeight: 44 }} />)}
        </Tabs>
        {current && <CopyField label={pick(language, COPY.command)} value={current.command} multiline />}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2.5, gap: 1 }}>
        <Button href="#/packages/connect" onClick={onClose} sx={{ minHeight: 44 }}>{pick(language, COPY.connectMore)}</Button>
        <Button variant="contained" onClick={onClose} sx={{ minHeight: 44 }}>{pick(language, COPY.close)}</Button>
      </DialogActions>
    </Dialog>
  );
}

export default function HomePage({ user }: { user: AuthUser }) {
  const { language, isAdvanced } = useKit();
  const say = (bi: Bi, params?: Record<string, string | number | null>) => fill(pick(language, bi), params, language);
  const home = useHomeSummary();
  const [connectOpen, setConnectOpen] = useState(false);
  const [checklistError, setChecklistError] = useState<unknown>(null);
  const canSystem = hasPermission(user.permissions, "system:read");
  const canServices = hasPermission(user.permissions, "services:read") || hasPermission(user.permissions, "domains:read");
  const status = useSystemStatus(canSystem);
  const data = home.data;

  useEffect(() => {
    void refreshHome();
  }, []);

  const firstName = (user.display_name || user.username || "").trim().split(/\s+/)[0];
  const greeting = firstName ? say(COPY.hello, { name: firstName }) : say(COPY.helloPlain);

  const attention: AttentionItem[] = (data?.attention ?? []).map((item) => {
    const text = attentionText(language, item);
    return { id: item.id, severity: text.severity, title: text.title, why: text.why, action: { label: text.button, href: text.route ?? "#/home" } };
  });
  const count = data?.verdict?.count ?? attention.length;
  const tone = !data ? "ok" : data.verdict.level === "problem" ? "error" : data.verdict.level === "attention" ? "warn" : count > 0 ? "warn" : "ok";
  const verdict = !data ? say(COPY.checking) : count === 0 ? say(COPY.allGood) : count === 1 ? say(COPY.needsYouOne) : say(COPY.needsYou, { n: count });

  const quick = (data?.quick_actions ?? []).filter((item) => QUICK_ACTION_COPY[item.id]);
  // docs/35: «سرویس‌های من» is one tap from Home even when the server does not list it yet.
  if (canServices && !quick.some((item) => item.id === "my_services")) quick.unshift({ id: "my_services", route: "#/services" });

  const steps: ChecklistStep[] = (data?.checklist ?? []).map((step) => ({
    key: step.id,
    label: CHECKLIST_COPY[step.id]?.[language] ?? step.id,
    done: step.done,
    optional: step.optional,
    onClick: step.route ? () => (window.location.hash = step.route!) : undefined
  }));
  const checklistIncomplete = steps.some((step) => !step.done);
  const dismissed = Boolean(data?.checklist_dismissed);

  const setDismissed = async (value: boolean) => {
    setChecklistError(null);
    try {
      await updateChecklist({ dismissed: value });
    } catch (error) {
      setChecklistError(error);
    }
  };

  // ── glance
  const components = status?.components ?? {};
  const registries = ["npm_registry", "pypi_registry"].filter((key) => components[key] && components[key] !== "not_configured");
  const ready = registries.filter((key) => components[key] === "ready").length;
  const storage = status?.storage;

  return (
    <Stack spacing={3}>
      <Box sx={{ pt: { xs: 0.5, sm: 0 } }}>
        <Verdict greeting={greeting} verdict={verdict} tone={tone} />
      </Box>

      {home.error && !data ? (
        <FriendlyError error={home.error} onRetry={() => void refreshHome()} />
      ) : !data ? (
        <Stack spacing={1.5}>
          <Skeleton variant="rounded" height={88} />
          <Skeleton variant="rounded" height={180} />
        </Stack>
      ) : (
        <>
          <AttentionList items={attention} title={say(COPY.attentionTitle)} />

          {quick.length > 0 && (
            <Box component="section" aria-labelledby="mrk-quick-title">
              <Typography id="mrk-quick-title" component="h2" variant="subtitle1" sx={{ fontWeight: 760, mb: 1.25 }}>{say(COPY.quickTitle)}</Typography>
              <QuickActionGrid>
                {quick.map((item) => {
                  const copy = QUICK_ACTION_COPY[item.id];
                  const Icon = QUICK_ICONS[item.id] ?? InfoRoundedIcon;
                  return item.id === "connect_project" ? (
                    <QuickActionTile key={item.id} icon={Icon} label={copy.label[language]} hint={copy.hint[language]} onClick={() => setConnectOpen(true)} />
                  ) : (
                    <QuickActionTile key={item.id} icon={Icon} label={copy.label[language]} hint={copy.hint[language]} href={item.route} />
                  );
                })}
              </QuickActionGrid>
            </Box>
          )}

          {checklistError ? <FriendlyError error={checklistError} title={say(COPY.checklistSaveFailed)} noAction onClose={() => setChecklistError(null)} /> : null}
          {!dismissed && checklistIncomplete && (
            <ChecklistCard
              steps={steps}
              title={say(COPY.checklistTitle, { n: steps.length })}
              onDismiss={() => void setDismissed(true)}
            />
          )}
          {dismissed && checklistIncomplete && (
            <Box>
              <Button size="small" onClick={() => void setDismissed(false)} sx={{ minHeight: 40 }}>{say(COPY.showChecklist)}</Button>
            </Box>
          )}
        </>
      )}

      {canSystem && status && (
        <Box component="section" aria-labelledby="mrk-glance-title">
          <Typography id="mrk-glance-title" component="h2" variant="subtitle1" sx={{ fontWeight: 760, mb: 1.25 }}>{say(COPY.glanceTitle)}</Typography>
          <StatGrid columns={2}>
            {registries.length > 0 && (
              <StatTile
                label={say(COPY.packagesTile)}
                icon={Inventory2RoundedIcon}
                value={ready === registries.length && registries.length === 2 ? say(COPY.packagesAllReady) : say(COPY.packagesReady, { ready, total: registries.length })}
                caption={ready < registries.length ? say(COPY.packagesSomeDown) : undefined}
                tone={ready === registries.length ? "ok" : "error"}
                href="#/packages/sources"
              />
            )}
            {storage && (
              <StatTile
                label={say(COPY.diskTile)}
                icon={StorageRoundedIcon}
                value={formatWithUnit(Math.round(storage.used_percent), "percent", language)}
                caption={say(COPY.diskCaption, { used: formatSize(storage.used_bytes, language), total: formatSize(storage.total_bytes, language) })}
                meter={storage.used_percent}
                tone={storage.used_percent >= 90 ? "error" : storage.used_percent >= 80 ? "warn" : "ok"}
                href="#/files/health"
              />
            )}
          </StatGrid>
        </Box>
      )}

      {isAdvanced && (
        <SectionCard title={say(COPY.about)} hint={say(COPY.aboutHint)} action={<Button href="#/about" startIcon={<InfoRoundedIcon />}>{say(COPY.about)}</Button>}>
          {hasPermission(user.permissions, "audit:read") ? (
            <Notice action={<Button href="#/alerts/history" startIcon={<HistoryRoundedIcon />} color="inherit">{say(COPY.history)}</Button>}>
              {say(COPY.historyHint)}
            </Notice>
          ) : null}
        </SectionCard>
      )}

      <ConnectDialog open={connectOpen} language={language} onClose={() => setConnectOpen(false)} />
    </Stack>
  );
}
