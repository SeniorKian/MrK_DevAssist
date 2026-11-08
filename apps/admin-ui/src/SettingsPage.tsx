/**
 * All settings (docs/33 §4.3, docs/34 §3).
 *
 * - "My preferences" (language, colours, display mode, my password) for everyone.
 * - The complete server settings registry (GET /api/v1/settings/registry), grouped like the nav,
 *   rendered by kit SettingsForm: search + filter chips, per-item save (PUT) and reset to default
 *   (DELETE), a restart-pending banner (GET …/restart), Compose-only rows read-only with their
 *   Compose line, and an explanation when a Compose value locks a setting.
 * - Older servers without the registry (404) see the documented fixture, read-only.
 * Loading, saving and the restart banner come from the kit (`useRegistrySettings`, `RestartNotice`).
 * Deep link: `#/settings?group=<group id>`.
 */
import { useMemo, useState } from "react";
import {
  Box, Button, Chip, List, ListItemButton, ListItemText, Skeleton, Stack, ToggleButton, ToggleButtonGroup, Typography, useMediaQuery, useTheme
} from "@mui/material";
import SettingsRoundedIcon from "@mui/icons-material/SettingsRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import type { AuthUser } from "./App";
import type { Language } from "./i18n";
import { FriendlyError, Notice, PageHeader, RestartNotice, SectionCard, SettingsForm, UiModeToggle, useKit, useRegistrySettings } from "./kit";
import { hashQuery } from "./nav";
import { fill, pick, type Bi } from "./copy/text";

// ── Copy ─────────────────────────────────────────────────────────────────────

const COPY = {
  title: { fa: "همه تنظیمات", en: "All settings" },
  subtitle: { fa: "تنظیمات خودتان و همه ریزتنظیمات سرور، یک‌جا.", en: "Your own preferences and every server setting, in one place." },
  mine: { fa: "ترجیح‌های من", en: "My preferences" },
  mineHint: { fa: "فقط روی پنل خودتان اثر دارد.", en: "These only change how the panel looks for you." },
  language: { fa: "زبان", en: "Language" },
  colours: { fa: "رنگ صفحه", en: "Colours" },
  light: { fa: "روشن", en: "Light" },
  dark: { fa: "تیره", en: "Dark" },
  mode: { fa: "حالت نمایش", en: "Display mode" },
  modeHint: { fa: "«ساده» کارهای روزمره را نشان می‌دهد؛ «پیشرفته» همه‌چیز را.", en: "Simple shows everyday tasks; Advanced shows everything." },
  password: { fa: "رمز من", en: "My password" },
  changePassword: { fa: "تغییر رمز", en: "Change password" },
  serverTitle: { fa: "تنظیمات سرور", en: "Server settings" },
  serverHint: {
    fa: "ریزترین تنظیم هر بخش این‌جاست؛ با مقدار پیش‌فرض، بازه مجاز و این‌که از کجا تنظیم می‌شود.",
    en: "Every setting of every part is here, with its default, allowed range and where it is set."
  },
  simpleIntro: {
    fa: "این تنظیمات بیشتر برای مسئول فنی است. کارهای روزمره را از خود بخش‌ها انجام دهید.",
    en: "These are mostly for the technical person in charge. Do everyday tasks from each section."
  },
  showAll: { fa: "نمایش تنظیمات سرور", en: "Show server settings" },
  goAdvanced: { fa: "رفتن به حالت پیشرفته", en: "Switch to Advanced" },
  groups: { fa: "بخش‌ها", en: "Sections" },
  allGroups: { fa: "همه بخش‌ها", en: "All sections" },
  fixture: {
    fa: "نسخه فعلی سرور هنوز فهرست کامل تنظیمات را نمی‌فرستد. این نمونه فقط برای دیدن است و چیزی را عوض نمی‌کند.",
    en: "This server version doesn't send the full settings list yet. This sample is view-only and changes nothing."
  },
  elsewhereTitle: { fa: "این‌ها در صفحه خودشان تنظیم می‌شوند", en: "These are set on their own page" },
  elsewhereHint: { fa: "برای تغییر، به همان صفحه بروید.", en: "Open that page to change them." },
  elsewhereCount: { fa: "{n} مورد", en: "{n} items" },
  open: { fa: "باز کردن", en: "Open" },
  notLoadedTitle: { fa: "تنظیمات سرور خوانده نشد", en: "Server settings couldn't be loaded" },
  noSettings: { fa: "تنظیمی برای نقش شما وجود ندارد.", en: "There are no settings for your role." }
} satisfies Record<string, Bi>;

// ── Page ─────────────────────────────────────────────────────────────────────

type SettingsPageProps = {
  user: AuthUser;
  colorMode?: "dark" | "light";
  onLanguageChange?: () => void;
  onColorModeChange?: () => void;
  onChangePassword?: () => void;
};

export default function SettingsPage({ user, colorMode = "dark", onLanguageChange, onColorModeChange, onChangePassword }: SettingsPageProps) {
  const { language, isAdvanced, setMode } = useKit();
  const theme = useTheme();
  const isDesktop = useMediaQuery(theme.breakpoints.up("md"));
  const say = (bi: Bi, params?: Record<string, string | number | null>) => fill(pick(language, bi), params, language);
  const [revealed, setRevealed] = useState(false);
  const [selected, setSelected] = useState<string>(() => hashQuery().get("group") ?? "");
  const showRegistry = isAdvanced || revealed;
  const registry = useRegistrySettings({ elsewhere: "list", enabled: showRegistry });
  const loaded = registry.status === "ready" || registry.status === "fallback"
    ? { groups: registry.groups, specs: registry.specs, elsewhere: registry.elsewhere, fixture: registry.status === "fallback" }
    : null;

  // Keep the selected group valid.
  const groupKeys = useMemo(() => registry.groups.map((group) => group.key), [registry.groups]);
  const current = selected && (selected === "all" || groupKeys.includes(selected)) ? selected : groupKeys[0] ?? "all";
  const countOf = (key: string) => (loaded?.specs.filter((spec) => spec.group === key).length ?? 0) + (loaded?.elsewhere.filter((item) => item.group === key).length ?? 0);
  const visibleSpecs = loaded ? (current === "all" ? loaded.specs : loaded.specs.filter((spec) => spec.group === current)) : [];
  const visibleElsewhere = loaded ? (current === "all" ? loaded.elsewhere : loaded.elsewhere.filter((item) => item.group === current)) : [];
  const currentGroup = loaded?.groups.find((group) => group.key === current);


  const preferences = (
    <SectionCard title={say(COPY.mine)} hint={say(COPY.mineHint)}>
      <Box sx={{ display: "grid", gap: 2.5, gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))" } }}>
        <Stack spacing={1}>
          <Typography variant="body2" fontWeight={700}>{say(COPY.language)}</Typography>
          <ToggleButtonGroup
            exclusive
            size="small"
            value={language}
            onChange={(_event, value: Language | null) => {
              if (value && value !== language) onLanguageChange?.();
            }}
            aria-label={say(COPY.language)}
          >
            <ToggleButton value="fa" lang="fa" sx={{ minWidth: 88, minHeight: 40 }}>فارسی</ToggleButton>
            <ToggleButton value="en" lang="en" sx={{ minWidth: 88, minHeight: 40 }}>English</ToggleButton>
          </ToggleButtonGroup>
        </Stack>
        <Stack spacing={1}>
          <Typography variant="body2" fontWeight={700}>{say(COPY.colours)}</Typography>
          <ToggleButtonGroup
            exclusive
            size="small"
            value={colorMode}
            onChange={(_event, value: "dark" | "light" | null) => {
              if (value && value !== colorMode) onColorModeChange?.();
            }}
            aria-label={say(COPY.colours)}
          >
            <ToggleButton value="light" sx={{ minWidth: 88, minHeight: 40 }}>{say(COPY.light)}</ToggleButton>
            <ToggleButton value="dark" sx={{ minWidth: 88, minHeight: 40 }}>{say(COPY.dark)}</ToggleButton>
          </ToggleButtonGroup>
        </Stack>
        <Stack spacing={1}>
          <Typography variant="body2" fontWeight={700}>{say(COPY.mode)}</Typography>
          <Box><UiModeToggle /></Box>
          <Typography variant="caption" color="text.secondary">{say(COPY.modeHint)}</Typography>
        </Stack>
        <Stack spacing={1} alignItems="flex-start">
          <Typography variant="body2" fontWeight={700}>{say(COPY.password)}</Typography>
          <Button variant="outlined" startIcon={<KeyRoundedIcon />} onClick={onChangePassword} sx={{ minHeight: 40 }}>{say(COPY.changePassword)}</Button>
        </Stack>
      </Box>
    </SectionCard>
  );

  const groupNav = loaded && loaded.groups.length > 1 && (
    isDesktop ? (
      <Box component="nav" aria-label={say(COPY.groups)} sx={{ position: "sticky", top: 80, alignSelf: "start" }}>
        <List dense disablePadding sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, py: 0.5, bgcolor: "background.paper" }}>
          {[{ key: "all", label: COPY.allGroups as Bi, n: loaded.specs.length + loaded.elsewhere.length }, ...loaded.groups.map((group) => ({ key: group.key, label: group.label, n: countOf(group.key) }))].map((group) => (
            <ListItemButton key={group.key} selected={group.key === current} onClick={() => setSelected(group.key)} sx={{ minHeight: 42, mx: 0.5, borderRadius: 1 }}>
              <ListItemText primary={group.label[language]} slotProps={{ primary: { fontWeight: group.key === current ? 720 : 560, fontSize: 14 } }} />
              <Typography variant="caption" color="text.secondary">{fill("{n}", { n: group.n }, language)}</Typography>
            </ListItemButton>
          ))}
        </List>
      </Box>
    ) : (
      <Stack direction="row" spacing={1} sx={{ overflowX: "auto", pb: 1, mx: -2, px: 2 }} role="tablist" aria-label={say(COPY.groups)}>
        {[{ key: "all", label: COPY.allGroups as Bi }, ...loaded.groups].map((group) => (
          <Chip
            key={group.key}
            role="tab"
            aria-selected={group.key === current}
            label={group.label[language]}
            color={group.key === current ? "primary" : "default"}
            variant={group.key === current ? "filled" : "outlined"}
            onClick={() => setSelected(group.key)}
            sx={{ flexShrink: 0, height: 40, maxWidth: "none" }}
          />
        ))}
      </Stack>
    )
  );

  const registryBlock = !showRegistry ? (
    <SectionCard title={say(COPY.serverTitle)} hint={say(COPY.simpleIntro)}>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
        <Button variant="contained" onClick={() => setRevealed(true)} sx={{ minHeight: 44 }}>{say(COPY.showAll)}</Button>
        <Button variant="outlined" onClick={() => setMode("advanced")} sx={{ minHeight: 44 }}>{say(COPY.goAdvanced)}</Button>
      </Stack>
    </SectionCard>
  ) : registry.status === "error" ? (
    <FriendlyError error={registry.error} title={say(COPY.notLoadedTitle)} onRetry={registry.reload} />
  ) : !loaded ? (
    <Stack spacing={1.5}>
      <Skeleton variant="rounded" height={56} />
      <Skeleton variant="rounded" height={320} />
    </Stack>
  ) : loaded.specs.length === 0 && loaded.elsewhere.length === 0 ? (
    <Notice>{say(COPY.noSettings)}</Notice>
  ) : (
    <Stack spacing={2}>
      <Box>
        <Typography component="h2" variant="h6" sx={{ fontWeight: 760 }}>{say(COPY.serverTitle)}</Typography>
        <Typography variant="body2" color="text.secondary">{say(COPY.serverHint)}</Typography>
      </Box>
      {loaded.fixture && <Notice tone="warning">{say(COPY.fixture)}</Notice>}
      <RestartNotice restart={registry.restart} labelOf={registry.labelOf} />
      {!isDesktop && groupNav}
      <Box sx={{ display: "grid", gap: 2.5, gridTemplateColumns: isDesktop && loaded.groups.length > 1 ? "240px minmax(0, 1fr)" : "1fr" }}>
        {isDesktop && groupNav}
        <Stack spacing={2} sx={{ minWidth: 0 }}>
          {visibleSpecs.length > 0 && (
            <SettingsForm
              key={current}
              specs={visibleSpecs}
              permissions={user.permissions}
              onSave={registry.save}
              groups={current === "all" ? loaded.groups.filter((group) => visibleSpecs.some((spec) => spec.group === group.key)) : undefined}
              title={current === "all" ? undefined : currentGroup?.label[language]}
              searchable
            />
          )}
          {visibleElsewhere.length > 0 && (
            <SectionCard title={say(COPY.elsewhereTitle)} hint={say(COPY.elsewhereHint)}>
              <Stack divider={<Box sx={{ borderTop: 1, borderColor: "divider" }} />}>
                {visibleElsewhere.map((item) => {
                  const label = item.label[language];
                  return (
                    <Stack key={item.key} direction="row" alignItems="center" spacing={1.5} sx={{ py: 1.25, minHeight: 48 }}>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="body2" fontWeight={650}>{label}</Typography>
                        {typeof item.count === "number" && (
                          <Typography variant="caption" color="text.secondary">{say(COPY.elsewhereCount, { n: item.count })}</Typography>
                        )}
                      </Box>
                      {item.href && (
                        <Button size="small" href={item.href} endIcon={<OpenInNewRoundedIcon fontSize="small" />} sx={{ minHeight: 40, flexShrink: 0 }}>
                          {say(COPY.open)}
                        </Button>
                      )}
                    </Stack>
                  );
                })}
              </Stack>
            </SectionCard>
          )}
        </Stack>
      </Box>
    </Stack>
  );

  return (
    <>
      <PageHeader title={say(COPY.title)} subtitle={say(COPY.subtitle)} icon={SettingsRoundedIcon} />
      <Stack spacing={3}>
        {preferences}
        {registryBlock}
      </Stack>
    </>
  );
}
