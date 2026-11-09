/**
 * `<RegistrySettings>`: the inline Advanced block «همه تنظیمات این بخش» (docs/33 §4.1) for one page,
 * built on `useRegistrySettings` (registry.ts). `<RestartNotice>`: the restart-pending banner.
 *
 *   <RegistrySettings groups={["security.firewall"]} exclude={["firewall.mode"]} permissions={user.permissions} title="…" />
 *   <RegistrySettings keys={["backup.retention_count"]} permissions={…} title="…" />
 */
import { Stack, Skeleton, Typography } from "@mui/material";
import RestartAltRoundedIcon from "@mui/icons-material/RestartAltRounded";
import { fill, pick, type Bi } from "../../copy/text";
import { CopyField } from "../CopyField";
import { Notice } from "../Feedback";
import { FriendlyError } from "../FriendlyError";
import { useKit } from "../useKit";
import { SettingsForm } from "./SettingsForm";
import { useRegistrySettings, type LegacySettingsAdapter, type RestartStatus } from "./registry";

const COPY = {
  fixture: {
    fa: "این نسخه سرور هنوز فهرست تنظیمات را نمی‌دهد. مقدارهای پیش‌فرض را می‌بینید و فعلاً از این‌جا عوض نمی‌شوند.",
    en: "This server version doesn't list its settings yet. You see the defaults, and they can't be changed here for now."
  },
  fixtureLegacy: {
    fa: "این نسخه سرور هنوز فهرست کامل تنظیمات را نمی‌دهد؛ فقط تنظیم‌های اصلی این بخش را می‌بینید.",
    en: "This server version doesn't send the full settings list yet; you see this section's main settings only."
  },
  defaultTitle: { fa: "همه تنظیمات این بخش", en: "Every setting for this section" },
  restartTitle: { fa: "چند تغییر پس از راه‌اندازی دوباره اعمال می‌شود", en: "Some changes apply after a restart" },
  restartBody: { fa: "{n} تنظیم عوض شده که فقط هنگام شروع سرویس خوانده می‌شود: {names}.", en: "{n} changed settings are only read when the service starts: {names}." },
  restartWho: { fa: "بخش‌هایی که باید دوباره راه‌اندازی شوند: {names}.", en: "Parts that need a restart: {names}." },
  restartHow: { fa: "روی سرور، کانتینر DevAssist را یک بار دوباره راه‌اندازی کنید:", en: "On the server, restart the DevAssist container once:" },
  restartCommand: { fa: "دستور راه‌اندازی دوباره", en: "Restart command" }
} satisfies Record<string, Bi>;

const PROCESS_WORDS: Record<string, Bi> = {
  "control-plane": { fa: "سرور DevAssist", en: "DevAssist server" },
  "pypi-router": { fa: "مسیریاب PyPI", en: "PyPI router" },
  "s3-engine": { fa: "فضای فایل", en: "File space" },
  verdaccio: { fa: "مخزن npm", en: "npm registry" },
  devpi: { fa: "مخزن PyPI", en: "PyPI registry" }
};

export type RestartNoticeProps = {
  restart: RestartStatus | null;
  /** Plain name of a setting key (`useRegistrySettings().labelOf`). */
  labelOf?: (key: string) => Bi;
  /** Show only when one of these keys is pending (default: any pending key). */
  onlyKeys?: readonly string[];
};

/** «چند تغییر پس از راه‌اندازی دوباره اعمال می‌شود» + which settings, which parts, and the command. */
export function RestartNotice({ restart, labelOf, onlyKeys }: RestartNoticeProps) {
  const { language } = useKit();
  if (!restart?.pending) return null;
  const keys = onlyKeys ? restart.keys.filter((key) => onlyKeys.includes(key)) : restart.keys;
  if (onlyKeys && keys.length === 0) return null;
  const join = (items: string[]) => items.join(language === "fa" ? "، " : ", ");
  const names = keys.map((key) => (labelOf ? labelOf(key)[language] : key));
  const processes = (restart.processes ?? []).map((name) => PROCESS_WORDS[name]?.[language] ?? name);
  return (
    <Notice tone="warning">
      <Stack spacing={1}>
        <Stack direction="row" spacing={1} alignItems="center">
          <RestartAltRoundedIcon fontSize="small" aria-hidden />
          <Typography fontWeight={720}>{pick(language, COPY.restartTitle)}</Typography>
        </Stack>
        {names.length > 0 && <Typography variant="body2">{fill(pick(language, COPY.restartBody), { n: names.length, names: join(names) }, language)}</Typography>}
        {processes.length > 0 && <Typography variant="body2">{fill(pick(language, COPY.restartWho), { names: join(processes) }, language)}</Typography>}
        <Typography variant="body2">{pick(language, COPY.restartHow)}</Typography>
        <CopyField label={pick(language, COPY.restartCommand)} value="docker compose up -d --force-recreate mrk-mirror" />
      </Stack>
    </Notice>
  );
}

export type RegistrySettingsProps = {
  /** Registry group ids, e.g. `["server.resources"]`. */
  groups?: readonly string[];
  /** Only these keys (any group). */
  keys?: readonly string[];
  /** Leave out keys this page already edits with its own controls. */
  exclude?: readonly string[];
  permissions: readonly string[];
  title?: string;
  hint?: string;
  /** Load and save the fixture rows through the module's older endpoint on servers without the registry. */
  legacy?: LegacySettingsAdapter;
  /** Also render in Simple mode (default: Advanced only). */
  simpleToo?: boolean;
};

/** Every remaining registry setting of a section, rendered by SettingsForm. Advanced only by default. */
export function RegistrySettings({ groups, keys, exclude, permissions, title, hint, legacy, simpleToo }: RegistrySettingsProps) {
  const { language, isAdvanced } = useKit();
  const visible = isAdvanced || Boolean(simpleToo);
  const state = useRegistrySettings({ groups, keys, exclude, legacy, enabled: visible });
  if (!visible) return null;
  if (state.status === "loading" || state.status === "idle") return <Skeleton variant="rounded" height={120} />;
  if (state.status === "error") return <FriendlyError error={state.error} onRetry={state.reload} />;
  if (state.specs.length === 0) return null;
  const heading = title ?? pick(language, COPY.defaultTitle);
  return (
    <Stack spacing={1.5}>
      {state.status === "fallback" && <Notice>{pick(language, legacy ? COPY.fixtureLegacy : COPY.fixture)}</Notice>}
      <RestartNotice restart={state.restart} labelOf={state.labelOf} onlyKeys={state.specs.map((spec) => spec.key)} />
      <SettingsForm
        specs={state.specs}
        permissions={permissions}
        onSave={state.save}
        groups={state.groups.length > 1 ? state.groups : undefined}
        title={heading}
        hint={hint}
      />
    </Stack>
  );
}
