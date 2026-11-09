/**
 * One card that edits a few sections of the DNS settings object (docs/38 §2: `querylog`, `stats`,
 * `pressure`) from the «پایش» and «لاگ» tabs. Same rules as DnsSettings.tsx: the whole object is
 * sent back with its `config_version`; a 409 asks the user to load the latest version instead of
 * overwriting someone else's change; 422 `fields` are shown next to the inputs.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Box, Button, CircularProgress, Stack, Typography } from "@mui/material";
import { ApiError, hasPermission, isAbortError } from "./api";
import { pick, type Bi } from "./copy";
import { FriendlyError, NoAccess, Notice, SectionCard, helperProblem, useKit, useUndoSnackbar } from "./kit";
import { dnsFieldMessages, fetchDnsSettings, saveDnsSettings, type DnsSettings } from "./dns";
import { withDefaults } from "./dnsLive";
import { warningsOf, type SettingsWarning } from "./dnsSecure";
import { SaveWarnings } from "./DnsSecuritySettings";

const COPY = {
  loadFailed: { fa: "تنظیمات خوانده نشد.", en: "The settings didn't load." },
  saveFailed: { fa: "تنظیمات ذخیره نشد.", en: "The settings weren't saved." },
  conflict: { fa: "کس دیگری هم‌زمان تنظیمات DNS را تغییر داد. آخرین نسخه را بگیرید و تغییرتان را دوباره بزنید.", en: "Someone else changed the DNS settings at the same time. Load the latest version and make your change again." },
  loadLatest: { fa: "گرفتن آخرین نسخه", en: "Load the latest version" },
  save: { fa: "ذخیره", en: "Save" },
  saving: { fa: "در حال ذخیره…", en: "Saving…" },
  discard: { fa: "دور انداختن تغییرات", en: "Discard changes" },
  saved: { fa: "ذخیره شد و همین حالا اعمال شد.", en: "Saved and applied right away." },
  fixFirst: { fa: "اول خانه‌های قرمز را درست کنید.", en: "Fix the fields in red first." },
  notSupported: { fa: "برنامه DNS روی سرور هنوز این تنظیمات را ندارد. آن را به‌روز کنید.", en: "The DNS program on the server doesn't have these settings yet. Update it." }
} satisfies Record<string, Bi>;

const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/** Section name → its value: an object (merged with defaults) or a list such as `client_groups` (docs/41 §3.2). */
export type SectionDraft = Record<string, object>;

export type DnsSectionSettingsProps<D extends SectionDraft> = {
  title: string;
  hint?: string;
  permissions: readonly string[];
  /** Section name → defaults for missing keys. */
  defaults: D;
  /** Plain sentences keyed by a field path, or {} when everything is fine. */
  validate?: (draft: D) => Record<string, string>;
  children: (props: { draft: D; update: (mutate: (next: D) => void) => void; problems: Record<string, string>; serverFields: Record<string, string> }) => ReactNode;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
  /** Called after a successful save (e.g. to reload a status). */
  onSaved?: () => void;
};

export function DnsSectionSettings<D extends SectionDraft>({ title, hint, permissions, defaults, validate, children, collapsible, defaultCollapsed, onSaved }: DnsSectionSettingsProps<D>) {
  const { language } = useKit();
  const canAdmin = hasPermission(permissions, "dns:admin");
  const [full, setFull] = useState<DnsSettings | null>(null);
  const [saved, setSaved] = useState<D | null>(null);
  const [draft, setDraft] = useState<D | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [conflict, setConflict] = useState(false);
  const [saving, setSaving] = useState(false);
  const [warnings, setWarnings] = useState<SettingsWarning[]>([]);
  const { notify, snackbar } = useUndoSnackbar();
  const controller = useRef<AbortController | null>(null);
  const keys = useMemo(() => Object.keys(defaults), [defaults]);

  const adopt = useCallback((settings: DnsSettings) => {
    const sections = {} as D;
    for (const key of keys) {
      const base = defaults[key];
      (sections as SectionDraft)[key] = Array.isArray(base) ? clone(Array.isArray(settings[key]) ? (settings[key] as object) : base) : withDefaults(settings[key], base);
    }
    const copy = clone(settings);
    delete copy.warnings;
    setFull(copy);
    setSaved(clone(sections));
    setDraft(clone(sections));
  }, [defaults, keys]);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      adopt(await fetchDnsSettings(current.signal));
      setError(null);
      setConflict(false);
      setSaveError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    }
  }, [adopt]);

  useEffect(() => {
    if (canAdmin) void load();
    return () => controller.current?.abort();
  }, [canAdmin, load]);

  const update = (mutate: (next: D) => void) => {
    setDraft((current) => {
      if (!current) return current;
      const next = clone(current);
      mutate(next);
      return next;
    });
  };

  const problems = useMemo(() => (draft && validate ? validate(draft) : {}), [draft, validate]);
  const invalid = Object.keys(problems).length > 0;
  const dirty = Boolean(draft && saved && JSON.stringify(draft) !== JSON.stringify(saved));
  const serverFields = useMemo(() => dnsFieldMessages(language, saveError), [language, saveError]);
  const missingSections = Boolean(full && keys.every((key) => full[key] === undefined));

  const save = async () => {
    if (!full || !draft || invalid || !dirty) return;
    setSaving(true);
    setSaveError(null);
    setConflict(false);
    try {
      const body: DnsSettings = { ...full, ...draft, config_version: full.config_version };
      const result = await saveDnsSettings(body);
      setWarnings(warningsOf(result));
      const next = result && typeof result === "object" ? ((result as { settings?: DnsSettings }).settings ?? (result as DnsSettings)) : null;
      if (next && Array.isArray(next.listen)) adopt(next);
      else await load();
      notify({ message: pick(language, COPY.saved), tone: "success" });
      onSaved?.();
    } catch (caught) {
      if (caught instanceof ApiError && (caught.code === "dns_config_conflict" || caught.code === "config_conflict" || caught.status === 409)) setConflict(true);
      else setSaveError(caught);
    } finally {
      setSaving(false);
    }
  };

  let body: ReactNode;
  if (!canAdmin) body = <NoAccess needs="dns:admin" />;
  else if (error && !draft) {
    body = helperProblem(error) === "module_missing"
      ? <Notice tone="info">{pick(language, COPY.notSupported)}</Notice>
      : <FriendlyError error={error} title={pick(language, COPY.loadFailed)} onRetry={() => void load()} severity="warning" />;
  } else if (!draft) body = <Box sx={{ display: "grid", placeItems: "center", py: 4 }}><CircularProgress size={24} aria-hidden /></Box>;
  else {
    body = (
      <Stack spacing={2}>
        {conflict ? (
          <Notice tone="warning" action={<Button color="inherit" size="small" onClick={() => void load()} sx={{ minHeight: 40 }}>{pick(language, COPY.loadLatest)}</Button>}>
            {pick(language, COPY.conflict)}
          </Notice>
        ) : null}
        <SaveWarnings warnings={warnings} onClose={() => setWarnings([])} />
        {missingSections ? <Notice tone="info">{pick(language, COPY.notSupported)}</Notice> : null}
        {children({ draft, update, problems, serverFields })}
        {saveError ? <FriendlyError error={saveError} title={pick(language, COPY.saveFailed)} onClose={() => setSaveError(null)} scope="dns" /> : null}
        {dirty ? (
          <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center" justifyContent="space-between">
            <Typography variant="body2" color={invalid ? "error" : "text.secondary"}>{invalid ? pick(language, COPY.fixFirst) : null}</Typography>
            <Stack direction="row" gap={1}>
              <Button onClick={() => setDraft(saved ? clone(saved) : draft)} disabled={saving} sx={{ minHeight: 44 }}>{pick(language, COPY.discard)}</Button>
              <Button variant="contained" onClick={() => void save()} disabled={saving || invalid} startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
                {pick(language, saving ? COPY.saving : COPY.save)}
              </Button>
            </Stack>
          </Stack>
        ) : null}
      </Stack>
    );
  }

  return (
    <SectionCard title={title} hint={hint} collapsible={collapsible} defaultCollapsed={defaultCollapsed}>
      {body}
      {snackbar}
    </SectionCard>
  );
}
