/**
 * Settings registry adapter (docs/34 §3), shared by every page:
 *
 *   GET    /api/v1/settings/registry          → {groups:[{id, key, name_fa, name_en, label, nav, items:[…]}], restart}
 *   PUT    /api/v1/settings/registry/{key}    {value} → {item, restart}
 *   DELETE /api/v1/settings/registry/{key}    → back to the default
 *   GET    /api/v1/settings/registry/restart  → {pending, keys, processes, container_restart_recommended}
 *
 * `registryItemToSpec` turns one backend item into the kit `SettingSpec` (bare-string enums → plain
 * words, `label_fa`/`description_fa` → Bi, non-editable rows (also `ref`/`map`) → read-only, `edit_in` →
 * a link to the page that edits it). `useRegistrySettings` loads, filters (groups / keys / exclude),
 * saves (PUT per key, DELETE when a changed value goes back to its default), tracks the restart status
 * and falls back to `SETTINGS_FIXTURE` on servers without the registry (404/405).
 * `<RegistrySettings>` (RegistrySettings.tsx) is the ready-made Advanced block for a page.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, apiMutate, getJson, isAbortError, toApiError } from "../../api";
import { errorSentence } from "../../copy/errors";
import { severityWord } from "../../copy/kinds";
import type { Bi } from "../../copy/text";
import { parseHash, routeHref } from "../../nav";
import { SETTINGS_FIXTURE, SETTINGS_FIXTURE_GROUPS } from "./fixture";
import type {
  SettingEnumOption, SettingResult, SettingSpec, SettingType, SettingUnit, SettingValue, SettingsGroupInfo, SettingsSaveResult
} from "./types";

// ── Backend shapes ───────────────────────────────────────────────────────────

export type RegistryRawEnum = string | { value: string; label?: Partial<Bi> | null; label_fa?: string; label_en?: string; description?: Bi };

export type RegistryRawItem = {
  key: string;
  group: string;
  type?: string;
  default?: SettingValue;
  min?: number | null;
  max?: number | null;
  step?: number | null;
  enum?: RegistryRawEnum[] | null;
  unit?: string | null;
  source?: SettingSpec["source"];
  env?: string | null;
  restart_required?: boolean;
  danger?: SettingSpec["danger"];
  requires?: string | null;
  depends_on?: { key: string; equals: SettingValue }[] | null;
  secret?: boolean;
  secret_configured?: boolean;
  label?: Partial<Bi> | null;
  label_fa?: string;
  label_en?: string;
  description?: Partial<Bi> | null;
  description_fa?: string;
  description_en?: string;
  env_only_note?: Bi | null;
  edit_in?: string | null;
  value?: SettingValue;
  overridden?: boolean;
  locked_by_env?: boolean;
  pending_restart?: boolean;
  editable?: boolean;
  available?: boolean;
  count?: number;
  max_items?: number | null;
};

export type RegistryRawGroup = { id?: string; key?: string; name_fa?: string; name_en?: string; label?: Partial<Bi> | null; nav?: string; items?: RegistryRawItem[] };

export type RestartStatus = { pending: boolean; keys: string[]; processes: string[]; container_restart_recommended?: boolean };

export type RegistryPayload = { groups?: RegistryRawGroup[]; items?: RegistryRawItem[]; restart?: RestartStatus };

// ── Item → SettingSpec ───────────────────────────────────────────────────────

const KNOWN_TYPES = new Set<string>([
  "bool", "int", "float", "string", "enum", "list", "duration", "bytes", "time", "timezone", "cidr_list", "url", "json", "secret", "map", "path", "ref"
]);
const KNOWN_UNITS = new Set<string>(["percent", "seconds", "minutes", "hours", "days", "ms", "bytes", "mb", "count", "per_second"]);
const SEVERITY_VALUES = new Set(["info", "warning", "error", "critical", "high", "medium", "low"]);

/** Plain words for enum values the registry sends as bare strings. */
export const REGISTRY_ENUM_WORDS: Record<string, Bi> = {
  off: { fa: "خاموش", en: "Off" },
  on: { fa: "روشن", en: "On" },
  dry_run: { fa: "حالت تمرین", en: "Practice mode" },
  enforce: { fa: "حالت فعال", en: "Active mode" },
  system: { fa: "همان DNS سرور", en: "The server's own DNS" },
  custom: { fa: "سفارشی", en: "Custom" }
};

function bi(raw: Partial<Bi> | null | undefined, fa?: string, en?: string): Bi | null {
  const faText = raw?.fa ?? fa;
  const enText = raw?.en ?? en;
  if (!faText && !enText) return null;
  return { fa: faText ?? enText ?? "", en: enText ?? faText ?? "" };
}

function enumOption(raw: RegistryRawEnum): SettingEnumOption {
  if (typeof raw !== "string") {
    const label = bi(raw.label, raw.label_fa, raw.label_en) ?? { fa: raw.value, en: raw.value };
    return { value: raw.value, label, description: raw.description };
  }
  const word = REGISTRY_ENUM_WORDS[raw];
  if (word) return { value: raw, label: word };
  if (SEVERITY_VALUES.has(raw)) return { value: raw, label: { fa: severityWord("fa", raw).label, en: severityWord("en", raw).label } };
  return { value: raw, label: { fa: raw, en: raw } };
}

/** `edit_in` (e.g. "files/backups") → a hash link that resolves through nav aliases. */
export function registryEditHref(editIn: string): string {
  const route = parseHash(`#/${editIn}`);
  if (route?.kind === "tab") return routeHref(route.group, route.tab);
  if (route?.kind === "utility") return `#/${route.key}`;
  return `#/${editIn}`;
}

export function registryItemLabel(item: RegistryRawItem): Bi {
  return bi(item.label, item.label_fa, item.label_en) ?? { fa: item.key, en: item.key };
}

export function registryGroupInfo(group: RegistryRawGroup): SettingsGroupInfo {
  const key = String(group.id ?? group.key ?? "");
  return { key, label: bi(group.label, group.name_fa, group.name_en) ?? { fa: key, en: key }, nav: group.nav };
}

/**
 * Backend registry item → kit SettingSpec.
 * - Panel-writable startup values behave like runtime rows that need a restart.
 * - Runtime values of a module that isn't running (`available: false`) and rows the server marks
 *   `editable: false` are read-only. Read-only rows (any type, including `ref` and `map`) link to the
 *   page that edits them when the item has `edit_in`.
 */
export function registryItemToSpec(item: RegistryRawItem): SettingSpec {
  const type = (item.type && KNOWN_TYPES.has(item.type) ? item.type : "string") as SettingType;
  const unit = item.unit && KNOWN_UNITS.has(item.unit) ? (item.unit as SettingUnit) : null;
  const base = bi(item.description, item.description_fa, item.description_en);
  const note = item.env_only_note;
  const description = note ? { fa: [base?.fa, note.fa].filter(Boolean).join(" "), en: [base?.en, note.en].filter(Boolean).join(" ") } : base;
  let source: SettingSpec["source"] = item.source ?? "runtime";
  let restart = Boolean(item.restart_required);
  if (source === "startup" && item.editable) {
    source = "runtime";
    restart = true;
  } else if (source === "runtime" && item.available === false) {
    source = "constant";
  }
  // The server says no (and it isn't a Compose lock or a missing permission, which the form explains itself).
  const readOnly = item.editable === false && source === "runtime" && !item.locked_by_env && !item.requires;
  return {
    key: item.key,
    group: item.group,
    type,
    default: item.default ?? null,
    min: item.min ?? null,
    max: item.max ?? null,
    step: item.step ?? null,
    enum: item.enum ? item.enum.map(enumOption) : null,
    unit,
    source,
    env: item.env ?? null,
    restart_required: restart,
    danger: item.danger ?? "low",
    requires: item.requires ?? null,
    depends_on: Array.isArray(item.depends_on) ? item.depends_on : null,
    label: registryItemLabel(item),
    description,
    value: item.value ?? null,
    overridden: Boolean(item.overridden),
    locked_by_env: Boolean(item.locked_by_env),
    secret: Boolean(item.secret) || type === "secret",
    secret_configured: Boolean(item.secret_configured),
    max_items: item.max_items ?? null,
    read_only: readOnly || undefined,
    edit_href: item.edit_in ? registryEditHref(item.edit_in) : null
  };
}

// ── Saving ───────────────────────────────────────────────────────────────────

function same(a: unknown, b: unknown) {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/** Per-key failure for SettingsForm (the catalog sentence in both languages). */
export function settingResultFromError(error: unknown): SettingResult {
  const code = error instanceof ApiError ? error.code : "";
  return { ok: false, error_code: code || undefined, field_message_fa: errorSentence("fa", error), field_message_en: errorSentence("en", error) };
}

/**
 * Save changed values one key at a time: `PUT {value}`, or `DELETE` (reset) when the new value is the
 * default of a row that is currently overridden. Returns per-key results and the newest restart status.
 */
export async function saveRegistryChanges(
  changes: Record<string, SettingValue>,
  specs: ReadonlyMap<string, SettingSpec>
): Promise<{ results: Record<string, SettingResult>; restart: RestartStatus | null }> {
  const results: Record<string, SettingResult> = {};
  let restart: RestartStatus | null = null;
  for (const [key, value] of Object.entries(changes)) {
    const spec = specs.get(key);
    const reset = Boolean(spec?.overridden) && same(value, spec?.default);
    try {
      const response = await apiMutate(`/api/v1/settings/registry/${encodeURIComponent(key)}`, reset ? { method: "DELETE" } : { method: "PUT", body: { value } });
      if (!response.ok) throw await toApiError(response);
      const payload = (await response.json().catch(() => null)) as { restart?: RestartStatus } | null;
      if (payload?.restart) restart = payload.restart;
      results[key] = { ok: true };
    } catch (caught) {
      results[key] = settingResultFromError(caught);
    }
  }
  return { results, restart };
}

// ── Hook ─────────────────────────────────────────────────────────────────────

/** Loads/saves the module's values through its older endpoint when the server has no registry. */
export type LegacySettingsAdapter = {
  load: (signal: AbortSignal) => Promise<Record<string, SettingValue>>;
  save: (changes: Record<string, SettingValue>) => Promise<void>;
};

export type RegistryFilter = {
  /** Registry group ids, e.g. `["server.resources"]`. Omit for every group. */
  groups?: readonly string[];
  /** Only these keys (any group). */
  keys?: readonly string[];
  /** Leave out keys the page already edits with its own controls. */
  exclude?: readonly string[];
  /**
   * `"hide"` (default, for inline page blocks): rows with `edit_in` are left out.
   * `"list"` (All settings): runtime rows with `edit_in` go to `elsewhere` (a link list); others stay as read-only rows with a link.
   */
  elsewhere?: "hide" | "list";
  /** Values for the fixture rows (and saving) on servers without the registry. */
  legacy?: LegacySettingsAdapter;
  /** Load only while true (default true), e.g. only in Advanced mode. */
  enabled?: boolean;
};

export type RegistryElsewhereItem = { key: string; group: string; label: Bi; count?: number; href: string };

export type RegistrySettingsState = {
  specs: SettingSpec[];
  groups: SettingsGroupInfo[];
  elsewhere: RegistryElsewhereItem[];
  /** `ready` = live registry; `fallback` = fixture rows (read-only unless a legacy adapter saves them). */
  status: "idle" | "loading" | "ready" | "fallback" | "error";
  error: unknown;
  restart: RestartStatus | null;
  /** Undefined when nothing can be saved (fixture without a legacy adapter). */
  save?: (changes: Record<string, SettingValue>) => Promise<SettingsSaveResult>;
  reload: () => void;
  /** Re-read `GET …/restart` (needs `system:read`; failures keep the last state). */
  refreshRestart: () => Promise<void>;
  /** Plain name of a key (for the restart banner). */
  labelOf: (key: string) => Bi;
};

function matches(filter: { groups: Set<string> | null; keys: Set<string> | null; exclude: Set<string> }, key: string, group: string) {
  if (filter.exclude.has(key)) return false;
  if (filter.keys && !filter.keys.has(key)) return false;
  if (filter.groups && !filter.groups.has(group)) return false;
  return true;
}

export function useRegistrySettings(filter: RegistryFilter = {}): RegistrySettingsState {
  const { legacy, enabled = true, elsewhere: elsewhereMode = "hide" } = filter;
  const groupsKey = filter.groups?.join("|") ?? "";
  const keysKey = filter.keys?.join("|") ?? "";
  const excludeKey = filter.exclude?.join("|") ?? "";
  const wanted = useMemo(
    () => ({
      groups: groupsKey ? new Set(groupsKey.split("|")) : null,
      keys: keysKey ? new Set(keysKey.split("|")) : null,
      exclude: new Set(excludeKey ? excludeKey.split("|") : [])
    }),
    [groupsKey, keysKey, excludeKey]
  );
  const [specs, setSpecs] = useState<SettingSpec[]>([]);
  const [groups, setGroups] = useState<SettingsGroupInfo[]>([]);
  const [elsewhere, setElsewhere] = useState<RegistryElsewhereItem[]>([]);
  const [status, setStatus] = useState<RegistrySettingsState["status"]>(enabled ? "loading" : "idle");
  const [error, setError] = useState<unknown>(null);
  const [restart, setRestart] = useState<RestartStatus | null>(null);
  const [tick, setTick] = useState(0);
  const labels = useRef(new Map<string, Bi>());
  const reload = useCallback(() => setTick((value) => value + 1), []);

  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    void (async () => {
      setStatus((current) => (current === "ready" || current === "fallback" ? current : "loading"));
      try {
        const payload = await getJson<RegistryPayload>("/api/v1/settings/registry", controller.signal);
        const rawGroups = payload.groups ?? [];
        const items = [...rawGroups.flatMap((group) => group.items ?? []), ...(payload.items ?? [])];
        const nextSpecs: SettingSpec[] = [];
        const nextElsewhere: RegistryElsewhereItem[] = [];
        labels.current = new Map(items.map((item) => [item.key, registryItemLabel(item)]));
        for (const item of items) {
          if (!matches(wanted, item.key, item.group)) continue;
          if (item.edit_in && (elsewhereMode === "hide" || (item.source ?? "runtime") === "runtime")) {
            if (elsewhereMode === "list") {
              nextElsewhere.push({ key: item.key, group: item.group, label: registryItemLabel(item), count: item.count, href: registryEditHref(item.edit_in) });
            }
            continue;
          }
          nextSpecs.push(registryItemToSpec(item));
        }
        const shown = new Set([...nextSpecs.map((spec) => spec.group), ...nextElsewhere.map((item) => item.group)]);
        setSpecs(nextSpecs);
        setElsewhere(nextElsewhere);
        setGroups(rawGroups.map(registryGroupInfo).filter((group) => shown.has(group.key)));
        setRestart(payload.restart ?? null);
        setError(null);
        setStatus("ready");
        return;
      } catch (caught) {
        if (isAbortError(caught)) return;
        if (caught instanceof ApiError && caught.status === 401) return;
        if (!(caught instanceof ApiError && (caught.status === 404 || caught.status === 405))) {
          setError(caught);
          setStatus("error");
          return;
        }
      }
      // Older server without the registry: the documented fixture, filled from the legacy endpoint if any.
      const fixture = SETTINGS_FIXTURE.filter((spec) => matches(wanted, spec.key, spec.group)).map((spec) => ({ ...spec }));
      labels.current = new Map(SETTINGS_FIXTURE.map((spec) => [spec.key, spec.label]));
      if (legacy) {
        try {
          const values = await legacy.load(controller.signal);
          for (const spec of fixture) {
            if (spec.key in values) {
              spec.value = values[spec.key];
              spec.overridden = !same(values[spec.key], spec.default);
            }
          }
        } catch (caught) {
          if (isAbortError(caught)) return;
        }
      }
      const shown = new Set(fixture.map((spec) => spec.group));
      setSpecs(fixture);
      setElsewhere([]);
      setGroups(SETTINGS_FIXTURE_GROUPS.filter((group) => shown.has(group.key)));
      setRestart(null);
      setError(null);
      setStatus("fallback");
    })();
    return () => controller.abort();
  }, [enabled, wanted, elsewhereMode, legacy, tick]);

  const refreshRestart = useCallback(async () => {
    try {
      setRestart(await getJson<RestartStatus>("/api/v1/settings/registry/restart"));
    } catch {
      // keep the last known state (e.g. no system:read)
    }
  }, []);

  const specMap = useMemo(() => new Map(specs.map((spec) => [spec.key, spec])), [specs]);

  const save = useCallback(
    async (changes: Record<string, SettingValue>): Promise<SettingsSaveResult> => {
      if (status === "fallback") {
        if (!legacy) return;
        try {
          await legacy.save(changes);
          reload();
          return { results: Object.fromEntries(Object.keys(changes).map((key) => [key, { ok: true }])) };
        } catch (caught) {
          const failure = settingResultFromError(caught);
          return { results: Object.fromEntries(Object.keys(changes).map((key) => [key, failure])) };
        }
      }
      const outcome = await saveRegistryChanges(changes, specMap);
      if (outcome.restart) setRestart(outcome.restart);
      else if (Object.values(outcome.results).some((result) => result.ok)) void refreshRestart();
      reload();
      return { results: outcome.results };
    },
    [legacy, refreshRestart, reload, specMap, status]
  );

  const labelOf = useCallback((key: string) => labels.current.get(key) ?? { fa: key, en: key }, []);
  const canSave = status === "ready" || (status === "fallback" && Boolean(legacy));
  return { specs, groups, elsewhere, status, error, restart, save: canSave ? save : undefined, reload, refreshRestart, labelOf };
}
