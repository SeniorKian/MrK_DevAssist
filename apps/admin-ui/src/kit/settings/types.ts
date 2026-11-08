/**
 * Settings registry schema (docs/33 §4.3), the same shape as backend BE1
 * `GET /api/v1/settings/registry` → `{ groups, items }`.
 */
import type { Bi } from "../../copy/text";

export type SettingType =
  | "bool"
  | "int"
  | "float"
  | "string"
  | "enum"
  | "list"
  | "duration"
  | "bytes"
  | "time"
  | "timezone"
  | "cidr_list"
  | "url"
  | "json"
  | "secret"
  | "map"
  | "path"
  /** Id of something a page manages (e.g. a proxy id). */
  | "ref";

/** Where the value comes from: panel (runtime), Compose env (startup), image build, or hard-coded today. */
export type SettingSource = "runtime" | "startup" | "build" | "constant";

export type SettingDanger = "none" | "low" | "medium" | "high" | "critical";

export type SettingUnit = "percent" | "seconds" | "minutes" | "hours" | "days" | "ms" | "bytes" | "mb" | "count" | "per_second";

export type SettingValue = boolean | number | string | string[] | Record<string, unknown> | null;

export type SettingEnumOption = { value: string; label: Bi; description?: Bi };

export type SettingSpec = {
  /** Stable dotted key, e.g. `monitoring.alerts.cpu_percent`. */
  key: string;
  /** Nav group/tab, e.g. `server.resources`. */
  group: string;
  type: SettingType;
  default: SettingValue;
  min?: number | null;
  max?: number | null;
  step?: number | null;
  enum?: SettingEnumOption[] | null;
  unit?: SettingUnit | null;
  source: SettingSource;
  /** Env name for startup values (or the env that overrides a runtime default). */
  env?: string | null;
  restart_required?: boolean;
  danger?: SettingDanger;
  /** Write permission needed to change it. */
  requires?: string | null;
  depends_on?: { key: string; equals: SettingValue }[] | null;
  label: Bi;
  description?: Bi | null;
  /** Current effective value. Secrets are never sent; see `secret_configured`. */
  value: SettingValue;
  overridden?: boolean;
  /** A Compose env pins the value; the panel can't change it. */
  locked_by_env?: boolean;
  secret?: boolean;
  secret_configured?: boolean;
  /** Max list length (list/cidr_list). */
  max_items?: number | null;
  /** The server marks the row as not editable from here (shown read-only). */
  read_only?: boolean;
  /** Link to the page that edits this value (registry `edit_in`), shown on read-only rows. */
  edit_href?: string | null;
};

export type SettingsGroupInfo = { key: string; label: Bi; nav?: string };

export type SettingsRegistry = { groups: SettingsGroupInfo[]; items: SettingSpec[] };

/** Per-key answer of `PUT /api/v1/settings/registry/{key}`. */
export type SettingResult = { ok: boolean; error_code?: string; field_message_fa?: string; field_message_en?: string };

export type SettingsSaveResult = { results?: Record<string, SettingResult> } | void;
