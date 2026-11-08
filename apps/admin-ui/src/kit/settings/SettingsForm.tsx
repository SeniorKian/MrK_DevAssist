import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Box, Button, Chip, CircularProgress, Divider, FormControl, InputAdornment, Link, MenuItem, Select, Stack, Switch,
  TextField, Tooltip, Typography
} from "@mui/material";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import RestartAltRoundedIcon from "@mui/icons-material/RestartAltRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import { hasPermission } from "../../api";
import type { Language } from "../../i18n";
import { formatNumber } from "../../format";
import { DANGER_WORDS } from "../../copy/roles";
import { errorEntry } from "../../copy/errors";
import { formatDuration, formatWithUnit, unitWord, type UnitKey } from "../formatters";
import { formatBytes } from "../../format";
import { BytesInput, DurationInput, ListInput, NumberInput, TimezonePicker } from "../inputs";
import { CopyButton } from "../CopyField";
import { ConfirmAction } from "../ConfirmAction";
import { FriendlyError } from "../FriendlyError";
import { HelpTip } from "../HelpTip";
import { NoAccess } from "../NoAccess";
import { SectionCard } from "../SectionCard";
import { useKit } from "../useKit";
import type { SettingSpec, SettingValue, SettingsGroupInfo, SettingsSaveResult } from "./types";

export type SettingsFormProps = {
  specs: SettingSpec[];
  /** The signed-in user's permissions; rows whose `requires` is missing are read-only. */
  permissions: readonly string[];
  /** Persist changed runtime values. Return per-key results to show field errors. Omit for a read-only form. */
  onSave?: (changes: Record<string, SettingValue>) => Promise<SettingsSaveResult>;
  /** Render one SectionCard per group (in this order). Without it, a single card titled `title`. */
  groups?: SettingsGroupInfo[];
  title?: string;
  hint?: string;
  /** Show the search box and filter chips (default: when there are more than 8 rows). */
  searchable?: boolean;
};

type FilterKey = "editable" | "compose" | "restart" | "changed" | "dangerous";

const COPY = {
  searchLabel: { fa: "جست‌وجوی تنظیمات (نام، کلید یا نام متغیر)", en: "Search settings (name, key or env name)" },
  filters: {
    editable: { fa: "قابل تغییر از پنل", en: "Editable here" },
    compose: { fa: "فقط از فایل Compose", en: "Compose file only" },
    restart: { fa: "نیاز به راه‌اندازی دوباره", en: "Needs a restart" },
    changed: { fa: "تغییر یافته از پیش‌فرض", en: "Changed from default" },
    dangerous: { fa: "خطرناک", en: "Dangerous" }
  } satisfies Record<FilterKey, { fa: string; en: string }>,
  source: {
    runtime: { fa: "از پنل", en: "Panel" },
    startup: { fa: "فایل Compose", en: "Compose" },
    build: { fa: "هنگام ساخت", en: "Build" },
    constant: { fa: "ثابت", en: "Fixed" }
  },
  restart: { fa: "نیاز به راه‌اندازی دوباره", en: "Needs restart" },
  lockedByEnv: { fa: "در فایل Compose تنظیم شده و از این‌جا عوض نمی‌شود.", en: "Set in the Compose file; can't be changed here." },
  startupNote: { fa: "این مقدار در فایل Compose نوشته می‌شود و پس از راه‌اندازی دوباره اعمال می‌شود.", en: "This value lives in the Compose file and applies after a restart." },
  constantNote: { fa: "هنوز قابل تغییر نیست.", en: "Can't be changed yet." },
  readOnlyNote: { fa: "این مقدار از این‌جا عوض نمی‌شود.", en: "This value can't be changed here." },
  openPage: { fa: "تغییر در صفحه خودش", en: "Change it on its page" },
  buildNote: { fa: "هنگام ساخت نسخه تعیین شده است.", en: "Fixed when this version was built." },
  defaultIs: { fa: "پیش‌فرض: {value}", en: "Default: {value}" },
  secretSet: { fa: "تنظیم شده", en: "Set" },
  secretNotSet: { fa: "تنظیم نشده", en: "Not set" },
  secretPlaceholder: { fa: "برای عوض کردن، مقدار تازه را بنویسید", en: "Type a new value to replace it" },
  dependsOff: { fa: "اول تنظیم بالاتر را روشن کنید.", en: "Turn on the setting above first." },
  nothing: { fa: "تنظیمی با این شرایط پیدا نشد.", en: "No settings match." },
  unsaved: { fa: "{n} تغییر ذخیره نشده", en: "{n} unsaved changes" },
  reviewTitle: { fa: "این تغییرات ذخیره شود؟", en: "Save these changes?" },
  reviewBody: { fa: "این مقدارها عوض می‌شوند:", en: "These values will change:" },
  saved: { fa: "تغییرات ذخیره شد.", en: "Changes saved." },
  copyCompose: { fa: "کپی خط Compose", en: "Copy Compose line" },
  invalidJson: { fa: "متن باید یک ساختار درست باشد (مثل {\"a\": 1}).", en: "This must be valid JSON (like {\"a\": 1})." },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  empty: { fa: "خالی", en: "Empty" },
  fieldError: { fa: "این مقدار ذخیره نشد.", en: "This value wasn't saved." }
};

const UNIT_SECONDS: Partial<Record<UnitKey, number>> = { ms: 0.001, seconds: 1, minutes: 60, hours: 3600, days: 86400 };
const UNIT_BYTES: Partial<Record<UnitKey, number>> = { bytes: 1, mb: 1024 ** 2 };

function same(a: SettingValue, b: SettingValue) {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/** Human text for a value (read-only rows, diff preview). */
export function displaySettingValue(spec: SettingSpec, value: SettingValue, language: Language): string {
  if (spec.secret || spec.type === "secret") return spec.secret_configured || value ? COPY.secretSet[language] : COPY.secretNotSet[language];
  if (value === null || value === undefined || value === "") return COPY.empty[language];
  if (spec.type === "bool") return value ? COPY.on[language] : COPY.off[language];
  if (spec.type === "enum") return spec.enum?.find((option) => option.value === value)?.label[language] ?? String(value);
  if (Array.isArray(value)) return value.length ? value.join("، ") : COPY.empty[language];
  if (typeof value === "number") {
    if (spec.type === "duration") return formatDuration(value * (UNIT_SECONDS[spec.unit ?? "seconds"] ?? 1), language);
    if (spec.type === "bytes") return formatBytes(value * (UNIT_BYTES[spec.unit ?? "bytes"] ?? 1), language);
    return formatWithUnit(value, spec.unit ?? null, language);
  }
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** `MRK_X=value` for the user's Compose file. */
export function composeLine(spec: SettingSpec, value: SettingValue): string {
  const env = spec.env ?? spec.key.toUpperCase().replace(/[.]/g, "_");
  if (spec.secret || spec.type === "secret") return `${env}=<secret>`;
  if (value === null || value === undefined) return `${env}=`;
  if (Array.isArray(value)) return `${env}=${value.join(",")}`;
  if (typeof value === "object") return `${env}=${JSON.stringify(value)}`;
  return `${env}=${String(value)}`;
}

function isEditable(spec: SettingSpec, permissions: readonly string[], canSave: boolean) {
  return canSave && spec.source === "runtime" && !spec.read_only && !spec.locked_by_env && (!spec.requires || hasPermission(permissions, spec.requires));
}

function Badge({ children, color, icon }: { children: ReactNode; color?: "warning" | "error" | "info" | "default"; icon?: ReactNode }) {
  return <Chip size="small" variant="outlined" color={color ?? "default"} icon={icon as never} label={children} sx={{ height: 22, "& .MuiChip-label": { px: 0.75, fontSize: "0.72rem" } }} />;
}

type ControlProps = {
  spec: SettingSpec;
  value: SettingValue;
  onChange: (value: SettingValue) => void;
  disabled: boolean;
  error?: string | null;
  language: Language;
};

function SettingControl({ spec, value, onChange, disabled, error, language }: ControlProps) {
  const [jsonText, setJsonText] = useState(() => (spec.type === "json" || spec.type === "map" ? JSON.stringify(value ?? {}, null, 2) : ""));
  const [jsonError, setJsonError] = useState<string | null>(null);
  const label = spec.label[language];
  const min = spec.min ?? undefined;
  const max = spec.max ?? undefined;
  switch (spec.type) {
    case "bool":
      return (
        <Stack direction="row" alignItems="center" spacing={1}>
          <Switch checked={Boolean(value)} onChange={(event) => onChange(event.target.checked)} disabled={disabled} slotProps={{ input: { "aria-label": label } }} />
          <Typography variant="body2" color="text.secondary">{value ? COPY.on[language] : COPY.off[language]}</Typography>
        </Stack>
      );
    case "int":
    case "float":
      return (
        <NumberInput
          label={label}
          value={typeof value === "number" ? value : null}
          onChange={onChange}
          min={min}
          max={max}
          integer={spec.type === "int"}
          unit={spec.unit ? unitWord(spec.unit, language) || undefined : undefined}
          disabled={disabled}
          error={error}
        />
      );
    case "duration": {
      const factor = UNIT_SECONDS[spec.unit ?? "seconds"] ?? 1;
      return (
        <DurationInput
          label={label}
          value={typeof value === "number" ? Math.round(value * factor) : null}
          onChange={(seconds) => onChange(seconds === null ? null : seconds / factor)}
          min={min !== undefined ? min * factor : undefined}
          max={max !== undefined ? max * factor : undefined}
          disabled={disabled}
          error={error}
        />
      );
    }
    case "bytes": {
      const factor = UNIT_BYTES[spec.unit ?? "bytes"] ?? 1;
      return (
        <BytesInput
          label={label}
          value={typeof value === "number" ? value * factor : null}
          onChange={(bytes) => onChange(bytes === null ? null : bytes / factor)}
          min={min !== undefined ? min * factor : undefined}
          max={max !== undefined ? max * factor : undefined}
          disabled={disabled}
          error={error}
        />
      );
    }
    case "enum":
      return (
        <FormControl size="small" fullWidth disabled={disabled} error={Boolean(error)}>
          <Select value={typeof value === "string" ? value : ""} onChange={(event) => onChange(event.target.value)} inputProps={{ "aria-label": label }}>
            {(spec.enum ?? []).map((option) => (
              <MenuItem key={option.value} value={option.value}>
                <Stack>
                  <span>{option.label[language]}</span>
                  {option.description && <Typography variant="caption" color="text.secondary">{option.description[language]}</Typography>}
                </Stack>
              </MenuItem>
            ))}
          </Select>
          {error && <Typography variant="caption" color="error.main" sx={{ mt: 0.5 }}>{error}</Typography>}
        </FormControl>
      );
    case "list":
    case "cidr_list":
      return (
        <ListInput
          label={label}
          value={Array.isArray(value) ? value : []}
          onChange={onChange}
          max={spec.max_items ?? undefined}
          disabled={disabled}
          helperText={error ?? undefined}
        />
      );
    case "timezone":
      return <TimezonePicker label={label} value={typeof value === "string" ? value : "Asia/Tehran"} onChange={onChange} disabled={disabled} />;
    case "time":
      return (
        <TextField
          type="time"
          size="small"
          label={label}
          value={typeof value === "string" ? value : ""}
          onChange={(event) => onChange(event.target.value)}
          disabled={disabled}
          error={Boolean(error)}
          helperText={error ?? " "}
          slotProps={{ htmlInput: { dir: "ltr", step: 60 }, inputLabel: { shrink: true } }}
        />
      );
    case "secret":
      return (
        <TextField
          type="password"
          size="small"
          fullWidth
          label={label}
          placeholder={COPY.secretPlaceholder[language]}
          value={typeof value === "string" ? value : ""}
          onChange={(event) => onChange(event.target.value || null)}
          disabled={disabled}
          error={Boolean(error)}
          helperText={error ?? (spec.secret_configured ? COPY.secretSet[language] : COPY.secretNotSet[language])}
          autoComplete="new-password"
          slotProps={{ htmlInput: { dir: "ltr" } }}
        />
      );
    case "json":
    case "map":
      return (
        <TextField
          multiline
          minRows={3}
          fullWidth
          size="small"
          label={label}
          value={jsonText}
          disabled={disabled}
          onChange={(event) => {
            setJsonText(event.target.value);
            try {
              onChange(JSON.parse(event.target.value) as SettingValue);
              setJsonError(null);
            } catch {
              setJsonError(COPY.invalidJson[language]);
            }
          }}
          error={Boolean(jsonError || error)}
          helperText={jsonError ?? error ?? " "}
          slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, style: { fontFamily: "ui-monospace, Menlo, Consolas, monospace" } } }}
        />
      );
    default:
      return (
        <TextField
          size="small"
          fullWidth
          label={label}
          value={typeof value === "string" ? value : value === null ? "" : String(value)}
          onChange={(event) => onChange(event.target.value === "" ? null : event.target.value)}
          disabled={disabled}
          error={Boolean(error)}
          helperText={error ?? " "}
          slotProps={{ htmlInput: { dir: spec.type === "url" || spec.type === "path" || spec.type === "string" || spec.type === "ref" ? "ltr" : undefined, spellCheck: false } }}
        />
      );
  }
}

/**
 * Settings rendered from the registry schema (docs/33 §4.3): one row per setting with plain name,
 * technical key (Advanced), generated control, default + reset, unit, source/restart/danger badges.
 * Startup rows are read-only and offer «کپی خط Compose». Saving shows a diff and asks for confirmation
 * (destructive style when any change is high/critical danger).
 */
export function SettingsForm({ specs, permissions, onSave, groups, title, hint, searchable }: SettingsFormProps) {
  const { language, isAdvanced, c } = useKit();
  const [draft, setDraft] = useState<Record<string, SettingValue>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<Set<FilterKey>>(new Set());
  const [reviewing, setReviewing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  // Values saved in this session, shown until the parent passes fresh `specs` from the server.
  const [committed, setCommitted] = useState<Record<string, SettingValue>>({});

  // A new schema (e.g. after a refresh) drops drafts for keys that no longer exist.
  useEffect(() => {
    setDraft((current) => Object.fromEntries(Object.entries(current).filter(([key]) => specs.some((spec) => spec.key === key))));
    setCommitted({});
  }, [specs]);

  const canSave = Boolean(onSave);
  const baseOf = (spec: SettingSpec): SettingValue => (spec.key in committed ? committed[spec.key] : spec.value);
  const valueOf = (spec: SettingSpec): SettingValue => (spec.key in draft ? draft[spec.key] : baseOf(spec));
  const specByKey = useMemo(() => new Map(specs.map((spec) => [spec.key, spec])), [specs]);
  const changedKeys = Object.keys(draft).filter((key) => {
    const spec = specByKey.get(key);
    return spec && !same(draft[key], baseOf(spec));
  });

  const showSearch = searchable ?? specs.length > 8;
  const needle = query.trim().toLowerCase();
  const visible = specs.filter((spec) => {
    if (needle) {
      const haystack = [spec.label.fa, spec.label.en, spec.key, spec.env ?? "", spec.description?.fa ?? "", spec.description?.en ?? ""].join(" ").toLowerCase();
      if (!haystack.includes(needle)) return false;
    }
    if (filters.has("editable") && !isEditable(spec, permissions, canSave)) return false;
    if (filters.has("compose") && spec.source !== "startup") return false;
    if (filters.has("restart") && !spec.restart_required) return false;
    if (filters.has("changed") && same(spec.value, spec.default) && !spec.overridden) return false;
    if (filters.has("dangerous") && !(spec.danger === "high" || spec.danger === "critical")) return false;
    return true;
  });

  const dependsMet = (spec: SettingSpec) =>
    (spec.depends_on ?? []).every((dep) => {
      const other = specByKey.get(dep.key);
      return other ? same(valueOf(other), dep.equals) : true;
    });

  const toggleFilter = (key: FilterKey) =>
    setFilters((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const save = async () => {
    if (!onSave) return;
    setSaving(true);
    setSaveError(null);
    try {
      const changes = Object.fromEntries(changedKeys.map((key) => [key, draft[key]]));
      const result = await onSave(changes);
      const errors: Record<string, string> = {};
      for (const [key, item] of Object.entries(result?.results ?? {})) {
        if (!item.ok) {
          errors[key] = (language === "fa" ? item.field_message_fa : item.field_message_en) ?? errorEntry(item.error_code)?.[language] ?? COPY.fieldError[language];
        }
      }
      setFieldErrors(errors);
      setCommitted((current) => ({ ...current, ...Object.fromEntries(Object.entries(changes).filter(([key]) => !(key in errors))) }));
      setDraft((current) => Object.fromEntries(Object.entries(current).filter(([key]) => key in errors)));
      setReviewing(false);
      if (Object.keys(errors).length === 0) setSavedAt(Date.now());
    } catch (error) {
      setSaveError(error);
    } finally {
      setSaving(false);
    }
  };

  const riskyChange = changedKeys.some((key) => {
    const danger = specByKey.get(key)?.danger;
    return danger === "high" || danger === "critical";
  });

  const renderRow = (spec: SettingSpec) => {
    const editable = isEditable(spec, permissions, canSave);
    const value = valueOf(spec);
    const deps = dependsMet(spec);
    const changedFromDefault = !same(spec.value, spec.default) || Boolean(spec.overridden);
    const dangerous = spec.danger === "high" || spec.danger === "critical";
    const missingPermission = spec.source === "runtime" && !spec.locked_by_env && spec.requires && !hasPermission(permissions, spec.requires);
    const note =
      spec.locked_by_env ? COPY.lockedByEnv[language]
      : spec.source === "startup" ? COPY.startupNote[language]
      : spec.source === "constant" ? COPY.constantNote[language]
      : spec.source === "build" ? COPY.buildNote[language]
      : spec.read_only && !spec.edit_href ? COPY.readOnlyNote[language]
      : null;
    return (
      <Box
        key={spec.key}
        sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "minmax(220px, 40%) 1fr" }, gap: { xs: 1, md: 2.5 }, py: 1.75, alignItems: "start" }}
      >
        <Box sx={{ minWidth: 0 }}>
          <Stack direction="row" alignItems="center" spacing={0.5} sx={{ flexWrap: "wrap", rowGap: 0.5 }}>
            <Typography component="h3" variant="body1" sx={{ fontWeight: 700 }}>{spec.label[language]}</Typography>
            {spec.description && <HelpTip label={spec.label[language]}>{spec.description[language]}</HelpTip>}
          </Stack>
          {isAdvanced && (
            <Typography variant="caption" color="text.secondary" component="div" dir="ltr" sx={{ fontFamily: "ui-monospace, Menlo, Consolas, monospace", textAlign: "start", overflowWrap: "anywhere" }}>
              {spec.key}{spec.env ? ` · ${spec.env}` : ""}
            </Typography>
          )}
          <Stack direction="row" spacing={0.5} sx={{ mt: 0.75, flexWrap: "wrap", rowGap: 0.5 }}>
            {(isAdvanced || spec.source !== "runtime") && <Badge>{COPY.source[spec.source][language]}</Badge>}
            {spec.restart_required && <Badge color="info" icon={<RestartAltRoundedIcon />}>{COPY.restart[language]}</Badge>}
            {dangerous && <Badge color="error" icon={<WarningAmberRoundedIcon />}>{DANGER_WORDS[spec.danger ?? "high"][language]}</Badge>}
            {spec.locked_by_env && <Badge icon={<LockRoundedIcon />}>{COPY.filters.compose[language]}</Badge>}
          </Stack>
        </Box>
        <Box sx={{ minWidth: 0 }}>
          {editable ? (
            <Stack spacing={0.5}>
              <SettingControl
                spec={spec}
                value={value}
                language={language}
                disabled={!deps || saving}
                error={fieldErrors[spec.key]}
                onChange={(next) => {
                  setSavedAt(null);
                  setFieldErrors((current) => {
                    if (!(spec.key in current)) return current;
                    const copy = { ...current };
                    delete copy[spec.key];
                    return copy;
                  });
                  setDraft((current) => ({ ...current, [spec.key]: next }));
                }}
              />
              {!deps && <Typography variant="caption" color="text.secondary">{COPY.dependsOff[language]}</Typography>}
              {spec.type !== "secret" && (
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography variant="caption" color="text.secondary">
                    {COPY.defaultIs[language].replace("{value}", displaySettingValue(spec, spec.default, language))}
                  </Typography>
                  {!same(value, spec.default) && (
                    <Link component="button" type="button" variant="caption" onClick={() => setDraft((current) => ({ ...current, [spec.key]: spec.default }))}>
                      {c.resetToDefault}
                    </Link>
                  )}
                </Stack>
              )}
            </Stack>
          ) : (
            <Stack spacing={0.5}>
              <Stack direction="row" alignItems="center" spacing={0.5}>
                <Typography
                  variant="body2"
                  sx={{ fontWeight: 650, overflowWrap: "anywhere" }}
                  dir={spec.type === "url" || spec.type === "path" || spec.type === "list" || spec.type === "cidr_list" || spec.type === "ref" || spec.type === "map" ? "ltr" : undefined}
                >
                  {displaySettingValue(spec, value, language)}
                </Typography>
                {changedFromDefault && isAdvanced && spec.type !== "secret" && (
                  <Tooltip title={COPY.defaultIs[language].replace("{value}", displaySettingValue(spec, spec.default, language))}>
                    <Box component="span" tabIndex={0} sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: "warning.main", display: "inline-block" }} aria-label={COPY.filters.changed[language]} />
                  </Tooltip>
                )}
              </Stack>
              {note && <Typography variant="caption" color="text.secondary">{note}</Typography>}
              {missingPermission && spec.requires && <NoAccess needs={spec.requires} />}
              {spec.edit_href && (
                <Link href={spec.edit_href} variant="caption" sx={{ alignSelf: "flex-start", minHeight: 24 }}>{COPY.openPage[language]}</Link>
              )}
              {spec.source === "startup" && (
                <Stack direction="row" alignItems="center" spacing={0.5}>
                  <Typography variant="caption" color="text.secondary">{COPY.copyCompose[language]}</Typography>
                  <CopyButton value={composeLine(spec, value)} label={COPY.copyCompose[language]} />
                </Stack>
              )}
            </Stack>
          )}
        </Box>
      </Box>
    );
  };

  const sections: { info: SettingsGroupInfo | null; items: SettingSpec[] }[] = groups
    ? groups.map((info) => ({ info, items: visible.filter((spec) => spec.group === info.key) })).filter((section) => section.items.length > 0)
    : [{ info: null, items: visible }];
  const ungrouped = groups ? visible.filter((spec) => !groups.some((info) => info.key === spec.group)) : [];
  if (ungrouped.length) sections.push({ info: null, items: ungrouped });

  return (
    <Stack spacing={2}>
      {showSearch && (
        <Stack spacing={1}>
          <TextField
            size="small"
            fullWidth
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={COPY.searchLabel[language]}
            slotProps={{
              htmlInput: { "aria-label": COPY.searchLabel[language] },
              input: { startAdornment: <InputAdornment position="start"><SearchRoundedIcon fontSize="small" /></InputAdornment> }
            }}
          />
          <Stack direction="row" spacing={0.75} sx={{ flexWrap: "wrap", rowGap: 0.75 }} role="group" aria-label={c.filter}>
            {(Object.keys(COPY.filters) as FilterKey[]).map((key) => (
              <Chip
                key={key}
                label={COPY.filters[key][language]}
                onClick={() => toggleFilter(key)}
                color={filters.has(key) ? "primary" : "default"}
                variant={filters.has(key) ? "filled" : "outlined"}
                aria-pressed={filters.has(key)}
              />
            ))}
          </Stack>
        </Stack>
      )}

      {sections.length === 0 || visible.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ py: 3, textAlign: "center" }}>{COPY.nothing[language]}</Typography>
      ) : (
        sections.map((section, index) => (
          <SectionCard key={section.info?.key ?? `rest-${index}`} title={section.info ? section.info.label[language] : title} hint={section.info ? undefined : hint}>
            <Stack divider={<Divider flexItem />}>{section.items.map(renderRow)}</Stack>
          </SectionCard>
        ))
      )}

      {canSave && (changedKeys.length > 0 || savedAt) && (
        <Box
          sx={{
            position: "sticky",
            bottom: "calc(var(--mrk-bottom-nav-height, 0px) + 8px)",
            zIndex: 2,
            p: 1.5,
            borderRadius: 2,
            border: "1px solid",
            borderColor: "divider",
            bgcolor: "background.paper",
            boxShadow: 3
          }}
        >
          {changedKeys.length > 0 ? (
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ sm: "center" }}>
              <Typography variant="body2" sx={{ flex: 1, fontWeight: 650 }} role="status">
                {COPY.unsaved[language].replace("{n}", formatNumber(changedKeys.length, language))}
              </Typography>
              <Button onClick={() => { setDraft({}); setFieldErrors({}); }} disabled={saving}>{c.discardChanges}</Button>
              <Button variant="contained" onClick={() => setReviewing(true)} disabled={saving} startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined}>
                {c.saveChanges}
              </Button>
            </Stack>
          ) : (
            <Typography variant="body2" color="success.main" role="status" sx={{ fontWeight: 650 }}>{COPY.saved[language]}</Typography>
          )}
          {saveError !== null && !reviewing && <Box sx={{ mt: 1 }}><FriendlyError error={saveError} onRetry={() => setReviewing(true)} /></Box>}
        </Box>
      )}

      <ConfirmAction
        open={reviewing}
        title={COPY.reviewTitle[language]}
        severity={riskyChange ? "destructive" : "disruptive"}
        confirmLabel={c.saveChanges}
        cancelLabel={c.cancel}
        busy={saving}
        error={saveError ?? undefined}
        onConfirm={() => void save()}
        onClose={() => setReviewing(false)}
        body={
          <Stack spacing={1}>
            <Typography variant="body2">{COPY.reviewBody[language]}</Typography>
            {changedKeys.map((key) => {
              const spec = specByKey.get(key);
              if (!spec) return null;
              return (
                <Box key={key} sx={{ p: 1, borderRadius: 1, bgcolor: "action.hover" }}>
                  <Typography variant="body2" sx={{ fontWeight: 700 }}>{spec.label[language]}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {displaySettingValue(spec, baseOf(spec), language)} {language === "fa" ? "←" : "→"} {displaySettingValue(spec, draft[key], language)}
                  </Typography>
                  {spec.restart_required && <Typography variant="caption" color="info.main">{c.restartRequired}</Typography>}
                </Box>
              );
            })}
          </Stack>
        }
      />
    </Stack>
  );
}
