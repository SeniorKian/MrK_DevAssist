import { useEffect, useMemo, useState } from "react";
import {
  Autocomplete, Box, Chip, FormControl, FormHelperText, InputLabel, MenuItem, Select, Slider, Stack, TextField, Typography
} from "@mui/material";
import { formatNumber } from "../format";
import { useKit } from "./useKit";

/** Parse a number typed with Persian, Arabic or Latin digits and «٫»/«,» decimal marks. */
export function parseLocalizedNumber(text: string): number | null {
  const normalized = text
    .trim()
    .replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit)))
    .replace(/[٠-٩]/g, (digit) => String("٠١٢٣٤٥٦٧٨٩".indexOf(digit)))
    .replace(/[٬,\s]/g, "")
    .replace(/[٫]/g, ".");
  if (!normalized || !/^-?\d*(\.\d+)?$/.test(normalized)) return null;
  const value = Number(normalized);
  return Number.isFinite(value) ? value : null;
}

const RANGE_COPY = {
  between: { fa: "عددی بین {min} تا {max}", en: "A number from {min} to {max}" },
  atLeast: { fa: "دست‌کم {min}", en: "At least {min}" },
  atMost: { fa: "حداکثر {max}", en: "At most {max}" },
  notNumber: { fa: "یک عدد بنویسید.", en: "Enter a number." },
  outOfRange: { fa: "باید {range} باشد.", en: "Must be {range}." },
  integer: { fa: "عدد باید صحیح باشد.", en: "Use a whole number." }
};

function rangeText(language: "fa" | "en", min?: number, max?: number) {
  const n = (value: number) => formatNumber(value, language);
  if (min !== undefined && max !== undefined) return RANGE_COPY.between[language].replace("{min}", n(min)).replace("{max}", n(max));
  if (min !== undefined) return RANGE_COPY.atLeast[language].replace("{min}", n(min));
  if (max !== undefined) return RANGE_COPY.atMost[language].replace("{max}", n(max));
  return "";
}

/** Validate a number against min/max/integer; returns a sentence or null. */
export function numberProblem(language: "fa" | "en", value: number | null, opts: { min?: number; max?: number; integer?: boolean }) {
  if (value === null) return RANGE_COPY.notNumber[language];
  if (opts.integer && !Number.isInteger(value)) return RANGE_COPY.integer[language];
  if ((opts.min !== undefined && value < opts.min) || (opts.max !== undefined && value > opts.max)) {
    return RANGE_COPY.outOfRange[language].replace("{range}", rangeText(language, opts.min, opts.max));
  }
  return null;
}

export type NumberInputProps = {
  label: string;
  value: number | null;
  onChange: (value: number | null) => void;
  min?: number;
  max?: number;
  integer?: boolean;
  /** Unit word shown at the end, e.g. «ثانیه». */
  unit?: string;
  helperText?: string;
  error?: string | null;
  disabled?: boolean;
  fullWidth?: boolean;
};

/** A number field that accepts Persian digits and explains its range in words. */
export function NumberInput({ label, value, onChange, min, max, integer, unit, helperText, error, disabled, fullWidth = true }: NumberInputProps) {
  const { language } = useKit();
  const [text, setText] = useState(value === null ? "" : formatNumber(value, language, { useGrouping: false, maximumFractionDigits: 6 }));
  useEffect(() => {
    if (parseLocalizedNumber(text) !== value) setText(value === null ? "" : formatNumber(value, language, { useGrouping: false, maximumFractionDigits: 6 }));
    // Resync only when the outside value (or language) changes, not on every keystroke.
  }, [value, language]);
  const parsed = parseLocalizedNumber(text);
  const problem = error ?? (text ? numberProblem(language, parsed, { min, max, integer }) : null);
  return (
    <TextField
      label={label}
      value={text}
      disabled={disabled}
      fullWidth={fullWidth}
      size="small"
      onChange={(event) => {
        setText(event.target.value);
        onChange(parseLocalizedNumber(event.target.value));
      }}
      error={Boolean(problem)}
      helperText={problem ?? helperText ?? (min !== undefined || max !== undefined ? rangeText(language, min, max) : " ")}
      slotProps={{
        htmlInput: { inputMode: integer ? "numeric" : "decimal", "aria-invalid": Boolean(problem) || undefined },
        input: unit ? { endAdornment: <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "nowrap", pl: 1 }}>{unit}</Typography> } : undefined
      }}
    />
  );
}

// ── DurationInput ────────────────────────────────────────────────────────────

const DURATION_UNITS = [
  { key: "seconds", factor: 1, fa: "ثانیه", en: "seconds" },
  { key: "minutes", factor: 60, fa: "دقیقه", en: "minutes" },
  { key: "hours", factor: 3600, fa: "ساعت", en: "hours" },
  { key: "days", factor: 86400, fa: "روز", en: "days" }
] as const;
type DurationUnit = (typeof DURATION_UNITS)[number]["key"];

function bestDurationUnit(seconds: number | null, allowed: readonly DurationUnit[]): DurationUnit {
  if (!seconds) return allowed[0];
  const fitting = [...DURATION_UNITS].reverse().find((unit) => allowed.includes(unit.key) && seconds % unit.factor === 0);
  return fitting?.key ?? allowed[0];
}

export type DurationInputProps = {
  label: string;
  /** Value in seconds. */
  value: number | null;
  onChange: (seconds: number | null) => void;
  /** Range in seconds. */
  min?: number;
  max?: number;
  units?: DurationUnit[];
  helperText?: string;
  error?: string | null;
  disabled?: boolean;
};

/** Number + unit select («۸» «ساعت») stored as seconds. Never shows 28800. */
export function DurationInput({ label, value, onChange, min, max, units = ["seconds", "minutes", "hours", "days"], helperText, error, disabled }: DurationInputProps) {
  const { language } = useKit();
  const [unit, setUnit] = useState<DurationUnit>(() => bestDurationUnit(value, units));
  const factor = DURATION_UNITS.find((item) => item.key === unit)?.factor ?? 1;
  const shown = value === null ? null : value / factor;
  const outOfRange = value !== null && ((min !== undefined && value < min) || (max !== undefined && value > max));
  const rangeHint = useMemo(() => {
    const fmt = (seconds: number) => {
      const best = bestDurationUnit(seconds, ["seconds", "minutes", "hours", "days"]);
      const item = DURATION_UNITS.find((entry) => entry.key === best) ?? DURATION_UNITS[0];
      return `${formatNumber(seconds / item.factor, language)} ${item[language]}`;
    };
    if (min !== undefined && max !== undefined) return language === "fa" ? `بین ${fmt(min)} تا ${fmt(max)}` : `from ${fmt(min)} to ${fmt(max)}`;
    if (min !== undefined) return language === "fa" ? `دست‌کم ${fmt(min)}` : `at least ${fmt(min)}`;
    if (max !== undefined) return language === "fa" ? `حداکثر ${fmt(max)}` : `at most ${fmt(max)}`;
    return undefined;
  }, [language, min, max]);
  const problem = error ?? (outOfRange ? (language === "fa" ? `باید ${rangeHint} باشد.` : `Must be ${rangeHint}.`) : null);
  return (
    <Stack spacing={0.5}>
      <Stack direction="row" spacing={1} alignItems="flex-start">
        <NumberInput label={label} value={shown} onChange={(next) => onChange(next === null ? null : Math.round(next * factor))} min={0} disabled={disabled} error={problem} helperText=" " />
        <FormControl size="small" sx={{ minWidth: 110 }} disabled={disabled}>
          <InputLabel id={`${label}-unit`}>{language === "fa" ? "واحد" : "Unit"}</InputLabel>
          <Select labelId={`${label}-unit`} label={language === "fa" ? "واحد" : "Unit"} value={unit} onChange={(event) => setUnit(event.target.value as DurationUnit)}>
            {DURATION_UNITS.filter((item) => units.includes(item.key)).map((item) => (
              <MenuItem key={item.key} value={item.key}>{item[language]}</MenuItem>
            ))}
          </Select>
        </FormControl>
      </Stack>
      {(helperText || rangeHint) && !problem && <FormHelperText sx={{ mt: -2 }}>{helperText ?? rangeHint}</FormHelperText>}
    </Stack>
  );
}

// ── BytesInput ───────────────────────────────────────────────────────────────

const BYTE_UNITS = [
  { key: "KB", factor: 1024, fa: "کیلوبایت" },
  { key: "MB", factor: 1024 ** 2, fa: "مگابایت" },
  { key: "GB", factor: 1024 ** 3, fa: "گیگابایت" },
  { key: "TB", factor: 1024 ** 4, fa: "ترابایت" }
] as const;
type ByteUnit = (typeof BYTE_UNITS)[number]["key"];

export type BytesInputProps = {
  label: string;
  /** Value in bytes. */
  value: number | null;
  onChange: (bytes: number | null) => void;
  min?: number;
  max?: number;
  helperText?: string;
  error?: string | null;
  disabled?: boolean;
};

/** Number + unit select («۵» «گیگابایت») stored as bytes. */
export function BytesInput({ label, value, onChange, min, max, helperText, error, disabled }: BytesInputProps) {
  const { language } = useKit();
  const initial: ByteUnit = value ? ([...BYTE_UNITS].reverse().find((unit) => value >= unit.factor && value % unit.factor === 0)?.key ?? "MB") : "MB";
  const [unit, setUnit] = useState<ByteUnit>(initial);
  const factor = BYTE_UNITS.find((item) => item.key === unit)?.factor ?? 1;
  const outOfRange = value !== null && ((min !== undefined && value < min) || (max !== undefined && value > max));
  const problem = error ?? (outOfRange ? (language === "fa" ? "این اندازه خارج از محدوده مجاز است." : "This size is outside the allowed range.") : null);
  return (
    <Stack direction="row" spacing={1} alignItems="flex-start">
      <NumberInput
        label={label}
        value={value === null ? null : Math.round((value / factor) * 100) / 100}
        onChange={(next) => onChange(next === null ? null : Math.round(next * factor))}
        min={0}
        disabled={disabled}
        error={problem}
        helperText={helperText ?? " "}
      />
      <FormControl size="small" sx={{ minWidth: 120 }} disabled={disabled}>
        <InputLabel id={`${label}-bytes-unit`}>{language === "fa" ? "واحد" : "Unit"}</InputLabel>
        <Select labelId={`${label}-bytes-unit`} label={language === "fa" ? "واحد" : "Unit"} value={unit} onChange={(event) => setUnit(event.target.value as ByteUnit)}>
          {BYTE_UNITS.map((item) => (
            <MenuItem key={item.key} value={item.key}>{language === "fa" ? item.fa : item.key}</MenuItem>
          ))}
        </Select>
      </FormControl>
    </Stack>
  );
}

// ── ListInput ────────────────────────────────────────────────────────────────

export type ListInputProps = {
  label: string;
  value: string[];
  onChange: (value: string[]) => void;
  /** Validate one entry; return a sentence to reject it. */
  validate?: (item: string) => string | null;
  max?: number;
  placeholder?: string;
  helperText?: string;
  /** Entries are technical (IPs, hostnames): LTR. Default true. */
  ltr?: boolean;
  suggestions?: string[];
  disabled?: boolean;
};

/** A list of short values as chips. Type and press Enter (or paste several lines). */
export function ListInput({ label, value, onChange, validate, max, placeholder, helperText, ltr = true, suggestions = [], disabled }: ListInputProps) {
  const { language } = useKit();
  const [problem, setProblem] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const add = (raw: string[]) => {
    const items = raw.flatMap((entry) => entry.split(/[\n,،]+/)).map((entry) => entry.trim()).filter(Boolean);
    const next = [...value];
    for (const item of items) {
      const issue = validate?.(item) ?? null;
      if (issue) {
        setProblem(issue);
        return;
      }
      if (max !== undefined && next.length >= max) {
        setProblem(language === "fa" ? `حداکثر ${formatNumber(max, language)} مورد.` : `At most ${max} items.`);
        return;
      }
      if (!next.includes(item)) next.push(item);
    }
    setProblem(null);
    onChange(next);
  };
  return (
    <Autocomplete
      multiple
      freeSolo
      disabled={disabled}
      options={suggestions}
      value={value}
      inputValue={input}
      onInputChange={(_event, next, reason) => {
        if (reason === "input" && /[\n,،]/.test(next)) {
          add([next]);
          setInput("");
        } else {
          setInput(next);
        }
      }}
      onChange={(_event, next) => {
        const added = next.filter((item) => !value.includes(item));
        if (added.length) add(added);
        else onChange(next);
      }}
      renderValue={(selected, getItemProps) =>
        selected.map((option, index) => {
          const { key, ...itemProps } = getItemProps({ index });
          return <Chip key={key} {...itemProps} size="small" label={<bdi dir={ltr ? "ltr" : undefined}>{option}</bdi>} />;
        })
      }
      renderInput={(params) => (
        <TextField
          {...params}
          size="small"
          label={label}
          placeholder={placeholder}
          error={Boolean(problem)}
          helperText={problem ?? helperText ?? (language === "fa" ? "هر مورد را بنویسید و Enter بزنید." : "Type an item and press Enter.")}
          inputProps={{ ...params.inputProps, dir: ltr ? "ltr" : undefined }}
        />
      )}
    />
  );
}

// ── PercentSlider ────────────────────────────────────────────────────────────

/** «وقتی بیشتر از ۹۰٪ شد» slider with localized value label. */
export function PercentSlider({ label, value, onChange, min = 1, max = 100, step = 1, disabled }: { label: string; value: number; onChange: (value: number) => void; min?: number; max?: number; step?: number; disabled?: boolean }) {
  const { language } = useKit();
  const text = (v: number) => `${formatNumber(v, language)}٪`.replace("٪", language === "fa" ? "٪" : "%");
  return (
    <Box>
      <Typography variant="body2" id={`${label}-slider`} gutterBottom>
        {label}: <strong>{text(value)}</strong>
      </Typography>
      <Slider
        aria-labelledby={`${label}-slider`}
        value={value}
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        valueLabelDisplay="auto"
        valueLabelFormat={text}
        getAriaValueText={text}
        onChange={(_event, next) => onChange(next as number)}
      />
    </Box>
  );
}

// ── SchedulePicker ───────────────────────────────────────────────────────────

export type SchedulePreset = "nightly" | "weekly" | "monthly" | "hourly" | "custom";

const WEEKDAYS = {
  fa: ["یکشنبه", "دوشنبه", "سه‌شنبه", "چهارشنبه", "پنجشنبه", "جمعه", "شنبه"],
  en: ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
};

/** Build a cron string from a preset (minute 0 at `hour`). */
export function presetToCron(preset: Exclude<SchedulePreset, "custom">, hour: number, weekday = 5, monthday = 1): string {
  if (preset === "hourly") return "0 * * * *";
  if (preset === "nightly") return `0 ${hour} * * *`;
  if (preset === "weekly") return `0 ${hour} * * ${weekday}`;
  return `0 ${hour} ${monthday} * *`;
}

/** Recognise a cron string as one of the presets (for showing «هر شب ساعت ۲»). */
export function cronToPreset(cron: string): { preset: SchedulePreset; hour: number; weekday: number; monthday: number } {
  const parts = cron.trim().split(/\s+/);
  const fallback = { preset: "custom" as SchedulePreset, hour: 2, weekday: 5, monthday: 1 };
  if (parts.length !== 5 || parts[0] !== "0") return fallback;
  const [, h, dom, mon, dow] = parts;
  if (h === "*" && dom === "*" && mon === "*" && dow === "*") return { ...fallback, preset: "hourly" };
  const hour = Number(h);
  if (!Number.isInteger(hour) || hour < 0 || hour > 23 || mon !== "*") return fallback;
  if (dom === "*" && dow === "*") return { preset: "nightly", hour, weekday: 5, monthday: 1 };
  if (dom === "*" && /^[0-6]$/.test(dow)) return { preset: "weekly", hour, weekday: Number(dow), monthday: 1 };
  if (/^([1-9]|1\d|2[0-8])$/.test(dom) && dow === "*") return { preset: "monthly", hour, weekday: 5, monthday: Number(dom) };
  return fallback;
}

/** A plain sentence for a cron schedule: «هر شب ساعت ۲», «هر جمعه ساعت ۳». */
export function describeSchedule(cron: string, language: "fa" | "en"): string {
  const { preset, hour, weekday, monthday } = cronToPreset(cron);
  const h = formatNumber(hour, language);
  if (preset === "hourly") return language === "fa" ? "هر ساعت" : "Every hour";
  if (preset === "nightly") return language === "fa" ? `هر شب ساعت ${h}` : `Every night at ${hour}:00`;
  if (preset === "weekly") return language === "fa" ? `هر ${WEEKDAYS.fa[weekday]} ساعت ${h}` : `Every ${WEEKDAYS.en[weekday]} at ${hour}:00`;
  if (preset === "monthly") return language === "fa" ? `روز ${formatNumber(monthday, language)} هر ماه، ساعت ${h}` : `On day ${monthday} of each month at ${hour}:00`;
  return language === "fa" ? "زمان‌بندی سفارشی" : "Custom schedule";
}

export type SchedulePickerProps = {
  /** A 5-field cron string. */
  value: string;
  onChange: (cron: string) => void;
  label?: string;
  /** Validate a custom cron (e.g. `cronValid` from ServerBackupsPanel). */
  validateCron?: (cron: string) => boolean;
  disabled?: boolean;
};

/** Presets («هر شب», «هر هفته», «هر ماه») + hour; raw cron only in Advanced «سفارشی». */
export function SchedulePicker({ value, onChange, label, validateCron, disabled }: SchedulePickerProps) {
  const { language, isAdvanced } = useKit();
  const parsed = cronToPreset(value);
  const [custom, setCustom] = useState(value);
  const presets: { key: SchedulePreset; fa: string; en: string }[] = [
    { key: "nightly", fa: "هر شب", en: "Every night" },
    { key: "weekly", fa: "هر هفته", en: "Every week" },
    { key: "monthly", fa: "هر ماه", en: "Every month" },
    { key: "hourly", fa: "هر ساعت", en: "Every hour" },
    ...(isAdvanced || parsed.preset === "custom" ? [{ key: "custom" as SchedulePreset, fa: "سفارشی", en: "Custom" }] : [])
  ];
  const set = (preset: SchedulePreset, hour = parsed.hour, weekday = parsed.weekday, monthday = parsed.monthday) => {
    if (preset === "custom") onChange(custom);
    else onChange(presetToCron(preset, hour, weekday, monthday));
  };
  const cronBad = parsed.preset === "custom" && validateCron ? !validateCron(custom) : false;
  return (
    <Stack spacing={1.5}>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
        <FormControl size="small" sx={{ minWidth: 150 }} disabled={disabled}>
          <InputLabel id="mrk-schedule-preset">{label ?? (language === "fa" ? "چند وقت یک بار" : "How often")}</InputLabel>
          <Select labelId="mrk-schedule-preset" label={label ?? (language === "fa" ? "چند وقت یک بار" : "How often")} value={parsed.preset} onChange={(event) => set(event.target.value as SchedulePreset)}>
            {presets.map((item) => <MenuItem key={item.key} value={item.key}>{item[language]}</MenuItem>)}
          </Select>
        </FormControl>
        {parsed.preset === "weekly" && (
          <FormControl size="small" sx={{ minWidth: 140 }} disabled={disabled}>
            <InputLabel id="mrk-schedule-weekday">{language === "fa" ? "روز" : "Day"}</InputLabel>
            <Select labelId="mrk-schedule-weekday" label={language === "fa" ? "روز" : "Day"} value={parsed.weekday} onChange={(event) => set("weekly", parsed.hour, Number(event.target.value))}>
              {[6, 0, 1, 2, 3, 4, 5].map((day) => <MenuItem key={day} value={day}>{WEEKDAYS[language][day]}</MenuItem>)}
            </Select>
          </FormControl>
        )}
        {parsed.preset === "monthly" && (
          <FormControl size="small" sx={{ minWidth: 120 }} disabled={disabled}>
            <InputLabel id="mrk-schedule-monthday">{language === "fa" ? "روز ماه" : "Day of month"}</InputLabel>
            <Select labelId="mrk-schedule-monthday" label={language === "fa" ? "روز ماه" : "Day of month"} value={parsed.monthday} onChange={(event) => set("monthly", parsed.hour, parsed.weekday, Number(event.target.value))}>
              {Array.from({ length: 28 }, (_, i) => i + 1).map((day) => <MenuItem key={day} value={day}>{formatNumber(day, language)}</MenuItem>)}
            </Select>
          </FormControl>
        )}
        {parsed.preset !== "hourly" && parsed.preset !== "custom" && (
          <FormControl size="small" sx={{ minWidth: 110 }} disabled={disabled}>
            <InputLabel id="mrk-schedule-hour">{language === "fa" ? "ساعت" : "Hour"}</InputLabel>
            <Select labelId="mrk-schedule-hour" label={language === "fa" ? "ساعت" : "Hour"} value={parsed.hour} onChange={(event) => set(parsed.preset, Number(event.target.value))}>
              {Array.from({ length: 24 }, (_, i) => i).map((hour) => (
                <MenuItem key={hour} value={hour}>{formatNumber(hour, language, { minimumIntegerDigits: 2 })}:{formatNumber(0, language, { minimumIntegerDigits: 2 })}</MenuItem>
              ))}
            </Select>
          </FormControl>
        )}
      </Stack>
      {parsed.preset === "custom" ? (
        <TextField
          size="small"
          label={language === "fa" ? "عبارت زمان‌بندی (cron)" : "Cron expression"}
          value={custom}
          disabled={disabled}
          onChange={(event) => {
            setCustom(event.target.value);
            onChange(event.target.value);
          }}
          error={cronBad}
          helperText={cronBad ? (language === "fa" ? "این عبارت را نفهمیدیم؛ پنج بخش دارد: دقیقه، ساعت، روز ماه، ماه، روز هفته." : "We couldn't read this; it has five parts: minute hour day month weekday.") : describeSchedule(value, language)}
          slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
        />
      ) : (
        <Typography variant="body2" color="text.secondary">{describeSchedule(value, language)}</Typography>
      )}
    </Stack>
  );
}

// ── TimezonePicker ───────────────────────────────────────────────────────────

const TZ_FA: Record<string, string> = {
  "Asia/Tehran": "تهران",
  UTC: "زمان جهانی (UTC)",
  "Asia/Dubai": "دبی",
  "Europe/Istanbul": "استانبول",
  "Europe/Berlin": "برلین",
  "Europe/London": "لندن"
};

/** Time zone picker with Persian names for common zones; default «تهران». */
export function TimezonePicker({ label, value, onChange, disabled }: { label?: string; value: string; onChange: (zone: string) => void; disabled?: boolean }) {
  const { language } = useKit();
  const zones = useMemo(() => {
    try {
      const all = (Intl as unknown as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.("timeZone") ?? [];
      const list = all.length ? all : Object.keys(TZ_FA);
      return ["Asia/Tehran", "UTC", ...list.filter((zone) => zone !== "Asia/Tehran" && zone !== "UTC")];
    } catch {
      return Object.keys(TZ_FA);
    }
  }, []);
  const name = (zone: string) => (language === "fa" && TZ_FA[zone] ? TZ_FA[zone] : zone.replace(/_/g, " "));
  return (
    <Autocomplete
      disabled={disabled}
      options={zones}
      value={value}
      disableClearable
      getOptionLabel={name}
      onChange={(_event, next) => next && onChange(next)}
      renderInput={(params) => <TextField {...params} size="small" label={label ?? (language === "fa" ? "منطقه زمانی" : "Time zone")} />}
    />
  );
}
