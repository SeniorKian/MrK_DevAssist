/**
 * Human formatting (docs/33 §2.4). Persian output uses Persian digits and the Jalali calendar
 * (`fa-IR-u-ca-persian-nu-arabext`); English uses the Gregorian calendar.
 * These complement `../format.ts` (numbers, bytes, percent) and add relative times and durations.
 */
import type { Language } from "../i18n";
import { formatBytes, formatNumber, toUnixSeconds } from "../format";

export function dateLocale(language: Language) {
  return language === "fa" ? "fa-IR-u-ca-persian-nu-arabext" : "en-US";
}

function toDate(value: number | string | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  const seconds = toUnixSeconds(value);
  if (seconds === null || seconds === 0) return null;
  return new Date(seconds * 1000);
}

/** Absolute date + time (Jalali in fa). Accepts UNIX seconds/ms, ISO strings or Dates. */
export function formatAbsolute(
  value: number | string | Date | null | undefined,
  language: Language,
  options: Intl.DateTimeFormatOptions = { dateStyle: "medium", timeStyle: "short" }
): string {
  const date = toDate(value);
  if (!date) return "—";
  return new Intl.DateTimeFormat(dateLocale(language), options).format(date);
}

/** Time of day only, e.g. «۲۳:۱۰». */
export function formatClock(value: number | string | Date | null | undefined, language: Language): string {
  return formatAbsolute(value, language, { hour: "2-digit", minute: "2-digit", hour12: false });
}

/**
 * Relative time for recent events: «همین حالا», «۱۰ دقیقه پیش», «دیروز ساعت ۲۳:۱۰»;
 * older than a week → absolute date. Future times read «۵ دقیقه دیگر».
 */
export function formatRelative(value: number | string | Date | null | undefined, language: Language, now: number = Date.now()): string {
  const date = toDate(value);
  if (!date) return "—";
  const diffSeconds = Math.round((date.getTime() - now) / 1000);
  const abs = Math.abs(diffSeconds);
  if (abs < 45) return language === "fa" ? "همین حالا" : "just now";
  const rtf = new Intl.RelativeTimeFormat(language === "fa" ? "fa-IR" : "en-US", { numeric: "auto" });
  if (abs < 3600) return rtf.format(Math.round(diffSeconds / 60), "minute");
  const startOfToday = new Date(now);
  startOfToday.setHours(0, 0, 0, 0);
  const dayDiff = Math.round((new Date(date).setHours(0, 0, 0, 0) - startOfToday.getTime()) / 86_400_000);
  if (dayDiff === 0) return rtf.format(Math.round(diffSeconds / 3600), "hour");
  if (dayDiff === -1 || dayDiff === 1) {
    const day = rtf.format(dayDiff, "day");
    const clock = formatClock(date, language);
    return language === "fa" ? `${day} ساعت ${clock}` : `${day} at ${clock}`;
  }
  if (Math.abs(dayDiff) < 7) return rtf.format(dayDiff, "day");
  return formatAbsolute(date, language, { dateStyle: "medium" });
}

const DURATION_UNITS = [
  { seconds: 86_400, fa: "روز", en: ["day", "days"] },
  { seconds: 3_600, fa: "ساعت", en: ["hour", "hours"] },
  { seconds: 60, fa: "دقیقه", en: ["minute", "minutes"] },
  { seconds: 1, fa: "ثانیه", en: ["second", "seconds"] }
] as const;

/**
 * Seconds → human words: 28800 → «۸ ساعت», 90 → «۱ دقیقه و ۳۰ ثانیه».
 * `parts` limits how many units are shown (default 2).
 */
export function formatDuration(totalSeconds: number | null | undefined, language: Language, parts = 2): string {
  if (totalSeconds === null || totalSeconds === undefined || !Number.isFinite(totalSeconds)) return "—";
  let remaining = Math.max(0, Math.round(totalSeconds));
  if (remaining === 0) return language === "fa" ? "۰ ثانیه" : "0 seconds";
  const pieces: string[] = [];
  for (const unit of DURATION_UNITS) {
    if (pieces.length >= parts) break;
    const count = Math.floor(remaining / unit.seconds);
    if (count > 0) {
      remaining -= count * unit.seconds;
      const number = formatNumber(count, language);
      pieces.push(language === "fa" ? `${number} ${unit.fa}` : `${number} ${count === 1 ? unit.en[0] : unit.en[1]}`);
    }
  }
  return pieces.join(language === "fa" ? " و " : " ");
}

/** Bytes in plain units; Simple mode uses decimal-looking names (KB/MB/GB) as in format.ts. */
export function formatSize(value: number | null | undefined, language: Language): string {
  return formatBytes(value, language);
}

export type UnitKey = "percent" | "seconds" | "minutes" | "hours" | "days" | "ms" | "bytes" | "mb" | "count" | "per_second";

const UNIT_WORDS: Record<UnitKey, { fa: string; en: string }> = {
  percent: { fa: "٪", en: "%" },
  seconds: { fa: "ثانیه", en: "seconds" },
  minutes: { fa: "دقیقه", en: "minutes" },
  hours: { fa: "ساعت", en: "hours" },
  days: { fa: "روز", en: "days" },
  ms: { fa: "میلی‌ثانیه", en: "ms" },
  bytes: { fa: "بایت", en: "bytes" },
  mb: { fa: "مگابایت", en: "MB" },
  count: { fa: "عدد", en: "" },
  per_second: { fa: "در ثانیه", en: "per second" }
};

export function unitWord(unit: UnitKey | null | undefined, language: Language): string {
  if (!unit) return "";
  return UNIT_WORDS[unit][language];
}

/** A number with its unit: (90, "percent") → «۹۰٪», (15, "seconds") → «۱۵ ثانیه». */
export function formatWithUnit(value: number | null | undefined, unit: UnitKey | null | undefined, language: Language): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  if (unit === "bytes") return formatBytes(value, language);
  if (unit === "seconds" && value >= 60) return formatDuration(value, language);
  const number = formatNumber(value, language, { maximumFractionDigits: 2 });
  if (unit === "percent") return `${number}${unitWord(unit, language)}`;
  const word = unitWord(unit, language);
  return word ? `${number} ${word}` : number;
}
