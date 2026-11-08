import type { Language } from "./i18n";

/** Locale-aware formatting helpers. Persian output uses Persian digits and the Persian calendar. */

export function localeOf(language: Language) {
  return language === "fa" ? "fa-IR" : "en-US";
}

export function formatNumber(value: number | null | undefined, language: Language, options?: Intl.NumberFormatOptions) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return new Intl.NumberFormat(localeOf(language), options).format(value);
}

/** `value` is a percentage in the 0–100 range. */
export function formatPercent(value: number | null | undefined, language: Language) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return new Intl.NumberFormat(localeOf(language), { style: "percent", maximumFractionDigits: 1 }).format(value / 100);
}

const BYTE_UNITS = {
  fa: ["بایت", "کیلوبایت", "مگابایت", "گیگابایت", "ترابایت"],
  en: ["B", "KB", "MB", "GB", "TB"]
} as const;

export function formatBytes(value: number | null | undefined, language: Language) {
  const units = BYTE_UNITS[language];
  if (value === null || value === undefined || !Number.isFinite(value) || value <= 0) return `${formatNumber(0, language)} ${units[0]}`;
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${formatNumber(value / 1024 ** exponent, language, { maximumFractionDigits: exponent === 0 ? 0 : 1 })} ${units[exponent]}`;
}

export function formatMs(value: number | null | undefined, language: Language) {
  return `${formatNumber(value ?? 0, language, { maximumFractionDigits: 1 })} ${language === "fa" ? "میلی‌ثانیه" : "ms"}`;
}

export function formatSeconds(value: number | null | undefined, language: Language) {
  return `${formatNumber(value ?? 0, language, { maximumFractionDigits: 1 })} ${language === "fa" ? "ثانیه" : "s"}`;
}

/** Format a UNIX timestamp in seconds (or a Date). Returns "—" for empty values. */
export function formatDateTime(value: number | Date | null | undefined, language: Language, options?: Intl.DateTimeFormatOptions) {
  if (value === null || value === undefined || value === 0) return "—";
  const date = value instanceof Date ? value : new Date(value * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(localeOf(language), options ?? { dateStyle: "medium", timeStyle: "short" }).format(date);
}

/** Accept UNIX seconds, UNIX milliseconds or an ISO/RFC3339 string; return UNIX seconds or null. */
export function toUnixSeconds(value: number | string | null | undefined): number | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") return Number.isFinite(value) ? (value > 1e12 ? value / 1000 : value) : null;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric > 1e12 ? numeric / 1000 : numeric;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed / 1000;
}

/** Bytes per second, e.g. "1.2 MB/s". */
export function formatRate(value: number | null | undefined, language: Language) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return `${formatBytes(value, language)}/${language === "fa" ? "ثانیه" : "s"}`;
}
