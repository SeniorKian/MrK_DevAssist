/**
 * Tiny helpers shared by every copy module.
 *
 * - `Bi` is one piece of copy in both languages.
 * - `pick` chooses the language.
 * - `fill` replaces `{name}` placeholders. Numbers are written with Persian digits in fa.
 */
import type { Language } from "../i18n";

export type Bi = { fa: string; en: string };

export function pick(language: Language, text: Bi): string {
  return text[language] ?? text.en;
}

export type FillValue = string | number | null | undefined;

function localizeNumber(value: number, language: Language) {
  return new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(value);
}

/** Replace `{key}` placeholders; numeric values are localized, missing keys become an empty string. */
export function fill(template: string, params: Record<string, FillValue> = {}, language: Language = "en"): string {
  return template.replace(/\{(\w+)\}/g, (_match, key: string) => {
    const value = params[key];
    if (value === null || value === undefined) return "";
    return typeof value === "number" ? localizeNumber(value, language) : value;
  });
}

/** `pick` + `fill` in one call. */
export function say(language: Language, text: Bi, params?: Record<string, FillValue>): string {
  return fill(pick(language, text), params, language);
}

/** Convert ASCII digits inside a sentence to Persian digits (for fa). Leaves anything else untouched. */
export function persianDigits(value: string): string {
  return value.replace(/[0-9]/g, (digit) => "۰۱۲۳۴۵۶۷۸۹"[Number(digit)]);
}

/**
 * Normalise text typed on any keyboard so comparisons are fair:
 * Arabic ي/ك → Persian ی/ک, diacritics and direction marks removed, digits unified, case folded.
 * Spaces and half-spaces are dropped entirely, so «پاک کن», «پاک‌کن» and «پاککن» are all equal.
 */
export function normalizeTyped(value: string): string {
  return value
    .replace(/[يى]/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[أإآ]/g, "ا")
    .replace(/[ً-ٰٟ‎‏‪-‮⁦-⁩]/g, "")
    .replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit)))
    .replace(/[٠-٩]/g, (digit) => String("٠١٢٣٤٥٦٧٨٩".indexOf(digit)))
    .replace(/[\s‌‍]+/g, "")
    .toLowerCase();
}
