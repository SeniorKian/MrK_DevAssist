import type { ReactNode } from "react";
import { Box, Tooltip } from "@mui/material";
import { formatBytes, formatNumber, formatPercent } from "../format";
import { formatAbsolute, formatDuration, formatRelative, formatWithUnit, type UnitKey } from "./formatters";
import { useKit } from "./useKit";

/**
 * Technical text (paths, URLs, hostnames, commands, ids) inside a Persian sentence.
 * Keeps it Latin and left-to-right without breaking the surrounding RTL text.
 */
export function Ltr({ children, mono = false }: { children: ReactNode; mono?: boolean }) {
  return (
    <Box
      component="bdi"
      dir="ltr"
      sx={{ unicodeBidi: "isolate", fontFamily: mono ? "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" : undefined, fontSize: mono ? "0.92em" : undefined, overflowWrap: "anywhere" }}
    >
      {children}
    </Box>
  );
}

/** A localized number (Persian digits in fa). */
export function Num({ value, options }: { value: number | null | undefined; options?: Intl.NumberFormatOptions }) {
  const { language } = useKit();
  return <>{formatNumber(value, language, options)}</>;
}

/** A percentage in the 0–100 range, e.g. «۸۷٪». */
export function Percent({ value }: { value: number | null | undefined }) {
  const { language } = useKit();
  return <>{formatPercent(value, language)}</>;
}

/** A size in bytes, e.g. «۱٫۲ گیگابایت». */
export function Bytes({ value }: { value: number | null | undefined }) {
  const { language } = useKit();
  return <>{formatBytes(value, language)}</>;
}

/** A duration in seconds, e.g. «۸ ساعت». */
export function Duration({ seconds, parts }: { seconds: number | null | undefined; parts?: number }) {
  const { language } = useKit();
  return <>{formatDuration(seconds, language, parts)}</>;
}

/** A value with a unit from the settings schema. */
export function WithUnit({ value, unit }: { value: number | null | undefined; unit?: UnitKey | null }) {
  const { language } = useKit();
  return <>{formatWithUnit(value, unit, language)}</>;
}

/**
 * Relative time («۱۰ دقیقه پیش») with the absolute Jalali date in a tooltip.
 * Advanced mode shows the absolute time directly (docs/33 §2.4) unless `relativeAlways`.
 */
export function RelativeTime({ value, relativeAlways = false }: { value: number | string | Date | null | undefined; relativeAlways?: boolean }) {
  const { language, isAdvanced } = useKit();
  const absolute = formatAbsolute(value, language);
  if (absolute === "—") return <>—</>;
  if (isAdvanced && !relativeAlways) return <time>{absolute}</time>;
  return (
    <Tooltip title={absolute}>
      <Box component="time" tabIndex={0} sx={{ borderBottom: "1px dotted", borderColor: "divider", cursor: "help" }}>
        {formatRelative(value, language)}
      </Box>
    </Tooltip>
  );
}

/** Absolute date/time (Jalali in fa). */
export function DateTime({ value, options }: { value: number | string | Date | null | undefined; options?: Intl.DateTimeFormatOptions }) {
  const { language } = useKit();
  return <time>{formatAbsolute(value, language, options)}</time>;
}
