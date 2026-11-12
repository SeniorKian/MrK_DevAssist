/**
 * Small SVG visuals for the server overview: radial gauge, per-core heat map,
 * usage bar and stacked breakdown bar. Dependency-free, theme-aware (light/dark),
 * and never colour-only: every gauge prints its value and a status word, every
 * heat-map cell has a text tooltip and the map has a text summary.
 *
 * Plots are drawn left-to-right in both languages (numbers and time stay LTR).
 */
import { useId, useMemo, useState } from "react";
import { Box, Stack, Typography, useTheme, type Theme } from "@mui/material";
import type { Tone } from "./copy/kinds";

/** Validated categorical slots (dataviz reference palette), light and dark steps. */
const SERIES = {
  light: { blue: "#2a78d6", orange: "#eb6834", aqua: "#1baf7a", violet: "#6250d6", magenta: "#e87ba4", yellow: "#eda100" },
  dark: { blue: "#3987e5", orange: "#d95926", aqua: "#199e70", violet: "#9085e9", magenta: "#d55181", yellow: "#c98500" }
} as const;

export type SeriesColor = keyof (typeof SERIES)["light"];

export function useSeriesColors() {
  const theme = useTheme();
  return SERIES[theme.palette.mode === "dark" ? "dark" : "light"];
}

export function toneColor(theme: Theme, tone: Tone): string {
  switch (tone) {
    case "ok": return theme.palette.success.main;
    case "warn": return theme.palette.warning.main;
    case "error": return theme.palette.error.main;
    case "busy": return theme.palette.primary.main;
    case "info": return theme.palette.info.main;
    default: return theme.palette.text.disabled;
  }
}

/** ok below `warn`, warn below `error`, error at or above; info when unknown. */
export function thresholdTone(value: number | null | undefined, warn: number, error: number): Tone {
  if (value === null || value === undefined || !Number.isFinite(value)) return "off";
  if (value >= error) return "error";
  if (value >= warn) return "warn";
  return "ok";
}

// ── Gauge ────────────────────────────────────────────────────────────────────

const SWEEP = 240;
const START = -120;

function polar(cx: number, cy: number, r: number, degrees: number) {
  const radians = ((degrees - 90) * Math.PI) / 180;
  return [cx + r * Math.cos(radians), cy + r * Math.sin(radians)] as const;
}

function arcPath(cx: number, cy: number, r: number, from: number, to: number) {
  const [x1, y1] = polar(cx, cy, r, from);
  const [x2, y2] = polar(cx, cy, r, to);
  const large = to - from > 180 ? 1 : 0;
  return `M${x1.toFixed(2)},${y1.toFixed(2)} A${r},${r} 0 ${large} 1 ${x2.toFixed(2)},${y2.toFixed(2)}`;
}

export type GaugeProps = {
  label: string;
  /** Already formatted value for the centre ("26%", "48 °C"); "—" when unknown. */
  valueText: string;
  /** Position on the dial, 0–100 (null = unknown). */
  percent: number | null;
  tone: Tone;
  /** Short status word printed under the value so state is never colour-only. */
  statusText?: string;
  /** Dial positions (0–100) where warning/critical begin; drawn as small ticks. */
  marks?: number[];
  caption?: string;
  size?: number;
};

export function Gauge({ label, valueText, percent, tone, statusText, marks = [], caption, size = 168 }: GaugeProps) {
  const theme = useTheme();
  const color = toneColor(theme, tone);
  const value = percent === null || !Number.isFinite(percent) ? 0 : Math.max(0, Math.min(100, percent));
  const cx = 100;
  const cy = 100;
  const r = 78;
  const track = arcPath(cx, cy, r, START, START + SWEEP);
  return (
    <Stack alignItems="center" spacing={0.25} sx={{ minWidth: 0 }}>
      <Box
        dir="ltr"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent === null ? undefined : Math.round(value)}
        aria-valuetext={`${valueText}${statusText ? ` · ${statusText}` : ""}`}
        sx={{ width: "100%", maxWidth: size, aspectRatio: "200 / 168" }}
      >
        <svg viewBox="0 0 200 168" width="100%" height="100%" style={{ display: "block", overflow: "visible" }} aria-hidden>
          <path d={track} fill="none" stroke={theme.palette.divider} strokeWidth={14} strokeLinecap="round" />
          {percent !== null && (
            <path
              d={track}
              fill="none"
              stroke={color}
              strokeWidth={14}
              strokeLinecap="round"
              pathLength={100}
              strokeDasharray={`${Math.max(value, 0.01)} 200`}
              style={{ transition: "stroke-dasharray .7s cubic-bezier(.2,.8,.2,1), stroke .4s" }}
            />
          )}
          {marks.map((mark) => {
            const angle = START + (SWEEP * Math.max(0, Math.min(100, mark))) / 100;
            const [x1, y1] = polar(cx, cy, r - 12, angle);
            const [x2, y2] = polar(cx, cy, r - 19, angle);
            return <line key={mark} x1={x1} y1={y1} x2={x2} y2={y2} stroke={theme.palette.text.secondary} strokeOpacity={0.55} strokeWidth={2} strokeLinecap="round" />;
          })}
          <text x={cx} y={cy + 4} textAnchor="middle" fontSize={34} fontWeight={780} fill={theme.palette.text.primary} style={{ fontFamily: "inherit" }}>
            {valueText}
          </text>
          {statusText && (
            <text x={cx} y={cy + 30} textAnchor="middle" fontSize={14} fontWeight={650} fill={theme.palette.text.secondary} style={{ fontFamily: "inherit" }}>
              {statusText}
            </text>
          )}
        </svg>
      </Box>
      <Typography variant="body2" sx={{ fontWeight: 720, mt: -1.5 }}>{label}</Typography>
      {caption && <Typography variant="caption" color="text.secondary" sx={{ textAlign: "center", lineHeight: 1.6 }}>{caption}</Typography>}
    </Stack>
  );
}

// ── Sequential ramp (one hue, light → dark) for the core heat map ───────────────

const RAMP = {
  light: ["#eef4fc", "#cfe0f7", "#9fc2ee", "#5f98df", "#2a78d6", "#1b56a3", "#0f3770"],
  dark: ["#162231", "#1b3352", "#22477a", "#2d62a8", "#3987e5", "#7aaef0", "#bcd6f8"]
} as const;

function hexToRgb(hex: string) {
  const value = parseInt(hex.slice(1), 16);
  return [(value >> 16) & 255, (value >> 8) & 255, value & 255];
}

export function rampColor(mode: "light" | "dark", percent: number | null) {
  const ramp = RAMP[mode];
  if (percent === null || !Number.isFinite(percent)) return null;
  const position = (Math.max(0, Math.min(100, percent)) / 100) * (ramp.length - 1);
  const low = Math.floor(position);
  const high = Math.min(ramp.length - 1, low + 1);
  const t = position - low;
  const a = hexToRgb(ramp[low]);
  const b = hexToRgb(ramp[high]);
  const mix = a.map((channel, index) => Math.round(channel + (b[index] - channel) * t));
  return `rgb(${mix[0]},${mix[1]},${mix[2]})`;
}

export type HeatMapProps = {
  /** rows[core][time] busy percent. */
  rows: Array<Array<number | null>>;
  rowLabel: (index: number) => string;
  cellText: (row: number, column: number, value: number | null) => string;
  title: string;
  summary: string;
  legendLow: string;
  legendHigh: string;
};

/** Cores × time heat map; each row is one core, time flows left → right. */
export function CoreHeatMap({ rows, rowLabel, cellText, title, summary, legendLow, legendHigh }: HeatMapProps) {
  const theme = useTheme();
  const mode = theme.palette.mode === "dark" ? "dark" : "light";
  const titleId = useId();
  const [hover, setHover] = useState<{ row: number; column: number } | null>(null);
  const columns = rows.reduce((max, row) => Math.max(max, row.length), 0);
  const rowHeight = rows.length > 48 ? 5 : rows.length > 24 ? 8 : rows.length > 12 ? 12 : 16;
  const gap = rows.length > 48 ? 0 : 2;
  const labelWidth = rows.length > 24 ? 0 : 34;
  const width = 600;
  const plotW = width - labelWidth;
  const cellW = columns > 0 ? plotW / columns : plotW;
  const height = rows.length * (rowHeight + gap);
  const empty = theme.palette.action.hover;
  const cells = useMemo(() => rows.map((row) => row.map((value) => rampColor(mode, value))), [rows, mode]);
  const tip = hover ? cellText(hover.row, hover.column, rows[hover.row]?.[hover.column] ?? null) : null;
  return (
    <Box>
      <Box dir="ltr" sx={{ position: "relative" }}>
        <svg viewBox={`0 0 ${width} ${Math.max(height, 1)}`} width="100%" preserveAspectRatio="none" style={{ display: "block", height: Math.max(height, 1) }} role="img" aria-labelledby={titleId} onPointerLeave={() => setHover(null)}>
          <title id={titleId}>{`${title}. ${summary}`}</title>
          {rows.map((row, rowIndex) => (
            <g key={rowIndex}>
              {labelWidth > 0 && (
                <text x={labelWidth - 6} y={rowIndex * (rowHeight + gap) + rowHeight / 2} dy="0.35em" textAnchor="end" fontSize={10} fill={theme.palette.text.secondary} style={{ fontFamily: "inherit" }}>
                  {rowLabel(rowIndex)}
                </text>
              )}
              {row.map((_value, column) => (
                <rect
                  key={column}
                  x={labelWidth + column * cellW}
                  y={rowIndex * (rowHeight + gap)}
                  width={Math.max(cellW - (columns > 120 ? 0 : 1), 0.5)}
                  height={rowHeight}
                  rx={rowHeight > 8 ? 2 : 0}
                  fill={cells[rowIndex][column] ?? empty}
                  onPointerEnter={() => setHover({ row: rowIndex, column })}
                />
              ))}
            </g>
          ))}
        </svg>
      </Box>
      <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={1} sx={{ mt: 1, minHeight: 22 }}>
        <Typography variant="caption" color="text.secondary" role="status" aria-live="off" sx={{ minWidth: 0 }}>{tip ?? summary}</Typography>
        <Stack direction="row" alignItems="center" spacing={0.75} sx={{ flexShrink: 0 }} aria-hidden>
          <Typography variant="caption" color="text.secondary">{legendLow}</Typography>
          <Box dir="ltr" sx={{ width: 72, height: 8, borderRadius: 4, background: `linear-gradient(90deg, ${RAMP[mode].join(",")})` }} />
          <Typography variant="caption" color="text.secondary">{legendHigh}</Typography>
        </Stack>
      </Stack>
    </Box>
  );
}

// ── Bars ─────────────────────────────────────────────────────────────────────

/** A thin usage bar with a status tone (filled from the reading side). */
export function UsageBar({ percent, tone, label, height = 8 }: { percent: number | null; tone: Tone; label: string; height?: number }) {
  const theme = useTheme();
  const value = percent === null || !Number.isFinite(percent) ? 0 : Math.max(0, Math.min(100, percent));
  return (
    <Box role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(value)} sx={{ height, borderRadius: height, bgcolor: "action.hover", overflow: "hidden" }}>
      <Box sx={{ width: `${value}%`, height: "100%", borderRadius: height, bgcolor: toneColor(theme, tone), transition: "width .6s cubic-bezier(.2,.8,.2,1)", "@media (prefers-reduced-motion: reduce)": { transition: "none" } }} />
    </Box>
  );
}

export type Segment = { key: string; label: string; value: number; color: string; valueText: string };

/** One horizontal stacked bar (e.g. memory: used / buffers / cache / free) with a legend. */
export function StackedBar({ segments, total, label }: { segments: Segment[]; total: number; label: string }) {
  const theme = useTheme();
  const safeTotal = total > 0 ? total : segments.reduce((sum, item) => sum + item.value, 0) || 1;
  return (
    <Box>
      <Box role="img" aria-label={`${label}: ${segments.map((item) => `${item.label} ${item.valueText}`).join("، ")}`} sx={{ display: "flex", height: 14, borderRadius: 7, overflow: "hidden", bgcolor: "action.hover", gap: "2px" }}>
        {segments.map((item) => (
          <Box
            key={item.key}
            title={`${item.label}: ${item.valueText}`}
            sx={{ width: `${(Math.max(item.value, 0) / safeTotal) * 100}%`, bgcolor: item.color, transition: "width .6s cubic-bezier(.2,.8,.2,1)", "@media (prefers-reduced-motion: reduce)": { transition: "none" } }}
          />
        ))}
      </Box>
      <Stack direction="row" flexWrap="wrap" useFlexGap columnGap={2} rowGap={0.5} sx={{ mt: 1 }}>
        {segments.map((item) => (
          <Stack key={item.key} direction="row" spacing={0.75} alignItems="center">
            <Box aria-hidden sx={{ width: 10, height: 10, borderRadius: 0.5, bgcolor: item.color, border: item.color === theme.palette.action.hover ? 1 : 0, borderColor: "divider" }} />
            <Typography variant="caption" color="text.secondary">{item.label}</Typography>
            <Typography variant="caption" sx={{ fontWeight: 700 }}>{item.valueText}</Typography>
          </Stack>
        ))}
      </Stack>
    </Box>
  );
}

/** A pulsing "live" dot; static when the user prefers reduced motion or the feed is paused. */
export function LiveDot({ active, color }: { active: boolean; color: string }) {
  return (
    <Box
      component="span"
      aria-hidden
      sx={{
        position: "relative",
        display: "inline-block",
        width: 9,
        height: 9,
        borderRadius: "50%",
        bgcolor: active ? color : "text.disabled",
        "&::after": active ? {
          content: '""',
          position: "absolute",
          inset: 0,
          borderRadius: "50%",
          bgcolor: color,
          animation: "mrk-live-pulse 1.8s ease-out infinite"
        } : undefined,
        "@keyframes mrk-live-pulse": { "0%": { transform: "scale(1)", opacity: 0.6 }, "100%": { transform: "scale(2.6)", opacity: 0 } },
        "@media (prefers-reduced-motion: reduce)": { "&::after": { animation: "none", opacity: 0 } }
      }}
    />
  );
}
