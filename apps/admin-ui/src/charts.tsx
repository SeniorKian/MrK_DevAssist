import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { Box, Stack, Typography, useTheme } from "@mui/material";

/**
 * Small dependency-free SVG charts.
 *
 * - The plot itself is always laid out left-to-right (time flows left→right in both languages);
 *   legend and tooltip text follow the page direction.
 * - Axis numbers/dates are formatted by the caller (localized digits).
 * - Accessible: `role="img"` with <title>/<desc>, focusable, ← → move the cursor, Esc clears it.
 */

export type ChartSeries = { label: string; color: string; values: Array<number | null> };

type LineChartProps = {
  title: string;
  description?: string;
  /** UNIX seconds, ascending; same length as every series' values. */
  times: number[];
  series: ChartSeries[];
  height?: number;
  /** Fixed upper bound (e.g. 100 for percentages); otherwise derived from the data. */
  yMax?: number;
  area?: boolean;
  formatY: (value: number) => string;
  formatX: (ts: number) => string;
  formatTooltipX: (ts: number) => string;
  emptyText: string;
  /** Words for the text summary (screen readers and `showSummary`); English by default. */
  words?: ChartWords;
  /** Also print the summary under the chart, so no value is hover-only. */
  showSummary?: boolean;
};

/** Localized words for the chart's text summary. */
export type ChartWords = { now: string; lowest: string; average: string; highest: string; separator?: string };

const DEFAULT_WORDS: ChartWords = { now: "now", lowest: "lowest", average: "average", highest: "highest", separator: "; " };

/** Latest, lowest, average and highest of a series (null when it has no numbers). */
export function seriesStats(values: Array<number | null>) {
  const numbers = values.filter((value): value is number => value !== null && Number.isFinite(value));
  if (!numbers.length) return null;
  const sum = numbers.reduce((total, value) => total + value, 0);
  return { latest: lastValue(values) ?? numbers[numbers.length - 1], min: Math.min(...numbers), max: Math.max(...numbers), avg: sum / numbers.length };
}

function niceCeil(value: number) {
  if (!(value > 0) || !Number.isFinite(value)) return 1;
  const exponent = 10 ** Math.floor(Math.log10(value));
  const fraction = value / exponent;
  const nice = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 2.5 ? 2.5 : fraction <= 5 ? 5 : 10;
  return nice * exponent;
}

function useElementWidth<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const update = () => setWidth(element.clientWidth);
    update();
    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", update);
      return () => window.removeEventListener("resize", update);
    }
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width] as const;
}

function buildPaths(values: Array<number | null>, xOf: (index: number) => number, yOf: (value: number) => number, baseY: number) {
  let line = "";
  let area = "";
  let segment: Array<[number, number]> = [];
  const flush = () => {
    if (segment.length === 0) return;
    line += segment.map(([x, y], index) => `${index ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
    if (segment.length === 1) line += "h0.01";
    area += `M${segment[0][0].toFixed(1)},${baseY.toFixed(1)}${segment.map(([x, y]) => `L${x.toFixed(1)},${y.toFixed(1)}`).join("")}L${segment[segment.length - 1][0].toFixed(1)},${baseY.toFixed(1)}Z`;
    segment = [];
  };
  values.forEach((value, index) => {
    if (value === null || !Number.isFinite(value)) flush();
    else segment.push([xOf(index), yOf(value)]);
  });
  flush();
  return { line, area };
}

function nearestIndex(times: number[], target: number) {
  let low = 0;
  let high = times.length - 1;
  while (high - low > 1) {
    const mid = (low + high) >> 1;
    if (times[mid] < target) low = mid;
    else high = mid;
  }
  return Math.abs(times[low] - target) <= Math.abs(times[high] - target) ? low : high;
}

function lastValue(values: Array<number | null>) {
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const value = values[index];
    if (value !== null && Number.isFinite(value)) return value;
  }
  return null;
}

export function LineChart({ title, description, times, series, height = 200, yMax, area = true, formatY, formatX, formatTooltipX, emptyText, words = DEFAULT_WORDS, showSummary = false }: LineChartProps) {
  const theme = useTheme();
  const rtl = theme.direction === "rtl";
  const [wrapperRef, measured] = useElementWidth<HTMLDivElement>();
  const width = Math.max(measured, 240);
  const [cursor, setCursor] = useState<number | null>(null);
  const baseId = useId();
  const titleId = `${baseId}-title`;
  const descId = `${baseId}-desc`;
  const gradientPrefix = `${baseId.replace(/[^a-zA-Z0-9_-]/g, "")}-grad`;

  const hasData = times.length > 0 && series.some((item) => item.values.some((value) => value !== null && Number.isFinite(value)));
  const dataMax = useMemo(() => {
    let max = 0;
    for (const item of series) for (const value of item.values) if (value !== null && Number.isFinite(value) && value > max) max = value;
    return max;
  }, [series]);
  const top = yMax ?? niceCeil(dataMax * 1.1);
  const ticksY = [0, top / 4, top / 2, (top * 3) / 4, top];
  const yLabels = ticksY.map((value) => formatY(value));
  const padLeft = Math.min(84, Math.max(30, Math.max(...yLabels.map((label) => label.length)) * 6.6 + 10));
  const padRight = 12;
  const padTop = 10;
  const padBottom = 24;
  const plotW = Math.max(10, width - padLeft - padRight);
  const plotH = Math.max(10, height - padTop - padBottom);
  const tMin = times[0] ?? 0;
  const tMax = times[times.length - 1] ?? 1;
  const span = tMax - tMin;
  const xOfTime = (ts: number) => padLeft + (span > 0 ? ((ts - tMin) / span) * plotW : plotW / 2);
  const xOf = (index: number) => xOfTime(times[index]);
  const yOf = (value: number) => padTop + plotH - (Math.min(Math.max(value, 0), top) / top) * plotH;
  const baseY = padTop + plotH;

  const paths = useMemo(
    () => (hasData ? series.map((item) => buildPaths(item.values, xOf, yOf, baseY)) : []),
    // xOf/yOf/baseY are derived only from the values listed here.
    [series, times, width, height, top, padLeft, hasData]
  );

  const tickCount = Math.max(2, Math.min(7, Math.floor(plotW / 110)));
  const ticksX = span > 0 ? Array.from({ length: tickCount }, (_, index) => tMin + (span * index) / (tickCount - 1)) : times.slice(0, 1);

  const summaryLines = series.map((item) => {
    const stats = seriesStats(item.values);
    if (!stats) return `${item.label}: —`;
    return `${item.label}: ${words.now} ${formatY(stats.latest)} · ${words.lowest} ${formatY(stats.min)} · ${words.average} ${formatY(stats.avg)} · ${words.highest} ${formatY(stats.max)}`;
  });
  const summary = summaryLines.join(words.separator ?? "; ");

  const onPointerMove = (event: PointerEvent<SVGSVGElement>) => {
    if (!hasData) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const x = ((event.clientX - rect.left) / rect.width) * width;
    const ts = span > 0 ? tMin + ((x - padLeft) / plotW) * span : tMin;
    setCursor(nearestIndex(times, ts));
  };
  const onKeyDown = (event: KeyboardEvent<SVGSVGElement>) => {
    if (!hasData) return;
    // The plot is LTR, so the arrow keys map directly onto time.
    if (event.key === "ArrowRight") { event.preventDefault(); setCursor((value) => Math.min(times.length - 1, (value ?? times.length - 2) + 1)); }
    else if (event.key === "ArrowLeft") { event.preventDefault(); setCursor((value) => Math.max(0, (value ?? times.length) - 1)); }
    else if (event.key === "Home") { event.preventDefault(); setCursor(0); }
    else if (event.key === "End") { event.preventDefault(); setCursor(times.length - 1); }
    else if (event.key === "Escape") setCursor(null);
  };

  const cursorX = cursor !== null && times[cursor] !== undefined ? xOf(cursor) : null;
  const tooltipShift = cursorX === null ? "-50%" : cursorX < 90 ? "0%" : cursorX > width - 90 ? "-100%" : "-50%";

  return (
    <Box>
      <Box ref={wrapperRef} dir="ltr" sx={{ position: "relative", width: "100%" }}>
        <svg
          width="100%"
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-labelledby={`${titleId} ${descId}`}
          tabIndex={hasData ? 0 : -1}
          onPointerMove={onPointerMove}
          onPointerLeave={() => setCursor(null)}
          onKeyDown={onKeyDown}
          onBlur={() => setCursor(null)}
          style={{ display: "block", touchAction: "pan-y", outline: "none", fontFamily: "inherit" }}
        >
          <title id={titleId}>{title}</title>
          <desc id={descId}>{description ? `${description}. ` : ""}{hasData ? summary : emptyText}</desc>
          <defs>
            {series.map((item, index) => (
              <linearGradient key={item.label} id={`${gradientPrefix}-${index}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={item.color} stopOpacity={0.28} />
                <stop offset="100%" stopColor={item.color} stopOpacity={0.02} />
              </linearGradient>
            ))}
          </defs>
          {ticksY.map((value, index) => (
            <g key={index}>
              <line x1={padLeft} x2={padLeft + plotW} y1={yOf(value)} y2={yOf(value)} stroke={theme.palette.divider} strokeDasharray={index === 0 ? undefined : "3 4"} />
              <text x={padLeft - 6} y={yOf(value)} dy="0.32em" textAnchor="end" fontSize={11} fill={theme.palette.text.secondary}>{yLabels[index]}</text>
            </g>
          ))}
          {hasData && ticksX.map((ts, index) => (
            <text
              key={index}
              x={xOfTime(ts)}
              y={height - 6}
              fontSize={11}
              fill={theme.palette.text.secondary}
              textAnchor={index === 0 && ticksX.length > 1 ? "start" : index === ticksX.length - 1 && ticksX.length > 1 ? "end" : "middle"}
            >
              {formatX(ts)}
            </text>
          ))}
          {paths.map((path, index) => (
            <g key={series[index].label}>
              {area && <path d={path.area} fill={`url(#${gradientPrefix}-${index})`} stroke="none" />}
              <path d={path.line} fill="none" stroke={series[index].color} strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round" />
            </g>
          ))}
          {cursorX !== null && cursor !== null && (
            <g pointerEvents="none">
              <line x1={cursorX} x2={cursorX} y1={padTop} y2={baseY} stroke={theme.palette.text.secondary} strokeOpacity={0.5} />
              {series.map((item) => {
                const value = item.values[cursor];
                return value === null || value === undefined || !Number.isFinite(value) ? null : (
                  <circle key={item.label} cx={cursorX} cy={yOf(value)} r={3.5} fill={item.color} stroke={theme.palette.background.paper} strokeWidth={1.5} />
                );
              })}
            </g>
          )}
          {!hasData && (
            <text x={padLeft + plotW / 2} y={padTop + plotH / 2} textAnchor="middle" fontSize={13} fill={theme.palette.text.secondary}>{emptyText}</text>
          )}
        </svg>
        {cursorX !== null && cursor !== null && (
          <Box
            role="status"
            aria-live="polite"
            dir={rtl ? "rtl" : "ltr"}
            // Inline style: the RTL stylis plugin would mirror `left` inside this LTR plot.
            style={{ left: cursorX, transform: `translateX(${tooltipShift})` }}
            sx={{
              position: "absolute",
              top: 0,
              pointerEvents: "none",
              px: 1.25,
              py: 0.75,
              borderRadius: 1,
              border: 1,
              borderColor: "divider",
              bgcolor: "background.paper",
              boxShadow: 3,
              whiteSpace: "nowrap",
              zIndex: 1
            }}
          >
            <Typography variant="caption" color="text.secondary" display="block">{formatTooltipX(times[cursor])}</Typography>
            {series.map((item) => {
              const value = item.values[cursor];
              return (
                <Stack key={item.label} direction="row" spacing={0.75} alignItems="center">
                  <Box aria-hidden sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: item.color }} />
                  <Typography variant="caption">{item.label}:</Typography>
                  <Typography variant="caption" fontWeight={750}>{value === null || value === undefined || !Number.isFinite(value) ? "—" : formatY(value)}</Typography>
                </Stack>
              );
            })}
          </Box>
        )}
      </Box>
      {showSummary && hasData && (
        <Stack spacing={0.25} sx={{ mt: 0.75 }} aria-hidden>
          {summaryLines.map((line) => (
            <Typography key={line} variant="caption" color="text.secondary">{line}</Typography>
          ))}
        </Stack>
      )}
      {series.length > 1 && (
        <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap sx={{ mt: 0.75 }} aria-hidden>
          {series.map((item) => (
            <Stack key={item.label} direction="row" spacing={0.75} alignItems="center">
              <Box sx={{ width: 10, height: 3, borderRadius: 2, bgcolor: item.color }} />
              <Typography variant="caption" color="text.secondary">{item.label}</Typography>
            </Stack>
          ))}
        </Stack>
      )}
    </Box>
  );
}

/** Tiny trend line without axes (table cells). */
export function Sparkline({ values, color, label, height = 28, max }: { values: Array<number | null>; color: string; label: string; height?: number; max?: number }) {
  const numbers = values.filter((value): value is number => value !== null && Number.isFinite(value));
  const top = max ?? (numbers.length ? Math.max(...numbers) * 1.1 || 1 : 1);
  const width = 100;
  const xOf = (index: number) => (values.length > 1 ? (index / (values.length - 1)) * width : width / 2);
  const yOf = (value: number) => 2 + (height - 4) - (Math.min(Math.max(value, 0), top) / top) * (height - 4);
  const { line, area } = buildPaths(values, xOf, yOf, height);
  return (
    <Box dir="ltr" sx={{ width: "100%", minWidth: 80, maxWidth: 180 }}>
      <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={label} style={{ display: "block" }}>
        <title>{label}</title>
        {numbers.length > 0 && <path d={area} fill={color} fillOpacity={0.15} stroke="none" />}
        {numbers.length > 0 && <path d={line} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />}
        {numbers.length === 0 && <line x1={0} x2={width} y1={height / 2} y2={height / 2} stroke="currentColor" strokeOpacity={0.2} vectorEffect="non-scaling-stroke" />}
      </svg>
    </Box>
  );
}
