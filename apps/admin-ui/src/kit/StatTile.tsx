import type { ReactNode } from "react";
import { Box, Card, CardActionArea, LinearProgress, Stack, Typography } from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import type { Tone } from "../copy/kinds";

export type StatTileProps = {
  label: string;
  /** Already formatted value (use Num/Bytes/Percent or format helpers). */
  value: ReactNode;
  /** One short line under the value, e.g. «از ۵۰ گیگابایت». */
  caption?: ReactNode;
  icon?: SvgIconComponent;
  /** 0–100: shows a progress bar (disk, memory). */
  meter?: number | null;
  tone?: Tone;
  /** Makes the whole tile a link/button. */
  onClick?: () => void;
  href?: string;
};

const TONE_TO_COLOR: Record<Tone, "success" | "warning" | "error" | "info" | "inherit" | "primary"> = {
  ok: "success",
  warn: "warning",
  error: "error",
  info: "info",
  off: "inherit",
  busy: "primary"
};

/** A number tile: label, big value, caption and optional meter. */
export function StatTile({ label, value, caption, icon: Icon, meter, tone = "info", onClick, href }: StatTileProps) {
  const body = (
    <Stack spacing={0.75} sx={{ p: 2, minHeight: 112 }}>
      <Stack direction="row" alignItems="center" spacing={1}>
        {Icon && <Icon fontSize="small" color="action" aria-hidden />}
        <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 650 }}>{label}</Typography>
      </Stack>
      <Typography component="div" variant="h5" sx={{ fontWeight: 780, lineHeight: 1.3 }}>{value}</Typography>
      {meter !== undefined && meter !== null && Number.isFinite(meter) && (
        <LinearProgress
          variant="determinate"
          value={Math.max(0, Math.min(100, meter))}
          color={TONE_TO_COLOR[tone]}
          aria-label={label}
          sx={{ height: 6, borderRadius: 3 }}
        />
      )}
      {caption && <Typography variant="caption" color="text.secondary">{caption}</Typography>}
    </Stack>
  );
  return (
    <Card variant="outlined" sx={{ height: "100%" }}>
      {onClick || href ? (
        <CardActionArea onClick={onClick} {...(href ? ({ href } as object) : {})} sx={{ height: "100%" }}>{body}</CardActionArea>
      ) : (
        body
      )}
    </Card>
  );
}

/** Responsive grid for StatTiles: 1 column on phones, 2 on tablets, up to `columns` on desktop. */
export function StatGrid({ children, columns = 3 }: { children: ReactNode; columns?: 2 | 3 | 4 }) {
  return (
    <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))", md: `repeat(${columns}, minmax(0, 1fr))` } }}>
      {children}
    </Box>
  );
}
