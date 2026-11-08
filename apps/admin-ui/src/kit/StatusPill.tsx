import { Box, CircularProgress, type SxProps, type Theme } from "@mui/material";
import { statusWord, type Tone } from "../copy/kinds";
import { useKit } from "./useKit";

export type StatusPillProps = {
  /** A known status key (`running`, `failed`, `unavailable`, …) looked up in copy/kinds STATUS_WORDS. */
  status?: string | null;
  /** Or set the tone and label yourself. */
  tone?: Tone;
  label?: string;
  size?: "small" | "medium";
  sx?: SxProps<Theme>;
};

const TONE_COLOR: Record<Tone, string> = {
  ok: "success.main",
  warn: "warning.main",
  error: "error.main",
  info: "info.main",
  off: "text.disabled",
  busy: "primary.main"
};

/**
 * A status as dot + word, never colour alone (accessible to colour-blind users).
 * `busy` shows a small spinner instead of a dot.
 */
export function StatusPill({ status, tone, label, size = "small", sx }: StatusPillProps) {
  const { language } = useKit();
  const known = status !== undefined ? statusWord(language, status) : null;
  const finalTone: Tone = tone ?? known?.tone ?? "off";
  const text = label ?? known?.label ?? "";
  const color = TONE_COLOR[finalTone];
  const small = size === "small";
  return (
    <Box
      component="span"
      sx={[
        {
          display: "inline-flex",
          alignItems: "center",
          gap: 0.75,
          maxWidth: "100%",
          px: small ? 1 : 1.25,
          py: small ? 0.25 : 0.5,
          borderRadius: 99,
          border: "1px solid",
          borderColor: "divider",
          bgcolor: "action.hover",
          fontSize: small ? "0.78rem" : "0.875rem",
          fontWeight: 650,
          lineHeight: 1.6,
          whiteSpace: "nowrap",
          color: "text.primary"
        },
        ...(Array.isArray(sx) ? sx : sx ? [sx] : [])
      ]}
    >
      {finalTone === "busy" ? (
        <CircularProgress size={small ? 10 : 12} thickness={6} sx={{ color }} aria-hidden />
      ) : (
        <Box component="span" aria-hidden sx={{ width: small ? 8 : 10, height: small ? 8 : 10, borderRadius: "50%", bgcolor: color, flexShrink: 0 }} />
      )}
      <Box component="span" sx={{ overflow: "hidden", textOverflow: "ellipsis" }}>{text}</Box>
    </Box>
  );
}
