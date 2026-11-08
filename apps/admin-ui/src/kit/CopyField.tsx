import { useEffect, useId, useRef, useState } from "react";
import { Box, IconButton, InputAdornment, Stack, TextField, Tooltip, Typography } from "@mui/material";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import CheckRoundedIcon from "@mui/icons-material/CheckRounded";
import { copyText } from "../api";
import { useKit } from "./useKit";

/** Copy to the clipboard and remember "copied" for 2 s. Returns [copy, copied, failed]. */
export function useCopy() {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async (value: string) => {
    const ok = await copyText(value);
    setState(ok ? "copied" : "failed");
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState("idle"), 2000);
    return ok;
  };
  return [copy, state === "copied", state === "failed"] as const;
}

/** A copy icon button with "copied" feedback (announced to screen readers). */
export function CopyButton({ value, label, size = "small" }: { value: string; label?: string; size?: "small" | "medium" }) {
  const { c } = useKit();
  const [copy, copied, failed] = useCopy();
  return (
    <Tooltip title={copied ? c.copied : failed ? c.copyFailed : (label ?? c.copy)}>
      <IconButton size={size} onClick={() => void copy(value)} aria-label={label ?? c.copy} color={copied ? "success" : "default"}>
        {copied ? <CheckRoundedIcon fontSize="small" /> : <ContentCopyRoundedIcon fontSize="small" />}
        <Box component="span" aria-live="polite" sx={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0 0 0 0)" }}>
          {copied ? c.copied : failed ? c.copyFailed : ""}
        </Box>
      </IconButton>
    </Tooltip>
  );
}

export type CopyFieldProps = {
  label: string;
  value: string;
  /** Technical values (URLs, commands, keys) are LTR and monospace. Default true. */
  ltr?: boolean;
  /** Multi-line (commands, snippets). */
  multiline?: boolean;
  helperText?: string;
  /** Hide the value behind dots until revealed (secrets). */
  masked?: boolean;
};

/** A read-only field with a copy button. */
export function CopyField({ label, value, ltr = true, multiline, helperText, masked }: CopyFieldProps) {
  const { c } = useKit();
  const [revealed, setRevealed] = useState(!masked);
  const id = useId();
  return (
    <Stack spacing={0.5}>
      <TextField
        id={id}
        label={label}
        value={revealed ? value : "•".repeat(Math.min(24, Math.max(8, value.length)))}
        fullWidth
        size="small"
        multiline={multiline}
        minRows={multiline ? 2 : undefined}
        helperText={helperText}
        slotProps={{
          htmlInput: {
            readOnly: true,
            dir: ltr ? "ltr" : undefined,
            style: ltr ? { fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", fontSize: "0.9em" } : undefined,
            onFocus: (event: { target: { select?: () => void } }) => event.target.select?.()
          },
          input: {
            endAdornment: (
              <InputAdornment position="end">
                {masked && (
                  <Typography
                    component="button"
                    type="button"
                    variant="caption"
                    onClick={() => setRevealed((v) => !v)}
                    sx={{ border: 0, bgcolor: "transparent", color: "primary.main", cursor: "pointer", px: 0.5, font: "inherit" }}
                  >
                    {revealed ? c.hide : c.show}
                  </Typography>
                )}
                <CopyButton value={value} />
              </InputAdornment>
            )
          }
        }}
      />
    </Stack>
  );
}
