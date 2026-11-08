import { useCallback, useState, type ReactNode } from "react";
import { Alert, Box, Button, CircularProgress, Snackbar, Stack, Typography } from "@mui/material";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import ErrorRoundedIcon from "@mui/icons-material/ErrorRounded";
import { reasonFor } from "../copy/errors";
import { formatMs } from "../format";
import { FriendlyError } from "./FriendlyError";
import { useKit } from "./useKit";

// ── UndoSnackbar ─────────────────────────────────────────────────────────────

export type UndoToast = { message: string; onUndo?: () => void; tone?: "success" | "info" | "error" };

/**
 * Toasts for reversible actions (pin, toggle): «… نگه‌داشته شد» [برگرداندن] for 6 s.
 *   const { notify, snackbar } = useUndoSnackbar();
 *   notify({ message: "…", onUndo: () => … });
 *   return <>{page}{snackbar}</>;
 */
export function useUndoSnackbar(durationMs = 6000) {
  const { c } = useKit();
  const [toast, setToast] = useState<UndoToast | null>(null);
  const [open, setOpen] = useState(false);
  const notify = useCallback((next: UndoToast) => {
    setToast(next);
    setOpen(true);
  }, []);
  const snackbar = (
    <Snackbar
      open={open}
      autoHideDuration={toast?.onUndo ? durationMs : 4000}
      onClose={(_event, reason) => {
        if (reason !== "clickaway") setOpen(false);
      }}
      anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      sx={{ bottom: { xs: "calc(var(--mrk-bottom-nav-height, 0px) + 16px)", sm: 24 } }}
    >
      <Alert
        severity={toast?.tone ?? "success"}
        variant="filled"
        onClose={() => setOpen(false)}
        action={
          toast?.onUndo ? (
            <Button
              color="inherit"
              size="small"
              onClick={() => {
                setOpen(false);
                toast.onUndo?.();
              }}
            >
              {c.undo}
            </Button>
          ) : undefined
        }
        sx={{ alignItems: "center", minWidth: { sm: 360 } }}
      >
        {toast?.message}
      </Alert>
    </Snackbar>
  );
  return { notify, snackbar };
}

// ── TestResult ───────────────────────────────────────────────────────────────

export type TestOutcome =
  | { state: "idle" }
  | { state: "running" }
  | { state: "ok"; latencyMs?: number | null; message?: string }
  | { state: "fail"; error?: unknown; code?: string | null; message?: string };

const TEST_COPY = {
  running: { fa: "در حال امتحان…", en: "Testing…" },
  ok: { fa: "وصل شد", en: "Connected" },
  okFast: { fa: "وصل شد و سریع جواب داد ({ms}).", en: "Connected and answered quickly ({ms})." },
  okSlow: { fa: "وصل شد ولی کند جواب داد ({ms}).", en: "Connected, but it answered slowly ({ms})." },
  fail: { fa: "وصل نشد", en: "Couldn't connect" }
};

/** Uniform «امتحان اتصال» result: ok with response time in words, or a plain failure reason. */
export function TestResult({ outcome, slowMs = 1500 }: { outcome: TestOutcome; slowMs?: number }) {
  const { language } = useKit();
  if (outcome.state === "idle") return null;
  if (outcome.state === "running") {
    return (
      <Stack direction="row" spacing={1} alignItems="center" role="status">
        <CircularProgress size={16} />
        <Typography variant="body2">{TEST_COPY.running[language]}</Typography>
      </Stack>
    );
  }
  if (outcome.state === "ok") {
    const ms = outcome.latencyMs;
    const text =
      outcome.message ??
      (ms === null || ms === undefined
        ? TEST_COPY.ok[language]
        : (ms > slowMs ? TEST_COPY.okSlow : TEST_COPY.okFast)[language].replace("{ms}", formatMs(ms, language)));
    return (
      <Stack direction="row" spacing={1} alignItems="center" role="status">
        <CheckCircleRoundedIcon color="success" fontSize="small" aria-hidden />
        <Typography variant="body2" sx={{ fontWeight: 650 }}>{text}</Typography>
      </Stack>
    );
  }
  if (outcome.error !== undefined) return <FriendlyError error={outcome.error} title={TEST_COPY.fail[language]} noAction />;
  return (
    <Stack direction="row" spacing={1} alignItems="flex-start" role="alert">
      <ErrorRoundedIcon color="error" fontSize="small" aria-hidden sx={{ mt: 0.25 }} />
      <Box>
        <Typography variant="body2" sx={{ fontWeight: 700 }}>{TEST_COPY.fail[language]}</Typography>
        <Typography variant="body2" color="text.secondary">{outcome.message ?? reasonFor(language, outcome.code)}</Typography>
      </Box>
    </Stack>
  );
}

// ── InlineNotice ─────────────────────────────────────────────────────────────

/** A calm one-line notice (info/warning/success) with an optional action. */
export function Notice({ tone = "info", children, action }: { tone?: "info" | "warning" | "success" | "error"; children: ReactNode; action?: ReactNode }) {
  return (
    <Alert severity={tone} action={action} sx={{ "& .MuiAlert-message": { lineHeight: 1.9 } }}>
      {children}
    </Alert>
  );
}
