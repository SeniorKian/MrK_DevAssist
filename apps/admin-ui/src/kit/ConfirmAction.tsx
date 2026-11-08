import { useCallback, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  Alert, Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField,
  Typography, useMediaQuery, useTheme
} from "@mui/material";
import { CONFIRM_COPY, confirmPrompt, matchesConfirmation, type ConfirmWord } from "../copy/confirm";
import { say } from "../copy/text";
import { FriendlyError } from "./FriendlyError";
import { useKit } from "./useKit";

/**
 * Severity ladder (docs/33 §2.7):
 * - "disruptive": simple confirm (stop a container, disconnect a channel).
 * - "destructive": red button + optional typed word (delete, prune, enforce).
 * Reversible actions should not confirm at all: use <UndoSnackbar/> instead.
 */
export type ConfirmSeverity = "disruptive" | "destructive";

export type ConfirmActionProps = {
  open: boolean;
  /** A question naming the object: «پشتیبان "DB اصلی" پاک شود؟» */
  title: string;
  /** What will happen, in one or two sentences. */
  body?: ReactNode;
  /** Bullet list of consequences. */
  consequences?: string[];
  /** Can it be undone? Adds the standard sentence. */
  undoable?: boolean;
  severity?: ConfirmSeverity;
  /** Typed confirmation: a Persian word or the object's name; the backend token is `typed.token`. */
  typed?: ConfirmWord;
  /** Button labels; defaults «بله، ادامه بده» / «نه، فعلاً نه» (destructive: «بله، پاک کن» / «نه، بماند»). */
  confirmLabel?: string;
  cancelLabel?: string;
  busy?: boolean;
  /** Error from the last attempt (rendered with FriendlyError). */
  error?: unknown;
  /** Extra fields (e.g. a reason). */
  children?: ReactNode;
  confirmDisabled?: boolean;
  onConfirm: () => void;
  onClose: () => void;
};

/**
 * Confirmation dialog following the writing guide. The destructive button is never focused by default;
 * Enter submits only when the typed word matches. Full-screen on phones.
 */
export function ConfirmAction({
  open, title, body, consequences, undoable, severity = "disruptive", typed, confirmLabel, cancelLabel, busy, error, children,
  confirmDisabled, onConfirm, onClose
}: ConfirmActionProps) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [value, setValue] = useState("");
  const destructive = severity === "destructive";
  const typedOk = !typed || matchesConfirmation(value, typed, language);
  const word = typed ? confirmPrompt(typed, language) : "";
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!typedOk || busy || confirmDisabled) return;
    onConfirm();
  };
  return (
    <Dialog
      open={open}
      onClose={busy ? undefined : onClose}
      fullScreen={fullScreen}
      fullWidth
      maxWidth="sm"
      aria-labelledby="mrk-confirm-action-title"
      aria-describedby="mrk-confirm-action-body"
      slotProps={{ transition: { onExited: () => setValue("") } }}
    >
      <Box component="form" onSubmit={submit} noValidate sx={{ display: "flex", flexDirection: "column", height: fullScreen ? "100%" : undefined }}>
        <DialogTitle id="mrk-confirm-action-title" sx={{ fontWeight: 760 }}>{title}</DialogTitle>
        <DialogContent sx={{ flex: fullScreen ? 1 : undefined }}>
          <Stack spacing={2} id="mrk-confirm-action-body" sx={{ pt: 0.5 }}>
            {body && (typeof body === "string" ? <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{body}</Typography> : body)}
            {consequences && consequences.length > 0 && (
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 700 }}>{CONFIRM_COPY.whatHappens[language]}</Typography>
                <Box component="ul" sx={{ m: 0, mt: 0.5, pl: 2.5, "& li": { lineHeight: 1.9 } }}>
                  {consequences.map((item) => <Typography component="li" variant="body2" key={item}>{item}</Typography>)}
                </Box>
              </Box>
            )}
            {undoable !== undefined && (
              <Typography variant="body2" color={undoable ? "text.secondary" : "error.main"} sx={{ fontWeight: undoable ? 400 : 650 }}>
                {undoable ? CONFIRM_COPY.canUndo[language] : CONFIRM_COPY.cannotUndo[language]}
              </Typography>
            )}
            {children}
            {typed && (
              <TextField
                fullWidth
                size="small"
                autoComplete="off"
                label={say(language, CONFIRM_COPY.typeToConfirm, { word })}
                value={value}
                onChange={(event) => setValue(event.target.value)}
                error={value.length > 0 && !typedOk}
                helperText={value.length > 0 && !typedOk ? say(language, CONFIRM_COPY.mismatch, { word }) : " "}
                slotProps={{ htmlInput: { "aria-label": say(language, CONFIRM_COPY.typeToConfirm, { word }), spellCheck: false } }}
              />
            )}
            {error !== undefined && error !== null && <FriendlyError error={error} noAction />}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1, flexDirection: fullScreen ? "column-reverse" : "row", "& > *": fullScreen ? { width: "100%", m: "0 !important" } : {} }}>
          <Button onClick={onClose} disabled={busy} autoFocus={!typed} sx={{ minHeight: 44 }}>
            {cancelLabel ?? (destructive ? CONFIRM_COPY.keepIt[language] : CONFIRM_COPY.notNow[language])}
          </Button>
          <Button
            type="submit"
            variant="contained"
            color={destructive ? "error" : "primary"}
            disabled={!typedOk || busy || confirmDisabled}
            startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined}
            sx={{ minHeight: 44 }}
          >
            {confirmLabel ?? (destructive ? CONFIRM_COPY.yesDelete[language] : CONFIRM_COPY.yesContinue[language])}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

export type ConfirmRequestOptions = Omit<ConfirmActionProps, "open" | "onConfirm" | "onClose" | "busy" | "error">;

/**
 * Promise-based ConfirmAction without any provider:
 *   const { ask, dialog } = useConfirmAction();
 *   … if (!(await ask({ title, severity: "destructive", typed: CONFIRM_WORDS.prune }))) return;
 *   return <>{page}{dialog}</>;
 */
export function useConfirmAction() {
  const [request, setRequest] = useState<ConfirmRequestOptions | null>(null);
  const [open, setOpen] = useState(false);
  const resolver = useRef<((ok: boolean) => void) | null>(null);
  const ask = useCallback((options: ConfirmRequestOptions) => {
    resolver.current?.(false);
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve;
      setRequest(options);
      setOpen(true);
    });
  }, []);
  const finish = (ok: boolean) => {
    resolver.current?.(ok);
    resolver.current = null;
    setOpen(false);
  };
  const dialog = request ? <ConfirmAction {...request} open={open} onConfirm={() => finish(true)} onClose={() => finish(false)} /> : null;
  return { ask, dialog };
}
