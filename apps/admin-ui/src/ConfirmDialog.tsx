import { createContext, useCallback, useContext, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  TextField,
  Typography
} from "@mui/material";
import { useUiMode } from "./uiMode";

export type ConfirmTone = "error" | "warning" | "primary";

type ConfirmDialogProps = {
  open: boolean;
  title: string;
  body?: ReactNode;
  confirmLabel?: string;
  tone?: ConfirmTone;
  /** When set, the user must type this exact phrase before confirming. */
  phrase?: string;
  /** Disable the confirm button (e.g. while extra fields are invalid). */
  confirmDisabled?: boolean;
  busy?: boolean;
  error?: string | null;
  onConfirm: () => void;
  onClose: () => void;
  /** Extra form fields rendered above the phrase input. */
  children?: ReactNode;
};

/** Accessible confirmation dialog; Enter submits, Escape cancels. */
export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  tone = "primary",
  phrase,
  confirmDisabled,
  busy,
  error,
  onConfirm,
  onClose,
  children
}: ConfirmDialogProps) {
  const { t } = useUiMode();
  const [typed, setTyped] = useState("");
  const phraseOk = !phrase || typed.trim() === phrase;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!phraseOk || confirmDisabled || busy) return;
    onConfirm();
  };
  return (
    <Dialog
      open={open}
      onClose={busy ? undefined : onClose}
      fullWidth
      maxWidth="sm"
      aria-labelledby="mrk-confirm-title"
      slotProps={{ transition: { onExited: () => setTyped("") } }}
    >
      <Box component="form" onSubmit={submit} noValidate>
        <DialogTitle id="mrk-confirm-title">{title}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 0.5 }}>
            {body && (typeof body === "string" ? <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{body}</Typography> : body)}
            {children}
            {phrase && (
              <Box>
                <Typography variant="body2" color="text.secondary">{t("typeToConfirm")}</Typography>
                <Typography component="code" dir="ltr" variant="body2" sx={{ display: "block", mt: 0.6, fontWeight: 700, overflowWrap: "anywhere" }}>{phrase}</Typography>
                <TextField
                  fullWidth
                  size="small"
                  autoFocus
                  autoComplete="off"
                  value={typed}
                  onChange={(event) => setTyped(event.target.value)}
                  error={typed.length > 0 && !phraseOk}
                  helperText={typed.length > 0 && !phraseOk ? t("phraseMismatch") : " "}
                  slotProps={{ htmlInput: { dir: "ltr", "aria-label": t("typeToConfirm") } }}
                  sx={{ mt: 1 }}
                />
              </Box>
            )}
            {error && <Alert severity="error">{error}</Alert>}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={onClose} disabled={busy}>{t("cancel")}</Button>
          <Button
            type="submit"
            variant="contained"
            color={tone}
            disabled={!phraseOk || confirmDisabled || busy}
            startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined}
          >
            {confirmLabel ?? t("confirm")}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

export type ConfirmRequest = {
  title: string;
  body?: ReactNode;
  confirmLabel?: string;
  tone?: ConfirmTone;
  phrase?: string;
  /** Ask for a free-text value; `prompt()` resolves with it. */
  input?: { label: string; initial?: string; minLength?: number; helper?: string; ltr?: boolean };
};

type ConfirmApi = {
  confirm: (request: ConfirmRequest) => Promise<boolean>;
  prompt: (request: ConfirmRequest & { input: NonNullable<ConfirmRequest["input"]> }) => Promise<string | null>;
};

const ConfirmContext = createContext<ConfirmApi>({
  confirm: async () => window.confirm("?"),
  prompt: async () => null
});

/** Promise-based confirmations: `const { confirm } = useConfirm(); if (!(await confirm({...}))) return;` */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<ConfirmRequest | null>(null);
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  const resolver = useRef<((result: string | null) => void) | null>(null);

  const ask = useCallback((next: ConfirmRequest) => {
    resolver.current?.(null);
    return new Promise<string | null>((resolve) => {
      resolver.current = resolve;
      setValue(next.input?.initial ?? "");
      setRequest(next);
      setOpen(true);
    });
  }, []);

  const finish = (result: string | null) => {
    resolver.current?.(result);
    resolver.current = null;
    setOpen(false);
  };

  const api = useMemo<ConfirmApi>(
    () => ({
      confirm: async (next) => (await ask(next)) !== null,
      prompt: (next) => ask(next)
    }),
    [ask]
  );

  const input = request?.input;
  const inputOk = !input || value.trim().length >= (input.minLength ?? 1);

  return (
    <ConfirmContext.Provider value={api}>
      {children}
      {request && (
        <ConfirmDialog
          open={open}
          title={request.title}
          body={request.body}
          confirmLabel={request.confirmLabel}
          tone={request.tone}
          phrase={request.phrase}
          confirmDisabled={!inputOk}
          onConfirm={() => finish(input ? value.trim() : "")}
          onClose={() => finish(null)}
        >
          {input && (
            <TextField
              fullWidth
              autoFocus={!request.phrase}
              label={input.label}
              value={value}
              onChange={(event) => setValue(event.target.value)}
              helperText={input.helper ?? " "}
              slotProps={{ htmlInput: { dir: input.ltr ? "ltr" : undefined, minLength: input.minLength } }}
            />
          )}
        </ConfirmDialog>
      )}
    </ConfirmContext.Provider>
  );
}

export function useConfirm() {
  return useContext(ConfirmContext);
}
