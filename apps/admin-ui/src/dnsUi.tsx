/**
 * Small pieces shared by the DNS tabs (docs/41 §7): a list loader and a form dialog.
 * Moved out of DnsNames.tsx so the templates, sync, signing and blocking tabs reuse them.
 */
import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Typography, useMediaQuery, useTheme } from "@mui/material";
import { ApiError, isAbortError } from "./api";
import { FriendlyError, useKit } from "./kit";
import { setDnsBase } from "./dns";

/**
 * Run the DNS dialogs and tabs inside against another API base (`/api/v1/my/dns` in «فضای من»,
 * docs/43 §3). The base is set during render, before any child effect loads data, and goes back
 * to the panel default when the scope unmounts.
 */
export function DnsApiScope({ base, children }: { base: string; children: ReactNode }) {
  setDnsBase(base);
  useEffect(() => {
    setDnsBase(base);
    return () => setDnsBase(null);
  }, [base]);
  return <>{children}</>;
}

/** Load something once (and on `reload`); 401 is left to the session, aborts are ignored. */
export function useLoader<T>(loader: (signal: AbortSignal) => Promise<T>, enabled = true) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const load = useCallback(async () => {
    if (!enabled) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      setData(await loader(current.signal));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, [loader, enabled]);
  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);
  return { data, error, loading, reload: load, setData };
}

/** `useLoader` for lists (`items` instead of `data`). */
export function useList<T>(loader: (signal: AbortSignal) => Promise<T[]>, enabled = true) {
  const { data, error, loading, reload } = useLoader<T[]>(loader, enabled);
  return { items: data, error, loading, reload };
}

/** A missing endpoint (older server): a bare 404/405 or a `not_found` code. */
export function isMissingEndpoint(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 404 || error.status === 405 || error.status === 501) && (!error.code || error.code === "not_found" || error.code === "http_error" || error.code === "dns_not_found");
}

/** A dialog with a form: full screen on phones, one primary button, errors in plain words. */
export function FormDialog({ title, hint, children, submitLabel, busy, error, disabled, onSubmit, onClose, wide, extraActions }: {
  title: string; hint?: string; children: ReactNode; submitLabel: string; busy: boolean; error: unknown; disabled?: boolean;
  onSubmit: () => void; onClose: () => void; wide?: boolean; extraActions?: ReactNode;
}) {
  const { c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!busy && !disabled) onSubmit();
  };
  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth={wide ? "md" : "sm"}>
      <Box component="form" onSubmit={submit} noValidate sx={{ display: "flex", flexDirection: "column", height: fullScreen ? "100%" : undefined, minHeight: 0 }}>
        <DialogTitle sx={{ fontWeight: 760 }}>{title}</DialogTitle>
        <DialogContent sx={{ flex: 1 }}>
          <Stack spacing={2} sx={{ pt: 0.5 }}>
            {hint ? <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{hint}</Typography> : null}
            {children}
            {error ? <FriendlyError error={error} scope="dns" /> : null}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1, flexWrap: "wrap" }}>
          {extraActions}
          <Box sx={{ flex: 1 }} />
          <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{c.cancel}</Button>
          <Button type="submit" variant="contained" disabled={busy || disabled} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
            {submitLabel}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

export const ltrInput = { htmlInput: { dir: "ltr" as const, spellCheck: false, autoCapitalize: "none", autoComplete: "off" } };

export function Loading() {
  return <Box sx={{ display: "grid", placeItems: "center", py: 3 }}><CircularProgress size={24} aria-hidden /></Box>;
}
