import { useState } from "react";
import { Alert, AlertTitle, Box, Button, Collapse, Link, Stack, Typography } from "@mui/material";
import { describeError, ERROR_ACTION_LABEL, technicalSummary, type ErrorAction } from "../copy/errors";
import { CopyButton } from "./CopyField";
import { useKit } from "./useKit";

export type FriendlyErrorProps = {
  /** Anything thrown (ApiError, TypeError, Error, string). */
  error: unknown;
  /** Optional lead-in naming what failed: «ذخیره نشد». The catalog sentence follows it. */
  title?: string;
  /** Handlers for the suggested action. `reload` and `signIn` work without a handler. */
  onRetry?: () => void;
  onAction?: (action: ErrorAction) => void;
  /** Hide the action button. */
  noAction?: boolean;
  severity?: "error" | "warning";
  onClose?: () => void;
  /** Render as plain text (for inside tables/cards) instead of an Alert. */
  inline?: boolean;
  /** Module scope for wording (`"firewall"` → catalog entry `firewall:<code>` first). */
  scope?: string;
};

/**
 * Error = plain sentence + one helpful button. In Advanced mode a collapsed «جزئیات فنی»
 * row shows code, HTTP status and the backend message (LTR, with a copy button) for support.
 * Simple mode never shows codes.
 */
export function FriendlyError({ error, title, onRetry, onAction, noAction, severity = "error", onClose, inline, scope }: FriendlyErrorProps) {
  const { language, isAdvanced, c } = useKit();
  const [open, setOpen] = useState(false);
  const info = describeError(language, error, scope);
  const summary = technicalSummary(info.technical);

  const action = noAction ? undefined : info.action;
  const runAction = () => {
    if (!action) return;
    if (onAction) return onAction(action);
    if ((action === "retry" || action === "refreshList") && onRetry) return onRetry();
    if (action === "reload" || action === "signIn") window.location.reload();
  };
  const actionAvailable = Boolean(
    action && (onAction || action === "reload" || action === "signIn" || ((action === "retry" || action === "refreshList") && onRetry))
  );

  const details = isAdvanced && summary && (
    <Box sx={{ mt: 0.75 }}>
      <Link component="button" type="button" variant="caption" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        {c.technicalDetails}
      </Link>
      <Collapse in={open}>
        <Stack direction="row" alignItems="flex-start" spacing={0.5} sx={{ mt: 0.5 }}>
          <Typography
            component="code"
            dir="ltr"
            variant="caption"
            sx={{ display: "block", flex: 1, p: 1, borderRadius: 1, bgcolor: "action.hover", fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", overflowWrap: "anywhere", textAlign: "left" }}
          >
            {summary}
          </Typography>
          <CopyButton value={summary} label={c.copyTechnicalDetails} />
        </Stack>
      </Collapse>
    </Box>
  );

  if (inline) {
    return (
      <Box role="alert">
        <Typography variant="body2" color={severity === "error" ? "error.main" : "warning.main"}>
          {title ? `${title} ` : ""}{info.message}
        </Typography>
        {details}
      </Box>
    );
  }

  return (
    <Alert
      severity={severity}
      onClose={onClose}
      action={
        actionAvailable && action ? (
          <Button color="inherit" size="small" onClick={runAction} sx={{ whiteSpace: "nowrap" }}>
            {ERROR_ACTION_LABEL[action][language]}
          </Button>
        ) : undefined
      }
    >
      {title && <AlertTitle sx={{ fontWeight: 720 }}>{title}</AlertTitle>}
      <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{info.message}</Typography>
      {details}
    </Alert>
  );
}
