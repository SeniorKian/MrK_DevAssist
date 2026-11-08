import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, LinearProgress,
  Step, StepLabel, Stepper, Typography, useMediaQuery, useTheme
} from "@mui/material";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import { say } from "../copy/text";
import { COMMON } from "../copy/common";
import { FriendlyError } from "./FriendlyError";
import { useKit } from "./useKit";

export type WizardStep = {
  key: string;
  /** Short step name for the stepper: «کیست؟», «چه کاری بکند؟», «بفرستید». */
  title: string;
  /** One sentence shown at the top of the step. */
  hint?: string;
  render: () => ReactNode;
  /** Return an error sentence to block «بعدی», or null when the step is valid. */
  validate?: () => string | null;
  /**
   * Async work when leaving the step (e.g. "test before save"). Throw to stay on the step;
   * the error is shown with FriendlyError.
   */
  onNext?: () => Promise<void>;
  /** Label for the «بعدی» button on this step, e.g. «امتحان اتصال». */
  nextLabel?: string;
  /** Optional steps can be skipped. */
  optional?: boolean;
};

export type ActionWizardProps = {
  open: boolean;
  title: string;
  steps: WizardStep[];
  /** Runs on the last step's main button. Throw to keep the wizard open with the error shown. */
  onFinish: () => Promise<void> | void;
  onClose: () => void;
  /** Label for the final button, a verb naming the result: «ساخت پشتیبان». */
  finishLabel?: string;
  /** Rendered instead of the steps after a successful finish (e.g. a OneTimeSecret or a success message). */
  done?: ReactNode;
};

/**
 * Stepper dialog for anything with more than 3 fields (docs/33 §4.1). One step per screen on phones,
 * Back/Next at the bottom, «در حال …» while async work runs, errors in plain words.
 */
export function ActionWizard({ open, title, steps, onFinish, onClose, finishLabel, done }: ActionWizardProps) {
  const { language, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [active, setActive] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [finished, setFinished] = useState(false);
  const contentRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    setActive(0);
    setError(null);
    setMessage(null);
    setFinished(false);
  }, [open]);

  // Move focus to the step content so keyboard and screen-reader users land on the new step.
  useEffect(() => {
    contentRef.current?.focus();
  }, [active]);

  const step = steps[Math.min(active, steps.length - 1)];
  const isLast = active === steps.length - 1;

  const next = async () => {
    setError(null);
    const problem = step.validate?.() ?? null;
    setMessage(problem);
    if (problem) return;
    setBusy(true);
    try {
      if (step.onNext) await step.onNext();
      if (isLast) {
        await onFinish();
        if (done) setFinished(true);
        else onClose();
      } else {
        setActive((value) => value + 1);
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const back = () => {
    setError(null);
    setMessage(null);
    setActive((value) => Math.max(0, value - 1));
  };

  const progress = ((active + 1) / steps.length) * 100;
  return (
    <Dialog
      open={open}
      onClose={busy ? undefined : onClose}
      fullScreen={fullScreen}
      fullWidth
      maxWidth="sm"
      aria-labelledby="mrk-wizard-title"
    >
      <DialogTitle id="mrk-wizard-title" sx={{ display: "flex", alignItems: "center", gap: 1, pr: 1 }}>
        <Box sx={{ flex: 1, minWidth: 0, fontWeight: 760 }}>{title}</Box>
        <IconButton onClick={onClose} disabled={busy} aria-label={c.closeDialog} sx={{ width: 44, height: 44 }}>
          <CloseRoundedIcon />
        </IconButton>
      </DialogTitle>
      {finished ? (
        <>
          <DialogContent>{done}</DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button variant="contained" onClick={onClose} sx={{ minHeight: 44 }}>{c.finish}</Button>
          </DialogActions>
        </>
      ) : (
        <>
          {fullScreen || steps.length > 4 ? (
            <Box sx={{ px: 3 }}>
              <Typography variant="caption" color="text.secondary">{say(language, COMMON.step, { current: active + 1, total: steps.length })}</Typography>
              <LinearProgress variant="determinate" value={progress} sx={{ mt: 0.5, height: 4, borderRadius: 2 }} aria-hidden />
            </Box>
          ) : (
            <Stepper activeStep={active} alternativeLabel sx={{ px: 2, pt: 1 }}>
              {steps.map((item) => (
                <Step key={item.key}>
                  <StepLabel optional={item.optional ? <Typography variant="caption">{c.optional}</Typography> : undefined}>{item.title}</StepLabel>
                </Step>
              ))}
            </Stepper>
          )}
          <DialogContent ref={contentRef} tabIndex={-1} sx={{ outline: "none", pt: 2.5 }} aria-live="polite">
            <Typography component="h3" variant="subtitle1" sx={{ fontWeight: 760, mb: 0.5 }}>{step.title}</Typography>
            {step.hint && <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.9 }}>{step.hint}</Typography>}
            <Box>{step.render()}</Box>
            {message && <Typography role="alert" variant="body2" color="error.main" sx={{ mt: 2 }}>{message}</Typography>}
            {error !== null && <Box sx={{ mt: 2 }}><FriendlyError error={error} noAction /></Box>}
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
            {active > 0 && <Button onClick={back} disabled={busy} sx={{ minHeight: 44 }}>{c.back}</Button>}
            <Box sx={{ flex: 1 }} />
            {step.optional && !isLast && (
              <Button onClick={() => setActive((value) => value + 1)} disabled={busy} sx={{ minHeight: 44 }}>{c.skip}</Button>
            )}
            <Button
              variant="contained"
              onClick={() => void next()}
              disabled={busy}
              startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined}
              sx={{ minHeight: 44, minWidth: 120 }}
            >
              {step.nextLabel ?? (isLast ? (finishLabel ?? c.finish) : c.next)}
            </Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );
}
