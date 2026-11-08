/**
 * «کند کن / مسدود کن» dialog (docs/38 §4 `POST /api/v1/dns/mitigations`, dns:write).
 * Used by «پایش» (busiest names/devices, attacks) and «لاگ» (a row's device or name).
 * The user picks what to do and for how long; Advanced also sets the allowed rate and a note.
 */
import { useState } from "react";
import {
  Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, ToggleButton, ToggleButtonGroup, Typography,
  useMediaQuery, useTheme
} from "@mui/material";
import SpeedRoundedIcon from "@mui/icons-material/SpeedRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import { pick, say, type Bi } from "./copy";
import { FriendlyError, Ltr, NumberInput, RangeToggle, useKit } from "./kit";
import { DEFAULT_THROTTLE_QPS, MITIGATION_MINUTES, createMitigation, minutesWord, type Mitigation, type MitigationKind } from "./dnsLive";

const COPY = {
  titleClient: { fa: "با این دستگاه چه کنیم؟", en: "What to do with this device?" },
  titleDomain: { fa: "با این نام چه کنیم؟", en: "What to do with this name?" },
  throttle: { fa: "کند کن", en: "Slow down" },
  block: { fa: "مسدود کن", en: "Block" },
  howLong: { fa: "تا کی؟", en: "For how long?" },
  whatToDo: { fa: "چه کاری؟", en: "What?" },
  clientThrottle: { fa: "این دستگاه تا {duration} حداکثر {qps} پرسش در ثانیه جواب می‌گیرد. بقیه بی‌جواب می‌مانند.", en: "For {duration}, this device gets answers for at most {qps} questions per second. The rest go unanswered." },
  clientBlock: { fa: "تا {duration} به این دستگاه هیچ جوابی داده نمی‌شود.", en: "For {duration}, this device gets no answers at all." },
  domainThrottle: { fa: "پرسش‌های این نام و همه زیرنام‌هایش تا {duration} حداکثر {qps} بار در ثانیه جواب می‌گیرند.", en: "For {duration}, this name and everything under it is answered at most {qps} times per second." },
  domainBlock: { fa: "تا {duration} این نام و همه زیرنام‌هایش جواب «چنین نامی نیست» می‌گیرند.", en: "For {duration}, this name and everything under it gets “no such name”." },
  undoHint: { fa: "هر وقت خواستید از «محدودسازی‌های فعال» برش دارید.", en: "You can remove it any time under Active limits." },
  qps: { fa: "پرسش مجاز در ثانیه", en: "Questions allowed per second" },
  reason: { fa: "یادداشت (اختیاری)", en: "Note (optional)" },
  cancel: { fa: "نه، فعلاً نه", en: "Not now" },
  applying: { fa: "در حال اعمال…", en: "Applying…" },
  failed: { fa: "محدودیت گذاشته نشد.", en: "The limit wasn't set." }
} satisfies Record<string, Bi>;

export type MitigateTarget = { kind: MitigationKind; match: string; action?: "throttle" | "block"; reason?: string };

export function MitigateDialog({ target, onClose, onDone }: { target: MitigateTarget; onClose: () => void; onDone: (item: Mitigation | null) => void }) {
  const { language, isAdvanced } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [action, setAction] = useState<"throttle" | "block">(target.action ?? "throttle");
  const [minutes, setMinutes] = useState<string>("60");
  const [qps, setQps] = useState<number | null>(DEFAULT_THROTTLE_QPS);
  const [reason, setReason] = useState(target.reason ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const duration = minutesWord(language, Number(minutes));
  const rate = qps ?? DEFAULT_THROTTLE_QPS;
  const explanation = target.kind === "client"
    ? say(language, action === "block" ? COPY.clientBlock : COPY.clientThrottle, { duration, qps: rate })
    : say(language, action === "block" ? COPY.domainBlock : COPY.domainThrottle, { duration, qps: rate });

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await createMitigation({
        kind: target.kind,
        match: target.match,
        action,
        minutes: Number(minutes),
        ...(action === "throttle" ? { qps: rate } : {}),
        ...(reason.trim() ? { reason: reason.trim() } : {})
      });
      onDone(result && typeof result === "object" && "id" in result ? result : null);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth="sm">
      <DialogTitle sx={{ fontWeight: 760 }}>{pick(language, target.kind === "client" ? COPY.titleClient : COPY.titleDomain)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Typography variant="body1" sx={{ fontWeight: 700, wordBreak: "break-all" }}><Ltr mono>{target.match}</Ltr></Typography>
          <Stack spacing={0.75}>
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.whatToDo)}</Typography>
            <ToggleButtonGroup exclusive value={action} onChange={(_event, next: "throttle" | "block" | null) => { if (next) setAction(next); }} aria-label={pick(language, COPY.whatToDo)} sx={{ flexWrap: "wrap" }}>
              <ToggleButton value="throttle" sx={{ minHeight: 44, gap: 1, textTransform: "none" }}><SpeedRoundedIcon fontSize="small" />{pick(language, COPY.throttle)}</ToggleButton>
              <ToggleButton value="block" sx={{ minHeight: 44, gap: 1, textTransform: "none" }}><BlockRoundedIcon fontSize="small" />{pick(language, COPY.block)}</ToggleButton>
            </ToggleButtonGroup>
          </Stack>
          <Stack spacing={0.75}>
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.howLong)}</Typography>
            <RangeToggle
              value={minutes}
              options={MITIGATION_MINUTES.map(String)}
              labelOf={(value) => minutesWord(language, Number(value))}
              onChange={setMinutes}
              label={pick(language, COPY.howLong)}
            />
          </Stack>
          {isAdvanced && action === "throttle" ? (
            <NumberInput label={pick(language, COPY.qps)} value={qps} onChange={setQps} min={1} max={100_000} integer />
          ) : null}
          {isAdvanced ? <TextField label={pick(language, COPY.reason)} value={reason} onChange={(event) => setReason(event.target.value.slice(0, 200))} size="small" fullWidth /> : null}
          <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{explanation}</Typography>
          <Typography variant="caption" color="text.secondary">{pick(language, COPY.undoHint)}</Typography>
          {error ? <FriendlyError error={error} title={pick(language, COPY.failed)} scope="dns" /> : null}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
        <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, COPY.cancel)}</Button>
        <Button
          variant="contained"
          color={action === "block" ? "error" : "primary"}
          onClick={() => void apply()}
          disabled={busy || (action === "throttle" && !(rate > 0))}
          startIcon={busy ? <CircularProgress size={16} color="inherit" /> : action === "block" ? <BlockRoundedIcon /> : <SpeedRoundedIcon />}
          sx={{ minHeight: 44 }}
        >
          {busy ? pick(language, COPY.applying) : pick(language, action === "block" ? COPY.block : COPY.throttle)}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
