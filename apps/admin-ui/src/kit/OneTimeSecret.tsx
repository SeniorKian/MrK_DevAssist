import { useState, type ReactNode } from "react";
import { Alert, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Stack, Typography, useMediaQuery, useTheme } from "@mui/material";
import { CopyField } from "./CopyField";
import { useKit } from "./useKit";

export type SecretItem = { label: string; value: string; ltr?: boolean; multiline?: boolean };

export type OneTimeSecretProps = {
  open: boolean;
  title: string;
  /** Short sentence: what this is for. */
  body?: ReactNode;
  /** One or more values shown once (access key + secret, token, invite password, backup key). */
  items: SecretItem[];
  /** Optional ready-to-paste message (e.g. an invite text). */
  message?: { label: string; value: string };
  /** Called after the user ticked «کپی کردم» and closed. */
  onClose: () => void;
};

const COPY = {
  warning: {
    fa: "این فقط همین یک بار نمایش داده می‌شود. همین حالا کپی کنید و جای امنی نگه دارید.",
    en: "This is shown only once. Copy it now and keep it somewhere safe."
  },
  acknowledge: { fa: "کپی کردم و جای امنی نگه داشتم", en: "I copied it and stored it safely" },
  close: { fa: "تمام", en: "Done" }
};

/** Show a secret once; the dialog can't be dismissed until the user confirms they copied it. */
export function OneTimeSecret({ open, title, body, items, message, onClose }: OneTimeSecretProps) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [acknowledged, setAcknowledged] = useState(false);
  return (
    <Dialog
      open={open}
      fullScreen={fullScreen}
      fullWidth
      maxWidth="sm"
      aria-labelledby="mrk-secret-title"
      onClose={() => {
        // Escape and backdrop clicks are ignored until the secret was acknowledged.
        if (acknowledged) onClose();
      }}
      slotProps={{ transition: { onExited: () => setAcknowledged(false) } }}
    >
      <DialogTitle id="mrk-secret-title">{title}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 0.5 }}>
          {body && (typeof body === "string" ? <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{body}</Typography> : body)}
          <Alert severity="warning">{COPY.warning[language]}</Alert>
          {items.map((item) => (
            <CopyField key={item.label} label={item.label} value={item.value} ltr={item.ltr ?? true} multiline={item.multiline} />
          ))}
          {message && <CopyField label={message.label} value={message.value} ltr={false} multiline />}
          <FormControlLabel
            control={<Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />}
            label={COPY.acknowledge[language]}
          />
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button variant="contained" disabled={!acknowledged} onClick={onClose}>{COPY.close[language]}</Button>
      </DialogActions>
    </Dialog>
  );
}

/** Alias with the name used in docs/33 §6. */
export const SecretOnce = OneTimeSecret;
