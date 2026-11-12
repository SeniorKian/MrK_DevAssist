import { useState, type FormEvent } from "react";
import {
  Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, InputAdornment,
  Stack, TextField, Tooltip, Typography, useMediaQuery, useTheme
} from "@mui/material";
import AutorenewRoundedIcon from "@mui/icons-material/AutorenewRounded";
import VisibilityOffRoundedIcon from "@mui/icons-material/VisibilityOffRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import { ApiError } from "../api";
import { formatNumber } from "../format";
import { FriendlyError } from "./FriendlyError";
import { useKit } from "./useKit";

// No look-alike characters (0/O, 1/l/I) so a suggestion is easy to read and retype.
const LETTERS = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const ALPHABET = LETTERS + DIGITS;

function randomIndex(size: number): number {
  // Rejection sampling keeps every character equally likely.
  const limit = Math.floor(256 / size) * size;
  const byte = new Uint8Array(1);
  for (;;) {
    crypto.getRandomValues(byte);
    if (byte[0] < limit) return byte[0] % size;
  }
}

/** A strong random password (letters and digits) made in the browser with crypto.getRandomValues. */
export function suggestPassword(length = 20): string {
  for (;;) {
    let value = "";
    for (let index = 0; index < length; index += 1) value += ALPHABET[randomIndex(ALPHABET.length)];
    if (/[A-Za-z]/.test(value) && /[0-9]/.test(value)) return value;
  }
}

export type PasswordRules = {
  minLength?: number;
  maxLength?: number;
  /** Max UTF-8 bytes (bcrypt reads only 72). */
  maxBytes?: number;
  /** Printable ASCII without spaces (S3 secret keys). */
  asciiOnly?: boolean;
};

const COPY = {
  password: { fa: "رمز ورود", en: "Password" },
  suggestAnother: { fa: "پیشنهاد تازه", en: "Suggest another" },
  show: { fa: "نمایش رمز", en: "Show password" },
  hide: { fa: "پنهان کردن رمز", en: "Hide password" },
  hint: {
    fa: "یک رمز قوی پیشنهاد شده است. می‌توانید همین را نگه دارید یا رمز خودتان را بنویسید.",
    en: "A strong password is suggested. Keep it or type your own."
  },
  empty: { fa: "رمز را بنویسید یا یک پیشنهاد تازه بگیرید.", en: "Type a password or get a new suggestion." },
  tooShort: { fa: "دست‌کم {min} نویسه بنویسید.", en: "Use at least {min} characters." },
  tooLong: { fa: "حداکثر {max} نویسه بنویسید.", en: "Use at most {max} characters." },
  needLetter: { fa: "رمز باید دست‌کم یک حرف داشته باشد.", en: "The password needs at least one letter." },
  needDigit: { fa: "رمز باید دست‌کم یک عدد داشته باشد.", en: "The password needs at least one digit." },
  badChars: { fa: "فقط حرف و عدد انگلیسی و نشانه‌ها، بدون فاصله.", en: "Use English letters, digits and symbols only, with no spaces." },
  control: { fa: "این رمز نویسه نامعتبر دارد.", en: "This password has a character that can't be used." }
};

/** A sentence explaining why `value` breaks the rules, or null when it is fine. */
export function passwordProblem(language: "fa" | "en", value: string, rules: PasswordRules = {}): string | null {
  const min = rules.minLength ?? 6;
  const max = rules.maxLength ?? 256;
  const n = (count: number) => formatNumber(count, language);
  if (!value) return COPY.empty[language];
  if (value.length < min) return COPY.tooShort[language].replace("{min}", n(min));
  const bytes = new TextEncoder().encode(value).length;
  if (value.length > max || (rules.maxBytes !== undefined && bytes > rules.maxBytes)) {
    return COPY.tooLong[language].replace("{max}", n(Math.min(max, rules.maxBytes ?? max)));
  }
  if (rules.asciiOnly && !/^[\x21-\x7e]+$/.test(value)) return COPY.badChars[language];
  if (/[\x00-\x1f\x7f]/.test(value)) return COPY.control[language];
  if (!/\p{L}/u.test(value)) return COPY.needLetter[language];
  if (!/\p{Nd}/u.test(value)) return COPY.needDigit[language];
  return null;
}

export type PasswordInputProps = {
  value: string;
  onChange: (value: string) => void;
  label?: string;
  helperText?: string;
  rules?: PasswordRules;
  /** Server-side problem to show instead of the local check. */
  error?: string | null;
  autoFocus?: boolean;
  /** Length of a new suggestion. */
  suggestLength?: number;
};

/**
 * A password field that starts with a suggestion: fully editable, with buttons to get a new
 * suggestion and to show or hide the value. Seed `value` with `suggestPassword()`.
 */
export function PasswordInput({ value, onChange, label, helperText, rules, error, autoFocus, suggestLength = 20 }: PasswordInputProps) {
  const { language } = useKit();
  const [visible, setVisible] = useState(true);
  const problem = error ?? (value ? passwordProblem(language, value, rules) : null);
  return (
    <TextField
      label={label ?? COPY.password[language]}
      value={value}
      autoFocus={autoFocus}
      type={visible ? "text" : "password"}
      onChange={(event) => onChange(event.target.value)}
      error={Boolean(problem)}
      helperText={problem ?? helperText ?? COPY.hint[language]}
      fullWidth
      slotProps={{
        htmlInput: {
          dir: "ltr",
          autoComplete: "new-password",
          spellCheck: false,
          maxLength: rules?.maxLength ?? 256,
          style: { fontFamily: "monospace" },
          "aria-invalid": Boolean(problem) || undefined
        },
        input: {
          endAdornment: (
            <InputAdornment position="end">
              <Tooltip title={COPY.suggestAnother[language]}>
                <IconButton aria-label={COPY.suggestAnother[language]} onClick={() => onChange(suggestPassword(suggestLength))} edge="end" size="small">
                  <AutorenewRoundedIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title={visible ? COPY.hide[language] : COPY.show[language]}>
                <IconButton aria-label={visible ? COPY.hide[language] : COPY.show[language]} onClick={() => setVisible((shown) => !shown)} edge="end" size="small" sx={{ ml: 0.5 }}>
                  {visible ? <VisibilityOffRoundedIcon fontSize="small" /> : <VisibilityRoundedIcon fontSize="small" />}
                </IconButton>
              </Tooltip>
            </InputAdornment>
          )
        }
      }}
    />
  );
}

export type PasswordDialogProps = {
  open: boolean;
  title: string;
  /** Short sentence: what changes when the new password is saved. */
  hint?: string;
  label?: string;
  saveLabel: string;
  rules?: PasswordRules;
  suggestLength?: number;
  /** Receives the chosen value; throw to show a FriendlyError and keep the dialog open. */
  onSubmit: (value: string) => Promise<void>;
  onClose: () => void;
};

/** Pick a password for a new key or an existing account: a suggestion the user may keep or replace. */
export function PasswordDialog({ open, title, hint, label, saveLabel, rules, suggestLength = 20, onSubmit, onClose }: PasswordDialogProps) {
  const { language, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [value, setValue] = useState(() => suggestPassword(suggestLength));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const problem = passwordProblem(language, value, rules);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (problem || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(value);
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={busy ? undefined : onClose}
      fullScreen={fullScreen}
      fullWidth
      maxWidth="xs"
      aria-labelledby="mrk-password-dialog"
      // A fresh suggestion for the next time the dialog opens.
      slotProps={{ transition: { onExited: () => { setValue(suggestPassword(suggestLength)); setError(null); } } }}
    >
      <Box component="form" onSubmit={submit} noValidate>
        <DialogTitle id="mrk-password-dialog">{title}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} sx={{ pt: 1 }}>
            {hint && <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{hint}</Typography>}
            <PasswordInput value={value} onChange={setValue} label={label} rules={rules} suggestLength={suggestLength} autoFocus />
            {error !== null && <FriendlyError error={error} noAction />}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{c.cancel}</Button>
          <Button type="submit" variant="contained" disabled={Boolean(problem) || busy} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
            {saveLabel}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}
