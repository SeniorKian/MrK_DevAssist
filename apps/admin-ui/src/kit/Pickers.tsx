/**
 * Small shared pieces promoted from Phase 1 pages:
 *   - `CardMenu`    – the ⋮ menu on a card (44 px targets, danger items in red); hidden when empty.
 *   - `ChoiceCards` – big tappable cards to pick one option (a radiogroup).
 *   - `NameDialog`  – one text field dialog (new folder, rename, …) with validation and FriendlyError.
 *   - `RangeToggle` – a compact single-choice toggle (time ranges, views).
 */
import { useState, type FormEvent, type ReactNode } from "react";
import {
  Box, Button, Card, CardActionArea, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, ListItemIcon,
  ListItemText, Menu, MenuItem, Stack, TextField, ToggleButton, ToggleButtonGroup, Typography, useMediaQuery, useTheme
} from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import MoreVertRoundedIcon from "@mui/icons-material/MoreVertRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import { ApiError } from "../api";
import { FriendlyError } from "./FriendlyError";
import { useKit } from "./useKit";

// ── ⋮ card menu ──────────────────────────────────────────────────────────────

export type CardMenuItem = { key: string; label: string; icon?: ReactNode; danger?: boolean; disabled?: boolean; onClick: () => void };

export function CardMenu({ label, items }: { label: string; items: CardMenuItem[] }) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  if (items.length === 0) return null;
  return (
    <>
      <IconButton aria-label={label} aria-haspopup="menu" onClick={(event) => setAnchor(event.currentTarget)} sx={{ width: 44, height: 44 }}>
        <MoreVertRoundedIcon />
      </IconButton>
      <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}>
        {items.map((item) => (
          <MenuItem
            key={item.key}
            disabled={item.disabled}
            onClick={() => { setAnchor(null); item.onClick(); }}
            sx={{ minHeight: 44, color: item.danger ? "error.main" : undefined }}
          >
            {item.icon && <ListItemIcon sx={{ color: item.danger ? "error.main" : undefined }}>{item.icon}</ListItemIcon>}
            <ListItemText>{item.label}</ListItemText>
          </MenuItem>
        ))}
      </Menu>
    </>
  );
}

// ── Choice cards ─────────────────────────────────────────────────────────────

export type ChoiceCardOption<K extends string> = {
  key: K;
  icon?: SvgIconComponent;
  title: ReactNode;
  body?: ReactNode;
  /** Small chips/pills shown next to the title. */
  badges?: ReactNode;
  disabled?: boolean;
  tone?: "warning";
};

/** Big tappable cards to pick one option (access levels, kinds, discovered items). */
export function ChoiceCards<K extends string>({ options, value, onChange, label }: {
  options: ChoiceCardOption<K>[];
  /** The picked key, or null when nothing is picked yet. */
  value: K | null;
  onChange: (key: K) => void;
  label: string;
}) {
  return (
    <Stack role="radiogroup" aria-label={label} spacing={1}>
      {options.map((option) => {
        const Icon = option.icon;
        const selected = option.key === value;
        const color = option.tone === "warning" ? "warning" : "primary";
        return (
          <Card
            key={option.key}
            variant="outlined"
            sx={{ borderColor: selected ? `${color}.main` : "divider", borderWidth: selected ? 2 : 1, opacity: option.disabled ? 0.55 : 1 }}
          >
            <CardActionArea role="radio" aria-checked={selected} disabled={option.disabled} onClick={() => onChange(option.key)} sx={{ p: 1.5, minHeight: 56 }}>
              <Stack direction="row" spacing={1.5} alignItems="center">
                {Icon && <Icon color={selected ? color : "action"} aria-hidden />}
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between" useFlexGap flexWrap="wrap">
                    <Typography fontWeight={720}>{option.title}</Typography>
                    {option.badges ? <Stack direction="row" spacing={0.5} alignItems="center">{option.badges}</Stack> : null}
                  </Stack>
                  {option.body ? <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>{option.body}</Typography> : null}
                </Box>
                {selected && <CheckCircleRoundedIcon color={color} aria-hidden />}
              </Stack>
            </CardActionArea>
          </Card>
        );
      })}
    </Stack>
  );
}

// ── Name dialog ──────────────────────────────────────────────────────────────

export type NameDialogProps = {
  title: string;
  hint?: string;
  label: string;
  initial?: string;
  saveLabel: string;
  /** Plain sentence when the (trimmed) value isn't acceptable. */
  validate?: (value: string) => string | null;
  /** Throw to show a FriendlyError and keep the dialog open. */
  onSubmit: (value: string) => Promise<void>;
  onClose: () => void;
  /** Left-to-right input (names, paths). Default true. */
  ltr?: boolean;
};

/** One text field dialog (new folder, rename). Full screen on phones. */
export function NameDialog({ title, hint, label, initial, saveLabel, validate, onSubmit, onClose, ltr = true }: NameDialogProps) {
  const { c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [value, setValue] = useState(initial ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const problem = value.trim() ? (validate?.(value.trim()) ?? null) : null;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!value.trim() || problem || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(value.trim());
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth="xs" aria-labelledby="mrk-name-dialog">
      <Box component="form" onSubmit={submit} noValidate>
        <DialogTitle id="mrk-name-dialog">{title}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} sx={{ pt: 1 }}>
            {hint && <Typography variant="body2" color="text.secondary">{hint}</Typography>}
            <TextField
              fullWidth
              autoFocus
              label={label}
              value={value}
              disabled={busy}
              error={Boolean(problem)}
              helperText={problem ?? " "}
              onChange={(event) => setValue(event.target.value)}
              slotProps={{ htmlInput: { dir: ltr ? "ltr" : undefined, spellCheck: false, autoComplete: "off" } }}
            />
            {error !== null && <FriendlyError error={error} noAction />}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{c.cancel}</Button>
          <Button type="submit" variant="contained" disabled={!value.trim() || Boolean(problem) || busy} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
            {saveLabel}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

// ── Range toggle ─────────────────────────────────────────────────────────────

export type RangeToggleProps<K extends string> = {
  value: K;
  options: readonly K[];
  /** Plain word for each option («۲۴ ساعت»). */
  labelOf: (key: K) => string;
  onChange: (key: K) => void;
  /** Accessible group name («بازه زمانی»). */
  label: string;
};

/** Compact single-choice toggle (time ranges). Never deselects. */
export function RangeToggle<K extends string>({ value, options, labelOf, onChange, label }: RangeToggleProps<K>) {
  return (
    <ToggleButtonGroup
      size="small"
      exclusive
      value={value}
      onChange={(_event, next: K | null) => { if (next) onChange(next); }}
      aria-label={label}
      sx={{ flexWrap: "wrap" }}
    >
      {options.map((option) => (
        <ToggleButton key={option} value={option} sx={{ px: 1.25, minHeight: 40, textTransform: "none" }}>{labelOf(option)}</ToggleButton>
      ))}
    </ToggleButtonGroup>
  );
}
