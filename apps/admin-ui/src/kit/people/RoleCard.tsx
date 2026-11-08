import type { ReactNode } from "react";
import { Avatar, Box, ButtonBase, Card, CardContent, Grid, Stack, Typography } from "@mui/material";
import CheckRoundedIcon from "@mui/icons-material/CheckRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import { say } from "../../copy/text";
import { useKit } from "../useKit";
import { initials, type RoleView } from "./types";

const COPY = {
  can: { fa: "می‌تواند", en: "Can" },
  cannot: { fa: "نمی‌تواند", en: "Can't" },
  people: { fa: "{count} نفر این نقش را دارند", en: "{count} people have this role" },
  nobody: { fa: "هنوز کسی این نقش را ندارد", en: "Nobody has this role yet" },
  more: { fa: "و {count} مورد دیگر", en: "and {count} more" },
  custom: { fa: "نقش سفارشی", en: "Custom role" },
  selected: { fa: "انتخاب شده", en: "Selected" }
};

export type RoleCardProps = {
  role: RoleView;
  /** Selectable card (role pickers): renders as a radio button. */
  onSelect?: () => void;
  selected?: boolean;
  /** Not selectable, with a plain reason shown under the name. */
  disabledReason?: string | null;
  /** Hide the can/can't lists (for tight pickers). */
  compact?: boolean;
  /** Show the user count line. */
  showCount?: boolean;
  /** Max bullets per list before «و n مورد دیگر». */
  maxItems?: number;
  /** Buttons at the bottom (e.g. «دیدن همه اجازه‌ها», edit, delete). */
  footer?: ReactNode;
};

function Bullets({ items, ok, max }: { items: string[]; ok: boolean; max: number }) {
  const { language } = useKit();
  if (items.length === 0) return null;
  const shown = items.slice(0, max);
  const rest = items.length - shown.length;
  const Icon = ok ? CheckRoundedIcon : CloseRoundedIcon;
  return (
    <Box component="ul" sx={{ listStyle: "none", m: 0, p: 0, display: "grid", gap: 0.5 }}>
      {shown.map((item) => (
        <Box component="li" key={item} sx={{ display: "flex", gap: 0.75, alignItems: "flex-start" }}>
          <Icon aria-hidden sx={{ fontSize: 18, mt: 0.25, color: ok ? "success.main" : "text.disabled", flexShrink: 0 }} />
          <Typography variant="body2" sx={{ lineHeight: 1.8 }}>{item}</Typography>
        </Box>
      ))}
      {rest > 0 && (
        <Typography component="li" variant="caption" color="text.secondary" sx={{ paddingInlineStart: 3.25 }}>
          {say(language, COPY.more, { count: rest })}
        </Typography>
      )}
    </Box>
  );
}

/**
 * A role in plain words (docs/33 §5.1): coloured avatar, name, one-liner, what the role can / can't do,
 * an optional note («می‌تواند افراد دیگر را هم اضافه کند») and how many people have it.
 * Never shows permission ids.
 */
export function RoleCard({ role, onSelect, selected, disabledReason, compact, showCount, maxItems = 5, footer }: RoleCardProps) {
  const { language } = useKit();
  const selectable = Boolean(onSelect) && !disabledReason;
  const body = (
    <CardContent sx={{ p: 2, "&:last-child": { pb: 2 }, height: "100%", display: "flex", flexDirection: "column", gap: 1.25 }}>
      <Stack direction="row" spacing={1.25} alignItems="center" sx={{ minWidth: 0 }}>
        <Avatar sx={{ bgcolor: `${role.color}.main`, color: `${role.color}.contrastText`, width: 40, height: 40, fontSize: 15, fontWeight: 760 }} aria-hidden>
          {initials(role.name)}
        </Avatar>
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Typography component="h3" variant="subtitle1" sx={{ fontWeight: 780, lineHeight: 1.4 }}>{role.name}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>{role.oneLiner}</Typography>
        </Box>
        {selected && <CheckCircleRoundedIcon color="primary" aria-label={COPY.selected[language]} />}
      </Stack>
      {!role.builtin && <Typography variant="caption" color="success.main" sx={{ fontWeight: 700 }}>{COPY.custom[language]}</Typography>}
      {disabledReason && <Typography variant="caption" color="text.secondary">{disabledReason}</Typography>}
      {!compact && (
        <>
          {role.can.length > 0 && (
            <Box>
              <Typography variant="caption" sx={{ fontWeight: 760, color: "success.main" }}>{COPY.can[language]}</Typography>
              <Bullets items={role.can} ok max={maxItems} />
            </Box>
          )}
          {role.cannot.length > 0 && (
            <Box>
              <Typography variant="caption" sx={{ fontWeight: 760, color: "text.secondary" }}>{COPY.cannot[language]}</Typography>
              <Bullets items={role.cannot} ok={false} max={Math.min(maxItems, 3)} />
            </Box>
          )}
        </>
      )}
      {role.note && (
        <Typography variant="caption" sx={{ color: "warning.main", fontWeight: 650, lineHeight: 1.8 }}>{role.note}</Typography>
      )}
      {showCount && role.userCount !== undefined && (
        <Typography variant="caption" color="text.secondary">
          {role.userCount > 0 ? say(language, COPY.people, { count: role.userCount }) : COPY.nobody[language]}
        </Typography>
      )}
      {footer && <Box sx={{ mt: "auto", pt: 0.5, display: "flex", flexWrap: "wrap", gap: 1 }}>{footer}</Box>}
    </CardContent>
  );
  return (
    <Card
      variant="outlined"
      sx={{
        height: "100%",
        borderColor: selected ? "primary.main" : undefined,
        borderWidth: selected ? 2 : 1,
        opacity: disabledReason ? 0.6 : 1
      }}
    >
      {onSelect ? (
        <ButtonBase
          role="radio"
          aria-checked={Boolean(selected)}
          aria-disabled={!selectable}
          disabled={!selectable}
          onClick={onSelect}
          sx={{ display: "block", width: "100%", height: "100%", textAlign: "start", borderRadius: "inherit" }}
        >
          {body}
        </ButtonBase>
      ) : (
        body
      )}
    </Card>
  );
}

export type RolePickerProps = {
  roles: RoleView[];
  value: string;
  onChange: (roleId: string) => void;
  /** Return a plain reason when a role can't be picked (e.g. only the owner can give it). */
  disabledReason?: (role: RoleView) => string | null;
  /** Accessible name for the radio group. */
  label: string;
  compact?: boolean;
};

/** Role cards as a radio group (invite wizard, change role). */
export function RolePicker({ roles, value, onChange, disabledReason, label, compact }: RolePickerProps) {
  return (
    <Grid container spacing={1.5} role="radiogroup" aria-label={label}>
      {roles.map((role) => (
        <Grid key={role.id} size={{ xs: 12, sm: 6 }}>
          <RoleCard
            role={role}
            selected={role.id === value}
            onSelect={() => onChange(role.id)}
            disabledReason={disabledReason?.(role) ?? null}
            compact={compact}
            maxItems={3}
          />
        </Grid>
      ))}
    </Grid>
  );
}
