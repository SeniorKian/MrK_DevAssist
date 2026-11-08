import type { ReactNode } from "react";
import {
  Box, Button, Card, CardActionArea, Checkbox, IconButton, LinearProgress, List, ListItem, ListItemButton,
  ListItemIcon, ListItemText, Stack, Tooltip, Typography
} from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import ErrorRoundedIcon from "@mui/icons-material/ErrorRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import InfoRoundedIcon from "@mui/icons-material/InfoRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import RadioButtonUncheckedRoundedIcon from "@mui/icons-material/RadioButtonUncheckedRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import { formatNumber } from "../format";
import { useKit } from "./useKit";

// ── AttentionList ────────────────────────────────────────────────────────────

export type AttentionSeverity = "critical" | "warning" | "info";

export type AttentionItem = {
  id: string;
  severity: AttentionSeverity;
  /** One sentence: «فضای دیسک رو به اتمام است (۸۷٪)». */
  title: string;
  /** Optional «چرا؟» line. */
  why?: string;
  action?: { label: string; onClick?: () => void; href?: string };
};

const SEVERITY_ICON: Record<AttentionSeverity, { icon: SvgIconComponent; color: "error" | "warning" | "info" }> = {
  critical: { icon: ErrorRoundedIcon, color: "error" },
  warning: { icon: WarningAmberRoundedIcon, color: "warning" },
  info: { icon: InfoRoundedIcon, color: "info" }
};

const RANK: Record<AttentionSeverity, number> = { critical: 0, warning: 1, info: 2 };

/** "Needs attention" list: one sentence + one button per item, sorted by severity, hidden when empty. */
export function AttentionList({ items, title }: { items: AttentionItem[]; title?: string }) {
  const { language } = useKit();
  if (items.length === 0) return null;
  const sorted = [...items].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  return (
    <Card component="section" aria-label={title ?? (language === "fa" ? "نیاز به توجه" : "Needs attention")}>
      {title && <Typography component="h2" variant="subtitle1" sx={{ fontWeight: 760, px: 2.5, pt: 2 }}>{title}</Typography>}
      <List disablePadding>
        {sorted.map((item) => {
          const { icon: Icon, color } = SEVERITY_ICON[item.severity];
          return (
            <ListItem key={item.id} divider sx={{ gap: 1.5, py: 1.5, px: 2.5, flexWrap: { xs: "wrap", sm: "nowrap" } }}>
              <Icon color={color} aria-hidden />
              <ListItemText primary={item.title} secondary={item.why} slotProps={{ primary: { sx: { fontWeight: 650 } } }} sx={{ minWidth: 0, flex: 1 }} />
              {item.action && (
                <Button variant="outlined" size="small" onClick={item.action.onClick} href={item.action.href} sx={{ whiteSpace: "nowrap", minHeight: 40, width: { xs: "100%", sm: "auto" } }}>
                  {item.action.label}
                </Button>
              )}
            </ListItem>
          );
        })}
      </List>
    </Card>
  );
}

// ── Verdict ──────────────────────────────────────────────────────────────────

/** Greeting + one-line verdict: green, amber or red; never a percentage or component name. */
export function Verdict({ greeting, verdict, tone }: { greeting: string; verdict: string; tone: "ok" | "warn" | "error" }) {
  const color = tone === "ok" ? "success.main" : tone === "warn" ? "warning.main" : "error.main";
  const Icon = tone === "ok" ? CheckCircleRoundedIcon : tone === "warn" ? WarningAmberRoundedIcon : ErrorRoundedIcon;
  return (
    <Stack direction="row" spacing={1.5} alignItems="center">
      <Icon sx={{ color, fontSize: 36 }} aria-hidden />
      <Box>
        <Typography component="h1" variant="h5" sx={{ fontWeight: 780 }}>{greeting}</Typography>
        <Typography variant="body1" sx={{ color, fontWeight: 650 }} role="status">{verdict}</Typography>
      </Box>
    </Stack>
  );
}

// ── QuickActionTile ──────────────────────────────────────────────────────────

export type QuickActionTileProps = {
  icon: SvgIconComponent;
  /** A verb: «وصل کردن یک پروژه». */
  label: string;
  hint?: string;
  onClick?: () => void;
  href?: string;
};

/** Big icon + verb tile for Home quick actions. Filter by permission before rendering. */
export function QuickActionTile({ icon: Icon, label, hint, onClick, href }: QuickActionTileProps) {
  return (
    <Card variant="outlined" sx={{ height: "100%" }}>
      <CardActionArea onClick={onClick} {...(href ? ({ href } as object) : {})} sx={{ height: "100%", p: 2, minHeight: 96 }}>
        <Stack spacing={1} alignItems="flex-start">
          <Box aria-hidden sx={{ display: "grid", placeItems: "center", width: 40, height: 40, borderRadius: 2, bgcolor: "action.hover", color: "primary.main" }}>
            <Icon />
          </Box>
          <Typography variant="body1" sx={{ fontWeight: 720 }}>{label}</Typography>
          {hint && <Typography variant="caption" color="text.secondary">{hint}</Typography>}
        </Stack>
      </CardActionArea>
    </Card>
  );
}

/** 2×3 grid on desktop, 2 columns on phones. */
export function QuickActionGrid({ children }: { children: ReactNode }) {
  return <Box sx={{ display: "grid", gap: 1.5, gridTemplateColumns: { xs: "repeat(2, minmax(0, 1fr))", md: "repeat(3, minmax(0, 1fr))" } }}>{children}</Box>;
}

// ── ChecklistCard ────────────────────────────────────────────────────────────

export type ChecklistStep = {
  key: string;
  label: string;
  done: boolean;
  optional?: boolean;
  /** Opens the wizard for this step. */
  onClick?: () => void;
};

const CHECKLIST_COPY = {
  title: { fa: "راه‌اندازی در {n} قدم", en: "Set up in {n} steps" },
  progress: { fa: "{done} از {total} قدم انجام شده", en: "{done} of {total} steps done" },
  dismiss: { fa: "پنهان کردن این فهرست", en: "Hide this checklist" },
  optional: { fa: "اختیاری", en: "optional" }
};

/** Getting-started checklist with progress and dismiss. Persisting `dismissed` is the page's job. */
export function ChecklistCard({ steps, onDismiss, title }: { steps: ChecklistStep[]; onDismiss?: () => void; title?: string }) {
  const { language } = useKit();
  const done = steps.filter((step) => step.done).length;
  if (steps.length === 0 || done === steps.length) return null;
  const n = (value: number) => formatNumber(value, language);
  return (
    <Card component="section" aria-labelledby="mrk-checklist-title">
      <Stack direction="row" alignItems="center" sx={{ px: 2.5, pt: 2 }}>
        <Box sx={{ flex: 1 }}>
          <Typography id="mrk-checklist-title" component="h2" variant="subtitle1" sx={{ fontWeight: 760 }}>
            {title ?? CHECKLIST_COPY.title[language].replace("{n}", n(steps.length))}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {CHECKLIST_COPY.progress[language].replace("{done}", n(done)).replace("{total}", n(steps.length))}
          </Typography>
        </Box>
        {onDismiss && (
          <Tooltip title={CHECKLIST_COPY.dismiss[language]}>
            <IconButton onClick={onDismiss} aria-label={CHECKLIST_COPY.dismiss[language]}><CloseRoundedIcon /></IconButton>
          </Tooltip>
        )}
      </Stack>
      <LinearProgress variant="determinate" value={(done / steps.length) * 100} sx={{ mx: 2.5, mt: 1, height: 6, borderRadius: 3 }} aria-hidden />
      <List>
        {steps.map((step) => (
          <ListItem key={step.key} disablePadding>
            <ListItemButton onClick={step.onClick} disabled={step.done || !step.onClick} sx={{ minHeight: 48, px: 2.5 }}>
              <ListItemIcon sx={{ minWidth: 36 }}>
                <Checkbox
                  edge="start"
                  checked={step.done}
                  tabIndex={-1}
                  disableRipple
                  icon={<RadioButtonUncheckedRoundedIcon />}
                  checkedIcon={<CheckCircleRoundedIcon color="success" />}
                  slotProps={{ input: { "aria-label": step.label } }}
                />
              </ListItemIcon>
              <ListItemText
                primary={step.optional ? `${step.label} (${CHECKLIST_COPY.optional[language]})` : step.label}
                slotProps={{ primary: { sx: { textDecoration: step.done ? "line-through" : undefined, color: step.done ? "text.secondary" : undefined } } }}
              />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </Card>
  );
}
