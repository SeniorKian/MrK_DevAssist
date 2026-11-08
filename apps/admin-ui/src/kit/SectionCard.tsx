import { useId, useState, type ReactNode } from "react";
import { Box, Card, CardContent, Collapse, IconButton, Stack, Typography } from "@mui/material";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import { useKit } from "./useKit";

export type SectionCardProps = {
  title?: string;
  /** One sentence under the title. */
  hint?: string;
  /** Small action(s) on the title row: a button, a switch, a ⋮ menu. */
  action?: ReactNode;
  /** A <StatusPill/> next to the title. */
  status?: ReactNode;
  children?: ReactNode;
  /** Let the user fold the card. */
  collapsible?: boolean;
  defaultCollapsed?: boolean;
  /** Render only in Advanced mode. */
  advanced?: boolean;
  /** Remove inner padding (for full-bleed lists/tables). */
  flush?: boolean;
  /** Tone of the left/right accent border. */
  tone?: "default" | "danger" | "warning";
};

/** The standard content block of a page. Replaces ad-hoc Card + CardContent + title rows. */
export function SectionCard({ title, hint, action, status, children, collapsible, defaultCollapsed, advanced, flush, tone = "default" }: SectionCardProps) {
  const { isAdvanced, c } = useKit();
  const [collapsed, setCollapsed] = useState(Boolean(defaultCollapsed));
  const headingId = useId();
  const bodyId = useId();
  if (advanced && !isAdvanced) return null;
  const accent = tone === "danger" ? "error.main" : tone === "warning" ? "warning.main" : undefined;
  return (
    <Card
      component="section"
      aria-labelledby={title ? headingId : undefined}
      sx={accent ? { borderLeftWidth: 4, borderLeftStyle: "solid", borderLeftColor: accent } : undefined}
    >
      {(title || action || status) && (
        <Stack direction="row" alignItems="flex-start" spacing={1.5} sx={{ px: { xs: 2, sm: 2.5 }, pt: 2, pb: collapsed ? 2 : flush ? 1.5 : 0 }}>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Stack direction="row" alignItems="center" spacing={1} sx={{ flexWrap: "wrap", rowGap: 0.5 }}>
              {title && (
                <Typography id={headingId} component="h2" variant="subtitle1" sx={{ fontWeight: 760, lineHeight: 1.5 }}>
                  {title}
                </Typography>
              )}
              {status}
            </Stack>
            {hint && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.25, lineHeight: 1.8 }}>
                {hint}
              </Typography>
            )}
          </Box>
          {action && <Box sx={{ flexShrink: 0 }}>{action}</Box>}
          {collapsible && (
            <IconButton
              size="small"
              onClick={() => setCollapsed((value) => !value)}
              aria-expanded={!collapsed}
              aria-controls={bodyId}
              aria-label={collapsed ? c.show : c.hide}
              sx={{ transform: collapsed ? "none" : "rotate(180deg)", transition: "transform .2s" }}
            >
              <ExpandMoreRoundedIcon />
            </IconButton>
          )}
        </Stack>
      )}
      <Collapse in={!collapsed} unmountOnExit id={bodyId}>
        {flush ? (
          <Box>{children}</Box>
        ) : (
          <CardContent sx={{ px: { xs: 2, sm: 2.5 }, pt: title ? 1.5 : 2, "&:last-child": { pb: 2.5 } }}>
            <Stack spacing={2}>{children}</Stack>
          </CardContent>
        )}
      </Collapse>
    </Card>
  );
}
