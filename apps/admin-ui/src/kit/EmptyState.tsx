import type { ReactNode } from "react";
import { Box, Stack, Typography } from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import InboxRoundedIcon from "@mui/icons-material/InboxRounded";

export type EmptyStateProps = {
  icon?: SvgIconComponent;
  /** «هنوز … ندارید» */
  title: string;
  /** One sentence on why it helps. */
  body?: string;
  /** The primary button that fixes the emptiness. */
  action?: ReactNode;
  /** Smaller padding for use inside cards and lists. */
  compact?: boolean;
};

/** Empty list / no results. Never just «داده‌ای یافت نشد» — say what to do (docs/33 §2.6). */
export function EmptyState({ icon: Icon = InboxRoundedIcon, title, body, action, compact }: EmptyStateProps) {
  return (
    <Stack alignItems="center" textAlign="center" spacing={1.25} sx={{ py: compact ? 3 : 6, px: 2 }}>
      <Box aria-hidden sx={{ display: "grid", placeItems: "center", width: compact ? 48 : 64, height: compact ? 48 : 64, borderRadius: "50%", bgcolor: "action.hover", color: "text.secondary" }}>
        <Icon fontSize={compact ? "medium" : "large"} />
      </Box>
      <Typography component="p" variant="subtitle1" sx={{ fontWeight: 720 }}>{title}</Typography>
      {body && <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 460, lineHeight: 1.9 }}>{body}</Typography>}
      {action && <Box sx={{ pt: 0.5 }}>{action}</Box>}
    </Stack>
  );
}
