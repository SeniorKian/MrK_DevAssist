import type { ReactNode } from "react";
import { Box, Divider, Stack, Typography } from "@mui/material";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import { SectionCard } from "./SectionCard";
import { useKit } from "./useKit";

export type DangerAction = {
  title: string;
  /** What happens, whether it can be undone, and who is affected. */
  description: string;
  /** A red outlined Button that opens a ConfirmAction. */
  action: ReactNode;
};

export type DangerZoneProps = {
  /** Defaults to «منطقه خطر». */
  title?: string;
  hint?: string;
  items: DangerAction[];
  /** Danger zones are Advanced-only by default (docs/33 §4.1). */
  simpleToo?: boolean;
};

/** Grouped destructive actions in a red-accented card. Buttons are never the default focus. */
export function DangerZone({ title, hint, items, simpleToo }: DangerZoneProps) {
  const { c } = useKit();
  if (items.length === 0) return null;
  return (
    <SectionCard
      title={title ?? c.dangerZone}
      hint={hint}
      tone="danger"
      advanced={!simpleToo}
      status={<WarningAmberRoundedIcon color="error" fontSize="small" aria-hidden />}
    >
      <Stack divider={<Divider flexItem />} spacing={1.5}>
        {items.map((item) => (
          <Stack key={item.title} direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ xs: "stretch", sm: "center" }}>
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography variant="body1" sx={{ fontWeight: 700 }}>{item.title}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>{item.description}</Typography>
            </Box>
            <Box sx={{ flexShrink: 0 }}>{item.action}</Box>
          </Stack>
        ))}
      </Stack>
    </SectionCard>
  );
}
