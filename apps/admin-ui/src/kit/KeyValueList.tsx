import type { ReactNode } from "react";
import { Box, Typography } from "@mui/material";
import { CopyButton } from "./CopyField";
import { useKit } from "./useKit";

export type KeyValueItem = {
  label: string;
  value: ReactNode;
  /** Technical value (path, URL, id): shown LTR in monospace. */
  ltr?: boolean;
  /** Show a copy button; pass the text to copy (defaults to `value` when it is a string). */
  copy?: boolean | string;
  /** Only in Advanced mode. */
  advancedOnly?: boolean;
  /** Small muted line under the value. */
  hint?: string;
};

/** Label/value rows. Two columns on wide screens, stacked on phones. */
export function KeyValueList({ items, dense }: { items: KeyValueItem[]; dense?: boolean }) {
  const { isAdvanced } = useKit();
  const visible = items.filter((item) => !item.advancedOnly || isAdvanced);
  return (
    <Box component="dl" sx={{ m: 0, display: "grid", gridTemplateColumns: { xs: "1fr", sm: "minmax(140px, 34%) 1fr" }, columnGap: 2, rowGap: dense ? 0.75 : 1.25 }}>
      {visible.map((item) => {
        const copyValue = typeof item.copy === "string" ? item.copy : item.copy && typeof item.value === "string" ? item.value : null;
        return (
          <Box key={item.label} sx={{ display: "contents" }}>
            <Typography component="dt" variant="body2" color="text.secondary" sx={{ pt: { sm: 0.25 } }}>{item.label}</Typography>
            <Box component="dd" sx={{ m: 0, minWidth: 0, display: "flex", alignItems: "center", gap: 0.5, mb: { xs: 0.75, sm: 0 } }}>
              <Box sx={{ minWidth: 0 }}>
                <Typography
                  component="div"
                  variant="body2"
                  dir={item.ltr ? "ltr" : undefined}
                  sx={{
                    fontWeight: 600,
                    overflowWrap: "anywhere",
                    fontFamily: item.ltr ? "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" : undefined,
                    fontSize: item.ltr ? "0.85rem" : undefined,
                    textAlign: item.ltr ? "start" : undefined
                  }}
                >
                  {item.value}
                </Typography>
                {item.hint && <Typography variant="caption" color="text.secondary">{item.hint}</Typography>}
              </Box>
              {copyValue && <CopyButton value={copyValue} />}
            </Box>
          </Box>
        );
      })}
    </Box>
  );
}
