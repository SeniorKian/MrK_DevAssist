import type { ReactNode } from "react";
import { Box, Stack, Typography, useMediaQuery, useTheme } from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";

export type PageHeaderProps = {
  title: string;
  /** One short sentence: what can I do here? */
  subtitle?: string;
  icon?: SvgIconComponent;
  /** The ONE primary verb of the page (a contained Button). On phones it becomes a full-width sticky bottom button. */
  primaryAction?: ReactNode;
  /** Secondary actions (text/outlined buttons, refresh, ⋮ menu). */
  secondaryActions?: ReactNode;
  /** Usually <GroupTabs/>, rendered under the title. */
  tabs?: ReactNode;
  /** Heading level for the title (default h1: one per page). */
  level?: "h1" | "h2";
};

/** Page title + one primary action. Sticky and compact on phones. */
export function PageHeader({ title, subtitle, icon: Icon, primaryAction, secondaryActions, tabs, level = "h1" }: PageHeaderProps) {
  const theme = useTheme();
  const isXs = useMediaQuery(theme.breakpoints.down("sm"));
  return (
    <Box
      component="header"
      sx={{
        position: isXs ? "sticky" : "static",
        top: isXs ? 0 : undefined,
        zIndex: isXs ? theme.zIndex.appBar - 1 : undefined,
        bgcolor: isXs ? "background.default" : "transparent",
        pt: isXs ? 1 : 0,
        mb: 2.5
      }}
    >
      <Stack direction="row" alignItems="center" spacing={1.5} sx={{ minWidth: 0 }}>
        {Icon && (
          <Box
            aria-hidden
            sx={{ display: { xs: "none", sm: "grid" }, placeItems: "center", width: 44, height: 44, borderRadius: 2, bgcolor: "action.hover", color: "primary.main", flexShrink: 0 }}
          >
            <Icon />
          </Box>
        )}
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Typography component={level} variant={isXs ? "h6" : "h5"} sx={{ fontWeight: 780, lineHeight: 1.35 }}>
            {title}
          </Typography>
          {subtitle && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.25, lineHeight: 1.8 }}>
              {subtitle}
            </Typography>
          )}
        </Box>
        {(secondaryActions || (!isXs && primaryAction)) && (
          <Stack direction="row" spacing={1} alignItems="center" sx={{ flexShrink: 0 }}>
            {secondaryActions}
            {!isXs && primaryAction}
          </Stack>
        )}
      </Stack>
      {tabs && <Box sx={{ mt: 1.5 }}>{tabs}</Box>}
      {isXs && primaryAction && (
        <Box
          sx={{
            position: "fixed",
            left: 0,
            right: 0,
            bottom: "calc(env(safe-area-inset-bottom, 0px) + var(--mrk-bottom-nav-height, 0px))",
            p: 1.5,
            zIndex: theme.zIndex.appBar,
            bgcolor: "background.paper",
            borderTop: "1px solid",
            borderColor: "divider",
            "& > *": { width: "100%", minHeight: 48 }
          }}
        >
          {primaryAction}
        </Box>
      )}
    </Box>
  );
}
