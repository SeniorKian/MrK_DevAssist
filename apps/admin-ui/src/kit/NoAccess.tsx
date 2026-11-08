import type { ReactNode } from "react";
import { Alert, Box, Typography } from "@mui/material";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import { hasPermission } from "../api";
import { noAccessSentence } from "../copy/roles";
import { useKit } from "./useKit";

export type NoAccessProps = {
  /** The permission(s) that would allow the action; the sentence names the lowest role that has one. */
  needs: string | readonly string[];
  /** Who to ask, e.g. the owner's display name. */
  ask?: string | null;
  /** "inline" = one muted line under a disabled control; "card" = a calm block. */
  variant?: "inline" | "card";
};

/** «این کار از «مدیر» به بالا برمی‌آید.» Never shows permission ids. */
export function NoAccess({ needs, ask, variant = "inline" }: NoAccessProps) {
  const { language } = useKit();
  const text = noAccessSentence(language, needs, ask);
  if (variant === "card") {
    return (
      <Alert severity="info" icon={<LockRoundedIcon fontSize="inherit" />}>
        {text}
      </Alert>
    );
  }
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, color: "text.secondary" }}>
      <LockRoundedIcon sx={{ fontSize: 16 }} aria-hidden />
      <Typography variant="caption">{text}</Typography>
    </Box>
  );
}

export type PermissionGateProps = {
  /** The signed-in user's permissions (from AuthUser.permissions). */
  permissions: readonly string[];
  /** Visible when the user holds any of these. */
  anyOf: readonly string[];
  children: ReactNode;
  /** What to render otherwise; defaults to nothing. Pass `true` for the standard <NoAccess/>. */
  fallback?: ReactNode | true;
  ask?: string | null;
};

/** Show children only to people whose role allows it. RBAC still lives on the server; this is presentation. */
export function PermissionGate({ permissions, anyOf, children, fallback, ask }: PermissionGateProps) {
  const allowed = anyOf.length === 0 || anyOf.some((permission) => hasPermission(permissions, permission));
  if (allowed) return <>{children}</>;
  if (fallback === true) return <NoAccess needs={anyOf} ask={ask} />;
  return <>{fallback ?? null}</>;
}

/** Hook form: `const can = useCan(user.permissions); can("cache:write")`. */
export function useCan(permissions: readonly string[]) {
  return (permission: string) => hasPermission(permissions, permission);
}
