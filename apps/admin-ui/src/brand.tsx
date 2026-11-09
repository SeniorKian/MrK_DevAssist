import { useId } from "react";
import { Box } from "@mui/material";

/**
 * DevAssist mark: a D with an A inside (DevAssist), in the panel's teal gradient.
 * Same drawing as public/favicon.svg.
 */
export function DevAssistMark({ size = 40, title }: { size?: number; title?: string }) {
  const gradient = `da-bg-${useId().replace(/:/g, "")}`;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      role={title ? "img" : undefined}
      aria-label={title}
      aria-hidden={title ? undefined : true}
      style={{ display: "block", flexShrink: 0 }}
    >
      <defs>
        <linearGradient id={gradient} x1="6" y1="2" x2="60" y2="62" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#99f6e4" />
          <stop offset="0.5" stopColor="#5eead4" />
          <stop offset="1" stopColor="#38bdf8" />
        </linearGradient>
      </defs>
      <rect x="2" y="2" width="60" height="60" rx="16" fill={`url(#${gradient})`} />
      <path d="M17 14 H29 a18 18 0 0 1 0 36 H17 Z" fill="none" stroke="#042f2e" strokeWidth="5.5" strokeLinejoin="round" />
      <path d="M25 41 L32 24 L39 41" fill="none" stroke="#042f2e" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M27.8 35 H36.2" stroke="#042f2e" strokeWidth="4" strokeLinecap="round" />
    </svg>
  );
}

/** Maker signature shown before the product name: exactly "MrK". */
export const MAKER = "MrK";

/** "MrK DevAssist": the maker signature (small, muted) before the product name, always left-to-right. */
export function ProductName({ name }: { name: string }) {
  return (
    <Box component="span" dir="ltr" sx={{ unicodeBidi: "isolate", whiteSpace: "nowrap" }}>
      <Box component="span" sx={{ fontSize: "0.72em", fontWeight: 650, color: "text.secondary", letterSpacing: "0.02em" }}>
        {MAKER}
      </Box>
      {" "}
      {name}
    </Box>
  );
}
