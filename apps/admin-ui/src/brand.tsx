import { useId } from "react";

/**
 * Pishkar mark: a key shaped like the letter P, with the three dots of the
 * Persian «پ» below it — the steward who holds the keys of the house.
 * Same drawing as public/favicon.svg.
 */
export function PishkarMark({ size = 40, title }: { size?: number; title?: string }) {
  const gradient = `pk-bg-${useId().replace(/:/g, "")}`;
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
      <g fill="none" stroke="#042f2e" strokeWidth="5.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M24 49 V14 H33 a9.5 9.5 0 0 1 0 19 H24" />
        <path d="M24 41.5 H30" />
        <path d="M24 49 H29" />
      </g>
      <g fill="#042f2e">
        <circle cx="38.5" cy="42.5" r="2.7" />
        <circle cx="45.5" cy="42.5" r="2.7" />
        <circle cx="42" cy="48.8" r="2.7" />
      </g>
    </svg>
  );
}
