import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Chip,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  Typography
} from "@mui/material";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import { translate, type Language, type MessageKey } from "./i18n";
import { formatNumber } from "./format";

/**
 * Global Simple / Advanced display mode.
 *
 * - Simple (default) keeps everyday, safe controls visible; expert and dangerous
 *   controls live in a collapsed <AdvancedSection> or are hidden with <AdvancedOnly>.
 * - Advanced shows everything and expands every <AdvancedSection>.
 * The mode is a presentation preference only: RBAC gating and confirmations apply in both modes.
 */
export type UiMode = "simple" | "advanced";

type UiPrefs = {
  mode: UiMode;
  setMode: (mode: UiMode) => void;
  language: Language;
  t: (key: MessageKey) => string;
};

const UiPrefsContext = createContext<UiPrefs>({
  mode: "simple",
  setMode: () => undefined,
  language: "fa",
  t: (key) => translate("fa", key)
});

function storageKey(userId: number) {
  return `mrk-ui-mode:${userId}`;
}

function readMode(userId: number): UiMode {
  try {
    return window.localStorage.getItem(storageKey(userId)) === "advanced" ? "advanced" : "simple";
  } catch {
    return "simple";
  }
}

export function UiModeProvider({ userId, language, children }: { userId: number; language: Language; children: ReactNode }) {
  const [mode, setModeState] = useState<UiMode>(() => readMode(userId));

  // A different signed-in user gets their own stored preference.
  useEffect(() => setModeState(readMode(userId)), [userId]);

  const setMode = useCallback(
    (next: UiMode) => {
      setModeState(next);
      try {
        window.localStorage.setItem(storageKey(userId), next);
      } catch {
        // storage may be unavailable (private mode, blocked site data)
      }
    },
    [userId]
  );

  const value = useMemo<UiPrefs>(
    () => ({ mode, setMode, language, t: (key: MessageKey) => translate(language, key) }),
    [language, mode, setMode]
  );
  return <UiPrefsContext.Provider value={value}>{children}</UiPrefsContext.Provider>;
}

export function useUiMode() {
  return useContext(UiPrefsContext);
}

/** Render children only in Advanced mode (for small inline items such as extra columns or buttons). */
export function AdvancedOnly({ children }: { children: ReactNode }) {
  const { mode } = useUiMode();
  return mode === "advanced" ? <>{children}</> : null;
}

/** Top-bar switch between Simple and Advanced mode. */
export function UiModeToggle() {
  const { mode, setMode, t } = useUiMode();
  return (
    <ToggleButtonGroup
      size="small"
      exclusive
      value={mode}
      aria-label={t("uiMode")}
      onChange={(_event, value: UiMode | null) => {
        if (value) setMode(value);
      }}
      sx={{ "& .MuiToggleButton-root": { px: 1.25, py: 0.4, textTransform: "none", fontWeight: 650 } }}
    >
      <ToggleButton value="simple">{t("simpleMode")}</ToggleButton>
      <ToggleButton value="advanced">{t("advancedMode")}</ToggleButton>
    </ToggleButtonGroup>
  );
}

type AdvancedSectionProps = {
  /** Optional sub-title shown after "Advanced options". */
  title?: string;
  /** Number of advanced items, shown as a chip. */
  count?: number;
  children: ReactNode;
};

function AdvancedSectionInner({ title, count, children, initiallyExpanded }: AdvancedSectionProps & { initiallyExpanded: boolean }) {
  const { t, language } = useUiMode();
  const [expanded, setExpanded] = useState(initiallyExpanded);
  return (
    <Accordion
      expanded={expanded}
      onChange={(_event, value) => setExpanded(value)}
      disableGutters
      variant="outlined"
      slotProps={{ transition: { unmountOnExit: true } }}
      sx={{ borderRadius: 1.25, "&::before": { display: "none" }, bgcolor: "transparent" }}
    >
      <AccordionSummary expandIcon={<ExpandMoreRoundedIcon />} sx={{ px: 2.5 }}>
        <Stack direction="row" spacing={1.2} alignItems="center" sx={{ minWidth: 0 }}>
          <TuneRoundedIcon color="action" fontSize="small" />
          <Typography fontWeight={760}>{t("advancedOptions")}{title ? ` · ${title}` : ""}</Typography>
          {count !== undefined && <Chip size="small" variant="outlined" label={formatNumber(count, language)} />}
        </Stack>
      </AccordionSummary>
      <AccordionDetails sx={{ px: { xs: 1.5, sm: 2.5 }, pb: 2.5 }}>
        <Stack spacing={2.5}>{children}</Stack>
      </AccordionDetails>
    </Accordion>
  );
}

/**
 * Collapsible container for a panel's expert controls: collapsed in Simple mode,
 * expanded in Advanced mode. Content is unmounted while collapsed.
 */
export function AdvancedSection(props: AdvancedSectionProps) {
  const { mode } = useUiMode();
  // Re-mount on mode change so the expanded state follows the global switch.
  return <AdvancedSectionInner key={mode} {...props} initiallyExpanded={mode === "advanced"} />;
}
