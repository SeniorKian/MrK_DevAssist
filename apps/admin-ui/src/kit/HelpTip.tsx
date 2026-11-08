import { useId, useState, type MouseEvent, type ReactNode } from "react";
import { Box, IconButton, Link, Popover, Stack, Typography } from "@mui/material";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import { GLOSSARY, termHint, type GlossaryEntry, type GlossaryKey } from "../copy/glossary";
import { useKit } from "./useKit";

export type HelpTipProps = {
  /** The explanation (plain words). Or pass `term` to use the glossary hint. */
  children?: ReactNode;
  term?: GlossaryKey;
  /** Accessible name of the (i) button; defaults to «راهنما». */
  label?: string;
  learnMoreHref?: string;
};

/** A small (i) button that opens a plain explanation. Keyboard and screen-reader friendly. */
export function HelpTip({ children, term: termKey, label, learnMoreHref }: HelpTipProps) {
  const { language, c, isAdvanced } = useKit();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const id = useId();
  const entry: GlossaryEntry | undefined = termKey ? GLOSSARY[termKey] : undefined;
  const content = children ?? (termKey ? termHint(language, termKey) : null);
  if (!content) return null;
  return (
    <>
      <IconButton
        size="small"
        aria-label={label ?? c.help}
        aria-describedby={anchor ? id : undefined}
        aria-haspopup="dialog"
        onClick={(event: MouseEvent<HTMLElement>) => setAnchor(event.currentTarget)}
        sx={{ p: 0.25, color: "text.secondary", verticalAlign: "middle" }}
      >
        <InfoOutlinedIcon sx={{ fontSize: 18 }} />
      </IconButton>
      <Popover
        id={id}
        open={Boolean(anchor)}
        anchorEl={anchor}
        onClose={() => setAnchor(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
        transformOrigin={{ vertical: "top", horizontal: "center" }}
        slotProps={{ paper: { sx: { p: 1.75, maxWidth: 320 }, role: "dialog" } }}
      >
        <Stack spacing={0.75}>
          {entry && (
            <Typography variant="subtitle2" sx={{ fontWeight: 750 }}>
              {entry.word[language]}
              {(isAdvanced || entry.english === "first") && language === "fa" && entry.english !== "never" && (
                <Box component="bdi" dir="ltr" sx={{ color: "text.secondary", fontWeight: 500 }}>{` ${entry.term}`}</Box>
              )}
            </Typography>
          )}
          <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{content}</Typography>
          {learnMoreHref && (
            <Link href={learnMoreHref} target="_blank" rel="noreferrer" variant="body2">{c.learnMore}</Link>
          )}
        </Stack>
      </Popover>
    </>
  );
}

export type TermProps = {
  k: GlossaryKey;
  /** First use on this page: append the English term in parentheses (fa only, when allowed). */
  first?: boolean;
  /** Show an (i) with the glossary hint. */
  withHelp?: boolean;
};

/** Render a glossary word consistently: <Term k="upstream" first /> → «منبع دریافت (upstream)». */
export function Term({ k, first, withHelp }: TermProps) {
  const { language, isAdvanced } = useKit();
  const entry: GlossaryEntry = GLOSSARY[k];
  const showEnglish = language === "fa" && ((first && entry.english === "first") || (isAdvanced && entry.english === "advanced"));
  return (
    <Box component="span" sx={{ whiteSpace: "normal" }}>
      {entry.word[language]}
      {showEnglish && (
        <>
          {" ("}
          <bdi dir="ltr">{entry.term}</bdi>
          {")"}
        </>
      )}
      {withHelp && entry.hint && <HelpTip term={k} />}
    </Box>
  );
}
