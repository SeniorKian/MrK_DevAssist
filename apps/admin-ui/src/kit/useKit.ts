import { useMemo } from "react";
import { useUiMode } from "../uiMode";
import { commonWords } from "../copy/common";

/**
 * Everything a kit component (or a page) needs about the viewer's preferences:
 * language, text direction, Simple/Advanced mode and the shared generic words.
 */
export function useKit() {
  const { language, mode, setMode } = useUiMode();
  return useMemo(
    () => ({
      language,
      mode,
      setMode,
      isAdvanced: mode === "advanced",
      isFa: language === "fa",
      dir: (language === "fa" ? "rtl" : "ltr") as "rtl" | "ltr",
      c: commonWords(language)
    }),
    [language, mode, setMode]
  );
}
