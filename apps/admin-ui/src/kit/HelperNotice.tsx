/**
 * The shared "server helper not connected / not answering / part missing" notice.
 *
 * Pages that talk to the server helper (Agent) or an optional module get the same three states:
 *   - `not_paired`     – `agent_not_configured`, or a bare 409: «دستیار سرور هنوز وصل نشده.» + «وصل کردن»
 *   - `helper_down`    – `agent_unreachable` / `agent_unavailable`, or a bare 502–504
 *   - `module_missing` – a bare 404 (the route doesn't exist on this server version)
 * Any other error (a specific backend code) returns null / falls through to FriendlyError.
 *
 *   const problem = helperProblem(error);           // for branching (e.g. stop polling)
 *   helperProblemText(language, error)              // sentence or null (toasts, inline)
 *   <HelperNotice error={error} onRetry={load} />   // Notice with one action, else FriendlyError
 */
import { Button } from "@mui/material";
import { ApiError } from "../api";
import type { Language } from "../i18n";
import { pick, type Bi } from "../copy/text";
import { FriendlyError } from "./FriendlyError";
import { Notice } from "./Feedback";
import { useKit } from "./useKit";

export type HelperProblem = "not_paired" | "helper_down" | "module_missing";

/** Where «وصل کردن دستیار سرور» goes (docs/34 §1 `agent_not_paired`). */
export const PAIR_AGENT_HREF = "#/server/overview?connect=agent";

const GENERIC_CODES = new Set(["", "http_error", "not_found"]);

const COPY = {
  not_paired: { fa: "دستیار سرور هنوز وصل نشده.", en: "The server helper isn't connected yet." },
  helper_down: { fa: "دستیار سرور جواب نمی‌دهد. مطمئن شوید روی سرور روشن است.", en: "The server helper isn't answering. Make sure it's running on the server." },
  module_missing: { fa: "این بخش روی نسخه فعلی سرور نیست. پیشکار را به‌روز کنید.", en: "This isn't on your server's current version. Update Pishkar." },
  pair: { fa: "وصل کردن دستیار سرور", en: "Connect the server helper" },
  refresh: { fa: "تازه کردن", en: "Refresh" }
} satisfies Record<string, Bi>;

/** Classify an error as one of the three helper/module states, or null for anything else. */
export function helperProblem(error: unknown): HelperProblem | null {
  if (!(error instanceof ApiError)) return null;
  if (error.code === "agent_not_configured") return "not_paired";
  if (error.code === "agent_unreachable" || error.code === "agent_unavailable") return "helper_down";
  if (!GENERIC_CODES.has(error.code)) return null;
  if (error.status === 404) return "module_missing";
  if (error.status === 409) return "not_paired";
  if (error.status === 502 || error.status === 503 || error.status === 504) return "helper_down";
  return null;
}

/** The sentence for a known state. */
export function helperSentence(language: Language, problem: HelperProblem): string {
  return pick(language, COPY[problem]);
}

/** One plain sentence for the helper/module state, or null (let FriendlyError / errorSentence explain). */
export function helperProblemText(language: Language, error: unknown, overrides?: Partial<Record<HelperProblem, Bi>>): string | null {
  const problem = helperProblem(error);
  if (!problem) return null;
  return pick(language, overrides?.[problem] ?? COPY[problem]);
}

export type HelperNoticeProps = {
  error: unknown;
  onRetry?: () => void;
  /** Hide the «وصل کردن» button (e.g. on the pairing page itself). */
  noPairAction?: boolean;
  /** Page-specific wording for a state. */
  overrides?: Partial<Record<HelperProblem, Bi>>;
  /** Passed to FriendlyError for every other error. */
  onClose?: () => void;
};

export function HelperNotice({ error, onRetry, noPairAction, overrides, onClose }: HelperNoticeProps) {
  const { language } = useKit();
  const problem = helperProblem(error);
  if (!problem) return <FriendlyError error={error} onRetry={onRetry} onClose={onClose} />;
  const action =
    problem === "not_paired" && !noPairAction ? (
      <Button color="inherit" size="small" href={PAIR_AGENT_HREF} sx={{ minHeight: 40 }}>{pick(language, COPY.pair)}</Button>
    ) : onRetry ? (
      <Button color="inherit" size="small" onClick={onRetry} sx={{ minHeight: 40 }}>{pick(language, COPY.refresh)}</Button>
    ) : undefined;
  return (
    <Notice tone={problem === "module_missing" ? "info" : "warning"} action={action}>
      {pick(language, overrides?.[problem] ?? COPY[problem])}
    </Notice>
  );
}
