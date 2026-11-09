/**
 * Typed confirmations that work on any keyboard (docs/33 §2.7).
 *
 * The user types a Persian word («پاک کن») or the object's own name; the page sends the backend
 * token (`PRUNE`, `DISCONNECT`, …) behind the scenes. In en mode the English token is asked for,
 * and it is also accepted in fa mode for people who already know it.
 *
 *   const word = CONFIRM_WORDS.prune;
 *   <ConfirmAction typed={{ word }} … onConfirm={() => api({ confirm: word.token })} />
 *   matchesConfirmation(typed, word, language)  → boolean
 */
import type { Language } from "../i18n";
import { normalizeTyped, type Bi } from "./text";

export type ConfirmWord = {
  /** What the user is asked to type, per language. */
  word: Bi;
  /** The token the backend expects. */
  token: string;
};

export const CONFIRM_WORDS = {
  /** Docker clean-up of unused items. */
  prune: { word: { fa: "پاک کن", en: "PRUNE" }, token: "PRUNE" },
  /** Disconnect Dokploy / the server helper. */
  disconnect: { word: { fa: "قطع کن", en: "DISCONNECT" }, token: "DISCONNECT" },
  /** Firewall: switch from practice mode to active mode. */
  enforce: { word: { fa: "فعال کن", en: "ENFORCE" }, token: "ENFORCE" },
  /** Firewall: release every blocked address. */
  unblockAll: { word: { fa: "همه را آزاد کن", en: "UNBLOCK ALL" }, token: "UNBLOCK ALL" },
  /** Unpair the firewall helper. */
  unpair: { word: { fa: "جدا کن", en: "UNPAIR" }, token: "UNPAIR" },
  /** Offline restore: the operator confirms DevAssist is stopped. */
  stoppedMrk: { word: { fa: "سرویس را خاموش کردم", en: "I_HAVE_STOPPED_MRK" }, token: "I_HAVE_STOPPED_MRK" },
  /** DNS: delete the question log (all of it, or everything before a time). */
  deleteLogs: { word: { fa: "پاک کن", en: "DELETE LOGS" }, token: "DELETE LOGS" },
  /** DNS: replace every DNS setting with a backup file (docs/41 §4). */
  restoreDns: { word: { fa: "بازگردانی کن", en: "RESTORE" }, token: "RESTORE" },
  /** Generic "I understand" confirmation for client-side-only checks. */
  confirm: { word: { fa: "تأیید", en: "CONFIRM" }, token: "CONFIRM" }
} satisfies Record<string, ConfirmWord>;

/** Tokens built from an id or name (the user types the Persian word; the page sends the token). */
export const CONFIRM_TOKENS = {
  /** Package purge: `PURGE npm/react`. */
  purge: (ecosystem: string, name: string) => `PURGE ${ecosystem}/${name}`,
  /** Permanent delete from the recycle bin: `DELETE <trash id>`. */
  trashDelete: (trashId: string | number) => `DELETE ${trashId}`,
  /** Apply a restore plan: `APPLY <backup id>` (the backend also returns it as `apply_confirmation`). */
  applyRestore: (backupId: string) => `APPLY ${backupId}`
};

/** Persian word + token pair for a destructive action whose token is computed. */
export function deleteConfirmation(token: string): ConfirmWord {
  return { word: { fa: "پاک کن", en: token }, token };
}

export type ConfirmWordKey = keyof typeof CONFIRM_WORDS;

/**
 * A confirmation whose typed text is an object's own name (bucket, connection, package).
 * The backend token is built from it, e.g. `PURGE pypi/requests`.
 */
export function nameConfirmation(name: string, token: string): ConfirmWord {
  return { word: { fa: name, en: name }, token };
}

/** The word to show in the dialog for this language. */
export function confirmPrompt(word: ConfirmWord, language: Language): string {
  return word.word[language];
}

/** True when `typed` matches the localized word, the English word, or the backend token (forgiving spacing, ي/ی, digits). */
export function matchesConfirmation(typed: string, word: ConfirmWord, language: Language): boolean {
  const value = normalizeTyped(typed);
  if (!value) return false;
  const accepted = [word.word[language], word.word.en, word.token];
  return accepted.some((candidate) => normalizeTyped(candidate) === value);
}

export const CONFIRM_COPY = {
  typeToConfirm: { fa: "برای اطمینان، «{word}» را بنویسید:", en: "To be sure, type {word}:" },
  mismatch: { fa: "هنوز با «{word}» یکی نیست.", en: "That doesn't match {word} yet." },
  cannotUndo: { fa: "این کار برگشت‌پذیر نیست.", en: "This can't be undone." },
  canUndo: { fa: "بعداً می‌توانید آن را برگردانید.", en: "You can undo this later." },
  yesDelete: { fa: "بله، پاک کن", en: "Yes, delete" },
  keepIt: { fa: "نه، بماند", en: "No, keep it" },
  yesContinue: { fa: "بله، ادامه بده", en: "Yes, continue" },
  notNow: { fa: "نه، فعلاً نه", en: "Not now" },
  whatHappens: { fa: "چه اتفاقی می‌افتد:", en: "What will happen:" }
} satisfies Record<string, Bi>;
