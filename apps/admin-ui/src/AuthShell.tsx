import { useState, type ReactNode } from "react";
import { Box, Button, IconButton, InputAdornment, Stack, TextField, Typography, type TextFieldProps } from "@mui/material";
import HubRoundedIcon from "@mui/icons-material/HubRounded";
import SecurityRoundedIcon from "@mui/icons-material/SecurityRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import VisibilityOffRoundedIcon from "@mui/icons-material/VisibilityOffRounded";
import type { Language } from "./i18n";
import { translate } from "./i18n";
import { errorEntry } from "./copy/errors";
import { fill, type Bi } from "./copy/text";

// ── Password policy (server-driven, docs/34 §2: GET /api/v1/auth/setup-status) ─────────────────

export type PasswordPolicy = { min_length: number; require_letters: boolean; require_digits: boolean };

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = { min_length: 6, require_letters: true, require_digits: true };

/** Read `password_policy` from any payload, falling back to the documented default. */
export function readPasswordPolicy(payload: unknown): PasswordPolicy {
  const raw = (payload as { password_policy?: Partial<PasswordPolicy> } | null)?.password_policy;
  if (!raw || typeof raw !== "object") return DEFAULT_PASSWORD_POLICY;
  return {
    min_length: typeof raw.min_length === "number" && raw.min_length > 0 ? raw.min_length : DEFAULT_PASSWORD_POLICY.min_length,
    require_letters: raw.require_letters !== false,
    require_digits: raw.require_digits !== false
  };
}

/** «دست‌کم ۸ نویسه، با حرف و عدد» built from the server's rule. */
export function passwordRuleText(language: Language, policy: PasswordPolicy): string {
  const parts: Bi =
    policy.require_letters && policy.require_digits
      ? { fa: "دست‌کم {n} نویسه، با حرف و عدد.", en: "At least {n} characters, with letters and numbers." }
      : policy.require_letters
        ? { fa: "دست‌کم {n} نویسه، با دست‌کم یک حرف.", en: "At least {n} characters, with at least one letter." }
        : policy.require_digits
          ? { fa: "دست‌کم {n} نویسه، با دست‌کم یک عدد.", en: "At least {n} characters, with at least one number." }
          : { fa: "دست‌کم {n} نویسه.", en: "At least {n} characters." };
  return fill(parts[language], { n: policy.min_length }, language);
}

/** Check a password in the browser with the same rule; returns the sentence to show, or null. */
export function passwordProblem(language: Language, policy: PasswordPolicy, password: string): string | null {
  if (password.length < policy.min_length) return fieldReasonText(language, "too_short", { min_length: policy.min_length }, "password");
  if (password.length > 256) return fieldReasonText(language, "too_long", { max_length: 256 }, "password");
  if (policy.require_letters && !/\p{L}/u.test(password)) return fieldReasonText(language, "missing_letter", {}, "password");
  if (policy.require_digits && !/\p{Nd}/u.test(password)) return fieldReasonText(language, "missing_digit", {}, "password");
  return null;
}

// ── Field-level errors (docs/34 §2: error.fields[{field, reason_code, params}]) ────────────────

export type FieldIssue = { field: string; reason_code: string; params?: Record<string, unknown> };
export type AuthFailure = { status: number; code: string; fields: FieldIssue[] };

const IS_PASSWORD = /password/;

/** One sentence for a field problem, naming the rule instead of saying "invalid". */
export function fieldReasonText(language: Language, reason: string, params: Record<string, unknown> = {}, field = ""): string {
  const n = (key: string) => (typeof params[key] === "number" ? (params[key] as number) : null);
  const isPassword = IS_PASSWORD.test(field);
  const isName = field === "display_name" || field === "name";
  const isEmail = field === "email";
  const text: Bi = (() => {
    switch (reason) {
      case "required":
        return { fa: "این خانه را پر کنید.", en: "Please fill this in." };
      case "too_short":
        return isPassword
          ? { fa: "رمز باید دست‌کم {min} نویسه باشد.", en: "The password needs at least {min} characters." }
          : isName
            ? { fa: "نام باید دست‌کم {min} نویسه باشد.", en: "The name needs at least {min} characters." }
            : { fa: "دست‌کم {min} نویسه بنویسید.", en: "Write at least {min} characters." };
      case "too_long":
        return { fa: "حداکثر {max} نویسه می‌شود نوشت.", en: "Use at most {max} characters." };
      case "missing_letter":
        return { fa: "رمز باید دست‌کم یک حرف داشته باشد.", en: "The password needs at least one letter." };
      case "missing_digit":
        return { fa: "رمز باید دست‌کم یک عدد داشته باشد.", en: "The password needs at least one number." };
      case "same_as_current":
        return { fa: "رمز تازه باید با رمز فعلی فرق داشته باشد.", en: "The new password must be different from the current one." };
      case "incorrect":
        return field === "current_password"
          ? { fa: "رمز فعلی درست نیست.", en: "Your current password is wrong." }
          : { fa: "این مقدار درست نیست.", en: "This isn't right." };
      case "mismatch":
        return { fa: "رمز و تکرار آن یکی نیستند.", en: "The two passwords don't match." };
      case "invalid_format":
        return isEmail
          ? { fa: "ایمیل باید مثل name@example.com باشد.", en: "The email should look like name@example.com." }
          : { fa: "شکل این مقدار درست نیست.", en: "This isn't in the right form." };
      case "taken":
      case "exists":
        return isEmail
          ? { fa: "حسابی با این ایمیل از قبل هست. اگر مال شماست، وارد شوید.", en: "An account with this email already exists. If it's yours, sign in." }
          : { fa: "این مقدار قبلاً گرفته شده؛ مقدار دیگری بنویسید.", en: "This is already taken; try another." };
      default:
        return { fa: "این خانه را بررسی کنید.", en: "Please check this field." };
    }
  })();
  return fill(text[language], { min: n("min_length") ?? n("min"), max: n("max_length") ?? n("max") }, language);
}

/** Read the error envelope of a failed auth request. */
export async function readAuthFailure(response: Response): Promise<AuthFailure> {
  try {
    const body = (await response.json()) as { error?: { code?: string; fields?: FieldIssue[]; field?: string; reason?: string; params?: Record<string, unknown> } };
    const error = body.error ?? {};
    const fields = Array.isArray(error.fields)
      ? error.fields.filter((item) => item && typeof item.field === "string")
      : error.field
        ? [{ field: error.field, reason_code: error.reason ?? "", params: error.params }]
        : [];
    return { status: response.status, code: error.code ?? "", fields };
  } catch {
    return { status: response.status, code: "", fields: [] };
  }
}

/** Sentences per form field, plus one general sentence for problems not tied to a field. */
export function failureMessages(
  language: Language,
  failure: AuthFailure,
  fieldNames: readonly string[],
  general: Record<string, Bi> = {}
): { fields: Record<string, string>; general: string | null } {
  const fields: Record<string, string> = {};
  for (const issue of failure.fields) {
    const name = issue.field.replace(/^body\./, "");
    if (fieldNames.includes(name) && !fields[name]) fields[name] = fieldReasonText(language, issue.reason_code, issue.params ?? {}, name);
  }
  if (Object.keys(fields).length > 0) return { fields, general: null };
  const own = general[failure.code];
  if (own) return { fields, general: own[language] };
  const entry = errorEntry(failure.code);
  if (entry) {
    // A known error tied to one field (e.g. weak_password → password) goes under that field.
    if (entry.field && fieldNames.includes(entry.field)) return { fields: { [entry.field]: entry[language] }, general: null };
    return { fields, general: entry[language] };
  }
  if (failure.status === 429) return { fields, general: language === "fa" ? "چند بار پشت سر هم امتحان شد. چند دقیقه صبر کنید و دوباره امتحان کنید." : "Too many tries in a row. Wait a few minutes and try again." };
  if (failure.status >= 500 || failure.status === 0) return { fields, general: translate(language, "connectionError") };
  return { fields, general: language === "fa" ? "کاری که خواستید انجام نشد. دوباره امتحان کنید." : "That didn't work. Please try again." };
}

// ── Inputs ───────────────────────────────────────────────────────────────────

/** Password input with a show/hide button. */
export function PasswordField({ language, ...props }: TextFieldProps & { language: Language }) {
  const [visible, setVisible] = useState(false);
  const label = visible
    ? language === "fa" ? "پنهان کردن رمز" : "Hide password"
    : language === "fa" ? "نمایش رمز" : "Show password";
  return (
    <TextField
      {...props}
      type={visible ? "text" : "password"}
      slotProps={{
        ...props.slotProps,
        htmlInput: { dir: "ltr", ...((props.slotProps?.htmlInput as object) ?? {}) },
        input: {
          endAdornment: (
            <InputAdornment position="end">
              <IconButton aria-label={label} onClick={() => setVisible((value) => !value)} edge="end" size="small">
                {visible ? <VisibilityOffRoundedIcon fontSize="small" /> : <VisibilityRoundedIcon fontSize="small" />}
              </IconButton>
            </InputAdornment>
          )
        }
      }}
    />
  );
}

// ── Shell ────────────────────────────────────────────────────────────────────

type AuthShellProps = {
  language: Language;
  onLanguageChange: () => void;
  children: ReactNode;
};

function Logo({ size }: { size: number }) {
  return (
    <Box
      aria-hidden
      sx={{
        width: size,
        height: size,
        borderRadius: 1.25,
        display: "grid",
        placeItems: "center",
        fontWeight: 850,
        fontSize: size < 40 ? 12 : 13,
        color: "#042f2e",
        background: "linear-gradient(145deg, #99f6e4, #38bdf8)",
        flexShrink: 0
      }}
    >
      MRK
    </Box>
  );
}

/** Two-column frame for sign-in, first-run setup, invite and forced password change. */
export function AuthShell({ language, onLanguageChange, children }: AuthShellProps) {
  const t = (key: Parameters<typeof translate>[1]) => translate(language, key);
  const items = [
    { icon: SecurityRoundedIcon, label: t("securedSetup") },
    { icon: StorageRoundedIcon, label: t("localData") },
    { icon: HubRoundedIcon, label: t("modularPlatform") }
  ];

  return (
    <Box
      component="main"
      dir={language === "fa" ? "rtl" : "ltr"}
      sx={{
        minHeight: "100vh",
        display: "grid",
        gridTemplateColumns: { xs: "1fr", md: "minmax(340px, 0.85fr) minmax(520px, 1.15fr)" },
        bgcolor: "background.default"
      }}
    >
      <Box
        sx={{
          display: { xs: "none", md: "flex" },
          flexDirection: "column",
          justifyContent: "space-between",
          p: { md: 5, lg: 7 },
          borderInlineEnd: 1,
          borderColor: "divider",
          background:
            "radial-gradient(circle at 30% 20%, rgba(45,212,191,.16), transparent 34%), linear-gradient(160deg, rgba(56,189,248,.06), transparent 52%)"
        }}
      >
        <Stack direction="row" alignItems="center" spacing={1.5}>
          <Logo size={42} />
          <Box>
            <Typography fontWeight={800}>{t("product")}</Typography>
            <Typography variant="caption" color="text.secondary">
              {t("subtitle")}
            </Typography>
          </Box>
        </Stack>

        <Box sx={{ maxWidth: 500 }}>
          <Typography variant="h3" component="p" sx={{ fontWeight: 820, lineHeight: 1.35 }}>
            {t("heroTitle")}
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 2, lineHeight: 1.9 }}>
            {t("heroBody")}
          </Typography>
          <Stack component="ul" spacing={1.4} sx={{ mt: 4, p: 0, listStyle: "none" }}>
            {items.map(({ icon: Icon, label }) => (
              <Stack component="li" key={label} direction="row" alignItems="center" spacing={1.25}>
                <Box sx={{ width: 34, height: 34, display: "grid", placeItems: "center", border: 1, borderColor: "divider", borderRadius: 1 }}>
                  <Icon color="primary" sx={{ fontSize: 19 }} aria-hidden />
                </Box>
                <Typography variant="body2" fontWeight={620}>
                  {label}
                </Typography>
              </Stack>
            ))}
          </Stack>
        </Box>
        <Typography variant="caption" color="text.secondary">
          {t("product")} · {t("singleNodeAppliance")}
        </Typography>
      </Box>

      <Box sx={{ minWidth: 0, display: "flex", flexDirection: "column", p: { xs: 2, sm: 4, lg: 7 } }}>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Stack direction="row" alignItems="center" spacing={1.2} sx={{ display: { md: "none" } }}>
            <Logo size={34} />
            <Typography fontWeight={780}>{t("subtitle")}</Typography>
          </Stack>
          <Box sx={{ display: { xs: "none", md: "block" } }} />
          <Button size="small" variant="outlined" onClick={onLanguageChange} lang={language === "fa" ? "en" : "fa"} sx={{ minHeight: 40 }}>
            {t("language")}
          </Button>
        </Stack>
        <Box sx={{ width: "100%", maxWidth: 560, m: "auto", py: { xs: 5, md: 3 } }}>{children}</Box>
      </Box>
    </Box>
  );
}

/** Icon badge + title + hint at the top of an auth form. */
export function AuthHeading({ icon, title, hint }: { icon: ReactNode; title: string; hint?: string }) {
  return (
    <>
      <Box
        aria-hidden
        sx={{ width: 44, height: 44, borderRadius: 1.25, display: "grid", placeItems: "center", color: "primary.contrastText", bgcolor: "primary.main" }}
      >
        {icon}
      </Box>
      <Typography variant="h4" component="h1" sx={{ mt: 2.5, fontWeight: 780 }}>
        {title}
      </Typography>
      {hint && (
        <Typography color="text.secondary" sx={{ mt: 1, lineHeight: 1.8 }}>
          {hint}
        </Typography>
      )}
    </>
  );
}
