import { useState, type ReactNode } from "react";
import { Box, Button, IconButton, InputAdornment, Stack, TextField, Typography, type TextFieldProps } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import TranslateRoundedIcon from "@mui/icons-material/TranslateRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import VisibilityOffRoundedIcon from "@mui/icons-material/VisibilityOffRounded";
import type { Language } from "./i18n";
import { translate } from "./i18n";
import { errorEntry } from "./copy/errors";
import { PishkarMark } from "./brand";
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
  return <PishkarMark size={size} />;
}

/** Centered, minimal frame for sign-in, first-run setup, invite and forced password change. */
export function AuthShell({ language, onLanguageChange, children }: AuthShellProps) {
  const t = (key: Parameters<typeof translate>[1]) => translate(language, key);
  const theme = useTheme();
  const dark = theme.palette.mode === "dark";
  const glow = alpha(theme.palette.primary.main, dark ? 0.16 : 0.12);
  const dot = dark ? "rgba(148, 183, 194, .13)" : "rgba(30, 64, 75, .11)";

  return (
    <Box
      component="main"
      dir={language === "fa" ? "rtl" : "ltr"}
      sx={{
        position: "relative",
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        bgcolor: "background.default",
        overflow: "hidden",
        isolation: "isolate",
        "&::before": {
          content: '""',
          position: "absolute",
          inset: 0,
          zIndex: -1,
          backgroundImage: `radial-gradient(${dot} 1px, transparent 1px)`,
          backgroundSize: "22px 22px",
          maskImage: "radial-gradient(ellipse 70% 60% at 50% 40%, #000 30%, transparent 100%)",
          WebkitMaskImage: "radial-gradient(ellipse 70% 60% at 50% 40%, #000 30%, transparent 100%)"
        },
        "&::after": {
          content: '""',
          position: "absolute",
          inset: 0,
          zIndex: -1,
          background: `radial-gradient(ellipse 55% 38% at 50% -6%, ${glow}, transparent 70%)`
        }
      }}
    >
      <Stack direction="row" justifyContent="flex-end" sx={{ p: { xs: 2, sm: 3 } }}>
        <Button
          size="small"
          variant="text"
          color="inherit"
          onClick={onLanguageChange}
          lang={language === "fa" ? "en" : "fa"}
          startIcon={<TranslateRoundedIcon fontSize="small" />}
          sx={{ minHeight: 40, px: 1.5, color: "text.secondary", "& .MuiButton-startIcon": { marginInlineStart: 0, marginInlineEnd: 1 } }}
        >
          {t("language")}
        </Button>
      </Stack>

      <Box sx={{ flex: 1, display: "grid", placeItems: "center", px: 2, pb: { xs: 4, sm: 8 } }}>
        <Box sx={{ width: "100%", maxWidth: 440 }}>
          <Stack alignItems="center" spacing={1.5} sx={{ mb: 3.5, textAlign: "center" }}>
            <Logo size={52} />
            <Box>
              <Typography variant="h6" component="p" sx={{ fontWeight: 800, lineHeight: 1.3 }}>
                {t("product")}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t("subtitle")}
              </Typography>
            </Box>
          </Stack>

          <Box
            sx={{
              p: { xs: 3, sm: 4 },
              borderRadius: 3,
              border: 1,
              borderColor: "divider",
              bgcolor: alpha(theme.palette.background.paper, dark ? 0.78 : 0.9),
              backdropFilter: "blur(10px)",
              boxShadow: dark ? "0 24px 60px rgba(0, 0, 0, .35)" : "0 24px 60px rgba(27, 59, 69, .10)"
            }}
          >
            {children}
          </Box>

          <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 3, textAlign: "center" }}>
            {t("product")} · {t("singleNodeAppliance")}
          </Typography>
        </Box>
      </Box>
    </Box>
  );
}

/** Title + hint at the top of an auth form (the icon is kept for callers but not drawn). */
export function AuthHeading({ title, hint }: { icon?: ReactNode; title: string; hint?: string }) {
  return (
    <Box sx={{ textAlign: "center" }}>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 780 }}>
        {title}
      </Typography>
      {hint && (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1, lineHeight: 1.8 }}>
          {hint}
        </Typography>
      )}
    </Box>
  );
}
