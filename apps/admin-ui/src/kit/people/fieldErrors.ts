/**
 * Field-level errors (docs/34 §2): `{error: {code, message, fields: [{field, reason_code, params?}], ...}}`.
 * `api.ts` `ApiError` carries `fields` (plus `users`, `permissions`, `requestId`), so any helper
 * (`mutateJson`, `getJson`, `ensureOk`) gives you everything:
 *
 *   await mutateJson("/api/v1/users/invite", { method: "POST", body });
 *   catch (error) { setFieldErrors(fieldMessages(language, error)); }
 */
import { ApiError, type FieldIssue } from "../../api";
import type { Language } from "../../i18n";
import { fill } from "../../copy/text";

export type { FieldIssue };

/** Field issues of an error (empty for anything else). */
export function fieldIssues(error: unknown): FieldIssue[] {
  return error instanceof ApiError ? error.fields : [];
}

type Words = { fa: string; en: string };

const REASONS: Record<string, Words> = {
  required: { fa: "این خانه را پر کنید.", en: "Fill in this field." },
  too_short: { fa: "دست‌کم {min} نویسه بنویسید.", en: "Use at least {min} characters." },
  too_long: { fa: "حداکثر {max} نویسه می‌شود؛ کوتاه‌ترش کنید.", en: "Use at most {max} characters." },
  too_small: { fa: "عدد باید دست‌کم {min} باشد.", en: "The number must be at least {min}." },
  too_large: { fa: "عدد باید حداکثر {max} باشد.", en: "The number must be at most {max}." },
  invalid_format: { fa: "شکل این مقدار درست نیست.", en: "This isn't in the right format." },
  invalid_choice: { fa: "یکی از گزینه‌ها را انتخاب کنید.", en: "Pick one of the options." },
  invalid_type: { fa: "این مقدار درست نیست.", en: "This value isn't valid." },
  unknown_field: { fa: "این خانه شناخته نشد. صفحه را تازه کنید.", en: "This field isn't recognised. Reload the page." },
  incorrect: { fa: "درست نیست؛ دوباره بنویسید.", en: "That isn't right; try again." },
  missing_letter: { fa: "رمز باید دست‌کم یک حرف داشته باشد.", en: "The password needs at least one letter." },
  missing_digit: { fa: "رمز باید دست‌کم یک عدد داشته باشد.", en: "The password needs at least one digit." },
  same_as_current: { fa: "رمز تازه باید با رمز فعلی فرق کند.", en: "The new password must be different." },
  duplicate: { fa: "این قبلاً استفاده شده؛ چیز دیگری بنویسید.", en: "This is already in use; try another." },
  reserved: { fa: "این نام رزرو شده؛ نام دیگری بنویسید.", en: "This name is reserved; choose another." },
  unknown_role: { fa: "این نقش دیگر وجود ندارد؛ فهرست را تازه کنید.", en: "This role no longer exists; refresh the list." },
  unknown_permission: { fa: "یکی از اجازه‌ها شناخته نشد؛ صفحه را تازه کنید.", en: "One permission isn't recognised; reload the page." },
  wildcard_forbidden: { fa: "نقش سفارشی نمی‌تواند «همه اجازه‌ها» را داشته باشد.", en: "A custom role can't hold every permission." },
  missing_dependency: { fa: "یکی از اجازه‌ها به اجازه دیگری نیاز دارد که تیک نخورده.", en: "One permission needs another one that isn't ticked." },
  exceeds_own_permissions: { fa: "شما خودتان این اجازه را ندارید، پس نمی‌توانید آن را بدهید.", en: "You don't hold this permission, so you can't grant it." },
  in_use: { fa: "هنوز {users} نفر این نقش را دارند.", en: "{users} people still have this role." },
  builtin: { fa: "نقش‌های آماده عوض نمی‌شوند؛ از روی آن یک نقش تازه بسازید.", en: "Built-in roles can't change; make a copy instead." },
  not_found: { fa: "پیدا نشد؛ فهرست را تازه کنید.", en: "Not found; refresh the list." }
};

/** Field-specific wording that reads better than the generic reason. */
const FIELD_REASONS: Record<string, Partial<Record<string, Words>>> = {
  email: {
    invalid_format: { fa: "ایمیل را مثل name@example.com بنویسید.", en: "Write the email like name@example.com." },
    duplicate: { fa: "حساب دیگری همین ایمیل را دارد.", en: "Another account uses this email." }
  },
  username: {
    invalid_format: { fa: "نام کاربری فقط حروف کوچک انگلیسی، عدد، نقطه، خط تیره و زیرخط دارد.", en: "A username may use lowercase letters, digits, dots, dashes and underscores." },
    duplicate: { fa: "این نام کاربری را کس دیگری دارد؛ نام دیگری بنویسید.", en: "Someone else has this username; try another." }
  },
  name: {
    duplicate: { fa: "نقش یا کانال دیگری همین نام را دارد؛ نام دیگری بنویسید.", en: "Something else already has this name; choose another." }
  },
  password: {
    too_short: { fa: "رمز باید دست‌کم {min} نویسه باشد.", en: "The password needs at least {min} characters." }
  }
};

function paramNumber(params: Record<string, unknown> | undefined, ...keys: string[]): number | undefined {
  for (const key of keys) {
    const value = params?.[key];
    if (typeof value === "number") return value;
  }
  return undefined;
}

/** One plain sentence for a field issue. */
export function fieldIssueMessage(language: Language, issue: FieldIssue): string {
  const words = FIELD_REASONS[issue.field]?.[issue.reason_code] ?? REASONS[issue.reason_code] ?? REASONS.invalid_type;
  const users = issue.params?.users;
  return fill(words[language], {
    min: paramNumber(issue.params, "min_length", "min", "ge"),
    max: paramNumber(issue.params, "max_length", "max", "le"),
    users: typeof users === "number" ? users : Array.isArray(users) ? users.length : undefined
  }, language);
}

/** `{field: sentence}` for the first issue of each field (for TextField helperText). */
export function fieldMessages(language: Language, error: unknown): Record<string, string> {
  const result: Record<string, string> = {};
  for (const issue of fieldIssues(error)) {
    if (!result[issue.field]) result[issue.field] = fieldIssueMessage(language, issue);
  }
  return result;
}
