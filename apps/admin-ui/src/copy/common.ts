/**
 * Generic words used on every page. Import these instead of writing «ذخیره» or «انصراف» again.
 *
 * Usage: `const c = commonWords(language); <Button>{c.save}</Button>`
 * Words follow the writing guide (docs/33 §2): «تازه کردن» means refresh, «به‌روزرسانی» means
 * updating to a new version, «پشتیبان» is the only word for backup, «کار» is a background job.
 */
import type { Language } from "../i18n";
import type { Bi } from "./text";

export const COMMON = {
  save: { fa: "ذخیره", en: "Save" },
  saving: { fa: "در حال ذخیره…", en: "Saving…" },
  saved: { fa: "ذخیره شد", en: "Saved" },
  saveChanges: { fa: "ذخیره تغییرات", en: "Save changes" },
  discardChanges: { fa: "دور انداختن تغییرات", en: "Discard changes" },
  cancel: { fa: "انصراف", en: "Cancel" },
  close: { fa: "بستن", en: "Close" },
  back: { fa: "قبلی", en: "Back" },
  next: { fa: "بعدی", en: "Next" },
  finish: { fa: "تمام", en: "Finish" },
  skip: { fa: "از این قدم بگذر", en: "Skip this step" },
  done: { fa: "انجام شد", en: "Done" },
  ok: { fa: "باشه", en: "OK" },
  yes: { fa: "بله", en: "Yes" },
  no: { fa: "نه", en: "No" },
  add: { fa: "افزودن", en: "Add" },
  edit: { fa: "ویرایش", en: "Edit" },
  remove: { fa: "پاک کردن", en: "Remove" },
  removeForever: { fa: "پاک کردن برای همیشه", en: "Delete forever" },
  rename: { fa: "تغییر نام", en: "Rename" },
  refresh: { fa: "تازه کردن", en: "Refresh" },
  refreshing: { fa: "در حال تازه کردن…", en: "Refreshing…" },
  updatedAt: { fa: "آخرین بار: {time}", en: "Updated {time}" },
  retry: { fa: "دوباره امتحان کن", en: "Try again" },
  test: { fa: "امتحان اتصال", en: "Test connection" },
  testing: { fa: "در حال امتحان…", en: "Testing…" },
  copy: { fa: "کپی", en: "Copy" },
  copied: { fa: "کپی شد", en: "Copied" },
  copyFailed: { fa: "کپی نشد؛ متن را خودتان انتخاب و کپی کنید.", en: "Couldn't copy. Select the text and copy it yourself." },
  download: { fa: "دانلود", en: "Download" },
  upload: { fa: "آپلود", en: "Upload" },
  search: { fa: "جست‌وجو", en: "Search" },
  searchPlaceholder: { fa: "جست‌وجو…", en: "Search…" },
  filter: { fa: "فیلتر", en: "Filter" },
  clear: { fa: "پاک کردن", en: "Clear" },
  loading: { fa: "در حال بارگذاری…", en: "Loading…" },
  more: { fa: "بیشتر", en: "More" },
  moreActions: { fa: "کارهای بیشتر", en: "More actions" },
  showMore: { fa: "نمایش بیشتر", en: "Show more" },
  showLess: { fa: "نمایش کمتر", en: "Show less" },
  show: { fa: "نمایش", en: "Show" },
  hide: { fa: "پنهان کردن", en: "Hide" },
  details: { fa: "جزئیات", en: "Details" },
  technicalDetails: { fa: "جزئیات فنی", en: "Technical details" },
  copyTechnicalDetails: { fa: "کپی جزئیات فنی", en: "Copy technical details" },
  why: { fa: "چرا؟", en: "Why?" },
  learnMore: { fa: "بیشتر بدانید", en: "Learn more" },
  help: { fa: "راهنما", en: "Help" },
  turnOn: { fa: "روشن کن", en: "Turn on" },
  turnOff: { fa: "خاموش کن", en: "Turn off" },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  enabled: { fa: "فعال", en: "Active" },
  disabled: { fa: "غیرفعال", en: "Inactive" },
  notSet: { fa: "هنوز تنظیم نشده", en: "Not set up yet" },
  isSet: { fa: "تنظیم شده", en: "Set" },
  none: { fa: "هیچ", en: "None" },
  unknown: { fa: "نامشخص", en: "Unknown" },
  default: { fa: "پیش‌فرض", en: "Default" },
  resetToDefault: { fa: "بازگشت به پیش‌فرض", en: "Reset to default" },
  optional: { fa: "اختیاری", en: "Optional" },
  required: { fa: "لازم است", en: "Required" },
  undo: { fa: "برگرداندن", en: "Undo" },
  comingSoon: { fa: "به‌زودی", en: "Coming soon" },
  advancedOptions: { fa: "تنظیمات بیشتر", en: "More options" },
  dangerZone: { fa: "منطقه خطر", en: "Danger zone" },
  justNow: { fa: "همین حالا", en: "just now" },
  step: { fa: "قدم {current} از {total}", en: "Step {current} of {total}" },
  emptyDash: { fa: "—", en: "—" },
  restartRequired: { fa: "پس از راه‌اندازی دوباره اعمال می‌شود", en: "Applies after a restart" },
  fromCompose: { fa: "فقط از فایل Compose", en: "Set in the Compose file" },
  fromPanel: { fa: "قابل تغییر از پنل", en: "Editable here" },
  changedFromDefault: { fa: "تغییر یافته از پیش‌فرض", en: "Changed from default" },
  notEditableYet: { fa: "هنوز قابل تغییر نیست", en: "Can't be changed yet" },
  readOnly: { fa: "فقط دیدنی", en: "View only" },
  copyComposeLine: { fa: "کپی خط Compose", en: "Copy Compose line" },
  dangerous: { fa: "خطرناک", en: "Dangerous" },
  noResults: { fa: "چیزی پیدا نشد.", en: "Nothing found." },
  noResultsFor: { fa: "چیزی با «{query}» پیدا نشد. املای آن را بررسی کنید.", en: "Nothing matches “{query}”. Check the spelling." },
  closeDialog: { fa: "بستن پنجره", en: "Close dialog" },
  menu: { fa: "منو", en: "Menu" }
} satisfies Record<string, Bi>;

export type CommonWord = keyof typeof COMMON;
export type CommonWords = Record<CommonWord, string>;

const cache: Partial<Record<Language, CommonWords>> = {};

/** All generic words in one language (memoised). */
export function commonWords(language: Language): CommonWords {
  const hit = cache[language];
  if (hit) return hit;
  const result = Object.fromEntries(Object.entries(COMMON).map(([key, value]) => [key, value[language]])) as CommonWords;
  cache[language] = result;
  return result;
}
