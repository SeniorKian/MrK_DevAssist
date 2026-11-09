/**
 * Copy for «فضای من» (docs/43 §4): the user's own space (domains, file space, packages, team, keys,
 * activity) and the admin side under «کاربران و دسترسی» (plans, workspaces, sign-ups, settings, view as).
 *
 * My space copy never uses admin words (role ids, permissions, «مدیر سامانه» only when the person has
 * to ask for something). Placeholders: `{name}` etc. are filled with `say()`.
 */
import type { Language } from "../i18n";
import { formatBytes, formatNumber } from "../format";
import { pick, say, type Bi } from "./text";

// ── workspace roles (docs/43 §1) ─────────────────────────────────────────────

export type WorkspaceRole = "owner" | "admin" | "member" | "viewer";
/** Lowest first. Nobody gives a role above their own; only an owner makes another owner. */
export const WORKSPACE_ROLE_ORDER: WorkspaceRole[] = ["viewer", "member", "admin", "owner"];

export const WORKSPACE_ROLES: Record<WorkspaceRole, { name: Bi; oneLiner: Bi }> = {
  owner: { name: { fa: "صاحب فضا", en: "Owner" }, oneLiner: { fa: "همه کارها، حتی پاک کردن فضا", en: "Everything, even deleting the space" } },
  admin: { name: { fa: "گرداننده", en: "Admin" }, oneLiner: { fa: "همه کارها، جز پاک کردن فضا و عوض کردن صاحب", en: "Everything except deleting the space or changing its owner" } },
  member: { name: { fa: "عضو", en: "Member" }, oneLiner: { fa: "می‌سازد و تغییر می‌دهد", en: "Creates and changes things" } },
  viewer: { name: { fa: "فقط دیدن", en: "Viewer" }, oneLiner: { fa: "فقط می‌بیند؛ چیزی را عوض نمی‌کند", en: "Can only look; changes nothing" } }
};

export function workspaceRoleName(language: Language, role: string | null | undefined): string {
  const info = WORKSPACE_ROLES[(role ?? "") as WorkspaceRole];
  return info ? pick(language, info.name) : pick(language, WORKSPACE_ROLES.viewer.name);
}

// ── plan features and limits (docs/43 §1 «بسته») ─────────────────────────────

export type FeatureKey =
  | "dns" | "dns_dnssec" | "dns_templates" | "s3" | "s3_public_links" | "s3_bucket_domains" | "npm" | "pypi" | "teams" | "api_tokens";
export const FEATURE_KEYS: FeatureKey[] = ["dns", "dns_dnssec", "dns_templates", "s3", "s3_public_links", "s3_bucket_domains", "npm", "pypi", "teams", "api_tokens"];

export const FEATURE_WORDS: Record<FeatureKey, { label: Bi; hint: Bi }> = {
  dns: { label: { fa: "دامنه‌ها", en: "Domains" }, hint: { fa: "دامنه خودش را بیاورد و رکوردهایش را بسازد.", en: "Bring their own domains and make records." } },
  dns_dnssec: { label: { fa: "امضای امنیتی دامنه", en: "Domain signing (DNSSEC)" }, hint: { fa: "دامنه را امضا کند تا جواب‌ها جعل نشوند.", en: "Sign domains so answers can't be forged." } },
  dns_templates: { label: { fa: "قالب‌های آماده دامنه", en: "Domain templates" }, hint: { fa: "رکوردهای معمول را با یک کلیک بسازد.", en: "Make the usual records in one click." } },
  s3: { label: { fa: "فضای فایل", en: "File space" }, hint: { fa: "فایل بگذارد و برنامه‌ها را به آن وصل کند.", en: "Keep files and connect apps to them." } },
  s3_public_links: { label: { fa: "پوشه عمومی", en: "Public folders" }, hint: { fa: "فایل‌های یک پوشه را برای همه باز کند.", en: "Open a folder's files to everyone." } },
  s3_bucket_domains: { label: { fa: "دامنه برای پوشه", en: "Folder domains" }, hint: { fa: "یک دامنه را به پوشه فایل وصل کند.", en: "Point a domain at a folder." } },
  npm: { label: { fa: "بسته‌های خصوصی npm", en: "Private npm packages" }, hint: { fa: "بسته npm خودش را منتشر کند.", en: "Publish their own npm packages." } },
  pypi: { label: { fa: "بسته‌های خصوصی پایتون", en: "Private Python packages" }, hint: { fa: "بسته پایتون خودش را منتشر کند.", en: "Publish their own Python packages." } },
  teams: { label: { fa: "فضای تیمی", en: "Team spaces" }, hint: { fa: "برای کار گروهی فضای جدا بسازد و هم‌تیمی دعوت کند.", en: "Make shared spaces and invite teammates." } },
  api_tokens: { label: { fa: "کلید برنامه", en: "API keys" }, hint: { fa: "برای اسکریپت‌ها کلید بسازد.", en: "Make keys for scripts." } }
};

export type QuotaKey =
  | "workspaces_team" | "members" | "dns_zones" | "dns_records_per_zone" | "s3_buckets" | "s3_bytes" | "s3_objects" | "s3_keys"
  | "s3_bucket_domains" | "npm_bytes" | "pypi_bytes" | "api_tokens";
export type QuotaUnit = "count" | "bytes";
export const QUOTA_KEYS: QuotaKey[] = [
  "dns_zones", "dns_records_per_zone", "s3_buckets", "s3_bytes", "s3_objects", "s3_keys", "s3_bucket_domains", "npm_bytes", "pypi_bytes",
  "members", "workspaces_team", "api_tokens"
];

export const QUOTA_WORDS: Record<QuotaKey, { label: Bi; unit: QuotaUnit; feature?: FeatureKey }> = {
  dns_zones: { label: { fa: "تعداد دامنه", en: "Domains" }, unit: "count", feature: "dns" },
  dns_records_per_zone: { label: { fa: "رکورد در هر دامنه", en: "Records per domain" }, unit: "count", feature: "dns" },
  s3_buckets: { label: { fa: "تعداد پوشه فایل", en: "File folders" }, unit: "count", feature: "s3" },
  s3_bytes: { label: { fa: "حجم فایل‌ها", en: "File storage" }, unit: "bytes", feature: "s3" },
  s3_objects: { label: { fa: "تعداد فایل", en: "Files" }, unit: "count", feature: "s3" },
  s3_keys: { label: { fa: "کلید دسترسی فایل", en: "File access keys" }, unit: "count", feature: "s3" },
  s3_bucket_domains: { label: { fa: "دامنه برای پوشه", en: "Folder domains" }, unit: "count", feature: "s3_bucket_domains" },
  npm_bytes: { label: { fa: "حجم بسته‌های npm", en: "npm package storage" }, unit: "bytes", feature: "npm" },
  pypi_bytes: { label: { fa: "حجم بسته‌های پایتون", en: "Python package storage" }, unit: "bytes", feature: "pypi" },
  members: { label: { fa: "تعداد اعضای هر فضا", en: "Members per space" }, unit: "count", feature: "teams" },
  workspaces_team: { label: { fa: "تعداد فضای تیمی", en: "Team spaces" }, unit: "count", feature: "teams" },
  api_tokens: { label: { fa: "تعداد کلید برنامه", en: "API keys" }, unit: "count", feature: "api_tokens" }
};

export function quotaLabel(language: Language, key: string): string {
  const info = QUOTA_WORDS[key as QuotaKey];
  return info ? pick(language, info.label) : pick(language, { fa: "یکی از سقف‌ها", en: "One of the limits" });
}

// ── API key scopes (docs/43 §3 «کلیدهای API من») ─────────────────────────────

export type MyScope = "my.dns:read" | "my.dns:write" | "my.s3:read" | "my.s3:write" | "my.packages:read" | "my.packages:write";
export const MY_SCOPES: { key: MyScope; area: "dns" | "s3" | "packages"; write: boolean; label: Bi }[] = [
  { key: "my.dns:read", area: "dns", write: false, label: { fa: "دیدن دامنه‌ها و رکوردها", en: "See domains and records" } },
  { key: "my.dns:write", area: "dns", write: true, label: { fa: "ساختن و تغییر رکوردها", en: "Create and change records" } },
  { key: "my.s3:read", area: "s3", write: false, label: { fa: "دیدن و دانلود فایل‌ها", en: "See and download files" } },
  { key: "my.s3:write", area: "s3", write: true, label: { fa: "آپلود و پاک کردن فایل‌ها", en: "Upload and delete files" } },
  { key: "my.packages:read", area: "packages", write: false, label: { fa: "نصب بسته‌های خصوصی", en: "Install private packages" } },
  { key: "my.packages:write", area: "packages", write: true, label: { fa: "انتشار و پاک کردن بسته‌ها", en: "Publish and delete packages" } }
];

export function scopeLabel(language: Language, scope: string): string {
  const found = MY_SCOPES.find((item) => item.key === scope);
  return found ? pick(language, found.label) : pick(language, { fa: "یک دسترسی دیگر", en: "Another permission" });
}

// ── My space: shell, picker, home ────────────────────────────────────────────

export const MY = {
  area: { fa: "بخش", en: "Area" },
  areaAdmin: { fa: "مدیریت سرور", en: "Server admin" },
  areaMine: { fa: "فضای من", en: "My space" },
  menu: { fa: "بخش‌های فضای من", en: "My space sections" },
  workspace: { fa: "فضای کاری", en: "Workspace" },
  personal: { fa: "فضای شخصی", en: "Personal" },
  team: { fa: "فضای تیمی", en: "Team" },
  newTeam: { fa: "ساخت فضای تیمی", en: "New team space" },
  newTeamTitle: { fa: "ساخت فضای تیمی تازه", en: "Create a team space" },
  newTeamHint: { fa: "برای کار گروهی یک فضای جدا بسازید و بعد هم‌تیمی‌ها را دعوت کنید.", en: "Make a separate space for group work, then invite teammates." },
  teamName: { fa: "نام فضا", en: "Space name" },
  teamCreated: { fa: "فضای «{name}» ساخته شد.", en: "Space “{name}” created." },
  suspended: { fa: "این فضا موقتاً بسته شده و فقط می‌شود دید. برای باز شدنش با مدیر سامانه صحبت کنید.", en: "This space is paused, so you can only look. Talk to the system admin to reopen it." },
  readOnlyRole: { fa: "نقش شما در این فضا «فقط دیدن» است؛ برای تغییر چیزی از صاحب فضا بخواهید.", en: "You're a viewer in this space; ask its owner to change anything." },
  loading: { fa: "در حال آماده کردن فضای شما…", en: "Getting your space ready…" },
  notReadyTitle: { fa: "فضای شما هنوز آماده نیست", en: "Your space isn't ready yet" },
  notReadyBody: { fa: "مدیر سامانه هنوز «فضای من» را روشن نکرده. کمی بعد دوباره سر بزنید.", en: "The system admin hasn't turned on My space yet. Check back a little later." },
  failedTitle: { fa: "فضای شما باز نشد", en: "Your space didn't open" },
  noWorkspaceTitle: { fa: "هنوز فضایی ندارید", en: "You don't have a space yet" },
  noWorkspaceBody: { fa: "از مدیر سامانه بخواهید برایتان یک فضا بسازد یا شما را دعوت کند.", en: "Ask the system admin to make a space for you or invite you." },
  featureOffTitle: { fa: "این بخش در بسته شما نیست", en: "This isn't in your plan" },
  featureOffBody: { fa: "برای داشتن «{feature}» با مدیر سامانه صحبت کنید.", en: "Talk to the system admin to get “{feature}”." },
  tabFiles: { fa: "فضای فایل", en: "File space" },
  // home
  hello: { fa: "سلام {name}", en: "Hi {name}" },
  helloPlain: { fa: "سلام", en: "Hi" },
  homeAllGood: { fa: "همه چیز روبه‌راه است.", en: "Everything is fine." },
  homeNear: { fa: "به سقف چند چیز نزدیک شده‌اید.", en: "You're close to a few limits." },
  homeFull: { fa: "یکی از سقف‌های شما پر شده.", en: "One of your limits is full." },
  planIs: { fa: "بسته شما: {plan}", en: "Your plan: {plan}" },
  noPlan: { fa: "بسته‌ای ندارد", en: "No plan" },
  usageTitle: { fa: "مصرف شما", en: "What you use" },
  usageHint: { fa: "هر نوار نشان می‌دهد چقدر از سقف بسته‌تان را استفاده کرده‌اید.", en: "Each bar shows how much of your plan's limit you use." },
  usageOf: { fa: "{used} از {limit}", en: "{used} of {limit}" },
  unlimited: { fa: "بی‌سقف", en: "Unlimited" },
  usedUnlimited: { fa: "{used} استفاده شده، بی‌سقف", en: "{used} used, unlimited" },
  nearTitle: { fa: "«{label}» نزدیک سقف است", en: "“{label}” is close to the limit" },
  nearWhy: { fa: "{used} از {limit} استفاده شده. کمی جا باز کنید یا بسته بزرگ‌تری بخواهید.", en: "{used} of {limit} used. Free some room or ask for a bigger plan." },
  fullTitle: { fa: "«{label}» پر شده", en: "“{label}” is full" },
  fullWhy: { fa: "تا چیزی پاک نکنید یا بسته بزرگ‌تر نگیرید، تازه نمی‌شود ساخت.", en: "You can't add more until you remove something or get a bigger plan." },
  noUsage: { fa: "هنوز چیزی نساخته‌اید. از دکمه‌های پایین شروع کنید.", en: "You haven't made anything yet. Start with the buttons below." },
  quickTitle: { fa: "کارهای سریع", en: "Quick actions" },
  quickDomain: { fa: "افزودن دامنه", en: "Add a domain" },
  quickBucket: { fa: "ساخت پوشه فایل", en: "Make a file folder" },
  quickPackages: { fa: "وصل کردن npm یا pip", en: "Connect npm or pip" },
  quickInvite: { fa: "دعوت هم‌تیمی", en: "Invite a teammate" },
  quickKey: { fa: "ساخت کلید برنامه", en: "Make an API key" },
  // shared words
  name: { fa: "نام", en: "Name" },
  created: { fa: "ساخته شده", en: "Created" },
  status: { fa: "وضعیت", en: "Status" },
  remove: { fa: "پاک کردن", en: "Delete" },
  open: { fa: "باز کردن", en: "Open" },
  back: { fa: "برگشت", en: "Back" },
  save: { fa: "ذخیره", en: "Save" },
  close: { fa: "بستن", en: "Close" },
  removed: { fa: "«{name}» پاک شد.", en: "“{name}” deleted." },
  saved: { fa: "ذخیره شد.", en: "Saved." },
  // errors
  quotaFull: { fa: "سقف «{label}» در بسته شما پر شده ({used} از {limit}). اول چیزی پاک کنید یا بسته بزرگ‌تری بخواهید.", en: "Your plan's “{label}” limit is full ({used} of {limit}). Remove something first, or ask for a bigger plan." },
  quotaFullShort: { fa: "سقف «{label}» در بسته شما پر شده. اول چیزی پاک کنید یا بسته بزرگ‌تری بخواهید.", en: "Your plan's “{label}” limit is full. Remove something first, or ask for a bigger plan." },
  featureOff: { fa: "«{feature}» در بسته شما نیست. برای داشتنش با مدیر سامانه صحبت کنید.", en: "“{feature}” isn't in your plan. Talk to the system admin to get it." }
} satisfies Record<string, Bi>;

// ── domains ──────────────────────────────────────────────────────────────────

export const MY_DNS = {
  title: { fa: "دامنه‌های من", en: "My domains" },
  hint: { fa: "دامنه‌ای را که خریده‌اید این‌جا بیاورید تا بگویید هر نامش به کجا برود.", en: "Bring a domain you own here and say where each of its names goes." },
  add: { fa: "افزودن دامنه", en: "Add a domain" },
  addTitle: { fa: "افزودن دامنه", en: "Add a domain" },
  addHint: { fa: "نام دامنه را بنویسید؛ رکوردهای معمول با قالب آماده ساخته می‌شوند.", en: "Write the domain name; the usual records come from a ready template." },
  domain: { fa: "نام دامنه", en: "Domain name" },
  domainHint: { fa: "مثلاً «example.com» — بدون «www» و بدون «https».", en: "For example example.com — no www, no https." },
  domainBad: { fa: "این شبیه نام دامنه نیست. مثل «example.com» بنویسید.", en: "That doesn't look like a domain. Write it like example.com." },
  added: { fa: "دامنه «{name}» اضافه شد.", en: "Domain “{name}” added." },
  addedVerify: { fa: "دامنه «{name}» اضافه شد. حالا ثابت کنید مال شماست.", en: "Domain “{name}” added. Now show it's yours." },
  emptyTitle: { fa: "هنوز دامنه‌ای نیاورده‌اید", en: "You haven't added a domain yet" },
  emptyBody: { fa: "دامنه خودتان را بیاورید تا سایت، ایمیل و برنامه‌هایتان با آن کار کنند.", en: "Bring your domain so your site, email and apps work with it." },
  records: { fa: "{n} رکورد", en: "{n} records" },
  recordsOf: { fa: "{n} از {limit} رکورد", en: "{n} of {limit} records" },
  waiting: { fa: "منتظر اثبات مالکیت", en: "Waiting for proof" },
  active: { fa: "فعال", en: "Active" },
  signed: { fa: "امضا شده", en: "Signed" },
  listLabel: { fa: "دامنه‌های من", en: "My domains" },
  deleteTitle: { fa: "دامنه «{name}» پاک شود؟", en: "Delete the domain “{name}”?" },
  deleteBody: { fa: "همه رکوردهای این دامنه پاک می‌شوند و نام‌هایش دیگر جواب نمی‌دهند.", en: "All of this domain's records are deleted and its names stop answering." },
  // verification
  verifyTitle: { fa: "ثابت کنید این دامنه مال شماست", en: "Show this domain is yours" },
  verifyBody: { fa: "تا این کار نشود، دامنه جواب نمی‌دهد. یکی از دو راه زیر کافی است.", en: "Until you do, the domain won't answer. Either way below is enough." },
  verifyTxt: { fa: "راه ۱: یک رکورد «TXT» بگذارید", en: "Way 1: add a TXT record" },
  verifyTxtSteps: { fa: "در سایتی که دامنه را از آن خریده‌اید، بخش DNS را باز کنید و این رکورد را بسازید:", en: "At the place you bought the domain, open its DNS section and make this record:" },
  verifyNs: { fa: "راه ۲: سرورهای نام را عوض کنید", en: "Way 2: change the name servers" },
  verifyNsSteps: { fa: "در سایتی که دامنه را از آن خریده‌اید، سرورهای نام دامنه را این‌ها بگذارید:", en: "At the place you bought the domain, set its name servers to these:" },
  recordType: { fa: "نوع", en: "Type" },
  recordHost: { fa: "نام", en: "Name" },
  recordValue: { fa: "مقدار", en: "Value" },
  nameServer: { fa: "سرور نام {n}", en: "Name server {n}" },
  verifyWait: { fa: "تغییرها گاهی تا یک ساعت طول می‌کشد تا همه‌جا برسد.", en: "Changes can take up to an hour to reach everywhere." },
  checkNow: { fa: "بررسی کن", en: "Check now" },
  checking: { fa: "در حال بررسی…", en: "Checking…" },
  verified: { fa: "عالی! دامنه «{name}» مال شما شناخته شد و فعال است.", en: "Great! “{name}” is confirmed as yours and is active." },
  notYet: { fa: "هنوز پیدا نشد. اگر همین الان رکورد را گذاشته‌اید، چند دقیقه بعد دوباره بزنید.", en: "Not found yet. If you just added it, try again in a few minutes." },
  verifyLoadFailed: { fa: "راهنمای اثبات مالکیت باز نشد.", en: "The proof steps didn't load." },
  // detail
  backToList: { fa: "برگشت به دامنه‌ها", en: "Back to domains" },
  recordsTitle: { fa: "رکوردها", en: "Records" },
  recordsHint: { fa: "هر رکورد می‌گوید یک نام به کجا برود.", en: "Each record says where one name goes." },
  addRecord: { fa: "افزودن رکورد", en: "Add a record" },
  editRecord: { fa: "تغییر", en: "Change" },
  applyTemplate: { fa: "افزودن رکوردهای یک قالب", en: "Add a template's records" },
  recordSaved: { fa: "رکورد «{name}» ذخیره شد.", en: "Record “{name}” saved." },
  recordDeleteTitle: { fa: "رکورد «{name}» پاک شود؟", en: "Delete the record “{name}”?" },
  recordDeleteBody: { fa: "این نام دیگر به این مقصد نمی‌رود.", en: "This name will stop going to this place." },
  recordsEmpty: { fa: "این دامنه هنوز رکوردی ندارد", en: "This domain has no records yet" },
  recordsEmptyBody: { fa: "مثلاً بگویید «www» به نشانی سایتتان برود.", en: "For example, send www to your site's address." },
  colName: { fa: "نام", en: "Name" },
  colType: { fa: "نوع", en: "Type" },
  colValue: { fa: "مقصد", en: "Goes to" },
  colTtl: { fa: "ماندگاری", en: "TTL" },
  off: { fa: "خاموش", en: "Off" },
  templateApplied: { fa: "رکوردهای قالب اضافه شد.", en: "The template's records were added." },
  tabRecords: { fa: "رکوردها", en: "Records" },
  tabSigning: { fa: "امضای امنیتی", en: "Signing" },
  tabVerify: { fa: "اثبات مالکیت", en: "Ownership" },
  limitNote: { fa: "انواع رکوردی که بسته شما اجازه می‌دهد: {types}", en: "Record types your plan allows: {types}" },
  signingTitle: { fa: "امضای امنیتی دامنه", en: "Domain signing" },
  signingHint: { fa: "با امضا، کسی نمی‌تواند به‌جای دامنه شما جواب جعلی بدهد.", en: "With signing, nobody can give fake answers for your domain." },
  signOn: { fa: "امضا روشن باشد", en: "Sign this domain" },
  signedOn: { fa: "امضای «{zone}» روشن شد.", en: "Signing for “{zone}” is on." },
  signedOff: { fa: "امضای «{zone}» خاموش شد.", en: "Signing for “{zone}” is off." },
  signOffTitle: { fa: "امضای «{zone}» خاموش شود؟", en: "Turn off signing for “{zone}”?" },
  signOffBody: { fa: "اول رکورد «DS» را از سایتی که دامنه را از آن خریده‌اید بردارید؛ وگرنه دامنه از کار می‌افتد.", en: "First remove the DS record at the place you bought the domain, or the domain stops working." },
  signOffYes: { fa: "بله، خاموش کن", en: "Yes, turn off" },
  dsTitle: { fa: "یک قدم مانده: این را در سایت فروشنده دامنه بگذارید", en: "One step left: add this where you bought the domain" },
  dsHint: { fa: "تا رکورد «DS» آن‌جا گذاشته نشود، امضا کامل نیست.", en: "Signing isn't complete until the DS record is added there." },
  dsRecord: { fa: "رکورد DS {n}", en: "DS record {n}" },
  signingPreparing: { fa: "کلیدها در حال ساخت‌اند؛ چند لحظه بعد تازه کنید.", en: "Keys are being made; refresh in a moment." }
} satisfies Record<string, Bi>;

// ── file space ───────────────────────────────────────────────────────────────

export const MY_FILES = {
  buckets: { fa: "پوشه‌های فایل", en: "File folders" },
  bucketsHint: { fa: "هر پوشه جای فایل‌های یک کار یا برنامه است. برای دیدن فایل‌ها رویش بزنید.", en: "Each folder holds files for one job or app. Tap it to see the files." },
  create: { fa: "ساخت پوشه فایل", en: "Make a file folder" },
  createTitle: { fa: "ساخت پوشه فایل تازه", en: "Make a file folder" },
  createHint: { fa: "نام در آدرس‌ها می‌آید؛ فقط حروف کوچک انگلیسی، عدد و خط تیره.", en: "The name appears in addresses: lowercase letters, digits and hyphens only." },
  nameLabel: { fa: "نام پوشه", en: "Folder name" },
  nameRule: { fa: "۳ تا ۶۳ نویسه: حروف کوچک انگلیسی، عدد و خط تیره؛ اول و آخرش حرف یا عدد.", en: "3–63 characters: lowercase letters, digits and hyphens; start and end with a letter or digit." },
  nameSuggest: { fa: "پیشنهاد: «{name}»", en: "Suggestion: {name}" },
  created: { fa: "پوشه «{name}» ساخته شد.", en: "Folder “{name}” created." },
  emptyTitle: { fa: "هنوز پوشه فایلی ندارید", en: "You don't have a file folder yet" },
  emptyBody: { fa: "یک پوشه بسازید تا فایل‌ها یا پشتیبان برنامه‌هایتان را در آن بگذارید.", en: "Make a folder to keep your files or app backups in it." },
  files: { fa: "{n} فایل", en: "{n} files" },
  filesCol: { fa: "فایل‌ها", en: "Files" },
  size: { fa: "حجم", en: "Size" },
  public: { fa: "عمومی", en: "Public" },
  private: { fa: "خصوصی", en: "Private" },
  makePublic: { fa: "عمومی کن", en: "Make public" },
  makePrivate: { fa: "خصوصی کن", en: "Make private" },
  publicTitle: { fa: "پوشه «{name}» عمومی شود؟", en: "Make “{name}” public?" },
  publicBody: { fa: "هر کسی که آدرس یک فایل را داشته باشد، بدون رمز می‌تواند آن را باز کند.", en: "Anyone with a file's address can open it, without a password." },
  publicYes: { fa: "بله، عمومی کن", en: "Yes, make public" },
  nowPublic: { fa: "پوشه «{name}» عمومی شد.", en: "“{name}” is now public." },
  nowPrivate: { fa: "پوشه «{name}» خصوصی شد.", en: "“{name}” is now private." },
  deleteTitle: { fa: "پوشه «{name}» با همه فایل‌هایش پاک شود؟", en: "Delete “{name}” and all its files?" },
  deleteBody: { fa: "همه فایل‌های داخلش برای همیشه پاک می‌شوند.", en: "Every file inside is deleted for good." },
  back: { fa: "برگشت به پوشه‌ها", en: "Back to folders" },
  listLabel: { fa: "پوشه‌های فایل", en: "File folders" },
  tabFolders: { fa: "پوشه‌ها و فایل‌ها", en: "Folders & files" },
  tabKeys: { fa: "کلیدهای دسترسی", en: "Access keys" },
  // keys
  keys: { fa: "کلیدهای دسترسی", en: "Access keys" },
  keysHint: { fa: "به هر برنامه یک کلید جدا بدهید تا اگر لازم شد فقط همان را قطع کنید. کلیدها فقط به پوشه‌های همین فضا دسترسی دارند.", en: "Give each app its own key so you can cut off just that one. Keys only reach this space's folders." },
  newKey: { fa: "ساخت کلید دسترسی", en: "Make an access key" },
  newKeyTitle: { fa: "ساخت کلید دسترسی تازه", en: "New access key" },
  keyName: { fa: "برای چه برنامه‌ای؟", en: "For which app?" },
  keyNamePlaceholder: { fa: "مثلاً «پشتیبان سایت»", en: "For example “site backups”" },
  keyNameRequired: { fa: "یک نام بنویسید تا بعداً بدانید این کلید مال کیست.", en: "Write a name so you know later who uses this key." },
  keyLevel: { fa: "چه کاری بکند؟", en: "What can it do?" },
  level_read_only: { fa: "فقط خواندن", en: "Read only" },
  level_read_only_body: { fa: "فایل‌ها را می‌بیند و دانلود می‌کند؛ چیزی را عوض نمی‌کند.", en: "Lists and downloads files; changes nothing." },
  level_read_write: { fa: "خواندن و نوشتن", en: "Read and write" },
  level_read_write_body: { fa: "فایل می‌گذارد، دانلود می‌کند و پاک می‌کند.", en: "Uploads, downloads and deletes files." },
  level_admin: { fa: "همه کارها در پوشه‌های این فضا", en: "Everything in this space's folders" },
  level_admin_body: { fa: "پوشه هم می‌سازد و پاک می‌کند. فقط به برنامه‌ای بدهید که کاملاً به آن اعتماد دارید.", en: "Can also make and delete folders. Give it only to an app you fully trust." },
  keyBuckets: { fa: "کدام پوشه‌ها؟", en: "Which folders?" },
  keyBucketsHint: { fa: "اگر هیچ‌کدام را انتخاب نکنید، کلید به همه پوشه‌های این فضا می‌رسد.", en: "Pick none and the key reaches every folder in this space." },
  keyCreate: { fa: "ساخت کلید", en: "Make key" },
  keysEmptyTitle: { fa: "هنوز کلید دسترسی ندارید", en: "No access keys yet" },
  keysEmptyBody: { fa: "برای وصل کردن برنامه یا ابزار پشتیبان به فایل‌هایتان یک کلید بسازید.", en: "Make a key to connect an app or a backup tool to your files." },
  keyDeleteTitle: { fa: "کلید «{name}» پاک شود؟", en: "Delete the key “{name}”?" },
  keyDeleteBody: { fa: "برنامه‌ای که با این کلید کار می‌کند، دیگر به فایل‌ها نمی‌رسد.", en: "Any app using this key can no longer reach the files." },
  keyLevelCol: { fa: "دسترسی", en: "Access" },
  keyBucketsCol: { fa: "پوشه‌ها", en: "Folders" },
  allBuckets: { fa: "همه پوشه‌های این فضا", en: "Every folder in this space" },
  keysCount: { fa: "{n} کلید", en: "{n} keys" },
  endpoint: { fa: "آدرس اتصال", en: "Endpoint" },
  // domains for a folder
  domains: { fa: "دامنه این پوشه", en: "This folder's domains" },
  domainsHint: { fa: "یک دامنه را به این پوشه وصل کنید تا فایل‌ها با آن باز شوند.", en: "Point a domain at this folder so files open with it." },
  addDomain: { fa: "وصل کردن دامنه", en: "Connect a domain" },
  addDomainTitle: { fa: "وصل کردن دامنه به «{name}»", en: "Connect a domain to “{name}”" },
  addDomainHint: { fa: "مثلاً «files.example.com». اگر دامنه در همین فضا باشد، اثبات لازم نیست.", en: "For example files.example.com. If the domain is in this space, no proof is needed." },
  domainLabel: { fa: "نام دامنه", en: "Domain" },
  domainAdded: { fa: "دامنه «{name}» به پوشه وصل شد.", en: "“{name}” is connected to the folder." },
  domainRemoveTitle: { fa: "دامنه «{name}» از این پوشه جدا شود؟", en: "Disconnect “{name}” from this folder?" },
  domainRemoveBody: { fa: "فایل‌ها دیگر با این دامنه باز نمی‌شوند.", en: "Files will stop opening at this domain." },
  domainRemoveYes: { fa: "بله، جدا کن", en: "Yes, disconnect" },
  domainsEmpty: { fa: "هنوز دامنه‌ای به این پوشه وصل نیست.", en: "No domain points at this folder yet." },
  publicNote: { fa: "پوشه‌های عمومی را هر کسی با آدرس فایل می‌بیند.", en: "Anyone with a file's address can see public folders." }
} satisfies Record<string, Bi>;

// ── packages ─────────────────────────────────────────────────────────────────

export const MY_PACKAGES = {
  title: { fa: "بسته‌های خصوصی من", en: "My private packages" },
  hint: { fa: "بسته‌های خودتان را این‌جا منتشر کنید؛ فقط کسانی که کلید دارند نصبشان می‌کنند.", en: "Publish your own packages here; only people with a key can install them." },
  npmTitle: { fa: "npm", en: "npm" },
  npmHint: { fa: "بسته‌هایتان با نام «{scope}» منتشر می‌شوند.", en: "Your packages are published under {scope}." },
  pypiTitle: { fa: "پایتون (pip)", en: "Python (pip)" },
  pypiHint: { fa: "بسته‌هایتان در فهرست «{index}» منتشر می‌شوند.", en: "Your packages are published to the {index} index." },
  setupTitle: { fa: "یک بار این را در رایانه‌تان بزنید", en: "Run this once on your computer" },
  setupHint: { fa: "دستور را کپی کنید و در خط فرمان بچسبانید.", en: "Copy the command and paste it into your terminal." },
  makeToken: { fa: "ساخت کلید انتشار", en: "Make a publish key" },
  newToken: { fa: "ساخت کلید تازه", en: "Make a new key" },
  making: { fa: "در حال ساخت…", en: "Making…" },
  tokenTitle: { fa: "کلید انتشار ساخته شد", en: "Publish key made" },
  tokenBody: { fa: "این دستورها کلید را دارند. همین حالا کپی کنید؛ کلید دوباره نشان داده نمی‌شود.", en: "These commands contain the key. Copy them now; the key isn't shown again." },
  tokenPlaceholder: { fa: "اول «ساخت کلید انتشار» را بزنید تا دستور با کلید شما کامل شود.", en: "First press “Make a publish key” so the command includes your key." },
  configNpm: { fa: "تنظیم npm", en: "npm setup" },
  publishNpm: { fa: "انتشار یک بسته", en: "Publish a package" },
  configPip: { fa: "تنظیم pip برای نصب", en: "pip setup for installing" },
  uploadPip: { fa: "انتشار با «twine»", en: "Publish with twine" },
  token: { fa: "کلید", en: "Key" },
  off: { fa: "در بسته شما نیست", en: "Not in your plan" },
  listTitle: { fa: "بسته‌های منتشرشده", en: "Published packages" },
  listEmptyTitle: { fa: "هنوز بسته‌ای منتشر نکرده‌اید", en: "You haven't published a package yet" },
  listEmptyBody: { fa: "دستور بالا را بزنید و بسته‌تان را منتشر کنید؛ این‌جا نشان داده می‌شود.", en: "Run the command above and publish; your package shows up here." },
  colPackage: { fa: "بسته", en: "Package" },
  colKind: { fa: "نوع", en: "Kind" },
  colVersions: { fa: "نسخه‌ها", en: "Versions" },
  colSize: { fa: "حجم", en: "Size" },
  versions: { fa: "{n} نسخه", en: "{n} versions" },
  versionsTitle: { fa: "نسخه‌های «{name}»", en: "Versions of “{name}”" },
  deleteVersion: { fa: "پاک کردن این نسخه", en: "Delete this version" },
  deleteVersionTitle: { fa: "نسخه {version} از «{name}» پاک شود؟", en: "Delete version {version} of “{name}”?" },
  deleteVersionBody: { fa: "برنامه‌هایی که همین نسخه را نصب می‌کنند دیگر پیدایش نمی‌کنند.", en: "Apps that install exactly this version will no longer find it." },
  versionDeleted: { fa: "نسخه {version} پاک شد.", en: "Version {version} deleted." },
  noVersions: { fa: "نسخه‌ای ندارد.", en: "No versions." },
  usage: { fa: "حجم بسته‌های شما: {size}", en: "Your packages use {size}" },
  fileNpmrc: { fa: "یا این را در فایل «.npmrc» بگذارید", en: "Or put this in .npmrc" },
  filePypirc: { fa: "یا این را در فایل «.pypirc» بگذارید", en: "Or put this in .pypirc" },
  tokensTitle: { fa: "کلیدهای انتشار", en: "Publish keys" },
  tokensHint: { fa: "کلیدی را که دیگر لازم ندارید باطل کنید.", en: "Revoke any key you no longer need." },
  revoke: { fa: "باطل کردن", en: "Revoke" },
  revokeTitle: { fa: "کلید انتشار «{name}» باطل شود؟", en: "Revoke the publish key “{name}”?" },
  revokeBody: { fa: "هر جایی که با این کلید بسته منتشر یا نصب می‌کند، از همین حالا متوقف می‌شود.", en: "Anything publishing or installing with this key stops right away." }
} satisfies Record<string, Bi>;

// ── team ─────────────────────────────────────────────────────────────────────

export const MY_TEAM = {
  membersTitle: { fa: "اعضای این فضا", en: "Members of this space" },
  membersHint: { fa: "هر کس نقشی دارد که می‌گوید چه کاری می‌تواند بکند.", en: "Each person has a role that says what they can do." },
  invite: { fa: "دعوت هم‌تیمی", en: "Invite a teammate" },
  inviteTitle: { fa: "دعوت به «{name}»", en: "Invite to “{name}”" },
  inviteHint: { fa: "ایمیل یا نام کاربری کسی را بنویسید که می‌خواهید با شما کار کند.", en: "Write the email or username of the person you want to work with." },
  who: { fa: "ایمیل یا نام کاربری", en: "Email or username" },
  whoRequired: { fa: "ایمیل یا نام کاربری را بنویسید.", en: "Write an email or username." },
  role: { fa: "نقش", en: "Role" },
  roleHint: { fa: "نقشی بالاتر از نقش خودتان نمی‌توانید بدهید.", en: "You can't give a role above your own." },
  send: { fa: "دعوت کن", en: "Invite" },
  invited: { fa: "{who} دعوت شد.", en: "{who} was invited." },
  accepted: { fa: "به فضای تازه پیوستید.", en: "You joined the space." },
  inviteLink: { fa: "لینک دعوت", en: "Invite link" },
  inviteLinkHint: { fa: "این شخص هنوز حساب ندارد. این لینک را برایش بفرستید؛ پس از ورود با همان ایمیل، به فضا می‌پیوندد. لینک فقط همین یک بار نشان داده می‌شود.", en: "This person has no account yet. Send them this link; after signing in with that email they join the space. The link is shown only once." },
  membersEmpty: { fa: "فعلاً فقط خودتان هستید", en: "It's just you for now" },
  membersEmptyBody: { fa: "هم‌تیمی‌ها را دعوت کنید تا با هم کار کنید.", en: "Invite teammates to work together." },
  you: { fa: "شما", en: "You" },
  changeRole: { fa: "تغییر نقش", en: "Change role" },
  roleChanged: { fa: "نقش {name} «{role}» شد.", en: "{name} is now “{role}”." },
  removeMember: { fa: "برداشتن از فضا", en: "Remove from space" },
  removeTitle: { fa: "{name} از این فضا برداشته شود؟", en: "Remove {name} from this space?" },
  removeBody: { fa: "دیگر به چیزهای این فضا دسترسی ندارد. حسابش پاک نمی‌شود.", en: "They lose access to this space. Their account isn't deleted." },
  removeYes: { fa: "بله، بردار", en: "Yes, remove" },
  memberRemoved: { fa: "{name} برداشته شد.", en: "{name} was removed." },
  leave: { fa: "ترک این فضا", en: "Leave this space" },
  leaveTitle: { fa: "از «{name}» بیرون بروید؟", en: "Leave “{name}”?" },
  leaveBody: { fa: "دیگر به چیزهای این فضا دسترسی ندارید، مگر دوباره دعوتتان کنند.", en: "You lose access to this space unless someone invites you again." },
  leaveYes: { fa: "بله، بیرون برو", en: "Yes, leave" },
  invitesTitle: { fa: "دعوت‌های باز", en: "Open invites" },
  invitesHint: { fa: "کسانی که دعوت شده‌اند ولی هنوز نیامده‌اند.", en: "People who were invited but haven't joined yet." },
  cancelInvite: { fa: "لغو دعوت", en: "Cancel invite" },
  inviteCancelled: { fa: "دعوت لغو شد.", en: "Invite cancelled." },
  expires: { fa: "اعتبار تا", en: "Valid until" },
  personalNote: { fa: "این فضای شخصی شماست و فقط مال خودتان است. برای کار گروهی یک فضای تیمی بسازید.", en: "This is your personal space, just for you. Make a team space to work with others." },
  colMember: { fa: "عضو", en: "Member" },
  colRole: { fa: "نقش", en: "Role" },
  colJoined: { fa: "از کی", en: "Since" },
  listLabel: { fa: "اعضا", en: "Members" },
  // space settings
  spaceTitle: { fa: "این فضا", en: "This space" },
  rename: { fa: "تغییر نام فضا", en: "Rename space" },
  renamed: { fa: "نام فضا عوض شد.", en: "The space was renamed." },
  deleteSpace: { fa: "پاک کردن این فضا", en: "Delete this space" },
  deleteSpaceDesc: { fa: "همه دامنه‌ها، فایل‌ها، بسته‌ها و کلیدهای این فضا برای همیشه پاک می‌شوند.", en: "Every domain, file, package and key in this space is deleted for good." },
  deleteSpaceTitle: { fa: "فضای «{name}» برای همیشه پاک شود؟", en: "Delete the space “{name}” for good?" },
  spaceDeleted: { fa: "فضای «{name}» پاک شد.", en: "Space “{name}” deleted." }
} satisfies Record<string, Bi>;

// ── API keys ─────────────────────────────────────────────────────────────────

export const MY_TOKENS = {
  title: { fa: "کلیدهای برنامه من", en: "My API keys" },
  hint: { fa: "اسکریپت‌ها و ابزارها با این کلیدها، بدون رمز شما، کار می‌کنند. هر کلید فقط به همین فضا می‌رسد.", en: "Scripts and tools use these keys instead of your password. Each key only reaches this space." },
  create: { fa: "ساخت کلید برنامه", en: "Make an API key" },
  createTitle: { fa: "ساخت کلید برنامه تازه", en: "New API key" },
  stepName: { fa: "برای چه کاری؟", en: "What's it for?" },
  stepNameHint: { fa: "یک نام بنویسید تا بعداً بدانید این کلید کجا استفاده می‌شود.", en: "Name it so you know later where it's used." },
  namePlaceholder: { fa: "مثلاً «به‌روز کردن رکورد از سرور خانه»", en: "For example “update a record from my home server”" },
  nameRequired: { fa: "یک نام بنویسید.", en: "Write a name." },
  stepScopes: { fa: "چه کارهایی بکند؟", en: "What can it do?" },
  stepScopesHint: { fa: "کمترین چیزی را که لازم است بدهید. کلید هرگز بیشتر از خود شما اختیار ندارد.", en: "Give the least it needs. A key never has more power than you." },
  scopesRequired: { fa: "دست‌کم یک کار را انتخاب کنید.", en: "Pick at least one thing." },
  viewerOnly: { fa: "نقش شما در این فضا «فقط دیدن» است، پس کلید هم فقط می‌تواند ببیند.", en: "You're a viewer here, so the key can only look too." },
  stepLimits: { fa: "تا کی و از کجا؟", en: "Until when, and from where?" },
  expiry: { fa: "تا کی کار کند؟", en: "How long should it work?" },
  e_30: { fa: "۳۰ روز", en: "30 days" },
  e_90: { fa: "۹۰ روز", en: "90 days" },
  e_365: { fa: "یک سال", en: "1 year" },
  e_never: { fa: "بدون تاریخ پایان", en: "No end date" },
  ipAllow: { fa: "فقط از این نشانی‌ها (اختیاری)", en: "Only from these addresses (optional)" },
  ipAllowHint: { fa: "نشانی IP یا محدوده، مثل «203.0.113.7» یا «10.0.0.0/8». خالی یعنی از همه‌جا.", en: "An IP or range, like 203.0.113.7 or 10.0.0.0/8. Empty means anywhere." },
  ipBad: { fa: "این شبیه نشانی IP یا محدوده نیست.", en: "That isn't an IP address or range." },
  secretTitle: { fa: "کلید برنامه ساخته شد", en: "API key made" },
  secretBody: { fa: "این کلید فقط همین یک بار نشان داده می‌شود. همین حالا کپی کنید و جای امنی بگذارید.", en: "This key is shown only once. Copy it now and keep it somewhere safe." },
  secret: { fa: "کلید", en: "Key" },
  emptyTitle: { fa: "هنوز کلید برنامه‌ای ندارید", en: "No API keys yet" },
  emptyBody: { fa: "برای اسکریپتی که خودکار رکورد عوض می‌کند یا فایل می‌گذارد، یک کلید بسازید.", en: "Make a key for a script that changes records or uploads files on its own." },
  colName: { fa: "نام", en: "Name" },
  colScopes: { fa: "کارها", en: "Can do" },
  colExpires: { fa: "تا", en: "Until" },
  colUsed: { fa: "آخرین استفاده", en: "Last used" },
  neverUsed: { fa: "هنوز استفاده نشده", en: "Not used yet" },
  noEnd: { fa: "بدون پایان", en: "No end" },
  expired: { fa: "تمام شده", en: "Expired" },
  revoke: { fa: "باطل کردن", en: "Revoke" },
  revokeTitle: { fa: "کلید «{name}» باطل شود؟", en: "Revoke the key “{name}”?" },
  revokeBody: { fa: "هر اسکریپتی که با این کلید کار می‌کند، از همین حالا متوقف می‌شود.", en: "Any script using this key stops working right away." },
  revokeYes: { fa: "بله، باطل کن", en: "Yes, revoke" },
  revoked: { fa: "کلید «{name}» باطل شد.", en: "Key “{name}” revoked." },
  listLabel: { fa: "کلیدهای برنامه", en: "API keys" },
  next: { fa: "بعدی", en: "Next" }
} satisfies Record<string, Bi>;

// ── activity ─────────────────────────────────────────────────────────────────

export const MY_ACTIVITY = {
  title: { fa: "تاریخچه این فضا", en: "This space's activity" },
  hint: { fa: "هر تغییری که در این فضا انجام شده، با نام کسی که انجامش داده.", en: "Every change in this space, with who made it." },
  emptyTitle: { fa: "هنوز اتفاقی نیفتاده", en: "Nothing has happened yet" },
  emptyBody: { fa: "وقتی دامنه، فایل یا کلیدی بسازید، این‌جا نوشته می‌شود.", en: "When you make a domain, file or key, it's written here." },
  more: { fa: "نمایش موارد قدیمی‌تر", en: "Show older" },
  onBehalf: { fa: "مدیر سامانه به‌جای {name}", en: "System admin, viewing as {name}" },
  listLabel: { fa: "تاریخچه", en: "Activity" },
  colWhat: { fa: "چه شد", en: "What happened" },
  colWhen: { fa: "کی", en: "When" },
  colResult: { fa: "نتیجه", en: "Result" }
} satisfies Record<string, Bi>;

// ── view as (docs/43 §2) ─────────────────────────────────────────────────────

export const VIEW_AS = {
  bar: { fa: "دارید فضای «{name}» را به‌جای صاحبش می‌بینید.", en: "You're viewing “{name}” as its owner sees it." },
  readOnly: { fa: "فقط دیدن؛ هیچ چیز تغییر نمی‌کند.", en: "Look only; nothing changes." },
  canWrite: { fa: "تغییرها به نام شما ثبت می‌شوند.", en: "Changes are recorded under your name." },
  endsIn: { fa: "تا {time}", en: "until {time}" },
  stop: { fa: "پایان دیدن به‌جای", en: "Stop viewing as" },
  ended: { fa: "دیدن به‌جای تمام شد.", en: "View as ended." },
  expired: { fa: "زمان دیدن به‌جای تمام شد.", en: "View-as time is over." }
} satisfies Record<string, Bi>;

// ── admin side: «کاربران و دسترسی» (docs/43 §2, §4) ───────────────────────────

export const TENANCY = {
  // tabs
  tabPlans: { fa: "بسته‌ها", en: "Plans" },
  tabPlansHint: { fa: "هر بسته می‌گوید کاربر چه امکاناتی دارد و تا چه سقفی.", en: "Each plan says what a user gets, and up to what limit." },
  tabWorkspaces: { fa: "فضاهای کاری", en: "Workspaces" },
  tabWorkspacesHint: { fa: "فضای هر کاربر و تیم، با مصرف و بسته‌اش.", en: "Each user's and team's space, with its usage and plan." },
  tabSignups: { fa: "ثبت‌نام‌های در انتظار", en: "Pending sign-ups" },
  tabSignupsHint: { fa: "کسانی که ثبت‌نام کرده‌اند و منتظر تأیید شما هستند.", en: "People who signed up and wait for your approval." },
  tabSettings: { fa: "تنظیمات فضای من", en: "My space settings" },
  tabSettingsHint: { fa: "روشن کردن «فضای من»، روش ثبت‌نام و بسته پیش‌فرض.", en: "Turn on My space, choose how sign-up works and the default plan." },
  // plans
  plans: { fa: "بسته‌ها", en: "Plans" },
  plansHint: { fa: "هر فضای کاری یک بسته دارد. سقف خالی یعنی بی‌سقف.", en: "Every workspace has one plan. An empty limit means unlimited." },
  newPlan: { fa: "ساخت بسته تازه", en: "New plan" },
  edit: { fa: "تغییر", en: "Edit" },
  editPlan: { fa: "تغییر بسته «{name}»", en: "Edit plan “{name}”" },
  createPlan: { fa: "ساخت بسته", en: "Create plan" },
  plansEmptyTitle: { fa: "هنوز بسته‌ای نیست", en: "No plans yet" },
  plansEmptyBody: { fa: "یک بسته بسازید تا بگویید کاربران چه چیزهایی و تا چه اندازه داشته باشند.", en: "Make a plan to say what users get and how much." },
  nameFa: { fa: "نام فارسی", en: "Persian name" },
  nameEn: { fa: "نام انگلیسی", en: "English name" },
  nameRequired: { fa: "دست‌کم نام فارسی را بنویسید.", en: "Write at least the Persian name." },
  description: { fa: "توضیح کوتاه", en: "Short description" },
  isDefault: { fa: "بسته پیش‌فرض برای کاربران تازه", en: "Default plan for new users" },
  defaultBadge: { fa: "پیش‌فرض", en: "Default" },
  features: { fa: "امکانات", en: "Features" },
  quotas: { fa: "سقف‌ها", en: "Limits" },
  unlimited: { fa: "بی‌سقف", en: "Unlimited" },
  recordTypes: { fa: "نوع رکوردهای مجاز", en: "Allowed record types" },
  recordTypesHint: { fa: "خالی یعنی همه نوع‌ها.", en: "Empty means every type." },
  planSaved: { fa: "بسته «{name}» ذخیره شد.", en: "Plan “{name}” saved." },
  planDeleteTitle: { fa: "بسته «{name}» پاک شود؟", en: "Delete the plan “{name}”?" },
  planDeleteBody: { fa: "فقط بسته‌ای پاک می‌شود که هیچ فضایی از آن استفاده نکند.", en: "Only a plan no workspace uses can be deleted." },
  inUse: { fa: "{n} فضا", en: "{n} spaces" },
  colInUse: { fa: "استفاده در", en: "Used by" },
  featuresOn: { fa: "{n} امکان روشن", en: "{n} features on" },
  // workspaces
  workspaces: { fa: "فضاهای کاری", en: "Workspaces" },
  workspacesHint: { fa: "برای دیدن جزئیات، تغییر بسته یا دیدن به‌جای صاحب فضا، روی آن بزنید.", en: "Tap one to see details, change its plan or view it as its owner." },
  search: { fa: "جست‌وجوی نام یا صاحب فضا", en: "Search a name or owner" },
  filterAll: { fa: "همه", en: "All" },
  filterActive: { fa: "فعال", en: "Active" },
  filterSuspended: { fa: "بسته‌شده", en: "Paused" },
  wsEmptyTitle: { fa: "هنوز فضای کاری‌ای نیست", en: "No workspaces yet" },
  wsEmptyBody: { fa: "وقتی «فضای من» روشن باشد، هر کاربر تازه یک فضای شخصی می‌گیرد.", en: "Once My space is on, every new user gets a personal space." },
  wsNoMatch: { fa: "فضایی با این نام پیدا نشد.", en: "No workspace matches that." },
  colSpace: { fa: "فضا", en: "Space" },
  colOwner: { fa: "صاحب", en: "Owner" },
  colPlan: { fa: "بسته", en: "Plan" },
  colUsage: { fa: "مصرف", en: "Usage" },
  colMembers: { fa: "اعضا", en: "Members" },
  colStatus: { fa: "وضعیت", en: "Status" },
  active: { fa: "فعال", en: "Active" },
  suspendedPill: { fa: "بسته‌شده", en: "Paused" },
  details: { fa: "جزئیات", en: "Details" },
  changePlan: { fa: "تغییر بسته یا استثنا", en: "Change plan or exceptions" },
  changePlanTitle: { fa: "بسته «{name}»", en: "Plan of “{name}”" },
  changePlanHint: { fa: "استثنا فقط برای همین فضا، سقفی از بسته را عوض می‌کند.", en: "An exception changes one of the plan's limits for this space only." },
  overrides: { fa: "استثناهای همین فضا", en: "Exceptions for this space" },
  override: { fa: "استثنا", en: "Exception" },
  fromPlan: { fa: "از بسته: {value}", en: "From plan: {value}" },
  planChanged: { fa: "بسته «{name}» عوض شد.", en: "The plan of “{name}” changed." },
  suspend: { fa: "بستن موقت", en: "Pause" },
  resume: { fa: "باز کردن دوباره", en: "Reopen" },
  suspendTitle: { fa: "فضای «{name}» موقتاً بسته شود؟", en: "Pause the space “{name}”?" },
  suspendBody: { fa: "اعضا فقط می‌توانند ببینند؛ دامنه‌ها و فایل‌ها پاک نمی‌شوند و کار می‌کنند.", en: "Members can only look; domains and files stay and keep working." },
  suspendYes: { fa: "بله، ببند", en: "Yes, pause" },
  suspended: { fa: "فضای «{name}» بسته شد.", en: "“{name}” is paused." },
  resumed: { fa: "فضای «{name}» دوباره باز شد.", en: "“{name}” is open again." },
  remove: { fa: "پاک کردن یا انتقال", en: "Delete or transfer" },
  removeTitle: { fa: "با فضای «{name}» چه شود؟", en: "What should happen to “{name}”?" },
  removeBody: { fa: "این فضا برای همیشه پاک می‌شود. منابعش را می‌توانید پاک کنید یا به سامانه بدهید.", en: "This space is removed for good. You can delete its resources or hand them to the system." },
  modeDelete: { fa: "همه منابعش هم پاک شود", en: "Delete its resources too" },
  modeDeleteBody: { fa: "دامنه‌ها، فایل‌ها، بسته‌ها و کلیدهایش پاک می‌شوند.", en: "Its domains, files, packages and keys are deleted." },
  modeTransfer: { fa: "منابعش به سامانه برسد", en: "Hand its resources to the system" },
  modeTransferBody: { fa: "منابع می‌مانند و فقط شما مدیرشان هستید.", en: "Resources stay, and only admins manage them." },
  removed: { fa: "فضای «{name}» پاک شد.", en: "Space “{name}” removed." },
  viewAs: { fa: "دیدن به‌جای صاحب فضا", en: "View as owner" },
  viewAsTitle: { fa: "فضای «{name}» را به‌جای صاحبش ببینید؟", en: "View “{name}” as its owner?" },
  viewAsBody: { fa: "۳۰ دقیقه فضای او را همان‌طور که او می‌بیند می‌بینید. این کار در تاریخچه او هم ثبت می‌شود.", en: "For 30 minutes you see the space as they do. It's recorded in their history too." },
  viewAsWrite: { fa: "اجازه تغییر هم بده (فقط برای کمک فوری)", en: "Allow changes too (for urgent help only)" },
  viewAsYes: { fa: "بله، ببین", en: "Yes, view" },
  // detail
  detailTitle: { fa: "فضای «{name}»", en: "Space “{name}”" },
  members: { fa: "اعضا", en: "Members" },
  resources: { fa: "منابع", en: "Resources" },
  resourcesEmpty: { fa: "این فضا هنوز منبعی ندارد.", en: "This space has no resources yet." },
  usage: { fa: "مصرف", en: "Usage" },
  transfer: { fa: "انتقال مالکیت", en: "Transfer ownership" },
  transferTitle: { fa: "«{name}» به کدام فضا برود؟", en: "Move “{name}” to which space?" },
  transferHint: { fa: "مالکیت این منبع به فضای انتخاب‌شده می‌رسد.", en: "This resource will belong to the chosen space." },
  toSystem: { fa: "سامانه (فقط مدیرها)", en: "The system (admins only)" },
  transferYes: { fa: "منتقل کن", en: "Transfer" },
  transferred: { fa: "مالکیت «{name}» منتقل شد.", en: "“{name}” was transferred." },
  kind_dns_zone: { fa: "دامنه", en: "Domain" },
  kind_s3_bucket: { fa: "پوشه فایل", en: "File folder" },
  kind_s3_identity: { fa: "کلید فایل", en: "File key" },
  kind_bucket_domain: { fa: "دامنه پوشه", en: "Folder domain" },
  kind_npm_scope: { fa: "بسته‌های npm", en: "npm scope" },
  kind_pypi_index: { fa: "بسته‌های پایتون", en: "Python index" },
  kind_api_token: { fa: "کلید برنامه", en: "API key" },
  kind_other: { fa: "منبع", en: "Resource" },
  // sign-ups
  signupsTitle: { fa: "ثبت‌نام‌های در انتظار", en: "Pending sign-ups" },
  signupsHint: { fa: "هر کدام را تأیید کنید تا حسابش باز شود، یا رد کنید.", en: "Approve each one to open their account, or reject it." },
  signupsEmptyTitle: { fa: "کسی منتظر نیست", en: "Nobody is waiting" },
  signupsEmptyBody: { fa: "وقتی کسی ثبت‌نام کند، این‌جا می‌آید تا تأییدش کنید.", en: "When someone signs up, they show up here for you to approve." },
  signupsOff: { fa: "ثبت‌نام با تأیید مدیر خاموش است. از تنظیمات فضای من روشنش کنید.", en: "Sign-up with approval is off. Turn it on in My space settings." },
  approve: { fa: "تأیید", en: "Approve" },
  reject: { fa: "رد کردن", en: "Reject" },
  approveTitle: { fa: "حساب {name} باز شود؟", en: "Open {name}'s account?" },
  approveBody: { fa: "یک فضای شخصی با بسته انتخاب‌شده برایش ساخته می‌شود.", en: "A personal space with the chosen plan is made for them." },
  approveYes: { fa: "بله، تأیید کن", en: "Yes, approve" },
  rejectTitle: { fa: "ثبت‌نام {name} رد شود؟", en: "Reject {name}'s sign-up?" },
  rejectBody: { fa: "حسابی ساخته نمی‌شود. اگر بخواهد، می‌تواند دوباره ثبت‌نام کند.", en: "No account is made. They can sign up again if they want." },
  rejectYes: { fa: "بله، رد کن", en: "Yes, reject" },
  approved: { fa: "حساب {name} باز شد.", en: "{name}'s account is open." },
  rejected: { fa: "ثبت‌نام {name} رد شد.", en: "{name}'s sign-up was rejected." },
  colPerson: { fa: "کاربر", en: "Person" },
  colWhen: { fa: "کی", en: "When" },
  plan: { fa: "بسته", en: "Plan" },
  // settings
  settingsTitle: { fa: "تنظیمات فضای من", en: "My space settings" },
  settingsHint: { fa: "این تنظیمات می‌گوید کاربران چطور حساب بگیرند و «فضای من» چطور کار کند.", en: "These say how people get accounts and how My space works." },
  enabled: { fa: "«فضای من» روشن باشد", en: "Turn on My space" },
  enabledHint: { fa: "خاموش که باشد، پنل دقیقاً مثل قبل کار می‌کند.", en: "When off, the panel works exactly as before." },
  signup: { fa: "کاربران تازه چطور حساب بگیرند؟", en: "How do new people get an account?" },
  signup_off: { fa: "فقط با دعوت شما", en: "Only by your invite" },
  signup_off_body: { fa: "هیچ‌کس خودش ثبت‌نام نمی‌کند. امن‌ترین حالت.", en: "Nobody signs up alone. The safest choice." },
  signup_approval: { fa: "ثبت‌نام با تأیید شما", en: "Sign-up with your approval" },
  signup_approval_body: { fa: "هر کسی ثبت‌نام می‌کند، ولی تا شما تأیید نکنید وارد نمی‌شود.", en: "Anyone can sign up, but can't enter until you approve." },
  signup_open: { fa: "ثبت‌نام آزاد", en: "Open sign-up" },
  signup_open_body: { fa: "هر کسی ثبت‌نام کند فوراً یک فضا با بسته پیش‌فرض می‌گیرد.", en: "Anyone who signs up gets a space with the default plan right away." },
  defaultPlan: { fa: "بسته پیش‌فرض کاربران تازه", en: "Default plan for new people" },
  noDefault: { fa: "هیچ (مدیر انتخاب کند)", en: "None (an admin picks)" },
  verifyDomains: { fa: "اثبات مالکیت دامنه لازم باشد", en: "Require proof of domain ownership" },
  verifyDomainsHint: { fa: "بدون آن، هر کسی می‌تواند دامنه دیگران را این‌جا بیاورد. فقط برای دامنه‌های داخلی خاموشش کنید.", en: "Without it, anyone can add someone else's domain. Turn off only for internal domains." },
  adminLocal: { fa: "بخش «مدیریت سرور» فقط از همین شبکه باز شود", en: "Open Server admin only from this network" },
  adminLocalHint: { fa: "مدیریت سرور فقط از همین سرور یا شبکه خصوصی (VPN) باز می‌شود.", en: "Server admin only opens from this server or the private network (VPN)." },
  settingsSaved: { fa: "تنظیمات ذخیره شد.", en: "Settings saved." },
  settingsMissing: { fa: "این تنظیمات روی نسخه فعلی سرور نیست. پیشکار را به‌روز کنید.", en: "These settings aren't on this server version. Update Pishkar." },
  verifyOffTitle: { fa: "اثبات مالکیت دامنه خاموش شود؟", en: "Turn off domain proof?" },
  verifyOffBody: { fa: "کاربران می‌توانند هر دامنه‌ای، حتی مال دیگران، را اضافه کنند.", en: "Users can add any domain, even someone else's." },
  missing: { fa: "این بخش روی نسخه فعلی سرور نیست. پیشکار را به‌روز کنید.", en: "This part isn't on this server version yet. Update Pishkar." }
} satisfies Record<string, Bi>;

// ── plan errors with numbers (docs/43 §3: quota_exceeded {quota, limit, used}, feature_disabled) ──

/** `used` / `limit` in the limit's own unit (bytes or a count). */
export function formatQuota(language: Language, key: string, value: number): string {
  return QUOTA_WORDS[key as QuotaKey]?.unit === "bytes" ? formatBytes(value, language) : formatNumber(value, language);
}

/**
 * The plan sentence for `quota_exceeded` (naming the limit and used/limit when the server sends them)
 * and `feature_disabled` (naming the feature). Null for any other error, or a quota error without a
 * `quota` key (the S3 engine's own bucket limit keeps its catalog sentence).
 */
export function planErrorSentence(language: Language, code: string, extra: Record<string, unknown> | undefined, detail = ""): string | null {
  const data = extra ?? {};
  // The S3 engine reports a full space as `engine_error` carrying its own `QuotaExceeded` message (docs/43 §0.1).
  if (code === "engine_error" && /QuotaExceeded/i.test(detail)) return say(language, MY.quotaFullShort, { label: pick(language, QUOTA_WORDS.s3_bytes.label) });
  if (code === "quota_exceeded" || code === "QuotaExceeded") {
    const key = typeof data.quota === "string" ? data.quota : "";
    if (!key) return null;
    const limit = typeof data.limit === "number" ? data.limit : null;
    const used = typeof data.used === "number" ? data.used : null;
    const label = quotaLabel(language, key);
    if (limit !== null && used !== null) return say(language, MY.quotaFull, { label, used: formatQuota(language, key, used), limit: formatQuota(language, key, limit) });
    return say(language, MY.quotaFullShort, { label });
  }
  if (code === "feature_disabled") {
    const word = FEATURE_WORDS[(typeof data.feature === "string" ? data.feature : "") as FeatureKey];
    return word ? say(language, MY.featureOff, { feature: pick(language, word.label) }) : null;
  }
  return null;
}
