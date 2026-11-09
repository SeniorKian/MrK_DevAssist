import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Box, Button, Card, CardActionArea, Checkbox, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel,
  FormGroup, Grid, MenuItem, Stack, Switch, TextField, ToggleButton, ToggleButtonGroup, Typography, useMediaQuery, useTheme
} from "@mui/material";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import PowerSettingsNewRoundedIcon from "@mui/icons-material/PowerSettingsNewRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import LockOpenRoundedIcon from "@mui/icons-material/LockOpenRounded";
import VerifiedUserRoundedIcon from "@mui/icons-material/VerifiedUserRounded";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import NetworkCheckRoundedIcon from "@mui/icons-material/NetworkCheckRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { CONFIRM_WORDS, matchesConfirmation, pick, reasonFor, say, type Bi } from "./copy";
import {
  ActionWizard, CopyField, DangerZone, Duration, EmptyState, FriendlyError, HelpTip, KeyValueList, Ltr, NoAccess, Notice, NumberInput,
  DurationInput, RelativeTime, ResponsiveList, SectionCard, StatGrid, StatTile, StatusPill, TestResult, useConfirmAction, useKit,
  useUndoSnackbar, formatDuration, RegistrySettings, type TestOutcome, type WizardStep
} from "./kit";
import { formatNumber } from "./format";
import type { Language } from "./i18n";

/**
 * Security › «دیوار آتش» (docs/32 §3.1, docs/33 §4.2).
 * Simple: status in plain words (off / watching only / protecting), a guided «روشن کردن محافظت» flow
 * (connect the helper → practice first → always-allowed list → typed «فعال کن»), blocked addresses
 * with unblock / always allow, a manual block form, the always-allowed list, and a humanized history.
 * Advanced: rules (thresholds, windows, durations), the exact ruleset preview, helper connection,
 * every firewall setting, and «آزاد کردن همه».
 */

type Mode = "off" | "dry_run" | "enforce";
type AllowEntry = { cidr: string; note: string; added_at?: number; auto?: boolean };
type FwStatus = {
  configured: boolean;
  source: "panel" | "env" | null;
  url: string | null;
  reachable: boolean | null;
  last_checked_at: number | null;
  last_error: string | null;
  mode: Mode;
  helper: { version?: string; nft_available?: boolean; force_dry_run?: boolean; mode?: Mode; effective_mode?: Mode; last_error?: string | null } | null;
  counts: { active_blocks: number; simulated_blocks: number; rules_enabled: number; decisions_24h: number; allowlist: number };
  in_sync: boolean;
  last_poll_at: number | null;
  last_apply_at: number | null;
  last_apply_error: string | null;
  sources: Record<string, { ok?: boolean; error?: string | null; lines?: number; signals?: number }> | null;
};
type FwSettings = { mode: Mode; allowlist: AllowEntry[]; allowlist_private: boolean; allow_private_blocks: boolean; default_ban_seconds: number; max_ban_seconds: number };
type Block = { id: string; cidr: string; origin: string; rule_id: string | null; reason: string; simulated: boolean; created_at: number; expires_at: number | null };
type Rule = { id: string; name: string; signal_kinds: string[]; threshold: number; window_seconds: number; ban_seconds: number | null; enabled: boolean; builtin: boolean };
type Decision = { id: number; occurred_at: number; action: string; ip: string | null; rule_id: string | null; mode: string; reason: string; details: Record<string, unknown> };
type Preview = { mode: Mode; would_apply: { allow: string[]; blocks: { cidr: string; expires_at: number | null }[] }; ruleset: string; simulated: Block[] };

const API = "/api/v1/firewall";
const COMPOSE = "docker compose -f deploy/appliance/compose.production.yaml";
const SIGNALS = ["ssh_failed_password", "ssh_invalid_user", "mrk_login_failure", "http_401", "http_403", "http_404", "http_sensitive_path"];

const COPY = {
  unavailable: { fa: "دیوار آتش روی نسخه فعلی سرور نیست. پیشکار را به‌روز کنید.", en: "The firewall isn't on this server version. Update Pishkar." },
  refresh: { fa: "تازه کردن", en: "Refresh" },
  // status
  statusTitle: { fa: "وضعیت دیوار آتش", en: "Firewall status" },
  modeOff: { fa: "خاموش", en: "Off" },
  modeOffBody: { fa: "دیوار آتش کاری نمی‌کند و حمله‌ها ثبت نمی‌شوند.", en: "The firewall does nothing and attacks aren't recorded." },
  modeWatch: { fa: "فقط تماشا", en: "Watching only" },
  modeWatchBody: { fa: "حمله‌ها ثبت می‌شوند ولی هیچ نشانی بسته نمی‌شود.", en: "Attacks are recorded, but no address is blocked." },
  modeProtect: { fa: "در حال محافظت", en: "Protecting" },
  modeProtectBody: { fa: "نشانی‌هایی که به سرور حمله کنند، خودکار مسدود می‌شوند.", en: "Addresses that attack the server are blocked automatically." },
  current: { fa: "حالت فعلی", en: "Current" },
  choose: { fa: "انتخاب", en: "Choose" },
  wouldBlock: { fa: "در ۲۴ ساعت گذشته {n} تصمیم گرفته شد.", en: "{n} decisions in the last 24 hours." },
  notPaired: { fa: "نگهبان دیوار آتش هنوز وصل نشده.", en: "The firewall helper isn't connected yet." },
  notPairedBody: { fa: "نگهبان برنامه کوچکی کنار پیشکار است که نشانی‌ها را روی خود سرور می‌بندد. «روشن کردن محافظت» قدم‌به‌قدم کمکتان می‌کند.", en: "The helper is a small program next to Pishkar that blocks addresses on the server itself. “Turn on protection” guides you step by step." },
  unreachable: { fa: "نگهبان دیوار آتش جواب نمی‌دهد؛ روشن بودنش را روی سرور بررسی کنید.", en: "The firewall helper isn't answering; check that it's running on the server." },
  forcedPractice: { fa: "روی سرور فقط حالت تمرین مجاز شده؛ حتی در «در حال محافظت» چیزی بسته نمی‌شود.", en: "The server only allows practice mode; nothing is blocked even when “Protecting”." },
  noNft: { fa: "دیوار آتش سرور در دسترس نیست؛ فعلاً فقط «فقط تماشا» کار می‌کند.", en: "The server firewall isn't available; only “Watching only” works for now." },
  outOfSync: { fa: "آخرین تغییر هنوز روی سرور اعمال نشده؛ چند ثانیه بعد تازه کنید.", en: "The last change isn't applied on the server yet; refresh in a few seconds." },
  turnOn: { fa: "روشن کردن محافظت", en: "Turn on protection" },
  blockedNow: { fa: "مسدود الان", en: "Blocked now" },
  practiceBlocks: { fa: "در تمرین بسته می‌شد", en: "Would block (practice)" },
  decisions: { fa: "تصمیم‌ها در ۲۴ ساعت", en: "Decisions in 24 h" },
  rulesOn: { fa: "قاعده روشن", en: "Rules on" },
  // mode change
  toOffTitle: { fa: "دیوار آتش خاموش شود؟", en: "Turn the firewall off?" },
  toOffBody: { fa: "همه مسدودی‌ها روی سرور برداشته می‌شوند و حمله‌ها دیگر ثبت نمی‌شوند.", en: "All blocks are lifted on the server and attacks are no longer recorded." },
  toOffYes: { fa: "بله، خاموش کن", en: "Yes, turn off" },
  toWatchTitle: { fa: "فقط تماشا شود؟", en: "Switch to watching only?" },
  toWatchBody: { fa: "حمله‌ها ثبت می‌شوند ولی نشانی‌ای بسته نمی‌شود. مسدودی‌های فعلی روی سرور برداشته می‌شوند.", en: "Attacks are recorded, but nothing is blocked. Current blocks are lifted on the server." },
  toWatchYes: { fa: "بله، فقط تماشا", en: "Yes, watch only" },
  modeSaved: { fa: "حالت دیوار آتش شد: {mode}", en: "The firewall is now: {mode}" },
  // wizard
  wizardTitle: { fa: "روشن کردن محافظت", en: "Turn on protection" },
  stepHelper: { fa: "نگهبان", en: "Helper" },
  stepHelperHint: { fa: "اول نگهبان دیوار آتش باید روی سرور روشن و به پنل وصل باشد.", en: "First, the firewall helper must run on the server and be connected to the panel." },
  helperOk: { fa: "نگهبان وصل است و جواب می‌دهد.", en: "The helper is connected and answering." },
  helperEnv: { fa: "اتصال نگهبان در فایل Compose تنظیم شده؛ اگر جواب نمی‌دهد همان‌جا را بررسی کنید.", en: "The helper connection is set in the Compose file; if it isn't answering, check there." },
  pair1: { fa: "۱. این دستور را روی سرور اجرا کنید تا نگهبان روشن شود:", en: "1. Run this on the server to start the helper:" },
  pair2: { fa: "۲. کد اتصال را از گزارش نگهبان بردارید:", en: "2. Get the pairing code from the helper's log:" },
  pair3: { fa: "۳. کد را این‌جا بچسبانید:", en: "3. Paste the code here:" },
  commandStart: { fa: "دستور روشن کردن", en: "Start command" },
  commandKey: { fa: "دستور دیدن کد", en: "Command to see the code" },
  key: { fa: "کد اتصال", en: "Pairing code" },
  url: { fa: "آدرس نگهبان", en: "Helper address" },
  urlHint: { fa: "معمولاً لازم نیست عوضش کنید.", en: "You usually don't need to change this." },
  connect: { fa: "وصل کن", en: "Connect" },
  needKey: { fa: "کد اتصال را بچسبانید.", en: "Paste the pairing code." },
  stepPractice: { fa: "تمرین", en: "Practice" },
  stepPracticeHint: { fa: "بهتر است چند روز در «فقط تماشا» بماند تا ببینید چه چیزهایی بسته می‌شد.", en: "It's best to stay in “Watching only” for a few days to see what would be blocked." },
  practiceNow: { fa: "الان در «فقط تماشا» است.", en: "It's in “Watching only” now." },
  practiceStart: { fa: "با «بعدی»، دیوار آتش به «فقط تماشا» می‌رود.", en: "“Next” switches the firewall to “Watching only”." },
  previewSummary: { fa: "اگر الان فعال شود: {blocks} نشانی بسته می‌شود و {allow} نشانی همیشه مجاز می‌ماند.", en: "If it turns on now: {blocks} addresses get blocked and {allow} stay always allowed." },
  previewNone: { fa: "تا حالا حمله‌ای دیده نشده که بسته شود.", en: "No attack worth blocking has been seen yet." },
  stepAllow: { fa: "همیشه مجاز", en: "Always allowed" },
  stepAllowHint: { fa: "این نشانی‌ها هیچ‌وقت بسته نمی‌شوند. نشانی خود شما خودکار اضافه می‌شود تا از سرور بیرون نمانید.", en: "These addresses are never blocked. Your own address is added automatically so you're never locked out." },
  privateAllowed: { fa: "شبکه‌های داخلی (مثل 192.168.x) همیشه مجاز باشند", en: "Internal networks (like 192.168.x) are always allowed" },
  allowCount: { fa: "{n} نشانی در فهرست همیشه مجاز است.", en: "{n} addresses are on the always-allowed list." },
  stepEnforce: { fa: "فعال کردن", en: "Turn on" },
  stepEnforceHint: { fa: "از این به بعد، نشانی‌هایی که حمله کنند واقعاً بسته می‌شوند.", en: "From now on, attacking addresses will really be blocked." },
  enforceWarn: { fa: "اگر نشانی کسی اشتباهی بسته شد، از «نشانی‌های مسدود» آزادش کنید. مسدودی‌ها خودکار هم تمام می‌شوند.", en: "If someone gets blocked by mistake, unblock them from “Blocked addresses”. Blocks also end on their own." },
  enforceType: { fa: "برای اطمینان، «{word}» را بنویسید:", en: "To be sure, type {word}:" },
  enforceMismatch: { fa: "هنوز با «{word}» یکی نیست.", en: "That doesn't match {word} yet." },
  enforceYes: { fa: "فعال کن", en: "Turn on" },
  enforced: { fa: "دیوار آتش حالا از سرور محافظت می‌کند.", en: "The firewall is now protecting the server." },
  // blocks
  blocksTitle: { fa: "نشانی‌های مسدود", en: "Blocked addresses" },
  blocksHint: { fa: "نشانی‌هایی که الان بسته‌اند یا در تمرین بسته می‌شدند.", en: "Addresses blocked now, or that would be blocked in practice." },
  showPractice: { fa: "نمایش موارد تمرینی", en: "Show practice entries" },
  address: { fa: "نشانی", en: "Address" },
  why: { fa: "چرا", en: "Why" },
  since: { fa: "از کی", en: "Since" },
  until: { fa: "تا کی", en: "Until" },
  forever: { fa: "تا وقتی آزادش کنید", en: "Until you unblock it" },
  kind: { fa: "نوع", en: "Kind" },
  realBlock: { fa: "مسدود", en: "Blocked" },
  practiceBlock: { fa: "فقط در تمرین", en: "Practice only" },
  manual: { fa: "دستی", en: "By hand" },
  unblock: { fa: "آزاد کن", en: "Unblock" },
  alwaysAllow: { fa: "همیشه مجاز کن", en: "Always allow" },
  unblocked: { fa: "{ip} آزاد شد.", en: "{ip} was unblocked." },
  allowedNow: { fa: "{ip} آزاد شد و همیشه مجاز است.", en: "{ip} was unblocked and is now always allowed." },
  fromBlockList: { fa: "از فهرست مسدودها", en: "From the block list" },
  blocksEmpty: { fa: "الان هیچ نشانی‌ای بسته نیست.", en: "No address is blocked right now." },
  blocksEmptyBody: { fa: "اگر نشانی مزاحمی دیدید، می‌توانید خودتان مسدودش کنید.", en: "If you see a troublesome address, you can block it yourself." },
  blockOne: { fa: "مسدود کردن یک نشانی", en: "Block an address" },
  blockTitle: { fa: "مسدود کردن یک نشانی", en: "Block an address" },
  blockAddress: { fa: "نشانی IP یا محدوده IP", en: "IP address or IP range" },
  blockAddressHint: { fa: "مثل 203.0.113.7 یا 203.0.113.0/24", en: "Like 203.0.113.7 or 203.0.113.0/24" },
  blockFor: { fa: "تا کی؟", en: "For how long?" },
  blockReason: { fa: "دلیل", en: "Reason" },
  blockReasonDefault: { fa: "مسدود کردن دستی از پنل", en: "Blocked by hand from the panel" },
  blockPracticeNote: { fa: "تا وقتی «در حال محافظت» نباشد، این مسدودی روی سرور اعمال نمی‌شود.", en: "Until the firewall is “Protecting”, this block isn't applied on the server." },
  blockYes: { fa: "مسدود کن", en: "Block" },
  blockedDone: { fa: "{ip} مسدود شد.", en: "{ip} was blocked." },
  needAddress: { fa: "یک نشانی IP بنویسید؛ مثل 203.0.113.7", en: "Type an IP address, like 203.0.113.7" },
  hour1: { fa: "۱ ساعت", en: "1 hour" },
  day1: { fa: "۱ روز", en: "1 day" },
  week1: { fa: "۷ روز", en: "7 days" },
  month1: { fa: "۳۰ روز", en: "30 days" },
  cancel: { fa: "انصراف", en: "Cancel" },
  // allowlist
  allowTitle: { fa: "فهرست همیشه مجاز", en: "Always-allowed list" },
  allowHint: { fa: "این نشانی‌ها هیچ‌وقت بسته نمی‌شوند؛ مثل نشانی دفتر یا سرورهای خودتان.", en: "These addresses are never blocked, such as your office or your own servers." },
  allowAdd: { fa: "افزودن", en: "Add" },
  allowAddress: { fa: "نشانی یا محدوده IP", en: "Address or IP range" },
  allowNote: { fa: "یادداشت (مثلاً «دفتر»)", en: "Note (for example “Office”)" },
  allowEmpty: { fa: "هنوز نشانی‌ای اضافه نکرده‌اید.", en: "You haven't added any address yet." },
  allowEmptyBody: { fa: "نشانی خود شما وقتی محافظت روشن شود خودکار اضافه می‌شود.", en: "Your own address is added automatically when protection turns on." },
  autoAdded: { fa: "خودکار", en: "Automatic" },
  remove: { fa: "پاک کن", en: "Remove" },
  allowSaved: { fa: "فهرست همیشه مجاز ذخیره شد.", en: "The always-allowed list was saved." },
  allowPrivateBlocks: { fa: "اجازه مسدود کردن نشانی‌های داخلی", en: "Allow blocking internal addresses" },
  allowPrivateBlocksHint: { fa: "خطرناک: ممکن است دستگاه‌های شبکه خودتان بیرون بمانند.", en: "Dangerous: your own network devices may get locked out." },
  removeAllowTitle: { fa: "{ip} از فهرست همیشه مجاز برداشته شود؟", en: "Remove {ip} from the always-allowed list?" },
  removeAllowBody: { fa: "اگر این نشانی حمله کند، ممکن است بسته شود.", en: "If this address attacks, it may get blocked." },
  // rules
  rulesTitle: { fa: "قواعد تشخیص حمله", en: "Attack detection rules" },
  rulesHint: { fa: "هر قاعده می‌گوید چند تلاش ناموفق در چه مدتی یعنی حمله، و نشانی تا کی بسته شود.", en: "Each rule says how many failed tries in how long count as an attack, and how long to block." },
  rule: { fa: "قاعده", en: "Rule" },
  watches: { fa: "چه چیزی را می‌پاید", en: "What it watches" },
  when: { fa: "کی", en: "When" },
  whenText: { fa: "{n} بار در {window}", en: "{n} times in {window}" },
  banFor: { fa: "مدت مسدودی", en: "Block for" },
  defaultBan: { fa: "پیش‌فرض", en: "Default" },
  ruleOn: { fa: "روشن", en: "On" },
  ruleOff: { fa: "خاموش", en: "Off" },
  ready: { fa: "آماده", en: "Built-in" },
  addRule: { fa: "قاعده تازه", en: "New rule" },
  editRule: { fa: "ویرایش قاعده", en: "Edit rule" },
  turnRuleOn: { fa: "روشن کن", en: "Turn on" },
  turnRuleOff: { fa: "خاموش کن", en: "Turn off" },
  ruleName: { fa: "نام قاعده", en: "Rule name" },
  ruleSignals: { fa: "چه اتفاق‌هایی شمرده شود؟", en: "Which events count?" },
  threshold: { fa: "چند بار", en: "How many times" },
  window: { fa: "در چه مدتی", en: "Within" },
  ruleBan: { fa: "نشانی تا کی بسته شود", en: "How long to block" },
  ruleSave: { fa: "ذخیره قاعده", en: "Save rule" },
  ruleSaved: { fa: "قاعده «{name}» ذخیره شد.", en: "The rule “{name}” was saved." },
  ruleDeleteTitle: { fa: "قاعده «{name}» پاک شود؟", en: "Delete the rule “{name}”?" },
  ruleDeleteBody: { fa: "این قاعده دیگر حمله‌ای را تشخیص نمی‌دهد.", en: "This rule will no longer detect attacks." },
  ruleDeleted: { fa: "قاعده «{name}» پاک شد.", en: "The rule “{name}” was deleted." },
  needRuleName: { fa: "یک نام بنویسید.", en: "Type a name." },
  needSignal: { fa: "دست‌کم یک مورد را انتخاب کنید.", en: "Pick at least one." },
  needNumbers: { fa: "تعداد باید بین ۱ تا ۱۰۰٬۰۰۰ و مدت بین ۱۰ ثانیه تا ۱ روز باشد.", en: "The count must be 1–100,000 and the period 10 seconds to 1 day." },
  // history
  historyTitle: { fa: "تاریخچه", en: "History" },
  historyHint: { fa: "دیوار آتش چه کرد و چرا.", en: "What the firewall did, and why." },
  historyEmpty: { fa: "هنوز اتفاقی ثبت نشده.", en: "Nothing has been recorded yet." },
  historyEmptyBody: { fa: "وقتی حمله‌ای دیده شود یا چیزی را تغییر دهید، این‌جا نوشته می‌شود.", en: "When an attack is seen or you change something, it shows up here." },
  loadMore: { fa: "موارد قدیمی‌تر", en: "Older entries" },
  filterAll: { fa: "همه", en: "All" },
  filterBlocks: { fa: "مسدودی‌ها", en: "Blocks" },
  filterPractice: { fa: "تمرینی", en: "Practice" },
  filterChanges: { fa: "تغییرها", en: "Changes" },
  filterIp: { fa: "فقط این نشانی", en: "Only this address" },
  ev_block: { fa: "{ip} خودکار مسدود شد{why}.", en: "{ip} was blocked automatically{why}." },
  ev_would_block: { fa: "در حالت تمرین، {ip} مسدود می‌شد{why}.", en: "In practice mode, {ip} would have been blocked{why}." },
  ev_skipped: { fa: "{ip} مسدود نشد چون همیشه مجاز یا محافظت‌شده است.", en: "{ip} wasn't blocked because it's always allowed or protected." },
  ev_manual_block: { fa: "{ip} دستی مسدود شد{why}.", en: "{ip} was blocked by hand{why}." },
  ev_unblock: { fa: "{ip} آزاد شد.", en: "{ip} was unblocked." },
  ev_expire: { fa: "زمان مسدودی {ip} تمام شد.", en: "The block on {ip} ended." },
  ev_clear: { fa: "همه مسدودی‌ها یک‌جا برداشته شد.", en: "Every block was lifted at once." },
  ev_mode: { fa: "حالت دیوار آتش شد: {mode}.", en: "The firewall changed to: {mode}." },
  ev_other: { fa: "یک تغییر در دیوار آتش ثبت شد.", en: "A firewall change was recorded." },
  because: { fa: " (به خاطر «{rule}»)", en: " (because of “{rule}”)" },
  // preview & helper (Advanced)
  previewTitle: { fa: "پیش‌نمایش قواعد سرور", en: "Server ruleset preview" },
  previewHint: { fa: "دقیقاً همان چیزی که «در حال محافظت» روی سرور می‌نویسد.", en: "Exactly what “Protecting” writes on the server." },
  previewLoad: { fa: "نشان بده", en: "Show it" },
  ruleset: { fa: "متن قواعد", en: "Ruleset" },
  helperTitle: { fa: "اتصال نگهبان", en: "Helper connection" },
  helperSource: { fa: "تنظیم از", en: "Set in" },
  fromPanel: { fa: "پنل", en: "Panel" },
  fromCompose: { fa: "فایل Compose", en: "Compose file" },
  helperVersion: { fa: "نسخه نگهبان", en: "Helper version" },
  nftAvailable: { fa: "دیوار آتش سرور", en: "Server firewall" },
  yes: { fa: "در دسترس", en: "Available" },
  no: { fa: "در دسترس نیست", en: "Not available" },
  effective: { fa: "حالتی که واقعاً اجرا می‌شود", en: "Mode actually running" },
  lastPoll: { fa: "آخرین خواندن گزارش‌ها", en: "Last log read" },
  lastApply: { fa: "آخرین اعمال روی سرور", en: "Last applied" },
  lastError: { fa: "آخرین مشکل", en: "Last problem" },
  sourcesState: { fa: "منابع گزارش", en: "Log sources" },
  testHelper: { fa: "امتحان اتصال", en: "Test connection" },
  repair: { fa: "وصل کردن دوباره", en: "Connect again" },
  unpair: { fa: "جدا کردن نگهبان…", en: "Disconnect the helper…" },
  unpairTitle: { fa: "نگهبان دیوار آتش جدا شود؟", en: "Disconnect the firewall helper?" },
  unpairBody: { fa: "نگهبان آخرین وضعیت را نگه می‌دارد. اگر می‌خواهید مسدودی‌ها برداشته شوند، اول دیوار آتش را خاموش کنید.", en: "The helper keeps its last state. To lift blocks, turn the firewall off first." },
  unpairDescription: { fa: "پنل دیگر به نگهبان دستور نمی‌دهد.", en: "The panel stops sending commands to the helper." },
  unpaired: { fa: "نگهبان جدا شد.", en: "The helper was disconnected." },
  paired: { fa: "نگهبان وصل شد.", en: "The helper is connected." },
  clearAll: { fa: "آزاد کردن همه…", en: "Unblock everything…" },
  clearAllTitle: { fa: "همه نشانی‌های مسدود آزاد شوند؟", en: "Unblock every address?" },
  clearAllBody: { fa: "همه مسدودی‌ها، حتی تمرینی‌ها، همین حالا برداشته می‌شوند.", en: "Every block, practice ones too, is lifted right now." },
  clearAllDescription: { fa: "برای وقتی که کسی اشتباهی بیرون مانده و عجله دارید.", en: "For when someone got locked out by mistake and you're in a hurry." },
  cleared: { fa: "{n} مسدودی برداشته شد.", en: "{n} blocks were lifted." },
  settingsTitle: { fa: "همه تنظیمات دیوار آتش", en: "Every firewall setting" },
  settingsHint: { fa: "منابع گزارش، مسیرهای حساس، سقف‌ها و مدت نگه‌داری تاریخچه.", en: "Log sources, sensitive paths, limits and how long history is kept." },
  readOnly: { fa: "نقش شما فقط اجازه دیدن دیوار آتش را دارد.", en: "Your role can only view the firewall." }
} satisfies Record<string, Bi>;

const RULE_WORDS: Record<string, Bi> = {
  "ssh-bruteforce": { fa: "تلاش پشت‌سرهم برای ورود به SSH", en: "Repeated SSH sign-in attempts" },
  "mrk-login": { fa: "ورود ناموفق پشت‌سرهم به پنل", en: "Repeated failed panel sign-ins" },
  "http-auth": { fa: "درخواست‌های بی‌اجازه پشت‌سرهم به سایت‌ها", en: "Bursts of unauthorized website requests" },
  "http-404": { fa: "گشتن دنبال صفحه‌های ناموجود", en: "Hunting for pages that don't exist" },
  "http-probe": { fa: "سر زدن به مسیرهای حساس", en: "Probing sensitive paths" }
};

const SIGNAL_WORDS: Record<string, Bi> = {
  ssh_failed_password: { fa: "رمز اشتباه در SSH", en: "Wrong SSH password" },
  ssh_invalid_user: { fa: "نام کاربری ناموجود در SSH", en: "Unknown SSH user" },
  mrk_login_failure: { fa: "ورود ناموفق به پنل", en: "Failed panel sign-in" },
  http_401: { fa: "درخواست بدون ورود به سایت", en: "Website request without sign-in" },
  http_403: { fa: "درخواست ممنوع به سایت", en: "Forbidden website request" },
  http_404: { fa: "صفحه ناموجود", en: "Missing page" },
  http_sensitive_path: { fa: "مسیر حساس (مثل فایل‌های تنظیمات)", en: "Sensitive path (such as config files)" }
};

/** Errors on this page use the catalog with this module's wording (copy/errors.ts `firewall:<code>`). */
function ErrorBox({ error, onClose, onRetry }: { error: unknown; onClose?: () => void; onRetry?: () => void }) {
  return <FriendlyError error={error} onClose={onClose} onRetry={onRetry} scope="firewall" />;
}

function modeWord(language: Language, mode: string | null | undefined) {
  if (mode === "enforce") return pick(language, COPY.modeProtect);
  if (mode === "dry_run") return pick(language, COPY.modeWatch);
  return pick(language, COPY.modeOff);
}

function ruleLabel(language: Language, rule: Pick<Rule, "id" | "name"> | undefined, fallback?: string | null) {
  if (rule && RULE_WORDS[rule.id]) return pick(language, RULE_WORDS[rule.id]);
  return rule?.name ?? fallback ?? "";
}

function signalWord(language: Language, kind: string) {
  return SIGNAL_WORDS[kind] ? pick(language, SIGNAL_WORDS[kind]) : kind;
}

// ── page ────────────────────────────────────────────────────────────────────

export default function FirewallPanel({ permissions }: { permissions: readonly string[] }) {
  const { language, isAdvanced, c } = useKit();
  const canWrite = hasPermission(permissions, "firewall:write");
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [status, setStatus] = useState<FwStatus | null>(null);
  const [settings, setSettings] = useState<FwSettings | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [blockOpen, setBlockOpen] = useState(false);
  const [ruleEdit, setRuleEdit] = useState<Rule | "new" | null>(null);
  const [historyKey, setHistoryKey] = useState(0);
  const [pairOpen, setPairOpen] = useState(false);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      const [nextStatus, nextSettings, nextBlocks, nextRules] = await Promise.all([
        getJson<FwStatus>(`${API}/status`, signal),
        getJson<FwSettings>(`${API}/settings`, signal),
        getJson<{ items: Block[] }>(`${API}/blocks?include_simulated=true`, signal),
        getJson<{ items: Rule[] }>(`${API}/rules`, signal)
      ]);
      setStatus(nextStatus);
      setSettings(nextSettings);
      setBlocks(nextBlocks.items);
      setRules(nextRules.items);
      setLoadError(null);
      setUnavailable(false);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      if (caught instanceof ApiError && caught.status === 404) setUnavailable(true);
      else setLoadError(caught);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const refreshAll = async () => {
    await load();
    setHistoryKey((value) => value + 1);
  };

  const putSettings = async (patch: Record<string, unknown>) => {
    const updated = await mutateJson<FwSettings>(`${API}/settings`, { method: "PUT", body: patch });
    if (updated) setSettings(updated);
    return updated;
  };

  const changeMode = async (mode: Mode) => {
    if (!status || mode === status.mode) return;
    if (mode === "enforce") {
      setWizardOpen(true);
      return;
    }
    const off = mode === "off";
    const accepted = await ask({
      title: pick(language, off ? COPY.toOffTitle : COPY.toWatchTitle),
      body: pick(language, off ? COPY.toOffBody : COPY.toWatchBody),
      undoable: true,
      confirmLabel: pick(language, off ? COPY.toOffYes : COPY.toWatchYes)
    });
    if (!accepted) return;
    setActionError(null);
    try {
      await putSettings({ mode });
      notify({ message: say(language, COPY.modeSaved, { mode: modeWord(language, mode) }) });
      await refreshAll();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const unblock = async (block: Block, alsoAllow = false) => {
    setActionError(null);
    try {
      if (alsoAllow && settings) {
        const exists = settings.allowlist.some((entry) => entry.cidr === block.cidr);
        if (!exists) await putSettings({ allowlist: [...settings.allowlist, { cidr: block.cidr, note: pick(language, COPY.fromBlockList) }] });
      }
      await mutateJson(`${API}/blocks/${encodeURIComponent(block.id)}`, { method: "DELETE", body: {} });
      notify({ message: say(language, alsoAllow ? COPY.allowedNow : COPY.unblocked, { ip: block.cidr }) });
      await refreshAll();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const clearAll = async () => {
    const word = CONFIRM_WORDS.unblockAll;
    const accepted = await ask({ title: pick(language, COPY.clearAllTitle), body: pick(language, COPY.clearAllBody), severity: "destructive", undoable: false, typed: word, confirmLabel: pick(language, COPY.unblock) });
    if (!accepted) return;
    try {
      const result = await mutateJson<{ removed: number }>(`${API}/blocks/clear`, { method: "POST", body: { confirmation: word.token } });
      notify({ message: say(language, COPY.cleared, { n: result?.removed ?? 0 }) });
      await refreshAll();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const unpair = async () => {
    const word = CONFIRM_WORDS.unpair;
    const accepted = await ask({ title: pick(language, COPY.unpairTitle), body: pick(language, COPY.unpairBody), severity: "destructive", undoable: true, typed: word, confirmLabel: pick(language, COPY.unpair).replace("…", "") });
    if (!accepted) return;
    try {
      await mutateJson(`${API}/config`, { method: "DELETE", body: { confirmation: word.token } });
      notify({ message: pick(language, COPY.unpaired) });
      await refreshAll();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const toggleRule = async (rule: Rule) => {
    try {
      await mutateJson(`${API}/rules/${encodeURIComponent(rule.id)}`, { method: "PATCH", body: { enabled: !rule.enabled } });
      notify({ message: say(language, COPY.ruleSaved, { name: ruleLabel(language, rule) }), onUndo: () => void mutateJson(`${API}/rules/${encodeURIComponent(rule.id)}`, { method: "PATCH", body: { enabled: rule.enabled } }).then(() => load()) });
      await load();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const deleteRule = async (rule: Rule) => {
    const accepted = await ask({ title: say(language, COPY.ruleDeleteTitle, { name: ruleLabel(language, rule) }), body: pick(language, COPY.ruleDeleteBody), severity: "destructive", undoable: false });
    if (!accepted) return;
    try {
      await mutateJson(`${API}/rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" });
      notify({ message: say(language, COPY.ruleDeleted, { name: ruleLabel(language, rule) }) });
      await load();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setActionError(caught);
    }
  };

  const rulesById = useMemo(() => new Map(rules.map((rule) => [rule.id, rule])), [rules]);

  if (unavailable) return <Notice>{pick(language, COPY.unavailable)}</Notice>;
  if (loadError !== null && !status) return <FriendlyError error={loadError} onRetry={() => void load()} />;
  if (!status || !settings) return <Stack sx={{ py: 4 }} alignItems="center"><CircularProgress /></Stack>;

  const modeCards: { mode: Mode; icon: typeof ShieldRoundedIcon; title: Bi; body: Bi }[] = [
    { mode: "off", icon: PowerSettingsNewRoundedIcon, title: COPY.modeOff, body: COPY.modeOffBody },
    { mode: "dry_run", icon: VisibilityRoundedIcon, title: COPY.modeWatch, body: COPY.modeWatchBody },
    { mode: "enforce", icon: ShieldRoundedIcon, title: COPY.modeProtect, body: COPY.modeProtectBody }
  ];
  const tone = status.mode === "enforce" ? "ok" : status.mode === "dry_run" ? "warn" : "off";

  return (
    <Stack spacing={2.5}>
      {actionError !== null && <ErrorBox error={actionError} onClose={() => setActionError(null)} />}
      {!canWrite && <NoAccess needs="firewall:write" />}

      {/* ── status ── */}
      <SectionCard
        title={pick(language, COPY.statusTitle)}
        status={<StatusPill tone={tone} label={modeWord(language, status.mode)} />}
        action={<Button size="small" onClick={() => void refreshAll()} disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} sx={{ minHeight: 44 }}>{c.refresh}</Button>}
      >
        <Stack spacing={2}>
          {!status.configured && <Notice tone="warning">{pick(language, COPY.notPaired)} {pick(language, COPY.notPairedBody)}</Notice>}
          {status.configured && status.reachable === false && <Notice tone="error">{pick(language, COPY.unreachable)}</Notice>}
          {status.helper?.force_dry_run && <Notice tone="warning">{pick(language, COPY.forcedPractice)}</Notice>}
          {status.helper && status.helper.nft_available === false && <Notice tone="warning">{pick(language, COPY.noNft)}</Notice>}
          {status.configured && status.reachable && !status.in_sync && <Notice>{pick(language, COPY.outOfSync)}</Notice>}

          <Grid container spacing={1.5}>
            {modeCards.map((card) => {
              const active = status.mode === card.mode;
              const Icon = card.icon;
              return (
                <Grid key={card.mode} size={{ xs: 12, md: 4 }}>
                  <Card variant="outlined" sx={{ height: "100%", borderWidth: active ? 2 : 1, borderColor: active ? (card.mode === "enforce" ? "success.main" : card.mode === "dry_run" ? "warning.main" : "text.disabled") : "divider" }}>
                    <CardActionArea
                      disabled={!canWrite || active}
                      onClick={() => void changeMode(card.mode)}
                      sx={{ p: 2, height: "100%", display: "flex", alignItems: "flex-start", justifyContent: "flex-start", minHeight: 96 }}
                      aria-pressed={active}
                    >
                      <Stack direction="row" spacing={1.5} alignItems="flex-start">
                        <Icon color={active ? "primary" : "disabled"} aria-hidden />
                        <Box>
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Typography fontWeight={760}>{pick(language, card.title)}</Typography>
                            {active && <StatusPill tone={tone} label={pick(language, COPY.current)} />}
                          </Stack>
                          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, lineHeight: 1.8 }}>{pick(language, card.body)}</Typography>
                        </Box>
                      </Stack>
                    </CardActionArea>
                  </Card>
                </Grid>
              );
            })}
          </Grid>

          <StatGrid>
            <StatTile label={pick(language, COPY.blockedNow)} value={formatNumber(status.counts.active_blocks, language)} icon={BlockRoundedIcon} tone={status.counts.active_blocks ? "warn" : undefined} />
            <StatTile label={pick(language, COPY.practiceBlocks)} value={formatNumber(status.counts.simulated_blocks, language)} icon={VisibilityRoundedIcon} />
            <StatTile label={pick(language, COPY.decisions)} value={formatNumber(status.counts.decisions_24h, language)} icon={HistoryRoundedIcon} />
            <StatTile label={pick(language, COPY.rulesOn)} value={formatNumber(status.counts.rules_enabled, language)} icon={VerifiedUserRoundedIcon} />
          </StatGrid>

          {status.mode !== "enforce" && canWrite && (
            <Box>
              <Button variant="contained" size="large" startIcon={<ShieldRoundedIcon />} onClick={() => setWizardOpen(true)} sx={{ minHeight: 52, px: 3 }}>
                {pick(language, COPY.turnOn)}
              </Button>
            </Box>
          )}
        </Stack>
      </SectionCard>

      {/* ── blocked addresses ── */}
      <BlocksCard
        blocks={blocks}
        rulesById={rulesById}
        canWrite={canWrite}
        mode={status.mode}
        onUnblock={(block) => void unblock(block)}
        onAllow={(block) => void unblock(block, true)}
        onBlockOne={() => setBlockOpen(true)}
      />

      {/* ── always allowed ── */}
      <AllowlistCard settings={settings} canWrite={canWrite} onSave={putSettings} onSaved={() => void refreshAll()} />

      {/* ── rules (Advanced) ── */}
      <SectionCard
        advanced
        title={pick(language, COPY.rulesTitle)}
        hint={pick(language, COPY.rulesHint)}
        flush
        action={canWrite ? <Button size="small" startIcon={<AddRoundedIcon />} onClick={() => setRuleEdit("new")} sx={{ minHeight: 44 }}>{pick(language, COPY.addRule)}</Button> : undefined}
      >
        <ResponsiveList<Rule>
          label={pick(language, COPY.rulesTitle)}
          rows={rules}
          rowKey={(row) => row.id}
          columns={[
            { key: "name", header: pick(language, COPY.rule), render: (row) => ruleLabel(language, row) },
            { key: "signals", header: pick(language, COPY.watches), render: (row) => row.signal_kinds.map((kind) => signalWord(language, kind)).join("، "), hideOnCard: true },
            { key: "when", header: pick(language, COPY.when), render: (row) => say(language, COPY.whenText, { n: formatNumber(row.threshold, language), window: formatDuration(row.window_seconds, language) }) },
            { key: "ban", header: pick(language, COPY.banFor), render: (row) => (row.ban_seconds ? <Duration seconds={row.ban_seconds} /> : pick(language, COPY.defaultBan)) },
            { key: "id", header: "ID", render: (row) => <Ltr mono>{row.id}</Ltr>, advancedOnly: true },
            { key: "state", header: pick(language, COPY.kind), render: (row) => <StatusPill tone={row.enabled ? "ok" : "off"} label={pick(language, row.enabled ? COPY.ruleOn : COPY.ruleOff)} /> }
          ]}
          card={{
            title: (row) => ruleLabel(language, row),
            meta: (row) => <>{say(language, COPY.whenText, { n: formatNumber(row.threshold, language), window: formatDuration(row.window_seconds, language) })} · {row.ban_seconds ? <Duration seconds={row.ban_seconds} /> : pick(language, COPY.defaultBan)}</>,
            status: (row) => <StatusPill tone={row.enabled ? "ok" : "off"} label={pick(language, row.enabled ? COPY.ruleOn : COPY.ruleOff)} />
          }}
          actions={canWrite ? [
            { key: "toggle-on", label: pick(language, COPY.turnRuleOn), onClick: (row) => void toggleRule(row), hidden: (row) => row.enabled },
            { key: "toggle-off", label: pick(language, COPY.turnRuleOff), onClick: (row) => void toggleRule(row), hidden: (row) => !row.enabled },
            { key: "edit", label: pick(language, COPY.editRule), icon: EditRoundedIcon, onClick: (row) => setRuleEdit(row) },
            { key: "delete", label: pick(language, COPY.remove), icon: DeleteOutlineRoundedIcon, onClick: (row) => void deleteRule(row), danger: true, hidden: (row) => row.builtin }
          ] : undefined}
        />
      </SectionCard>

      {/* ── history ── */}
      <HistoryCard key={historyKey} rulesById={rulesById} />

      {/* ── Advanced: preview, helper, settings, danger ── */}
      {isAdvanced && <PreviewCard />}
      {isAdvanced && (
        <HelperCard
          status={status}
          canWrite={canWrite}
          onRepair={() => setPairOpen(true)}
          onTested={(message) => notify({ message })}
        />
      )}
      <RegistrySettings
        groups={["security.firewall"]}
        exclude={["firewall.mode", "firewall.allowlist", "firewall.allowlist_private", "firewall.allow_private_blocks", "firewall.rules"]}
        permissions={permissions}
        title={pick(language, COPY.settingsTitle)}
        hint={pick(language, COPY.settingsHint)}
      />
      {canWrite && (
        <DangerZone
          items={[
            { title: pick(language, COPY.clearAll).replace("…", ""), description: pick(language, COPY.clearAllDescription), action: <Button variant="outlined" color="error" onClick={() => void clearAll()}>{pick(language, COPY.clearAll)}</Button> },
            ...(status.configured && status.source === "panel"
              ? [{ title: pick(language, COPY.unpair).replace("…", ""), description: pick(language, COPY.unpairDescription), action: <Button variant="outlined" color="error" onClick={() => void unpair()}>{pick(language, COPY.unpair)}</Button> }]
              : [])
          ]}
        />
      )}

      {wizardOpen && (
        <ProtectWizard
          status={status}
          settings={settings}
          onSettings={putSettings}
          onClose={() => {
            setWizardOpen(false);
            void refreshAll();
          }}
          onDone={() => {
            setWizardOpen(false);
            notify({ message: pick(language, COPY.enforced) });
            void refreshAll();
          }}
        />
      )}
      {blockOpen && (
        <ManualBlockDialog
          settings={settings}
          mode={status.mode}
          onClose={() => setBlockOpen(false)}
          onDone={(ip) => {
            setBlockOpen(false);
            notify({ message: say(language, COPY.blockedDone, { ip }) });
            void refreshAll();
          }}
        />
      )}
      {ruleEdit && (
        <RuleDialog
          rule={ruleEdit === "new" ? null : ruleEdit}
          onClose={() => setRuleEdit(null)}
          onDone={(name) => {
            setRuleEdit(null);
            notify({ message: say(language, COPY.ruleSaved, { name }) });
            void load();
          }}
        />
      )}
      {pairOpen && (
        <PairDialog
          status={status}
          onClose={() => setPairOpen(false)}
          onDone={() => {
            setPairOpen(false);
            notify({ message: pick(language, COPY.paired) });
            void refreshAll();
          }}
        />
      )}
      {dialog}
      {snackbar}
    </Stack>
  );
}

// ── pairing steps (shared by the wizard and the Advanced «وصل کردن دوباره») ──

function PairFields({ status, keyValue, onKey, url, onUrl }: { status: FwStatus; keyValue: string; onKey: (value: string) => void; url: string; onUrl: (value: string) => void }) {
  const { language, isAdvanced } = useKit();
  if (status.source === "env") return <Notice>{pick(language, COPY.helperEnv)}</Notice>;
  return (
    <Stack spacing={1.5}>
      <Typography variant="body2">{pick(language, COPY.pair1)}</Typography>
      <CopyField label={pick(language, COPY.commandStart)} value={`${COMPOSE} --profile firewall up -d mrk-firewall`} multiline />
      <Typography variant="body2">{pick(language, COPY.pair2)}</Typography>
      <CopyField label={pick(language, COPY.commandKey)} value={`${COMPOSE} logs mrk-firewall | grep "pairing key"`} multiline />
      <Typography variant="body2">{pick(language, COPY.pair3)}</Typography>
      <TextField fullWidth label={pick(language, COPY.key)} value={keyValue} onChange={(event) => onKey(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoComplete: "off" } }} />
      {isAdvanced && <TextField fullWidth label={pick(language, COPY.url)} helperText={pick(language, COPY.urlHint)} value={url} onChange={(event) => onUrl(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />}
    </Stack>
  );
}

async function pairHelper(key: string, url: string) {
  const body: Record<string, string> = { key: key.trim() };
  if (url.trim()) body.url = url.trim();
  return mutateJson<FwStatus>(`${API}/config`, { method: "PUT", body });
}

function PairDialog({ status, onClose, onDone }: { status: FwStatus; onClose: () => void; onDone: () => void }) {
  const { language } = useKit();
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(status.url ?? "");
  return (
    <ActionWizard
      open
      title={pick(language, COPY.repair)}
      finishLabel={pick(language, COPY.connect)}
      onClose={onClose}
      onFinish={async () => {
        await pairHelper(key, url);
        onDone();
      }}
      steps={[{ key: "pair", title: pick(language, COPY.stepHelper), hint: pick(language, COPY.stepHelperHint), validate: () => (key.trim() ? null : pick(language, COPY.needKey)), render: () => <PairFields status={status} keyValue={key} onKey={setKey} url={url} onUrl={setUrl} /> }]}
    />
  );
}

// ── «روشن کردن محافظت» wizard ────────────────────────────────────────────────

function ProtectWizard({ status, settings, onSettings, onClose, onDone }: {
  status: FwStatus;
  settings: FwSettings;
  onSettings: (patch: Record<string, unknown>) => Promise<FwSettings | null>;
  onClose: () => void;
  onDone: () => void;
}) {
  const { language } = useKit();
  const [current, setCurrent] = useState(status);
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(status.url ?? "");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [allowPrivate, setAllowPrivate] = useState(settings.allowlist_private);
  const [typed, setTyped] = useState("");
  const word = CONFIRM_WORDS.enforce;
  const typedOk = matchesConfirmation(typed, word, language);
  const helperReady = current.configured && current.reachable !== false;

  useEffect(() => {
    void getJson<Preview>(`${API}/preview`).then(setPreview).catch(() => setPreview(null));
  }, []);

  const steps: WizardStep[] = [
    {
      key: "helper",
      title: pick(language, COPY.stepHelper),
      hint: pick(language, COPY.stepHelperHint),
      validate: () => (helperReady || current.source === "env" || key.trim() ? null : pick(language, COPY.needKey)),
      onNext: async () => {
        if (helperReady || current.source === "env") return;
        setCurrent(await pairHelper(key, url));
      },
      nextLabel: helperReady ? undefined : pick(language, COPY.connect),
      render: () => (helperReady ? <TestResult outcome={{ state: "ok", message: pick(language, COPY.helperOk) }} /> : <PairFields status={current} keyValue={key} onKey={setKey} url={url} onUrl={setUrl} />)
    },
    {
      key: "practice",
      title: pick(language, COPY.stepPractice),
      hint: pick(language, COPY.stepPracticeHint),
      onNext: async () => {
        if (settings.mode === "off") await onSettings({ mode: "dry_run" });
      },
      render: () => (
        <Stack spacing={1.5}>
          <Notice tone={settings.mode === "off" ? "info" : "success"}>{pick(language, settings.mode === "off" ? COPY.practiceStart : COPY.practiceNow)}</Notice>
          {preview && (preview.would_apply.blocks.length > 0
            ? <Typography variant="body2">{say(language, COPY.previewSummary, { blocks: preview.would_apply.blocks.length, allow: preview.would_apply.allow.length })}</Typography>
            : <Typography variant="body2" color="text.secondary">{pick(language, COPY.previewNone)}</Typography>)}
          {preview && preview.simulated.length > 0 && (
            <Stack spacing={0.5}>
              {preview.simulated.slice(0, 5).map((block) => (
                <Typography key={block.id} variant="caption" color="text.secondary"><Ltr mono>{block.cidr}</Ltr> · <RelativeTime value={block.created_at} /></Typography>
              ))}
            </Stack>
          )}
        </Stack>
      )
    },
    {
      key: "allow",
      title: pick(language, COPY.stepAllow),
      hint: pick(language, COPY.stepAllowHint),
      onNext: async () => {
        if (allowPrivate !== settings.allowlist_private) await onSettings({ allowlist_private: allowPrivate });
      },
      render: () => (
        <Stack spacing={1.5}>
          <FormControlLabel control={<Switch checked={allowPrivate} onChange={(_event, value) => setAllowPrivate(value)} />} label={pick(language, COPY.privateAllowed)} />
          <Typography variant="body2" color="text.secondary">{say(language, COPY.allowCount, { n: settings.allowlist.length })}</Typography>
          {settings.allowlist.slice(0, 8).map((entry) => (
            <Typography key={entry.cidr} variant="caption"><Ltr mono>{entry.cidr}</Ltr>{entry.note ? ` · ${entry.note}` : ""}</Typography>
          ))}
        </Stack>
      )
    },
    {
      key: "enforce",
      title: pick(language, COPY.stepEnforce),
      hint: pick(language, COPY.stepEnforceHint),
      validate: () => (typedOk ? null : say(language, COPY.enforceMismatch, { word: word.word[language] })),
      render: () => (
        <Stack spacing={1.5}>
          <Notice tone="warning">{pick(language, COPY.enforceWarn)}</Notice>
          <TextField
            fullWidth
            autoComplete="off"
            label={say(language, COPY.enforceType, { word: word.word[language] })}
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
            error={typed.length > 0 && !typedOk}
            helperText={typed.length > 0 && !typedOk ? say(language, COPY.enforceMismatch, { word: word.word[language] }) : " "}
            slotProps={{ htmlInput: { spellCheck: false } }}
          />
        </Stack>
      )
    }
  ];

  return (
    <ActionWizard
      open
      title={pick(language, COPY.wizardTitle)}
      steps={steps}
      finishLabel={pick(language, COPY.enforceYes)}
      onClose={onClose}
      onFinish={async () => {
        await onSettings({ mode: "enforce", confirmation: word.token });
        onDone();
      }}
    />
  );
}

// ── blocked addresses ───────────────────────────────────────────────────────

function BlocksCard({ blocks, rulesById, canWrite, mode, onUnblock, onAllow, onBlockOne }: {
  blocks: Block[];
  rulesById: Map<string, Rule>;
  canWrite: boolean;
  mode: Mode;
  onUnblock: (block: Block) => void;
  onAllow: (block: Block) => void;
  onBlockOne: () => void;
}) {
  const { language } = useKit();
  const [showPractice, setShowPractice] = useState(mode !== "enforce");
  const rows = showPractice ? blocks : blocks.filter((block) => !block.simulated);
  const why = (block: Block) => (block.rule_id ? ruleLabel(language, rulesById.get(block.rule_id), block.reason) : block.origin === "manual" ? `${pick(language, COPY.manual)}${block.reason ? ` · ${block.reason}` : ""}` : block.reason);
  const kindPill = (block: Block) => <StatusPill tone={block.simulated ? "warn" : "error"} label={pick(language, block.simulated ? COPY.practiceBlock : COPY.realBlock)} />;
  return (
    <SectionCard
      title={pick(language, COPY.blocksTitle)}
      hint={pick(language, COPY.blocksHint)}
      flush
      action={
        <Stack direction="row" spacing={1} alignItems="center">
          <FormControlLabel control={<Switch size="small" checked={showPractice} onChange={(_event, value) => setShowPractice(value)} />} label={<Typography variant="body2">{pick(language, COPY.showPractice)}</Typography>} />
          {canWrite && <Button size="small" variant="outlined" startIcon={<BlockRoundedIcon />} onClick={onBlockOne} sx={{ minHeight: 44 }}>{pick(language, COPY.blockOne)}</Button>}
        </Stack>
      }
    >
      <ResponsiveList<Block>
        label={pick(language, COPY.blocksTitle)}
        rows={rows}
        rowKey={(row) => row.id}
        columns={[
          { key: "ip", header: pick(language, COPY.address), render: (row) => <Ltr mono>{row.cidr}</Ltr> },
          { key: "why", header: pick(language, COPY.why), render: (row) => <Box component="span" dir="auto">{why(row)}</Box> },
          { key: "since", header: pick(language, COPY.since), render: (row) => <RelativeTime value={row.created_at} /> },
          { key: "until", header: pick(language, COPY.until), render: (row) => (row.expires_at ? <RelativeTime value={row.expires_at} relativeAlways /> : pick(language, COPY.forever)) },
          { key: "kind", header: pick(language, COPY.kind), render: kindPill }
        ]}
        card={{
          title: (row) => <Ltr mono>{row.cidr}</Ltr>,
          meta: (row) => <><Box component="span" dir="auto">{why(row)}</Box> · {row.expires_at ? <RelativeTime value={row.expires_at} relativeAlways /> : pick(language, COPY.forever)}</>,
          status: kindPill
        }}
        actions={canWrite ? [
          { key: "unblock", label: pick(language, COPY.unblock), icon: LockOpenRoundedIcon, onClick: onUnblock },
          { key: "allow", label: pick(language, COPY.alwaysAllow), icon: VerifiedUserRoundedIcon, onClick: onAllow }
        ] : undefined}
        empty={
          <EmptyState
            compact
            icon={ShieldRoundedIcon}
            title={pick(language, COPY.blocksEmpty)}
            body={pick(language, COPY.blocksEmptyBody)}
            action={canWrite ? <Button variant="outlined" startIcon={<BlockRoundedIcon />} onClick={onBlockOne}>{pick(language, COPY.blockOne)}</Button> : undefined}
          />
        }
      />
    </SectionCard>
  );
}

function ManualBlockDialog({ settings, mode, onClose, onDone }: { settings: FwSettings; mode: Mode; onClose: () => void; onDone: (ip: string) => void }) {
  const { language, isAdvanced } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [address, setAddress] = useState("");
  const [duration, setDuration] = useState<number | "default" | "forever">("default");
  const [reason, setReason] = useState(pick(language, COPY.blockReasonDefault));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const options: { value: number | "default" | "forever"; label: ReactNode }[] = [
    { value: "default", label: <>{pick(language, COPY.defaultBan)} (<Duration seconds={settings.default_ban_seconds} />)</> },
    { value: 3600, label: pick(language, COPY.hour1) },
    { value: 86400, label: pick(language, COPY.day1) },
    { value: 604800, label: pick(language, COPY.week1) },
    { value: 2592000, label: pick(language, COPY.month1) },
    ...(isAdvanced ? [{ value: "forever" as const, label: pick(language, COPY.forever) }] : [])
  ];

  const submit = async () => {
    const value = address.trim();
    if (!value) {
      setError(new ApiError(422, "invalid_address", ""));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = { reason: reason.trim() || pick(language, COPY.blockReasonDefault) };
      body[value.includes("/") ? "cidr" : "ip"] = value;
      if (duration === "forever") body.duration_seconds = null;
      else if (duration !== "default") body.duration_seconds = Math.min(duration, settings.max_ban_seconds);
      await mutateJson(`${API}/blocks`, { method: "POST", body });
      onDone(value);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onClose} fullWidth maxWidth="sm" fullScreen={fullScreen} aria-labelledby="mrk-fw-block-title">
      <DialogTitle id="mrk-fw-block-title">{pick(language, COPY.blockTitle)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <TextField autoFocus fullWidth label={pick(language, COPY.blockAddress)} helperText={pick(language, COPY.blockAddressHint)} value={address} onChange={(event) => setAddress(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
          <TextField select fullWidth label={pick(language, COPY.blockFor)} value={duration} onChange={(event) => setDuration(event.target.value === "default" || event.target.value === "forever" ? event.target.value : Number(event.target.value))}>
            {options.map((option) => <MenuItem key={String(option.value)} value={option.value}>{option.label}</MenuItem>)}
          </TextField>
          <TextField fullWidth label={pick(language, COPY.blockReason)} value={reason} onChange={(event) => setReason(event.target.value)} slotProps={{ htmlInput: { maxLength: 500, dir: "auto" } }} />
          {mode !== "enforce" && <Notice>{pick(language, COPY.blockPracticeNote)}</Notice>}
          {error !== null && (error instanceof ApiError && error.code === "invalid_address" && !address.trim() ? <Notice tone="error">{pick(language, COPY.needAddress)}</Notice> : <ErrorBox error={error} />)}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
        <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, COPY.cancel)}</Button>
        <Button variant="contained" color="error" disabled={busy} onClick={() => void submit()} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : <BlockRoundedIcon />} sx={{ minHeight: 44 }}>
          {pick(language, COPY.blockYes)}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ── always-allowed list ─────────────────────────────────────────────────────

function AllowlistCard({ settings, canWrite, onSave, onSaved }: { settings: FwSettings; canWrite: boolean; onSave: (patch: Record<string, unknown>) => Promise<FwSettings | null>; onSaved: () => void }) {
  const { language, isAdvanced } = useKit();
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [cidr, setCidr] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const save = async (patch: Record<string, unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await onSave(patch);
      notify({ message: pick(language, COPY.allowSaved) });
      onSaved();
      return true;
    } catch (caught) {
      setError(caught);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const add = async () => {
    if (!cidr.trim()) return;
    if (await save({ allowlist: [...settings.allowlist, { cidr: cidr.trim(), note: note.trim() }] })) {
      setCidr("");
      setNote("");
    }
  };

  const remove = async (entry: AllowEntry) => {
    const accepted = await ask({ title: say(language, COPY.removeAllowTitle, { ip: entry.cidr }), body: pick(language, COPY.removeAllowBody), confirmLabel: pick(language, COPY.remove) });
    if (!accepted) return;
    await save({ allowlist: settings.allowlist.filter((item) => item.cidr !== entry.cidr) });
  };

  return (
    <SectionCard title={pick(language, COPY.allowTitle)} hint={pick(language, COPY.allowHint)} action={<HelpTip term="allowlist" />}>
      <Stack spacing={1.5}>
        <FormControlLabel
          control={<Switch checked={settings.allowlist_private} disabled={!canWrite || busy} onChange={(_event, value) => void save({ allowlist_private: value })} />}
          label={pick(language, COPY.privateAllowed)}
        />
        {isAdvanced && (
          <Box>
            <FormControlLabel
              control={<Switch color="error" checked={settings.allow_private_blocks} disabled={!canWrite || busy} onChange={(_event, value) => void save({ allow_private_blocks: value })} />}
              label={pick(language, COPY.allowPrivateBlocks)}
            />
            <Typography variant="caption" color="text.secondary" display="block">{pick(language, COPY.allowPrivateBlocksHint)}</Typography>
          </Box>
        )}
        <ResponsiveList<AllowEntry>
          label={pick(language, COPY.allowTitle)}
          rows={settings.allowlist}
          rowKey={(row) => row.cidr}
          dense
          columns={[
            { key: "cidr", header: pick(language, COPY.address), render: (row) => <Ltr mono>{row.cidr}</Ltr> },
            { key: "note", header: pick(language, COPY.allowNote), render: (row) => (row.auto ? pick(language, COPY.autoAdded) : <Box component="span" dir="auto">{row.note || "—"}</Box>) },
            { key: "added", header: pick(language, COPY.since), render: (row) => <RelativeTime value={row.added_at ?? null} />, advancedOnly: true }
          ]}
          card={{ title: (row) => <Ltr mono>{row.cidr}</Ltr>, meta: (row) => (row.auto ? pick(language, COPY.autoAdded) : row.note) }}
          actions={canWrite ? [{ key: "remove", label: pick(language, COPY.remove), icon: DeleteOutlineRoundedIcon, onClick: (row) => void remove(row), danger: true }] : undefined}
          empty={<EmptyState compact icon={VerifiedUserRoundedIcon} title={pick(language, COPY.allowEmpty)} body={pick(language, COPY.allowEmptyBody)} />}
        />
        {canWrite && (
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "flex-start" }}>
            <TextField size="small" label={pick(language, COPY.allowAddress)} helperText={pick(language, COPY.blockAddressHint)} value={cidr} onChange={(event) => setCidr(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
            <TextField size="small" label={pick(language, COPY.allowNote)} value={note} onChange={(event) => setNote(event.target.value)} slotProps={{ htmlInput: { maxLength: 200, dir: "auto" } }} />
            <Button variant="outlined" startIcon={busy ? <CircularProgress size={14} /> : <AddRoundedIcon />} disabled={busy || !cidr.trim()} onClick={() => void add()} sx={{ minHeight: 40 }}>
              {pick(language, COPY.allowAdd)}
            </Button>
          </Stack>
        )}
        {error !== null && <ErrorBox error={error} onClose={() => setError(null)} />}
      </Stack>
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

// ── rule editor (Advanced) ──────────────────────────────────────────────────

function RuleDialog({ rule, onClose, onDone }: { rule: Rule | null; onClose: () => void; onDone: (name: string) => void }) {
  const { language } = useKit();
  const [name, setName] = useState(rule?.name ?? "");
  const [kinds, setKinds] = useState<string[]>(rule?.signal_kinds ?? ["http_404"]);
  const [threshold, setThreshold] = useState<number | null>(rule?.threshold ?? 20);
  const [windowSeconds, setWindowSeconds] = useState<number | null>(rule?.window_seconds ?? 60);
  const [ban, setBan] = useState<number | null>(rule?.ban_seconds ?? 3600);
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const builtin = Boolean(rule?.builtin);

  const problem = () => {
    if (!builtin && !name.trim()) return pick(language, COPY.needRuleName);
    if (!builtin && kinds.length === 0) return pick(language, COPY.needSignal);
    if (threshold === null || threshold < 1 || threshold > 100000 || windowSeconds === null || windowSeconds < 10 || windowSeconds > 86400) return pick(language, COPY.needNumbers);
    return null;
  };

  const save = async () => {
    const body: Record<string, unknown> = { threshold, window_seconds: windowSeconds, enabled };
    if (ban !== null) body.ban_seconds = ban;
    if (!builtin) {
      body.name = name.trim();
      body.signal_kinds = kinds;
    }
    if (rule) await mutateJson(`${API}/rules/${encodeURIComponent(rule.id)}`, { method: "PATCH", body });
    else await mutateJson(`${API}/rules`, { method: "POST", body });
    onDone(builtin && rule ? ruleLabel(language, rule) : name.trim());
  };

  return (
    <ActionWizard
      open
      title={rule ? `${pick(language, COPY.editRule)} · ${ruleLabel(language, rule)}` : pick(language, COPY.addRule)}
      finishLabel={pick(language, COPY.ruleSave)}
      onClose={onClose}
      onFinish={save}
      steps={[{
        key: "rule",
        title: pick(language, COPY.rule),
        validate: problem,
        render: () => (
          <Stack spacing={2}>
            {!builtin && <TextField fullWidth label={pick(language, COPY.ruleName)} value={name} onChange={(event) => setName(event.target.value)} slotProps={{ htmlInput: { maxLength: 80, dir: "auto" } }} />}
            {!builtin && (
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 650 }}>{pick(language, COPY.ruleSignals)}</Typography>
                <FormGroup>
                  {SIGNALS.map((kind) => (
                    <FormControlLabel
                      key={kind}
                      control={<Checkbox checked={kinds.includes(kind)} onChange={(event) => setKinds((current) => (event.target.checked ? [...current, kind] : current.filter((item) => item !== kind)))} />}
                      label={signalWord(language, kind)}
                    />
                  ))}
                </FormGroup>
              </Box>
            )}
            <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
              <NumberInput label={pick(language, COPY.threshold)} value={threshold} onChange={setThreshold} min={1} max={100000} integer />
              <DurationInput label={pick(language, COPY.window)} value={windowSeconds} onChange={setWindowSeconds} min={10} max={86400} units={["seconds", "minutes", "hours"]} />
            </Stack>
            <DurationInput label={pick(language, COPY.ruleBan)} value={ban} onChange={setBan} min={60} max={365 * 86400} units={["minutes", "hours", "days"]} />
            <FormControlLabel control={<Switch checked={enabled} onChange={(_event, value) => setEnabled(value)} />} label={pick(language, COPY.ruleOn)} />
          </Stack>
        )
      }]}
    />
  );
}

// ── history ─────────────────────────────────────────────────────────────────

const TONE_DOT: Record<string, string> = { error: "error.main", warn: "warning.main", ok: "success.main", info: "info.main" };

type HistoryFilter = "all" | "blocks" | "practice" | "changes";
const FILTER_ACTIONS: Record<HistoryFilter, string | null> = { all: null, blocks: "block", practice: "would_block", changes: "mode" };

function HistoryCard({ rulesById }: { rulesById: Map<string, Rule> }) {
  const { language, isAdvanced } = useKit();
  const [items, setItems] = useState<Decision[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [filter, setFilter] = useState<HistoryFilter>("all");
  const [ip, setIp] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const fetchPage = useCallback(async (before: number | null) => {
    const params = new URLSearchParams({ limit: "50" });
    const action = FILTER_ACTIONS[filter];
    if (action) params.set("action", action);
    if (ip.trim()) params.set("ip", ip.trim());
    if (before) params.set("before_id", String(before));
    return getJson<{ items: Decision[]; next_before_id: number | null }>(`${API}/events?${params}`);
  }, [filter, ip]);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    const timer = window.setTimeout(() => {
      void fetchPage(null)
        .then((page) => {
          if (!alive) return;
          setItems(page.items);
          setNext(page.next_before_id);
          setError(null);
        })
        .catch((caught) => alive && setError(caught))
        .finally(() => alive && setLoading(false));
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [fetchPage]);

  const more = async () => {
    if (!next) return;
    setLoading(true);
    try {
      const page = await fetchPage(next);
      setItems((current) => [...current, ...page.items]);
      setNext(page.next_before_id);
    } catch (caught) {
      setError(caught);
    } finally {
      setLoading(false);
    }
  };

  const sentence = (event: Decision) => {
    const rule = event.rule_id ? rulesById.get(event.rule_id) : undefined;
    const ruleName = rule ? ruleLabel(language, rule) : event.rule_id ? event.rule_id : "";
    const why = ruleName ? say(language, COPY.because, { rule: ruleName }) : "";
    const ipText = event.ip ?? "";
    switch (event.action) {
      case "block": return say(language, COPY.ev_block, { ip: ipText, why });
      case "would_block": return say(language, COPY.ev_would_block, { ip: ipText, why });
      case "skipped": return say(language, COPY.ev_skipped, { ip: ipText });
      case "manual_block": return say(language, COPY.ev_manual_block, { ip: ipText, why: event.reason ? ` (${event.reason})` : "" });
      case "unblock": return say(language, COPY.ev_unblock, { ip: ipText });
      case "expire": return say(language, COPY.ev_expire, { ip: ipText });
      case "clear": return pick(language, COPY.ev_clear);
      case "mode": return say(language, COPY.ev_mode, { mode: modeWord(language, event.mode) });
      default: return pick(language, COPY.ev_other);
    }
  };

  const tone = (action: string) => (action === "block" || action === "manual_block" ? "error" : action === "would_block" ? "warn" : action === "unblock" || action === "expire" ? "ok" : "info");

  return (
    <SectionCard title={pick(language, COPY.historyTitle)} hint={pick(language, COPY.historyHint)} collapsible>
      <Stack spacing={1.5}>
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
          <ToggleButtonGroup exclusive size="small" value={filter} onChange={(_event, value: HistoryFilter | null) => value && setFilter(value)} sx={{ flexWrap: "wrap", "& .MuiToggleButton-root": { minHeight: 40 } }}>
            <ToggleButton value="all">{pick(language, COPY.filterAll)}</ToggleButton>
            <ToggleButton value="blocks">{pick(language, COPY.filterBlocks)}</ToggleButton>
            <ToggleButton value="practice">{pick(language, COPY.filterPractice)}</ToggleButton>
            <ToggleButton value="changes">{pick(language, COPY.filterChanges)}</ToggleButton>
          </ToggleButtonGroup>
          {isAdvanced && <TextField size="small" label={pick(language, COPY.filterIp)} value={ip} onChange={(event) => setIp(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", maxLength: 64 } }} />}
        </Stack>
        {error !== null && <FriendlyError error={error} />}
        {!loading && items.length === 0 && error === null && <EmptyState compact icon={HistoryRoundedIcon} title={pick(language, COPY.historyEmpty)} body={pick(language, COPY.historyEmptyBody)} />}
        <Stack component="ol" spacing={1} sx={{ m: 0, p: 0, listStyle: "none" }}>
          {items.map((event) => (
            <Box component="li" key={event.id} sx={{ display: "flex", gap: 1.5, alignItems: "flex-start", pb: 1, borderBottom: 1, borderColor: "divider" }}>
              <Box aria-hidden sx={{ mt: 0.9, width: 10, height: 10, borderRadius: "50%", flexShrink: 0, bgcolor: TONE_DOT[tone(event.action)] }} />
              <Box sx={{ minWidth: 0, flex: 1 }}>
                <Typography variant="body2" sx={{ overflowWrap: "anywhere" }}>{sentence(event)}</Typography>
                <Typography variant="caption" color="text.secondary">
                  <RelativeTime value={event.occurred_at} />
                  {isAdvanced && <> · <Ltr mono>{event.action}</Ltr>{event.reason ? <> · <Box component="span" dir="auto">{event.reason}</Box></> : null}</>}
                </Typography>
              </Box>
            </Box>
          ))}
        </Stack>
        {loading && <CircularProgress size={20} />}
        {next && !loading && <Box><Button onClick={() => void more()} sx={{ minHeight: 44 }}>{pick(language, COPY.loadMore)}</Button></Box>}
      </Stack>
    </SectionCard>
  );
}

// ── Advanced: preview + helper connection ───────────────────────────────────

function PreviewCard() {
  const { language } = useKit();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      setPreview(await getJson<Preview>(`${API}/preview`));
    } catch (caught) {
      setError(caught);
    } finally {
      setLoading(false);
    }
  };
  return (
    <SectionCard
      title={pick(language, COPY.previewTitle)}
      hint={pick(language, COPY.previewHint)}
      collapsible
      defaultCollapsed
      action={<Button size="small" onClick={() => void load()} disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : undefined} sx={{ minHeight: 44 }}>{pick(language, COPY.previewLoad)}</Button>}
    >
      {error !== null && <FriendlyError error={error} />}
      {preview && (
        <Stack spacing={1.5}>
          <Typography variant="body2">{say(language, COPY.previewSummary, { blocks: preview.would_apply.blocks.length, allow: preview.would_apply.allow.length })}</Typography>
          <CopyField label={pick(language, COPY.ruleset)} value={preview.ruleset} multiline />
        </Stack>
      )}
    </SectionCard>
  );
}

function HelperCard({ status, canWrite, onRepair, onTested }: { status: FwStatus; canWrite: boolean; onRepair: () => void; onTested: (message: string) => void }) {
  const { language } = useKit();
  const [outcome, setOutcome] = useState<TestOutcome>({ state: "idle" });
  const test = async () => {
    setOutcome({ state: "running" });
    try {
      const result = await mutateJson<{ ok: boolean; latency_ms: number; error_code?: string }>(`${API}/test`, { method: "POST" });
      setOutcome(result.ok ? { state: "ok", latencyMs: result.latency_ms } : { state: "fail", code: result.error_code ?? null });
      if (result.ok) onTested(pick(language, COPY.helperOk));
    } catch (caught) {
      setOutcome({ state: "fail", error: caught });
    }
  };
  const sources = Object.entries(status.sources ?? {});
  return (
    <SectionCard
      title={pick(language, COPY.helperTitle)}
      collapsible
      status={<StatusPill tone={!status.configured ? "off" : status.reachable ? "ok" : "error"} label={!status.configured ? pick(language, COPY.no) : status.reachable ? pick(language, COPY.yes) : pick(language, COPY.no)} />}
      action={canWrite ? (
        <Stack direction="row" spacing={1}>
          {status.configured && <Button size="small" startIcon={<NetworkCheckRoundedIcon />} onClick={() => void test()} sx={{ minHeight: 44 }}>{pick(language, COPY.testHelper)}</Button>}
          {status.source !== "env" && <Button size="small" onClick={onRepair} sx={{ minHeight: 44 }}>{pick(language, COPY.repair)}</Button>}
        </Stack>
      ) : undefined}
    >
      <Stack spacing={1.5}>
        <TestResult outcome={outcome} />
        <KeyValueList
          items={[
            { label: pick(language, COPY.helperSource), value: status.source === "env" ? pick(language, COPY.fromCompose) : status.source === "panel" ? pick(language, COPY.fromPanel) : "—" },
            { label: pick(language, COPY.url), value: status.url ?? "—", ltr: true, copy: Boolean(status.url) },
            { label: pick(language, COPY.helperVersion), value: status.helper?.version ?? "—", ltr: true },
            { label: pick(language, COPY.nftAvailable), value: status.helper ? pick(language, status.helper.nft_available ? COPY.yes : COPY.no) : "—" },
            { label: pick(language, COPY.effective), value: modeWord(language, status.helper?.effective_mode ?? null) },
            { label: pick(language, COPY.lastPoll), value: <RelativeTime value={status.last_poll_at} /> },
            { label: pick(language, COPY.lastApply), value: <RelativeTime value={status.last_apply_at} /> },
            ...(status.last_apply_error || status.last_error ? [{ label: pick(language, COPY.lastError), value: reasonFor(language, status.last_apply_error ?? status.last_error), hint: status.last_apply_error ?? status.last_error ?? undefined }] : []),
            ...(sources.length ? [{ label: pick(language, COPY.sourcesState), value: sources.map(([name, state]) => `${name}: ${state.ok === false ? reasonFor(language, state.error ?? null) : "✓"}`).join(" · ") }] : [])
          ]}
        />
      </Stack>
    </SectionCard>
  );
}
