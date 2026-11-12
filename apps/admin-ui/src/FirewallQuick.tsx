import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Box, Button, Chip, CircularProgress, Collapse, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Stack, Switch, TextField,
  ToggleButton, ToggleButtonGroup, Typography
} from "@mui/material";
import BoltRoundedIcon from "@mui/icons-material/BoltRounded";
import LockOpenRoundedIcon from "@mui/icons-material/LockOpenRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import LanguageRoundedIcon from "@mui/icons-material/LanguageRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import PersonPinCircleRoundedIcon from "@mui/icons-material/PersonPinCircleRounded";
import KeyboardReturnRoundedIcon from "@mui/icons-material/KeyboardReturnRounded";
import { ApiError, getJson, isAbortError, mutateJson } from "./api";
import { CONFIRM_WORDS, matchesConfirmation, pick, say, type Bi } from "./copy";
import { CopyField, EmptyState, Ltr, Notice, RelativeTime, ResponsiveList, SectionCard, StatusPill, formatDuration, useKit, useUndoSnackbar } from "./kit";
import { formatNumber } from "./format";
import type { Language } from "./i18n";

/**
 * Security › Firewall › «کارهای سریع» (docs/45): every common firewall job has a shortcut.
 * A one-line command bar («open 8080», «3306 را ببند», «allow 10.0.0.0/8 -> 5432», «block 1.2.3.4»),
 * a short form with smart inputs, presets, one-click toggles per listening port, the SSH port with
 * where it was found, and undo for every change. Everything is previewed (exact rule changes, ruleset
 * diff, lockout check) before it is applied through the same safe pipeline as the full rule editor.
 */

type Protocol = "tcp" | "udp" | "both";
type Source = { kind: "public" } | { kind: "cidrs"; cidrs: string[] } | { kind: "list"; list_id: string } | { kind: "me" };
type PortIntent = {
  kind: "port"; action: "accept" | "drop"; ports: string[]; protocol: Protocol; scope: string; source: Source; source_label: string | null;
  exclusive: boolean; expires_in: number | null; note: string; unchanged?: boolean;
};
type BlockIntent = { kind: "block"; cidr: string; expires_in: number | null; note: string; unchanged?: boolean };
type Intent = PortIntent | BlockIntent;
type Problem = { code: string; address?: string; port?: number; ports?: number[]; later?: boolean };
type RuleLite = { id: string; name: string; ports: string[]; protocol: Protocol; action: "accept" | "drop" };
type ParseError = { line?: string; index?: number; error: string; word?: string; message?: string };
type Preview = {
  intents: Intent[]; errors: ParseError[]; created: RuleLite[]; removed: RuleLite[]; moved: number;
  blocks: { cidr: string; duration: number; refused: string | null }[]; empty: boolean; problems: Problem[]; overridable: boolean;
  diff: string[]; opens_only: boolean; trial: boolean; other_changes: boolean; configured: boolean; force_dry_run: boolean; dynamic_mode: string;
  rollback_seconds: number; requester: string | null;
};
type SshDetected = {
  ports: number[]; source: string;
  listener: { available: boolean; ports: number[]; other: { port: number; software: string }[] };
  sshd_config: { readable: boolean; ports: number[] }; ssh_socket: { readable: boolean; enabled: boolean | null; ports: number[] };
  mounts: { ssh: boolean; systemd: boolean };
};
type Listening = {
  port: number; protocol: "tcp" | "udp"; owner: { kind: string; name: string | null }; scope: string; exposure: "open" | "restricted" | "closed";
  me: boolean; draft: string; ssh: boolean; panel: boolean;
};
type Overview = {
  configured: boolean; active: boolean; force_dry_run: boolean; dynamic_mode: string; requester: string | null; my_network: string | null;
  ssh: { ports: number[]; source: string; admin_ports: number[]; detected: SshDetected }; panel_ports: number[];
  listening: Listening[]; listening_known: boolean; lists: { id: string; name: string; count: number }[]; draft_differs: boolean;
};
type HistoryItem = { id: string; at: number; status: string; kept: boolean | null; intents: Intent[] | null; rules: number; removed: number; blocks: string[] | null };
type QuickRequest = { text: string } | { intents: Record<string, unknown>[] };
type QuickResult = { change_id: string | null; pending?: boolean; kept?: boolean; nothing?: boolean };

const API = "/api/v1/firewall/ports";
const PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const DB_PORTS = [5432, 3306, 27017, 6379];
const MOUNTS = "      - /etc/ssh:/host/etc/ssh:ro\n      - /etc/ufw:/host/etc/ufw:ro\n      - /etc/systemd:/host/etc/systemd:ro";
const EXAMPLES: Record<Language, string[]> = {
  fa: ["8080 را باز کن", "3306 را ببند", "فقط از 10.0.0.0/8 به 5432", "1.2.3.4 را مسدود کن", "فقط من به 22 برای 1 ساعت"],
  en: ["open 8080", "close 3306", "allow 10.0.0.0/8 -> 5432", "block 1.2.3.4", "only me to 22 for 1h"]
};

const W = {
  title: { fa: "کارهای سریع", en: "Quick actions" },
  hint: { fa: "هر کار را با یک خط یا یک کلیک انجام دهید؛ پیش از اعمال دقیقاً می‌بینید چه عوض می‌شود و هر تغییر یک «برگردان» دارد.", en: "Do any job with one line or one click; you see exactly what changes before it's applied, and every change can be undone." },
  practice: { fa: "فقط تمرین", en: "Practice only" },
  commandLabel: { fa: "چه کاری انجام شود؟", en: "What should happen?" },
  commandHelp: { fa: "مثل نمونه‌های زیر بنویسید؛ چند کار را با «؛» یا خط تازه جدا کنید. «من» یعنی نشانی فعلی شما.", en: "Write it like the examples below; separate several jobs with “;” or a new line. “me” means your current address." },
  examples: { fa: "نمونه‌ها:", en: "Examples:" },
  apply: { fa: "اعمال", en: "Apply" },
  applyN: { fa: "اعمال {n} کار", en: "Apply {n} jobs" },
  cancel: { fa: "انصراف", en: "Cancel" },
  close: { fa: "بستن", en: "Close" },
  checking: { fa: "در حال بررسی…", en: "Checking…" },
  // intents
  i_open_all: { fa: "باز کردن پورت {ports} ({proto}) برای همه", en: "Open port {ports} ({proto}) to everyone" },
  i_close_all: { fa: "بستن پورت {ports} ({proto}) برای همه", en: "Close port {ports} ({proto}) to everyone" },
  i_allow: { fa: "اجازه به {who} برای پورت {ports} ({proto})", en: "Allow {who} on port {ports} ({proto})" },
  i_only: { fa: "پورت {ports} ({proto}) فقط برای {who}؛ برای بقیه بسته", en: "Port {ports} ({proto}) only for {who}; closed to everyone else" },
  i_deny: { fa: "بستن پورت {ports} ({proto}) برای {who}", en: "Close port {ports} ({proto}) to {who}" },
  i_block: { fa: "مسدود کردن {cidr} روی همه پورت‌ها", en: "Block {cidr} on every port" },
  i_for: { fa: " — به مدت {d}", en: " — for {d}" },
  i_same: { fa: "از قبل همین‌طور است", en: "Already so" },
  who_me: { fa: "نشانی شما", en: "your address" },
  who_list: { fa: "فهرست «{name}»", en: "the list “{name}”" },
  pr_tcp: { fa: "TCP", en: "TCP" },
  pr_udp: { fa: "UDP", en: "UDP" },
  pr_both: { fa: "TCP و UDP", en: "TCP and UDP" },
  // preview
  nothing: { fa: "چیزی عوض نمی‌شود؛ همه این‌ها از قبل همین‌طور است.", en: "Nothing changes; all of this is already so." },
  removedRules: { fa: "این قانون‌ها برداشته می‌شوند چون درست برعکس این کار هستند:", en: "These rules are removed because they say exactly the opposite:" },
  moved: { fa: "ترتیب {n} قانون دیگر جابه‌جا می‌شود تا قانون تازه درست سر جایش بنشیند.", en: "{n} other rules move so the new rule lands in the right place." },
  opensOnly: { fa: "این تغییر فقط باز می‌کند و کسی را بیرون نمی‌گذارد؛ بلافاصله ماندگار می‌شود.", en: "This only opens and can't lock anyone out; it's kept right away." },
  trial: { fa: "این تغییر چیزی را می‌بندد، پس آزمایشی اعمال می‌شود: اگر تا {s} ثانیه «این قوانین بمانند» را نزنید، خودکار برمی‌گردد.", en: "This closes something, so it's applied on trial: unless you press “Keep these rules” within {s} seconds, it's undone automatically." },
  otherChanges: { fa: "در پیش‌نویس قانون‌های ذخیره‌شده دیگری هم هست که هنوز اعمال نشده‌اند؛ آن‌ها هم همراه این کار اعمال می‌شوند.", en: "The draft has other saved rules that aren't applied yet; they're applied together with this." },
  forced: { fa: "سرور فقط حالت تمرین را می‌پذیرد؛ قانون‌ها ذخیره می‌شوند ولی روی سرور اعمال نمی‌شوند.", en: "The server only allows practice mode; the rules are saved but not applied on the server." },
  blockPractice: { fa: "دفاع پویا در حالت تمرین است؛ مسدودسازی فقط ثبت می‌شود و جلوی کسی را نمی‌گیرد.", en: "Dynamic defense is in practice mode; the block is only recorded and stops nobody." },
  notPaired: { fa: "نگهبان دیوار آتش وصل نیست؛ پیش‌نمایش را می‌بینید ولی اعمال ممکن نیست.", en: "The firewall helper isn't connected; you can preview but not apply." },
  problemsTitle: { fa: "این کار شما را بیرون می‌گذارد:", en: "This would lock you out:" },
  later: { fa: " (پس از تمام شدن زمان قانون موقت)", en: " (once the temporary rule runs out)" },
  p_ssh: { fa: "SSH (پورت {ports}) برای {address} بسته می‌شود.", en: "SSH (port {ports}) would close for {address}." },
  p_panel: { fa: "همین پنل (پورت {port}) برای {address} بسته می‌شود.", en: "This panel (port {port}) would close for {address}." },
  p_protected: { fa: "یک پورت محافظت‌شده (پورت {port}) بسته می‌شود.", en: "A protected port ({port}) would close." },
  everyone: { fa: "همه نشانی‌ها", en: "every address" },
  overrideHint: { fa: "اگر مطمئن هستید راه دیگری برای رسیدن به سرور دارید (مثلاً کنسول ارائه‌دهنده)، برای ادامه «{word}» را بنویسید:", en: "If you're sure you have another way into the server (for example your provider's console), type {word} to go on:" },
  refused: { fa: "{cidr} مسدود نمی‌شود: {why}", en: "{cidr} can't be blocked: {why}" },
  showDiff: { fa: "تغییر دقیق روی سرور", en: "Exact change on the server" },
  noDiff: { fa: "قوانین پورت روی سرور عوض نمی‌شود.", en: "The port rules on the server don't change." },
  done: { fa: "انجام شد و ماندگار است.", en: "Done and kept." },
  doneTrial: { fa: "آزمایشی اعمال شد؛ پس از بررسی دسترسی، بالای صفحه «این قوانین بمانند» را بزنید.", en: "Applied on trial; after checking access, press “Keep these rules” at the top." },
  doneNothing: { fa: "چیزی برای تغییر نبود.", en: "There was nothing to change." },
  undone: { fa: "برگردانده شد.", en: "Undone." },
  undo: { fa: "برگردان", en: "Undo" },
  // parse errors
  e_unknown_verb: { fa: "کار «{word}» را نفهمیدم. با «باز کن»، «ببند»، «مسدود کن» یا «فقط» بنویسید.", en: "I don't know “{word}”. Use open, close, block or only." },
  e_need_ports: { fa: "کدام پورت؟ یک عدد مثل 8080 بنویسید.", en: "Which port? Write a number like 8080." },
  e_unknown_list: { fa: "فهرستی به نام «{word}» نیست.", en: "There's no list named “{word}”." },
  e_bad_duration: { fa: "مدت را مثل 1h یا «2 ساعت» بنویسید.", en: "Write the time like 1h or 2 hours." },
  e_bad_port: { fa: "پورت «{word}» درست نیست؛ عددی بین 1 تا 65535.", en: "Port “{word}” isn't valid; use 1 to 65535." },
  e_unknown_word: { fa: "کلمه «{word}» را نفهمیدم.", en: "I don't understand “{word}”." },
  e_invalid_expiry: { fa: "مدت باید دست‌کم یک دقیقه و حداکثر 30 روز باشد.", en: "The time must be at least a minute and at most 30 days." },
  e_invalid_ports: { fa: "پورت درست نیست؛ مثل 80 یا 8000-8100 یا 80,443.", en: "That port isn't valid; like 80, 8000-8100 or 80,443." },
  e_invalid_sources: { fa: "نشانی درست نیست؛ یک IP یا محدوده مثل 10.0.0.0/8 بنویسید.", en: "That address isn't valid; write an IP or a range like 10.0.0.0/8." },
  e_requester_unknown: { fa: "نشانی شما برای پنل معلوم نیست؛ نشانی را خودتان بنویسید.", en: "The panel doesn't know your address; type it yourself." },
  e_other: { fa: "این بخش را نفهمیدم.", en: "I couldn't understand this part." },
  e_helper_too_old: { fa: "قانون موقت به نسخه تازه‌تر نگهبان دیوار آتش نیاز دارد؛ نگهبان را به‌روز کنید یا «همیشه» را انتخاب کنید.", en: "Temporary rules need a newer firewall helper; update it or choose “Always”." },
  // form
  formTitle: { fa: "با فرم", en: "With a form" },
  f_action: { fa: "کار", en: "Action" },
  f_open: { fa: "باز کن", en: "Open" },
  f_close: { fa: "ببند", en: "Close" },
  f_block: { fa: "مسدود کامل یک نشانی", en: "Block an address entirely" },
  f_ports: { fa: "پورت یا بازه", en: "Port or range" },
  f_portsHelp: { fa: "مثل 80 یا 8000-8100 یا 80,443", en: "Like 80, 8000-8100 or 80,443" },
  f_protocol: { fa: "نوع اتصال", en: "Connection type" },
  f_source: { fa: "برای چه کسی؟", en: "For whom?" },
  f_everyone: { fa: "همه", en: "Everyone" },
  f_me: { fa: "فقط نشانی من ({ip})", en: "Just my address ({ip})" },
  f_addr: { fa: "نشانی یا محدوده مشخص", en: "A specific address or range" },
  f_list: { fa: "فهرست «{name}»", en: "List “{name}”" },
  f_addrField: { fa: "نشانی‌ها (IP یا محدوده)", en: "Addresses (IP or range)" },
  f_only: { fa: "فقط همین‌ها؛ برای بقیه بسته شود", en: "Only these; close it to everyone else" },
  f_expiry: { fa: "تا کی؟", en: "Until when?" },
  f_forever: { fa: "همیشه", en: "Always" },
  f_1h: { fa: "1 ساعت", en: "1 hour" },
  f_1d: { fa: "1 روز", en: "1 day" },
  f_custom: { fa: "دلخواه", en: "Custom" },
  f_hours: { fa: "چند ساعت؟", en: "How many hours?" },
  f_note: { fa: "یادداشت (اختیاری)", en: "Note (optional)" },
  // presets
  presetsTitle: { fa: "الگوهای آماده", en: "Presets" },
  ps_web: { fa: "وب‌سرور", en: "Web server" },
  ps_webHint: { fa: "باز کردن 80 و 443 برای همه", en: "Open 80 and 443 to everyone" },
  ps_db: { fa: "پایگاه‌داده فقط داخلی", en: "Databases private only" },
  ps_dbHint: { fa: "پورت {ports} فقط از شبکه‌های داخلی", en: "Port {ports} only from private networks" },
  ps_ssh: { fa: "SSH فقط از نشانی من", en: "SSH from my address only" },
  ps_sshHint: { fa: "پورت {ports} فقط برای {ip}؛ اگر نشانی اینترنت شما عوض می‌شود، این را نزنید", en: "Port {ports} only for {ip}; skip this if your internet address changes" },
  previewTitle: { fa: "پیش‌نمایش", en: "Preview" },
  // ports
  portsTitle: { fa: "پورت‌های باز سرور", en: "Open ports on the server" },
  portsHint: { fa: "هر پورتی که روی سرور منتظر اتصال است؛ با یک کلیک ببندید یا محدود کنید.", en: "Every port the server listens on; close or restrict it in one click." },
  portsUnknown: { fa: "نگهبان هنوز فهرست پورت‌های باز را نفرستاده است.", en: "The helper hasn't sent the list of open ports yet." },
  noPorts: { fa: "پورت بازی پیدا نشد.", en: "No open port found." },
  port: { fa: "پورت", en: "Port" },
  owner: { fa: "مال", en: "Owner" },
  exposure: { fa: "از اینترنت", en: "From the internet" },
  you: { fa: "شما", en: "You" },
  ex_open: { fa: "باز برای همه", en: "Open to everyone" },
  ex_restricted: { fa: "فقط برای بعضی‌ها", en: "Only for some" },
  ex_closed: { fa: "بسته", en: "Closed" },
  me_yes: { fa: "دسترسی دارید", en: "You can reach it" },
  me_no: { fa: "دسترسی ندارید", en: "You can't reach it" },
  draftNote: { fa: "در پیش‌نویس: {state}", en: "In the draft: {state}" },
  ow_ssh: { fa: "SSH سرور", en: "Server SSH" },
  ow_panel: { fa: "همین پنل", en: "This panel" },
  ow_guess: { fa: "احتمالاً {name}", en: "Probably {name}" },
  ow_unknown: { fa: "نامشخص", en: "Unknown" },
  a_open: { fa: "باز برای همه", en: "Open to everyone" },
  a_close: { fa: "بستن به روی اینترنت", en: "Close to the internet" },
  a_me: { fa: "فقط نشانی من", en: "Only my address" },
  a_custom: { fa: "فقط برای نشانی یا فهرست…", en: "Only for an address or list…" },
  // ssh
  sshTitle: { fa: "پورت SSH", en: "SSH port" },
  sshHint: { fa: "دیوار آتش هیچ‌وقت این پورت را برای شما نمی‌بندد، مگر خودتان صریحاً تأیید کنید.", en: "The firewall never closes this port for you unless you explicitly confirm it." },
  s_listener: { fa: "پورت {ports}: خود سرویس SSH روی سرور به این پورت جواب داد.", en: "Port {ports}: the SSH service on the server answered on this port." },
  s_ssh_socket: { fa: "پورت {ports}: از تنظیمات راه‌اندازی SSH سیستم (ssh.socket) خوانده شد.", en: "Port {ports}: read from the system's SSH start-up settings (ssh.socket)." },
  s_sshd_config: { fa: "پورت {ports}: از فایل تنظیمات SSH سرور (sshd_config) خوانده شد.", en: "Port {ports}: read from the server's SSH settings file (sshd_config)." },
  s_admin: { fa: "پورت {ports}: خودتان تعیین کرده‌اید.", en: "Port {ports}: set by you." },
  s_assumed: { fa: "پورت SSH سرور شناخته نشد؛ 22 فرض شده است.", en: "The server's SSH port couldn't be found; 22 is assumed." },
  s_fixTitle: { fa: "برای رفع یکی از این دو کار را بکنید:", en: "To fix it, do one of these:" },
  s_fix1: { fa: "پورت را همین پایین خودتان بنویسید و ذخیره کنید.", en: "Type the port below yourself and save." },
  s_fix2: { fa: "در Dokploy به بخش «volumes» سرویس دیوار آتش این خط‌ها را اضافه کنید و آن را دوباره راه بیندازید تا نگهبان تنظیمات SSH را فقط بخواند:", en: "In Dokploy, add these lines under «volumes» of the firewall service and redeploy it, so the helper can read (only read) the SSH settings:" },
  s_mounts: { fa: "خط‌های اضافه", en: "Lines to add" },
  s_fix3: { fa: "نسخه تازه نگهبان پورت SSH را از روی خود سرویس در حال اجرا هم پیدا می‌کند؛ اگر نگهبان قدیمی است، آن را به‌روز کنید.", en: "The new helper version also finds the SSH port from the running service itself; if your helper is older, update it." },
  s_notPaired: { fa: "نگهبان دیوار آتش وصل نیست، پس پورت SSH از سرور خوانده نمی‌شود. اگر SSH روی 22 نیست، پورت را همین پایین بنویسید.", en: "The firewall helper isn't connected, so the SSH port can't be read from the server. If SSH isn't on 22, type the port below." },
  s_differs: { fa: "سرور الان پورت {ports} را نشان می‌دهد.", en: "The server now shows port {ports}." },
  s_useDetected: { fa: "استفاده از پورت {ports}", en: "Use port {ports}" },
  s_confirm: { fa: "پورت {ports} درست است", en: "Port {ports} is right" },
  s_auto: { fa: "خودکار تشخیص بده", en: "Detect automatically" },
  s_field: { fa: "پورت SSH (جدا با کاما)", en: "SSH port (comma separated)" },
  s_save: { fa: "ذخیره", en: "Save" },
  s_saved: { fa: "پورت SSH ذخیره شد.", en: "SSH port saved." },
  s_other: { fa: "یک سرور SSH دیگر هم روی پورت {ports} جواب داد (احتمالاً مال یک کانتینر)؛ برای جلوگیری از قفل شدن حساب نمی‌شود.", en: "Another SSH server answered on port {ports} (probably a container's); it doesn't count for the lockout check." },
  s_mismatch: { fa: "فایل تنظیمات SSH پورت {ports} را می‌گوید، ولی سرویس روی پورت دیگری جواب می‌دهد.", en: "The SSH settings file says port {ports}, but the service answers on another port." },
  // history
  historyTitle: { fa: "تغییرهای سریع اخیر", en: "Recent quick changes" },
  noHistory: { fa: "هنوز تغییر سریعی انجام نشده.", en: "No quick change yet." },
  h_applied: { fa: "اعمال‌شده", en: "Applied" },
  h_undone: { fa: "برگردانده‌شده", en: "Undone" },
  h_rolled_back: { fa: "خودکار برگشت", en: "Rolled back" },
  h_failed: { fa: "انجام نشد", en: "Failed" },
  h_rules: { fa: "{n} قانون", en: "{n} rules" }
} satisfies Record<string, Bi>;

const ERROR_WORDS: Record<string, Bi> = {
  unknown_verb: W.e_unknown_verb, need_ports: W.e_need_ports, unknown_list: W.e_unknown_list, bad_duration: W.e_bad_duration,
  bad_port: W.e_bad_port, unknown_word: W.e_unknown_word, invalid_expiry: W.e_invalid_expiry, invalid_ports: W.e_invalid_ports,
  invalid_sources: W.e_invalid_sources, requester_unknown: W.e_requester_unknown, source_list_not_found: W.e_unknown_list,
  helper_too_old: W.e_helper_too_old
};

const failed = (caught: unknown) => !(caught instanceof ApiError && caught.status === 401) && !isAbortError(caught);

function protoWord(language: Language, protocol: Protocol) {
  return pick(language, protocol === "tcp" ? W.pr_tcp : protocol === "udp" ? W.pr_udp : W.pr_both);
}

export function describeIntent(language: Language, intent: Intent, lists: Map<string, string>): string {
  const tail = intent.expires_in ? say(language, W.i_for, { d: formatDuration(intent.expires_in, language) }) : "";
  if (intent.kind === "block") return say(language, W.i_block, { cidr: intent.cidr }) + tail;
  const ports = intent.ports.join(", ");
  const proto = protoWord(language, intent.protocol);
  const source = intent.source;
  let who = "";
  if (intent.source_label === "me") who = pick(language, W.who_me);
  else if (source.kind === "list") who = say(language, W.who_list, { name: intent.source_label ?? lists.get(source.list_id) ?? "" });
  else if (source.kind === "cidrs") who = source.cidrs.join(", ");
  if (source.kind === "public") return say(language, intent.action === "accept" ? W.i_open_all : W.i_close_all, { ports, proto }) + tail;
  if (intent.action === "drop") return say(language, W.i_deny, { ports, proto, who }) + tail;
  return say(language, intent.exclusive ? W.i_only : W.i_allow, { ports, proto, who }) + tail;
}

function errorText(language: Language, error: ParseError) {
  const words = ERROR_WORDS[error.error];
  return words ? say(language, words, { word: error.word ?? "" }) : pick(language, W.e_other);
}

function problemLine(language: Language, problem: Problem) {
  const address = !problem.address || problem.address === "public" ? pick(language, W.everyone) : problem.address;
  const base = problem.code === "lockout_ssh" ? say(language, W.p_ssh, { ports: (problem.ports ?? []).join(", "), address })
    : problem.code === "lockout_panel" ? say(language, W.p_panel, { port: String(problem.port ?? ""), address })
      : say(language, W.p_protected, { port: String(problem.port ?? "") });
  return base + (problem.later ? pick(language, W.later) : "");
}

function DiffLines({ lines }: { lines: string[] }) {
  return (
    <Box component="pre" dir="ltr" sx={{ m: 0, p: 1.5, maxHeight: 280, overflow: "auto", borderRadius: 1, bgcolor: "action.hover", fontSize: 12, lineHeight: 1.6, tabSize: 4, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" }}>
      {lines.map((line, index) => (
        <Box key={index} component="span" sx={{ display: "block", whiteSpace: "pre", color: line.startsWith("+") && !line.startsWith("+++") ? "success.main" : line.startsWith("-") && !line.startsWith("---") ? "error.main" : undefined }}>{line || " "}</Box>
      ))}
    </Box>
  );
}

/** Debounced server preview of a quick request (nothing is written). */
function usePreview(request: QuickRequest | null, delay = 450) {
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const key = request ? JSON.stringify(request) : "";
  useEffect(() => {
    setError(null);
    if (!key) {
      setPreview(null);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    const timer = window.setTimeout(() => {
      mutateJson<Preview>(`${API}/quick`, { method: "POST", body: JSON.parse(key) as Record<string, unknown> })
        .then((result) => { if (!cancelled) setPreview(result); })
        .catch((caught) => { if (!cancelled && failed(caught)) { setPreview(null); setError(caught); } })
        .finally(() => { if (!cancelled) setLoading(false); });
    }, delay);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [key, delay]);
  return { preview, error, loading };
}

function PreviewView({ preview, lists, typed, onTyped }: {
  preview: Preview; lists: Map<string, string>; typed: string; onTyped: (value: string) => void;
}) {
  const { language, isAdvanced } = useKit();
  const [showDiff, setShowDiff] = useState(false);
  const word = CONFIRM_WORDS.enforce;
  const ports = preview.intents.filter((item) => item.kind === "port" && !item.unchanged).length;
  const blocks = preview.intents.some((item) => item.kind === "block");
  return (
    <Stack spacing={1.25}>
      {preview.errors.length > 0 && (
        <Notice tone="warning">
          <Box component="ul" sx={{ m: 0, ps: 2.5 }}>
            {preview.errors.map((item, index) => <li key={index}><Typography variant="body2">{item.line ? <><Ltr>{item.line}</Ltr>: </> : null}{errorText(language, item)}</Typography></li>)}
          </Box>
        </Notice>
      )}
      {preview.intents.length > 0 && (
        <Stack direction="row" spacing={0.75} useFlexGap flexWrap="wrap">
          {preview.intents.map((intent, index) => {
            const icon = intent.kind === "block" ? <BlockRoundedIcon /> : intent.action === "accept" ? <LockOpenRoundedIcon /> : <LockRoundedIcon />;
            const color = intent.unchanged ? "default" : intent.kind === "block" || intent.action === "drop" ? "warning" : "success";
            return (
              <Chip key={index} icon={icon} color={color} variant={intent.unchanged ? "outlined" : "filled"}
                label={describeIntent(language, intent, lists) + (intent.unchanged ? ` · ${pick(language, W.i_same)}` : "")}
                sx={{ height: "auto", py: 0.5, "& .MuiChip-label": { whiteSpace: "normal" } }} />
            );
          })}
        </Stack>
      )}
      {preview.removed.length > 0 && (
        <Typography variant="body2" color="text.secondary">{pick(language, W.removedRules)} {preview.removed.map((rule) => <Ltr key={rule.id}>{rule.name}</Ltr>).reduce<ReactNode[]>((all, item, index) => (index ? [...all, "، ", item] : [item]), [])}</Typography>
      )}
      {preview.moved > 0 && isAdvanced && <Typography variant="caption" color="text.secondary">{say(language, W.moved, { n: formatNumber(preview.moved, language) })}</Typography>}
      {preview.blocks.filter((item) => item.refused).map((item) => (
        <Notice key={item.cidr} tone="error">{say(language, W.refused, { cidr: item.cidr, why: item.refused ?? "" })}</Notice>
      ))}
      {preview.problems.length > 0 && (
        <Notice tone="error">
          <Typography variant="body2" fontWeight={700}>{pick(language, W.problemsTitle)}</Typography>
          <Box component="ul" sx={{ m: 0, ps: 2.5 }}>{preview.problems.map((problem, index) => <li key={index}><Typography variant="body2">{problemLine(language, problem)}</Typography></li>)}</Box>
          {preview.overridable && (
            <TextField size="small" sx={{ mt: 1 }} fullWidth autoComplete="off" value={typed} onChange={(event) => onTyped(event.target.value)}
              label={say(language, W.overrideHint, { word: pick(language, word.word) })} />
          )}
        </Notice>
      )}
      {!preview.configured && <Notice tone="warning">{pick(language, W.notPaired)}</Notice>}
      {preview.force_dry_run && ports > 0 && <Notice tone="warning">{pick(language, W.forced)}</Notice>}
      {blocks && preview.dynamic_mode !== "enforce" && <Notice tone="warning">{pick(language, W.blockPractice)}</Notice>}
      {preview.other_changes && ports > 0 && <Notice>{pick(language, W.otherChanges)}</Notice>}
      {!preview.empty && ports > 0 && preview.problems.length === 0 && (
        <Typography variant="body2" color={preview.trial ? "warning.main" : "success.main"}>
          {preview.trial ? say(language, W.trial, { s: formatNumber(preview.rollback_seconds, language) }) : pick(language, W.opensOnly)}
        </Typography>
      )}
      {preview.empty && preview.errors.length === 0 && preview.intents.length > 0 && <Typography variant="body2" color="text.secondary">{pick(language, W.nothing)}</Typography>}
      {ports > 0 && (
        isAdvanced || showDiff
          ? (preview.diff.length ? <DiffLines lines={preview.diff} /> : <Typography variant="caption" color="text.secondary">{pick(language, W.noDiff)}</Typography>)
          : <Box><Button size="small" onClick={() => setShowDiff(true)}>{pick(language, W.showDiff)}</Button></Box>
      )}
    </Stack>
  );
}

function canApply(preview: Preview | null, typed: string, language: Language) {
  if (!preview || preview.empty || preview.errors.length > 0 || !preview.configured) return false;
  if (preview.blocks.some((item) => item.refused)) return false;
  if (preview.problems.length === 0) return true;
  return preview.overridable && matchesConfirmation(typed, CONFIRM_WORDS.enforce, language);
}

// ── main section ─────────────────────────────────────────────────────────────

export default function FirewallQuick({ canWrite, reloadKey, onChanged, renderError }: {
  canWrite: boolean; reloadKey: number; onChanged: () => void; renderError: (error: unknown, onClose?: () => void) => ReactNode;
}) {
  const { language } = useKit();
  const { notify, snackbar } = useUndoSnackbar(10000);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [dialog, setDialog] = useState<{ title: string; request: QuickRequest } | null>(null);
  const [formSeed, setFormSeed] = useState<FormSeed | null>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const [next, recent] = await Promise.all([
        getJson<Overview>(`${API}/quick/overview`, signal),
        getJson<{ items: HistoryItem[] }>(`${API}/quick/history`, signal)
      ]);
      setOverview(next);
      setHistory(recent.items);
    } catch (caught) {
      if (failed(caught)) setError(caught);
    }
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load, reloadKey]);

  const lists = useMemo(() => new Map((overview?.lists ?? []).map((item) => [item.id, item.name])), [overview]);

  const undo = useCallback(async (changeId: string) => {
    try {
      await mutateJson(`${API}/quick/undo`, { method: "POST", body: { change_id: changeId } });
      notify({ message: pick(language, W.undone) });
    } catch (caught) {
      if (failed(caught)) setError(caught);
    }
    onChanged();
    void load();
  }, [language, load, notify, onChanged]);

  const applied = useCallback((result: QuickResult | null) => {
    setDialog(null);
    setFormSeed(null);
    if (!result || result.nothing || !result.change_id) notify({ message: pick(language, W.doneNothing) });
    else {
      const changeId = result.change_id;
      notify({ message: pick(language, result.kept ? W.done : W.doneTrial), tone: "success", onUndo: () => void undo(changeId) });
    }
    onChanged();
    void load();
  }, [language, load, notify, onChanged, undo]);

  const open = (title: string, request: QuickRequest) => setDialog({ title, request });

  const portIntent = (item: Listening, action: "accept" | "drop", source: Record<string, unknown>, exclusive = false) => ({
    kind: "port", action, ports: String(item.port), protocol: item.protocol, scope: "both", source, exclusive
  });

  return (
    <Stack spacing={2.5}>
      <SectionCard title={pick(language, W.title)} hint={pick(language, W.hint)}
        status={overview?.force_dry_run ? <StatusPill tone="warn" label={pick(language, W.practice)} /> : undefined}>
        <Stack spacing={2}>
          {error !== null && renderError(error, () => setError(null))}
          {canWrite && <CommandBar lists={lists} onApplied={applied} renderError={renderError} />}
          {canWrite && overview && <Presets overview={overview} onPick={open} />}
          {canWrite && overview && <ShortcutForm overview={overview} lists={lists} seed={formSeed} onApplied={applied} renderError={renderError} />}
        </Stack>
      </SectionCard>

      {overview && <SshCard overview={overview} canWrite={canWrite} onSaved={() => { notify({ message: pick(language, W.s_saved) }); onChanged(); void load(); }} onError={setError} />}

      {overview && (
        <SectionCard title={pick(language, W.portsTitle)} hint={pick(language, W.portsHint)} flush>
          {!overview.listening_known ? <Box sx={{ p: 2 }}><Notice>{pick(language, W.portsUnknown)}</Notice></Box> : (
            <ResponsiveList<Listening>
              label={pick(language, W.portsTitle)}
              rows={overview.listening}
              rowKey={(row) => `${row.protocol}-${row.port}`}
              empty={<EmptyState compact title={pick(language, W.noPorts)} />}
              columns={[
                { key: "port", header: pick(language, W.port), render: (row) => <Ltr mono>{`${row.port}/${row.protocol}`}</Ltr> },
                { key: "owner", header: pick(language, W.owner), render: (row) => <OwnerText row={row} /> },
                { key: "exposure", header: pick(language, W.exposure), render: (row) => <ExposurePill row={row} /> },
                { key: "me", header: pick(language, W.you), render: (row) => <StatusPill tone={row.me ? "ok" : "warn"} label={pick(language, row.me ? W.me_yes : W.me_no)} />, hideOnCard: true }
              ]}
              card={{
                title: (row) => <><Ltr mono>{`${row.port}/${row.protocol}`}</Ltr> · <OwnerText row={row} /></>,
                meta: (row) => pick(language, row.me ? W.me_yes : W.me_no),
                status: (row) => <ExposurePill row={row} />
              }}
              actions={canWrite ? [
                { key: "open", label: pick(language, W.a_open), icon: LockOpenRoundedIcon, hidden: (row) => row.exposure === "open",
                  onClick: (row) => open(pick(language, W.a_open), { intents: [portIntent(row, "accept", { kind: "public" })] }) },
                { key: "close", label: pick(language, W.a_close), icon: LockRoundedIcon, danger: true, hidden: (row) => row.exposure === "closed",
                  onClick: (row) => open(pick(language, W.a_close), { intents: [portIntent(row, "drop", { kind: "public" })] }) },
                { key: "me", label: pick(language, W.a_me), icon: PersonPinCircleRoundedIcon, disabled: () => !overview.requester,
                  onClick: (row) => open(pick(language, W.a_me), { intents: [portIntent(row, "accept", { kind: "me" }, true)] }) },
                { key: "custom", label: pick(language, W.a_custom), icon: TuneRoundedIcon,
                  onClick: (row) => setFormSeed({ ports: String(row.port), protocol: row.protocol, action: "accept", source: "addr", exclusive: true, at: Date.now() }) }
              ] : undefined}
            />
          )}
        </SectionCard>
      )}

      <SectionCard title={pick(language, W.historyTitle)} collapsible defaultCollapsed flush>
        <ResponsiveList<HistoryItem>
          label={pick(language, W.historyTitle)}
          dense
          rows={history}
          rowKey={(row) => row.id}
          empty={<EmptyState compact title={pick(language, W.noHistory)} />}
          columns={[
            { key: "at", header: "", render: (row) => <RelativeTime value={row.at * 1000} /> },
            { key: "what", header: "", render: (row) => (row.intents ?? []).map((intent) => describeIntent(language, intent, lists)).join("؛ ") },
            { key: "status", header: "", render: (row) => <HistoryPill row={row} /> }
          ]}
          card={{
            title: (row) => (row.intents ?? []).map((intent) => describeIntent(language, intent, lists)).join("؛ ") || say(language, W.h_rules, { n: formatNumber(row.rules, language) }),
            meta: (row) => <RelativeTime value={row.at * 1000} />,
            status: (row) => <HistoryPill row={row} />
          }}
          actions={canWrite ? [{ key: "undo", label: pick(language, W.undo), hidden: (row) => row.status !== "applied", onClick: (row) => void undo(row.id) }] : undefined}
        />
      </SectionCard>

      {dialog && <PreviewDialog title={dialog.title} request={dialog.request} lists={lists} onClose={() => setDialog(null)} onApplied={applied} renderError={renderError} />}
      {snackbar}
    </Stack>
  );
}

function HistoryPill({ row }: { row: HistoryItem }) {
  const { language } = useKit();
  const words: Record<string, Bi> = { applied: W.h_applied, undone: W.h_undone, rolled_back: W.h_rolled_back, failed: W.h_failed, undo_failed: W.h_failed };
  const tone = row.status === "applied" ? "ok" : row.status === "failed" || row.status === "undo_failed" ? "error" : "off";
  return <StatusPill tone={tone} label={pick(language, words[row.status] ?? W.h_applied)} />;
}

function OwnerText({ row }: { row: Listening }) {
  const { language } = useKit();
  if (row.owner.kind === "ssh") return <>{pick(language, W.ow_ssh)}</>;
  if (row.owner.kind === "panel") return <>{pick(language, W.ow_panel)}</>;
  if (row.owner.kind === "container") return <Ltr>{row.owner.name ?? ""}</Ltr>;
  if (row.owner.kind === "guess") return <>{say(language, W.ow_guess, { name: row.owner.name ?? "" })}</>;
  return <>{pick(language, W.ow_unknown)}</>;
}

function ExposurePill({ row }: { row: Listening }) {
  const { language } = useKit();
  const word = (state: string) => pick(language, state === "open" ? W.ex_open : state === "restricted" ? W.ex_restricted : W.ex_closed);
  return (
    <Stack spacing={0.25} alignItems="flex-start">
      <StatusPill tone={row.exposure === "open" ? "warn" : row.exposure === "restricted" ? "ok" : "off"} label={word(row.exposure)} />
      {row.draft !== row.exposure && <Typography variant="caption" color="text.secondary">{say(language, W.draftNote, { state: word(row.draft) })}</Typography>}
    </Stack>
  );
}

// ── command bar ──────────────────────────────────────────────────────────────

function CommandBar({ lists, onApplied, renderError }: { lists: Map<string, string>; onApplied: (result: QuickResult | null) => void; renderError: (error: unknown, onClose?: () => void) => ReactNode }) {
  const { language } = useKit();
  const [text, setText] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [applyError, setApplyError] = useState<unknown>(null);
  const request = useMemo<QuickRequest | null>(() => (text.trim() ? { text: text.trim() } : null), [text]);
  const { preview, error, loading } = usePreview(request);
  const ready = canApply(preview, typed, language) && !loading;
  const inputRef = useRef<HTMLInputElement | null>(null);

  const apply = async () => {
    if (!request || !ready) return;
    setBusy(true);
    setApplyError(null);
    try {
      const body: Record<string, unknown> = { ...request, apply: true };
      if (preview?.problems.length) body.override = CONFIRM_WORDS.enforce.token;
      const result = await mutateJson<QuickResult>(`${API}/quick`, { method: "POST", body });
      setText("");
      setTyped("");
      onApplied(result);
    } catch (caught) {
      if (failed(caught)) setApplyError(caught);
    } finally {
      setBusy(false);
    }
  };

  const count = preview ? preview.intents.filter((item) => !item.unchanged).length : 0;
  return (
    <Stack spacing={1.25}>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ sm: "flex-start" }}>
        <TextField
          inputRef={inputRef}
          fullWidth
          label={pick(language, W.commandLabel)}
          helperText={pick(language, W.commandHelp)}
          value={text}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void apply(); } }}
          multiline
          maxRows={4}
          slotProps={{ htmlInput: { dir: "auto", spellCheck: false, "aria-describedby": "quick-examples" }, input: { startAdornment: <BoltRoundedIcon color="primary" sx={{ me: 1 }} /> } }}
        />
        <Button variant="contained" onClick={() => void apply()} disabled={!ready || busy} startIcon={busy || loading ? <CircularProgress size={16} color="inherit" /> : <KeyboardReturnRoundedIcon />} sx={{ minHeight: 56, flexShrink: 0 }}>
          {count > 1 ? say(language, W.applyN, { n: formatNumber(count, language) }) : pick(language, W.apply)}
        </Button>
      </Stack>
      <Stack id="quick-examples" direction="row" spacing={0.75} useFlexGap flexWrap="wrap" alignItems="center">
        <Typography variant="caption" color="text.secondary">{pick(language, W.examples)}</Typography>
        {EXAMPLES[language].map((example) => (
          <Chip key={example} size="small" variant="outlined" label={<Box component="span" dir="auto">{example}</Box>} onClick={() => { setText(example); inputRef.current?.focus(); }} />
        ))}
      </Stack>
      {error !== null && renderError(error)}
      {applyError !== null && renderError(applyError, () => setApplyError(null))}
      {preview && <PreviewView preview={preview} lists={lists} typed={typed} onTyped={setTyped} />}
    </Stack>
  );
}

// ── presets ──────────────────────────────────────────────────────────────────

function Presets({ overview, onPick }: { overview: Overview; onPick: (title: string, request: QuickRequest) => void }) {
  const { language } = useKit();
  const listeningDb = DB_PORTS.filter((port) => overview.listening.some((item) => item.port === port && item.protocol === "tcp"));
  const dbPorts = (listeningDb.length ? listeningDb : DB_PORTS).join(",");
  const ssh = overview.ssh.ports.join(",");
  const presets = [
    { key: "web", icon: LanguageRoundedIcon, title: pick(language, W.ps_web), hint: pick(language, W.ps_webHint),
      request: { intents: [{ kind: "port", action: "accept", ports: "80,443", protocol: "tcp", scope: "both", source: { kind: "public" } }] } },
    { key: "db", icon: StorageRoundedIcon, title: pick(language, W.ps_db), hint: say(language, W.ps_dbHint, { ports: dbPorts.replaceAll(",", "، ") }),
      request: { intents: [{ kind: "port", action: "accept", ports: dbPorts, protocol: "tcp", scope: "both", source: { kind: "cidrs", cidrs: PRIVATE_NETS }, exclusive: true }] } },
    ...(overview.requester ? [{ key: "ssh", icon: TerminalRoundedIcon, title: pick(language, W.ps_ssh), hint: say(language, W.ps_sshHint, { ports: ssh, ip: overview.requester }),
      request: { intents: [{ kind: "port", action: "accept", ports: ssh, protocol: "tcp", scope: "both", source: { kind: "me" }, exclusive: true }] } }] : [])
  ];
  return (
    <Stack spacing={1}>
      <Typography variant="subtitle2">{pick(language, W.presetsTitle)}</Typography>
      <Box sx={{ display: "grid", gap: 1, gridTemplateColumns: { xs: "1fr", sm: "repeat(3, minmax(0, 1fr))" } }}>
        {presets.map(({ key, icon: Icon, title, hint, request }) => (
          <Button key={key} variant="outlined" color="inherit" onClick={() => onPick(title, request)}
            sx={{ justifyContent: "flex-start", textAlign: "start", alignItems: "flex-start", p: 1.5, minHeight: 72, gap: 1.25, textTransform: "none" }}>
            <Icon color="primary" />
            <Box>
              <Typography variant="body2" fontWeight={700}>{title}</Typography>
              <Typography variant="caption" color="text.secondary" component="div">{hint}</Typography>
            </Box>
          </Button>
        ))}
      </Box>
    </Stack>
  );
}

// ── shortcut form ───────────────────────────────────────────────────────────

type FormSeed = { ports: string; protocol: Protocol; action: "accept" | "drop"; source: string; exclusive: boolean; at: number };
const EXPIRY: Record<string, number | null> = { forever: null, h1: 3600, d1: 86400 };

function ShortcutForm({ overview, lists, seed, onApplied, renderError }: {
  overview: Overview; lists: Map<string, string>; seed: FormSeed | null; onApplied: (result: QuickResult | null) => void; renderError: (error: unknown, onClose?: () => void) => ReactNode;
}) {
  const { language } = useKit();
  const [open, setOpen] = useState(false);
  const [action, setAction] = useState<"accept" | "drop" | "block">("accept");
  const [ports, setPorts] = useState("");
  const [protocol, setProtocol] = useState<Protocol>("tcp");
  const [source, setSource] = useState("public");
  const [addresses, setAddresses] = useState("");
  const [exclusive, setExclusive] = useState(true);
  const [expiry, setExpiry] = useState("forever");
  const [hours, setHours] = useState("4");
  const [note, setNote] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [applyError, setApplyError] = useState<unknown>(null);
  const anchor = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!seed) return;
    setOpen(true);
    setAction(seed.action);
    setPorts(seed.ports);
    setProtocol(seed.protocol);
    setSource(seed.source);
    setExclusive(seed.exclusive);
    window.setTimeout(() => anchor.current?.scrollIntoView({ behavior: "smooth", block: "center" }), 50);
  }, [seed]);

  const expiresIn = expiry === "custom" ? Math.round(Number(hours.replace(/[۰-۹]/g, (d) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(d)))) * 3600) || null : EXPIRY[expiry];
  const cidrs = addresses.split(/[\s,،]+/).map((item) => item.trim()).filter(Boolean);
  const request = useMemo<QuickRequest | null>(() => {
    if (!open) return null;
    if (action === "block") {
      if (!cidrs.length) return null;
      return { intents: cidrs.slice(0, 16).map((cidr) => ({ kind: "block", cidr, expires_in: expiresIn, note })) };
    }
    if (!ports.trim()) return null;
    let src: Record<string, unknown> = { kind: "public" };
    if (source === "me") src = { kind: "me" };
    else if (source === "addr") { if (!cidrs.length) return null; src = { kind: "cidrs", cidrs }; }
    else if (source.startsWith("list:")) src = { kind: "list", list_id: source.slice(5) };
    return { intents: [{ kind: "port", action, ports: ports.trim(), protocol, scope: "both", source: src, exclusive: action === "accept" && source !== "public" && exclusive, expires_in: expiresIn, note }] };
  }, [open, action, ports, protocol, source, addresses, exclusive, expiresIn, note]); // eslint-disable-line react-hooks/exhaustive-deps
  const { preview, error, loading } = usePreview(request);
  const ready = canApply(preview, typed, language) && !loading;

  const apply = async () => {
    if (!request || !ready) return;
    setBusy(true);
    setApplyError(null);
    try {
      const body: Record<string, unknown> = { ...request, apply: true };
      if (preview?.problems.length) body.override = CONFIRM_WORDS.enforce.token;
      const result = await mutateJson<QuickResult>(`${API}/quick`, { method: "POST", body });
      setPorts("");
      setAddresses("");
      setNote("");
      setTyped("");
      onApplied(result);
    } catch (caught) {
      if (failed(caught)) setApplyError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box ref={anchor}>
      <Button size="small" startIcon={<TuneRoundedIcon />} onClick={() => setOpen(!open)} aria-expanded={open} sx={{ minHeight: 44 }}>{pick(language, W.formTitle)}</Button>
      <Collapse in={open} unmountOnExit>
        <Stack spacing={1.75} sx={{ pt: 1.5 }}>
          <ToggleButtonGroup exclusive size="small" value={action} onChange={(_event, value) => value && setAction(value)} aria-label={pick(language, W.f_action)} sx={{ flexWrap: "wrap" }}>
            <ToggleButton value="accept"><LockOpenRoundedIcon fontSize="small" sx={{ me: 0.75 }} />{pick(language, W.f_open)}</ToggleButton>
            <ToggleButton value="drop"><LockRoundedIcon fontSize="small" sx={{ me: 0.75 }} />{pick(language, W.f_close)}</ToggleButton>
            <ToggleButton value="block"><BlockRoundedIcon fontSize="small" sx={{ me: 0.75 }} />{pick(language, W.f_block)}</ToggleButton>
          </ToggleButtonGroup>
          {action !== "block" && (
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
              <TextField label={pick(language, W.f_ports)} helperText={pick(language, W.f_portsHelp)} value={ports} onChange={(event) => setPorts(event.target.value)} sx={{ flex: 1 }}
                slotProps={{ htmlInput: { dir: "ltr", inputMode: "numeric", spellCheck: false } }} />
              <Box>
                <Typography variant="caption" color="text.secondary" component="div" sx={{ mb: 0.5 }}>{pick(language, W.f_protocol)}</Typography>
                <ToggleButtonGroup exclusive size="small" value={protocol} onChange={(_event, value) => value && setProtocol(value)} aria-label={pick(language, W.f_protocol)}>
                  <ToggleButton value="tcp">{pick(language, W.pr_tcp)}</ToggleButton>
                  <ToggleButton value="udp">{pick(language, W.pr_udp)}</ToggleButton>
                  <ToggleButton value="both">{pick(language, W.pr_both)}</ToggleButton>
                </ToggleButtonGroup>
              </Box>
            </Stack>
          )}
          {action !== "block" && (
            <TextField select label={pick(language, W.f_source)} value={source} onChange={(event) => setSource(event.target.value)} fullWidth slotProps={{ select: { native: true } }}>
              <option value="public">{pick(language, W.f_everyone)}</option>
              {overview.requester && <option value="me">{say(language, W.f_me, { ip: overview.requester })}</option>}
              <option value="addr">{pick(language, W.f_addr)}</option>
              {[...lists.entries()].map(([id, name]) => <option key={id} value={`list:${id}`}>{say(language, W.f_list, { name })}</option>)}
            </TextField>
          )}
          {(action === "block" || source === "addr") && (
            <TextField label={pick(language, W.f_addrField)} value={addresses} onChange={(event) => setAddresses(event.target.value)} fullWidth placeholder="203.0.113.7, 10.0.0.0/8"
              slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
          )}
          {action === "accept" && source !== "public" && (
            <FormControlLabel control={<Switch checked={exclusive} onChange={(event) => setExclusive(event.target.checked)} />} label={pick(language, W.f_only)} />
          )}
          <Box>
            <Typography variant="caption" color="text.secondary" component="div" sx={{ mb: 0.5 }}>{pick(language, W.f_expiry)}</Typography>
            <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
              <ToggleButtonGroup exclusive size="small" value={expiry} onChange={(_event, value) => value && setExpiry(value)} aria-label={pick(language, W.f_expiry)}>
                <ToggleButton value="forever">{pick(language, W.f_forever)}</ToggleButton>
                <ToggleButton value="h1">{pick(language, W.f_1h)}</ToggleButton>
                <ToggleButton value="d1">{pick(language, W.f_1d)}</ToggleButton>
                <ToggleButton value="custom">{pick(language, W.f_custom)}</ToggleButton>
              </ToggleButtonGroup>
              {expiry === "custom" && <TextField size="small" label={pick(language, W.f_hours)} value={hours} onChange={(event) => setHours(event.target.value)} sx={{ width: 140 }} slotProps={{ htmlInput: { inputMode: "decimal", dir: "ltr" } }} />}
            </Stack>
          </Box>
          <TextField label={pick(language, W.f_note)} value={note} onChange={(event) => setNote(event.target.value)} fullWidth />
          {error !== null && renderError(error)}
          {applyError !== null && renderError(applyError, () => setApplyError(null))}
          {preview && <PreviewView preview={preview} lists={lists} typed={typed} onTyped={setTyped} />}
          <Box>
            <Button variant="contained" onClick={() => void apply()} disabled={!ready || busy} startIcon={busy || loading ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 48 }}>
              {pick(language, W.apply)}
            </Button>
          </Box>
        </Stack>
      </Collapse>
    </Box>
  );
}

// ── preview dialog (port toggles, presets) ────────────────────────────────────

function PreviewDialog({ title, request, lists, onClose, onApplied, renderError }: {
  title: string; request: QuickRequest; lists: Map<string, string>; onClose: () => void; onApplied: (result: QuickResult | null) => void;
  renderError: (error: unknown, onClose?: () => void) => ReactNode;
}) {
  const { language } = useKit();
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [applyError, setApplyError] = useState<unknown>(null);
  const { preview, error, loading } = usePreview(request, 0);
  const ready = canApply(preview, typed, language) && !loading;
  const apply = async () => {
    setBusy(true);
    setApplyError(null);
    try {
      const body: Record<string, unknown> = { ...request, apply: true };
      if (preview?.problems.length) body.override = CONFIRM_WORDS.enforce.token;
      onApplied(await mutateJson<QuickResult>(`${API}/quick`, { method: "POST", body }));
    } catch (caught) {
      if (failed(caught)) setApplyError(caught);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm" scroll="body">
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Stack spacing={1.5} sx={{ pt: 0.5 }}>
          {loading && !preview && <Stack alignItems="center" sx={{ py: 2 }}><CircularProgress size={28} /><Typography variant="caption" sx={{ mt: 1 }}>{pick(language, W.checking)}</Typography></Stack>}
          {error !== null && renderError(error)}
          {applyError !== null && renderError(applyError, () => setApplyError(null))}
          {preview && <PreviewView preview={preview} lists={lists} typed={typed} onTyped={setTyped} />}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{pick(language, W.cancel)}</Button>
        <Button variant="contained" onClick={() => void apply()} disabled={!ready || busy}>{pick(language, W.apply)}</Button>
      </DialogActions>
    </Dialog>
  );
}

// ── SSH port: where it came from, confirm or set it ──────────────────────────

function SshCard({ overview, canWrite, onSaved, onError }: { overview: Overview; canWrite: boolean; onSaved: () => void; onError: (error: unknown) => void }) {
  const { language } = useKit();
  const ssh = overview.ssh;
  const detected = ssh.detected;
  const [text, setText] = useState(ssh.admin_ports.join(", "));
  const [busy, setBusy] = useState(false);
  useEffect(() => setText(ssh.admin_ports.join(", ")), [ssh.admin_ports]);
  const save = async (ports: number[]) => {
    setBusy(true);
    try {
      await mutateJson(`${API}/settings`, { method: "PUT", body: { ssh_ports: ports } });
      onSaved();
    } catch (caught) {
      if (failed(caught)) onError(caught);
    } finally {
      setBusy(false);
    }
  };
  const parsed = text.replace(/[۰-۹]/g, (d) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(d))).split(/[\s,،]+/).map(Number).filter((value) => Number.isInteger(value) && value >= 1 && value <= 65535);
  const list = (ports: number[]) => ports.join("، ");
  const sourceWords: Record<string, Bi> = { listener: W.s_listener, ssh_socket: W.s_ssh_socket, sshd_config: W.s_sshd_config, admin: W.s_admin };
  const line = ssh.source === "assumed" ? pick(language, W.s_assumed) : say(language, sourceWords[ssh.source] ?? W.s_admin, { ports: list(ssh.ports) });
  const detectedReal = detected.source !== "assumed";
  const differs = ssh.source === "admin" && detectedReal && list(detected.ports) !== list([...ssh.admin_ports].sort((a, b) => a - b));
  const configDiffers = detected.source === "listener" && detected.sshd_config.readable && detected.sshd_config.ports.length > 0
    && detected.sshd_config.ports.some((port) => !detected.ports.includes(port));
  return (
    <SectionCard title={pick(language, W.sshTitle)} hint={pick(language, W.sshHint)}
      status={<StatusPill tone={ssh.source === "assumed" ? "warn" : "ok"} label={list(ssh.ports)} />}>
      <Stack spacing={1.25}>
        <Typography variant="body2">{line}</Typography>
        {differs && <Typography variant="body2" color="warning.main">{say(language, W.s_differs, { ports: list(detected.ports) })}</Typography>}
        {configDiffers && <Typography variant="body2" color="text.secondary">{say(language, W.s_mismatch, { ports: list(detected.sshd_config.ports) })}</Typography>}
        {detected.listener.other.length > 0 && <Typography variant="body2" color="text.secondary">{say(language, W.s_other, { ports: list(detected.listener.other.map((item) => item.port)) })}</Typography>}
        {ssh.source === "assumed" && !overview.configured && <Notice tone="warning">{pick(language, W.s_notPaired)}</Notice>}
        {ssh.source === "assumed" && overview.configured && (
          <Notice tone="warning">
            <Typography variant="body2" fontWeight={700}>{pick(language, W.s_fixTitle)}</Typography>
            <Box component="ol" sx={{ m: 0, ps: 2.5 }}>
              <li><Typography variant="body2">{pick(language, W.s_fix1)}</Typography></li>
              <li><Typography variant="body2">{pick(language, W.s_fix2)}</Typography></li>
            </Box>
            <Box sx={{ mt: 1 }}><CopyField label={pick(language, W.s_mounts)} value={MOUNTS} multiline /></Box>
            <Typography variant="body2" sx={{ mt: 1 }}>{pick(language, W.s_fix3)}</Typography>
          </Notice>
        )}
        {canWrite && (
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ sm: "center" }} useFlexGap flexWrap="wrap">
            {ssh.source !== "admin" && detectedReal && (
              <Button variant="outlined" onClick={() => void save(detected.ports)} disabled={busy} sx={{ minHeight: 44 }}>{say(language, W.s_confirm, { ports: list(detected.ports) })}</Button>
            )}
            {differs && <Button variant="outlined" onClick={() => void save(detected.ports)} disabled={busy} sx={{ minHeight: 44 }}>{say(language, W.s_useDetected, { ports: list(detected.ports) })}</Button>}
            {ssh.source === "admin" && <Button onClick={() => void save([])} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, W.s_auto)}</Button>}
          </Stack>
        )}
        {canWrite && (
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ sm: "flex-start" }}>
            <TextField size="small" label={pick(language, W.s_field)} value={text} onChange={(event) => setText(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", inputMode: "numeric" } }} sx={{ minWidth: 220 }} />
            <Button variant="contained" onClick={() => void save(parsed)} disabled={busy || parsed.length === 0} sx={{ minHeight: 40 }}>{pick(language, W.s_save)}</Button>
          </Stack>
        )}
      </Stack>
    </SectionCard>
  );
}
