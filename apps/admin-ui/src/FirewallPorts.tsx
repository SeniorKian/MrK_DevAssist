import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Box, Button, Checkbox, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Stack, Switch, TextField, Typography
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import RouterRoundedIcon from "@mui/icons-material/RouterRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import ViewInArRoundedIcon from "@mui/icons-material/ViewInArRounded";
import PublicRoundedIcon from "@mui/icons-material/PublicRounded";
import ListAltRoundedIcon from "@mui/icons-material/ListAltRounded";
import PinDropRoundedIcon from "@mui/icons-material/PinDropRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import CloudDownloadRoundedIcon from "@mui/icons-material/CloudDownloadRounded";
import { ApiError, getJson, isAbortError, mutateJson } from "./api";
import { CONFIRM_WORDS, matchesConfirmation, pick, say, type Bi } from "./copy";
import {
  ChoiceCards, CopyField, EmptyState, FriendlyError, Ltr, Notice, NumberInput, RelativeTime, ResponsiveList, SectionCard, StatusPill, useConfirmAction, useKit,
  useUndoSnackbar
} from "./kit";
import { formatNumber } from "./format";
import type { Language } from "./i18n";
import FirewallQuick from "./FirewallQuick";

/**
 * Security › Firewall › «پورت‌ها و سرویس‌ها» (docs/45).
 * Port rules for host services and Docker-published ports, a preview with the exact ruleset diff,
 * a typed confirmation, an automatic rollback timer with «این قوانین بمانند», read-only import from
 * UFW and the legacy «PAASIFY-DOCKER-FW» chain, and the emergency commands for the server console.
 */

type Protocol = "tcp" | "udp" | "both";
type Scope = "host" | "docker" | "both";
type Action = "accept" | "drop";
type Source = { kind: "public" } | { kind: "cidrs"; cidrs: string[] } | { kind: "list"; list_id: string };
type PortRule = {
  id: string; name: string; description: string; protocol: Protocol; ports: string[]; source: Source; scope: Scope; action: Action;
  enabled: boolean; priority: number; log: boolean; log_rate: number; origin: string; created_at: number;
};
type SourceList = { id: string; name: string; note: string; cidrs: string[] };
type Problem = { code: string; address?: string; port?: number; ports?: number[]; scope?: string; protocol?: string; key?: string };
type PortSettings = {
  default_deny_host: boolean; default_deny_docker: boolean; trust_docker_bridges: boolean; allow_icmp: boolean; log_drops: boolean;
  log_rate_per_minute: number; ssh_ports: number[]; panel_ports: number[]; temp_allow_requester: boolean; temp_allow_seconds: number;
  rollback_seconds: number; allow_closed_protected: string[];
};
type PortStatus = {
  configured: boolean; reachable: boolean | null; force_dry_run: boolean; nft_available: boolean | null; settings: PortSettings; active: boolean;
  applied_rules: number; pending: { deadline: number; started_at: number; remaining: number } | null;
  last_rollback: { at: number; reason: string; outcome: string } | null; applied_at: number | null;
  draft: { rules: number; enabled: number; differs: boolean }; ssh: { ports: number[]; source: "admin" | "listener" | "ssh_socket" | "sshd_config" | "assumed" };
  panel_ports: number[]; requester: string | null; problems: Problem[]; warnings: { code: string; name?: string }[]; protected: string[];
};
type Preview = { current: string; next: string; diff: string[]; changed: boolean; problems: Problem[]; rules: number; temp_allow: string[]; ssh_ports: number[]; panel_ports: number[] };
type Proposal = {
  name: string; description: string; protocol: Protocol; ports: string[]; source: Source; scope: Scope; action: Action; origin: string; raw: string;
  valid: boolean; imported: boolean;
};
type ImportResult = {
  ufw: { present: boolean; enabled: boolean | null; rules: Proposal[]; skipped: string[] };
  legacy: { available: boolean; present: boolean; backend: string | null; rules: Proposal[]; skipped: string[]; default_drop: boolean; docker_user_jump: boolean | null };
  ssh: { detected: boolean; ports: number[] };
  comparison: { port: number; protocol: "tcp" | "udp"; panel: boolean; ufw: boolean }[];
};

const API = "/api/v1/firewall/ports";
const COMPOSE = "docker compose";
const RECOVER = `${COMPOSE} exec mrk-firewall mrk-firewall recover`;
const RECOVER_OPEN = `${RECOVER} --open`;
const RECOVER_EXEC = "docker exec $(docker ps -qf name=mrk-firewall) mrk-firewall recover --open";
const LAST_RESORT = "sudo nft delete table inet mrk";
const JUMP_REMOVE = "sudo iptables -D DOCKER-USER -j PAASIFY-DOCKER-FW";
const JUMP_RESTORE = "sudo iptables -I DOCKER-USER 1 -j PAASIFY-DOCKER-FW";

const T = {
  title: { fa: "پورت‌ها و سرویس‌ها", en: "Ports and services" },
  hint: { fa: "کدام پورت‌های سرور و کانتینرهای Docker از بیرون باز باشند؛ هر تغییر اول پیش‌نمایش و بعد با تأیید شما اعمال می‌شود.", en: "Which ports of the server and of Docker containers are open from outside; every change is previewed first and applied only when you confirm." },
  off: { fa: "خاموش", en: "Off" },
  on: { fa: "روشن", en: "On" },
  waiting: { fa: "منتظر تأیید شما", en: "Waiting for you" },
  offBody: { fa: "پنل هنوز پورتی را باز یا بسته نمی‌کند. قوانین را بسازید، پیش‌نمایش را ببینید و بعد اعمال کنید.", en: "The panel doesn't open or close any port yet. Build the rules, check the preview, then apply." },
  onBody: { fa: "{n} قانون پورت روی سرور اعمال است.", en: "{n} port rules are applied on the server." },
  migrationTitle: { fa: "تا پایان مهاجرت", en: "Until the migration is finished" },
  migration: {
    fa: "قوانین UFW و «PAASIFY-DOCKER-FW» هنوز سر جایشان هستند و پاک نمی‌شوند. پس برای یک پورت منتشرشده Docker هر سه لازم است: انتشار پورت در Compose، اجازه در UFW و اجازه در «PAASIFY-DOCKER-FW» پیش از رد نهایی. «فهرست همیشه مجاز» فقط جلوی مسدود شدن نشانی را می‌گیرد و هیچ پورتی را باز نمی‌کند.",
    en: "UFW and «PAASIFY-DOCKER-FW» rules are still in place and are never deleted. So a Docker-published port needs all three: published in Compose, allowed in UFW and allowed in «PAASIFY-DOCKER-FW» before its final drop. The always-allowed list only keeps an address from being blocked; it never opens a port."
  },
  forced: { fa: "روی سرور فقط حالت تمرین مجاز است؛ قوانین پورت اعمال نمی‌شوند.", en: "The server only allows practice mode; port rules aren't applied." },
  notPaired: { fa: "اول نگهبان دیوار آتش را وصل کنید؛ بدون آن چیزی روی سرور اعمال نمی‌شود.", en: "Connect the firewall helper first; nothing is applied on the server without it." },
  draftDiffers: { fa: "قوانینی که این‌جا می‌بینید با آن‌چه روی سرور است فرق دارد. برای اعمال، «پیش‌نمایش و اعمال» را بزنید.", en: "The rules here differ from what's on the server. Use “Preview and apply” to apply them." },
  previewApply: { fa: "پیش‌نمایش و اعمال", en: "Preview and apply" },
  turnOff: { fa: "خاموش کردن قوانین پورت…", en: "Turn port rules off…" },
  turnOffTitle: { fa: "قوانین پورت خاموش شوند؟", en: "Turn port rules off?" },
  turnOffBody: { fa: "همه پورت‌ها مثل قبل از روشن کردن باز می‌شوند. نشانی‌های مسدود همچنان بسته می‌مانند.", en: "Every port opens again, as before you turned this on. Blocked addresses stay blocked." },
  turnedOff: { fa: "قوانین پورت خاموش شد.", en: "Port rules are off." },
  // pending / rollback
  pendingTitle: { fa: "قوانین تازه آزمایشی اعمال شد", en: "The new rules are on trial" },
  pendingBody: { fa: "اگر تا {s} ثانیه دیگر تأیید نکنید، سرور خودش به قوانین قبلی برمی‌گردد. اول از یک پنجره یا دستگاه دیگر مطمئن شوید که SSH و پنل باز هستند.", en: "If you don't confirm within {s} seconds, the server goes back to the previous rules on its own. First check from another window or device that SSH and the panel still open." },
  keep: { fa: "این قوانین بمانند", en: "Keep these rules" },
  undoNow: { fa: "همین حالا برگردان", en: "Undo now" },
  kept: { fa: "قوانین تازه ماندگار شد.", en: "The new rules are kept." },
  undone: { fa: "به قوانین قبلی برگشت.", en: "Went back to the previous rules." },
  rolledBack: { fa: "آخرین تغییر قوانین پورت نگه داشته نشد و سرور به قوانین قبلی برگشت ({reason}).", en: "The last port rule change wasn't kept; the server went back to the previous rules ({reason})." },
  reason_timeout: { fa: "تأیید به‌موقع نرسید", en: "it wasn't confirmed in time" },
  reason_restart: { fa: "نگهبان وسط آزمایش دوباره روشن شد", en: "the helper restarted during the trial" },
  reason_undo: { fa: "خودتان برگرداندید", en: "you undid it" },
  reason_recover: { fa: "دستور بازیابی روی سرور اجرا شد", en: "the recovery command ran on the server" },
  // problems
  problemsTitle: { fa: "این قوانین شما را بیرون می‌گذارند؛ تا درست نشوند اعمال نمی‌شوند:", en: "These rules would lock you out; they can't be applied until fixed:" },
  p_lockout_ssh: { fa: "SSH (پورت {ports}) برای {address} بسته می‌شود. یک قانون بسازید که آن را برای این نشانی باز کند.", en: "SSH (port {ports}) would close for {address}. Add a rule that opens it for this address." },
  p_lockout_panel: { fa: "پنل (پورت {port}) برای {address} بسته می‌شود ({scope}). قانونی با دامنه «هر دو» بسازید.", en: "The panel (port {port}) would close for {address} ({scope}). Add a rule with scope “Both”." },
  p_protected_port_closed: { fa: "پورت محافظت‌شده {port} ({protocol}) برای {what} بسته می‌شود.", en: "Protected port {port} ({protocol}) for {what} would close." },
  p_other: { fa: "این تغییر ممکن است دسترسی را قطع کند.", en: "This change could cut off access." },
  publicAddr: { fa: "همه نشانی‌ها", en: "every address" },
  // rules list
  rulesTitle: { fa: "قوانین پورت", en: "Port rules" },
  rulesHint: { fa: "از بالا به پایین خوانده می‌شوند و اولین قانونی که بخورد تصمیم می‌گیرد.", en: "Read top to bottom; the first rule that matches decides." },
  newRule: { fa: "قانون تازه", en: "New rule" },
  noRules: { fa: "هنوز قانونی نساخته‌اید.", en: "You haven't made any rule yet." },
  noRulesBody: { fa: "قانون بسازید یا قوانین فعلی را از سرور بخوانید.", en: "Make a rule, or read the current rules from the server." },
  name: { fa: "نام", en: "Name" },
  ports: { fa: "پورت‌ها", en: "Ports" },
  from: { fa: "از", en: "From" },
  where: { fa: "کجا", en: "Where" },
  what: { fa: "کار", en: "Does" },
  state: { fa: "وضعیت", en: "State" },
  allow: { fa: "باز کن", en: "Open" },
  deny: { fa: "ببند", en: "Close" },
  enabled: { fa: "روشن", en: "On" },
  disabled: { fa: "خاموش", en: "Off" },
  turnOn: { fa: "روشن کن", en: "Turn on" },
  turnOffRule: { fa: "خاموش کن", en: "Turn off" },
  edit: { fa: "ویرایش", en: "Edit" },
  remove: { fa: "پاک کن", en: "Remove" },
  removeTitle: { fa: "قانون «{name}» پاک شود؟", en: "Remove the rule “{name}”?" },
  removeBody: { fa: "تا وقتی دوباره اعمال نکنید، روی سرور چیزی عوض نمی‌شود.", en: "Nothing changes on the server until you apply again." },
  saved: { fa: "قانون «{name}» ذخیره شد. برای اعمال روی سرور «پیش‌نمایش و اعمال» را بزنید.", en: "The rule “{name}” was saved. Use “Preview and apply” to put it on the server." },
  removed: { fa: "قانون «{name}» پاک شد.", en: "The rule “{name}” was removed." },
  fromImport: { fa: "از سرور خوانده شد", en: "Read from the server" },
  sc_host: { fa: "خود سرور", en: "Server" },
  sc_docker: { fa: "کانتینرهای Docker", en: "Docker containers" },
  sc_both: { fa: "هر دو", en: "Both" },
  pr_tcp: { fa: "TCP", en: "TCP" },
  pr_udp: { fa: "UDP", en: "UDP" },
  pr_both: { fa: "TCP و UDP", en: "TCP and UDP" },
  src_public: { fa: "همه", en: "Everyone" },
  // editor
  editTitle: { fa: "قانون پورت", en: "Port rule" },
  description: { fa: "توضیح (اختیاری)", en: "Description (optional)" },
  portsField: { fa: "پورت یا بازه", en: "Port or range" },
  portsHelp: { fa: "مثل 22 یا 80,443 یا 14000-14999", en: "Like 22, or 80,443, or 14000-14999" },
  protocol: { fa: "نوع اتصال", en: "Connection type" },
  scope: { fa: "این پورت مال کیست؟", en: "Whose port is this?" },
  scHostBody: { fa: "برنامه‌هایی که مستقیم روی سرور اجرا می‌شوند، مثل SSH.", en: "Programs running directly on the server, like SSH." },
  scDockerBody: { fa: "پورت‌هایی که کانتینرها منتشر کرده‌اند (Docker، Swarm و Dokploy).", en: "Ports published by containers (Docker, Swarm and Dokploy)." },
  scBothBody: { fa: "اگر مطمئن نیستید یا سرور IPv6 دارد این را انتخاب کنید.", en: "Pick this if you're not sure, or the server uses IPv6." },
  source: { fa: "چه کسانی؟", en: "Who?" },
  srcPublicBody: { fa: "هر نشانی در اینترنت.", en: "Any address on the internet." },
  srcCidrs: { fa: "نشانی‌های مشخص", en: "Specific addresses" },
  srcCidrsBody: { fa: "یک یا چند نشانی IP یا محدوده (CIDR).", en: "One or more IP addresses or ranges (CIDR)." },
  srcList: { fa: "یک فهرست نام‌دار", en: "A named list" },
  srcListBody: { fa: "مثلاً فهرست «management» برای شبکه مدیریت.", en: "For example a «management» list for the admin network." },
  cidrsField: { fa: "نشانی‌ها (هر خط یکی)", en: "Addresses (one per line)" },
  listField: { fa: "فهرست", en: "List" },
  action: { fa: "چه کند؟", en: "What should it do?" },
  allowBody: { fa: "اتصال تازه به این پورت پذیرفته شود.", en: "New connections to this port are accepted." },
  denyBody: { fa: "اتصال تازه رد شود، حتی اگر بقیه پورت‌ها باز باشند.", en: "New connections are dropped, even when other ports are open." },
  order: { fa: "ترتیب (عدد کمتر زودتر)", en: "Order (lower goes first)" },
  logField: { fa: "ثبت در گزارش سرور (با سقف در دقیقه)", en: "Write to the server log (with a per-minute cap)" },
  logRate: { fa: "سقف خط در دقیقه", en: "Lines per minute" },
  enabledField: { fa: "این قانون روشن باشد", en: "This rule is on" },
  save: { fa: "ذخیره", en: "Save" },
  cancel: { fa: "انصراف", en: "Cancel" },
  close: { fa: "بستن", en: "Close" },
  needName: { fa: "یک نام بنویسید.", en: "Type a name." },
  needPorts: { fa: "دست‌کم یک پورت بنویسید.", en: "Type at least one port." },
  needList: { fa: "یک فهرست انتخاب کنید.", en: "Pick a list." },
  // lists
  listsTitle: { fa: "فهرست‌های نشانی", en: "Address lists" },
  listsHint: { fa: "گروهی از نشانی‌ها با یک نام. فهرستی به نام «management» همیشه باید به SSH و پنل برسد.", en: "A named group of addresses. A list named «management» must always reach SSH and the panel." },
  newList: { fa: "فهرست تازه", en: "New list" },
  noLists: { fa: "هنوز فهرستی نساخته‌اید.", en: "No list yet." },
  note: { fa: "یادداشت", en: "Note" },
  addresses: { fa: "نشانی‌ها", en: "Addresses" },
  listSaved: { fa: "فهرست «{name}» ذخیره شد.", en: "The list “{name}” was saved." },
  listRemoveTitle: { fa: "فهرست «{name}» پاک شود؟", en: "Remove the list “{name}”?" },
  listRemoveBody: { fa: "اگر قانونی از آن استفاده کند پاک نمی‌شود.", en: "It can't be removed while a rule uses it." },
  // settings
  settingsTitle: { fa: "رفتار پیش‌فرض", en: "Default behaviour" },
  settingsHint: { fa: "این‌ها هم مثل قوانین فقط با «پیش‌نمایش و اعمال» روی سرور می‌روند.", en: "Like the rules, these reach the server only through “Preview and apply”." },
  denyHost: { fa: "بقیه پورت‌های خود سرور بسته باشند", en: "Close every other port of the server" },
  denyDocker: { fa: "بقیه پورت‌های منتشرشده Docker بسته باشند", en: "Close every other Docker-published port" },
  denyHint: { fa: "خاموش یعنی هر پورتی که قانون ندارد باز می‌ماند؛ با نصب، هیچ پورتی خودبه‌خود بسته نمی‌شود.", en: "Off means any port without a rule stays open; installing never closes a port by itself." },
  trustBridges: { fa: "کانتینرها همیشه به خود سرور برسند", en: "Containers can always reach the server" },
  allowIcmp: { fa: "پاسخ به «ping»", en: "Answer «ping»" },
  logDrops: { fa: "اتصال‌های ردشده ثبت شوند", en: "Log dropped connections" },
  panelPorts: { fa: "پورت‌های دیگر پنل (جدا با کاما)", en: "Other panel ports (comma separated)" },
  panelPortsHint: { fa: "پورتی که الان با آن وارد شده‌اید ({ports}) همیشه بررسی می‌شود.", en: "The port you're using now ({ports}) is always checked." },
  tempAllow: { fa: "نشانی من موقتاً همیشه باز باشد", en: "Keep my address open for a while" },
  tempAllowHint: { fa: "نشانی شما ({ip}) هنگام اعمال برای مدتی همه پورت‌ها را دارد تا بیرون نمانید.", en: "When applying, your address ({ip}) can reach every port for a while so you aren't locked out." },
  tempSeconds: { fa: "مدت باز ماندن نشانی من (ثانیه)", en: "How long my address stays open (seconds)" },
  rollbackSeconds: { fa: "زمان برگشت خودکار (ثانیه)", en: "Automatic undo after (seconds)" },
  settingsSaved: { fa: "رفتار پیش‌فرض ذخیره شد.", en: "Default behaviour saved." },
  // apply dialog
  applyTitle: { fa: "پیش‌نمایش و اعمال قوانین پورت", en: "Preview and apply port rules" },
  applyIntro: { fa: "این دقیقاً تغییری است که روی سرور نوشته می‌شود. خطوط سبز اضافه و خطوط قرمز حذف می‌شوند.", en: "This is exactly what changes on the server. Green lines are added, red lines removed." },
  noChange: { fa: "قوانین پورت روی سرور عوض نمی‌شود.", en: "The port rules on the server don't change." },
  fullNext: { fa: "متن کامل قوانین بعدی", en: "Full next ruleset" },
  applyRollback: { fa: "اگر ظرف {s} ثانیه «این قوانین بمانند» را نزنید، خودکار برمی‌گردد.", en: "If you don't press “Keep these rules” within {s} seconds, it's undone automatically." },
  applyTyped: { fa: "برای اطمینان، «{word}» را بنویسید:", en: "To be sure, type {word}:" },
  applyYes: { fa: "اعمال آزمایشی", en: "Apply on trial" },
  applied: { fa: "قوانین آزمایشی اعمال شد؛ پس از بررسی دسترسی، «این قوانین بمانند» را بزنید.", en: "The rules are on trial; after checking access, press “Keep these rules”." },
  appliedFinal: { fa: "قوانین پورت اعمال شد.", en: "Port rules applied." },
  // import
  importTitle: { fa: "خواندن قوانین فعلی سرور", en: "Read the server's current rules" },
  importHint: { fa: "قوانین UFW و «PAASIFY-DOCKER-FW» فقط خوانده می‌شوند و دست نمی‌خورند. هر چه وارد کنید خاموش اضافه می‌شود تا اول بررسی کنید.", en: "UFW and «PAASIFY-DOCKER-FW» rules are only read, never changed. Whatever you import is added turned off so you can review it first." },
  readServer: { fa: "خواندن از سرور", en: "Read from the server" },
  ufw: { fa: "قوانین UFW", en: "UFW rules" },
  ufwOn: { fa: "UFW روشن است", en: "UFW is on" },
  ufwOff: { fa: "UFW خاموش است", en: "UFW is off" },
  ufwMissing: { fa: "قوانین UFW روی سرور پیدا نشد (یا پوشه آن به نگهبان وصل نیست).", en: "No UFW rules found on the server (or its folder isn't mounted into the helper)." },
  legacy: { fa: "زنجیره قدیمی «PAASIFY-DOCKER-FW»", en: "Legacy «PAASIFY-DOCKER-FW» chain" },
  legacyMissing: { fa: "این زنجیره روی سرور پیدا نشد.", en: "This chain wasn't found on the server." },
  legacyJump: { fa: "پرش از «DOCKER-USER» به این زنجیره فعال است.", en: "«DOCKER-USER» jumps to this chain." },
  legacyDrop: { fa: "این زنجیره در پایان هر چیز دیگری را رد می‌کند.", en: "This chain drops everything else at its end." },
  alreadyImported: { fa: "وارد شده", en: "Imported" },
  importSelected: { fa: "وارد کردن انتخاب‌شده‌ها (خاموش)", en: "Import the selected ones (turned off)" },
  imported: { fa: "{n} قانون خاموش اضافه شد؛ بررسی و روشن کنید.", en: "{n} rules were added turned off; review and turn them on." },
  skipped: { fa: "{n} خط خوانده نشد (مثلاً قانون خروجی یا شرط منفی).", en: "{n} lines couldn't be read (for example outgoing rules or negated matches)." },
  compareTitle: { fa: "مقایسه با پورت‌های باز سرور", en: "Compared with the server's open ports" },
  listening: { fa: "پورت باز روی سرور", en: "Open on the server" },
  inPanel: { fa: "در قوانین پنل", en: "In panel rules" },
  inUfw: { fa: "در UFW", en: "In UFW" },
  yes: { fa: "باز", en: "Open" },
  no: { fa: "بسته", en: "Closed" },
  stepsTitle: { fa: "قدم‌های دستی مهاجرت", en: "Manual migration steps" },
  steps: { fa: "این دستورها را پنل اجرا نمی‌کند. فقط بعد از اعمال و تأیید قوانین تازه و آزمایش SSH، پنل، وب، DNS، ایمیل و پایگاه‌داده از داخل و بیرون، پرش قدیمی را موقتاً بردارید. اگر مشکلی بود همان لحظه برگردانید. UFW و اسکریپت قدیمی را فقط پس از چند دور آزمایش و یک راه‌اندازی دوباره کنار بگذارید.", en: "The panel never runs these. Only after the new rules are applied and confirmed, and SSH, the panel, web, DNS, mail and databases were tested from inside and outside, remove the old jump temporarily. If anything breaks, put it back at once. Retire UFW and the old script only after several test rounds and a reboot." },
  stepRemove: { fa: "برداشتن موقت پرش قدیمی", en: "Remove the old jump temporarily" },
  stepRestore: { fa: "برگرداندن فوری پرش قدیمی", en: "Put the old jump back at once" },
  // emergency
  emergencyTitle: { fa: "اگر از سرور بیرون ماندید", en: "If you get locked out" },
  emergencyHint: { fa: "این دستورها را از کنسول سرور (مثلاً کنسول ارائه‌دهنده) در پوشه‌ای که فایروال نصب شده اجرا کنید.", en: "Run these from the server console (for example your provider's console) in the folder where the firewall was deployed." },
  cmdRecover: { fa: "برگشت به آخرین قوانین تأییدشده", en: "Go back to the last confirmed rules" },
  cmdOpen: { fa: "باز کردن همه پورت‌ها (مسدودی‌ها می‌مانند)", en: "Open every port (blocks stay)" },
  cmdExec: { fa: "همان، بدون Compose", en: "The same, without Compose" },
  cmdLast: { fa: "آخرین چاره: پاک کردن کامل جدول فایروال پنل", en: "Last resort: remove the panel's firewall table entirely" },
  protectedTitle: { fa: "پورت‌های محافظت‌شده", en: "Protected ports" },
  protectedHint: { fa: "پنل نمی‌گذارد این‌ها ناخواسته بسته شوند: {list}", en: "The panel won't let these close by accident: {list}" },
  refresh: { fa: "تازه کردن", en: "Refresh" }
} satisfies Record<string, Bi>;

const PROTECTED_WORDS: Record<string, Bi> = {
  "swarm-manager": { fa: "مدیریت Swarm", en: "Swarm management" },
  "swarm-gossip-tcp": { fa: "ارتباط گره‌های Swarm", en: "Swarm node gossip" },
  "swarm-gossip-udp": { fa: "ارتباط گره‌های Swarm", en: "Swarm node gossip" },
  "swarm-overlay": { fa: "شبکه داخلی Swarm", en: "Swarm overlay network" },
  dokploy: { fa: "پنل Dokploy", en: "Dokploy panel" },
  "dns-udp": { fa: "سرویس DNS", en: "DNS service" },
  "dns-tcp": { fa: "سرویس DNS", en: "DNS service" }
};

/** Codes this page explains itself; everything else goes through the shared catalog. */
const ERRORS: Record<string, Bi> = {
  invalid_ports: { fa: "پورت درست نیست؛ عددی بین 1 تا 65535 یا بازه‌ای مثل 14000-14999 بنویسید.", en: "That port isn't valid; use a number from 1 to 65535 or a range like 14000-14999." },
  invalid_sources: { fa: "نشانی‌ها درست نیستند؛ هر خط یک نشانی IP یا محدوده بنویسید.", en: "The addresses aren't valid; write one IP address or range per line." },
  invalid_port_rule: { fa: "قانون ذخیره نشد؛ فیلدها را بررسی کنید.", en: "The rule wasn't saved; check the fields." },
  invalid_source_list: { fa: "فهرست ذخیره نشد؛ نام و نشانی‌ها را بررسی کنید.", en: "The list wasn't saved; check its name and addresses." },
  invalid_port_settings: { fa: "این تنظیم ذخیره نشد؛ مقدارها را بررسی کنید.", en: "This setting wasn't saved; check the values." },
  port_rule_name_taken: { fa: "قانونی با همین نام هست؛ نام دیگری بنویسید.", en: "A rule with this name exists; pick another name." },
  source_list_name_taken: { fa: "فهرستی با همین نام هست.", en: "A list with this name exists." },
  source_list_not_found: { fa: "این فهرست دیگر وجود ندارد.", en: "That list no longer exists." },
  source_list_in_use: { fa: "قانونی هنوز از این فهرست استفاده می‌کند؛ اول آن قانون را عوض کنید.", en: "A rule still uses this list; change that rule first." },
  lockout_ssh: { fa: "اعمال نشد: SSH برای شما بسته می‌شد.", en: "Not applied: SSH would close for you." },
  lockout_panel: { fa: "اعمال نشد: پنل برای شما بسته می‌شد.", en: "Not applied: the panel would close for you." },
  protected_port_closed: { fa: "اعمال نشد: یک پورت محافظت‌شده بسته می‌شد.", en: "Not applied: a protected port would close." },
  no_pending_change: { fa: "تغییری منتظر تأیید نیست؛ شاید زمانش گذشته و برگشته است.", en: "No change is waiting; it may have timed out and been undone." },
  confirmation_required: { fa: "کلمه تأیید درست نوشته نشده.", en: "The confirmation word doesn't match." },
  too_many_port_rules: { fa: "تعداد قوانین پورت به سقف رسیده.", en: "The port rule limit is reached." }
};

function ErrorView({ error, onClose }: { error: unknown; onClose?: () => void }) {
  const { language } = useKit();
  if (error instanceof ApiError && ERRORS[error.code]) {
    const problems = Array.isArray(error.extra.problems) ? (error.extra.problems as Problem[]) : [];
    return (
      <Notice tone="error" action={onClose ? <Button color="inherit" size="small" onClick={onClose}>{pick(language, T.close)}</Button> : undefined}>
        {pick(language, ERRORS[error.code])}
        {problems.length > 0 && <ProblemList problems={problems} />}
      </Notice>
    );
  }
  return <FriendlyError error={error} onClose={onClose} scope="firewall" />;
}

function problemText(language: Language, problem: Problem) {
  const address = problem.address === "public" || !problem.address ? pick(language, T.publicAddr) : problem.address;
  const scope = problem.scope === "docker" ? pick(language, T.sc_docker) : pick(language, T.sc_host);
  switch (problem.code) {
    case "lockout_ssh": return say(language, T.p_lockout_ssh, { ports: (problem.ports ?? []).join(", "), address });
    case "lockout_panel": return say(language, T.p_lockout_panel, { port: String(problem.port ?? ""), address, scope });
    case "protected_port_closed": return say(language, T.p_protected_port_closed, {
      port: String(problem.port ?? ""), protocol: (problem.protocol ?? "").toUpperCase(), what: problem.key && PROTECTED_WORDS[problem.key] ? pick(language, PROTECTED_WORDS[problem.key]) : problem.key ?? ""
    });
    default: return pick(language, T.p_other);
  }
}

function ProblemList({ problems }: { problems: Problem[] }) {
  const { language } = useKit();
  return (
    <Box component="ul" sx={{ m: 0, mt: 0.5, ps: 2.5 }}>
      {problems.map((problem, index) => <li key={index}><Typography variant="body2">{problemText(language, problem)}</Typography></li>)}
    </Box>
  );
}

function scopeWord(language: Language, scope: Scope) {
  return pick(language, scope === "host" ? T.sc_host : scope === "docker" ? T.sc_docker : T.sc_both);
}

function protocolWord(language: Language, protocol: Protocol) {
  return pick(language, protocol === "tcp" ? T.pr_tcp : protocol === "udp" ? T.pr_udp : T.pr_both);
}

function sourceWord(language: Language, source: Source, lists: Map<string, SourceList>) {
  if (source.kind === "public") return pick(language, T.src_public);
  if (source.kind === "cidrs") return <Ltr mono>{source.cidrs.join(", ")}</Ltr>;
  return lists.get(source.list_id)?.name ?? "—";
}

function reasonWord(language: Language, reason: string) {
  if (reason.startsWith("recover")) return pick(language, T.reason_recover);
  if (reason === "timeout") return pick(language, T.reason_timeout);
  if (reason === "restart") return pick(language, T.reason_restart);
  if (reason === "undo") return pick(language, T.reason_undo);
  return reason;
}

const failed = (caught: unknown) => !(caught instanceof ApiError && caught.status === 401) && !isAbortError(caught);

// ── page section ─────────────────────────────────────────────────────────────

export default function FirewallPorts({ canWrite }: { canWrite: boolean }) {
  const { language } = useKit();
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [status, setStatus] = useState<PortStatus | null>(null);
  const [rules, setRules] = useState<PortRule[]>([]);
  const [lists, setLists] = useState<SourceList[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<PortRule | "new" | null>(null);
  const [listEditing, setListEditing] = useState<SourceList | "new" | null>(null);
  const [applyOpen, setApplyOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [quickKey, setQuickKey] = useState(0);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setQuickKey((key) => key + 1);
    try {
      const [nextStatus, nextRules, nextLists] = await Promise.all([
        getJson<PortStatus>(`${API}/status`, signal),
        getJson<{ items: PortRule[] }>(`${API}/rules`, signal),
        getJson<{ items: SourceList[] }>(`${API}/lists`, signal)
      ]);
      setStatus(nextStatus);
      setRules(nextRules.items);
      setLists(nextLists.items);
    } catch (caught) {
      if (failed(caught)) setError(caught);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const listsById = useMemo(() => new Map(lists.map((item) => [item.id, item])), [lists]);

  const run = async (work: () => Promise<unknown>, message?: Bi) => {
    setError(null);
    setBusy(true);
    try {
      await work();
      if (message) notify({ message: pick(language, message) });
      await load();
    } catch (caught) {
      if (failed(caught)) setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const toggle = (rule: PortRule) => run(() => mutateJson(`${API}/rules/${encodeURIComponent(rule.id)}`, { method: "PATCH", body: { enabled: !rule.enabled } }));
  const removeRule = async (rule: PortRule) => {
    const ok = await ask({ title: say(language, T.removeTitle, { name: rule.name }), body: pick(language, T.removeBody), severity: "destructive", undoable: false });
    if (ok) await run(() => mutateJson(`${API}/rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" }));
  };
  const turnOff = async () => {
    const ok = await ask({ title: pick(language, T.turnOffTitle), body: pick(language, T.turnOffBody), undoable: true, confirmLabel: pick(language, T.turnOff).replace("…", "") });
    if (ok) await run(() => mutateJson(`${API}/disable`, { method: "POST", body: {} }), T.turnedOff);
  };

  if (!status) {
    if (error) return <SectionCard title={pick(language, T.title)}><ErrorView error={error} /></SectionCard>;
    return <SectionCard title={pick(language, T.title)}><Stack alignItems="center" sx={{ py: 3 }}><CircularProgress /></Stack></SectionCard>;
  }

  const pill = status.pending
    ? <StatusPill tone="warn" label={pick(language, T.waiting)} />
    : <StatusPill tone={status.active ? "ok" : "off"} label={pick(language, status.active ? T.on : T.off)} />;

  return (
    <Stack spacing={2.5}>
      <SectionCard
        title={pick(language, T.title)}
        hint={pick(language, T.hint)}
        status={pill}
        action={<Button size="small" onClick={() => void load()} disabled={loading} sx={{ minHeight: 44 }}>{pick(language, T.refresh)}</Button>}
      >
        <Stack spacing={1.5}>
          {error !== null && <ErrorView error={error} onClose={() => setError(null)} />}
          {!status.configured && <Notice tone="warning">{pick(language, T.notPaired)}</Notice>}
          {status.force_dry_run && <Notice tone="warning">{pick(language, T.forced)}</Notice>}
          {status.pending && <PendingBanner key={status.pending.deadline} pending={status.pending} canWrite={canWrite} busy={busy}
            onKeep={() => void run(() => mutateJson(`${API}/confirm`, { method: "POST", body: {} }), T.kept)}
            onUndo={() => void run(() => mutateJson(`${API}/rollback`, { method: "POST", body: {} }), T.undone)}
            onExpired={() => void load()} />}
          {!status.pending && status.last_rollback && (
            <Notice tone="warning">{say(language, T.rolledBack, { reason: reasonWord(language, status.last_rollback.reason) })} <RelativeTime value={status.last_rollback.at * 1000} /></Notice>
          )}
          <Typography variant="body2" color="text.secondary">
            {status.active ? say(language, T.onBody, { n: formatNumber(status.applied_rules, language) }) : pick(language, T.offBody)}
          </Typography>
          <Notice>
            <Typography variant="body2" fontWeight={700}>{pick(language, T.migrationTitle)}</Typography>
            {pick(language, T.migration)}
          </Notice>
          {status.draft.differs && <Notice>{pick(language, T.draftDiffers)}</Notice>}
          {status.problems.length > 0 && status.draft.differs && (
            <Notice tone="warning">{pick(language, T.problemsTitle)}<ProblemList problems={status.problems} /></Notice>
          )}
          {status.protected.length > 0 && (
            <Typography variant="body2" color="text.secondary">
              {say(language, T.protectedHint, { list: [...new Set(status.protected.map((key) => (PROTECTED_WORDS[key] ? pick(language, PROTECTED_WORDS[key]) : key)))].join("، ") })}
            </Typography>
          )}
          {canWrite && (
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
              <Button variant="contained" onClick={() => setApplyOpen(true)} disabled={!status.configured || busy || Boolean(status.pending)} sx={{ minHeight: 48 }}>
                {pick(language, T.previewApply)}
              </Button>
              {status.active && !status.pending && <Button color="error" variant="outlined" onClick={() => void turnOff()} disabled={busy} sx={{ minHeight: 48 }}>{pick(language, T.turnOff)}</Button>}
            </Stack>
          )}
        </Stack>
      </SectionCard>

      <FirewallQuick canWrite={canWrite} reloadKey={quickKey} onChanged={() => void load()} renderError={(caught, onClose) => <ErrorView error={caught} onClose={onClose} />} />

      <SectionCard
        title={pick(language, T.rulesTitle)}
        hint={pick(language, T.rulesHint)}
        flush
        action={canWrite ? <Button size="small" startIcon={<AddRoundedIcon />} onClick={() => setEditing("new")} sx={{ minHeight: 44 }}>{pick(language, T.newRule)}</Button> : undefined}
      >
        <ResponsiveList<PortRule>
          label={pick(language, T.rulesTitle)}
          rows={rules}
          rowKey={(row) => row.id}
          empty={<EmptyState compact title={pick(language, T.noRules)} body={pick(language, T.noRulesBody)} />}
          columns={[
            { key: "name", header: pick(language, T.name), render: (row) => row.name },
            { key: "ports", header: pick(language, T.ports), render: (row) => <><Ltr mono>{row.ports.join(", ")}</Ltr> · {protocolWord(language, row.protocol)}</> },
            { key: "from", header: pick(language, T.from), render: (row) => sourceWord(language, row.source, listsById) },
            { key: "scope", header: pick(language, T.where), render: (row) => scopeWord(language, row.scope), hideOnCard: true },
            { key: "action", header: pick(language, T.what), render: (row) => pick(language, row.action === "accept" ? T.allow : T.deny) },
            { key: "order", header: "#", render: (row) => formatNumber(row.priority, language), advancedOnly: true },
            { key: "state", header: pick(language, T.state), render: (row) => <StatusPill tone={row.enabled ? "ok" : "off"} label={pick(language, row.enabled ? T.enabled : T.disabled)} /> }
          ]}
          card={{
            title: (row) => row.name,
            meta: (row) => <><Ltr mono>{row.ports.join(", ")}</Ltr> · {protocolWord(language, row.protocol)} · {scopeWord(language, row.scope)}{row.origin !== "manual" ? ` · ${pick(language, T.fromImport)}` : ""}</>,
            status: (row) => <StatusPill tone={row.enabled ? (row.action === "accept" ? "ok" : "warn") : "off"} label={pick(language, row.enabled ? (row.action === "accept" ? T.allow : T.deny) : T.disabled)} />
          }}
          actions={canWrite ? [
            { key: "on", label: pick(language, T.turnOn), onClick: (row) => void toggle(row), hidden: (row) => row.enabled },
            { key: "off", label: pick(language, T.turnOffRule), onClick: (row) => void toggle(row), hidden: (row) => !row.enabled },
            { key: "edit", label: pick(language, T.edit), icon: EditRoundedIcon, onClick: (row) => setEditing(row) },
            { key: "delete", label: pick(language, T.remove), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (row) => void removeRule(row) }
          ] : undefined}
        />
      </SectionCard>

      <ListsCard lists={lists} canWrite={canWrite} onEdit={setListEditing} onRemove={async (item) => {
        const ok = await ask({ title: say(language, T.listRemoveTitle, { name: item.name }), body: pick(language, T.listRemoveBody), severity: "destructive", undoable: false });
        if (ok) await run(() => mutateJson(`${API}/lists/${encodeURIComponent(item.id)}`, { method: "DELETE" }));
      }} />

      <SettingsCard status={status} canWrite={canWrite} onSaved={() => { notify({ message: pick(language, T.settingsSaved) }); void load(); }} onError={setError} />

      <ImportCard canWrite={canWrite} configured={status.configured} onImported={(n) => { notify({ message: say(language, T.imported, { n: formatNumber(n, language) }) }); void load(); }} />

      <SectionCard title={pick(language, T.emergencyTitle)} hint={pick(language, T.emergencyHint)} collapsible defaultCollapsed>
        <Stack spacing={1.5}>
          <CopyField label={pick(language, T.cmdRecover)} value={RECOVER} />
          <CopyField label={pick(language, T.cmdOpen)} value={RECOVER_OPEN} />
          <CopyField label={pick(language, T.cmdExec)} value={RECOVER_EXEC} />
          <CopyField label={pick(language, T.cmdLast)} value={LAST_RESORT} />
        </Stack>
      </SectionCard>

      {editing && <RuleDialog rule={editing === "new" ? null : editing} lists={lists} onClose={() => setEditing(null)} onDone={(name) => { setEditing(null); notify({ message: say(language, T.saved, { name }) }); void load(); }} />}
      {listEditing && <ListDialog item={listEditing === "new" ? null : listEditing} onClose={() => setListEditing(null)} onDone={(name) => { setListEditing(null); notify({ message: say(language, T.listSaved, { name }) }); void load(); }} />}
      {applyOpen && <ApplyDialog status={status} onClose={() => setApplyOpen(false)} onDone={(pending) => { setApplyOpen(false); notify({ message: pick(language, pending ? T.applied : T.appliedFinal) }); void load(); }} />}
      {dialog}
      {snackbar}
    </Stack>
  );
}

// ── rollback countdown ──────────────────────────────────────────────────────

function PendingBanner({ pending, canWrite, busy, onKeep, onUndo, onExpired }: {
  pending: NonNullable<PortStatus["pending"]>; canWrite: boolean; busy: boolean; onKeep: () => void; onUndo: () => void; onExpired: () => void;
}) {
  const { language } = useKit();
  const [left, setLeft] = useState(pending.remaining);
  const expired = useRef(onExpired);
  expired.current = onExpired;
  const initial = useRef(pending.remaining);
  useEffect(() => {
    // Count down from the server's remaining time once per pending change (keyed by deadline);
    // re-renders of the page must not restart the clock.
    const end = Date.now() + initial.current * 1000;
    let fired = false;
    const timer = window.setInterval(() => {
      const next = Math.max(0, Math.round((end - Date.now()) / 1000));
      setLeft(next);
      if (next === 0 && !fired) {
        fired = true;
        window.setTimeout(() => expired.current(), 2500);
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, [pending.deadline]);
  return (
    <Notice tone="warning">
      <Typography variant="body2" fontWeight={700}>{pick(language, T.pendingTitle)}</Typography>
      <span role="timer" aria-live="polite">{say(language, T.pendingBody, { s: formatNumber(left, language) })}</span>
      {canWrite && (
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ mt: 1.25 }}>
          <Button variant="contained" color="success" startIcon={<CheckCircleRoundedIcon />} onClick={onKeep} disabled={busy || left === 0} sx={{ minHeight: 44 }}>{pick(language, T.keep)}</Button>
          <Button variant="outlined" color="inherit" onClick={onUndo} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, T.undoNow)}</Button>
        </Stack>
      )}
    </Notice>
  );
}

// ── rule editor ─────────────────────────────────────────────────────────────

function RuleDialog({ rule, lists, onClose, onDone }: { rule: PortRule | null; lists: SourceList[]; onClose: () => void; onDone: (name: string) => void }) {
  const { language, isAdvanced } = useKit();
  const [name, setName] = useState(rule?.name ?? "");
  const [description, setDescription] = useState(rule?.description ?? "");
  const [ports, setPorts] = useState(rule?.ports.join(",") ?? "");
  const [protocol, setProtocol] = useState<Protocol>(rule?.protocol ?? "tcp");
  const [scope, setScope] = useState<Scope>(rule?.scope ?? "both");
  const [sourceKind, setSourceKind] = useState<Source["kind"]>(rule?.source.kind ?? "public");
  const [cidrs, setCidrs] = useState(rule?.source.kind === "cidrs" ? rule.source.cidrs.join("\n") : "");
  const [listId, setListId] = useState(rule?.source.kind === "list" ? rule.source.list_id : lists[0]?.id ?? "");
  const [action, setAction] = useState<Action>(rule?.action ?? "accept");
  const [priority, setPriority] = useState<number | null>(rule?.priority ?? null);
  const [log, setLog] = useState(rule?.log ?? false);
  const [logRate, setLogRate] = useState<number | null>(rule?.log_rate ?? 10);
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [problem, setProblem] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!name.trim()) return setProblem(pick(language, T.needName));
    if (!ports.trim()) return setProblem(pick(language, T.needPorts));
    if (sourceKind === "list" && !listId) return setProblem(pick(language, T.needList));
    setProblem(null);
    const source: Source = sourceKind === "public" ? { kind: "public" } : sourceKind === "cidrs"
      ? { kind: "cidrs", cidrs: cidrs.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean) }
      : { kind: "list", list_id: listId };
    const body: Record<string, unknown> = { name: name.trim(), description: description.trim(), protocol, ports: ports.trim(), scope, action, source, enabled, log, log_rate: logRate ?? 10 };
    if (priority !== null) body.priority = priority;
    setSaving(true);
    try {
      if (rule) await mutateJson(`${API}/rules/${encodeURIComponent(rule.id)}`, { method: "PATCH", body });
      else await mutateJson(`${API}/rules`, { method: "POST", body });
      onDone(name.trim());
    } catch (caught) {
      if (failed(caught)) setError(caught);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm" scroll="body">
      <DialogTitle>{pick(language, T.editTitle)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error !== null && <ErrorView error={error} onClose={() => setError(null)} />}
          <TextField label={pick(language, T.name)} value={name} onChange={(event) => setName(event.target.value)} fullWidth />
          <TextField label={pick(language, T.portsField)} helperText={pick(language, T.portsHelp)} value={ports} onChange={(event) => setPorts(event.target.value)} fullWidth slotProps={{ htmlInput: { dir: "ltr", inputMode: "numeric", spellCheck: false } }} />
          <ChoiceCards<Protocol> label={pick(language, T.protocol)} value={protocol} onChange={setProtocol} options={[
            { key: "tcp", title: pick(language, T.pr_tcp) }, { key: "udp", title: pick(language, T.pr_udp) }, { key: "both", title: pick(language, T.pr_both) }
          ]} />
          <Typography variant="subtitle2">{pick(language, T.scope)}</Typography>
          <ChoiceCards<Scope> label={pick(language, T.scope)} value={scope} onChange={setScope} options={[
            { key: "host", icon: DnsRoundedIcon, title: pick(language, T.sc_host), body: pick(language, T.scHostBody) },
            { key: "docker", icon: ViewInArRoundedIcon, title: pick(language, T.sc_docker), body: pick(language, T.scDockerBody) },
            { key: "both", icon: RouterRoundedIcon, title: pick(language, T.sc_both), body: pick(language, T.scBothBody) }
          ]} />
          <Typography variant="subtitle2">{pick(language, T.source)}</Typography>
          <ChoiceCards<Source["kind"]> label={pick(language, T.source)} value={sourceKind} onChange={setSourceKind} options={[
            { key: "public", icon: PublicRoundedIcon, title: pick(language, T.src_public), body: pick(language, T.srcPublicBody) },
            { key: "cidrs", icon: PinDropRoundedIcon, title: pick(language, T.srcCidrs), body: pick(language, T.srcCidrsBody) },
            { key: "list", icon: ListAltRoundedIcon, title: pick(language, T.srcList), body: pick(language, T.srcListBody), disabled: lists.length === 0 }
          ]} />
          {sourceKind === "cidrs" && <TextField label={pick(language, T.cidrsField)} value={cidrs} onChange={(event) => setCidrs(event.target.value)} multiline minRows={2} fullWidth slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />}
          {sourceKind === "list" && (
            <TextField select label={pick(language, T.listField)} value={listId} onChange={(event) => setListId(event.target.value)} fullWidth slotProps={{ select: { native: true } }}>
              {lists.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </TextField>
          )}
          <Typography variant="subtitle2">{pick(language, T.action)}</Typography>
          <ChoiceCards<Action> label={pick(language, T.action)} value={action} onChange={setAction} options={[
            { key: "accept", icon: CheckCircleRoundedIcon, title: pick(language, T.allow), body: pick(language, T.allowBody) },
            { key: "drop", icon: BlockRoundedIcon, title: pick(language, T.deny), body: pick(language, T.denyBody), tone: "warning" }
          ]} />
          <TextField label={pick(language, T.description)} value={description} onChange={(event) => setDescription(event.target.value)} fullWidth />
          {isAdvanced && <NumberInput label={pick(language, T.order)} value={priority} onChange={setPriority} min={0} max={100000} integer />}
          <FormControlLabel control={<Switch checked={log} onChange={(event) => setLog(event.target.checked)} />} label={pick(language, T.logField)} />
          {log && <NumberInput label={pick(language, T.logRate)} value={logRate} onChange={setLogRate} min={1} max={600} integer />}
          <FormControlLabel control={<Switch checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />} label={pick(language, T.enabledField)} />
          {problem && <Notice tone="warning">{problem}</Notice>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{pick(language, T.cancel)}</Button>
        <Button variant="contained" onClick={() => void save()} disabled={saving}>{pick(language, T.save)}</Button>
      </DialogActions>
    </Dialog>
  );
}

// ── named lists ─────────────────────────────────────────────────────────────

function ListsCard({ lists, canWrite, onEdit, onRemove }: { lists: SourceList[]; canWrite: boolean; onEdit: (item: SourceList | "new") => void; onRemove: (item: SourceList) => void }) {
  const { language } = useKit();
  return (
    <SectionCard
      title={pick(language, T.listsTitle)}
      hint={pick(language, T.listsHint)}
      flush
      collapsible
      action={canWrite ? <Button size="small" startIcon={<AddRoundedIcon />} onClick={() => onEdit("new")} sx={{ minHeight: 44 }}>{pick(language, T.newList)}</Button> : undefined}
    >
      <ResponsiveList<SourceList>
        label={pick(language, T.listsTitle)}
        rows={lists}
        rowKey={(row) => row.id}
        empty={<EmptyState compact title={pick(language, T.noLists)} />}
        columns={[
          { key: "name", header: pick(language, T.name), render: (row) => row.name },
          { key: "cidrs", header: pick(language, T.addresses), render: (row) => <Ltr mono>{row.cidrs.join(", ")}</Ltr> },
          { key: "note", header: pick(language, T.note), render: (row) => row.note, hideOnCard: true }
        ]}
        card={{ title: (row) => row.name, meta: (row) => <Ltr mono>{row.cidrs.join(", ")}</Ltr> }}
        actions={canWrite ? [
          { key: "edit", label: pick(language, T.edit), icon: EditRoundedIcon, onClick: (row) => onEdit(row) },
          { key: "delete", label: pick(language, T.remove), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (row) => onRemove(row) }
        ] : undefined}
      />
    </SectionCard>
  );
}

function ListDialog({ item, onClose, onDone }: { item: SourceList | null; onClose: () => void; onDone: (name: string) => void }) {
  const { language } = useKit();
  const [name, setName] = useState(item?.name ?? "");
  const [note, setNote] = useState(item?.note ?? "");
  const [cidrs, setCidrs] = useState(item?.cidrs.join("\n") ?? "");
  const [error, setError] = useState<unknown>(null);
  const save = async () => {
    const body = { name: name.trim(), note: note.trim(), cidrs: cidrs.split(/[\s,]+/).map((entry) => entry.trim()).filter(Boolean) };
    try {
      if (item) await mutateJson(`${API}/lists/${encodeURIComponent(item.id)}`, { method: "PATCH", body });
      else await mutateJson(`${API}/lists`, { method: "POST", body });
      onDone(body.name);
    } catch (caught) {
      if (failed(caught)) setError(caught);
    }
  };
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{pick(language, T.listsTitle)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error !== null && <ErrorView error={error} onClose={() => setError(null)} />}
          <TextField label={pick(language, T.name)} value={name} onChange={(event) => setName(event.target.value)} fullWidth />
          <TextField label={pick(language, T.cidrsField)} value={cidrs} onChange={(event) => setCidrs(event.target.value)} multiline minRows={3} fullWidth slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
          <TextField label={pick(language, T.note)} value={note} onChange={(event) => setNote(event.target.value)} fullWidth />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{pick(language, T.cancel)}</Button>
        <Button variant="contained" onClick={() => void save()} disabled={!name.trim() || !cidrs.trim()}>{pick(language, T.save)}</Button>
      </DialogActions>
    </Dialog>
  );
}

// ── default behaviour ───────────────────────────────────────────────────────

function parsePorts(text: string) {
  return text.split(/[\s,]+/).map((item) => Number(item)).filter((value) => Number.isInteger(value) && value >= 1 && value <= 65535);
}

function SettingsCard({ status, canWrite, onSaved, onError }: { status: PortStatus; canWrite: boolean; onSaved: () => void; onError: (error: unknown) => void }) {
  const { language, isAdvanced } = useKit();
  const [draft, setDraft] = useState<PortSettings>(status.settings);
  const [panelText, setPanelText] = useState(status.settings.panel_ports.join(","));
  useEffect(() => {
    setDraft(status.settings);
    setPanelText(status.settings.panel_ports.join(","));
  }, [status.settings]);
  const flag = (key: keyof PortSettings, label: Bi, hint?: string) => (
    <FormControlLabel
      control={<Switch checked={Boolean(draft[key])} disabled={!canWrite} onChange={(event) => setDraft({ ...draft, [key]: event.target.checked })} />}
      label={<Box><Typography variant="body2">{pick(language, label)}</Typography>{hint && <Typography variant="caption" color="text.secondary">{hint}</Typography>}</Box>}
    />
  );
  const save = async () => {
    try {
      const { ssh_ports: _ssh, ...rest } = draft;
      void _ssh; // the SSH port has its own card (FirewallQuick)
      await mutateJson(`${API}/settings`, { method: "PUT", body: { ...rest, panel_ports: parsePorts(panelText) } });
      onSaved();
    } catch (caught) {
      if (failed(caught)) onError(caught);
    }
  };
  return (
    <SectionCard title={pick(language, T.settingsTitle)} hint={pick(language, T.settingsHint)} collapsible>
      <Stack spacing={1.25}>
        {flag("default_deny_host", T.denyHost, pick(language, T.denyHint))}
        {flag("default_deny_docker", T.denyDocker)}
        {flag("temp_allow_requester", T.tempAllow, say(language, T.tempAllowHint, { ip: status.requester ?? "—" }))}
        {flag("trust_docker_bridges", T.trustBridges)}
        {flag("allow_icmp", T.allowIcmp)}
        {flag("log_drops", T.logDrops)}
        {isAdvanced && (
          <>
            <TextField label={pick(language, T.panelPorts)} helperText={say(language, T.panelPortsHint, { ports: status.panel_ports.join(", ") })} value={panelText} disabled={!canWrite} onChange={(event) => setPanelText(event.target.value)} slotProps={{ htmlInput: { dir: "ltr" } }} />
            <NumberInput label={pick(language, T.rollbackSeconds)} value={draft.rollback_seconds} onChange={(value) => setDraft({ ...draft, rollback_seconds: value ?? 120 })} min={30} max={900} integer />
            <NumberInput label={pick(language, T.tempSeconds)} value={draft.temp_allow_seconds} onChange={(value) => setDraft({ ...draft, temp_allow_seconds: value ?? 3600 })} min={300} max={604800} integer />
          </>
        )}
        {canWrite && <Box><Button variant="outlined" onClick={() => void save()} sx={{ minHeight: 44 }}>{pick(language, T.save)}</Button></Box>}
      </Stack>
    </SectionCard>
  );
}

// ── preview + apply ─────────────────────────────────────────────────────────

function DiffView({ lines }: { lines: string[] }) {
  return (
    <Box component="pre" dir="ltr" sx={{ m: 0, p: 1.5, maxHeight: 360, overflow: "auto", borderRadius: 1, bgcolor: "action.hover", fontSize: 12, lineHeight: 1.6, tabSize: 4, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" }}>
      {lines.map((line, index) => (
        <Box key={index} component="span" sx={{ display: "block", whiteSpace: "pre", color: line.startsWith("+") && !line.startsWith("+++") ? "success.main" : line.startsWith("-") && !line.startsWith("---") ? "error.main" : undefined }}>{line || " "}</Box>
      ))}
    </Box>
  );
}

function ApplyDialog({ status, onClose, onDone }: { status: PortStatus; onClose: () => void; onDone: (pending: boolean) => void }) {
  const { language, isAdvanced } = useKit();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [typed, setTyped] = useState("");
  const [tempAllow, setTempAllow] = useState(status.settings.temp_allow_requester);
  const [busy, setBusy] = useState(false);
  const word = CONFIRM_WORDS.enforce;
  const typedOk = matchesConfirmation(typed, word, language);
  useEffect(() => {
    const controller = new AbortController();
    getJson<Preview>(`${API}/preview`, controller.signal).then(setPreview).catch((caught) => { if (failed(caught)) setError(caught); });
    return () => controller.abort();
  }, []);
  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await mutateJson<PortStatus>(`${API}/apply`, { method: "POST", body: { confirmation: word.token, temp_allow: tempAllow } });
      onDone(Boolean(result?.pending));
    } catch (caught) {
      if (failed(caught)) setError(caught);
    } finally {
      setBusy(false);
    }
  };
  const blocked = !preview || preview.problems.length > 0;
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md" scroll="body">
      <DialogTitle>{pick(language, T.applyTitle)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error !== null && <ErrorView error={error} />}
          {!preview && !error && <Stack alignItems="center" sx={{ py: 3 }}><CircularProgress /></Stack>}
          {preview && (
            <>
              {preview.problems.length > 0 && <Notice tone="error">{pick(language, T.problemsTitle)}<ProblemList problems={preview.problems} /></Notice>}
              <Typography variant="body2">{pick(language, T.applyIntro)}</Typography>
              {preview.diff.length ? <DiffView lines={preview.diff} /> : <Notice>{pick(language, T.noChange)}</Notice>}
              {isAdvanced && <CopyField label={pick(language, T.fullNext)} value={preview.next} multiline />}
              <FormControlLabel control={<Switch checked={tempAllow} onChange={(event) => setTempAllow(event.target.checked)} />}
                label={<Box><Typography variant="body2">{pick(language, T.tempAllow)}</Typography><Typography variant="caption" color="text.secondary">{say(language, T.tempAllowHint, { ip: status.requester ?? "—" })}</Typography></Box>} />
              <Notice tone="warning">{say(language, T.applyRollback, { s: formatNumber(status.settings.rollback_seconds, language) })}</Notice>
              <TextField label={say(language, T.applyTyped, { word: pick(language, word.word) })} value={typed} onChange={(event) => setTyped(event.target.value)} disabled={blocked} fullWidth autoComplete="off" />
            </>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{pick(language, T.cancel)}</Button>
        <Button variant="contained" color="warning" onClick={() => void apply()} disabled={blocked || !typedOk || busy}>{pick(language, T.applyYes)}</Button>
      </DialogActions>
    </Dialog>
  );
}

// ── read-only import ────────────────────────────────────────────────────────

function ImportCard({ canWrite, configured, onImported }: { canWrite: boolean; configured: boolean; onImported: (count: number) => void }) {
  const { language } = useKit();
  const [data, setData] = useState<ImportResult | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const read = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getJson<ImportResult>(`${API}/import`);
      setData(result);
      setSelected(new Set());
    } catch (caught) {
      if (failed(caught)) setError(caught);
    } finally {
      setLoading(false);
    }
  };
  const all = data ? [...data.ufw.rules.map((item, index) => ({ key: `ufw-${index}`, item })), ...data.legacy.rules.map((item, index) => ({ key: `legacy-${index}`, item }))] : [];
  const importNow = async () => {
    const items = all.filter((entry) => selected.has(entry.key)).map((entry) => entry.item);
    try {
      const result = await mutateJson<{ items: unknown[] }>(`${API}/import`, { method: "POST", body: { items } });
      onImported(result?.items.length ?? items.length);
      await read();
    } catch (caught) {
      if (failed(caught)) setError(caught);
    }
  };
  const row = (key: string, item: Proposal) => (
    <FormControlLabel key={key} disabled={!canWrite || !item.valid || item.imported}
      control={<Checkbox checked={selected.has(key)} onChange={(event) => {
        const next = new Set(selected);
        if (event.target.checked) next.add(key); else next.delete(key);
        setSelected(next);
      }} />}
      label={<Box>
        <Typography variant="body2"><Ltr mono>{item.ports.join(", ")}</Ltr> · {protocolWord(language, item.protocol)} · {pick(language, item.action === "accept" ? T.allow : T.deny)} · {item.source.kind === "cidrs" ? <Ltr mono>{item.source.cidrs.join(", ")}</Ltr> : pick(language, T.src_public)}{item.imported ? ` · ${pick(language, T.alreadyImported)}` : ""}</Typography>
        <Typography variant="caption" color="text.secondary"><Ltr mono>{item.raw}</Ltr></Typography>
      </Box>}
    />
  );
  return (
    <SectionCard title={pick(language, T.importTitle)} hint={pick(language, T.importHint)} collapsible
      action={<Button size="small" startIcon={loading ? <CircularProgress size={14} /> : <CloudDownloadRoundedIcon />} onClick={() => void read()} disabled={!configured || loading} sx={{ minHeight: 44 }}>{pick(language, T.readServer)}</Button>}>
      <Stack spacing={2}>
        {error !== null && <ErrorView error={error} onClose={() => setError(null)} />}
        {data && (
          <>
            <Typography variant="subtitle2">{pick(language, T.ufw)} {data.ufw.present && <StatusPill tone={data.ufw.enabled ? "ok" : "off"} label={pick(language, data.ufw.enabled ? T.ufwOn : T.ufwOff)} />}</Typography>
            {data.ufw.present ? <Stack>{data.ufw.rules.map((item, index) => row(`ufw-${index}`, item))}</Stack> : <Notice>{pick(language, T.ufwMissing)}</Notice>}
            {data.ufw.skipped.length > 0 && <Typography variant="caption" color="text.secondary">{say(language, T.skipped, { n: formatNumber(data.ufw.skipped.length, language) })}</Typography>}
            <Typography variant="subtitle2">{pick(language, T.legacy)}</Typography>
            {data.legacy.present ? (
              <>
                {data.legacy.docker_user_jump && <Typography variant="body2">{pick(language, T.legacyJump)}</Typography>}
                {data.legacy.default_drop && <Typography variant="body2">{pick(language, T.legacyDrop)}</Typography>}
                <Stack>{data.legacy.rules.map((item, index) => row(`legacy-${index}`, item))}</Stack>
                {data.legacy.skipped.length > 0 && <Typography variant="caption" color="text.secondary">{say(language, T.skipped, { n: formatNumber(data.legacy.skipped.length, language) })}</Typography>}
              </>
            ) : <Notice>{pick(language, T.legacyMissing)}</Notice>}
            {canWrite && all.length > 0 && <Box><Button variant="outlined" onClick={() => void importNow()} disabled={selected.size === 0} sx={{ minHeight: 44 }}>{pick(language, T.importSelected)}</Button></Box>}
            {data.comparison.length > 0 && (
              <>
                <Typography variant="subtitle2">{pick(language, T.compareTitle)}</Typography>
                <ResponsiveList<ImportResult["comparison"][number]>
                  label={pick(language, T.compareTitle)}
                  dense
                  rows={data.comparison}
                  rowKey={(item) => `${item.protocol}-${item.port}`}
                  columns={[
                    { key: "port", header: pick(language, T.listening), render: (item) => <Ltr mono>{`${item.port}/${item.protocol}`}</Ltr> },
                    { key: "panel", header: pick(language, T.inPanel), render: (item) => <StatusPill tone={item.panel ? "ok" : "warn"} label={pick(language, item.panel ? T.yes : T.no)} /> },
                    { key: "ufw", header: pick(language, T.inUfw), render: (item) => <StatusPill tone={item.ufw ? "ok" : "off"} label={pick(language, item.ufw ? T.yes : T.no)} /> }
                  ]}
                  card={{ title: (item) => <Ltr mono>{`${item.port}/${item.protocol}`}</Ltr>, meta: (item) => `${pick(language, T.inPanel)}: ${pick(language, item.panel ? T.yes : T.no)} · ${pick(language, T.inUfw)}: ${pick(language, item.ufw ? T.yes : T.no)}` }}
                />
              </>
            )}
          </>
        )}
        <Typography variant="subtitle2">{pick(language, T.stepsTitle)}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{pick(language, T.steps)}</Typography>
        <CopyField label={pick(language, T.stepRemove)} value={JUMP_REMOVE} />
        <CopyField label={pick(language, T.stepRestore)} value={JUMP_RESTORE} />
      </Stack>
    </SectionCard>
  );
}
