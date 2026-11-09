import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Box, Button, ButtonBase, Card, CardContent, Divider, FormControlLabel, Grid, IconButton, ListItemIcon, ListItemText,
  Menu, MenuItem, Skeleton, Stack, Switch, TextField, Typography
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import SendRoundedIcon from "@mui/icons-material/SendRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import TelegramIcon from "@mui/icons-material/Telegram";
import ChatRoundedIcon from "@mui/icons-material/ChatRounded";
import EmailRoundedIcon from "@mui/icons-material/EmailRounded";
import WebhookRoundedIcon from "@mui/icons-material/WebhookRounded";
import NotificationsActiveRoundedIcon from "@mui/icons-material/NotificationsActiveRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import type { SvgIconComponent } from "@mui/icons-material";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { AuthUser } from "./App";
import {
  ActionWizard, DateTime, EmptyState, FriendlyError, KeyValueList, ListInput, Ltr, NoAccess, Notice, NumberInput, RelativeTime, StatusPill,
  TestResult, useConfirmAction, useKit, useUndoSnackbar, CardMenu, type TestOutcome, type WizardStep
} from "./kit";
import { CHANNEL_KIND_WORDS, describeError, errorSentence, nameConfirmation, pick, say, type Bi } from "./copy";
import { ProxyPicker, supportedTypesFor, useProxyList } from "./ProxyControls";

export type ChannelKind = "telegram" | "bale" | "email" | "webhook";
export type Channel = {
  id: string;
  name: string;
  kind: ChannelKind;
  enabled: boolean;
  config: Record<string, unknown>;
  secret_configured: boolean;
  created_at: number;
  updated_at: number;
  last_delivery_at: number | null;
  last_status: string | null;
};

export const NOTIFY_BASE = "/api/v1/notifications";

export const KIND_ICONS: Record<ChannelKind, SvgIconComponent> = {
  telegram: TelegramIcon,
  bale: ChatRoundedIcon,
  email: EmailRoundedIcon,
  webhook: WebhookRoundedIcon
};

export function kindWord(language: "fa" | "en", kind: string) {
  return CHANNEL_KIND_WORDS[kind]?.[language] ?? (language === "fa" ? "کانال" : "Channel");
}

/** Delivery statuses in plain words (shared with DeliveriesPanel). */
export const DELIVERY_WORDS: Record<string, { tone: "ok" | "error" | "info" | "off" | "warn"; label: Bi }> = {
  sent: { tone: "ok", label: { fa: "فرستاده شد", en: "Sent" } },
  ok: { tone: "ok", label: { fa: "فرستاده شد", en: "Sent" } },
  success: { tone: "ok", label: { fa: "فرستاده شد", en: "Sent" } },
  failed: { tone: "error", label: { fa: "فرستاده نشد", en: "Not sent" } },
  error: { tone: "error", label: { fa: "فرستاده نشد", en: "Not sent" } },
  pending: { tone: "info", label: { fa: "در نوبت", en: "Waiting" } },
  queued: { tone: "info", label: { fa: "در نوبت", en: "Waiting" } },
  retrying: { tone: "info", label: { fa: "دوباره امتحان می‌شود", en: "Retrying" } },
  delayed: { tone: "info", label: { fa: "بعد از ساعت سکوت فرستاده می‌شود", en: "Held for quiet hours" } },
  suppressed: { tone: "off", label: { fa: "تکراری بود؛ فرستاده نشد", en: "Repeat; not sent" } }
};

export function deliveryWord(language: "fa" | "en", status: string | null | undefined) {
  const entry = (status && DELIVERY_WORDS[status]) || null;
  return entry ? { tone: entry.tone, label: entry.label[language] } : { tone: "off" as const, label: language === "fa" ? "نامشخص" : "Unknown" };
}

const KIND_INFO: Record<ChannelKind, { description: Bi; howTo: Bi[] }> = {
  telegram: {
    description: { fa: "پیام به گروه یا گفتگوی تلگرام شما", en: "A message to your Telegram group or chat" },
    howTo: [
      { fa: "در تلگرام به ‎@BotFather پیام بدهید، ‎/newbot را بفرستید و توکن ربات را کپی کنید.", en: "In Telegram, message @BotFather, send /newbot and copy the bot token." },
      { fa: "ربات را به گروه تیمتان اضافه کنید، یا خودتان یک پیام به آن بدهید.", en: "Add the bot to your team group, or send it a message yourself." },
      { fa: "شناسه گفتگو را با ربات ‎@userinfobot پیدا کنید. شناسه گروه‌ها با «-» شروع می‌شود.", en: "Find the chat ID with @userinfobot. Group IDs start with “-”." }
    ]
  },
  bale: {
    description: { fa: "پیام در بله؛ داخل ایران بدون پروکسی کار می‌کند", en: "A message in Bale; works inside Iran without a proxy" },
    howTo: [
      { fa: "در بله به ‎@botfather پیام بدهید و یک ربات بسازید تا توکنش را بگیرید.", en: "In Bale, message @botfather and make a bot to get its token." },
      { fa: "ربات را به گروه اضافه کنید، یا خودتان یک پیام به آن بدهید.", en: "Add the bot to a group, or send it a message yourself." },
      { fa: "شناسه گفتگو را از یک ربات شناسه‌یاب بله بگیرید.", en: "Get the chat ID from a Bale ID bot." }
    ]
  },
  email: {
    description: { fa: "ایمیل با سرور ایمیل سازمان یا جیمیل", en: "Email through your company mail server or Gmail" },
    howTo: [
      { fa: "نشانی سرور ایمیل، پورت و نام کاربری را از مسئول ایمیل یا سرویس‌دهنده‌تان بگیرید.", en: "Get the mail server address, port and username from your mail admin or provider." },
      { fa: "برای جیمیل، به‌جای رمز اصلی یک «رمز برنامه» بسازید و آن را بنویسید.", en: "For Gmail, create an app password and use it instead of your real password." },
      { fa: "پورت ۵۸۷ معمولاً با «امن، با شروع ساده» و پورت ۴۶۵ با «امن از ابتدا» کار می‌کند.", en: "Port 587 usually goes with “Secure (STARTTLS)”, port 465 with “Secure from the start (TLS)”." }
    ]
  },
  webhook: {
    description: { fa: "فرستادن خودکار رویداد به نشانی یک سرویس دیگر", en: "Send events automatically to another service's address" },
    howTo: [
      { fa: "پیشکار هر رویداد را به نشانی‌ای که می‌دهید می‌فرستد؛ مثلاً به ابزار گفتگوی تیم یا سامانه پیگیری.", en: "Pishkar sends each event to the address you give, such as your team chat tool or a ticketing system." },
      { fa: "اگر کلید امضا بگذارید، هر پیام امضا می‌شود تا سرویس مقصد مطمئن شود از پیشکار آمده.", en: "With a signing key, each message is signed so the receiver knows it came from Pishkar." }
    ]
  }
};

const T = {
  title: { fa: "کانال‌های اعلان", en: "Alert channels" },
  hint: { fa: "جاهایی که پیشکار وقتی اتفاق مهمی افتاد به شما خبر می‌دهد.", en: "Where Pishkar tells you when something important happens." },
  add: { fa: "افزودن کانال", en: "Add a channel" },
  addTelegram: { fa: "افزودن تلگرام", en: "Add Telegram" },
  addOther: { fa: "کانال دیگر", en: "Another channel" },
  emptyTitle: { fa: "هنوز کانال اعلانی ندارید", en: "You don't have an alert channel yet" },
  emptyBody: { fa: "با افزودن تلگرام یا بله، اگر سرور مشکلی پیدا کند فوراً خبردار می‌شوید.", en: "Add Telegram or Bale and you'll hear right away if the server has a problem." },
  unavailable: { fa: "بخش اعلان‌ها روی نسخه فعلی سرور نیست. پیشکار را به‌روز کنید.", en: "Alerts aren't available on this server version. Update Pishkar." },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  switchLabel: { fa: "روشن یا خاموش کردن «{name}»", en: "Turn “{name}” on or off" },
  never: { fa: "هنوز پیامی نفرستاده", en: "No messages yet" },
  lastSent: { fa: "آخرین پیام: ", en: "Last message: " },
  noSecret: { fa: "توکن ربات تنظیم نشده", en: "Bot token not set" },
  test: { fa: "پیام آزمایشی", en: "Send a test" },
  menu: { fa: "کارهای مربوط به {name}", en: "Actions for {name}" },
  edit: { fa: "ویرایش", en: "Edit" },
  remove: { fa: "پاک کردن", en: "Delete" },
  testOk: { fa: "پیام آزمایشی رسید؟ {kind} را نگاه کنید.", en: "Did the test arrive? Check {kind}." },
  turnedOn: { fa: "«{name}» روشن شد.", en: "“{name}” is on." },
  turnedOff: { fa: "«{name}» خاموش شد؛ تا روشنش نکنید پیامی به آن نمی‌رود.", en: "“{name}” is off; nothing is sent to it until you turn it on." },
  deleteTitle: { fa: "کانال «{name}» پاک شود؟", en: "Delete the channel “{name}”?" },
  deleteBody: { fa: "دیگر هیچ پیامی به این کانال نمی‌رود.", en: "No more messages go to this channel." },
  deleteEffect: { fa: "قواعد اعلانِ این کانال هم پاک می‌شوند.", en: "This channel's alert rules are deleted too." },
  deletedToast: { fa: "کانال «{name}» پاک شد.", en: "“{name}” was deleted." },
  // wizard
  wizardNew: { fa: "افزودن کانال اعلان", en: "Add an alert channel" },
  wizardEdit: { fa: "ویرایش «{name}»", en: "Edit “{name}”" },
  stepKind: { fa: "کجا خبرتان کنیم؟", en: "Where should we tell you?" },
  stepKindHint: { fa: "یکی را انتخاب کنید. بعداً می‌توانید کانال‌های بیشتری اضافه کنید.", en: "Pick one. You can add more channels later." },
  pickKind: { fa: "یکی از گزینه‌ها را انتخاب کنید.", en: "Pick one of the options." },
  stepDetails: { fa: "اطلاعات اتصال", en: "Connection details" },
  stepDetailsHint: { fa: "این چند قدم را انجام دهید و نتیجه را این‌جا بنویسید.", en: "Follow these steps and fill in the result here." },
  stepSave: { fa: "ذخیره و امتحان", en: "Save and test" },
  stepSaveHint: { fa: "کانال ذخیره می‌شود و یک پیام آزمایشی به آن می‌فرستیم.", en: "We save the channel and send it a test message." },
  finishNew: { fa: "ذخیره و فرستادن پیام آزمایشی", en: "Save and send a test" },
  finishEdit: { fa: "ذخیره تغییرات", en: "Save changes" },
  name: { fa: "نام کانال (مثلاً «گروه تیم فنی»)", en: "Channel name (e.g. “Ops team”)" },
  botToken: { fa: "توکن ربات", en: "Bot token" },
  chatId: { fa: "شناسه گفتگو", en: "Chat ID" },
  apiBase: { fa: "نشانی سرور ربات (اختیاری)", en: "Bot server address (optional)" },
  apiBaseHint: { fa: "خالی بگذارید تا نشانی معمول استفاده شود. فقط برای سرور ربات خودتان یا واسطه.", en: "Leave empty for the usual address. Only for your own bot server or a relay." },
  htmlFormat: { fa: "پیام‌های قالب‌دار (پررنگ و پیوند)", en: "Formatted messages (HTML)" },
  smtpHost: { fa: "نشانی سرور ایمیل", en: "Mail server address" },
  smtpPort: { fa: "پورت", en: "Port" },
  security: { fa: "اتصال امن", en: "Secure connection" },
  starttls: { fa: "امن، با شروع ساده (پیشنهادی، پورت ۵۸۷)", en: "Secure (STARTTLS, port 587, recommended)" },
  tls: { fa: "امن از ابتدا (پورت ۴۶۵)", en: "Secure from the start (TLS, port 465)" },
  insecure: { fa: "بدون رمزنگاری (پیشنهاد نمی‌شود)", en: "Not encrypted (not recommended)" },
  smtpUser: { fa: "نام کاربری ایمیل", en: "Mail username" },
  smtpPassword: { fa: "رمز ایمیل", en: "Mail password" },
  from: { fa: "نشانی فرستنده", en: "Sender address" },
  to: { fa: "گیرنده‌ها", en: "Recipients" },
  toHint: { fa: "هر ایمیل را بنویسید و Enter بزنید.", en: "Type each email and press Enter." },
  url: { fa: "نشانی وب‌هوک", en: "Webhook address" },
  headers: { fa: "سرآیندهای اضافه (هر خط یکی، مثل «X-Team: ops»)", en: "Extra headers (one per line, like “X-Team: ops”)" },
  signingKey: { fa: "کلید امضا (اختیاری، دست‌کم ۱۶ نویسه)", en: "Signing key (optional, 16+ characters)" },
  timeout: { fa: "حداکثر زمان انتظار", en: "Timeout" },
  seconds: { fa: "ثانیه", en: "seconds" },
  keepSecret: { fa: "ذخیره شده؛ برای نگه داشتن همین، خالی بگذارید", en: "Saved; leave empty to keep it" },
  required: { fa: "این خانه را پر کنید.", en: "Fill in this field." },
  portRule: { fa: "پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد.", en: "The port must be a number from 1 to 65535." },
  urlRule: { fa: "نشانی باید با https:// یا http:// شروع شود.", en: "The address must start with https:// or http://." },
  headersRule: { fa: "هر خط باید به شکل «نام: مقدار» باشد.", en: "Each line must look like “Name: value”." },
  timeoutRule: { fa: "حداکثر زمان انتظار باید بین ۲ تا ۶۰ ثانیه باشد.", en: "The timeout must be 2 to 60 seconds." },
  emailRule: { fa: "ایمیل را مثل name@example.com بنویسید.", en: "Write the email like name@example.com." },
  fixFirst: { fa: "چند خانه را باید درست کنید؛ با رنگ قرمز مشخص شده‌اند.", en: "A few fields need fixing; they're marked in red." },
  defaultRule: { fa: "برای هشدارها و مشکلات مهم، به این کانال پیام بفرست", en: "Send warnings and important problems to this channel" },
  defaultRuleHint: { fa: "بعداً در «قواعد اعلان» دقیق‌ترش کنید.", en: "Fine-tune it later under Alert rules." },
  savedNew: { fa: "کانال «{name}» ذخیره شد.", en: "“{name}” was saved." },
  savedEdit: { fa: "تغییرات «{name}» ذخیره شد.", en: "Changes to “{name}” were saved." },
  testAgain: { fa: "دوباره امتحان کن", en: "Test again" },
  // advanced
  advId: { fa: "شناسه", en: "ID" },
  advProxy: { fa: "راه ارتباط", en: "Connection" },
  advDirect: { fa: "مستقیم", en: "Direct" },
  advDefaultProxy: { fa: "پروکسی پیش‌فرض", en: "Default proxy" },
  advSpecificProxy: { fa: "یک پروکسی مشخص", en: "A specific proxy" },
  advCreated: { fa: "ساخته شده", en: "Created" },
  advUpdated: { fa: "آخرین تغییر", en: "Last change" },
  readOnly: { fa: "نقش شما فقط اجازه دیدن کانال‌ها را دارد.", en: "Your role can only see channels." }
} satisfies Record<string, Bi>;

type Form = {
  name: string;
  chatId: string;
  apiBaseUrl: string;
  html: boolean;
  botToken: string;
  smtpHost: string;
  smtpPort: number | null;
  security: "starttls" | "tls" | "none";
  username: string;
  password: string;
  fromAddress: string;
  toAddresses: string[];
  url: string;
  headers: string;
  signingKey: string;
  timeout: number | null;
  proxyId: string;
  createDefaultRule: boolean;
};

type FormErrors = Partial<Record<keyof Form, string>>;

function str(value: unknown) {
  return typeof value === "string" ? value : typeof value === "number" ? String(value) : "";
}

function emptyForm(kind: ChannelKind, language: "fa" | "en"): Form {
  return {
    name: kindWord(language, kind),
    chatId: "",
    apiBaseUrl: "",
    html: false,
    botToken: "",
    smtpHost: "",
    smtpPort: 587,
    security: "starttls",
    username: "",
    password: "",
    fromAddress: "",
    toAddresses: [],
    url: "",
    headers: "",
    signingKey: "",
    timeout: null,
    proxyId: "",
    createDefaultRule: true
  };
}

function formFromChannel(channel: Channel, language: "fa" | "en"): Form {
  const config = channel.config ?? {};
  const headers = config.headers && typeof config.headers === "object" ? (config.headers as Record<string, unknown>) : {};
  const to = Array.isArray(config.to_addresses) ? (config.to_addresses as unknown[]).map(str).filter(Boolean) : [];
  const security = str(config.security);
  return {
    ...emptyForm(channel.kind, language),
    name: channel.name,
    chatId: str(config.chat_id),
    apiBaseUrl: str(config.api_base_url),
    html: config.parse_mode === "HTML",
    smtpHost: str(config.smtp_host),
    smtpPort: typeof config.smtp_port === "number" ? config.smtp_port : Number(config.smtp_port) || 587,
    security: security === "tls" || security === "none" ? security : "starttls",
    username: str(config.username),
    fromAddress: str(config.from_address),
    toAddresses: to,
    url: str(config.url),
    headers: Object.entries(headers).map(([key, value]) => `${key}: ${str(value)}`).join("\n"),
    timeout: typeof config.timeout_seconds === "number" ? config.timeout_seconds : null,
    proxyId: str(config.proxy_id),
    createDefaultRule: false
  };
}

function parseHeaders(text: string): Record<string, string> | null {
  const result: Record<string, string> = {};
  for (const line of text.split("\n").map((item) => item.trim()).filter(Boolean)) {
    const index = line.indexOf(":");
    if (index <= 0) return null;
    const key = line.slice(0, index).trim();
    if (!/^[A-Za-z0-9-]+$/.test(key)) return null;
    result[key] = line.slice(index + 1).trim();
  }
  return result;
}

const HTTP_URL = /^https?:\/\/\S+$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validate(kind: ChannelKind, form: Form, editing: Channel | null, language: "fa" | "en"): FormErrors {
  const errors: FormErrors = {};
  const need = pick(language, T.required);
  if (!form.name.trim()) errors.name = need;
  if (kind === "telegram" || kind === "bale") {
    if (!form.botToken.trim() && !editing?.secret_configured) errors.botToken = need;
    if (!form.chatId.trim()) errors.chatId = need;
    if (form.apiBaseUrl.trim() && !HTTP_URL.test(form.apiBaseUrl.trim())) errors.apiBaseUrl = pick(language, T.urlRule);
  } else if (kind === "email") {
    if (!form.smtpHost.trim()) errors.smtpHost = need;
    if (form.smtpPort === null || !Number.isInteger(form.smtpPort) || form.smtpPort < 1 || form.smtpPort > 65535) errors.smtpPort = pick(language, T.portRule);
    if (!EMAIL.test(form.fromAddress.trim())) errors.fromAddress = pick(language, T.emailRule);
    if (form.toAddresses.length === 0) errors.toAddresses = need;
  } else {
    if (!HTTP_URL.test(form.url.trim())) errors.url = pick(language, T.urlRule);
    if (parseHeaders(form.headers) === null) errors.headers = pick(language, T.headersRule);
  }
  if (form.timeout !== null && (form.timeout < 2 || form.timeout > 60)) errors.timeout = pick(language, T.timeoutRule);
  return errors;
}

function buildConfig(kind: ChannelKind, form: Form, clearProxy: boolean): Record<string, unknown> {
  let config: Record<string, unknown>;
  if (kind === "telegram" || kind === "bale") {
    config = { chat_id: form.chatId.trim() };
    if (form.apiBaseUrl.trim()) config.api_base_url = form.apiBaseUrl.trim();
    if (form.html) config.parse_mode = "HTML";
  } else if (kind === "email") {
    config = {
      smtp_host: form.smtpHost.trim(),
      smtp_port: form.smtpPort,
      security: form.security,
      username: form.username.trim(),
      from_address: form.fromAddress.trim(),
      to_addresses: form.toAddresses
    };
  } else {
    const headers = parseHeaders(form.headers) ?? {};
    config = Object.keys(headers).length ? { url: form.url.trim(), headers } : { url: form.url.trim() };
  }
  if (form.timeout !== null) config.timeout_seconds = form.timeout;
  if (form.proxyId) config.proxy_id = form.proxyId;
  else if (clearProxy) config.proxy_id = null;
  return config;
}

function buildSecret(kind: ChannelKind, form: Form): Record<string, string> | null {
  if (kind === "telegram" || kind === "bale") return form.botToken.trim() ? { bot_token: form.botToken.trim() } : null;
  if (kind === "email") return form.password ? { password: form.password } : null;
  return form.signingKey.trim() ? { signing_key: form.signingKey.trim() } : null;
}

/** Backend field names → form keys, for server-side field errors. */
const FIELD_MAP: Record<string, keyof Form> = {
  name: "name", bot_token: "botToken", chat_id: "chatId", api_base_url: "apiBaseUrl", parse_mode: "html", smtp_host: "smtpHost",
  smtp_port: "smtpPort", security: "security", username: "username", password: "password", from_address: "fromAddress",
  to_addresses: "toAddresses", url: "url", headers: "headers", signing_key: "signingKey", timeout_seconds: "timeout"
};

function summary(channel: Channel) {
  const config = channel.config ?? {};
  if (channel.kind === "email") return Array.isArray(config.to_addresses) ? (config.to_addresses as unknown[]).map(str).join(", ") : str(config.from_address);
  if (channel.kind === "webhook") return str(config.url);
  return str(config.chat_id);
}

function KindCard({ kind, selected, onClick }: { kind: ChannelKind; selected: boolean; onClick: () => void }) {
  const { language } = useKit();
  const Icon = KIND_ICONS[kind];
  return (
    <Card variant="outlined" sx={{ height: "100%", borderColor: selected ? "primary.main" : undefined, borderWidth: selected ? 2 : 1 }}>
      <ButtonBase role="radio" aria-checked={selected} onClick={onClick} sx={{ display: "block", width: "100%", height: "100%", textAlign: "start" }}>
        <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <Icon color={selected ? "primary" : "action"} sx={{ fontSize: 32 }} aria-hidden />
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography sx={{ fontWeight: 760 }}>{kindWord(language, kind)}</Typography>
              <Typography variant="body2" color="text.secondary">{pick(language, KIND_INFO[kind].description)}</Typography>
            </Box>
            {selected && <CheckCircleRoundedIcon color="primary" fontSize="small" aria-hidden />}
          </Stack>
        </CardContent>
      </ButtonBase>
    </Card>
  );
}

export type ChannelsPanelProps = {
  user: AuthUser;
  /** Increment to open the add wizard (the page's primary button). */
  addRequest?: number;
  /** Called after channels change (rules/deliveries may want to reload). */
  onChanged?: () => void;
};

export function ChannelsPanel({ user, addRequest = 0, onChanged }: ChannelsPanelProps) {
  const { language, isAdvanced, c } = useKit();
  const { ask, dialog: confirmDialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canWrite = hasPermission(user.permissions, "notification:write");
  const [channels, setChannels] = useState<Channel[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [tests, setTests] = useState<Record<string, TestOutcome>>({});
  const controller = useRef<AbortController | null>(null);
  const { list: proxyList, failed: proxyFailed } = useProxyList();

  // wizard
  const [wizardOpen, setWizardOpen] = useState(false);
  const [editing, setEditing] = useState<Channel | null>(null);
  const [kind, setKind] = useState<ChannelKind | null>(null);
  const [form, setForm] = useState<Form>(() => emptyForm("telegram", language));
  const [touched, setTouched] = useState(false);
  const [serverErrors, setServerErrors] = useState<FormErrors>({});
  const [wizardTest, setWizardTest] = useState<TestOutcome>({ state: "idle" });
  const [savedChannel, setSavedChannel] = useState<Channel | null>(null);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      const payload = await getJson<{ items: Channel[] }>(`${NOTIFY_BASE}/channels`, current.signal);
      setChannels(payload.items ?? []);
      setUnavailable(false);
      setLoadError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      if (caught instanceof ApiError && caught.status === 404) setUnavailable(true);
      else setLoadError(caught);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const openNew = useCallback((preset: ChannelKind | null = null) => {
    setEditing(null);
    setKind(preset);
    setForm(emptyForm(preset ?? "telegram", language));
    setTouched(false);
    setServerErrors({});
    setWizardTest({ state: "idle" });
    setSavedChannel(null);
    setWizardOpen(true);
  }, [language]);

  const openEdit = (channel: Channel) => {
    setEditing(channel);
    setKind(channel.kind);
    setForm(formFromChannel(channel, language));
    setTouched(false);
    setServerErrors({});
    setWizardTest({ state: "idle" });
    setSavedChannel(null);
    setWizardOpen(true);
  };

  useEffect(() => {
    if (addRequest > 0 && canWrite) openNew();
  }, [addRequest, canWrite, openNew]);

  // Home's attention item links to #/alerts/channels?new=1
  useEffect(() => {
    if (canWrite && /[?&]new=1/.test(window.location.hash)) openNew("telegram");
  }, [canWrite, openNew]);

  const runTest = async (channel: Channel): Promise<TestOutcome> => {
    try {
      const result = await mutateJson<{ ok: boolean; latency_ms?: number; error_code?: string | null }>(`${NOTIFY_BASE}/channels/${encodeURIComponent(channel.id)}/test`, { method: "POST" });
      return result.ok
        ? { state: "ok", latencyMs: result.latency_ms, message: say(language, T.testOk, { kind: kindWord(language, channel.kind) }) }
        : { state: "fail", code: result.error_code ?? undefined };
    } catch (caught) {
      return { state: "fail", error: caught };
    }
  };

  const testChannel = async (channel: Channel) => {
    setTests((current) => ({ ...current, [channel.id]: { state: "running" } }));
    const outcome = await runTest(channel);
    setTests((current) => ({ ...current, [channel.id]: outcome }));
    void load();
  };

  const toggle = async (channel: Channel, enabled: boolean, quiet = false) => {
    setChannels((items) => items?.map((item) => (item.id === channel.id ? { ...item, enabled } : item)) ?? items);
    try {
      await mutateJson(`${NOTIFY_BASE}/channels/${encodeURIComponent(channel.id)}`, { method: "PATCH", body: { enabled } });
      if (!quiet) notify({ message: say(language, enabled ? T.turnedOn : T.turnedOff, { name: channel.name }), onUndo: () => void toggle(channel, !enabled, true) });
    } catch (caught) {
      setChannels((items) => items?.map((item) => (item.id === channel.id ? { ...item, enabled: !enabled } : item)) ?? items);
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
    void load();
  };

  const remove = async (channel: Channel) => {
    const ok = await ask({
      title: say(language, T.deleteTitle, { name: channel.name }),
      body: pick(language, T.deleteBody),
      consequences: [pick(language, T.deleteEffect)],
      severity: "destructive",
      undoable: false,
      typed: nameConfirmation(channel.name, channel.name)
    });
    if (!ok) return;
    try {
      await mutateJson(`${NOTIFY_BASE}/channels/${encodeURIComponent(channel.id)}`, { method: "DELETE", body: { confirmation: channel.name } });
      notify({ message: say(language, T.deletedToast, { name: channel.name }) });
      await load();
      onChanged?.();
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
  };

  const clientErrors = kind ? validate(kind, form, editing, language) : {};
  const shownErrors: FormErrors = { ...(touched ? clientErrors : {}), ...serverErrors };
  const patch = (next: Partial<Form>) => {
    setForm((current) => ({ ...current, ...next }));
    const keys = Object.keys(next) as (keyof Form)[];
    setServerErrors((current) => {
      const copy = { ...current };
      keys.forEach((key) => delete copy[key]);
      return copy;
    });
  };

  const field = (key: keyof Form, label: string, extra: { ltr?: boolean; type?: string; helper?: string; multiline?: boolean; secret?: boolean } = {}) => (
    <TextField
      fullWidth
      label={label}
      type={extra.type}
      multiline={extra.multiline}
      minRows={extra.multiline ? 2 : undefined}
      value={form[key] as string}
      error={Boolean(shownErrors[key])}
      helperText={shownErrors[key] ?? extra.helper ?? " "}
      placeholder={extra.secret && editing?.secret_configured ? pick(language, T.keepSecret) : undefined}
      autoComplete={extra.secret ? "new-password" : "off"}
      slotProps={{ htmlInput: { dir: extra.ltr ? "ltr" : undefined, spellCheck: false }, inputLabel: extra.secret && editing?.secret_configured ? { shrink: true } : undefined }}
      onChange={(event) => patch({ [key]: event.target.value } as Partial<Form>)}
    />
  );

  const detailsStep = (current: ChannelKind) => (
    <Stack spacing={1}>
      <Box component="ol" sx={{ m: 0, mb: 1, pl: 2.5, "& li": { lineHeight: 1.9 } }}>
        {KIND_INFO[current].howTo.map((item) => <Typography component="li" variant="body2" key={item.en}>{pick(language, item)}</Typography>)}
      </Box>
      {field("name", pick(language, T.name))}
      {(current === "telegram" || current === "bale") && (
        <>
          {field("botToken", pick(language, T.botToken), { ltr: true, type: "password", secret: true })}
          {field("chatId", pick(language, T.chatId), { ltr: true })}
          {isAdvanced && field("apiBaseUrl", pick(language, T.apiBase), { ltr: true, helper: pick(language, T.apiBaseHint) })}
          {isAdvanced && <FormControlLabel control={<Switch checked={form.html} onChange={(_event, value) => patch({ html: value })} />} label={pick(language, T.htmlFormat)} />}
        </>
      )}
      {current === "email" && (
        <>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
            <Box sx={{ flex: 2 }}>{field("smtpHost", pick(language, T.smtpHost), { ltr: true })}</Box>
            <Box sx={{ flex: 1 }}>
              <NumberInput label={pick(language, T.smtpPort)} value={form.smtpPort} onChange={(value) => patch({ smtpPort: value })} min={1} max={65535} integer error={shownErrors.smtpPort ?? null} />
            </Box>
          </Stack>
          <TextField select fullWidth label={pick(language, T.security)} value={form.security} helperText={shownErrors.security ?? " "} error={Boolean(shownErrors.security)} onChange={(event) => patch({ security: event.target.value as Form["security"] })}>
            <MenuItem value="starttls">{pick(language, T.starttls)}</MenuItem>
            <MenuItem value="tls">{pick(language, T.tls)}</MenuItem>
            <MenuItem value="none">{pick(language, T.insecure)}</MenuItem>
          </TextField>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
            <Box sx={{ flex: 1 }}>{field("username", pick(language, T.smtpUser), { ltr: true })}</Box>
            <Box sx={{ flex: 1 }}>{field("password", pick(language, T.smtpPassword), { ltr: true, type: "password", secret: true })}</Box>
          </Stack>
          {field("fromAddress", pick(language, T.from), { ltr: true, type: "email" })}
          <ListInput
            label={pick(language, T.to)}
            value={form.toAddresses}
            onChange={(value) => patch({ toAddresses: value })}
            validate={(value) => (EMAIL.test(value) ? null : pick(language, T.emailRule))}
            max={20}
            helperText={shownErrors.toAddresses ?? pick(language, T.toHint)}
          />
        </>
      )}
      {current === "webhook" && (
        <>
          {field("url", pick(language, T.url), { ltr: true })}
          {isAdvanced && field("headers", pick(language, T.headers), { ltr: true, multiline: true })}
          {isAdvanced && field("signingKey", pick(language, T.signingKey), { ltr: true, type: "password", secret: true })}
        </>
      )}
      {isAdvanced && (
        <NumberInput label={pick(language, T.timeout)} value={form.timeout} onChange={(value) => patch({ timeout: value })} min={2} max={60} integer unit={pick(language, T.seconds)} error={shownErrors.timeout ?? null} />
      )}
      {!proxyFailed && proxyList && (isAdvanced || proxyList.default_proxy_id || form.proxyId) && (
        <ProxyPicker
          language={language}
          list={proxyList}
          value={form.proxyId}
          onChange={(value) => patch({ proxyId: value })}
          supported={supportedTypesFor(current)}
          advanced={isAdvanced}
          label={form.name}
        />
      )}
    </Stack>
  );

  const steps: WizardStep[] = [];
  if (!editing) {
    steps.push({
      key: "kind",
      title: pick(language, T.stepKind),
      hint: pick(language, T.stepKindHint),
      validate: () => (kind ? null : pick(language, T.pickKind)),
      render: () => (
        <Grid container spacing={1.5} role="radiogroup" aria-label={pick(language, T.stepKind)}>
          {(["telegram", "bale", "email", "webhook"] as ChannelKind[]).map((item) => (
            <Grid key={item} size={{ xs: 12, sm: 6 }}>
              <KindCard
                kind={item}
                selected={kind === item}
                onClick={() => {
                  if (kind !== item) setForm(emptyForm(item, language));
                  setKind(item);
                  setTouched(false);
                  setServerErrors({});
                }}
              />
            </Grid>
          ))}
        </Grid>
      )
    });
  }
  steps.push({
    key: "details",
    title: pick(language, T.stepDetails),
    hint: pick(language, T.stepDetailsHint),
    validate: () => {
      setTouched(true);
      return kind && Object.keys(validate(kind, form, editing, language)).length ? pick(language, T.fixFirst) : null;
    },
    render: () => (kind ? detailsStep(kind) : null)
  });
  if (!editing) {
    steps.push({
      key: "save",
      title: pick(language, T.stepSave),
      hint: pick(language, T.stepSaveHint),
      render: () => (
        <Stack spacing={1.5}>
          <KeyValueList items={[{ label: pick(language, T.name), value: form.name }, { label: pick(language, T.stepKind), value: kind ? kindWord(language, kind) : "" }]} />
          <FormControlLabel
            control={<Switch checked={form.createDefaultRule} onChange={(_event, value) => patch({ createDefaultRule: value })} />}
            label={<Box><Typography variant="body2" sx={{ fontWeight: 650 }}>{pick(language, T.defaultRule)}</Typography><Typography variant="caption" color="text.secondary">{pick(language, T.defaultRuleHint)}</Typography></Box>}
          />
        </Stack>
      )
    });
  }

  const finish = async () => {
    if (!kind) return;
    setServerErrors({});
    const config = buildConfig(kind, form, Boolean(editing && str(editing.config?.proxy_id)));
    const secret = buildSecret(kind, form);
    try {
      let saved: Channel;
      if (editing) {
        const body: Record<string, unknown> = { name: form.name.trim(), config };
        if (secret) body.secret = secret;
        saved = await mutateJson<Channel>(`${NOTIFY_BASE}/channels/${encodeURIComponent(editing.id)}`, { method: "PATCH", body });
        notify({ message: say(language, T.savedEdit, { name: form.name.trim() }) });
      } else {
        saved = await mutateJson<Channel>(`${NOTIFY_BASE}/channels`, {
          method: "POST",
          body: { name: form.name.trim(), kind, enabled: true, config, secret: secret ?? {}, create_default_rule: form.createDefaultRule }
        });
        setSavedChannel(saved);
        setWizardTest({ state: "running" });
        setWizardTest(await runTest(saved));
      }
      void load();
      onChanged?.();
    } catch (caught) {
      const info = describeError(language, caught);
      const key = info.field ? FIELD_MAP[info.field] ?? (info.field === "secret" ? (kind === "email" ? "password" : kind === "webhook" ? "signingKey" : "botToken") : undefined) : undefined;
      if (key) setServerErrors({ [key]: info.message });
      throw caught;
    }
  };

  const doneContent = !editing && savedChannel ? (
    <Stack spacing={2} sx={{ pt: 1 }}>
      <Notice tone="success">{say(language, T.savedNew, { name: savedChannel.name })}</Notice>
      <TestResult outcome={wizardTest} />
      {wizardTest.state === "fail" && (
        <Box>
          <Button startIcon={<SendRoundedIcon />} onClick={async () => { setWizardTest({ state: "running" }); setWizardTest(await runTest(savedChannel)); }} sx={{ minHeight: 44 }}>
            {pick(language, T.testAgain)}
          </Button>
        </Box>
      )}
    </Stack>
  ) : undefined;

  if (unavailable) return <Notice tone="info">{pick(language, T.unavailable)}</Notice>;

  const rows = channels ?? [];
  return (
    <Stack spacing={2}>
      {loadError !== null && <FriendlyError error={loadError} onRetry={() => void load()} />}
      {!canWrite && <NoAccess needs="notification:write" />}
      {channels === null && loadError === null && (
        <Grid container spacing={2}>{[0, 1].map((key) => <Grid key={key} size={{ xs: 12, md: 6, xl: 4 }}><Skeleton variant="rounded" height={170} /></Grid>)}</Grid>
      )}
      {channels !== null && rows.length === 0 && (
        <Card>
          <EmptyState
            icon={NotificationsActiveRoundedIcon}
            title={pick(language, T.emptyTitle)}
            body={pick(language, T.emptyBody)}
            action={canWrite ? (
              <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                <Button variant="contained" startIcon={<TelegramIcon />} onClick={() => openNew("telegram")} sx={{ minHeight: 44 }}>{pick(language, T.addTelegram)}</Button>
                <Button startIcon={<AddRoundedIcon />} onClick={() => openNew(null)} sx={{ minHeight: 44 }}>{pick(language, T.addOther)}</Button>
              </Stack>
            ) : undefined}
          />
        </Card>
      )}
      <Grid container spacing={2}>
        {rows.map((channel) => {
          const Icon = KIND_ICONS[channel.kind] ?? NotificationsActiveRoundedIcon;
          const last = channel.last_status ? deliveryWord(language, channel.last_status) : null;
          const needsSecret = (channel.kind === "telegram" || channel.kind === "bale") && !channel.secret_configured;
          const proxy = str(channel.config?.proxy_id);
          const outcome = tests[channel.id];
          return (
            <Grid key={channel.id} size={{ xs: 12, md: 6, xl: 4 }}>
              <Card sx={{ height: "100%", opacity: channel.enabled ? 1 : 0.75 }}>
                <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                  <Stack direction="row" spacing={1.25} alignItems="flex-start">
                    <Icon aria-hidden sx={{ fontSize: 32, color: channel.enabled ? "primary.main" : "text.disabled", mt: 0.25 }} />
                    <Box sx={{ minWidth: 0, flex: 1 }}>
                      <Typography component="h3" sx={{ fontWeight: 760 }} noWrap title={channel.name}>{channel.name}</Typography>
                      <Typography variant="caption" color="text.secondary" display="block" noWrap>
                        {kindWord(language, channel.kind)}{summary(channel) ? <> · <Ltr>{summary(channel)}</Ltr></> : null}
                      </Typography>
                    </Box>
                    <Switch
                      checked={channel.enabled}
                      disabled={!canWrite}
                      onChange={(_event, value) => void toggle(channel, value)}
                      slotProps={{ input: { "aria-label": say(language, T.switchLabel, { name: channel.name }) } }}
                    />
                    <CardMenu
                      label={say(language, T.menu, { name: channel.name })}
                      items={canWrite ? [
                        { key: "edit", label: pick(language, T.edit), icon: <EditRoundedIcon fontSize="small" />, onClick: () => openEdit(channel) },
                        { key: "delete", label: pick(language, T.remove), icon: <DeleteOutlineRoundedIcon fontSize="small" />, danger: true, onClick: () => void remove(channel) }
                      ] : []}
                    />
                  </Stack>
                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 1.25 }}>
                    <StatusPill tone={channel.enabled ? "ok" : "off"} label={pick(language, channel.enabled ? T.on : T.off)} />
                    {last && <StatusPill tone={last.tone} label={last.label} />}
                    {needsSecret && <StatusPill tone="warn" label={pick(language, T.noSecret)} />}
                  </Stack>
                  <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                    {channel.last_delivery_at ? <>{pick(language, T.lastSent)}<RelativeTime value={channel.last_delivery_at} /></> : pick(language, T.never)}
                  </Typography>
                  {isAdvanced && (
                    <Box sx={{ mt: 1.25 }}>
                      <KeyValueList
                        dense
                        items={[
                          { label: pick(language, T.advId), value: channel.id, ltr: true, copy: true },
                          { label: pick(language, T.advProxy), value: pick(language, proxy === "" ? T.advDirect : proxy === "default" ? T.advDefaultProxy : T.advSpecificProxy) },
                          { label: pick(language, T.advCreated), value: <DateTime value={channel.created_at} /> },
                          { label: pick(language, T.advUpdated), value: <DateTime value={channel.updated_at} /> }
                        ]}
                      />
                    </Box>
                  )}
                  {canWrite && (
                    <>
                      <Divider sx={{ my: 1.5 }} />
                      <Stack spacing={1}>
                        <Box>
                          <Button size="small" startIcon={<SendRoundedIcon />} disabled={!channel.enabled || outcome?.state === "running"} onClick={() => void testChannel(channel)} sx={{ minHeight: 40 }}>
                            {pick(language, T.test)}
                          </Button>
                        </Box>
                        {outcome && <TestResult outcome={outcome} />}
                      </Stack>
                    </>
                  )}
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      <ActionWizard
        open={wizardOpen}
        title={editing ? say(language, T.wizardEdit, { name: editing.name }) : pick(language, T.wizardNew)}
        steps={steps}
        finishLabel={pick(language, editing ? T.finishEdit : T.finishNew)}
        onFinish={finish}
        onClose={() => setWizardOpen(false)}
        done={doneContent ?? (editing ? undefined : <Typography>{c.done}</Typography>)}
      />
      {confirmDialog}
      {snackbar}
    </Stack>
  );
}

export default ChannelsPanel;
