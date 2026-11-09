/**
 * «DNS › اتصال رمزدار» (`#/dns/encrypted`, docs/40 §6): phones, laptops and browsers connect to MRK
 * over encrypted DNS (DoT, DoH, DoQ) without MRK becoming an open resolver.
 *
 * Cards: the three switches (the `encrypted` settings section), the certificate (self-signed /
 * upload / «از دامنه با Traefik» via My services), access tokens for the internet (shown once, with
 * copy and QR), and short per-device guides from `GET encrypted/clients` (Apple profile download).
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import {
  Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Divider, Paper, Stack, Tab, Tabs, TextField, Typography,
  useMediaQuery, useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import UploadFileRoundedIcon from "@mui/icons-material/UploadFileRounded";
import VerifiedUserRoundedIcon from "@mui/icons-material/VerifiedUserRounded";
import LanguageRoundedIcon from "@mui/icons-material/LanguageRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import { ApiError, hasPermission, isAbortError } from "./api";
import { errorSentence, pick, say, type Bi } from "./copy";
import { fill } from "./copy/text";
import {
  AdvancedSection, ChoiceCards, CopyField, DateTime, EmptyState, FriendlyError, KeyValueList, ListInput, Ltr, NoAccess, Notice, NumberInput, OneTimeSecret,
  QrCode, RelativeTime, ResponsiveList, SectionCard, StatusPill, helperProblem, useConfirmAction, useKit, useUndoSnackbar, type RowAction
} from "./kit";
import { formatNumber } from "./format";
import { DnsAvailability } from "./DnsPage";
import { DnsSectionSettings } from "./DnsSectionSettings";
import { SwitchRow } from "./DnsSecuritySettings";
import { engineReady, isCidr, isDnsName, isIPv4, isIPv6, isListenAddress, useDnsStatus } from "./dns";
import {
  DEFAULT_ENCRYPTED, DOH_BEHIND_PROXY_LISTEN, DOH_PUBLIC_LISTEN, DOH_TOKEN_DEFAULT_QPS, DOH_TOKEN_MAX, GUIDE_IDS, GUIDE_STEPS, GUIDE_WORDS, RANGES,
  createDohToken, createSelfSigned, daysLeft, deleteDohToken, deleteTls, downloadAppleProfile, fetchDohTokens, fetchEncryptedClients, fetchTls, guideReason,
  linuxCommand, patchDohToken, tlsErrorText, toMillis, uploadTls, type DnsD4Status, type DohToken, type DohTokenCreated, type EncryptedClients, type EncryptedSettings,
  type GuideId, type TlsInfo
} from "./dnsSecure";

const COPY = {
  introTitle: { fa: "اتصال رمزدار به DNS", en: "Encrypted connection to DNS" },
  introBody: {
    fa: "گوشی، لپ‌تاپ و مرورگر می‌توانند رمزدار از MRK بپرسند؛ این‌طوری کسی در مسیر (مثلاً Wi-Fi عمومی یا شرکت اینترنت) نمی‌بیند چه سایت‌هایی را باز می‌کنید و نمی‌تواند جواب را عوض کند.",
    en: "Phones, laptops and browsers can ask MRK over an encrypted connection, so nobody along the way (like public Wi-Fi or your internet company) sees which sites you open or can change the answers."
  },
  connections: { fa: "اتصال‌های باز الان: {dot} با TLS، {doh} با HTTPS، {doq} سریع", en: "Open connections now: {dot} over TLS, {doh} over HTTPS, {doq} fast" },
  // switches
  switchesTitle: { fa: "راه‌های اتصال رمزدار", en: "Encrypted ways to connect" },
  switchesHint: { fa: "هر کدام را که دستگاه‌هایتان لازم دارند روشن کنید. هیچ‌کدام اجباری نیست.", en: "Turn on whichever your devices need. None is required." },
  dot: { fa: "رمزدار با TLS (DoT)", en: "Encrypted with TLS (DoT)" },
  dotHint: { fa: "برای «DNS خصوصی» گوشی‌های Android و برای Linux. روی پورت ۸۵۳.", en: "For Android's “Private DNS” and for Linux. On port 853." },
  doh: { fa: "رمزدار با HTTPS (DoH)", en: "Encrypted with HTTPS (DoH)" },
  dohHint: { fa: "برای مرورگرها، Windows 11، iPhone و Mac. مثل یک سایت معمولی کار می‌کند.", en: "For browsers, Windows 11, iPhone and Mac. Works like an ordinary website." },
  doq: { fa: "رمزدار و سریع روی UDP (DoQ)", en: "Encrypted and fast over UDP (DoQ)" },
  doqHint: { fa: "تازه‌ترین روش؛ روی اینترنت موبایل سریع‌تر است. فقط برخی برنامه‌ها پشتیبانی می‌کنند.", en: "The newest way; faster on mobile internet. Only some apps support it." },
  dohHow: { fa: "گواهی HTTPS از کجا بیاید؟", en: "Where does the HTTPS certificate come from?" },
  dohSelf: { fa: "خود MRK (پورت ۴۴۳)", en: "MRK itself (port 443)" },
  dohSelfBody: { fa: "از گواهی کارت پایین استفاده می‌شود. اگر پورت ۴۴۳ دست Traefik است، گزینه بعدی را بزنید.", en: "Uses the certificate in the card below. If Traefik holds port 443, pick the next option." },
  dohProxy: { fa: "پشت Traefik، با یک دامنه", en: "Behind Traefik, with a domain" },
  dohProxyBody: { fa: "پیشنهاد ما برای سرورهایی که Dokploy دارند: Traefik گواهی معتبر می‌گیرد و همه دستگاه‌ها بی‌دردسر وصل می‌شوند.", en: "Our suggestion for servers with Dokploy: Traefik gets a trusted certificate and every device connects easily." },
  goServices: { fa: "رفتن به «سرویس‌های من»", en: "Go to My services" },
  proxyNext: { fa: "پس از ذخیره، در «سرویس‌های من» برای «DNS رمزدار» یک دامنه بگذارید.", en: "After saving, give “Encrypted DNS” a domain under My services." },
  needCert: { fa: "این اتصال‌ها گواهی لازم دارند. اول در کارت «گواهی» یکی بسازید یا بارگذاری کنید.", en: "These connections need a certificate. Make or upload one in the Certificate card first." },
  advTitle: { fa: "جزئیات اتصال رمزدار", en: "Encrypted connection details" },
  sameAllow: { fa: "همان کسانی که اجازه پرسیدن از اینترنت دارند", en: "The same devices allowed to ask the internet" },
  sameAllowHint: { fa: "خاموش کنید تا برای اتصال رمزدار محدوده جدا بدهید. دستگاه‌های دارای کلید دسترسی از هر جا وصل می‌شوند.", en: "Turn off to give encrypted connections their own ranges. Devices with an access token connect from anywhere." },
  allow: { fa: "محدوده‌هایی که می‌توانند رمزدار وصل شوند", en: "Ranges that may connect encrypted" },
  rangeHint: { fa: "مثل 192.168.0.0/16", en: "Like 192.168.0.0/16" },
  badRange: { fa: "محدوده را مثل 192.168.0.0/16 بنویسید.", en: "Write the range like 192.168.0.0/16." },
  openAll: { fa: "خطرناک: «همه نشانی‌ها» اجازه دارند و سرور شما برای همه اینترنت باز می‌شود. به‌جایش کلید دسترسی بسازید.", en: "Dangerous: every address is allowed and your server opens to the whole internet. Make access tokens instead." },
  listenDot: { fa: "نشانی‌های TLS", en: "TLS addresses" },
  listenDoh: { fa: "نشانی‌های HTTPS", en: "HTTPS addresses" },
  listenDoq: { fa: "نشانی‌های سریع (UDP)", en: "Fast (UDP) addresses" },
  listenHint: { fa: "مثل 0.0.0.0:853 یا 127.0.0.1:8053", en: "Like 0.0.0.0:853 or 127.0.0.1:8053" },
  badListen: { fa: "مثل 0.0.0.0:853 یا [::]:853 بنویسید.", en: "Write it like 0.0.0.0:853 or [::]:853." },
  needListen: { fa: "دست‌کم یک نشانی لازم است.", en: "At least one address is needed." },
  dohPath: { fa: "مسیر HTTPS", en: "HTTPS path" },
  badPath: { fa: "مسیر باید با / شروع شود، مثل /dns-query", en: "The path must start with /, like /dns-query" },
  allowGet: { fa: "پرسش‌هایی که داخل خود نشانی می‌آیند هم پذیرفته شوند", en: "Also accept questions sent inside the address (GET)" },
  proxies: { fa: "Traefik یا پروکسی‌های مورد اعتماد", en: "Trusted Traefik or proxies" },
  proxiesHint: { fa: "فقط از این محدوده‌ها نشانی واقعی دستگاه از سرصفحه گرفته می‌شود.", en: "Only from these ranges is the device's real address read from the headers." },
  maxConn: { fa: "بیشترین اتصال رمزدار هم‌زمان", en: "Most encrypted connections at once" },
  maxConnClient: { fa: "بیشترین اتصال هر دستگاه", en: "Most connections per device" },
  idle: { fa: "بستن اتصال بی‌کار پس از", en: "Close an idle connection after" },
  streams: { fa: "بیشترین پرسش هم‌زمان روی یک اتصال", en: "Most questions at once on one connection" },
  handshake: { fa: "صبر برای شروع اتصال", en: "Wait for a connection to start" },
  ms: { fa: "میلی‌ثانیه", en: "ms" },
  // certificate
  certTitle: { fa: "گواهی", en: "Certificate" },
  certHint: { fa: "دستگاه با گواهی مطمئن می‌شود واقعاً به MRK شما وصل شده، نه به کس دیگری.", en: "With the certificate a device makes sure it really reached your MRK and not someone else." },
  certLoadFailed: { fa: "وضعیت گواهی خوانده نشد.", en: "The certificate status didn't load." },
  certNone: { fa: "هنوز گواهی ندارید. یکی از سه راه زیر را انتخاب کنید.", en: "No certificate yet. Pick one of the three ways below." },
  certOk: { fa: "گواهی معتبر است تا {date} ({days} روز دیگر).", en: "The certificate is valid until {date} ({days} more days)." },
  certSoon: { fa: "گواهی {days} روز دیگر تمام می‌شود.", en: "The certificate ends in {days} days." },
  certExpired: { fa: "تاریخ گواهی گذشته است؛ دستگاه‌ها وصل نمی‌شوند.", en: "The certificate has expired; devices won't connect." },
  selfSignedBadge: { fa: "خودامضا", en: "Self-signed" },
  uploadedBadge: { fa: "بارگذاری‌شده", en: "Uploaded" },
  selfSignedNote: { fa: "خیلی از گوشی‌ها و مرورگرها به گواهی خودامضا اعتماد نمی‌کنند (مثلاً «DNS خصوصی» Android). برای آن‌ها راه «از دامنه با Traefik» بهتر است. MRK این گواهی را ۳۰ روز پیش از پایان خودکار تمدید می‌کند.", en: "Many phones and browsers don't trust a self-signed certificate (for example Android's Private DNS). For them, “Via a domain with Traefik” is better. MRK renews this certificate 30 days before it ends." },
  names: { fa: "نام‌ها", en: "Names" },
  issuer: { fa: "صادرکننده", en: "Issuer" },
  notBefore: { fa: "معتبر از", en: "Valid from" },
  notAfter: { fa: "معتبر تا", en: "Valid until" },
  fingerprint: { fa: "اثر انگشت", en: "Fingerprint" },
  keyType: { fa: "نوع کلید", en: "Key type" },
  waySelf: { fa: "ساخت گواهی خودامضا", en: "Make a self-signed certificate" },
  waySelfBody: { fa: "فوری و رایگان. برای Linux و برنامه‌هایی که می‌شود به آن‌ها گفت اعتماد کنند خوب است.", en: "Instant and free. Good for Linux and apps you can tell to trust it." },
  wayUpload: { fa: "بارگذاری گواهی خودم", en: "Upload my own certificate" },
  wayUploadBody: { fa: "اگر برای نام این سرور گواهی معتبر دارید، فایل گواهی و کلیدش را بدهید.", en: "If you have a trusted certificate for this server's name, give its certificate and key files." },
  wayTraefik: { fa: "از دامنه با Traefik", en: "Via a domain with Traefik" },
  wayTraefikBody: { fa: "بی‌دردسرترین: «DNS رمزدار» در «سرویس‌های من» یک دامنه می‌گیرد و Traefik خودش گواهی معتبر می‌گیرد و تمدید می‌کند.", en: "The easiest: “Encrypted DNS” gets a domain under My services and Traefik gets and renews a trusted certificate itself." },
  make: { fa: "بساز", en: "Make it" },
  upload: { fa: "بارگذاری", en: "Upload" },
  replace: { fa: "جایگزین کن", en: "Replace" },
  removeCert: { fa: "حذف گواهی", en: "Remove the certificate" },
  removeCertTitle: { fa: "گواهی حذف شود؟", en: "Remove the certificate?" },
  removeCertBody: { fa: "دستگاه‌هایی که رمزدار وصل‌اند قطع می‌شوند. اگر اتصال رمزداری روشن است، اول آن را خاموش کنید.", en: "Devices connected encrypted will drop. If an encrypted connection is on, turn it off first." },
  removeYes: { fa: "بله، حذف کن", en: "Yes, remove" },
  certRemoved: { fa: "گواهی حذف شد.", en: "The certificate was removed." },
  selfTitle: { fa: "ساخت گواهی خودامضا", en: "Make a self-signed certificate" },
  selfNames: { fa: "نام‌ها یا نشانی‌های این سرور", en: "This server's names or addresses" },
  selfNamesHint: { fa: "همان نام یا IP که دستگاه‌ها با آن وصل می‌شوند؛ مثل dns.example.com یا 203.0.113.5", en: "The name or IP devices use to connect, like dns.example.com or 203.0.113.5" },
  badCertName: { fa: "یک نام مثل dns.example.com یا یک IP بنویسید.", en: "Write a name like dns.example.com or an IP." },
  selfMade: { fa: "گواهی خودامضا ساخته شد.", en: "The self-signed certificate was made." },
  uploadTitle: { fa: "بارگذاری گواهی", en: "Upload a certificate" },
  certPem: { fa: "گواهی (همراه زنجیره)", en: "Certificate (with its chain)" },
  keyPem: { fa: "کلید خصوصی", en: "Private key" },
  pemHint: { fa: "متنی که با «-----BEGIN» شروع می‌شود. کلید خصوصی فقط روی سرور ذخیره می‌شود و هرگز نشان داده نمی‌شود.", en: "Text starting with “-----BEGIN”. The private key is stored only on the server and never shown again." },
  fromFile: { fa: "از فایل", en: "From a file" },
  uploaded: { fa: "گواهی بارگذاری و همین حالا استفاده شد.", en: "The certificate was uploaded and is in use now." },
  uploadFailed: { fa: "گواهی بارگذاری نشد.", en: "The certificate wasn't uploaded." },
  // tokens
  tokensTitle: { fa: "کلیدهای دسترسی از اینترنت", en: "Access tokens for the internet" },
  tokensHint: { fa: "برای گوشی‌ای که بیرون از شبکه شماست (مثلاً با اینترنت موبایل). هر دستگاه یک کلید جدا بگیرد تا اگر گم شد، فقط همان را باطل کنید.", en: "For a phone outside your network (like on mobile data). Give each device its own token so a lost one can be cancelled alone." },
  tokensNeedDoh: { fa: "کلیدها فقط با «رمزدار با HTTPS» کار می‌کنند؛ اول آن را روشن کنید.", en: "Tokens only work with “Encrypted with HTTPS”; turn it on first." },
  tokensEmpty: { fa: "هنوز کلیدی نساخته‌اید.", en: "You haven't made a token yet." },
  tokensEmptyBody: { fa: "برای هر دستگاهی که از بیرون وصل می‌شود یکی بسازید.", en: "Make one for each device that connects from outside." },
  newToken: { fa: "ساخت کلید تازه", en: "Make a new token" },
  tokenName: { fa: "برای کدام دستگاه؟", en: "For which device?" },
  tokenNameHint: { fa: "مثلاً «گوشی علی»", en: "For example “Ali's phone”" },
  tokenNameBad: { fa: "یک نام ۱ تا ۶۴ نویسه‌ای بنویسید.", en: "Write a name of 1 to 64 characters." },
  tokenQps: { fa: "بیشترین پرسش در ثانیه", en: "Most questions per second" },
  create: { fa: "بساز", en: "Make it" },
  save: { fa: "ذخیره", en: "Save" },
  cancel: { fa: "انصراف", en: "Cancel" },
  createdTitle: { fa: "کلید «{name}» ساخته شد", en: "Token “{name}” is ready" },
  createdBody: { fa: "این نشانی را در دستگاه بگذارید یا با دوربین گوشی کد QR را بخوانید. نشانی شامل کلید است؛ به کسی ندهید.", en: "Put this address on the device, or scan the QR code with the phone's camera. The address contains the token; don't share it." },
  tokenLabel: { fa: "کلید", en: "Token" },
  urlLabel: { fa: "نشانی DNS رمزدار", en: "Encrypted DNS address" },
  qrLabel: { fa: "کد QR نشانی DNS رمزدار", en: "QR code of the encrypted DNS address" },
  colName: { fa: "دستگاه", en: "Device" },
  colQps: { fa: "سقف در ثانیه", en: "Limit per second" },
  colLastUsed: { fa: "آخرین استفاده", en: "Last used" },
  colQueries: { fa: "پرسش‌ها", en: "Questions" },
  colCreated: { fa: "ساخته شده", en: "Made" },
  never: { fa: "هنوز نه", en: "Not yet" },
  editToken: { fa: "تغییر", en: "Edit" },
  deleteToken: { fa: "باطل کردن", en: "Cancel token" },
  deleteTokenTitle: { fa: "کلید «{name}» باطل شود؟", en: "Cancel the token “{name}”?" },
  deleteTokenBody: { fa: "دستگاهی که با این کلید وصل است دیگر جواب نمی‌گیرد. برگشت‌پذیر نیست؛ اگر لازم شد کلید تازه بسازید.", en: "The device using this token stops getting answers. This can't be undone; make a new token if needed." },
  deleteYes: { fa: "بله، باطل کن", en: "Yes, cancel it" },
  tokenDeleted: { fa: "کلید باطل شد.", en: "The token was cancelled." },
  tokenSaved: { fa: "کلید ذخیره شد.", en: "The token was saved." },
  tokensFailed: { fa: "فهرست کلیدها خوانده نشد.", en: "The token list didn't load." },
  tokenLimit: { fa: "به سقف {max} کلید رسیده‌اید.", en: "You've reached the limit of {max} tokens." },
  // guides
  guidesTitle: { fa: "راه‌اندازی روی هر دستگاه", en: "Set up each device" },
  guidesHint: { fa: "دستگاه خودتان را انتخاب کنید و چند قدم کوتاه را انجام دهید.", en: "Pick your device and follow a few short steps." },
  guidesFailed: { fa: "راهنماها خوانده نشد.", en: "The guides didn't load." },
  untrusted: { fa: "گواهی فعلی خودامضاست؛ بعضی دستگاه‌ها وصل نمی‌شوند. برای همه دستگاه‌ها «از دامنه با Traefik» را در کارت «گواهی» ببینید.", en: "The current certificate is self-signed; some devices won't connect. For every device, see “Via a domain with Traefik” in the Certificate card." },
  getProfile: { fa: "دریافت پروفایل", en: "Get the profile" },
  profileFailed: { fa: "پروفایل ساخته نشد.", en: "The profile wasn't made." },
  dotNameLabel: { fa: "نام DNS خصوصی", en: "Private DNS name" },
  dohUrlLabel: { fa: "نشانی DNS روی HTTPS", en: "DNS over HTTPS address" },
  ipLabel: { fa: "نشانی IP سرور", en: "Server IP address" },
  commandLabel: { fa: "دستور", en: "Command" },
  outsideTip: { fa: "اگر این دستگاه بیرون از شبکه شماست، به‌جای این نشانی، نشانی یک «کلید دسترسی» را بگذارید.", en: "If this device is outside your network, use an access token's address instead." },
  notAvailable: { fa: "فعلاً آماده نیست", en: "Not ready yet" },
  ready: { fa: "آماده", en: "Ready" }
} satisfies Record<string, Bi>;

const OPEN_RANGES = new Set(["0.0.0.0/0", "::/0"]);

function isMissing(error: unknown) {
  return error instanceof ApiError && error.status === 404 && (!error.code || error.code === "not_found");
}

/** Load once (and on demand); 404 → `missing` so older servers show a calm notice. */
function useLoad<T>(loader: (signal: AbortSignal) => Promise<T>, enabled = true) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      setData(await loaderRef.current(current.signal));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);
  useEffect(() => {
    if (enabled) void load();
    return () => controller.current?.abort();
  }, [load, enabled]);
  return { data, error, loading, reload: load };
}

function Grid2({ children }: { children: React.ReactNode }) {
  return <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" } }}>{children}</Box>;
}

// ── switches (settings section `encrypted`) ──────────────────────────────────

type EncryptedDraft = { encrypted: EncryptedSettings & Record<string, unknown> };
const ENCRYPTED_DEFAULTS: EncryptedDraft = { encrypted: DEFAULT_ENCRYPTED as EncryptedDraft["encrypted"] };

function sameList(a: string[] | undefined, b: string[]) {
  return JSON.stringify([...(a ?? [])].sort()) === JSON.stringify([...b].sort());
}

function validateEncrypted(language: "fa" | "en") {
  return (draft: EncryptedDraft) => {
    const result: Record<string, string> = {};
    const value = draft.encrypted;
    (["dot", "doq", "doh"] as const).forEach((key) => {
      const listen = value[key]?.listen ?? [];
      if (value[key]?.enabled && !listen.length) result[`${key}.listen`] = pick(language, COPY.needListen);
      if (listen.some((item) => !isListenAddress(item))) result[`${key}.listen`] = pick(language, COPY.badListen);
    });
    if (!/^\/[A-Za-z0-9._~\-/]*$/.test(value.doh?.path ?? "")) result["doh.path"] = pick(language, COPY.badPath);
    return result;
  };
}

function SwitchesCard({ permissions, tls, onSaved }: { permissions: readonly string[]; tls: TlsInfo | null; onSaved: () => void }) {
  const { language } = useKit();
  const validate = useMemo(() => validateEncrypted(language), [language]);
  const rangeProblem = (item: string) => (isCidr(item) ? null : pick(language, COPY.badRange));
  const listenProblem = (item: string) => (isListenAddress(item) ? null : pick(language, COPY.badListen));
  return (
    <DnsSectionSettings<EncryptedDraft> title={pick(language, COPY.switchesTitle)} hint={pick(language, COPY.switchesHint)} permissions={permissions} defaults={ENCRYPTED_DEFAULTS} validate={validate} onSaved={onSaved}>
      {({ draft, update, problems, serverFields }) => {
        const value = draft.encrypted;
        const field = (key: string) => problems[key] ?? serverFields[`encrypted.${key}`] ?? null;
        const needsCert = (value.dot.enabled || value.doq.enabled || (value.doh.enabled && value.doh.tls)) && !tls?.present;
        const openAll = Array.isArray(value.allow) && value.allow.some((item) => OPEN_RANGES.has(item.trim()));
        const setDohTls = (on: boolean) => update((next) => {
          const doh = next.encrypted.doh;
          doh.tls = on;
          // Switch the listen addresses only while they are still the other mode's defaults.
          if (on && sameList(doh.listen, DOH_BEHIND_PROXY_LISTEN)) doh.listen = [...DOH_PUBLIC_LISTEN];
          if (!on && sameList(doh.listen, DOH_PUBLIC_LISTEN)) doh.listen = [...DOH_BEHIND_PROXY_LISTEN];
        });
        return (
          <Stack spacing={2}>
            <SwitchRow label={pick(language, COPY.dot)} hint={pick(language, COPY.dotHint)} checked={Boolean(value.dot.enabled)} onChange={(on) => update((next) => { next.encrypted.dot.enabled = on; })} />
            <SwitchRow label={pick(language, COPY.doh)} hint={pick(language, COPY.dohHint)} checked={Boolean(value.doh.enabled)} onChange={(on) => update((next) => { next.encrypted.doh.enabled = on; })} />
            {value.doh.enabled ? (
              <Box sx={{ ps: { xs: 0, sm: 6 } }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 720, mb: 1 }}>{pick(language, COPY.dohHow)}</Typography>
                <ChoiceCards<"proxy" | "self">
                  label={pick(language, COPY.dohHow)}
                  value={value.doh.tls ? "self" : "proxy"}
                  onChange={(key) => setDohTls(key === "self")}
                  options={[
                    { key: "proxy", title: pick(language, COPY.dohProxy), body: pick(language, COPY.dohProxyBody), icon: LanguageRoundedIcon },
                    { key: "self", title: pick(language, COPY.dohSelf), body: pick(language, COPY.dohSelfBody), icon: LockRoundedIcon }
                  ]}
                />
                {!value.doh.tls ? (
                  <Notice tone="info" action={<Button color="inherit" size="small" href="#/services" sx={{ minHeight: 40 }}>{pick(language, COPY.goServices)}</Button>}>
                    {pick(language, COPY.proxyNext)}
                  </Notice>
                ) : null}
              </Box>
            ) : null}
            <SwitchRow label={pick(language, COPY.doq)} hint={pick(language, COPY.doqHint)} checked={Boolean(value.doq.enabled)} onChange={(on) => update((next) => { next.encrypted.doq.enabled = on; })} />
            {needsCert ? <Notice tone="warning">{pick(language, COPY.needCert)}</Notice> : null}

            <AdvancedSection title={pick(language, COPY.advTitle)}>
              <SwitchRow
                label={pick(language, COPY.sameAllow)}
                hint={pick(language, COPY.sameAllowHint)}
                checked={value.allow === null || value.allow === undefined}
                onChange={(on) => update((next) => { next.encrypted.allow = on ? null : []; })}
              />
              {Array.isArray(value.allow) ? (
                <ListInput label={pick(language, COPY.allow)} value={value.allow} onChange={(list) => update((next) => { next.encrypted.allow = list; })} validate={rangeProblem} helperText={field("allow") ?? pick(language, COPY.rangeHint)} />
              ) : null}
              {openAll ? <Notice tone="error">{pick(language, COPY.openAll)}</Notice> : null}
              <Divider />
              <ListInput label={pick(language, COPY.listenDot)} value={value.dot.listen ?? []} onChange={(list) => update((next) => { next.encrypted.dot.listen = list; })} validate={listenProblem} helperText={field("dot.listen") ?? pick(language, COPY.listenHint)} />
              <ListInput label={pick(language, COPY.listenDoh)} value={value.doh.listen ?? []} onChange={(list) => update((next) => { next.encrypted.doh.listen = list; })} validate={listenProblem} helperText={field("doh.listen") ?? pick(language, COPY.listenHint)} />
              <ListInput label={pick(language, COPY.listenDoq)} value={value.doq.listen ?? []} onChange={(list) => update((next) => { next.encrypted.doq.listen = list; })} validate={listenProblem} helperText={field("doq.listen") ?? pick(language, COPY.listenHint)} />
              <Grid2>
                <TextField size="small" label={pick(language, COPY.dohPath)} value={value.doh.path} onChange={(event) => update((next) => { next.encrypted.doh.path = event.target.value.trim(); })}
                  error={Boolean(field("doh.path"))} helperText={field("doh.path") ?? " "} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
                <SwitchRow label={pick(language, COPY.allowGet)} checked={Boolean(value.doh.allow_get)} onChange={(on) => update((next) => { next.encrypted.doh.allow_get = on; })} />
              </Grid2>
              <ListInput label={pick(language, COPY.proxies)} value={value.doh.trusted_proxies ?? []} onChange={(list) => update((next) => { next.encrypted.doh.trusted_proxies = list; })} validate={rangeProblem} helperText={field("doh.trusted_proxies") ?? pick(language, COPY.proxiesHint)} />
              <Grid2>
                <NumberInput label={pick(language, COPY.maxConn)} value={value.max_connections} onChange={(n) => update((next) => { next.encrypted.max_connections = n ?? 2000; })} min={RANGES.max_connections[0]} max={RANGES.max_connections[1]} integer error={field("max_connections")} />
                <NumberInput label={pick(language, COPY.maxConnClient)} value={value.max_connections_per_client} onChange={(n) => update((next) => { next.encrypted.max_connections_per_client = n ?? 50; })} min={RANGES.max_connections_per_client[0]} max={RANGES.max_connections_per_client[1]} integer error={field("max_connections_per_client")} />
                <NumberInput label={pick(language, COPY.idle)} value={value.idle_timeout_ms} onChange={(n) => update((next) => { next.encrypted.idle_timeout_ms = n ?? 30_000; })} min={RANGES.idle_timeout_ms[0]} max={RANGES.idle_timeout_ms[1]} integer unit={pick(language, COPY.ms)} error={field("idle_timeout_ms")} />
                <NumberInput label={pick(language, COPY.streams)} value={value.max_streams_per_connection} onChange={(n) => update((next) => { next.encrypted.max_streams_per_connection = n ?? 100; })} min={RANGES.max_streams_per_connection[0]} max={RANGES.max_streams_per_connection[1]} integer error={field("max_streams_per_connection")} />
                <NumberInput label={pick(language, COPY.handshake)} value={value.handshake_timeout_ms} onChange={(n) => update((next) => { next.encrypted.handshake_timeout_ms = n ?? 5000; })} min={RANGES.handshake_timeout_ms[0]} max={RANGES.handshake_timeout_ms[1]} integer unit={pick(language, COPY.ms)} error={field("handshake_timeout_ms")} />
              </Grid2>
            </AdvancedSection>
          </Stack>
        );
      }}
    </DnsSectionSettings>
  );
}

// ── certificate ──────────────────────────────────────────────────────────────

function SelfSignedDialog({ suggestions, onClose, onDone }: { suggestions: string[]; onClose: () => void; onDone: () => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [names, setNames] = useState<string[]>(suggestions.slice(0, 2));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const valid = (item: string) => (isDnsName(item) || isIPv4(item) || isIPv6(item) ? null : pick(language, COPY.badCertName));
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await createSelfSigned(names);
      onDone();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth="sm">
      <DialogTitle sx={{ fontWeight: 760 }}>{pick(language, COPY.selfTitle)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 0.5 }}>
          <ListInput label={pick(language, COPY.selfNames)} value={names} onChange={setNames} validate={valid} helperText={pick(language, COPY.selfNamesHint)} suggestions={suggestions} max={20} />
          <Notice tone="info">{pick(language, COPY.selfSignedNote)}</Notice>
          {error ? <FriendlyError error={error} onClose={() => setError(null)} scope="dns" /> : null}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
        <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, COPY.cancel)}</Button>
        <Button variant="contained" onClick={() => void submit()} disabled={busy || !names.length} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
          {pick(language, COPY.make)}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function PemField({ label, value, onChange, accept }: { label: string; value: string; onChange: (value: string) => void; accept: string }) {
  const { language } = useKit();
  const input = useRef<HTMLInputElement | null>(null);
  const read = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || file.size > 65_536) return;
    onChange(await file.text());
  };
  return (
    <Box>
      <Stack direction="row" alignItems="center" justifyContent="space-between" gap={1} sx={{ mb: 0.5 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{label}</Typography>
        <Button size="small" startIcon={<UploadFileRoundedIcon />} onClick={() => input.current?.click()} sx={{ minHeight: 40 }}>{pick(language, COPY.fromFile)}</Button>
        <input ref={input} type="file" accept={accept} hidden onChange={(event) => void read(event)} />
      </Stack>
      <TextField
        value={value}
        onChange={(event) => onChange(event.target.value)}
        multiline
        minRows={4}
        maxRows={10}
        fullWidth
        placeholder="-----BEGIN …"
        slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoCapitalize: "none", style: { fontFamily: "monospace", fontSize: 12 } } }}
        aria-label={label}
      />
    </Box>
  );
}

function UploadDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await uploadTls({ cert_pem: cert, key_pem: key });
      setKey("");
      onDone();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };
  const reason = tlsErrorText(language, error);
  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth="md">
      <DialogTitle sx={{ fontWeight: 760 }}>{pick(language, COPY.uploadTitle)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 0.5 }}>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>{pick(language, COPY.pemHint)}</Typography>
          <PemField label={pick(language, COPY.certPem)} value={cert} onChange={setCert} accept=".pem,.crt,.cer,.txt" />
          <PemField label={pick(language, COPY.keyPem)} value={key} onChange={setKey} accept=".pem,.key,.txt" />
          {error && reason ? <Notice tone="error">{reason}</Notice> : null}
          {error && !reason ? <FriendlyError error={error} title={pick(language, COPY.uploadFailed)} onClose={() => setError(null)} scope="dns" /> : null}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
        <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, COPY.cancel)}</Button>
        <Button variant="contained" onClick={() => void submit()} disabled={busy || !cert.trim() || !key.trim()} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : <UploadFileRoundedIcon />} sx={{ minHeight: 44 }}>
          {pick(language, COPY.upload)}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function WayTile({ icon: Icon, title, body, action }: { icon: typeof KeyRoundedIcon; title: string; body: string; action: React.ReactNode }) {
  return (
    <Paper variant="outlined" sx={{ p: 1.5, display: "flex", flexDirection: "column", gap: 1, minWidth: 0 }}>
      <Stack direction="row" gap={1} alignItems="center">
        <Icon color="primary" fontSize="small" aria-hidden />
        <Typography variant="body2" sx={{ fontWeight: 720 }}>{title}</Typography>
      </Stack>
      <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1.8, flex: 1 }}>{body}</Typography>
      <Box>{action}</Box>
    </Paper>
  );
}

function CertificateCard({ tls, error, onRetry, onChanged, canAdmin, suggestions }: {
  tls: TlsInfo | null; error: unknown; onRetry: () => void; onChanged: () => void; canAdmin: boolean; suggestions: string[];
}) {
  const { language, isAdvanced } = useKit();
  const [dialog, setDialog] = useState<"self" | "upload" | null>(null);
  const { ask, dialog: confirmDialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const days = daysLeft(tls?.not_after);
  const notAfterMs = toMillis(tls?.not_after);
  const present = Boolean(tls?.present);

  const remove = async () => {
    const ok = await ask({ title: pick(language, COPY.removeCertTitle), body: pick(language, COPY.removeCertBody), severity: "destructive", confirmLabel: pick(language, COPY.removeYes) });
    if (!ok) return;
    try {
      await deleteTls();
      notify({ message: pick(language, COPY.certRemoved), tone: "success" });
      onChanged();
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
  };

  let state: React.ReactNode = null;
  if (error && !tls) {
    state = isMissing(error) ? null : <FriendlyError error={error} title={pick(language, COPY.certLoadFailed)} onRetry={onRetry} severity="warning" scope="dns" />;
  } else if (tls && !present) {
    state = <Notice tone="info">{pick(language, COPY.certNone)}</Notice>;
  } else if (tls && present) {
    const tone = days !== null && days < 0 ? "error" : days !== null && days <= 14 ? "warning" : "success";
    const sentence = days !== null && days < 0
      ? pick(language, COPY.certExpired)
      : days !== null && days <= 14
        ? say(language, COPY.certSoon, { days: formatNumber(days, language) })
        : say(language, COPY.certOk, { date: notAfterMs !== null ? new Intl.DateTimeFormat(language === "fa" ? "fa-IR" : "en-US", { dateStyle: "medium" }).format(new Date(notAfterMs)) : "—", days: formatNumber(days ?? 0, language) });
    state = (
      <Stack spacing={1.5}>
        <Notice tone={tone}>{sentence}</Notice>
        <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center">
          {(tls.names ?? []).map((name) => <StatusPill key={name} tone="info" label={name} />)}
          {tls.self_signed ? <StatusPill tone="warn" label={pick(language, COPY.selfSignedBadge)} /> : <StatusPill tone="ok" label={pick(language, COPY.uploadedBadge)} />}
        </Stack>
        {tls.self_signed ? <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>{pick(language, COPY.selfSignedNote)}</Typography> : null}
        {isAdvanced ? (
          <KeyValueList
            dense
            items={[
              { label: pick(language, COPY.names), value: (tls.names ?? []).join(", ") || "—", ltr: true },
              ...(tls.issuer ? [{ label: pick(language, COPY.issuer), value: tls.issuer, ltr: true }] : []),
              ...(tls.not_before ? [{ label: pick(language, COPY.notBefore), value: <DateTime value={tls.not_before} /> }] : []),
              ...(tls.not_after ? [{ label: pick(language, COPY.notAfter), value: <DateTime value={tls.not_after} /> }] : []),
              ...(tls.key_type ? [{ label: pick(language, COPY.keyType), value: tls.key_type, ltr: true }] : []),
              ...(tls.fingerprint_sha256 ? [{ label: pick(language, COPY.fingerprint), value: <Box component="span" sx={{ wordBreak: "break-all" }}><Ltr mono>{tls.fingerprint_sha256}</Ltr></Box> }] : [])
            ]}
          />
        ) : null}
      </Stack>
    );
  }

  return (
    <SectionCard title={pick(language, COPY.certTitle)} hint={pick(language, COPY.certHint)} status={present ? <StatusPill tone={days !== null && days < 0 ? "error" : days !== null && days <= 14 ? "warn" : "ok"} label={pick(language, tls?.self_signed ? COPY.selfSignedBadge : COPY.uploadedBadge)} /> : undefined}>
      <Stack spacing={2}>
        {state}
        <Box sx={{ display: "grid", gap: 1.5, gridTemplateColumns: { xs: "1fr", md: "repeat(3, minmax(0, 1fr))" } }}>
          <WayTile icon={LanguageRoundedIcon} title={pick(language, COPY.wayTraefik)} body={pick(language, COPY.wayTraefikBody)}
            action={<Button variant="contained" size="small" href="#/services" sx={{ minHeight: 40 }}>{pick(language, COPY.goServices)}</Button>} />
          <WayTile icon={VerifiedUserRoundedIcon} title={pick(language, COPY.waySelf)} body={pick(language, COPY.waySelfBody)}
            action={canAdmin ? <Button variant="outlined" size="small" onClick={() => setDialog("self")} sx={{ minHeight: 40 }}>{pick(language, present ? COPY.replace : COPY.make)}</Button> : <NoAccess needs="dns:admin" />} />
          <WayTile icon={UploadFileRoundedIcon} title={pick(language, COPY.wayUpload)} body={pick(language, COPY.wayUploadBody)}
            action={canAdmin ? <Button variant="outlined" size="small" onClick={() => setDialog("upload")} sx={{ minHeight: 40 }}>{pick(language, present ? COPY.replace : COPY.upload)}</Button> : <NoAccess needs="dns:admin" />} />
        </Box>
        {present && canAdmin && isAdvanced ? (
          <Box>
            <Button color="error" startIcon={<DeleteOutlineRoundedIcon />} onClick={() => void remove()} sx={{ minHeight: 44 }}>{pick(language, COPY.removeCert)}</Button>
          </Box>
        ) : null}
      </Stack>
      {dialog === "self" ? (
        <SelfSignedDialog suggestions={suggestions} onClose={() => setDialog(null)} onDone={() => { setDialog(null); notify({ message: pick(language, COPY.selfMade), tone: "success" }); onChanged(); }} />
      ) : null}
      {dialog === "upload" ? (
        <UploadDialog onClose={() => setDialog(null)} onDone={() => { setDialog(null); notify({ message: pick(language, COPY.uploaded), tone: "success" }); onChanged(); }} />
      ) : null}
      {confirmDialog}
      {snackbar}
    </SectionCard>
  );
}

// ── tokens ───────────────────────────────────────────────────────────────────

function TokenDialog({ token, onClose, onSaved }: { token: DohToken | null; onClose: () => void; onSaved: (created: DohTokenCreated | null) => void }) {
  const { language, isAdvanced } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [name, setName] = useState(token?.name ?? "");
  const [qps, setQps] = useState<number | null>(token?.qps ?? DOH_TOKEN_DEFAULT_QPS);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const trimmed = name.trim();
  const nameProblem = name && (trimmed.length < 1 || trimmed.length > 64) ? pick(language, COPY.tokenNameBad) : null;
  const qpsOk = qps !== null && qps >= 1 && qps <= 10_000;
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      if (token) {
        await patchDohToken(token.id, { name: trimmed, ...(qpsOk ? { qps: qps as number } : {}) });
        onSaved(null);
      } else {
        onSaved(await createDohToken({ name: trimmed, ...(isAdvanced && qpsOk ? { qps: qps as number } : {}) }));
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth="xs">
      <DialogTitle sx={{ fontWeight: 760 }}>{pick(language, token ? COPY.editToken : COPY.newToken)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 0.5 }}>
          <TextField label={pick(language, COPY.tokenName)} placeholder={pick(language, COPY.tokenNameHint)} value={name} onChange={(event) => setName(event.target.value)}
            error={Boolean(nameProblem)} helperText={nameProblem ?? " "} autoFocus fullWidth slotProps={{ htmlInput: { maxLength: 64 } }} />
          {isAdvanced || token ? (
            <NumberInput label={pick(language, COPY.tokenQps)} value={qps} onChange={setQps} min={1} max={10_000} integer />
          ) : null}
          {error ? <FriendlyError error={error} onClose={() => setError(null)} scope="dns" /> : null}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
        <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, COPY.cancel)}</Button>
        <Button variant="contained" onClick={() => void submit()} disabled={busy || !trimmed || Boolean(nameProblem) || ((isAdvanced || Boolean(token)) && !qpsOk)} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
          {pick(language, token ? COPY.save : COPY.create)}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function TokensCard({ canAdmin, dohOn }: { canAdmin: boolean; dohOn: boolean }) {
  const { language } = useKit();
  const tokens = useLoad<DohToken[]>((signal) => fetchDohTokens(signal));
  const [editing, setEditing] = useState<DohToken | "new" | null>(null);
  const [created, setCreated] = useState<DohTokenCreated | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const rows = tokens.data ?? [];

  const remove = async (row: DohToken) => {
    const ok = await ask({ title: say(language, COPY.deleteTokenTitle, { name: row.name }), body: pick(language, COPY.deleteTokenBody), severity: "destructive", confirmLabel: pick(language, COPY.deleteYes) });
    if (!ok) return;
    try {
      await deleteDohToken(row.id);
      notify({ message: pick(language, COPY.tokenDeleted), tone: "success" });
      void tokens.reload();
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
  };

  const actions: RowAction<DohToken>[] = canAdmin ? [
    { key: "edit", label: pick(language, COPY.editToken), icon: EditRoundedIcon, onClick: (row) => setEditing(row) },
    { key: "delete", label: pick(language, COPY.deleteToken), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (row) => void remove(row) }
  ] : [];
  const url = created?.urls?.doh ?? "";

  if (tokens.error && !tokens.data && isMissing(tokens.error)) return null;
  return (
    <SectionCard
      title={pick(language, COPY.tokensTitle)}
      hint={pick(language, COPY.tokensHint)}
      action={canAdmin ? (
        <Button startIcon={<AddRoundedIcon />} onClick={() => setEditing("new")} disabled={rows.length >= DOH_TOKEN_MAX} sx={{ minHeight: 44 }}>{pick(language, COPY.newToken)}</Button>
      ) : undefined}
    >
      <Stack spacing={1.5}>
        {!dohOn ? <Notice tone="info">{pick(language, COPY.tokensNeedDoh)}</Notice> : null}
        {rows.length >= DOH_TOKEN_MAX ? <Notice tone="warning">{say(language, COPY.tokenLimit, { max: formatNumber(DOH_TOKEN_MAX, language) })}</Notice> : null}
        {tokens.error ? <FriendlyError error={tokens.error} title={pick(language, COPY.tokensFailed)} onRetry={() => void tokens.reload()} severity={tokens.data ? "warning" : "error"} scope="dns" /> : null}
        {tokens.loading && !tokens.data ? <Box sx={{ display: "grid", placeItems: "center", py: 3 }}><CircularProgress size={24} aria-hidden /></Box> : null}
        {tokens.data ? (
          <ResponsiveList
            rows={rows}
            rowKey={(row) => row.id}
            label={pick(language, COPY.tokensTitle)}
            dense
            actions={actions}
            columns={[
              { key: "name", header: pick(language, COPY.colName), render: (row) => row.name, hideOnCard: true },
              { key: "last", header: pick(language, COPY.colLastUsed), render: (row) => (row.last_used_at ? <RelativeTime value={row.last_used_at} relativeAlways /> : pick(language, COPY.never)) },
              { key: "queries", header: pick(language, COPY.colQueries), render: (row) => formatNumber(row.queries ?? 0, language), align: "end" },
              { key: "qps", header: pick(language, COPY.colQps), render: (row) => formatNumber(row.qps ?? DOH_TOKEN_DEFAULT_QPS, language), align: "end", advancedOnly: true },
              { key: "created", header: pick(language, COPY.colCreated), render: (row) => (row.created_at ? <DateTime value={row.created_at} /> : "—"), advancedOnly: true }
            ]}
            card={{
              title: (row) => row.name,
              meta: (row) => <>{pick(language, COPY.colLastUsed)}: {row.last_used_at ? <RelativeTime value={row.last_used_at} relativeAlways /> : pick(language, COPY.never)}</>
            }}
            empty={<EmptyState icon={KeyRoundedIcon} title={pick(language, COPY.tokensEmpty)} body={pick(language, COPY.tokensEmptyBody)} />}
          />
        ) : null}
      </Stack>
      {editing ? (
        <TokenDialog
          key={editing === "new" ? "new" : editing.id}
          token={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={(result) => {
            setEditing(null);
            if (result) setCreated(result);
            else notify({ message: pick(language, COPY.tokenSaved), tone: "success" });
            void tokens.reload();
          }}
        />
      ) : null}
      <OneTimeSecret
        open={Boolean(created)}
        title={say(language, COPY.createdTitle, { name: created?.name ?? "" })}
        body={
          <Stack spacing={1.5} alignItems="center">
            <Typography variant="body2" sx={{ lineHeight: 1.9, alignSelf: "stretch" }}>{pick(language, COPY.createdBody)}</Typography>
            {url ? <QrCode value={url} label={pick(language, COPY.qrLabel)} /> : null}
          </Stack>
        }
        items={[
          ...(url ? [{ label: pick(language, COPY.urlLabel), value: url }] : []),
          { label: pick(language, COPY.tokenLabel), value: created?.token ?? "" }
        ]}
        onClose={() => setCreated(null)}
      />
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

// ── device guides ────────────────────────────────────────────────────────────

function GuidesCard({ clients, error, onRetry }: { clients: EncryptedClients | null; error: unknown; onRetry: () => void }) {
  const { language } = useKit();
  const [tab, setTab] = useState<GuideId>(() => {
    const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
    if (/android/i.test(ua)) return "android";
    if (/iphone|ipad/i.test(ua)) return "ios";
    if (/mac os/i.test(ua)) return "macos";
    if (/windows/i.test(ua)) return "windows";
    if (/linux/i.test(ua)) return "linux";
    return "android";
  });
  const [busy, setBusy] = useState(false);
  const { notify, snackbar } = useUndoSnackbar();

  if (error && !clients) {
    if (isMissing(error)) return null;
    return <FriendlyError error={error} title={pick(language, COPY.guidesFailed)} onRetry={onRetry} severity="warning" scope="dns" />;
  }
  if (!clients) return null;
  const guides = new Map((clients.guides ?? []).map((item) => [item.id, item]));
  const guide = guides.get(tab);
  const available = guide ? guide.available !== false : false;
  const values = { dot: clients.dot_name ?? "—", doh: clients.doh_url ?? "—", ip: clients.ip ?? "—" };
  const needs = GUIDE_WORDS[tab].needs;

  const profile = async () => {
    setBusy(true);
    try {
      await downloadAppleProfile({ ...(clients.doh_url ? { doh_url: clients.doh_url } : {}), ...(clients.dot_name ? { dot_name: clients.dot_name } : {}), name: "MRK DNS" });
    } catch (caught) {
      notify({ message: `${pick(language, COPY.profileFailed)} ${errorSentence(language, caught, "dns")}`, tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard title={pick(language, COPY.guidesTitle)} hint={pick(language, COPY.guidesHint)}>
      <Stack spacing={2}>
        {clients.certificate && clients.certificate.trusted === false && clients.certificate.present !== false && clients.certificate.self_signed !== false ? <Notice tone="warning">{pick(language, COPY.untrusted)}</Notice> : null}
        <Box sx={{ borderBottom: 1, borderColor: "divider", maxWidth: "100%" }}>
          <Tabs value={tab} onChange={(_event, value: GuideId) => setTab(value)} variant="scrollable" scrollButtons="auto" allowScrollButtonsMobile aria-label={pick(language, COPY.guidesTitle)}>
            {GUIDE_IDS.map((id) => <Tab key={id} value={id} label={pick(language, GUIDE_WORDS[id].title)} sx={{ minHeight: 48, textTransform: "none", fontWeight: 650 }} />)}
          </Tabs>
        </Box>
        <Stack direction="row" gap={1} alignItems="center">
          <StatusPill tone={available ? "ok" : "warn"} label={pick(language, available ? COPY.ready : COPY.notAvailable)} />
        </Stack>
        {!available ? (
          <Notice tone="info">{guideReason(language, guide?.reason)}</Notice>
        ) : (
          <Stack spacing={1.5}>
            <Stack component="ol" spacing={0.75} sx={{ m: 0, ps: 3 }}>
              {GUIDE_STEPS[tab].map((step, index) => (
                <Typography component="li" variant="body2" key={index} sx={{ lineHeight: 1.9 }}>
                  {fill(step[language], { dot: values.dot, doh: values.doh, ip: values.ip }, language)}
                </Typography>
              ))}
            </Stack>
            {needs === "dot" && clients.dot_name ? <CopyField label={pick(language, COPY.dotNameLabel)} value={clients.dot_name} /> : null}
            {needs === "doh" && clients.doh_url ? <CopyField label={pick(language, COPY.dohUrlLabel)} value={clients.doh_url} /> : null}
            {tab === "windows" && clients.ip ? <CopyField label={pick(language, COPY.ipLabel)} value={clients.ip} /> : null}
            {needs === "profile" ? (
              <Box>
                <Button variant="contained" onClick={() => void profile()} disabled={busy} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : <DownloadRoundedIcon />} sx={{ minHeight: 44 }}>
                  {pick(language, COPY.getProfile)}
                </Button>
              </Box>
            ) : null}
            {needs === "linux" && clients.ip && clients.dot_name ? <CopyField label={pick(language, COPY.commandLabel)} value={linuxCommand(clients.ip, clients.dot_name)} multiline /> : null}
            {needs === "doh" && clients.doh_url ? (
              <Box sx={{ display: { xs: "none", sm: "block" } }}><QrCode value={clients.doh_url} label={pick(language, COPY.qrLabel)} size={140} /></Box>
            ) : null}
            <Typography variant="caption" color="text.secondary">{pick(language, COPY.outsideTip)}</Typography>
          </Stack>
        )}
      </Stack>
      {snackbar}
    </SectionCard>
  );
}

// ── tab ──────────────────────────────────────────────────────────────────────

export default function DnsEncryptedTab({ permissions }: { permissions: readonly string[] }) {
  const { language } = useKit();
  const canAdmin = hasPermission(permissions, "dns:admin");
  const { status, error: statusError, reload: reloadStatus } = useDnsStatus(30_000);
  const ready = engineReady(status);
  const tls = useLoad<TlsInfo>((signal) => fetchTls(signal), ready);
  const clients = useLoad<EncryptedClients>((signal) => fetchEncryptedClients(signal), ready);
  const engine = (status?.engine ?? null) as DnsD4Status | null;
  const connections = engine?.encrypted?.connections ?? null;
  const dohOn = Boolean(clients.data?.doh_url) || (status?.engine?.listeners ?? []).some((item) => item.proto === "doh");
  const suggestions = [clients.data?.dot_name, clients.data?.ip].filter((item): item is string => Boolean(item));

  const refreshAll = () => {
    void tls.reload();
    void clients.reload();
    void reloadStatus();
  };

  if (status && !ready) {
    return (
      <Stack spacing={2.5}>
        <DnsAvailability status={status} error={statusError} onRetry={() => void reloadStatus()} />
      </Stack>
    );
  }
  if (statusError && !status && helperProblem(statusError) === "module_missing") {
    return <DnsAvailability status={null} error={statusError} onRetry={() => void reloadStatus()} />;
  }

  return (
    <Stack spacing={2.5}>
      <DnsAvailability status={status} error={statusError} onRetry={() => void reloadStatus()} />
      <SectionCard title={pick(language, COPY.introTitle)}>
        <Stack spacing={1}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>{pick(language, COPY.introBody)}</Typography>
          {connections ? (
            <Typography variant="caption" color="text.secondary">
              {say(language, COPY.connections, { dot: formatNumber(connections.dot ?? 0, language), doh: formatNumber(connections.doh ?? 0, language), doq: formatNumber(connections.doq ?? 0, language) })}
            </Typography>
          ) : null}
        </Stack>
      </SectionCard>
      <SwitchesCard permissions={permissions} tls={tls.data} onSaved={refreshAll} />
      <CertificateCard tls={tls.data} error={tls.error} onRetry={() => void tls.reload()} onChanged={refreshAll} canAdmin={canAdmin} suggestions={suggestions} />
      <TokensCard canAdmin={canAdmin} dohOn={dohOn} />
      <GuidesCard clients={clients.data} error={clients.error} onRetry={() => void clients.reload()} />
    </Stack>
  );
}
