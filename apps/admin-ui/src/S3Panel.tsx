/**
 * Files › file space: buckets (as big folders), the file manager, access keys and "connect a tool".
 * Rendered under FilesPage's PageHeader + GroupTabs, so it starts with SectionCards (no h1).
 * Simple: create-bucket wizard (name → who can open the files → optional key), open/upload/share, change access.
 * Advanced: server-folder buckets, size limits, ids and dates, domain guide and every `files.space` setting.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  Box,
  Button,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Checkbox,
  IconButton,
  LinearProgress,
  MenuItem,
  Radio,
  RadioGroup,
  Stack,
  Tab,
  Tabs,
  TextField,
  Typography,
  useMediaQuery,
  useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import ArrowBackRoundedIcon from "@mui/icons-material/ArrowBackRounded";
import InventoryRoundedIcon from "@mui/icons-material/InventoryRounded";
import FolderSharedRoundedIcon from "@mui/icons-material/FolderSharedRounded";
import FolderOpenRoundedIcon from "@mui/icons-material/FolderOpenRounded";
import PublicRoundedIcon from "@mui/icons-material/PublicRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import LinkRoundedIcon from "@mui/icons-material/LinkRounded";
import KeyOffRoundedIcon from "@mui/icons-material/KeyOffRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import CloudQueueRoundedIcon from "@mui/icons-material/CloudQueueRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import ErrorOutlineRoundedIcon from "@mui/icons-material/ErrorOutlineRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { formatBytes, formatNumber } from "./format";
import type { Language } from "./i18n";
import { useVisibleInterval } from "./polling";
import { KeySecretDialog, S3Connect, S3Identities, TEMPLATE_CARDS, createKeyFor, type NewKey } from "./S3Access";
import { S3FileManager } from "./S3FileManager";
import { S3Lifecycle } from "./S3Lifecycle";
import {
  ActionWizard, BytesInput, ConfirmAction, CopyField, EmptyState, FriendlyError, HelpTip, Ltr, NoAccess, Notice, RelativeTime,
  ResponsiveList, SectionCard, StatGrid, StatTile, StatusPill, Term, useKit, useUndoSnackbar, ChoiceCards, RegistrySettings, helperProblem,
  type ListColumn, type RowAction, type WizardStep
} from "./kit";
import { nameConfirmation, pick, say, type Bi } from "./copy";

type Props = { language: Language; permissions: string[]; onUnauthorized: () => void };
type Bucket = {
  name: string;
  mode: "managed" | "linked";
  link_path: string | null;
  link_mode: "ro" | "rw" | null;
  public_read: boolean;
  quota_bytes: number | null;
  objects: number | null;
  bytes: number | null;
  created_at: number | string | null;
};
type Status = { engine_reachable: boolean; enabled: boolean; buckets: number; objects: number | null; bytes: number | null; endpoint: string | null; endpoint_is_fallback?: boolean };
type Settings = { enabled: boolean; region: string; public_endpoint: string | null; virtual_host_suffix: string | null; max_object_bytes: number | null; default_quota_bytes: number | null };
type LinkItem = { path: string; writable: boolean; size_bytes?: number | null; bucket?: string | null };
type Links = { items: LinkItem[]; root?: string; compose_hint?: string };
type Access = "private" | "link" | "public";
type KeyChoice = "none" | "read_write" | "backup_client";

const BASE = "/api/v1/s3";
const RESERVED = ["mrk", "admin", "api", "www", "_"];

const T = {
  statusTitle: { fa: "فضای فایل", en: "File space" },
  statusHint: { fa: "یک فضای فایل روی سرور خودتان، مثل Google Drive، که برنامه‌ها هم می‌توانند در آن پشتیبان بگذارند.", en: "File storage on your own server, like Google Drive, where apps can also keep backups." },
  refresh: { fa: "تازه کردن", en: "Refresh" },
  unavailable: { fa: "این بخش روی نسخه فعلی سرور نیست. پیشکار را به‌روز کنید.", en: "This section isn't on this server version yet. Update Pishkar." },
  engineUp: { fa: "آماده", en: "Ready" },
  engineDown: { fa: "جواب نمی‌دهد", en: "Not answering" },
  engineDownHint: { fa: "فضای فایل الان جواب نمی‌دهد. چند لحظه بعد تازه کنید؛ اگر ماند، سرویس پیشکار را دوباره راه‌اندازی کنید.", en: "File space isn't answering. Refresh in a moment; if it stays, restart the Pishkar service." },
  disabledModule: { fa: "خاموش", en: "Off" },
  disabledHint: { fa: "فضای فایل خاموش است. در بخش تنظیمات پیشرفته می‌توانید روشنش کنید.", en: "File space is turned off. You can turn it on in the advanced settings." },
  totalBuckets: { fa: "پوشه اصلی", en: "Buckets" },
  totalObjects: { fa: "فایل", en: "Files" },
  totalBytes: { fa: "حجم کل", en: "Total size" },
  endpoint: { fa: "آدرس اتصال", en: "Endpoint" },
  endpointFallback: { fa: "آدرس عمومی فضای فایل تنظیم نشده؛ برنامه‌های بیرون از این سرور نمی‌توانند وصل شوند.", en: "No public address is set, so apps outside this server can't connect." },
  setAddress: { fa: "تنظیم آدرس عمومی", en: "Set public address" },
  tabBuckets: { fa: "پوشه‌ها و فایل‌ها", en: "Buckets & files" },
  tabKeys: { fa: "کلیدهای دسترسی", en: "Access keys" },
  tabConnect: { fa: "اتصال ابزارها", en: "Connect a tool" },
  buckets: { fa: "پوشه‌های اصلی", en: "Buckets" },
  bucketsHint: { fa: "هر برنامه معمولاً یک پوشه اصلی برای خودش دارد. برای دیدن فایل‌ها روی آن بزنید.", en: "Each app usually gets its own bucket. Tap one to see its files." },
  emptyTitle: { fa: "هنوز پوشه اصلی ندارید", en: "No buckets yet" },
  emptyBody: { fa: "یک پوشه اصلی بسازید تا فایل‌ها یا پشتیبان برنامه‌ها را در آن بگذارید.", en: "Create a bucket to keep files or app backups in it." },
  createBucket: { fa: "ساخت پوشه اصلی", en: "Create bucket" },
  managed: { fa: "فضای پیشکار", en: "Managed" },
  linkedRo: { fa: "پوشه سرور، فقط خواندنی", en: "Server folder, read-only" },
  linkedRw: { fa: "پوشه سرور، خواندن و نوشتن", en: "Server folder, read/write" },
  public: { fa: "عمومی", en: "Public" },
  private: { fa: "خصوصی", en: "Private" },
  filesCount: { fa: "{n} فایل", en: "{n} files" },
  unknownStats: { fa: "آمارش هنوز آماده نیست", en: "Stats not ready yet" },
  quota: { fa: "سقف حجم", en: "Size limit" },
  noQuota: { fa: "بدون سقف", en: "No limit" },
  kind: { fa: "نوع", en: "Kind" },
  created: { fa: "ساخته شده", en: "Created" },
  name: { fa: "نام", en: "Name" },
  access: { fa: "چه کسی فایل‌ها را می‌بیند", en: "Who can see files" },
  size: { fa: "حجم", en: "Size" },
  files: { fa: "فایل‌ها", en: "Files" },
  open: { fa: "باز کردن", en: "Open" },
  back: { fa: "برگشت به پوشه‌های اصلی", en: "Back to buckets" },
  changeAccess: { fa: "تغییر سطح دسترسی", en: "Change access" },
  delete: { fa: "پاک کردن پوشه اصلی", en: "Delete bucket" },
  listLabel: { fa: "پوشه‌های اصلی", en: "Buckets" },
  // wizard
  wizardTitle: { fa: "ساخت پوشه اصلی تازه", en: "Create a bucket" },
  stepName: { fa: "نامش چه باشد؟", en: "What's its name?" },
  stepNameHint: { fa: "نام در آدرس‌ها می‌آید؛ برای همین فقط حروف انگلیسی می‌پذیرد.", en: "The name appears in addresses, so it uses English letters only." },
  nameLabel: { fa: "نام پوشه اصلی", en: "Bucket name" },
  ruleGeneral: { fa: "فقط حروف کوچک انگلیسی، عدد، نقطه و خط تیره؛ ۳ تا ۶۳ نویسه، و اول و آخرش حرف یا عدد.", en: "Lowercase letters, digits, dots and hyphens; 3–63 characters, starting and ending with a letter or digit." },
  ruleDots: { fa: "نام نباید شبیه نشانی IP باشد یا دو نقطه پشت سر هم داشته باشد.", en: "The name can't look like an IP address or have two dots in a row." },
  rulePrefix: { fa: "نام نباید با «xn--» شروع یا با «-s3alias» یا «--ol-s3» تمام شود.", en: "The name can't start with “xn--” or end with “-s3alias” or “--ol-s3”." },
  ruleReserved: { fa: "این نام برای خود سامانه کنار گذاشته شده؛ نام دیگری بنویسید.", en: "This name is reserved by the system; pick another." },
  ruleTaken: { fa: "این نام قبلاً گرفته شده؛ نام دیگری بنویسید.", en: "That name is already taken; pick another." },
  ruleOk: { fa: "این نام مناسب است.", en: "This name works." },
  stepAccess: { fa: "چه کسی فایل‌ها را ببیند؟", en: "Who can open the files?" },
  stepAccessHint: { fa: "بعداً هم می‌توانید عوضش کنید.", en: "You can change this later." },
  a_private: { fa: "فقط برنامه‌های من", en: "Only my apps" },
  ab_private: { fa: "فقط برنامه‌هایی که کلید دسترسی دارند و کسانی که وارد این پنل می‌شوند. امن‌ترین انتخاب.", en: "Only apps with an access key and people signed in to this panel. The safest choice." },
  a_link: { fa: "هر کسی که لینک را دارد", en: "Anyone with the link" },
  ab_link: { fa: "فایل‌ها خصوصی می‌مانند؛ برای هر فایلی که بخواهید یک لینک اشتراک موقت می‌سازید.", en: "Files stay private; you create a temporary share link for each file you want to share." },
  a_public: { fa: "همه (عمومی)", en: "Everyone (public)" },
  ab_public: { fa: "هر کسی آدرس را بداند، بدون کلید همه فایل‌ها را دانلود می‌کند. برای فایل‌های شخصی مناسب نیست.", en: "Anyone who knows the address can download every file without a key. Not for private files." },
  stepWhere: { fa: "فایل‌ها کجا نگه داشته شوند؟", en: "Where are the files kept?" },
  typeManaged: { fa: "در فضای خود پیشکار (پیشنهادی)", en: "In Pishkar's own storage (recommended)" },
  typeManagedHint: { fa: "پیشکار همه چیز را خودش نگه می‌دارد.", en: "Pishkar keeps everything itself." },
  typeLinked: { fa: "یک پوشه واقعی روی سرور", en: "A real folder on the server" },
  typeLinkedHint: { fa: "یک پوشه موجود روی سرور را مثل پوشه اصلی در دسترس می‌گذارد.", en: "Exposes an existing server folder as a bucket." },
  ownerOnly: { fa: "فقط «مالک» می‌تواند پوشه سرور را وصل کند.", en: "Only the “Owner” can link a server folder." },
  linksTitle: { fa: "پوشه‌های سرور که می‌شود وصل کرد", en: "Server folders you can link" },
  linksHint: { fa: "پیشکار فقط پوشه‌های زیر {root} را می‌بیند؛ هیچ‌وقت بیرون از آن را نمی‌بیند.", en: "Pishkar only sees folders under {root}, never anything outside it." },
  noLinks: { fa: "هنوز پوشه‌ای به پیشکار داده نشده. این خط را به سرویس پیشکار در فایل Compose اضافه کنید و سرویس را دوباره راه‌اندازی کنید:", en: "No folder is mounted yet. Add this line to the Pishkar service in the Compose file and restart it:" },
  composeLine: { fa: "خط Compose", en: "Compose line" },
  writable: { fa: "قابل نوشتن", en: "writable" },
  readOnlyMount: { fa: "فقط خواندنی", en: "read-only" },
  inUse: { fa: "به «{bucket}» وصل است", en: "linked to “{bucket}”" },
  pickLink: { fa: "یک پوشه سرور انتخاب کنید.", en: "Choose a server folder." },
  linkMode: { fa: "برنامه‌ها با این پوشه چه کنند؟", en: "What can apps do in this folder?" },
  ro: { fa: "فقط بخوانند (امن‌تر)", en: "Read only (safer)" },
  rw: { fa: "بخوانند و بنویسند", en: "Read and write" },
  quotaLabel: { fa: "سقف حجم (خالی یعنی بدون سقف)", en: "Size limit (empty = none)" },
  stepKey: { fa: "کلید برای برنامه‌ها؟", en: "A key for apps?" },
  stepKeyHint: { fa: "اگر برنامه‌ای قرار است فایل بگذارد، همین حالا برایش کلید بسازید.", en: "If an app will store files here, make its key now." },
  k_none: { fa: "فعلاً نه", en: "Not now" },
  kb_none: { fa: "بعداً از بخش «کلیدهای دسترسی» هم می‌شود ساخت.", en: "You can make one later under “Access keys”." },
  create: { fa: "ساخت پوشه اصلی", en: "Create bucket" },
  bucketCreated: { fa: "پوشه اصلی «{name}» ساخته شد.", en: "Bucket “{name}” created." },
  notSynced: { fa: "پوشه اصلی ثبت شد ولی هنوز آماده نیست. چند ثانیه دیگر صفحه را تازه کنید.", en: "The bucket was saved but isn't ready yet. Refresh in a few seconds." },
  // edit
  editTitle: { fa: "سطح دسترسی «{name}»", en: "Access for “{name}”" },
  save: { fa: "ذخیره", en: "Save" },
  cancel: { fa: "انصراف", en: "Cancel" },
  saved: { fa: "تغییرات «{name}» ذخیره شد.", en: "Changes to “{name}” saved." },
  // delete
  deleteTitle: { fa: "پوشه اصلی «{name}» پاک شود؟", en: "Delete bucket “{name}”?" },
  deleteBody: { fa: "پوشه و همه فایل‌هایش برای همیشه پاک می‌شوند. برنامه‌هایی که در آن فایل می‌گذارند دیگر نمی‌توانند.", en: "The bucket and all its files are deleted for good. Apps that store files in it will stop working." },
  deleteLinkedBody: { fa: "فقط اتصال این پوشه برداشته می‌شود؛ فایل‌های واقعی روی سرور سر جایشان می‌مانند.", en: "Only the link is removed; the real files on the server stay where they are." },
  force: { fa: "حتی اگر خالی نیست پاک شود", en: "Delete even if it isn't empty" },
  deleteSummary: { fa: "در آن {n} فایل با حجم {size} هست.", en: "It holds {n} files ({size})." },
  deleted: { fa: "پوشه اصلی پاک شد ({n} فایل).", en: "Bucket deleted ({n} files)." },
  noAdmin: { fa: "ساختن و تنظیم پوشه‌های اصلی", en: "Creating and configuring buckets" },
  // public address
  addressTitle: { fa: "آدرس عمومی فضای فایل", en: "Public address for file space" },
  addressHint: { fa: "آدرسی که برنامه‌های بیرون از این سرور با آن وصل می‌شوند، مثل https://s3.example.com", en: "The address apps outside this server use, for example https://s3.example.com" },
  addressLabel: { fa: "آدرس عمومی", en: "Public endpoint" },
  addressRule: { fa: "آدرس باید با http:// یا https:// شروع شود و مسیر اضافه نداشته باشد.", en: "The address must start with http:// or https:// and have no extra path." },
  addressSaved: { fa: "آدرس عمومی ذخیره شد.", en: "Public address saved." },
  addressHelp: { fa: "اول باید دامنه را به این سرور وصل کنید. راهنمای کامل در حالت پیشرفته هست.", en: "First point a domain at this server. The full guide is in Advanced mode." },
  // advanced
  linkedTitle: { fa: "پوشه‌های سرور", en: "Server folders" },
  linkedHint: { fa: "پوشه‌هایی از سرور که به پیشکار داده شده‌اند و می‌توانند پوشه اصلی شوند.", en: "Server folders mounted into Pishkar that can become buckets." },
  domainTitle: { fa: "وصل کردن یک دامنه به فضای فایل", en: "Attach a domain to file space" },
  domainSteps: {
    fa: [
      "در تنظیمات DNS دامنه، رکورد s3.example.com را به IP همین سرور بدهید (برای نوع آدرس‌دهی با دامنه، ‎*.s3.example.com را هم).",
      "در Dokploy یا Traefik یک مسیر برای این دامنه به درگاه 9000 همین سرور بسازید و اتصال امن (TLS) را روشن کنید.",
      "در همین صفحه «آدرس عمومی» را https://s3.example.com بگذارید.",
      "از بخش «اتصال ابزارها» تنظیمات آماده را کپی کنید."
    ],
    en: [
      "In DNS, point s3.example.com (and *.s3.example.com for virtual-host style) at this server's IP.",
      "In Dokploy or Traefik add a route for that domain to port 9000 on this server, with TLS; keep the Host header.",
      "On this page set the public endpoint to https://s3.example.com.",
      "Copy ready-made tool settings from “Connect a tool”."
    ]
  },
  settingsTitle: { fa: "همه تنظیمات فضای فایل", en: "Every file-space setting" }
} satisfies Record<string, Bi | { fa: string[]; en: string[] }>;

function nameProblem(name: string, existing: readonly string[]): Bi | null {
  if (name.length < 3 || name.length > 63 || !/^[a-z0-9.-]+$/.test(name) || !/^[a-z0-9](.*[a-z0-9])?$/.test(name)) return T.ruleGeneral;
  if (name.includes("..") || /^\d{1,3}(\.\d{1,3}){3}$/.test(name)) return T.ruleDots;
  if (name.startsWith("xn--") || name.endsWith("-s3alias") || name.endsWith("--ol-s3")) return T.rulePrefix;
  if (RESERVED.includes(name)) return T.ruleReserved;
  if (existing.includes(name)) return T.ruleTaken;
  return null;
}

function accessOptions(language: Language, keys: Access[]) {
  const icon = { private: LockRoundedIcon, link: LinkRoundedIcon, public: PublicRoundedIcon } as const;
  return keys.map((key) => ({
    key,
    icon: icon[key],
    title: pick(language, T[`a_${key}`]),
    body: pick(language, T[`ab_${key}`]),
    tone: key === "public" ? ("warning" as const) : undefined
  }));
}

function AccessPill({ bucket }: { bucket: Bucket }) {
  const { language } = useKit();
  return bucket.public_read ? <StatusPill tone="warn" label={pick(language, T.public)} /> : <StatusPill tone="info" label={pick(language, T.private)} />;
}

function bucketKind(language: Language, bucket: Bucket) {
  if (bucket.mode !== "linked") return pick(language, T.managed);
  return pick(language, bucket.link_mode === "rw" ? T.linkedRw : T.linkedRo);
}

function LinkPicker({ links, linksError, value, onChange, onRetry }: { links: Links | null; linksError: unknown; value: string; onChange: (path: string) => void; onRetry: () => void }) {
  const { language, isAdvanced } = useKit();
  return (
    <Box>
      <Typography variant="subtitle2">{pick(language, T.linksTitle)}</Typography>
      <Typography variant="caption" color="text.secondary" display="block">
        {pick(language, T.linksHint).split("{root}")[0]}<Ltr mono>{links?.root ?? "/mnt/links"}</Ltr>{pick(language, T.linksHint).split("{root}")[1]}
      </Typography>
      {linksError !== null && <Box sx={{ mt: 1 }}><FriendlyError error={linksError} onRetry={onRetry} /></Box>}
      {links === null && linksError === null && <LinearProgress sx={{ mt: 1 }} />}
      {links && links.items.length > 0 && (
        <RadioGroup value={value} onChange={(event) => onChange(event.target.value)} aria-label={pick(language, T.linksTitle)} sx={{ mt: 1 }}>
          {links.items.map((item) => (
            <FormControlLabel
              key={item.path}
              value={item.path}
              disabled={Boolean(item.bucket)}
              control={<Radio size="small" />}
              sx={{ minHeight: 44 }}
              label={
                <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
                  <Ltr mono>{item.path}</Ltr>
                  <StatusPill tone={item.writable ? "ok" : "off"} label={pick(language, item.writable ? T.writable : T.readOnlyMount)} />
                  {item.size_bytes ? <Typography variant="caption" color="text.secondary">{formatBytes(item.size_bytes, language)}</Typography> : null}
                  {item.bucket && <Typography variant="caption" color="text.secondary">{say(language, T.inUse, { bucket: item.bucket })}</Typography>}
                </Stack>
              }
            />
          ))}
        </RadioGroup>
      )}
      {links && (links.items.length === 0 || isAdvanced) && links.compose_hint && (
        <Box sx={{ mt: 1 }}>
          {links.items.length === 0 && <Typography variant="body2" sx={{ mb: 0.5 }}>{pick(language, T.noLinks)}</Typography>}
          <CopyField label={pick(language, T.composeLine)} value={links.compose_hint} multiline />
        </Box>
      )}
    </Box>
  );
}

function useLinks(enabled: boolean) {
  const [links, setLinks] = useState<Links | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    setError(null);
    void (async () => {
      try {
        setLinks(await getJson<Links>(`${BASE}/links`, controller.signal));
      } catch (caught) {
        if (!isAbortError(caught) && !(caught instanceof ApiError && caught.status === 401)) setError(caught);
      }
    })();
    return () => controller.abort();
  }, [enabled, attempt]);
  return { links, error, retry: () => setAttempt((value) => value + 1) };
}

function CreateBucketWizard({ isOwner, existing, onClose, onDone }: {
  isOwner: boolean;
  existing: string[];
  onClose: () => void;
  onDone: (result: { name: string; warning: boolean; secret: NewKey | null }) => void;
}) {
  const { language, isAdvanced } = useKit();
  const [name, setName] = useState("");
  const [access, setAccess] = useState<Access>("private");
  const [mode, setMode] = useState<"managed" | "linked">("managed");
  const [linkPath, setLinkPath] = useState("");
  const [linkMode, setLinkMode] = useState<"ro" | "rw">("ro");
  const [quota, setQuota] = useState<number | null>(null);
  const [keyChoice, setKeyChoice] = useState<KeyChoice>("none");
  const created = useRef<{ name: string; warning: boolean } | null>(null);
  const { links, error: linksError, retry } = useLinks(isAdvanced && mode === "linked");
  const chosenLink = links?.items.find((item) => item.path === linkPath) ?? null;
  const problem = name ? nameProblem(name, existing) : null;

  const steps: WizardStep[] = [
    {
      key: "name",
      title: pick(language, T.stepName),
      hint: pick(language, T.stepNameHint),
      validate: () => {
        const issue = nameProblem(name, existing);
        return issue ? pick(language, issue) : null;
      },
      render: () => (
        <Stack spacing={1}>
          <TextField
            fullWidth
            autoFocus
            label={pick(language, T.nameLabel)}
            value={name}
            onChange={(event) => setName(event.target.value.toLowerCase().trim())}
            slotProps={{ htmlInput: { dir: "ltr", maxLength: 63, autoComplete: "off", spellCheck: false } }}
          />
          <Stack direction="row" spacing={0.75} alignItems="flex-start" aria-live="polite">
            {name && !problem ? <CheckCircleRoundedIcon color="success" sx={{ fontSize: 18, mt: 0.25 }} aria-hidden /> : <ErrorOutlineRoundedIcon color={name ? "error" : "disabled"} sx={{ fontSize: 18, mt: 0.25 }} aria-hidden />}
            <Typography variant="body2" color={name && !problem ? "success.main" : name ? "error.main" : "text.secondary"}>
              {pick(language, name && !problem ? T.ruleOk : (problem ?? T.ruleGeneral))}
            </Typography>
          </Stack>
        </Stack>
      )
    },
    {
      key: "access",
      title: pick(language, T.stepAccess),
      hint: pick(language, T.stepAccessHint),
      render: () => <ChoiceCards label={pick(language, T.stepAccess)} value={access} onChange={setAccess} options={accessOptions(language, ["private", "link", "public"])} />
    }
  ];

  if (isAdvanced) {
    steps.push({
      key: "where",
      title: pick(language, T.stepWhere),
      validate: () => (mode === "linked" && !chosenLink ? pick(language, T.pickLink) : null),
      render: () => (
        <Stack spacing={2}>
          <ChoiceCards
            label={pick(language, T.stepWhere)}
            value={mode}
            onChange={setMode}
            options={[
              { key: "managed", icon: InventoryRoundedIcon, title: pick(language, T.typeManaged), body: pick(language, T.typeManagedHint) },
              { key: "linked", icon: FolderSharedRoundedIcon, title: pick(language, T.typeLinked), body: pick(language, isOwner ? T.typeLinkedHint : T.ownerOnly), disabled: !isOwner }
            ]}
          />
          {mode === "linked" && <LinkPicker links={links} linksError={linksError} value={linkPath} onChange={setLinkPath} onRetry={retry} />}
          {mode === "linked" && chosenLink && (
            <TextField select fullWidth size="small" label={pick(language, T.linkMode)} value={chosenLink.writable ? linkMode : "ro"} disabled={!chosenLink.writable} onChange={(event) => setLinkMode(event.target.value as "ro" | "rw")}>
              <MenuItem value="ro">{pick(language, T.ro)}</MenuItem>
              <MenuItem value="rw">{pick(language, T.rw)}</MenuItem>
            </TextField>
          )}
          <BytesInput label={pick(language, T.quotaLabel)} value={quota} onChange={setQuota} min={1} />
        </Stack>
      )
    });
  }

  steps.push({
    key: "key",
    title: pick(language, T.stepKey),
    hint: pick(language, T.stepKeyHint),
    render: () => (
      <ChoiceCards
        label={pick(language, T.stepKey)}
        value={keyChoice}
        onChange={setKeyChoice}
        options={[
          { key: "none" as const, icon: KeyOffRoundedIcon, title: pick(language, T.k_none), body: pick(language, T.kb_none) },
          { key: "read_write" as const, icon: TEMPLATE_CARDS.read_write.icon, title: pick(language, TEMPLATE_CARDS.read_write.title), body: pick(language, TEMPLATE_CARDS.read_write.body) },
          { key: "backup_client" as const, icon: TEMPLATE_CARDS.backup_client.icon, title: pick(language, TEMPLATE_CARDS.backup_client.title), body: pick(language, TEMPLATE_CARDS.backup_client.body) }
        ]}
      />
    )
  });

  const finish = async () => {
    if (!created.current) {
      const body: Record<string, unknown> = { name, mode: isAdvanced ? mode : "managed", public_read: access === "public" };
      if (isAdvanced && quota) body.quota_bytes = quota;
      if (isAdvanced && mode === "linked") {
        body.link_path = linkPath;
        body.link_mode = chosenLink?.writable ? linkMode : "ro";
      }
      const result = await mutateJson<{ engine_synced?: boolean } | null>(`${BASE}/buckets`, { method: "POST", body });
      created.current = { name, warning: Boolean(result && result.engine_synced === false) };
    }
    let secret: NewKey | null = null;
    if (keyChoice !== "none") secret = await createKeyFor(`${created.current.name}-${keyChoice === "backup_client" ? "backup" : "app"}`, created.current.name, keyChoice);
    onDone({ ...created.current, secret });
  };

  return <ActionWizard open title={pick(language, T.wizardTitle)} steps={steps} onFinish={finish} onClose={onClose} finishLabel={pick(language, T.create)} />;
}

function EditBucketDialog({ bucket, isOwner, onClose, onDone }: { bucket: Bucket; isOwner: boolean; onClose: () => void; onDone: (message: string) => void }) {
  const { language, isAdvanced } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [access, setAccess] = useState<Access>(bucket.public_read ? "public" : "private");
  const [quota, setQuota] = useState<number | null>(bucket.quota_bytes);
  const [linkMode, setLinkMode] = useState<"ro" | "rw">(bucket.link_mode ?? "ro");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    const changes: Record<string, unknown> = {};
    const publicRead = access === "public";
    if (publicRead !== bucket.public_read) changes.public_read = publicRead;
    if (isAdvanced && (quota ?? null) !== (bucket.quota_bytes ?? null)) changes.quota_bytes = quota;
    if (isAdvanced && bucket.mode === "linked" && isOwner && linkMode !== bucket.link_mode) changes.link_mode = linkMode;
    if (!Object.keys(changes).length) {
      onClose();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await mutateJson(`${BASE}/buckets/${encodeURIComponent(bucket.name)}`, { method: "PATCH", body: changes });
      onDone(say(language, T.saved, { name: bucket.name }));
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth="sm" aria-labelledby="mrk-bucket-edit-title">
      <Box component="form" onSubmit={submit} noValidate>
        <DialogTitle id="mrk-bucket-edit-title">{say(language, T.editTitle, { name: bucket.name })}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <ChoiceCards
              label={pick(language, T.access)}
              value={access === "link" ? "private" : access}
              onChange={setAccess}
              options={accessOptions(language, ["private", "public"]).map((option) => (option.key === "private" ? { ...option, body: `${option.body} ${pick(language, T.ab_link)}` } : option))}
            />
            {isAdvanced && <BytesInput label={pick(language, T.quotaLabel)} value={quota} onChange={setQuota} min={1} disabled={busy} />}
            {isAdvanced && bucket.mode === "linked" && (
              <TextField select size="small" label={pick(language, T.linkMode)} value={linkMode} disabled={busy || !isOwner} helperText={isOwner ? " " : pick(language, T.ownerOnly)} onChange={(event) => setLinkMode(event.target.value as "ro" | "rw")}>
                <MenuItem value="ro">{pick(language, T.ro)}</MenuItem>
                <MenuItem value="rw">{pick(language, T.rw)}</MenuItem>
              </TextField>
            )}
            {error !== null && <FriendlyError error={error} noAction />}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, T.cancel)}</Button>
          <Button type="submit" variant="contained" disabled={busy} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>{pick(language, T.save)}</Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

/** Simple one-field dialog for the most-asked setting: the public address. */
function PublicAddressDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [value, setValue] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const settings = await getJson<Settings>(`${BASE}/settings`, controller.signal);
        setValue(settings.public_endpoint ?? "");
      } catch (caught) {
        if (!isAbortError(caught) && !(caught instanceof ApiError && caught.status === 401)) setError(caught);
      } finally {
        setLoaded(true);
      }
    })();
    return () => controller.abort();
  }, []);

  const trimmed = value.trim();
  const ok = !trimmed || /^https?:\/\/[^\s/]+\/?$/i.test(trimmed);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!ok || busy) return;
    setBusy(true);
    setError(null);
    try {
      await mutateJson(`${BASE}/settings`, { method: "PUT", body: { public_endpoint: trimmed.replace(/\/$/, "") || null } });
      onDone();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth="sm" aria-labelledby="mrk-s3-address-title">
      <Box component="form" onSubmit={submit} noValidate>
        <DialogTitle id="mrk-s3-address-title">{pick(language, T.addressTitle)}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">{pick(language, T.addressHint)}</Typography>
            {!loaded && <LinearProgress />}
            <TextField
              fullWidth
              label={pick(language, T.addressLabel)}
              value={value}
              disabled={busy || !loaded}
              error={!ok}
              helperText={ok ? pick(language, T.addressHelp) : pick(language, T.addressRule)}
              onChange={(event) => setValue(event.target.value)}
              slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoComplete: "off" } }}
            />
            {error !== null && <FriendlyError error={error} noAction />}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, T.cancel)}</Button>
          <Button type="submit" variant="contained" disabled={!ok || busy || !loaded} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>{pick(language, T.save)}</Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

function LinkedFoldersCard() {
  const { language } = useKit();
  const { links, error, retry } = useLinks(true);
  return (
    <SectionCard advanced collapsible defaultCollapsed title={pick(language, T.linkedTitle)} hint={pick(language, T.linkedHint)}>
      <LinkPicker links={links} linksError={error} value="" onChange={() => undefined} onRetry={retry} />
    </SectionCard>
  );
}

function hashWantsSettings() {
  const query = window.location.hash.split("?")[1] ?? "";
  return new URLSearchParams(query).get("settings") === "1";
}

export function S3Panel({ language, permissions }: Props) {
  const { isAdvanced } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const canWrite = hasPermission(permissions, "s3:write");
  const canAdmin = hasPermission(permissions, "s3:admin");
  const isOwner = permissions.includes("*");
  const [status, setStatus] = useState<Status | null>(null);
  const [buckets, setBuckets] = useState<Bucket[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [tab, setTab] = useState<"buckets" | "keys" | "connect">("buckets");
  const [openBucket, setOpenBucket] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Bucket | null>(null);
  const [deleting, setDeleting] = useState<Bucket | null>(null);
  const [force, setForce] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<unknown>(null);
  const [secret, setSecret] = useState<NewKey | null>(null);
  const [addressOpen, setAddressOpen] = useState(() => canAdmin && hashWantsSettings());
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async (background = false) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    if (!background) setLoading(true);
    try {
      const [nextStatus, list] = await Promise.all([
        getJson<Status>(`${BASE}/status`, current.signal),
        getJson<{ items: Bucket[] }>(`${BASE}/buckets`, current.signal)
      ]);
      setStatus(nextStatus);
      setBuckets(list.items ?? []);
      setUnavailable(false);
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      if (helperProblem(caught) === "module_missing") setUnavailable(true);
      else setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);
  useVisibleInterval(() => void load(true), unavailable || openBucket ? null : 60_000);

  const bucketNames = useMemo(() => (buckets ?? []).map((bucket) => bucket.name), [buckets]);

  const removeBucket = async () => {
    if (!deleting) return;
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      const result = await mutateJson<{ files_removed?: number } | null>(`${BASE}/buckets/${encodeURIComponent(deleting.name)}`, { method: "DELETE", body: { confirmation: deleting.name, force } });
      notify({ message: say(language, T.deleted, { n: formatNumber(result?.files_removed ?? 0, language) }) });
      setDeleting(null);
      await load(true);
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setDeleteError(caught);
    } finally {
      setDeleteBusy(false);
    }
  };

  const createButton = canAdmin ? (
    <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setCreating(true)} sx={{ minHeight: 44 }}>{pick(language, T.createBucket)}</Button>
  ) : undefined;

  const columns: ListColumn<Bucket>[] = [
    {
      key: "name",
      header: pick(language, T.name),
      render: (bucket) => (
        <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
          {bucket.mode === "linked" ? <FolderSharedRoundedIcon sx={{ color: "#f59e0b" }} aria-hidden /> : <FolderOpenRoundedIcon color="primary" aria-hidden />}
          <Typography fontWeight={700} noWrap><Ltr>{bucket.name}</Ltr></Typography>
        </Stack>
      )
    },
    { key: "access", header: pick(language, T.access), render: (bucket) => <AccessPill bucket={bucket} /> },
    { key: "size", header: pick(language, T.size), align: "end", render: (bucket) => (bucket.bytes === null ? "—" : formatBytes(bucket.bytes, language)) },
    { key: "files", header: pick(language, T.files), align: "end", render: (bucket) => (bucket.objects === null ? pick(language, T.unknownStats) : formatNumber(bucket.objects, language)) },
    { key: "quota", header: pick(language, T.quota), advancedOnly: true, render: (bucket) => (bucket.quota_bytes ? formatBytes(bucket.quota_bytes, language) : pick(language, T.noQuota)) },
    {
      key: "kind",
      header: pick(language, T.kind),
      advancedOnly: true,
      render: (bucket) => (
        <Box>
          {bucketKind(language, bucket)}
          {bucket.link_path && <Typography variant="caption" color="text.secondary" display="block"><Ltr mono>{bucket.link_path}</Ltr></Typography>}
        </Box>
      )
    },
    { key: "created", header: pick(language, T.created), advancedOnly: true, render: (bucket) => <RelativeTime value={bucket.created_at} /> }
  ];

  const actions: RowAction<Bucket>[] = [
    { key: "open", label: pick(language, T.open), icon: FolderOpenRoundedIcon, onClick: (bucket) => setOpenBucket(bucket.name) },
    { key: "access", label: pick(language, T.changeAccess), icon: TuneRoundedIcon, hidden: () => !canAdmin, onClick: (bucket) => setEditing(bucket) },
    {
      key: "delete",
      label: pick(language, T.delete),
      icon: DeleteOutlineRoundedIcon,
      danger: true,
      hidden: () => !canAdmin,
      onClick: (bucket) => {
        setForce(false);
        setDeleteError(null);
        setDeleting(bucket);
      }
    }
  ];

  const engineTone = !status ? null : !status.enabled ? <StatusPill tone="off" label={pick(language, T.disabledModule)} /> : status.engine_reachable ? <StatusPill tone="ok" label={pick(language, T.engineUp)} /> : <StatusPill tone="error" label={pick(language, T.engineDown)} />;

  return (
    <Stack spacing={2.5}>
      {unavailable && <Notice>{pick(language, T.unavailable)}</Notice>}
      {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
      {warning && <Notice tone="warning">{warning}</Notice>}
      {loading && !status && !unavailable && error === null && <LinearProgress />}

      {status && (
        <SectionCard
          title={pick(language, T.statusTitle)}
          hint={pick(language, T.statusHint)}
          status={engineTone}
          action={
            <IconButton aria-label={pick(language, T.refresh)} onClick={() => void load()} disabled={loading} sx={{ width: 44, height: 44 }}>
              {loading ? <CircularProgress size={18} /> : <RefreshRoundedIcon />}
            </IconButton>
          }
        >
          <Stack spacing={1.5}>
            <StatGrid columns={3}>
              <StatTile icon={FolderOpenRoundedIcon} label={pick(language, T.totalBuckets)} value={formatNumber(status.buckets, language)} />
              <StatTile icon={CloudQueueRoundedIcon} label={pick(language, T.totalObjects)} value={formatNumber(status.objects, language)} />
              <StatTile icon={InventoryRoundedIcon} label={pick(language, T.totalBytes)} value={formatBytes(status.bytes, language)} />
            </StatGrid>
            {status.enabled && !status.engine_reachable && <Notice tone="error">{pick(language, T.engineDownHint)}</Notice>}
            {!status.enabled && <Notice>{pick(language, T.disabledHint)}</Notice>}
            {status.endpoint_is_fallback && (
              <Notice
                tone="warning"
                action={canAdmin ? <Button color="inherit" size="small" onClick={() => setAddressOpen(true)}>{pick(language, T.setAddress)}</Button> : undefined}
              >
                {pick(language, T.endpointFallback)}
              </Notice>
            )}
            {isAdvanced && status.endpoint && <CopyField label={pick(language, T.endpoint)} value={status.endpoint} />}
          </Stack>
        </SectionCard>
      )}

      {status && buckets && (
        <>
          <Tabs value={tab} onChange={(_event, value: "buckets" | "keys" | "connect") => setTab(value)} variant="scrollable" allowScrollButtonsMobile aria-label={pick(language, T.statusTitle)} sx={{ borderBottom: 1, borderColor: "divider" }}>
            <Tab value="buckets" label={pick(language, T.tabBuckets)} sx={{ minHeight: 44 }} />
            {canAdmin && <Tab value="keys" label={pick(language, T.tabKeys)} sx={{ minHeight: 44 }} />}
            <Tab value="connect" label={pick(language, T.tabConnect)} sx={{ minHeight: 44 }} />
          </Tabs>

          {tab === "buckets" && (openBucket ? (
            <SectionCard
              title={openBucket}
              action={
                <Button
                  startIcon={<ArrowBackRoundedIcon sx={{ transform: language === "fa" ? "scaleX(-1)" : undefined }} />}
                  onClick={() => {
                    setOpenBucket(null);
                    void load(true);
                  }}
                  sx={{ minHeight: 44 }}
                >
                  {pick(language, T.back)}
                </Button>
              }
            >
              <S3FileManager key={openBucket} bucket={openBucket} language={language} canWrite={canWrite} />
              {isAdvanced && (
                <Box sx={{ mt: 2 }}>
                  <S3Lifecycle key={openBucket} bucket={openBucket} canAdmin={canAdmin} />
                </Box>
              )}
            </SectionCard>
          ) : (
            <SectionCard
              title={pick(language, T.buckets)}
              hint={pick(language, T.bucketsHint)}
              action={buckets.length > 0 ? createButton : <HelpTip term="bucket" />}
              flush
            >
              <Box sx={{ px: 2, pt: 0.5, pb: 1 }}>
                <Typography variant="caption" color="text.secondary"><Term k="bucket" first withHelp /></Typography>
              </Box>
              <ResponsiveList
                label={pick(language, T.listLabel)}
                rows={buckets}
                rowKey={(bucket) => bucket.name}
                columns={columns}
                card={{
                  title: (bucket) => <Ltr>{bucket.name}</Ltr>,
                  meta: (bucket) => (bucket.bytes === null ? pick(language, T.unknownStats) : `${formatBytes(bucket.bytes, language)} · ${say(language, T.filesCount, { n: formatNumber(bucket.objects ?? 0, language) })}`),
                  status: (bucket) => <AccessPill bucket={bucket} />
                }}
                actions={actions}
                onRowClick={(bucket) => setOpenBucket(bucket.name)}
                empty={<EmptyState icon={FolderOpenRoundedIcon} title={pick(language, T.emptyTitle)} body={pick(language, T.emptyBody)} action={createButton} />}
              />
              {!canAdmin && <Box sx={{ px: 2, pb: 2 }}><NoAccess needs="s3:admin" /></Box>}
            </SectionCard>
          ))}
          {tab === "keys" && canAdmin && <S3Identities language={language} bucketNames={bucketNames} />}
          {tab === "connect" && <S3Connect language={language} bucketNames={bucketNames} canAdmin={canAdmin} />}

          {isAdvanced && (
            <>
              {isOwner && <LinkedFoldersCard />}
              <SectionCard advanced collapsible defaultCollapsed title={pick(language, T.domainTitle)}>
                <Stack component="ol" spacing={1} sx={{ m: 0, paddingInlineStart: 2.5 }}>
                  {T.domainSteps[language].map((step) => <Typography component="li" variant="body2" key={step} sx={{ lineHeight: 1.9 }}>{step}</Typography>)}
                </Stack>
                {canAdmin && <Button sx={{ mt: 1.5, minHeight: 44 }} onClick={() => setAddressOpen(true)}>{pick(language, T.setAddress)}</Button>}
              </SectionCard>
              <RegistrySettings groups={["files.space"]} permissions={permissions} title={pick(language, T.settingsTitle)} />
            </>
          )}
        </>
      )}

      {creating && (
        <CreateBucketWizard
          isOwner={isOwner}
          existing={bucketNames}
          onClose={() => setCreating(false)}
          onDone={({ name, warning: notReady, secret: key }) => {
            setCreating(false);
            notify({ message: say(language, T.bucketCreated, { name }) });
            setWarning(notReady ? pick(language, T.notSynced) : null);
            if (key) setSecret(key);
            void load(true);
          }}
        />
      )}
      {editing && (
        <EditBucketDialog
          bucket={editing}
          isOwner={isOwner}
          onClose={() => setEditing(null)}
          onDone={(message) => {
            setEditing(null);
            notify({ message });
            void load(true);
          }}
        />
      )}
      {addressOpen && (
        <PublicAddressDialog
          onClose={() => setAddressOpen(false)}
          onDone={() => {
            setAddressOpen(false);
            notify({ message: pick(language, T.addressSaved) });
            void load(true);
          }}
        />
      )}
      <ConfirmAction
        open={deleting !== null}
        title={deleting ? say(language, T.deleteTitle, { name: deleting.name }) : ""}
        body={deleting?.mode === "linked" ? pick(language, T.deleteLinkedBody) : pick(language, T.deleteBody)}
        severity="destructive"
        undoable={false}
        typed={deleting ? nameConfirmation(deleting.name, deleting.name) : undefined}
        busy={deleteBusy}
        error={deleteError}
        onConfirm={() => void removeBucket()}
        onClose={() => setDeleting(null)}
      >
        <Stack spacing={0.5}>
          {deleting && deleting.objects !== null && (
            <Typography variant="body2" color="text.secondary">
              {say(language, T.deleteSummary, { n: formatNumber(deleting.objects, language), size: formatBytes(deleting.bytes, language) })}
            </Typography>
          )}
          <FormControlLabel control={<Checkbox checked={force} onChange={(event) => setForce(event.target.checked)} />} label={pick(language, T.force)} />
        </Stack>
      </ConfirmAction>
      <KeySecretDialog secret={secret} onClose={() => setSecret(null)} />
      {snackbar}
    </Stack>
  );
}
