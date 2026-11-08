/**
 * Files › App backups (docs/33 §4.2, docs/31 §4): automatic, encrypted backups of app data and databases.
 * Simple: «پشتیبان تازه» wizard (what → where → when → keep), run now, last result.
 * Advanced: cron, keep-days, destination details (endpoint, region, prefix, path-style, proxy),
 * key export, run history ids, delete, and every `files.backups` setting (time zone …).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Avatar, Box, Button, CircularProgress, FormControlLabel, Grid, LinearProgress, MenuItem, Paper, Radio, RadioGroup,
  Stack, Switch, TextField, Tooltip, Typography
} from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import FolderRoundedIcon from "@mui/icons-material/FolderRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import MemoryRoundedIcon from "@mui/icons-material/MemoryRounded";
import DataObjectRoundedIcon from "@mui/icons-material/DataObjectRounded";
import CloudRoundedIcon from "@mui/icons-material/CloudRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import BackupRoundedIcon from "@mui/icons-material/BackupRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { Language } from "./i18n";
import { useVisibleInterval } from "./polling";
import { PROXY_TYPES, ProxyPicker, choiceFromApi, choiceToApi, useProxyList } from "./ProxyControls";
import {
  ActionWizard, Bytes, ConfirmAction, EmptyState, FriendlyError, HelpTip, Ltr, NoAccess, Notice, NumberInput, RelativeTime, ResponsiveList,
  SchedulePicker, SecretOnce, SectionCard, StatusPill, TestResult, describeSchedule, useConfirmAction, useKit, useUndoSnackbar,
  RegistrySettings, helperProblem, type TestOutcome
} from "./kit";
import { nameConfirmation, reasonFor, say, type Bi } from "./copy";

type Props = { language: Language; permissions: string[]; onUnauthorized: () => void };
type DestKind = "local" | "s3" | "mrk_s3";
type DestConfig = { path?: string; endpoint?: string; bucket?: string; region?: string; prefix?: string; path_style?: boolean; access_key_id?: string; proxy_id?: string | null };
type Destination = { id: string; name: string; kind: DestKind; config: DestConfig; secret_configured?: boolean; created_at?: number | string | null };
type SourceKind = "volume" | "postgres" | "mysql" | "mariadb" | "mongo" | "redis";
type JobSource = { kind: SourceKind; volume?: string; container?: string; database?: string };
type RunState = "running" | "succeeded" | "failed";
type Job = {
  id: string;
  name: string;
  source: JobSource;
  destination_id: string;
  schedule: string;
  retention: { keep_last: number | null; keep_days: number | null };
  enabled: boolean;
  last_run?: { state: RunState; finished_at?: number | string | null; bytes?: number | null; error_code?: string | null } | null;
  next_run_at?: number | string | null;
};
type Run = { id: string; job_id: string; state: RunState; started_at: number | string | null; finished_at: number | string | null; bytes: number | null; object_key: string | null; error_code: string | null };
type Source = JobSource & { key: string; label: string; detail?: string; protected?: boolean; size_bytes?: number | null; supported?: boolean };
type DestTest = { ok: boolean; latency_ms: number; error_code?: string | null };
type KeyExport = { passphrase: string; key_ref?: string; decrypt_command?: string };

const BASE = "/api/v1/server-backups";
const DEFAULT_SCHEDULE = "0 2 * * *";
const SOURCE_ICONS: Record<string, SvgIconComponent> = { volume: FolderRoundedIcon, postgres: StorageRoundedIcon, mysql: StorageRoundedIcon, mariadb: StorageRoundedIcon, mongo: DataObjectRoundedIcon, redis: MemoryRoundedIcon };
const DEST_ICONS: Record<DestKind, SvgIconComponent> = { local: FolderRoundedIcon, s3: CloudRoundedIcon, mrk_s3: DnsRoundedIcon };
const ENGINE_NAMES: Record<string, string> = { postgres: "PostgreSQL", mysql: "MySQL", mariadb: "MariaDB", mongo: "MongoDB", redis: "Redis" };

const T = {
  jobsTitle: { fa: "برنامه‌های پشتیبان", en: "Backup schedules" },
  jobsHint: { fa: "از اطلاعات برنامه‌ها و پایگاه‌های داده، خودکار و رمزدار پشتیبان بگیرید.", en: "Automatic, encrypted backups of your apps and databases." },
  newBackup: { fa: "پشتیبان تازه", en: "New backup" },
  unavailable: { fa: "این بخش روی نسخه فعلی سرور نیست. MRK را به‌روز کنید.", en: "This section isn't on this server version yet. Update MRK." },
  noJobsTitle: { fa: "هنوز از برنامه‌ها پشتیبان نمی‌گیرید", en: "You're not backing up any apps yet" },
  noJobsBody: { fa: "با یک پشتیبان شبانه، اگر سرور یا دیسک خراب شود اطلاعات برنامه‌ها از دست نمی‌رود.", en: "With a nightly backup, your app data survives a broken server or disk." },
  runNow: { fa: "همین حالا پشتیبان بگیر", en: "Back up now" },
  runStarted: { fa: "پشتیبان‌گیری «{name}» شروع شد.", en: "Backup “{name}” started." },
  lastResult: { fa: "آخرین پشتیبان", en: "Last backup" },
  never: { fa: "هنوز انجام نشده", en: "Not run yet" },
  nextRun: { fa: "پشتیبان بعدی", en: "Next backup" },
  keepCopies: { fa: "{n} نسخه آخر می‌ماند", en: "Keeps the last {n}" },
  keepDays: { fa: "و دست‌کم {n} روز", en: "and at least {n} days" },
  onOff: { fa: "پشتیبان‌گیری خودکار «{name}»", en: "Automatic backup for “{name}”" },
  paused: { fa: "متوقف", en: "Paused" },
  turnedOn: { fa: "پشتیبان‌گیری «{name}» روشن شد.", en: "Backups for “{name}” are on." },
  turnedOff: { fa: "پشتیبان‌گیری «{name}» متوقف شد.", en: "Backups for “{name}” are paused." },
  exportKey: { fa: "دیدن کلید رمز", en: "Show encryption key" },
  keyTitle: { fa: "کلید رمز پشتیبان «{name}»", en: "Encryption key for “{name}”" },
  keyBody: { fa: "بدون این کلید، فایل‌های پشتیبان باز نمی‌شوند. آن را جای امنی بیرون از این سرور نگه دارید.", en: "Backup files can't be opened without this key. Keep it somewhere safe, away from this server." },
  keyLabel: { fa: "کلید رمز", en: "Encryption key" },
  keyCommand: { fa: "دستور باز کردن فایل پشتیبان", en: "Command to decrypt a backup file" },
  keyConfirmTitle: { fa: "کلید رمز «{name}» نمایش داده شود؟", en: "Show the encryption key for “{name}”?" },
  keyConfirmBody: { fa: "هر کسی که این کلید را داشته باشد می‌تواند پشتیبان‌ها را باز کند. نمایش آن در تاریخچه ثبت می‌شود.", en: "Anyone with this key can open the backups. Showing it is recorded in the history." },
  keyConfirmYes: { fa: "بله، نشان بده", en: "Yes, show it" },
  deleteJobTitle: { fa: "برنامه پشتیبان «{name}» پاک شود؟", en: "Delete backup schedule “{name}”?" },
  deleteJobBody: { fa: "دیگر خودکار پشتیبان گرفته نمی‌شود. فایل‌های پشتیبان قبلی در مقصد می‌مانند.", en: "No more automatic backups. Earlier backup files stay at the destination." },
  deleteArtifacts: { fa: "فایل‌های پشتیبان قبلی و کلید رمزشان هم پاک شوند", en: "Also delete earlier backup files and their key" },
  deleteArtifactsHint: { fa: "این کار برگشت ندارد؛ آن پشتیبان‌ها دیگر قابل بازگردانی نیستند.", en: "This can't be undone; those backups can no longer be restored." },
  deleted: { fa: "«{name}» پاک شد.", en: "“{name}” was deleted." },
  saved: { fa: "«{name}» ذخیره شد.", en: "“{name}” was saved." },

  runsTitle: { fa: "پشتیبان‌های گرفته‌شده", en: "Backups taken" },
  runsHint: { fa: "هر بار که پشتیبان گرفته شد این‌جا می‌آید. فایل‌ها رمزدارند.", en: "Every backup shows up here. The files are encrypted." },
  noRunsTitle: { fa: "هنوز پشتیبانی گرفته نشده", en: "No backups taken yet" },
  noRunsBody: { fa: "اولین پشتیبان سر وقتش گرفته می‌شود؛ یا همین حالا شروعش کنید.", en: "The first backup runs on schedule, or start one now." },
  allJobs: { fa: "همه برنامه‌ها", en: "All schedules" },
  colJob: { fa: "برنامه", en: "Schedule" },
  colWhen: { fa: "زمان", en: "When" },
  colState: { fa: "نتیجه", en: "Result" },
  colSize: { fa: "حجم", en: "Size" },
  colDuration: { fa: "مدت", en: "Duration" },
  colId: { fa: "شناسه", en: "ID" },
  colFile: { fa: "فایل", en: "File" },
  seconds: { fa: "{n} ثانیه", en: "{n} s" },
  download: { fa: "دانلود فایل رمزدار", en: "Download encrypted file" },

  destTitle: { fa: "جای نگه‌داری پشتیبان‌ها", en: "Where backups are kept" },
  destHint: { fa: "پشتیبان‌ها کجا ذخیره شوند. بهتر است دست‌کم یک جای بیرون از این سرور داشته باشید.", en: "Where backups are stored. Keep at least one place outside this server." },
  addDest: { fa: "افزودن جای نگه‌داری", en: "Add a place" },
  noDestTitle: { fa: "هنوز جایی برای پشتیبان‌ها ندارید", en: "No place for backups yet" },
  noDestBody: { fa: "اول مشخص کنید پشتیبان‌ها کجا بروند؛ مثلاً فضای فایل همین سرور یا یک فضای S3 بیرونی.", en: "First choose where backups go, e.g. this server's file space or an external S3 storage." },
  k_local: { fa: "پوشه‌ای روی همین سرور", en: "A folder on this server" },
  k_s3: { fa: "فضای S3 بیرونی", en: "External S3 storage" },
  k_mrk_s3: { fa: "فضای فایل همین سرور", en: "This server's file space" },
  kh_local: { fa: "ساده‌ترین راه؛ فایل‌ها روی دیسک همین سرور می‌مانند.", en: "Simplest; files stay on this server's disk." },
  kh_s3: { fa: "امن‌ترین راه؛ هر سرویس سازگار با S3 مثل آروان، Liara یا MinIO.", en: "Safest; any S3-compatible service such as Arvan, Liara or MinIO." },
  kh_mrk_s3: { fa: "فضای فایل داخلی MRK؛ بدون مصرف اینترنت.", en: "MRK's built-in file space; no internet traffic." },
  sameDisk: { fa: "این جا روی دیسک همین سرور است. اگر سرور از دست برود، پشتیبان‌ها هم از دست می‌روند. یک جای بیرونی هم اضافه کنید.", en: "This is on this server's disk. If the server is lost, so are the backups. Add an outside place too." },
  sameDiskShort: { fa: "روی همین سرور؛ اگر سرور از دست برود، این هم می‌رود", en: "On this server; lost if the server is lost" },
  deleteDestTitle: { fa: "جای نگه‌داری «{name}» پاک شود؟", en: "Remove the place “{name}”?" },
  deleteDestBody: { fa: "فقط تنظیماتش پاک می‌شود؛ فایل‌هایی که آن‌جا هستند می‌مانند.", en: "Only its settings are removed; files already there stay." },
  testResult: { fa: "نتیجه امتحان", en: "Test result" },

  wizardTitle: { fa: "پشتیبان تازه", en: "New backup" },
  wizardEditTitle: { fa: "ویرایش «{name}»", en: "Edit “{name}”" },
  stepWhat: { fa: "از چه چیزی؟", en: "What?" },
  stepWhatHint: { fa: "برنامه یا پایگاه داده‌ای را که می‌خواهید از آن پشتیبان بگیرید انتخاب کنید.", en: "Pick the app data or database to back up." },
  stepWhere: { fa: "کجا؟", en: "Where?" },
  stepWhereHint: { fa: "پشتیبان‌ها کجا نگه داشته شوند؟", en: "Where should the backups be kept?" },
  stepWhen: { fa: "کی؟", en: "When?" },
  stepWhenHint: { fa: "چه وقت خودکار پشتیبان گرفته شود؟ شب‌ها که سرور خلوت است بهتر است.", en: "When should it run automatically? Night time, when the server is quiet, is best." },
  stepKeep: { fa: "چند نسخه بماند؟", en: "How many to keep?" },
  stepKeepHint: { fa: "نسخه‌های قدیمی‌تر خودکار پاک می‌شوند تا فضا پر نشود.", en: "Older copies are removed automatically so space doesn't run out." },
  pickSource: { fa: "یک مورد را انتخاب کنید.", en: "Pick one item." },
  pickDest: { fa: "یک جای نگه‌داری انتخاب کنید.", en: "Pick a place to keep backups." },
  scheduleInvalid: { fa: "زمان‌بندی باید ۵ بخش داشته باشد: دقیقه ساعت روز ماه روز-هفته.", en: "The schedule needs 5 parts: minute hour day month weekday." },
  keepInvalid: { fa: "تعداد نسخه‌ها باید عددی بین ۱ تا ۱۰۰۰ باشد.", en: "Copies must be a number from 1 to 1000." },
  keepDaysInvalid: { fa: "روزها باید عددی بین ۱ تا ۳۶۵۰ باشد.", en: "Days must be a number from 1 to 3650." },
  sourcesLoading: { fa: "در حال پیدا کردن برنامه‌ها و پایگاه‌های داده…", en: "Finding apps and databases…" },
  noSourcesTitle: { fa: "چیزی برای پشتیبان‌گیری پیدا نشد", en: "Nothing to back up was found" },
  noSourcesBody: { fa: "برای دیدن برنامه‌ها، دستیار سرور باید وصل باشد.", en: "The server helper must be connected to see your apps." },
  connectAgent: { fa: "وصل کردن دستیار سرور", en: "Connect the server helper" },
  appData: { fa: "اطلاعات برنامه", en: "App data" },
  protectedSource: { fa: "این مورد مال Dokploy است؛ بهتر است از پشتیبان‌گیری خود Dokploy استفاده کنید.", en: "This belongs to Dokploy; Dokploy's own backups are a better fit." },
  database: { fa: "نام پایگاه داده (خالی یعنی همه)", en: "Database name (empty = all)" },
  copies: { fa: "تعداد نسخه‌ها", en: "Copies to keep" },
  copiesUnit: { fa: "نسخه", en: "copies" },
  minDays: { fa: "دست‌کم این چند روز بماند (اختیاری)", en: "Keep at least this many days (optional)" },
  daysUnit: { fa: "روز", en: "days" },
  name: { fa: "نام این پشتیبان", en: "Name for this backup" },
  encrypted: { fa: "همه پشتیبان‌ها رمزدار ذخیره می‌شوند و کلیدش روی همین سرور امن نگه‌داری می‌شود.", en: "Every backup is stored encrypted; its key is kept safely on this server." },
  create: { fa: "ساخت پشتیبان", en: "Create backup" },
  save: { fa: "ذخیره", en: "Save" },
  doneTitle: { fa: "پشتیبان «{name}» ساخته شد.", en: "Backup “{name}” was created." },
  doneBody: { fa: "از این به بعد {schedule} خودکار پشتیبان گرفته می‌شود.", en: "From now on it runs {schedule}, automatically." },
  addDestInline: { fa: "جای تازه", en: "New place" },

  destWizardTitle: { fa: "جای نگه‌داری تازه", en: "New place for backups" },
  destWizardEdit: { fa: "ویرایش «{name}»", en: "Edit “{name}”" },
  stepKind: { fa: "چه نوعی؟", en: "Which kind?" },
  stepDetails: { fa: "مشخصات", en: "Details" },
  destName: { fa: "یک نام کوتاه", en: "A short name" },
  path: { fa: "مسیر پوشه روی سرور", en: "Folder path on the server" },
  pathRule: { fa: "مسیر باید با / شروع شود؛ مثل /data/backups", en: "The path must start with /, e.g. /data/backups" },
  endpoint: { fa: "آدرس سرویس S3", en: "S3 service address" },
  endpointRule: { fa: "آدرس باید با https:// یا http:// شروع شود.", en: "The address must start with https:// or http://." },
  bucket: { fa: "پوشه اصلی (باکت)", en: "Bucket" },
  region: { fa: "منطقه", en: "Region" },
  prefix: { fa: "زیرپوشه داخل پوشه اصلی", en: "Sub-folder inside the bucket" },
  pathStyle: { fa: "آدرس‌دهی مسیری (برای MinIO و بیشتر سرویس‌های ایرانی روشن بماند)", en: "Path-style addressing (keep on for MinIO and most non-AWS services)" },
  accessKey: { fa: "کلید دسترسی (Access Key)", en: "Access key" },
  secretKey: { fa: "رمز کلید", en: "Secret key" },
  secretKeep: { fa: "قبلاً تنظیم شده؛ برای نگه‌داشتن، خالی بگذارید.", en: "Already set; leave empty to keep it." },
  mrkKey: { fa: "کلید دسترسی فضای فایل", en: "File space access key" },
  mrkKeyHint: { fa: "در «فضای فایل» یک کلید با سطح «برای پشتیبان‌گیری» بسازید.", en: "Create a key with the “for backups” level under File space." },
  required: { fa: "این را پر کنید.", en: "Fill this in." },
  saveAndTest: { fa: "ذخیره و امتحان", en: "Save and test" },
  destSaved: { fa: "«{name}» ذخیره شد. حالا اتصال امتحان می‌شود:", en: "“{name}” was saved. Testing the connection now:" },

  advTitle: { fa: "تنظیمات پیشرفته پشتیبان برنامه‌ها", en: "Advanced app-backup settings" }
} satisfies Record<string, Bi>;

type Key = keyof typeof T;

/** Five-field cron check (minute hour day month weekday). */
export function cronValid(expression: string) {
  const field = /^(\*|\d+(-\d+)?(,\d+(-\d+)?)*)(\/\d+)?$/;
  const parts = expression.trim().split(/\s+/);
  return parts.length === 5 && parts.every((part) => field.test(part));
}

function sourceKey(source: JobSource) {
  return `${source.kind}:${source.volume ?? source.container ?? ""}:${source.database ?? ""}`;
}

/** Accept either `{items:[…]}` or `{volumes:[…], databases:[…]}` from GET /sources. */
function normalizeSources(payload: unknown): Source[] {
  const result: Source[] = [];
  const record = (payload ?? {}) as Record<string, unknown>;
  const text = (value: unknown) => (typeof value === "string" ? value : undefined);
  const push = (source: Omit<Source, "key">) => result.push({ ...source, key: sourceKey(source) });
  for (const raw of Array.isArray(record.items) ? record.items : []) {
    const item = raw as Record<string, unknown>;
    const kind = (text(item.kind) ?? text(item.engine) ?? "volume") as SourceKind;
    const volume = kind === "volume" ? text(item.volume) ?? text(item.name) : undefined;
    const container = kind !== "volume" ? text(item.container) ?? text(item.container_id) ?? text(item.name) : undefined;
    push({ kind, volume, container, database: text(item.database), label: text(item.label) ?? text(item.name) ?? volume ?? container ?? "?", detail: text(item.image) ?? text(item.detail), protected: Boolean(item.protected), size_bytes: typeof item.size_bytes === "number" ? item.size_bytes : null });
  }
  for (const raw of Array.isArray(record.volumes) ? record.volumes : []) {
    const item = (typeof raw === "string" ? { name: raw } : raw) as Record<string, unknown>;
    const name = text(item.name) ?? text(item.volume) ?? "?";
    const usedBy = Array.isArray(item.used_by) ? (item.used_by as unknown[]).map(String).join(", ") : undefined;
    push({ kind: "volume", volume: name, label: name, detail: usedBy ?? text(item.compose_project), protected: Boolean(item.protected), size_bytes: typeof item.size_bytes === "number" ? item.size_bytes : null, supported: item.supported !== false });
  }
  for (const raw of Array.isArray(record.databases) ? record.databases : []) {
    const item = raw as Record<string, unknown>;
    const kind = (text(item.engine) ?? text(item.kind) ?? "postgres") as SourceKind;
    const container = text(item.name) || text(item.container) || text(item.container_id) || "?";
    push({ kind, container, database: text(item.database), label: container, detail: text(item.image), protected: Boolean(item.protected), supported: true });
  }
  return result;
}

function isUnauthorized(error: unknown) {
  return error instanceof ApiError && error.status === 401;
}

function isMissingModule(error: unknown) {
  return helperProblem(error) === "module_missing";
}

function kindWord(language: Language, kind: SourceKind) {
  return kind === "volume" ? T.appData[language] : ENGINE_NAMES[kind] ?? kind;
}

// ─────────────────────────── destination wizard ───────────────────────────

type DestForm = { name: string; kind: DestKind; path: string; endpoint: string; bucket: string; region: string; prefix: string; pathStyle: boolean; accessKey: string; secret: string; proxy: string };

function destForm(dest: Destination | null): DestForm {
  const config = dest?.config ?? {};
  return {
    name: dest?.name ?? "",
    kind: dest?.kind ?? "mrk_s3",
    path: config.path ?? "/data/backups",
    endpoint: config.endpoint ?? "",
    bucket: config.bucket ?? "",
    region: config.region ?? "us-east-1",
    prefix: config.prefix ?? "mrk-backups/",
    pathStyle: config.path_style ?? true,
    accessKey: config.access_key_id ?? "",
    secret: "",
    proxy: choiceFromApi(config.proxy_id)
  };
}

function DestinationWizard({ editing, onClose, onSaved }: { editing: Destination | null; onClose: () => void; onSaved: (dest: Destination) => void }) {
  const { language, isAdvanced } = useKit();
  const t = (key: Key) => T[key][language];
  const { list: proxyList, failed: proxyFailed } = useProxyList();
  const [form, setForm] = useState<DestForm>(() => destForm(editing));
  const [buckets, setBuckets] = useState<string[]>([]);
  const [keys, setKeys] = useState<string[]>([]);
  const [saved, setSaved] = useState<Destination | null>(null);
  const [test, setTest] = useState<TestOutcome>({ state: "idle" });
  const patch = (value: Partial<DestForm>) => setForm((current) => ({ ...current, ...value }));

  useEffect(() => {
    if (form.kind !== "mrk_s3") return;
    const controller = new AbortController();
    void getJson<{ items: { name: string }[] }>("/api/v1/s3/buckets", controller.signal).then((payload) => setBuckets((payload.items ?? []).map((item) => item.name)), () => setBuckets([]));
    void getJson<{ items: { keys: { access_key_id: string; enabled: boolean }[] }[] }>("/api/v1/s3/identities", controller.signal).then(
      (payload) => setKeys((payload.items ?? []).flatMap((identity) => identity.keys.filter((key) => key.enabled).map((key) => key.access_key_id))),
      () => setKeys([])
    );
    return () => controller.abort();
  }, [form.kind]);

  const problems = (): string | null => {
    if (!form.name.trim()) return t("required");
    if (form.kind === "local" && !form.path.trim().startsWith("/")) return t("pathRule");
    if (form.kind === "s3" && !/^https?:\/\/\S+$/i.test(form.endpoint.trim())) return t("endpointRule");
    if (form.kind !== "local" && (!form.bucket.trim() || !form.accessKey.trim())) return t("required");
    if (form.kind === "s3" && !form.secret && !editing?.secret_configured) return t("required");
    return null;
  };

  const finish = async () => {
    const config: DestConfig = form.kind === "local"
      ? { path: form.path.trim() }
      : form.kind === "mrk_s3"
        ? { bucket: form.bucket.trim(), prefix: form.prefix.trim(), access_key_id: form.accessKey.trim() }
        : { endpoint: form.endpoint.trim(), bucket: form.bucket.trim(), region: form.region.trim() || "us-east-1", prefix: form.prefix.trim(), path_style: form.pathStyle, access_key_id: form.accessKey.trim(), proxy_id: choiceToApi(form.proxy) };
    const body: Record<string, unknown> = { name: form.name.trim(), kind: form.kind, config };
    if (form.kind === "s3" && form.secret) body.secret = { secret_access_key: form.secret };
    const result = editing
      ? await mutateJson<Destination>(`${BASE}/destinations/${encodeURIComponent(editing.id)}`, { method: "PATCH", body })
      : await mutateJson<Destination>(`${BASE}/destinations`, { method: "POST", body });
    const dest = result ?? ({ ...(editing ?? { id: "" }), name: form.name.trim(), kind: form.kind, config } as Destination);
    setSaved(dest);
    onSaved(dest);
    if (dest.id) {
      setTest({ state: "running" });
      try {
        const outcome = await mutateJson<DestTest>(`${BASE}/destinations/${encodeURIComponent(dest.id)}/test`, { method: "POST" });
        setTest(outcome.ok ? { state: "ok", latencyMs: outcome.latency_ms } : { state: "fail", code: outcome.error_code, message: reasonFor(language, outcome.error_code) });
      } catch (caught) {
        setTest({ state: "fail", error: caught });
      }
    }
  };

  const text = (key: keyof DestForm, label: string, extra: { ltr?: boolean; type?: string; helper?: string; placeholder?: string } = {}) => (
    <TextField
      fullWidth
      size="small"
      label={label}
      type={extra.type}
      value={form[key] as string}
      helperText={extra.helper ?? " "}
      placeholder={extra.placeholder}
      onChange={(event) => patch({ [key]: event.target.value } as Partial<DestForm>)}
      slotProps={{ htmlInput: { dir: extra.ltr ? "ltr" : "auto", autoComplete: extra.type === "password" ? "new-password" : "off" }, inputLabel: extra.placeholder ? { shrink: true } : undefined }}
    />
  );

  return (
    <ActionWizard
      open
      title={editing ? say(language, T.destWizardEdit, { name: editing.name }) : t("destWizardTitle")}
      onClose={onClose}
      onFinish={finish}
      finishLabel={t("saveAndTest")}
      done={saved ? (
        <Stack spacing={1.5}>
          <Typography>{say(language, T.destSaved, { name: saved.name })}</Typography>
          <TestResult outcome={test} />
        </Stack>
      ) : undefined}
      steps={[
        {
          key: "kind",
          title: t("stepKind"),
          render: () => (
            <RadioGroup value={form.kind} onChange={(event) => patch({ kind: event.target.value as DestKind })} aria-label={t("stepKind")}>
              <Stack spacing={1}>
                {(["mrk_s3", "s3", "local"] as const).map((kind) => {
                  const Icon = DEST_ICONS[kind];
                  return (
                    <Paper key={kind} variant="outlined" sx={{ px: 1.5, py: 0.75, borderColor: form.kind === kind ? "primary.main" : "divider" }}>
                      <FormControlLabel
                        value={kind}
                        disabled={Boolean(editing)}
                        control={<Radio />}
                        sx={{ m: 0, width: "100%" }}
                        label={
                          <Stack direction="row" spacing={1.25} alignItems="center">
                            <Icon color="primary" aria-hidden />
                            <Box>
                              <Typography fontWeight={700}>{t(`k_${kind}`)}</Typography>
                              <Typography variant="body2" color="text.secondary">{t(`kh_${kind}`)}</Typography>
                            </Box>
                          </Stack>
                        }
                      />
                    </Paper>
                  );
                })}
              </Stack>
            </RadioGroup>
          )
        },
        {
          key: "details",
          title: t("stepDetails"),
          validate: problems,
          render: () => (
            <Stack spacing={1}>
              {text("name", t("destName"), { placeholder: t(`k_${form.kind}`) })}
              {(form.kind === "local" || form.kind === "mrk_s3") && <Notice tone="warning">{t("sameDisk")}</Notice>}
              {form.kind === "local" && text("path", t("path"), { ltr: true, helper: t("pathRule") })}
              {form.kind === "mrk_s3" && (
                <>
                  <TextField select={buckets.length > 0} fullWidth size="small" label={t("bucket")} value={form.bucket} helperText=" " onChange={(event) => patch({ bucket: event.target.value })} slotProps={{ htmlInput: { dir: "ltr" } }}>
                    {buckets.map((name) => <MenuItem key={name} value={name}><Ltr>{name}</Ltr></MenuItem>)}
                  </TextField>
                  <TextField select={keys.length > 0} fullWidth size="small" label={t("mrkKey")} value={form.accessKey} helperText={t("mrkKeyHint")} onChange={(event) => patch({ accessKey: event.target.value })} slotProps={{ htmlInput: { dir: "ltr" } }}>
                    {keys.map((akid) => <MenuItem key={akid} value={akid}><Ltr mono>{akid}</Ltr></MenuItem>)}
                  </TextField>
                  {isAdvanced && text("prefix", t("prefix"), { ltr: true })}
                </>
              )}
              {form.kind === "s3" && (
                <>
                  {text("endpoint", t("endpoint"), { ltr: true, placeholder: "https://s3.ir-thr-at1.arvanstorage.ir" })}
                  {text("bucket", t("bucket"), { ltr: true })}
                  {text("accessKey", t("accessKey"), { ltr: true })}
                  {text("secret", t("secretKey"), { ltr: true, type: "password", helper: editing?.secret_configured ? t("secretKeep") : undefined })}
                  {isAdvanced && (
                    <>
                      {text("region", t("region"), { ltr: true })}
                      {text("prefix", t("prefix"), { ltr: true })}
                      <FormControlLabel control={<Switch checked={form.pathStyle} onChange={(event) => patch({ pathStyle: event.target.checked })} />} label={t("pathStyle")} />
                    </>
                  )}
                  {!proxyFailed && proxyList && (isAdvanced || proxyList.default_proxy_id || form.proxy) && (
                    <ProxyPicker language={language} list={proxyList} value={form.proxy} onChange={(value) => patch({ proxy: value })} supported={PROXY_TYPES} advanced={isAdvanced} label={form.name} />
                  )}
                </>
              )}
            </Stack>
          )
        }
      ]}
    />
  );
}

// ─────────────────────────── job wizard ───────────────────────────

function JobWizard({ editing, destinations, canWrite, onClose, onSaved, onDestinationAdded, onRunNow }: {
  editing: Job | null;
  destinations: Destination[];
  canWrite: boolean;
  onClose: () => void;
  onSaved: (job: Job | null, name: string) => void;
  onDestinationAdded: () => void;
  onRunNow: (job: Job) => void;
}) {
  const { language, isAdvanced } = useKit();
  const t = (key: Key) => T[key][language];
  const [sources, setSources] = useState<Source[] | null>(null);
  const [sourcesError, setSourcesError] = useState<unknown>(null);
  const [selected, setSelected] = useState(editing ? sourceKey(editing.source) : "");
  const [database, setDatabase] = useState(editing?.source.database ?? "");
  const [destinationId, setDestinationId] = useState(editing?.destination_id ?? destinations[0]?.id ?? "");
  const [schedule, setSchedule] = useState(editing?.schedule ?? DEFAULT_SCHEDULE);
  const [keepLast, setKeepLast] = useState<number | null>(editing?.retention.keep_last ?? 7);
  const [keepDays, setKeepDays] = useState<number | null>(editing?.retention.keep_days ?? null);
  const [name, setName] = useState(editing?.name ?? "");
  const [addingDest, setAddingDest] = useState(false);
  const [created, setCreated] = useState<Job | null>(null);
  const [doneName, setDoneName] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    void getJson<unknown>(`${BASE}/sources`, controller.signal).then(
      (payload) => setSources(normalizeSources(payload)),
      (caught) => {
        if (!isAbortError(caught)) setSourcesError(caught);
      }
    );
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!destinationId && destinations[0]) setDestinationId(destinations[0].id);
  }, [destinationId, destinations]);

  const source = useMemo(() => {
    const found = sources?.find((item) => item.key === selected);
    if (found) return found;
    if (editing && selected === sourceKey(editing.source)) return { ...editing.source, key: selected, label: editing.source.volume ?? editing.source.container ?? "?" } as Source;
    return null;
  }, [editing, selected, sources]);
  const destination = destinations.find((item) => item.id === destinationId);
  const autoName = source ? `${source.label}${source.kind !== "volume" ? ` (${ENGINE_NAMES[source.kind] ?? source.kind})` : ""}` : "";

  const finish = async () => {
    if (!source) return;
    const jobSource: JobSource = source.kind === "volume"
      ? { kind: "volume", volume: source.volume }
      : { kind: source.kind, container: source.container, ...(database.trim() || source.database ? { database: database.trim() || source.database } : {}) };
    const finalName = name.trim() || autoName;
    const body = { name: finalName, source: jobSource, destination_id: destinationId, schedule: schedule.trim(), retention: { keep_last: keepLast, keep_days: keepDays }, enabled: editing?.enabled ?? true };
    const result = editing
      ? await mutateJson<Job>(`${BASE}/jobs/${encodeURIComponent(editing.id)}`, { method: "PATCH", body })
      : await mutateJson<Job>(`${BASE}/jobs`, { method: "POST", body });
    setCreated(result ?? null);
    setDoneName(finalName);
    onSaved(result ?? null, finalName);
  };

  return (
    <>
      <ActionWizard
        open
        title={editing ? say(language, T.wizardEditTitle, { name: editing.name }) : t("wizardTitle")}
        onClose={onClose}
        onFinish={finish}
        finishLabel={editing ? t("save") : t("create")}
        done={doneName ? (
          <Stack spacing={1.5} alignItems="flex-start">
            <Typography fontWeight={700}>{say(language, editing ? T.saved : T.doneTitle, { name: doneName })}</Typography>
            <Typography color="text.secondary">{say(language, T.doneBody, { schedule: describeSchedule(schedule, language) })}</Typography>
            {created && canWrite && <Button variant="outlined" startIcon={<PlayArrowRoundedIcon />} onClick={() => onRunNow(created)}>{t("runNow")}</Button>}
          </Stack>
        ) : undefined}
        steps={[
          {
            key: "what",
            title: t("stepWhat"),
            hint: t("stepWhatHint"),
            validate: () => (source ? null : t("pickSource")),
            render: () => (
              <Box>
                {sourcesError !== null && <FriendlyError error={sourcesError} severity="warning" noAction />}
                {sources === null && sourcesError === null && (
                  <Stack direction="row" spacing={1} alignItems="center"><CircularProgress size={16} /><Typography color="text.secondary">{t("sourcesLoading")}</Typography></Stack>
                )}
                {sources !== null && sources.length === 0 && (
                  <EmptyState compact title={t("noSourcesTitle")} body={t("noSourcesBody")} action={<Button href="#/server/overview" variant="outlined">{t("connectAgent")}</Button>} />
                )}
                {sources !== null && sources.length > 0 && (
                  <RadioGroup value={selected} onChange={(event) => setSelected(event.target.value)} aria-label={t("stepWhat")}>
                    <Grid container spacing={1}>
                      {sources.map((item) => {
                        const Icon = SOURCE_ICONS[item.kind] ?? StorageRoundedIcon;
                        return (
                          <Grid key={item.key} size={{ xs: 12, sm: 6 }}>
                            <Paper variant="outlined" sx={{ px: 1, py: 0.5, borderColor: selected === item.key ? "primary.main" : "divider" }}>
                              <FormControlLabel
                                value={item.key}
                                disabled={item.supported === false}
                                control={<Radio />}
                                sx={{ m: 0, width: "100%", "& .MuiFormControlLabel-label": { minWidth: 0, flex: 1 } }}
                                label={
                                  <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                                    <Icon fontSize="small" color="action" aria-hidden />
                                    <Box sx={{ minWidth: 0, flex: 1 }}>
                                      <Typography variant="body2" fontWeight={700} noWrap><Ltr>{item.label}</Ltr></Typography>
                                      <Typography variant="caption" color="text.secondary" noWrap display="block">
                                        {kindWord(language, item.kind)}
                                        {item.size_bytes ? <> · <Bytes value={item.size_bytes} /></> : null}
                                        {isAdvanced && item.detail ? <> · <Ltr>{item.detail}</Ltr></> : null}
                                      </Typography>
                                    </Box>
                                    {item.protected && <Tooltip title={t("protectedSource")}><LockRoundedIcon fontSize="small" color="secondary" aria-label={t("protectedSource")} /></Tooltip>}
                                  </Stack>
                                }
                              />
                            </Paper>
                          </Grid>
                        );
                      })}
                    </Grid>
                  </RadioGroup>
                )}
                {source?.protected && <Box sx={{ mt: 1 }}><Notice>{t("protectedSource")}</Notice></Box>}
                {isAdvanced && source && source.kind !== "volume" && source.kind !== "redis" && (
                  <TextField size="small" label={t("database")} value={database} onChange={(event) => setDatabase(event.target.value)} sx={{ mt: 1.5, minWidth: 260 }} slotProps={{ htmlInput: { dir: "ltr" } }} />
                )}
              </Box>
            )
          },
          {
            key: "where",
            title: t("stepWhere"),
            hint: t("stepWhereHint"),
            validate: () => (destination ? null : t("pickDest")),
            render: () => (
              <Stack spacing={1.5}>
                {destinations.length === 0 ? (
                  <EmptyState compact title={t("noDestTitle")} body={t("noDestBody")} action={<Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setAddingDest(true)}>{t("addDest")}</Button>} />
                ) : (
                  <>
                    <RadioGroup value={destinationId} onChange={(event) => setDestinationId(event.target.value)} aria-label={t("stepWhere")}>
                      <Stack spacing={1}>
                        {destinations.map((item) => {
                          const Icon = DEST_ICONS[item.kind] ?? CloudRoundedIcon;
                          return (
                            <Paper key={item.id} variant="outlined" sx={{ px: 1.5, py: 0.5, borderColor: destinationId === item.id ? "primary.main" : "divider" }}>
                              <FormControlLabel
                                value={item.id}
                                control={<Radio />}
                                sx={{ m: 0, width: "100%" }}
                                label={
                                  <Stack direction="row" spacing={1.25} alignItems="center">
                                    <Icon color="primary" fontSize="small" aria-hidden />
                                    <Box>
                                      <Typography fontWeight={700} dir="auto">{item.name}</Typography>
                                      <Typography variant="caption" color="text.secondary">{t(`k_${item.kind}`)}</Typography>
                                    </Box>
                                  </Stack>
                                }
                              />
                            </Paper>
                          );
                        })}
                      </Stack>
                    </RadioGroup>
                    {canWrite && <Box><Button size="small" startIcon={<AddRoundedIcon />} onClick={() => setAddingDest(true)}>{t("addDestInline")}</Button></Box>}
                  </>
                )}
                {destination && (destination.kind === "local" || destination.kind === "mrk_s3") && <Notice tone="warning">{t("sameDisk")}</Notice>}
              </Stack>
            )
          },
          {
            key: "when",
            title: t("stepWhen"),
            hint: t("stepWhenHint"),
            validate: () => (cronValid(schedule) ? null : t("scheduleInvalid")),
            render: () => <SchedulePicker value={schedule} onChange={setSchedule} validateCron={cronValid} label={t("stepWhen")} />
          },
          {
            key: "keep",
            title: t("stepKeep"),
            hint: t("stepKeepHint"),
            validate: () => {
              if (keepLast === null || !Number.isInteger(keepLast) || keepLast < 1 || keepLast > 1000) return t("keepInvalid");
              if (keepDays !== null && (!Number.isInteger(keepDays) || keepDays < 1 || keepDays > 3650)) return t("keepDaysInvalid");
              return null;
            },
            render: () => (
              <Stack spacing={1.5}>
                <NumberInput label={t("copies")} value={keepLast} onChange={setKeepLast} min={1} max={1000} integer unit={t("copiesUnit")} />
                {isAdvanced && <NumberInput label={t("minDays")} value={keepDays} onChange={setKeepDays} min={1} max={3650} integer unit={t("daysUnit")} />}
                <TextField size="small" label={t("name")} value={name} placeholder={autoName} onChange={(event) => setName(event.target.value)} slotProps={{ inputLabel: autoName ? { shrink: true } : undefined, htmlInput: { dir: "auto" } }} />
                <Notice>{t("encrypted")}</Notice>
              </Stack>
            )
          }
        ]}
      />
      {addingDest && (
        <DestinationWizard
          editing={null}
          onClose={() => setAddingDest(false)}
          onSaved={(dest) => {
            if (dest.id) setDestinationId(dest.id);
            onDestinationAdded();
          }}
        />
      )}
    </>
  );
}

// ─────────────────────────── destination card ───────────────────────────

function DestinationCard({ dest, canWrite, onEdit, onDelete }: { dest: Destination; canWrite: boolean; onEdit: () => void; onDelete: () => void }) {
  const { language, isAdvanced, c } = useKit();
  const t = (key: Key) => T[key][language];
  const [test, setTest] = useState<TestOutcome>({ state: "idle" });
  const Icon = DEST_ICONS[dest.kind] ?? CloudRoundedIcon;
  const detail = dest.kind === "local" ? dest.config.path : dest.kind === "mrk_s3" ? `${dest.config.bucket ?? ""}/${dest.config.prefix ?? ""}` : `${dest.config.endpoint ?? ""} · ${dest.config.bucket ?? ""}/${dest.config.prefix ?? ""}`;

  const runTest = async () => {
    setTest({ state: "running" });
    try {
      const outcome = await mutateJson<DestTest>(`${BASE}/destinations/${encodeURIComponent(dest.id)}/test`, { method: "POST" });
      setTest(outcome.ok ? { state: "ok", latencyMs: outcome.latency_ms } : { state: "fail", code: outcome.error_code, message: reasonFor(language, outcome.error_code) });
    } catch (caught) {
      if (isUnauthorized(caught)) return setTest({ state: "idle" });
      setTest({ state: "fail", error: caught });
    }
  };

  return (
    <Paper variant="outlined" sx={{ p: 1.75, height: "100%" }}>
      <Stack direction="row" spacing={1.25} alignItems="center" sx={{ minWidth: 0 }}>
        <Avatar aria-hidden sx={{ width: 36, height: 36, bgcolor: "action.hover", color: "primary.main" }}><Icon fontSize="small" /></Avatar>
        <Box sx={{ minWidth: 0 }}>
          <Typography fontWeight={740} dir="auto" noWrap>{dest.name}</Typography>
          <Typography variant="caption" color="text.secondary">{t(`k_${dest.kind}`)}</Typography>
        </Box>
      </Stack>
      {isAdvanced && detail && <Typography variant="caption" color="text.secondary" display="block" noWrap sx={{ mt: 0.75 }} title={detail}><Ltr mono>{detail}</Ltr></Typography>}
      {(dest.kind === "local" || dest.kind === "mrk_s3") && <Typography variant="caption" color="warning.main" display="block" sx={{ mt: 0.5 }}>{t("sameDiskShort")}</Typography>}
      <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
        {canWrite && <Button size="small" variant="outlined" disabled={test.state === "running"} onClick={() => void runTest()}>{test.state === "running" ? c.testing : c.test}</Button>}
        {canWrite && isAdvanced && (
          <>
            <Button size="small" startIcon={<EditRoundedIcon />} onClick={onEdit}>{c.edit}</Button>
            <Button size="small" color="error" startIcon={<DeleteOutlineRoundedIcon />} onClick={onDelete}>{c.remove}</Button>
          </>
        )}
      </Stack>
      {test.state !== "idle" && <Box sx={{ mt: 1 }} aria-label={t("testResult")}><TestResult outcome={test} /></Box>}
    </Paper>
  );
}

// ─────────────────────────── panel ───────────────────────────

export function ServerBackupsPanel({ language, permissions }: Props) {
  const { isAdvanced, c } = useKit();
  const t = (key: Key) => T[key][language];
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canWrite = hasPermission(permissions, "backup:server:write");
  const [destinations, setDestinations] = useState<Destination[] | null>(null);
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [runs, setRuns] = useState<Run[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [jobWizard, setJobWizard] = useState<{ editing: Job | null } | null>(null);
  const [destWizard, setDestWizard] = useState<{ editing: Destination | null } | null>(null);
  const [runFilter, setRunFilter] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [keySecret, setKeySecret] = useState<{ name: string; key: KeyExport } | null>(null);
  const [deleting, setDeleting] = useState<{ job: Job; artifacts: boolean; busy: boolean; error: unknown } | null>(null);
  const controller = useRef<AbortController | null>(null);
  const openedFromHash = useRef(false);

  const load = useCallback(async (background = false) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    if (!background) setLoading(true);
    try {
      const [dests, jobList, runList] = await Promise.all([
        getJson<{ items: Destination[] }>(`${BASE}/destinations`, current.signal),
        getJson<{ items: Job[] }>(`${BASE}/jobs`, current.signal),
        getJson<{ items: Run[] }>(`${BASE}/runs?limit=50${runFilter ? `&job_id=${encodeURIComponent(runFilter)}` : ""}`, current.signal)
      ]);
      setDestinations(dests.items ?? []);
      setJobs(jobList.items ?? []);
      setRuns(runList.items ?? []);
      setUnavailable(false);
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || isUnauthorized(caught)) return;
      if (isMissingModule(caught)) setUnavailable(true);
      else setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, [runFilter]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const anyRunning = (runs ?? []).some((run) => run.state === "running");
  useVisibleInterval(() => void load(true), unavailable ? null : anyRunning ? 10_000 : 60_000);

  // `#/files/app-backups?new=1` (Home "create your first backup") opens the wizard once.
  useEffect(() => {
    if (openedFromHash.current || !canWrite || !destinations) return;
    if (/[?&]new=1\b/.test(window.location.hash)) {
      openedFromHash.current = true;
      setJobWizard({ editing: null });
    }
  }, [canWrite, destinations]);

  const act = async (id: string, action: () => Promise<void>) => {
    setBusy(id);
    setActionError(null);
    try {
      await action();
      await load(true);
    } catch (caught) {
      if (!isUnauthorized(caught)) setActionError(caught);
    } finally {
      setBusy(null);
    }
  };

  const runNow = (job: Job) => act(job.id, async () => {
    await mutateJson(`${BASE}/jobs/${encodeURIComponent(job.id)}/run`, { method: "POST" });
    notify({ message: say(language, T.runStarted, { name: job.name }), tone: "success" });
  });

  const toggle = (job: Job, enabled: boolean) => act(job.id, async () => {
    await mutateJson(`${BASE}/jobs/${encodeURIComponent(job.id)}`, { method: "PATCH", body: { enabled } });
    notify({
      message: say(language, enabled ? T.turnedOn : T.turnedOff, { name: job.name }),
      onUndo: () => void act(job.id, async () => { await mutateJson(`${BASE}/jobs/${encodeURIComponent(job.id)}`, { method: "PATCH", body: { enabled: !enabled } }); })
    });
  });

  const exportKey = async (job: Job) => {
    if (!(await ask({ title: say(language, T.keyConfirmTitle, { name: job.name }), body: t("keyConfirmBody"), severity: "disruptive", confirmLabel: t("keyConfirmYes") }))) return;
    await act(job.id, async () => {
      const key = await mutateJson<KeyExport>(`${BASE}/jobs/${encodeURIComponent(job.id)}/key`, { method: "POST" });
      setKeySecret({ name: job.name, key });
    });
  };

  const confirmDeleteJob = async () => {
    if (!deleting) return;
    setDeleting({ ...deleting, busy: true, error: null });
    try {
      await mutateJson(`${BASE}/jobs/${encodeURIComponent(deleting.job.id)}`, { method: "DELETE", body: { confirmation: deleting.job.name, delete_artifacts: deleting.artifacts } });
      notify({ message: say(language, T.deleted, { name: deleting.job.name }), tone: "success" });
      setDeleting(null);
      await load(true);
    } catch (caught) {
      setDeleting((current) => (current ? { ...current, busy: false, error: caught } : current));
    }
  };

  const deleteDestination = async (dest: Destination) => {
    if (!(await ask({ title: say(language, T.deleteDestTitle, { name: dest.name }), body: t("deleteDestBody"), severity: "destructive", typed: nameConfirmation(dest.name, dest.name) }))) return;
    await act(dest.id, async () => {
      await mutateJson(`${BASE}/destinations/${encodeURIComponent(dest.id)}`, { method: "DELETE", body: { confirmation: dest.name } });
      notify({ message: say(language, T.deleted, { name: dest.name }), tone: "success" });
    });
  };

  const destName = (id: string) => destinations?.find((item) => item.id === id)?.name ?? id;
  const jobName = (id: string) => jobs?.find((item) => item.id === id)?.name ?? id;
  const newButton = canWrite && !unavailable ? (
    <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setJobWizard({ editing: null })}>{t("newBackup")}</Button>
  ) : undefined;

  if (unavailable) return <Notice>{t("unavailable")}</Notice>;

  return (
    <Stack spacing={2.5}>
      {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
      {actionError !== null && <FriendlyError error={actionError} onClose={() => setActionError(null)} noAction />}
      {!canWrite && <NoAccess needs="backup:server:write" variant="card" />}
      {loading && !jobs && error === null && <LinearProgress aria-label={c.loading} />}

      {jobs && destinations && runs && (
        <>
          <SectionCard
            title={t("jobsTitle")}
            hint={t("jobsHint")}
            action={
              <Stack direction="row" spacing={1} alignItems="center">
                <Tooltip title={c.refresh}>
                  <span>
                    <Button aria-label={c.refresh} onClick={() => void load()} disabled={loading} sx={{ minWidth: 44, minHeight: 44 }}>
                      {loading ? <CircularProgress size={18} /> : <RefreshRoundedIcon />}
                    </Button>
                  </span>
                </Tooltip>
                {jobs.length > 0 && newButton}
              </Stack>
            }
          >
            {jobs.length === 0 ? (
              <EmptyState icon={BackupRoundedIcon} title={t("noJobsTitle")} body={t("noJobsBody")} action={newButton} />
            ) : (
              <Grid container spacing={1.5}>
                {jobs.map((job) => {
                  const Icon = SOURCE_ICONS[job.source.kind] ?? StorageRoundedIcon;
                  const last = job.last_run;
                  return (
                    <Grid key={job.id} size={{ xs: 12, lg: 6 }}>
                      <Paper variant="outlined" sx={{ p: 1.75, height: "100%" }}>
                        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={1}>
                          <Stack direction="row" spacing={1.25} alignItems="center" sx={{ minWidth: 0 }}>
                            <Avatar aria-hidden sx={{ width: 36, height: 36, bgcolor: "action.hover", color: "primary.main" }}><Icon fontSize="small" /></Avatar>
                            <Box sx={{ minWidth: 0 }}>
                              <Typography fontWeight={740} dir="auto" noWrap>{job.name}</Typography>
                              <Typography variant="caption" color="text.secondary" noWrap display="block">
                                {kindWord(language, job.source.kind)} {language === "fa" ? "←" : "→"} {destName(job.destination_id)}
                              </Typography>
                            </Box>
                          </Stack>
                          {canWrite ? (
                            <Switch checked={job.enabled} disabled={busy === job.id} onChange={(_event, value) => void toggle(job, value)} slotProps={{ input: { "aria-label": say(language, T.onOff, { name: job.name }) } }} />
                          ) : <StatusPill tone={job.enabled ? "ok" : "off"} label={job.enabled ? c.on : t("paused")} />}
                        </Stack>
                        <Typography variant="body2" sx={{ mt: 1 }}>
                          {describeSchedule(job.schedule, language)}
                          {" · "}
                          {say(language, T.keepCopies, { n: job.retention.keep_last ?? 0 })}
                          {job.retention.keep_days ? ` ${say(language, T.keepDays, { n: job.retention.keep_days })}` : ""}
                        </Typography>
                        {isAdvanced && <Typography variant="caption" color="text.secondary" display="block"><Ltr mono>{job.schedule}</Ltr> · <Ltr mono>{job.source.volume ?? job.source.container}{job.source.database ? `/${job.source.database}` : ""}</Ltr></Typography>}
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
                          <Typography variant="caption" color="text.secondary">{t("lastResult")}:</Typography>
                          {last ? (
                            <>
                              <StatusPill status={last.state} />
                              {last.finished_at && <Typography variant="caption" color="text.secondary"><RelativeTime value={last.finished_at} /></Typography>}
                            </>
                          ) : <Typography variant="caption" color="text.secondary">{t("never")}</Typography>}
                        </Stack>
                        {last?.state === "failed" && <Typography variant="body2" color="error.main" sx={{ mt: 0.5 }}>{reasonFor(language, last.error_code)}</Typography>}
                        {job.enabled && job.next_run_at && <Typography variant="caption" color="text.secondary" display="block">{t("nextRun")}: <RelativeTime value={job.next_run_at} /></Typography>}
                        {canWrite && (
                          <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ mt: 1.25 }}>
                            <Button size="small" variant="outlined" startIcon={busy === job.id ? <CircularProgress size={14} /> : <PlayArrowRoundedIcon />} disabled={busy === job.id || last?.state === "running"} onClick={() => void runNow(job)}>{t("runNow")}</Button>
                            {isAdvanced && (
                              <>
                                <Button size="small" startIcon={<EditRoundedIcon />} onClick={() => setJobWizard({ editing: job })}>{c.edit}</Button>
                                <Button size="small" startIcon={<KeyRoundedIcon />} onClick={() => void exportKey(job)}>{t("exportKey")}</Button>
                                <Button size="small" color="error" startIcon={<DeleteOutlineRoundedIcon />} onClick={() => setDeleting({ job, artifacts: false, busy: false, error: null })}>{c.remove}</Button>
                              </>
                            )}
                          </Stack>
                        )}
                      </Paper>
                    </Grid>
                  );
                })}
              </Grid>
            )}
          </SectionCard>

          <SectionCard
            title={t("runsTitle")}
            hint={t("runsHint")}
            flush
            action={jobs.length > 1 ? (
              <TextField select size="small" label={t("colJob")} value={runFilter} onChange={(event) => setRunFilter(event.target.value)} sx={{ minWidth: 180 }}>
                <MenuItem value="">{t("allJobs")}</MenuItem>
                {jobs.map((job) => <MenuItem key={job.id} value={job.id}>{job.name}</MenuItem>)}
              </TextField>
            ) : undefined}
          >
            <ResponsiveList
              label={t("runsTitle")}
              rows={runs}
              rowKey={(run) => run.id}
              columns={[
                { key: "job", header: t("colJob"), render: (run) => <Box component="span" dir="auto">{jobName(run.job_id)}</Box> },
                { key: "when", header: t("colWhen"), render: (run) => <RelativeTime value={run.started_at} /> },
                {
                  key: "state", header: t("colState"),
                  render: (run) => (
                    <Stack spacing={0.25}>
                      <StatusPill status={run.state} />
                      {run.state === "failed" && <Typography variant="caption" color="error.main">{reasonFor(language, run.error_code)}</Typography>}
                    </Stack>
                  )
                },
                { key: "size", header: t("colSize"), render: (run) => (run.bytes ? <Bytes value={run.bytes} /> : "—") },
                {
                  key: "duration", header: t("colDuration"), advancedOnly: true,
                  render: (run) => {
                    const started = run.started_at ? new Date(typeof run.started_at === "number" ? run.started_at * 1000 : run.started_at).getTime() : NaN;
                    const finished = run.finished_at ? new Date(typeof run.finished_at === "number" ? run.finished_at * 1000 : run.finished_at).getTime() : NaN;
                    return Number.isFinite(started) && Number.isFinite(finished) ? say(language, T.seconds, { n: Math.round((finished - started) / 1000) }) : "—";
                  }
                },
                { key: "id", header: t("colId"), advancedOnly: true, ltr: true, render: (run) => <Ltr mono>{run.id}</Ltr> },
                { key: "file", header: t("colFile"), advancedOnly: true, ltr: true, render: (run) => (run.object_key ? <Ltr mono>{run.object_key}</Ltr> : "—") },
                {
                  key: "download", header: c.download, align: "end",
                  render: (run) => run.state === "succeeded" ? (
                    <Button size="small" startIcon={<DownloadRoundedIcon />} href={`${BASE}/runs/${encodeURIComponent(run.id)}/download`}>{c.download}</Button>
                  ) : null
                }
              ]}
              card={{
                title: (run) => <Box component="span" dir="auto">{jobName(run.job_id)}</Box>,
                meta: (run) => <><RelativeTime value={run.started_at} />{run.bytes ? <> · <Bytes value={run.bytes} /></> : null}</>,
                status: (run) => <StatusPill status={run.state} />
              }}
              empty={<EmptyState compact title={t("noRunsTitle")} body={t("noRunsBody")} />}
            />
          </SectionCard>

          <SectionCard
            title={t("destTitle")}
            hint={t("destHint")}
            action={canWrite ? <Button variant="outlined" startIcon={<AddRoundedIcon />} onClick={() => setDestWizard({ editing: null })}>{t("addDest")}</Button> : undefined}
          >
            {destinations.length === 0 ? (
              <EmptyState compact title={t("noDestTitle")} body={t("noDestBody")} action={canWrite ? <Button variant="contained" onClick={() => setDestWizard({ editing: null })}>{t("addDest")}</Button> : undefined} />
            ) : (
              <Grid container spacing={1.5}>
                {destinations.map((dest) => (
                  <Grid key={dest.id} size={{ xs: 12, md: 6, xl: 4 }}>
                    <DestinationCard dest={dest} canWrite={canWrite} onEdit={() => setDestWizard({ editing: dest })} onDelete={() => void deleteDestination(dest)} />
                  </Grid>
                ))}
              </Grid>
            )}
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1.5 }}>
              {t("encrypted")} <HelpTip term="passphrase" />
            </Typography>
          </SectionCard>

          {isAdvanced && <RegistrySettings groups={["files.backups"]} permissions={permissions} title={t("advTitle")} />}
        </>
      )}

      {jobWizard && destinations && (
        <JobWizard
          editing={jobWizard.editing}
          destinations={destinations}
          canWrite={canWrite}
          onClose={() => setJobWizard(null)}
          onSaved={() => void load(true)}
          onDestinationAdded={() => void load(true)}
          onRunNow={(job) => {
            setJobWizard(null);
            void runNow(job);
          }}
        />
      )}
      {destWizard && <DestinationWizard editing={destWizard.editing} onClose={() => setDestWizard(null)} onSaved={() => void load(true)} />}
      {deleting && (
        <ConfirmAction
          open
          title={say(language, T.deleteJobTitle, { name: deleting.job.name })}
          body={t("deleteJobBody")}
          severity="destructive"
          typed={nameConfirmation(deleting.job.name, deleting.job.name)}
          busy={deleting.busy}
          error={deleting.error}
          onConfirm={() => void confirmDeleteJob()}
          onClose={() => setDeleting(null)}
        >
          <FormControlLabel
            control={<Switch checked={deleting.artifacts} onChange={(event) => setDeleting({ ...deleting, artifacts: event.target.checked })} />}
            label={<Box><Typography variant="body2">{t("deleteArtifacts")}</Typography><Typography variant="caption" color="error.main">{t("deleteArtifactsHint")}</Typography></Box>}
          />
        </ConfirmAction>
      )}
      {keySecret && (
        <SecretOnce
          open
          title={say(language, T.keyTitle, { name: keySecret.name })}
          body={t("keyBody")}
          items={[
            { label: t("keyLabel"), value: keySecret.key.passphrase, ltr: true },
            ...(keySecret.key.decrypt_command ? [{ label: t("keyCommand"), value: keySecret.key.decrypt_command, ltr: true, multiline: true }] : [])
          ]}
          onClose={() => setKeySecret(null)}
        />
      )}
      {dialog}
      {snackbar}
    </Stack>
  );
}
