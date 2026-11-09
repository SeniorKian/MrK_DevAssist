/**
 * Server › databases (Gate 19, docs/32 §5.1). Owner/admin only (`db:read`; changes need `db:write`).
 *
 * Simple: the list of connected databases, an "Add database" wizard (discover from Dokploy or the
 * server helper, credentials hints, network guide, test), and a read-only browser for tables,
 * collections and Redis keys. Advanced adds the query editor (read-only by default; write mode with a
 * typed confirmation and a dry-run preview), raw ids and every `server.databases` setting.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Box,
  Button,
  ButtonBase,
  Chip,
  FormControlLabel,
  LinearProgress,
  MenuItem,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  TextField,
  Typography
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import { apiMutate, ensureOk, getJson, mutateJson } from "./api";
import type { Language } from "./i18n";
import {
  ActionWizard, Bytes, CopyField, EmptyState, FriendlyError, KeyValueList, Ltr, NoAccess, Notice, Num, RelativeTime, ResponsiveList,
  SectionCard, StatusPill, TestResult, useCan, useConfirmAction, useKit, useUndoSnackbar, RegistrySettings, ChoiceCards, type TestOutcome,
  type WizardStep
} from "./kit";
import { errorSentence, nameConfirmation, pick, say, type Bi, type ConfirmWord } from "./copy";

// ── API shapes ──────────────────────────────────────────────────────────────────────────

type Engine = "postgres" | "mysql" | "mariadb" | "mongo" | "redis";
const ENGINES: Engine[] = ["postgres", "mysql", "mariadb", "mongo", "redis"];
const DEFAULT_PORTS: Record<Engine, number> = { postgres: 5432, mysql: 3306, mariadb: 3306, mongo: 27017, redis: 6379 };
type TlsMode = "disable" | "require" | "verify";

type Connection = {
  id: string;
  name: string;
  engine: Engine;
  host: string;
  port: number;
  database: string | null;
  username: string | null;
  tls_mode: TlsMode;
  options: Record<string, unknown>;
  password_configured: boolean;
  write_confirmation?: string;
  env_hints?: string[];
  last_tested_at: number | string | null;
  last_test_ok: boolean | null;
  created_at?: number | string | null;
  updated_at?: number | string | null;
};

type Suggestion = {
  source: "dokploy" | "agent";
  engine: Engine;
  name: string;
  project?: string | null;
  environment?: string | null;
  host: string | null;
  port: number;
  database?: string | null;
  username?: string | null;
  status?: string | null;
  state?: string | null;
  image?: string | null;
  protected?: boolean;
  env_hints?: string[];
  configured?: boolean;
};

type DiscoverSource = { available: boolean; error_code?: string; items: Suggestion[] };
type Discover = { dokploy: DiscoverSource; agent: DiscoverSource; network?: string };

type NetworkGuide = {
  network: string;
  summary: string;
  compose_snippet: string;
  docker_command: string;
  default_ports: Record<string, number>;
  notes: string[];
};

type SchemaTable = { name: string; type?: string | null; rows_estimate?: number | null; size_bytes?: number | null };
type SchemaNamespace = { name: string; tables: SchemaTable[]; keys?: number | null };
type SchemaResponse = {
  engine: Engine;
  database?: string | null;
  namespace_kind: "schema" | "database";
  namespaces: SchemaNamespace[];
  users?: string[];
  truncated?: boolean;
  dbsize?: number;
};

type ColumnInfo = { name: string; type?: string | null; nullable?: boolean; default?: unknown };
type ResultColumn = string | { name: string; type?: string | null };

type TableResponse = {
  schema?: string | null;
  table: string;
  columns: ColumnInfo[];
  primary_key?: string[];
  rows_estimate?: number | null;
  size_bytes?: number | null;
  result_columns: ResultColumn[];
  rows: unknown[][];
  row_count: number;
  has_more: boolean;
  truncated?: boolean;
  truncated_reason?: string | null;
  truncated_cells?: number;
  page: number;
  limit: number;
  elapsed_ms?: number;
};

type QueryResponse = {
  columns: ResultColumn[];
  rows: unknown[][];
  row_count: number;
  truncated?: boolean;
  truncated_reason?: string | null;
  truncated_cells?: number;
  affected_rows?: number | null;
  statement_kind?: string | null;
  elapsed_ms?: number;
  mode?: "read" | "write";
  dry_run?: boolean;
  rolled_back?: boolean;
  statement_sha256?: string;
  cursor?: string;
  inserted_ids?: unknown[];
  matched?: number;
};

type TestResponse = { ok: boolean; latency_ms?: number; server_version?: string; user?: string; database?: string };

type FilterOp = "eq" | "ne" | "gt" | "lt" | "contains" | "is_null" | "not_null";
type Filter = { column: string; op: FilterOp; value: string };

const API = "/api/v1/dbadmin";

// ── Copy ────────────────────────────────────────────────────────────────────────────────

const ENGINE_NAMES: Record<Engine, string> = {
  postgres: "PostgreSQL",
  mysql: "MySQL",
  mariadb: "MariaDB",
  mongo: "MongoDB",
  redis: "Redis"
};

const T = {
  listTitle: { fa: "پایگاه‌های داده وصل‌شده", en: "Connected databases" },
  listHint: { fa: "پایگاه‌های داده برنامه‌هایتان را این‌جا ببینید. پیش‌فرض فقط خواندن است و چیزی تغییر نمی‌کند.", en: "Browse your apps' databases here. By default it's read-only and nothing changes." },
  add: { fa: "افزودن پایگاه داده", en: "Add database" },
  emptyTitle: { fa: "هنوز پایگاه داده‌ای وصل نکرده‌اید", en: "No databases connected yet" },
  emptyBody: { fa: "پایگاه داده یک برنامه را وصل کنید تا جدول‌ها و داده‌هایش را بدون ابزار دیگری ببینید.", en: "Connect an app's database to see its tables and data without another tool." },
  colName: { fa: "نام", en: "Name" },
  colEngine: { fa: "نوع", en: "Type" },
  colHost: { fa: "نشانی", en: "Address" },
  colDatabase: { fa: "پایگاه داده", en: "Database" },
  colTest: { fa: "آخرین امتحان", en: "Last test" },
  colId: { fa: "شناسه", en: "ID" },
  notTested: { fa: "هنوز امتحان نشده", en: "Not tested yet" },
  testOk: { fa: "وصل شد", en: "Connected" },
  testFail: { fa: "وصل نشد", en: "Didn't connect" },
  test: { fa: "امتحان اتصال", en: "Test connection" },
  browse: { fa: "دیدن داده‌ها", en: "Browse data" },
  edit: { fa: "ویرایش", en: "Edit" },
  remove: { fa: "پاک کردن", en: "Remove" },
  testedOk: { fa: "اتصال به «{name}» برقرار است.", en: "“{name}” is reachable." },
  removeTitle: { fa: "اتصال «{name}» پاک شود؟", en: "Remove the connection “{name}”?" },
  removeBody: { fa: "فقط اتصال از پیشکار پاک می‌شود. خود پایگاه داده و داده‌هایش دست نمی‌خورند.", en: "Only the connection is removed from Pishkar. The database and its data are untouched." },
  removed: { fa: "اتصال «{name}» پاک شد.", en: "Connection “{name}” removed." },
  saved: { fa: "اتصال «{name}» ذخیره شد.", en: "Connection “{name}” saved." },
  noWrite: { fa: "فقط می‌توانید ببینید؛ افزودن و تغییر اتصال‌ها کار مدیر است.", en: "You can only look; adding and changing connections is for admins." },

  // wizard
  wizardTitle: { fa: "افزودن پایگاه داده", en: "Add a database" },
  editTitle: { fa: "ویرایش اتصال «{name}»", en: "Edit “{name}”" },
  stepSource: { fa: "کدام پایگاه داده؟", en: "Which database?" },
  stepSourceHint: { fa: "پیشکار پایگاه‌های داده Dokploy و کانتینرهای سرور را پیدا کرده است. یکی را انتخاب کنید.", en: "Pishkar found these databases in Dokploy and on the server. Pick one." },
  stepDetails: { fa: "مشخصات ورود", en: "Sign-in details" },
  stepDetailsHint: { fa: "نام کاربری و رمز پایگاه داده را بنویسید. رمز امن نگه‌داری می‌شود و دیگر نمایش داده نمی‌شود.", en: "Enter the database username and password. The password is stored safely and never shown again." },
  stepNetwork: { fa: "راه ارتباط", en: "Network" },
  stepNetworkHint: { fa: "پیشکار باید به شبکه پایگاه داده دسترسی داشته باشد. بعد از ذخیره، اتصال را امتحان می‌کنیم.", en: "Pishkar must be able to reach the database's network. After saving, we test the connection." },
  manual: { fa: "خودم مشخصات را می‌نویسم", en: "I'll enter the details myself" },
  manualHint: { fa: "برای پایگاه داده‌ای که در فهرست نیست.", en: "For a database that isn't listed." },
  discovering: { fa: "در حال پیدا کردن پایگاه‌های داده…", en: "Looking for databases…" },
  nothingFound: { fa: "پایگاه داده‌ای پیدا نشد. مشخصات را خودتان بنویسید.", en: "No databases found. Enter the details yourself." },
  fromDokploy: { fa: "از Dokploy", en: "From Dokploy" },
  fromAgent: { fa: "کانتینر روی سرور", en: "Container on the server" },
  dokployMissing: { fa: "Dokploy وصل نیست؛ پایگاه‌های داده آن را نمی‌بینیم.", en: "Dokploy isn't connected, so its databases aren't listed." },
  agentMissing: { fa: "دستیار سرور وصل نیست؛ کانتینرهای سرور را نمی‌بینیم.", en: "The server helper isn't connected, so containers aren't listed." },
  alreadyAdded: { fa: "قبلاً اضافه شده", en: "Already added" },
  protectedContainer: { fa: "کانتینر محافظت‌شده", en: "Protected container" },
  fieldName: { fa: "نامی برای این اتصال", en: "A name for this connection" },
  fieldNameHint: { fa: "فقط برای شناختن در همین پنل؛ مثلاً «فروشگاه اصلی».", en: "Just for you to recognise it here, e.g. “Main shop”." },
  fieldEngine: { fa: "نوع پایگاه داده", en: "Database type" },
  fieldHost: { fa: "نشانی سرور پایگاه داده", en: "Database server address" },
  fieldHostHint: { fa: "برای Dokploy همان نام برنامه پایگاه داده است.", en: "For Dokploy, it's the database app name." },
  fieldPort: { fa: "درگاه", en: "Port" },
  fieldDatabase: { fa: "نام پایگاه داده", en: "Database name" },
  fieldRedisDb: { fa: "شماره پایگاه داده (۰ تا ۲۵۵)", en: "Database number (0–255)" },
  fieldUser: { fa: "نام کاربری", en: "Username" },
  fieldPassword: { fa: "رمز", en: "Password" },
  fieldPasswordKeep: { fa: "برای نگه داشتن رمز فعلی خالی بگذارید.", en: "Leave empty to keep the current password." },
  fieldTls: { fa: "اتصال امن", en: "Secure connection" },
  tlsDisable: { fa: "خاموش (داخل شبکه خود سرور)", en: "Off (inside the server's own network)" },
  tlsRequire: { fa: "روشن", en: "On" },
  tlsVerify: { fa: "روشن، با بررسی گواهی", en: "On, and check the certificate" },
  hintVars: { fa: "رمز را از تنظیمات شروع برنامه پایگاه داده بردارید. معمولاً این نام‌ها را دارد:", en: "Copy the password from the database app's start settings. It's usually under these names:" },
  hintDokploy: { fa: "در Dokploy: پایگاه داده ← بخش «General» ← «Internal Credentials».", en: "In Dokploy: the database → General → Internal Credentials." },
  requiredName: { fa: "یک نام برای اتصال بنویسید.", en: "Enter a name for the connection." },
  requiredHost: { fa: "نشانی سرور پایگاه داده را بنویسید.", en: "Enter the database server address." },
  portRule: { fa: "درگاه باید عددی بین ۱ تا ۶۵۵۳۵ باشد.", en: "The port must be a number from 1 to 65535." },
  redisDbRule: { fa: "شماره پایگاه داده باید بین ۰ تا ۲۵۵ باشد.", en: "The database number must be from 0 to 255." },
  networkName: { fa: "شبکه‌ای که پیشکار باید به آن بپیوندد:", en: "The network Pishkar must join:" },
  networkPlain: { fa: "پایگاه‌های داده Dokploy فقط داخل شبکه Docker خودشان در دسترس‌اند. یک بار این چند خط را به سرویس پیشکار در فایل Compose اضافه کنید و دوباره منتشرش کنید.", en: "Dokploy databases are only reachable inside their own Docker network. Add these lines to the Pishkar service in your Compose file once, then redeploy it." },
  composeLabel: { fa: "خطوط فایل Compose", en: "Compose file lines" },
  dockerLabel: { fa: "یا یک بار این دستور را روی سرور اجرا کنید (با ساخت دوباره کانتینر از بین می‌رود)", en: "Or run this once on the server (lost when the container is recreated)" },
  saveAndTest: { fa: "ذخیره و امتحان اتصال", en: "Save and test" },
  savedButFailed: { fa: "اتصال ذخیره شد ولی پیشکار هنوز به آن نمی‌رسد.", en: "The connection was saved, but Pishkar can't reach it yet." },
  doneTitle: { fa: "«{name}» وصل شد.", en: "“{name}” is connected." },
  doneBody: { fa: "حالا می‌توانید جدول‌ها و داده‌هایش را ببینید.", en: "You can now browse its tables and data." },

  // browser
  browserTitle: { fa: "دیدن داده‌ها", en: "Browse data" },
  browserHint: { fa: "جدول یا مجموعه‌ای را انتخاب کنید تا ردیف‌هایش را ببینید. چیزی تغییر نمی‌کند.", en: "Pick a table or collection to see its rows. Nothing changes." },
  pickConnection: { fa: "پایگاه داده", en: "Database" },
  schemaNs: { fa: "بخش", en: "Schema" },
  databaseNs: { fa: "پایگاه داده", en: "Database" },
  noTables: { fa: "این بخش هنوز جدولی ندارد.", en: "This part has no tables yet." },
  tablesTruncated: { fa: "فهرست بلند بود و فقط بخشی از آن نمایش داده شد.", en: "The list was long; only part of it is shown." },
  tableKind: { fa: "جدول", en: "Table" },
  viewKind: { fa: "نما", en: "View" },
  collectionKind: { fa: "مجموعه", en: "Collection" },
  approxRows: { fa: "حدود {count} ردیف", en: "About {count} rows" },
  rowsTitle: { fa: "ردیف‌های «{name}»", en: "Rows of “{name}”" },
  noRows: { fa: "ردیفی با این شرایط پیدا نشد.", en: "No rows match." },
  page: { fa: "صفحه {page}", en: "Page {page}" },
  prev: { fa: "قبلی", en: "Previous" },
  next: { fa: "بعدی", en: "Next" },
  perPage: { fa: "در هر صفحه", en: "Per page" },
  elapsed: { fa: "در {ms} میلی‌ثانیه", en: "in {ms} ms" },
  filterColumn: { fa: "ستون", en: "Column" },
  filterOp: { fa: "شرط", en: "Condition" },
  filterValue: { fa: "مقدار", en: "Value" },
  applyFilter: { fa: "اعمال", en: "Apply" },
  clearFilter: { fa: "برداشتن شرط", en: "Clear" },
  exportCsv: { fa: "دریافت فایل CSV", en: "Download CSV" },
  exporting: { fa: "در حال آماده کردن فایل…", en: "Preparing the file…" },
  exported: { fa: "فایل «{file}» آماده شد.", en: "“{file}” is ready." },
  nullCell: { fa: "خالی", en: "empty" },
  binaryCell: { fa: "داده دودویی ({size})", en: "binary ({size})" },
  cutCell: { fa: "…(کوتاه شد)", en: "…(cut)" },
  truncRows: { fa: "فقط بخشی از ردیف‌ها آمد چون تعدادشان زیاد بود.", en: "Only part of the rows came back because there were too many." },
  truncSize: { fa: "پاسخ خیلی بزرگ بود و بخشی از آن نیامد.", en: "The answer was too big; part of it was left out." },
  truncCells: { fa: "{count} خانه خیلی بلند بود و کوتاه نمایش داده شد.", en: "{count} cells were too long and are shown cut." },
  pickTable: { fa: "یک جدول یا مجموعه را از فهرست انتخاب کنید.", en: "Pick a table or collection from the list." },
  columnsTitle: { fa: "ستون‌ها", en: "Columns" },

  // redis
  redisTitle: { fa: "کلیدهای Redis", en: "Redis keys" },
  redisPattern: { fa: "الگوی نام کلید", en: "Key name pattern" },
  redisPatternHint: { fa: "ستاره یعنی «هر چیزی»؛ مثلاً «session:*».", en: "A star means “anything”, e.g. “session:*”." },
  redisSearch: { fa: "جست‌وجو", en: "Search" },
  redisMore: { fa: "کلیدهای بیشتر", en: "More keys" },
  redisNoKeys: { fa: "کلیدی با این الگو پیدا نشد.", en: "No keys match this pattern." },
  redisKeysCount: { fa: "{count} کلید در این پایگاه داده", en: "{count} keys in this database" },
  redisType: { fa: "نوع", en: "Type" },
  redisTtl: { fa: "زمان باقی‌مانده", en: "Time left" },
  redisNoTtl: { fa: "همیشه می‌ماند", en: "Never expires" },
  redisSeconds: { fa: "{count} ثانیه", en: "{count} s" },
  redisValue: { fa: "مقدار", en: "Value" },
  redisFirstItems: { fa: "فقط ۱۰۰ مورد اول نمایش داده می‌شود.", en: "Only the first 100 items are shown." },

  // query editor
  queryTitle: { fa: "نوشتن درخواست", en: "Query editor" },
  queryHint: { fa: "درخواست به‌طور پیش‌فرض فقط می‌خواند و هیچ چیزی را تغییر نمی‌دهد.", en: "Queries are read-only by default and change nothing." },
  querySimple: { fa: "برای نوشتن درخواست دلخواه، حالت پیشرفته را روشن کنید.", en: "Turn on Advanced mode to write your own queries." },
  querySql: { fa: "درخواست SQL", en: "SQL query" },
  queryMongo: { fa: "درخواست MongoDB (به شکل «JSON»)", en: "MongoDB request (JSON)" },
  queryMongoHint: { fa: "مثلاً مجموعه، نوع کار و شرط جست‌وجو را مشخص کنید.", en: "Give the collection, the operation and a filter." },
  queryRedisCommand: { fa: "دستور Redis", en: "Redis command" },
  queryRedisArgs: { fa: "ورودی‌های دستور (هر کدام در یک خط)", en: "Command arguments (one per line)" },
  queryDatabase: { fa: "پایگاه داده (اختیاری)", en: "Database (optional)" },
  run: { fa: "اجرا", en: "Run" },
  running: { fa: "در حال اجرا…", en: "Running…" },
  writeMode: { fa: "حالت نوشتن (تغییر داده‌ها)", en: "Write mode (change data)" },
  writeModeHint: { fa: "در این حالت داده‌ها واقعاً تغییر می‌کنند. اول پیش‌نمایش بگیرید.", en: "In this mode data really changes. Preview first." },
  preview: { fa: "پیش‌نمایش (بدون تغییر)", en: "Preview (no change)" },
  previewResult: { fa: "اگر اجرا شود، {count} ردیف تغییر می‌کند. چیزی ذخیره نشد.", en: "If you run it, {count} rows will change. Nothing was saved." },
  writeTitle: { fa: "این درخواست روی «{name}» اجرا شود؟", en: "Run this on “{name}”?" },
  writeBody: { fa: "داده‌های پایگاه داده واقعاً تغییر می‌کنند. پیشکار نمی‌تواند این تغییر را برگرداند.", en: "The database's data really changes. Pishkar can't undo it." },
  writeConfirm: { fa: "بله، اجرا کن", en: "Yes, run it" },
  writeDone: { fa: "درخواست اجرا شد؛ {count} ردیف تغییر کرد.", en: "Done; {count} rows changed." },
  readDone: { fa: "{count} ردیف آمد", en: "{count} rows" },
  badJson: { fa: "متن درخواست MongoDB باید به شکل «JSON» درست باشد.", en: "The MongoDB request must be valid JSON." },
  emptyQuery: { fa: "متن درخواست را بنویسید.", en: "Write the request first." },
  noDbWrite: { fa: "حالت نوشتن فقط برای مدیر است.", en: "Write mode is for admins only." },

  advancedTitle: { fa: "جزئیات فنی اتصال", en: "Connection details" },
  serverVersion: { fa: "نسخه سرور پایگاه داده", en: "Database server version" },
  statementHash: { fa: "اثر انگشت درخواست (برای تاریخچه)", en: "Request fingerprint (for history)" },
  writeToken: { fa: "عبارت تأیید نوشتن", en: "Write confirmation phrase" },
  settingsTitle: { fa: "همه تنظیمات پایگاه‌های داده", en: "Every database setting" },
  settingsHint: { fa: "سقف ردیف‌ها، حداکثر زمان انتظار و اندازه فایل خروجی.", en: "Row limits, timeouts and export size." }
} satisfies Record<string, Bi>;

const OP_WORDS: Record<FilterOp, Bi> = {
  eq: { fa: "برابر باشد با", en: "equals" },
  ne: { fa: "برابر نباشد با", en: "is not" },
  gt: { fa: "بیشتر از", en: "greater than" },
  lt: { fa: "کمتر از", en: "less than" },
  contains: { fa: "شامل این متن باشد", en: "contains" },
  is_null: { fa: "خالی باشد", en: "is empty" },
  not_null: { fa: "خالی نباشد", en: "is not empty" }
};

const SQL_ENGINES: Engine[] = ["postgres", "mysql", "mariadb"];
const MONGO_SAMPLE = '{\n  "collection": "users",\n  "op": "find",\n  "filter": {},\n  "limit": 50\n}';

// ── Helpers ─────────────────────────────────────────────────────────────────────────────

function columnName(column: ResultColumn): string {
  return typeof column === "string" ? column : column.name;
}

function filterParam(filter: Filter | null): string | null {
  if (!filter || !filter.column) return null;
  if (filter.op === "is_null" || filter.op === "not_null") return JSON.stringify([{ column: filter.column, op: filter.op }]);
  if (filter.op === "contains") return JSON.stringify([{ column: filter.column, op: "ilike", value: `%${filter.value}%` }]);
  return JSON.stringify([{ column: filter.column, op: filter.op, value: filter.value }]);
}

function fileNameFrom(response: Response, fallback: string): string {
  const header = response.headers.get("Content-Disposition") ?? "";
  const star = /filename\*=(?:UTF-8'')?([^;]+)/i.exec(header);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim().replace(/^"|"$/g, ""));
    } catch {
      // fall through
    }
  }
  const plain = /filename="?([^";]+)"?/i.exec(header);
  return plain ? plain[1] : fallback;
}

async function downloadCsv(connectionId: string, body: Record<string, unknown>, fallbackName: string): Promise<string> {
  const response = await ensureOk(await apiMutate(`${API}/connections/${encodeURIComponent(connectionId)}/export`, { method: "POST", body: { ...body, excel_safe: true } }));
  const blob = await response.blob();
  const name = fileNameFrom(response, fallbackName);
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 2000);
  return name;
}

/** One cell value: null → muted «خالی», binary → size, objects → compact JSON, long text cut. */
function Cell({ value }: { value: unknown }) {
  const { language } = useKit();
  if (value === null || value === undefined) {
    return (
      <Typography component="span" variant="body2" color="text.disabled">
        {pick(language, T.nullCell)}
      </Typography>
    );
  }
  if (typeof value === "object" && value !== null && "$binary" in (value as Record<string, unknown>)) {
    const bytes = Number((value as Record<string, unknown>).bytes ?? 0);
    return (
      <Typography component="span" variant="body2" color="text.secondary">
        {say(language, T.binaryCell, { size: formatBytesText(bytes, language) })}
      </Typography>
    );
  }
  const text = typeof value === "string" ? value : typeof value === "object" ? JSON.stringify(value) : String(value);
  const short = text.length > 160 ? `${text.slice(0, 160)}…` : text;
  return (
    <Box component="span" title={text.length > 160 ? text : undefined} sx={{ whiteSpace: "pre", fontFamily: typeof value === "object" ? "monospace" : undefined, fontSize: 13 }}>
      <Ltr>{short}</Ltr>
    </Box>
  );
}

function formatBytesText(bytes: number, language: Language): string {
  const units = language === "fa" ? ["بایت", "کیلوبایت", "مگابایت", "گیگابایت"] : ["B", "KB", "MB", "GB"];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  const number = new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US", { maximumFractionDigits: 1 }).format(value);
  return `${number} ${units[index]}`;
}

function TruncationNotice({ reason, cells }: { reason?: string | null; cells?: number }) {
  const { language } = useKit();
  const lines: string[] = [];
  if (reason === "row_limit") lines.push(pick(language, T.truncRows));
  else if (reason === "response_size") lines.push(pick(language, T.truncSize));
  else if (reason) lines.push(pick(language, T.truncRows));
  if (cells && cells > 0) lines.push(say(language, T.truncCells, { count: cells }));
  if (lines.length === 0) return null;
  return <Notice tone="warning">{lines.join(" ")}</Notice>;
}

/** Rows as a horizontally scrollable table (works at 375 px by scrolling sideways). */
function RowsTable({
  columns,
  rows,
  sort,
  onSort,
  label,
  onRowClick
}: {
  columns: string[];
  rows: unknown[][];
  sort?: string[];
  onSort?: (column: string) => void;
  label: string;
  onRowClick?: (row: unknown[]) => void;
}) {
  return (
    <TableContainer sx={{ maxHeight: 520, border: 1, borderColor: "divider", borderRadius: 1 }}>
      <Table size="small" stickyHeader aria-label={label}>
        <TableHead>
          <TableRow>
            {columns.map((column) => {
              const active = sort?.find((item) => item.replace(/^-/, "") === column);
              return (
                <TableCell key={column} sx={{ whiteSpace: "nowrap", fontWeight: 600 }}>
                  {onSort ? (
                    <TableSortLabel active={Boolean(active)} direction={active?.startsWith("-") ? "desc" : "asc"} onClick={() => onSort(column)}>
                      <Ltr>{column}</Ltr>
                    </TableSortLabel>
                  ) : (
                    <Ltr>{column}</Ltr>
                  )}
                </TableCell>
              );
            })}
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((row, index) => (
            <TableRow key={index} hover={Boolean(onRowClick)} onClick={onRowClick ? () => onRowClick(row) : undefined} sx={onRowClick ? { cursor: "pointer" } : undefined}>
              {columns.map((column, cellIndex) => (
                <TableCell key={column} sx={{ maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", verticalAlign: "top" }}>
                  <Cell value={row[cellIndex]} />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

// ── Panel ───────────────────────────────────────────────────────────────────────────────

type Props = { language: Language; permissions: string[]; onUnauthorized: () => void };

export function DbAdminPanel({ permissions }: Props) {
  const { language, isAdvanced } = useKit();
  const can = useCan(permissions);
  const canRead = can("db:read");
  const canWrite = can("db:write");
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [connections, setConnections] = useState<Connection[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [wizard, setWizard] = useState<{ mode: "create" } | { mode: "edit"; connection: Connection } | null>(null);
  const [versions, setVersions] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    try {
      const response = await getJson<{ items: Connection[] }>(`${API}/connections`);
      setConnections(response.items);
      setError(null);
      setSelectedId((current) => (current && response.items.some((item) => item.id === current) ? current : response.items[0]?.id ?? null));
    } catch (caught) {
      setError(caught);
    }
  }, []);

  useEffect(() => {
    if (canRead) void load();
  }, [canRead, load]);

  // Open the wizard from a deep link: #/server/databases?new=1
  useEffect(() => {
    if (canWrite && /[?&]new=1/.test(window.location.hash)) setWizard({ mode: "create" });
  }, [canWrite]);

  const testConnection = useCallback(
    async (connection: Connection) => {
      try {
        const result = await mutateJson<TestResponse>(`${API}/connections/${encodeURIComponent(connection.id)}/test`, { method: "POST" });
        if (result?.server_version) setVersions((current) => ({ ...current, [connection.id]: result.server_version ?? "" }));
        notify({ message: say(language, T.testedOk, { name: connection.name }), tone: "success" });
      } catch (caught) {
        notify({ message: errorSentence(language, caught), tone: "error" });
      }
      void load();
    },
    [language, load, notify]
  );

  const removeConnection = useCallback(
    async (connection: Connection) => {
      const typed: ConfirmWord = nameConfirmation(connection.name, connection.name);
      const ok = await ask({
        title: say(language, T.removeTitle, { name: connection.name }),
        body: pick(language, T.removeBody),
        severity: "destructive",
        typed
      });
      if (!ok) return;
      try {
        await mutateJson(`${API}/connections/${encodeURIComponent(connection.id)}`, { method: "DELETE", body: { confirmation: connection.name } });
        notify({ message: say(language, T.removed, { name: connection.name }), tone: "success" });
      } catch (caught) {
        notify({ message: errorSentence(language, caught), tone: "error" });
      }
      void load();
    },
    [ask, language, load, notify]
  );

  if (!canRead) return <NoAccess needs="db:read" variant="card" />;

  const selected = connections?.find((item) => item.id === selectedId) ?? null;

  return (
    <Stack spacing={2}>
      <SectionCard
        title={pick(language, T.listTitle)}
        hint={pick(language, T.listHint)}
        action={
          canWrite && connections && connections.length > 0 ? (
            <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setWizard({ mode: "create" })}>
              {pick(language, T.add)}
            </Button>
          ) : undefined
        }
        flush
      >
        {error ? (
          <Box sx={{ p: 2 }}>
            <FriendlyError error={error} onRetry={() => void load()} />
          </Box>
        ) : connections === null ? (
          <LinearProgress />
        ) : (
          <ResponsiveList
            label={pick(language, T.listTitle)}
            rows={connections}
            rowKey={(row) => row.id}
            onRowClick={(row) => setSelectedId(row.id)}
            columns={[
              { key: "name", header: pick(language, T.colName), render: (row) => <Typography fontWeight={row.id === selectedId ? 700 : 500}>{row.name}</Typography> },
              { key: "engine", header: pick(language, T.colEngine), render: (row) => ENGINE_NAMES[row.engine] ?? row.engine },
              { key: "host", header: pick(language, T.colHost), ltr: true, render: (row) => <Ltr mono>{`${row.host}:${row.port}`}</Ltr> },
              { key: "database", header: pick(language, T.colDatabase), ltr: true, advancedOnly: true, render: (row) => <Ltr>{row.database ?? "—"}</Ltr> },
              { key: "test", header: pick(language, T.colTest), render: (row) => <TestCell connection={row} /> },
              { key: "id", header: pick(language, T.colId), ltr: true, advancedOnly: true, render: (row) => <Ltr mono>{row.id}</Ltr> }
            ]}
            card={{
              title: (row) => row.name,
              meta: (row) => (
                <>
                  {ENGINE_NAMES[row.engine] ?? row.engine} · <Ltr mono>{row.host}</Ltr>
                </>
              ),
              status: (row) => <TestPill connection={row} />
            }}
            actions={[
              { key: "browse", label: pick(language, T.browse), onClick: (row) => setSelectedId(row.id) },
              { key: "test", label: pick(language, T.test), onClick: (row) => void testConnection(row) },
              { key: "edit", label: pick(language, T.edit), hidden: () => !canWrite, onClick: (row) => setWizard({ mode: "edit", connection: row }) },
              { key: "remove", label: pick(language, T.remove), danger: true, hidden: () => !canWrite, onClick: (row) => void removeConnection(row) }
            ]}
            empty={
              <EmptyState
                icon={StorageRoundedIcon}
                title={pick(language, T.emptyTitle)}
                body={pick(language, T.emptyBody)}
                action={
                  canWrite ? (
                    <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setWizard({ mode: "create" })}>
                      {pick(language, T.add)}
                    </Button>
                  ) : undefined
                }
              />
            }
          />
        )}
        {!canWrite && (
          <Box sx={{ px: 2, pb: 2 }}>
            <NoAccess needs="db:write" />
          </Box>
        )}
      </SectionCard>

      {selected && <Browser key={selected.id} connection={selected} />}

      {selected && isAdvanced && <QueryEditor key={`q-${selected.id}`} connection={selected} canWrite={canWrite} />}
      {selected && !isAdvanced && <Notice>{pick(language, T.querySimple)}</Notice>}

      {selected && (
        <SectionCard advanced title={pick(language, T.advancedTitle)} collapsible defaultCollapsed>
          <KeyValueList
            items={[
              { label: pick(language, T.colId), value: <Ltr mono>{selected.id}</Ltr>, copy: selected.id },
              { label: pick(language, T.colEngine), value: <Ltr mono>{selected.engine}</Ltr> },
              { label: pick(language, T.colHost), value: <Ltr mono>{`${selected.host}:${selected.port}`}</Ltr> },
              { label: pick(language, T.colDatabase), value: <Ltr mono>{selected.database ?? "—"}</Ltr> },
              { label: pick(language, T.fieldUser), value: <Ltr mono>{selected.username ?? "—"}</Ltr> },
              { label: pick(language, T.fieldTls), value: <Ltr mono>{selected.tls_mode}</Ltr> },
              { label: pick(language, T.serverVersion), value: <Ltr mono>{versions[selected.id] ?? "—"}</Ltr> },
              { label: pick(language, T.writeToken), value: <Ltr mono>{selected.write_confirmation ?? `WRITE ${selected.name}`}</Ltr> },
              { label: pick(language, T.colTest), value: <RelativeTime value={selected.last_tested_at} /> }
            ]}
          />
        </SectionCard>
      )}

      {isAdvanced && (
        <RegistrySettings groups={["server.databases"]} permissions={permissions} title={pick(language, T.settingsTitle)} hint={pick(language, T.settingsHint)} />
      )}

      {wizard && (
        <ConnectionWizard
          key={wizard.mode === "edit" ? wizard.connection.id : "create"}
          existing={wizard.mode === "edit" ? wizard.connection : null}
          connections={connections ?? []}
          onClose={() => setWizard(null)}
          onSaved={(connection, version) => {
            if (version) setVersions((current) => ({ ...current, [connection.id]: version }));
            setSelectedId(connection.id);
            void load();
          }}
        />
      )}
      {dialog}
      {snackbar}
    </Stack>
  );
}

export default DbAdminPanel;

function TestPill({ connection }: { connection: Connection }) {
  const { language } = useKit();
  if (connection.last_test_ok === null || connection.last_test_ok === undefined) return <StatusPill tone="off" label={pick(language, T.notTested)} />;
  return connection.last_test_ok ? <StatusPill tone="ok" label={pick(language, T.testOk)} /> : <StatusPill tone="error" label={pick(language, T.testFail)} />;
}

function TestCell({ connection }: { connection: Connection }) {
  return (
    <Stack direction="row" spacing={1} alignItems="center">
      <TestPill connection={connection} />
      {connection.last_tested_at ? (
        <Typography variant="caption" color="text.secondary">
          <RelativeTime value={connection.last_tested_at} />
        </Typography>
      ) : null}
    </Stack>
  );
}

// ── Add / edit wizard ───────────────────────────────────────────────────────────────────

type FormState = {
  name: string;
  engine: Engine;
  host: string;
  port: string;
  database: string;
  username: string;
  password: string;
  tls_mode: TlsMode;
};

function emptyForm(): FormState {
  return { name: "", engine: "postgres", host: "", port: String(DEFAULT_PORTS.postgres), database: "", username: "", password: "", tls_mode: "disable" };
}

function formFromConnection(connection: Connection): FormState {
  return {
    name: connection.name,
    engine: connection.engine,
    host: connection.host,
    port: String(connection.port),
    database: connection.database ?? "",
    username: connection.username ?? "",
    password: "",
    tls_mode: connection.tls_mode
  };
}

function ConnectionWizard({
  existing,
  connections,
  onClose,
  onSaved
}: {
  existing: Connection | null;
  connections: Connection[];
  onClose: () => void;
  onSaved: (connection: Connection, version?: string) => void;
}) {
  const { language, isAdvanced, c } = useKit();
  const [form, setForm] = useState<FormState>(() => (existing ? formFromConnection(existing) : emptyForm()));
  const [picked, setPicked] = useState<Suggestion | "manual" | null>(existing ? "manual" : null);
  const [discover, setDiscover] = useState<Discover | null>(null);
  const [discoverError, setDiscoverError] = useState<unknown>(null);
  const [guide, setGuide] = useState<NetworkGuide | null>(null);
  const [outcome, setOutcome] = useState<TestOutcome>({ state: "idle" });
  const [done, setDone] = useState<{ name: string } | null>(null);
  const savedId = useRef<string | null>(existing?.id ?? null);

  useEffect(() => {
    if (!existing) {
      getJson<Discover>(`${API}/discover`).then(setDiscover, setDiscoverError);
    }
    getJson<NetworkGuide>(`${API}/network-guide`).then(setGuide, () => setGuide(null));
  }, [existing]);

  const update = (patch: Partial<FormState>) => setForm((current) => ({ ...current, ...patch }));

  const choose = (suggestion: Suggestion | "manual") => {
    setPicked(suggestion);
    if (suggestion === "manual") return;
    setForm({
      name: suggestion.name,
      engine: suggestion.engine,
      host: suggestion.host ?? "",
      port: String(suggestion.port ?? DEFAULT_PORTS[suggestion.engine]),
      database: suggestion.database ?? (suggestion.engine === "redis" ? "0" : ""),
      username: suggestion.username ?? "",
      password: "",
      tls_mode: "disable"
    });
  };

  const hints = picked && picked !== "manual" ? picked.env_hints ?? [] : existing?.env_hints ?? [];
  const fromDokploy = picked && picked !== "manual" && picked.source === "dokploy";

  const validateDetails = (): string | null => {
    if (!form.name.trim()) return pick(language, T.requiredName);
    if (!form.host.trim()) return pick(language, T.requiredHost);
    const port = Number(form.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return pick(language, T.portRule);
    if (form.engine === "redis" && form.database.trim()) {
      const db = Number(form.database);
      if (!Number.isInteger(db) || db < 0 || db > 255) return pick(language, T.redisDbRule);
    }
    return null;
  };

  const save = async () => {
    const body: Record<string, unknown> = {
      name: form.name.trim(),
      engine: form.engine,
      host: form.host.trim(),
      port: Number(form.port),
      database: form.database.trim() || null,
      username: form.engine === "redis" && !form.username.trim() ? null : form.username.trim() || null,
      tls_mode: form.tls_mode
    };
    if (form.password) body.password = form.password;
    let connection: Connection;
    if (savedId.current) {
      connection = await mutateJson<Connection>(`${API}/connections/${encodeURIComponent(savedId.current)}`, { method: "PATCH", body });
    } else {
      connection = await mutateJson<Connection>(`${API}/connections`, { method: "POST", body });
      savedId.current = connection.id;
    }
    setOutcome({ state: "running" });
    try {
      const result = await mutateJson<TestResponse>(`${API}/connections/${encodeURIComponent(connection.id)}/test`, { method: "POST" });
      setOutcome({ state: "ok", latencyMs: result?.latency_ms ?? null });
      onSaved(connection, result?.server_version);
      setDone({ name: connection.name });
    } catch (caught) {
      setOutcome({ state: "fail", error: caught, message: pick(language, T.savedButFailed) });
      onSaved(connection);
      throw caught;
    }
  };

  const sourceStep: WizardStep = {
    key: "source",
    title: pick(language, T.stepSource),
    hint: pick(language, T.stepSourceHint),
    validate: () => (picked ? null : pick(language, T.stepSourceHint)),
    render: () => {
      const items = [...(discover?.dokploy.items ?? []), ...(discover?.agent.items ?? [])];
      return (
        <Stack spacing={1.5}>
          {discoverError ? <FriendlyError error={discoverError} noAction severity="warning" /> : null}
          {!discover && !discoverError ? (
            <Stack spacing={1}>
              <Typography variant="body2" color="text.secondary">
                {pick(language, T.discovering)}
              </Typography>
              <LinearProgress />
            </Stack>
          ) : null}
          {discover && !discover.dokploy.available ? <Notice>{pick(language, T.dokployMissing)}</Notice> : null}
          {discover && !discover.agent.available ? <Notice>{pick(language, T.agentMissing)}</Notice> : null}
          {discover && items.length === 0 ? <Notice>{pick(language, T.nothingFound)}</Notice> : null}
          <ChoiceCards
            label={pick(language, T.stepSource)}
            value={picked === "manual" ? "manual" : picked ? String(items.indexOf(picked)) : null}
            onChange={(key) => choose(key === "manual" ? "manual" : items[Number(key)])}
            options={[
              ...items.map((item, index) => {
                const already = item.configured || connections.some((connection) => connection.host === item.host && connection.engine === item.engine);
                return {
                  key: String(index),
                  title: item.name,
                  body: (
                    <>
                      {ENGINE_NAMES[item.engine]} · {pick(language, item.source === "dokploy" ? T.fromDokploy : T.fromAgent)}
                      {item.project ? (
                        <>
                          {" · "}
                          <Ltr>{item.project}</Ltr>
                        </>
                      ) : null}
                    </>
                  ),
                  badges: (
                    <>
                      {already ? <Chip size="small" label={pick(language, T.alreadyAdded)} /> : null}
                      {item.protected ? <Chip size="small" color="warning" label={pick(language, T.protectedContainer)} /> : null}
                      {item.status || item.state ? <StatusPill status={item.status ?? item.state} size="small" /> : null}
                    </>
                  )
                };
              }),
              { key: "manual", title: pick(language, T.manual), body: pick(language, T.manualHint) }
            ]}
          />
        </Stack>
      );
    }
  };

  const detailsStep: WizardStep = {
    key: "details",
    title: pick(language, T.stepDetails),
    hint: pick(language, T.stepDetailsHint),
    validate: validateDetails,
    render: () => (
      <Stack spacing={2}>
        <TextField label={pick(language, T.fieldName)} helperText={pick(language, T.fieldNameHint)} value={form.name} onChange={(event) => update({ name: event.target.value })} required autoFocus />
        <TextField
          select
          label={pick(language, T.fieldEngine)}
          value={form.engine}
          onChange={(event) => {
            const engine = event.target.value as Engine;
            update({ engine, port: String(DEFAULT_PORTS[engine]), database: engine === "redis" ? "0" : form.engine === "redis" ? "" : form.database });
          }}
        >
          {ENGINES.map((engine) => (
            <MenuItem key={engine} value={engine}>
              {ENGINE_NAMES[engine]}
            </MenuItem>
          ))}
        </TextField>
        <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
          <TextField
            label={pick(language, T.fieldHost)}
            helperText={pick(language, T.fieldHostHint)}
            value={form.host}
            onChange={(event) => update({ host: event.target.value })}
            required
            fullWidth
            slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
          />
          <TextField
            label={pick(language, T.fieldPort)}
            value={form.port}
            onChange={(event) => update({ port: event.target.value.replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit))) })}
            sx={{ width: { sm: 140 } }}
            slotProps={{ htmlInput: { dir: "ltr", inputMode: "numeric" } }}
          />
        </Stack>
        <TextField
          label={pick(language, form.engine === "redis" ? T.fieldRedisDb : T.fieldDatabase)}
          value={form.database}
          onChange={(event) => update({ database: event.target.value })}
          slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
        />
        {form.engine !== "redis" || isAdvanced ? (
          <TextField label={pick(language, T.fieldUser)} value={form.username} onChange={(event) => update({ username: event.target.value })} autoComplete="off" slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
        ) : null}
        <TextField
          label={pick(language, T.fieldPassword)}
          type="password"
          value={form.password}
          onChange={(event) => update({ password: event.target.value })}
          autoComplete="new-password"
          helperText={existing?.password_configured ? pick(language, T.fieldPasswordKeep) : undefined}
          slotProps={{ htmlInput: { dir: "ltr" } }}
        />
        {hints.length > 0 ? (
          <Notice>
            <Typography variant="body2">{pick(language, T.hintVars)}</Typography>
            <Stack direction="row" spacing={0.75} useFlexGap flexWrap="wrap" sx={{ mt: 0.75 }}>
              {hints.map((hint) => (
                <Chip key={hint} size="small" variant="outlined" label={<Ltr mono>{hint}</Ltr>} />
              ))}
            </Stack>
            {fromDokploy ? (
              <Typography variant="body2" sx={{ mt: 0.75 }}>
                {pick(language, T.hintDokploy)}
              </Typography>
            ) : null}
          </Notice>
        ) : null}
        {isAdvanced ? (
          <TextField select label={pick(language, T.fieldTls)} value={form.tls_mode} onChange={(event) => update({ tls_mode: event.target.value as TlsMode })}>
            <MenuItem value="disable">{pick(language, T.tlsDisable)}</MenuItem>
            <MenuItem value="require">{pick(language, T.tlsRequire)}</MenuItem>
            <MenuItem value="verify">{pick(language, T.tlsVerify)}</MenuItem>
          </TextField>
        ) : null}
      </Stack>
    )
  };

  const networkStep: WizardStep = {
    key: "network",
    title: pick(language, T.stepNetwork),
    hint: pick(language, T.stepNetworkHint),
    render: () => (
      <Stack spacing={2}>
        {guide ? (
          <>
            <Typography variant="body2">{pick(language, T.networkPlain)}</Typography>
            <Typography variant="body2">
              {pick(language, T.networkName)} <Ltr mono>{guide.network}</Ltr>
            </Typography>
            <CopyField label={pick(language, T.composeLabel)} value={guide.compose_snippet} multiline />
            <CopyField label={pick(language, T.dockerLabel)} value={guide.docker_command} />
          </>
        ) : (
          <Typography variant="body2">{pick(language, T.networkPlain)}</Typography>
        )}
        <TestResult outcome={outcome} />
      </Stack>
    )
  };

  const steps = existing ? [detailsStep, networkStep] : [sourceStep, detailsStep, networkStep];

  return (
    <ActionWizard
      open
      title={existing ? say(language, T.editTitle, { name: existing.name }) : pick(language, T.wizardTitle)}
      steps={steps}
      onFinish={save}
      onClose={onClose}
      finishLabel={pick(language, T.saveAndTest)}
      done={
        done ? (
          <Stack spacing={1.5} alignItems="flex-start">
            <TestResult outcome={outcome} />
            <Typography variant="h6">{say(language, T.doneTitle, { name: done.name })}</Typography>
            <Typography variant="body2" color="text.secondary">
              {pick(language, T.doneBody)}
            </Typography>
            <Button variant="contained" onClick={onClose}>
              {c.done}
            </Button>
          </Stack>
        ) : undefined
      }
    />
  );
}

// ── Browser ─────────────────────────────────────────────────────────────────────────────

function Browser({ connection }: { connection: Connection }) {
  const { language } = useKit();
  const [schema, setSchema] = useState<SchemaResponse | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [namespace, setNamespace] = useState<string>("");
  const [table, setTable] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setSchema(null);
    try {
      const response = await getJson<SchemaResponse>(`${API}/connections/${encodeURIComponent(connection.id)}/schema`);
      setSchema(response);
      const preferred = response.namespaces.find((item) => item.name === "public") ?? response.namespaces.find((item) => item.name === response.database) ?? response.namespaces[0];
      setNamespace(preferred?.name ?? "");
      setTable(null);
    } catch (caught) {
      setError(caught);
    }
  }, [connection.id]);

  useEffect(() => {
    void load();
  }, [load]);

  const current = schema?.namespaces.find((item) => item.name === namespace) ?? null;
  const isRedis = connection.engine === "redis";
  const kindWord = (type?: string | null) => {
    if (connection.engine === "mongo") return pick(language, T.collectionKind);
    return type && /view/i.test(type) ? pick(language, T.viewKind) : pick(language, T.tableKind);
  };

  return (
    <SectionCard
      title={`${pick(language, T.browserTitle)}: ${connection.name}`}
      hint={isRedis ? undefined : pick(language, T.browserHint)}
      action={
        <Button size="small" startIcon={<RefreshRoundedIcon />} onClick={() => void load()}>
          {pick(language, { fa: "تازه کردن", en: "Refresh" })}
        </Button>
      }
    >
      {error ? <FriendlyError error={error} onRetry={() => void load()} /> : null}
      {!schema && !error ? <LinearProgress /> : null}
      {schema && isRedis ? <RedisBrowser connection={connection} dbsize={schema.dbsize ?? current?.keys ?? null} /> : null}
      {schema && !isRedis ? (
        <Stack spacing={2}>
          {schema.namespaces.length > 1 ? (
            <TextField
              select
              size="small"
              label={pick(language, schema.namespace_kind === "schema" ? T.schemaNs : T.databaseNs)}
              value={namespace}
              onChange={(event) => {
                setNamespace(event.target.value);
                setTable(null);
              }}
              sx={{ maxWidth: 320 }}
            >
              {schema.namespaces.map((item) => (
                <MenuItem key={item.name} value={item.name}>
                  <Ltr>{item.name}</Ltr>
                </MenuItem>
              ))}
            </TextField>
          ) : null}
          {schema.truncated ? <Notice tone="warning">{pick(language, T.tablesTruncated)}</Notice> : null}
          {current && current.tables.length === 0 ? <Typography color="text.secondary">{pick(language, T.noTables)}</Typography> : null}
          {current && current.tables.length > 0 ? (
            <Box sx={{ display: "flex", gap: 1, overflowX: "auto", pb: 0.5, flexWrap: { xs: "nowrap", md: "wrap" } }}>
              {current.tables.map((item) => (
                <ButtonBase
                  key={item.name}
                  onClick={() => setTable(item.name)}
                  aria-pressed={table === item.name}
                  sx={{
                    flex: "0 0 auto",
                    display: "block",
                    textAlign: "start",
                    px: 1.5,
                    py: 1,
                    minHeight: 44,
                    borderRadius: 2,
                    border: 1,
                    borderColor: table === item.name ? "primary.main" : "divider",
                    bgcolor: table === item.name ? "action.selected" : "transparent"
                  }}
                >
                  <Typography variant="body2" fontWeight={600}>
                    <Ltr>{item.name}</Ltr>
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {kindWord(item.type)}
                    {item.rows_estimate !== null && item.rows_estimate !== undefined && item.rows_estimate >= 0 ? <> · {say(language, T.approxRows, { count: item.rows_estimate })}</> : null}
                    {item.size_bytes ? (
                      <>
                        {" · "}
                        <Bytes value={item.size_bytes} />
                      </>
                    ) : null}
                  </Typography>
                </ButtonBase>
              ))}
            </Box>
          ) : null}
          {table ? <TableView key={`${namespace}.${table}`} connection={connection} namespace={namespace || null} table={table} /> : current && current.tables.length > 0 ? <Typography color="text.secondary">{pick(language, T.pickTable)}</Typography> : null}
        </Stack>
      ) : null}
    </SectionCard>
  );
}

function TableView({ connection, namespace, table }: { connection: Connection; namespace: string | null; table: string }) {
  const { language, isAdvanced } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(50);
  const [sort, setSort] = useState<string[]>([]);
  const [filter, setFilter] = useState<Filter | null>(null);
  const [draft, setDraft] = useState<Filter>({ column: "", op: "eq", value: "" });
  const [data, setData] = useState<TableResponse | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    const params = new URLSearchParams({ page: String(page), limit: String(limit) });
    if (namespace) params.set("schema", namespace);
    if (sort.length) params.set("sort", sort.join(","));
    const filterText = filterParam(filter);
    if (filterText) params.set("filter", filterText);
    try {
      const response = await getJson<TableResponse>(`${API}/connections/${encodeURIComponent(connection.id)}/tables/${encodeURIComponent(table)}?${params.toString()}`);
      setData(response);
      setDraft((current) => (current.column ? current : { ...current, column: response.columns[0]?.name ?? columnName(response.result_columns[0] ?? "") }));
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }, [connection.id, filter, limit, namespace, page, sort, table]);

  useEffect(() => {
    void load();
  }, [load]);

  const columns = useMemo(() => (data ? data.result_columns.map(columnName) : []), [data]);
  const filterColumns = data?.columns.length ? data.columns.map((item) => item.name) : columns;

  const toggleSort = (column: string) => {
    setPage(1);
    setSort((current) => {
      const existing = current.find((item) => item.replace(/^-/, "") === column);
      if (!existing) return [column];
      if (!existing.startsWith("-")) return [`-${column}`];
      return [];
    });
  };

  const exportCsv = async () => {
    setExporting(true);
    try {
      const tableBody: Record<string, unknown> = { name: table };
      if (namespace) tableBody.schema = namespace;
      const filterText = filterParam(filter);
      if (filterText) tableBody.filter = filterText;
      if (sort.length) tableBody.sort = sort.join(",");
      const file = await downloadCsv(connection.id, { table: tableBody }, `${table}.csv`);
      notify({ message: say(language, T.exported, { file }), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    } finally {
      setExporting(false);
    }
  };

  const needsValue = draft.op !== "is_null" && draft.op !== "not_null";

  return (
    <Stack spacing={1.5}>
      <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between" useFlexGap flexWrap="wrap">
        <Typography variant="subtitle1" fontWeight={700}>
          {say(language, T.rowsTitle, { name: table })}
        </Typography>
        <Button size="small" variant="outlined" startIcon={<DownloadRoundedIcon />} disabled={exporting || connection.engine === "redis"} onClick={() => void exportCsv()}>
          {exporting ? pick(language, T.exporting) : pick(language, T.exportCsv)}
        </Button>
      </Stack>

      <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ sm: "center" }}>
        <TextField select size="small" label={pick(language, T.filterColumn)} value={draft.column} onChange={(event) => setDraft({ ...draft, column: event.target.value })} sx={{ minWidth: 160 }}>
          {filterColumns.map((column) => (
            <MenuItem key={column} value={column}>
              <Ltr>{column}</Ltr>
            </MenuItem>
          ))}
        </TextField>
        <TextField select size="small" label={pick(language, T.filterOp)} value={draft.op} onChange={(event) => setDraft({ ...draft, op: event.target.value as FilterOp })} sx={{ minWidth: 170 }}>
          {(Object.keys(OP_WORDS) as FilterOp[]).map((op) => (
            <MenuItem key={op} value={op}>
              {pick(language, OP_WORDS[op])}
            </MenuItem>
          ))}
        </TextField>
        {needsValue ? <TextField size="small" label={pick(language, T.filterValue)} value={draft.value} onChange={(event) => setDraft({ ...draft, value: event.target.value })} slotProps={{ htmlInput: { dir: "auto" } }} /> : null}
        <Button
          size="small"
          variant="contained"
          disabled={!draft.column}
          onClick={() => {
            setPage(1);
            setFilter({ ...draft });
          }}
        >
          {pick(language, T.applyFilter)}
        </Button>
        {filter ? (
          <Button
            size="small"
            onClick={() => {
              setPage(1);
              setFilter(null);
            }}
          >
            {pick(language, T.clearFilter)}
          </Button>
        ) : null}
      </Stack>

      {busy ? <LinearProgress /> : null}
      {error ? <FriendlyError error={error} onRetry={() => void load()} /> : null}
      {data ? (
        <>
          <TruncationNotice reason={data.truncated ? data.truncated_reason ?? "row_limit" : null} cells={data.truncated_cells} />
          {data.rows.length === 0 ? (
            <Typography color="text.secondary">{pick(language, T.noRows)}</Typography>
          ) : (
            <RowsTable columns={columns} rows={data.rows} sort={sort} onSort={toggleSort} label={say(language, T.rowsTitle, { name: table })} />
          )}
          <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
            <Button size="small" disabled={page <= 1 || busy} onClick={() => setPage((value) => value - 1)}>
              {pick(language, T.prev)}
            </Button>
            <Typography variant="body2">{say(language, T.page, { page })}</Typography>
            <Button size="small" disabled={!data.has_more || busy} onClick={() => setPage((value) => value + 1)}>
              {pick(language, T.next)}
            </Button>
            <TextField
              select
              size="small"
              label={pick(language, T.perPage)}
              value={limit}
              onChange={(event) => {
                setPage(1);
                setLimit(Number(event.target.value));
              }}
              sx={{ width: 120 }}
            >
              {[25, 50, 100, 200, 500].map((value) => (
                <MenuItem key={value} value={value}>
                  <Num value={value} />
                </MenuItem>
              ))}
            </TextField>
            {data.elapsed_ms !== undefined ? (
              <Typography variant="caption" color="text.secondary">
                {say(language, T.elapsed, { ms: Math.round(data.elapsed_ms) })}
              </Typography>
            ) : null}
          </Stack>
          {isAdvanced && data.columns.length > 0 ? (
            <SectionCard title={pick(language, T.columnsTitle)} collapsible defaultCollapsed>
              <KeyValueList
                dense
                items={data.columns.map((column) => ({
                  label: column.name,
                  value: (
                    <Ltr mono>
                      {`${column.type ?? ""}${column.nullable === false ? " NOT NULL" : ""}${data.primary_key?.includes(column.name) ? " PK" : ""}`}
                    </Ltr>
                  )
                }))}
              />
            </SectionCard>
          ) : null}
        </>
      ) : null}
      {snackbar}
    </Stack>
  );
}

// ── Redis ───────────────────────────────────────────────────────────────────────────────

function runQuery(connectionId: string, body: Record<string, unknown>) {
  return mutateJson<QueryResponse>(`${API}/connections/${encodeURIComponent(connectionId)}/query`, { method: "POST", body });
}

const REDIS_VALUE_COMMAND: Record<string, (key: string) => string[]> = {
  string: (key) => ["GET", key],
  hash: (key) => ["HGETALL", key],
  list: (key) => ["LRANGE", key, "0", "99"],
  set: (key) => ["SMEMBERS", key],
  zset: (key) => ["ZRANGE", key, "0", "99", "WITHSCORES"],
  stream: (key) => ["XRANGE", key, "-", "+", "COUNT", "50"]
};

function RedisBrowser({ connection, dbsize }: { connection: Connection; dbsize: number | null }) {
  const { language } = useKit();
  const [pattern, setPattern] = useState("*");
  const [keys, setKeys] = useState<string[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const activePattern = useRef("*");

  const scan = useCallback(
    async (from: string, reset: boolean) => {
      setBusy(true);
      setError(null);
      try {
        const response = await runQuery(connection.id, { redis: { command: "SCAN", args: [from, "MATCH", activePattern.current || "*", "COUNT", "200"] } });
        const found = response.rows.map((row) => String(row[0]));
        setKeys((current) => (reset ? found : [...current, ...found.filter((key) => !current.includes(key))]));
        setCursor(response.cursor && response.cursor !== "0" ? response.cursor : null);
      } catch (caught) {
        setError(caught);
      } finally {
        setBusy(false);
      }
    },
    [connection.id]
  );

  useEffect(() => {
    void scan("0", true);
  }, [scan]);

  return (
    <Stack spacing={1.5}>
      <Typography variant="subtitle1" fontWeight={700}>
        {pick(language, T.redisTitle)}
      </Typography>
      {dbsize !== null ? (
        <Typography variant="body2" color="text.secondary">
          {say(language, T.redisKeysCount, { count: dbsize })}
        </Typography>
      ) : null}
      <Stack
        component="form"
        direction={{ xs: "column", sm: "row" }}
        spacing={1}
        onSubmit={(event) => {
          event.preventDefault();
          activePattern.current = pattern.trim() || "*";
          setSelected(null);
          void scan("0", true);
        }}
      >
        <TextField size="small" label={pick(language, T.redisPattern)} helperText={pick(language, T.redisPatternHint)} value={pattern} onChange={(event) => setPattern(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
        <Box>
          <Button type="submit" variant="contained" disabled={busy}>
            {pick(language, T.redisSearch)}
          </Button>
        </Box>
      </Stack>
      {busy ? <LinearProgress /> : null}
      {error ? <FriendlyError error={error} onRetry={() => void scan("0", true)} /> : null}
      {!busy && !error && keys.length === 0 ? <Typography color="text.secondary">{pick(language, T.redisNoKeys)}</Typography> : null}
      <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems="stretch">
        {keys.length > 0 ? (
          <Box sx={{ flex: "0 0 320px", maxHeight: 420, overflowY: "auto", border: 1, borderColor: "divider", borderRadius: 1 }}>
            {keys.map((key) => (
              <ButtonBase
                key={key}
                onClick={() => setSelected(key)}
                sx={{ display: "block", width: "100%", textAlign: "start", px: 1.5, py: 1, minHeight: 44, bgcolor: selected === key ? "action.selected" : "transparent", borderBottom: 1, borderColor: "divider" }}
              >
                <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
                  <Ltr>{key}</Ltr>
                </Typography>
              </ButtonBase>
            ))}
            {cursor ? (
              <Box sx={{ p: 1 }}>
                <Button size="small" fullWidth disabled={busy} onClick={() => void scan(cursor, false)}>
                  {pick(language, T.redisMore)}
                </Button>
              </Box>
            ) : null}
          </Box>
        ) : null}
        {selected ? <RedisKeyView key={selected} connection={connection} redisKey={selected} /> : null}
      </Stack>
    </Stack>
  );
}

function RedisKeyView({ connection, redisKey }: { connection: Connection; redisKey: string }) {
  const { language } = useKit();
  const [type, setType] = useState<string | null>(null);
  const [ttl, setTtl] = useState<number | null>(null);
  const [value, setValue] = useState<QueryResponse | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const typeResponse = await runQuery(connection.id, { redis: { command: "TYPE", args: [redisKey] } });
        const kind = String(typeResponse.rows[0]?.[0] ?? "none");
        const ttlResponse = await runQuery(connection.id, { redis: { command: "TTL", args: [redisKey] } });
        if (!alive) return;
        setType(kind);
        setTtl(Number(ttlResponse.rows[0]?.[0] ?? -1));
        const builder = REDIS_VALUE_COMMAND[kind];
        if (builder) {
          const [command, ...args] = builder(redisKey);
          const valueResponse = await runQuery(connection.id, { redis: { command, args } });
          if (alive) setValue(valueResponse);
        }
      } catch (caught) {
        if (alive) setError(caught);
      }
    })();
    return () => {
      alive = false;
    };
  }, [connection.id, redisKey]);

  return (
    <Box sx={{ flex: 1, minWidth: 0 }}>
      <Typography variant="subtitle2" sx={{ fontFamily: "monospace", wordBreak: "break-all", mb: 1 }}>
        <Ltr>{redisKey}</Ltr>
      </Typography>
      {error ? <FriendlyError error={error} /> : null}
      {!type && !error ? <LinearProgress /> : null}
      {type ? (
        <KeyValueList
          dense
          items={[
            { label: pick(language, T.redisType), value: <Ltr mono>{type}</Ltr> },
            { label: pick(language, T.redisTtl), value: ttl !== null && ttl >= 0 ? say(language, T.redisSeconds, { count: ttl }) : pick(language, T.redisNoTtl) }
          ]}
        />
      ) : null}
      {value ? (
        <Stack spacing={1} sx={{ mt: 1 }}>
          {type && type !== "string" && type !== "hash" ? (
            <Typography variant="caption" color="text.secondary">
              {pick(language, T.redisFirstItems)}
            </Typography>
          ) : null}
          <TruncationNotice reason={value.truncated ? value.truncated_reason ?? "row_limit" : null} cells={value.truncated_cells} />
          <RowsTable columns={value.columns.map(columnName)} rows={value.rows} label={pick(language, T.redisValue)} />
        </Stack>
      ) : null}
    </Box>
  );
}

// ── Query editor (Advanced) ─────────────────────────────────────────────────────────────

function QueryEditor({ connection, canWrite }: { connection: Connection; canWrite: boolean }) {
  const { language } = useKit();
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const engine = connection.engine;
  const isSql = SQL_ENGINES.includes(engine);
  const [text, setText] = useState(isSql ? "SELECT 1" : engine === "mongo" ? MONGO_SAMPLE : "");
  const [command, setCommand] = useState("INFO");
  const [args, setArgs] = useState("");
  const [database, setDatabase] = useState("");
  const [writeMode, setWriteMode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<QueryResponse | null>(null);
  const [preview, setPreview] = useState<QueryResponse | null>(null);
  const [error, setError] = useState<unknown>(null);

  const token = connection.write_confirmation ?? `WRITE ${connection.name}`;
  const typed: ConfirmWord = { word: { fa: `نوشتن ${connection.name}`, en: token }, token };

  const buildBody = (): Record<string, unknown> | string => {
    const body: Record<string, unknown> = {};
    if (isSql) {
      if (!text.trim()) return pick(language, T.emptyQuery);
      body.text = text;
    } else if (engine === "mongo") {
      try {
        body.mongo = JSON.parse(text);
      } catch {
        return pick(language, T.badJson);
      }
    } else {
      if (!command.trim()) return pick(language, T.emptyQuery);
      body.redis = { command: command.trim().toUpperCase(), args: args.split("\n").map((line) => line.trim()).filter(Boolean) };
    }
    if (database.trim() && engine !== "postgres" && engine !== "redis") body.database = database.trim();
    return body;
  };

  const execute = async (mode: "read" | "preview" | "write") => {
    const body = buildBody();
    if (typeof body === "string") {
      setError(new Error(body));
      return;
    }
    if (mode === "write") {
      const ok = await ask({
        title: say(language, T.writeTitle, { name: connection.name }),
        body: preview?.affected_rows !== undefined && preview?.affected_rows !== null ? `${pick(language, T.writeBody)} ${say(language, T.previewResult, { count: preview.affected_rows })}` : pick(language, T.writeBody),
        severity: "destructive",
        typed,
        confirmLabel: pick(language, T.writeConfirm)
      });
      if (!ok) return;
    }
    if (mode !== "read") {
      body.write = true;
      body.confirmation = token;
      if (mode === "preview") body.dry_run = true;
    }
    setBusy(true);
    setError(null);
    try {
      const response = await runQuery(connection.id, body);
      if (mode === "preview") {
        setPreview(response);
      } else {
        setResult(response);
        setPreview(null);
        if (mode === "write") notify({ message: say(language, T.writeDone, { count: response.affected_rows ?? 0 }), tone: "success" });
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const exportCsv = async () => {
    const body = buildBody();
    if (typeof body === "string") {
      setError(new Error(body));
      return;
    }
    try {
      const file = await downloadCsv(connection.id, body, `${connection.name}.csv`);
      notify({ message: say(language, T.exported, { file }), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
  };

  return (
    <SectionCard title={pick(language, T.queryTitle)} hint={pick(language, T.queryHint)} tone={writeMode ? "danger" : "default"}>
      <Stack spacing={1.5}>
        {engine === "redis" ? (
          <>
            <TextField size="small" label={pick(language, T.queryRedisCommand)} value={command} onChange={(event) => setCommand(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} sx={{ maxWidth: 240 }} />
            <TextField label={pick(language, T.queryRedisArgs)} value={args} onChange={(event) => setArgs(event.target.value)} multiline minRows={2} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, style: { fontFamily: "monospace" } } }} />
          </>
        ) : (
          <TextField
            label={pick(language, isSql ? T.querySql : T.queryMongo)}
            helperText={engine === "mongo" ? pick(language, T.queryMongoHint) : undefined}
            value={text}
            onChange={(event) => {
              setText(event.target.value);
              setPreview(null);
            }}
            multiline
            minRows={4}
            slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, style: { fontFamily: "monospace" } } }}
          />
        )}
        {engine === "mysql" || engine === "mariadb" || engine === "mongo" ? (
          <TextField size="small" label={pick(language, T.queryDatabase)} value={database} onChange={(event) => setDatabase(event.target.value)} sx={{ maxWidth: 260 }} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
        ) : null}
        {canWrite ? (
          <FormControlLabel
            control={
              <Switch
                checked={writeMode}
                color="error"
                onChange={(event) => {
                  setWriteMode(event.target.checked);
                  setPreview(null);
                }}
              />
            }
            label={pick(language, T.writeMode)}
          />
        ) : (
          <NoAccess needs="db:write" />
        )}
        {writeMode ? <Notice tone="warning">{pick(language, T.writeModeHint)}</Notice> : null}
        <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
          {writeMode ? (
            <>
              <Button variant="outlined" disabled={busy || engine === "redis"} onClick={() => void execute("preview")}>
                {pick(language, T.preview)}
              </Button>
              <Button variant="contained" color="error" startIcon={<PlayArrowRoundedIcon />} disabled={busy} onClick={() => void execute("write")}>
                {busy ? pick(language, T.running) : pick(language, T.run)}
              </Button>
            </>
          ) : (
            <>
              <Button variant="contained" startIcon={<PlayArrowRoundedIcon />} disabled={busy} onClick={() => void execute("read")}>
                {busy ? pick(language, T.running) : pick(language, T.run)}
              </Button>
              {engine !== "redis" ? (
                <Button variant="outlined" startIcon={<DownloadRoundedIcon />} disabled={busy} onClick={() => void exportCsv()}>
                  {pick(language, T.exportCsv)}
                </Button>
              ) : null}
            </>
          )}
        </Stack>
        {busy ? <LinearProgress /> : null}
        {error ? <FriendlyError error={error} onClose={() => setError(null)} /> : null}
        {preview ? <Notice tone="info">{say(language, T.previewResult, { count: preview.affected_rows ?? preview.matched ?? 0 })}</Notice> : null}
        {result ? (
          <Stack spacing={1}>
            <Typography variant="body2" color="text.secondary">
              {result.mode === "write" ? say(language, T.writeDone, { count: result.affected_rows ?? 0 }) : say(language, T.readDone, { count: result.row_count })}
              {result.elapsed_ms !== undefined ? ` · ${say(language, T.elapsed, { ms: Math.round(result.elapsed_ms) })}` : ""}
            </Typography>
            <TruncationNotice reason={result.truncated ? result.truncated_reason ?? "row_limit" : null} cells={result.truncated_cells} />
            {result.columns.length > 0 ? <RowsTable columns={result.columns.map(columnName)} rows={result.rows} label={pick(language, T.queryTitle)} /> : null}
            {result.statement_sha256 ? (
              <KeyValueList dense items={[{ label: pick(language, T.statementHash), value: <Ltr mono>{result.statement_sha256}</Ltr>, copy: result.statement_sha256 }]} />
            ) : null}
          </Stack>
        ) : null}
      </Stack>
      {dialog}
      {snackbar}
    </SectionCard>
  );
}
