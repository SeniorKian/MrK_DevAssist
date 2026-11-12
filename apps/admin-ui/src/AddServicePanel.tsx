/**
 * «افزودن سرویس» / Add a service (docs/44). The panel runs alone; every other part of DevAssist is
 * its own small program the operator adds from here. One card per service, and a wizard that:
 *
 *   1. picks where to run it (Dokploy, Coolify or plain Docker Compose),
 *   2. asks the few values that matter (with defaults),
 *   3. hands over a ready `compose.yaml` and `.env` (the `.env` carries a one-time pairing key)
 *      with step-by-step instructions for the chosen tool,
 *   4. connects the panel to the running service and checks it answers.
 *
 * Data: `GET /api/v1/install/catalog` (services:read); `POST /api/v1/install/{id}/bundle` and
 * `POST /api/v1/install/{id}/connect` (services:operate + the service's own write permission).
 *
 * Automatic install (docs/44 phase 6): `GET /api/v1/install/targets` lists the connected Dokploy /
 * Coolify with their projects, environments and servers; `POST /api/v1/install/{id}/auto` creates,
 * configures and deploys the stack there and pairs it; the wizard follows
 * `GET /api/v1/install/auto/jobs/{job}` and can retry the pairing with `.../connect`.
 * Coolify's URL and token are saved inline with `PUT /api/v1/coolify/config`.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Box, Button, Card, CardActions, CardContent, Grid, LinearProgress, MenuItem, Skeleton, Stack, TextField, Typography } from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import AccountTreeRoundedIcon from "@mui/icons-material/AccountTreeRounded";
import LayersRoundedIcon from "@mui/icons-material/LayersRounded";
import SupportAgentRoundedIcon from "@mui/icons-material/SupportAgentRounded";
import TravelExploreRoundedIcon from "@mui/icons-material/TravelExploreRounded";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";
import FolderRoundedIcon from "@mui/icons-material/FolderRounded";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import RocketLaunchRoundedIcon from "@mui/icons-material/RocketLaunchRounded";
import CloudQueueRoundedIcon from "@mui/icons-material/CloudQueueRounded";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import AutoModeRoundedIcon from "@mui/icons-material/AutoModeRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import { getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { pick, say, type Bi } from "./copy";
import { ActionWizard, ChoiceCards, CopyButton, CopyField, FriendlyError, Ltr, Notice, StatusPill, useKit, type WizardStep } from "./kit";
import type { Language } from "./i18n";
import { InstallStorage, useStorage } from "./InstallStorage";

// ── API types ────────────────────────────────────────────────────────────────

type Connection = "connected" | "unreachable" | "not_connected" | "planned" | "unavailable";
type Method = "dokploy" | "coolify" | "compose";

type EnvSpec = { name: string; default: string; help_fa: string; help_en: string; editable: boolean };

type CatalogItem = {
  id: string;
  availability: "ready" | "planned";
  same_host: boolean;
  image: string | null;
  needs_privileges_fa: string;
  needs_privileges_en: string;
  resources_fa: string;
  resources_en: string;
  methods: Method[];
  pairing: boolean;
  default_url: string | null;
  env: EnvSpec[];
  notes_fa: string[];
  notes_en: string[];
  connection: Connection;
  managed_by_environment: boolean;
  bundle_created_at: number | null;
};

type Bundle = { id: string; image: string; compose: string; env: string; pairing: boolean };

type Choice = Method | "auto";
type AutoTarget = "dokploy" | "coolify";
type TargetEnv = { id: string | null; name: string };
type TargetProject = { id: string; name: string; environments: TargetEnv[]; legacy?: boolean };
type TargetServer = { id: string; name: string; local: boolean; reachable: boolean | null };
type TargetState = {
  configured: boolean;
  allowed: boolean;
  reachable: boolean | null;
  error_code: string | null;
  projects: TargetProject[];
};
type Targets = {
  dokploy: TargetState & { panel_url: string | null };
  coolify: TargetState & { url: string | null; servers: TargetServer[] };
  same_host_required: boolean;
};
type JobPhase = "preparing" | "creating" | "configuring" | "deploying" | "waiting" | "connecting" | "done";
type AutoJob = {
  id: string;
  status: "running" | "succeeded" | "failed";
  phase: JobPhase;
  error_code: string | null;
  message: string | null;
  connection: Connection | null;
  deployed: boolean;
  reused: boolean;
  resource_url: string | null;
  warnings: string[];
};

const NEW_PROJECT = "__new__";

// ── copy ─────────────────────────────────────────────────────────────────────

const COPY = {
  intro: {
    fa: "پنل جدا از بقیه اجرا می‌شود. هر بخشی را که لازم دارید از اینجا اضافه کنید؛ برای هر کدام فایل‌های آماده و راهنمای قدم‌به‌قدم می‌گیرید.",
    en: "The panel runs on its own. Add each part you need from here; every one comes with ready files and step-by-step instructions."
  },
  loadFailed: { fa: "فهرست سرویس‌ها باز نشد.", en: "The service list didn't load." },
  install: { fa: "نصب", en: "Install" },
  reinstall: { fa: "نصب یا اتصال دوباره", en: "Reinstall or reconnect" },
  soon: { fa: "به‌زودی", en: "Coming soon" },
  plannedBody: {
    fa: "این بخش فعلاً داخل نسخه قدیمی یکپارچه است و در به‌روزرسانی بعدی برنامه جدای خودش را می‌گیرد.",
    en: "This part still lives in the old all-in-one build; the next update gives it its own program."
  },
  envManaged: {
    fa: "اتصال این بخش با متغیرهای محیطی سرور تنظیم شده و از اینجا عوض نمی‌شود.",
    en: "This connection is set by the server's environment variables and can't be changed here."
  },
  noPermission: { fa: "برای نصب، اجازه «روشن و خاموش کردن سرویس‌ها» لازم است.", en: "Installing needs the “start and stop services” permission." },
  sameHost: { fa: "باید روی همان سروری نصب شود که پنل روی آن است.", en: "Must run on the same server as the panel." },
  privileges: { fa: "دسترسی‌ها", en: "Access it needs" },
  resources: { fa: "منابع", en: "Resources" },
  wizardTitle: { fa: "افزودن «{name}»", en: "Add “{name}”" },
  stepMethod: { fa: "کجا اجرا شود؟", en: "Where?" },
  stepMethodHint: { fa: "ابزاری را انتخاب کنید که با آن برنامه‌ها را روی سرور بالا می‌آورید.", en: "Pick the tool you use to run apps on the server." },
  methodLabel: { fa: "روش نصب", en: "Install method" },
  dokploy: { fa: "Dokploy", en: "Dokploy" },
  dokployBody: { fa: "یک سرویس Compose در Dokploy می‌سازید و فایل‌ها را در آن می‌چسبانید.", en: "Create a Compose service in Dokploy and paste the files into it." },
  coolify: { fa: "Coolify", en: "Coolify" },
  coolifyBody: { fa: "یک منبع Compose در Coolify می‌سازید و فایل‌ها را در آن می‌چسبانید.", en: "Create a Compose resource in Coolify and paste the files into it." },
  compose: { fa: "Docker Compose روی سرور", en: "Docker Compose on the server" },
  composeBody: { fa: "دو فایل را در یک پوشه روی سرور می‌گذارید و یک دستور اجرا می‌کنید.", en: "Put two files in a folder on the server and run one command." },
  auto: { fa: "نصب خودکار از طرف پنل", en: "Automatic install by the panel" },
  autoBody: {
    fa: "پنل خودش در Dokploy یا Coolify سرویس را می‌سازد، فایل‌ها را در آن می‌گذارد، بالا می‌آورد و وصل می‌کند.",
    en: "The panel creates the service in Dokploy or Coolify, puts the files in, starts it and connects to it."
  },
  autoNotReady: {
    fa: "اول Dokploy یا Coolify را به پنل وصل کنید؛ در قدم بعد راهش را می‌بینید.",
    en: "Connect Dokploy or Coolify to the panel first; the next step shows how."
  },
  autoLoading: { fa: "در حال بررسی Dokploy و Coolify…", en: "Checking Dokploy and Coolify…" },
  ready: { fa: "آماده", en: "Ready" },
  stepTarget: { fa: "کجا ساخته شود؟", en: "Where to create it?" },
  stepTargetHint: { fa: "ابزار و پروژه‌ای را انتخاب کنید که پنل سرویس را در آن بسازد.", en: "Pick the tool and project the panel creates the service in." },
  targetLabel: { fa: "ابزار نصب", en: "Install tool" },
  targetOff: { fa: "وصل نیست", en: "Not connected" },
  targetDown: { fa: "جواب نمی‌دهد", en: "Not answering" },
  targetNoPermission: { fa: "اجازه انتشار در Dokploy را ندارید", en: "You can't deploy to Dokploy" },
  dokployAutoBody: { fa: "یک سرویس Compose در پروژه انتخابی ساخته و منتشر می‌شود.", en: "A Compose service is created and deployed in the project you pick." },
  coolifyAutoBody: { fa: "یک منبع Compose روی سرور انتخابی ساخته و اجرا می‌شود.", en: "A Compose resource is created and started on the server you pick." },
  connectDokploy: {
    fa: "Dokploy هنوز به پنل وصل نیست. نشانی و کلید دسترسی آن را در صفحه «برنامه‌های Dokploy» وارد کنید و برگردید.",
    en: "Dokploy isn't connected yet. Enter its address and access key on the “Dokploy apps” page, then come back."
  },
  openDokploy: { fa: "رفتن به برنامه‌های Dokploy", en: "Open Dokploy apps" },
  connectCoolify: {
    fa: "برای Coolify نشانی آن و یک کلید دسترسی را وارد کنید (در Coolify از بخش «Keys & Tokens» بسازید). کلید فقط رمزشده در پنل می‌ماند.",
    en: "For Coolify, enter its address and an access key (create one in Coolify under “Keys & Tokens”). The key stays encrypted in the panel only."
  },
  coolifyUrl: { fa: "نشانی Coolify", en: "Coolify address" },
  coolifyToken: { fa: "کلید دسترسی Coolify", en: "Coolify access key" },
  saveCoolify: { fa: "ذخیره و بررسی", en: "Save and check" },
  project: { fa: "پروژه", en: "Project" },
  newProject: { fa: "پروژه تازه «MrK DevAssist»", en: "New project “MrK DevAssist”" },
  environment: { fa: "محیط", en: "Environment" },
  server: { fa: "سرور", en: "Server" },
  thisServer: { fa: "(همین سرور)", en: "(this server)" },
  pickTarget: { fa: "یک ابزار وصل‌شده را انتخاب کنید.", en: "Pick a connected tool." },
  pickServer: { fa: "سروری را که پنل روی آن است انتخاب کنید.", en: "Pick the server the panel runs on." },
  sameHostAuto: {
    fa: "سرویس به شبکه داخلی پنل وصل می‌شود، پس Dokploy یا Coolify باید آن را روی همان سرور پنل اجرا کند.",
    en: "The service joins the panel's internal network, so Dokploy or Coolify must run it on the panel's own server."
  },
  serverNotLocal: {
    fa: "این سرور، سرور خود Coolify نیست. اگر پنل روی آن نیست، پنل به سرویس وصل نمی‌شود.",
    en: "This isn't Coolify's own server. If the panel doesn't run there, it can't reach the service."
  },
  installNow: { fa: "نصب", en: "Install" },
  stepProgress: { fa: "نصب", en: "Install" },
  stepProgressHint: { fa: "پنل سرویس را می‌سازد، بالا می‌آورد و به آن وصل می‌شود. چند دقیقه طول می‌کشد.", en: "The panel creates the service, starts it and connects to it. This takes a few minutes." },
  stillWorking: { fa: "هنوز در حال نصب است؛ کمی صبر کنید.", en: "Still installing; please wait." },
  retryConnect: { fa: "اتصال دوباره", en: "Connect again" },
  openThere: { fa: "دیدن در همان ابزار", en: "Open it there" },
  reused: { fa: "این سرویس از قبل در Dokploy بود و همان به‌روز شد؛ سرویس تازه‌ای ساخته نشد.", en: "This service was already in Dokploy and was updated in place; no new service was made." },
  storageUnchecked: {
    fa: "دستیار سرور وصل نبود، پس پوشه‌های داده بررسی نشدند. اگر سرویس بالا نیامد، مالک پوشه‌ها را بررسی کنید.",
    en: "The server agent wasn't connected, so the data folders weren't checked. If the service doesn't start, check the folders' owner."
  },
  composeKept: {
    fa: "فایل compose این سرویس را خودتان تغییر داده بودید، پس پنل آن را دست نزد و فقط متغیرهای لازم را گذاشت.",
    en: "You had changed this service's compose file, so the panel kept it and only set the variables it needs."
  },
  autoFailed: { fa: "نصب خودکار کامل نشد.", en: "The automatic install didn't finish." },
  finish: { fa: "تمام", en: "Done" },
  stepSettings: { fa: "تنظیمات", en: "Settings" },
  stepSettingsHint: { fa: "مقدارهای پیش‌فرض برای بیشتر سرورها درست است؛ فقط اگر لازم است عوض کنید.", en: "The defaults suit most servers; change them only if you need to." },
  noSettings: { fa: "این بخش تنظیمی لازم ندارد.", en: "This part needs no settings." },
  makeFiles: { fa: "ساختن فایل‌ها", en: "Create the files" },
  stepFiles: { fa: "اجرا", en: "Run it" },
  stepFilesHint: { fa: "این دو فایل را با قدم‌های زیر به کار ببرید.", en: "Use these two files with the steps below." },
  secretWarning: {
    fa: "فایل .env کلید اتصال این بخش به پنل را دارد و فقط همین یک بار نشان داده می‌شود. آن را جایی عمومی نگذارید.",
    en: "The .env file holds this part's key for the panel and is shown only this once. Don't put it anywhere public."
  },
  download: { fa: "دریافت {file}", en: "Download {file}" },
  composeFile: { fa: "فایل compose.yaml", en: "compose.yaml file" },
  envFile: { fa: "فایل .env", en: ".env file" },
  stepsTitle: { fa: "قدم‌ها", en: "Steps" },
  stepConnect: { fa: "اتصال", en: "Connect" },
  stepConnectHint: { fa: "وقتی سرویس بالا آمد، پنل به آن وصل می‌شود و جواب دادنش را امتحان می‌کند.", en: "Once the service is up, the panel connects to it and checks that it answers." },
  url: { fa: "نشانی داخلی سرویس", en: "Service's internal address" },
  urlHelp: { fa: "اگر در فایل compose چیزی را عوض نکرده‌اید، همین پیش‌فرض درست است.", en: "If you didn't change the compose file, keep the default." },
  connectNow: { fa: "اتصال و امتحان", en: "Connect and check" },
  connected: { fa: "وصل شد و جواب می‌دهد.", en: "Connected, and it answers." },
  unreachableHelp: {
    fa: "هنوز جواب نمی‌دهد. چند ثانیه صبر کنید تا بالا بیاید و دوباره امتحان کنید؛ اگر نشد، گزارش‌های همان سرویس را در Dokploy یا Coolify ببینید.",
    en: "It doesn't answer yet. Give it a few seconds to start and try again; if it still fails, check that service's logs in Dokploy or Coolify."
  },
  notFoundHelp: {
    fa: "پنل هنوز اثری از این سرویس نمی‌بیند. مطمئن شوید روی همین سرور و بعد از پنل بالا آمده است.",
    en: "The panel can't see this service yet. Make sure it runs on this server and was started after the panel."
  },
  doneTitle: { fa: "«{name}» اضافه شد", en: "“{name}” was added" },
  doneBody: { fa: "از این به بعد در «سرویس‌های من» دیده می‌شود.", en: "From now on it shows up in My services." }
} satisfies Record<string, Bi>;

const NAMES: Record<string, { name: Bi; body: Bi; icon: SvgIconComponent }> = {
  agent: {
    name: { fa: "دستیار سرور", en: "Server agent" },
    body: { fa: "وضعیت سرور و برنامه‌های Docker را به پنل می‌دهد. پایش، پشتیبان‌گیری و به‌روزرسانی‌ها به آن نیاز دارند.", en: "Gives the panel your server's health and its Docker apps. Monitoring, backups and updates need it." },
    icon: SupportAgentRoundedIcon
  },
  dns: {
    name: { fa: "سرور DNS", en: "DNS server" },
    body: { fa: "نام‌ها را برای سرور، کانتینرها و شبکه شما پاسخ می‌دهد و تبلیغ و بدافزار را می‌بندد.", en: "Answers names for your server, containers and network, and blocks ads and malware." },
    icon: TravelExploreRoundedIcon
  },
  firewall: {
    name: { fa: "فایروال", en: "Firewall" },
    body: { fa: "حمله‌ها و تلاش‌های ورود ناموفق را می‌بیند و نشانی‌های مزاحم را می‌بندد.", en: "Spots attacks and failed logins and blocks the addresses behind them." },
    icon: ShieldRoundedIcon
  },
  s3: {
    name: { fa: "فضای فایل (S3)", en: "File storage (S3)" },
    body: { fa: "فضای فایل سازگار با S3 برای برنامه‌ها و پشتیبان‌ها.", en: "S3-compatible file storage for apps and backups." },
    icon: FolderRoundedIcon
  },
  npm: {
    name: { fa: "مخزن npm", en: "npm registry" },
    body: { fa: "بسته‌های npm را برای پروژه‌ها نگه می‌دارد و از اینترنت می‌آورد.", en: "Caches npm packages for your projects." },
    icon: Inventory2RoundedIcon
  },
  pypi: {
    name: { fa: "مخزن PyPI", en: "PyPI registry" },
    body: { fa: "بسته‌های پایتون را برای پروژه‌ها نگه می‌دارد و از اینترنت می‌آورد.", en: "Caches Python packages for your projects." },
    icon: Inventory2RoundedIcon
  },
  git: {
    name: { fa: "Git (مخزن کد)", en: "Git (code repositories)" },
    body: {
      fa: "مخزن‌های کد تیم شما روی همین سرور، و آینه مخزن‌های GitHub و GitLab تا همیشه نسخه‌ای در دسترس باشد.",
      en: "Your team's code repositories on this server, and mirrors of GitHub and GitLab repositories so a copy is always at hand."
    },
    icon: AccountTreeRoundedIcon
  },
  registry: {
    name: { fa: "مخزن ایمیج Docker", en: "Docker image registry" },
    body: {
      fa: "ایمیج‌های خصوصی شما، و آینه Docker Hub و ghcr.io با منبع‌های پشتیبان تا دریافت ایمیج‌ها قطع نشود.",
      en: "Your private images, and a mirror of Docker Hub and ghcr.io with fallback sources so image pulls keep working."
    },
    icon: LayersRoundedIcon
  }
};

const CONNECTION: Record<Connection, { tone: "ok" | "warn" | "off" | "info"; label: Bi }> = {
  connected: { tone: "ok", label: { fa: "نصب و وصل است", en: "Installed and connected" } },
  unreachable: { tone: "warn", label: { fa: "وصل است ولی جواب نمی‌دهد", en: "Connected but not answering" } },
  not_connected: { tone: "off", label: { fa: "نصب نشده", en: "Not installed" } },
  planned: { tone: "info", label: { fa: "به‌زودی", en: "Coming soon" } },
  unavailable: { tone: "off", label: { fa: "در دسترس نیست", en: "Unavailable" } }
};

const PHASES: { key: JobPhase; label: Bi }[] = [
  { key: "creating", label: { fa: "ساختن سرویس", en: "Creating the service" } },
  { key: "configuring", label: { fa: "گذاشتن فایل‌ها", en: "Adding the files" } },
  { key: "deploying", label: { fa: "شروع انتشار", en: "Starting the deployment" } },
  { key: "waiting", label: { fa: "صبر تا بالا آمدن", en: "Waiting for it to start" } },
  { key: "connecting", label: { fa: "اتصال و امتحان", en: "Connecting and checking" } },
  { key: "done", label: { fa: "تمام شد", en: "Done" } }
];

const JOB_ERRORS: Record<string, Bi> = {
  deploy_failed: {
    fa: "انتشار ناموفق بود. گزارش انتشار همان سرویس را در Dokploy ببینید.",
    en: "The deployment failed. Check that service's deployment log in Dokploy."
  },
  deploy_timeout: { fa: "بالا آمدن سرویس خیلی طول کشید. گزارش‌های آن را در همان ابزار ببینید.", en: "The service took too long to start. Check its logs in that tool." },
  connect_failed: {
    fa: "سرویس بالا آمد ولی هنوز به پنل جواب نمی‌دهد. چند ثانیه بعد «اتصال دوباره» را بزنید و مطمئن شوید روی همین سرور اجرا شده است.",
    en: "The service started but doesn't answer the panel yet. Press “Connect again” in a few seconds, and make sure it runs on this server."
  },
  already_installed: {
    fa: "این سرویس همین حالا در پروژه دیگری از Dokploy اجرا می‌شود. همان پروژه را انتخاب کنید (یا هیچ پروژه‌ای را) تا همان به‌روز شود، یا اول آن یکی را پاک کنید.",
    en: "This service already runs in another Dokploy project. Pick that project (or none) to update it in place, or remove the other one first."
  },
  server_required: { fa: "Coolify چند سرور دارد؛ سروری را که پنل روی آن است انتخاب کنید.", en: "Coolify has several servers; pick the one the panel runs on." },
  server_not_found: { fa: "این سرور در Coolify پیدا نشد.", en: "That server wasn't found in Coolify." },
  project_not_found: { fa: "این پروژه پیدا نشد؛ فهرست را تازه کنید.", en: "That project wasn't found; refresh the list." },
  environment_not_found: { fa: "این محیط پیدا نشد؛ فهرست را تازه کنید.", en: "That environment wasn't found; refresh the list." },
  environment_required: { fa: "یک محیط از پروژه Dokploy انتخاب کنید.", en: "Pick an environment of the Dokploy project." },
  dokploy_auth_failed: { fa: "Dokploy کلید دسترسی را نپذیرفت.", en: "Dokploy didn't accept the access key." },
  coolify_auth_failed: { fa: "Coolify کلید دسترسی را نپذیرفت یا دسترسی برنامه‌ها در تنظیمات آن خاموش است.", en: "Coolify didn't accept the access key, or its API is turned off in its settings." },
  dokploy_unreachable: { fa: "Dokploy در دسترس نیست.", en: "Dokploy can't be reached." },
  coolify_unreachable: { fa: "Coolify در دسترس نیست.", en: "Coolify can't be reached." },
  dokploy_rejected: { fa: "Dokploy درخواست را نپذیرفت.", en: "Dokploy refused the request." },
  coolify_rejected: { fa: "Coolify درخواست را نپذیرفت.", en: "Coolify refused the request." }
};

const METHOD_STEPS: Record<Method, Bi[]> = {
  dokploy: [
    { fa: "در Dokploy پروژه‌ای را باز کنید (یا بسازید) و «Create Service» و بعد «Compose» را بزنید.", en: "In Dokploy open (or create) a project and choose “Create Service”, then “Compose”." },
    { fa: "در بخش «General» منبع را «Raw» بگذارید و متن compose.yaml را در آن بچسبانید و ذخیره کنید.", en: "Under “General”, set the source to “Raw”, paste compose.yaml and save." },
    { fa: "در زبانه «Environment» متن فایل .env را بچسبانید و ذخیره کنید.", en: "In the “Environment” tab paste the .env file and save." },
    { fa: "«Deploy» را بزنید و صبر کنید تا کار تمام شود؛ بعد به قدم آخر همین صفحه بیایید.", en: "Click “Deploy” and wait until it finishes; then come to the last step here." }
  ],
  coolify: [
    { fa: "در Coolify، در همان سروری که پنل روی آن است، «+ New» و بعد «Docker Compose Empty» را بزنید.", en: "In Coolify, on the server that runs the panel, choose “+ New”, then “Docker Compose Empty”." },
    { fa: "متن compose.yaml را بچسبانید و ذخیره کنید.", en: "Paste compose.yaml and save." },
    { fa: "در «Environment Variables» مقدارهای فایل .env را وارد کنید (در «Developer view» می‌توانید کل متن را یکجا بچسبانید).", en: "In “Environment Variables” enter the values from .env (“Developer view” lets you paste the whole file)." },
    { fa: "«Deploy» را بزنید و صبر کنید تا کار تمام شود؛ بعد به قدم آخر همین صفحه بیایید.", en: "Click “Deploy” and wait until it finishes; then come to the last step here." }
  ],
  compose: [
    { fa: "روی همان سرور یک پوشه بسازید، مثلاً /opt/mrk-{id}.", en: "On the same server create a folder, for example /opt/mrk-{id}." },
    { fa: "دو فایل compose.yaml و .env را در آن پوشه بگذارید.", en: "Put the two files, compose.yaml and .env, in that folder." },
    { fa: "در همان پوشه این دستور را اجرا کنید:", en: "In that folder run:" }
  ]
};

// ── helpers ──────────────────────────────────────────────────────────────────

function text(language: Language, fa: string, en: string) {
  return language === "fa" ? fa || en : en || fa;
}

export function serviceName(language: Language, id: string) {
  const entry = NAMES[id];
  return entry ? pick(language, entry.name) : id;
}

function downloadText(fileName: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function CodeBlock({ title, value, fileName }: { title: string; value: string; fileName: string }) {
  const { language } = useKit();
  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
        <Typography variant="subtitle2" sx={{ flex: 1 }}>{title}</Typography>
        <CopyButton value={value} />
        <Button size="small" startIcon={<DownloadRoundedIcon />} onClick={() => downloadText(fileName, value)}>
          {say(language, COPY.download, { file: fileName })}
        </Button>
      </Stack>
      <Box
        component="pre"
        dir="ltr"
        sx={{
          m: 0, p: 1.5, maxHeight: 260, overflow: "auto", borderRadius: 1, fontSize: 12, lineHeight: 1.6,
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
          bgcolor: "action.hover", border: 1, borderColor: "divider", whiteSpace: "pre"
        }}
      >
        {value}
      </Box>
    </Box>
  );
}

// ── wizard ───────────────────────────────────────────────────────────────────

function targetIssue(state: TargetState | undefined): Bi | null {
  if (!state || !state.configured) return COPY.targetOff;
  if (!state.allowed) return COPY.targetNoPermission;
  if (state.reachable === false) return COPY.targetDown;
  return null;
}

function JobProgress({ job }: { job: AutoJob | null }) {
  const { language } = useKit();
  if (!job) return <LinearProgress />;
  const current = PHASES.findIndex((phase) => phase.key === job.phase);
  const failed = job.status === "failed";
  const errorCopy = job.error_code ? JOB_ERRORS[job.error_code] : undefined;
  return (
    <Stack spacing={2}>
      {job.status === "running" ? <LinearProgress /> : null}
      <Box component="ol" sx={{ m: 0, ps: 3, "& li": { mb: 0.75 } }}>
        {PHASES.map((phase, index) => {
          const tone = index < current || job.status === "succeeded" ? "ok" : index === current ? (failed ? "warn" : "busy") : "off";
          return (
            <li key={phase.key}>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography sx={{ flex: 1 }}>{pick(language, phase.label)}</Typography>
                {tone !== "off" ? <StatusPill tone={tone} label={pick(language, tone === "ok" ? COPY.ready : tone === "warn" ? COPY.autoFailed : COPY.stillWorking)} /> : null}
              </Stack>
            </li>
          );
        })}
      </Box>
      {job.reused ? <Notice tone="info">{pick(language, COPY.reused)}</Notice> : null}
      {job.warnings.includes("server_not_local") ? <Notice tone="warning">{pick(language, COPY.serverNotLocal)}</Notice> : null}
      {job.warnings.includes("compose_customized") ? <Notice tone="info">{pick(language, COPY.composeKept)}</Notice> : null}
      {job.warnings.includes("storage_unchecked") ? <Notice tone="info">{pick(language, COPY.storageUnchecked)}</Notice> : null}
      {job.status === "succeeded" ? <Notice tone="success">{pick(language, COPY.connected)}</Notice> : null}
      {failed ? (
        <Notice tone={job.error_code === "connect_failed" ? "warning" : "error"}>
          {errorCopy ? pick(language, errorCopy) : pick(language, COPY.autoFailed)}
          {job.message ? <Box sx={{ mt: 0.5 }}><Ltr>{job.message}</Ltr></Box> : null}
        </Notice>
      ) : null}
      {job.resource_url ? (
        <Box>
          <Button href={job.resource_url} target="_blank" rel="noopener noreferrer" sx={{ minHeight: 44 }}>{pick(language, COPY.openThere)}</Button>
        </Box>
      ) : null}
    </Stack>
  );
}

function CoolifyInlineForm({ onSaved }: { onSaved: () => void }) {
  const { language } = useKit();
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await mutateJson("/api/v1/coolify/config", { method: "PUT", body: { url: url.trim(), token: token.trim() } });
      setToken("");
      onSaved();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Stack spacing={1.5}>
      <Typography variant="body2" color="text.secondary">{pick(language, COPY.connectCoolify)}</Typography>
      <TextField
        label={pick(language, COPY.coolifyUrl)}
        value={url}
        onChange={(event) => setUrl(event.target.value)}
        placeholder="http://coolify.lan:8000"
        slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
        size="small"
        fullWidth
      />
      <TextField
        label={pick(language, COPY.coolifyToken)}
        value={token}
        onChange={(event) => setToken(event.target.value)}
        type="password"
        autoComplete="off"
        slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
        size="small"
        fullWidth
      />
      {error !== null ? <FriendlyError error={error} scope="services" /> : null}
      <Box>
        <Button variant="outlined" disabled={busy || url.trim().length < 8 || token.trim().length < 16} onClick={() => void save()} sx={{ minHeight: 44 }}>
          {pick(language, COPY.saveCoolify)}
        </Button>
      </Box>
    </Stack>
  );
}

function InstallWizard({ item, onClose, onChanged }: { item: CatalogItem; onClose: () => void; onChanged: () => void }) {
  const { language } = useKit();
  const name = serviceName(language, item.id);
  const [method, setMethod] = useState<Choice | null>(item.methods[0] ?? null);
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(item.env.map((entry) => [entry.name, entry.default]))
  );
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [url, setUrl] = useState(item.default_url ?? "");
  const [connection, setConnection] = useState<Connection | null>(null);
  const [connectError, setConnectError] = useState<unknown>(null);
  const [connecting, setConnecting] = useState(false);
  // automatic install
  const [targets, setTargets] = useState<Targets | null>(null);
  const [targetsError, setTargetsError] = useState<unknown>(null);
  const [target, setTarget] = useState<AutoTarget | null>(null);
  const [projectId, setProjectId] = useState(NEW_PROJECT);
  const [environmentId, setEnvironmentId] = useState("");
  const [environmentName, setEnvironmentName] = useState("production");
  const [serverId, setServerId] = useState("");
  const [job, setJob] = useState<AutoJob | null>(null);
  const storage = useStorage(item.id);

  const autoSupported = item.methods.includes("dokploy") || item.methods.includes("coolify");
  const usable = (key: AutoTarget) => item.methods.includes(key) && targetIssue(targets?.[key]) === null;

  const loadTargets = useCallback(async (refresh = false, signal?: AbortSignal) => {
    try {
      const payload = await getJson<Targets>(`/api/v1/install/targets${refresh ? "?refresh=true" : ""}`, signal);
      setTargets(payload);
      setTargetsError(null);
    } catch (caught) {
      if (!isAbortError(caught)) setTargetsError(caught);
    }
  }, []);

  useEffect(() => {
    if (!autoSupported) return;
    const controller = new AbortController();
    void loadTargets(false, controller.signal);
    return () => controller.abort();
  }, [autoSupported, loadTargets]);

  // Pick sensible defaults once the lists arrive.
  useEffect(() => {
    if (!targets) return;
    setTarget((current) => current ?? (usable("dokploy") ? "dokploy" : usable("coolify") ? "coolify" : null));
    const local = targets.coolify.servers.find((server) => server.local) ?? (targets.coolify.servers.length === 1 ? targets.coolify.servers[0] : undefined);
    setServerId((current) => current || local?.id || "");
  }, [targets]);

  const projects = target ? targets?.[target].projects ?? [] : [];
  const project = projects.find((entry) => entry.id === projectId);

  useEffect(() => {
    if (target === "dokploy") setEnvironmentId(project?.environments[0]?.id ?? "");
    if (target === "coolify") {
      const names = project?.environments.map((env) => env.name) ?? [];
      setEnvironmentName((current) => (names.length === 0 || names.includes(current) ? current : names[0]));
    }
  }, [target, project]);

  // Follow the running job.
  useEffect(() => {
    if (!job || job.status !== "running") return;
    const timer = window.setTimeout(async () => {
      try {
        const next = await getJson<AutoJob>(`/api/v1/install/auto/jobs/${job.id}`);
        setJob(next);
        if (next.status === "succeeded") onChanged();
      } catch {
        setJob({ ...job });
      }
    }, 1500);
    return () => window.clearTimeout(timer);
  }, [job, onChanged]);

  const connect = async () => {
    setConnecting(true);
    setConnectError(null);
    try {
      const result = await mutateJson<{ connection: Connection }>(`/api/v1/install/${item.id}/connect`, {
        method: "POST",
        body: item.default_url && url.trim() && url.trim() !== item.default_url ? { url: url.trim() } : {}
      });
      setConnection(result.connection);
      onChanged();
      return result.connection;
    } catch (caught) {
      setConnectError(caught);
      return null;
    } finally {
      setConnecting(false);
    }
  };

  const startAuto = async () => {
    if (!target) throw new Error(pick(language, COPY.pickTarget));
    const body: Record<string, unknown> = { target, env: values, storage: storage.request };
    if (projectId !== NEW_PROJECT) body.project_id = projectId;
    if (target === "dokploy" && projectId !== NEW_PROJECT && environmentId) body.environment_id = environmentId;
    if (target === "coolify") {
      body.environment_name = environmentName || "production";
      if (serverId) body.server_id = serverId;
    }
    if (item.default_url && url.trim() && url.trim() !== item.default_url) body.url = url.trim();
    setJob(null);
    const started = await mutateJson<AutoJob>(`/api/v1/install/${item.id}/auto`, { method: "POST", body });
    setJob(started);
  };

  const autoReady = targets !== null && (usable("dokploy") || usable("coolify"));
  const methodOptions = [
    ...item.methods.map((key) => ({
      key: key as Choice,
      icon: key === "dokploy" ? RocketLaunchRoundedIcon : key === "coolify" ? CloudQueueRoundedIcon : TerminalRoundedIcon,
      title: pick(language, COPY[key]),
      body: pick(language, key === "dokploy" ? COPY.dokployBody : key === "coolify" ? COPY.coolifyBody : COPY.composeBody)
    })),
    ...(autoSupported
      ? [
          {
            key: "auto" as Choice,
            icon: AutoModeRoundedIcon,
            title: pick(language, COPY.auto),
            body: pick(language, targets === null && targetsError === null ? COPY.autoLoading : autoReady ? COPY.autoBody : COPY.autoNotReady),
            badges: autoReady ? <StatusPill tone="ok" label={pick(language, COPY.ready)} /> : undefined,
            disabled: targets === null
          }
        ]
      : [])
  ];

  const settingsStep = (auto: boolean): WizardStep => ({
    key: "settings",
    title: pick(language, COPY.stepSettings),
    hint: pick(language, COPY.stepSettingsHint),
    nextLabel: pick(language, auto ? COPY.installNow : COPY.makeFiles),
    onNext: auto
      ? startAuto
      : async () => {
          const result = await mutateJson<Bundle>(`/api/v1/install/${item.id}/bundle`, {
            method: "POST",
            body: { env: values, method: method === "auto" || !method ? "compose" : method, storage: storage.request }
          });
          setBundle(result);
          setConnection(null);
        },
    render: () => (
      <Stack spacing={2}>
        {item.env.length === 0 ? <Typography color="text.secondary">{pick(language, COPY.noSettings)}</Typography> : null}
        {item.env.map((entry) => (
          <TextField
            key={entry.name}
            label={<Ltr>{entry.name}</Ltr>}
            value={values[entry.name] ?? ""}
            onChange={(event) => setValues((current) => ({ ...current, [entry.name]: event.target.value }))}
            helperText={text(language, entry.help_fa, entry.help_en)}
            disabled={!entry.editable}
            slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
            size="small"
            fullWidth
          />
        ))}
        {auto && (item.id === "agent" || item.id === "s3") ? (
          <TextField
            label={pick(language, COPY.url)}
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            helperText={pick(language, COPY.urlHelp)}
            slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
            size="small"
            fullWidth
          />
        ) : null}
        <InstallStorage serviceId={item.id} storage={storage} />
        {(language === "fa" ? item.notes_fa : item.notes_en).map((note) => (
          <Notice key={note} tone="info">{note}</Notice>
        ))}
      </Stack>
    )
  });

  const methodStep: WizardStep = {
    key: "method",
    title: pick(language, COPY.stepMethod),
    hint: pick(language, COPY.stepMethodHint),
    validate: () => (method ? null : pick(language, COPY.stepMethodHint)),
    render: () => (
      <Stack spacing={2}>
        {item.same_host ? <Notice tone="info">{pick(language, COPY.sameHost)}</Notice> : null}
        <ChoiceCards label={pick(language, COPY.methodLabel)} options={methodOptions} value={method} onChange={(key) => setMethod(key)} />
      </Stack>
    )
  };

  const targetOptions = (["dokploy", "coolify"] as const)
    .filter((key) => item.methods.includes(key))
    .map((key) => {
      const issue = targetIssue(targets?.[key]);
      return {
        key,
        icon: key === "dokploy" ? RocketLaunchRoundedIcon : CloudQueueRoundedIcon,
        title: pick(language, COPY[key]),
        body: pick(language, key === "dokploy" ? COPY.dokployAutoBody : COPY.coolifyAutoBody),
        badges: <StatusPill tone={issue ? "off" : "ok"} label={pick(language, issue ?? COPY.ready)} />,
        disabled: key === "dokploy" && issue !== null
      };
    });

  const selectedServer = targets?.coolify.servers.find((server) => server.id === serverId);
  const coolifyNeedsSetup = target === "coolify" && !targets?.coolify.configured;

  const targetStep: WizardStep = {
    key: "target",
    title: pick(language, COPY.stepTarget),
    hint: pick(language, COPY.stepTargetHint),
    validate: () => {
      if (!target || !usable(target)) return pick(language, COPY.pickTarget);
      if (target === "coolify" && !serverId) return pick(language, COPY.pickServer);
      return null;
    },
    render: () => (
      <Stack spacing={2}>
        <Notice tone="info">{pick(language, COPY.sameHostAuto)}</Notice>
        {targetsError !== null ? <FriendlyError error={targetsError} scope="services" onRetry={() => void loadTargets(true)} /> : null}
        <ChoiceCards label={pick(language, COPY.targetLabel)} options={targetOptions} value={target} onChange={(key) => setTarget(key)} />
        {targets && !targets.dokploy.configured && item.methods.includes("dokploy") ? (
          <Notice tone="info" action={<Button color="inherit" size="small" href="#/server/apps" onClick={onClose} sx={{ minHeight: 40 }}>{pick(language, COPY.openDokploy)}</Button>}>
            {pick(language, COPY.connectDokploy)}
          </Notice>
        ) : null}
        {coolifyNeedsSetup ? <CoolifyInlineForm onSaved={() => void loadTargets(true)} /> : null}
        {target && usable(target) ? (
          <Stack spacing={2}>
            <TextField select label={pick(language, COPY.project)} value={projectId} onChange={(event) => setProjectId(event.target.value)} size="small" fullWidth>
              <MenuItem value={NEW_PROJECT}>{pick(language, COPY.newProject)}</MenuItem>
              {projects.map((entry) => (
                <MenuItem key={entry.id} value={entry.id}>{entry.name}</MenuItem>
              ))}
            </TextField>
            {target === "dokploy" && project && !project.legacy && project.environments.length > 0 ? (
              <TextField select label={pick(language, COPY.environment)} value={environmentId} onChange={(event) => setEnvironmentId(event.target.value)} size="small" fullWidth>
                {project.environments.map((env) => (
                  <MenuItem key={env.id ?? env.name} value={env.id ?? ""}>{env.name}</MenuItem>
                ))}
              </TextField>
            ) : null}
            {target === "coolify" && project && project.environments.length > 0 ? (
              <TextField select label={pick(language, COPY.environment)} value={environmentName} onChange={(event) => setEnvironmentName(event.target.value)} size="small" fullWidth>
                {project.environments.map((env) => (
                  <MenuItem key={env.name} value={env.name}>{env.name}</MenuItem>
                ))}
              </TextField>
            ) : null}
            {target === "coolify" ? (
              <TextField select label={pick(language, COPY.server)} value={serverId} onChange={(event) => setServerId(event.target.value)} size="small" fullWidth>
                {(targets?.coolify.servers ?? []).map((server) => (
                  <MenuItem key={server.id} value={server.id}>
                    {server.name} {server.local ? pick(language, COPY.thisServer) : ""}
                  </MenuItem>
                ))}
              </TextField>
            ) : null}
            {target === "coolify" && selectedServer && !selectedServer.local ? <Notice tone="warning">{pick(language, COPY.serverNotLocal)}</Notice> : null}
          </Stack>
        ) : null}
      </Stack>
    )
  };

  const progressStep: WizardStep = {
    key: "progress",
    title: pick(language, COPY.stepProgress),
    hint: pick(language, COPY.stepProgressHint),
    render: () => <JobProgress job={job} />
  };

  const manualSteps: WizardStep[] = [
    {
      key: "files",
      title: pick(language, COPY.stepFiles),
      hint: pick(language, COPY.stepFilesHint),
      render: () =>
        bundle ? (
          <Stack spacing={2}>
            <Typography variant="subtitle2">{pick(language, COPY.stepsTitle)}</Typography>
            <Box component="ol" sx={{ m: 0, ps: 3, "& li": { mb: 1, lineHeight: 1.9 } }}>
              {METHOD_STEPS[method === "auto" || !method ? "compose" : method].map((step) => (
                <li key={step.en}>{say(language, step, { id: item.id })}</li>
              ))}
            </Box>
            {method === "compose" ? <CopyField label={pick(language, COPY.compose)} value="docker compose up -d" /> : null}
            {bundle.pairing ? <Notice tone="warning">{pick(language, COPY.secretWarning)}</Notice> : null}
            <CodeBlock title={pick(language, COPY.composeFile)} value={bundle.compose} fileName="compose.yaml" />
            <CodeBlock title={pick(language, COPY.envFile)} value={bundle.env} fileName=".env" />
          </Stack>
        ) : null
    },
    {
      key: "connect",
      title: pick(language, COPY.stepConnect),
      hint: pick(language, COPY.stepConnectHint),
      render: () => (
        <Stack spacing={2}>
          {item.id === "agent" || item.id === "s3" ? (
            <TextField
              label={pick(language, COPY.url)}
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              helperText={pick(language, COPY.urlHelp)}
              slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
              size="small"
              fullWidth
            />
          ) : null}
          {connecting ? <StatusPill tone="busy" label={pick(language, COPY.connectNow)} /> : null}
          {connectError !== null ? <FriendlyError error={connectError} scope="services" onRetry={() => void connect()} /> : null}
          {connection === "connected" ? <Notice tone="success">{pick(language, COPY.connected)}</Notice> : null}
          {connection === "unreachable" ? <Notice tone="warning">{pick(language, COPY.unreachableHelp)}</Notice> : null}
          {connection === "not_connected" ? <Notice tone="warning">{pick(language, COPY.notFoundHelp)}</Notice> : null}
        </Stack>
      )
    }
  ];

  const auto = method === "auto";
  const steps: WizardStep[] = auto ? [methodStep, targetStep, settingsStep(true), progressStep] : [methodStep, settingsStep(false), ...manualSteps];

  const finishAuto = async () => {
    if (!job || job.status === "running") throw new Error(pick(language, COPY.stillWorking));
    if (job.status === "succeeded") return;
    if (job.deployed) {
      const next = await mutateJson<AutoJob>(`/api/v1/install/auto/jobs/${job.id}/connect`, { method: "POST", body: {} });
      setJob(next);
      if (next.status === "succeeded") {
        onChanged();
        return;
      }
      throw new Error(pick(language, JOB_ERRORS.connect_failed));
    }
    const errorCopy = job.error_code ? JOB_ERRORS[job.error_code] : undefined;
    throw new Error(pick(language, errorCopy ?? COPY.autoFailed));
  };

  return (
    <ActionWizard
      open
      title={say(language, COPY.wizardTitle, { name })}
      steps={steps}
      finishLabel={pick(language, auto ? (job?.status === "failed" && job.deployed ? COPY.retryConnect : COPY.finish) : COPY.connectNow)}
      onClose={onClose}
      onFinish={async () => {
        if (auto) return finishAuto();
        const result = connection === "connected" ? connection : await connect();
        if (result !== "connected") {
          throw new Error(pick(language, result === "not_connected" ? COPY.notFoundHelp : COPY.unreachableHelp));
        }
      }}
      done={
        <Stack spacing={1}>
          <Typography variant="h6">{say(language, COPY.doneTitle, { name })}</Typography>
          <Typography color="text.secondary">{pick(language, COPY.doneBody)}</Typography>
        </Stack>
      }
    />
  );
}

// ── page ─────────────────────────────────────────────────────────────────────

function ServiceTile({ item, canInstall, onInstall }: { item: CatalogItem; canInstall: boolean; onInstall: (item: CatalogItem) => void }) {
  const { language } = useKit();
  const meta = NAMES[item.id];
  const Icon = meta?.icon ?? Inventory2RoundedIcon;
  const state = CONNECTION[item.connection] ?? CONNECTION.unavailable;
  const ready = item.availability === "ready";
  const privileges = text(language, item.needs_privileges_fa, item.needs_privileges_en);
  const resources = text(language, item.resources_fa, item.resources_en);
  return (
    <Card sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <CardContent sx={{ flex: 1 }}>
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 1 }}>
          <Icon color={ready ? "primary" : "disabled"} />
          <Typography variant="h6" sx={{ flex: 1, fontSize: 17 }}>{serviceName(language, item.id)}</Typography>
          <StatusPill tone={state.tone} label={pick(language, state.label)} />
        </Stack>
        {meta ? <Typography color="text.secondary" sx={{ mb: 1.5 }}>{pick(language, meta.body)}</Typography> : null}
        {ready ? (
          <Stack spacing={0.5}>
            {item.same_host ? <Typography variant="body2">{pick(language, COPY.sameHost)}</Typography> : null}
            {privileges ? <Typography variant="body2"><b>{pick(language, COPY.privileges)}:</b> {privileges}</Typography> : null}
            {resources ? <Typography variant="body2"><b>{pick(language, COPY.resources)}:</b> {resources}</Typography> : null}
          </Stack>
        ) : (
          <Typography variant="body2" color="text.secondary">{pick(language, COPY.plannedBody)}</Typography>
        )}
        {item.managed_by_environment ? <Box sx={{ mt: 1.5 }}><Notice tone="info">{pick(language, COPY.envManaged)}</Notice></Box> : null}
      </CardContent>
      <CardActions sx={{ px: 2, pb: 2 }}>
        {ready ? (
          <Button
            variant={item.connection === "connected" ? "text" : "contained"}
            startIcon={<AddRoundedIcon />}
            disabled={!canInstall || item.managed_by_environment}
            onClick={() => onInstall(item)}
            sx={{ minHeight: 44 }}
          >
            {pick(language, item.connection === "not_connected" ? COPY.install : COPY.reinstall)}
          </Button>
        ) : (
          <Button disabled sx={{ minHeight: 44 }}>{pick(language, COPY.soon)}</Button>
        )}
      </CardActions>
    </Card>
  );
}

export function AddServicePanel({ permissions, onChanged }: { permissions: readonly string[]; onChanged?: () => void }) {
  const { language } = useKit();
  const [items, setItems] = useState<CatalogItem[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [active, setActive] = useState<{ item: CatalogItem; key: number } | null>(null);
  const canInstall = hasPermission(permissions, "services:operate");

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const payload = await getJson<{ items: CatalogItem[] }>("/api/v1/install/catalog", signal);
      setItems(payload.items ?? []);
      setError(null);
    } catch (caught) {
      if (!isAbortError(caught)) setError(caught);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const ordered = useMemo(
    () => [...(items ?? [])].sort((a, b) => Number(b.availability === "ready") - Number(a.availability === "ready")),
    [items]
  );

  return (
    <Stack spacing={2.5}>
      <Typography color="text.secondary">{pick(language, COPY.intro)}</Typography>
      {!canInstall ? <Notice tone="info">{pick(language, COPY.noPermission)}</Notice> : null}
      {error !== null ? <FriendlyError error={error} title={pick(language, COPY.loadFailed)} scope="services" onRetry={() => void load()} /> : null}
      <Grid container spacing={2}>
        {items === null && error === null
          ? [0, 1, 2].map((index) => (
              <Grid key={index} size={{ xs: 12, md: 6, lg: 4 }}>
                <Skeleton variant="rounded" height={220} />
              </Grid>
            ))
          : ordered.map((item) => (
              <Grid key={item.id} size={{ xs: 12, md: 6, lg: 4 }}>
                <ServiceTile item={item} canInstall={canInstall} onInstall={(target) => setActive({ item: target, key: Date.now() })} />
              </Grid>
            ))}
      </Grid>
      {active ? (
        <InstallWizard
          key={active.key}
          item={active.item}
          onClose={() => {
            setActive(null);
            void load();
          }}
          onChanged={() => {
            void load();
            onChanged?.();
          }}
        />
      ) : null}
    </Stack>
  );
}
