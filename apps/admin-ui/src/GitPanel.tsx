/**
 * «مخزن‌های کد» / Code repositories (group `code`, tab `git`). Git on our own server (Gitea).
 *
 * - Status card: connected or not, version, «باز کردن Gitea».
 * - Repositories: search, mirror badge, copy clone addresses, sync now (mirrors), delete (typed name).
 * - «مخزن تازه» and «آینه از GitHub/GitLab» wizards. A mirror keeps a copy of an outside repository here,
 *   so projects keep working when GitHub is slow or blocked.
 * - Users (with a one-time password) and, in Advanced mode, organizations.
 *
 * Data: `/api/v1/git/*` (git:read; changes need git:write). A server without this part (404) or
 * without Gitea (`connected: false`) gets a friendly empty state.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Box, Button, Chip, FormControlLabel, MenuItem, Stack, Switch, TextField, Typography } from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import CloudSyncRoundedIcon from "@mui/icons-material/CloudSyncRounded";
import CodeRoundedIcon from "@mui/icons-material/CodeRounded";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import PersonAddRoundedIcon from "@mui/icons-material/PersonAddRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import SyncRoundedIcon from "@mui/icons-material/SyncRounded";
import { ApiError, copyText, getJson, mutateJson } from "./api";
import type { Language } from "./i18n";
import { nameConfirmation, pick, say, type Bi } from "./copy";
import {
  ActionWizard, Bytes, CopyButton, CopyField, EmptyState, FriendlyError, KeyValueList, Ltr, NameDialog, NoAccess, Notice, Num,
  OneTimeSecret, PasswordDialog, PasswordInput, RelativeTime, ResponsiveList, SectionCard, StatusPill, passwordProblem, suggestPassword,
  useCan, useConfirmAction, useKit, useUndoSnackbar, type PasswordRules
} from "./kit";
import { useVisibleInterval } from "./polling";

export type CodePanelProps = { language?: Language; permissions: string[]; onUnauthorized?: () => void };

type GitStatus = {
  connected?: boolean;
  reachable?: boolean;
  version?: string | null;
  url?: string | null;
  public_url?: string | null;
  admin_user?: string;
};

type GitRepo = {
  id?: number | string;
  full_name?: string;
  owner?: string;
  name?: string;
  private?: boolean;
  mirror?: boolean;
  description?: string;
  clone_http?: string;
  clone_ssh?: string;
  html_url?: string;
  updated_at?: string;
  size_kb?: number;
};

type GitUser = { id?: number | string; login?: string; email?: string; full_name?: string; admin?: boolean; active?: boolean; created?: string };
type GitOrg = { id?: number | string; name?: string; full_name?: string; repos_count?: number };

const API = "/api/v1/git";
/** Gitea user, organization and repository names. */
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const SOURCE_RE = /^https?:\/\/[^\s/]+\/\S+$/i;

const T = {
  missingTitle: { fa: "Git هنوز روی این سرور نصب نیست", en: "Git isn't installed on this server yet" },
  missingBody: {
    fa: "با Git کد پروژه‌هایتان روی سرور خودتان می‌ماند و می‌توانید از GitHub و GitLab آینه بگیرید. اول سرویس Gitea را اضافه کنید.",
    en: "With Git your projects' code stays on your own server, and you can mirror GitHub and GitLab. Add the Gitea service first."
  },
  oldServerTitle: { fa: "این نسخه از سرور هنوز بخش Git ندارد", en: "This server version has no Git section yet" },
  oldServerBody: { fa: "بعد از به‌روزرسانی DevAssist دوباره سر بزنید.", en: "Come back after updating DevAssist." },
  addService: { fa: "افزودن سرویس", en: "Add a service" },
  statusTitle: { fa: "سرویس Git", en: "Git service" },
  statusHint: { fa: "کد پروژه‌ها روی سرور خودتان، با همان دستورهای همیشگی Git.", en: "Your projects' code on your own server, with the usual Git commands." },
  state: { fa: "وضعیت", en: "Status" },
  notAnswering: { fa: "Gitea نصب است ولی الان جواب نمی‌دهد. چند دقیقه بعد دوباره نگاه کنید یا سرویس را در «سرویس‌های من» بررسی کنید.", en: "Gitea is installed but isn't answering right now. Look again in a few minutes, or check it under My services." },
  version: { fa: "نسخه", en: "Version" },
  publicUrl: { fa: "نشانی باز کردن", en: "Web address" },
  internalUrl: { fa: "نشانی داخلی", en: "Internal address" },
  adminUser: { fa: "کاربر مدیر", en: "Admin user" },
  openGitea: { fa: "باز کردن Gitea", en: "Open Gitea" },
  noPublicUrl: { fa: "هنوز دامنه‌ای ندارد؛ از «سرویس‌های من» یک دامنه به آن وصل کنید.", en: "No domain yet; attach one from My services." },
  reposTitle: { fa: "مخزن‌ها", en: "Repositories" },
  reposHint: { fa: "هر مخزن کد یک پروژه است. آینه‌ها خودکار با نسخه اصلی همگام می‌شوند.", en: "Each repository holds one project's code. Mirrors follow the original automatically." },
  search: { fa: "جست‌وجوی مخزن", en: "Search repositories" },
  newRepo: { fa: "مخزن تازه", en: "New repository" },
  newMirror: { fa: "آینه از GitHub/GitLab", en: "Mirror from GitHub/GitLab" },
  emptyRepos: { fa: "هنوز مخزنی ندارید", en: "You have no repositories yet" },
  emptyReposBody: { fa: "یک مخزن تازه بسازید، یا از یک پروژه GitHub آینه بگیرید تا همیشه در دسترس باشد.", en: "Create a repository, or mirror a GitHub project so it's always within reach." },
  noMatch: { fa: "مخزنی با این نام پیدا نشد", en: "No repository matches this name" },
  colName: { fa: "نام", en: "Name" },
  colDescription: { fa: "توضیح", en: "Description" },
  colUpdated: { fa: "آخرین تغییر", en: "Last change" },
  colSize: { fa: "حجم", en: "Size" },
  colClone: { fa: "نشانی دریافت", en: "Clone address" },
  mirror: { fa: "آینه", en: "Mirror" },
  private: { fa: "خصوصی", en: "Private" },
  public: { fa: "عمومی", en: "Public" },
  showMore: { fa: "مخزن‌های بیشتر", en: "More repositories" },
  shown: { fa: "{shown} از {total} مخزن", en: "{shown} of {total} repositories" },
  copyHttp: { fa: "کپی نشانی دریافت", en: "Copy clone address" },
  copySsh: { fa: "کپی نشانی SSH", en: "Copy SSH address" },
  copiedToast: { fa: "نشانی کپی شد.", en: "Address copied." },
  openRepo: { fa: "باز کردن در Gitea", en: "Open in Gitea" },
  syncNow: { fa: "همگام‌سازی الان", en: "Sync now" },
  syncStarted: { fa: "همگام‌سازی «{name}» شروع شد؛ چند لحظه بعد تغییرها را می‌بینید.", en: "Syncing “{name}” started; you'll see the changes in a moment." },
  remove: { fa: "پاک کردن", en: "Delete" },
  removeTitle: { fa: "مخزن «{name}» پاک شود؟", en: "Delete repository “{name}”?" },
  removeBody: { fa: "همه کد، تاریخچه و تنظیمات این مخزن از سرور پاک می‌شود. برای اطمینان، نام کامل مخزن را بنویسید.", en: "All code, history and settings of this repository are removed from the server. Type its full name to be sure." },
  removeMirrorNote: { fa: "نسخه اصلی در GitHub یا GitLab دست نمی‌خورد.", en: "The original on GitHub or GitLab is not touched." },
  removed: { fa: "مخزن «{name}» پاک شد.", en: "Repository “{name}” was deleted." },
  writeNeeded: { fa: "برای ساختن و پاک کردن مخزن", en: "to create and delete repositories" },
  // New repository wizard
  repoStepName: { fa: "نام", en: "Name" },
  repoStepNameHint: { fa: "یک نام کوتاه انگلیسی بدهید، مثل «my-app».", en: "Give it a short name, such as “my-app”." },
  repoStepAccess: { fa: "دسترسی", en: "Access" },
  repoStepAccessHint: { fa: "مخزن خصوصی را فقط کسانی می‌بینند که شما اجازه بدهید.", en: "Only people you allow can see a private repository." },
  owner: { fa: "صاحب مخزن", en: "Owner" },
  ownerHint: { fa: "خودتان یا یکی از سازمان‌ها.", en: "You, or one of your organizations." },
  repoName: { fa: "نام مخزن", en: "Repository name" },
  description: { fa: "توضیح کوتاه (دلخواه)", en: "Short description (optional)" },
  privateSwitch: { fa: "خصوصی باشد", en: "Keep it private" },
  createRepo: { fa: "ساخت مخزن", en: "Create repository" },
  repoCreated: { fa: "مخزن «{name}» ساخته شد.", en: "Repository “{name}” was created." },
  nameRule: { fa: "نام فقط حروف انگلیسی، عدد، نقطه، خط تیره و زیرخط باشد و با حرف یا عدد شروع شود.", en: "Use only letters, digits, dots, dashes and underscores, starting with a letter or digit." },
  // Mirror wizard
  mirrorTitle: { fa: "آینه گرفتن از GitHub یا GitLab", en: "Mirror from GitHub or GitLab" },
  mirrorStepSource: { fa: "از کجا؟", en: "From where?" },
  mirrorStepSourceHint: {
    fa: "یک نسخه از آن مخزن روی سرور خودتان ساخته و خودکار به‌روز می‌شود. اگر GitHub کند یا بسته شد، کار شما نمی‌خوابد.",
    en: "A copy of that repository is kept on your own server and updated automatically. If GitHub gets slow or blocked, your work goes on."
  },
  sourceUrl: { fa: "نشانی مخزن اصلی", en: "Original repository address" },
  sourceUrlHelp: { fa: "همان نشانی که در مرورگر می‌بینید، مثل https://github.com/owner/project", en: "The address you see in the browser, such as https://github.com/owner/project" },
  sourceRule: { fa: "نشانی باید با https:// شروع شود و به یک مخزن برسد.", en: "The address must start with https:// and point to a repository." },
  mirrorStepAuth: { fa: "اجازه دسترسی", en: "Access" },
  mirrorStepAuthHint: { fa: "فقط برای مخزن‌های خصوصی لازم است؛ برای مخزن عمومی خالی بگذارید.", en: "Only needed for private repositories; leave empty for a public one." },
  authUser: { fa: "نام کاربری در GitHub یا GitLab", en: "GitHub or GitLab username" },
  authToken: { fa: "کلید دسترسی شخصی", en: "Personal access token" },
  authTokenHelp: { fa: "در تنظیمات GitHub یا GitLab بسازید؛ فقط اجازه خواندن کافی است.", en: "Create it in your GitHub or GitLab settings; read access is enough." },
  mirrorStepWhere: { fa: "کجا و هر چند وقت؟", en: "Where and how often?" },
  mirrorStepWhereHint: { fa: "نام نسخه روی سرور شما و این‌که هر چند وقت با نسخه اصلی همگام شود.", en: "The copy's name on your server, and how often it follows the original." },
  interval: { fa: "همگام‌سازی خودکار", en: "Automatic sync" },
  interval1h: { fa: "هر ساعت", en: "Every hour" },
  interval8h: { fa: "هر ۸ ساعت", en: "Every 8 hours" },
  interval24h: { fa: "روزی یک بار", en: "Once a day" },
  intervalManual: { fa: "فقط وقتی خودم بخواهم", en: "Only when I ask" },
  intervalCustom: { fa: "فاصله دلخواه", en: "Custom interval" },
  intervalCustomHelp: { fa: "مثل 30m یا 12h", en: "Such as 30m or 12h" },
  intervalRule: { fa: "فاصله را مثل 30m یا 12h بنویسید.", en: "Write the interval like 30m or 12h." },
  createMirror: { fa: "ساخت آینه", en: "Create mirror" },
  mirrorCreated: { fa: "آینه «{name}» ساخته شد.", en: "Mirror “{name}” was created." },
  mirrorDone: { fa: "آینه ساخته شد. اولین دریافت کد ممکن است چند دقیقه طول بکشد.", en: "The mirror was created. The first copy may take a few minutes." },
  mirrorUseIt: { fa: "از این به بعد به‌جای نشانی GitHub از این نشانی استفاده کنید:", en: "From now on, use this address instead of the GitHub one:" },
  // Users
  usersTitle: { fa: "کاربران Git", en: "Git users" },
  usersHint: { fa: "کسانی که با Git کد را دریافت یا ارسال می‌کنند.", en: "People who pull or push code with Git." },
  newUser: { fa: "کاربر تازه", en: "New user" },
  emptyUsers: { fa: "هنوز کاربری ندارید", en: "You have no users yet" },
  emptyUsersBody: { fa: "برای هر هم‌تیمی یک کاربر بسازید تا با نام خودش کد بفرستد.", en: "Create a user for each teammate so they push code under their own name." },
  colLogin: { fa: "نام کاربری", en: "Username" },
  colEmail: { fa: "ایمیل", en: "Email" },
  colRole: { fa: "نقش", en: "Role" },
  colCreated: { fa: "ساخته‌شده", en: "Created" },
  roleAdmin: { fa: "مدیر", en: "Admin" },
  roleUser: { fa: "کاربر", en: "User" },
  active: { fa: "فعال", en: "Active" },
  inactive: { fa: "غیرفعال", en: "Inactive" },
  userStep: { fa: "مشخصات", en: "Details" },
  userStepHint: { fa: "یک رمز قوی پیشنهاد شده است. می‌توانید همین را نگه دارید یا رمز خودتان را بنویسید.", en: "A strong password is suggested. Keep it or type your own." },
  mustChange: { fa: "در اولین ورود رمزش را عوض کند", en: "Ask them to change it at first sign-in" },
  login: { fa: "نام کاربری", en: "Username" },
  email: { fa: "ایمیل", en: "Email" },
  fullName: { fa: "نام کامل (دلخواه)", en: "Full name (optional)" },
  isAdmin: { fa: "مدیر Gitea باشد", en: "Make them a Gitea admin" },
  isAdminHelp: { fa: "مدیر به همه مخزن‌ها و کاربران دسترسی دارد.", en: "An admin can reach every repository and user." },
  emailRule: { fa: "یک ایمیل درست بنویسید، مثل ali@example.com", en: "Write a valid email, such as ali@example.com" },
  createUser: { fa: "ساخت کاربر", en: "Create user" },
  userSecretTitle: { fa: "کاربر «{name}» ساخته شد", en: "User “{name}” was created" },
  userSecretBody: { fa: "این رمز را به خود او بدهید. بعد از اولین ورود می‌تواند عوضش کند.", en: "Give this password to them. They can change it after the first sign-in." },
  password: { fa: "رمز ورود", en: "Password" },
  changePassword: { fa: "عوض کردن رمز", en: "Change password" },
  changePasswordTitle: { fa: "رمز تازه برای «{name}»", en: "New password for “{name}”" },
  changePasswordHint: { fa: "رمز قبلی دیگر کار نمی‌کند. او در ورود بعدی باید رمزش را عوض کند.", en: "The old password stops working. They'll be asked to change it at their next sign-in." },
  savePassword: { fa: "ذخیره رمز", en: "Save password" },
  passwordChanged: { fa: "رمز «{name}» عوض شد", en: "The password of “{name}” was changed" },
  // Organizations
  orgsTitle: { fa: "سازمان‌ها", en: "Organizations" },
  orgsHint: { fa: "مخزن‌های یک تیم یا شرکت را زیر یک نام جمع کنید.", en: "Group a team's or company's repositories under one name." },
  newOrg: { fa: "سازمان تازه", en: "New organization" },
  orgName: { fa: "نام سازمان", en: "Organization name" },
  orgCreated: { fa: "سازمان «{name}» ساخته شد.", en: "Organization “{name}” was created." },
  emptyOrgs: { fa: "هنوز سازمانی ندارید", en: "You have no organizations yet" },
  emptyOrgsBody: { fa: "با سازمان، مخزن‌های یک تیم کنار هم می‌مانند.", en: "An organization keeps a team's repositories together." },
  colRepos: { fa: "مخزن‌ها", en: "Repositories" }
} satisfies Record<string, Bi>;

const INTERVALS = [
  { value: "1h", label: T.interval1h },
  { value: "8h", label: T.interval8h },
  { value: "24h", label: T.interval24h },
  { value: "0", label: T.intervalManual }
];

function repoKey(repo: GitRepo): string {
  return repo.full_name || `${repo.owner ?? ""}/${repo.name ?? ""}`;
}

function repoPath(repo: GitRepo): string {
  const [owner, name] = repo.owner && repo.name ? [repo.owner, repo.name] : repoKey(repo).split("/");
  return `${API}/repos/${encodeURIComponent(owner ?? "")}/${encodeURIComponent(name ?? "")}`;
}

/** `https://github.com/acme/tool.git` → `tool`. */
function nameFromSource(url: string): string {
  const last = url.trim().replace(/\/+$/, "").split("/").pop() ?? "";
  return last.replace(/\.git$/i, "").replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 100);
}

function isMissing(error: unknown) {
  return error instanceof ApiError && (error.status === 404 || error.status === 405);
}

export function GitPanel({ permissions }: CodePanelProps) {
  const { language, isAdvanced } = useKit();
  const can = useCan(permissions);
  const canWrite = can("git:write");
  const { notify, snackbar } = useUndoSnackbar();
  const [status, setStatus] = useState<GitStatus | null>(null);
  const [statusError, setStatusError] = useState<unknown>(null);

  const loadStatus = useCallback(() => {
    getJson<GitStatus>(`${API}/status`).then(
      (value) => {
        setStatus(value ?? {});
        setStatusError(null);
      },
      (error) => setStatusError(error)
    );
  }, []);
  useEffect(() => loadStatus(), [loadStatus]);
  useVisibleInterval(loadStatus, 15000);

  if (statusError && !status) {
    if (isMissing(statusError)) {
      return <SectionCard><EmptyState icon={CodeRoundedIcon} title={pick(language, T.oldServerTitle)} body={pick(language, T.oldServerBody)} /></SectionCard>;
    }
    return <FriendlyError error={statusError} onRetry={loadStatus} />;
  }
  if (!status) return null;
  if (!status.connected) {
    return (
      <SectionCard>
        <EmptyState
          icon={CodeRoundedIcon}
          title={pick(language, T.missingTitle)}
          body={pick(language, T.missingBody)}
          action={<Button variant="contained" href="#/services/add" startIcon={<AddRoundedIcon />}>{pick(language, T.addService)}</Button>}
        />
      </SectionCard>
    );
  }

  const say2 = (bi: Bi, name: string) => say(language, bi, { name });
  return (
    <Stack spacing={2}>
      <StatusCard status={status} />
      <ReposSection status={status} canWrite={canWrite} notify={(bi, name) => notify({ message: say2(bi, name) })} />
      <UsersSection canWrite={canWrite} notify={(bi, name) => notify({ message: say2(bi, name) })} />
      {isAdvanced && <OrgsSection canWrite={canWrite} notify={(bi, name) => notify({ message: say2(bi, name) })} />}
      {!canWrite && <NoAccess needs="git:write" ask={pick(language, T.writeNeeded)} />}
      {snackbar}
    </Stack>
  );
}

type Notify = (bi: Bi, name: string) => void;

function StatusCard({ status }: { status: GitStatus }) {
  const { language } = useKit();
  const reachable = status.reachable !== false;
  return (
    <SectionCard
      title={pick(language, T.statusTitle)}
      hint={pick(language, T.statusHint)}
      status={<StatusPill status={reachable ? "connected" : "unreachable"} />}
      action={status.public_url ? (
        <Button variant="outlined" href={status.public_url} target="_blank" rel="noopener noreferrer" endIcon={<OpenInNewRoundedIcon />}>
          {pick(language, T.openGitea)}
        </Button>
      ) : undefined}
    >
      <Stack spacing={1.5}>
        {!reachable && <Notice tone="warning">{pick(language, T.notAnswering)}</Notice>}
        <KeyValueList
          items={[
            { label: pick(language, T.publicUrl), value: status.public_url ? <Ltr>{status.public_url}</Ltr> : pick(language, T.noPublicUrl), copy: Boolean(status.public_url) },
            { label: pick(language, T.version), value: status.version ? <Ltr>{status.version}</Ltr> : "—" },
            { label: pick(language, T.adminUser), value: status.admin_user ? <Ltr>{status.admin_user}</Ltr> : "—", advancedOnly: true },
            { label: pick(language, T.internalUrl), value: status.url ? <Ltr>{status.url}</Ltr> : "—", advancedOnly: true }
          ]}
        />
      </Stack>
    </SectionCard>
  );
}

// ── Repositories ─────────────────────────────────────────────────────────────

function ReposSection({ status, canWrite, notify }: { status: GitStatus; canWrite: boolean; notify: Notify }) {
  const { language, c } = useKit();
  const { ask, dialog } = useConfirmAction();
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<GitRepo[] | null>(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [wizard, setWizard] = useState<"repo" | "mirror" | null>(null);
  const [owners, setOwners] = useState<string[]>([]);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(query.trim()), 300);
    return () => window.clearTimeout(timer);
  }, [query]);

  const load = useCallback((q: string, p: number) => {
    const params = new URLSearchParams({ page: String(p) });
    if (q) params.set("q", q);
    return getJson<{ items?: GitRepo[]; total?: number }>(`${API}/repos?${params}`).then(
      (value) => {
        const items = value?.items ?? [];
        setRows((current) => (p > 1 && current ? [...current, ...items] : items));
        setTotal(value?.total ?? items.length);
        setError(null);
      },
      (caught) => setError(caught)
    );
  }, []);

  useEffect(() => {
    setPage(1);
    void load(debounced, 1);
  }, [debounced, load]);

  const reload = useCallback(() => {
    setPage(1);
    void load(debounced, 1);
  }, [debounced, load]);

  // Owners for the wizards: the admin user and every organization.
  useEffect(() => {
    if (!canWrite) return;
    getJson<{ items?: GitOrg[] }>(`${API}/orgs`).then(
      (value) => setOwners((value?.items ?? []).map((org) => org.name ?? "").filter(Boolean)),
      () => setOwners([])
    );
  }, [canWrite, wizard]);
  const ownerOptions = useMemo(() => [status.admin_user, ...owners].filter((value): value is string => Boolean(value)), [status.admin_user, owners]);

  const sync = async (repo: GitRepo) => {
    setActionError(null);
    try {
      await mutateJson(`${repoPath(repo)}/sync`, { method: "POST" });
      notify(T.syncStarted, repoKey(repo));
    } catch (caught) {
      setActionError(caught);
    }
  };

  const remove = async (repo: GitRepo) => {
    const full = repoKey(repo);
    const ok = await ask({
      title: say(language, T.removeTitle, { name: full }),
      body: pick(language, T.removeBody),
      consequences: repo.mirror ? [pick(language, T.removeMirrorNote)] : undefined,
      severity: "destructive",
      undoable: false,
      typed: nameConfirmation(full, full)
    });
    if (!ok) return;
    setActionError(null);
    try {
      await mutateJson(repoPath(repo), { method: "DELETE", body: { confirmation: full } });
      notify(T.removed, full);
      reload();
    } catch (caught) {
      setActionError(caught);
    }
  };

  const copyAddress = async (value?: string) => {
    if (value && (await copyText(value))) notify(T.copiedToast, "");
  };

  const shownRows = rows ?? [];
  const searching = debounced.length > 0;
  return (
    <SectionCard
      title={pick(language, T.reposTitle)}
      hint={pick(language, T.reposHint)}
      action={canWrite ? (
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
          <Button variant="contained" startIcon={<CloudSyncRoundedIcon />} onClick={() => setWizard("mirror")}>{pick(language, T.newMirror)}</Button>
          <Button variant="outlined" startIcon={<AddRoundedIcon />} onClick={() => setWizard("repo")}>{pick(language, T.newRepo)}</Button>
        </Stack>
      ) : undefined}
    >
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={1} alignItems="center">
          <TextField
            size="small"
            type="search"
            label={pick(language, T.search)}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            sx={{ flex: 1, maxWidth: 420 }}
          />
          <Button onClick={reload} startIcon={<RefreshRoundedIcon />} sx={{ minHeight: 40 }}>{c.refresh}</Button>
        </Stack>
        {error ? <FriendlyError error={error} onRetry={reload} /> : null}
        {actionError ? <FriendlyError error={actionError} onClose={() => setActionError(null)} /> : null}
        {rows === null && !error ? null : (
          <ResponsiveList<GitRepo>
            label={pick(language, T.reposTitle)}
            rows={shownRows}
            rowKey={(row) => String(row.id ?? repoKey(row))}
            columns={[
              { key: "name", header: pick(language, T.colName), render: (row) => <RepoName repo={row} /> },
              { key: "description", header: pick(language, T.colDescription), render: (row) => row.description || "—", hideOnCard: true },
              { key: "updated", header: pick(language, T.colUpdated), render: (row) => <RelativeTime value={row.updated_at} /> },
              { key: "size", header: pick(language, T.colSize), render: (row) => <Bytes value={typeof row.size_kb === "number" ? row.size_kb * 1024 : null} />, advancedOnly: true },
              {
                key: "clone",
                header: pick(language, T.colClone),
                render: (row) => row.clone_http ? (
                  <Stack direction="row" spacing={0.5} alignItems="center" sx={{ minWidth: 0 }}>
                    <Box sx={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 280 }}><Ltr mono>{row.clone_http}</Ltr></Box>
                    <CopyButton value={row.clone_http} label={pick(language, T.copyHttp)} />
                  </Stack>
                ) : "—",
                hideOnCard: true
              }
            ]}
            card={{
              title: (row) => <RepoName repo={row} />,
              meta: (row) => (
                <Stack spacing={0.25}>
                  {row.description ? <Typography variant="body2" color="text.secondary">{row.description}</Typography> : null}
                  <Typography variant="caption" color="text.secondary"><RelativeTime value={row.updated_at} /></Typography>
                </Stack>
              )
            }}
            actions={[
              { key: "copy", label: pick(language, T.copyHttp), icon: ContentCopyRoundedIcon, onClick: (row) => void copyAddress(row.clone_http), hidden: (row) => !row.clone_http },
              { key: "copy-ssh", label: pick(language, T.copySsh), icon: ContentCopyRoundedIcon, onClick: (row) => void copyAddress(row.clone_ssh), hidden: (row) => !row.clone_ssh, advancedOnly: true },
              { key: "open", label: pick(language, T.openRepo), icon: OpenInNewRoundedIcon, onClick: (row) => row.html_url && window.open(row.html_url, "_blank", "noopener,noreferrer"), hidden: (row) => !row.html_url },
              { key: "sync", label: pick(language, T.syncNow), icon: SyncRoundedIcon, onClick: (row) => void sync(row), hidden: (row) => !canWrite || !row.mirror },
              { key: "delete", label: pick(language, T.remove), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (row) => void remove(row), hidden: () => !canWrite }
            ]}
            empty={searching ? (
              <EmptyState compact title={pick(language, T.noMatch)} action={<Button onClick={() => setQuery("")}>{c.clear}</Button>} />
            ) : (
              <EmptyState
                compact
                icon={CodeRoundedIcon}
                title={pick(language, T.emptyRepos)}
                body={pick(language, T.emptyReposBody)}
                action={canWrite ? <Button variant="contained" startIcon={<CloudSyncRoundedIcon />} onClick={() => setWizard("mirror")}>{pick(language, T.newMirror)}</Button> : undefined}
              />
            )}
          />
        )}
        {shownRows.length > 0 && (
          <Stack direction="row" spacing={1.5} alignItems="center" justifyContent="space-between" flexWrap="wrap" useFlexGap>
            <Typography variant="caption" color="text.secondary">{say(language, T.shown, { shown: shownRows.length, total: Math.max(total, shownRows.length) })}</Typography>
            {shownRows.length < total && (
              <Button
                onClick={() => {
                  const next = page + 1;
                  setPage(next);
                  void load(debounced, next);
                }}
              >
                {pick(language, T.showMore)}
              </Button>
            )}
          </Stack>
        )}
      </Stack>
      <NewRepoWizard open={wizard === "repo"} owners={ownerOptions} onClose={() => setWizard(null)} onCreated={(repo) => { notify(T.repoCreated, repoKey(repo)); reload(); }} />
      <MirrorWizard open={wizard === "mirror"} owners={ownerOptions} onClose={() => { setWizard(null); reload(); }} onCreated={(repo) => notify(T.mirrorCreated, repoKey(repo))} />
      {dialog}
    </SectionCard>
  );
}

function RepoName({ repo }: { repo: GitRepo }) {
  const { language } = useKit();
  return (
    <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
      <Box component="span" sx={{ fontWeight: 650 }}><Ltr>{repoKey(repo)}</Ltr></Box>
      {repo.mirror && <Chip size="small" color="info" variant="outlined" icon={<CloudSyncRoundedIcon />} label={pick(language, T.mirror)} />}
      {repo.private !== undefined && <Chip size="small" variant="outlined" label={pick(language, repo.private ? T.private : T.public)} />}
    </Stack>
  );
}

function OwnerField({ owners, value, onChange }: { owners: string[]; value: string; onChange: (value: string) => void }) {
  const { language } = useKit();
  if (owners.length <= 1) {
    return (
      <TextField label={pick(language, T.owner)} helperText={pick(language, T.ownerHint)} value={value} onChange={(event) => onChange(event.target.value.trim())} slotProps={{ htmlInput: { dir: "ltr" } }} fullWidth />
    );
  }
  return (
    <TextField select label={pick(language, T.owner)} helperText={pick(language, T.ownerHint)} value={value} onChange={(event) => onChange(event.target.value)} fullWidth>
      {owners.map((owner) => <MenuItem key={owner} value={owner}><Ltr>{owner}</Ltr></MenuItem>)}
    </TextField>
  );
}

function NewRepoWizard({ open, owners, onClose, onCreated }: { open: boolean; owners: string[]; onClose: () => void; onCreated: (repo: GitRepo) => void }) {
  const { language } = useKit();
  const [owner, setOwner] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [isPrivate, setPrivate] = useState(true);

  useEffect(() => {
    if (!open) return;
    setOwner(owners[0] ?? "");
    setName("");
    setDescription("");
    setPrivate(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  return (
    <ActionWizard
      open={open}
      title={pick(language, T.newRepo)}
      finishLabel={pick(language, T.createRepo)}
      onClose={onClose}
      steps={[
        {
          key: "name",
          title: pick(language, T.repoStepName),
          hint: pick(language, T.repoStepNameHint),
          validate: () => (NAME_RE.test(name.trim()) && (!owner || NAME_RE.test(owner)) ? null : pick(language, T.nameRule)),
          render: () => (
            <Stack spacing={2}>
              <OwnerField owners={owners} value={owner} onChange={setOwner} />
              <TextField autoFocus label={pick(language, T.repoName)} value={name} onChange={(event) => setName(event.target.value)} slotProps={{ htmlInput: { dir: "ltr" } }} fullWidth />
            </Stack>
          )
        },
        {
          key: "access",
          title: pick(language, T.repoStepAccess),
          hint: pick(language, T.repoStepAccessHint),
          render: () => (
            <Stack spacing={2}>
              <FormControlLabel control={<Switch checked={isPrivate} onChange={(event) => setPrivate(event.target.checked)} />} label={pick(language, T.privateSwitch)} />
              <TextField label={pick(language, T.description)} value={description} onChange={(event) => setDescription(event.target.value)} multiline minRows={2} fullWidth />
            </Stack>
          )
        }
      ]}
      onFinish={async () => {
        const body: Record<string, unknown> = { name: name.trim(), private: isPrivate };
        if (owner) body.owner = owner;
        if (description.trim()) body.description = description.trim();
        const repo = await mutateJson<GitRepo>(`${API}/repos`, { method: "POST", body });
        onCreated(repo ?? { owner, name: name.trim() });
      }}
    />
  );
}

function MirrorWizard({ open, owners, onClose, onCreated }: { open: boolean; owners: string[]; onClose: () => void; onCreated: (repo: GitRepo) => void }) {
  const { language, isAdvanced } = useKit();
  const [source, setSource] = useState("");
  const [authUser, setAuthUser] = useState("");
  const [authToken, setAuthToken] = useState("");
  const [owner, setOwner] = useState("");
  const [name, setName] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const [isPrivate, setPrivate] = useState(true);
  const [interval, setSyncInterval] = useState("8h");
  const [custom, setCustom] = useState("");
  const [created, setCreated] = useState<GitRepo | null>(null);

  useEffect(() => {
    if (!open) return;
    setSource("");
    setAuthUser("");
    setAuthToken("");
    setOwner(owners[0] ?? "");
    setName("");
    setNameTouched(false);
    setPrivate(true);
    setSyncInterval("8h");
    setCustom("");
    setCreated(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const chosenInterval = interval === "custom" ? custom.trim() : interval;
  return (
    <ActionWizard
      open={open}
      title={pick(language, T.mirrorTitle)}
      finishLabel={pick(language, T.createMirror)}
      onClose={onClose}
      done={created ? (
        <Stack spacing={2}>
          <Notice tone="success">{pick(language, T.mirrorDone)}</Notice>
          {created.clone_http && (
            <>
              <Typography variant="body2">{pick(language, T.mirrorUseIt)}</Typography>
              <CopyField label={pick(language, T.colClone)} value={created.clone_http} />
            </>
          )}
          {isAdvanced && created.clone_ssh && <CopyField label={pick(language, T.copySsh)} value={created.clone_ssh} />}
        </Stack>
      ) : <Notice tone="success">{pick(language, T.mirrorDone)}</Notice>}
      steps={[
        {
          key: "source",
          title: pick(language, T.mirrorStepSource),
          hint: pick(language, T.mirrorStepSourceHint),
          validate: () => (SOURCE_RE.test(source.trim()) ? null : pick(language, T.sourceRule)),
          onNext: async () => {
            if (!nameTouched || !name) setName(nameFromSource(source));
          },
          render: () => (
            <TextField
              autoFocus
              label={pick(language, T.sourceUrl)}
              helperText={pick(language, T.sourceUrlHelp)}
              value={source}
              onChange={(event) => setSource(event.target.value)}
              placeholder="https://github.com/owner/project"
              slotProps={{ htmlInput: { dir: "ltr", inputMode: "url" } }}
              fullWidth
            />
          )
        },
        {
          key: "auth",
          title: pick(language, T.mirrorStepAuth),
          hint: pick(language, T.mirrorStepAuthHint),
          optional: true,
          render: () => (
            <Stack spacing={2}>
              <TextField label={pick(language, T.authUser)} value={authUser} onChange={(event) => setAuthUser(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", autoComplete: "off" } }} fullWidth />
              <TextField
                type="password"
                label={pick(language, T.authToken)}
                helperText={pick(language, T.authTokenHelp)}
                value={authToken}
                onChange={(event) => setAuthToken(event.target.value)}
                slotProps={{ htmlInput: { dir: "ltr", autoComplete: "new-password" } }}
                fullWidth
              />
            </Stack>
          )
        },
        {
          key: "where",
          title: pick(language, T.mirrorStepWhere),
          hint: pick(language, T.mirrorStepWhereHint),
          validate: () => {
            if (!NAME_RE.test(name.trim()) || (owner && !NAME_RE.test(owner))) return pick(language, T.nameRule);
            if (interval === "custom" && !/^\d+(m|h)$/.test(custom.trim())) return pick(language, T.intervalRule);
            return null;
          },
          render: () => (
            <Stack spacing={2}>
              <OwnerField owners={owners} value={owner} onChange={setOwner} />
              <TextField
                label={pick(language, T.repoName)}
                value={name}
                onChange={(event) => {
                  setNameTouched(true);
                  setName(event.target.value);
                }}
                slotProps={{ htmlInput: { dir: "ltr" } }}
                fullWidth
              />
              <TextField select label={pick(language, T.interval)} value={interval} onChange={(event) => setSyncInterval(event.target.value)} fullWidth>
                {INTERVALS.map((item) => <MenuItem key={item.value} value={item.value}>{pick(language, item.label)}</MenuItem>)}
                {isAdvanced && <MenuItem value="custom">{pick(language, T.intervalCustom)}</MenuItem>}
              </TextField>
              {interval === "custom" && (
                <TextField label={pick(language, T.intervalCustom)} helperText={pick(language, T.intervalCustomHelp)} value={custom} onChange={(event) => setCustom(event.target.value)} slotProps={{ htmlInput: { dir: "ltr" } }} fullWidth />
              )}
              <FormControlLabel control={<Switch checked={isPrivate} onChange={(event) => setPrivate(event.target.checked)} />} label={pick(language, T.privateSwitch)} />
            </Stack>
          )
        }
      ]}
      onFinish={async () => {
        const body: Record<string, unknown> = { source_url: source.trim(), name: name.trim(), private: isPrivate };
        if (owner) body.owner = owner;
        if (chosenInterval) body.interval = chosenInterval;
        if (authUser.trim()) body.auth_username = authUser.trim();
        if (authToken) body.auth_token = authToken;
        const repo = await mutateJson<GitRepo>(`${API}/mirrors`, { method: "POST", body });
        setAuthToken("");
        const result = repo ?? { owner, name: name.trim(), mirror: true };
        setCreated(result);
        onCreated(result);
      }}
    />
  );
}

// ── Users ────────────────────────────────────────────────────────────────────

const PASSWORD_RULES: PasswordRules = { minLength: 8, maxLength: 255 }; // Gitea's own minimum is 8

function UsersSection({ canWrite, notify }: { canWrite: boolean; notify: Notify }) {
  const { language } = useKit();
  const [rows, setRows] = useState<GitUser[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [open, setOpen] = useState(false);
  const [secret, setSecret] = useState<{ login: string; password: string; changed?: boolean } | null>(null);
  const [changing, setChanging] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [mustChange, setMustChange] = useState(true);
  const [login, setLogin] = useState("");
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [admin, setAdmin] = useState(false);

  const load = useCallback(() => {
    getJson<{ items?: GitUser[] }>(`${API}/users`).then(
      (value) => {
        setRows(value?.items ?? []);
        setError(null);
      },
      (caught) => setError(caught)
    );
  }, []);
  useEffect(() => load(), [load]);

  const start = () => {
    setLogin("");
    setEmail("");
    setFullName("");
    setAdmin(false);
    setPassword(suggestPassword());
    setMustChange(true);
    setOpen(true);
  };

  return (
    <SectionCard
      title={pick(language, T.usersTitle)}
      hint={pick(language, T.usersHint)}
      action={canWrite ? <Button variant="outlined" startIcon={<PersonAddRoundedIcon />} onClick={start}>{pick(language, T.newUser)}</Button> : undefined}
      collapsible
    >
      {error ? <FriendlyError error={error} onRetry={load} /> : rows === null ? null : (
        <ResponsiveList<GitUser>
          label={pick(language, T.usersTitle)}
          rows={rows}
          rowKey={(row) => String(row.id ?? row.login)}
          columns={[
            { key: "login", header: pick(language, T.colLogin), render: (row) => <Ltr>{row.login ?? "—"}</Ltr> },
            { key: "name", header: pick(language, T.fullName), render: (row) => row.full_name || "—", hideOnCard: true },
            { key: "email", header: pick(language, T.colEmail), render: (row) => (row.email ? <Ltr>{row.email}</Ltr> : "—") },
            { key: "role", header: pick(language, T.colRole), render: (row) => pick(language, row.admin ? T.roleAdmin : T.roleUser) },
            { key: "created", header: pick(language, T.colCreated), render: (row) => <RelativeTime value={row.created} />, advancedOnly: true }
          ]}
          card={{
            title: (row) => <Ltr>{row.login ?? "—"}</Ltr>,
            meta: (row) => (row.email ? <Ltr>{row.email}</Ltr> : row.full_name),
            status: (row) => <StatusPill tone={row.active === false ? "off" : "ok"} label={pick(language, row.active === false ? T.inactive : T.active)} />
          }}
          actions={canWrite ? [{
            key: "password", label: pick(language, T.changePassword), icon: KeyRoundedIcon,
            hidden: (row: GitUser) => !row.login || row.login === "mrk-panel",
            onClick: (row: GitUser) => setChanging(row.login ?? null)
          }] : undefined}
          empty={<EmptyState compact title={pick(language, T.emptyUsers)} body={pick(language, T.emptyUsersBody)} action={canWrite ? <Button variant="contained" onClick={start}>{pick(language, T.newUser)}</Button> : undefined} />}
        />
      )}
      <ActionWizard
        open={open}
        title={pick(language, T.newUser)}
        finishLabel={pick(language, T.createUser)}
        onClose={() => setOpen(false)}
        steps={[
          {
            key: "details",
            title: pick(language, T.userStep),
            hint: pick(language, T.userStepHint),
            validate: () => {
              if (!NAME_RE.test(login.trim())) return pick(language, T.nameRule);
              if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return pick(language, T.emailRule);
              return passwordProblem(language, password, PASSWORD_RULES);
            },
            render: () => (
              <Stack spacing={2}>
                <TextField autoFocus label={pick(language, T.login)} value={login} onChange={(event) => setLogin(event.target.value)} slotProps={{ htmlInput: { dir: "ltr", autoComplete: "off" } }} fullWidth />
                <TextField type="email" label={pick(language, T.email)} value={email} onChange={(event) => setEmail(event.target.value)} slotProps={{ htmlInput: { dir: "ltr" } }} fullWidth />
                <TextField label={pick(language, T.fullName)} value={fullName} onChange={(event) => setFullName(event.target.value)} fullWidth />
                <PasswordInput value={password} onChange={setPassword} rules={PASSWORD_RULES} />
                <FormControlLabel control={<Switch checked={mustChange} onChange={(event) => setMustChange(event.target.checked)} />} label={pick(language, T.mustChange)} />
                <Box>
                  <FormControlLabel control={<Switch checked={admin} onChange={(event) => setAdmin(event.target.checked)} />} label={pick(language, T.isAdmin)} />
                  <Typography variant="caption" color="text.secondary" component="p">{pick(language, T.isAdminHelp)}</Typography>
                </Box>
              </Stack>
            )
          }
        ]}
        onFinish={async () => {
          const body: Record<string, unknown> = { login: login.trim(), email: email.trim(), admin, password, must_change_password: mustChange };
          if (fullName.trim()) body.full_name = fullName.trim();
          const result = await mutateJson<{ user?: GitUser; password?: string }>(`${API}/users`, { method: "POST", body });
          const created = result?.user?.login ?? login.trim();
          if (result?.password) setSecret({ login: created, password: result.password });
          else notify(T.userSecretTitle, created);
          load();
        }}
      />
      <PasswordDialog
        open={changing !== null}
        title={say(language, T.changePasswordTitle, { name: changing ?? "" })}
        hint={pick(language, T.changePasswordHint)}
        saveLabel={pick(language, T.savePassword)}
        rules={PASSWORD_RULES}
        onClose={() => setChanging(null)}
        onSubmit={async (value) => {
          if (!changing) return;
          const result = await mutateJson<{ login?: string; password?: string }>(`${API}/users/${encodeURIComponent(changing)}/password`, { method: "POST", body: { password: value } });
          setSecret({ login: changing, password: result?.password ?? value, changed: true });
          setChanging(null);
        }}
      />
      <OneTimeSecret
        open={secret !== null}
        title={say(language, secret?.changed ? T.passwordChanged : T.userSecretTitle, { name: secret?.login ?? "" })}
        body={pick(language, T.userSecretBody)}
        items={secret ? [{ label: pick(language, T.login), value: secret.login, ltr: true }, { label: pick(language, T.password), value: secret.password, ltr: true }] : []}
        onClose={() => setSecret(null)}
      />
    </SectionCard>
  );
}

// ── Organizations (Advanced) ─────────────────────────────────────────────────

function OrgsSection({ canWrite, notify }: { canWrite: boolean; notify: Notify }) {
  const { language } = useKit();
  const [rows, setRows] = useState<GitOrg[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [open, setOpen] = useState(false);

  const load = useCallback(() => {
    getJson<{ items?: GitOrg[] }>(`${API}/orgs`).then(
      (value) => {
        setRows(value?.items ?? []);
        setError(null);
      },
      (caught) => setError(caught)
    );
  }, []);
  useEffect(() => load(), [load]);

  return (
    <SectionCard
      title={pick(language, T.orgsTitle)}
      hint={pick(language, T.orgsHint)}
      action={canWrite ? <Button variant="outlined" startIcon={<AddRoundedIcon />} onClick={() => setOpen(true)}>{pick(language, T.newOrg)}</Button> : undefined}
      collapsible
      advanced
    >
      {error ? <FriendlyError error={error} onRetry={load} /> : rows === null ? null : (
        <ResponsiveList<GitOrg>
          label={pick(language, T.orgsTitle)}
          rows={rows}
          rowKey={(row) => String(row.id ?? row.name)}
          columns={[
            { key: "name", header: pick(language, T.orgName), render: (row) => <Ltr>{row.name ?? "—"}</Ltr> },
            { key: "full", header: pick(language, T.colDescription), render: (row) => row.full_name || "—" },
            { key: "repos", header: pick(language, T.colRepos), render: (row) => (typeof row.repos_count === "number" ? <Num value={row.repos_count} /> : "—") }
          ]}
          card={{ title: (row) => <Ltr>{row.name ?? "—"}</Ltr>, meta: (row) => row.full_name }}
          empty={<EmptyState compact title={pick(language, T.emptyOrgs)} body={pick(language, T.emptyOrgsBody)} action={canWrite ? <Button variant="contained" onClick={() => setOpen(true)}>{pick(language, T.newOrg)}</Button> : undefined} />}
        />
      )}
      {open && (
        <NameDialog
          title={pick(language, T.newOrg)}
          hint={pick(language, T.orgsHint)}
          label={pick(language, T.orgName)}
          saveLabel={pick(language, T.newOrg)}
          validate={(value) => (NAME_RE.test(value) ? null : pick(language, T.nameRule))}
          onSubmit={async (value) => {
            await mutateJson(`${API}/orgs`, { method: "POST", body: { name: value } });
            notify(T.orgCreated, value);
            setOpen(false);
            load();
          }}
          onClose={() => setOpen(false)}
        />
      )}
    </SectionCard>
  );
}
