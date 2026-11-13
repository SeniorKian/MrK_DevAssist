/**
 * «سرور و برنامه‌ها › ساخت از مخزن داخلی» (docs/48, phase 1).
 * A five-step wizard plus a health list: (1) what is needed, (2) what to use, (3) one command on
 * the server (layers A/B; DevAssist never edits system files itself), (4) the variables on each
 * Dokploy app (layer C, through Dokploy's API), (5) checks of every layer and a copyable report.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Box, Button, Checkbox, CircularProgress, Collapse, FormControlLabel, Radio, RadioGroup, Stack, Switch, TextField, Typography } from "@mui/material";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import UndoRoundedIcon from "@mui/icons-material/UndoRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { pick, say, type Bi } from "./copy";
import type { Tone } from "./copy/kinds";
import { CopyField, FriendlyError, Ltr, Notice, SectionCard, StatusPill, useConfirmAction, useCopy, useKit, useUndoSnackbar } from "./kit";

const API = "/api/v1/build-mirrors";

type CheckState = "ok" | "warn" | "fail" | "unknown" | "skipped";
type Check = { id: string; state: CheckState; code: string; params: Record<string, unknown> };
type Endpoints = { npm: string | null; pypi: string | null; registry: string | null };
type Settings = {
  enabled: boolean;
  npm: boolean;
  pypi: boolean;
  auto_apply_new: boolean;
  npm_url: string;
  pypi_url: string;
  registry_host: string;
  check_interval_seconds: number;
  endpoints?: Endpoints;
};
type Status = { overall: CheckState; checks: Check[]; endpoints: Endpoints; settings: Settings };
type Coverage = { result: string; gaps: string[]; direct: { npm: number; pypi: number } } | null;
type Project = {
  type: "application" | "compose";
  id: string;
  name: string;
  project?: string | null;
  eligible: boolean | null;
  state: string;
  reason: string | null;
  build_type: string | null;
  overridden: string[];
  coverage: Coverage;
};
type Command = { command: string; args: string[] };

const T = {
  intro: {
    fa: "با این ویزارد، ساخت و انتشار برنامه‌های Dokploy پکیج‌های npm و پایتون و ایمیج‌های Docker را اول از مخزن‌های همین سرور می‌گیرد. اگر چیزی آنجا نبود، خود مخزن‌ها از اینترنت می‌آورند. به خود Dokploy دست نمی‌زنیم.",
    en: "With this wizard, Dokploy builds and deploys take npm and Python packages and Docker images from this server's mirrors first. Whatever isn't there, the mirrors fetch from the Internet. Dokploy itself is not changed."
  },
  step: { fa: "قدم {n}", en: "Step {n}" },
  s1: { fa: "پیش‌نیازها", en: "What's needed" },
  s1Hint: { fa: "این‌ها خودکار بررسی می‌شوند. هر مورد قرمز را اول درست کنید.", en: "These are checked automatically. Fix anything red first." },
  s2: { fa: "چه چیزی از مخزن داخلی بیاید", en: "What comes from the internal mirrors" },
  s2Hint: { fa: "پیش‌فرض‌ها برای بیشتر سرورها درست‌اند؛ فقط «ذخیره» را بزنید.", en: "The defaults suit most servers; just press Save." },
  s3: { fa: "اجرای یک فرمان روی سرور", en: "Run one command on the server" },
  s3Hint: {
    fa: "این فرمان را کپی کنید و در SSH سرور بچسبانید. از فایل‌ها پشتیبان می‌گیرد، Docker را بدون خاموش کردن برنامه‌ها دوباره بارگذاری می‌کند و در آخر یک آزمایش انجام می‌دهد. اجرای دوباره‌اش بی‌خطر است.",
    en: "Copy this command and paste it into the server's SSH. It backs up the files, reloads Docker without stopping apps and runs a test at the end. Running it again is safe."
  },
  s3Other: {
    fa: "سرور دیگری زیر همین Dokploy دارید (سرور ساخت یا انتشار)؟ همین فرمان را یک بار روی آن هم اجرا کنید.",
    en: "Another server under the same Dokploy (a build or deploy server)? Run the same command once there too."
  },
  allowRestart: { fa: "اگر لازم شد Docker را دوباره راه‌اندازی کن", en: "Restart Docker if needed" },
  allowRestartHint: {
    fa: "فقط وقتی روشن کنید که بررسی گفت «Docker آینه را نخواند». راه‌اندازی دوباره همه برنامه‌ها را چند لحظه قطع می‌کند؛ ساعت خلوت انجام دهید.",
    en: "Turn on only if the check said Docker didn't pick up the mirror. A restart stops every app for a moment; do it at a quiet time."
  },
  more: { fa: "فرمان بررسی و برگرداندن", en: "Check and undo commands" },
  statusCmd: { fa: "بررسی روی سرور", en: "Check on the server" },
  undoCmd: { fa: "برگرداندن تغییرات سرور", en: "Undo the server changes" },
  commandLabel: { fa: "فرمان نصب", en: "Install command" },
  s4: { fa: "اعمال روی برنامه‌های Dokploy", en: "Apply to the Dokploy apps" },
  s4Hint: {
    fa: "DevAssist نشانی مخزن‌ها را به‌عنوان متغیر روی هر برنامه می‌گذارد. اثرش از انتشار بعدی هر برنامه است.",
    en: "DevAssist sets the mirror addresses as variables on each app. It takes effect from each app's next deploy."
  },
  applyAll: { fa: "اعمال روی همه", en: "Apply to all" },
  applySelected: { fa: "اعمال روی انتخاب‌شده‌ها", en: "Apply to selected" },
  removeSelected: { fa: "برداشتن از انتخاب‌شده‌ها", en: "Remove from selected" },
  needRegistry: {
    fa: "فرمان وقتی آماده می‌شود که مخزن ایمیج Docker دامنه با HTTPS داشته باشد (قدم ۱).",
    en: "The command is ready once the Docker image registry has a domain with HTTPS (step 1)."
  },
  needDokploy: { fa: "اول Dokploy را از «برنامه‌های Dokploy» وصل کنید.", en: "Connect Dokploy first, from «Dokploy apps»." },
  noApps: { fa: "هنوز برنامه‌ای در Dokploy نیست.", en: "There are no Dokploy apps yet." },
  partial: { fa: "بعضی برنامه‌ها هنوز خوانده نشده‌اند؛ چند لحظه بعد «دوباره بررسی کن» را بزنید.", en: "Some apps aren't read yet; press Check again in a moment." },
  s5: { fa: "سلامت و آزمایش", en: "Health and test" },
  s5Hint: {
    fa: "هر لایه جدا بررسی می‌شود. اگر جایی زرد یا قرمز است، متن کنارش می‌گوید چه کنید.",
    en: "Every layer is checked on its own. If something is yellow or red, the text next to it says what to do."
  },
  recheck: { fa: "دوباره بررسی کن", en: "Check again" },
  checking: { fa: "در حال بررسی…", en: "Checking…" },
  copyReport: { fa: "کپی گزارش کامل", en: "Copy the full report" },
  reportCopied: { fa: "گزارش کپی شد.", en: "Report copied." },
  save: { fa: "ذخیره", en: "Save" },
  saved: { fa: "ذخیره شد.", en: "Saved." },
  applied: { fa: "{n} برنامه به‌روز شد.", en: "{n} apps updated." },
  removed: { fa: "از {n} برنامه برداشته شد.", en: "Removed from {n} apps." },
  undoAll: { fa: "برگرداندن همه", en: "Undo everything" },
  undoAllBody: {
    fa: "متغیرهای DevAssist از همه برنامه‌های Dokploy برداشته می‌شود و اعمال خودکار خاموش می‌شود. برای سرور، فرمان «برگرداندن تغییرات سرور» را هم اجرا کنید.",
    en: "DevAssist's variables are removed from every Dokploy app and automatic apply turns off. For the server, also run the «Undo the server changes» command."
  },
  optNpm: { fa: "پکیج‌های npm (و pnpm و yarn)", en: "npm packages (and pnpm, yarn)" },
  optPypi: { fa: "پکیج‌های پایتون (pip و uv)", en: "Python packages (pip, uv)" },
  optAuto: { fa: "برنامه‌های تازه هم خودکار بگیرند", en: "New apps get it automatically" },
  addresses: { fa: "نشانی‌ها", en: "Addresses" },
  phase2: {
    fa: "برنامه‌هایی که با «Dockerfile» یا Compose ساخته می‌شوند فعلاً فقط ایمیج پایه را از مخزن می‌گیرند؛ npm و پایتونشان در فاز بعد پوشش داده می‌شود.",
    en: "Apps built from a «Dockerfile» or Compose only take their base images from the mirror for now; their npm and Python come in the next phase."
  },
  loadFailed: { fa: "وضعیت خوانده نشد.", en: "The status didn't load." },
  moduleMissing: { fa: "این بخش روی نسخه فعلی سرور نیست. DevAssist را به‌روز کنید.", en: "This isn't on your server's current version. Update DevAssist." }
} satisfies Record<string, Bi>;

/** Plain sentences for each check code (docs/48 status contract). */
const CHECK_TEXT: Record<string, Bi> = {
  connected: { fa: "Dokploy وصل است.", en: "Dokploy is connected." },
  dokploy_not_connected: { fa: "Dokploy وصل نیست. از «برنامه‌های Dokploy» آن را وصل کنید.", en: "Dokploy isn't connected. Connect it from «Dokploy apps»." },
  turned_off: { fa: "خاموش است.", en: "Turned off." },
  mirror_address_missing: { fa: "این مخزن نشانی ندارد. در «سرویس‌های من» به آن دامنه بدهید.", en: "This mirror has no address. Give it a domain in «My services»." },
  mirror_not_https: { fa: "نشانی HTTPS نیست؛ کار می‌کند ولی بهتر است دامنه با HTTPS بدهید.", en: "The address isn't HTTPS; it works, but a domain with HTTPS is better." },
  mirror_ready: { fa: "آماده: {url}", en: "Ready: {url}" },
  registry_ready: { fa: "مخزن ایمیج: {host}", en: "Image registry: {host}" },
  registry_address_missing: { fa: "مخزن ایمیج Docker دامنه با HTTPS ندارد. Docker فقط با HTTPS وصل می‌شود؛ در «سرویس‌های من» به آن دامنه بدهید.", en: "The Docker image registry has no HTTPS domain. Docker only connects over HTTPS; give it a domain in «My services»." },
  token_ok: { fa: "Docker بدون رمز از پنل مجوز دریافت می‌گیرد (نشانی‌های مورد اعتماد: {ranges}).", en: "Docker gets a pull token from the panel without a password (trusted addresses: {ranges})." },
  token_registry_missing: { fa: "مخزن ایمیج Docker نصب نیست. از «سرویس‌های من ← افزودن سرویس» نصبش کنید.", en: "The Docker image registry isn't installed. Add it from «My services → Add a service»." },
  token_off: { fa: "«دسترسی Docker از راه پنل» خاموش است، پس مخزن از Docker رمز می‌خواهد و Docker از آن رد می‌شود. در قدم ۲ روشنش کنید.", en: "«Docker access through the panel» is off, so the registry asks Docker for a password and Docker skips it. Turn it on in step 2." },
  token_registry_unreachable: { fa: "مخزن ایمیج جواب نمی‌دهد.", en: "The image registry doesn't answer." },
  token_not_in_zot_yet: { fa: "مخزن ایمیج هنوز Docker را به پنل نمی‌فرستد. چند ثانیه بعد دوباره بررسی کنید؛ اگر ماند، مخزن ایمیج را از «نسخه‌ها و به‌روزرسانی» به‌روز کنید.", en: "The image registry doesn't send Docker to the panel yet. Check again in a few seconds; if it stays, update the image registry from «Versions and updates»." },
  agent_ok: { fa: "دستیار سرور وصل است.", en: "The server agent is connected." },
  agent_not_configured: { fa: "دستیار سرور وصل نیست؛ بررسی سرور ممکن نیست ولی فرمان کار می‌کند.", en: "The server agent isn't connected; the server can't be checked, but the command still works." },
  agent_unreachable: { fa: "دستیار سرور جواب نمی‌دهد.", en: "The server agent doesn't answer." },
  agent_outdated: { fa: "دستیار سرور قدیمی است؛ به‌روزش کنید تا این بررسی‌ها کار کنند.", en: "The server agent is old; update it so these checks work." },
  server_unknown: { fa: "وضعیت سرور معلوم نیست (دستیار سرور لازم است).", en: "The server's state is unknown (needs the server agent)." },
  agent_no_host_root: { fa: "دستیار سرور به فایل‌های سرور دسترسی ندارد.", en: "The server agent can't see the server's files." },
  script_not_run: { fa: "فرمان قدم ۳ هنوز روی این سرور اجرا نشده.", en: "Step 3's command hasn't run on this server yet." },
  script_marker_invalid: { fa: "فایل نتیجه فرمان خراب است؛ فرمان قدم ۳ را دوباره اجرا کنید.", en: "The command's result file is broken; run step 3's command again." },
  script_old_registry: { fa: "فرمان با نشانی قدیمی ({applied}) اجرا شده؛ فرمان تازه قدم ۳ را اجرا کنید.", en: "The command ran with an old address ({applied}); run step 3's new command." },
  script_applied: { fa: "فرمان سرور اجرا شده است.", en: "The server command has run." },
  daemon_has_mirror: { fa: "تنظیم Docker آینه را دارد.", en: "Docker's settings have the mirror." },
  daemon_no_mirror: { fa: "تنظیم Docker آینه ندارد؛ فرمان قدم ۳ را اجرا کنید.", en: "Docker's settings have no mirror; run step 3's command." },
  docker_uses_mirror: { fa: "Docker همین حالا از آینه استفاده می‌کند.", en: "Docker uses the mirror right now." },
  docker_reload_needed: { fa: "Docker آینه را هنوز نخوانده. فرمان قدم ۳ را با «دوباره راه‌اندازی» اجرا کنید.", en: "Docker hasn't picked up the mirror yet. Run step 3's command with «restart»." },
  docker_unreachable: { fa: "Docker از دستیار سرور جواب نمی‌دهد.", en: "Docker doesn't answer the server agent." },
  builder_file_written: { fa: "تنظیم آینه سازنده نوشته شده است.", en: "The builder's mirror settings are written." },
  builder_file_missing: { fa: "تنظیم آینه سازنده نوشته نشده.", en: "The builder's mirror settings aren't written." },
  test_ok: { fa: "آزمایش موفق: ایمیج از آینه آمد.", en: "Test passed: the image came through the mirror." },
  test_cached: { fa: "ایمیج‌های آزمایشی از قبل در آینه هستند؛ یک اجرای قبلی از آینه گذشته است.", en: "The test images are in the mirror already; an earlier run went through it." },
  test_mirror_auth: { fa: "آزمایش ناموفق: مخزن از Docker رمز خواست. «دسترسی Docker از راه پنل» را در قدم ۲ روشن کنید.", en: "Test failed: the registry asked Docker for a password. Turn on «Docker access through the panel» in step 2." },
  test_not_via_mirror: { fa: "آزمایش: ایمیج از آینه نیامد و Docker مستقیم از اینترنت گرفت؛ «Docker آینه را خواند؟» را بالا ببینید.", en: "Test: the image didn't come through the mirror; Docker pulled it directly. See whether Docker picked up the mirror above." },
  test_pull_failed: { fa: "آزمایش: دریافت ایمیج نشد. اینترنت سرور و مخزن ایمیج را بررسی کنید.", en: "Test: the image pull failed. Check the server's Internet and the image registry." },
  test_skipped: { fa: "آزمایش اجرا نشده.", en: "The test didn't run." },
  projects_ready: { fa: "متغیرها روی {applied} برنامه هست.", en: "The variables are on {applied} apps." },
  projects_pending: { fa: "{pending} برنامه هنوز متغیر ندارد یا قدیمی است؛ قدم ۴.", en: "{pending} apps don't have the variables yet or have old ones; step 4." },
  projects_none: { fa: "هنوز روی برنامه‌ای اعمال نشده.", en: "Not applied to any app yet." },
  projects_unreadable: { fa: "برنامه‌های Dokploy خوانده نشد.", en: "The Dokploy apps couldn't be read." },
  coverage_full: { fa: "در ساخت‌های اخیر دانلود مستقیم از اینترنت دیده نشد.", en: "No direct Internet downloads were seen in recent builds." },
  coverage_gaps: { fa: "در بعضی ساخت‌ها دانلود مستقیم دیده شد؛ دلیل هر برنامه در قدم ۴ است.", en: "Some builds downloaded directly; each app's reason is in step 4." },
  coverage_no_builds: { fa: "هنوز ساختی بعد از اعمال تمام نشده.", en: "No build has finished since applying." }
};

const CHECK_TITLE: Record<string, Bi> = {
  dokploy: { fa: "اتصال به Dokploy", en: "Dokploy connection" },
  npm_mirror: { fa: "مخزن npm", en: "npm mirror" },
  pypi_mirror: { fa: "مخزن PyPI", en: "PyPI mirror" },
  registry: { fa: "نشانی آینه ایمیج", en: "Image mirror address" },
  registry_token: { fa: "دسترسی Docker از راه پنل", en: "Docker access through the panel" },
  agent: { fa: "دستیار سرور", en: "Server agent" },
  server: { fa: "فرمان سرور", en: "Server command" },
  daemon_file: { fa: "تنظیم Docker", en: "Docker settings" },
  daemon_live: { fa: "Docker آینه را خواند؟", en: "Did Docker pick it up?" },
  builder_file: { fa: "تنظیم سازنده", en: "Builder settings" },
  self_test: { fa: "آزمایش واقعی", en: "Real test" },
  projects: { fa: "برنامه‌ها", en: "Apps" },
  coverage: { fa: "پوشش واقعی ساخت‌ها", en: "Real build coverage" }
};

const STATE_TEXT: Record<string, Bi> = {
  applied: { fa: "اعمال شده", en: "Applied" },
  missing: { fa: "اعمال نشده", en: "Not applied" },
  outdated: { fa: "نشانی قدیمی", en: "Old address" },
  skipped: { fa: "لازم نیست", en: "Not needed" },
  leftover: { fa: "متغیر جامانده", en: "Leftover variables" },
  unknown: { fa: "خوانده نشده", en: "Not read yet" }
};

const REASON_TEXT: Record<string, Bi> = {
  dockerfile_build: { fa: "با «Dockerfile» ساخته می‌شود؛ فعلاً فقط ایمیج پایه از مخزن می‌آید.", en: "Built from a «Dockerfile»; only the base image comes from the mirror for now." },
  compose_build: { fa: "Compose است؛ فعلاً فقط ایمیج‌ها از مخزن می‌آیند.", en: "A Compose app; only images come from the mirror for now." },
  no_build: { fa: "ایمیج آماده است و ساختی ندارد؛ دریافت ایمیج از آینه است.", en: "A ready image with no build; the image pull uses the mirror." },
  unknown_build_type: { fa: "نوع ساخت شناخته نشد.", en: "Unknown build type." },
  not_buildable: { fa: "ساخت ندارد.", en: "Has no build." },
  no_mirror_address: { fa: "مخزن npm و PyPI نشانی ندارند.", en: "The npm and PyPI mirrors have no address." }
};

const GAP_TEXT: Record<string, Bi> = {
  yarn_v1_lock: { fa: "yarn قدیمی با yarn.lock نشانی ثابت دارد.", en: "Old yarn with yarn.lock has fixed addresses." },
  poetry: { fa: "Poetry متغیر را نمی‌پذیرد.", en: "Poetry ignores the variable." },
  uv_lock: { fa: "uv.lock نشانی ثابت دارد.", en: "uv.lock has fixed addresses." },
  pip_index_in_requirements: { fa: "داخل requirements.txt خط «--index-url» هست.", en: "requirements.txt has an --index-url line." }
};

const COVERAGE_TEXT: Record<string, Bi> = {
  full: { fa: "کامل", en: "Full" },
  partial: { fa: "ناقص", en: "Partial" },
  none: { fa: "مستقیم از اینترنت", en: "Straight from the Internet" },
  unknown: { fa: "نامعلوم", en: "Unknown" }
};

const TONE: Record<string, Tone> = { ok: "ok", warn: "warn", fail: "error", unknown: "off", skipped: "off" };
const STATE_TONE: Record<string, Tone> = { applied: "ok", missing: "warn", outdated: "warn", skipped: "off", leftover: "warn", unknown: "off" };
const PREREQUISITES = ["dokploy", "npm_mirror", "pypi_mirror", "registry", "registry_token", "agent"];
const HEALTH = ["server", "daemon_file", "daemon_live", "builder_file", "self_test", "projects", "coverage"];

function fill(language: "fa" | "en", bi: Bi | undefined, params: Record<string, unknown>, fallback: string) {
  if (!bi) return fallback;
  const values = Object.fromEntries(Object.entries(params).map(([key, value]) => [key, String(value ?? "")]));
  return say(language, bi, values);
}

function CheckRow({ check }: { check: Check }) {
  const { language, isAdvanced } = useKit();
  const stateWord: Record<string, Bi> = {
    ok: { fa: "درست", en: "OK" },
    warn: { fa: "توجه", en: "Attention" },
    fail: { fa: "مشکل", en: "Problem" },
    unknown: { fa: "نامعلوم", en: "Unknown" },
    skipped: { fa: "خاموش", en: "Off" }
  };
  return (
    <Stack direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ sm: "center" }} sx={{ py: 1, borderBottom: 1, borderColor: "divider" }}>
      <Box sx={{ minWidth: 180 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{pick(language, CHECK_TITLE[check.id] ?? { fa: check.id, en: check.id })}</Typography>
      </Box>
      <StatusPill tone={TONE[check.state] ?? "off"} label={pick(language, stateWord[check.state] ?? stateWord.unknown)} />
      <Typography variant="body2" sx={{ flex: 1, lineHeight: 1.9 }}>
        {fill(language, CHECK_TEXT[check.code], check.params, check.code)}
      </Typography>
      {isAdvanced ? <Ltr mono>{check.code}</Ltr> : null}
    </Stack>
  );
}

export function BuildMirrorPanel({ permissions }: { permissions: readonly string[] }) {
  const { language } = useKit();
  const canWrite = hasPermission(permissions, "dokploy:write");
  const { notify, snackbar } = useUndoSnackbar();
  const { ask, dialog } = useConfirmAction();
  const [copy] = useCopy();
  const [status, setStatus] = useState<Status | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [projects, setProjects] = useState<{ items: Project[]; partial: boolean } | null>(null);
  const [projectsError, setProjectsError] = useState<unknown>(null);
  const [command, setCommand] = useState<Record<string, Command | null>>({});
  const [commandError, setCommandError] = useState<unknown>(null);
  const [restart, setRestart] = useState(false);
  const [showMore, setShowMore] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const toast = (bi: Bi, values: Record<string, string> = {}) => notify({ message: say(language, bi, values) });

  const loadCommands = useCallback(async (withRestart: boolean) => {
    // Each command on its own: «install» needs the image registry's domain, «status»/«undo» don't.
    const next: Record<string, Command | null> = {};
    let installError: unknown = null;
    for (const action of ["install", "status", "undo"]) {
      const query = action === "install" && withRestart ? "&restart=true" : "";
      try {
        next[action] = await getJson<Command>(`${API}/command?action=${action}${query}`);
      } catch (caught) {
        next[action] = null;
        if (action === "install") installError = caught;
      }
    }
    setCommand(next);
    setCommandError(installError);
  }, []);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      const [nextStatus, nextSettings] = await Promise.all([
        getJson<Status>(`${API}/status`, current.signal),
        getJson<Settings>(`${API}/settings`, current.signal)
      ]);
      setStatus(nextStatus);
      setSettings(nextSettings);
      setDraft((previous) => previous ?? nextSettings);
      setError(null);
      try {
        setProjects(await getJson<{ items: Project[]; partial: boolean }>(`${API}/projects`, current.signal));
        setProjectsError(null);
      } catch (caught) {
        if (!isAbortError(caught)) {
          setProjects(null);
          setProjectsError(caught);
        }
      }
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const commandKey = settings ? `${status?.endpoints.registry}|${status?.endpoints.npm}|${status?.endpoints.pypi}` : "";
  useEffect(() => {
    if (commandKey) void loadCommands(restart);
  }, [loadCommands, restart, commandKey]);

  const checks = useMemo(() => new Map((status?.checks ?? []).map((check) => [check.id, check])), [status]);
  const dirty = Boolean(settings && draft && JSON.stringify(pickSettings(settings)) !== JSON.stringify(pickSettings(draft)));

  const saveSettings = async (extra: Record<string, unknown> = {}) => {
    if (!draft) return;
    setBusy(true);
    setActionError(null);
    try {
      const body: Record<string, unknown> = { ...pickSettings(draft), ...extra };
      const next = await mutateJson<Settings>(`${API}/settings`, { method: "PUT", body });
      setSettings(next);
      setDraft(next);
      toast(T.saved);
      await load();
    } catch (caught) {
      setActionError(caught);
    } finally {
      setBusy(false);
    }
  };

  const change = async (mode: "apply" | "remove", targets: "all" | Project[]) => {
    setBusy(true);
    setActionError(null);
    try {
      const body = targets === "all" ? { all: true } : { targets: targets.map((item) => ({ type: item.type, id: item.id })) };
      const result = await mutateJson<{ counts: Record<string, number> }>(`${API}/projects/${mode}`, { method: "POST", body });
      const n = String(result.counts[mode === "apply" ? "applied" : "removed"] ?? 0);
      toast(mode === "apply" ? T.applied : T.removed, { n });
      setSelected(new Set());
      await load();
    } catch (caught) {
      setActionError(caught);
    } finally {
      setBusy(false);
    }
  };

  const undoAll = async () => {
    if (!(await ask({ title: pick(language, T.undoAll), body: pick(language, T.undoAllBody), severity: "disruptive" }))) return;
    await change("remove", "all");
    setShowMore(true);
  };

  const copyReport = async () => {
    try {
      const report = await getJson<{ text: string }>(`${API}/report`);
      await copy(report.text);
      toast(T.reportCopied);
    } catch (caught) {
      setActionError(caught);
    }
  };

  if (error && !status) {
    if (error instanceof ApiError && error.status === 404) return <Notice tone="info">{pick(language, T.moduleMissing)}</Notice>;
    return <FriendlyError error={error} title={pick(language, T.loadFailed)} onRetry={() => void load()} />;
  }
  if (!status || !draft) {
    return (
      <Box sx={{ display: "grid", placeItems: "center", py: 6 }}>
        <CircularProgress size={28} aria-hidden />
      </Box>
    );
  }

  const n = (value: number) => (language === "fa" ? new Intl.NumberFormat("fa-IR").format(value) : String(value));
  const stepTitle = (index: number, title: Bi) => `${say(language, T.step, { n: n(index) })}: ${pick(language, title)}`;
  const items = projects?.items ?? [];
  const chosen = items.filter((item) => selected.has(`${item.type}:${item.id}`));
  const recheck = (
    <Button variant="contained" onClick={() => void load()} disabled={loading} startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <RefreshRoundedIcon />} sx={{ minHeight: 44 }}>
      {pick(language, loading ? T.checking : T.recheck)}
    </Button>
  );
  const toggle = (key: keyof Settings) => (event: React.ChangeEvent<HTMLInputElement>) =>
    setDraft((current) => current && { ...current, [key]: event.target.checked });

  return (
    <Stack spacing={2.5}>
      <Notice tone="info">{pick(language, T.intro)}</Notice>
      {actionError ? <FriendlyError error={actionError} severity="warning" /> : null}

      <SectionCard title={stepTitle(1, T.s1)} hint={pick(language, T.s1Hint)}>
        {PREREQUISITES.map((id) => checks.get(id)).filter(Boolean).map((check) => <CheckRow key={check!.id} check={check!} />)}
      </SectionCard>

      <SectionCard title={stepTitle(2, T.s2)} hint={pick(language, T.s2Hint)}>
        <Stack spacing={1}>
          <FormControlLabel control={<Switch checked={draft.npm} disabled={!canWrite} onChange={toggle("npm")} />} label={pick(language, T.optNpm)} />
          <FormControlLabel control={<Switch checked={draft.pypi} disabled={!canWrite} onChange={toggle("pypi")} />} label={pick(language, T.optPypi)} />
          <FormControlLabel control={<Switch checked={draft.auto_apply_new} disabled={!canWrite} onChange={toggle("auto_apply_new")} />} label={pick(language, T.optAuto)} />
          <TokenSettings permissions={permissions} onSaved={() => void load()} />
          <Typography variant="subtitle2" sx={{ pt: 1 }}>{pick(language, T.addresses)}</Typography>
          <Stack spacing={0.5}>
            {(["npm", "pypi", "registry"] as const).map((key) => (
              <Typography key={key} variant="body2"><Ltr mono>{`${key}: ${status.endpoints[key] ?? "—"}`}</Ltr></Typography>
            ))}
          </Stack>
          {canWrite ? (
            <Box sx={{ pt: 1 }}>
              <Button variant="contained" disabled={!dirty || busy} onClick={() => void saveSettings()} sx={{ minHeight: 44 }}>{pick(language, T.save)}</Button>
            </Box>
          ) : null}
        </Stack>
      </SectionCard>

      <SectionCard title={stepTitle(3, T.s3)} hint={pick(language, T.s3Hint)}>
        <Stack spacing={1.5}>
          {commandError ? (
            errorCode(commandError) === "build_mirror_registry_missing"
              ? <Notice tone="warning">{pick(language, T.needRegistry)}</Notice>
              : <FriendlyError error={commandError} severity="warning" />
          ) : null}
          {command.install ? <CopyField label={pick(language, T.commandLabel)} value={command.install.command} multiline /> : null}
          <Box>
            <FormControlLabel control={<Checkbox checked={restart} onChange={(event) => setRestart(event.target.checked)} />} label={pick(language, T.allowRestart)} />
            <Typography variant="caption" color="text.secondary" component="p">{pick(language, T.allowRestartHint)}</Typography>
          </Box>
          <Notice tone="info">{pick(language, T.s3Other)}</Notice>
          <Box>
            <Button size="small" startIcon={<UndoRoundedIcon />} onClick={() => setShowMore((value) => !value)} aria-expanded={showMore} sx={{ minHeight: 40 }}>
              {pick(language, T.more)}
            </Button>
            <Collapse in={showMore} unmountOnExit>
              <Stack spacing={1.5} sx={{ mt: 1.5 }}>
                {command.status ? <CopyField label={pick(language, T.statusCmd)} value={command.status.command} multiline /> : null}
                {command.undo ? <CopyField label={pick(language, T.undoCmd)} value={command.undo.command} multiline /> : null}
              </Stack>
            </Collapse>
          </Box>
        </Stack>
      </SectionCard>

      <SectionCard title={stepTitle(4, T.s4)} hint={pick(language, T.s4Hint)}>
        <Stack spacing={1.5}>
          {projects?.partial ? <Notice tone="info">{pick(language, T.partial)}</Notice> : null}
          {projectsError ? (
            errorCode(projectsError) === "build_mirror_dokploy_missing"
              ? <Notice tone="warning">{pick(language, T.needDokploy)}</Notice>
              : <FriendlyError error={projectsError} severity="warning" />
          ) : items.length === 0 ? <Typography variant="body2" color="text.secondary">{pick(language, T.noApps)}</Typography> : null}
          {items.map((item) => {
            const key = `${item.type}:${item.id}`;
            const reason = item.reason ? pick(language, REASON_TEXT[item.reason] ?? { fa: item.reason, en: item.reason }) : null;
            const cover = item.coverage;
            return (
              <Stack key={key} direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ sm: "center" }} sx={{ py: 1, borderBottom: 1, borderColor: "divider" }}>
                <Stack direction="row" alignItems="center" sx={{ minWidth: 220 }}>
                  {canWrite ? (
                    <Checkbox
                      checked={selected.has(key)}
                      onChange={(event) => setSelected((current) => {
                        const next = new Set(current);
                        if (event.target.checked) next.add(key);
                        else next.delete(key);
                        return next;
                      })}
                      inputProps={{ "aria-label": item.name }}
                    />
                  ) : null}
                  <Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                    {item.project ? <Typography variant="caption" color="text.secondary">{item.project}</Typography> : null}
                  </Box>
                </Stack>
                <StatusPill tone={STATE_TONE[item.state] ?? "off"} label={pick(language, STATE_TEXT[item.state] ?? STATE_TEXT.unknown)} />
                <Box sx={{ flex: 1 }}>
                  {reason ? <Typography variant="body2" color="text.secondary">{reason}</Typography> : null}
                  {item.overridden.length ? (
                    <Typography variant="caption" color="text.secondary" component="p">
                      {pick(language, { fa: "این نام‌ها را خود برنامه هم دارد؛ مقدار DevAssist برنده است:", en: "The app sets these names too; DevAssist's value wins:" })} <Ltr mono>{item.overridden.join(", ")}</Ltr>
                    </Typography>
                  ) : null}
                  {cover ? (
                    <Typography variant="caption" component="p">
                      {pick(language, { fa: "آخرین ساخت: ", en: "Last build: " })}
                      {pick(language, COVERAGE_TEXT[cover.result] ?? COVERAGE_TEXT.unknown)}
                      {cover.gaps.length ? ` — ${cover.gaps.map((gap) => pick(language, GAP_TEXT[gap] ?? { fa: gap, en: gap })).join(" ")}` : ""}
                    </Typography>
                  ) : null}
                </Box>
              </Stack>
            );
          })}
          <Notice tone="info">{pick(language, T.phase2)}</Notice>
          {canWrite ? (
            <Stack direction={{ xs: "column", sm: "row" }} gap={1}>
              <Button variant="contained" disabled={busy || !items.length || Boolean(projectsError)} onClick={() => void change("apply", "all")} sx={{ minHeight: 44 }}>{pick(language, T.applyAll)}</Button>
              <Button variant="outlined" disabled={busy || !chosen.length} onClick={() => void change("apply", chosen)} sx={{ minHeight: 44 }}>{pick(language, T.applySelected)}</Button>
              <Button color="inherit" disabled={busy || !chosen.length} onClick={() => void change("remove", chosen)} sx={{ minHeight: 44 }}>{pick(language, T.removeSelected)}</Button>
            </Stack>
          ) : null}
        </Stack>
      </SectionCard>

      <SectionCard
        title={stepTitle(5, T.s5)}
        hint={pick(language, T.s5Hint)}
        status={<StatusPill tone={TONE[status.overall] ?? "off"} label={pick(language, status.overall === "ok" ? { fa: "همه درست", en: "All good" } : status.overall === "fail" ? { fa: "مشکل دارد", en: "Has problems" } : { fa: "نیاز به توجه", en: "Needs attention" })} />}
      >
        <Stack spacing={1.5}>
          <Box>{HEALTH.map((id) => checks.get(id)).filter(Boolean).map((check) => <CheckRow key={check!.id} check={check!} />)}</Box>
          <Stack direction={{ xs: "column", sm: "row" }} gap={1}>
            {recheck}
            <Button variant="outlined" startIcon={<ContentCopyRoundedIcon />} onClick={() => void copyReport()} sx={{ minHeight: 44 }}>{pick(language, T.copyReport)}</Button>
            {canWrite && settings?.enabled ? (
              <Button color="error" startIcon={<UndoRoundedIcon />} disabled={busy} onClick={() => void undoAll()} sx={{ minHeight: 44 }}>{pick(language, T.undoAll)}</Button>
            ) : null}
          </Stack>
        </Stack>
      </SectionCard>
      {dialog}
      {snackbar}
    </Stack>
  );
}

type TokenSettingsView = {
  enabled: boolean;
  realm: string;
  trusted_ranges: string[];
  scope: "mirrors" | "all";
  effective_realm: string | null;
  derived_realm: string | null;
};
type TokenDecision = { at: number; ip: string | null; user: string | null; trusted: boolean; result: string; requested: string[]; granted: string[] };

const TT = {
  title: { fa: "دسترسی Docker از راه پنل", en: "Docker access through the panel" },
  hint: {
    fa: "Docker برای آینه رمز نمی‌فرستد. با این گزینه مخزن ایمیج Docker را به پنل می‌فرستد و پنل تصمیم می‌گیرد: از نشانی‌های مورد اعتماد (خود سرور و سرورهای ساخت) فقط «دریافت» بدون رمز؛ بقیه همان قوانین فعلی. نوشتن بدون رمز از هیچ نشانی‌ای ممکن نیست.",
    en: "Docker sends no password to a mirror. With this on, the image registry sends Docker to the panel, which decides: from trusted addresses (this server and build servers) pull-only without a password; everyone else keeps today's rules. No address can push without a password."
  },
  enable: { fa: "روشن", en: "On" },
  ranges: { fa: "نشانی‌های مورد اعتماد (هر خط یک رنج)", en: "Trusted addresses (one range per line)" },
  rangesHint: {
    fa: "پیش‌فرض: خود سرور و شبکه داخلی Docker. نشانی سرورهای ساخت و انتشار دیگر را هم اضافه کنید، مثلاً «203.0.113.7/32».",
    en: "Default: this server and Docker's internal network. Add your other build and deploy servers too, e.g. «203.0.113.7/32»."
  },
  scopeMirrors: { fa: "فقط آینه‌ها و ایمیج‌های رسمی (پیشنهادی)", en: "Only the mirrors and official images (recommended)" },
  scopeAll: { fa: "همه ایمیج‌ها، حتی خصوصی", en: "Every image, private ones too" },
  scopeAllWarning: {
    fa: "هر کانتینری روی همین سرور (حتی برنامه مشتری‌ها) می‌تواند همه ایمیج‌های خصوصی را بخواند. فقط وقتی همه برنامه‌های این سرور مال خودتان است روشن کنید.",
    en: "Any container on this server (customers' apps too) can then read every private image. Only use it when every app on this server is yours."
  },
  realm: { fa: "نشانی صدور مجوز", en: "Token address" },
  realmHint: {
    fa: "خالی یعنی دامنه اصلی پنل. Docker روی همه سرورها باید به این نشانی برسد.",
    en: "Empty means the panel's main domain. Docker on every server must be able to reach it."
  },
  noRealm: { fa: "پنل دامنه ندارد؛ اول در «سرویس‌های من» به پنل دامنه بدهید یا نشانی را بنویسید.", en: "The panel has no domain; give it one in «My services» or type the address." },
  save: { fa: "ذخیره دسترسی Docker", en: "Save Docker access" },
  saved: { fa: "ذخیره شد. مخزن ایمیج چند ثانیه بعد آن را می‌خواند.", en: "Saved. The image registry picks it up in a few seconds." },
  log: { fa: "آخرین درخواست‌های Docker", en: "Latest Docker requests" },
  logEmpty: { fa: "هنوز درخواستی نیامده.", en: "No request yet." },
  noAccess: { fa: "برای تغییر این بخش دسترسی نوشتن مخزن ایمیج لازم است.", en: "Changing this needs write access to the image registry." }
} satisfies Record<string, Bi>;

const RESULT_TEXT: Record<string, Bi> = {
  granted: { fa: "مجوز داده شد", en: "Granted" },
  nothing: { fa: "مجوزی نگرفت", en: "Nothing granted" },
  bad_password: { fa: "رمز اشتباه", en: "Wrong password" },
  disabled: { fa: "خاموش بود", en: "Was off" }
};

function TokenSettings({ permissions, onSaved }: { permissions: readonly string[]; onSaved: () => void }) {
  const { language, isAdvanced } = useKit();
  const canRead = hasPermission(permissions, "registry:read");
  const canWrite = hasPermission(permissions, "registry:write");
  const [view, setView] = useState<TokenSettingsView | null>(null);
  const [draft, setDraft] = useState<{ enabled: boolean; realm: string; ranges: string; scope: "mirrors" | "all" } | null>(null);
  const [log, setLog] = useState<TokenDecision[]>([]);
  const [showLog, setShowLog] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  const load = useCallback(async () => {
    if (!canRead) return;
    try {
      const next = await getJson<TokenSettingsView>("/api/v1/registry/token-settings");
      setView(next);
      setDraft({ enabled: next.enabled, realm: next.realm, ranges: next.trusted_ranges.join("\n"), scope: next.scope });
      setLog((await getJson<{ items: TokenDecision[] }>("/api/v1/registry/token-log")).items);
      setError(null);
    } catch (caught) {
      if (!isAbortError(caught)) setError(caught);
    }
  }, [canRead]);
  useEffect(() => void load(), [load]);

  if (!canRead) return null;
  if (error && !view) return <FriendlyError error={error} severity="warning" />;
  if (!view || !draft) return null;

  const save = async () => {
    setBusy(true);
    setError(null);
    setDone(false);
    try {
      const body = {
        enabled: draft.enabled,
        realm: draft.realm.trim(),
        trusted_ranges: draft.ranges.split("\n").map((line) => line.trim()).filter(Boolean),
        scope: draft.scope
      };
      await mutateJson("/api/v1/registry/token-settings", { method: "PUT", body });
      setDone(true);
      await load();
      onSaved();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box sx={{ mt: 1, p: 2, border: 1, borderColor: "divider", borderRadius: 2 }}>
      <Stack spacing={1.5}>
        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{pick(language, TT.title)}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{pick(language, TT.hint)}</Typography>
        {!canWrite ? <Notice tone="info">{pick(language, TT.noAccess)}</Notice> : null}
        <FormControlLabel
          control={<Switch checked={draft.enabled} disabled={!canWrite || busy} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} />}
          label={pick(language, TT.enable)}
        />
        <TextField
          label={pick(language, TT.ranges)}
          value={draft.ranges}
          onChange={(event) => setDraft({ ...draft, ranges: event.target.value })}
          helperText={pick(language, TT.rangesHint)}
          disabled={!canWrite || busy}
          multiline
          minRows={3}
          inputProps={{ dir: "ltr", style: { fontFamily: "monospace" } }}
        />
        <RadioGroup value={draft.scope} onChange={(event) => setDraft({ ...draft, scope: event.target.value as "mirrors" | "all" })}>
          <FormControlLabel value="mirrors" control={<Radio disabled={!canWrite || busy} />} label={pick(language, TT.scopeMirrors)} />
          <FormControlLabel value="all" control={<Radio disabled={!canWrite || busy} />} label={pick(language, TT.scopeAll)} />
        </RadioGroup>
        {draft.scope === "all" ? <Notice tone="warning">{pick(language, TT.scopeAllWarning)}</Notice> : null}
        {isAdvanced || !view.effective_realm ? (
          <TextField
            label={pick(language, TT.realm)}
            value={draft.realm}
            placeholder={view.derived_realm ?? ""}
            onChange={(event) => setDraft({ ...draft, realm: event.target.value })}
            helperText={pick(language, TT.realmHint)}
            disabled={!canWrite || busy}
            inputProps={{ dir: "ltr" }}
          />
        ) : (
          <Typography variant="body2"><Ltr mono>{view.effective_realm}</Ltr></Typography>
        )}
        {!view.effective_realm && !draft.realm.trim() ? <Notice tone="warning">{pick(language, TT.noRealm)}</Notice> : null}
        {error ? <FriendlyError error={error} severity="warning" /> : null}
        {done ? <Notice tone="success">{pick(language, TT.saved)}</Notice> : null}
        {canWrite ? (
          <Box>
            <Button variant="contained" onClick={() => void save()} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, TT.save)}</Button>
          </Box>
        ) : null}
        <Box>
          <Button size="small" onClick={() => setShowLog((value) => !value)} aria-expanded={showLog}>{pick(language, TT.log)}</Button>
          <Collapse in={showLog} unmountOnExit>
            <Stack spacing={0.5} sx={{ mt: 1 }}>
              {log.length === 0 ? <Typography variant="body2" color="text.secondary">{pick(language, TT.logEmpty)}</Typography> : null}
              {log.slice(0, 20).map((item, index) => (
                <Typography key={`${item.at}-${index}`} variant="caption" component="p">
                  <Ltr mono>{`${new Date(item.at * 1000).toLocaleTimeString()} ${item.ip ?? "?"} ${item.user ?? "-"}${item.trusted ? " (trusted)" : ""} → ${item.granted.join(" ") || "—"}`}</Ltr>
                  {" "}{pick(language, RESULT_TEXT[item.result] ?? { fa: item.result, en: item.result })}
                </Typography>
              ))}
            </Stack>
          </Collapse>
        </Box>
      </Stack>
    </Box>
  );
}

function errorCode(error: unknown): string | null {
  return error instanceof ApiError ? (error.code ?? null) : null;
}

function pickSettings(value: Settings) {
  const { npm, pypi, auto_apply_new } = value;
  return { npm, pypi, auto_apply_new };
}

export default BuildMirrorPanel;
