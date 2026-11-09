/**
 * Kit demo (dev-only route `#/__kit`). Shows every kit component with realistic Persian copy,
 * so Phase 1 agents can see the look and behaviour in Simple/Advanced, fa/en, light/dark, phone/desktop.
 * Wire it from the shell with: lazy(() => import("./kit/KitDemo")) when `import.meta.env.DEV`.
 */
import { useState } from "react";
import { Box, Button, Stack, TextField, Typography } from "@mui/material";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import CloudSyncRoundedIcon from "@mui/icons-material/CloudSyncRounded";
import BackupRoundedIcon from "@mui/icons-material/BackupRounded";
import GroupAddRoundedIcon from "@mui/icons-material/GroupAddRounded";
import LinkRoundedIcon from "@mui/icons-material/LinkRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import NotificationsRoundedIcon from "@mui/icons-material/NotificationsRounded";
import { ApiError } from "../api";
import { CONFIRM_WORDS } from "../copy/confirm";
import { humanizeAudit } from "../copy/audit";
import { ROLES, ROLE_ORDER } from "../copy/roles";
import {
  ActionWizard, AttentionList, Bytes, ChecklistCard, CopyField, DangerZone, DurationInput, EmptyState, FriendlyError,
  GroupTabs, HelpTip, KeyValueList, ListInput, Ltr, NoAccess, Num, OneTimeSecret, PageHeader, Percent, QuickActionGrid,
  QuickActionTile, RelativeTime, ResponsiveList, SchedulePicker, SectionCard, SettingsForm, SETTINGS_FIXTURE,
  SETTINGS_FIXTURE_GROUPS, StatGrid, StatTile, StatusPill, Term, TestResult, UiModeToggle, useConfirmAction, useKit,
  useUndoSnackbar, Verdict, type SettingValue, type TestOutcome
} from "./index";

type DemoRow = { id: number; name: string; ecosystem: string; size: number; status: string; at: number };

const ROWS: DemoRow[] = [
  { id: 1, name: "react", ecosystem: "npm", size: 312_000, status: "pinned", at: Date.now() / 1000 - 600 },
  { id: 2, name: "requests", ecosystem: "pypi", size: 64_000, status: "quarantined", at: Date.now() / 1000 - 90_000 },
  { id: 3, name: "lodash", ecosystem: "npm", size: 1_400_000, status: "ready", at: Date.now() / 1000 - 5 * 86_400 }
];

export default function KitDemo({ permissions = ["*"] }: { permissions?: readonly string[] }) {
  const { language, isAdvanced } = useKit();
  const fa = language === "fa";
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [wizardOpen, setWizardOpen] = useState(false);
  const [secretOpen, setSecretOpen] = useState(false);
  const [name, setName] = useState("");
  const [ttl, setTtl] = useState<number | null>(28800);
  const [cron, setCron] = useState("0 2 * * *");
  const [servers, setServers] = useState<string[]>(["1.1.1.1"]);
  const [test, setTest] = useState<TestOutcome>({ state: "idle" });

  const sampleError = new ApiError(409, "unsafe_upstream_delete", "Refusing to delete the last enabled upstream of npm");
  const unknownError = new ApiError(500, "some_new_code", "Traceback hidden");

  return (
    <Box sx={{ pb: 12 }}>
      <PageHeader
        title={fa ? "نمونه اجزای پنل" : "Panel kit"}
        subtitle={fa ? "همه اجزای مشترک در یک صفحه، برای ساختن صفحه‌های تازه." : "Every shared component on one page."}
        icon={Inventory2RoundedIcon}
        primaryAction={<Button variant="contained" onClick={() => setWizardOpen(true)}>{fa ? "افزودن منبع" : "Add source"}</Button>}
        secondaryActions={<UiModeToggle />}
        tabs={<GroupTabs group="packages" permissions={permissions} value="search" onChange={() => undefined} />}
      />

      <Stack spacing={2.5}>
        <Verdict greeting={fa ? "سلام مریم" : "Hi Maryam"} verdict={fa ? "۲ مورد به توجه شما نیاز دارد" : "2 things need you"} tone="warn" />
        <AttentionList
          title={fa ? "نیاز به توجه" : "Needs attention"}
          items={[
            { id: "disk", severity: "critical", title: fa ? "فضای دیسک رو به اتمام است (۸۷٪)" : "Disk is almost full (87%)", action: { label: fa ? "آزاد کردن فضا" : "Free up space" } },
            { id: "notify", severity: "info", title: fa ? "اگر مشکلی پیش بیاید خبردار نمی‌شوید" : "You won't hear about problems", why: fa ? "هنوز کانال اعلانی ندارید." : "No alert channel yet.", action: { label: fa ? "افزودن تلگرام" : "Add Telegram" } }
          ]}
        />
        <QuickActionGrid>
          <QuickActionTile icon={LinkRoundedIcon} label={fa ? "وصل کردن یک پروژه" : "Connect a project"} />
          <QuickActionTile icon={SearchRoundedIcon} label={fa ? "جست‌وجوی بسته" : "Find a package"} />
          <QuickActionTile icon={BackupRoundedIcon} label={fa ? "پشتیبان‌گیری همین حالا" : "Back up now"} />
          <QuickActionTile icon={GroupAddRoundedIcon} label={fa ? "دعوت همکار" : "Invite a teammate"} />
        </QuickActionGrid>
        <ChecklistCard
          steps={[
            { key: "owner", label: fa ? "ساخت حساب مالک" : "Create the owner account", done: true },
            { key: "project", label: fa ? "وصل کردن اولین پروژه" : "Connect your first project", done: false, onClick: () => undefined },
            { key: "alerts", label: fa ? "افزودن کانال اعلان" : "Add an alert channel", done: false, onClick: () => undefined },
            { key: "domain", label: fa ? "تنظیم آدرس عمومی" : "Set the public address", done: false, optional: true, onClick: () => undefined }
          ]}
          onDismiss={() => undefined}
        />

        <StatGrid>
          <StatTile icon={StorageRoundedIcon} label={fa ? "دیسک" : "Disk"} value={<Percent value={87} />} meter={87} tone="warn" caption={<><Bytes value={43e9} /> / <Bytes value={50e9} /></>} />
          <StatTile icon={Inventory2RoundedIcon} label={fa ? "بسته‌های ذخیره‌شده" : "Cached packages"} value={<Num value={12480} />} tone="ok" />
          <StatTile icon={BackupRoundedIcon} label={fa ? "آخرین پشتیبان" : "Last backup"} value={<RelativeTime value={Date.now() / 1000 - 3 * 3600} relativeAlways />} />
        </StatGrid>

        <SectionCard
          title={fa ? "منابع دریافت npm" : "npm sources"}
          hint={fa ? "DevAssist بسته‌ها را به این ترتیب از منابع می‌گیرد." : "DevAssist fetches packages from these, in order."}
          status={<StatusPill status="ready" />}
          action={<HelpTip term="upstream" />}
        >
          <Typography variant="body2">
            <Term k="upstream" first /> · <Term k="bucket" first withHelp /> · <Ltr mono>https://registry.npmjs.org/</Ltr>
          </Typography>
          <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", rowGap: 1 }}>
            {["running", "succeeded", "failed", "offline", "pending", "dry_run"].map((status) => <StatusPill key={status} status={status} />)}
          </Stack>
          <TestResult outcome={test} />
          <Stack direction="row" spacing={1}>
            <Button variant="outlined" onClick={() => { setTest({ state: "running" }); window.setTimeout(() => setTest({ state: "ok", latencyMs: 320 }), 700); }}>
              {fa ? "امتحان اتصال" : "Test connection"}
            </Button>
            <Button onClick={() => setTest({ state: "fail", code: "proxy_unavailable" })}>{fa ? "نمایش خطا" : "Show failure"}</Button>
          </Stack>
        </SectionCard>

        <SectionCard title={fa ? "خطاها به زبان ساده" : "Friendly errors"}>
          <FriendlyError error={sampleError} onRetry={() => undefined} />
          <FriendlyError error={unknownError} title={fa ? "ذخیره نشد" : "Not saved"} onRetry={() => undefined} />
          <FriendlyError error={new TypeError("Failed to fetch")} onRetry={() => undefined} />
          <NoAccess needs="upstream:write" />
          <NoAccess needs="user:write" ask={fa ? "مریم" : "Maryam"} variant="card" />
        </SectionCard>

        <SectionCard title={fa ? "بسته‌ها" : "Packages"} flush>
          <ResponsiveList
            label={fa ? "بسته‌های ذخیره‌شده" : "Cached packages"}
            rows={ROWS}
            rowKey={(row) => row.id}
            columns={[
              { key: "name", header: fa ? "نام" : "Name", render: (row) => <Ltr>{row.name}</Ltr>, hideOnCard: true },
              { key: "eco", header: fa ? "مخزن" : "Registry", render: (row) => (row.ecosystem === "npm" ? "npm" : "PyPI") },
              { key: "size", header: fa ? "حجم" : "Size", render: (row) => <Bytes value={row.size} /> },
              { key: "at", header: fa ? "آخرین استفاده" : "Last used", render: (row) => <RelativeTime value={row.at} /> },
              { key: "id", header: fa ? "شناسه" : "ID", render: (row) => <Ltr mono>{`pkg-${row.id}`}</Ltr>, advancedOnly: true }
            ]}
            card={{ title: (row) => <Ltr>{row.name}</Ltr>, meta: (row) => <Bytes value={row.size} />, status: (row) => <StatusPill status={row.status} /> }}
            actions={[
              { key: "pin", label: fa ? "نگه‌دار" : "Keep", onClick: (row) => notify({ message: fa ? `«${row.name}» نگه‌داشته شد` : `“${row.name}” is kept`, onUndo: () => undefined }) },
              {
                key: "delete", label: fa ? "پاک کن" : "Remove", icon: DeleteOutlineRoundedIcon, danger: true,
                onClick: async (row) => {
                  const ok = await ask({
                    title: fa ? `بسته «${row.name}» پاک شود؟` : `Remove “${row.name}”?`,
                    body: fa ? "فایل‌های این بسته از ذخیره محلی پاک می‌شوند." : "Its files are removed from local copies.",
                    consequences: [fa ? "تا ۷ روز در سطل بازیافت می‌ماند." : "It stays in the recycle bin for 7 days."],
                    undoable: true,
                    severity: "destructive",
                    typed: CONFIRM_WORDS.prune
                  });
                  if (ok) notify({ message: fa ? "پاک شد" : "Removed" });
                }
              }
            ]}
            empty={<EmptyState title={fa ? "هنوز بسته‌ای ذخیره نشده" : "No packages yet"} body={fa ? "وقتی پروژه‌ها از این سرور نصب کنند، بسته‌ها این‌جا می‌آیند." : "Packages show up here once projects install through this server."} action={<Button variant="contained">{fa ? "وصل کردن یک پروژه" : "Connect a project"}</Button>} />}
          />
        </SectionCard>

        <SectionCard title={fa ? "ورودی‌ها" : "Inputs"}>
          <DurationInput label={fa ? "مدت اعتبار هر ورود" : "Sign-in lasts for"} value={ttl} onChange={setTtl} min={300} max={2592000} />
          <SchedulePicker value={cron} onChange={setCron} />
          <ListInput label={fa ? "سرورهای DNS" : "DNS servers"} value={servers} onChange={setServers} max={6} />
          <CopyField label={fa ? "دستور npm" : "npm command"} value="npm config set registry http://mrk.local:4873/" />
          <KeyValueList
            items={[
              { label: fa ? "نشانی مخزن" : "Registry address", value: "http://mrk.local:4873/", ltr: true, copy: true },
              { label: fa ? "وضعیت" : "Status", value: <StatusPill status="online" /> },
              { label: fa ? "شناسه داخلی" : "Internal id", value: "npm-primary", ltr: true, advancedOnly: true }
            ]}
          />
        </SectionCard>

        <SectionCard title={fa ? "نقش‌ها" : "Roles"} collapsible defaultCollapsed>
          {ROLE_ORDER.map((role) => (
            <Box key={role}>
              <Typography sx={{ fontWeight: 700 }}>{ROLES[role].name[language]}</Typography>
              <Typography variant="body2" color="text.secondary">{ROLES[role].oneLiner[language]}</Typography>
            </Box>
          ))}
          <Typography variant="body2">{humanizeAudit(language, { action: "upstream.delete", object_id: "npm-liara", result: "success" }, { actorName: fa ? "مریم" : "Maryam" }).sentence}</Typography>
        </SectionCard>

        <SettingsForm
          specs={SETTINGS_FIXTURE}
          groups={SETTINGS_FIXTURE_GROUPS}
          permissions={permissions}
          onSave={async (changes: Record<string, SettingValue>) => {
            await new Promise((resolve) => window.setTimeout(resolve, 500));
            const first = Object.keys(changes)[0];
            return { results: Object.fromEntries(Object.keys(changes).map((key) => [key, key === first && key === "network.dns.servers" ? { ok: false, error_code: "invalid_dns_settings" } : { ok: true }])) };
          }}
        />

        <DangerZone
          items={[
            { title: fa ? "قطع اتصال Dokploy" : "Disconnect Dokploy", description: fa ? "برنامه‌ها کار می‌کنند ولی از این‌جا دیده نمی‌شوند." : "Apps keep running but disappear from here.", action: <Button color="error" variant="outlined" onClick={() => void ask({ title: fa ? "اتصال Dokploy قطع شود؟" : "Disconnect Dokploy?", severity: "destructive", typed: CONFIRM_WORDS.disconnect, confirmLabel: fa ? "بله، قطع کن" : "Yes, disconnect" })}>{fa ? "قطع اتصال" : "Disconnect"}</Button> }
          ]}
        />
        {!isAdvanced && <Typography variant="caption" color="text.secondary">{fa ? "منطقه خطر فقط در حالت پیشرفته دیده می‌شود." : "The danger zone shows in Advanced mode only."}</Typography>}
        <Button variant="outlined" startIcon={<NotificationsRoundedIcon />} onClick={() => setSecretOpen(true)}>{fa ? "نمایش رمز یک‌باره" : "Show one-time secret"}</Button>
      </Stack>

      <ActionWizard
        open={wizardOpen}
        title={fa ? "افزودن منبع دریافت" : "Add a package source"}
        finishLabel={fa ? "افزودن منبع" : "Add source"}
        onClose={() => setWizardOpen(false)}
        onFinish={async () => {
          await new Promise((resolve) => window.setTimeout(resolve, 400));
        }}
        steps={[
          {
            key: "url",
            title: fa ? "نشانی منبع" : "Source address",
            hint: fa ? "نشانی سایتی که بسته‌ها از آن گرفته می‌شود." : "The site packages are fetched from.",
            render: () => <TextField fullWidth size="small" label={fa ? "نشانی" : "Address"} value={name} onChange={(event) => setName(event.target.value)} slotProps={{ htmlInput: { dir: "ltr" } }} />,
            validate: () => (/^https?:\/\//.test(name) ? null : fa ? "نشانی باید با https:// شروع شود." : "The address must start with https://.")
          },
          {
            key: "test",
            title: fa ? "امتحان" : "Test",
            nextLabel: fa ? "امتحان اتصال" : "Test connection",
            render: () => <Typography variant="body2">{fa ? "پیش از ذخیره، اتصال را امتحان می‌کنیم." : "We test the connection before saving."}</Typography>,
            onNext: async () => {
              await new Promise((resolve) => window.setTimeout(resolve, 500));
            }
          },
          { key: "done", title: fa ? "ذخیره" : "Save", render: () => <TestResult outcome={{ state: "ok", latencyMs: 210 }} /> }
        ]}
      />
      <OneTimeSecret
        open={secretOpen}
        title={fa ? "کلید دسترسی تازه" : "New access key"}
        body={fa ? "این کلید را در برنامه پشتیبان‌گیری بگذارید." : "Put this key into your backup tool."}
        items={[
          { label: fa ? "کلید دسترسی" : "Access key", value: "MRKAK7Q2EXAMPLE" },
          { label: fa ? "رمز کلید" : "Secret", value: "s3cr3t-example-value-only-for-demo" }
        ]}
        onClose={() => setSecretOpen(false)}
      />
      {dialog}
      {snackbar}
    </Box>
  );
}
