/**
 * Access keys for file space (Files › file space › "Access keys") and "Connect a tool" snippets.
 * Simple: an access-key wizard with four access-level cards (read only / read & write / for backups / manager)
 * and the secret shown once. Advanced: custom JSON policy, per-key on/off and delete, edit, ids and dates.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Box,
  Button,
  Card,
  CardActionArea,
  Checkbox,
  Chip,
  CircularProgress,
  Divider,
  FormControlLabel,
  FormGroup,
  Grid,
  IconButton,
  LinearProgress,
  MenuItem,
  Paper,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography
} from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import EditNoteRoundedIcon from "@mui/icons-material/EditNoteRounded";
import BackupRoundedIcon from "@mui/icons-material/BackupRounded";
import AdminPanelSettingsRoundedIcon from "@mui/icons-material/AdminPanelSettingsRounded";
import DataObjectRoundedIcon from "@mui/icons-material/DataObjectRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import LockResetRoundedIcon from "@mui/icons-material/LockResetRounded";
import { ApiError, getJson, isAbortError, mutateJson } from "./api";
import type { Language } from "./i18n";
import {
  ActionWizard, CopyField, EmptyState, FriendlyError, HelpTip, KeyValueList, Ltr, Notice, PasswordDialog, PasswordInput, RelativeTime,
  SecretOnce, SectionCard, StatusPill, Term, passwordProblem, suggestPassword, useConfirmAction, useKit, useUndoSnackbar, ChoiceCards,
  type PasswordRules, type WizardStep
} from "./kit";
import { nameConfirmation, pick, say, type Bi } from "./copy";

export type S3Key = { access_key_id: string; enabled: boolean; created_at: number | string | null; last_used_at: number | string | null };
export type S3Identity = { id: string; name: string; enabled: boolean; policy_template: Template; buckets: string[]; policy: unknown; keys: S3Key[]; created_at: number | string | null };
export type Template = "read_only" | "read_write" | "admin" | "backup_client" | "custom";
export type NewKey = { access_key_id: string; secret_access_key: string; changed?: boolean };

/** The engine accepts 8-128 printable characters without spaces for a secret key. */
export const S3_SECRET_RULES: PasswordRules = { minLength: 8, maxLength: 128, asciiOnly: true };
export const S3_SECRET_LENGTH = 40;

export function suggestSecretKey() {
  return suggestPassword(S3_SECRET_LENGTH);
}

export function secretKeyProblem(language: Language, value: string) {
  return passwordProblem(language, value, S3_SECRET_RULES);
}

/** The secret-key field of a new key: a suggestion the user may keep or replace. */
export function SecretKeyInput({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const { language } = useKit();
  return <PasswordInput value={value} onChange={onChange} label={pick(language, T.secretKey)} helperText={pick(language, T.secretHint)} rules={S3_SECRET_RULES} suggestLength={S3_SECRET_LENGTH} />;
}
type Connection = { endpoint: string; endpoint_is_fallback?: boolean; internal_endpoint?: string | null; region: string; path_style: boolean; snippets: Record<string, string> };

const BASE = "/api/v1/s3";
const SIMPLE_TEMPLATES: Template[] = ["read_only", "read_write", "backup_client", "admin"];
const ALL_TEMPLATES: Template[] = [...SIMPLE_TEMPLATES, "custom"];
const SIMPLE_SNIPPETS = ["rclone", "restic", "dokploy", "aws_cli"];
const ALL_SNIPPETS = ["rclone", "restic", "dokploy", "aws_cli", "mc", "boto3", "s3cmd"];
const POLICY_EXAMPLE = `{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"] }
  ]
}`;

/** Access-level cards, shared with the bucket wizard. */
export const TEMPLATE_CARDS: Record<Template, { icon: SvgIconComponent; title: Bi; body: Bi }> = {
  read_only: {
    icon: VisibilityRoundedIcon,
    title: { fa: "فقط خواندن", en: "Read only" },
    body: { fa: "فایل‌ها را می‌بیند و دانلود می‌کند؛ چیزی را عوض نمی‌کند.", en: "Can list and download files; changes nothing." }
  },
  read_write: {
    icon: EditNoteRoundedIcon,
    title: { fa: "خواندن و نوشتن", en: "Read and write" },
    body: { fa: "فایل می‌گذارد، دانلود می‌کند و پاک می‌کند.", en: "Can upload, download and delete files." }
  },
  backup_client: {
    icon: BackupRoundedIcon,
    title: { fa: "برای پشتیبان‌گیری", en: "For backups" },
    body: { fa: "مناسب restic و Dokploy: پشتیبان می‌گذارد و می‌خواند، ولی پاک نمی‌کند.", en: "For restic and Dokploy: writes and reads backups, but never deletes." }
  },
  admin: {
    icon: AdminPanelSettingsRoundedIcon,
    title: { fa: "مدیر همه پوشه‌ها", en: "Manager of every bucket" },
    body: { fa: "به همه پوشه‌های اصلی دسترسی کامل دارد. فقط به برنامه‌ای که کاملاً به آن اعتماد دارید بدهید.", en: "Full access to every bucket. Give it only to an app you fully trust." }
  },
  custom: {
    icon: DataObjectRoundedIcon,
    title: { fa: "دسترسی دلخواه", en: "Custom policy (JSON)" },
    body: { fa: "دسترسی را خودتان دقیق بنویسید. فقط برای کاربران حرفه‌ای.", en: "Write the exact IAM policy yourself. For experts only." }
  }
};

const T = {
  identities: { fa: "کلیدهای دسترسی", en: "Access keys" },
  identitiesHint: { fa: "به هر برنامه یا سرور یک کلید جدا بدهید تا اگر لازم شد، فقط همان را قطع کنید.", en: "Give each app or server its own key, so you can cut off just that one if needed." },
  separateUsers: { fa: "این کلیدها فقط برای فضای فایل‌اند و ربطی به کاربران پنل ندارند.", en: "These keys are only for file space; they are separate from panel users." },
  add: { fa: "ساخت کلید دسترسی", en: "Create access key" },
  wizardTitle: { fa: "ساخت کلید دسترسی تازه", en: "New access key" },
  stepName: { fa: "برای چه برنامه‌ای؟", en: "For which app?" },
  stepNameHint: { fa: "یک نام بنویسید که بعداً بفهمید این کلید مال کیست.", en: "Pick a name so you know later who uses this key." },
  name: { fa: "نام", en: "Name" },
  namePlaceholder: { fa: "مثلاً «پشتیبان Dokploy»", en: "For example “Dokploy backups”" },
  nameRequired: { fa: "یک نام بنویسید.", en: "Write a name." },
  stepLevel: { fa: "چه کاری بکند؟", en: "What can it do?" },
  stepLevelHint: { fa: "کمترین دسترسی‌ای را که برنامه لازم دارد انتخاب کنید.", en: "Choose the least access the app needs." },
  stepBuckets: { fa: "کدام پوشه‌ها؟", en: "Which buckets?" },
  stepBucketsHint: { fa: "این کلید فقط به پوشه‌هایی که تیک می‌زنید دسترسی دارد.", en: "The key only reaches the buckets you tick." },
  bucketsRequired: { fa: "دست‌کم یک پوشه اصلی انتخاب کنید.", en: "Choose at least one bucket." },
  noBuckets: { fa: "هنوز پوشه اصلی ندارید. اول یکی بسازید.", en: "You have no buckets yet. Create one first." },
  everyBucket: { fa: "این سطح دسترسی به همه پوشه‌های اصلی می‌رسد؛ لازم نیست پوشه‌ای انتخاب کنید.", en: "This access level covers every bucket; no need to choose." },
  adv_policy: { fa: "متن دسترسی دلخواه", en: "Policy (JSON)" },
  adv_policyInvalid: { fa: "ساختار متن درست نیست؛ شاید یک ویرگول یا آکولاد جا افتاده باشد.", en: "The text must be valid JSON; a comma or brace is missing." },
  adv_policyShape: { fa: "متن باید «Version» و فهرست «Statement» داشته باشد.", en: "The policy needs a “Version” and a “Statement” list." },
  createKeyNow: { fa: "همین حالا کلید هم ساخته شود", en: "Create a key right away" },
  create: { fa: "ساخت کلید", en: "Create key" },
  save: { fa: "ذخیره", en: "Save" },
  editTitle: { fa: "ویرایش «{name}»", en: "Edit “{name}”" },
  created: { fa: "کلید «{name}» ساخته شد.", en: "Key “{name}” created." },
  saved: { fa: "تغییرات «{name}» ذخیره شد.", en: "Changes to “{name}” saved." },
  emptyTitle: { fa: "هنوز کلید دسترسی ندارید", en: "No access keys yet" },
  emptyBody: { fa: "برنامه‌ها با کلید دسترسی به فضای فایل وصل می‌شوند؛ مثلاً برای پشتیبان‌گیری Dokploy.", en: "Apps connect to file space with an access key — for example Dokploy backups." },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  turnedOn: { fa: "«{name}» روشن شد.", en: "“{name}” turned on." },
  turnedOff: { fa: "«{name}» خاموش شد؛ برنامه‌هایش فعلاً وصل نمی‌شوند.", en: "“{name}” turned off; its apps can't connect for now." },
  keys: { fa: "کلیدها", en: "Keys" },
  noKeys: { fa: "هنوز کلیدی ندارد. با «کلید تازه» یکی بسازید.", en: "No key yet. Use “New key” to make one." },
  keyLabel: { fa: "کلید …{last}", en: "Key …{last}" },
  newKey: { fa: "کلید تازه", en: "New key" },
  lastUsed: { fa: "آخرین استفاده:", en: "Last used:" },
  neverUsed: { fa: "هنوز استفاده نشده", en: "Not used yet" },
  createdAt: { fa: "ساخته شده:", en: "Created:" },
  deleteKey: { fa: "پاک کردن کلید", en: "Delete key" },
  deleteKeyTitle: { fa: "کلید «…{last}» پاک شود؟", en: "Delete key “…{last}”?" },
  deleteKeyBody: { fa: "برنامه‌هایی که از این کلید استفاده می‌کنند قطع می‌شوند.", en: "Apps that use this key are cut off." },
  deleteIdentity: { fa: "پاک کردن", en: "Delete" },
  deleteIdentityTitle: { fa: "«{name}» با همه کلیدهایش پاک شود؟", en: "Delete “{name}” and all its keys?" },
  deleteIdentityBody: { fa: "همه برنامه‌هایی که از کلیدهای آن استفاده می‌کنند قطع می‌شوند.", en: "Every app using its keys is cut off." },
  deleted: { fa: "«{name}» پاک شد.", en: "“{name}” deleted." },
  edit: { fa: "ویرایش", en: "Edit" },
  secretTitle: { fa: "کلید دسترسی ساخته شد", en: "Access key created" },
  secretBody: { fa: "این دو مقدار را در تنظیمات برنامه بگذارید. رمز کلید فقط همین یک بار نمایش داده می‌شود؛ همین حالا کپی کنید.", en: "Put both values in your app's settings. The secret is shown only this once; copy it now." },
  accessKey: { fa: "کلید دسترسی (Access Key)", en: "Access Key ID" },
  secretKey: { fa: "رمز کلید (Secret Key)", en: "Secret Access Key" },
  secretHint: { fa: "یک رمز قوی پیشنهاد شده است. می‌توانید همین را نگه دارید یا رمز خودتان را بنویسید.", en: "A strong secret is suggested. Keep it or type your own." },
  newKeyTitle: { fa: "کلید تازه برای «{name}»", en: "New key for “{name}”" },
  newKeyHint: { fa: "شناسه کلید خودکار ساخته می‌شود. رمز کلید را می‌توانید خودتان انتخاب کنید.", en: "The key ID is made automatically. You can choose the secret yourself." },
  makeKey: { fa: "ساخت کلید", en: "Create key" },
  changeSecret: { fa: "عوض کردن رمز کلید", en: "Change secret" },
  changeSecretTitle: { fa: "رمز تازه برای کلید «…{last}»", en: "New secret for key “…{last}”" },
  changeSecretHint: { fa: "شناسه کلید همان می‌ماند. رمز قبلی بلافاصله از کار می‌افتد؛ رمز تازه را در برنامه‌ها بگذارید.", en: "The key ID stays the same. The old secret stops working at once; put the new one in your apps." },
  saveSecret: { fa: "ذخیره رمز", en: "Save secret" },
  secretChangedTitle: { fa: "رمز کلید عوض شد", en: "The secret was changed" },
  connect: { fa: "اتصال ابزارها", en: "Connect a tool" },
  connectHint: { fa: "آدرس و تنظیمات آماده برای ابزارهای رایج. رمز کلید را همان موقع ساختن کلید کپی کرده‌اید.", en: "Address and ready settings for common tools. You copied the secret when you made the key." },
  bucket: { fa: "پوشه اصلی", en: "Bucket" },
  anyBucket: { fa: "بدون پوشه خاص", en: "No specific bucket" },
  key: { fa: "کلید دسترسی", en: "Access key" },
  noKey: { fa: "بدون کلید (جای خالی بگذار)", en: "No key (leave a placeholder)" },
  endpoint: { fa: "آدرس فضای فایل", en: "Endpoint" },
  internalEndpoint: { fa: "آدرس برای برنامه‌های همین سرور", en: "Address for apps on this server" },
  region: { fa: "منطقه", en: "Region" },
  pathStyle: { fa: "نوع آدرس‌دهی", en: "Addressing style" },
  pathStyleYes: { fa: "نام پوشه در مسیر آدرس", en: "Path-style" },
  pathStyleNo: { fa: "نام پوشه در دامنه", en: "Virtual-host style" },
  fallbackWarning: { fa: "آدرس عمومی فضای فایل تنظیم نشده؛ ابزارهای بیرون از این سرور شاید نتوانند وصل شوند.", en: "The public address isn't set, so tools outside this server may not connect." },
  s_dokploy: { fa: "Dokploy (مقصد پشتیبان)", en: "Dokploy (backup destination)" },
  noSnippet: { fa: "سرور برای این ابزار نمونه آماده‌ای نفرستاد.", en: "The server sent no ready settings for this tool." },
  level: { fa: "سطح دسترسی", en: "Access level" },
  listLabel: { fa: "کلیدهای دسترسی", en: "Access keys" },
  id: { fa: "شناسه", en: "ID" }
} satisfies Record<string, Bi>;

const SNIPPET_LABELS: Record<string, Bi> = {
  aws_cli: { fa: "AWS CLI", en: "AWS CLI" },
  rclone: { fa: "rclone", en: "rclone" },
  restic: { fa: "restic", en: "restic" },
  dokploy: T.s_dokploy,
  mc: { fa: "MinIO mc", en: "MinIO mc" },
  boto3: { fa: "Python boto3", en: "Python boto3" },
  s3cmd: { fa: "s3cmd", en: "s3cmd" }
};

function last4(id: string) {
  return id.slice(-4);
}

function policyProblem(text: string, language: Language): string | null {
  try {
    const parsed = JSON.parse(text) as { Version?: unknown; Statement?: unknown };
    if (!parsed || typeof parsed !== "object" || !parsed.Version || !Array.isArray(parsed.Statement)) return pick(language, T.adv_policyShape);
    return null;
  } catch {
    return pick(language, T.adv_policyInvalid);
  }
}

function BucketPicker({ bucketNames, value, onChange }: { bucketNames: string[]; value: string[]; onChange: (next: string[]) => void }) {
  const { language } = useKit();
  if (bucketNames.length === 0) return <Notice tone="warning">{pick(language, T.noBuckets)}</Notice>;
  return (
    <FormGroup aria-label={pick(language, T.stepBuckets)}>
      {bucketNames.map((bucket) => (
        <FormControlLabel
          key={bucket}
          sx={{ minHeight: 44 }}
          control={<Checkbox checked={value.includes(bucket)} onChange={(event) => onChange(event.target.checked ? [...value, bucket] : value.filter((item) => item !== bucket))} />}
          label={<Ltr>{bucket}</Ltr>}
        />
      ))}
    </FormGroup>
  );
}

/** Create (wizard) or edit (Advanced) an access key holder. */
function IdentityWizard({ bucketNames, editing, presetBuckets, onClose, onDone }: {
  bucketNames: string[];
  editing: S3Identity | null;
  presetBuckets?: string[];
  onClose: () => void;
  onDone: (message: string, secret: NewKey | null) => void;
}) {
  const { language, isAdvanced } = useKit();
  const templates = isAdvanced ? ALL_TEMPLATES : SIMPLE_TEMPLATES;
  const [name, setName] = useState(editing?.name ?? "");
  const [template, setTemplate] = useState<Template>(editing?.policy_template ?? "read_write");
  const [buckets, setBuckets] = useState<string[]>(editing?.buckets ?? presetBuckets ?? (bucketNames.length === 1 ? bucketNames : []));
  const [policy, setPolicy] = useState(editing?.policy ? JSON.stringify(editing.policy, null, 2) : POLICY_EXAMPLE);
  const [withKey, setWithKey] = useState(!editing);
  const [secretKey, setSecretKey] = useState(suggestSecretKey);
  const needsBuckets = template !== "admin" && template !== "custom";
  const shown = templates.includes(template) ? templates : [...templates, template];

  const steps: WizardStep[] = [
    {
      key: "name",
      title: pick(language, T.stepName),
      hint: pick(language, T.stepNameHint),
      validate: () => (name.trim() ? null : pick(language, T.nameRequired)),
      render: () => (
        <TextField
          fullWidth
          autoFocus
          label={pick(language, T.name)}
          placeholder={pick(language, T.namePlaceholder)}
          value={name}
          onChange={(event) => setName(event.target.value)}
          slotProps={{ htmlInput: { dir: "auto", maxLength: 64 } }}
        />
      )
    },
    {
      key: "level",
      title: pick(language, T.stepLevel),
      hint: pick(language, T.stepLevelHint),
      validate: () => (template === "custom" ? policyProblem(policy, language) : null),
      render: () => (
        <Stack spacing={1.5}>
          <ChoiceCards
            label={pick(language, T.level)}
            value={template}
            onChange={setTemplate}
            options={shown.map((key) => ({
              key,
              icon: TEMPLATE_CARDS[key].icon,
              title: pick(language, TEMPLATE_CARDS[key].title),
              body: pick(language, TEMPLATE_CARDS[key].body),
              tone: key === "admin" ? ("warning" as const) : undefined
            }))}
          />
          {template === "custom" && (
            <TextField
              fullWidth
              multiline
              minRows={8}
              label={pick(language, T.adv_policy)}
              value={policy}
              error={Boolean(policyProblem(policy, language))}
              helperText={policyProblem(policy, language) ?? " "}
              onChange={(event) => setPolicy(event.target.value)}
              slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, style: { fontFamily: "ui-monospace, Consolas, monospace", fontSize: 12.5 } } }}
            />
          )}
        </Stack>
      )
    },
    {
      key: "buckets",
      title: pick(language, T.stepBuckets),
      hint: needsBuckets ? pick(language, T.stepBucketsHint) : undefined,
      validate: () => {
        if (needsBuckets && buckets.length === 0) return pick(language, T.bucketsRequired);
        return !editing && withKey ? secretKeyProblem(language, secretKey) : null;
      },
      render: () => (
        <Stack spacing={1.5}>
          {needsBuckets ? <BucketPicker bucketNames={bucketNames} value={buckets} onChange={setBuckets} /> : <Notice>{pick(language, T.everyBucket)}</Notice>}
          {!editing && isAdvanced && (
            <FormControlLabel control={<Checkbox checked={withKey} onChange={(event) => setWithKey(event.target.checked)} />} label={pick(language, T.createKeyNow)} />
          )}
          {!editing && withKey && <SecretKeyInput value={secretKey} onChange={setSecretKey} />}
        </Stack>
      )
    }
  ];

  const finish = async () => {
    const body: Record<string, unknown> = { name: name.trim(), policy_template: template, buckets: needsBuckets ? buckets : [] };
    if (template === "custom") body.policy = JSON.parse(policy);
    if (editing) {
      await mutateJson(`${BASE}/identities/${encodeURIComponent(editing.id)}`, { method: "PATCH", body });
      onDone(say(language, T.saved, { name: name.trim() }), null);
      return;
    }
    const created = await mutateJson<S3Identity | null>(`${BASE}/identities`, { method: "POST", body });
    let secret: NewKey | null = null;
    if (withKey && created?.id) {
      secret = await mutateJson<NewKey>(`${BASE}/identities/${encodeURIComponent(created.id)}/keys`, { method: "POST", body: { secret_access_key: secretKey } });
    }
    onDone(say(language, T.created, { name: name.trim() }), secret);
  };

  return (
    <ActionWizard
      open
      title={editing ? say(language, T.editTitle, { name: editing.name }) : pick(language, T.wizardTitle)}
      steps={steps}
      onFinish={finish}
      onClose={onClose}
      finishLabel={pick(language, editing ? T.save : T.create)}
    />
  );
}

/** Show a freshly created key once (the user must tick «کپی کردم»). */
export function KeySecretDialog({ secret, onClose }: { secret: NewKey | null; onClose: () => void }) {
  const { language } = useKit();
  return (
    <SecretOnce
      open={secret !== null}
      title={pick(language, secret?.changed ? T.secretChangedTitle : T.secretTitle)}
      body={pick(language, T.secretBody)}
      items={secret ? [
        { label: pick(language, T.accessKey), value: secret.access_key_id },
        { label: pick(language, T.secretKey), value: secret.secret_access_key }
      ] : []}
      onClose={onClose}
    />
  );
}

/** Create one identity + key in one go (used by the bucket wizard). */
export async function createKeyFor(name: string, bucket: string, template: Exclude<Template, "custom" | "admin">, secretKey?: string): Promise<NewKey | null> {
  const created = await mutateJson<S3Identity | null>(`${BASE}/identities`, { method: "POST", body: { name, policy_template: template, buckets: [bucket] } });
  if (!created?.id) return null;
  return mutateJson<NewKey>(`${BASE}/identities/${encodeURIComponent(created.id)}/keys`, { method: "POST", body: secretKey ? { secret_access_key: secretKey } : {} });
}

export function S3Identities({ language, bucketNames, onChanged }: { language: Language; bucketNames: string[]; onChanged?: () => void }) {
  const { isAdvanced } = useKit();
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [items, setItems] = useState<S3Identity[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [wizard, setWizard] = useState<{ editing: S3Identity | null } | null>(null);
  const [secret, setSecret] = useState<NewKey | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [newKeyFor, setNewKeyFor] = useState<S3Identity | null>(null);
  const [changing, setChanging] = useState<{ identity: S3Identity; key: S3Key } | null>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const payload = await getJson<{ items: S3Identity[] }>(`${BASE}/identities`, signal);
      setItems(payload.items ?? []);
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const act = async (id: string, action: () => Promise<void>) => {
    setBusy(id);
    setError(null);
    try {
      await action();
      await load();
      onChanged?.();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setBusy(null);
    }
  };

  const identityPath = (identity: S3Identity) => `${BASE}/identities/${encodeURIComponent(identity.id)}`;

  const setEnabled = (identity: S3Identity, value: boolean) => act(identity.id, async () => {
    await mutateJson(identityPath(identity), { method: "PATCH", body: { enabled: value } });
    notify({
      message: say(language, value ? T.turnedOn : T.turnedOff, { name: identity.name }),
      onUndo: () => void act(identity.id, async () => { await mutateJson(identityPath(identity), { method: "PATCH", body: { enabled: !value } }); })
    });
  });

  const addButton = (
    <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setWizard({ editing: null })} sx={{ minHeight: 44 }}>{pick(language, T.add)}</Button>
  );

  return (
    <SectionCard title={pick(language, T.identities)} hint={pick(language, T.identitiesHint)} action={items && items.length > 0 ? addButton : <HelpTip term="accessKey" />}>
      <Stack spacing={1.5}>
        {error !== null && <FriendlyError error={error} onRetry={() => void load()} onClose={() => setError(null)} />}
        {items === null && error === null && <LinearProgress />}
        {items !== null && items.length === 0 && (
          <EmptyState icon={KeyRoundedIcon} title={pick(language, T.emptyTitle)} body={pick(language, T.emptyBody)} action={addButton} />
        )}
        {items !== null && items.length > 0 && <Typography variant="body2" color="text.secondary">{pick(language, T.separateUsers)}</Typography>}
        <Grid container spacing={1.5}>
          {(items ?? []).map((identity) => (
            <Grid key={identity.id} size={{ xs: 12, lg: 6 }}>
              <Paper variant="outlined" sx={{ p: 2, borderRadius: 1.25, height: "100%" }}>
                <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={1}>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography fontWeight={760} dir="auto" noWrap>{identity.name}</Typography>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ mt: 0.5 }}>
                      <Chip size="small" color="primary" variant="outlined" label={pick(language, TEMPLATE_CARDS[identity.policy_template]?.title ?? TEMPLATE_CARDS.custom.title)} />
                      {identity.buckets.map((bucket) => <Chip key={bucket} size="small" variant="outlined" label={<Ltr>{bucket}</Ltr>} />)}
                      <StatusPill status={identity.enabled ? "enabled" : "disabled"} size="small" />
                    </Stack>
                  </Box>
                  <Switch
                    checked={identity.enabled}
                    disabled={busy === identity.id}
                    onChange={(_event, value) => void setEnabled(identity, value)}
                    slotProps={{ input: { "aria-label": `${pick(language, identity.enabled ? T.on : T.off)} · ${identity.name}` } }}
                  />
                </Stack>
                {isAdvanced && <Typography variant="caption" color="text.secondary">{pick(language, T.id)}: <Ltr mono>{identity.id}</Ltr></Typography>}
                <Divider sx={{ my: 1.25 }} />
                <Typography variant="caption" color="text.secondary" fontWeight={700}>{pick(language, T.keys)}</Typography>
                {identity.keys.length === 0 && <Typography variant="body2" color="text.secondary">{pick(language, T.noKeys)}</Typography>}
                <Stack spacing={0.75} sx={{ mt: 0.5 }}>
                  {identity.keys.map((key) => (
                    <Stack key={key.access_key_id} direction="row" alignItems="center" spacing={1} sx={{ minWidth: 0 }}>
                      <KeyRoundedIcon fontSize="small" color={key.enabled ? "success" : "disabled"} aria-hidden />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="body2" noWrap>
                          {isAdvanced ? <Ltr mono>{key.access_key_id}</Ltr> : say(language, T.keyLabel, { last: last4(key.access_key_id) })}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {pick(language, T.lastUsed)} {key.last_used_at ? <RelativeTime value={key.last_used_at} /> : pick(language, T.neverUsed)}
                          {isAdvanced && <> · {pick(language, T.createdAt)} <RelativeTime value={key.created_at} /></>}
                        </Typography>
                      </Box>
                      {isAdvanced && (
                        <Switch
                          size="small"
                          checked={key.enabled}
                          disabled={busy === identity.id}
                          onChange={(_event, value) => void act(identity.id, async () => { await mutateJson(`${identityPath(identity)}/keys/${encodeURIComponent(key.access_key_id)}`, { method: "PATCH", body: { enabled: value } }); })}
                          slotProps={{ input: { "aria-label": `${pick(language, T.on)} · ${key.access_key_id}` } }}
                        />
                      )}
                      <Tooltip title={pick(language, T.changeSecret)}>
                        <span>
                          <IconButton
                            aria-label={`${pick(language, T.changeSecret)} · ${last4(key.access_key_id)}`}
                            disabled={busy === identity.id}
                            sx={{ width: 44, height: 44 }}
                            onClick={() => setChanging({ identity, key })}
                          >
                            <LockResetRoundedIcon fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                      <Tooltip title={pick(language, T.deleteKey)}>
                        <span>
                          <IconButton
                            color="error"
                            aria-label={`${pick(language, T.deleteKey)} · ${last4(key.access_key_id)}`}
                            disabled={busy === identity.id}
                            sx={{ width: 44, height: 44 }}
                            onClick={() => void (async () => {
                              const ok = await ask({ title: say(language, T.deleteKeyTitle, { last: last4(key.access_key_id) }), body: pick(language, T.deleteKeyBody), severity: "destructive", undoable: false });
                              if (!ok) return;
                              await act(identity.id, async () => { await mutateJson(`${identityPath(identity)}/keys/${encodeURIComponent(key.access_key_id)}`, { method: "DELETE" }); });
                            })()}
                          >
                            <DeleteOutlineRoundedIcon fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </Stack>
                  ))}
                </Stack>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ mt: 1.25 }}>
                  <Button
                    startIcon={busy === identity.id ? <CircularProgress size={14} /> : <KeyRoundedIcon />}
                    disabled={busy === identity.id}
                    sx={{ minHeight: 44 }}
                    onClick={() => setNewKeyFor(identity)}
                  >
                    {pick(language, T.newKey)}
                  </Button>
                  {isAdvanced && <Button startIcon={<EditRoundedIcon />} onClick={() => setWizard({ editing: identity })} sx={{ minHeight: 44 }}>{pick(language, T.edit)}</Button>}
                  <Button
                    color="error"
                    startIcon={<DeleteOutlineRoundedIcon />}
                    sx={{ minHeight: 44 }}
                    onClick={() => void (async () => {
                      const ok = await ask({
                        title: say(language, T.deleteIdentityTitle, { name: identity.name }),
                        body: pick(language, T.deleteIdentityBody),
                        severity: "destructive",
                        undoable: false,
                        typed: nameConfirmation(identity.name, identity.name)
                      });
                      if (!ok) return;
                      await act(identity.id, async () => { await mutateJson(identityPath(identity), { method: "DELETE", body: { confirmation: identity.name } }); });
                      notify({ message: say(language, T.deleted, { name: identity.name }) });
                    })()}
                  >
                    {pick(language, T.deleteIdentity)}
                  </Button>
                </Stack>
              </Paper>
            </Grid>
          ))}
        </Grid>
        <Typography variant="caption" color="text.secondary"><Term k="accessKey" first /> · <Term k="secretKey" first /></Typography>
      </Stack>
      {wizard && (
        <IdentityWizard
          bucketNames={bucketNames}
          editing={wizard.editing}
          onClose={() => setWizard(null)}
          onDone={(message, created) => {
            setWizard(null);
            notify({ message });
            if (created) setSecret(created);
            void load();
            onChanged?.();
          }}
        />
      )}
      <PasswordDialog
        open={newKeyFor !== null}
        title={say(language, T.newKeyTitle, { name: newKeyFor?.name ?? "" })}
        hint={pick(language, T.newKeyHint)}
        label={pick(language, T.secretKey)}
        saveLabel={pick(language, T.makeKey)}
        rules={S3_SECRET_RULES}
        suggestLength={S3_SECRET_LENGTH}
        onClose={() => setNewKeyFor(null)}
        onSubmit={async (value) => {
          if (!newKeyFor) return;
          const created = await mutateJson<NewKey>(`${identityPath(newKeyFor)}/keys`, { method: "POST", body: { secret_access_key: value } });
          setNewKeyFor(null);
          setSecret(created);
          await load();
          onChanged?.();
        }}
      />
      <PasswordDialog
        open={changing !== null}
        title={say(language, T.changeSecretTitle, { last: changing ? last4(changing.key.access_key_id) : "" })}
        hint={pick(language, T.changeSecretHint)}
        label={pick(language, T.secretKey)}
        saveLabel={pick(language, T.saveSecret)}
        rules={S3_SECRET_RULES}
        suggestLength={S3_SECRET_LENGTH}
        onClose={() => setChanging(null)}
        onSubmit={async (value) => {
          if (!changing) return;
          const path = `${identityPath(changing.identity)}/keys/${encodeURIComponent(changing.key.access_key_id)}/secret`;
          const result = await mutateJson<NewKey>(path, { method: "POST", body: { secret_access_key: value } });
          setChanging(null);
          setSecret({ access_key_id: result?.access_key_id ?? changing.key.access_key_id, secret_access_key: result?.secret_access_key ?? value, changed: true });
        }}
      />
      <KeySecretDialog secret={secret} onClose={() => setSecret(null)} />
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

export function S3Connect({ language, bucketNames, canAdmin }: { language: Language; bucketNames: string[]; canAdmin: boolean }) {
  const { isAdvanced } = useKit();
  const snippetKeys = isAdvanced ? ALL_SNIPPETS : SIMPLE_SNIPPETS;
  const [bucket, setBucket] = useState(bucketNames[0] ?? "");
  const [keyId, setKeyId] = useState("");
  const [keys, setKeys] = useState<string[]>([]);
  const [connection, setConnection] = useState<Connection | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState(0);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    if (!canAdmin) return;
    const controller = new AbortController();
    void (async () => {
      try {
        const payload = await getJson<{ items: S3Identity[] }>(`${BASE}/identities`, controller.signal);
        setKeys((payload.items ?? []).flatMap((identity) => identity.keys.filter((key) => key.enabled).map((key) => key.access_key_id)));
      } catch {
        // the key list is optional
      }
    })();
    return () => controller.abort();
  }, [canAdmin]);

  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams();
    if (bucket) params.set("bucket", bucket);
    if (keyId) params.set("access_key_id", keyId);
    void (async () => {
      try {
        setConnection(await getJson<Connection>(`${BASE}/connection?${params.toString()}`, controller.signal));
        setError(null);
      } catch (caught) {
        if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
        setError(caught);
      }
    })();
    return () => controller.abort();
  }, [bucket, keyId, reload]);

  const visibleSnippets = useMemo(() => snippetKeys.filter((key) => connection?.snippets?.[key] !== undefined || SIMPLE_SNIPPETS.includes(key)), [connection, snippetKeys]);
  const activeTab = Math.min(tab, Math.max(0, visibleSnippets.length - 1));
  const activeKey = visibleSnippets[activeTab];
  const snippet = activeKey ? connection?.snippets?.[activeKey] : undefined;
  const snippetLabel = (key: string) => pick(language, SNIPPET_LABELS[key] ?? { fa: key, en: key });

  return (
    <SectionCard title={pick(language, T.connect)} hint={pick(language, T.connectHint)}>
      <Stack spacing={2}>
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
          <TextField select size="small" label={pick(language, T.bucket)} value={bucket} onChange={(event) => setBucket(event.target.value)} sx={{ minWidth: 200 }}>
            <MenuItem value="">{pick(language, T.anyBucket)}</MenuItem>
            {bucketNames.map((name) => <MenuItem key={name} value={name}><Ltr>{name}</Ltr></MenuItem>)}
          </TextField>
          {canAdmin && (
            <TextField select size="small" label={pick(language, T.key)} value={keyId} onChange={(event) => setKeyId(event.target.value)} sx={{ minWidth: 240 }}>
              <MenuItem value="">{pick(language, T.noKey)}</MenuItem>
              {keys.map((akid) => (
                <MenuItem key={akid} value={akid}>{isAdvanced ? <Ltr mono>{akid}</Ltr> : say(language, T.keyLabel, { last: last4(akid) })}</MenuItem>
              ))}
            </TextField>
          )}
        </Stack>
        {error !== null && <FriendlyError error={error} onRetry={() => setReload((value) => value + 1)} />}
        {connection === null && error === null && <LinearProgress />}
        {connection && (
          <Stack spacing={1.5}>
            {connection.endpoint_is_fallback && <Notice tone="warning">{pick(language, T.fallbackWarning)}</Notice>}
            <CopyField label={pick(language, T.endpoint)} value={connection.endpoint} />
            {isAdvanced && connection.internal_endpoint && <CopyField label={pick(language, T.internalEndpoint)} value={connection.internal_endpoint} />}
            <KeyValueList
              dense
              items={[
                { label: pick(language, T.region), value: connection.region, ltr: true, copy: true },
                { label: pick(language, T.pathStyle), value: pick(language, connection.path_style ? T.pathStyleYes : T.pathStyleNo), advancedOnly: true }
              ]}
            />
            <Tabs value={activeTab} onChange={(_event, value: number) => setTab(value)} variant="scrollable" allowScrollButtonsMobile aria-label={pick(language, T.connect)}>
              {visibleSnippets.map((key) => <Tab key={key} label={snippetLabel(key)} sx={{ textTransform: "none", minHeight: 44 }} />)}
            </Tabs>
            {snippet ? <CopyField label={snippetLabel(activeKey!)} value={snippet} multiline /> : <Typography variant="body2" color="text.secondary">{pick(language, T.noSnippet)}</Typography>}
          </Stack>
        )}
      </Stack>
    </SectionCard>
  );
}
