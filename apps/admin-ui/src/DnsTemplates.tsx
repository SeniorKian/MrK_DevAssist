/**
 * «DNS › قالب‌ها» (contract docs/41 §5, §7).
 *
 * A template is a ready set of records (website, email, Google Workspace, …) that a new domain gets
 * in one click. This file holds:
 * - `TemplateChooser`: the part of «افزودن دامنه» that picks a template (the default one is already
 *   picked), asks only for the few variables needed and says in plain words what will be made;
 * - `ApplyTemplateDialog`: add a template's records to an existing domain, with a preview of
 *   new / already there / clashing records, applied as one change;
 * - the «قالب‌ها» tab: view, copy, edit, delete and choose the default.
 */
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Divider, FormControlLabel, IconButton, MenuItem, Paper,
  Stack, Switch, TextField, Tooltip, Typography, useMediaQuery, useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import StarRoundedIcon from "@mui/icons-material/StarRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import DashboardCustomizeRoundedIcon from "@mui/icons-material/DashboardCustomizeRounded";
import CheckCircleOutlineRoundedIcon from "@mui/icons-material/CheckCircleOutlineRounded";
import RemoveCircleOutlineRoundedIcon from "@mui/icons-material/RemoveCircleOutlineRounded";
import ErrorOutlineRoundedIcon from "@mui/icons-material/ErrorOutlineRounded";
import { hasPermission } from "./api";
import { errorSentence, pick, say, type Bi } from "./copy";
import { EmptyState, FriendlyError, ListInput, Ltr, NoAccess, Notice, SectionCard, StatusPill, useConfirmAction, useKit, useUndoSnackbar } from "./kit";
import { RECORD_SPECS, RECORD_TYPES, TTL_MAX, dnsFieldMessages, isDnsName, isRecordType, recordTypeLabel } from "./dns";
import {
  applyTemplate, askedVariables, cleanVariables, createTemplate, deleteTemplate, expandRecord, fetchTemplates, hasPlaceholder, initialVariables,
  isAutoVariable, missingVariables, previewTemplate, setDefaultTemplate, templateDescription, templateName, templateRecordSentence, templateValue,
  updateTemplate, variableLabel, VARIABLE_WORDS, type DnsTemplate, type PreviewRecord, type TemplateInput, type TemplateList, type TemplatePreview, type TemplateRecord,
  type TemplateVariable
} from "./dnsFinal";
import { FormDialog, Loading, isMissingEndpoint, ltrInput, useLoader } from "./dnsUi";

export const TEMPLATE_COPY = {
  template: { fa: "قالب", en: "Template" },
  templateHint: { fa: "رکوردهای آماده‌ای که همراه دامنه ساخته می‌شوند. بعداً هر کدام را می‌توانید تغییر دهید.", en: "Ready records made with the domain. You can change any of them later." },
  none: { fa: "بدون قالب (دامنه خالی)", en: "No template (empty domain)" },
  noneBody: { fa: "فقط خود دامنه ساخته می‌شود؛ رکوردها را خودتان اضافه می‌کنید.", en: "Only the domain is made; you add the records yourself." },
  defaultBadge: { fa: "پیش‌فرض", en: "Default" },
  builtinBadge: { fa: "آماده", en: "Built-in" },
  willCreate: { fa: "این‌ها ساخته می‌شود", en: "This will be made" },
  willCreateCount: { fa: "{count} رکورد", en: "{count} records" },
  askTitle: { fa: "فقط این‌ها را بنویسید", en: "Just fill these in" },
  required: { fa: "لازم", en: "Needed" },
  optional: { fa: "اختیاری", en: "Optional" },
  fillRequired: { fa: "این را بنویسید تا رکوردهایش ساخته شود.", en: "Fill this in so its records can be made." },
  autoValue: { fa: "خودکار", en: "Automatic" },
  serverV4: { fa: "IPv4 این سرور", en: "this server's IPv4" },
  serverV6: { fa: "IPv6 این سرور", en: "this server's IPv6" },
  yourDomain: { fa: "دامنه شما", en: "your domain" },
  templatesMissing: { fa: "قالب‌ها روی نسخه فعلی سرور نیستند؛ دامنه خالی ساخته می‌شود.", en: "Templates aren't on your server's current version; an empty domain is made." },
  templatesFailed: { fa: "فهرست قالب‌ها خوانده نشد.", en: "The list of templates didn't load." },
  autoNote: { fa: "نشانی سرور را DevAssist خودش پیدا می‌کند و جای آن می‌گذارد.", en: "DevAssist finds the server's address and puts it in." },
  // apply
  applyTitle: { fa: "افزودن رکوردهای یک قالب به «{zone}»", en: "Add a template's records to “{zone}”" },
  applyHint: { fa: "رکوردهای تازه اضافه می‌شوند؛ رکوردهایی که از قبل هست دست نمی‌خورد. همه در یک تغییر انجام می‌شود و از «تاریخچه» برمی‌گردد.", en: "New records are added; records already there aren't touched. It's all one change, which you can undo from History." },
  applyButton: { fa: "افزودن رکوردها", en: "Add the records" },
  applyCount: { fa: "افزودن {count} رکورد", en: "Add {count} records" },
  applied: { fa: "رکوردهای قالب به «{zone}» اضافه شد.", en: "The template's records were added to “{zone}”." },
  pickTemplate: { fa: "یک قالب انتخاب کنید", en: "Pick a template" },
  checking: { fa: "در حال بررسی…", en: "Checking…" },
  statusNew: { fa: "تازه", en: "New" },
  statusDuplicate: { fa: "از قبل هست", en: "Already there" },
  statusConflict: { fa: "با رکورد فعلی جور نیست", en: "Clashes with a current record" },
  statusSkipped: { fa: "ساخته نمی‌شود (خانه‌اش خالی است)", en: "Not made (its field is empty)" },
  replaceConflicts: { fa: "رکوردهای فعلیِ ناجور را با رکوردهای قالب جایگزین کن", en: "Replace the clashing current records with the template's" },
  replaceHint: { fa: "خاموش: تا وقتی ناجوری هست، چیزی اضافه نمی‌شود. روشن: رکوردهای ناجور فعلی برداشته و رکوردهای قالب گذاشته می‌شوند (از «تاریخچه» برمی‌گردد).", en: "Off: nothing is added while there are clashes. On: the clashing current records are removed and the template's are put in (undo from History)." },
  replaceRemoves: { fa: "{count} رکورد فعلی برداشته می‌شود.", en: "{count} current records will be removed." },
  replaceComments: { fa: "یادداشت {count} رکورد پاک می‌شود.", en: "The notes of {count} records are dropped." },
  conflictsBlock: { fa: "چند رکورد با رکوردهای فعلی جور نیست. برای ادامه، جایگزینی را روشن کنید یا اول آن رکوردها را دستی تغییر دهید.", en: "Some records clash with current ones. To go on, turn on replacing, or change those records by hand first." },
  serverIpUnknown: { fa: "DevAssist نشانی عمومی سرور را پیدا نکرد؛ آن را بنویسید تا رکوردهای سایت ساخته شوند.", en: "DevAssist couldn't find the server's public address; write it so the site records can be made." },
  createdNoTemplate: { fa: "دامنه ساخته شد، ولی رکوردهای قالب اضافه نشد. از داخل دامنه «افزودن رکوردهای یک قالب» را بزنید.", en: "The domain was made, but the template's records weren't added. Use “Add a template's records” inside the domain." },
  nothingNew: { fa: "همه رکوردهای این قالب از قبل در این دامنه هست.", en: "Every record of this template is already in this domain." },
  previewFailed: { fa: "پیش‌نمایش از سرور نیامد؛ فهرست زیر از روی خود قالب است.", en: "The server didn't send a preview; the list below is from the template itself." },
  // page
  pageTitle: { fa: "قالب‌های دامنه", en: "Domain templates" },
  pageHint: { fa: "وقتی دامنه تازه می‌سازید، رکوردهای قالب پیش‌فرض خودکار ساخته می‌شوند. قالب‌های آماده را کپی کنید و به سلیقه خودتان تغییر دهید.", en: "When you make a new domain, the default template's records are made automatically. Copy a ready template and change it your way." },
  newTemplate: { fa: "قالب تازه", en: "New template" },
  emptyTitle: { fa: "هنوز قالبی نیست", en: "No templates yet" },
  emptyBody: { fa: "یک قالب بسازید تا دامنه‌های تازه با همان رکوردها ساخته شوند.", en: "Make a template so new domains are made with the same records." },
  view: { fa: "دیدن", en: "View" },
  copy: { fa: "کپی", en: "Copy" },
  edit: { fa: "تغییر", en: "Edit" },
  remove: { fa: "پاک کردن", en: "Delete" },
  makeDefault: { fa: "پیش‌فرض شود", en: "Make default" },
  clearDefault: { fa: "بدون قالب پیش‌فرض", en: "No default template" },
  clearDefaultHint: { fa: "دامنه‌های تازه خالی ساخته شوند، مگر خودتان قالبی انتخاب کنید.", en: "New domains are made empty unless you pick a template." },
  defaultSet: { fa: "«{name}» قالب پیش‌فرض شد.", en: "“{name}” is now the default template." },
  defaultCleared: { fa: "دیگر قالب پیش‌فرضی نیست.", en: "There's no default template now." },
  copyOf: { fa: "کپی {name}", en: "Copy of {name}" },
  builtinNote: { fa: "قالب‌های آماده تغییر نمی‌کنند؛ یک کپی بگیرید و کپی را تغییر دهید.", en: "Built-in templates don't change; copy one and edit the copy." },
  removeTitle: { fa: "قالب «{name}» پاک شود؟", en: "Delete the template “{name}”?" },
  removeBody: { fa: "دامنه‌هایی که با این قالب ساخته شده‌اند دست نمی‌خورند.", en: "Domains already made with it aren't touched." },
  removed: { fa: "قالب «{name}» پاک شد.", en: "The template “{name}” was deleted." },
  saved: { fa: "قالب «{name}» ذخیره شد.", en: "The template “{name}” was saved." },
  records: { fa: "{count} رکورد", en: "{count} records" },
  variablesCount: { fa: "{count} پرسش", en: "{count} questions" },
  adminNeeded: { fa: "ساختن و تغییر قالب‌ها", en: "Making and changing templates" },
  sampleDomain: { fa: "دامنه نمونه برای پیش‌نمایش", en: "Sample domain for the preview" },
  viewTitle: { fa: "قالب «{name}»", en: "Template “{name}”" },
  // editor
  editorNew: { fa: "قالب تازه", en: "New template" },
  editorEdit: { fa: "تغییر قالب «{name}»", en: "Edit template “{name}”" },
  name: { fa: "نام قالب", en: "Template name" },
  description: { fa: "توضیح کوتاه", en: "Short description" },
  recordsTitle: { fa: "رکوردها", en: "Records" },
  recordsHint: {
    fa: "در نام و مقدار می‌توانید این‌ها را بنویسید تا هنگام ساخت پر شوند: {domain} نام دامنه، {server_ipv4} و {server_ipv6} نشانی سرور، یا یک نام دلخواه مثل {mail_host}.",
    en: "In names and values you can write these to be filled in when the domain is made: {domain} the domain, {server_ipv4} and {server_ipv6} the server's address, or a name of your own like {mail_host}."
  },
  addRecord: { fa: "افزودن رکورد", en: "Add a record" },
  recordName: { fa: "نام", en: "Name" },
  recordType: { fa: "نوع", en: "Type" },
  ttl: { fa: "نگه‌داری (ثانیه، اختیاری)", en: "Keep for (seconds, optional)" },
  comment: { fa: "یادداشت", en: "Note" },
  removeRow: { fa: "برداشتن این رکورد", en: "Remove this record" },
  variablesTitle: { fa: "پرسش‌ها", en: "Questions" },
  variablesHint: { fa: "چیزهایی که هنگام ساخت دامنه پرسیده می‌شود. نشانی سرور و نام دامنه خودکار پر می‌شوند و لازم نیست اینجا باشند.", en: "What's asked when a domain is made. The server's address and the domain name fill in by themselves." },
  addVariable: { fa: "افزودن پرسش", en: "Add a question" },
  varKey: { fa: "نام کوتاه (انگلیسی)", en: "Short name" },
  varKeyHint: { fa: "مثل mail_host؛ در رکوردها به‌صورت {mail_host}", en: "Like mail_host; used as {mail_host} in records" },
  varLabelFa: { fa: "پرسش به فارسی", en: "Question in Persian" },
  varLabelEn: { fa: "پرسش به انگلیسی", en: "Question in English" },
  varDefault: { fa: "مقدار پیش‌فرض", en: "Default value" },
  varRequired: { fa: "حتماً پرسیده شود", en: "Must be filled" },
  zoneTitle: { fa: "مشخصات دامنه", en: "Domain details" },
  zoneHint: { fa: "اختیاری؛ خالی بماند تا مقدارهای معمول DevAssist استفاده شود.", en: "Optional; leave empty to use DevAssist's usual values." },
  zoneTtl: { fa: "نگه‌داری پیش‌فرض رکوردها (ثانیه)", en: "Default keep time for records (seconds)" },
  nameServers: { fa: "سرورهای نام «NS»", en: "Name servers (NS)" },
  hostmaster: { fa: "ایمیل مسئول دامنه", en: "Domain contact email" },
  refresh: { fa: "فاصله بررسی نسخه دوم (ثانیه)", en: "Copy check interval (seconds)" },
  retry: { fa: "تلاش دوباره (ثانیه)", en: "Retry (seconds)" },
  expire: { fa: "انقضای نسخه دوم (ثانیه)", en: "Copy expiry (seconds)" },
  minimum: { fa: "نگه‌داری جواب «نیست» (ثانیه)", en: "Keep “not found” answers (seconds)" },
  save: { fa: "ذخیره قالب", en: "Save template" },
  nameNeeded: { fa: "یک نام برای قالب بنویسید.", en: "Give the template a name." },
  badRecordName: { fa: "نام را مثل «www» یا @ بنویسید.", en: "Write the name like www or @." },
  fieldNeeded: { fa: "این خانه را پر کنید.", en: "Fill in this field." },
  badVarKey: { fa: "فقط حروف کوچک انگلیسی، عدد و _ ؛ مثل mail_host", en: "Lowercase letters, digits and _ only; like mail_host" },
  duplicateVar: { fa: "این نام کوتاه تکراری است.", en: "This short name is used twice." },
  badTtl: { fa: "عددی بین ۰ تا ۶۰۴۸۰۰ بنویسید.", en: "Write a number from 0 to 604800." },
  recordsNeeded: { fa: "دست‌کم یک رکورد اضافه کنید.", en: "Add at least one record." },
  fixFirst: { fa: "اول خانه‌های قرمز را درست کنید.", en: "Fix the fields in red first." }
} satisfies Record<string, Bi>;

const C = TEMPLATE_COPY;
const AUTO_WORDS: Record<string, Bi> = { server_ipv4: C.serverV4, server_ipv6: C.serverV6 };

/** Values for the plain-words list: typed ones, server-filled ones, then words for the automatic ones. */
function displayValues(language: "fa" | "en", zone: string, typed: Record<string, string>, server: Record<string, string>): Record<string, string> {
  const values: Record<string, string> = { domain: zone || pick(language, C.yourDomain) };
  for (const [key, word] of Object.entries(AUTO_WORDS)) values[key] = pick(language, word);
  return { ...values, ...server, ...cleanVariables(typed), domain: zone || server.domain || values.domain };
}

// ── shared pieces ────────────────────────────────────────────────────────────

const STATUS_LOOK: Record<string, { icon: typeof CheckCircleOutlineRoundedIcon; color: "success" | "disabled" | "warning"; label: Bi }> = {
  new: { icon: CheckCircleOutlineRoundedIcon, color: "success", label: C.statusNew },
  duplicate: { icon: RemoveCircleOutlineRoundedIcon, color: "disabled", label: C.statusDuplicate },
  conflict: { icon: ErrorOutlineRoundedIcon, color: "warning", label: C.statusConflict },
  skipped: { icon: RemoveCircleOutlineRoundedIcon, color: "disabled", label: C.statusSkipped }
};

/** «این‌ها ساخته می‌شود»: one plain sentence per record; Advanced adds the technical line. */
export function TemplateSummary({ records, zone, values, showStatus }: { records: (TemplateRecord | PreviewRecord)[]; zone: string; values: Record<string, string>; showStatus?: boolean }) {
  const { language, isAdvanced } = useKit();
  if (!records.length) return null;
  return (
    <Stack component="ul" spacing={1} sx={{ listStyle: "none", m: 0, p: 0 }}>
      {records.map((raw, index) => {
        const record = expandRecord(raw, values, "…");
        const status = showStatus ? (raw as PreviewRecord).status ?? "new" : null;
        const look = status ? STATUS_LOOK[status] ?? STATUS_LOOK.new : STATUS_LOOK.new;
        const Icon = look.icon;
        const value = templateValue(record);
        return (
          <Stack component="li" key={`${raw.type}-${raw.name}-${index}`} direction="row" spacing={1.25} alignItems="flex-start">
            <Icon fontSize="small" color={look.color} aria-hidden sx={{ mt: 0.4 }} />
            <Box sx={{ minWidth: 0, flex: 1 }}>
              <Typography variant="body2" sx={{ lineHeight: 1.9, overflowWrap: "anywhere", opacity: status === "duplicate" || status === "skipped" ? 0.7 : 1, textDecoration: status === "skipped" ? "line-through" : undefined }}>
                {templateRecordSentence(language, record, zone)}
                {status && status !== "new" ? <Chip size="small" variant="outlined" label={pick(language, look.label)} sx={{ mx: 1 }} /> : null}
              </Typography>
              {isAdvanced ? (
                <Typography variant="caption" color="text.secondary" component="div" sx={{ overflowWrap: "anywhere" }}>
                  <Ltr mono>{`${record.name || "@"} ${typeof record.ttl === "number" ? `${record.ttl} ` : ""}${record.type} ${value}`}</Ltr>
                </Typography>
              ) : null}
            </Box>
          </Stack>
        );
      })}
    </Stack>
  );
}

/** One input per variable the template needs (automatic ones only in Advanced, as overrides). */
function VariableFields({ template, values, onChange, touched, serverValues, fieldErrors = {}, alsoAsk = [] }: {
  template: DnsTemplate; values: Record<string, string>; onChange: (values: Record<string, string>) => void; touched: boolean; serverValues: Record<string, string>;
  /** Server reasons keyed `variables.<key>`. */
  fieldErrors?: Record<string, string>;
  /** Automatic variables to ask even in Simple mode (e.g. the server's address wasn't found). */
  alsoAsk?: string[];
}) {
  const { language, isAdvanced } = useKit();
  const all = askedVariables(template, true);
  const asked = all.filter((item) => isAdvanced || !isAutoVariable(item.key) || alsoAsk.includes(item.key));
  for (const key of alsoAsk) if (!asked.some((item) => item.key === key)) asked.push({ key, required: false });
  if (!asked.length) return null;
  return (
    <Stack spacing={1.5}>
      <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, C.askTitle)}</Typography>
      {asked.map((variable) => {
        const auto = isAutoVariable(variable.key);
        const value = values[variable.key] ?? "";
        const empty = !value.trim();
        const problem = fieldErrors[`variables.${variable.key}`] ?? (touched && variable.required && !auto && empty ? pick(language, C.fillRequired) : null);
        const known = VARIABLE_WORDS[variable.key]?.hint;
        const helper = problem ?? (auto ? (serverValues[variable.key] ? `${pick(language, C.autoValue)}: ${serverValues[variable.key]}` : known ? pick(language, known) : pick(language, C.autoValue)) : known ? pick(language, known) : variable.required ? pick(language, C.required) : pick(language, C.optional));
        return (
          <TextField
            key={variable.key}
            label={variableLabel(language, variable)}
            value={value}
            onChange={(event) => onChange({ ...values, [variable.key]: event.target.value })}
            required={Boolean(variable.required && !auto)}
            placeholder={auto ? serverValues[variable.key] ?? pick(language, C.autoValue) : variable.default ?? undefined}
            error={Boolean(problem)}
            helperText={helper}
            fullWidth
            multiline={variable.key === "dkim_value"}
            slotProps={ltrInput}
          />
        );
      })}
    </Stack>
  );
}

/** Ask the server for its preview (debounced). `null` while nothing came back. */
function useServerPreview(templateId: string | null, zone: string, variables: Record<string, string>, enabled: boolean) {
  const [preview, setPreview] = useState<TemplatePreview | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const key = JSON.stringify(cleanVariables(variables));
  useEffect(() => {
    setPreview(null);
    setError(null);
    if (!enabled || !templateId || !zone) return;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setLoading(true);
      previewTemplate(templateId, zone, JSON.parse(key) as Record<string, string>, controller.signal)
        .then((result) => setPreview(result), (caught) => { if (!controller.signal.aborted) setError(caught); })
        .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    }, 450);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [templateId, zone, key, enabled]);
  return { preview, error, loading };
}

/**
 * What the chooser reports. `known` = the server has templates (so «بدون قالب» must be sent as
 * `template_id: null`; leaving it out means «the default template», docs/41 §0.3).
 */
export type TemplateChoice = { templateId: string | null; variables: Record<string, string>; ready: boolean; known: boolean };

const countOf = (records: PreviewRecord[], status: string) => records.filter((record) => (record.status ?? "new") === status).length;

/**
 * The template part of «افزودن دامنه». The default template is picked on first load; the person
 * can pick another or «بدون قالب». Reports the choice with `onChange`.
 */
export function TemplateChooser({ zone, zoneValid, touched, onChange, fieldErrors }: {
  zone: string; zoneValid: boolean; touched: boolean; onChange: (choice: TemplateChoice) => void; fieldErrors?: Record<string, string>;
}) {
  const { language } = useKit();
  const loader = useCallback((signal: AbortSignal) => fetchTemplates(signal), []);
  const { data, error, loading } = useLoader<TemplateList>(loader);
  const [templateId, setTemplateId] = useState<string | null | undefined>(undefined);
  const [variables, setVariables] = useState<Record<string, string>>({});
  const templates = data?.items ?? [];
  const template = templates.find((item) => item.id === templateId) ?? null;

  // Pick the default once the list arrives.
  useEffect(() => {
    if (templateId !== undefined || !data) return;
    const initial = data.items.find((item) => item.id === data.defaultId) ?? null;
    setTemplateId(initial?.id ?? null);
    setVariables(initialVariables(initial));
  }, [data, templateId]);

  const server = useServerPreview(template?.id ?? null, zone, variables, zoneValid);
  const ipUnknown = Boolean(server.preview?.warnings.includes("server_ipv4_unknown")) && !(variables.server_ipv4 ?? "").trim();
  const missing = missingVariables(template, variables);
  const settled = templateId !== undefined || Boolean(error);
  const ready = settled && missing.length === 0;
  const known = Boolean(data && data.items.length);
  useEffect(() => {
    onChange({ templateId: template?.id ?? null, variables: cleanVariables(variables), ready, known });
    // `onChange` is a state setter in practice; listening to it would loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [template?.id, JSON.stringify(variables), ready, known]);

  const values = displayValues(language, zone, variables, server.preview?.variables ?? {});
  const records: PreviewRecord[] = server.preview?.records.length ? server.preview.records : template?.records ?? [];
  const made = records.length - countOf(records, "skipped");
  const usesServerAddress = template ? template.records.some((record) => /\{server_ipv[46]\}/i.test(JSON.stringify(record))) : false;

  if (error && !data) {
    return isMissingEndpoint(error)
      ? <Typography variant="caption" color="text.secondary">{pick(language, C.templatesMissing)}</Typography>
      : <FriendlyError error={error} title={pick(language, C.templatesFailed)} severity="warning" />;
  }
  if (!data && loading) return <Loading />;
  if (!data || !templates.length) return null;

  const pickTemplate = (id: string) => {
    const next = id === "__none" ? null : templates.find((item) => item.id === id) ?? null;
    setTemplateId(next?.id ?? null);
    setVariables(initialVariables(next));
  };

  return (
    <Stack spacing={2}>
      <TextField
        select
        label={pick(language, C.template)}
        value={template?.id ?? "__none"}
        onChange={(event) => pickTemplate(event.target.value)}
        helperText={template ? templateDescription(language, template) || pick(language, C.templateHint) : pick(language, C.noneBody)}
        fullWidth
      >
        {templates.map((item) => (
          <MenuItem key={item.id} value={item.id}>
            <Stack direction="row" gap={1} alignItems="center" sx={{ minWidth: 0 }}>
              <span>{templateName(language, item)}</span>
              {item.id === data.defaultId ? <Chip size="small" color="primary" variant="outlined" label={pick(language, C.defaultBadge)} /> : null}
            </Stack>
          </MenuItem>
        ))}
        <Divider />
        <MenuItem value="__none">{pick(language, C.none)}</MenuItem>
      </TextField>
      {template ? (
        <>
          {ipUnknown ? <Notice tone="warning">{pick(language, C.serverIpUnknown)}</Notice> : null}
          <VariableFields template={template} values={variables} onChange={setVariables} touched={touched} serverValues={server.preview?.variables ?? {}} fieldErrors={fieldErrors} alsoAsk={ipUnknown ? ["server_ipv4"] : []} />
          {/* «فضای من» lists templates without their records (docs/43 §0.1): nothing to summarise then. */}
          {records.length > 0 || server.loading ? <Paper variant="outlined" sx={{ p: 1.75, borderRadius: 2 }}>
            <Stack spacing={1.25}>
              <Stack direction="row" alignItems="center" justifyContent="space-between" gap={1}>
                <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, C.willCreate)}</Typography>
                {server.loading ? <CircularProgress size={14} aria-label={pick(language, C.checking)} /> : <Typography variant="caption" color="text.secondary">{say(language, C.willCreateCount, { count: made })}</Typography>}
              </Stack>
              <TemplateSummary records={records} zone={zone} values={values} showStatus={Boolean(server.preview)} />
              {usesServerAddress && !server.preview?.variables?.server_ipv4 && !ipUnknown ? <Typography variant="caption" color="text.secondary">{pick(language, C.autoNote)}</Typography> : null}
            </Stack>
          </Paper> : null}
        </>
      ) : null}
    </Stack>
  );
}

// ── apply to an existing zone ────────────────────────────────────────────────

export function ApplyTemplateDialog({ zone, onClose, onApplied }: { zone: string; onClose: () => void; onApplied: () => void }) {
  const { language } = useKit();
  const loader = useCallback((signal: AbortSignal) => fetchTemplates(signal), []);
  const { data, error: listError } = useLoader<TemplateList>(loader);
  const [templateId, setTemplateId] = useState<string | null>(null);
  const [variables, setVariables] = useState<Record<string, string>>({});
  const [replace, setReplace] = useState(false);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const templates = data?.items ?? [];
  const template = templates.find((item) => item.id === templateId) ?? null;
  const missing = missingVariables(template, variables);
  const server = useServerPreview(template?.id ?? null, zone, variables, Boolean(template) && missing.length === 0);
  const preview = server.preview;
  const values = displayValues(language, zone, variables, preview?.variables ?? {});
  const fromServer = Boolean(preview);
  const records: PreviewRecord[] = preview ? preview.records : template?.records ?? [];
  const fresh = preview ? preview.summary?.new ?? countOf(records, "new") : records.length;
  const conflicts = preview ? preview.summary?.conflict ?? countOf(records, "conflict") : 0;
  const ipUnknown = Boolean(preview?.warnings.includes("server_ipv4_unknown")) && !(variables.server_ipv4 ?? "").trim();
  const blockedByConflicts = conflicts > 0 && !replace;
  const nothingToDo = fromServer && fresh === 0 && conflicts === 0;
  const fieldErrors = useMemo(() => dnsFieldMessages(language, error), [language, error]);

  useEffect(() => {
    if (templateId || !data?.items.length) return;
    const initial = data.items.find((item) => item.id === data.defaultId) ?? data.items[0];
    setTemplateId(initial.id);
    setVariables(initialVariables(initial));
  }, [data, templateId]);

  const run = async () => {
    setTouched(true);
    if (!template || missing.length || blockedByConflicts) return;
    setBusy(true);
    setError(null);
    try {
      await applyTemplate(zone, template.id, cleanVariables(variables), replace && conflicts > 0);
      onApplied();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const effects = preview?.replaceEffects;
  return (
    <FormDialog
      title={say(language, C.applyTitle, { zone })}
      hint={pick(language, C.applyHint)}
      submitLabel={fromServer && fresh + (replace ? conflicts : 0) > 0 ? say(language, C.applyCount, { count: fresh + (replace ? conflicts : 0) }) : pick(language, C.applyButton)}
      busy={busy}
      error={error ?? listError}
      disabled={!template || nothingToDo || blockedByConflicts}
      onSubmit={() => void run()}
      onClose={onClose}
      wide
    >
      {!data && !listError ? <Loading /> : null}
      {templates.length ? (
        <TextField select label={pick(language, C.pickTemplate)} value={template?.id ?? ""} onChange={(event) => {
          const next = templates.find((item) => item.id === event.target.value) ?? null;
          setTemplateId(next?.id ?? null);
          setVariables(initialVariables(next));
          setReplace(false);
        }} helperText={template ? templateDescription(language, template) || " " : " "} fullWidth>
          {templates.map((item) => <MenuItem key={item.id} value={item.id}>{templateName(language, item)}</MenuItem>)}
        </TextField>
      ) : null}
      {template ? (
        <>
          {ipUnknown ? <Notice tone="warning">{pick(language, C.serverIpUnknown)}</Notice> : null}
          <VariableFields template={template} values={variables} onChange={setVariables} touched={touched} serverValues={preview?.variables ?? {}} fieldErrors={fieldErrors} alsoAsk={ipUnknown ? ["server_ipv4"] : []} />
          {server.error ? <Typography variant="caption" color="text.secondary">{pick(language, C.previewFailed)}</Typography> : null}
          <Paper variant="outlined" sx={{ p: 1.75, borderRadius: 2 }}>
            <Stack spacing={1.25}>
              <Stack direction="row" alignItems="center" justifyContent="space-between">
                <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, C.willCreate)}</Typography>
                {server.loading ? <CircularProgress size={14} aria-label={pick(language, C.checking)} /> : null}
              </Stack>
              <TemplateSummary records={records} zone={zone} values={values} showStatus={fromServer} />
              {nothingToDo ? <Notice tone="info">{pick(language, C.nothingNew)}</Notice> : null}
            </Stack>
          </Paper>
          {conflicts > 0 ? (
            <Stack spacing={1}>
              <FormControlLabel control={<Switch checked={replace} color="warning" onChange={(event) => setReplace(event.target.checked)} />} label={pick(language, C.replaceConflicts)} />
              <Typography variant="caption" color="text.secondary">{pick(language, C.replaceHint)}</Typography>
              {replace && typeof effects?.removes === "number" ? <Typography variant="body2" color="warning.main">{say(language, C.replaceRemoves, { count: effects.removes })}</Typography> : null}
              {replace && effects?.comments_dropped ? <Typography variant="body2" color="warning.main">{say(language, C.replaceComments, { count: effects.comments_dropped })}</Typography> : null}
              {!replace ? <Notice tone="warning">{pick(language, C.conflictsBlock)}</Notice> : null}
            </Stack>
          ) : null}
        </>
      ) : null}
    </FormDialog>
  );
}

// ── editor ───────────────────────────────────────────────────────────────────

type DraftRecord = { key: number; name: string; type: string; ttl: string; fields: Record<string, string>; comment: string };
type DraftVariable = { key: number; name: string; label_fa: string; label_en: string; default: string; required: boolean };

let draftKey = 0;
const nextKey = () => ++draftKey;

function toDraftRecord(record: TemplateRecord): DraftRecord {
  const type = record.type || "A";
  const specFields = isRecordType(type) ? RECORD_SPECS[type].fields : [{ key: "value" }];
  const fields: Record<string, string> = {};
  if (typeof record.data === "string") fields[specFields[0].key] = record.data;
  else for (const field of specFields) fields[field.key] = record.data?.[field.key] === undefined || record.data?.[field.key] === null ? "" : String(record.data[field.key]);
  return { key: nextKey(), name: record.name || "@", type, ttl: typeof record.ttl === "number" ? String(record.ttl) : "", fields, comment: record.comment ?? "" };
}

function emptyFields(type: string): Record<string, string> {
  if (!isRecordType(type)) return { value: "" };
  return Object.fromEntries(RECORD_SPECS[type].fields.map((field) => [field.key, field.defaultValue !== undefined ? String(field.defaultValue) : ""]));
}

const VAR_KEY = /^[a-z][a-z0-9_]{0,31}$/;
const digits = (text: string) => text.replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit)));

function TemplateEditor({ initial, mode, onClose, onSaved }: { initial: DnsTemplate | null; mode: "new" | "edit" | "copy"; onClose: () => void; onSaved: (name: string) => void }) {
  const { language, isAdvanced } = useKit();
  const [name, setName] = useState(() => (mode === "copy" && initial ? say(language, C.copyOf, { name: templateName(language, initial) }) : initial ? templateName(language, initial) : ""));
  const [description, setDescription] = useState(() => (initial ? templateDescription(language, initial) : ""));
  const [records, setRecords] = useState<DraftRecord[]>(() => (initial?.records.length ? initial.records.map(toDraftRecord) : [toDraftRecord({ name: "@", type: "A", data: { address: "{server_ipv4}" } })]));
  const [variables, setVariables] = useState<DraftVariable[]>(() => (initial?.variables ?? []).map((item) => ({ key: nextKey(), name: item.key, label_fa: item.label_fa ?? "", label_en: item.label_en ?? "", default: item.default ?? "", required: Boolean(item.required) })));
  const [zoneTtl, setZoneTtl] = useState(initial?.zone?.ttl ? String(initial.zone.ttl) : "");
  const [ns, setNs] = useState<string[]>(initial?.zone?.ns ?? []);
  const [soa, setSoa] = useState<Record<string, string>>(() => {
    const value = initial?.zone?.soa ?? {};
    return Object.fromEntries(["hostmaster", "refresh", "retry", "expire", "minimum"].map((key) => [key, value[key as keyof typeof value] === undefined || value[key as keyof typeof value] === null ? "" : String(value[key as keyof typeof value])]));
  });
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const serverFields = useMemo(() => dnsFieldMessages(language, error), [language, error]);

  const ttlProblem = (text: string) => {
    if (!text.trim()) return null;
    const value = Number(digits(text.trim()));
    return Number.isInteger(value) && value >= 0 && value <= TTL_MAX ? null : pick(language, C.badTtl);
  };
  const recordNameProblem = (text: string) => {
    const filled = text.trim().replace(/\{[a-z0-9_]+\}/gi, "x");
    return filled && isDnsName(filled, true) ? null : pick(language, C.badRecordName);
  };
  const problems: Record<string, string> = {};
  if (!name.trim()) problems.name = pick(language, C.nameNeeded);
  if (!records.length) problems.records = pick(language, C.recordsNeeded);
  records.forEach((record) => {
    const nameProblem = recordNameProblem(record.name);
    if (nameProblem) problems[`r${record.key}.name`] = nameProblem;
    const ttl = ttlProblem(record.ttl);
    if (ttl) problems[`r${record.key}.ttl`] = ttl;
    for (const [key, value] of Object.entries(record.fields)) {
      const spec = isRecordType(record.type) ? RECORD_SPECS[record.type].fields.find((field) => field.key === key) : undefined;
      if (!value.trim() && !(spec?.kind === "int" && spec.defaultValue !== undefined)) problems[`r${record.key}.${key}`] = pick(language, C.fieldNeeded);
    }
  });
  const seen = new Set<string>();
  variables.forEach((variable) => {
    if (!VAR_KEY.test(variable.name.trim())) problems[`v${variable.key}`] = pick(language, C.badVarKey);
    else if (seen.has(variable.name.trim())) problems[`v${variable.key}`] = pick(language, C.duplicateVar);
    seen.add(variable.name.trim());
  });
  if (ttlProblem(zoneTtl)) problems.zoneTtl = ttlProblem(zoneTtl)!;
  const invalid = Object.keys(problems).length > 0;
  const show = (key: string) => (touched ? problems[key] : undefined);

  const changeRecord = (key: number, change: Partial<DraftRecord>) => setRecords((current) => current.map((item) => (item.key === key ? { ...item, ...change } : item)));
  const changeVariable = (key: number, change: Partial<DraftVariable>) => setVariables((current) => current.map((item) => (item.key === key ? { ...item, ...change } : item)));

  const save = async () => {
    setTouched(true);
    if (invalid) return;
    setBusy(true);
    setError(null);
    const number = (text: string) => (text.trim() ? Number(digits(text.trim())) : undefined);
    const soaBody = Object.fromEntries(Object.entries(soa).filter(([, value]) => value.trim()).map(([key, value]) => [key, key === "hostmaster" ? value.trim() : number(value)]));
    const body: TemplateInput = {
      name: name.trim(),
      description: description.trim() || null,
      zone: { ttl: number(zoneTtl) ?? null, ns: ns.length ? ns : null, soa: Object.keys(soaBody).length ? soaBody : null },
      records: records.map((record) => {
        const data: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(record.fields)) {
          const spec = isRecordType(record.type) ? RECORD_SPECS[record.type].fields.find((field) => field.key === key) : undefined;
          const clean = value.trim();
          data[key] = spec?.kind === "int" && !hasPlaceholder(clean) ? Number(digits(clean) || spec.defaultValue || 0) : clean;
        }
        return { name: record.name.trim() || "@", type: record.type, ...(record.ttl.trim() ? { ttl: number(record.ttl) } : {}), data, ...(record.comment.trim() ? { comment: record.comment.trim() } : {}) };
      }),
      variables: variables.map((variable): TemplateVariable => ({
        key: variable.name.trim(),
        label_fa: variable.label_fa.trim() || null,
        label_en: variable.label_en.trim() || null,
        default: variable.default.trim() || null,
        required: variable.required
      }))
    };
    try {
      if (mode === "edit" && initial) await updateTemplate(initial.id, body);
      else await createTemplate(body);
      onSaved(body.name);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog
      title={mode === "edit" && initial ? say(language, C.editorEdit, { name: templateName(language, initial) }) : pick(language, C.editorNew)}
      submitLabel={pick(language, C.save)}
      busy={busy}
      error={error}
      onSubmit={() => void save()}
      onClose={onClose}
      wide
      extraActions={touched && invalid ? <Typography variant="body2" color="error">{pick(language, C.fixFirst)}</Typography> : undefined}
    >
      <TextField label={pick(language, C.name)} value={name} onChange={(event) => setName(event.target.value)} error={Boolean(show("name") || serverFields.name)} helperText={show("name") ?? serverFields.name ?? " "} fullWidth autoFocus />
      <TextField label={pick(language, C.description)} value={description} onChange={(event) => setDescription(event.target.value)} fullWidth multiline minRows={1} />

      <Stack spacing={1}>
        <Typography variant="subtitle1" sx={{ fontWeight: 760 }}>{pick(language, C.recordsTitle)}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{pick(language, C.recordsHint)}</Typography>
        {show("records") ? <Typography variant="caption" color="error">{show("records")}</Typography> : null}
      </Stack>
      {records.map((record) => {
        const specFields = isRecordType(record.type) ? RECORD_SPECS[record.type].fields : [{ key: "value", label: { fa: "مقدار", en: "Value" } as Bi, kind: "text" as const }];
        return (
          <Paper key={record.key} variant="outlined" sx={{ p: 1.5, borderRadius: 2 }}>
            <Stack spacing={1.25}>
              <Stack direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ sm: "flex-start" }}>
                <TextField select size="small" label={pick(language, C.recordType)} value={record.type} onChange={(event) => changeRecord(record.key, { type: event.target.value, fields: emptyFields(event.target.value) })} sx={{ minWidth: 170 }}>
                  {RECORD_TYPES.map((type) => <MenuItem key={type} value={type}>{recordTypeLabel(language, type)} <Typography component="span" variant="caption" color="text.secondary" sx={{ mx: 1 }}><Ltr>{type}</Ltr></Typography></MenuItem>)}
                </TextField>
                <TextField size="small" label={pick(language, C.recordName)} value={record.name} onChange={(event) => changeRecord(record.key, { name: event.target.value })} error={Boolean(show(`r${record.key}.name`))} helperText={show(`r${record.key}.name`) ?? " "} sx={{ flex: 1 }} slotProps={ltrInput} />
                {isAdvanced ? (
                  <TextField size="small" label={pick(language, C.ttl)} value={record.ttl} onChange={(event) => changeRecord(record.key, { ttl: event.target.value })} error={Boolean(show(`r${record.key}.ttl`))} helperText={show(`r${record.key}.ttl`) ?? " "} sx={{ width: { sm: 170 } }} slotProps={{ htmlInput: { dir: "ltr", inputMode: "numeric" } }} />
                ) : null}
                <Tooltip title={pick(language, C.removeRow)}>
                  <IconButton aria-label={pick(language, C.removeRow)} onClick={() => setRecords((current) => current.filter((item) => item.key !== record.key))} sx={{ width: 44, height: 44, alignSelf: { xs: "flex-end", sm: "flex-start" } }}>
                    <DeleteOutlineRoundedIcon />
                  </IconButton>
                </Tooltip>
              </Stack>
              <Stack direction={{ xs: "column", sm: "row" }} gap={1}>
                {specFields.map((field) => (
                  <TextField
                    key={field.key}
                    size="small"
                    label={pick(language, field.label)}
                    value={record.fields[field.key] ?? ""}
                    onChange={(event) => changeRecord(record.key, { fields: { ...record.fields, [field.key]: event.target.value } })}
                    error={Boolean(show(`r${record.key}.${field.key}`))}
                    helperText={show(`r${record.key}.${field.key}`) ?? " "}
                    placeholder={"placeholder" in field ? (field.placeholder as string | undefined) : undefined}
                    sx={{ flex: field.kind === "int" ? "0 0 140px" : 1 }}
                    slotProps={ltrInput}
                  />
                ))}
              </Stack>
              {isAdvanced ? <TextField size="small" label={pick(language, C.comment)} value={record.comment} onChange={(event) => changeRecord(record.key, { comment: event.target.value })} fullWidth /> : null}
            </Stack>
          </Paper>
        );
      })}
      <Box>
        <Button startIcon={<AddRoundedIcon />} onClick={() => setRecords((current) => [...current, { key: nextKey(), name: "", type: "A", ttl: "", fields: emptyFields("A"), comment: "" }])} sx={{ minHeight: 44 }}>
          {pick(language, C.addRecord)}
        </Button>
      </Box>

      <Divider />
      <Stack spacing={1}>
        <Typography variant="subtitle1" sx={{ fontWeight: 760 }}>{pick(language, C.variablesTitle)}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{pick(language, C.variablesHint)}</Typography>
      </Stack>
      {variables.map((variable) => (
        <Paper key={variable.key} variant="outlined" sx={{ p: 1.5, borderRadius: 2 }}>
          <Stack spacing={1}>
            <Stack direction={{ xs: "column", sm: "row" }} gap={1}>
              <TextField size="small" label={pick(language, C.varKey)} value={variable.name} onChange={(event) => changeVariable(variable.key, { name: event.target.value.toLowerCase() })} error={Boolean(show(`v${variable.key}`))} helperText={show(`v${variable.key}`) ?? pick(language, C.varKeyHint)} sx={{ flex: 1 }} slotProps={ltrInput} />
              <TextField size="small" label={pick(language, C.varDefault)} value={variable.default} onChange={(event) => changeVariable(variable.key, { default: event.target.value })} helperText=" " sx={{ flex: 1 }} slotProps={ltrInput} />
              <Tooltip title={pick(language, C.removeRow)}>
                <IconButton aria-label={pick(language, C.removeRow)} onClick={() => setVariables((current) => current.filter((item) => item.key !== variable.key))} sx={{ width: 44, height: 44, alignSelf: { xs: "flex-end", sm: "flex-start" } }}>
                  <DeleteOutlineRoundedIcon />
                </IconButton>
              </Tooltip>
            </Stack>
            <Stack direction={{ xs: "column", sm: "row" }} gap={1}>
              <TextField size="small" label={pick(language, C.varLabelFa)} value={variable.label_fa} onChange={(event) => changeVariable(variable.key, { label_fa: event.target.value })} sx={{ flex: 1 }} />
              <TextField size="small" label={pick(language, C.varLabelEn)} value={variable.label_en} onChange={(event) => changeVariable(variable.key, { label_en: event.target.value })} sx={{ flex: 1 }} slotProps={{ htmlInput: { dir: "ltr" } }} />
            </Stack>
            <FormControlLabel control={<Switch checked={variable.required} onChange={(event) => changeVariable(variable.key, { required: event.target.checked })} />} label={pick(language, C.varRequired)} />
          </Stack>
        </Paper>
      ))}
      <Box>
        <Button startIcon={<AddRoundedIcon />} onClick={() => setVariables((current) => [...current, { key: nextKey(), name: "", label_fa: "", label_en: "", default: "", required: true }])} sx={{ minHeight: 44 }}>
          {pick(language, C.addVariable)}
        </Button>
      </Box>

      {isAdvanced ? (
        <>
          <Divider />
          <Stack spacing={1}>
            <Typography variant="subtitle1" sx={{ fontWeight: 760 }}>{pick(language, C.zoneTitle)}</Typography>
            <Typography variant="body2" color="text.secondary">{pick(language, C.zoneHint)}</Typography>
          </Stack>
          <TextField size="small" label={pick(language, C.zoneTtl)} value={zoneTtl} onChange={(event) => setZoneTtl(event.target.value)} error={Boolean(show("zoneTtl"))} helperText={show("zoneTtl") ?? " "} slotProps={{ htmlInput: { dir: "ltr", inputMode: "numeric" } }} />
          <ListInput label={pick(language, C.nameServers)} value={ns} onChange={setNs} validate={(item) => (isDnsName(item.replace(/\{[a-z0-9_]+\}/gi, "x")) ? null : pick(language, C.badRecordName))} max={8} />
          <Stack direction={{ xs: "column", sm: "row" }} gap={1} flexWrap="wrap">
            <TextField size="small" label={pick(language, C.hostmaster)} value={soa.hostmaster} onChange={(event) => setSoa({ ...soa, hostmaster: event.target.value })} sx={{ flex: "1 1 220px" }} slotProps={ltrInput} />
            {(["refresh", "retry", "expire", "minimum"] as const).map((key) => (
              <TextField key={key} size="small" label={pick(language, C[key])} value={soa[key]} onChange={(event) => setSoa({ ...soa, [key]: event.target.value })} sx={{ flex: "1 1 160px" }} slotProps={{ htmlInput: { dir: "ltr", inputMode: "numeric" } }} />
            ))}
          </Stack>
        </>
      ) : null}
    </FormDialog>
  );
}

// ── view ─────────────────────────────────────────────────────────────────────

function ViewDialog({ template, onClose }: { template: DnsTemplate; onClose: () => void }) {
  const { language, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [domain, setDomain] = useState("example.com");
  const values = displayValues(language, domain.trim() || "example.com", initialVariables(template), {});
  return (
    <Dialog open onClose={onClose} fullScreen={fullScreen} fullWidth maxWidth="sm">
      <DialogTitle sx={{ fontWeight: 760 }}>{say(language, C.viewTitle, { name: templateName(language, template) })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 0.5 }}>
          {templateDescription(language, template) ? <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{templateDescription(language, template)}</Typography> : null}
          <TextField size="small" label={pick(language, C.sampleDomain)} value={domain} onChange={(event) => setDomain(event.target.value)} slotProps={ltrInput} />
          <TemplateSummary records={template.records} zone={domain.trim() || "example.com"} values={values} />
          {askedVariables(template).length ? (
            <Stack direction="row" gap={0.75} flexWrap="wrap" alignItems="center">
              <Typography variant="caption" color="text.secondary">{pick(language, C.askTitle)}:</Typography>
              {askedVariables(template).map((item) => <Chip key={item.key} size="small" variant="outlined" label={variableLabel(language, item)} />)}
            </Stack>
          ) : null}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ minHeight: 44 }}>{c.close}</Button>
      </DialogActions>
    </Dialog>
  );
}

// ── page ─────────────────────────────────────────────────────────────────────

function TemplateCard({ template, isDefault, canAdmin, onView, onCopy, onEdit, onDelete, onDefault }: {
  template: DnsTemplate; isDefault: boolean; canAdmin: boolean; onView: () => void; onCopy: () => void; onEdit: () => void; onDelete: () => void; onDefault: () => void;
}) {
  const { language } = useKit();
  const asked = askedVariables(template).length;
  const action = (label: Bi, icon: ReactNode, onClick: () => void, color?: "error") => (
    <Button size="small" color={color} startIcon={icon} onClick={onClick} sx={{ minHeight: 40 }}>{pick(language, label)}</Button>
  );
  return (
    <Paper variant="outlined" sx={{ p: 2, borderRadius: 2, borderColor: isDefault ? "primary.main" : "divider", borderWidth: isDefault ? 2 : 1, display: "flex", flexDirection: "column", gap: 1.25, height: "100%" }}>
      <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
        <Typography variant="subtitle1" sx={{ fontWeight: 760, flex: 1, minWidth: 0 }}>{templateName(language, template)}</Typography>
        {isDefault ? <StatusPill tone="ok" label={pick(language, C.defaultBadge)} /> : null}
        {template.builtin ? <Chip size="small" variant="outlined" label={pick(language, C.builtinBadge)} /> : null}
      </Stack>
      {templateDescription(language, template) ? <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>{templateDescription(language, template)}</Typography> : null}
      <Typography variant="caption" color="text.secondary">
        {say(language, C.records, { count: template.records.length })}
        {asked ? `${language === "fa" ? "، " : " · "}${say(language, C.variablesCount, { count: asked })}` : ""}
      </Typography>
      <Box sx={{ flex: 1 }} />
      <Stack direction="row" gap={0.5} flexWrap="wrap">
        {action(C.view, <VisibilityRoundedIcon />, onView)}
        {canAdmin ? action(C.copy, <ContentCopyRoundedIcon />, onCopy) : null}
        {canAdmin && !template.builtin ? action(C.edit, <EditRoundedIcon />, onEdit) : null}
        {canAdmin && !isDefault ? action(C.makeDefault, <StarRoundedIcon />, onDefault) : null}
        {canAdmin && !template.builtin && !isDefault ? action(C.remove, <DeleteOutlineRoundedIcon />, onDelete, "error") : null}
      </Stack>
    </Paper>
  );
}

export default function DnsTemplatesTab({ permissions }: { permissions: readonly string[] }) {
  const { language } = useKit();
  const canAdmin = hasPermission(permissions, "dns:admin");
  const loader = useCallback((signal: AbortSignal) => fetchTemplates(signal), []);
  const { data, error, loading, reload, setData } = useLoader<TemplateList>(loader);
  const [editing, setEditing] = useState<{ template: DnsTemplate | null; mode: "new" | "edit" | "copy"; key: number } | null>(null);
  const [viewing, setViewing] = useState<DnsTemplate | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const items = data?.items ?? [];
  const sorted = useMemo(() => [...items].sort((a, b) => Number(b.id === data?.defaultId) - Number(a.id === data?.defaultId) || Number(Boolean(b.builtin)) - Number(Boolean(a.builtin))), [items, data?.defaultId]);

  const makeDefault = async (template: DnsTemplate | null) => {
    try {
      await setDefaultTemplate(template?.id ?? null);
      setData((current) => (current ? { ...current, defaultId: template?.id ?? null } : current));
      notify({ message: template ? say(language, C.defaultSet, { name: templateName(language, template) }) : pick(language, C.defaultCleared), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
  };

  const remove = async (template: DnsTemplate) => {
    const name = templateName(language, template);
    const ok = await ask({ title: say(language, C.removeTitle, { name }), body: pick(language, C.removeBody), severity: "destructive", confirmLabel: pick(language, C.remove) });
    if (!ok) return;
    try {
      await deleteTemplate(template.id);
      notify({ message: say(language, C.removed, { name }), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
    void reload();
  };

  const newButton = canAdmin ? (
    <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setEditing({ template: null, mode: "new", key: Date.now() })} sx={{ minHeight: 44 }}>
      {pick(language, C.newTemplate)}
    </Button>
  ) : null;

  return (
    <Stack spacing={2.5}>
      <SectionCard title={pick(language, C.pageTitle)} hint={pick(language, C.pageHint)} action={items.length ? newButton : undefined}>
        <Stack spacing={2}>
          {error && !data ? (
            isMissingEndpoint(error) ? <Notice tone="info">{pick(language, C.templatesMissing)}</Notice> : <FriendlyError error={error} title={pick(language, C.templatesFailed)} onRetry={() => void reload()} />
          ) : null}
          {!data && loading ? <Loading /> : null}
          {data && !items.length ? <EmptyState compact icon={DashboardCustomizeRoundedIcon} title={pick(language, C.emptyTitle)} body={pick(language, C.emptyBody)} action={newButton} /> : null}
          {items.length ? (
            <Box sx={{ display: "grid", gap: 1.5, gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))", lg: "repeat(3, minmax(0, 1fr))" } }}>
              {sorted.map((template) => (
                <TemplateCard
                  key={template.id}
                  template={template}
                  isDefault={template.id === data?.defaultId}
                  canAdmin={canAdmin}
                  onView={() => setViewing(template)}
                  onCopy={() => setEditing({ template, mode: "copy", key: Date.now() })}
                  onEdit={() => setEditing({ template, mode: "edit", key: Date.now() })}
                  onDelete={() => void remove(template)}
                  onDefault={() => void makeDefault(template)}
                />
              ))}
            </Box>
          ) : null}
          {items.some((item) => item.builtin) && canAdmin ? <Typography variant="caption" color="text.secondary">{pick(language, C.builtinNote)}</Typography> : null}
          {canAdmin && data?.defaultId ? (
            <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
              <Button size="small" onClick={() => void makeDefault(null)} sx={{ minHeight: 40 }}>{pick(language, C.clearDefault)}</Button>
              <Typography variant="caption" color="text.secondary">{pick(language, C.clearDefaultHint)}</Typography>
            </Stack>
          ) : null}
          {!canAdmin ? <NoAccess needs="dns:admin" /> : null}
        </Stack>
      </SectionCard>
      {editing ? (
        <TemplateEditor
          key={editing.key}
          initial={editing.template}
          mode={editing.mode}
          onClose={() => setEditing(null)}
          onSaved={(name) => {
            setEditing(null);
            notify({ message: say(language, C.saved, { name }), tone: "success" });
            void reload();
          }}
        />
      ) : null}
      {viewing ? <ViewDialog template={viewing} onClose={() => setViewing(null)} /> : null}
      {dialog}
      {snackbar}
    </Stack>
  );
}
