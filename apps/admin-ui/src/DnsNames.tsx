/**
 * «DNS › نام‌ها» (contract docs/37 §2 zones/records/overrides, §5).
 *
 * Simple: «این نام → این آدرس» (overrides) with add / edit / remove.
 * Advanced adds the domains (zones): create a primary or forwarder zone, turn it off, delete it
 * (typed confirmation), and inside a zone every record type with a type-aware form, import/export
 * of RFC 1035 zone text, and the version history with rollback.
 * Hash query: `?zone=<name>` opens a zone (Advanced).
 */
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, MenuItem, Stack, Switch,
  TextField, Typography, useMediaQuery, useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import ArrowBackRoundedIcon from "@mui/icons-material/ArrowBackRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import FolderOpenRoundedIcon from "@mui/icons-material/FolderOpenRounded";
import PowerSettingsNewRoundedIcon from "@mui/icons-material/PowerSettingsNewRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import UploadFileRoundedIcon from "@mui/icons-material/UploadFileRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import RestoreRoundedIcon from "@mui/icons-material/RestoreRounded";
import LanRoundedIcon from "@mui/icons-material/LanRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import CallSplitRoundedIcon from "@mui/icons-material/CallSplitRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import { ApiError, hasPermission, isAbortError } from "./api";
import { errorSentence, nameConfirmation, pick, say, type Bi } from "./copy";
import {
  ChoiceCards, CopyField, DurationInput, EmptyState, FriendlyError, ListInput, Ltr, NoAccess, RelativeTime, ResponsiveList,
  SectionCard, StatusPill, useConfirmAction, useKit, useUndoSnackbar, type ListColumn, type RowAction
} from "./kit";
import { hashQuery } from "./nav";
import { DnsAvailability } from "./DnsPage";
import {
  RECORD_SPECS, RECORD_TYPES, TTL_MAX, ZONE_TYPE_WORDS, createOverride, createRecord, createZone, deleteOverride, deleteRecord, deleteZone,
  dnsFieldMessages, download, engineReady, exportZone, fetchOverrides, fetchRecords, fetchZoneHistory, fetchZones, fieldProblem, importZone,
  isDnsName, isIPv4, isIPv6, isRecordType, overrideTypeFor, patchZone, recordTypeLabel, recordValue, rollbackZone, updateOverride, updateRecord,
  useDnsStatus, zoneTypeWord, type DnsOverride, type DnsRecord, type DnsZone, type DnsZoneVersion, type RecordType, type ZoneType
} from "./dns";

const COPY = {
  // overrides
  overridesTitle: { fa: "نام‌های من", en: "My names" },
  overridesHint: { fa: "بگویید هر نام به کدام آدرس برود. برای سرور، کانتینرها و شبکه خودتان.", en: "Say which address each name goes to: for the server, its containers and your network." },
  addName: { fa: "افزودن نام", en: "Add a name" },
  emptyNames: { fa: "هنوز نامی نساخته‌اید", en: "You haven't made any names yet" },
  emptyNamesBody: { fa: "مثلاً «git.office» را به نشانی سرور گیت بفرستید تا همه با همین نام به آن برسند.", en: "For example, send “git.office” to your Git server's address so everyone reaches it by that name." },
  colName: { fa: "این نام", en: "This name" },
  colGoesTo: { fa: "به این آدرس می‌رود", en: "Goes to" },
  colType: { fa: "نوع", en: "Type" },
  colTtl: { fa: "نگه‌داری", en: "Kept for" },
  colState: { fa: "وضعیت", en: "State" },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  fromServices: { fa: "از «سرویس‌های من»", en: "From My services" },
  fromServicesHint: { fa: "این نام را «سرویس‌های من» خودکار ساخته و همان‌جا تغییر می‌کند.", en: "My services made this name automatically and keeps it up to date." },
  turnOff: { fa: "خاموش کن", en: "Turn off" },
  turnOn: { fa: "روشن کن", en: "Turn on" },
  editName: { fa: "تغییر نام", en: "Edit name" },
  newName: { fa: "نام تازه", en: "New name" },
  nameField: { fa: "این نام", en: "This name" },
  nameFieldHint: { fa: "مثل git.office یا app.example.com", en: "Like git.office or app.example.com" },
  valueField: { fa: "به این آدرس برود", en: "Goes to this address" },
  valueFieldHint: { fa: "یک نشانی IP مثل 192.168.1.10، یا یک نام دیگر مثل server.example.com", en: "An IP address like 192.168.1.10, or another name like server.example.com" },
  ttlField: { fa: "مدت نگه‌داری جواب", en: "How long answers are kept" },
  ttlHint: { fa: "دستگاه‌ها جواب را این مدت نگه می‌دارند. کمتر = تغییرها زودتر می‌رسند.", en: "Devices keep the answer this long. Shorter means changes arrive sooner." },
  inferred: { fa: "MRK این را «{type}» ثبت می‌کند.", en: "MRK saves this as “{type}”." },
  badName: { fa: "نام را مثل git.office یا app.example.com بنویسید.", en: "Write the name like git.office or app.example.com." },
  badValue: { fa: "یک نشانی IP مثل 192.168.1.10 یا یک نام مثل server.example.com بنویسید.", en: "Write an IP like 192.168.1.10 or a name like server.example.com." },
  ttlRange: { fa: "مدت نگه‌داری باید بین ۰ ثانیه تا ۷ روز باشد.", en: "The time to keep must be between 0 seconds and 7 days." },
  saveName: { fa: "ذخیره نام", en: "Save name" },
  nameSaved: { fa: "نام «{name}» ذخیره شد.", en: "The name “{name}” was saved." },
  removeNameTitle: { fa: "نام «{name}» برداشته شود؟", en: "Remove the name “{name}”?" },
  removeNameBody: { fa: "از این به بعد MRK برای این نام جواب خودش را نمی‌دهد و جواب از اینترنت می‌آید.", en: "From now on MRK won't give its own answer for this name; the answer comes from the internet." },
  removeYes: { fa: "بله، بردار", en: "Yes, remove" },
  nameRemoved: { fa: "نام «{name}» برداشته شد.", en: "The name “{name}” was removed." },
  nameToggled: { fa: "نام «{name}» {state} شد.", en: "The name “{name}” was turned {state}." },
  loadFailed: { fa: "فهرست نام‌ها خوانده نشد.", en: "The list of names didn't load." },
  writeNeeded: { fa: "افزودن و تغییر نام‌ها", en: "Adding and changing names" },
  // zones
  zonesTitle: { fa: "دامنه‌ها", en: "Domains" },
  zonesHint: { fa: "دامنه‌هایی که MRK خودش جوابشان را می‌دهد، یا پرسش‌هایشان را به سرور دیگری می‌فرستد.", en: "Domains MRK answers for itself, or whose questions it sends to another server." },
  addZone: { fa: "افزودن دامنه", en: "Add a domain" },
  emptyZones: { fa: "هنوز دامنه‌ای اضافه نکرده‌اید", en: "You haven't added a domain yet" },
  emptyZonesBody: { fa: "برای شبکه داخلی مثل office.local، یا برای دامنه‌ای که می‌خواهید همه رکوردهایش اینجا باشد.", en: "For an internal network like office.local, or a domain whose records you want to keep here." },
  colZone: { fa: "دامنه", en: "Domain" },
  colZoneType: { fa: "کار", en: "Kind" },
  colRecords: { fa: "رکوردها", en: "Records" },
  colSerial: { fa: "شماره نسخه", en: "Serial" },
  colUpdated: { fa: "آخرین تغییر", en: "Last change" },
  open: { fa: "باز کردن", en: "Open" },
  zoneName: { fa: "نام دامنه", en: "Domain name" },
  zoneNameHint: { fa: "مثل office.local یا example.com", en: "Like office.local or example.com" },
  zoneKind: { fa: "این دامنه چه کار کند؟", en: "What should this domain do?" },
  forwarders: { fa: "سرورهای DNS مقصد", en: "Destination DNS servers" },
  forwardersHint: { fa: "نشانی IP، مثل 10.0.0.2 یا 10.0.0.2:53", en: "An IP address, like 10.0.0.2 or 10.0.0.2:53" },
  forwardersNeeded: { fa: "دست‌کم یک سرور DNS مقصد بنویسید.", en: "Write at least one destination DNS server." },
  badForwarder: { fa: "نشانی را مثل 10.0.0.2 یا 10.0.0.2:53 بنویسید.", en: "Write the address like 10.0.0.2 or 10.0.0.2:53." },
  badZone: { fa: "نام دامنه را مثل office.local یا example.com بنویسید.", en: "Write the domain like office.local or example.com." },
  createZone: { fa: "ساخت دامنه", en: "Create domain" },
  zoneCreated: { fa: "دامنه «{name}» ساخته شد.", en: "The domain “{name}” was created." },
  zoneOffTitle: { fa: "دامنه «{name}» خاموش شود؟", en: "Turn off the domain “{name}”?" },
  zoneOffBody: { fa: "تا روشنش نکنید، MRK برای نام‌های این دامنه جوابی نمی‌دهد. رکوردها سر جایشان می‌مانند.", en: "Until you turn it back on, MRK won't answer for names in this domain. The records stay." },
  zoneOffYes: { fa: "بله، خاموش کن", en: "Yes, turn off" },
  zoneToggled: { fa: "دامنه «{name}» {state} شد.", en: "The domain “{name}” was turned {state}." },
  zoneDeleteTitle: { fa: "دامنه «{name}» و همه رکوردهایش پاک شود؟", en: "Delete the domain “{name}” and all its records?" },
  zoneDeleteBody: { fa: "همه رکوردها و تاریخچه این دامنه پاک می‌شوند. اگر می‌خواهید بعداً برگردد، اول از آن خروجی بگیرید.", en: "Every record and the history of this domain are deleted. Export it first if you may want it back." },
  zoneDeleteYes: { fa: "بله، پاک کن", en: "Yes, delete" },
  zoneDeleted: { fa: "دامنه «{name}» پاک شد.", en: "The domain “{name}” was deleted." },
  zonesFailed: { fa: "فهرست دامنه‌ها خوانده نشد.", en: "The list of domains didn't load." },
  // zone detail
  back: { fa: "همه دامنه‌ها", en: "All domains" },
  recordsTitle: { fa: "رکوردها", en: "Records" },
  recordsHint: { fa: "هر رکورد می‌گوید یک نام در این دامنه به کجا برود.", en: "Each record says where a name in this domain goes." },
  addRecord: { fa: "افزودن رکورد", en: "Add a record" },
  allTypes: { fa: "همه", en: "All" },
  emptyRecords: { fa: "هنوز رکوردی در این دامنه نیست", en: "No records in this domain yet" },
  emptyRecordsBody: { fa: "با «افزودن رکورد» اولین نام این دامنه را بسازید.", en: "Use Add a record to make this domain's first name." },
  colRecName: { fa: "نام", en: "Name" },
  colValue: { fa: "مقدار", en: "Value" },
  apex: { fa: "خود دامنه", en: "The domain itself" },
  wildcard: { fa: "هر نام دیگری", en: "Any other name" },
  soaNote: { fa: "خودکار", en: "Automatic" },
  editRecord: { fa: "تغییر رکورد", en: "Edit record" },
  newRecord: { fa: "رکورد تازه", en: "New record" },
  recordType: { fa: "نوع رکورد", en: "Record type" },
  recordName: { fa: "نام", en: "Name" },
  recordNameHint: { fa: "فقط بخش اول؛ برای خود دامنه @ و برای همه نام‌های دیگر * بنویسید.", en: "Only the first part; write @ for the domain itself and * for every other name." },
  badRecordName: { fa: "نام را مثل «www» یا «mail» بنویسید؛ @ برای خود دامنه.", en: "Write the name like www or mail; @ for the domain itself." },
  comment: { fa: "یادداشت (اختیاری)", en: "Note (optional)" },
  recordOn: { fa: "این رکورد روشن باشد", en: "This record is on" },
  saveRecord: { fa: "ذخیره رکورد", en: "Save record" },
  recordSaved: { fa: "رکورد «{name}» ذخیره شد.", en: "The record “{name}” was saved." },
  removeRecordTitle: { fa: "رکورد «{name}» پاک شود؟", en: "Delete the record “{name}”?" },
  removeRecordBody: { fa: "این نام دیگر به این مقدار نمی‌رود. از «تاریخچه» می‌توانید برش گردانید.", en: "This name won't go to this value any more. You can bring it back from History." },
  recordRemoved: { fa: "رکورد «{name}» پاک شد.", en: "The record “{name}” was deleted." },
  recordsFailed: { fa: "رکوردهای این دامنه خوانده نشد.", en: "This domain's records didn't load." },
  forwardTitle: { fa: "فرستادن پرسش‌ها", en: "Where questions go" },
  forwardHint: { fa: "پرسش‌های این دامنه به این سرورها فرستاده می‌شود.", en: "Questions for this domain go to these servers." },
  saveForwarders: { fa: "ذخیره سرورها", en: "Save servers" },
  forwardersSaved: { fa: "سرورهای مقصد ذخیره شد.", en: "The destination servers were saved." },
  export: { fa: "خروجی فایل", en: "Export file" },
  import: { fa: "وارد کردن از فایل", en: "Import file" },
  history: { fa: "تاریخچه", en: "History" },
  exported: { fa: "فایل دامنه «{name}» آماده شد.", en: "The zone file for “{name}” is ready." },
  exportTitle: { fa: "فایل دامنه", en: "Zone file" },
  importTitle: { fa: "وارد کردن رکوردها از فایل", en: "Import records from a file" },
  importHint: { fa: "متن فایل دامنه (همان شکلی که بیشتر سرورهای DNS خروجی می‌دهند) را اینجا بگذارید یا فایل را انتخاب کنید.", en: "Paste zone-file text (the format BIND and most servers export) or pick the file." },
  pickFile: { fa: "انتخاب فایل", en: "Pick a file" },
  importText: { fa: "متن فایل دامنه", en: "Zone-file text" },
  replace: { fa: "رکوردهای فعلی پاک شوند و فقط رکوردهای فایل بمانند", en: "Delete the current records and keep only the file's records" },
  replaceHint: { fa: "خاموش: رکوردهای فایل به رکوردهای فعلی اضافه می‌شوند.", en: "Off: the file's records are added to the current ones." },
  importYes: { fa: "وارد کن", en: "Import" },
  importReplaceTitle: { fa: "همه رکوردهای «{name}» با فایل جایگزین شود؟", en: "Replace every record of “{name}” with the file?" },
  importReplaceBody: { fa: "رکوردهای فعلی پاک می‌شوند. از «تاریخچه» می‌توانید به نسخه قبل برگردید.", en: "The current records are deleted. You can go back to the earlier version from History." },
  imported: { fa: "رکوردهای فایل وارد شد.", en: "The file's records were imported." },
  historyTitle: { fa: "تاریخچه دامنه «{name}»", en: "History of “{name}”" },
  historyHint: { fa: "هر تغییر یک نسخه می‌سازد. می‌توانید دامنه را به هر نسخه قبلی برگردانید.", en: "Every change makes a version. You can take the domain back to any earlier version." },
  noHistory: { fa: "هنوز نسخه قبلی ثبت نشده است.", en: "No earlier version yet." },
  versionLabel: { fa: "نسخه {version}", en: "Version {version}" },
  versionRecords: { fa: "{count} رکورد", en: "{count} records" },
  rollback: { fa: "برگرداندن به این نسخه", en: "Go back to this version" },
  rollbackTitle: { fa: "دامنه «{name}» به نسخه {version} برگردد؟", en: "Take “{name}” back to version {version}?" },
  rollbackBody: { fa: "رکوردها همان می‌شوند که در آن نسخه بودند. وضعیت فعلی هم به‌عنوان یک نسخه در تاریخچه می‌ماند.", en: "The records become what they were in that version. The current state stays in the history too." },
  rollbackYes: { fa: "بله، برگردان", en: "Yes, go back" },
  rolledBack: { fa: "دامنه به نسخه {version} برگشت.", en: "The domain went back to version {version}." },
  historyFailed: { fa: "تاریخچه خوانده نشد.", en: "The history didn't load." },
  current: { fa: "نسخه فعلی", en: "Current" },
  primaryOnly: { fa: "دامنه‌ها، رکوردها، خروجی و تاریخچه در حالت «پیشرفته» هستند.", en: "Domains, records, export and history are in Advanced mode." }
} satisfies Record<string, Bi>;

const RECORD_ICONS: Partial<Record<ZoneType, typeof DnsRoundedIcon>> = { primary: DnsRoundedIcon, forwarder: CallSplitRoundedIcon };

function useList<T>(loader: (signal: AbortSignal) => Promise<T[]>, enabled = true) {
  const [items, setItems] = useState<T[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const load = useCallback(async () => {
    if (!enabled) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      setItems(await loader(current.signal));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, [loader, enabled]);
  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);
  return { items, error, loading, reload: load };
}

/** A dialog with a form: full screen on phones, one primary button, errors in plain words. */
function FormDialog({ title, hint, children, submitLabel, busy, error, disabled, onSubmit, onClose, wide }: {
  title: string; hint?: string; children: ReactNode; submitLabel: string; busy: boolean; error: unknown; disabled?: boolean;
  onSubmit: () => void; onClose: () => void; wide?: boolean;
}) {
  const { c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!busy && !disabled) onSubmit();
  };
  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth={wide ? "md" : "sm"}>
      <Box component="form" onSubmit={submit} noValidate sx={{ display: "flex", flexDirection: "column", height: fullScreen ? "100%" : undefined }}>
        <DialogTitle sx={{ fontWeight: 760 }}>{title}</DialogTitle>
        <DialogContent sx={{ flex: 1 }}>
          <Stack spacing={2} sx={{ pt: 0.5 }}>
            {hint ? <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.9 }}>{hint}</Typography> : null}
            {children}
            {error ? <FriendlyError error={error} /> : null}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{c.cancel}</Button>
          <Button type="submit" variant="contained" disabled={busy || disabled} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
            {submitLabel}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

const ltrInput = { htmlInput: { dir: "ltr" as const, spellCheck: false, autoCapitalize: "none", autoComplete: "off" } };

// ── overrides ────────────────────────────────────────────────────────────────

function OverrideDialog({ initial, onClose, onSaved }: { initial: DnsOverride | null; onClose: () => void; onSaved: (name: string) => void }) {
  const { language, isAdvanced } = useKit();
  const [name, setName] = useState(initial?.name ?? "");
  const [value, setValue] = useState(initial?.value ?? "");
  const [ttl, setTtl] = useState<number | null>(initial?.ttl ?? 300);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [fields, setFields] = useState<Record<string, string>>({});
  const cleanName = name.trim().replace(/\.$/, "").toLowerCase();
  const cleanValue = value.trim().replace(/\.$/, "");
  const type = cleanValue ? overrideTypeFor(cleanValue) : null;
  const nameProblem = cleanName && !isDnsName(cleanName) ? pick(language, COPY.badName) : null;
  const valueProblem = cleanValue && !type ? pick(language, COPY.badValue) : null;
  const ttlProblem = ttl === null || ttl < 0 || ttl > TTL_MAX ? pick(language, COPY.ttlRange) : null;

  const save = async () => {
    if (!cleanName || !type || nameProblem || valueProblem || ttlProblem) return;
    setBusy(true);
    setError(null);
    setFields({});
    const body = { name: cleanName, type, value: cleanValue, ttl: ttl ?? 300, disabled: initial?.disabled ?? false };
    try {
      if (initial) await updateOverride(initial.id, body);
      else await createOverride(body);
      onSaved(cleanName);
    } catch (caught) {
      setFields(dnsFieldMessages(language, caught));
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog
      title={pick(language, initial ? COPY.editName : COPY.newName)}
      submitLabel={pick(language, COPY.saveName)}
      busy={busy}
      error={error}
      disabled={!cleanName || !cleanValue || Boolean(nameProblem || valueProblem || ttlProblem)}
      onSubmit={() => void save()}
      onClose={onClose}
    >
      <TextField
        label={pick(language, COPY.nameField)}
        value={name}
        onChange={(event) => { setName(event.target.value); setFields((current) => ({ ...current, name: "" })); }}
        error={Boolean(nameProblem || fields.name)}
        helperText={nameProblem ?? fields.name ?? pick(language, COPY.nameFieldHint)}
        autoFocus
        fullWidth
        slotProps={ltrInput}
      />
      <TextField
        label={pick(language, COPY.valueField)}
        value={value}
        onChange={(event) => { setValue(event.target.value); setFields((current) => ({ ...current, value: "" })); }}
        error={Boolean(valueProblem || fields.value)}
        helperText={valueProblem ?? fields.value ?? pick(language, COPY.valueFieldHint)}
        fullWidth
        slotProps={ltrInput}
      />
      {isAdvanced ? (
        <>
          <DurationInput label={pick(language, COPY.ttlField)} value={ttl} onChange={setTtl} min={0} max={TTL_MAX} error={ttlProblem ?? fields.ttl ?? null} helperText={pick(language, COPY.ttlHint)} />
          {type ? <Typography variant="caption" color="text.secondary">{say(language, COPY.inferred, { type })}</Typography> : null}
        </>
      ) : null}
    </FormDialog>
  );
}

function OverridesSection({ permissions, ready }: { permissions: readonly string[]; ready: boolean }) {
  const { language, isAdvanced } = useKit();
  const canWrite = hasPermission(permissions, "dns:write");
  const loader = useCallback((signal: AbortSignal) => fetchOverrides(signal), []);
  const { items, error, loading, reload } = useList(loader, ready);
  const [editing, setEditing] = useState<{ item: DnsOverride | null; key: number } | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const rows = useMemo(() => [...(items ?? [])].sort((a, b) => a.name.localeCompare(b.name)), [items]);
  const fromServices = (row: DnsOverride) => row.source === "services";

  const remove = async (row: DnsOverride) => {
    const ok = await ask({
      title: say(language, COPY.removeNameTitle, { name: row.name }),
      body: pick(language, COPY.removeNameBody),
      severity: "destructive",
      confirmLabel: pick(language, COPY.removeYes)
    });
    if (!ok) return;
    try {
      await deleteOverride(row.id);
      notify({
        message: say(language, COPY.nameRemoved, { name: row.name }),
        tone: "success",
        onUndo: () => {
          void createOverride({ name: row.name, type: (row.type as "A") ?? "A", value: row.value, ttl: row.ttl ?? 300, disabled: row.disabled }).then(() => reload(), (caught) => notify({ message: errorSentence(language, caught, "dns"), tone: "error" }));
        }
      });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
    void reload();
  };

  const toggle = async (row: DnsOverride) => {
    try {
      await updateOverride(row.id, { name: row.name, type: row.type as "A", value: row.value, ttl: row.ttl ?? 300, disabled: !row.disabled });
      notify({ message: say(language, COPY.nameToggled, { name: row.name, state: pick(language, row.disabled ? COPY.on : COPY.off) }), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
    void reload();
  };

  const columns: ListColumn<DnsOverride>[] = [
    { key: "name", header: pick(language, COPY.colName), hideOnCard: true, render: (row) => <Ltr mono>{row.name}</Ltr> },
    { key: "value", header: pick(language, COPY.colGoesTo), hideOnCard: true, render: (row) => <Ltr mono>{row.value}</Ltr> },
    { key: "type", header: pick(language, COPY.colType), advancedOnly: true, render: (row) => <Ltr>{row.type}</Ltr> },
    { key: "ttl", header: pick(language, COPY.colTtl), advancedOnly: true, render: (row) => (typeof row.ttl === "number" ? <RelativeDuration seconds={row.ttl} /> : "—") },
    {
      key: "state",
      header: pick(language, COPY.colState),
      hideOnCard: true,
      render: (row) => (
        <Stack direction="row" gap={0.75} flexWrap="wrap">
          <StatusPill tone={row.disabled ? "off" : "ok"} label={pick(language, row.disabled ? COPY.off : COPY.on)} />
          {fromServices(row) ? <Chip size="small" variant="outlined" label={pick(language, COPY.fromServices)} /> : null}
        </Stack>
      )
    }
  ];
  const actions: RowAction<DnsOverride>[] = canWrite
    ? [
        { key: "edit", label: pick(language, COPY.editName), icon: EditRoundedIcon, onClick: (row) => setEditing({ item: row, key: Date.now() }), hidden: fromServices },
        { key: "toggle", label: pick(language, COPY.turnOff), icon: PowerSettingsNewRoundedIcon, onClick: (row) => void toggle(row), hidden: (row) => fromServices(row) || Boolean(row.disabled) },
        { key: "toggleOn", label: pick(language, COPY.turnOn), icon: PowerSettingsNewRoundedIcon, onClick: (row) => void toggle(row), hidden: (row) => fromServices(row) || !row.disabled },
        { key: "remove", label: pick(language, COPY.removeYes), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (row) => void remove(row), hidden: fromServices }
      ]
    : [];

  const addButton = canWrite ? (
    <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setEditing({ item: null, key: Date.now() })} disabled={!ready} sx={{ minHeight: 44 }}>
      {pick(language, COPY.addName)}
    </Button>
  ) : null;

  return (
    <SectionCard title={pick(language, COPY.overridesTitle)} hint={pick(language, COPY.overridesHint)} action={rows.length ? addButton : undefined}>
      <Stack spacing={2}>
        {error ? <FriendlyError error={error} title={pick(language, COPY.loadFailed)} onRetry={() => void reload()} /> : null}
        {!ready ? null : items === null && loading ? (
          <Box sx={{ display: "grid", placeItems: "center", py: 3 }}><CircularProgress size={24} aria-hidden /></Box>
        ) : (
          <ResponsiveList
            rows={rows}
            rowKey={(row) => row.id}
            columns={columns}
            label={pick(language, COPY.overridesTitle)}
            card={{
              title: (row) => <Ltr mono>{row.name}</Ltr>,
              meta: (row) => <>{language === "fa" ? "←" : "→"} <Ltr mono>{row.value}</Ltr>{fromServices(row) ? ` · ${pick(language, COPY.fromServices)}` : ""}</>,
              status: (row) => <StatusPill tone={row.disabled ? "off" : "ok"} label={pick(language, row.disabled ? COPY.off : COPY.on)} />
            }}
            actions={actions}
            empty={<EmptyState compact icon={LanRoundedIcon} title={pick(language, COPY.emptyNames)} body={pick(language, COPY.emptyNamesBody)} action={addButton} />}
          />
        )}
        {rows.some(fromServices) && isAdvanced ? <Typography variant="caption" color="text.secondary">{pick(language, COPY.fromServicesHint)}</Typography> : null}
        {!canWrite && ready ? <NoAccess needs="dns:write" /> : null}
      </Stack>
      {editing ? (
        <OverrideDialog
          key={editing.key}
          initial={editing.item}
          onClose={() => setEditing(null)}
          onSaved={(name) => {
            setEditing(null);
            notify({ message: say(language, COPY.nameSaved, { name }), tone: "success" });
            void reload();
          }}
        />
      ) : null}
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

function RelativeDuration({ seconds }: { seconds: number }) {
  const { language } = useKit();
  return <>{formatTtl(language, seconds)}</>;
}

function formatTtl(language: "fa" | "en", seconds: number): string {
  const units: [number, Bi][] = [
    [86_400, { fa: "روز", en: "d" }],
    [3_600, { fa: "ساعت", en: "h" }],
    [60, { fa: "دقیقه", en: "min" }],
    [1, { fa: "ثانیه", en: "s" }]
  ];
  const [factor, unit] = units.find(([size]) => seconds >= size && seconds % size === 0) ?? units[3];
  const value = new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(seconds / factor);
  return language === "fa" ? `${value} ${unit.fa}` : `${value} ${unit.en}`;
}

// ── zones ────────────────────────────────────────────────────────────────────

function forwarderProblem(language: "fa" | "en", value: string): string | null {
  const text = value.trim();
  const host = text.replace(/^\[(.+)\](:\d+)?$/, "$1").replace(/^([^:]+):\d{1,5}$/, "$1");
  return isIPv4(host) || isIPv6(host) ? null : pick(language, COPY.badForwarder);
}

function ZoneDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (zone: string) => void }) {
  const { language } = useKit();
  const [name, setName] = useState("");
  const [type, setType] = useState<ZoneType>("primary");
  const [forwarders, setForwarders] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [fields, setFields] = useState<Record<string, string>>({});
  const clean = name.trim().replace(/\.$/, "").toLowerCase();
  const nameProblem = clean && !isDnsName(clean) ? pick(language, COPY.badZone) : null;
  const forwardProblem = type === "forwarder" && forwarders.length === 0 ? pick(language, COPY.forwardersNeeded) : null;

  const save = async () => {
    if (!clean || nameProblem || forwardProblem) return;
    setBusy(true);
    setError(null);
    setFields({});
    try {
      await createZone({ name: clean, type, ...(type === "forwarder" ? { forwarders } : {}) });
      onCreated(clean);
    } catch (caught) {
      setFields(dnsFieldMessages(language, caught));
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog
      title={pick(language, COPY.addZone)}
      submitLabel={pick(language, COPY.createZone)}
      busy={busy}
      error={error}
      disabled={!clean || Boolean(nameProblem || forwardProblem)}
      onSubmit={() => void save()}
      onClose={onClose}
    >
      <TextField
        label={pick(language, COPY.zoneName)}
        value={name}
        onChange={(event) => setName(event.target.value)}
        error={Boolean(nameProblem || fields.name)}
        helperText={nameProblem ?? fields.name ?? pick(language, COPY.zoneNameHint)}
        autoFocus
        fullWidth
        slotProps={ltrInput}
      />
      <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.zoneKind)}</Typography>
      <ChoiceCards<ZoneType>
        label={pick(language, COPY.zoneKind)}
        value={type}
        onChange={setType}
        options={(["primary", "forwarder"] as ZoneType[]).map((key) => ({
          key,
          icon: RECORD_ICONS[key],
          title: pick(language, ZONE_TYPE_WORDS[key].label),
          body: pick(language, ZONE_TYPE_WORDS[key].body)
        }))}
      />
      {type === "forwarder" ? (
        <ListInput
          label={pick(language, COPY.forwarders)}
          value={forwarders}
          onChange={setForwarders}
          validate={(item) => forwarderProblem(language, item)}
          helperText={fields.forwarders ?? pick(language, COPY.forwardersHint)}
          max={8}
        />
      ) : null}
    </FormDialog>
  );
}

function ZonesSection({ permissions, ready, onOpen }: { permissions: readonly string[]; ready: boolean; onOpen: (zone: DnsZone) => void }) {
  const { language } = useKit();
  const canWrite = hasPermission(permissions, "dns:write");
  const loader = useCallback((signal: AbortSignal) => fetchZones(signal), []);
  const { items, error, loading, reload } = useList(loader, ready);
  const [creating, setCreating] = useState<number | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const rows = useMemo(() => [...(items ?? [])].sort((a, b) => a.name.localeCompare(b.name)), [items]);
  const number = (value: number | null | undefined) => (typeof value === "number" ? new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(value) : "—");

  const toggle = async (zone: DnsZone) => {
    if (!zone.disabled) {
      const ok = await ask({ title: say(language, COPY.zoneOffTitle, { name: zone.name }), body: pick(language, COPY.zoneOffBody), severity: "disruptive", undoable: true, confirmLabel: pick(language, COPY.zoneOffYes) });
      if (!ok) return;
    }
    try {
      await patchZone(zone.name, { disabled: !zone.disabled });
      notify({ message: say(language, COPY.zoneToggled, { name: zone.name, state: pick(language, zone.disabled ? COPY.on : COPY.off) }), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
    void reload();
  };

  const remove = async (zone: DnsZone) => {
    const ok = await ask({
      title: say(language, COPY.zoneDeleteTitle, { name: zone.name }),
      body: pick(language, COPY.zoneDeleteBody),
      severity: "destructive",
      typed: nameConfirmation(zone.name, zone.name),
      confirmLabel: pick(language, COPY.zoneDeleteYes)
    });
    if (!ok) return;
    try {
      await deleteZone(zone.name);
      notify({ message: say(language, COPY.zoneDeleted, { name: zone.name }), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
    void reload();
  };

  const columns: ListColumn<DnsZone>[] = [
    { key: "name", header: pick(language, COPY.colZone), hideOnCard: true, render: (row) => <Ltr mono>{row.name}</Ltr> },
    { key: "type", header: pick(language, COPY.colZoneType), hideOnCard: true, render: (row) => zoneTypeWord(language, row.type) },
    { key: "records", header: pick(language, COPY.colRecords), render: (row) => (row.type === "forwarder" ? "—" : number(row.records)) },
    { key: "serial", header: pick(language, COPY.colSerial), advancedOnly: true, ltr: true, render: (row) => (row.serial ? String(row.serial) : "—") },
    { key: "updated", header: pick(language, COPY.colUpdated), render: (row) => (row.updated_at ? <RelativeTime value={typeof row.updated_at === "number" && row.updated_at < 1e12 ? row.updated_at * 1000 : row.updated_at} /> : "—") },
    { key: "state", header: pick(language, COPY.colState), hideOnCard: true, render: (row) => <StatusPill tone={row.disabled ? "off" : "ok"} label={pick(language, row.disabled ? COPY.off : COPY.on)} /> }
  ];
  const actions: RowAction<DnsZone>[] = [
    { key: "open", label: pick(language, COPY.open), icon: FolderOpenRoundedIcon, onClick: onOpen },
    ...(canWrite
      ? [
          { key: "off", label: pick(language, COPY.turnOff), icon: PowerSettingsNewRoundedIcon, onClick: (row: DnsZone) => void toggle(row), hidden: (row: DnsZone) => Boolean(row.disabled) },
          { key: "on", label: pick(language, COPY.turnOn), icon: PowerSettingsNewRoundedIcon, onClick: (row: DnsZone) => void toggle(row), hidden: (row: DnsZone) => !row.disabled },
          { key: "delete", label: pick(language, COPY.zoneDeleteYes), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (row: DnsZone) => void remove(row) }
        ]
      : [])
  ];
  const addButton = canWrite ? (
    <Button variant={rows.length ? "outlined" : "contained"} startIcon={<AddRoundedIcon />} onClick={() => setCreating(Date.now())} disabled={!ready} sx={{ minHeight: 44 }}>
      {pick(language, COPY.addZone)}
    </Button>
  ) : null;

  return (
    <SectionCard title={pick(language, COPY.zonesTitle)} hint={pick(language, COPY.zonesHint)} action={rows.length ? addButton : undefined}>
      <Stack spacing={2}>
        {error ? <FriendlyError error={error} title={pick(language, COPY.zonesFailed)} onRetry={() => void reload()} /> : null}
        {!ready ? null : items === null && loading ? (
          <Box sx={{ display: "grid", placeItems: "center", py: 3 }}><CircularProgress size={24} aria-hidden /></Box>
        ) : (
          <ResponsiveList
            rows={rows}
            rowKey={(row) => row.name}
            columns={columns}
            label={pick(language, COPY.zonesTitle)}
            onRowClick={onOpen}
            card={{
              title: (row) => <Ltr mono>{row.name}</Ltr>,
              meta: (row) => `${zoneTypeWord(language, row.type)}${row.type !== "forwarder" ? ` · ${say(language, COPY.versionRecords, { count: row.records ?? 0 })}` : ""}`,
              status: (row) => <StatusPill tone={row.disabled ? "off" : "ok"} label={pick(language, row.disabled ? COPY.off : COPY.on)} />
            }}
            actions={actions}
            empty={<EmptyState compact icon={DnsRoundedIcon} title={pick(language, COPY.emptyZones)} body={pick(language, COPY.emptyZonesBody)} action={addButton} />}
          />
        )}
      </Stack>
      {creating ? (
        <ZoneDialog
          key={creating}
          onClose={() => setCreating(null)}
          onCreated={(zone) => {
            setCreating(null);
            notify({ message: say(language, COPY.zoneCreated, { name: zone }), tone: "success" });
            void reload();
          }}
        />
      ) : null}
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

// ── records ──────────────────────────────────────────────────────────────────

function recordNameLabel(language: "fa" | "en", name: string): ReactNode {
  if (name === "@" || name === "") return <>{pick(language, COPY.apex)} <Typography component="span" variant="caption" color="text.secondary"><Ltr>@</Ltr></Typography></>;
  if (name === "*") return <>{pick(language, COPY.wildcard)} <Typography component="span" variant="caption" color="text.secondary"><Ltr>*</Ltr></Typography></>;
  return <Ltr mono>{name}</Ltr>;
}

function initialData(type: RecordType, data?: Record<string, unknown>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const field of RECORD_SPECS[type].fields) {
    const value = data?.[field.key];
    result[field.key] = value === undefined || value === null ? (field.defaultValue !== undefined ? String(field.defaultValue) : "") : String(value);
  }
  return result;
}

function RecordDialog({ zone, initial, onClose, onSaved }: { zone: string; initial: DnsRecord | null; onClose: () => void; onSaved: (name: string) => void }) {
  const { language } = useKit();
  const startType: RecordType = initial && isRecordType(initial.type) ? initial.type : "A";
  const [type, setType] = useState<RecordType>(startType);
  const [name, setName] = useState(initial?.name ?? "");
  const [ttl, setTtl] = useState<number | null>(initial?.ttl ?? 3600);
  const [values, setValues] = useState<Record<string, string>>(() => initialData(startType, initial?.data));
  const [comment, setComment] = useState(initial?.comment ?? "");
  const [enabled, setEnabled] = useState(!initial?.disabled);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [fields, setFields] = useState<Record<string, string>>({});
  const spec = RECORD_SPECS[type];
  const cleanName = name.trim().replace(/\.$/, "") || "@";
  const zoneSuffix = `.${zone}`;
  const relativeName = cleanName.toLowerCase().endsWith(zoneSuffix.toLowerCase()) ? cleanName.slice(0, -zoneSuffix.length) || "@" : cleanName;
  const nameProblem = !isDnsName(relativeName, true) ? pick(language, COPY.badRecordName) : null;
  const ttlProblem = ttl === null || ttl < 0 || ttl > TTL_MAX ? pick(language, COPY.ttlRange) : null;
  const problems = Object.fromEntries(spec.fields.map((field) => [field.key, fieldProblem(language, field, values[field.key] ?? "")]));
  const invalid = Boolean(nameProblem || ttlProblem || Object.values(problems).some(Boolean));

  const changeType = (next: RecordType) => {
    setType(next);
    setValues(initialData(next));
    setFields({});
  };

  const save = async () => {
    setTouched(true);
    if (invalid) return;
    setBusy(true);
    setError(null);
    setFields({});
    const data: Record<string, unknown> = {};
    for (const field of spec.fields) {
      const raw = (values[field.key] ?? "").trim();
      if (field.kind === "int") data[field.key] = Number(raw.replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit))) || field.defaultValue || 0);
      else data[field.key] = field.kind === "name" ? raw.replace(/\.$/, "") : raw;
    }
    const body = { name: relativeName, type, ttl: ttl ?? 3600, data, disabled: !enabled, ...(comment.trim() ? { comment: comment.trim() } : {}) };
    try {
      if (initial) await updateRecord(zone, initial.id, body);
      else await createRecord(zone, body);
      onSaved(relativeName === "@" ? zone : `${relativeName}.${zone}`);
    } catch (caught) {
      setFields(dnsFieldMessages(language, caught));
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog
      title={pick(language, initial ? COPY.editRecord : COPY.newRecord)}
      hint={pick(language, spec.hint)}
      submitLabel={pick(language, COPY.saveRecord)}
      busy={busy}
      error={error}
      onSubmit={() => void save()}
      onClose={onClose}
    >
      <TextField select label={pick(language, COPY.recordType)} value={type} onChange={(event) => changeType(event.target.value as RecordType)} disabled={Boolean(initial)} fullWidth error={Boolean(fields.type)} helperText={fields.type}>
        {RECORD_TYPES.map((item) => (
          <MenuItem key={item} value={item}>
            {pick(language, RECORD_SPECS[item].label)}
            <Typography component="span" variant="caption" color="text.secondary" sx={{ mx: 1 }}><Ltr>{item}</Ltr></Typography>
          </MenuItem>
        ))}
      </TextField>
      <TextField
        label={pick(language, COPY.recordName)}
        value={name}
        onChange={(event) => setName(event.target.value)}
        placeholder="@"
        error={Boolean((touched || name) && nameProblem) || Boolean(fields.name)}
        helperText={((touched || name) && nameProblem) || fields.name || pick(language, COPY.recordNameHint)}
        fullWidth
        slotProps={{
          ...ltrInput,
          input: { [language === "fa" ? "startAdornment" : "endAdornment"]: <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "nowrap", direction: "ltr" }}>{zoneSuffix}</Typography> }
        }}
      />
      {spec.fields.map((field) => {
        const problem = (touched || values[field.key]) ? problems[field.key] : null;
        const serverProblem = fields[field.key];
        const helper = problem ?? serverProblem ?? (field.hint ? pick(language, field.hint) : " ");
        if (field.kind === "choice") {
          return (
            <TextField key={field.key} select label={pick(language, field.label)} value={values[field.key] ?? ""} onChange={(event) => setValues((current) => ({ ...current, [field.key]: event.target.value }))} fullWidth error={Boolean(serverProblem)} helperText={serverProblem ?? " "}>
              {(field.options ?? []).map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {pick(language, option.label)}
                  <Typography component="span" variant="caption" color="text.secondary" sx={{ mx: 1 }}><Ltr>{option.value}</Ltr></Typography>
                </MenuItem>
              ))}
            </TextField>
          );
        }
        return (
          <TextField
            key={field.key}
            label={pick(language, field.label)}
            value={values[field.key] ?? ""}
            onChange={(event) => setValues((current) => ({ ...current, [field.key]: event.target.value }))}
            placeholder={field.placeholder}
            error={Boolean(problem || serverProblem)}
            helperText={helper}
            multiline={field.multiline}
            minRows={field.multiline ? 2 : undefined}
            fullWidth
            slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoCapitalize: "none", inputMode: field.kind === "int" ? "numeric" : undefined } }}
          />
        );
      })}
      <DurationInput label={pick(language, COPY.ttlField)} value={ttl} onChange={setTtl} min={0} max={TTL_MAX} error={ttlProblem ?? fields.ttl ?? null} helperText={pick(language, COPY.ttlHint)} />
      <TextField label={pick(language, COPY.comment)} value={comment} onChange={(event) => setComment(event.target.value)} fullWidth />
      <FormControlLabel control={<Switch checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />} label={pick(language, COPY.recordOn)} />
    </FormDialog>
  );
}

function ImportDialog({ zone, onClose, onDone }: { zone: string; onClose: () => void; onDone: () => void }) {
  const { language } = useKit();
  const [text, setText] = useState("");
  const [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [fields, setFields] = useState<Record<string, string>>({});
  const { ask, dialog } = useConfirmAction();
  const fileInput = useRef<HTMLInputElement | null>(null);

  const run = async () => {
    if (!text.trim()) return;
    if (replace) {
      const ok = await ask({ title: say(language, COPY.importReplaceTitle, { name: zone }), body: pick(language, COPY.importReplaceBody), severity: "destructive", confirmLabel: pick(language, COPY.importYes) });
      if (!ok) return;
    }
    setBusy(true);
    setError(null);
    setFields({});
    try {
      await importZone(zone, text, replace);
      onDone();
    } catch (caught) {
      setFields(dnsFieldMessages(language, caught));
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog title={pick(language, COPY.importTitle)} hint={pick(language, COPY.importHint)} submitLabel={pick(language, COPY.importYes)} busy={busy} error={error} disabled={!text.trim()} onSubmit={() => void run()} onClose={onClose} wide>
      <Box>
        <input
          ref={fileInput}
          type="file"
          accept=".zone,.txt,.db,text/plain"
          hidden
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void file.text().then(setText);
            event.target.value = "";
          }}
        />
        <Button variant="outlined" startIcon={<UploadFileRoundedIcon />} onClick={() => fileInput.current?.click()} sx={{ minHeight: 44 }}>{pick(language, COPY.pickFile)}</Button>
      </Box>
      <TextField
        label={pick(language, COPY.importText)}
        value={text}
        onChange={(event) => setText(event.target.value)}
        multiline
        minRows={8}
        maxRows={18}
        fullWidth
        error={Boolean(fields.text)}
        helperText={fields.text ?? " "}
        slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, style: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", fontSize: 13 } } }}
      />
      <FormControlLabel control={<Switch checked={replace} color="warning" onChange={(event) => setReplace(event.target.checked)} />} label={pick(language, COPY.replace)} />
      <Typography variant="caption" color="text.secondary">{pick(language, COPY.replaceHint)}</Typography>
      {dialog}
    </FormDialog>
  );
}

function HistoryDialog({ zone, canWrite, onClose, onRolledBack }: { zone: string; canWrite: boolean; onClose: () => void; onRolledBack: (version: string) => void }) {
  const { language, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const loader = useCallback((signal: AbortSignal) => fetchZoneHistory(zone, signal), [zone]);
  const { items, error, loading, reload } = useList<DnsZoneVersion>(loader);
  const [busy, setBusy] = useState<string | null>(null);
  const [rollbackError, setRollbackError] = useState<unknown>(null);
  const { ask, dialog } = useConfirmAction();
  const versions = useMemo(() => [...(items ?? [])].sort((a, b) => Number(b.version) - Number(a.version)), [items]);
  const versionText = (version: number | string) => (language === "fa" ? new Intl.NumberFormat("fa-IR", { useGrouping: false }).format(Number(version)) : String(version));

  const rollback = async (item: DnsZoneVersion) => {
    const version = versionText(item.version);
    const ok = await ask({ title: say(language, COPY.rollbackTitle, { name: zone, version }), body: pick(language, COPY.rollbackBody), severity: "disruptive", confirmLabel: pick(language, COPY.rollbackYes) });
    if (!ok) return;
    setBusy(String(item.version));
    setRollbackError(null);
    try {
      await rollbackZone(zone, item.version);
      onRolledBack(version);
    } catch (caught) {
      setRollbackError(caught);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Dialog open onClose={onClose} fullScreen={fullScreen} fullWidth maxWidth="sm">
      <DialogTitle sx={{ fontWeight: 760 }}>{say(language, COPY.historyTitle, { name: zone })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">{pick(language, COPY.historyHint)}</Typography>
          {error ? <FriendlyError error={error} title={pick(language, COPY.historyFailed)} onRetry={() => void reload()} /> : null}
          {rollbackError ? <FriendlyError error={rollbackError} /> : null}
          {items === null && loading ? <Box sx={{ display: "grid", placeItems: "center", py: 3 }}><CircularProgress size={24} aria-hidden /></Box> : null}
          {items !== null && !versions.length ? <Typography variant="body2" color="text.secondary">{pick(language, COPY.noHistory)}</Typography> : null}
          {versions.map((item, index) => (
            <Stack key={String(item.version)} direction="row" alignItems="center" justifyContent="space-between" gap={1} flexWrap="wrap" sx={{ py: 1, borderBottom: "1px solid", borderColor: "divider" }}>
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 700 }}>
                  {say(language, COPY.versionLabel, { version: versionText(item.version) })}
                  {index === 0 ? <Chip size="small" label={pick(language, COPY.current)} sx={{ mx: 1 }} /> : null}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {item.created_at ? <RelativeTime value={typeof item.created_at === "number" && item.created_at < 1e12 ? item.created_at * 1000 : item.created_at} /> : null}
                  {typeof item.records === "number" ? ` · ${say(language, COPY.versionRecords, { count: item.records })}` : ""}
                  {item.actor ? ` · ${item.actor}` : ""}
                </Typography>
              </Box>
              {canWrite && index > 0 ? (
                <Button size="small" startIcon={busy === String(item.version) ? <CircularProgress size={14} /> : <RestoreRoundedIcon />} disabled={busy !== null} onClick={() => void rollback(item)} sx={{ minHeight: 40 }}>
                  {pick(language, COPY.rollback)}
                </Button>
              ) : null}
            </Stack>
          ))}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ minHeight: 44 }}>{c.close}</Button>
      </DialogActions>
      {dialog}
    </Dialog>
  );
}

function ForwardersCard({ zone, canWrite, onSaved }: { zone: DnsZone; canWrite: boolean; onSaved: () => void }) {
  const { language } = useKit();
  const [value, setValue] = useState<string[]>(zone.forwarders ?? []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const { notify, snackbar } = useUndoSnackbar();
  useEffect(() => setValue(zone.forwarders ?? []), [zone.forwarders]);
  const dirty = JSON.stringify(value) !== JSON.stringify(zone.forwarders ?? []);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await patchZone(zone.name, { forwarders: value });
      notify({ message: pick(language, COPY.forwardersSaved), tone: "success" });
      onSaved();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };
  return (
    <SectionCard title={pick(language, COPY.forwardTitle)} hint={pick(language, COPY.forwardHint)}>
      <Stack spacing={2}>
        <ListInput label={pick(language, COPY.forwarders)} value={value} onChange={setValue} validate={(item) => forwarderProblem(language, item)} helperText={pick(language, COPY.forwardersHint)} max={8} disabled={!canWrite} />
        {error ? <FriendlyError error={error} /> : null}
        {canWrite ? (
          <Box>
            <Button variant="contained" disabled={!dirty || busy || value.length === 0} onClick={() => void save()} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
              {pick(language, COPY.saveForwarders)}
            </Button>
          </Box>
        ) : (
          <NoAccess needs="dns:write" />
        )}
      </Stack>
      {snackbar}
    </SectionCard>
  );
}

function ZoneDetail({ zone, permissions, onBack, onChanged }: { zone: DnsZone; permissions: readonly string[]; onBack: () => void; onChanged: () => void }) {
  const { language, isAdvanced, c } = useKit();
  const canWrite = hasPermission(permissions, "dns:write");
  const isForwarder = zone.type === "forwarder";
  const loader = useCallback((signal: AbortSignal) => fetchRecords(zone.name, signal), [zone.name]);
  const { items, error, loading, reload } = useList<DnsRecord>(loader, !isForwarder);
  const [filter, setFilter] = useState<string>("all");
  const [editing, setEditing] = useState<{ item: DnsRecord | null; key: number } | null>(null);
  const [importing, setImporting] = useState<number | null>(null);
  const [history, setHistory] = useState<number | null>(null);
  const [exported, setExported] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const records = items ?? [];
  const typesPresent = useMemo(() => [...new Set(records.map((record) => record.type))].sort(), [records]);
  const rows = useMemo(
    () => records.filter((record) => filter === "all" || record.type === filter).sort((a, b) => (a.type === "SOA" ? -1 : b.type === "SOA" ? 1 : a.name.localeCompare(b.name) || a.type.localeCompare(b.type))),
    [records, filter]
  );
  const fqdn = (name: string) => (name === "@" || !name ? zone.name : `${name}.${zone.name}`);

  const remove = async (record: DnsRecord) => {
    const ok = await ask({ title: say(language, COPY.removeRecordTitle, { name: fqdn(record.name) }), body: pick(language, COPY.removeRecordBody), severity: "destructive", confirmLabel: pick(language, COPY.zoneDeleteYes) });
    if (!ok) return;
    try {
      await deleteRecord(zone.name, record.id);
      notify({ message: say(language, COPY.recordRemoved, { name: fqdn(record.name) }), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    }
    void reload();
    onChanged();
  };

  const doExport = async () => {
    setExporting(true);
    try {
      const text = await exportZone(zone.name);
      setExported(text);
      notify({ message: say(language, COPY.exported, { name: zone.name }), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    } finally {
      setExporting(false);
    }
  };

  const columns: ListColumn<DnsRecord>[] = [
    { key: "name", header: pick(language, COPY.colRecName), hideOnCard: true, render: (row) => recordNameLabel(language, row.name) },
    {
      key: "type",
      header: pick(language, COPY.colType),
      hideOnCard: true,
      render: (row) => (
        <Stack spacing={0}>
          <Typography variant="body2">{recordTypeLabel(language, row.type)}</Typography>
          <Typography variant="caption" color="text.secondary"><Ltr>{row.type}</Ltr></Typography>
        </Stack>
      )
    },
    { key: "value", header: pick(language, COPY.colValue), hideOnCard: true, render: (row) => <Box component="span" sx={{ wordBreak: "break-all" }}><Ltr mono>{recordValue(row)}</Ltr></Box> },
    { key: "ttl", header: pick(language, COPY.colTtl), render: (row) => (typeof row.ttl === "number" ? formatTtl(language, row.ttl) : "—") },
    {
      key: "state",
      header: pick(language, COPY.colState),
      hideOnCard: true,
      render: (row) => (row.type === "SOA" ? <StatusPill tone="info" label={pick(language, COPY.soaNote)} /> : <StatusPill tone={row.disabled ? "off" : "ok"} label={pick(language, row.disabled ? COPY.off : COPY.on)} />)
    },
    { key: "comment", header: pick(language, COPY.comment), advancedOnly: true, hideOnCard: true, render: (row) => row.comment || "—" }
  ];
  const editable = (row: DnsRecord) => row.type !== "SOA" && isRecordType(row.type);
  const actions: RowAction<DnsRecord>[] = canWrite
    ? [
        { key: "edit", label: pick(language, COPY.editRecord), icon: EditRoundedIcon, onClick: (row) => setEditing({ item: row, key: Date.now() }), hidden: (row) => !editable(row) },
        { key: "delete", label: pick(language, COPY.zoneDeleteYes), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (row) => void remove(row), hidden: (row) => row.type === "SOA" }
      ]
    : [];
  const addButton = canWrite ? (
    <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setEditing({ item: null, key: Date.now() })} sx={{ minHeight: 44 }}>
      {pick(language, COPY.addRecord)}
    </Button>
  ) : null;

  return (
    <Stack spacing={2.5}>
      <SectionCard
        title={zone.name}
        hint={pick(language, ZONE_TYPE_WORDS[zone.type as ZoneType]?.body ?? ZONE_TYPE_WORDS.primary.body)}
        status={<StatusPill tone={zone.disabled ? "off" : "ok"} label={pick(language, zone.disabled ? COPY.off : COPY.on)} />}
      >
        <Stack direction="row" gap={1} flexWrap="wrap">
          <Button startIcon={<ArrowBackRoundedIcon sx={{ transform: language === "fa" ? "scaleX(-1)" : undefined }} />} onClick={onBack} sx={{ minHeight: 44 }}>
            {pick(language, COPY.back)}
          </Button>
          {!isForwarder ? (
            <>
              <Button variant="outlined" startIcon={exporting ? <CircularProgress size={14} /> : <DownloadRoundedIcon />} disabled={exporting} onClick={() => void doExport()} sx={{ minHeight: 44 }}>
                {pick(language, COPY.export)}
              </Button>
              {canWrite ? (
                <Button variant="outlined" startIcon={<UploadFileRoundedIcon />} onClick={() => setImporting(Date.now())} sx={{ minHeight: 44 }}>
                  {pick(language, COPY.import)}
                </Button>
              ) : null}
              <Button variant="outlined" startIcon={<HistoryRoundedIcon />} onClick={() => setHistory(Date.now())} sx={{ minHeight: 44 }}>
                {pick(language, COPY.history)}
              </Button>
            </>
          ) : null}
          <Button startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} onClick={() => void reload()} disabled={loading || isForwarder} sx={{ minHeight: 44, display: isForwarder ? "none" : undefined }}>
            {c.refresh}
          </Button>
        </Stack>
        {exported !== null ? (
          <Stack spacing={1} sx={{ mt: 2 }}>
            <CopyField label={pick(language, COPY.exportTitle)} value={exported} multiline />
            <Box>
              <Button size="small" startIcon={<DownloadRoundedIcon />} onClick={() => download(`${zone.name}.zone`, exported)} sx={{ minHeight: 40 }}>{c.download}</Button>
            </Box>
          </Stack>
        ) : null}
      </SectionCard>

      {isForwarder ? (
        <ForwardersCard zone={zone} canWrite={canWrite} onSaved={onChanged} />
      ) : (
        <SectionCard title={pick(language, COPY.recordsTitle)} hint={pick(language, COPY.recordsHint)} action={records.length ? addButton : undefined}>
          <Stack spacing={2}>
            {typesPresent.length > 1 ? (
              <Stack direction="row" gap={1} flexWrap="wrap" role="group" aria-label={pick(language, COPY.recordType)}>
                {["all", ...typesPresent].map((type) => (
                  <Chip
                    key={type}
                    label={type === "all" ? pick(language, COPY.allTypes) : isAdvanced ? type : recordTypeLabel(language, type)}
                    color={filter === type ? "primary" : "default"}
                    variant={filter === type ? "filled" : "outlined"}
                    onClick={() => setFilter(type)}
                    sx={{ minHeight: 36 }}
                  />
                ))}
              </Stack>
            ) : null}
            {error ? <FriendlyError error={error} title={pick(language, COPY.recordsFailed)} onRetry={() => void reload()} /> : null}
            {items === null && loading ? (
              <Box sx={{ display: "grid", placeItems: "center", py: 3 }}><CircularProgress size={24} aria-hidden /></Box>
            ) : (
              <ResponsiveList
                rows={rows}
                rowKey={(row) => row.id}
                columns={columns}
                label={pick(language, COPY.recordsTitle)}
                card={{
                  title: (row) => recordNameLabel(language, row.name),
                  meta: (row) => <>{recordTypeLabel(language, row.type)} · <Ltr mono>{recordValue(row)}</Ltr></>,
                  status: (row) => (row.type === "SOA" ? <StatusPill tone="info" label={pick(language, COPY.soaNote)} /> : <StatusPill tone={row.disabled ? "off" : "ok"} label={pick(language, row.disabled ? COPY.off : COPY.on)} />)
                }}
                actions={actions}
                empty={<EmptyState compact icon={DnsRoundedIcon} title={pick(language, COPY.emptyRecords)} body={pick(language, COPY.emptyRecordsBody)} action={addButton} />}
              />
            )}
            {!canWrite ? <NoAccess needs="dns:write" /> : null}
          </Stack>
        </SectionCard>
      )}

      {editing ? (
        <RecordDialog
          key={editing.key}
          zone={zone.name}
          initial={editing.item}
          onClose={() => setEditing(null)}
          onSaved={(name) => {
            setEditing(null);
            notify({ message: say(language, COPY.recordSaved, { name }), tone: "success" });
            void reload();
            onChanged();
          }}
        />
      ) : null}
      {importing ? (
        <ImportDialog
          key={importing}
          zone={zone.name}
          onClose={() => setImporting(null)}
          onDone={() => {
            setImporting(null);
            notify({ message: pick(language, COPY.imported), tone: "success" });
            void reload();
            onChanged();
          }}
        />
      ) : null}
      {history ? (
        <HistoryDialog
          key={history}
          zone={zone.name}
          canWrite={canWrite}
          onClose={() => setHistory(null)}
          onRolledBack={(version) => {
            setHistory(null);
            notify({ message: say(language, COPY.rolledBack, { version }), tone: "success" });
            void reload();
            onChanged();
          }}
        />
      ) : null}
      {dialog}
      {snackbar}
    </Stack>
  );
}

/** The zone the hash names (`?zone=`), refreshed from the list so its counters stay current. */
function OpenZone({ name, permissions, onBack }: { name: string; permissions: readonly string[]; onBack: () => void }) {
  const loader = useCallback((signal: AbortSignal) => fetchZones(signal), []);
  const { items, error, reload } = useList<DnsZone>(loader);
  const zone = items?.find((item) => item.name === name) ?? null;
  if (error && !items) return <FriendlyError error={error} onRetry={() => void reload()} />;
  if (!items) return <Box sx={{ display: "grid", placeItems: "center", py: 6 }}><CircularProgress size={28} aria-hidden /></Box>;
  if (!zone) return <FriendlyError error={new ApiError(404, "dns_zone_not_found", "")} onAction={onBack} onRetry={onBack} />;
  return <ZoneDetail zone={zone} permissions={permissions} onBack={onBack} onChanged={() => void reload()} />;
}

export default function DnsNamesTab({ permissions }: { permissions: readonly string[] }) {
  const { language, isAdvanced } = useKit();
  const { status, error, reload } = useDnsStatus(null);
  const [openZone, setOpenZone] = useState<string | null>(() => hashQuery().get("zone"));
  const [zonesKey, setZonesKey] = useState(0);
  const ready = engineReady(status);

  // Follow `?zone=` when a link changes the hash while this tab is open.
  useEffect(() => {
    const onHash = () => setOpenZone(hashQuery().get("zone"));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const open =(zone: DnsZone | null) => {
    setOpenZone(zone?.name ?? null);
    const base = window.location.hash.split("?")[0] || "#/dns/names";
    window.history.replaceState(null, "", zone ? `${base}?zone=${encodeURIComponent(zone.name)}` : base);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <Stack spacing={2.5}>
      <DnsAvailability status={status} error={error} onRetry={() => void reload()} />
      {isAdvanced && openZone && ready ? (
        <OpenZone
          name={openZone}
          permissions={permissions}
          onBack={() => {
            open(null);
            setZonesKey((value) => value + 1);
          }}
        />
      ) : (
        <>
          <OverridesSection permissions={permissions} ready={ready} />
          {isAdvanced ? <ZonesSection key={zonesKey} permissions={permissions} ready={ready} onOpen={(zone) => open(zone)} /> : null}
          {!isAdvanced && ready ? <Typography variant="caption" color="text.secondary">{pick(language, COPY.primaryOnly)}</Typography> : null}
        </>
      )}
    </Stack>
  );
}
