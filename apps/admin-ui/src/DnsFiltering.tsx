/**
 * «DNS › مسدودسازی» (contract docs/41 §3.1, §3.2, §7).
 *
 * - One switch for blocking ads and malware, two free suggested lists (off until added), your own
 *   lists with their size and last update, and «همیشه باز» / «همیشه بسته» names (dns:admin).
 * - «این دامنه چرا بسته شد؟»: asks the engine which list and rule blocked a name (dns:read).
 * - Client groups (Advanced): different rules for parts of the network; the first matching group wins.
 * Lists, allow/block and groups are sections of the engine settings, saved with `config_version`.
 */
import { useCallback, useState, type FormEvent } from "react";
import {
  Box, Button, Chip, CircularProgress, Divider, FormControlLabel, IconButton, MenuItem, Paper, Stack, Switch, TextField, Tooltip, Typography
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import ArrowDownwardRoundedIcon from "@mui/icons-material/ArrowDownwardRounded";
import ArrowUpwardRoundedIcon from "@mui/icons-material/ArrowUpwardRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import GroupsRoundedIcon from "@mui/icons-material/GroupsRounded";
import HelpOutlineRoundedIcon from "@mui/icons-material/HelpOutlineRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import { hasPermission } from "./api";
import { errorSentence, pick, say, type Bi } from "./copy";
import {
  ChoiceCards, EmptyState, FriendlyError, ListInput, Ltr, Notice, NumberInput, RelativeTime, SectionCard, StatGrid, StatTile, StatusPill,
  useKit, useUndoSnackbar
} from "./kit";
import { fetchDnsSettings, isCidr, isIPv4, isIPv6, type DnsUpstream } from "./dns";
import { DnsSectionSettings } from "./DnsSectionSettings";
import {
  DEFAULT_FILTERING, FILTER_ACTION_WORDS, FILTER_FORMATS, FORMAT_WORDS, GROUP_FILTERING_WORDS, SUGGESTED_LISTS, checkFiltering, fetchFilteringStatus,
  isFilterName, newId, refreshFiltering, toTime, type ClientGroup, type FilterAction, type FilterCheck, type FilterList, type FilteringSettings,
  type FilteringStatus, type GroupFiltering
} from "./dnsFinal";
import { FormDialog, isMissingEndpoint, ltrInput, useLoader } from "./dnsUi";

const COPY = {
  title: { fa: "مسدودسازی تبلیغات و بدافزار", en: "Block ads and malware" },
  hint: { fa: "دستگاه‌هایی که از این DNS می‌پرسند به سایت‌های تبلیغاتی و خطرناکِ فهرست‌ها نمی‌رسند. هیچ چیز اجباری نیست؛ هر وقت خواستید خاموشش کنید.", en: "Devices that ask this DNS can't reach the ad and dangerous sites on the lists. Nothing is forced; turn it off whenever you like." },
  enabled: { fa: "مسدودسازی روشن باشد", en: "Blocking is on" },
  enabledHint: { fa: "خاموش: همه نام‌ها مثل قبل جواب می‌گیرند و فهرست‌ها فقط نگه داشته می‌شوند.", en: "Off: every name is answered as before; the lists are only kept." },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  suggestionsTitle: { fa: "فهرست‌های پیشنهادی", en: "Suggested lists" },
  suggestionsHint: { fa: "رایگان و شناخته‌شده؛ روی یکی بزنید تا اضافه شود.", en: "Free and well known; tap one to add it." },
  added: { fa: "اضافه شد", en: "Added" },
  addThis: { fa: "افزودن", en: "Add" },
  listsTitle: { fa: "فهرست‌ها", en: "Lists" },
  noLists: { fa: "هنوز فهرستی اضافه نشده؛ یکی از پیشنهادی‌ها را بزنید.", en: "No lists yet; tap one of the suggestions." },
  addList: { fa: "افزودن فهرست دلخواه", en: "Add your own list" },
  entries: { fa: "{count} نام", en: "{count} names" },
  updated: { fa: "به‌روز شده", en: "Updated" },
  updating: { fa: "در حال به‌روزرسانی", en: "Updating" },
  neverUpdated: { fa: "هنوز دانلود نشده", en: "Not downloaded yet" },
  listFailed: { fa: "آخرین دانلود انجام نشد؛ نسخه قبلی استفاده می‌شود.", en: "The last download failed; the previous copy is used." },
  edit: { fa: "تغییر", en: "Edit" },
  remove: { fa: "برداشتن", en: "Remove" },
  allowTitle: { fa: "همیشه باز", en: "Always open" },
  allowHint: { fa: "این نام‌ها هیچ‌وقت بسته نمی‌شوند، حتی اگر در فهرستی باشند.", en: "These names are never blocked, even if a list has them." },
  blockTitle: { fa: "همیشه بسته", en: "Always blocked" },
  blockHint: { fa: "این نام‌ها همیشه بسته‌اند. برای همه زیردامنه‌ها ‎*.example.com بنویسید.", en: "These names are always blocked. Write *.example.com for every subdomain." },
  nameHint: { fa: "مثل ads.example.com یا ‎*.example.com", en: "Like ads.example.com or *.example.com" },
  badName: { fa: "نام را مثل ads.example.com بنویسید.", en: "Write the name like ads.example.com." },
  actionTitle: { fa: "به نام بسته‌شده چه جوابی بدهد؟", en: "What to answer for a blocked name?" },
  safeSearch: { fa: "جست‌وجوی امن (Google و Bing و YouTube)", en: "Safe search (Google, Bing and YouTube)" },
  safeSearchHint: { fa: "نتیجه‌های بزرگسالان در جست‌وجو پنهان می‌شود.", en: "Adult results are hidden in searches." },
  statusTitle: { fa: "وضعیت", en: "Status" },
  totalEntries: { fa: "نام‌های بسته", en: "Blocked names" },
  blocked1h: { fa: "بسته‌شده در یک ساعت گذشته", en: "Blocked in the last hour" },
  refreshLists: { fa: "همین حالا به‌روز کن", en: "Update now" },
  refreshed: { fa: "به‌روزرسانی فهرست‌ها شروع شد؛ چند دقیقه طول می‌کشد.", en: "Updating the lists has started; it takes a few minutes." },
  statusFailed: { fa: "وضعیت مسدودسازی خوانده نشد.", en: "The blocking status didn't load." },
  notSupported: { fa: "برنامه DNS روی سرور هنوز مسدودسازی ندارد. آن را به‌روز کنید.", en: "The DNS program on the server can't block yet. Update it." },
  // list dialog
  listDialogNew: { fa: "فهرست تازه", en: "New list" },
  listDialogEdit: { fa: "تغییر فهرست", en: "Edit list" },
  listName: { fa: "نام فهرست", en: "List name" },
  listUrl: { fa: "نشانی فهرست", en: "List address" },
  listUrlHint: { fa: "فقط HTTPS؛ مثل https://example.com/hosts.txt", en: "HTTPS only; like https://example.com/hosts.txt" },
  badUrl: { fa: "نشانی باید با https://‎ شروع شود.", en: "The address must start with https://." },
  listFormat: { fa: "شکل فهرست", en: "List format" },
  updateHours: { fa: "هر چند ساعت به‌روز شود", en: "Update every (hours)" },
  listOn: { fa: "این فهرست روشن باشد", en: "This list is on" },
  saveList: { fa: "ثبت در فهرست‌ها", en: "Put in the lists" },
  saveHint: { fa: "بعد از این، «ذخیره» پایین کارت را بزنید.", en: "Then press Save at the bottom of the card." },
  nameNeeded: { fa: "یک نام بنویسید.", en: "Write a name." },
  // check
  checkTitle: { fa: "این دامنه چرا بسته شد؟", en: "Why was this domain blocked?" },
  checkHint: { fa: "نام سایتی را که باز نمی‌شود بنویسید تا ببینید کدام فهرست آن را بسته است.", en: "Write the name of a site that won't open to see which list blocked it." },
  checkName: { fa: "نام سایت", en: "Site name" },
  checkClient: { fa: "از طرف این دستگاه (اختیاری)", en: "As this device (optional)" },
  checkClientHint: { fa: "برای گروه‌های دستگاه، نشانی IP دستگاه را بدهید.", en: "For device groups, give the device's IP address." },
  check: { fa: "بررسی", en: "Check" },
  checking: { fa: "در حال بررسی…", en: "Checking…" },
  checkBlocked: { fa: "«{name}» بسته است.", en: "“{name}” is blocked." },
  checkBlockedBy: { fa: "فهرست: {list}", en: "List: {list}" },
  checkRule: { fa: "قاعده: ", en: "Rule: " },
  checkManual: { fa: "در «همیشه بسته» نوشته شده است.", en: "It's in “Always blocked”." },
  checkOpen: { fa: "«{name}» بسته نیست.", en: "“{name}” isn't blocked." },
  checkAllowed: { fa: "«{name}» در «همیشه باز» است و بسته نمی‌شود.", en: "“{name}” is in “Always open”, so it's never blocked." },
  checkService: { fa: "سرویس «{service}» برای این دستگاه‌ها بسته شده است.", en: "The service “{service}” is blocked for these devices." },
  checkGroup: { fa: "گروه دستگاه: {group}", en: "Device group: {group}" },
  checkSafeSearch: { fa: "«{name}» بسته نیست؛ به نسخه جست‌وجوی امن فرستاده می‌شود.", en: "“{name}” isn't blocked; it's sent to the safe-search version." },
  checkOff: { fa: "مسدودسازی برای این دستگاه خاموش است؛ «{name}» بسته نمی‌شود.", en: "Blocking is off for this device; “{name}” isn't blocked." },
  checkOpenHint: { fa: "اگر باز نمی‌شود، علت جای دیگری است؛ در «تست» بپرسید یا «لاگ» را ببینید.", en: "If it won't open, the cause is elsewhere; ask under Test or see the Log." },
  unblockHint: { fa: "اگر باید باز باشد، آن را در «همیشه باز» پایین همین صفحه بنویسید و «ذخیره» را بزنید.", en: "If it should open, write it under “Always open” below and press Save." },
  checkFailed: { fa: "بررسی انجام نشد.", en: "The check didn't run." },
  // groups
  groupsTitle: { fa: "گروه‌های دستگاه", en: "Device groups" },
  groupsHint: { fa: "برای بخشی از شبکه قاعده جدا بگذارید؛ مثلاً اتاق بچه‌ها همیشه مسدودسازی، یا سرورها بدون آن. اولین گروهی که دستگاه در آن باشد اعمال می‌شود.", en: "Set separate rules for part of the network; for example the kids' room always blocked, or servers without it. The first group a device is in applies." },
  addGroup: { fa: "افزودن گروه", en: "Add a group" },
  noGroups: { fa: "هنوز گروهی نیست", en: "No groups yet" },
  noGroupsBody: { fa: "بدون گروه، همه دستگاه‌ها یک قاعده دارند.", en: "Without groups, every device follows one rule." },
  groupName: { fa: "نام گروه", en: "Group name" },
  groupNetworks: { fa: "محدوده‌های شبکه", en: "Network ranges" },
  groupNetworksHint: { fa: "مثل 192.168.1.0/24", en: "Like 192.168.1.0/24" },
  badRange: { fa: "محدوده را مثل 192.168.1.0/24 بنویسید.", en: "Write the range like 192.168.1.0/24." },
  groupFiltering: { fa: "مسدودسازی برای این گروه", en: "Blocking for this group" },
  groupLists: { fa: "فقط این فهرست‌ها (خالی = همه)", en: "Only these lists (empty = all)" },
  groupUpstreams: { fa: "DNS بیرونی این گروه (خالی = همان همیشگی)", en: "This group's outside DNS (empty = the usual)" },
  groupId: { fa: "شناسه", en: "ID" },
  groupIdHint: { fa: "در رکوردهای «فقط برای این گروه» استفاده می‌شود.", en: "Used by records meant only for this group." },
  moveUp: { fa: "بالاتر", en: "Move up" },
  moveDown: { fa: "پایین‌تر", en: "Move down" },
  networksNeeded: { fa: "دست‌کم یک محدوده بنویسید.", en: "Write at least one range." },
  groupCount: { fa: "{count} محدوده", en: "{count} ranges" },
  advancedNote: { fa: "گروه‌های دستگاه در حالت «پیشرفته» هستند.", en: "Device groups are in Advanced mode." }
} satisfies Record<string, Bi>;

const FILTERING_DEFAULTS = { filtering: DEFAULT_FILTERING };
const GROUP_DEFAULTS = { client_groups: [] as ClientGroup[], upstreams: [] as DnsUpstream[] };

const isHttps = (value: string) => {
  try {
    return new URL(value.trim()).protocol === "https:";
  } catch {
    return false;
  }
};

// ── status ───────────────────────────────────────────────────────────────────

function useFilteringStatus() {
  const loader = useCallback((signal: AbortSignal) => fetchFilteringStatus(signal), []);
  return useLoader<FilteringStatus>(loader);
}

function number(language: "fa" | "en", value: number | null | undefined) {
  return typeof value === "number" ? new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(value) : "—";
}

// ── list dialog ──────────────────────────────────────────────────────────────

function ListDialog({ initial, taken, onClose, onSave }: { initial: FilterList | null; taken: string[]; onClose: () => void; onSave: (list: FilterList) => void }) {
  const { language } = useKit();
  const [name, setName] = useState(initial?.name ?? "");
  const [url, setUrl] = useState(initial?.url ?? "");
  const [format, setFormat] = useState<string>(initial?.format ?? "hosts");
  const [hours, setHours] = useState<number | null>(initial?.update_hours ?? 24);
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [touched, setTouched] = useState(false);
  const nameProblem = !name.trim() ? pick(language, COPY.nameNeeded) : null;
  const urlProblem = !isHttps(url) ? pick(language, COPY.badUrl) : null;
  const save = () => {
    setTouched(true);
    if (nameProblem || urlProblem) return;
    onSave({ id: initial?.id ?? newId(name, taken), name: name.trim(), url: url.trim(), format, update_hours: hours ?? 24, enabled });
  };
  return (
    <FormDialog title={pick(language, initial ? COPY.listDialogEdit : COPY.listDialogNew)} hint={pick(language, COPY.saveHint)} submitLabel={pick(language, COPY.saveList)} busy={false} error={null} onSubmit={save} onClose={onClose}>
      <TextField label={pick(language, COPY.listName)} value={name} onChange={(event) => setName(event.target.value)} error={touched && Boolean(nameProblem)} helperText={(touched && nameProblem) || " "} autoFocus fullWidth />
      <TextField label={pick(language, COPY.listUrl)} value={url} onChange={(event) => setUrl(event.target.value)} error={(touched || Boolean(url)) && Boolean(urlProblem)} helperText={((touched || url) && urlProblem) || pick(language, COPY.listUrlHint)} fullWidth slotProps={ltrInput} />
      <TextField select label={pick(language, COPY.listFormat)} value={format} onChange={(event) => setFormat(event.target.value)} fullWidth>
        {FILTER_FORMATS.map((item) => <MenuItem key={item} value={item}>{pick(language, FORMAT_WORDS[item])}</MenuItem>)}
      </TextField>
      <NumberInput label={pick(language, COPY.updateHours)} value={hours} onChange={setHours} min={1} max={168} integer />
      <FormControlLabel control={<Switch checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />} label={pick(language, COPY.listOn)} />
    </FormDialog>
  );
}

// ── main card ────────────────────────────────────────────────────────────────

function FilteringCard({ permissions, status, onSaved }: { permissions: readonly string[]; status: FilteringStatus | null; onSaved: () => void }) {
  const { language, isAdvanced } = useKit();
  const [editing, setEditing] = useState<{ list: FilterList | null; key: number } | null>(null);
  const validate = useCallback((draft: typeof FILTERING_DEFAULTS) => {
    const problems: Record<string, string> = {};
    const bad = (items: string[]) => items.some((item) => !isFilterName(item));
    if (bad(draft.filtering.allow ?? [])) problems.allow = pick(language, COPY.badName);
    if (bad(draft.filtering.block ?? [])) problems.block = pick(language, COPY.badName);
    return problems;
  }, [language]);
  const nameProblem = (value: string) => (isFilterName(value) ? null : pick(language, COPY.badName));
  const listStatus = (id: string) => status?.lists?.find((item) => item.id === id) ?? null;

  return (
    <DnsSectionSettings title={pick(language, COPY.title)} hint={pick(language, COPY.hint)} permissions={permissions} defaults={FILTERING_DEFAULTS} validate={validate} onSaved={onSaved}>
      {({ draft, update, problems, serverFields }) => {
        const filtering: FilteringSettings = draft.filtering;
        const lists = filtering.lists ?? [];
        const set = (mutate: (next: FilteringSettings) => void) => update((next) => mutate(next.filtering));
        const saveList = (list: FilterList) => {
          set((next) => {
            const index = next.lists.findIndex((item) => item.id === list.id);
            if (index >= 0) next.lists[index] = list;
            else next.lists.push(list);
          });
          setEditing(null);
        };
        return (
          <Stack spacing={2.5}>
            <Paper variant="outlined" sx={{ p: 1.5, borderRadius: 2, borderColor: filtering.enabled ? "success.main" : "divider" }}>
              <FormControlLabel
                control={<Switch checked={Boolean(filtering.enabled)} onChange={(event) => set((next) => { next.enabled = event.target.checked; })} />}
                label={<Typography sx={{ fontWeight: 720 }}>{pick(language, COPY.enabled)}</Typography>}
              />
              <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>{pick(language, COPY.enabledHint)}</Typography>
            </Paper>

            <Stack spacing={1}>
              <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.suggestionsTitle)}</Typography>
              <Typography variant="caption" color="text.secondary">{pick(language, COPY.suggestionsHint)}</Typography>
              <Box sx={{ display: "grid", gap: 1, gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))" } }}>
                {SUGGESTED_LISTS.map((suggestion) => {
                  const present = lists.some((item) => item.url === suggestion.list.url || item.id === suggestion.list.id);
                  return (
                    <Paper key={suggestion.key} variant="outlined" sx={{ p: 1.5, borderRadius: 2, display: "flex", flexDirection: "column", gap: 1 }}>
                      <Typography sx={{ fontWeight: 720 }}>{pick(language, suggestion.name)}</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, flex: 1 }}>{pick(language, suggestion.hint)}</Typography>
                      <Box>
                        {present ? <Chip size="small" color="success" variant="outlined" label={pick(language, COPY.added)} /> : (
                          <Button size="small" startIcon={<AddRoundedIcon />} onClick={() => set((next) => {
                            next.lists.push({ ...suggestion.list, id: newId(suggestion.list.id, next.lists.map((item) => item.id)), name: pick(language, suggestion.name), enabled: true });
                            if (next.lists.length === 1) next.enabled = true;
                          })} sx={{ minHeight: 40 }}>
                            {pick(language, COPY.addThis)}
                          </Button>
                        )}
                      </Box>
                    </Paper>
                  );
                })}
              </Box>
            </Stack>

            <Stack spacing={1}>
              <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.listsTitle)}</Typography>
              {!lists.length ? <Typography variant="body2" color="text.secondary">{pick(language, COPY.noLists)}</Typography> : null}
              <Stack divider={<Divider flexItem />} spacing={1}>
                {lists.map((list, index) => {
                  const info = listStatus(list.id);
                  return (
                    <Stack key={list.id} direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ sm: "center" }}>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
                          <Typography sx={{ fontWeight: 700 }}>{list.name || list.id}</Typography>
                          <StatusPill tone={list.enabled ? (info?.error ? "warn" : "ok") : "off"} label={pick(language, list.enabled ? COPY.on : COPY.off)} />
                          {info?.updating ? <StatusPill tone="busy" label={pick(language, COPY.updating)} /> : null}
                          {typeof info?.entries === "number" ? <Typography variant="caption" color="text.secondary">{say(language, COPY.entries, { count: info.entries })}</Typography> : null}
                        </Stack>
                        <Typography variant="caption" color="text.secondary" component="div">
                          {info?.updated_at ? <>{pick(language, COPY.updated)} <RelativeTime value={toTime(info.updated_at)} /></> : pick(language, COPY.neverUpdated)}
                          {" · "}{pick(language, FORMAT_WORDS[list.format as keyof typeof FORMAT_WORDS] ?? { fa: list.format, en: list.format })}
                        </Typography>
                        {isAdvanced ? <Typography variant="caption" color="text.secondary" component="div" sx={{ overflowWrap: "anywhere" }}><Ltr mono>{list.url}</Ltr></Typography> : null}
                        {info?.error ? <Typography variant="caption" color="warning.main" component="div">{pick(language, COPY.listFailed)}</Typography> : null}
                      </Box>
                      <Stack direction="row" gap={0.5} alignItems="center">
                        <Switch checked={Boolean(list.enabled)} onChange={(event) => set((next) => { next.lists[index].enabled = event.target.checked; })} slotProps={{ input: { "aria-label": list.name } }} />
                        <Tooltip title={pick(language, COPY.edit)}><IconButton aria-label={pick(language, COPY.edit)} onClick={() => setEditing({ list, key: Date.now() })} sx={{ width: 44, height: 44 }}><EditRoundedIcon /></IconButton></Tooltip>
                        <Tooltip title={pick(language, COPY.remove)}><IconButton aria-label={pick(language, COPY.remove)} onClick={() => set((next) => { next.lists.splice(index, 1); })} sx={{ width: 44, height: 44 }}><DeleteOutlineRoundedIcon /></IconButton></Tooltip>
                      </Stack>
                    </Stack>
                  );
                })}
              </Stack>
              <Box>
                <Button startIcon={<AddRoundedIcon />} onClick={() => setEditing({ list: null, key: Date.now() })} sx={{ minHeight: 44 }}>{pick(language, COPY.addList)}</Button>
              </Box>
            </Stack>

            <Divider />
            <ListInput label={pick(language, COPY.allowTitle)} value={filtering.allow ?? []} onChange={(value) => set((next) => { next.allow = value; })} validate={nameProblem} helperText={problems.allow ?? serverFields["filtering.allow"] ?? pick(language, COPY.allowHint)} max={2000} />
            <ListInput label={pick(language, COPY.blockTitle)} value={filtering.block ?? []} onChange={(value) => set((next) => { next.block = value; })} validate={nameProblem} helperText={problems.block ?? serverFields["filtering.block"] ?? pick(language, COPY.blockHint)} max={2000} />
            <FormControlLabel control={<Switch checked={Boolean(filtering.safe_search)} onChange={(event) => set((next) => { next.safe_search = event.target.checked; })} />} label={pick(language, COPY.safeSearch)} />
            <Typography variant="caption" color="text.secondary" sx={{ mt: -2 }}>{pick(language, COPY.safeSearchHint)}</Typography>
            {isAdvanced ? (
              <Stack spacing={1}>
                <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.actionTitle)}</Typography>
                <ChoiceCards<FilterAction>
                  label={pick(language, COPY.actionTitle)}
                  value={(filtering.action as FilterAction) ?? "nxdomain"}
                  onChange={(value) => set((next) => { next.action = value; })}
                  options={(Object.keys(FILTER_ACTION_WORDS) as FilterAction[]).map((key) => ({ key, title: pick(language, FILTER_ACTION_WORDS[key].label), body: pick(language, FILTER_ACTION_WORDS[key].body) }))}
                />
              </Stack>
            ) : null}
            {editing ? <ListDialog key={editing.key} initial={editing.list} taken={lists.map((item) => item.id)} onClose={() => setEditing(null)} onSave={saveList} /> : null}
          </Stack>
        );
      }}
    </DnsSectionSettings>
  );
}

// ── status + refresh ─────────────────────────────────────────────────────────

function StatusCard({ permissions, status, error, loading, onReload }: { permissions: readonly string[]; status: FilteringStatus | null; error: unknown; loading: boolean; onReload: () => void }) {
  const { language, c } = useKit();
  const canAdmin = hasPermission(permissions, "dns:admin");
  const [busy, setBusy] = useState(false);
  const { notify, snackbar } = useUndoSnackbar();
  const refresh = async () => {
    setBusy(true);
    try {
      await refreshFiltering();
      notify({ message: pick(language, COPY.refreshed), tone: "success" });
      window.setTimeout(onReload, 3_000);
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    } finally {
      setBusy(false);
    }
  };
  if (error && !status) {
    return isMissingEndpoint(error)
      ? <Notice tone="info">{pick(language, COPY.notSupported)}</Notice>
      : <FriendlyError error={error} title={pick(language, COPY.statusFailed)} onRetry={onReload} severity="warning" />;
  }
  return (
    <SectionCard
      title={pick(language, COPY.statusTitle)}
      action={
        <Stack direction="row" gap={1}>
          <Button size="small" startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} onClick={onReload} disabled={loading} sx={{ minHeight: 40 }}>{c.refresh}</Button>
          {canAdmin ? <Button size="small" variant="outlined" startIcon={busy ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} disabled={busy} onClick={() => void refresh()} sx={{ minHeight: 40 }}>{pick(language, COPY.refreshLists)}</Button> : null}
        </Stack>
      }
    >
      <StatGrid columns={2}>
        <StatTile label={pick(language, COPY.totalEntries)} value={number(language, status?.total_entries)} icon={BlockRoundedIcon} />
        <StatTile label={pick(language, COPY.blocked1h)} value={number(language, status?.blocked_1h)} />
      </StatGrid>
      {snackbar}
    </SectionCard>
  );
}

// ── why blocked ──────────────────────────────────────────────────────────────

function WhyBlockedCard({ listNames }: { listNames: Record<string, string> }) {
  const { language, isAdvanced } = useKit();
  const [name, setName] = useState("");
  const [client, setClient] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ name: string; data: FilterCheck } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const clean = name.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0].replace(/\.$/, "");
  const nameProblem = clean && !isFilterName(clean) ? pick(language, COPY.badName) : null;
  const clientProblem = client.trim() && !isIPv4(client.trim()) && !isIPv6(client.trim()) ? pick(language, COPY.checkClientHint) : null;
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!clean || nameProblem || clientProblem) return;
    setBusy(true);
    setError(null);
    try {
      setResult({ name: clean, data: await checkFiltering(clean, client.trim() || undefined) });
    } catch (caught) {
      setError(caught);
      setResult(null);
    } finally {
      setBusy(false);
    }
  };
  const data = result?.data;
  const listLabel = data?.list_id ? listNames[data.list_id] ?? data.list_id : null;
  const reason = data?.reason ?? (data?.allowed ? "allow_list" : null);
  const manual = reason === "custom_block" || data?.list_id === "block";
  return (
    <SectionCard title={pick(language, COPY.checkTitle)} hint={pick(language, COPY.checkHint)}>
      <Stack spacing={2} component="form" onSubmit={(event) => void submit(event)} noValidate>
        <Stack direction={{ xs: "column", sm: "row" }} gap={1.5} alignItems={{ sm: "flex-start" }}>
          <TextField label={pick(language, COPY.checkName)} value={name} onChange={(event) => setName(event.target.value)} error={Boolean(nameProblem)} helperText={nameProblem ?? pick(language, COPY.nameHint)} sx={{ flex: 2 }} slotProps={ltrInput} />
          {isAdvanced ? <TextField label={pick(language, COPY.checkClient)} value={client} onChange={(event) => setClient(event.target.value)} error={Boolean(clientProblem)} helperText={clientProblem ?? " "} sx={{ flex: 1 }} slotProps={ltrInput} /> : null}
          <Button type="submit" variant="contained" disabled={!clean || busy || Boolean(nameProblem || clientProblem)} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : <HelpOutlineRoundedIcon />} sx={{ minHeight: 56 }}>
            {pick(language, busy ? COPY.checking : COPY.check)}
          </Button>
        </Stack>
        {error ? <FriendlyError error={error} title={pick(language, COPY.checkFailed)} scope="dns" /> : null}
        {result && data ? (
          data.blocked ? (
            <Notice tone="warning">
              <Typography sx={{ fontWeight: 720 }}>{say(language, COPY.checkBlocked, { name: result.name })}</Typography>
              {manual ? <Typography variant="body2">{pick(language, COPY.checkManual)}</Typography>
                : reason === "service" ? <Typography variant="body2">{say(language, COPY.checkService, { service: data.service ?? "" })}</Typography>
                : listLabel ? <Typography variant="body2">{say(language, COPY.checkBlockedBy, { list: listLabel })}</Typography> : null}
              {data.group ? <Typography variant="body2">{say(language, COPY.checkGroup, { group: data.group })}</Typography> : null}
              {data.rule ? <Typography variant="body2">{pick(language, COPY.checkRule)}<Ltr mono>{data.rule}</Ltr></Typography> : null}
              <Typography variant="caption" component="div">{pick(language, COPY.unblockHint)}</Typography>
            </Notice>
          ) : (
            <Notice tone={reason === "filtering_off" ? "info" : "success"}>
              <Typography sx={{ fontWeight: 720 }}>{say(language, reason === "allow_list" ? COPY.checkAllowed : reason === "safe_search" ? COPY.checkSafeSearch : reason === "filtering_off" ? COPY.checkOff : COPY.checkOpen, { name: result.name })}</Typography>
              {reason !== "allow_list" && reason !== "safe_search" ? <Typography variant="body2">{pick(language, COPY.checkOpenHint)}</Typography> : null}
            </Notice>
          )
        ) : null}
      </Stack>
    </SectionCard>
  );
}

// ── client groups ────────────────────────────────────────────────────────────

function GroupsCard({ permissions, listOptions }: { permissions: readonly string[]; listOptions: { id: string; name: string }[] }) {
  const { language } = useKit();
  const validate = useCallback((draft: typeof GROUP_DEFAULTS) => {
    const problems: Record<string, string> = {};
    draft.client_groups.forEach((group, index) => {
      if (!group.name.trim()) problems[`g${index}.name`] = pick(language, COPY.nameNeeded);
      if (!group.networks.length) problems[`g${index}.networks`] = pick(language, COPY.networksNeeded);
    });
    return problems;
  }, [language]);
  return (
    <DnsSectionSettings title={pick(language, COPY.groupsTitle)} hint={pick(language, COPY.groupsHint)} permissions={permissions} defaults={GROUP_DEFAULTS} validate={validate}>
      {({ draft, update, problems }) => {
        const groups = draft.client_groups;
        const upstreams = (draft.upstreams ?? []).filter((item) => item.id);
        const set = (index: number, change: Partial<ClientGroup>) => update((next) => { next.client_groups[index] = { ...next.client_groups[index], ...change }; });
        const move = (index: number, by: number) => update((next) => {
          const [item] = next.client_groups.splice(index, 1);
          next.client_groups.splice(index + by, 0, item);
        });
        return (
          <Stack spacing={2}>
            {!groups.length ? <EmptyState compact icon={GroupsRoundedIcon} title={pick(language, COPY.noGroups)} body={pick(language, COPY.noGroupsBody)} /> : null}
            {groups.map((group, index) => (
              <Paper key={`${group.id}-${index}`} variant="outlined" sx={{ p: 1.5, borderRadius: 2 }}>
                <Stack spacing={1.5}>
                  <Stack direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ sm: "flex-start" }}>
                    <TextField size="small" label={pick(language, COPY.groupName)} value={group.name} onChange={(event) => set(index, { name: event.target.value })} error={Boolean(problems[`g${index}.name`])} helperText={problems[`g${index}.name`] ?? " "} sx={{ flex: 1 }} />
                    <TextField size="small" label={pick(language, COPY.groupId)} value={group.id} helperText={pick(language, COPY.groupIdHint)} sx={{ flex: 1 }} slotProps={{ htmlInput: { dir: "ltr", readOnly: true } }} />
                    <Stack direction="row">
                      <Tooltip title={pick(language, COPY.moveUp)}><span><IconButton aria-label={pick(language, COPY.moveUp)} disabled={index === 0} onClick={() => move(index, -1)} sx={{ width: 44, height: 44 }}><ArrowUpwardRoundedIcon /></IconButton></span></Tooltip>
                      <Tooltip title={pick(language, COPY.moveDown)}><span><IconButton aria-label={pick(language, COPY.moveDown)} disabled={index === groups.length - 1} onClick={() => move(index, 1)} sx={{ width: 44, height: 44 }}><ArrowDownwardRoundedIcon /></IconButton></span></Tooltip>
                      <Tooltip title={pick(language, COPY.remove)}><IconButton aria-label={pick(language, COPY.remove)} onClick={() => update((next) => { next.client_groups.splice(index, 1); })} sx={{ width: 44, height: 44 }}><DeleteOutlineRoundedIcon /></IconButton></Tooltip>
                    </Stack>
                  </Stack>
                  <ListInput label={pick(language, COPY.groupNetworks)} value={group.networks ?? []} onChange={(value) => set(index, { networks: value })} validate={(value) => (isCidr(value) ? null : pick(language, COPY.badRange))} helperText={problems[`g${index}.networks`] ?? pick(language, COPY.groupNetworksHint)} max={64} />
                  <TextField select size="small" label={pick(language, COPY.groupFiltering)} value={group.filtering ?? "inherit"} onChange={(event) => set(index, { filtering: event.target.value as GroupFiltering })} fullWidth>
                    {(Object.keys(GROUP_FILTERING_WORDS) as GroupFiltering[]).map((key) => <MenuItem key={key} value={key}>{pick(language, GROUP_FILTERING_WORDS[key])}</MenuItem>)}
                  </TextField>
                  {listOptions.length && group.filtering !== "off" ? (
                    <TextField select size="small" label={pick(language, COPY.groupLists)} value={group.lists ?? []} onChange={(event) => set(index, { lists: typeof event.target.value === "string" ? event.target.value.split(",") : (event.target.value as string[]) })} slotProps={{ select: { multiple: true } }} fullWidth>
                      {listOptions.map((item) => <MenuItem key={item.id} value={item.id}>{item.name}</MenuItem>)}
                    </TextField>
                  ) : null}
                  {upstreams.length ? (
                    <TextField select size="small" label={pick(language, COPY.groupUpstreams)} value={group.upstreams ?? []} onChange={(event) => set(index, { upstreams: typeof event.target.value === "string" ? event.target.value.split(",") : (event.target.value as string[]) })} slotProps={{ select: { multiple: true } }} fullWidth>
                      {upstreams.map((item) => <MenuItem key={item.id} value={item.id!}><Ltr mono>{item.address}</Ltr></MenuItem>)}
                    </TextField>
                  ) : null}
                </Stack>
              </Paper>
            ))}
            <Box>
              <Button startIcon={<AddRoundedIcon />} onClick={() => update((next) => {
                const taken = next.client_groups.map((item) => item.id);
                next.client_groups.push({ id: newId(`group-${taken.length + 1}`, taken), name: "", networks: [], filtering: "inherit" });
              })} sx={{ minHeight: 44 }}>
                {pick(language, COPY.addGroup)}
              </Button>
            </Box>
          </Stack>
        );
      }}
    </DnsSectionSettings>
  );
}

// ── the tab ──────────────────────────────────────────────────────────────────

export default function DnsFilteringTab({ permissions }: { permissions: readonly string[] }) {
  const { language, isAdvanced } = useKit();
  const canAdmin = hasPermission(permissions, "dns:admin");
  const status = useFilteringStatus();
  const [lists, setLists] = useState<{ id: string; name: string }[]>([]);
  const listNames = Object.fromEntries(lists.map((item) => [item.id, item.name]));
  return (
    <Stack spacing={2.5}>
      <StatusCard permissions={permissions} status={status.data} error={status.error} loading={status.loading} onReload={() => void status.reload()} />
      <WhyBlockedCard listNames={listNames} />
      {canAdmin ? <ListsWatcher onLists={setLists} /> : null}
      <FilteringCard permissions={permissions} status={status.data} onSaved={() => void status.reload()} />
      {isAdvanced ? <GroupsCard permissions={permissions} listOptions={lists} /> : <Typography variant="caption" color="text.secondary">{pick(language, COPY.advancedNote)}</Typography>}
    </Stack>
  );
}

/** Reads the list names once (for «چرا بسته شد؟» and the groups), without its own card. */
function ListsWatcher({ onLists }: { onLists: (lists: { id: string; name: string }[]) => void }) {
  const loader = useCallback(async (signal: AbortSignal) => {
    const settings = await fetchDnsSettings(signal);
    const filtering = settings.filtering as Partial<FilteringSettings> | undefined;
    const lists = (filtering?.lists ?? []).map((item) => ({ id: item.id, name: item.name || item.id }));
    onLists(lists);
    return lists;
  }, [onLists]);
  useLoader(loader);
  return null;
}
