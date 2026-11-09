/**
 * «DNS › لاگ» (#/dns/logs, dns:logs; contract docs/38 §4–§5): who asked which name, and what came back.
 *
 * Simple: one search box (a name or an IP), result chips, the list, «زنده» (live, over SSE) and
 * «بیشتر» (next page by cursor), download as CSV/NDJSON.
 * Advanced: every filter and time range, storage status, keep-for and privacy settings
 * (saved into the DNS settings object, dns:admin), and deleting logs (typed confirmation).
 */
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  Box, Button, Chip, CircularProgress, FormControlLabel, InputAdornment, LinearProgress, ListItemText, Menu, MenuItem, Stack, Switch, TextField, Typography
} from "@mui/material";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import SpeedRoundedIcon from "@mui/icons-material/SpeedRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import FilterAltRoundedIcon from "@mui/icons-material/FilterAltRounded";
import DeleteForeverRoundedIcon from "@mui/icons-material/DeleteForeverRounded";
import ReceiptLongRoundedIcon from "@mui/icons-material/ReceiptLongRounded";
import FiberManualRecordRoundedIcon from "@mui/icons-material/FiberManualRecordRounded";
import { ApiError, hasPermission, isAbortError } from "./api";
import { errorSentence, pick, say, type Bi } from "./copy";
import { CONFIRM_WORDS, nameConfirmation } from "./copy/confirm";
import { formatNumber } from "./format";
import {
  BytesInput, ChoiceCards, DurationInput, EmptyState, FriendlyError, KeyValueList, ListInput, Ltr, NoAccess, Notice, NumberInput, PercentSlider, RelativeTime,
  ResponsiveList, SectionCard, StatusPill, formatSize, useConfirmAction, useKit, useUndoSnackbar, type ListColumn, type RowAction
} from "./kit";
import { useVisibleInterval } from "./polling";
import { DnsAvailability } from "./DnsPage";
import { engineReady, isCidr, isDnsName, isIPv4, isIPv6, useDnsStatus } from "./dns";
import {
  DEFAULT_QUERYLOG, DEFAULT_STATS, LIVE_MAX_ROWS, LOG_DNSSEC, LOG_DNSSEC_WORDS, LOG_PROTOS, LOG_PROTO_WORDS, LOG_QTYPES, LOG_RCODES, LOG_SOURCES, LOG_SOURCE_WORDS, QTYPE_WORDS, RESULT_CHIPS, RESULT_CHIP_WORDS,
  chipFilter, degradedReason, deleteLogs, fetchLogStatus, fetchLogs, logExportUrl, logSourceWord, logStreamUrl, rcodeOf, resultWord, searchFilter,
  type LogFilters, type QueryLogEntry, type QueryLogSettings, type QueryLogStatus, type ResultChip, type StatsSettings
} from "./dnsLive";
import { MitigateDialog, type MitigateTarget } from "./DnsMitigate";
import { DnsSectionSettings } from "./DnsSectionSettings";

const COPY = {
  searchLabel: { fa: "جست‌وجوی یک نام یا نشانی IP", en: "Search a name or an IP address" },
  searchPlaceholder: { fa: "مثلاً google.com یا 192.168.1.20", en: "e.g. google.com or 192.168.1.20" },
  search: { fa: "جست‌وجو", en: "Search" },
  results: { fa: "نتیجه", en: "Result" },
  live: { fa: "زنده", en: "Live" },
  liveHint: { fa: "پرسش‌های تازه همین که برسند بالای فهرست می‌آیند.", en: "New questions appear at the top as they arrive." },
  liveOn: { fa: "در حال نمایش زنده", en: "Showing live" },
  liveConnecting: { fa: "در حال وصل شدن…", en: "Connecting…" },
  livePaused: { fa: "تا وقتی این صفحه را نمی‌بینید، نمایش زنده مکث می‌کند.", en: "Live view pauses while this page is hidden." },
  liveFailed: { fa: "نمایش زنده قطع شد. دوباره روشنش کنید.", en: "The live view stopped. Turn it on again." },
  liveCap: { fa: "فقط {count} پرسش آخر نگه داشته می‌شود.", en: "Only the last {count} questions are kept." },
  sampled: { fa: "پرسش‌ها آن‌قدر زیادند که فقط بخشی نمایش داده می‌شود؛ {count} پرسش نشان داده نشد.", en: "There are so many questions that only some are shown; {count} were skipped." },
  more: { fa: "بیشتر", en: "More" },
  loading: { fa: "در حال خواندن…", en: "Loading…" },
  truncated: { fa: "جست‌وجو طول کشید و فقط بخشی از لاگ گشته شد. بازه را کوچک‌تر کنید یا «بیشتر» را بزنید.", en: "The search took long and only part of the log was searched. Narrow the range or press More." },
  loadFailed: { fa: "لاگ خوانده نشد.", en: "The log didn't load." },
  notSupported: { fa: "برنامه DNS روی سرور هنوز لاگ پرسش‌ها را ندارد. MRK و برنامه DNS را به‌روز کنید.", en: "The DNS program on the server doesn't keep a question log yet. Update MRK and the DNS program." },
  emptyTitle: { fa: "هنوز پرسشی ثبت نشده", en: "No questions recorded yet" },
  emptyBody: { fa: "وقتی دستگاه‌ها از این DNS بپرسند، اینجا می‌بینید چه کسی چه نامی پرسید و چه جوابی گرفت.", en: "When devices ask this DNS, you'll see here who asked which name and what came back." },
  emptySearch: { fa: "چیزی با «{query}» پیدا نشد. املا را بررسی کنید یا بازه زمانی را بزرگ‌تر کنید.", en: "Nothing matched “{query}”. Check the spelling or widen the time range." },
  emptyFilter: { fa: "با این فیلترها پرسشی پیدا نشد.", en: "No questions match these filters." },
  time: { fa: "زمان", en: "Time" },
  client: { fa: "دستگاه", en: "Device" },
  name: { fa: "نام", en: "Name" },
  type: { fa: "نوع", en: "Type" },
  source: { fa: "جواب از", en: "Answered by" },
  took: { fa: "زمان جواب", en: "Took" },
  msValue: { fa: "{ms} میلی‌ثانیه", en: "{ms} ms" },
  proto: { fa: "راه اتصال", en: "Transport" },
  dnssec: { fa: "امضای امنیتی", en: "Signature" },
  tokenFlag: { fa: "با کلید «{id}»", en: "with token “{id}”" },
  upstream: { fa: "DNS بیرونی", en: "Outside DNS" },
  size: { fa: "اندازه جواب", en: "Answer size" },
  flags: { fa: "نکته", en: "Notes" },
  stale: { fa: "جواب قدیمی", en: "Old answer" },
  truncatedFlag: { fa: "کوتاه‌شده", en: "Cut short" },
  onlyThisClient: { fa: "فقط پرسش‌های این دستگاه", en: "Only this device's questions" },
  onlyThisName: { fa: "فقط پرسش‌های این نام", en: "Only this name" },
  limitClient: { fa: "کند یا مسدود کردن این دستگاه", en: "Slow down or block this device" },
  limitName: { fa: "مسدود کردن این نام", en: "Block this name" },
  limitAdded: { fa: "محدودیت «{name}» گذاشته شد.", en: "A limit was set on “{name}”." },
  export: { fa: "دانلود", en: "Download" },
  exportCsv: { fa: "فایل CSV (برای برنامه‌های جدول)", en: "CSV file (for spreadsheets)" },
  exportNdjson: { fa: "فایل NDJSON (برای برنامه‌ها)", en: "NDJSON file (for scripts)" }, // copy-ok: file format name
  exportHint: { fa: "همان پرسش‌هایی که با فیلترهای فعلی دیده می‌شوند؛ حداکثر یک میلیون ردیف.", en: "The questions matching the current filters; at most one million rows." },
  // status
  logOff: { fa: "ثبت لاگ پرسش‌ها خاموش است؛ فقط آمار کلی جمع می‌شود.", en: "The question log is off; only overall numbers are collected." },
  logErrorsOnly: { fa: "فقط پرسش‌هایی که جواب درست نگرفتند ثبت می‌شوند.", en: "Only questions that didn't get a proper answer are logged." },
  logSample: { fa: "فقط بخشی از پرسش‌ها ثبت می‌شود.", en: "Only some of the questions are logged." },
  degraded: { fa: "لاگ کامل موقتاً نوشته نمی‌شود چون {reason}. وقتی درست شد، خودکار برمی‌گردد.", en: "The full log is paused for now because {reason}. It comes back by itself once that's fixed." },
  statusTitle: { fa: "فضای لاگ", en: "Log storage" },
  stSize: { fa: "حجم", en: "Size" },
  stOldest: { fa: "قدیمی‌ترین پرسش", en: "Oldest question" },
  stWritten: { fa: "پرسش‌های ثبت‌شده", en: "Questions logged" },
  stDropped: { fa: "پرسش‌های ثبت‌نشده (از دست رفته)", en: "Questions not logged (lost)" },
  stDroppedHint: { fa: "وقتی پرسش‌ها خیلی زیاد شوند، MRK به‌جای کند کردن DNS، ثبت بعضی را رها می‌کند.", en: "When questions pour in, MRK skips logging some instead of slowing DNS down." },
  stDisk: { fa: "فضای خالی دیسک", en: "Free disk space" },
  stMode: { fa: "الان چه چیزی ثبت می‌شود", en: "What's logged now" },
  stSegments: { fa: "تعداد تکه‌های فایل", en: "File pieces" },
  // filters
  filtersTitle: { fa: "فیلترها", en: "Filters" },
  range: { fa: "بازه زمانی", en: "Time range" },
  from: { fa: "از", en: "From" },
  to: { fa: "تا", en: "To" },
  any: { fa: "همه", en: "Any" },
  rcode: { fa: "کد جواب", en: "Response code" },
  minMs: { fa: "کندتر از (میلی‌ثانیه)", en: "Slower than (ms)" },
  clear: { fa: "پاک کردن فیلترها", en: "Clear filters" },
  // settings
  settingsTitle: { fa: "نگه‌داری و حریم خصوصی", en: "Keeping and privacy" },
  settingsHint: { fa: "چه چیزی ثبت شود، تا کی بماند و نشانی دستگاه‌ها چطور نوشته شود.", en: "What gets logged, how long it stays, and how device addresses are written." },
  modeTitle: { fa: "چه چیزی ثبت شود", en: "What to log" },
  modeAll: { fa: "همه پرسش‌ها", en: "Every question" },
  modeAllBody: { fa: "کامل‌ترین؛ برای پیدا کردن مشکل‌ها.", en: "The most complete; good for finding problems." },
  modeSample: { fa: "فقط بخشی", en: "Only some" },
  modeSampleBody: { fa: "برای سرورهای خیلی شلوغ؛ فضای کمتری می‌گیرد.", en: "For very busy servers; uses less space." },
  modeErrors: { fa: "فقط مشکل‌دارها", en: "Only problems" },
  modeErrorsBody: { fa: "پرسش‌هایی که پیدا نشدند، رد شدند یا خطا گرفتند.", en: "Questions that weren't found, were refused or failed." },
  modeOff: { fa: "هیچ", en: "Nothing" },
  modeOffBody: { fa: "لاگ ثبت نمی‌شود؛ آمار کلی همچنان جمع می‌شود.", en: "No log; overall numbers are still collected." },
  samplePercent: { fa: "چند درصد از پرسش‌ها ثبت شود", en: "What share of questions to log" },
  maxAge: { fa: "لاگ تا این مدت بماند", en: "Keep the log for" },
  maxBytes: { fa: "بیشترین حجم لاگ", en: "Largest log size" },
  minFree: { fa: "اگر فضای خالی دیسک کمتر از این شد، ثبت کامل متوقف شود", en: "Pause the full log when free disk space drops below" },
  ipTitle: { fa: "نشانی دستگاه‌ها چطور ثبت شود", en: "How device addresses are written" },
  ipFull: { fa: "کامل", en: "In full" },
  ipFullBody: { fa: "مثل 192.168.1.20؛ دقیق‌ترین.", en: "Like 192.168.1.20; the most exact." },
  ipMask: { fa: "نیمه‌پنهان", en: "Partly hidden" },
  ipMaskBody: { fa: "مثل 192.168.1.0؛ شبکه معلوم است ولی خود دستگاه نه.", en: "Like 192.168.1.0; the network shows but not the device." },
  ipHash: { fa: "با شناسه رمزی", en: "As a coded ID" },
  ipHashBody: { fa: "هر دستگاه یک شناسه ثابت دارد ولی نشانی‌اش معلوم نیست.", en: "Each device has a fixed ID, but its address isn't shown." },
  ipNone: { fa: "ثبت نشود", en: "Not at all" },
  ipNoneBody: { fa: "بیشترین حریم خصوصی؛ نمی‌شود فهمید چه کسی پرسیده.", en: "Most private; you can't tell who asked." },
  excludeNames: { fa: "این نام‌ها هیچ‌وقت ثبت نشوند", en: "Never log these names" },
  excludeNamesHint: { fa: "مثل example.com یا *.internal", en: "Like example.com or *.internal" },
  excludeClients: { fa: "پرسش‌های این دستگاه‌ها ثبت نشود", en: "Never log these devices" },
  excludeClientsHint: { fa: "یک نشانی یا محدوده، مثل 10.0.0.5 یا 10.0.0.0/8", en: "An address or a range, like 10.0.0.5 or 10.0.0.0/8" },
  badName: { fa: "نام را مثل example.com بنویسید.", en: "Write the name like example.com." },
  badClient: { fa: "نشانی را مثل 10.0.0.5 یا 10.0.0.0/8 بنویسید.", en: "Write it like 10.0.0.5 or 10.0.0.0/8." },
  streamEps: { fa: "بیشترین پرسش در ثانیه در نمایش زنده", en: "Most questions per second in the live view" },
  statsTitle: { fa: "آمار کلی تا کی بماند", en: "How long overall numbers stay" },
  statsMinute: { fa: "آمار دقیقه‌به‌دقیقه", en: "Minute-by-minute numbers" },
  statsHour: { fa: "آمار ساعت‌به‌ساعت", en: "Hour-by-hour numbers" },
  statsDay: { fa: "آمار روزبه‌روز", en: "Day-by-day numbers" },
  topK: { fa: "چند مورد در فهرست پرمصرف‌ترین‌ها", en: "How many items in the busiest lists" },
  // delete
  deleteTitle: { fa: "پاک کردن لاگ‌ها", en: "Delete logs" },
  deleteHint: { fa: "آمار کلی پاک نمی‌شود؛ فقط ردیف‌های لاگ.", en: "Overall numbers stay; only log rows are removed." },
  deleteAll: { fa: "همه لاگ‌ها", en: "All logs" },
  deleteClient: { fa: "فقط یک دستگاه", en: "Only one device" },
  deleteClientBody: { fa: "مثلاً اگر کسی خواست پرسش‌هایش پاک شود.", en: "For example when someone asks for their questions to be removed." },
  deleteBefore: { fa: "قدیمی‌تر از یک زمان", en: "Older than a time" },
  deleteClientField: { fa: "نشانی دستگاه", en: "Device address" },
  deleteBeforeField: { fa: "پاک کردن پرسش‌های قبل از", en: "Delete questions before" },
  deleteButton: { fa: "پاک کردن لاگ‌ها", en: "Delete logs" },
  deleteConfirmAll: { fa: "همه لاگ پرسش‌های DNS برای همیشه پاک شود؟", en: "Delete the whole DNS question log for good?" },
  deleteConfirmClient: { fa: "لاگ پرسش‌های «{client}» برای همیشه پاک شود؟", en: "Delete the questions of “{client}” for good?" },
  deleteConfirmBefore: { fa: "لاگ پرسش‌های قبل از {when} برای همیشه پاک شود؟", en: "Delete the questions before {when} for good?" },
  deleteBody: { fa: "این ردیف‌ها دیگر در جست‌وجو و دانلود نمی‌آیند. آمار کلی و نمودارها می‌مانند.", en: "These rows no longer show up in search or downloads. Overall numbers and charts stay." },
  deleted: { fa: "{count} ردیف لاگ پاک شد.", en: "{count} log rows were deleted." },
  deletedNone: { fa: "لاگ پاک شد.", en: "The log was deleted." }
} satisfies Record<string, Bi>;

type Row = QueryLogEntry & { _k: string };
type RangePreset = "15m" | "1h" | "24h" | "7d" | "all" | "custom";
const RANGE_PRESETS: RangePreset[] = ["15m", "1h", "24h", "7d", "all", "custom"];
const RANGE_WORDS: Record<RangePreset, Bi> = {
  "15m": { fa: "۱۵ دقیقه", en: "15 min" },
  "1h": { fa: "۱ ساعت", en: "1 hour" },
  "24h": { fa: "۲۴ ساعت", en: "24 hours" },
  "7d": { fa: "۷ روز", en: "7 days" },
  all: { fa: "همه", en: "All" },
  custom: { fa: "دلخواه", en: "Custom" }
};
const RANGE_MS: Partial<Record<RangePreset, number>> = { "15m": 900_000, "1h": 3_600_000, "24h": 86_400_000, "7d": 604_800_000 };

let rowCounter = 0;
const keyed = (entry: QueryLogEntry): Row => ({ ...entry, _k: `r${(rowCounter += 1)}` });

function isMissing(error: unknown) {
  return error instanceof ApiError && error.status === 404 && (!error.code || error.code === "not_found");
}
function toLocalInput(ms: number) {
  const date = new Date(ms - new Date().getTimezoneOffset() * 60_000);
  return date.toISOString().slice(0, 16);
}

type AdvancedFilters = { range: RangePreset; from: string; to: string; qtype: string; rcode: string; source: string; minMs: number | null; dnssec: string; proto: string };
const EMPTY_ADVANCED: AdvancedFilters = { range: "all", from: "", to: "", qtype: "", rcode: "", source: "", minMs: null, dnssec: "", proto: "" };

function buildFilters(search: string, chip: ResultChip, advanced: AdvancedFilters | null): LogFilters {
  const filters: LogFilters = { ...searchFilter(search), ...chipFilter(chip) };
  if (!advanced) return filters;
  if (advanced.range === "custom") {
    const from = advanced.from ? Date.parse(advanced.from) : NaN;
    const to = advanced.to ? Date.parse(advanced.to) : NaN;
    if (Number.isFinite(from)) filters.from = from;
    if (Number.isFinite(to)) filters.to = to;
  } else if (RANGE_MS[advanced.range]) {
    filters.from = Date.now() - (RANGE_MS[advanced.range] as number);
  }
  if (advanced.qtype) filters.qtype = advanced.qtype;
  if (advanced.rcode && chip === "all") filters.rcode = advanced.rcode;
  if (advanced.source) filters.source = advanced.source;
  if (advanced.minMs) filters.min_ms = advanced.minMs;
  if (advanced.dnssec && chip !== "bogus") filters.dnssec = advanced.dnssec;
  if (advanced.proto) filters.proto = advanced.proto;
  return filters;
}

// ── storage status ───────────────────────────────────────────────────────────

function StatusNotices({ status }: { status: QueryLogStatus | null }) {
  const { language } = useKit();
  if (!status) return null;
  const effective = status.mode_effective ?? status.mode;
  if (status.degraded_reason) return <Notice tone="warning">{say(language, COPY.degraded, { reason: degradedReason(language, status.degraded_reason) })}</Notice>;
  if (status.enabled === false || effective === "off") return <Notice tone="info">{pick(language, COPY.logOff)}</Notice>;
  if (effective === "errors_only") return <Notice tone="info">{pick(language, COPY.logErrorsOnly)}</Notice>;
  if (effective === "sample") return <Notice tone="info">{pick(language, COPY.logSample)}</Notice>;
  return null;
}

function StatusCard({ status }: { status: QueryLogStatus | null }) {
  const { language } = useKit();
  if (!status) return null;
  const effective = status.mode_effective ?? status.mode ?? "all";
  const modeWord: Record<string, Bi> = { all: COPY.modeAll, sample: COPY.modeSample, errors_only: COPY.modeErrors, off: COPY.modeOff };
  return (
    <SectionCard title={pick(language, COPY.statusTitle)} collapsible>
      <KeyValueList
        items={[
          { label: pick(language, COPY.stMode), value: modeWord[effective] ? pick(language, modeWord[effective]) : effective },
          { label: pick(language, COPY.stSize), value: formatSize(status.bytes ?? 0, language) },
          { label: pick(language, COPY.stOldest), value: status.oldest_ts ? <RelativeTime value={status.oldest_ts} /> : "—" },
          { label: pick(language, COPY.stWritten), value: formatNumber(status.written_total ?? null, language) },
          {
            label: pick(language, COPY.stDropped),
            value: (
              <Box>
                <span>{formatNumber(status.dropped_total ?? 0, language)}</span>
                {status.dropped_total ? <Typography variant="caption" color="text.secondary" component="p">{pick(language, COPY.stDroppedHint)}</Typography> : null}
              </Box>
            )
          },
          { label: pick(language, COPY.stDisk), value: typeof status.disk_free_percent === "number" ? `${formatNumber(Math.round(status.disk_free_percent), language)}${language === "fa" ? "٪" : "%"}` : "—" },
          { label: pick(language, COPY.stSegments), value: formatNumber(status.segments ?? null, language) },
          ...(status.degraded_reason ? [{ label: pick(language, { fa: "چرا کم شده", en: "Why it's reduced" }), value: degradedReason(language, status.degraded_reason) }] : [])
        ]}
      />
    </SectionCard>
  );
}

// ── settings (Advanced, dns:admin) ───────────────────────────────────────────

type LogDraft = { querylog: QueryLogSettings; stats: StatsSettings };
const LOG_DEFAULTS: LogDraft = { querylog: DEFAULT_QUERYLOG, stats: DEFAULT_STATS };

function nameProblem(language: "fa" | "en") {
  return (item: string) => (isDnsName(item.replace(/^\*\./, "")) ? null : pick(language, COPY.badName));
}
function clientProblem(language: "fa" | "en") {
  return (item: string) => (isIPv4(item) || isIPv6(item) || isCidr(item) ? null : pick(language, COPY.badClient));
}

function LogSettingsCard({ permissions }: { permissions: readonly string[] }) {
  const { language } = useKit();
  type Mode = "all" | "sample" | "errors_only" | "off";
  type IpMode = "full" | "mask" | "hash" | "none";
  return (
    <DnsSectionSettings<LogDraft> title={pick(language, COPY.settingsTitle)} hint={pick(language, COPY.settingsHint)} permissions={permissions} defaults={LOG_DEFAULTS} collapsible defaultCollapsed>
      {({ draft, update, serverFields }) => {
        const log = draft.querylog;
        const stats = draft.stats;
        const mode = (["all", "sample", "errors_only", "off"].includes(log.mode) ? log.mode : "all") as Mode;
        const ip = (["full", "mask", "hash", "none"].includes(log.client_ip) ? log.client_ip : "full") as IpMode;
        return (
          <Stack spacing={2.5}>
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.modeTitle)}</Typography>
            <ChoiceCards<Mode>
              label={pick(language, COPY.modeTitle)}
              value={log.enabled === false ? "off" : mode}
              onChange={(value) => update((next) => { next.querylog.mode = value; next.querylog.enabled = value !== "off"; })}
              options={[
                { key: "all", title: pick(language, COPY.modeAll), body: pick(language, COPY.modeAllBody) },
                { key: "sample", title: pick(language, COPY.modeSample), body: pick(language, COPY.modeSampleBody) },
                { key: "errors_only", title: pick(language, COPY.modeErrors), body: pick(language, COPY.modeErrorsBody) },
                { key: "off", title: pick(language, COPY.modeOff), body: pick(language, COPY.modeOffBody) }
              ]}
            />
            {mode === "sample" ? (
              <PercentSlider label={pick(language, COPY.samplePercent)} value={log.sample_percent} onChange={(value) => update((next) => { next.querylog.sample_percent = value; })} min={1} max={100} />
            ) : null}
            <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" } }}>
              <DurationInput label={pick(language, COPY.maxAge)} value={log.max_age_days * 86_400} onChange={(value) => update((next) => { next.querylog.max_age_days = Math.max(1, Math.round((value ?? 0) / 86_400)); })} min={86_400} max={365 * 86_400} units={["days"]} error={serverFields["querylog.max_age_days"] ?? null} />
              <BytesInput label={pick(language, COPY.maxBytes)} value={log.max_bytes} onChange={(value) => update((next) => { next.querylog.max_bytes = value ?? 0; })} min={16 * 1_048_576} error={serverFields["querylog.max_bytes"] ?? null} />
              <NumberInput label={pick(language, COPY.minFree)} value={log.min_free_disk_percent} onChange={(value) => update((next) => { next.querylog.min_free_disk_percent = value ?? 0; })} min={1} max={90} integer unit="٪" />
              <NumberInput label={pick(language, COPY.streamEps)} value={log.stream_max_eps} onChange={(value) => update((next) => { next.querylog.stream_max_eps = value ?? 0; })} min={1} max={10_000} integer />
            </Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.ipTitle)}</Typography>
            <ChoiceCards<IpMode>
              label={pick(language, COPY.ipTitle)}
              value={ip}
              onChange={(value) => update((next) => { next.querylog.client_ip = value; })}
              options={[
                { key: "full", title: pick(language, COPY.ipFull), body: pick(language, COPY.ipFullBody) },
                { key: "mask", title: pick(language, COPY.ipMask), body: pick(language, COPY.ipMaskBody) },
                { key: "hash", title: pick(language, COPY.ipHash), body: pick(language, COPY.ipHashBody) },
                { key: "none", title: pick(language, COPY.ipNone), body: pick(language, COPY.ipNoneBody) }
              ]}
            />
            <ListInput label={pick(language, COPY.excludeNames)} value={log.exclude_names ?? []} onChange={(value) => update((next) => { next.querylog.exclude_names = value; })} validate={nameProblem(language)} helperText={pick(language, COPY.excludeNamesHint)} max={500} />
            <ListInput label={pick(language, COPY.excludeClients)} value={log.exclude_clients ?? []} onChange={(value) => update((next) => { next.querylog.exclude_clients = value; })} validate={clientProblem(language)} helperText={pick(language, COPY.excludeClientsHint)} max={500} />
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.statsTitle)}</Typography>
            <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" } }}>
              <DurationInput label={pick(language, COPY.statsMinute)} value={stats.minute_retention_hours * 3600} onChange={(value) => update((next) => { next.stats.minute_retention_hours = Math.max(1, Math.round((value ?? 0) / 3600)); })} min={3600} max={30 * 86_400} units={["hours", "days"]} />
              <DurationInput label={pick(language, COPY.statsHour)} value={stats.hour_retention_days * 86_400} onChange={(value) => update((next) => { next.stats.hour_retention_days = Math.max(1, Math.round((value ?? 0) / 86_400)); })} min={86_400} max={730 * 86_400} units={["days"]} />
              <DurationInput label={pick(language, COPY.statsDay)} value={stats.day_retention_days * 86_400} onChange={(value) => update((next) => { next.stats.day_retention_days = Math.max(1, Math.round((value ?? 0) / 86_400)); })} min={86_400} max={3650 * 86_400} units={["days"]} />
              <NumberInput label={pick(language, COPY.topK)} value={stats.top_k} onChange={(value) => update((next) => { next.stats.top_k = value ?? 0; })} min={10} max={10_000} integer />
            </Box>
          </Stack>
        );
      }}
    </DnsSectionSettings>
  );
}

// ── delete (Advanced, dns:admin) ─────────────────────────────────────────────

function DeleteCard({ permissions, onDeleted }: { permissions: readonly string[]; onDeleted: () => void }) {
  const { language } = useKit();
  const canAdmin = hasPermission(permissions, "dns:admin");
  type Scope = "all" | "client" | "before";
  const [scope, setScope] = useState<Scope>("all");
  const [client, setClient] = useState("");
  const [before, setBefore] = useState(() => toLocalInput(Date.now() - 7 * 86_400_000));
  const [busy, setBusy] = useState(false);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const clientValue = client.trim();
  const clientBad = scope === "client" && clientValue !== "" && !(isIPv4(clientValue) || isIPv6(clientValue));
  const beforeMs = Date.parse(before);
  const ready = scope === "all" || (scope === "client" && clientValue && !clientBad) || (scope === "before" && Number.isFinite(beforeMs));

  const run = async () => {
    const word = scope === "client" ? nameConfirmation(clientValue, clientValue) : CONFIRM_WORDS.deleteLogs;
    const title = scope === "client"
      ? say(language, COPY.deleteConfirmClient, { client: clientValue })
      : scope === "before"
        ? say(language, COPY.deleteConfirmBefore, { when: new Intl.DateTimeFormat(language === "fa" ? "fa-IR-u-ca-persian" : "en-US", { dateStyle: "medium", timeStyle: "short" }).format(new Date(beforeMs)) })
        : pick(language, COPY.deleteConfirmAll);
    const ok = await ask({ title, body: pick(language, COPY.deleteBody), severity: "destructive", typed: word, undoable: false });
    if (!ok) return;
    setBusy(true);
    try {
      const result = await deleteLogs({
        ...(scope === "client" ? { client: clientValue } : {}),
        ...(scope === "before" ? { before: beforeMs } : {}),
        confirmation: word.token
      });
      notify({
        message: typeof result?.deleted_rows === "number" ? say(language, COPY.deleted, { count: formatNumber(result.deleted_rows, language) }) : pick(language, COPY.deletedNone),
        tone: "success"
      });
      onDeleted();
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns_logs"), tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard title={pick(language, COPY.deleteTitle)} hint={pick(language, COPY.deleteHint)} tone="danger" collapsible defaultCollapsed>
      {canAdmin ? (
        <Stack spacing={2}>
          <ChoiceCards<Scope>
            label={pick(language, COPY.deleteTitle)}
            value={scope}
            onChange={setScope}
            options={[
              { key: "all", title: pick(language, COPY.deleteAll) },
              { key: "client", title: pick(language, COPY.deleteClient), body: pick(language, COPY.deleteClientBody) },
              { key: "before", title: pick(language, COPY.deleteBefore) }
            ]}
          />
          {scope === "client" ? (
            <TextField label={pick(language, COPY.deleteClientField)} value={client} onChange={(event) => setClient(event.target.value)} error={clientBad} helperText={clientBad ? pick(language, COPY.badClient) : " "} size="small" slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
          ) : null}
          {scope === "before" ? (
            <TextField type="datetime-local" label={pick(language, COPY.deleteBeforeField)} value={before} onChange={(event) => setBefore(event.target.value)} size="small" slotProps={{ inputLabel: { shrink: true }, htmlInput: { dir: "ltr" } }} />
          ) : null}
          <Box>
            <Button variant="outlined" color="error" startIcon={busy ? <CircularProgress size={16} /> : <DeleteForeverRoundedIcon />} disabled={!ready || busy} onClick={() => void run()} sx={{ minHeight: 44 }}>
              {pick(language, COPY.deleteButton)}
            </Button>
          </Box>
        </Stack>
      ) : (
        <NoAccess needs="dns:admin" />
      )}
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

// ── live stream ──────────────────────────────────────────────────────────────

type LiveState = "off" | "connecting" | "live" | "paused" | "failed";

/**
 * `GET /api/v1/dns/logs/stream` as SSE. Frames carry `{type:"hello"|"entry"|"ping"|"sampled", …}`
 * either as the default `message` event or as a named event. Closed while the page is hidden.
 */
function useLiveLog(enabled: boolean, filters: LogFilters, onEntries: (rows: Row[]) => void, onSampled: (skipped: number) => void) {
  const [state, setState] = useState<LiveState>("off");
  const entries = useRef(onEntries);
  const sampled = useRef(onSampled);
  entries.current = onEntries;
  sampled.current = onSampled;
  const query = logStreamUrl(filters);

  useEffect(() => {
    if (!enabled || typeof EventSource === "undefined") {
      setState(enabled ? "failed" : "off");
      return;
    }
    let source: EventSource | null = null;
    let attempts = 0;
    let retry: number | undefined;
    let closed = false;
    let pending: Row[] = [];
    const flush = window.setInterval(() => {
      if (!pending.length) return;
      const batch = pending;
      pending = [];
      entries.current(batch.reverse());
    }, 400);
    const handle = (event: MessageEvent<string>) => {
      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(event.data) as Record<string, unknown>;
      } catch {
        return;
      }
      const type = (typeof frame.type === "string" ? frame.type : event.type === "message" ? "entry" : event.type) as string;
      if (type === "entry") {
        const entry = (frame.entry && typeof frame.entry === "object" ? frame.entry : frame) as QueryLogEntry;
        pending.push(keyed(entry));
        if (pending.length > LIVE_MAX_ROWS) pending = pending.slice(pending.length - LIVE_MAX_ROWS);
      } else if (type === "sampled") {
        const skipped = Number(frame.skipped ?? 0);
        if (skipped > 0) sampled.current(skipped);
      }
    };
    const disconnect = () => {
      source?.close();
      source = null;
    };
    const connect = () => {
      if (closed || source) return;
      setState("connecting");
      source = new EventSource(query);
      source.onopen = () => {
        attempts = 0;
        setState("live");
      };
      source.onmessage = handle;
      for (const name of ["entry", "sampled", "hello", "ping"]) source.addEventListener(name, handle as EventListener);
      source.onerror = () => {
        disconnect();
        if (closed || document.visibilityState !== "visible") return;
        if (attempts >= 5) {
          setState("failed");
          return;
        }
        attempts += 1;
        setState("connecting");
        retry = window.setTimeout(connect, 1000 * 2 ** attempts);
      };
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        attempts = 0;
        connect();
      } else {
        window.clearTimeout(retry);
        disconnect();
        setState("paused");
      }
    };
    if (document.visibilityState === "visible") connect();
    else setState("paused");
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      closed = true;
      disconnect();
      window.clearTimeout(retry);
      window.clearInterval(flush);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [enabled, query]);

  return state;
}

// ── tab ──────────────────────────────────────────────────────────────────────

export default function DnsLogsTab({ permissions }: { permissions: readonly string[] }) {
  const { language, isAdvanced } = useKit();
  const canLogs = hasPermission(permissions, "dns:logs");
  const canWrite = hasPermission(permissions, "dns:write");
  const { status, error: statusError, reload: reloadStatus } = useDnsStatus(null);
  const [text, setText] = useState("");
  const [search, setSearch] = useState("");
  const [chip, setChip] = useState<ResultChip>("all");
  const [advanced, setAdvanced] = useState<AdvancedFilters>(EMPTY_ADVANCED);
  const [rows, setRows] = useState<Row[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [live, setLive] = useState(false);
  const [skipped, setSkipped] = useState(0);
  const [logStatus, setLogStatus] = useState<QueryLogStatus | null>(null);
  const [exportAnchor, setExportAnchor] = useState<HTMLElement | null>(null);
  const [target, setTarget] = useState<MitigateTarget | null>(null);
  const { notify, snackbar } = useUndoSnackbar();
  const controller = useRef<AbortController | null>(null);
  // Advanced filters apply only in Advanced mode; Simple mode keeps the search box and chips.
  const filters = useMemo(() => buildFilters(search, chip, isAdvanced ? advanced : null), [search, chip, advanced, isAdvanced]);
  const filterKey = JSON.stringify({ ...filters, from: isAdvanced ? `${advanced.range}:${advanced.from}` : undefined });

  const load = useCallback(async (next: string | null) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      const page = await fetchLogs(filters, next, current.signal);
      const items = page.items.map(keyed);
      setRows((previous) => (next ? previous.concat(items) : items));
      setCursor(page.next_cursor ?? null);
      setTruncated(Boolean(page.truncated));
      setError(null);
      setLoaded(true);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
      setLoaded(true);
    } finally {
      if (controller.current === current) setLoading(false);
    }
    // filterKey stands for `filters` (from/to move with the clock).
  }, [filterKey]);

  const loadStatus = useCallback(async () => {
    try {
      setLogStatus(await fetchLogStatus());
    } catch {
      // the status is a nice-to-have; the list shows its own error
    }
  }, []);

  useEffect(() => {
    if (!canLogs || live) return;
    void load(null);
    return () => controller.current?.abort();
  }, [canLogs, live, load]);
  useEffect(() => {
    if (canLogs) void loadStatus();
  }, [canLogs, loadStatus]);
  useVisibleInterval(() => void loadStatus(), canLogs ? 60_000 : null);

  const liveState = useLiveLog(
    canLogs && live,
    filters,
    (batch) => setRows((previous) => {
      const merged = batch.concat(previous);
      return merged.length > LIVE_MAX_ROWS ? merged.slice(0, LIVE_MAX_ROWS) : merged;
    }),
    (count) => setSkipped((value) => value + count)
  );

  const toggleLive = (on: boolean) => {
    setSkipped(0);
    setLive(on);
    if (on) {
      setRows([]);
      setCursor(null);
      setTruncated(false);
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setSearch(text.trim());
  };

  const exportAs = (format: "csv" | "ndjson") => {
    setExportAnchor(null);
    const link = document.createElement("a");
    link.href = logExportUrl(filters, format);
    link.download = `mrk-dns-log.${format === "csv" ? "csv" : "ndjson"}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  if (!canLogs) return <NoAccess needs="dns:logs" variant="card" />;
  if (status && !engineReady(status)) {
    return (
      <Stack spacing={2.5}>
        <DnsAvailability status={status} error={statusError} onRetry={() => void reloadStatus()} />
      </Stack>
    );
  }

  const columns: ListColumn<Row>[] = [
    { key: "time", header: pick(language, COPY.time), render: (row) => <RelativeTime value={row.ts} relativeAlways={!isAdvanced} />, hideOnCard: true },
    { key: "client", header: pick(language, COPY.client), render: (row) => <Ltr mono>{row.client || "—"}</Ltr>, hideOnCard: true },
    { key: "name", header: pick(language, COPY.name), render: (row) => <Box component="span" sx={{ wordBreak: "break-all" }}><Ltr mono>{row.name || "—"}</Ltr></Box>, hideOnCard: true },
    {
      key: "type",
      header: pick(language, COPY.type),
      render: (row) => {
        const type = (row.qtype ?? "").toUpperCase();
        return !isAdvanced && QTYPE_WORDS[type] ? pick(language, QTYPE_WORDS[type]) : <Ltr>{type || "—"}</Ltr>;
      }
    },
    { key: "result", header: pick(language, COPY.results), render: (row) => { const word = resultWord(language, row); return <StatusPill tone={word.tone} label={word.label} />; }, hideOnCard: true },
    { key: "source", header: pick(language, COPY.source), render: (row) => logSourceWord(language, row.source) },
    { key: "ms", header: pick(language, COPY.took), render: (row) => (typeof row.ms === "number" ? say(language, COPY.msValue, { ms: formatNumber(row.ms, language, { maximumFractionDigits: row.ms < 10 ? 1 : 0 }) }) : "—"), align: "end" },
    {
      key: "dnssec",
      header: pick(language, COPY.dnssec),
      render: (row) => {
        const word = row.dnssec ? LOG_DNSSEC_WORDS[row.dnssec] : undefined;
        return word ? <StatusPill tone={word.tone} label={pick(language, word.label)} /> : "—";
      }
    },
    { key: "proto", header: pick(language, COPY.proto), render: (row) => <Ltr>{(row.proto ?? "").toUpperCase() || "—"}</Ltr>, advancedOnly: true },
    { key: "upstream", header: pick(language, COPY.upstream), render: (row) => (row.token ? say(language, COPY.tokenFlag, { id: row.token }) : <Ltr mono>{row.upstream || "—"}</Ltr>), advancedOnly: true },
    { key: "size", header: pick(language, COPY.size), render: (row) => (typeof row.size === "number" ? formatSize(row.size, language) : "—"), advancedOnly: true },
    {
      key: "flags",
      header: pick(language, COPY.flags),
      advancedOnly: true,
      render: (row) => [row.flags?.stale ? pick(language, COPY.stale) : "", row.flags?.tc ? pick(language, COPY.truncatedFlag) : "", isAdvanced ? rcodeOf(row.rcode) : ""].filter(Boolean).join(" · ") || "—"
    }
  ];
  const actions: RowAction<Row>[] = [
    { key: "client", label: pick(language, COPY.onlyThisClient), icon: FilterAltRoundedIcon, hidden: (row) => !row.client, onClick: (row) => { setText(row.client ?? ""); setSearch(row.client ?? ""); } },
    { key: "name", label: pick(language, COPY.onlyThisName), icon: FilterAltRoundedIcon, hidden: (row) => !row.name, onClick: (row) => { const name = (row.name ?? "").replace(/\.$/, ""); setText(name); setSearch(name); } },
    ...(canWrite ? [
      { key: "limit-client", label: pick(language, COPY.limitClient), icon: SpeedRoundedIcon, hidden: (row: Row) => !row.client || !(isIPv4(row.client) || isIPv6(row.client)), onClick: (row: Row) => setTarget({ kind: "client", match: row.client as string, action: "throttle" }) },
      { key: "limit-name", label: pick(language, COPY.limitName), icon: BlockRoundedIcon, danger: true, hidden: (row: Row) => !row.name, onClick: (row: Row) => setTarget({ kind: "domain", match: (row.name as string).replace(/\.$/, ""), action: "block" }) }
    ] : [])
  ];

  const filtered = Boolean(search) || chip !== "all" || (isAdvanced && JSON.stringify(advanced) !== JSON.stringify(EMPTY_ADVANCED));
  const empty = isMissing(error) ? (
    <Notice tone="info">{pick(language, COPY.notSupported)}</Notice>
  ) : search ? (
    <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>{say(language, COPY.emptySearch, { query: search })}</Typography>
  ) : filtered ? (
    <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>{pick(language, COPY.emptyFilter)}</Typography>
  ) : live ? (
    <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>{pick(language, COPY.liveHint)}</Typography>
  ) : (
    <EmptyState icon={ReceiptLongRoundedIcon} title={pick(language, COPY.emptyTitle)} body={pick(language, COPY.emptyBody)} />
  );

  const liveLabel = liveState === "live" ? COPY.liveOn : liveState === "connecting" ? COPY.liveConnecting : liveState === "paused" ? COPY.livePaused : liveState === "failed" ? COPY.liveFailed : null;

  return (
    <Stack spacing={2.5}>
      <DnsAvailability status={status} error={statusError} onRetry={() => void reloadStatus()} />
      <StatusNotices status={logStatus} />

      <SectionCard>
        <Stack spacing={1.75}>
          <Box component="form" onSubmit={submit} noValidate>
            <Stack direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ xs: "stretch", sm: "center" }}>
              <TextField
                label={pick(language, COPY.searchLabel)}
                placeholder={pick(language, COPY.searchPlaceholder)}
                value={text}
                onChange={(event) => {
                  setText(event.target.value);
                  if (!event.target.value.trim()) setSearch("");
                }}
                fullWidth
                size="small"
                autoComplete="off"
                slotProps={{
                  htmlInput: { dir: "ltr", spellCheck: false, autoCapitalize: "none", enterKeyHint: "search" },
                  input: { startAdornment: <InputAdornment position="start"><SearchRoundedIcon fontSize="small" /></InputAdornment> }
                }}
              />
              <Button type="submit" variant="contained" sx={{ minHeight: 40, flexShrink: 0 }}>{pick(language, COPY.search)}</Button>
            </Stack>
          </Box>
          <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center" role="group" aria-label={pick(language, COPY.results)}>
            {RESULT_CHIPS.map((key) => (
              <Chip
                key={key}
                label={pick(language, RESULT_CHIP_WORDS[key])}
                color={chip === key ? "primary" : "default"}
                variant={chip === key ? "filled" : "outlined"}
                onClick={() => setChip(key)}
                aria-pressed={chip === key}
                sx={{ minHeight: 36 }}
              />
            ))}
          </Stack>
          <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center" justifyContent="space-between">
            <Stack direction="row" alignItems="center" gap={1} sx={{ minWidth: 0 }}>
              <FormControlLabel control={<Switch checked={live} onChange={(event) => toggleLive(event.target.checked)} />} label={pick(language, COPY.live)} sx={{ me: 0 }} />
              {live && liveLabel ? (
                <Stack direction="row" alignItems="center" gap={0.5} sx={{ minWidth: 0 }}>
                  {liveState === "live" ? <FiberManualRecordRoundedIcon sx={{ fontSize: 12, color: "error.main" }} aria-hidden /> : null}
                  <Typography variant="caption" color={liveState === "failed" ? "error" : "text.secondary"}>{pick(language, liveLabel)}</Typography>
                </Stack>
              ) : null}
            </Stack>
            <Button startIcon={<DownloadRoundedIcon />} onClick={(event) => setExportAnchor(event.currentTarget)} sx={{ minHeight: 40 }} aria-haspopup="menu">
              {pick(language, COPY.export)}
            </Button>
            <Menu anchorEl={exportAnchor} open={Boolean(exportAnchor)} onClose={() => setExportAnchor(null)}>
              <MenuItem onClick={() => exportAs("csv")} sx={{ minHeight: 44 }}><ListItemText primary={pick(language, COPY.exportCsv)} /></MenuItem>
              <MenuItem onClick={() => exportAs("ndjson")} sx={{ minHeight: 44 }}><ListItemText primary={pick(language, COPY.exportNdjson)} /></MenuItem>
              <Typography variant="caption" color="text.secondary" component="p" sx={{ px: 2, pb: 1, maxWidth: 300 }}>{pick(language, COPY.exportHint)}</Typography>
            </Menu>
          </Stack>

          {isAdvanced ? (
            <Box sx={{ display: "grid", gap: 1.5, gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr", lg: "repeat(4, 1fr)" } }}>
              <TextField select size="small" label={pick(language, COPY.range)} value={advanced.range} onChange={(event) => setAdvanced({ ...advanced, range: event.target.value as RangePreset, from: event.target.value === "custom" && !advanced.from ? toLocalInput(Date.now() - 3_600_000) : advanced.from })}>
                {RANGE_PRESETS.map((key) => <MenuItem key={key} value={key}>{pick(language, RANGE_WORDS[key])}</MenuItem>)}
              </TextField>
              {advanced.range === "custom" ? (
                <>
                  <TextField type="datetime-local" size="small" label={pick(language, COPY.from)} value={advanced.from} onChange={(event) => setAdvanced({ ...advanced, from: event.target.value })} slotProps={{ inputLabel: { shrink: true }, htmlInput: { dir: "ltr" } }} />
                  <TextField type="datetime-local" size="small" label={pick(language, COPY.to)} value={advanced.to} onChange={(event) => setAdvanced({ ...advanced, to: event.target.value })} slotProps={{ inputLabel: { shrink: true }, htmlInput: { dir: "ltr" } }} />
                </>
              ) : null}
              <TextField select size="small" label={pick(language, COPY.type)} value={advanced.qtype} onChange={(event) => setAdvanced({ ...advanced, qtype: event.target.value })}>
                <MenuItem value="">{pick(language, COPY.any)}</MenuItem>
                {LOG_QTYPES.map((type) => <MenuItem key={type} value={type}><Ltr>{type}</Ltr></MenuItem>)}
              </TextField>
              <TextField select size="small" label={pick(language, COPY.rcode)} value={chip === "all" ? advanced.rcode : ""} disabled={chip !== "all"} onChange={(event) => setAdvanced({ ...advanced, rcode: event.target.value })}>
                <MenuItem value="">{pick(language, COPY.any)}</MenuItem>
                {LOG_RCODES.map((code) => <MenuItem key={code} value={code}><Ltr>{code}</Ltr></MenuItem>)}
              </TextField>
              <TextField select size="small" label={pick(language, COPY.source)} value={advanced.source} onChange={(event) => setAdvanced({ ...advanced, source: event.target.value })}>
                <MenuItem value="">{pick(language, COPY.any)}</MenuItem>
                {LOG_SOURCES.map((source) => <MenuItem key={source} value={source}>{pick(language, LOG_SOURCE_WORDS[source])}</MenuItem>)}
              </TextField>
              <TextField select size="small" label={pick(language, COPY.dnssec)} value={chip === "bogus" ? "" : advanced.dnssec} disabled={chip === "bogus"} onChange={(event) => setAdvanced({ ...advanced, dnssec: event.target.value })}>
                <MenuItem value="">{pick(language, COPY.any)}</MenuItem>
                {LOG_DNSSEC.map((key) => <MenuItem key={key} value={key}>{pick(language, LOG_DNSSEC_WORDS[key].label)}</MenuItem>)}
              </TextField>
              <TextField select size="small" label={pick(language, COPY.proto)} value={advanced.proto} onChange={(event) => setAdvanced({ ...advanced, proto: event.target.value })}>
                <MenuItem value="">{pick(language, COPY.any)}</MenuItem>
                {LOG_PROTOS.map((key) => <MenuItem key={key} value={key}>{pick(language, LOG_PROTO_WORDS[key])}</MenuItem>)}
              </TextField>
              <NumberInput label={pick(language, COPY.minMs)} value={advanced.minMs} onChange={(value) => setAdvanced({ ...advanced, minMs: value })} min={0} max={60_000} integer />
              {JSON.stringify(advanced) !== JSON.stringify(EMPTY_ADVANCED) ? (
                <Box sx={{ alignSelf: "center" }}><Button onClick={() => setAdvanced(EMPTY_ADVANCED)} sx={{ minHeight: 40 }}>{pick(language, COPY.clear)}</Button></Box>
              ) : null}
            </Box>
          ) : null}
        </Stack>
      </SectionCard>

      {live && skipped > 0 ? <Notice tone="info">{say(language, COPY.sampled, { count: formatNumber(skipped, language) })}</Notice> : null}
      {truncated && !live ? <Notice tone="warning">{pick(language, COPY.truncated)}</Notice> : null}
      {error && !isMissing(error) ? <FriendlyError error={error} title={pick(language, COPY.loadFailed)} onRetry={() => void load(null)} scope="dns" /> : null}

      <SectionCard flush={rows.length > 0}>
        {loading && !rows.length ? <LinearProgress /> : null}
        {loaded || live ? (
          <ResponsiveList
            rows={rows}
            rowKey={(row) => row._k}
            columns={columns}
            dense
            label={pick(language, { fa: "پرسش‌های DNS", en: "DNS questions" })}
            actions={actions}
            card={{
              title: (row) => <Ltr mono>{row.name || "—"}</Ltr>,
              meta: (row) => (
                <>
                  <Ltr mono>{row.client || "—"}</Ltr>{" · "}<RelativeTime value={row.ts} relativeAlways />
                </>
              ),
              status: (row) => { const word = resultWord(language, row); return <StatusPill tone={word.tone} label={word.label} />; }
            }}
            empty={empty}
          />
        ) : null}
        {live && rows.length >= LIVE_MAX_ROWS ? (
          <Typography variant="caption" color="text.secondary" component="p" sx={{ p: 1.5 }}>{say(language, COPY.liveCap, { count: formatNumber(LIVE_MAX_ROWS, language) })}</Typography>
        ) : null}
        {!live && cursor ? (
          <Box sx={{ display: "flex", justifyContent: "center", p: 1.5 }}>
            <Button variant="outlined" onClick={() => void load(cursor)} disabled={loading} startIcon={loading ? <CircularProgress size={16} /> : undefined} sx={{ minHeight: 44 }}>
              {pick(language, loading ? COPY.loading : COPY.more)}
            </Button>
          </Box>
        ) : null}
      </SectionCard>

      {isAdvanced ? <StatusCard status={logStatus} /> : null}
      {isAdvanced ? <LogSettingsCard permissions={permissions} /> : null}
      {isAdvanced ? <DeleteCard permissions={permissions} onDeleted={() => { void loadStatus(); if (!live) void load(null); }} /> : null}

      {target ? (
        <MitigateDialog
          key={`${target.kind}:${target.match}`}
          target={target}
          onClose={() => setTarget(null)}
          onDone={() => {
            notify({ message: say(language, COPY.limitAdded, { name: target.match }), tone: "success" });
            setTarget(null);
          }}
        />
      ) : null}
      {snackbar}
    </Stack>
  );
}
