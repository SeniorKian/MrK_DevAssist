/**
 * «DNS» (docs/36, contract docs/37 §5): Pishkar's own DNS server, phase D1.
 * Tabs from nav.ts: status · monitor (D2) · logs (D2, dns:logs) · setup · names · templates (docs/41) · blocking (docs/41) · test ·
 * encrypted (D4) · settings (dns:admin).
 * The D3 («دور زدن تحریم») tab is added when that phase lands.
 *
 * This file holds the page shell plus the two small tabs (status and test); the bigger tabs
 * load on demand from DnsMonitor.tsx, DnsLogs.tsx, DnsSetup.tsx, DnsNames.tsx and DnsSettings.tsx.
 */
import { lazy, useState, type FormEvent } from "react";
import { Box, Button, Checkbox, CircularProgress, Divider, FormControlLabel, MenuItem, Stack, TextField, Typography } from "@mui/material";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import TravelExploreRoundedIcon from "@mui/icons-material/TravelExploreRounded";
import SpeedRoundedIcon from "@mui/icons-material/SpeedRounded";
import BoltRoundedIcon from "@mui/icons-material/BoltRounded";
import PublicRoundedIcon from "@mui/icons-material/PublicRounded";
import CleaningServicesRoundedIcon from "@mui/icons-material/CleaningServicesRounded";
import PlaylistAddCheckRoundedIcon from "@mui/icons-material/PlaylistAddCheckRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import { hasPermission } from "./api";
import { errorSentence, pick, say, type Bi } from "./copy";
import {
  Duration, EmptyState, FriendlyError, HelperNotice, KeyValueList, Ltr, NoAccess, Notice, PageHeader, GroupTabs, SectionCard,
  StatGrid, StatTile, StatusPill, helperProblem, useConfirmAction, useKit, useUndoSnackbar, formatSize
} from "./kit";
import { TabBody, type GroupPageProps } from "./ServerPage";
import { TabPanel, useVisibleTab } from "./PackagesPage";
import {
  RECORD_TYPES, dnsVerdict, engineReady, flushDnsCache, formatQps, hitPercent, isDnsName, isIPv4, isIPv6, rcodeName, rcodeWord,
  resolveName, sourceWord, answerValue, upstreamProto, PROTO_WORDS, type DnsStatus, type ResolveResult
} from "./dns";
import { useDnsStatus } from "./dns";
import { DnssecBadge, TRACE_COPY, TraceView } from "./DnsTrace";

const DnsSetupTab = lazy(() => import("./DnsSetup"));
const DnsNamesTab = lazy(() => import("./DnsNames"));
const DnsSettingsTab = lazy(() => import("./DnsSettings"));
const DnsMonitorTab = lazy(() => import("./DnsMonitor"));
const DnsLogsTab = lazy(() => import("./DnsLogs"));
const DnsEncryptedTab = lazy(() => import("./DnsEncrypted"));
const DnsTemplatesTab = lazy(() => import("./DnsTemplates"));
const DnsFilteringTab = lazy(() => import("./DnsFiltering"));

const COPY = {
  title: { fa: "DNS", en: "DNS" },
  setupLink: { fa: "رفتن به راه‌اندازی", en: "Go to Set up" },
  startSetup: { fa: "شروع راه‌اندازی", en: "Start setup" },
  notInstalledTitle: { fa: "DNS هنوز روی این سرور راه نیفتاده", en: "DNS isn't set up on this server yet" },
  notInstalledBody: {
    fa: "با چند قدم ساده، سرور و کانتینرها نام‌ها را از پیشکار می‌پرسند و شما می‌توانید نام‌های خودتان را بسازید.",
    en: "In a few simple steps, the server and its containers ask Pishkar for names, and you can make your own names."
  },
  setupUnfinished: { fa: "DNS روشن است، ولی راه‌اندازی هنوز تمام نشده. بقیه قدم‌ها را در «راه‌اندازی» ببینید.", en: "DNS is running, but setup isn't finished. See the remaining steps in Set up." },
  statusFailed: { fa: "وضعیت DNS خوانده نشد.", en: "The DNS status didn't load." },
  moduleMissing: { fa: "بخش DNS روی نسخه فعلی سرور نیست. پیشکار را به‌روز کنید.", en: "DNS isn't on your server's current version. Update Pishkar." },
  qps: { fa: "پرسش در ثانیه", en: "Questions per second" },
  qpsCaption: { fa: "میانگین دقیقه گذشته: {value}", en: "Last minute average: {value}" },
  hit: { fa: "جواب از حافظه", en: "Answered from memory" },
  hitCaption: { fa: "هر چه بیشتر، سریع‌تر", en: "Higher is faster" },
  upstreamTile: { fa: "DNS‌های بیرونی سالم", en: "Healthy outside DNS servers" },
  upstreamCaption: { fa: "{healthy} از {total}", en: "{healthy} of {total}" },
  allHealthy: { fa: "همه جواب می‌دهند", en: "All of them answer" },
  someSick: { fa: "{count} تا جواب نمی‌دهد", en: "{count} not answering" },
  noUpstreams: { fa: "هیچ DNS بیرونی تنظیم نشده", en: "No outside DNS is set" },
  totalQueries: { fa: "همه پرسش‌ها", en: "All questions" },
  uptime: { fa: "روشن از", en: "Running for" },
  upstreamsTitle: { fa: "DNS‌های بیرونی", en: "Outside DNS servers" },
  upstreamsHint: { fa: "پیشکار نام‌هایی را که خودش نمی‌داند از این‌ها می‌پرسد.", en: "Pishkar asks these for names it doesn't know itself." },
  healthy: { fa: "سالم", en: "Healthy" },
  unhealthy: { fa: "جواب نمی‌دهد", en: "Not answering" },
  rtt: { fa: "{ms} میلی‌ثانیه", en: "{ms} ms" },
  listenersTitle: { fa: "نشانی‌هایی که DNS روی آن‌ها جواب می‌دهد", en: "Addresses DNS answers on" },
  listenersHint: { fa: "برنامه‌ها باید از یکی از این نشانی‌ها بپرسند.", en: "Apps should ask one of these addresses." },
  listening: { fa: "جواب می‌دهد", en: "Answering" },
  notListening: { fa: "گوش نمی‌دهد", en: "Not listening" },
  noListeners: { fa: "DNS هنوز روی هیچ نشانی گوش نمی‌دهد.", en: "DNS isn't listening on any address yet." },
  technical: { fa: "جزئیات فنی", en: "Technical details" },
  version: { fa: "نسخه", en: "Version" },
  pressure: { fa: "فشار کار", en: "Load level" },
  memory: { fa: "حافظه مصرفی", en: "Memory used" },
  goroutines: { fa: "کارهای هم‌زمان داخلی", en: "Internal workers" },
  cacheSize: { fa: "جواب‌های ذخیره‌شده", en: "Stored answers" },
  cacheSizeValue: { fa: "{entries} جواب، {size} از {max}", en: "{entries} answers, {size} of {max}" },
  configVersion: { fa: "نسخه تنظیمات", en: "Settings version" },
  flush: { fa: "پاک کردن جواب‌های ذخیره‌شده", en: "Clear stored answers" },
  flushHint: { fa: "اگر آدرس یک سایت عوض شده ولی هنوز آدرس قدیمی می‌آید، این را بزنید.", en: "If a site's address changed but the old one still comes back, press this." },
  flushTitle: { fa: "همه جواب‌های ذخیره‌شده پاک شود؟", en: "Clear all stored answers?" },
  flushBody: { fa: "چند ثانیه پرسش‌ها کمی کندتر می‌شوند تا دوباره جمع شوند. چیزی از دست نمی‌رود.", en: "Questions get a little slower for a few seconds while answers build up again. Nothing is lost." },
  flushYes: { fa: "بله، پاک کن", en: "Yes, clear" },
  flushed: { fa: "جواب‌های ذخیره‌شده پاک شد.", en: "Stored answers were cleared." },
  // test tab
  testTitle: { fa: "یک نام را امتحان کنید", en: "Try a name" },
  testHint: { fa: "ببینید پیشکار برای این نام چه جوابی می‌دهد و جواب از کجا آمد.", en: "See what Pishkar answers for this name and where the answer came from." },
  name: { fa: "نام", en: "Name" },
  namePlaceholder: { fa: "مثلاً google.com", en: "e.g. google.com" },
  type: { fa: "چه چیزی", en: "What" },
  clientIp: { fa: "از طرف این نشانی بپرس (اختیاری)", en: "Ask as this address (optional)" },
  clientIpHint: { fa: "برای دیدن این‌که یک دستگاه خاص اجازه پرسیدن دارد یا نه.", en: "To see whether a specific device is allowed to ask." },
  ask: { fa: "بپرس", en: "Ask" },
  asking: { fa: "در حال پرسیدن…", en: "Asking…" },
  badName: { fa: "نام را مثل google.com بنویسید.", en: "Write the name like google.com." },
  badIp: { fa: "نشانی را مثل 192.168.1.20 بنویسید.", en: "Write the address like 192.168.1.20." },
  result: { fa: "جواب", en: "Answer" },
  from: { fa: "از کجا", en: "From" },
  took: { fa: "در {ms} میلی‌ثانیه", en: "in {ms} ms" },
  noAnswers: { fa: "جوابی برای این نوع پرسش نیامد.", en: "No answer came back for this kind of question." },
  keepsFor: { fa: "نگه‌داری تا", en: "Kept for" },
  upstreamUsed: { fa: "DNS بیرونی که جواب داد", en: "Outside DNS that answered" },
  rcode: { fa: "کد جواب", en: "Response code" },
  notReady: { fa: "تا DNS روشن نشده، امتحان کردن ممکن نیست.", en: "You can try names once DNS is running." },
  testFailed: { fa: "پرسش انجام نشد.", en: "The question didn't go through." },
  trace: { fa: "مسیر کامل را نشانم بده", en: "Show me the full path" },
  traceHint: { fa: "از ریشه اینترنت تا خود دامنه، قدم‌به‌قدم؛ کمی کندتر است.", en: "From the internet's root to the domain itself, step by step; a little slower." },
  traceNeedsWrite: { fa: "برای دیدن مسیر کامل، اجازه «تغییر DNS» لازم است.", en: "Seeing the full path needs permission to change DNS." },
  askSignatures: { fa: "امضاها را هم بخواه", en: "Ask for signatures too" },
  skipCheck: { fa: "بدون بررسی امضا (برای عیب‌یابی)", en: "Don't check signatures (for troubleshooting)" },
  noCache: { fa: "از حافظه استفاده نکن، تازه بپرس", en: "Don't use memory, ask fresh" }
} satisfies Record<string, Bi>;

/** Plain words for the common question types; the rest keep their technical name. */
const QUESTION_WORDS: Record<string, Bi> = {
  A: { fa: "نشانی IPv4", en: "IPv4 address" },
  AAAA: { fa: "نشانی IPv6", en: "IPv6 address" },
  CNAME: { fa: "نام دیگر", en: "Alias" },
  MX: { fa: "سرور ایمیل", en: "Mail server" },
  TXT: { fa: "متن", en: "Text" },
  NS: { fa: "سرور نام", en: "Name server" },
  SRV: { fa: "آدرس سرویس", en: "Service location" },
  PTR: { fa: "نام یک نشانی", en: "Name of an address" },
  CAA: { fa: "صادرکننده گواهی", en: "Certificate issuer" },
  SOA: { fa: "مشخصات دامنه", en: "Zone details" }
};
const SIMPLE_QUESTIONS = ["A", "AAAA", "MX", "TXT", "CNAME"];
const ADVANCED_QUESTIONS = [...RECORD_TYPES, "SOA"];

const PRESSURE_WORDS: Record<string, { tone: "ok" | "warn" | "error"; label: Bi }> = {
  normal: { tone: "ok", label: { fa: "عادی", en: "Normal" } },
  warning: { tone: "warn", label: { fa: "هشدار", en: "Warning" } },
  critical: { tone: "error", label: { fa: "بحرانی", en: "Critical" } },
  emergency: { tone: "error", label: { fa: "اضطراری", en: "Emergency" } }
};

/** Calm notice for "no DNS module" / "not installed" / "not answering", shared by the tabs. */
export function DnsAvailability({ status, error, onRetry, showReady = false }: { status: DnsStatus | null; error: unknown; onRetry: () => void; showReady?: boolean }) {
  const { language } = useKit();
  if (error && !status) {
    if (helperProblem(error) === "module_missing") return <Notice tone="info">{pick(language, COPY.moduleMissing)}</Notice>;
    return <HelperNotice error={error} onRetry={onRetry} />;
  }
  if (!status) return null;
  if (!status.installed) {
    return (
      <Notice tone="info" action={<Button color="inherit" size="small" href="#/dns/setup" sx={{ minHeight: 40 }}>{pick(language, COPY.setupLink)}</Button>}>
        {dnsVerdict(language, status).sentence}
      </Notice>
    );
  }
  if (!status.reachable) {
    return (
      <Notice tone="error" action={<Button color="inherit" size="small" onClick={onRetry} sx={{ minHeight: 40 }}>{pick(language, { fa: "دوباره امتحان کن", en: "Try again" })}</Button>}>
        {dnsVerdict(language, status).sentence}
      </Notice>
    );
  }
  return showReady ? <Notice tone="success">{dnsVerdict(language, status).sentence}</Notice> : null;
}

function StatusTab({ permissions }: { permissions: readonly string[] }) {
  const { language, isAdvanced, c } = useKit();
  const { status, error, loading, reload } = useDnsStatus(5_000);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [flushing, setFlushing] = useState(false);
  const canWrite = hasPermission(permissions, "dns:write");
  const verdict = dnsVerdict(language, status);
  const engine = status?.engine ?? null;
  const upstreams = engine?.upstreams ?? [];
  const listeners = engine?.listeners ?? [];
  const healthy = upstreams.filter((item) => item.healthy).length;
  const hit = hitPercent(engine?.cache?.hit_ratio);
  const number = (value: number | null | undefined) => (typeof value === "number" ? new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(value) : "—");

  const flush = async () => {
    const ok = await ask({ title: pick(language, COPY.flushTitle), body: pick(language, COPY.flushBody), severity: "disruptive", confirmLabel: pick(language, COPY.flushYes) });
    if (!ok) return;
    setFlushing(true);
    try {
      await flushDnsCache();
      notify({ message: pick(language, COPY.flushed), tone: "success" });
      void reload();
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    } finally {
      setFlushing(false);
    }
  };

  if (error && !status) {
    if (helperProblem(error) === "module_missing") return <Notice tone="info">{pick(language, COPY.moduleMissing)}</Notice>;
    return <FriendlyError error={error} title={pick(language, COPY.statusFailed)} onRetry={() => void reload()} />;
  }

  const refresh = (
    <Button onClick={() => void reload()} disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} sx={{ minHeight: 44 }}>
      {c.refresh}
    </Button>
  );

  if (status && !status.installed) {
    return (
      <SectionCard title={pick(language, { fa: "وضعیت DNS", en: "DNS status" })} status={<StatusPill tone={verdict.tone} label={verdict.label} />} action={refresh}>
        <EmptyState
          icon={PlaylistAddCheckRoundedIcon}
          title={pick(language, COPY.notInstalledTitle)}
          body={pick(language, COPY.notInstalledBody)}
          action={<Button variant="contained" href="#/dns/setup" sx={{ minHeight: 44 }}>{pick(language, COPY.startSetup)}</Button>}
        />
      </SectionCard>
    );
  }

  return (
    <Stack spacing={2.5}>
      {error && status ? <FriendlyError error={error} title={pick(language, COPY.statusFailed)} onRetry={() => void reload()} severity="warning" /> : null}
      <SectionCard title={pick(language, { fa: "وضعیت DNS", en: "DNS status" })} status={<StatusPill tone={verdict.tone} label={verdict.label} />} action={refresh}>
        <Stack spacing={1.5}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>{verdict.sentence}</Typography>
          {status && status.installed && status.reachable === false ? (
            <Box>
              <Button href="#/dns/setup" sx={{ minHeight: 44 }}>{pick(language, COPY.setupLink)}</Button>
            </Box>
          ) : null}
          {status?.installed && status.reachable && status.setup_complete === false ? (
            <Notice tone="info" action={<Button color="inherit" size="small" href="#/dns/setup" sx={{ minHeight: 40 }}>{pick(language, COPY.setupLink)}</Button>}>
              {pick(language, COPY.setupUnfinished)}
            </Notice>
          ) : null}
        </Stack>
      </SectionCard>

      {engine ? (
        <StatGrid columns={isAdvanced ? 4 : 3}>
          <StatTile
            label={pick(language, COPY.qps)}
            icon={SpeedRoundedIcon}
            value={formatQps(language, engine.qps_1s)}
            caption={typeof engine.qps_1m === "number" ? say(language, COPY.qpsCaption, { value: formatQps(language, engine.qps_1m) }) : undefined}
          />
          <StatTile
            label={pick(language, COPY.hit)}
            icon={BoltRoundedIcon}
            value={hit === null ? "—" : new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US", { style: "percent", maximumFractionDigits: 0 }).format(hit / 100)}
            meter={hit}
            caption={pick(language, COPY.hitCaption)}
          />
          <StatTile
            label={pick(language, COPY.upstreamTile)}
            icon={PublicRoundedIcon}
            tone={upstreams.length === 0 ? "off" : healthy === 0 ? "error" : healthy < upstreams.length ? "warn" : "ok"}
            value={upstreams.length ? say(language, COPY.upstreamCaption, { healthy, total: upstreams.length }) : "—"}
            caption={!upstreams.length ? pick(language, COPY.noUpstreams) : healthy === upstreams.length ? pick(language, COPY.allHealthy) : say(language, COPY.someSick, { count: upstreams.length - healthy })}
          />
          {isAdvanced ? (
            <StatTile
              label={pick(language, COPY.totalQueries)}
              icon={TravelExploreRoundedIcon}
              value={number(engine.queries_total)}
              caption={typeof engine.uptime_s === "number" ? <>{pick(language, COPY.uptime)} <Duration seconds={engine.uptime_s} /></> : undefined}
            />
          ) : null}
        </StatGrid>
      ) : null}

      {engine ? (
        <SectionCard title={pick(language, COPY.upstreamsTitle)} hint={pick(language, COPY.upstreamsHint)}>
          {upstreams.length ? (
            <Stack divider={<Divider flexItem />} spacing={1}>
              {upstreams.map((item, index) => (
                <Stack key={item.id ?? `${item.address}-${index}`} direction="row" alignItems="center" justifyContent="space-between" gap={1} flexWrap="wrap" sx={{ py: 0.5 }}>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="body2" sx={{ fontWeight: 650, wordBreak: "break-all" }}><Ltr mono>{item.address}</Ltr></Typography>
                    <Typography variant="caption" color="text.secondary">{pick(language, PROTO_WORDS[upstreamProto(item.address)])}</Typography>
                  </Box>
                  <Stack direction="row" alignItems="center" gap={1}>
                    {item.healthy && typeof item.rtt_ms === "number" ? (
                      <Typography variant="caption" color="text.secondary">{say(language, COPY.rtt, { ms: Math.round(item.rtt_ms) })}</Typography>
                    ) : null}
                    <StatusPill tone={item.healthy ? "ok" : "error"} label={pick(language, item.healthy ? COPY.healthy : COPY.unhealthy)} />
                  </Stack>
                </Stack>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">{pick(language, COPY.noUpstreams)}</Typography>
          )}
        </SectionCard>
      ) : null}

      {engine ? (
        <SectionCard title={pick(language, COPY.listenersTitle)} hint={pick(language, COPY.listenersHint)}>
          {listeners.length ? (
            <Stack divider={<Divider flexItem />} spacing={1}>
              {listeners.map((item, index) => (
                <Stack key={`${item.address}-${item.proto ?? ""}-${index}`} direction="row" alignItems="center" justifyContent="space-between" gap={1} flexWrap="wrap" sx={{ py: 0.5 }}>
                  <Typography variant="body2" sx={{ fontWeight: 650 }}>
                    <Ltr mono>{item.address}</Ltr>
                    {item.proto ? <Typography component="span" variant="caption" color="text.secondary" sx={{ mx: 1 }}><Ltr>{item.proto.toUpperCase()}</Ltr></Typography> : null}
                  </Typography>
                  <StatusPill tone={item.ok === false ? "error" : "ok"} label={pick(language, item.ok === false ? COPY.notListening : COPY.listening)} />
                  {item.ok === false && item.error && isAdvanced ? (
                    <Typography variant="caption" color="text.secondary" sx={{ width: "100%" }}><Ltr mono>{item.error}</Ltr></Typography>
                  ) : null}
                </Stack>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">{pick(language, COPY.noListeners)}</Typography>
          )}
        </SectionCard>
      ) : null}

      {engine ? (
        <SectionCard advanced title={pick(language, COPY.technical)} collapsible defaultCollapsed>
          <KeyValueList
            items={[
              { label: pick(language, COPY.version), value: engine.version ?? "—", ltr: true },
              { label: pick(language, COPY.uptime), value: <Duration seconds={engine.uptime_s} /> },
              {
                label: pick(language, COPY.pressure),
                value: engine.pressure ? (
                  <StatusPill tone={PRESSURE_WORDS[engine.pressure]?.tone ?? "off"} label={PRESSURE_WORDS[engine.pressure] ? pick(language, PRESSURE_WORDS[engine.pressure].label) : engine.pressure} />
                ) : "—"
              },
              {
                label: pick(language, COPY.cacheSize),
                value: say(language, COPY.cacheSizeValue, {
                  entries: engine.cache?.entries ?? 0,
                  size: formatSize(engine.cache?.bytes ?? 0, language),
                  max: formatSize(engine.cache?.max_bytes ?? 0, language)
                })
              },
              { label: pick(language, COPY.memory), value: formatSize(engine.memory_bytes ?? null, language) },
              { label: pick(language, COPY.goroutines), value: number(engine.goroutines) },
              { label: pick(language, COPY.configVersion), value: String(engine.config_version ?? "—"), ltr: true }
            ]}
          />
        </SectionCard>
      ) : null}

      {isAdvanced && engineReady(status) ? (
        <SectionCard title={pick(language, COPY.flush)} hint={pick(language, COPY.flushHint)}>
          {canWrite ? (
            <Box>
              <Button variant="outlined" onClick={() => void flush()} disabled={flushing} startIcon={flushing ? <CircularProgress size={14} /> : <CleaningServicesRoundedIcon />} sx={{ minHeight: 44 }}>
                {pick(language, COPY.flush)}
              </Button>
            </Box>
          ) : (
            <NoAccess needs="dns:write" />
          )}
        </SectionCard>
      ) : null}
      {dialog}
      {snackbar}
    </Stack>
  );
}

function TestTab({ permissions }: { permissions: readonly string[] }) {
  const { language, isAdvanced } = useKit();
  const canTrace = hasPermission(permissions, "dns:write");
  const [trace, setTrace] = useState(false);
  const [askDo, setAskDo] = useState(true);
  const [skipCheck, setSkipCheck] = useState(false);
  const [noCache, setNoCache] = useState(false);
  const { status, error: statusError, reload } = useDnsStatus(null);
  const [name, setName] = useState("");
  const [type, setType] = useState("A");
  const [clientIp, setClientIp] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ name: string; type: string; data: ResolveResult } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const trimmed = name.trim().replace(/\.$/, "");
  const nameProblem = trimmed && !isDnsName(trimmed) && !isIPv4(trimmed) && !isIPv6(trimmed) ? pick(language, COPY.badName) : null;
  const ipProblem = clientIp.trim() && !isIPv4(clientIp.trim()) && !isIPv6(clientIp.trim()) ? pick(language, COPY.badIp) : null;
  const types = isAdvanced ? ADVANCED_QUESTIONS : SIMPLE_QUESTIONS;
  const ready = engineReady(status);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!trimmed || nameProblem || ipProblem || busy) return;
    setBusy(true);
    setError(null);
    try {
      const data = await resolveName({
        name: trimmed,
        type,
        ...(isAdvanced && clientIp.trim() ? { client_ip: clientIp.trim() } : {}),
        ...(trace && canTrace ? { trace: true } : {}),
        ...(isAdvanced && !askDo ? { dnssec: false } : {}),
        ...(isAdvanced && skipCheck ? { cd: true } : {}),
        ...(isAdvanced && noCache ? { no_cache: true } : {})
      });
      setResult({ name: trimmed, type, data: data ?? {} });
    } catch (caught) {
      setResult(null);
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  const source = result ? sourceWord(language, result.data.source) : null;
  const answers = result?.data.answers ?? [];
  const rcode = rcodeName(result?.data.rcode);
  const okRcode = rcode === "NOERROR" || rcode === "";

  return (
    <Stack spacing={2.5}>
      <DnsAvailability status={status} error={statusError} onRetry={() => void reload()} />
      <SectionCard title={pick(language, COPY.testTitle)} hint={pick(language, COPY.testHint)}>
        <Box component="form" onSubmit={(event) => void submit(event)} noValidate>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ xs: "stretch", sm: "flex-start" }}>
            <TextField
              label={pick(language, COPY.name)}
              placeholder={pick(language, COPY.namePlaceholder)}
              value={name}
              onChange={(event) => setName(event.target.value)}
              error={Boolean(nameProblem)}
              helperText={nameProblem ?? " "}
              fullWidth
              autoComplete="off"
              slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoCapitalize: "none" } }}
            />
            <TextField select label={pick(language, COPY.type)} value={types.includes(type) ? type : "A"} onChange={(event) => setType(event.target.value)} sx={{ minWidth: { sm: 200 } }} helperText=" ">
              {types.map((item) => (
                <MenuItem key={item} value={item}>
                  {QUESTION_WORDS[item] ? pick(language, QUESTION_WORDS[item]) : item}
                  {isAdvanced ? <Typography component="span" variant="caption" color="text.secondary" sx={{ mx: 1 }}><Ltr>{item}</Ltr></Typography> : null}
                </MenuItem>
              ))}
            </TextField>
            {isAdvanced ? (
              <TextField
                label={pick(language, COPY.clientIp)}
                value={clientIp}
                onChange={(event) => setClientIp(event.target.value)}
                error={Boolean(ipProblem)}
                helperText={ipProblem ?? pick(language, COPY.clientIpHint)}
                fullWidth
                slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
              />
            ) : null}
            <Button
              type="submit"
              variant="contained"
              disabled={!trimmed || Boolean(nameProblem) || Boolean(ipProblem) || busy || !ready}
              startIcon={busy ? <CircularProgress size={16} color="inherit" /> : <SearchRoundedIcon />}
              sx={{ minHeight: 56, minWidth: 120, flexShrink: 0 }}
            >
              {pick(language, busy ? COPY.asking : COPY.ask)}
            </Button>
          </Stack>
          {!ready && status ? <Typography variant="caption" color="text.secondary">{pick(language, COPY.notReady)}</Typography> : null}
          <Stack direction={{ xs: "column", md: "row" }} columnGap={2} sx={{ mt: 0.5 }}>
            <Box>
              <FormControlLabel control={<Checkbox checked={trace && canTrace} disabled={!canTrace} onChange={(event) => setTrace(event.target.checked)} />} label={pick(language, COPY.trace)} />
              <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: -0.5, mx: 4 }}>{pick(language, canTrace ? COPY.traceHint : COPY.traceNeedsWrite)}</Typography>
            </Box>
            {isAdvanced ? (
              <>
                <FormControlLabel control={<Checkbox checked={askDo} onChange={(event) => setAskDo(event.target.checked)} />} label={pick(language, COPY.askSignatures)} />
                <FormControlLabel control={<Checkbox checked={skipCheck} onChange={(event) => setSkipCheck(event.target.checked)} />} label={pick(language, COPY.skipCheck)} />
                <FormControlLabel control={<Checkbox checked={noCache} onChange={(event) => setNoCache(event.target.checked)} />} label={pick(language, COPY.noCache)} />
              </>
            ) : null}
          </Stack>
        </Box>
      </SectionCard>

      {error ? <FriendlyError error={error} title={pick(language, COPY.testFailed)} onRetry={() => setError(null)} /> : null}

      {result && source ? (
        <SectionCard
          title={pick(language, COPY.result)}
          status={<StatusPill tone={okRcode ? (answers.length ? "ok" : "warn") : rcode === "REFUSED" ? "warn" : "error"} label={rcodeWord(language, result.data.rcode ?? "NOERROR")} />}
        >
          <Stack spacing={2}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <Ltr mono>{result.name}</Ltr>
              {" · "}
              <StatusPill tone={source.tone} label={source.label} />
              {typeof result.data.rtt_ms === "number" ? <>{" · "}{say(language, COPY.took, { ms: formatQps(language, result.data.rtt_ms) })}</> : null}
            </Typography>
            {source.body ? <Typography variant="body2" color="text.secondary">{source.body}</Typography> : null}
            <DnssecBadge dnssec={result.data.dnssec} ede={result.data.ede} />
            {answers.length ? (
              <Stack divider={<Divider flexItem />} spacing={1}>
                {answers.map((answer, index) => (
                  <Stack key={`${answer.type}-${index}`} direction="row" gap={1.5} flexWrap="wrap" alignItems="baseline">
                    <Typography variant="body2" sx={{ fontWeight: 700, minWidth: 64 }}>
                      {QUESTION_WORDS[answer.type] && !isAdvanced ? pick(language, QUESTION_WORDS[answer.type]) : <Ltr>{answer.type}</Ltr>}
                    </Typography>
                    <Typography variant="body2" sx={{ flex: 1, minWidth: 0, wordBreak: "break-all" }}><Ltr mono>{answerValue(answer)}</Ltr></Typography>
                    {typeof answer.ttl === "number" ? (
                      <Typography variant="caption" color="text.secondary">{pick(language, COPY.keepsFor)} <Duration seconds={answer.ttl} /></Typography>
                    ) : null}
                    {isAdvanced && answer.name && answer.name.replace(/\.$/, "") !== result.name ? (
                      <Typography variant="caption" color="text.secondary" sx={{ width: "100%" }}><Ltr mono>{answer.name}</Ltr></Typography>
                    ) : null}
                  </Stack>
                ))}
              </Stack>
            ) : (
              <Typography variant="body2" color="text.secondary">{pick(language, COPY.noAnswers)}</Typography>
            )}
            {isAdvanced ? (
              <KeyValueList
                dense
                items={[
                  { label: pick(language, COPY.rcode), value: rcode || "NOERROR", ltr: true },
                  ...(result.data.upstream ? [{ label: pick(language, COPY.upstreamUsed), value: result.data.upstream, ltr: true }] : [])
                ]}
              />
            ) : null}
          </Stack>
        </SectionCard>
      ) : null}

      {result && Array.isArray(result.data.trace) ? (
        <SectionCard title={pick(language, TRACE_COPY.traceTitle)} hint={pick(language, TRACE_COPY.traceHint)}
          status={<StatusPill tone="info" label={say(language, TRACE_COPY.steps, { count: result.data.trace.length })} />}>
          <TraceView steps={result.data.trace} forwardMode={result.data.source !== "recursive" && result.data.trace.every((step) => (step.zone ?? ".") === "." || step.server === "validator")} />
        </SectionCard>
      ) : null}
    </Stack>
  );
}

export default function DnsPage(props: GroupPageProps) {
  const permissions = props.user?.permissions ?? props.permissions ?? [];
  const { language } = useKit();
  const { definition, current } = useVisibleTab("dns", permissions);
  const title = pick(language, COPY.title);

  if (!current) {
    return (
      <>
        <PageHeader title={title} icon={TravelExploreRoundedIcon} />
        <NoAccess needs="dns:read" variant="card" />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title={title}
        subtitle={pick(language, current.hint)}
        icon={definition?.icon ?? TravelExploreRoundedIcon}
        tabs={<GroupTabs group="dns" permissions={permissions} value={current.key} />}
      />
      <TabPanel group="dns" tab={current.key}>
        <TabBody>
          {current.key === "status" && <StatusTab permissions={permissions} />}
          {current.key === "monitor" && <DnsMonitorTab permissions={permissions} />}
          {current.key === "logs" && <DnsLogsTab permissions={permissions} />}
          {current.key === "setup" && <DnsSetupTab permissions={permissions} />}
          {current.key === "names" && <DnsNamesTab permissions={permissions} />}
          {current.key === "templates" && <DnsTemplatesTab permissions={permissions} />}
          {current.key === "blocking" && <DnsFilteringTab permissions={permissions} />}
          {current.key === "test" && <TestTab permissions={permissions} />}
          {current.key === "encrypted" && <DnsEncryptedTab permissions={permissions} />}
          {current.key === "settings" && <DnsSettingsTab permissions={permissions} />}
        </TabBody>
      </TabPanel>
    </>
  );
}
