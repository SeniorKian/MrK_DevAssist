/**
 * «DNS › تنظیمات» (Advanced, dns:admin; contract docs/37 §2 `GET/PUT /v1/settings`).
 * Every engine setting: listen addresses, who may ask, recursion, outside DNS servers (with ready
 * presets), cache, limits and protections. The whole object is saved with its `config_version`;
 * a 409 `dns_config_conflict` asks the user to load the latest version instead of overwriting it.
 *
 * D4 (docs/40 §6): the «روش پیدا کردن نشانی‌ها» and «امضای امنیتی» cards edit the `resolution` and
 * `dnssec` sections of the same draft. They are the only cards in Simple mode; Advanced shows all.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Box, Button, Checkbox, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Divider, FormControlLabel, IconButton,
  MenuItem, Paper, Stack, Switch, TextField, Tooltip, Typography, useMediaQuery, useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import ArrowUpwardRoundedIcon from "@mui/icons-material/ArrowUpwardRounded";
import ArrowDownwardRoundedIcon from "@mui/icons-material/ArrowDownwardRounded";
import CleaningServicesRoundedIcon from "@mui/icons-material/CleaningServicesRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import PublicRoundedIcon from "@mui/icons-material/PublicRounded";
import { ApiError, hasPermission, isAbortError } from "./api";
import { withDefaults } from "./dnsLive";
import { DEFAULT_DNSSEC, DEFAULT_RESOLUTION, warningsOf, type DnsD4Status, type DnssecSettings, type ResolutionSettings, type SettingsWarning } from "./dnsSecure";
import { DnsBackupCard } from "./DnsBackup";
import { DnssecCard, ResolutionCard, SaveWarnings, cleanSecuritySections, validateDnssec, validateResolution } from "./DnsSecuritySettings";
import { errorSentence, pick, say, type Bi } from "./copy";
import {
  BytesInput, ChoiceCards, DurationInput, FriendlyError, ListInput, Ltr, NoAccess, Notice, NumberInput, SectionCard, helperProblem,
  formatRelative, useConfirmAction, useKit, useUndoSnackbar
} from "./kit";
import {
  PROTO_WORDS, STRATEGY_WORDS, UPSTREAM_PRESETS, buildUpstreamAddress, dnsFieldMessages, fetchDnsIntegration, useDnsStatus, fetchDnsSettings, flushDnsCache, isCidr, isDnsName,
  isIPv4, isIPv6, isListenAddress, presetFor, saveDnsIntegration, saveDnsSettings, type DnsIntegration, type DnsIntegrationSettings, upstreamAddressProblem, upstreamProto, type DnsSettings, type DnsUpstream, type UpstreamProto, type UpstreamStrategy
} from "./dns";

const COPY = {
  loadFailed: { fa: "تنظیمات DNS خوانده نشد.", en: "The DNS settings didn't load." },
  moduleMissing: { fa: "بخش DNS روی نسخه فعلی سرور نیست. DevAssist را به‌روز کنید.", en: "DNS isn't on your server's current version. Update DevAssist." },
  // listen
  listenTitle: { fa: "نشانی‌هایی که DNS روی آن‌ها جواب می‌دهد", en: "Addresses DNS answers on" },
  listenHint: {
    fa: "پیش‌فرض: خود سرور (127.0.0.1) و شبکه Docker (172.17.0.1). نشانی عمومی سرور را فقط وقتی بگذارید که واقعاً لازم است.",
    en: "Default: the server itself (127.0.0.1) and the Docker network (172.17.0.1). Add the server's public address only if you really need it."
  },
  listenAddress: { fa: "نشانی و پورت", en: "Address and port" },
  badListen: { fa: "مثل 127.0.0.1:53 یا [::1]:53 بنویسید.", en: "Write it like 127.0.0.1:53 or [::1]:53." },
  addListen: { fa: "افزودن نشانی", en: "Add an address" },
  listenNeeded: { fa: "دست‌کم یک نشانی لازم است.", en: "At least one address is needed." },
  protoNeeded: { fa: "دست‌کم یکی از UDP یا TCP را روشن بگذارید.", en: "Keep at least one of UDP or TCP on." },
  remove: { fa: "برداشتن", en: "Remove" },
  // access
  accessTitle: { fa: "چه کسی می‌تواند بپرسد", en: "Who may ask" },
  accessHint: { fa: "فقط دستگاه‌های این محدوده‌ها جواب می‌گیرند؛ بقیه بی‌جواب می‌مانند.", en: "Only devices in these ranges get answers; everyone else is refused." },
  queryAllow: { fa: "محدوده‌هایی که اجازه پرسیدن دارند", en: "Ranges allowed to ask" },
  rangeHint: { fa: "مثل 192.168.0.0/16 یا 10.0.0.0/8", en: "Like 192.168.0.0/16 or 10.0.0.0/8" },
  badRange: { fa: "محدوده را مثل 192.168.0.0/16 بنویسید.", en: "Write the range like 192.168.0.0/16." },
  recursion: { fa: "پرسیدن از اینترنت برای نام‌های ناشناخته", en: "Ask the internet for unknown names" },
  recursionHint: { fa: "اگر خاموش باشد، DevAssist فقط نام‌ها و دامنه‌های خودتان را جواب می‌دهد.", en: "When off, DevAssist only answers your own names and domains." },
  recursionAllow: { fa: "محدوده‌هایی که می‌توانند از اینترنت بپرسند", en: "Ranges that may ask the internet" },
  openResolver: {
    fa: "خطرناک: «همه نشانی‌ها» اجازه گرفته‌اند. هر کسی در اینترنت می‌تواند از سرور شما برای حمله استفاده کند. فقط شبکه‌های خودتان را بگذارید.",
    en: "Dangerous: every address is allowed. Anyone on the internet could use your server for attacks. List only your own networks."
  },
  publicQueries: {
    fa: "پرسش عمومی روشن است؛ همه می‌توانند رکوردهای دامنه‌های شما را بپرسند، اما پرسیدن نام‌های ناشناخته همچنان فقط برای شبکه‌های مجاز است.",
    en: "Public queries are on: everyone may ask for your domain records, while recursion for unknown names remains limited to the allowed networks."
  },
  // upstreams
  upstreamTitle: { fa: "DNS‌های بیرونی", en: "Outside DNS servers" },
  upstreamHint: { fa: "نام‌هایی که DevAssist خودش نمی‌داند از این‌ها پرسیده می‌شود. رمزدارها جلوی شنود و دست‌کاری را می‌گیرند.", en: "Names DevAssist doesn't know are asked here. Encrypted ones stop snooping and tampering." },
  noUpstreams: { fa: "هنوز هیچ DNS بیرونی ندارید؛ نام‌های اینترنتی جواب نمی‌گیرند.", en: "No outside DNS yet; internet names won't get answers." },
  addUpstream: { fa: "افزودن DNS بیرونی", en: "Add an outside DNS" },
  strategy: { fa: "از کدام بپرسد؟", en: "Which one to ask?" },
  moveUp: { fa: "بالاتر", en: "Move up" },
  moveDown: { fa: "پایین‌تر", en: "Move down" },
  presetsTitle: { fa: "آماده‌ها", en: "Ready-made" },
  presetsHint: { fa: "روی یکی بزنید تا نشانی‌هایش اضافه شود.", en: "Tap one to add its addresses." },
  iranBadge: { fa: "ایرانی", en: "Iranian" },
  encryptedBadge: { fa: "رمزدار", en: "Encrypted" },
  added: { fa: "اضافه شد", en: "Added" },
  custom: { fa: "یا نشانی دلخواه", en: "Or your own address" },
  protocol: { fa: "نوع اتصال", en: "Connection" },
  host: { fa: "نشانی", en: "Address" },
  hostHintUdp: { fa: "مثل 1.1.1.1 یا 1.1.1.1:53", en: "Like 1.1.1.1 or 1.1.1.1:53" },
  hostHintDot: { fa: "مثل 1.1.1.1 یا 1.1.1.1:853", en: "Like 1.1.1.1 or 1.1.1.1:853" },
  hostHintDoh: { fa: "مثل https://dns.google/dns-query", en: "Like https://dns.google/dns-query" },
  tlsName: { fa: "نام گواهی سرور", en: "Server certificate name" },
  tlsNameHint: { fa: "مثل cloudflare-dns.com؛ برای بررسی این‌که واقعاً همان سرور است.", en: "Like cloudflare-dns.com; checks that it really is that server." },
  addThis: { fa: "افزودن", en: "Add" },
  duplicate: { fa: "این نشانی قبلاً اضافه شده است.", en: "This address is already in the list." },
  // cache
  cacheTitle: { fa: "حافظه جواب‌ها", en: "Answer memory" },
  cacheHint: { fa: "DevAssist جواب‌ها را مدتی نگه می‌دارد تا پرسش بعدی فوری جواب بگیرد.", en: "DevAssist keeps answers for a while so the next question is answered instantly." },
  maxBytes: { fa: "بیشترین حجم", en: "Largest size" },
  minTtl: { fa: "کمترین زمان نگه‌داری", en: "Shortest time to keep" },
  maxTtl: { fa: "بیشترین زمان نگه‌داری", en: "Longest time to keep" },
  negTtl: { fa: "نگه‌داری جواب «چنین نامی نیست»", en: "Keep “no such name” answers for" },
  serveStale: { fa: "اگر اینترنت قطع شد، جواب قدیمی بده", en: "Give the old answer if the internet is down" },
  serveStaleHint: { fa: "بهتر از هیچ جوابی است؛ برنامه‌ها کار می‌کنند تا اینترنت برگردد.", en: "Better than no answer; apps keep working until the internet is back." },
  staleTtl: { fa: "جواب قدیمی تا چه مدت", en: "Old answers for up to" },
  prefetch: { fa: "نام‌های پرکاربرد را پیش از تمام شدن، تازه کن", en: "Refresh popular names before they expire" },
  prefetchHint: { fa: "تا پرسش‌های پرتکرار هیچ‌وقت منتظر اینترنت نمانند.", en: "So frequent questions never wait for the internet." },
  ttlOrder: { fa: "کمترین زمان باید از بیشترین کمتر باشد.", en: "The shortest time must be less than the longest." },
  flush: { fa: "پاک کردن جواب‌های ذخیره‌شده", en: "Clear stored answers" },
  flushName: { fa: "فقط برای این نام (اختیاری)", en: "Only for this name (optional)" },
  flushTitleAll: { fa: "همه جواب‌های ذخیره‌شده پاک شود؟", en: "Clear all stored answers?" },
  flushTitleOne: { fa: "جواب‌های ذخیره‌شده «{name}» پاک شود؟", en: "Clear stored answers for “{name}”?" },
  flushBody: { fa: "چند ثانیه پرسش‌ها کمی کندتر می‌شوند. چیزی از دست نمی‌رود.", en: "Questions get a little slower for a few seconds. Nothing is lost." },
  flushYes: { fa: "بله، پاک کن", en: "Yes, clear" },
  flushed: { fa: "جواب‌های ذخیره‌شده پاک شد.", en: "Stored answers were cleared." },
  badFlushName: { fa: "نام را مثل google.com بنویسید.", en: "Write the name like google.com." },
  // limits
  limitsTitle: { fa: "سقف‌ها و محافظت در برابر حمله", en: "Limits and attack protection" },
  limitsHint: { fa: "تا اگر یک دستگاه یا حمله زیاد پرسید، بقیه سالم بمانند. پیش‌فرض‌ها برای بیشتر سرورها خوب‌اند.", en: "So one device or an attack can't hurt everyone else. The defaults suit most servers." },
  clientQps: { fa: "پرسش در ثانیه برای هر دستگاه", en: "Questions per second per device" },
  clientBurst: { fa: "اوج مجاز کوتاه‌مدت هر دستگاه", en: "Short burst allowed per device" },
  rrl: { fa: "جواب یکسان در ثانیه به یک شبکه", en: "Same answer per second to one network" },
  rrlHint: { fa: "جلوی استفاده از سرور برای حمله به دیگران را می‌گیرد.", en: "Stops attackers from using your server against others." },
  rrlSlip: { fa: "از هر چند جواب ردشده یکی کوتاه برود", en: "Send one short reply per this many refused" },
  rrlV4: { fa: "اندازه شبکه IPv4 برای شمارش", en: "IPv4 network size for counting" },
  rrlV6: { fa: "اندازه شبکه IPv6 برای شمارش", en: "IPv6 network size for counting" },
  maxTcp: { fa: "بیشترین اتصال TCP هم‌زمان", en: "Most TCP connections at once" },
  tcpIdle: { fa: "بستن اتصال TCP بی‌کار پس از", en: "Close an idle TCP connection after" },
  ms: { fa: "میلی‌ثانیه", en: "ms" },
  udpSize: { fa: "بزرگ‌ترین جواب UDP", en: "Largest UDP answer" },
  bytes: { fa: "بایت", en: "bytes" },
  inflight: { fa: "بیشترین پرسش هم‌زمان به DNS‌های بیرونی", en: "Most questions to outside DNS at once" },
  perSecond: { fa: "در ثانیه", en: "per second" },
  minimalAny: { fa: "به پرسش «همه‌چیز» جواب کوتاه بده", en: "Answer “everything” questions briefly" },
  minimalAnyHint: { fa: "این پرسش‌ها بیشتر برای حمله استفاده می‌شوند.", en: "These questions are mostly used in attacks." },
  refuseAny: { fa: "پرسش «همه‌چیز» را کلاً رد کن", en: "Refuse “everything” questions entirely" },
  rebinding: { fa: "محافظت در برابر فریب شبکه داخلی", en: "Protect against internal-network tricks" },
  rebindingHint: { fa: "اگر سایتی بیرونی نشانی شبکه داخلی را برگرداند، آن جواب حذف می‌شود.", en: "If an outside site answers with an internal-network address, that answer is dropped." },
  overrides: { fa: "«نام‌های من» جواب داده شود", en: "Answer “My names”" },
  overridesHint: { fa: "اگر خاموش شود، نام‌هایی که در «نام‌ها» ساخته‌اید موقتاً جواب داده نمی‌شوند.", en: "When off, the names you made under Names aren't answered for now." },
  // save
  changes: { fa: "{count} تغییر ذخیره نشده", en: "{count} unsaved changes" },
  discard: { fa: "دور انداختن تغییرات", en: "Discard changes" },
  save: { fa: "ذخیره تنظیمات", en: "Save settings" },
  saving: { fa: "در حال ذخیره…", en: "Saving…" },
  saved: { fa: "تنظیمات DNS ذخیره شد و همین حالا اعمال شد.", en: "The DNS settings were saved and applied right away." },
  fixFirst: { fa: "اول خانه‌های قرمز را درست کنید.", en: "Fix the fields in red first." },
  conflict: { fa: "کس دیگری هم‌زمان این تنظیمات را تغییر داد. آخرین نسخه را بگیرید و تغییرتان را دوباره بزنید.", en: "Someone else changed these settings at the same time. Load the latest version and make your change again." },
  loadLatest: { fa: "گرفتن آخرین نسخه", en: "Load the latest version" },
  saveTitle: { fa: "تنظیمات DNS ذخیره شود؟", en: "Save the DNS settings?" },
  saveDanger: { fa: "این تغییر ممکن است جواب‌دادن DNS را برای بعضی دستگاه‌ها قطع کند. مطمئنید؟", en: "This change may stop DNS answering some devices. Are you sure?" },
  saveYes: { fa: "بله، ذخیره کن", en: "Yes, save" },
  version: { fa: "نسخه تنظیمات", en: "Settings version" },
  moreInAdvanced: { fa: "تنظیمات بیشتر (نشانی‌ها، DNS‌های بیرونی، حافظه، سقف‌ها) در حالت «پیشرفته» است.", en: "More settings (addresses, outside DNS servers, memory, limits) are in Advanced mode." },
  d4Missing: { fa: "برنامه DNS روی سرور هنوز «روش پیدا کردن نشانی‌ها» و «امضای امنیتی» را ندارد. آن را به‌روز کنید.", en: "The DNS program on the server doesn't have “How addresses are found” and “Security signatures” yet. Update it." },
  dnssecOffBody: { fa: "با خاموش کردن بررسی امضا، DevAssist جواب‌های جعلی را تشخیص نمی‌دهد. مطمئنید؟", en: "With signature checks off, DevAssist won't notice fake answers. Are you sure?" }
} satisfies Record<string, Bi>;

const OPEN_RANGES = new Set(["0.0.0.0/0", "::/0"]);

const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/** Fill missing keys of the D4 sections (only when the engine sent them) and drop a stray `warnings`. */
function normalize(settings: DnsSettings): DnsSettings {
  const next = clone(settings);
  delete next.warnings;
  if (next.resolution && typeof next.resolution === "object") next.resolution = withDefaults(next.resolution, DEFAULT_RESOLUTION);
  if (next.dnssec && typeof next.dnssec === "object") next.dnssec = withDefaults(next.dnssec, DEFAULT_DNSSEC);
  return next;
}

/** Paths that differ (`cache.max_ttl`, `upstreams`), for the «n تغییر» counter. */
function changedPaths(a: unknown, b: unknown, prefix = ""): string[] {
  if (Array.isArray(a) || Array.isArray(b) || typeof a !== "object" || typeof b !== "object" || a === null || b === null) {
    return JSON.stringify(a) === JSON.stringify(b) ? [] : [prefix || "root"];
  }
  const keys = new Set([...Object.keys(a as object), ...Object.keys(b as object)]);
  keys.delete("config_version");
  return [...keys].flatMap((key) => changedPaths((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key], prefix ? `${prefix}.${key}` : key));
}

function Row({ children }: { children: ReactNode }) {
  return <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" } }}>{children}</Box>;
}

function SwitchRow({ label, hint, checked, onChange, tone }: { label: string; hint?: string; checked: boolean; onChange: (value: boolean) => void; tone?: "warning" }) {
  return (
    <Box>
      <FormControlLabel control={<Switch checked={checked} color={tone ?? "primary"} onChange={(event) => onChange(event.target.checked)} />} label={label} />
      {hint ? <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: -0.5, mx: 6 }}>{hint}</Typography> : null}
    </Box>
  );
}

function newUpstreamId(address: string, existing: DnsUpstream[]): string {
  const base = (presetFor(address)?.key ?? "upstream").replace(/[^a-z0-9]/gi, "");
  let index = existing.length + 1;
  const ids = new Set(existing.map((item) => item.id));
  while (ids.has(`${base}-${index}`)) index += 1;
  return `${base}-${index}`;
}

function AddUpstreamDialog({ existing, onAdd, onClose }: { existing: DnsUpstream[]; onAdd: (addresses: string[]) => void; onClose: () => void }) {
  const { language, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [proto, setProto] = useState<UpstreamProto>("dot");
  const [host, setHost] = useState("");
  const [tlsName, setTlsName] = useState("");
  const have = new Set(existing.map((item) => item.address));
  const address = host.trim() ? buildUpstreamAddress(proto, host, tlsName) : "";
  const problem = address ? (have.has(address) ? pick(language, COPY.duplicate) : upstreamAddressProblem(language, address)) : null;
  const hostHint = proto === "doh" ? COPY.hostHintDoh : proto === "dot" || proto === "doq" ? COPY.hostHintDot : COPY.hostHintUdp;

  return (
    <Dialog open onClose={onClose} fullScreen={fullScreen} fullWidth maxWidth="sm">
      <DialogTitle sx={{ fontWeight: 760 }}>{pick(language, COPY.addUpstream)}</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.presetsTitle)}</Typography>
            <Typography variant="caption" color="text.secondary">{pick(language, COPY.presetsHint)}</Typography>
          </Box>
          <Box sx={{ display: "grid", gap: 1, gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" } }}>
            {UPSTREAM_PRESETS.map((preset) => {
              const missing = preset.addresses.filter((item) => !have.has(item));
              const encrypted = preset.addresses.some((item) => upstreamProto(item) !== "udp");
              return (
                <Paper
                  key={preset.key}
                  variant="outlined"
                  component="button"
                  type="button"
                  disabled={!missing.length}
                  onClick={() => onAdd(missing)}
                  sx={{
                    textAlign: "start", p: 1.5, cursor: missing.length ? "pointer" : "default", bgcolor: "background.paper", color: "text.primary",
                    font: "inherit", opacity: missing.length ? 1 : 0.6, minHeight: 72, "&:hover": missing.length ? { borderColor: "primary.main" } : undefined
                  }}
                >
                  <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap">
                    {encrypted ? <LockRoundedIcon fontSize="small" color="success" aria-hidden /> : <PublicRoundedIcon fontSize="small" color="action" aria-hidden />}
                    <Typography variant="body2" sx={{ fontWeight: 720 }}>{pick(language, preset.name)}</Typography>
                    {preset.iran ? <Chip size="small" label={pick(language, COPY.iranBadge)} /> : null}
                    {encrypted ? <Chip size="small" color="success" variant="outlined" label={pick(language, COPY.encryptedBadge)} /> : null}
                    {!missing.length ? <Chip size="small" label={pick(language, COPY.added)} /> : null}
                  </Stack>
                  <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 0.5 }}>{pick(language, preset.hint)}</Typography>
                </Paper>
              );
            })}
          </Box>
          <Divider />
          <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.custom)}</Typography>
          <TextField select label={pick(language, COPY.protocol)} value={proto} onChange={(event) => setProto(event.target.value as UpstreamProto)} fullWidth>
            {(["dot", "doh", "doq", "udp"] as UpstreamProto[]).map((key) => (
              <MenuItem key={key} value={key}>{pick(language, PROTO_WORDS[key])}</MenuItem>
            ))}
          </TextField>
          <TextField
            label={pick(language, COPY.host)}
            value={host}
            onChange={(event) => setHost(event.target.value)}
            error={Boolean(problem)}
            helperText={problem ?? pick(language, hostHint)}
            fullWidth
            slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoCapitalize: "none" } }}
          />
          {proto === "dot" || proto === "doq" ? (
            <TextField
              label={pick(language, COPY.tlsName)}
              value={tlsName}
              onChange={(event) => setTlsName(event.target.value)}
              helperText={pick(language, COPY.tlsNameHint)}
              fullWidth
              slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoCapitalize: "none" } }}
            />
          ) : null}
          {address && !problem ? <Typography variant="caption" color="text.secondary"><Ltr mono>{address}</Ltr></Typography> : null}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
        <Button onClick={onClose} sx={{ minHeight: 44 }}>{c.cancel}</Button>
        <Button variant="contained" disabled={!address || Boolean(problem)} onClick={() => onAdd([address])} sx={{ minHeight: 44 }}>{pick(language, COPY.addThis)}</Button>
      </DialogActions>
    </Dialog>
  );
}

const INTEGRATION_COPY = {
  title: { fa: "هماهنگی با «سرویس‌های من»", en: "Working with My services" },
  hint: {
    fa: "دامنه‌های سرویس‌ها می‌توانند خودکار به نشانی داخلی سرور جواب داده شوند تا کانتینرها مستقیم به سرور برسند.",
    en: "Your services' domains can be answered with the server's internal address, so containers reach the server directly."
  },
  servicesOverrides: { fa: "دامنه‌های «سرویس‌های من» را خودکار به نشانی داخلی سرور بفرست", en: "Send My services domains to the server's internal address" },
  servicesOverridesHint: { fa: "این نام‌ها در «نام‌ها» با برچسب «از سرویس‌های من» دیده می‌شوند.", en: "These names show under Names, marked “From My services”." },
  target: { fa: "نشانی داخلی سرور (اختیاری)", en: "Server's internal address (optional)" },
  targetHint: { fa: "خالی بماند تا DevAssist خودش پیدا کند؛ الان: {target}", en: "Leave empty to let DevAssist find it; now: {target}" },
  badTarget: { fa: "یک نشانی IP مثل 172.17.0.1 بنویسید.", en: "Write an IP address like 172.17.0.1." },
  internalZone: { fa: "نام‌های داخلی DevAssist را بساز", en: "Make DevAssist's internal names" },
  internalZoneHint: { fa: "مثل {names}", en: "Like {names}" },
  fallback: { fa: "DNS پشتیبان در دستورهای راه‌اندازی", en: "Backup DNS in the setup commands" },
  fallbackHint: { fa: "اگر DevAssist افتاد، سرور از این‌ها می‌پرسد. مثل 1.1.1.1", en: "If DevAssist goes down, the server asks these. Like 1.1.1.1" },
  save: { fa: "ذخیره هماهنگی", en: "Save" },
  saved: { fa: "هماهنگی با «سرویس‌های من» ذخیره شد.", en: "Saved." },
  lastSync: { fa: "آخرین هماهنگی: {when} — {created} تازه، {updated} تغییر، {deleted} برداشته", en: "Last sync: {when} — {created} added, {updated} changed, {deleted} removed" },
  syncFailed: { fa: "آخرین هماهنگی انجام نشد: {reason}", en: "The last sync failed: {reason}" },
  loadFailed: { fa: "تنظیم هماهنگی خوانده نشد.", en: "The sync setting didn't load." }
} satisfies Record<string, Bi>;

function IntegrationCard() {
  const { language } = useKit();
  const [data, setData] = useState<DnsIntegration | null>(null);
  const [draft, setDraft] = useState<DnsIntegrationSettings | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const { notify, snackbar } = useUndoSnackbar();

  const load = useCallback(async () => {
    try {
      const result = await fetchDnsIntegration();
      setData(result);
      setDraft(result?.settings ? clone(result.settings) : null);
      setError(null);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 404) return;
      setError(caught);
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  if (error && !data) return <FriendlyError error={error} title={pick(language, INTEGRATION_COPY.loadFailed)} onRetry={() => void load()} severity="warning" />;
  if (!data || !draft) return null;
  const targetProblem = draft.services_override_target.trim() && !isIPv4(draft.services_override_target.trim()) && !isIPv6(draft.services_override_target.trim())
    ? pick(language, INTEGRATION_COPY.badTarget)
    : null;
  const dirty = JSON.stringify(draft) !== JSON.stringify(data.settings);
  const sync = data.last_sync;
  const names = (data.internal_names ?? []).slice(0, 3).join(language === "fa" ? "، " : ", ");

  const save = async () => {
    setBusy(true);
    try {
      const result = await saveDnsIntegration({ ...draft, services_override_target: draft.services_override_target.trim() });
      if (result?.settings) {
        setData(result);
        setDraft(clone(result.settings));
      } else {
        await load();
      }
      notify({ message: pick(language, INTEGRATION_COPY.saved), tone: "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard title={pick(language, INTEGRATION_COPY.title)} hint={pick(language, INTEGRATION_COPY.hint)}>
      <Stack spacing={2}>
        <SwitchRow
          label={pick(language, INTEGRATION_COPY.servicesOverrides)}
          hint={pick(language, INTEGRATION_COPY.servicesOverridesHint)}
          checked={draft.services_overrides}
          onChange={(value) => setDraft({ ...draft, services_overrides: value })}
        />
        <TextField
          label={pick(language, INTEGRATION_COPY.target)}
          value={draft.services_override_target}
          onChange={(event) => setDraft({ ...draft, services_override_target: event.target.value })}
          error={Boolean(targetProblem)}
          helperText={targetProblem ?? say(language, INTEGRATION_COPY.targetHint, { target: data.effective_target || "—" })}
          size="small"
          slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
        />
        <SwitchRow
          label={pick(language, INTEGRATION_COPY.internalZone)}
          hint={names ? say(language, INTEGRATION_COPY.internalZoneHint, { names }) : undefined}
          checked={draft.internal_zone_enabled}
          onChange={(value) => setDraft({ ...draft, internal_zone_enabled: value })}
        />
        <ListInput
          label={pick(language, INTEGRATION_COPY.fallback)}
          value={draft.fallback_servers ?? []}
          onChange={(value) => setDraft({ ...draft, fallback_servers: value })}
          validate={(item) => (isIPv4(item) || isIPv6(item) ? null : pick(language, INTEGRATION_COPY.badTarget))}
          helperText={pick(language, INTEGRATION_COPY.fallbackHint)}
          max={4}
        />
        {sync?.at ? (
          sync.error_code ? (
            <Notice tone="warning">{say(language, INTEGRATION_COPY.syncFailed, { reason: errorSentence(language, { name: "ApiError", status: 0, code: sync.error_code, detail: "" }, "dns") })}</Notice>
          ) : (
            <Typography variant="caption" color="text.secondary">
              {say(language, INTEGRATION_COPY.lastSync, {
                when: formatRelative(sync.at * 1000, language),
                created: sync.created ?? 0,
                updated: sync.updated ?? 0,
                deleted: sync.deleted ?? 0
              })}
            </Typography>
          )
        ) : null}
        <Box>
          <Button variant="contained" disabled={!dirty || busy || Boolean(targetProblem)} onClick={() => void save()} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
            {pick(language, INTEGRATION_COPY.save)}
          </Button>
        </Box>
      </Stack>
      {snackbar}
    </SectionCard>
  );
}

export default function DnsSettingsTab({ permissions }: { permissions: readonly string[] }) {
  const { language, isAdvanced } = useKit();
  const { status } = useDnsStatus(30_000);
  const [warnings, setWarnings] = useState<SettingsWarning[]>([]);
  const canAdmin = hasPermission(permissions, "dns:admin");
  const [saved, setSaved] = useState<DnsSettings | null>(null);
  const [draft, setDraft] = useState<DnsSettings | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [conflict, setConflict] = useState(false);
  const [saving, setSaving] = useState(false);
  const [adding, setAdding] = useState<number | null>(null);
  const [flushName, setFlushName] = useState("");
  const [flushing, setFlushing] = useState(false);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      const data = normalize(await fetchDnsSettings(current.signal));
      setSaved(clone(data));
      setDraft(clone(data));
      setError(null);
      setConflict(false);
      setSaveError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    }
  }, []);

  useEffect(() => {
    if (canAdmin) void load();
    return () => controller.current?.abort();
  }, [load, canAdmin]);

  const changes = useMemo(() => (saved && draft ? changedPaths(saved, draft) : []), [saved, draft]);

  const update = (mutate: (next: DnsSettings) => void) => {
    setDraft((current) => {
      if (!current) return current;
      const next = clone(current);
      mutate(next);
      return next;
    });
  };

  const problems = useMemo(() => {
    const result: Record<string, string> = {};
    if (!draft) return result;
    if (!draft.listen?.length) result.listen = pick(language, COPY.listenNeeded);
    draft.listen?.forEach((item, index) => {
      if (!isListenAddress(item.address)) result[`listen.${index}`] = pick(language, COPY.badListen);
      else if (!item.udp && !item.tcp) result[`listen.${index}`] = pick(language, COPY.protoNeeded);
    });
    if (draft.cache && draft.cache.min_ttl > draft.cache.max_ttl) result.ttl = pick(language, COPY.ttlOrder);
    Object.assign(result, validateResolution(language, draft.resolution as ResolutionSettings | undefined), validateDnssec(language, draft.dnssec as DnssecSettings | undefined));
    return result;
  }, [draft, language]);
  const invalid = Object.keys(problems).length > 0;
  const openResolver = Boolean(draft?.recursion?.enabled && draft.recursion.allow?.some((item) => OPEN_RANGES.has(item.trim())));
  const openQuery = Boolean(draft?.query_allow?.some((item) => OPEN_RANGES.has(item.trim())));

  const save = async () => {
    if (!draft || invalid || !changes.length) return;
    const risky = openResolver || changes.some((path) => path.startsWith("listen") || path.startsWith("query_allow") || path.startsWith("recursion"));
    const dnssecOff = (draft.dnssec as DnssecSettings | undefined)?.mode === "off" && (saved?.dnssec as DnssecSettings | undefined)?.mode !== "off";
    if (risky || dnssecOff) {
      const ok = await ask({
        title: pick(language, COPY.saveTitle),
        body: pick(language, risky ? COPY.saveDanger : COPY.dnssecOffBody),
        severity: openResolver ? "destructive" : "disruptive",
        confirmLabel: pick(language, COPY.saveYes)
      });
      if (!ok) return;
    }
    setSaving(true);
    setSaveError(null);
    setConflict(false);
    try {
      const body = clone({ ...draft, config_version: saved?.config_version ?? draft.config_version });
      cleanSecuritySections(body as { resolution?: ResolutionSettings; dnssec?: DnssecSettings });
      const result = await saveDnsSettings(body);
      setWarnings(warningsOf(result));
      const raw = result && typeof result === "object" ? ((result as { settings?: DnsSettings }).settings ?? (result as DnsSettings)) : null;
      if (raw && Array.isArray(raw.listen)) {
        const next = normalize(raw);
        setSaved(clone(next));
        setDraft(clone(next));
      } else {
        await load();
      }
      notify({ message: pick(language, COPY.saved), tone: "success" });
    } catch (caught) {
      if (caught instanceof ApiError && (caught.code === "dns_config_conflict" || caught.code === "config_conflict" || caught.status === 409)) setConflict(true);
      else setSaveError(caught);
    } finally {
      setSaving(false);
    }
  };

  const flush = async () => {
    const name = flushName.trim().replace(/\.$/, "");
    if (name && !isDnsName(name)) return;
    const ok = await ask({
      title: name ? say(language, COPY.flushTitleOne, { name }) : pick(language, COPY.flushTitleAll),
      body: pick(language, COPY.flushBody),
      severity: "disruptive",
      confirmLabel: pick(language, COPY.flushYes)
    });
    if (!ok) return;
    setFlushing(true);
    try {
      await flushDnsCache(name || undefined);
      notify({ message: pick(language, COPY.flushed), tone: "success" });
      setFlushName("");
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    } finally {
      setFlushing(false);
    }
  };

  if (!canAdmin) return <NoAccess needs="dns:admin" variant="card" />;
  if (error && !draft) {
    if (helperProblem(error) === "module_missing") return <Notice tone="info">{pick(language, COPY.moduleMissing)}</Notice>;
    return <FriendlyError error={error} title={pick(language, COPY.loadFailed)} onRetry={() => void load()} />;
  }
  if (!draft) return <Box sx={{ display: "grid", placeItems: "center", py: 6 }}><CircularProgress size={28} aria-hidden /></Box>;

  const rangeProblem = (item: string) => (isCidr(item) ? null : pick(language, COPY.badRange));
  const upstreams = draft.upstreams ?? [];
  const flushProblem = flushName.trim() && !isDnsName(flushName.trim()) ? pick(language, COPY.badFlushName) : null;
  const strategy = (draft.upstream_strategy in STRATEGY_WORDS ? draft.upstream_strategy : "fastest") as UpstreamStrategy;
  const serverFields = dnsFieldMessages(language, saveError);
  const d4Status = (status?.engine ?? null) as DnsD4Status | null;
  const securityCards = draft.resolution && draft.dnssec ? (
    <>
      <ResolutionCard
        value={draft.resolution as ResolutionSettings}
        update={(mutate) => update((next) => { mutate(next.resolution as ResolutionSettings); })}
        problems={problems}
        serverFields={serverFields}
        status={d4Status?.resolution}
        enabledUpstreams={upstreams.filter((item) => item.enabled !== false).length}
      />
      <DnssecCard
        value={draft.dnssec as DnssecSettings}
        update={(mutate) => update((next) => { mutate(next.dnssec as DnssecSettings); })}
        problems={problems}
        serverFields={serverFields}
        canAdmin={canAdmin}
      />
    </>
  ) : (
    <Notice tone="info">{pick(language, COPY.d4Missing)}</Notice>
  );

  return (
    <Stack spacing={2.5} sx={{ pb: changes.length ? 10 : 0 }}>
      {conflict ? (
        <Notice tone="warning" action={<Button color="inherit" size="small" onClick={() => void load()} sx={{ minHeight: 40 }}>{pick(language, COPY.loadLatest)}</Button>}>
          {pick(language, COPY.conflict)}
        </Notice>
      ) : null}

      <SaveWarnings warnings={warnings} onClose={() => setWarnings([])} />

      {!isAdvanced ? securityCards : null}
      {!isAdvanced ? <Notice tone="info">{pick(language, COPY.moreInAdvanced)}</Notice> : null}

      {isAdvanced ? (<>
      <SectionCard title={pick(language, COPY.listenTitle)} hint={pick(language, COPY.listenHint)}>
        <Stack spacing={1.5}>
          {draft.listen.map((item, index) => (
            <Stack key={index} direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ xs: "stretch", sm: "flex-start" }}>
              <TextField
                label={pick(language, COPY.listenAddress)}
                value={item.address}
                onChange={(event) => update((next) => { next.listen[index].address = event.target.value.trim(); })}
                error={Boolean(problems[`listen.${index}`])}
                helperText={problems[`listen.${index}`] ?? " "}
                size="small"
                sx={{ flex: 1 }}
                slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
              />
              <Stack direction="row" alignItems="center" gap={0.5}>
                <FormControlLabel control={<Checkbox checked={item.udp} onChange={(event) => update((next) => { next.listen[index].udp = event.target.checked; })} />} label="UDP" />
                <FormControlLabel control={<Checkbox checked={item.tcp} onChange={(event) => update((next) => { next.listen[index].tcp = event.target.checked; })} />} label="TCP" />
                <Tooltip title={pick(language, COPY.remove)}>
                  <span>
                    <IconButton aria-label={pick(language, COPY.remove)} onClick={() => update((next) => { next.listen.splice(index, 1); })} disabled={draft.listen.length <= 1} sx={{ width: 44, height: 44 }}>
                      <DeleteOutlineRoundedIcon />
                    </IconButton>
                  </span>
                </Tooltip>
              </Stack>
            </Stack>
          ))}
          {problems.listen ? <Typography variant="caption" color="error">{problems.listen}</Typography> : null}
          <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center">
            <Button startIcon={<AddRoundedIcon />} onClick={() => update((next) => { next.listen.push({ address: "", udp: true, tcp: true }); })} sx={{ minHeight: 44 }}>
              {pick(language, COPY.addListen)}
            </Button>
            {["127.0.0.1:53", "172.17.0.1:53", "[::1]:53"].filter((address) => !draft.listen.some((item) => item.address === address)).map((address) => (
              <Chip key={address} label={<Ltr mono>{address}</Ltr>} icon={<AddRoundedIcon />} variant="outlined" onClick={() => update((next) => { next.listen.push({ address, udp: true, tcp: true }); })} />
            ))}
          </Stack>
        </Stack>
      </SectionCard>

      <SectionCard title={pick(language, COPY.accessTitle)} hint={pick(language, COPY.accessHint)}>
        <Stack spacing={2}>
          <ListInput label={pick(language, COPY.queryAllow)} value={draft.query_allow ?? []} onChange={(value) => update((next) => { next.query_allow = value; })} validate={rangeProblem} helperText={pick(language, COPY.rangeHint)} />
          <SwitchRow label={pick(language, COPY.recursion)} hint={pick(language, COPY.recursionHint)} checked={Boolean(draft.recursion?.enabled)} onChange={(value) => update((next) => { next.recursion.enabled = value; })} />
          {draft.recursion?.enabled ? (
            <ListInput
              label={pick(language, COPY.recursionAllow)}
              value={draft.recursion.allow ?? []}
              onChange={(value) => update((next) => { next.recursion.allow = value; })}
              validate={(item) => OPEN_RANGES.has(item.trim()) ? pick(language, COPY.openResolver) : rangeProblem(item)}
              helperText={pick(language, COPY.rangeHint)}
            />
          ) : null}
          {openResolver ? <Notice tone="error">{pick(language, COPY.openResolver)}</Notice> : null}
          {!openResolver && openQuery ? <Notice tone="info">{pick(language, COPY.publicQueries)}</Notice> : null}
        </Stack>
      </SectionCard>

      <SectionCard title={pick(language, COPY.upstreamTitle)} hint={pick(language, COPY.upstreamHint)} action={<Button startIcon={<AddRoundedIcon />} onClick={() => setAdding(Date.now())} sx={{ minHeight: 44 }}>{pick(language, COPY.addUpstream)}</Button>}>
        <Stack spacing={2}>
          {upstreams.length ? (
            <Stack divider={<Divider flexItem />} spacing={1}>
              {upstreams.map((item, index) => {
                const preset = presetFor(item.address);
                return (
                  <Stack key={item.id ?? `${item.address}-${index}`} direction="row" alignItems="center" gap={1} flexWrap="wrap">
                    <Switch checked={item.enabled !== false} onChange={(event) => update((next) => { next.upstreams[index].enabled = event.target.checked; })} slotProps={{ input: { "aria-label": item.address } }} />
                    <Box sx={{ flex: 1, minWidth: 180 }}>
                      <Typography variant="body2" sx={{ fontWeight: 650, wordBreak: "break-all" }}><Ltr mono>{item.address}</Ltr></Typography>
                      <Typography variant="caption" color="text.secondary">
                        {preset ? `${pick(language, preset.name)} · ` : ""}{pick(language, PROTO_WORDS[upstreamProto(item.address)])}
                      </Typography>
                    </Box>
                    <Stack direction="row">
                      <IconButton aria-label={pick(language, COPY.moveUp)} disabled={index === 0} onClick={() => update((next) => { [next.upstreams[index - 1], next.upstreams[index]] = [next.upstreams[index], next.upstreams[index - 1]]; })} sx={{ width: 44, height: 44 }}>
                        <ArrowUpwardRoundedIcon fontSize="small" />
                      </IconButton>
                      <IconButton aria-label={pick(language, COPY.moveDown)} disabled={index === upstreams.length - 1} onClick={() => update((next) => { [next.upstreams[index + 1], next.upstreams[index]] = [next.upstreams[index], next.upstreams[index + 1]]; })} sx={{ width: 44, height: 44 }}>
                        <ArrowDownwardRoundedIcon fontSize="small" />
                      </IconButton>
                      <IconButton aria-label={pick(language, COPY.remove)} onClick={() => update((next) => { next.upstreams.splice(index, 1); })} sx={{ width: 44, height: 44 }}>
                        <DeleteOutlineRoundedIcon fontSize="small" />
                      </IconButton>
                    </Stack>
                  </Stack>
                );
              })}
            </Stack>
          ) : (
            <Notice tone="warning">{pick(language, COPY.noUpstreams)}</Notice>
          )}
          <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.strategy)}</Typography>
          <ChoiceCards<UpstreamStrategy>
            label={pick(language, COPY.strategy)}
            value={strategy}
            onChange={(value) => update((next) => { next.upstream_strategy = value; })}
            options={(Object.keys(STRATEGY_WORDS) as UpstreamStrategy[]).map((key) => ({ key, title: pick(language, STRATEGY_WORDS[key].label), body: pick(language, STRATEGY_WORDS[key].body) }))}
          />
        </Stack>
      </SectionCard>

      {securityCards}

      <SectionCard title={pick(language, COPY.cacheTitle)} hint={pick(language, COPY.cacheHint)}>
        <Stack spacing={2}>
          <Row>
            <BytesInput label={pick(language, COPY.maxBytes)} value={draft.cache.max_bytes} onChange={(value) => update((next) => { next.cache.max_bytes = value ?? 0; })} min={1_048_576} />
            <DurationInput label={pick(language, COPY.negTtl)} value={draft.cache.negative_max_ttl} onChange={(value) => update((next) => { next.cache.negative_max_ttl = value ?? 0; })} min={0} max={86_400} />
            <DurationInput label={pick(language, COPY.minTtl)} value={draft.cache.min_ttl} onChange={(value) => update((next) => { next.cache.min_ttl = value ?? 0; })} min={0} max={86_400} error={problems.ttl ?? null} />
            <DurationInput label={pick(language, COPY.maxTtl)} value={draft.cache.max_ttl} onChange={(value) => update((next) => { next.cache.max_ttl = value ?? 0; })} min={0} max={604_800} error={problems.ttl ?? null} />
          </Row>
          <SwitchRow label={pick(language, COPY.serveStale)} hint={pick(language, COPY.serveStaleHint)} checked={Boolean(draft.cache.serve_stale)} onChange={(value) => update((next) => { next.cache.serve_stale = value; })} />
          {draft.cache.serve_stale ? (
            <Box sx={{ maxWidth: { md: "50%" } }}>
              <DurationInput label={pick(language, COPY.staleTtl)} value={draft.cache.stale_ttl} onChange={(value) => update((next) => { next.cache.stale_ttl = value ?? 0; })} min={0} max={604_800} />
            </Box>
          ) : null}
          <SwitchRow label={pick(language, COPY.prefetch)} hint={pick(language, COPY.prefetchHint)} checked={Boolean(draft.cache.prefetch)} onChange={(value) => update((next) => { next.cache.prefetch = value; })} />
          <Divider />
          <Stack direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ xs: "stretch", sm: "flex-start" }}>
            <TextField
              label={pick(language, COPY.flushName)}
              value={flushName}
              onChange={(event) => setFlushName(event.target.value)}
              error={Boolean(flushProblem)}
              helperText={flushProblem ?? " "}
              size="small"
              sx={{ flex: 1 }}
              slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoCapitalize: "none" } }}
            />
            <Button variant="outlined" onClick={() => void flush()} disabled={flushing || Boolean(flushProblem)} startIcon={flushing ? <CircularProgress size={14} /> : <CleaningServicesRoundedIcon />} sx={{ minHeight: 40 }}>
              {pick(language, COPY.flush)}
            </Button>
          </Stack>
        </Stack>
      </SectionCard>

      <SectionCard title={pick(language, COPY.limitsTitle)} hint={pick(language, COPY.limitsHint)}>
        <Stack spacing={2}>
          <Row>
            <NumberInput label={pick(language, COPY.clientQps)} value={draft.limits.client_qps} onChange={(value) => update((next) => { next.limits.client_qps = value ?? 0; })} min={0} max={1_000_000} integer unit={pick(language, COPY.perSecond)} />
            <NumberInput label={pick(language, COPY.clientBurst)} value={draft.limits.client_burst} onChange={(value) => update((next) => { next.limits.client_burst = value ?? 0; })} min={0} max={1_000_000} integer />
            <NumberInput label={pick(language, COPY.rrl)} value={draft.limits.rrl_responses_per_second} onChange={(value) => update((next) => { next.limits.rrl_responses_per_second = value ?? 0; })} min={0} max={100_000} integer unit={pick(language, COPY.perSecond)} helperText={pick(language, COPY.rrlHint)} />
            <NumberInput label={pick(language, COPY.rrlSlip)} value={draft.limits.rrl_slip} onChange={(value) => update((next) => { next.limits.rrl_slip = value ?? 0; })} min={0} max={10} integer />
            <NumberInput label={pick(language, COPY.rrlV4)} value={draft.limits.rrl_ipv4_prefix} onChange={(value) => update((next) => { next.limits.rrl_ipv4_prefix = value ?? 24; })} min={8} max={32} integer />
            <NumberInput label={pick(language, COPY.rrlV6)} value={draft.limits.rrl_ipv6_prefix} onChange={(value) => update((next) => { next.limits.rrl_ipv6_prefix = value ?? 56; })} min={16} max={128} integer />
            <NumberInput label={pick(language, COPY.maxTcp)} value={draft.limits.max_tcp_connections} onChange={(value) => update((next) => { next.limits.max_tcp_connections = value ?? 0; })} min={1} max={100_000} integer />
            <NumberInput label={pick(language, COPY.tcpIdle)} value={draft.limits.tcp_idle_timeout_ms} onChange={(value) => update((next) => { next.limits.tcp_idle_timeout_ms = value ?? 0; })} min={100} max={600_000} integer unit={pick(language, COPY.ms)} />
            <NumberInput label={pick(language, COPY.udpSize)} value={draft.limits.udp_max_size} onChange={(value) => update((next) => { next.limits.udp_max_size = value ?? 1232; })} min={512} max={4096} integer unit={pick(language, COPY.bytes)} />
            <NumberInput label={pick(language, COPY.inflight)} value={draft.limits.max_inflight_upstream} onChange={(value) => update((next) => { next.limits.max_inflight_upstream = value ?? 0; })} min={1} max={1_000_000} integer />
          </Row>
          <Divider />
          <SwitchRow label={pick(language, COPY.minimalAny)} hint={pick(language, COPY.minimalAnyHint)} checked={Boolean(draft.minimal_any)} onChange={(value) => update((next) => { next.minimal_any = value; })} />
          <SwitchRow label={pick(language, COPY.refuseAny)} checked={Boolean(draft.refuse_any)} onChange={(value) => update((next) => { next.refuse_any = value; })} />
          <SwitchRow label={pick(language, COPY.rebinding)} hint={pick(language, COPY.rebindingHint)} checked={Boolean(draft.rebinding_protection)} onChange={(value) => update((next) => { next.rebinding_protection = value; })} />
          <SwitchRow label={pick(language, COPY.overrides)} hint={pick(language, COPY.overridesHint)} checked={draft.overrides?.enabled !== false} onChange={(value) => update((next) => { next.overrides = { ...(next.overrides ?? {}), enabled: value }; })} />
        </Stack>
      </SectionCard>

      <IntegrationCard />
      </>) : null}

      <DnsBackupCard permissions={permissions} />

      {saved?.config_version !== undefined ? (
        <Typography variant="caption" color="text.secondary">{pick(language, COPY.version)}: <Ltr mono>{String(saved.config_version)}</Ltr></Typography>
      ) : null}

      {saveError ? <FriendlyError error={saveError} title={pick(language, { fa: "تنظیمات ذخیره نشد.", en: "The settings weren't saved." })} onClose={() => setSaveError(null)} /> : null}

      {changes.length ? (
        <Paper
          elevation={6}
          sx={{
            position: "sticky", bottom: { xs: "calc(var(--mrk-bottom-nav-height, 0px) + 8px)", sm: 16 }, zIndex: 5, p: 1.5,
            display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap", justifyContent: "space-between"
          }}
        >
          <Typography variant="body2" sx={{ fontWeight: 650 }}>
            {invalid ? pick(language, COPY.fixFirst) : say(language, COPY.changes, { count: changes.length })}
          </Typography>
          <Stack direction="row" gap={1}>
            <Button onClick={() => setDraft(saved ? clone(saved) : draft)} disabled={saving} sx={{ minHeight: 44 }}>{pick(language, COPY.discard)}</Button>
            <Button variant="contained" onClick={() => void save()} disabled={saving || invalid} startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
              {pick(language, saving ? COPY.saving : COPY.save)}
            </Button>
          </Stack>
        </Paper>
      ) : null}

      {adding ? (
        <AddUpstreamDialog
          key={adding}
          existing={upstreams}
          onClose={() => setAdding(null)}
          onAdd={(addresses) => {
            update((next) => {
              for (const address of addresses) next.upstreams.push({ id: newUpstreamId(address, next.upstreams), address, enabled: true });
            });
            setAdding(null);
          }}
        />
      ) : null}
      {dialog}
      {snackbar}
    </Stack>
  );
}
