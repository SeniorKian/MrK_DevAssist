/**
 * DNS phase D4 settings cards (docs/40 §6): «روش پیدا کردن نشانی‌ها» (`resolution`) and
 * «امضای امنیتی (DNSSEC)» (`dnssec`). Both are controlled: DnsSettings.tsx owns the one draft of
 * the whole settings object and its single save (so the cards never race each other with
 * `config_version`). Simple mode shows plain choices; every engine parameter sits in an
 * «تنظیمات پیشرفته» section that opens by itself in Advanced mode.
 */
import { useCallback, useEffect, useState } from "react";
import {
  Box, Button, CircularProgress, Divider, FormControlLabel, IconButton, MenuItem, Stack, Switch, TextField, Tooltip, Typography
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import AltRouteRoundedIcon from "@mui/icons-material/AltRouteRounded";
import { formatNumber } from "./format";
import AccountTreeRoundedIcon from "@mui/icons-material/AccountTreeRounded";
import CallSplitRoundedIcon from "@mui/icons-material/CallSplitRounded";
import { ApiError, isAbortError } from "./api";
import { errorSentence, pick, say, type Bi } from "./copy";
import {
  AdvancedSection, ChoiceCards, DurationInput, FriendlyError, KeyValueList, Ltr, Notice, NumberInput, RelativeTime, SectionCard, StatusPill,
  useKit, useUndoSnackbar
} from "./kit";
import { isDnsName, isIPv4, isIPv6 } from "./dns";
import {
  ANCHOR_STATE_WORDS, RANGES, anchorSentence, fetchDnssec, refreshDnssec, warningText, type DnsD4Status, type DnssecSettings, type DnssecView,
  type NegativeTrustAnchor, type ResolutionMode, type ResolutionSettings, type RootHint, type SettingsWarning
} from "./dnsSecure";

const COPY = {
  // resolution
  resTitle: { fa: "روش پیدا کردن نشانی‌ها", en: "How addresses are found" },
  resHint: { fa: "وقتی کسی نام سایتی را می‌پرسد، MRK نشانی آن را از کجا بیاورد.", en: "When someone asks for a site's name, where MRK gets its address from." },
  forwardTitle: { fa: "از سرورهای مطمئن بپرس", en: "Ask trusted servers" },
  forwardBody: {
    fa: "MRK از DNS‌های بیرونی فهرست بالا می‌پرسد. ساده و سریع است؛ فقط باید به آن سرورها اعتماد کنید.",
    en: "MRK asks the outside DNS servers listed above. Simple and fast; you just have to trust those servers."
  },
  recursiveTitle: { fa: "خودش مستقیم پیدا کند", en: "Find it directly" },
  recursiveBody: {
    fa: "MRK از سرورهای ریشه اینترنت شروع می‌کند و خودش جواب را پیدا می‌کند؛ به هیچ واسطه‌ای وابسته نیست. پرسش اولِ هر نام کمی کندتر است.",
    en: "MRK starts at the internet's root servers and finds the answer itself, with no middleman. The first question for each name is a bit slower."
  },
  bothTitle: { fa: "اول بپرس، اگر نشد خودش", en: "Ask first, find it myself if that fails" },
  bothBody: {
    fa: "معمولاً از DNS‌های بیرونی می‌پرسد؛ اگر هیچ‌کدام جواب ندادند، خودش از ریشه پیدا می‌کند. برای اینترنت ناپایدار خوب است.",
    en: "Usually asks the outside DNS servers; if none of them answers, it finds the answer from the root itself. Good for a shaky internet."
  },
  suggested: { fa: "پیشنهادی", en: "Suggested" },
  primingOk: { fa: "سرورهای ریشه در دسترس‌اند ({count} از ۱۳ جواب دادند).", en: "The root servers are reachable ({count} of 13 answered)." },
  primingBad: { fa: "MRK به سرورهای ریشه نرسید. شاید پورت ۵۳ خروجی سرور بسته است.", en: "MRK couldn't reach the root servers. Outgoing port 53 may be blocked." },
  primingWaiting: { fa: "MRK هنوز سرورهای ریشه را بررسی نکرده است؛ چند لحظه بعد ذخیره و دوباره نگاه کنید.", en: "MRK hasn't checked the root servers yet; save and look again in a moment." },
  noUpstreamsForward: { fa: "برای این روش دست‌کم یک DNS بیرونی روشن لازم است.", en: "This way needs at least one outside DNS server turned on." },
  resAdvanced: { fa: "جزئیات حل از ریشه", en: "Finding from the root" },
  qmin: { fa: "کمتر گفتن نام کامل به سرورهای بین راه", en: "Tell servers along the way less of the name" },
  qminHint: { fa: "به سرور ریشه و پسوند فقط همان بخشی از نام گفته می‌شود که لازم دارند (حریم خصوصی بیشتر).", en: "The root and ending servers only hear the part of the name they need (more privacy)." },
  qminOff: { fa: "خاموش", en: "Off" },
  qminRelaxed: { fa: "روشن، با جایگزین اگر سروری بد جواب داد", en: "On, with a fallback if a server answers badly" },
  qminStrict: { fa: "روشن و سخت‌گیر", en: "On and strict" },
  ipVersions: { fa: "پرسیدن از سرورها با", en: "Ask servers over" },
  ipv4: { fa: "فقط IPv4", en: "IPv4 only" },
  ipv6: { fa: "فقط IPv6", en: "IPv6 only" },
  both: { fa: "هر دو", en: "Both" },
  caseRandom: { fa: "حروف بزرگ و کوچک تصادفی در پرسش", en: "Random upper and lower case in questions" },
  caseRandomHint: { fa: "جعل جواب را سخت‌تر می‌کند؛ با سرورهای ناسازگار خودکار خاموش می‌شود.", en: "Makes fake answers harder; turns itself off for servers that can't handle it." },
  privateNs: { fa: "اجازه پرسیدن از سرورهای شبکه داخلی", en: "Allow asking servers on internal networks" },
  privateNsHint: { fa: "خطرناک: فقط برای شبکه آزمایشگاهی. وگرنه یک سایت بیرونی می‌تواند MRK را به شبکه داخلی شما بفرستد.", en: "Risky: lab networks only. Otherwise an outside site could point MRK into your internal network." },
  maxReferrals: { fa: "بیشترین ارجاع در یک حل", en: "Most referrals in one lookup" },
  maxQueries: { fa: "بیشترین پرسش در یک حل", en: "Most questions in one lookup" },
  maxQueriesHint: { fa: "شامل پیدا کردن نشانی سرورها و کلیدهای امضا.", en: "Includes finding servers' addresses and signing keys." },
  maxNs: { fa: "بیشترین سرور هر دامنه که امتحان شود", en: "Most servers tried per domain" },
  queryTimeout: { fa: "صبر برای هر سرور", en: "Wait for each server" },
  resolveTimeout: { fa: "صبر برای کل یک حل", en: "Wait for a whole lookup" },
  resolveOrder: { fa: "صبر کل باید از صبر هر سرور بیشتر باشد.", en: "The whole wait must be longer than each server's wait." },
  infraCache: { fa: "تعداد سرورهایی که سرعتشان به خاطر سپرده می‌شود", en: "Servers whose speed is remembered" },
  ms: { fa: "میلی‌ثانیه", en: "ms" },
  rootHints: { fa: "سرورهای ریشه", en: "Root servers" },
  rootHintsHint: { fa: "خالی بماند تا همان ۱۳ سرور ریشه رسمی اینترنت استفاده شود. فقط برای شبکه جدا یا آزمایشگاه عوضش کنید.", en: "Leave empty to use the internet's 13 official root servers. Change it only for a separate or lab network." },
  rootBuiltin: { fa: "از سرورهای ریشه رسمی استفاده می‌شود.", en: "The official root servers are used." },
  rootName: { fa: "نام سرور", en: "Server name" },
  rootV4: { fa: "نشانی IPv4", en: "IPv4 address" },
  rootV6: { fa: "نشانی IPv6", en: "IPv6 address" },
  addRoot: { fa: "افزودن سرور ریشه", en: "Add a root server" },
  remove: { fa: "برداشتن", en: "Remove" },
  badName: { fa: "نام را مثل a.root-servers.net بنویسید.", en: "Write the name like a.root-servers.net." },
  badV4: { fa: "نشانی را مثل 198.41.0.4 بنویسید.", en: "Write the address like 198.41.0.4." },
  badV6: { fa: "نشانی را مثل 2001:503:ba3e::2:30 بنویسید.", en: "Write the address like 2001:503:ba3e::2:30." },
  needAddress: { fa: "دست‌کم یک نشانی لازم است.", en: "At least one address is needed." },
  duplicate: { fa: "این نام تکراری است.", en: "This name is repeated." },
  tooManyRoots: { fa: "حداکثر ۲۶ سرور ریشه.", en: "At most 26 root servers." },
  // dnssec
  secTitle: { fa: "امضای امنیتی (DNSSEC)", en: "Security signatures (DNSSEC)" },
  secHint: {
    fa: "بسیاری از دامنه‌ها جوابشان را امضا می‌کنند. MRK امضا را بررسی می‌کند تا کسی نتواند جواب جعلی به دستگاه‌های شما بدهد.",
    en: "Many domains sign their answers. MRK checks the signature so nobody can hand your devices a fake answer."
  },
  secOn: { fa: "امضای جواب‌ها بررسی شود", en: "Check answers' signatures" },
  secOnHint: { fa: "نام‌های شبکه داخلی و دامنه‌های خودتان خودکار بیرون از این بررسی می‌مانند.", en: "Your internal network names and your own domains are left out automatically." },
  secOffWarn: { fa: "خاموش است: MRK جواب جعلی را تشخیص نمی‌دهد.", en: "Off: MRK won't notice fake answers." },
  validateTitle: { fa: "جواب جعلی را نده", en: "Hold back fake answers" },
  validateBody: { fa: "پیشنهاد ما. اگر امضا خراب بود، دستگاه جواب «سرور نتوانست جواب بدهد» می‌گیرد و دلیلش در لاگ و «تست» دیده می‌شود.", en: "Our suggestion. If a signature is broken, the device gets “the server couldn't answer” and the reason shows in the log and Test." },
  logOnlyTitle: { fa: "فقط ثبت کن، جلویش را نگیر", en: "Just record it, don't block" },
  logOnlyBody: { fa: "برای عیب‌یابی: امضا بررسی و در لاگ ثبت می‌شود، ولی جواب خراب هم داده می‌شود.", en: "For troubleshooting: signatures are checked and logged, but broken answers are still given." },
  anchorTitle: { fa: "کلید اعتماد ریشه", en: "Root trust key" },
  refresh: { fa: "به‌روزرسانی", en: "Update" },
  refreshed: { fa: "کلید اعتماد ریشه بررسی و به‌روز شد.", en: "The root trust key was checked and updated." },
  refreshFailed: { fa: "به‌روزرسانی انجام نشد؛ MRK همان کلید قبلی را نگه داشت.", en: "The update didn't work; MRK kept the current key." },
  anchorLoadFailed: { fa: "وضعیت کلید اعتماد خوانده نشد.", en: "The trust key status didn't load." },
  updatedAt: { fa: "آخرین به‌روزرسانی", en: "Last updated" },
  counters: { fa: "بررسی‌ها از روشن شدن", en: "Checks since start" },
  countersValue: { fa: "{secure} امن، {insecure} بدون امضا، {bogus} خراب", en: "{secure} secure, {insecure} not signed, {bogus} broken" },
  secAdvanced: { fa: "جزئیات امضای امنیتی", en: "Signature details" },
  ntaTitle: { fa: "استثناها (دامنه‌هایی که امضایشان بررسی نشود)", en: "Exceptions (domains whose signatures aren't checked)" },
  ntaHint: { fa: "اگر دامنه‌ای امضای خراب دارد ولی می‌دانید سالم است، موقتاً اینجا بگذارید. بهتر است تاریخ پایان داشته باشد.", en: "If a domain's signature is broken but you know it's fine, put it here for a while. Best with an end date." },
  ntaEmpty: { fa: "هیچ استثنایی نیست.", en: "No exceptions." },
  ntaDomain: { fa: "دامنه", en: "Domain" },
  ntaReason: { fa: "دلیل (اختیاری)", en: "Reason (optional)" },
  ntaExpires: { fa: "تا (اختیاری)", en: "Until (optional)" },
  ntaExpired: { fa: "تمام شده", en: "Ended" },
  addNta: { fa: "افزودن استثنا", en: "Add an exception" },
  badDomain: { fa: "دامنه را مثل example.com بنویسید.", en: "Write the domain like example.com." },
  reasonLong: { fa: "دلیل حداکثر ۲۵۶ نویسه.", en: "The reason can be at most 256 characters." },
  tooManyNta: { fa: "حداکثر ۵۰۰ استثنا.", en: "At most 500 exceptions." },
  autoUpdate: { fa: "کلید اعتماد ریشه خودکار به‌روز شود", en: "Keep the root trust key updated automatically" },
  autoUpdateHint: { fa: "روش استاندارد اینترنت برای عوض شدن کلید ریشه؛ خاموش کردنش پیشنهاد نمی‌شود.", en: "The internet's standard way of rolling the root key; turning it off isn't advised." },
  autoLocal: { fa: "نام‌های داخلی و دامنه‌های خودم بررسی نشوند", en: "Don't check internal names and my own domains" },
  autoLocalHint: { fa: "تا چیزی در شبکه داخلی خراب نشود.", en: "So nothing on your internal network breaks." },
  aggressive: { fa: "استفاده از اثبات‌های امضاشده برای جواب سریع «چنین نامی نیست»", en: "Use signed proofs to answer “no such name” faster" },
  aggressiveHint: { fa: "سرعت و مقاومت در برابر حمله نام‌های ساختگی را بیشتر می‌کند.", en: "Speeds things up and resists made-up-name attacks." },
  nsec3: { fa: "سنگین‌ترین امضای «نبودن نام» که بررسی شود", en: "Heaviest “name doesn't exist” proof to check" },
  nsec3Hint: { fa: "بیشتر از این، مثل «بدون امضا» رفتار می‌شود تا سرور خسته نشود.", en: "Above this it's treated as not signed so the server isn't worn out." },
  bogusTtl: { fa: "نگه‌داری نتیجه «امضا خراب است»", en: "Keep “signature is broken” results for" },
  skew: { fa: "تحمل اختلاف ساعت", en: "Clock difference allowed" },
  anchorsList: { fa: "کلیدهای ریشه", en: "Root keys" },
  keyTag: { fa: "کلید {tag}", en: "Key {tag}" },
  since: { fa: "از", en: "since" },
  // warnings
  warningsTitle: { fa: "ذخیره شد؛ چند نکته:", en: "Saved; a few things to note:" }
} satisfies Record<string, Bi>;

const MODE_ICONS = { forward: AltRouteRoundedIcon, recursive: AccountTreeRoundedIcon, forward_then_recursive: CallSplitRoundedIcon };

export function SwitchRow({ label, hint, checked, onChange, tone, disabled }: { label: string; hint?: string; checked: boolean; onChange: (value: boolean) => void; tone?: "warning"; disabled?: boolean }) {
  return (
    <Box>
      <FormControlLabel control={<Switch checked={checked} color={tone ?? "primary"} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />} label={label} />
      {hint ? <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: -0.5, mx: 6 }}>{hint}</Typography> : null}
    </Box>
  );
}

function Grid2({ children }: { children: React.ReactNode }) {
  return <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" } }}>{children}</Box>;
}

/** Plain warnings from a settings PUT (docs/40 §5), shown until dismissed. */
export function SaveWarnings({ warnings, onClose }: { warnings: SettingsWarning[]; onClose: () => void }) {
  const { language, c } = useKit();
  if (!warnings.length) return null;
  return (
    <Notice tone="warning" action={<Button color="inherit" size="small" onClick={onClose} sx={{ minHeight: 40 }}>{c.close}</Button>}>
      <Typography variant="body2" sx={{ fontWeight: 700 }}>{pick(language, COPY.warningsTitle)}</Typography>
      <Stack component="ul" spacing={0.5} sx={{ m: 0, ps: 2.5 }}>
        {warnings.map((warning) => (
          <Typography component="li" variant="body2" key={warning.code} sx={{ lineHeight: 1.8 }}>{warningText(language, warning)}</Typography>
        ))}
      </Stack>
    </Notice>
  );
}

// ── validation ───────────────────────────────────────────────────────────────

export function validateResolution(language: "fa" | "en", value: ResolutionSettings | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!value) return result;
  if (value.resolve_timeout_ms <= value.query_timeout_ms) result["resolution.resolve_timeout_ms"] = pick(language, COPY.resolveOrder);
  const hints = value.root_hints ?? [];
  if (hints.length > RANGES.root_hints[1]) result["resolution.root_hints"] = pick(language, COPY.tooManyRoots);
  const seen = new Set<string>();
  hints.forEach((hint, index) => {
    const name = hint.name.trim().replace(/\.$/, "").toLowerCase();
    if (!isDnsName(name)) result[`resolution.root_hints.${index}.name`] = pick(language, COPY.badName);
    else if (seen.has(name)) result[`resolution.root_hints.${index}.name`] = pick(language, COPY.duplicate);
    seen.add(name);
    const v4 = (hint.ipv4 ?? "").trim();
    const v6 = (hint.ipv6 ?? "").trim();
    if (!v4 && !v6) result[`resolution.root_hints.${index}.ipv4`] = pick(language, COPY.needAddress);
    if (v4 && !isIPv4(v4)) result[`resolution.root_hints.${index}.ipv4`] = pick(language, COPY.badV4);
    if (v6 && !isIPv6(v6)) result[`resolution.root_hints.${index}.ipv6`] = pick(language, COPY.badV6);
  });
  return result;
}

export function validateDnssec(language: "fa" | "en", value: DnssecSettings | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!value) return result;
  const list = value.negative_trust_anchors ?? [];
  if (list.length > RANGES.negative_trust_anchors[1]) result["dnssec.negative_trust_anchors"] = pick(language, COPY.tooManyNta);
  const seen = new Set<string>();
  list.forEach((item, index) => {
    const domain = item.domain.trim().replace(/\.$/, "").toLowerCase();
    if (!isDnsName(domain)) result[`dnssec.negative_trust_anchors.${index}.domain`] = pick(language, COPY.badDomain);
    else if (seen.has(domain)) result[`dnssec.negative_trust_anchors.${index}.domain`] = pick(language, COPY.duplicate);
    seen.add(domain);
    if ((item.reason ?? "").length > 256) result[`dnssec.negative_trust_anchors.${index}.reason`] = pick(language, COPY.reasonLong);
  });
  return result;
}

/** Trim the free-text parts before saving (the engine normalises the rest). */
export function cleanSecuritySections(settings: { resolution?: ResolutionSettings; dnssec?: DnssecSettings }) {
  if (settings.resolution?.root_hints) {
    settings.resolution.root_hints = settings.resolution.root_hints.map((hint) => {
      const next: RootHint = { name: hint.name.trim() };
      if (hint.ipv4?.trim()) next.ipv4 = hint.ipv4.trim();
      if (hint.ipv6?.trim()) next.ipv6 = hint.ipv6.trim();
      return next;
    });
  }
  if (settings.dnssec?.negative_trust_anchors) {
    settings.dnssec.negative_trust_anchors = settings.dnssec.negative_trust_anchors.map((item) => {
      const next: NegativeTrustAnchor = { domain: item.domain.trim() };
      if (item.reason?.trim()) next.reason = item.reason.trim();
      if (item.expires_at) next.expires_at = item.expires_at;
      return next;
    });
  }
}

// ── resolution card ──────────────────────────────────────────────────────────

type CardProps<T> = {
  value: T;
  update: (mutate: (next: T) => void) => void;
  problems: Record<string, string>;
  serverFields: Record<string, string>;
};

export function ResolutionCard({ value, update, problems, serverFields, status, enabledUpstreams }: CardProps<ResolutionSettings> & { status?: DnsD4Status["resolution"]; enabledUpstreams: number }) {
  const { language } = useKit();
  const problem = (key: string) => problems[`resolution.${key}`] ?? serverFields[`resolution.${key}`] ?? null;
  const mode = (["forward", "recursive", "forward_then_recursive"].includes(value.mode) ? value.mode : "forward") as ResolutionMode;
  const priming = status?.root_priming ?? null;
  const usesRoot = mode !== "forward";
  const usesForward = mode !== "recursive";
  const hints = value.root_hints ?? [];

  return (
    <SectionCard title={pick(language, COPY.resTitle)} hint={pick(language, COPY.resHint)}>
      <Stack spacing={2}>
        <ChoiceCards<ResolutionMode>
          label={pick(language, COPY.resTitle)}
          value={mode}
          onChange={(key) => update((next) => { next.mode = key; })}
          options={[
            { key: "forward", title: pick(language, COPY.forwardTitle), body: pick(language, COPY.forwardBody), icon: MODE_ICONS.forward },
            { key: "recursive", title: pick(language, COPY.recursiveTitle), body: pick(language, COPY.recursiveBody), icon: MODE_ICONS.recursive },
            {
              key: "forward_then_recursive", title: pick(language, COPY.bothTitle), body: pick(language, COPY.bothBody), icon: MODE_ICONS.forward_then_recursive,
              badges: <StatusPill tone="info" label={pick(language, COPY.suggested)} />
            }
          ]}
        />
        {serverFields["resolution.mode"] ? <Typography variant="caption" color="error">{serverFields["resolution.mode"]}</Typography> : null}
        {usesForward && enabledUpstreams === 0 ? <Notice tone="warning">{pick(language, COPY.noUpstreamsForward)}</Notice> : null}
        {usesRoot && status?.mode && status.mode !== "forward" ? (
          priming && priming.ok ? (
            <Notice tone="success">{say(language, COPY.primingOk, { count: formatNumber(priming.servers_reachable ?? 0, language) })}</Notice>
          ) : priming && priming.at ? (
            <Notice tone="warning">{pick(language, COPY.primingBad)}</Notice>
          ) : (
            <Notice tone="info">{pick(language, COPY.primingWaiting)}</Notice>
          )
        ) : null}

        <AdvancedSection title={pick(language, COPY.resAdvanced)}>
          <Grid2>
            <TextField select size="small" label={pick(language, COPY.qmin)} value={value.qname_minimization} onChange={(event) => update((next) => { next.qname_minimization = event.target.value; })} helperText={pick(language, COPY.qminHint)}>
              <MenuItem value="off">{pick(language, COPY.qminOff)}</MenuItem>
              <MenuItem value="relaxed">{pick(language, COPY.qminRelaxed)}</MenuItem>
              <MenuItem value="strict">{pick(language, COPY.qminStrict)}</MenuItem>
            </TextField>
            <TextField select size="small" label={pick(language, COPY.ipVersions)} value={value.ip_versions} onChange={(event) => update((next) => { next.ip_versions = event.target.value; })} helperText=" ">
              <MenuItem value="ipv4">{pick(language, COPY.ipv4)}</MenuItem>
              <MenuItem value="ipv6">{pick(language, COPY.ipv6)}</MenuItem>
              <MenuItem value="both">{pick(language, COPY.both)}</MenuItem>
            </TextField>
            <NumberInput label={pick(language, COPY.maxReferrals)} value={value.max_referrals} onChange={(number) => update((next) => { next.max_referrals = number ?? DEFAULT_NUMBERS.max_referrals; })} min={RANGES.max_referrals[0]} max={RANGES.max_referrals[1]} integer error={problem("max_referrals")} />
            <NumberInput label={pick(language, COPY.maxQueries)} value={value.max_queries_per_resolution} onChange={(number) => update((next) => { next.max_queries_per_resolution = number ?? DEFAULT_NUMBERS.max_queries_per_resolution; })} min={RANGES.max_queries_per_resolution[0]} max={RANGES.max_queries_per_resolution[1]} integer helperText={pick(language, COPY.maxQueriesHint)} error={problem("max_queries_per_resolution")} />
            <NumberInput label={pick(language, COPY.maxNs)} value={value.max_ns_per_zone} onChange={(number) => update((next) => { next.max_ns_per_zone = number ?? DEFAULT_NUMBERS.max_ns_per_zone; })} min={RANGES.max_ns_per_zone[0]} max={RANGES.max_ns_per_zone[1]} integer error={problem("max_ns_per_zone")} />
            <NumberInput label={pick(language, COPY.infraCache)} value={value.infra_cache_entries} onChange={(number) => update((next) => { next.infra_cache_entries = number ?? DEFAULT_NUMBERS.infra_cache_entries; })} min={RANGES.infra_cache_entries[0]} max={RANGES.infra_cache_entries[1]} integer error={problem("infra_cache_entries")} />
            <NumberInput label={pick(language, COPY.queryTimeout)} value={value.query_timeout_ms} onChange={(number) => update((next) => { next.query_timeout_ms = number ?? DEFAULT_NUMBERS.query_timeout_ms; })} min={RANGES.query_timeout_ms[0]} max={RANGES.query_timeout_ms[1]} integer unit={pick(language, COPY.ms)} error={problem("query_timeout_ms")} />
            <NumberInput label={pick(language, COPY.resolveTimeout)} value={value.resolve_timeout_ms} onChange={(number) => update((next) => { next.resolve_timeout_ms = number ?? DEFAULT_NUMBERS.resolve_timeout_ms; })} min={RANGES.resolve_timeout_ms[0]} max={RANGES.resolve_timeout_ms[1]} integer unit={pick(language, COPY.ms)} error={problem("resolve_timeout_ms")} />
          </Grid2>
          <SwitchRow label={pick(language, COPY.caseRandom)} hint={pick(language, COPY.caseRandomHint)} checked={Boolean(value.case_randomization)} onChange={(on) => update((next) => { next.case_randomization = on; })} />
          <SwitchRow label={pick(language, COPY.privateNs)} hint={pick(language, COPY.privateNsHint)} tone="warning" checked={Boolean(value.allow_private_ns)} onChange={(on) => update((next) => { next.allow_private_ns = on; })} />
          <Divider />
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.rootHints)}</Typography>
            <Typography variant="caption" color="text.secondary" component="p">{pick(language, COPY.rootHintsHint)}</Typography>
          </Box>
          {hints.length ? (
            <Stack spacing={1.5} divider={<Divider flexItem />}>
              {hints.map((hint, index) => (
                <Stack key={index} direction={{ xs: "column", md: "row" }} gap={1} alignItems={{ xs: "stretch", md: "flex-start" }}>
                  <TextField size="small" label={pick(language, COPY.rootName)} value={hint.name} onChange={(event) => update((next) => { next.root_hints[index].name = event.target.value; })}
                    error={Boolean(problem(`root_hints.${index}.name`))} helperText={problem(`root_hints.${index}.name`) ?? " "} sx={{ flex: 1.2 }} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoCapitalize: "none" } }} />
                  <TextField size="small" label={pick(language, COPY.rootV4)} value={hint.ipv4 ?? ""} onChange={(event) => update((next) => { next.root_hints[index].ipv4 = event.target.value; })}
                    error={Boolean(problem(`root_hints.${index}.ipv4`))} helperText={problem(`root_hints.${index}.ipv4`) ?? " "} sx={{ flex: 1 }} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
                  <TextField size="small" label={pick(language, COPY.rootV6)} value={hint.ipv6 ?? ""} onChange={(event) => update((next) => { next.root_hints[index].ipv6 = event.target.value; })}
                    error={Boolean(problem(`root_hints.${index}.ipv6`))} helperText={problem(`root_hints.${index}.ipv6`) ?? " "} sx={{ flex: 1.2 }} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
                  <Tooltip title={pick(language, COPY.remove)}>
                    <IconButton aria-label={pick(language, COPY.remove)} onClick={() => update((next) => { next.root_hints.splice(index, 1); })} sx={{ width: 44, height: 44, alignSelf: { xs: "flex-end", md: "flex-start" } }}>
                      <DeleteOutlineRoundedIcon />
                    </IconButton>
                  </Tooltip>
                </Stack>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">{pick(language, COPY.rootBuiltin)}</Typography>
          )}
          {problem("root_hints") ? <Typography variant="caption" color="error">{problem("root_hints")}</Typography> : null}
          <Box>
            <Button startIcon={<AddRoundedIcon />} disabled={hints.length >= RANGES.root_hints[1]} onClick={() => update((next) => { next.root_hints = [...(next.root_hints ?? []), { name: "", ipv4: "", ipv6: "" }]; })} sx={{ minHeight: 44 }}>
              {pick(language, COPY.addRoot)}
            </Button>
          </Box>
        </AdvancedSection>
      </Stack>
    </SectionCard>
  );
}

const DEFAULT_NUMBERS = { max_referrals: 30, max_queries_per_resolution: 100, max_ns_per_zone: 13, query_timeout_ms: 1500, resolve_timeout_ms: 4000, infra_cache_entries: 10_000 };

// ── DNSSEC card ──────────────────────────────────────────────────────────────

/** RFC3339 (UTC) ↔ the browser's `datetime-local` value. */
function toLocalInput(value: string | null | undefined): string {
  if (!value) return "";
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return "";
  const date = new Date(ms - new Date(ms).getTimezoneOffset() * 60_000);
  return date.toISOString().slice(0, 16);
}
function fromLocalInput(value: string): string | null {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z") : null;
}

function TrustAnchorBlock({ canAdmin }: { canAdmin: boolean }) {
  const { language, isAdvanced } = useKit();
  const [view, setView] = useState<DnssecView | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const { notify, snackbar } = useUndoSnackbar();

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      setView(await fetchDnssec(signal));
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

  const refresh = async () => {
    setBusy(true);
    try {
      const next = await refreshDnssec();
      if (next && typeof next === "object") setView(next);
      notify({ message: pick(language, next?.error ? COPY.refreshFailed : COPY.refreshed), tone: next?.error ? "error" : "success" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  if (error && !view) {
    if (error instanceof ApiError && error.status === 404) return null;
    return <FriendlyError error={error} title={pick(language, COPY.anchorLoadFailed)} onRetry={() => void load()} severity="warning" scope="dns" />;
  }
  const sentence = anchorSentence(language, view);
  const counters = view?.counters;
  const anchors = view?.trust_anchors ?? [];

  return (
    <Box sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, p: 1.5 }}>
      <Stack spacing={1}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" gap={1} flexWrap="wrap">
          <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.anchorTitle)}</Typography>
          {canAdmin ? (
            <Button size="small" onClick={() => void refresh()} disabled={busy} startIcon={busy ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} sx={{ minHeight: 40 }}>
              {pick(language, COPY.refresh)}
            </Button>
          ) : null}
        </Stack>
        <Stack direction="row" gap={1} alignItems="flex-start">
          <StatusPill tone={sentence.tone} label={pick(language, sentence.tone === "ok" ? ANCHOR_STATE_WORDS.valid.label : sentence.tone === "warn" ? { fa: "نیاز به توجه", en: "Needs attention" } : sentence.tone === "error" ? { fa: "مشکل دارد", en: "Problem" } : { fa: "در حال بررسی", en: "Checking" })} />
          <Typography variant="body2" sx={{ lineHeight: 1.8 }}>{sentence.text}</Typography>
        </Stack>
        {view?.updated_at ? (
          <Typography variant="caption" color="text.secondary">{pick(language, COPY.updatedAt)}: <RelativeTime value={view.updated_at} relativeAlways /></Typography>
        ) : null}
        {isAdvanced ? (
          <KeyValueList
            dense
            items={[
              ...anchors.map((anchor) => ({
                label: say(language, COPY.keyTag, { tag: String(anchor.key_tag) }),
                value: (
                  <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
                    <StatusPill tone={ANCHOR_STATE_WORDS[anchor.state]?.tone ?? "off"} label={ANCHOR_STATE_WORDS[anchor.state] ? pick(language, ANCHOR_STATE_WORDS[anchor.state].label) : anchor.state} />
                    {anchor.since ? <Typography variant="caption" color="text.secondary">{pick(language, COPY.since)} <RelativeTime value={anchor.since} relativeAlways /></Typography> : null}
                  </Stack>
                )
              })),
              ...(counters ? [{
                label: pick(language, COPY.counters),
                value: say(language, COPY.countersValue, {
                  secure: formatNumber(counters.secure ?? 0, language), insecure: formatNumber(counters.insecure ?? 0, language), bogus: formatNumber(counters.bogus ?? 0, language)
                })
              }] : []),
              ...(view?.error ? [{ label: pick(language, { fa: "پیام فنی", en: "Technical message" }), value: <Ltr mono>{view.error}</Ltr> }] : [])
            ]}
          />
        ) : null}
      </Stack>
      {snackbar}
    </Box>
  );
}

export function DnssecCard({ value, update, problems, serverFields, canAdmin }: CardProps<DnssecSettings> & { canAdmin: boolean }) {
  const { language } = useKit();
  const problem = (key: string) => problems[`dnssec.${key}`] ?? serverFields[`dnssec.${key}`] ?? null;
  const on = value.mode !== "off";
  const [lastOnMode, setLastOnMode] = useState<"validate" | "log_only">(value.mode === "log_only" ? "log_only" : "validate");
  const list = value.negative_trust_anchors ?? [];
  const now = Date.now();

  return (
    <SectionCard title={pick(language, COPY.secTitle)} hint={pick(language, COPY.secHint)}>
      <Stack spacing={2}>
        <SwitchRow
          label={pick(language, COPY.secOn)}
          hint={pick(language, COPY.secOnHint)}
          checked={on}
          onChange={(checked) => {
            if (!checked && on) setLastOnMode(value.mode === "log_only" ? "log_only" : "validate");
            update((next) => { next.mode = checked ? lastOnMode : "off"; });
          }}
        />
        {on ? (
          <ChoiceCards<"validate" | "log_only">
            label={pick(language, COPY.secTitle)}
            value={value.mode === "log_only" ? "log_only" : "validate"}
            onChange={(key) => update((next) => { next.mode = key; })}
            options={[
              { key: "validate", title: pick(language, COPY.validateTitle), body: pick(language, COPY.validateBody), badges: <StatusPill tone="info" label={pick(language, COPY.suggested)} /> },
              { key: "log_only", title: pick(language, COPY.logOnlyTitle), body: pick(language, COPY.logOnlyBody), tone: "warning" }
            ]}
          />
        ) : (
          <Notice tone="warning">{pick(language, COPY.secOffWarn)}</Notice>
        )}
        {serverFields["dnssec.mode"] ? <Typography variant="caption" color="error">{serverFields["dnssec.mode"]}</Typography> : null}

        <TrustAnchorBlock canAdmin={canAdmin} />

        <AdvancedSection title={pick(language, COPY.secAdvanced)} count={list.length || undefined}>
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.ntaTitle)}</Typography>
            <Typography variant="caption" color="text.secondary" component="p">{pick(language, COPY.ntaHint)}</Typography>
          </Box>
          {list.length ? (
            <Stack spacing={1.5} divider={<Divider flexItem />}>
              {list.map((item, index) => {
                const expires = item.expires_at ? Date.parse(item.expires_at) : NaN;
                const ended = Number.isFinite(expires) && expires < now;
                return (
                  <Stack key={index} direction={{ xs: "column", md: "row" }} gap={1} alignItems={{ xs: "stretch", md: "flex-start" }}>
                    <TextField size="small" label={pick(language, COPY.ntaDomain)} value={item.domain} onChange={(event) => update((next) => { next.negative_trust_anchors[index].domain = event.target.value; })}
                      error={Boolean(problem(`negative_trust_anchors.${index}.domain`))} helperText={problem(`negative_trust_anchors.${index}.domain`) ?? " "} sx={{ flex: 1.2 }}
                      slotProps={{ htmlInput: { dir: "ltr", spellCheck: false, autoCapitalize: "none" } }} />
                    <TextField size="small" label={pick(language, COPY.ntaReason)} value={item.reason ?? ""} onChange={(event) => update((next) => { next.negative_trust_anchors[index].reason = event.target.value; })}
                      error={Boolean(problem(`negative_trust_anchors.${index}.reason`))} helperText={problem(`negative_trust_anchors.${index}.reason`) ?? " "} sx={{ flex: 1.2 }} />
                    <TextField size="small" type="datetime-local" label={pick(language, COPY.ntaExpires)} value={toLocalInput(item.expires_at)}
                      onChange={(event) => update((next) => { next.negative_trust_anchors[index].expires_at = fromLocalInput(event.target.value); })}
                      error={Boolean(problem(`negative_trust_anchors.${index}.expires_at`))}
                      helperText={problem(`negative_trust_anchors.${index}.expires_at`) ?? (ended ? pick(language, COPY.ntaExpired) : " ")}
                      sx={{ flex: 1 }} slotProps={{ inputLabel: { shrink: true }, htmlInput: { dir: "ltr" } }} />
                    <Tooltip title={pick(language, COPY.remove)}>
                      <IconButton aria-label={pick(language, COPY.remove)} onClick={() => update((next) => { next.negative_trust_anchors.splice(index, 1); })} sx={{ width: 44, height: 44, alignSelf: { xs: "flex-end", md: "flex-start" } }}>
                        <DeleteOutlineRoundedIcon />
                      </IconButton>
                    </Tooltip>
                  </Stack>
                );
              })}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">{pick(language, COPY.ntaEmpty)}</Typography>
          )}
          {problem("negative_trust_anchors") ? <Typography variant="caption" color="error">{problem("negative_trust_anchors")}</Typography> : null}
          <Box>
            <Button startIcon={<AddRoundedIcon />} disabled={list.length >= RANGES.negative_trust_anchors[1]}
              onClick={() => update((next) => { next.negative_trust_anchors = [...(next.negative_trust_anchors ?? []), { domain: "", reason: "", expires_at: fromLocalInput(toLocalInput(new Date(Date.now() + 7 * 86_400_000).toISOString())) }]; })}
              sx={{ minHeight: 44 }}>
              {pick(language, COPY.addNta)}
            </Button>
          </Box>
          <Divider />
          <SwitchRow label={pick(language, COPY.autoUpdate)} hint={pick(language, COPY.autoUpdateHint)} checked={Boolean(value.trust_anchor_auto_update)} onChange={(checked) => update((next) => { next.trust_anchor_auto_update = checked; })} />
          <SwitchRow label={pick(language, COPY.autoLocal)} hint={pick(language, COPY.autoLocalHint)} checked={Boolean(value.auto_insecure_local)} onChange={(checked) => update((next) => { next.auto_insecure_local = checked; })} />
          <SwitchRow label={pick(language, COPY.aggressive)} hint={pick(language, COPY.aggressiveHint)} checked={Boolean(value.aggressive_nsec)} onChange={(checked) => update((next) => { next.aggressive_nsec = checked; })} />
          <Grid2>
            <NumberInput label={pick(language, COPY.nsec3)} value={value.nsec3_max_iterations} onChange={(number) => update((next) => { next.nsec3_max_iterations = number ?? 150; })} min={RANGES.nsec3_max_iterations[0]} max={RANGES.nsec3_max_iterations[1]} integer helperText={pick(language, COPY.nsec3Hint)} error={problem("nsec3_max_iterations")} />
            <DurationInput label={pick(language, COPY.bogusTtl)} value={value.bogus_ttl} onChange={(number) => update((next) => { next.bogus_ttl = number ?? 60; })} min={RANGES.bogus_ttl[0]} max={RANGES.bogus_ttl[1]} units={["seconds", "minutes"]} error={problem("bogus_ttl")} />
            <DurationInput label={pick(language, COPY.skew)} value={value.sig_skew_seconds} onChange={(number) => update((next) => { next.sig_skew_seconds = number ?? 3600; })} min={RANGES.sig_skew_seconds[0]} max={RANGES.sig_skew_seconds[1]} units={["seconds", "minutes", "hours"]} error={problem("sig_skew_seconds")} />
          </Grid2>
        </AdvancedSection>
      </Stack>
    </SectionCard>
  );
}
