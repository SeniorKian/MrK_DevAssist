/**
 * Test tab additions (docs/40 §6): the DNSSEC badge with a plain reason (from `dnssec.reason` or
 * the EDE codes) and «مسیر کامل» — the trace shown step by step: root → ending → domain.
 */
import { Box, Paper, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import PublicRoundedIcon from "@mui/icons-material/PublicRounded";
import AccountTreeRoundedIcon from "@mui/icons-material/AccountTreeRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import VerifiedUserRoundedIcon from "@mui/icons-material/VerifiedUserRounded";
import AltRouteRoundedIcon from "@mui/icons-material/AltRouteRounded";
import { pick, say, type Bi } from "./copy";
import { KeyValueList, Ltr, StatusPill, useKit } from "./kit";
import { formatNumber } from "./format";
import {
  DNSSEC_STATUS_WORDS, TRACE_LEVEL_WORDS, dnssecReasonText, edeText, traceLevel, traceOutcome, type Ede, type ResolveExtras, type TraceLevel, type TraceStep
} from "./dnsSecure";

const COPY = {
  signature: { fa: "امضای امنیتی", en: "Security signature" },
  why: { fa: "چرا:", en: "Why:" },
  edeTitle: { fa: "یادداشت‌های سرور", en: "Server notes" },
  traceTitle: { fa: "مسیر کامل پیدا کردن جواب", en: "The full path to the answer" },
  traceHint: { fa: "پیشکار از کجا شروع کرد و هر سرور به کجا فرستادش.", en: "Where Pishkar started and where each server sent it next." },
  traceEmpty: { fa: "مسیری برنگشت؛ احتمالاً جواب از نام‌های خودتان یا حافظه بود.", en: "No path came back; the answer probably came from your own names or memory." },
  stepAsked: { fa: "از {server} پرسید: {qname}", en: "Asked {server}: {qname}" },
  stepCheck: { fa: "کلید امضای {zone} را بررسی کرد", en: "Checked the signing key of {zone}" },
  ms: { fa: "{ms} میلی‌ثانیه", en: "{ms} ms" },
  rootZone: { fa: "ریشه", en: "the root" },
  steps: { fa: "{count} قدم", en: "{count} steps" },
  rcode: { fa: "کد جواب", en: "Response code" },
  zone: { fa: "بخش", en: "Zone" },
  server: { fa: "نشانی سرور", en: "Server address" },
  qtype: { fa: "نوع پرسش", en: "Question type" },
  error: { fa: "خطا", en: "Error" }
} satisfies Record<string, Bi>;

const LEVEL_ICONS: Record<TraceLevel, typeof PublicRoundedIcon> = {
  root: PublicRoundedIcon,
  tld: AccountTreeRoundedIcon,
  domain: DnsRoundedIcon,
  validator: VerifiedUserRoundedIcon,
  forwarder: AltRouteRoundedIcon
};

/** «امضا درست است / بدون امضا / امضا خراب است» + one plain reason. */
export function DnssecBadge({ dnssec, ede }: { dnssec: ResolveExtras["dnssec"]; ede: Ede[] | null | undefined }) {
  const { language, isAdvanced } = useKit();
  const status = dnssec?.status ?? "";
  const words = DNSSEC_STATUS_WORDS[status];
  if (!words) return null;
  const reason = dnssecReasonText(language, dnssec?.reason, ede);
  return (
    <Box sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, p: 1.5 }}>
      <Stack spacing={0.75}>
        <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
          <Typography variant="body2" sx={{ fontWeight: 720 }}>{pick(language, COPY.signature)}</Typography>
          <StatusPill tone={words.tone} label={pick(language, words.label)} />
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>{pick(language, words.body)}</Typography>
        {reason ? <Typography variant="body2" sx={{ lineHeight: 1.8 }}><b>{pick(language, COPY.why)}</b> {reason}</Typography> : null}
        {isAdvanced && ede?.length ? (
          <KeyValueList
            dense
            items={ede.map((item) => ({ label: `EDE ${item.code}`, value: item.text ? <Ltr mono>{item.text}</Ltr> : edeText(language, item) }))}
          />
        ) : null}
      </Stack>
    </Box>
  );
}

function zoneWord(language: "fa" | "en", zone: string | undefined) {
  const clean = (zone ?? "").replace(/\.$/, "");
  return clean ? clean : pick(language, COPY.rootZone);
}

/** The trace as a vertical list of steps, each with its level, server and what came back. */
export function TraceView({ steps, forwardMode }: { steps: TraceStep[]; forwardMode: boolean }) {
  const { language, isAdvanced } = useKit();
  const theme = useTheme();
  if (!steps.length) return <Typography variant="body2" color="text.secondary">{pick(language, COPY.traceEmpty)}</Typography>;
  return (
    <Stack spacing={0} component="ol" sx={{ m: 0, p: 0, listStyle: "none" }} aria-label={pick(language, COPY.traceTitle)}>
      {steps.map((step, index) => {
        const level = traceLevel(step, forwardMode);
        const Icon = LEVEL_ICONS[level];
        const failed = Boolean(step.error);
        const color = failed ? theme.palette.error.main : level === "validator" ? theme.palette.success.main : theme.palette.primary.main;
        const server = step.server_name ? step.server_name.replace(/\.$/, "") : step.server ?? "—";
        const sign = step.dnssec ? DNSSEC_STATUS_WORDS[step.dnssec] : undefined;
        const last = index === steps.length - 1;
        return (
          <Box component="li" key={`${step.step ?? index}-${index}`} sx={{ display: "flex", gap: 1.5 }}>
            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", flexShrink: 0 }}>
              <Box sx={{ width: 36, height: 36, borderRadius: "50%", display: "grid", placeItems: "center", bgcolor: alpha(color, 0.12), color }}>
                <Icon fontSize="small" aria-hidden />
              </Box>
              {!last ? <Box sx={{ flex: 1, width: 2, minHeight: 12, bgcolor: "divider", my: 0.5 }} /> : null}
            </Box>
            <Paper variant="outlined" sx={{ flex: 1, minWidth: 0, p: 1.25, mb: last ? 0 : 1 }}>
              <Stack spacing={0.5}>
                <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700 }}>{formatNumber(index + 1, language)}</Typography>
                  <StatusPill tone={failed ? "error" : level === "validator" ? "ok" : "info"} label={pick(language, TRACE_LEVEL_WORDS[level])} />
                  {level !== "validator" && level !== "root" ? <Typography variant="body2" sx={{ fontWeight: 700 }}><Ltr mono>{zoneWord(language, step.zone)}</Ltr></Typography> : null}
                  {typeof step.rtt_ms === "number" ? <Typography variant="caption" color="text.secondary">{say(language, COPY.ms, { ms: formatNumber(Math.round(step.rtt_ms), language) })}</Typography> : null}
                  {sign ? <StatusPill tone={sign.tone} label={pick(language, sign.label)} /> : null}
                </Stack>
                <Typography variant="body2" sx={{ lineHeight: 1.8, wordBreak: "break-word" }}>
                  {level === "validator"
                    ? say(language, COPY.stepCheck, { zone: zoneWord(language, step.zone) })
                    : say(language, COPY.stepAsked, { server, qname: (step.qname ?? "").replace(/\.$/, "") || "." })}
                </Typography>
                <Typography variant="body2" color={failed ? "error" : "text.secondary"} sx={{ lineHeight: 1.8, wordBreak: "break-word" }}>{traceOutcome(language, step)}</Typography>
                {isAdvanced ? (
                  <KeyValueList
                    dense
                    items={[
                      { label: pick(language, COPY.zone), value: step.zone || ".", ltr: true },
                      { label: pick(language, COPY.server), value: step.server || "—", ltr: true },
                      { label: pick(language, COPY.qtype), value: step.qtype || "—", ltr: true },
                      { label: pick(language, COPY.rcode), value: String(step.rcode ?? "—"), ltr: true },
                      ...(step.error ? [{ label: pick(language, COPY.error), value: <Ltr mono>{step.error}</Ltr> }] : [])
                    ]}
                  />
                ) : null}
              </Stack>
            </Paper>
          </Box>
        );
      })}
    </Stack>
  );
}

export const TRACE_COPY = COPY;
