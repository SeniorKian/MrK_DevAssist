/**
 * Domains of one service (docs/35): the «افزودن دامنه» wizard, the domain details dialog
 * (health: DNS, certificate, reachability; main domain; HTTPS; verify; remove) and the manual
 * Dokploy instructions. Used by ServicesPage.
 */
import { useEffect, useState, type ReactNode } from "react";
import {
  Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, Stack, Switch,
  TextField, Tooltip, Typography, useMediaQuery, useTheme
} from "@mui/material";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import StarRoundedIcon from "@mui/icons-material/StarRounded";
import FactCheckRoundedIcon from "@mui/icons-material/FactCheckRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import AutoModeRoundedIcon from "@mui/icons-material/AutoModeRounded";
import HubRoundedIcon from "@mui/icons-material/HubRounded";
import DescriptionRoundedIcon from "@mui/icons-material/DescriptionRounded";
import BackHandRoundedIcon from "@mui/icons-material/BackHandRounded";
import { ApiError, hasPermission } from "./api";
import { nameConfirmation, pick, reasonFor, say, type Bi } from "./copy";
import {
  ActionWizard, ChoiceCards, CopyField, FriendlyError, KeyValueList, Ltr, NoAccess, Notice, RelativeTime, StatusPill, useConfirmAction, useKit,
  type ChoiceCardOption, type WizardStep
} from "./kit";
import {
  ROUTING_MODE_WORDS, apiTime, createDomain, deleteDomain, domainHealthSummary, domainProblemText, effectiveMode, modeAvailable, routingModeWord,
  serviceName, updateDomain, verifyDomain,
  type CreateDomainResult, type DomainHealth, type DomainRecord, type ManualInstructions, type RoutingChoice, type RoutingDetected,
  type RoutingSummary, type ServiceDomainRef, type ServiceInfo
} from "./services";

const COPY = {
  // wizard
  wizardTitle: { fa: "افزودن دامنه به «{name}»", en: "Add a domain to “{name}”" },
  stepDomain: { fa: "دامنه", en: "Domain" },
  stepDomainHint: {
    fa: "آدرسی را بنویسید که می‌خواهید این سرویس با آن باز شود. اول در پنل ثبت دامنه، آن را به نشانی این سرور وصل کنید.",
    en: "Type the address this service should open on. First, point it to this server where you bought the domain."
  },
  domainLabel: { fa: "نام دامنه", en: "Domain name" },
  domainHelper: { fa: "مثل npm.example.com. حروف فارسی هم قبول است.", en: "Like npm.example.com. Non-Latin letters are fine too." },
  pointTo: { fa: "رکورد A این دامنه باید به {ips} اشاره کند.", en: "This domain's A record should point to {ips}." },
  stepRoute: { fa: "روش اتصال", en: "How it connects" },
  stepRouteHint: { fa: "MRK پورت ۸۰ و ۴۴۳ را نمی‌گیرد؛ دامنه از راه Dokploy به این سرویس می‌رسد.", en: "MRK never takes ports 80 and 443; the domain reaches this service through Dokploy." },
  chosenMode: { fa: "روشی که خودکار انتخاب شد: {mode}", en: "Picked automatically: {mode}" },
  changeModeAdvanced: { fa: "برای انتخاب روش دیگر، حالت پیشرفته را روشن کنید.", en: "Turn on Advanced mode to pick another way." },
  modeChoice: { fa: "روش اتصال این دامنه", en: "How this domain connects" },
  notAvailable: { fa: "روی این سرور در دسترس نیست", en: "Not available on this server" },
  makePrimary: { fa: "این دامنه، دامنه اصلی این سرویس باشد", en: "Make this the service's main domain" },
  primaryHint: { fa: "لینک‌ها و دستورهای اتصال با دامنه اصلی ساخته می‌شوند.", en: "Links and connection commands use the main domain." },
  useHttps: { fa: "اتصال امن (HTTPS) با گواهی رایگان", en: "Secure connection (HTTPS) with a free certificate" },
  addButton: { fa: "افزودن دامنه", en: "Add the domain" },
  stepResult: { fa: "نتیجه", en: "Result" },
  appliedAuto: { fa: "دامنه {host} خودکار وصل شد ({mode}).", en: "{host} was connected automatically ({mode})." },
  certWait: { fa: "گرفتن گواهی HTTPS ممکن است چند دقیقه طول بکشد. بعد «بررسی کن» را بزنید.", en: "The HTTPS certificate can take a few minutes. Then press “Check it”." },
  savedNotApplied: { fa: "دامنه ذخیره شد، ولی خودکار وصل نشد: {reason} آن را دستی در Dokploy ثبت کنید:", en: "The domain was saved but not connected automatically: {reason} Add it in Dokploy by hand:" },
  manualIntro: { fa: "دامنه ذخیره شد. حالا آن را در Dokploy ثبت کنید:", en: "The domain was saved. Now add it in Dokploy:" },
  // conflicts
  inUseDokploy: { fa: "این دامنه الان در Dokploy به برنامه «{name}» وصل است. اول آن را از آنجا بردارید یا دامنه دیگری بنویسید.", en: "This domain is attached to the Dokploy app “{name}”. Remove it there first, or use another domain." },
  inUseService: { fa: "این دامنه الان مال سرویس «{name}» در همین پنل است. اول آن را از آن سرویس بردارید.", en: "This domain already belongs to the service “{name}” in this panel. Remove it from that service first." },
  inUseOther: { fa: "این دامنه جای دیگری استفاده شده است. دامنه دیگری بنویسید.", en: "This domain is used somewhere else. Use another domain." },
  inUseThis: { fa: "این دامنه همین الان روی همین سرویس هست.", en: "This domain is already on this service." },
  // manual steps
  manualTitle: { fa: "ثبت دستی در Dokploy", en: "Add it in Dokploy by hand" },
  manualStep1: { fa: "Dokploy را باز کنید و به پروژه «{project}» بروید.", en: "Open Dokploy and go to the project “{project}”." },
  manualStep1Unknown: { fa: "Dokploy را باز کنید و به پروژه‌ای بروید که MRK در آن نصب است.", en: "Open Dokploy and go to the project MRK is installed in." },
  manualStep2: { fa: "سرویس «{service}» را باز کنید و به بخش «Domains» بروید.", en: "Open the service “{service}” and go to “Domains”." },
  manualStep2Unknown: { fa: "سرویس MRK را باز کنید و به بخش «Domains» بروید.", en: "Open the MRK service and go to “Domains”." },
  manualStep3: { fa: "یک دامنه تازه بسازید و سه مقدار زیر را در آن بگذارید. HTTPS را روشن کنید.", en: "Create a new domain with the three values below. Turn HTTPS on." },
  manualStep4: { fa: "ذخیره کنید و این‌جا «بررسی کن» را بزنید.", en: "Save, then press “Check it” here." },
  fieldHost: { fa: "دامنه", en: "Domain" },
  fieldService: { fa: "سرویس مقصد", en: "Target service" },
  fieldPort: { fa: "پورت", en: "Port" },
  // dialog
  verify: { fa: "بررسی کن", en: "Check it" },
  verifying: { fa: "در حال بررسی…", en: "Checking…" },
  verified: { fa: "بررسی شد.", en: "Checked." },
  makeMain: { fa: "دامنه اصلی شود", en: "Make main" },
  isMain: { fa: "دامنه اصلی", en: "Main domain" },
  remove: { fa: "برداشتن دامنه", en: "Remove domain" },
  removeTitle: { fa: "دامنه «{host}» برداشته شود؟", en: "Remove the domain “{host}”?" },
  removeBody: { fa: "این سرویس دیگر با این آدرس باز نمی‌شود. اگر دستی در Dokploy ثبت کرده‌اید، آن‌جا هم پاکش کنید.", en: "The service won't open on this address any more. If you added it in Dokploy by hand, remove it there too." },
  removeYes: { fa: "بله، بردار", en: "Yes, remove" },
  removed: { fa: "دامنه «{host}» برداشته شد.", en: "“{host}” was removed." },
  primarySaved: { fa: "«{host}» دامنه اصلی شد.", en: "“{host}” is now the main domain." },
  httpsSaved: { fa: "تنظیم HTTPS ذخیره شد.", en: "The HTTPS setting was saved." },
  allGood: { fa: "همه‌چیز درست است: DNS، گواهی و رسیدن به همین سرویس.", en: "Everything is fine: DNS, certificate, and it reaches this service." },
  notChecked: { fa: "این دامنه هنوز بررسی نشده. «بررسی کن» را بزنید.", en: "This domain hasn't been checked yet. Press “Check it”." },
  whatToDo: { fa: "چه کار کنید: {fix}", en: "What to do: {fix}" },
  dnsLabel: { fa: "DNS", en: "DNS" },
  dnsOk: { fa: "به این سرور اشاره می‌کند", en: "Points to this server" },
  dnsBad: { fa: "به این سرور اشاره نمی‌کند", en: "Doesn't point to this server" },
  dnsNow: { fa: "الان:", en: "Now:" },
  dnsExpected: { fa: "باید باشد:", en: "Should be:" },
  dnsNone: { fa: "هیچ نشانی‌ای", en: "no address" },
  tlsLabel: { fa: "گواهی HTTPS", en: "HTTPS certificate" },
  tlsOk: { fa: "معتبر", en: "Valid" },
  tlsBad: { fa: "مشکل دارد", en: "Has a problem" },
  tlsExpires: { fa: "تمام می‌شود:", en: "Expires:" },
  tlsIssuer: { fa: "صادرکننده:", en: "Issuer:" },
  reachLabel: { fa: "رسیدن به سرویس", en: "Reaches the service" },
  reachOk: { fa: "به همین سرویس می‌رسد", en: "Reaches this service" },
  reachBad: { fa: "به این سرویس نمی‌رسد", en: "Doesn't reach this service" },
  reachCode: { fa: "پاسخ سرور: {code}", en: "Server answer: {code}" },
  checkedAt: { fa: "آخرین بررسی", en: "Last checked" },
  modeLabel: { fa: "روش اتصال", en: "How it connects" },
  createdAt: { fa: "اضافه شده", en: "Added" },
  dokployId: { fa: "شناسه در Dokploy", en: "Dokploy id" },
  httpsSwitch: { fa: "اتصال امن (HTTPS)", en: "Secure connection (HTTPS)" },
  unknownValue: { fa: "نامشخص", en: "Unknown" },
  noWrite: { fa: "دامنه‌ها را فقط می‌بینید.", en: "You can only look at domains." },
  // chips
  domainsLabel: { fa: "دامنه‌های «{name}»", en: "Domains of “{name}”" },
  primaryChip: { fa: "اصلی", en: "Main" }
} satisfies Record<string, Bi>;

// ── helpers ──────────────────────────────────────────────────────────────────

const HOST_LABEL = /^[\p{L}\p{N}](?:[\p{L}\p{N}\p{M}-]*[\p{L}\p{N}\p{M}])?$/u;

const HOST_PROBLEMS = {
  empty: { fa: "نام دامنه را بنویسید؛ مثل npm.example.com", en: "Type a domain name, like npm.example.com" },
  port: { fa: "فقط نام دامنه را بنویسید، بدون پورت.", en: "Type only the domain name, without a port." },
  ip: { fa: "نشانی IP قبول نیست؛ یک نام دامنه بنویسید.", en: "An IP address won't work here; type a domain name." },
  shape: { fa: "دامنه باید مثل npm.example.com باشد: چند بخش با نقطه، فقط حرف، عدد و خط تیره.", en: "A domain looks like npm.example.com: parts separated by dots, using letters, digits and hyphens." },
  wildcard: { fa: "دامنه ستاره‌دار پشتیبانی نمی‌شود؛ هر دامنه را جدا اضافه کنید.", en: "Wildcard domains aren't supported; add each domain separately." },
  long: { fa: "این دامنه بیش از حد بلند است.", en: "This domain is too long." }
} satisfies Record<string, Bi>;

/**
 * Check a typed domain on the client (docs/35 `invalid_host` on the server stays the final word).
 * Accepts Unicode (IDNA) names and returns the ASCII (punycode) form to send.
 */
export function checkDomainInput(raw: string): { ascii: string; display: string } | { problem: keyof typeof HOST_PROBLEMS } {
  let value = raw.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  value = value.split(/[/?#]/)[0].replace(/\.$/, "");
  if (!value) return { problem: "empty" };
  if (value.startsWith("*")) return { problem: "wildcard" };
  if (value.includes(":") || value.includes("[")) return { problem: value.includes("[") || /^[0-9a-f:]+$/.test(value) ? "ip" : "port" };
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return { problem: "ip" };
  const labels = value.split(".");
  if (labels.length < 2 || labels.some((label) => !label || label.length > 63 || !HOST_LABEL.test(label))) return { problem: "shape" };
  let ascii = value;
  try {
    ascii = new URL(`http://${value}`).hostname;
  } catch {
    return { problem: "shape" };
  }
  if (ascii.length > 253) return { problem: "long" };
  if (/^\d+$/.test(ascii.split(".").pop() ?? "")) return { problem: "ip" };
  return { ascii, display: value };
}

type Owner = { kind: "dokploy" | "service" | "other"; name: string };

function readOwner(error: ApiError): Owner | null {
  const raw = error.extra.owner ?? error.extra.conflict ?? null;
  if (!raw) return { kind: "other", name: "" };
  if (typeof raw === "string") return { kind: raw.toLowerCase().includes("dokploy") ? "dokploy" : "other", name: "" };
  if (typeof raw !== "object") return { kind: "other", name: "" };
  const item = raw as Record<string, unknown>;
  const kind = String(item.kind ?? item.type ?? item.source ?? "").toLowerCase();
  const name = String(item.name ?? item.app_name ?? item.application ?? item.app ?? item.service_name ?? item.service ?? item.service_id ?? "");
  if (kind.includes("dokploy")) return { kind: "dokploy", name };
  if (kind.includes("mrk") || kind.includes("service") || item.service_id) return { kind: "service", name };
  return { kind: "other", name };
}

function ownerSentence(language: "fa" | "en", owner: Owner, services: ServiceInfo[], currentId: string): string {
  if (owner.kind === "service") {
    const match = services.find((service) => service.id === owner.name);
    if (match?.id === currentId) return pick(language, COPY.inUseThis);
    const name = match ? serviceName(language, match) : owner.name;
    return name ? say(language, COPY.inUseService, { name }) : pick(language, COPY.inUseOther);
  }
  if (owner.kind === "dokploy") return say(language, COPY.inUseDokploy, { name: owner.name || "؟" });
  return pick(language, COPY.inUseOther);
}

function ipsText(language: "fa" | "en", detected: RoutingDetected | null | undefined): string | null {
  const ips = (detected?.server_ips ?? []).filter(Boolean);
  return ips.length ? ips.join(language === "fa" ? "، " : ", ") : null;
}

const MODE_ICONS = { auto: AutoModeRoundedIcon, dokploy_api: HubRoundedIcon, traefik_file: DescriptionRoundedIcon, manual: BackHandRoundedIcon };

// ── manual instructions ──────────────────────────────────────────────────────

export function ManualSteps({ host, port, instructions, detected }: {
  host: string;
  port?: number | null;
  instructions?: ManualInstructions | null;
  detected?: RoutingDetected | null;
}) {
  const { language } = useKit();
  const dokploy = instructions?.dokploy ?? {};
  const project = dokploy.project ?? detected?.dokploy_project ?? null;
  const service = dokploy.service ?? detected?.dokploy_service ?? null;
  const finalPort = dokploy.port ?? port ?? null;
  const finalHost = dokploy.host ?? host;
  const fromServer = language === "fa" ? instructions?.steps_fa : instructions?.steps_en;
  const steps = fromServer?.length
    ? fromServer
    : [
        project ? say(language, COPY.manualStep1, { project }) : pick(language, COPY.manualStep1Unknown),
        service ? say(language, COPY.manualStep2, { service }) : pick(language, COPY.manualStep2Unknown),
        pick(language, COPY.manualStep3),
        pick(language, COPY.manualStep4)
      ];
  return (
    <Stack spacing={1.5}>
      <Typography variant="subtitle2" sx={{ fontWeight: 760 }}>{pick(language, COPY.manualTitle)}</Typography>
      <Box component="ol" sx={{ m: 0, pl: 3, pr: 3, display: "grid", gap: 0.75 }}>
        {steps.map((step, index) => (
          <Typography key={index} component="li" variant="body2" sx={{ lineHeight: 1.9 }}>{step}</Typography>
        ))}
      </Box>
      <CopyField label={pick(language, COPY.fieldHost)} value={finalHost} />
      {service ? <CopyField label={pick(language, COPY.fieldService)} value={service} /> : null}
      {finalPort ? <CopyField label={pick(language, COPY.fieldPort)} value={String(finalPort)} /> : null}
    </Stack>
  );
}

// ── health details ───────────────────────────────────────────────────────────

function listOrNone(language: "fa" | "en", values: string[] | null | undefined) {
  const list = (values ?? []).filter(Boolean);
  return list.length ? <Ltr mono>{list.join(", ")}</Ltr> : <>{pick(language, COPY.dnsNone)}</>;
}

function okPill(ok: boolean | null | undefined, good: string, bad: string, unknown: string) {
  if (ok === true) return <StatusPill tone="ok" label={good} />;
  if (ok === false) return <StatusPill tone="error" label={bad} />;
  return <StatusPill tone="off" label={unknown} />;
}

/** «What's wrong + what to do» for a domain, then (Advanced) the DNS / certificate / reachability rows. */
export function DomainHealthDetails({ health, port, detected }: { health?: DomainHealth | null; port?: number | null; detected?: RoutingDetected | null }) {
  const { language } = useKit();
  const summary = domainHealthSummary(language, health ?? null);
  const unknown = pick(language, COPY.unknownValue);
  let message: ReactNode;
  if (summary.tone === "off") message = <Notice>{pick(language, COPY.notChecked)}</Notice>;
  else if (summary.tone === "ok") message = <Notice tone="success">{pick(language, COPY.allGood)}</Notice>;
  else {
    const problem = domainProblemText(language, summary.problem ?? health?.problem_code ?? null, { health, port, expectedIps: detected?.server_ips });
    message = (
      <Notice tone={problem.tone === "warn" ? "warning" : "error"}>
        <Typography variant="body2" sx={{ fontWeight: 700 }}>{problem.title}</Typography>
        <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{say(language, COPY.whatToDo, { fix: problem.fix })}</Typography>
      </Notice>
    );
  }
  const dns = health?.dns;
  const tls = health?.tls;
  const reach = health?.reach;
  return (
    <Stack spacing={1.5}>
      {message}
      {health ? (
        <KeyValueList
          dense
          items={[
            {
              label: pick(language, COPY.dnsLabel),
              advancedOnly: true,
              value: (
                <Stack spacing={0.5}>
                  {okPill(dns?.ok, pick(language, COPY.dnsOk), pick(language, COPY.dnsBad), unknown)}
                  <Typography variant="caption" color="text.secondary">{pick(language, COPY.dnsNow)} {listOrNone(language, dns?.addresses)}</Typography>
                  {(dns?.expected?.length || detected?.server_ips?.length) ? (
                    <Typography variant="caption" color="text.secondary">
                      {pick(language, COPY.dnsExpected)}{" "}
                      {listOrNone(language, dns?.expected?.length ? dns.expected : detected?.server_ips)}
                    </Typography>
                  ) : null}
                </Stack>
              )
            },
            {
              label: pick(language, COPY.tlsLabel),
              advancedOnly: true,
              value: (
                <Stack spacing={0.5}>
                  {okPill(tls?.ok, pick(language, COPY.tlsOk), pick(language, COPY.tlsBad), unknown)}
                  {tls?.expires_at ? (
                    <Typography variant="caption" color="text.secondary">
                      {pick(language, COPY.tlsExpires)}{" "}
                      <RelativeTime value={apiTime(tls.expires_at)} />
                    </Typography>
                  ) : null}
                  {tls?.issuer ? <Typography variant="caption" color="text.secondary">{pick(language, COPY.tlsIssuer)} <Ltr>{tls.issuer}</Ltr></Typography> : null}
                </Stack>
              )
            },
            {
              label: pick(language, COPY.reachLabel),
              advancedOnly: true,
              value: (
                <Stack spacing={0.5}>
                  {okPill(reach?.ok, pick(language, COPY.reachOk), pick(language, COPY.reachBad), unknown)}
                  {typeof reach?.status_code === "number" ? (
                    <Typography variant="caption" color="text.secondary">{say(language, COPY.reachCode, { code: String(reach.status_code) })}</Typography>
                  ) : null}
                </Stack>
              )
            },
            ...(health.checked_at ? [{ label: pick(language, COPY.checkedAt), value: <RelativeTime value={apiTime(health.checked_at)} /> }] : [])
          ]}
        />
      ) : null}
    </Stack>
  );
}

// ── chips ────────────────────────────────────────────────────────────────────

const DOT: Record<string, string> = { ok: "success.main", warn: "warning.main", error: "error.main", off: "text.disabled" };

export function DomainChips({ service, domains, onOpen }: { service: ServiceInfo; domains: (ServiceDomainRef | DomainRecord)[]; onOpen?: (id: string) => void }) {
  const { language } = useKit();
  if (!domains.length) return null;
  return (
    <Stack direction="row" useFlexGap flexWrap="wrap" gap={1} aria-label={say(language, COPY.domainsLabel, { name: serviceName(language, service) })} role="list">
      {domains.map((domain) => {
        const summary = domainHealthSummary(language, domain.health ?? null);
        return (
          <Tooltip key={domain.id} title={domain.primary ? `${summary.label} · ${pick(language, COPY.primaryChip)}` : summary.label}>
            <Chip
              role="listitem"
              variant="outlined"
              onClick={onOpen ? () => onOpen(domain.id) : undefined}
              icon={
                domain.primary ? (
                  <StarRoundedIcon sx={{ color: `${DOT[summary.tone]} !important`, fontSize: 18 }} aria-hidden />
                ) : (
                  <Box component="span" aria-hidden sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: DOT[summary.tone], ml: 1, mr: 0.25, flexShrink: 0 }} />
                )
              }
              label={
                <Box component="span" sx={{ display: "inline-flex", gap: 0.75, alignItems: "center", maxWidth: { xs: 220, sm: 320 } }}>
                  <Ltr>{domain.host}</Ltr>
                  <Box component="span" sx={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0 0 0 0)" }}>{summary.label}</Box>
                </Box>
              }
              sx={{ minHeight: 36, maxWidth: "100%" }}
            />
          </Tooltip>
        );
      })}
    </Stack>
  );
}

// ── add-domain wizard ────────────────────────────────────────────────────────

export type AddDomainWizardProps = {
  service: ServiceInfo;
  services: ServiceInfo[];
  routing: RoutingSummary | null;
  availableModes?: string[] | null;
  onClose: () => void;
  /** Called after the domain was created or checked, so the page reloads. */
  onChanged: () => void;
};

export function AddDomainWizard({ service, services, routing, availableModes, onClose, onChanged }: AddDomainWizardProps) {
  const { language, isAdvanced, c } = useKit();
  const [input, setInput] = useState("");
  const [touched, setTouched] = useState(false);
  const hasDomains = (service.domains?.length ?? 0) > 0;
  const [primary, setPrimary] = useState(!hasDomains);
  const [https, setHttps] = useState(true);
  const [mode, setMode] = useState<RoutingChoice>("auto");
  const [owner, setOwner] = useState<Owner | null>(null);
  const [result, setResult] = useState<{ host: string; data: CreateDomainResult } | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<unknown>(null);
  const [checked, setChecked] = useState<DomainHealth | null>(null);

  const checkedInput = checkDomainInput(input);
  const problem = "problem" in checkedInput ? pick(language, HOST_PROBLEMS[checkedInput.problem]) : null;
  const detected = routing?.detected ?? null;
  const autoMode = effectiveMode(routing);
  const plannedMode = mode === "auto" ? autoMode : mode;
  const ips = ipsText(language, detected);
  const name = serviceName(language, service);

  const modeOptions: ChoiceCardOption<RoutingChoice>[] = (["auto", "dokploy_api", "traefik_file", "manual"] as RoutingChoice[]).map((key) => {
    const available = modeAvailable(key, detected, availableModes);
    return {
      key,
      icon: MODE_ICONS[key],
      title: key === "auto" ? `${pick(language, ROUTING_MODE_WORDS.auto.label)} (${routingModeWord(language, autoMode)})` : pick(language, ROUTING_MODE_WORDS[key].label),
      body: pick(language, ROUTING_MODE_WORDS[key].body),
      disabled: !available,
      badges: available ? undefined : <StatusPill tone="off" label={pick(language, COPY.notAvailable)} />
    };
  });

  const submit = async () => {
    if ("problem" in checkedInput) throw new Error(problem ?? "");
    if (result && result.host === checkedInput.ascii) return;
    setOwner(null);
    try {
      const data = await createDomain({
        service_id: String(service.id),
        host: checkedInput.ascii,
        https,
        primary: primary || undefined,
        mode
      });
      setResult({ host: checkedInput.ascii, data: data ?? {} });
      setChecked(data?.domain?.health ?? null);
      onChanged();
    } catch (error) {
      if (error instanceof ApiError && error.code === "domain_in_use") setOwner(readOwner(error));
      throw error;
    }
  };

  const verify = async () => {
    const id = result?.data.domain?.id;
    if (!id) return;
    setVerifying(true);
    setVerifyError(null);
    try {
      const response = await verifyDomain(id);
      const record = response && "domain" in response && response.domain ? response.domain : (response as DomainRecord | null);
      const health = (response && "health" in response ? (response.health as DomainHealth | undefined) : undefined) ?? record?.health ?? null;
      setChecked(health);
      onChanged();
    } catch (error) {
      setVerifyError(error);
    } finally {
      setVerifying(false);
    }
  };

  const applied = result?.data.applied ?? null;
  const appliedMode = (applied?.mode ?? result?.data.domain?.mode ?? plannedMode) as string;
  const isManual = appliedMode === "manual";
  const appliedOk = applied?.ok !== false;

  const steps: WizardStep[] = [
    {
      key: "domain",
      title: pick(language, COPY.stepDomain),
      hint: pick(language, COPY.stepDomainHint),
      validate: () => problem,
      render: () => (
        <Stack spacing={1.5}>
          <TextField
            autoFocus
            fullWidth
            label={pick(language, COPY.domainLabel)}
            value={input}
            onChange={(event) => {
              setInput(event.target.value);
              setOwner(null);
              setResult(null);
            }}
            onBlur={() => setTouched(true)}
            error={touched && Boolean(problem) && input.trim() !== ""}
            helperText={touched && problem && input.trim() !== "" ? problem : pick(language, COPY.domainHelper)}
            slotProps={{ htmlInput: { dir: "ltr", inputMode: "url", autoCapitalize: "none", autoCorrect: "off", spellCheck: false } }}
          />
          {ips ? <Notice>{say(language, COPY.pointTo, { ips })}</Notice> : null}
        </Stack>
      )
    },
    {
      key: "route",
      title: pick(language, COPY.stepRoute),
      hint: pick(language, COPY.stepRouteHint),
      nextLabel: pick(language, COPY.addButton),
      onNext: submit,
      render: () => (
        <Stack spacing={1.5}>
          {!isAdvanced ? (
            <>
              <Notice tone={autoMode === "manual" ? "warning" : "info"}>
                <Typography variant="body2" sx={{ fontWeight: 700 }}>{say(language, COPY.chosenMode, { mode: routingModeWord(language, autoMode) })}</Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{pick(language, ROUTING_MODE_WORDS[autoMode].body)}</Typography>
              </Notice>
              <Typography variant="caption" color="text.secondary">{pick(language, COPY.changeModeAdvanced)}</Typography>
            </>
          ) : (
            <ChoiceCards options={modeOptions} value={mode} onChange={setMode} label={pick(language, COPY.modeChoice)} />
          )}
          {hasDomains ? (
            <Box>
              <FormControlLabel control={<Switch checked={primary} onChange={(event) => setPrimary(event.target.checked)} />} label={pick(language, COPY.makePrimary)} />
              <Typography variant="caption" color="text.secondary" component="p">{pick(language, COPY.primaryHint)}</Typography>
            </Box>
          ) : null}
          {isAdvanced ? (
            <FormControlLabel control={<Switch checked={https} onChange={(event) => setHttps(event.target.checked)} />} label={pick(language, COPY.useHttps)} />
          ) : null}
          {owner ? <Notice tone="warning">{ownerSentence(language, owner, services, String(service.id))}</Notice> : null}
        </Stack>
      )
    },
    {
      key: "result",
      title: pick(language, COPY.stepResult),
      render: () => {
        const host = result?.data.domain?.host ?? result?.host ?? "";
        return (
          <Stack spacing={2}>
            {!isManual && appliedOk ? (
              <Notice tone="success">
                <Typography variant="body2" sx={{ fontWeight: 700 }}>{say(language, COPY.appliedAuto, { host, mode: routingModeWord(language, appliedMode) })}</Typography>
                {https ? <Typography variant="body2">{pick(language, COPY.certWait)}</Typography> : null}
              </Notice>
            ) : (
              <>
                <Notice tone={isManual ? "info" : "warning"}>
                  {isManual
                    ? pick(language, COPY.manualIntro)
                    : say(language, COPY.savedNotApplied, { reason: reasonFor(language, applied?.error_code ?? "", "domains") })}
                </Notice>
                <ManualSteps host={host} port={service.internal_port} instructions={result?.data.instructions} detected={detected} />
              </>
            )}
            {ips ? <Typography variant="body2" color="text.secondary">{say(language, COPY.pointTo, { ips })}</Typography> : null}
            {result?.data.domain?.id ? (
              <Box>
                <Button
                  variant="outlined"
                  onClick={() => void verify()}
                  disabled={verifying}
                  startIcon={verifying ? <CircularProgress size={16} /> : <FactCheckRoundedIcon />}
                  sx={{ minHeight: 44 }}
                >
                  {verifying ? pick(language, COPY.verifying) : pick(language, COPY.verify)}
                </Button>
              </Box>
            ) : null}
            {verifyError !== null ? <FriendlyError error={verifyError} scope="domains" onRetry={() => void verify()} /> : null}
            {checked ? <DomainHealthDetails health={checked} port={service.internal_port} detected={detected} /> : null}
          </Stack>
        );
      }
    }
  ];

  return (
    <ActionWizard
      open
      title={say(language, COPY.wizardTitle, { name })}
      steps={steps}
      onFinish={() => undefined}
      onClose={onClose}
      finishLabel={c.finish}
    />
  );
}

// ── domain details dialog ────────────────────────────────────────────────────

export type DomainDialogProps = {
  domain: DomainRecord;
  service: ServiceInfo | null;
  detected?: RoutingDetected | null;
  permissions: readonly string[];
  onClose: () => void;
  onChanged: () => void;
  notify: (message: string, tone?: "success" | "error" | "info") => void;
};

export function DomainDialog({ domain, service, detected, permissions, onClose, onChanged, notify }: DomainDialogProps) {
  const { language, isAdvanced, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const { ask, dialog } = useConfirmAction();
  const [busy, setBusy] = useState<"verify" | "primary" | "https" | "delete" | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [health, setHealth] = useState<DomainHealth | null>(domain.health ?? null);
  // A fresh list (polling, another change) brings newer health; show it.
  useEffect(() => {
    if (domain.health) setHealth(domain.health);
  }, [domain.health]);
  const canWrite = hasPermission(permissions, "domains:write");
  const summary = domainHealthSummary(language, health);
  const port = service?.internal_port ?? null;

  const run = async (kind: NonNullable<typeof busy>, work: () => Promise<void>) => {
    setBusy(kind);
    setError(null);
    try {
      await work();
      onChanged();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(null);
    }
  };

  const verify = () =>
    run("verify", async () => {
      const response = await verifyDomain(domain.id);
      const record = response && "domain" in response && response.domain ? response.domain : (response as DomainRecord | null);
      const next = (response && "health" in response ? (response.health as DomainHealth | undefined) : undefined) ?? record?.health ?? null;
      if (next) setHealth(next);
      notify(pick(language, COPY.verified), "info");
    });

  const makePrimary = () =>
    run("primary", async () => {
      await updateDomain(domain.id, { primary: true });
      notify(say(language, COPY.primarySaved, { host: domain.host }));
    });

  const toggleHttps = (value: boolean) =>
    run("https", async () => {
      await updateDomain(domain.id, { https: value });
      notify(pick(language, COPY.httpsSaved));
    });

  const remove = async () => {
    const confirmed = await ask({
      title: say(language, COPY.removeTitle, { host: domain.host }),
      body: pick(language, COPY.removeBody),
      severity: "destructive",
      typed: nameConfirmation(domain.host, domain.host),
      confirmLabel: pick(language, COPY.removeYes)
    });
    if (!confirmed) return;
    setBusy("delete");
    setError(null);
    try {
      await deleteDomain(domain.id, domain.host);
      notify(say(language, COPY.removed, { host: domain.host }));
      onChanged();
      onClose();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onClose} fullWidth maxWidth="sm" fullScreen={fullScreen} aria-labelledby="mrk-domain-title">
      <DialogTitle id="mrk-domain-title" sx={{ display: "flex", alignItems: "center", gap: 1, pr: 1 }}>
        <Box sx={{ flex: 1, minWidth: 0, fontWeight: 760, overflowWrap: "anywhere" }}><Ltr>{domain.host}</Ltr></Box>
        <IconButton onClick={onClose} disabled={Boolean(busy)} aria-label={c.closeDialog} sx={{ width: 44, height: 44 }}>
          <CloseRoundedIcon />
        </IconButton>
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" alignItems="center">
            <StatusPill tone={summary.tone} label={summary.label} />
            {domain.primary ? <StatusPill tone="info" label={pick(language, COPY.isMain)} /> : null}
            {service ? <Typography variant="body2" color="text.secondary">{serviceName(language, service)}</Typography> : null}
          </Stack>
          <DomainHealthDetails health={health} port={port} detected={detected} />
          {error !== null ? <FriendlyError error={error} scope="domains" onRetry={() => setError(null)} /> : null}
          {domain.mode === "manual" && summary.tone !== "ok" ? <ManualSteps host={domain.host} port={port} detected={detected} /> : null}
          {isAdvanced ? (
            <KeyValueList
              dense
              items={[
                { label: pick(language, COPY.modeLabel), value: routingModeWord(language, domain.mode) },
                ...(domain.created_at ? [{ label: pick(language, COPY.createdAt), value: <RelativeTime value={apiTime(domain.created_at)} /> }] : []),
                ...(domain.dokploy_domain_id ? [{ label: pick(language, COPY.dokployId), value: domain.dokploy_domain_id, ltr: true, copy: true }] : [])
              ]}
            />
          ) : null}
          {isAdvanced && canWrite ? (
            <FormControlLabel
              control={<Switch checked={domain.https !== false} disabled={busy !== null} onChange={(event) => void toggleHttps(event.target.checked)} />}
              label={pick(language, COPY.httpsSwitch)}
            />
          ) : null}
          {!canWrite ? <NoAccess needs="domains:write" /> : null}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2, gap: 1, flexWrap: "wrap" }}>
        {canWrite ? (
          <Button color="error" onClick={() => void remove()} disabled={busy !== null} startIcon={busy === "delete" ? <CircularProgress size={16} /> : <DeleteOutlineRoundedIcon />} sx={{ minHeight: 44 }}>
            {pick(language, COPY.remove)}
          </Button>
        ) : null}
        <Box sx={{ flex: 1 }} />
        {canWrite && !domain.primary ? (
          <Button onClick={() => void makePrimary()} disabled={busy !== null} startIcon={busy === "primary" ? <CircularProgress size={16} /> : <StarRoundedIcon />} sx={{ minHeight: 44 }}>
            {pick(language, COPY.makeMain)}
          </Button>
        ) : null}
        {canWrite ? (
          <Button variant="contained" onClick={() => void verify()} disabled={busy !== null} startIcon={busy === "verify" ? <CircularProgress size={16} color="inherit" /> : <FactCheckRoundedIcon />} sx={{ minHeight: 44 }}>
            {busy === "verify" ? pick(language, COPY.verifying) : pick(language, COPY.verify)}
          </Button>
        ) : null}
      </DialogActions>
      {dialog}
    </Dialog>
  );
}
