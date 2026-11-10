/**
 * «سرویس‌های من» / My services (docs/35). One card per service: its status in plain words,
 * start/stop/restart when allowed, the domains attached to it (with a health dot) and «افزودن دامنه».
 * Advanced adds the public address, the internal port, usage tiles and «مسیریابی دامنه».
 *
 * Data: `GET /api/v1/services` (services:read) and `GET /api/v1/domains` (domains:read), refreshed
 * every 10 s while the tab is visible and right after every change.
 * Hash query: `?add=<service id>` opens the wizard, `?domain=<id>` opens a domain, `?routing=1` scrolls to routing.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Box, Button, CircularProgress, Grid, Skeleton, Stack, Typography } from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import AppsRoundedIcon from "@mui/icons-material/AppsRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import StopRoundedIcon from "@mui/icons-material/StopRounded";
import RestartAltRoundedIcon from "@mui/icons-material/RestartAltRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import DashboardRoundedIcon from "@mui/icons-material/DashboardRounded";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import FolderRoundedIcon from "@mui/icons-material/FolderRounded";
import SupportAgentRoundedIcon from "@mui/icons-material/SupportAgentRounded";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import NumbersRoundedIcon from "@mui/icons-material/NumbersRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import TrendingUpRoundedIcon from "@mui/icons-material/TrendingUpRounded";
import TravelExploreRoundedIcon from "@mui/icons-material/TravelExploreRounded";
import { ApiError, hasPermission, isAbortError } from "./api";
import { errorSentence, nameConfirmation, persianDigits, pick, say, type Bi } from "./copy";
import {
  CopyField, EmptyState, FriendlyError, Ltr, NoAccess, PageHeader, RelativeTime, SectionCard, StatGrid, StatTile, StatusPill,
  GroupTabs, Notice, formatSize, useConfirmAction, useKit, useUndoSnackbar
} from "./kit";
import { findGroup, hashQuery, visibleTabs } from "./nav";
import { AddServicePanel } from "./AddServicePanel";
import { TabBody, useHashTab } from "./ServerPage";
import { useVisibleInterval } from "./polling";
import type { GroupPageProps } from "./ServerPage";
import { AddDomainWizard, DomainChips, DomainDialog } from "./ServiceDomains";
import { DomainRouting } from "./DomainRouting";
import {
  ACTION_WORDS, SERVICE_ACTIONS, apiTime, resetServices, fetchDomains, fetchServices, runServiceAction, serviceDescription, serviceName, serviceStateText,
  type DomainRecord, type RoutingInfo, type ServiceAction, type ServiceInfo, type ServicesPayload
} from "./services";

const COPY = {
  title: { fa: "سرویس‌های من", en: "My services" },
  subtitle: {
    fa: "هر سرویس جدا: روشن است یا نه، با چه دامنه‌ای باز می‌شود و چقدر جا گرفته.",
    en: "Each service on its own: is it running, which domain opens it, and how much space it uses."
  },
  empty: { fa: "هنوز سرویسی گزارش نشده", en: "No services reported yet" },
  emptyBody: { fa: "این نسخه از سرور فهرست سرویس‌ها را نمی‌دهد. بعد از به‌روزرسانی DevAssist دوباره سر بزنید.", en: "This server version doesn't list its services. Come back after updating DevAssist." },
  loadFailed: { fa: "فهرست سرویس‌ها باز نشد.", en: "The service list didn't load." },
  domainsFailed: { fa: "جزئیات سلامت دامنه‌ها باز نشد؛ فقط فهرست آن‌ها را می‌بینید.", en: "Domain health details didn't load; you only see the list." },
  port: { fa: "این سرویس روی پورت {port} داخل سرور است.", en: "This service listens on port {port} inside the server." },
  publicUrl: { fa: "آدرس عمومی", en: "Public address" },
  noPublicUrl: { fa: "هنوز دامنه‌ای ندارد؛ فقط از داخل سرور در دسترس است.", en: "No domain yet; it's only reachable from inside the server." },
  domains: { fa: "دامنه‌ها", en: "Domains" },
  noDomains: { fa: "هنوز دامنه‌ای به این سرویس وصل نیست.", en: "No domain is attached to this service yet." },
  addDomain: { fa: "افزودن دامنه", en: "Add a domain" },
  manage: { fa: "مدیریت", en: "Manage" },
  disk: { fa: "فضای مصرف‌شده", en: "Space used" },
  items: { fa: "تعداد موارد", en: "Items" },
  itemsPackages: { fa: "بسته‌های ذخیره‌شده", en: "Stored packages" },
  itemsFiles: { fa: "فایل‌ها", en: "Files" },
  itemsBlocked: { fa: "نشانی‌های مسدود", en: "Blocked addresses" },
  itemsNames: { fa: "نام‌ها و دامنه‌ها", en: "Names and domains" },
  itemsContainers: { fa: "کانتینرها", en: "Containers" },
  lastActivity: { fa: "آخرین فعالیت", en: "Last activity" },
  nextRetry: { fa: "تلاش بعدی برای روشن کردن:", en: "Next automatic try:" },
  retries: { fa: "تلاش‌های خودکار تا الان:", en: "Automatic tries so far:" },
  crashDetail: { fa: "جزئیات فنی:", en: "Technical detail:" },
  requests: { fa: "درخواست در ۲۴ ساعت گذشته", en: "Requests in the last 24 hours" },
  technicalId: { fa: "شناسه فنی", en: "Technical id" },
  statusOnly: { fa: "این سرویس از پنل روشن و خاموش نمی‌شود؛ فقط وضعیتش را می‌بینید.", en: "This service can't be started or stopped from the panel; you only see its status." },
  stopTitle: { fa: "«{name}» خاموش شود؟", en: "Stop “{name}”?" },
  stopBody: { fa: "تا وقتی دوباره روشنش نکنید، به برنامه‌ها و پروژه‌ها جواب نمی‌دهد.", en: "Until you start it again, it won't answer your apps and projects." },
  stopYes: { fa: "بله، خاموش کن", en: "Yes, stop it" },
  restartTitle: { fa: "«{name}» دوباره راه‌اندازی شود؟", en: "Restart “{name}”?" },
  restartBody: { fa: "چند ثانیه جواب نمی‌دهد و بعد خودش برمی‌گردد.", en: "It stops answering for a few seconds, then comes back by itself." },
  restartPanelBody: { fa: "پنل چند ثانیه قطع می‌شود؛ بعد این صفحه را تازه کنید.", en: "The panel goes away for a few seconds; then reload this page." },
  restartYes: { fa: "بله، دوباره راه‌اندازی کن", en: "Yes, restart" },
  actionFailed: { fa: "«{name}»: {reason}", en: "“{name}”: {reason}" },
  operateNeeded: { fa: "روشن و خاموش کردن", en: "Start and stop" },
  addService: { fa: "افزودن سرویس", en: "Add a service" },
  addTitle: { fa: "افزودن سرویس", en: "Add a service" },
  addSubtitle: {
    fa: "هر بخش DevAssist برنامه جدای خودش است؛ هر کدام را که لازم دارید با Dokploy، Coolify یا Docker Compose اضافه کنید.",
    en: "Each part of DevAssist is its own program; add the ones you need with Dokploy, Coolify or Docker Compose."
  },
  startHere: {
    fa: "پنل آماده است. حالا بخش‌هایی را که لازم دارید اضافه کنید؛ از «دستیار سرور» شروع کنید.",
    en: "The panel is ready. Now add the parts you need; start with the server agent."
  }
} satisfies Record<string, Bi>;

const SERVICE_ICONS: Record<string, SvgIconComponent> = {
  panel: DashboardRoundedIcon,
  npm: Inventory2RoundedIcon,
  pypi: Inventory2RoundedIcon,
  s3: FolderRoundedIcon,
  agent: SupportAgentRoundedIcon,
  firewall: ShieldRoundedIcon,
  dns: TravelExploreRoundedIcon
};

const ACTION_ICONS: Record<ServiceAction, SvgIconComponent> = { start: PlayArrowRoundedIcon, stop: StopRoundedIcon, restart: RestartAltRoundedIcon };

function itemsLabel(id: string): Bi {
  if (id === "npm" || id === "pypi") return COPY.itemsPackages;
  if (id === "s3") return COPY.itemsFiles;
  if (id === "firewall") return COPY.itemsBlocked;
  if (id === "agent") return COPY.itemsContainers;
  if (id === "dns") return COPY.itemsNames;
  return COPY.items;
}

/** Actions the card offers: allowed by the server, sensible for the current state. */
function visibleActions(service: ServiceInfo): ServiceAction[] {
  if (!service.controllable) return [];
  const allowed = new Set(service.actions ?? []);
  return SERVICE_ACTIONS.filter((action) => {
    if (!allowed.has(action)) return false;
    if (action === "start") return service.state !== "running" && service.state !== "starting" && service.state !== "degraded" && service.state !== "crashed";
    if (action === "stop") return service.state !== "stopped" && service.state !== "not_installed" && service.state !== "disabled";
    if (action === "restart") return service.state !== "stopped" && service.state !== "not_installed";
    return true;
  });
}

type CardProps = {
  service: ServiceInfo;
  domains: DomainRecord[];
  permissions: readonly string[];
  busyAction: ServiceAction | null;
  onAction: (service: ServiceInfo, action: ServiceAction) => void;
  onAddDomain: (service: ServiceInfo) => void;
  onOpenDomain: (id: string) => void;
};

function ServiceCard({ service, domains, permissions, busyAction, onAction, onAddDomain, onOpenDomain }: CardProps) {
  const { language, isAdvanced } = useKit();
  const name = serviceName(language, service);
  const state = serviceStateText(language, service);
  const Icon = SERVICE_ICONS[service.id] ?? AppsRoundedIcon;
  const canOperate = hasPermission(permissions, "services:operate");
  const canReadDomains = hasPermission(permissions, "domains:read");
  const canWriteDomains = hasPermission(permissions, "domains:write");
  const actions = visibleActions(service);
  // Prefer the full domain records (richer health); fall back to what the services list carries.
  const byId = new Map(domains.map((domain) => [domain.id, domain]));
  const refs = service.domains ?? [];
  const chips = refs.length ? refs.map((ref) => byId.get(ref.id) ?? ref) : domains;
  const sortedChips = [...chips].sort((a, b) => Number(Boolean(b.primary)) - Number(Boolean(a.primary)));
  const usage = service.usage ?? {};
  const manage = service.manage_route && service.manage_route.startsWith("#") ? service.manage_route : null;
  const domainsSupported = service.id !== "agent" && service.id !== "firewall" && service.id !== "dns";
  const notInstalled = service.state === "not_installed";

  const tiles = [
    typeof usage.disk_bytes === "number"
      ? <StatTile key="disk" label={pick(language, COPY.disk)} icon={StorageRoundedIcon} value={formatSize(usage.disk_bytes, language)} />
      : null,
    typeof usage.items === "number"
      ? <StatTile key="items" label={pick(language, itemsLabel(String(service.id)))} icon={NumbersRoundedIcon} value={new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(usage.items)} />
      : null,
    typeof usage.requests_24h === "number"
      ? <StatTile key="requests" label={pick(language, COPY.requests)} icon={TrendingUpRoundedIcon} value={new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(usage.requests_24h)} />
      : null,
    usage.last_activity_at
      ? <StatTile key="last" label={pick(language, COPY.lastActivity)} icon={HistoryRoundedIcon} value={<RelativeTime value={apiTime(usage.last_activity_at)} relativeAlways />} />
      : null
  ].filter(Boolean);

  return (
    <SectionCard
      title={name}
      hint={serviceDescription(language, service) || undefined}
      status={<StatusPill tone={state.tone} label={state.label} />}
      action={<Icon color="action" aria-hidden />}
    >
      <Stack spacing={2} id={`mrk-service-${service.id}`}>
        <Typography variant="body2" color={state.tone === "error" || state.tone === "warn" ? "text.primary" : "text.secondary"} sx={{ lineHeight: 1.9 }}>
          {state.why}
        </Typography>

        {service.state === "crashed" && service.recovery && (
          <Stack spacing={0.5}>
            {service.recovery.next_retry_at ? (
              <Typography variant="caption" color="text.secondary">
                {pick(language, COPY.nextRetry)} <RelativeTime value={apiTime(service.recovery.next_retry_at)} relativeAlways />
              </Typography>
            ) : null}
            {typeof service.recovery.attempts === "number" && service.recovery.attempts > 0 ? (
              <Typography variant="caption" color="text.secondary">
                {pick(language, COPY.retries)} {new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(service.recovery.attempts)}
              </Typography>
            ) : null}
            {isAdvanced && service.recovery.last_error ? (
              <Typography variant="caption" color="text.secondary">
                {pick(language, COPY.crashDetail)} <Ltr>{service.recovery.last_error}</Ltr>
              </Typography>
            ) : null}
          </Stack>
        )}

        {(actions.length > 0 || manage) && (
          <Stack direction="row" useFlexGap flexWrap="wrap" gap={1}>
            {canOperate &&
              actions.map((action) => {
                const ActionIcon = ACTION_ICONS[action];
                const busy = busyAction === action;
                return (
                  <Button
                    key={action}
                    variant={action === "start" ? "contained" : "outlined"}
                    color={action === "stop" ? "error" : "primary"}
                    onClick={() => onAction(service, action)}
                    disabled={busyAction !== null}
                    startIcon={busy ? <CircularProgress size={16} color="inherit" /> : <ActionIcon />}
                    sx={{ minHeight: 44 }}
                  >
                    {busy ? pick(language, ACTION_WORDS[action].busy) : pick(language, ACTION_WORDS[action].button)}
                  </Button>
                );
              })}
            {manage ? (
              <Button href={manage} endIcon={<OpenInNewRoundedIcon sx={{ transform: language === "fa" ? "scaleX(-1)" : undefined }} />} sx={{ minHeight: 44 }}>
                {pick(language, COPY.manage)}
              </Button>
            ) : null}
          </Stack>
        )}
        {actions.length > 0 && !canOperate ? <NoAccess needs="services:operate" /> : null}
        {isAdvanced && !service.controllable && !notInstalled ? (
          <Typography variant="caption" color="text.secondary">{pick(language, COPY.statusOnly)}</Typography>
        ) : null}

        {domainsSupported && !notInstalled && (
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 720, mb: 1 }}>{pick(language, COPY.domains)}</Typography>
            {sortedChips.length ? (
              <DomainChips service={service} domains={sortedChips} onOpen={canReadDomains ? onOpenDomain : undefined} />
            ) : (
              <Typography variant="body2" color="text.secondary">{pick(language, COPY.noDomains)}</Typography>
            )}
            {canWriteDomains ? (
              <Button onClick={() => onAddDomain(service)} startIcon={<AddRoundedIcon />} sx={{ mt: 1, minHeight: 44 }}>
                {pick(language, COPY.addDomain)}
              </Button>
            ) : null}
          </Box>
        )}

        {isAdvanced && (
          <Stack spacing={1.5}>
            {service.public_url ? (
              <CopyField label={pick(language, COPY.publicUrl)} value={service.public_url} />
            ) : domainsSupported && !notInstalled && sortedChips.length > 0 ? (
              <Typography variant="body2" color="text.secondary">{pick(language, COPY.noPublicUrl)}</Typography>
            ) : null}
            {typeof service.internal_port === "number" ? (
              <Typography variant="body2" color="text.secondary">{say(language, COPY.port, { port: language === "fa" ? persianDigits(String(service.internal_port)) : String(service.internal_port) })}</Typography>
            ) : null}
            {tiles.length ? <StatGrid columns={2}>{tiles}</StatGrid> : null}
            <Typography variant="caption" color="text.secondary">
              {pick(language, COPY.technicalId)}: <Ltr mono>{String(service.id)}{service.reason_code ? ` · ${service.reason_code}` : ""}</Ltr>
            </Typography>
          </Stack>
        )}
      </Stack>
    </SectionCard>
  );
}

function ServicesList({ user, permissions: permissionsProp, tabs }: GroupPageProps & { tabs: ReactNode }) {
  const { language, isAdvanced, c } = useKit();
  const permissions = useMemo(() => user?.permissions ?? permissionsProp ?? [], [user, permissionsProp]);
  const canServices = hasPermission(permissions, "services:read");
  const canDomains = hasPermission(permissions, "domains:read");
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();

  const [payload, setPayload] = useState<ServicesPayload | null>(null);
  const [domains, setDomains] = useState<DomainRecord[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [domainsError, setDomainsError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<{ id: string; action: ServiceAction } | null>(null);
  const [wizard, setWizard] = useState<{ service: ServiceInfo; key: number } | null>(null);
  const [openDomain, setOpenDomain] = useState<string | null>(null);
  const [routingInfo, setRoutingInfo] = useState<RoutingInfo | null>(null);
  const controller = useRef<AbortController | null>(null);
  const timers = useRef<number[]>([]);
  const queryHandled = useRef(false);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    const tasks: Promise<void>[] = [];
    if (canServices) {
      tasks.push(
        fetchServices(current.signal).then(
          (data) => {
            setPayload(data);
            setError(null);
          },
          (caught: unknown) => {
            if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
            setError(caught);
          }
        )
      );
    }
    if (canDomains) {
      tasks.push(
        fetchDomains(current.signal).then(
          (items) => {
            setDomains(items);
            setDomainsError(null);
          },
          (caught: unknown) => {
            if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
            setDomainsError(caught);
          }
        )
      );
    }
    await Promise.all(tasks);
    if (controller.current === current) setLoading(false);
  }, [canServices, canDomains]);

  useEffect(() => {
    void load();
    const pending = timers.current;
    return () => {
      controller.current?.abort();
      pending.forEach((timer) => window.clearTimeout(timer));
    };
  }, [load]);

  useVisibleInterval(() => void load(), 10_000);

  /** Reload now and once more a few seconds later (services take a moment to settle). */
  const reloadSoon = useCallback(() => {
    void load();
    timers.current.push(window.setTimeout(() => void load(), 3_000));
  }, [load]);

  const services = useMemo(() => payload?.items ?? [], [payload]);

  // Hash query: open a wizard / domain or scroll to a service (Home links, deep links).
  useEffect(() => {
    if (queryHandled.current || !payload) return;
    queryHandled.current = true;
    const query = hashQuery();
    const add = query.get("add");
    const domain = query.get("domain");
    const focus = query.get("service");
    if (add && hasPermission(permissions, "domains:write")) {
      const target = services.find((item) => item.id === add);
      if (target) setWizard({ service: target, key: Date.now() });
    }
    if (domain && canDomains) setOpenDomain(domain);
    const scrollTo = query.get("routing") ? "mrk-domain-routing" : focus ? `mrk-service-${focus}` : null;
    if (scrollTo) window.setTimeout(() => document.getElementById(scrollTo)?.scrollIntoView({ behavior: "smooth", block: "start" }), 300);
  }, [payload, services, permissions, canDomains]);

  const handleAction = async (service: ServiceInfo, action: ServiceAction) => {
    const name = serviceName(language, service);
    let confirmed = false;
    if (action === "stop") {
      confirmed = await ask({
        title: say(language, COPY.stopTitle, { name }),
        body: pick(language, COPY.stopBody),
        undoable: true,
        severity: "destructive",
        typed: nameConfirmation(name, String(service.id)),
        confirmLabel: pick(language, COPY.stopYes)
      });
      if (!confirmed) return;
    } else if (action === "restart") {
      confirmed = await ask({
        title: say(language, COPY.restartTitle, { name }),
        body: pick(language, service.id === "panel" ? COPY.restartPanelBody : COPY.restartBody),
        severity: "disruptive",
        confirmLabel: pick(language, COPY.restartYes)
      });
      if (!confirmed) return;
    }
    setBusy({ id: String(service.id), action });
    try {
      await runServiceAction(service, action, confirmed);
      notify({ message: say(language, ACTION_WORDS[action].done, { name }), tone: "success" });
    } catch (caught) {
      notify({ message: say(language, COPY.actionFailed, { name, reason: errorSentence(language, caught, "services") }), tone: "error" });
    } finally {
      setBusy(null);
      reloadSoon();
    }
  };

  const domainsFor = (service: ServiceInfo) => domains.filter((domain) => domain.service_id === service.id);
  const currentDomain = useMemo((): DomainRecord | null => {
    if (!openDomain) return null;
    const full = domains.find((domain) => domain.id === openDomain);
    if (full) return full;
    // The domains list may be missing (older server, failed load): use what the services list carries.
    for (const service of services) {
      const ref = service.domains?.find((item) => item.id === openDomain);
      if (ref) return { ...ref, service_id: service.id, health: ref.health && typeof ref.health === "object" ? ref.health : null };
    }
    return null;
  }, [openDomain, domains, services]);
  const currentDomainService = currentDomain ? services.find((service) => service.id === currentDomain.service_id) ?? null : null;
  const routing = payload?.routing ?? null;

  const refreshButton = (
    <Stack direction="row" spacing={1}>
      <Button onClick={() => void load()} disabled={loading} startIcon={loading ? <CircularProgress size={14} /> : <RefreshRoundedIcon />} sx={{ minHeight: 44 }}>
        {c.refresh}
      </Button>
      {canServices ? (
        <Button variant="contained" href="#/services/add" startIcon={<AddRoundedIcon />} sx={{ minHeight: 44 }}>
          {pick(language, COPY.addService)}
        </Button>
      ) : null}
    </Stack>
  );
  // docs/44: a fresh panel has nothing else yet; point straight at the wizard.
  const nothingAdded =
    payload !== null && services.length > 0 && services.filter((item) => item.id !== "panel").every((item) => item.state === "not_installed");

  let body;
  if (!canServices && !canDomains) {
    body = <NoAccess needs="services:read" variant="card" />;
  } else if (!canServices) {
    body = <NoAccess needs="services:read" variant="card" />;
  } else if (error !== null && !payload) {
    body = <FriendlyError error={error} title={pick(language, COPY.loadFailed)} scope="services" onRetry={() => void load()} />;
  } else if (!payload) {
    body = (
      <Grid container spacing={2}>
        {[0, 1, 2, 3].map((index) => (
          <Grid key={index} size={{ xs: 12, md: 6 }}>
            <Skeleton variant="rounded" height={200} />
          </Grid>
        ))}
      </Grid>
    );
  } else if (!services.length) {
    body = <EmptyState title={pick(language, COPY.empty)} body={pick(language, COPY.emptyBody)} icon={AppsRoundedIcon} />;
  } else {
    body = (
      <Grid container spacing={2}>
        {services.map((service) => (
          <Grid key={String(service.id)} size={{ xs: 12, md: 6 }}>
            <ServiceCard
              service={service}
              domains={domainsFor(service)}
              permissions={permissions}
              busyAction={busy?.id === service.id ? busy.action : null}
              onAction={(target, action) => void handleAction(target, action)}
              onAddDomain={(target) => setWizard({ service: target, key: Date.now() })}
              onOpenDomain={setOpenDomain}
            />
          </Grid>
        ))}
      </Grid>
    );
  }

  return (
    <>
      <PageHeader title={pick(language, COPY.title)} subtitle={pick(language, COPY.subtitle)} icon={AppsRoundedIcon} secondaryActions={refreshButton} tabs={tabs} />
      <Stack spacing={2.5}>
        {nothingAdded ? (
          <Notice
            tone="info"
            action={
              <Button color="inherit" href="#/services/add" sx={{ minHeight: 44, whiteSpace: "nowrap" }}>
                {pick(language, COPY.addService)}
              </Button>
            }
          >
            {pick(language, COPY.startHere)}
          </Notice>
        ) : null}
        {error !== null && payload ? <FriendlyError error={error} title={pick(language, COPY.loadFailed)} scope="services" onRetry={() => void load()} severity="warning" /> : null}
        {domainsError !== null && isAdvanced ? <FriendlyError error={domainsError} title={pick(language, COPY.domainsFailed)} scope="domains" onRetry={() => void load()} severity="warning" /> : null}
        {body}
        {isAdvanced && (canDomains || canServices) ? (
          <DomainRouting permissions={permissions} summary={routing} onChanged={reloadSoon} onLoaded={setRoutingInfo} />
        ) : null}
      </Stack>

      {wizard ? (
        <AddDomainWizard
          key={wizard.key}
          service={services.find((item) => item.id === wizard.service.id) ?? wizard.service}
          services={services}
          routing={routingInfo ?? routing}
          availableModes={routingInfo?.available_modes}
          onClose={() => setWizard(null)}
          onChanged={reloadSoon}
        />
      ) : null}
      {currentDomain ? (
        <DomainDialog
          key={currentDomain.id}
          domain={currentDomain}
          service={currentDomainService}
          detected={(routingInfo ?? routing)?.detected ?? null}
          permissions={permissions}
          onClose={() => setOpenDomain(null)}
          onChanged={reloadSoon}
          notify={(message, tone = "success") => notify({ message, tone })}
        />
      ) : null}
      {dialog}
      {snackbar}
    </>
  );
}

/** «سرویس‌های من» group: the service cards and «افزودن سرویس» (docs/44). */
export default function ServicesPage(props: GroupPageProps) {
  const { language, mode } = useKit();
  const { user, permissions: permissionsProp } = props;
  const permissions = useMemo(() => user?.permissions ?? permissionsProp ?? [], [user, permissionsProp]);
  const group = findGroup("services");
  const tabs = group ? visibleTabs(group, permissions, mode).map((item) => item.key) : [];
  const tab = useHashTab("services", {}, tabs, tabs[0] ?? "all");
  const tabBar = <GroupTabs group="services" permissions={permissions} value={tab} />;
  if (tab === "add") {
    return (
      <>
        <PageHeader title={pick(language, COPY.addTitle)} subtitle={pick(language, COPY.addSubtitle)} icon={AddRoundedIcon} tabs={tabBar} />
        <TabBody>
          <AddServicePanel permissions={permissions} onChanged={resetServices} />
        </TabBody>
      </>
    );
  }
  return <ServicesList {...props} tabs={tabBar} />;
}
