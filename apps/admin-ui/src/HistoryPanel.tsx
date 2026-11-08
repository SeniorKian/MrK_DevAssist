import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Avatar, Box, Button, Divider, MenuItem, Skeleton, Stack, TextField, Typography } from "@mui/material";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import SupportAgentRoundedIcon from "@mui/icons-material/SupportAgentRounded";
import QueryStatsRoundedIcon from "@mui/icons-material/QueryStatsRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import { ApiError, getJson, hasPermission, isAbortError } from "./api";
import type { AuthUser } from "./App";
import type { Language } from "./i18n";
import { CopyField, DateTime, EmptyState, FriendlyError, KeyValueList, Ltr, NoAccess, Notice, RelativeTime, SectionCard, StatusPill, useKit } from "./kit";
import { initials, type UserRecord } from "./kit/people";
import { humanizeAudit, normalizeTyped, pick, say, type Bi } from "./copy";

type AuditEvent = {
  id: number;
  actor_user_id: number | null;
  action: string;
  object_type: string;
  object_id: string | null;
  result: string;
  source_ip: string | null;
  request_id?: string | null;
  occurred_at: number;
};

type Area = "all" | "people" | "packages" | "server" | "files" | "security" | "alerts" | "other";
type When = "day" | "week" | "month" | "all";

const AREA_PREFIXES: Record<Exclude<Area, "all" | "other">, string[]> = {
  people: ["auth.", "user.", "role.", "token.", "registration."],
  packages: ["package.", "upstream.", "ecosystem."],
  server: ["agent.", "docker.", "logs.", "monitoring.", "dokploy.", "updates.", "dbadmin."],
  files: ["backup.", "server_backup.", "s3.", "integrity."],
  security: ["firewall.", "vuln.", "settings.proxy.", "settings.outbound_service.", "settings.network."],
  alerts: ["notification.", "task.", "audit.", "support."]
};

function areaOf(action: string): Exclude<Area, "all"> {
  for (const [area, prefixes] of Object.entries(AREA_PREFIXES)) {
    if (prefixes.some((prefix) => action.startsWith(prefix))) return area as Exclude<Area, "all">;
  }
  return "other";
}

const T = {
  title: { fa: "تاریخچه فعالیت", en: "Activity history" },
  hint: { fa: "چه کسی، چه زمانی، چه کاری کرد. هیچ ردیفی پاک یا عوض نمی‌شود.", en: "Who did what, and when. No row is ever changed or deleted." },
  who: { fa: "چه کسی", en: "Who" },
  what: { fa: "در کدام بخش", en: "Which area" },
  when: { fa: "چه زمانی", en: "When" },
  result: { fa: "نتیجه", en: "Result" },
  search: { fa: "جست‌وجو در جمله‌ها", en: "Search the sentences" },
  everyone: { fa: "همه", en: "Everyone" },
  system: { fa: "خود سامانه", en: "The system" },
  someone: { fa: "یک کاربر", en: "Someone" },
  areaAll: { fa: "همه بخش‌ها", en: "All areas" },
  areaPeople: { fa: "ورود و افراد", en: "Sign-in and people" },
  areaPackages: { fa: "بسته‌ها", en: "Packages" },
  areaServer: { fa: "سرور و برنامه‌ها", en: "Server and apps" },
  areaFiles: { fa: "فایل‌ها و پشتیبان", en: "Files and backups" },
  areaSecurity: { fa: "امنیت و اینترنت", en: "Security and internet" },
  areaAlerts: { fa: "اعلان‌ها و کارها", en: "Alerts and jobs" },
  areaOther: { fa: "تنظیمات و بقیه", en: "Settings and other" },
  day: { fa: "۲۴ ساعت گذشته", en: "Last 24 hours" },
  week: { fa: "۷ روز گذشته", en: "Last 7 days" },
  month: { fa: "۳۰ روز گذشته", en: "Last 30 days" },
  allTime: { fa: "همه زمان‌ها", en: "Any time" },
  resultAll: { fa: "همه", en: "All" },
  resultFailed: { fa: "فقط کارهایی که انجام نشد", en: "Only what didn't work" },
  emptyTitle: { fa: "هنوز فعالیتی ثبت نشده", en: "No activity yet" },
  emptyBody: { fa: "هر ورود و هر تغییری در پنل این‌جا با نام انجام‌دهنده ثبت می‌شود.", en: "Every sign-in and change in the panel is recorded here with who did it." },
  noMatch: { fa: "با این فیلترها چیزی پیدا نشد.", en: "Nothing matches these filters." },
  clearFilters: { fa: "پاک کردن فیلترها", en: "Clear filters" },
  shown: { fa: "{count} مورد", en: "{count} items" },
  exportCsv: { fa: "دانلود فایل CSV", en: "Download CSV" },
  exportHint: { fa: "تا ۵۰۰ ردیف آخر، برای بایگانی یا بررسی در صفحه‌گسترده.", en: "Up to the last 500 rows, for archiving or a spreadsheet." },
  advAction: { fa: "کد کار", en: "Action" },
  advObject: { fa: "روی", en: "Object" },
  advIp: { fa: "نشانی IP", en: "IP address" },
  advRequest: { fa: "شناسه درخواست", en: "Request ID" },
  advTime: { fa: "زمان دقیق", en: "Exact time" },
  noAudit: { fa: "دیدن تاریخچه فعالیت فقط برای مدیرها و مسئولان روزانه است.", en: "Only admins and operators can see activity history." }
} satisfies Record<string, Bi>;

const AREA_LABEL: Record<Area, Bi> = {
  all: T.areaAll, people: T.areaPeople, packages: T.areaPackages, server: T.areaServer, files: T.areaFiles,
  security: T.areaSecurity, alerts: T.areaAlerts, other: T.areaOther
};

const WHEN_SECONDS: Record<When, number | null> = { day: 86400, week: 7 * 86400, month: 30 * 86400, all: null };

export type HistoryPanelProps = {
  user?: AuthUser;
  permissions: string[];
  language?: Language;
  onUnauthorized?: () => void;
};

/** Humanized activity feed (docs/33 §4.2 Alerts › history) with who / what / when filters. */
export function HistoryPanel({ permissions }: HistoryPanelProps) {
  const { language, isAdvanced, c } = useKit();
  const canAudit = hasPermission(permissions, "audit:read");
  const canUsers = hasPermission(permissions, "user:read");
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [users, setUsers] = useState<Map<number, UserRecord>>(new Map());
  const [error, setError] = useState<unknown>(null);
  const [who, setWho] = useState<string>("all");
  const [area, setArea] = useState<Area>("all");
  const [when, setWhen] = useState<When>("all");
  const [failedOnly, setFailedOnly] = useState(false);
  const [query, setQuery] = useState("");
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    if (!canAudit) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      const [audit, people] = await Promise.all([
        getJson<{ items: AuditEvent[] }>("/api/v1/audit-events?limit=500", current.signal),
        canUsers ? getJson<{ items: UserRecord[] }>("/api/v1/users", current.signal).catch(() => ({ items: [] as UserRecord[] })) : Promise.resolve({ items: [] as UserRecord[] })
      ]);
      setEvents(audit.items ?? []);
      setUsers(new Map((people.items ?? []).map((item) => [item.id, item])));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    }
  }, [canAudit, canUsers]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const actorName = useCallback((id: number | null) => {
    if (id === null) return pick(language, T.system);
    const person = users.get(id);
    return person ? person.display_name?.trim() || person.username : pick(language, T.someone);
  }, [users, language]);

  const rows = useMemo(() => {
    return (events ?? []).map((event) => {
      const target = event.object_type === "user" && event.object_id ? users.get(Number(event.object_id)) : undefined;
      // Machine ids ("application:PoAn…", "42", uuids) never go into a sentence; names do. Raw ids stay in Advanced details.
      const id = event.object_id ?? "";
      const machineLike = !target && (/[:/]/.test(id) || /^\d+$/.test(id) || /^[0-9a-f-]{16,}$/i.test(id) || (id.length > 24 && !/\s/.test(id)));
      const human = humanizeAudit(language, machineLike ? { ...event, object_id: null } : event, {
        actorName: event.actor_user_id === null ? null : actorName(event.actor_user_id),
        targetName: target ? target.display_name?.trim() || target.username : null
      });
      return { event, human, area: areaOf(event.action), actor: event.actor_user_id === null ? "system" : String(event.actor_user_id) };
    });
  }, [events, users, language, actorName]);

  const actors = useMemo(() => {
    const seen = new Map<string, string>();
    for (const row of rows) if (!seen.has(row.actor)) seen.set(row.actor, row.actor === "system" ? pick(language, T.system) : actorName(row.event.actor_user_id));
    return [...seen.entries()];
  }, [rows, actorName, language]);

  const now = Math.floor(Date.now() / 1000);
  const filtered = rows.filter((row) => {
    if (who !== "all" && row.actor !== who) return false;
    if (area !== "all" && row.area !== area) return false;
    const limit = WHEN_SECONDS[when];
    if (limit !== null && now - row.event.occurred_at > limit) return false;
    if (failedOnly && row.human.result.tone === "ok") return false;
    if (query && !normalizeTyped(row.human.sentence).includes(normalizeTyped(query))) return false;
    return true;
  });

  const clear = () => {
    setWho("all");
    setArea("all");
    setWhen("all");
    setFailedOnly(false);
    setQuery("");
  };

  if (!canAudit) return <Notice tone="info">{pick(language, T.noAudit)}</Notice>;

  return (
    <SectionCard
      title={pick(language, T.title)}
      hint={pick(language, T.hint)}
      action={isAdvanced ? <Button startIcon={<DownloadRoundedIcon />} href="/api/v1/audit-events/export.csv" download sx={{ minHeight: 44 }}>{pick(language, T.exportCsv)}</Button> : undefined}
      flush
    >
      <Stack spacing={1.5} sx={{ px: { xs: 2, sm: 2.5 }, pb: 1.5 }}>
        {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
        <Stack direction={{ xs: "column", md: "row" }} spacing={1.25}>
          <TextField select size="small" label={pick(language, T.who)} value={who} onChange={(event) => setWho(event.target.value)} sx={{ minWidth: 160 }}>
            <MenuItem value="all">{pick(language, T.everyone)}</MenuItem>
            {actors.map(([key, name]) => <MenuItem key={key} value={key}>{name}</MenuItem>)}
          </TextField>
          <TextField select size="small" label={pick(language, T.what)} value={area} onChange={(event) => setArea(event.target.value as Area)} sx={{ minWidth: 180 }}>
            {(Object.keys(AREA_LABEL) as Area[]).map((key) => <MenuItem key={key} value={key}>{pick(language, AREA_LABEL[key])}</MenuItem>)}
          </TextField>
          <TextField select size="small" label={pick(language, T.when)} value={when} onChange={(event) => setWhen(event.target.value as When)} sx={{ minWidth: 160 }}>
            <MenuItem value="day">{pick(language, T.day)}</MenuItem>
            <MenuItem value="week">{pick(language, T.week)}</MenuItem>
            <MenuItem value="month">{pick(language, T.month)}</MenuItem>
            <MenuItem value="all">{pick(language, T.allTime)}</MenuItem>
          </TextField>
          <TextField select size="small" label={pick(language, T.result)} value={failedOnly ? "failed" : "all"} onChange={(event) => setFailedOnly(event.target.value === "failed")} sx={{ minWidth: 180 }}>
            <MenuItem value="all">{pick(language, T.resultAll)}</MenuItem>
            <MenuItem value="failed">{pick(language, T.resultFailed)}</MenuItem>
          </TextField>
          <TextField size="small" label={pick(language, T.search)} value={query} onChange={(event) => setQuery(event.target.value)} sx={{ flex: 1, minWidth: 160 }} />
        </Stack>
        {events !== null && <Typography variant="caption" color="text.secondary">{say(language, T.shown, { count: filtered.length })}</Typography>}
      </Stack>
      <Divider />
      {events === null && error === null && <Box sx={{ p: 2.5 }}><Skeleton variant="rounded" height={160} /></Box>}
      {events !== null && events.length === 0 && <EmptyState compact icon={HistoryRoundedIcon} title={pick(language, T.emptyTitle)} body={pick(language, T.emptyBody)} />}
      {events !== null && events.length > 0 && filtered.length === 0 && (
        <EmptyState compact icon={HistoryRoundedIcon} title={pick(language, T.noMatch)} action={<Button onClick={clear} sx={{ minHeight: 44 }}>{pick(language, T.clearFilters)}</Button>} />
      )}
      <Stack component="ol" divider={<Divider component="li" aria-hidden />} sx={{ listStyle: "none", m: 0, p: 0 }}>
        {filtered.map(({ event, human }) => {
          const actor = event.actor_user_id === null ? pick(language, T.system) : actorName(event.actor_user_id);
          return (
            <Box component="li" key={event.id} sx={{ px: { xs: 2, sm: 2.5 }, py: 1.25, display: "flex", gap: 1.5, alignItems: "flex-start" }}>
              <Avatar sx={{ width: 32, height: 32, fontSize: 13, bgcolor: event.actor_user_id === null ? "action.selected" : "primary.main" }} aria-hidden>
                {event.actor_user_id === null ? "⚙" : initials(actor)}
              </Avatar>
              <Box sx={{ minWidth: 0, flex: 1 }}>
                <Typography variant="body2" sx={{ fontWeight: 600, lineHeight: 1.8 }}>{human.sentence}</Typography>
                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                  <Typography variant="caption" color="text.secondary"><RelativeTime value={event.occurred_at} /></Typography>
                  {human.result.tone !== "ok" && <StatusPill tone={human.result.tone} label={human.result.label} size="small" />}
                </Stack>
                {isAdvanced && (
                  <Box sx={{ mt: 0.75 }}>
                    <KeyValueList
                      dense
                      items={[
                        { label: pick(language, T.advAction), value: event.action, ltr: true },
                        { label: pick(language, T.advObject), value: event.object_id ? `${event.object_type} · ${event.object_id}` : event.object_type || c.emptyDash, ltr: true },
                        { label: pick(language, T.advIp), value: event.source_ip ?? c.emptyDash, ltr: Boolean(event.source_ip) },
                        ...(event.request_id ? [{ label: pick(language, T.advRequest), value: event.request_id, ltr: true, copy: true }] : []),
                        { label: pick(language, T.advTime), value: <DateTime value={event.occurred_at} /> }
                      ]}
                    />
                  </Box>
                )}
              </Box>
            </Box>
          );
        })}
      </Stack>
      {isAdvanced && <Typography variant="caption" color="text.secondary" display="block" sx={{ px: 2.5, py: 1.5 }}>{pick(language, T.exportHint)}</Typography>}
    </SectionCard>
  );
}

const S = {
  bundleTitle: { fa: "بسته گزارش برای پشتیبانی", en: "Support report bundle" },
  bundleHint: { fa: "یک فایل که وضعیت سرور، تنظیمات امن، کارها و تاریخچه را دارد. رمزها و لاگ خام عمداً در آن نیستند.", en: "One file with server status, safe settings, jobs and history. Passwords and raw logs are deliberately left out." },
  bundleButton: { fa: "دانلود بسته گزارش", en: "Download the report bundle" },
  bundleWhen: { fa: "وقتی از پشتیبانی کمک می‌خواهید، همین فایل را برایشان بفرستید.", en: "When you ask support for help, send them this file." },
  metricsTitle: { fa: "خواندن آمار با Prometheus", en: "Read stats with Prometheus" },
  metricsHint: { fa: "ابزار پایش شما می‌تواند آمار MRK را از این نشانی بخواند.", en: "Your monitoring tool can read MRK's stats from this address." },
  metricsAddress: { fa: "نشانی آمار", en: "Stats address" },
  metricsKey: { fa: "برای این کار یک کلید برنامه «برای ابزار پایش» بسازید و در تنظیمات Prometheus بگذارید.", en: "Create an app key “For monitoring” and put it in your Prometheus settings." },
  makeKey: { fa: "ساخت کلید برنامه", en: "Create an app key" }
} satisfies Record<string, Bi>;

/** Advanced-only support tab: support bundle download and the metrics address. */
export function SupportPanel({ permissions }: { permissions: string[] }) {
  const { language } = useKit();
  const canAudit = hasPermission(permissions, "audit:read");
  const canToken = hasPermission(permissions, "token:write");
  const metricsUrl = `${window.location.origin}/metrics`;
  return (
    <Stack spacing={2.5}>
      <SectionCard title={pick(language, S.bundleTitle)} hint={pick(language, S.bundleHint)} action={<SupportAgentRoundedIcon color="action" aria-hidden />}>
        <Stack spacing={1.5}>
          <Typography variant="body2" color="text.secondary">{pick(language, S.bundleWhen)}</Typography>
          <Box>
            <Button variant="contained" startIcon={<DownloadRoundedIcon />} href="/api/v1/support-bundle" download disabled={!canAudit} sx={{ minHeight: 44 }}>
              {pick(language, S.bundleButton)}
            </Button>
          </Box>
          {!canAudit && <NoAccess needs="audit:read" />}
        </Stack>
      </SectionCard>
      <SectionCard title={pick(language, S.metricsTitle)} hint={pick(language, S.metricsHint)} action={<QueryStatsRoundedIcon color="action" aria-hidden />}>
        <Stack spacing={1.5}>
          <CopyField label={pick(language, S.metricsAddress)} value={metricsUrl} />
          <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{pick(language, S.metricsKey)}</Typography>
          {canToken && (
            <Box>
              <Button startIcon={<KeyRoundedIcon />} href="#/people/app-keys" sx={{ minHeight: 44 }}>{pick(language, S.makeKey)}</Button>
            </Box>
          )}
          <Typography variant="caption" color="text.secondary"><Ltr mono>GET /metrics</Ltr></Typography>
        </Stack>
      </SectionCard>
    </Stack>
  );
}

export default HistoryPanel;
