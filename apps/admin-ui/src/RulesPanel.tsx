import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Box, Button, Card, CardContent, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, FormGroup,
  IconButton, MenuItem, Radio, RadioGroup, Skeleton, Stack, Switch, TextField, Tooltip, Typography, useMediaQuery, useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import RuleRoundedIcon from "@mui/icons-material/RuleRounded";
import SendRoundedIcon from "@mui/icons-material/SendRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { AuthUser } from "./App";
import {
  EmptyState, FriendlyError, Ltr, NoAccess, Notice, RegistrySettings, SectionCard, StatusPill, useConfirmAction, useKit, useUndoSnackbar,
  type LegacySettingsAdapter, type SettingValue
} from "./kit";
import { EVENT_FAMILY_WORDS, errorSentence, pick, say, severityWord, type Bi } from "./copy";
import { NOTIFY_BASE, kindWord, type Channel } from "./ChannelsPanel";

type Severity = "info" | "warning" | "error" | "critical";
const SEVERITIES: Severity[] = ["info", "warning", "error", "critical"];
type Rule = { id: string; channel_id: string; event_pattern: string; min_severity: Severity; enabled: boolean };

/** Well-known single events, as the end of «وقتی …». */
const EVENT_PHRASES: Record<string, Bi> = {
  "server_backup.failed": { fa: "پشتیبان‌گیری انجام نشود", en: "a backup fails" },
  "server_backup.succeeded": { fa: "پشتیبان‌گیری تمام شود", en: "a backup finishes" },
  "agent.offline": { fa: "دستیار سرور قطع شود", en: "the server helper goes offline" },
  "agent.online": { fa: "دستیار سرور دوباره وصل شود", en: "the server helper comes back" },
  "update.available": { fa: "برای برنامه‌ای نسخه تازه بیاید", en: "an app has a new version" },
  "dokploy.deploy_failed": { fa: "انتشار برنامه‌ای در Dokploy انجام نشود", en: "a Dokploy deploy fails" },
  "dokploy.unreachable": { fa: "Dokploy جواب ندهد", en: "Dokploy stops answering" },
  "service.crashed": { fa: "یکی از سرویس‌ها (npm، PyPI یا S3) از کار بیفتد", en: "a service (npm, PyPI or S3) crashes" },
  "service.recovered": { fa: "سرویسی که از کار افتاده بود دوباره کار کند", en: "a crashed service works again" },
  "domain.unhealthy": { fa: "یکی از دامنه‌ها مشکل پیدا کند", en: "a domain develops a problem" },
  "domain.cert_expiring": { fa: "گواهی HTTPS یک دامنه رو به اتمام باشد", en: "a domain's HTTPS certificate is about to expire" },
  "firewall.blocked": { fa: "دیوار آتش نشانی‌ای را مسدود کند", en: "the firewall blocks an address" },
  "docker.pruned": { fa: "موارد بی‌استفاده Docker پاک شود", en: "unused Docker items are cleaned up" },
  "notification.test": { fa: "پیام آزمایشی فرستاده شود", en: "a test alert is sent" },
  "dns.unreachable": { fa: "DNS سرور جواب ندهد", en: "the server's DNS stops answering" },
  "dns.pressure": { fa: "DNS سرور زیر فشار برود یا از فشار بیرون بیاید", en: "the server's DNS comes under load or recovers" },
  "dns.attack_detected": { fa: "حمله‌ای به DNS سرور دیده شود", en: "an attack on the server's DNS is seen" },
  "dns.mitigation_auto": { fa: "MRK خودکار دستگاه یا نامی را در DNS کند یا مسدود کند", en: "MRK automatically slows down or blocks a device or name in DNS" },
  "dns.logs_degraded": { fa: "لاگ کامل پرسش‌های DNS موقتاً نوشته نشود", en: "the full DNS question log is paused" },
  "dns.logs_recovered": { fa: "نوشتن لاگ پرسش‌های DNS به حالت عادی برگردد", en: "the DNS question log is back to normal" }
};

const IMPORTANCE: Record<Severity, { label: Bi; hint: Bi; phrase: Bi; any: Bi }> = {
  info: {
    label: { fa: "همه خبرها", en: "Everything" },
    hint: { fa: "حتی خبرهای خوب، مثل «پشتیبان تمام شد».", en: "Even good news, like “backup finished”." },
    phrase: { fa: "هر خبری از {topic} برسد", en: "there's any news about {topic}" },
    any: { fa: "هر اتفاقی بیفتد", en: "anything happens" }
  },
  warning: {
    label: { fa: "هشدارها و مشکلات", en: "Warnings and problems" },
    hint: { fa: "پیشنهاد ما: چیزهایی که بهتر است بدانید.", en: "Our suggestion: things you should know about." },
    phrase: { fa: "در {topic} هشدار یا مشکلی پیش بیاید", en: "there's a warning or a problem in {topic}" },
    any: { fa: "هر جا هشدار یا مشکلی پیش بیاید", en: "there's any warning or problem" }
  },
  error: {
    label: { fa: "فقط مشکلات مهم", en: "Only important problems" },
    hint: { fa: "وقتی چیزی واقعاً خراب شده.", en: "When something is really broken." },
    phrase: { fa: "در {topic} مشکل مهمی پیش بیاید", en: "there's an important problem in {topic}" },
    any: { fa: "هر جا مشکل مهمی پیش بیاید", en: "there's any important problem" }
  },
  critical: {
    label: { fa: "فقط موارد خیلی جدی", en: "Only very serious issues" },
    hint: { fa: "فقط وقتی کار فوری لازم است.", en: "Only when urgent action is needed." },
    phrase: { fa: "در {topic} مشکل خیلی جدی پیش بیاید", en: "there's a very serious issue in {topic}" },
    any: { fa: "هر جا مشکل خیلی جدی پیش بیاید", en: "there's any very serious issue" }
  }
};

const T = {
  title: { fa: "قواعد اعلان", en: "Alert rules" },
  hint: { fa: "برای چه چیزهایی و به کدام کانال پیام بیاید.", en: "Which events send a message, and to which channel." },
  add: { fa: "قاعده تازه", en: "New rule" },
  sentence: { fa: "وقتی {when}، در {kind} «{channel}» خبرم کن.", en: "Tell me on {kind} “{channel}” when {when}." },
  anything: { fa: "همه بخش‌ها", en: "everything" },
  other: { fa: "رویدادهای خاص", en: "specific events" },
  deletedChannel: { fa: "کانال پاک‌شده", en: "a deleted channel" },
  emptyTitle: { fa: "هنوز قاعده‌ای ندارید", en: "No rules yet" },
  emptyBody: { fa: "بدون قاعده، هیچ پیامی فرستاده نمی‌شود. یک قاعده بسازید تا مثلاً وقتی پشتیبان‌گیری انجام نشد خبردار شوید.", en: "Without rules, no message is sent. Make one so you hear, for example, when a backup fails." },
  noChannels: { fa: "اول یک کانال اعلان (مثل تلگرام) بسازید، بعد این‌جا بگویید چه چیزهایی به آن برود.", en: "First add an alert channel (like Telegram), then say here what should go to it." },
  goChannels: { fa: "رفتن به کانال‌ها", en: "Go to channels" },
  on: { fa: "روشن", en: "On" },
  off: { fa: "خاموش", en: "Off" },
  toggle: { fa: "روشن یا خاموش کردن این قاعده", en: "Turn this rule on or off" },
  edit: { fa: "ویرایش الگو", en: "Edit pattern" },
  remove: { fa: "پاک کردن", en: "Delete" },
  deleteTitle: { fa: "این قاعده پاک شود؟", en: "Delete this rule?" },
  deletedToast: { fa: "قاعده پاک شد.", en: "The rule was deleted." },
  turnedOn: { fa: "قاعده روشن شد.", en: "The rule is on." },
  turnedOff: { fa: "قاعده خاموش شد.", en: "The rule is off." },
  readOnly: { fa: "نقش شما فقط اجازه دیدن قواعد را دارد.", en: "Your role can only see rules." },
  // builder
  builderTitle: { fa: "قاعده اعلان تازه", en: "New alert rule" },
  where: { fa: "کجا خبرتان کنیم؟", en: "Where should we tell you?" },
  what: { fa: "درباره چه چیزهایی؟", en: "About what?" },
  everything: { fa: "همه بخش‌ها", en: "Everything" },
  how: { fa: "چقدر مهم باشد؟", en: "How important?" },
  preview: { fa: "این قاعده می‌گوید:", en: "This rule says:" },
  pickTopic: { fa: "دست‌کم یک موضوع را انتخاب کنید.", en: "Pick at least one topic." },
  save: { fa: "ساخت قاعده", en: "Create rule" },
  createdToast: { fa: "قاعده ساخته شد.", en: "The rule was created." },
  // advanced editor
  patternTitle: { fa: "ویرایش قاعده با الگو", en: "Edit rule by pattern" },
  patternNew: { fa: "قاعده تازه با الگو", en: "New rule by pattern" },
  addPattern: { fa: "افزودن با الگو", en: "Add by pattern" },
  pattern: { fa: "الگوی رویداد", en: "Event pattern" },
  patternHint: { fa: "مثل «*» برای همه، «server_backup.*» برای پشتیبان‌ها یا «agent.offline».", en: "Like “*” for everything, “server_backup.*” for backups, or “agent.offline”." },
  patternRule: { fa: "الگو را بنویسید (حداکثر ۲۰۰ نویسه).", en: "Write a pattern (up to 200 characters)." },
  minSeverity: { fa: "کمترین اهمیت", en: "Minimum severity" },
  channel: { fa: "کانال", en: "Channel" },
  enabled: { fa: "روشن باشد", en: "Turned on" },
  savedToast: { fa: "قاعده ذخیره شد.", en: "The rule was saved." },
  patterns: { fa: "الگوها: ", en: "Patterns: " },
  // advanced settings
  settingsTitle: { fa: "ساعات سکوت، تکرار و تلاش دوباره", en: "Quiet hours, repeats and retries" },
  settingsHint: { fa: "همه تنظیمات فرستادن پیام‌ها.", en: "Every setting for sending alerts." },
  testTitle: { fa: "فرستادن یک رویداد آزمایشی", en: "Send a test event" },
  testHint: { fa: "یک رویداد آزمایشی ساخته می‌شود و طبق همین قواعد به کانال‌ها می‌رود.", en: "A test event is created and routed by these rules." },
  testSeverity: { fa: "اهمیت رویداد", en: "Event severity" },
  testSend: { fa: "بفرست", en: "Send" },
  testQueued: { fa: "رویداد آزمایشی ساخته شد؛ {count} پیام در راه است.", en: "Test event created; {count} messages on the way." },
  testNone: { fa: "رویداد آزمایشی ساخته شد، ولی هیچ قاعده‌ای آن را نمی‌گیرد.", en: "Test event created, but no rule picks it up." }
} satisfies Record<string, Bi>;

type Family = keyof typeof EVENT_FAMILY_WORDS;
const FAMILY_BY_PATTERN = new Map<string, Family>();
for (const [key, value] of Object.entries(EVENT_FAMILY_WORDS)) for (const pattern of value.patterns) FAMILY_BY_PATTERN.set(pattern, key as Family);

type RuleGroup = { key: string; channelId: string; severity: Severity; enabled: boolean; topic: "all" | Family | "event" | "other"; rules: Rule[] };

/** Group rules that came from one Simple rule (same channel, severity, state and family). */
function groupRules(rules: Rule[]): RuleGroup[] {
  const groups = new Map<string, RuleGroup>();
  for (const rule of rules) {
    const family = FAMILY_BY_PATTERN.get(rule.event_pattern);
    const topic: RuleGroup["topic"] = rule.event_pattern === "*" ? "all" : family ?? (EVENT_PHRASES[rule.event_pattern] ? "event" : "other");
    const key = topic === "event" || topic === "other" ? `${rule.id}` : `${rule.channel_id}|${rule.min_severity}|${rule.enabled}|${topic}`;
    const existing = groups.get(key);
    if (existing) existing.rules.push(rule);
    else groups.set(key, { key, channelId: rule.channel_id, severity: rule.min_severity, enabled: rule.enabled, topic, rules: [rule] });
  }
  return [...groups.values()];
}

/** Legacy endpoint ↔ registry keys, for when the settings registry is unavailable. */
const LEGACY_KEYS: Record<string, (value: Record<string, unknown>) => unknown> = {
  "notifications.quiet_hours.enabled": (s) => (s.quiet_hours as Record<string, unknown> | undefined)?.enabled,
  "notifications.quiet_hours.start": (s) => (s.quiet_hours as Record<string, unknown> | undefined)?.start,
  "notifications.quiet_hours.end": (s) => (s.quiet_hours as Record<string, unknown> | undefined)?.end,
  "notifications.quiet_hours.timezone": (s) => (s.quiet_hours as Record<string, unknown> | undefined)?.timezone,
  "notifications.quiet_hours.min_severity_during_quiet": (s) => (s.quiet_hours as Record<string, unknown> | undefined)?.min_severity_during_quiet,
  "notifications.dedupe_window_seconds": (s) => s.dedupe_window_seconds,
  "notifications.max_attempts": (s) => s.max_attempts,
  "notifications.retry_base_seconds": (s) => s.retry_base_seconds,
  "notifications.retry_max_seconds": (s) => s.retry_max_seconds,
  "notifications.retention_days": (s) => s.retention_days
};

const LEGACY_SETTINGS: LegacySettingsAdapter = {
  load: async (signal) => {
    const settings = await getJson<Record<string, unknown>>(`${NOTIFY_BASE}/settings`, signal);
    const values: Record<string, SettingValue> = {};
    for (const [key, read] of Object.entries(LEGACY_KEYS)) {
      const value = read(settings);
      if (value !== undefined) values[key] = value as SettingValue;
    }
    return values;
  },
  save: async (changes) => {
    const current = await getJson<Record<string, unknown>>(`${NOTIFY_BASE}/settings`);
    const quiet = { ...((current.quiet_hours as Record<string, unknown>) ?? {}) };
    const next: Record<string, unknown> = { ...current };
    for (const [key, value] of Object.entries(changes)) {
      if (key.startsWith("notifications.quiet_hours.")) quiet[key.slice("notifications.quiet_hours.".length)] = value;
      else next[key.slice("notifications.".length)] = value;
    }
    next.quiet_hours = quiet;
    await mutateJson(`${NOTIFY_BASE}/settings`, { method: "PUT", body: next });
  }
};

export type RulesPanelProps = {
  user: AuthUser;
  /** Increment to open the rule builder (the page's primary button). */
  addRequest?: number;
};

export function RulesPanel({ user, addRequest = 0 }: RulesPanelProps) {
  const { language, isAdvanced, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const { ask, dialog: confirmDialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canWrite = hasPermission(user.permissions, "notification:write");
  const [channels, setChannels] = useState<Channel[] | null>(null);
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const controller = useRef<AbortController | null>(null);

  // simple builder
  const [builderOpen, setBuilderOpen] = useState(false);
  const [channelId, setChannelId] = useState("");
  const [topics, setTopics] = useState<("all" | Family)[]>(["backups", "server"]);
  const [severity, setSeverity] = useState<Severity>("warning");
  const [builderBusy, setBuilderBusy] = useState(false);
  const [builderError, setBuilderError] = useState<unknown>(null);
  const [builderProblem, setBuilderProblem] = useState<string | null>(null);

  // advanced pattern editor
  const [patternEdit, setPatternEdit] = useState<{ rule: Rule | null } | null>(null);
  const [pattern, setPattern] = useState("*");
  const [patternSeverity, setPatternSeverity] = useState<Severity>("warning");
  const [patternChannel, setPatternChannel] = useState("");
  const [patternEnabled, setPatternEnabled] = useState(true);
  const [patternBusy, setPatternBusy] = useState(false);
  const [patternError, setPatternError] = useState<unknown>(null);
  const [patternProblem, setPatternProblem] = useState<string | null>(null);

  // test event
  const [testSeverity, setTestSeverity] = useState<Severity>("warning");
  const [testBusy, setTestBusy] = useState(false);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      const [channelPayload, rulePayload] = await Promise.all([
        getJson<{ items: Channel[] }>(`${NOTIFY_BASE}/channels`, current.signal),
        getJson<{ items: Rule[] }>(`${NOTIFY_BASE}/rules`, current.signal)
      ]);
      setChannels(channelPayload.items ?? []);
      setRules(rulePayload.items ?? []);
      setLoadError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setLoadError(caught);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const channelList = channels ?? [];
  const channelById = useMemo(() => new Map(channelList.map((item) => [item.id, item])), [channelList]);

  const openBuilder = useCallback(() => {
    setChannelId(channelList[0]?.id ?? "");
    setTopics(["backups", "server"]);
    setSeverity("warning");
    setBuilderError(null);
    setBuilderProblem(null);
    setBuilderOpen(true);
  }, [channelList]);

  useEffect(() => {
    if (addRequest > 0 && canWrite && channelList.length > 0) openBuilder();
    // only react to the request counter
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [addRequest]);

  const topicName = (topic: RuleGroup["topic"] | "all" | Family, rule?: Rule) => {
    if (topic === "all") return pick(language, T.anything);
    if (topic === "event" && rule) return pick(language, EVENT_PHRASES[rule.event_pattern]);
    if (topic === "other") return pick(language, T.other);
    return pick(language, EVENT_FAMILY_WORDS[topic].label);
  };

  const sentence = (channel: Channel | undefined, sev: Severity, topicList: ("all" | Family)[] | null, rule?: Rule, topic?: RuleGroup["topic"]) => {
    let when: string;
    if (topic === "event" && rule) when = pick(language, EVENT_PHRASES[rule.event_pattern]);
    else if (topicList?.includes("all") || topic === "all") when = pick(language, IMPORTANCE[sev].any);
    else {
      const names = topicList ? topicList.map((item) => topicName(item)) : [topicName(topic ?? "other", rule)];
      const quoted = language === "fa" ? names.map((item) => `«${item}»`) : names;
      const joined = quoted.length > 1
        ? `${quoted.slice(0, -1).join(language === "fa" ? "، " : ", ")}${language === "fa" ? " و " : " and "}${quoted[quoted.length - 1]}`
        : quoted[0];
      when = say(language, IMPORTANCE[sev].phrase, { topic: joined });
    }
    return say(language, T.sentence, {
      when,
      kind: channel ? kindWord(language, channel.kind) : "",
      channel: channel?.name ?? pick(language, T.deletedChannel)
    });
  };

  const createFromBuilder = async () => {
    setBuilderProblem(null);
    setBuilderError(null);
    if (topics.length === 0) {
      setBuilderProblem(pick(language, T.pickTopic));
      return;
    }
    const patterns = topics.includes("all") ? ["*"] : [...new Set(topics.flatMap((item) => EVENT_FAMILY_WORDS[item].patterns))];
    setBuilderBusy(true);
    try {
      for (const item of patterns) {
        await mutateJson(`${NOTIFY_BASE}/rules`, { method: "POST", body: { event_pattern: item, min_severity: severity, channel_id: channelId, enabled: true } });
      }
      notify({ message: pick(language, T.createdToast) });
      setBuilderOpen(false);
    } catch (caught) {
      setBuilderError(caught);
    } finally {
      setBuilderBusy(false);
      void load();
    }
  };

  const setGroupEnabled = async (group: RuleGroup, enabled: boolean, quiet = false) => {
    try {
      for (const rule of group.rules) await mutateJson(`${NOTIFY_BASE}/rules/${encodeURIComponent(rule.id)}`, { method: "PATCH", body: { enabled } });
      if (!quiet) notify({ message: pick(language, enabled ? T.turnedOn : T.turnedOff), onUndo: () => void setGroupEnabled({ ...group, enabled }, !enabled, true) });
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
    await load();
  };

  const removeGroup = async (group: RuleGroup) => {
    const ok = await ask({
      title: pick(language, T.deleteTitle),
      body: sentence(channelById.get(group.channelId), group.severity, null, group.rules[0], group.topic),
      severity: "destructive",
      undoable: false
    });
    if (!ok) return;
    try {
      for (const rule of group.rules) await mutateJson(`${NOTIFY_BASE}/rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" });
      notify({ message: pick(language, T.deletedToast) });
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
    await load();
  };

  const openPattern = (rule: Rule | null) => {
    setPatternEdit({ rule });
    setPattern(rule?.event_pattern ?? "*");
    setPatternSeverity(rule?.min_severity ?? "warning");
    setPatternChannel(rule?.channel_id ?? channelList[0]?.id ?? "");
    setPatternEnabled(rule?.enabled ?? true);
    setPatternError(null);
    setPatternProblem(null);
  };

  const savePattern = async () => {
    setPatternError(null);
    setPatternProblem(null);
    if (!pattern.trim() || pattern.trim().length > 200) {
      setPatternProblem(pick(language, T.patternRule));
      return;
    }
    setPatternBusy(true);
    try {
      const body = { event_pattern: pattern.trim(), min_severity: patternSeverity, channel_id: patternChannel, enabled: patternEnabled };
      if (patternEdit?.rule) await mutateJson(`${NOTIFY_BASE}/rules/${encodeURIComponent(patternEdit.rule.id)}`, { method: "PATCH", body });
      else await mutateJson(`${NOTIFY_BASE}/rules`, { method: "POST", body });
      notify({ message: pick(language, T.savedToast) });
      setPatternEdit(null);
      await load();
    } catch (caught) {
      setPatternError(caught);
    } finally {
      setPatternBusy(false);
    }
  };

  const sendTestEvent = async () => {
    setTestBusy(true);
    try {
      const payload = await mutateJson<{ queued?: number | boolean; deliveries?: number }>(`${NOTIFY_BASE}/test-event`, { method: "POST", body: { severity: testSeverity } });
      const count = typeof payload?.queued === "number" ? payload.queued : typeof payload?.deliveries === "number" ? payload.deliveries : payload?.queued ? 1 : 0;
      notify({ message: count > 0 ? say(language, T.testQueued, { count }) : pick(language, T.testNone), tone: count > 0 ? "success" : "info" });
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    } finally {
      setTestBusy(false);
    }
  };

  const groups = useMemo(() => groupRules(rules ?? []), [rules]);
  const severityOptions = SEVERITIES.map((item) => <MenuItem key={item} value={item}>{severityWord(language, item).label}</MenuItem>);

  return (
    <Stack spacing={2.5}>
      {loadError !== null && <FriendlyError error={loadError} onRetry={() => void load()} />}
      <SectionCard
        title={pick(language, T.title)}
        hint={pick(language, T.hint)}
        action={canWrite && isAdvanced && channelList.length > 0 ? <Button startIcon={<AddRoundedIcon />} onClick={() => openPattern(null)} sx={{ minHeight: 44 }}>{pick(language, T.addPattern)}</Button> : undefined}
      >
        <Stack spacing={1.5}>
          {!canWrite && <NoAccess needs="notification:write" />}
          {rules === null && loadError === null && <Skeleton variant="rounded" height={120} />}
          {channels !== null && channelList.length === 0 && (
            <Notice tone="info" action={<Button color="inherit" href="#/alerts/channels" sx={{ minHeight: 40 }}>{pick(language, T.goChannels)}</Button>}>
              {pick(language, T.noChannels)}
            </Notice>
          )}
          {rules !== null && groups.length === 0 && channelList.length > 0 && (
            <EmptyState
              compact
              icon={RuleRoundedIcon}
              title={pick(language, T.emptyTitle)}
              body={pick(language, T.emptyBody)}
              action={canWrite ? <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={openBuilder} sx={{ minHeight: 44 }}>{pick(language, T.add)}</Button> : undefined}
            />
          )}
          {groups.map((group) => {
            const channel = channelById.get(group.channelId);
            return (
              <Card key={group.key} variant="outlined" sx={{ opacity: group.enabled ? 1 : 0.7 }}>
                <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                  <Stack direction="row" spacing={1.5} alignItems="flex-start">
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Typography sx={{ fontWeight: 650, lineHeight: 1.9 }}>
                        {sentence(channel, group.severity, group.topic === "all" ? ["all"] : group.topic === "event" || group.topic === "other" ? null : [group.topic], group.rules[0], group.topic)}
                      </Typography>
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 0.75 }}>
                        <StatusPill tone={group.enabled ? "ok" : "off"} label={pick(language, group.enabled ? T.on : T.off)} />
                        <StatusPill tone={severityWord(language, group.severity).tone} label={pick(language, IMPORTANCE[group.severity].label)} />
                      </Stack>
                      {(isAdvanced || group.topic === "other") && (
                        <Stack spacing={0.25} sx={{ mt: 1 }}>
                          {group.rules.map((rule) => (
                            <Stack key={rule.id} direction="row" spacing={0.5} alignItems="center">
                              <Typography variant="caption" color="text.secondary">{pick(language, T.patterns)}<Ltr mono>{rule.event_pattern}</Ltr></Typography>
                              {isAdvanced && canWrite && (
                                <Tooltip title={pick(language, T.edit)}>
                                  <IconButton size="small" aria-label={`${pick(language, T.edit)} ${rule.event_pattern}`} onClick={() => openPattern(rule)}><EditRoundedIcon fontSize="small" /></IconButton>
                                </Tooltip>
                              )}
                            </Stack>
                          ))}
                        </Stack>
                      )}
                    </Box>
                    <Switch checked={group.enabled} disabled={!canWrite} onChange={(_event, value) => void setGroupEnabled(group, value)} slotProps={{ input: { "aria-label": pick(language, T.toggle) } }} />
                    {canWrite && (
                      <Tooltip title={pick(language, T.remove)}>
                        <IconButton color="error" aria-label={pick(language, T.remove)} onClick={() => void removeGroup(group)} sx={{ width: 44, height: 44 }}><DeleteOutlineRoundedIcon /></IconButton>
                      </Tooltip>
                    )}
                  </Stack>
                </CardContent>
              </Card>
            );
          })}
          {canWrite && groups.length > 0 && channelList.length > 0 && (
            <Box><Button startIcon={<AddRoundedIcon />} onClick={openBuilder} sx={{ minHeight: 44 }}>{pick(language, T.add)}</Button></Box>
          )}
        </Stack>
      </SectionCard>

      {isAdvanced && (
        <>
          <RegistrySettings groups={["alerts"]} legacy={LEGACY_SETTINGS} permissions={user.permissions} title={pick(language, T.settingsTitle)} hint={pick(language, T.settingsHint)} />
          <SectionCard title={pick(language, T.testTitle)} hint={pick(language, T.testHint)}>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
              <TextField select size="small" label={pick(language, T.testSeverity)} value={testSeverity} disabled={!canWrite || testBusy} onChange={(event) => setTestSeverity(event.target.value as Severity)} sx={{ minWidth: 200 }}>
                {severityOptions}
              </TextField>
              <Button variant="outlined" startIcon={<SendRoundedIcon />} disabled={!canWrite || testBusy} onClick={() => void sendTestEvent()} sx={{ minHeight: 44 }}>{pick(language, T.testSend)}</Button>
            </Stack>
          </SectionCard>
        </>
      )}

      <Dialog open={builderOpen} onClose={builderBusy ? undefined : () => setBuilderOpen(false)} fullScreen={fullScreen} fullWidth maxWidth="sm" aria-labelledby="mrk-rule-builder-title">
        <DialogTitle id="mrk-rule-builder-title" sx={{ fontWeight: 760 }}>{pick(language, T.builderTitle)}</DialogTitle>
        <DialogContent>
          <Stack spacing={2.5} sx={{ pt: 0.5 }}>
            <TextField select fullWidth label={pick(language, T.where)} value={channelId} onChange={(event) => setChannelId(event.target.value)}>
              {channelList.map((item) => <MenuItem key={item.id} value={item.id}>{kindWord(language, item.kind)} · {item.name}</MenuItem>)}
            </TextField>
            <Box>
              <Typography component="h3" variant="subtitle2" sx={{ fontWeight: 760, mb: 0.5 }}>{pick(language, T.what)}</Typography>
              <FormGroup>
                <FormControlLabel
                  control={<Checkbox checked={topics.includes("all")} onChange={(_event, on) => setTopics(on ? ["all"] : [])} />}
                  label={pick(language, T.everything)}
                />
                {(Object.keys(EVENT_FAMILY_WORDS) as Family[]).map((key) => (
                  <FormControlLabel
                    key={key}
                    control={
                      <Checkbox
                        checked={topics.includes(key)}
                        disabled={topics.includes("all")}
                        onChange={(_event, on) => setTopics((current) => (on ? [...current.filter((item) => item !== "all"), key] : current.filter((item) => item !== key)))}
                      />
                    }
                    label={pick(language, EVENT_FAMILY_WORDS[key].label)}
                  />
                ))}
              </FormGroup>
            </Box>
            <Box>
              <Typography component="h3" variant="subtitle2" sx={{ fontWeight: 760, mb: 0.5 }}>{pick(language, T.how)}</Typography>
              <RadioGroup value={severity} onChange={(_event, value) => setSeverity(value as Severity)}>
                {SEVERITIES.map((item) => (
                  <FormControlLabel
                    key={item}
                    value={item}
                    control={<Radio />}
                    label={<Box><Typography variant="body2" sx={{ fontWeight: 650 }}>{pick(language, IMPORTANCE[item].label)}</Typography><Typography variant="caption" color="text.secondary">{pick(language, IMPORTANCE[item].hint)}</Typography></Box>}
                    sx={{ alignItems: "flex-start", mb: 0.5, "& .MuiRadio-root": { pt: 0.5 } }}
                  />
                ))}
              </RadioGroup>
            </Box>
            <Box sx={{ p: 1.5, borderRadius: 1.25, bgcolor: "action.hover" }} role="status" aria-live="polite">
              <Typography variant="caption" color="text.secondary">{pick(language, T.preview)}</Typography>
              <Typography sx={{ fontWeight: 650, lineHeight: 1.9 }}>
                {topics.length ? sentence(channelById.get(channelId), severity, topics) : pick(language, T.pickTopic)}
              </Typography>
            </Box>
            {builderProblem && <Typography role="alert" color="error.main" variant="body2">{builderProblem}</Typography>}
            {builderError !== null && <FriendlyError error={builderError} noAction />}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button onClick={() => setBuilderOpen(false)} disabled={builderBusy} sx={{ minHeight: 44 }}>{c.cancel}</Button>
          <Button variant="contained" onClick={() => void createFromBuilder()} disabled={builderBusy || !channelId} sx={{ minHeight: 44 }}>{builderBusy ? c.saving : pick(language, T.save)}</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={patternEdit !== null} onClose={patternBusy ? undefined : () => setPatternEdit(null)} fullScreen={fullScreen} fullWidth maxWidth="xs" aria-labelledby="mrk-rule-pattern-title">
        <DialogTitle id="mrk-rule-pattern-title" sx={{ fontWeight: 760 }}>{pick(language, patternEdit?.rule ? T.patternTitle : T.patternNew)}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} sx={{ pt: 0.5 }}>
            <TextField
              fullWidth
              label={pick(language, T.pattern)}
              value={pattern}
              onChange={(event) => setPattern(event.target.value)}
              error={Boolean(patternProblem)}
              helperText={patternProblem ?? pick(language, T.patternHint)}
              slotProps={{ htmlInput: { dir: "ltr", maxLength: 200, spellCheck: false } }}
            />
            <TextField select fullWidth label={pick(language, T.minSeverity)} value={patternSeverity} onChange={(event) => setPatternSeverity(event.target.value as Severity)}>{severityOptions}</TextField>
            <TextField select fullWidth label={pick(language, T.channel)} value={patternChannel} onChange={(event) => setPatternChannel(event.target.value)}>
              {channelList.map((item) => <MenuItem key={item.id} value={item.id}>{kindWord(language, item.kind)} · {item.name}</MenuItem>)}
            </TextField>
            <FormControlLabel control={<Switch checked={patternEnabled} onChange={(_event, value) => setPatternEnabled(value)} />} label={pick(language, T.enabled)} />
            {patternError !== null && <FriendlyError error={patternError} noAction />}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button onClick={() => setPatternEdit(null)} disabled={patternBusy} sx={{ minHeight: 44 }}>{c.cancel}</Button>
          <Button variant="contained" onClick={() => void savePattern()} disabled={patternBusy || !patternChannel} sx={{ minHeight: 44 }}>{patternBusy ? c.saving : c.save}</Button>
        </DialogActions>
      </Dialog>

      {confirmDialog}
      {snackbar}
    </Stack>
  );
}

export default RulesPanel;
