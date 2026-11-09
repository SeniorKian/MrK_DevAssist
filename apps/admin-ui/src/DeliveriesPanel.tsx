import { useCallback, useEffect, useRef, useState } from "react";
import { Box, Button, MenuItem, Skeleton, Stack, TextField, Typography } from "@mui/material";
import MarkEmailReadRoundedIcon from "@mui/icons-material/MarkEmailReadRounded";
import { ApiError, getJson, isAbortError } from "./api";
import { useVisibleInterval } from "./polling";
import { DateTime, EmptyState, FriendlyError, Ltr, Num, RelativeTime, ResponsiveList, SectionCard, StatusPill, useKit } from "./kit";
import { pick, reasonFor, severityWord, type Bi } from "./copy";
import { NOTIFY_BASE, DELIVERY_WORDS, deliveryWord } from "./ChannelsPanel";

type Delivery = {
  id: string;
  event_type: string;
  severity: string;
  title: string;
  channel_id: string | null;
  channel_name: string | null;
  status: string;
  attempts: number;
  error_code: string | null;
  created_at: number;
  sent_at: number | null;
};

const FILTERS = ["", "sent", "failed", "pending", "delayed", "suppressed"] as const;

const T = {
  title: { fa: "پیام‌های اخیر", en: "Recent messages" },
  hint: { fa: "آخرین پیام‌هایی که DevAssist به کانال‌ها فرستاده یا خواسته بفرستد.", en: "The latest messages DevAssist sent, or tried to send, to your channels." },
  titleAdvanced: { fa: "همه پیام‌ها", en: "All messages" },
  emptyTitle: { fa: "هنوز پیامی فرستاده نشده", en: "No messages sent yet" },
  emptyBody: { fa: "وقتی اتفاقی بیفتد که قاعده‌ای آن را بگیرد، این‌جا می‌بینید که پیامش رسید یا نه.", en: "When an event matches a rule, you'll see here whether its message got through." },
  filter: { fa: "نمایش", en: "Show" },
  all: { fa: "همه", en: "All" },
  deletedChannel: { fa: "کانال پاک‌شده", en: "Deleted channel" },
  colTime: { fa: "زمان", en: "Time" },
  colWhat: { fa: "پیام", en: "Message" },
  colSeverity: { fa: "اهمیت", en: "Severity" },
  colChannel: { fa: "کانال", en: "Channel" },
  colStatus: { fa: "وضعیت", en: "Status" },
  colAttempts: { fa: "تلاش‌ها", en: "Attempts" },
  colEvent: { fa: "نوع رویداد", en: "Event type" },
  colCode: { fa: "کد خطا", en: "Error code" },
  seeRules: { fa: "دیدن قواعد اعلان", en: "See alert rules" }
} satisfies Record<string, Bi>;

export type DeliveriesPanelProps = { refreshKey?: number };

/** Delivery feed: a short list in Simple mode, the full filterable log in Advanced. */
export function DeliveriesPanel({ refreshKey = 0 }: DeliveriesPanelProps) {
  const { language, isAdvanced, c } = useKit();
  const [status, setStatus] = useState<(typeof FILTERS)[number]>("");
  const [items, setItems] = useState<Delivery[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      const query = new URLSearchParams({ limit: isAdvanced ? "100" : "10" });
      if (isAdvanced && status) query.set("status", status);
      const payload = await getJson<{ items: Delivery[] }>(`${NOTIFY_BASE}/deliveries?${query.toString()}`, current.signal);
      setItems(payload.items ?? []);
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      if (caught instanceof ApiError && caught.status === 404) {
        setItems([]);
        return;
      }
      setError(caught);
    }
  }, [isAdvanced, status]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load, refreshKey]);
  useVisibleInterval(() => void load(), 30_000);

  const reason = (item: Delivery) => (item.status === "failed" || item.status === "error") && item.error_code ? reasonFor(language, item.error_code) : null;

  return (
    <SectionCard
      title={pick(language, isAdvanced ? T.titleAdvanced : T.title)}
      hint={pick(language, T.hint)}
      action={isAdvanced ? (
        <TextField select size="small" label={pick(language, T.filter)} value={status} onChange={(event) => setStatus(event.target.value as (typeof FILTERS)[number])} sx={{ minWidth: 200 }}>
          {FILTERS.map((item) => <MenuItem key={item || "all"} value={item}>{item ? DELIVERY_WORDS[item].label[language] : pick(language, T.all)}</MenuItem>)}
        </TextField>
      ) : undefined}
      flush
    >
      {error !== null && <Box sx={{ px: 2.5, pb: 1 }}><FriendlyError error={error} onRetry={() => void load()} /></Box>}
      {items === null && error === null && <Box sx={{ px: 2.5, pb: 2 }}><Skeleton variant="rounded" height={80} /></Box>}
      {items !== null && (
        <ResponsiveList
          label={pick(language, T.title)}
          rows={items}
          rowKey={(row) => row.id}
          dense
          columns={[
            { key: "time", header: pick(language, T.colTime), render: (row) => <RelativeTime value={row.sent_at ?? row.created_at} /> },
            {
              key: "what",
              header: pick(language, T.colWhat),
              render: (row) => (
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="body2" sx={{ fontWeight: 650 }}>{row.title || c.emptyDash}</Typography>
                  {reason(row) && <Typography variant="caption" color="error.main" display="block">{reason(row)}</Typography>}
                </Box>
              )
            },
            { key: "severity", header: pick(language, T.colSeverity), render: (row) => <StatusPill tone={severityWord(language, row.severity).tone} label={severityWord(language, row.severity).label} /> },
            { key: "channel", header: pick(language, T.colChannel), render: (row) => row.channel_name ?? pick(language, T.deletedChannel) },
            { key: "status", header: pick(language, T.colStatus), hideOnCard: true, render: (row) => <StatusPill tone={deliveryWord(language, row.status).tone} label={deliveryWord(language, row.status).label} /> },
            { key: "attempts", header: pick(language, T.colAttempts), advancedOnly: true, render: (row) => <Num value={row.attempts} /> },
            { key: "event", header: pick(language, T.colEvent), advancedOnly: true, ltr: true, render: (row) => <Ltr mono>{row.event_type}</Ltr> },
            { key: "code", header: pick(language, T.colCode), advancedOnly: true, ltr: true, render: (row) => (row.error_code ? <Ltr mono>{row.error_code}</Ltr> : c.emptyDash) },
            { key: "abs", header: pick(language, T.colTime), advancedOnly: true, render: (row) => <DateTime value={row.sent_at ?? row.created_at} /> }
          ]}
          card={{
            title: (row) => row.title || c.emptyDash,
            meta: (row) => (
              <Stack component="span" spacing={0.25}>
                <span>{row.channel_name ?? pick(language, T.deletedChannel)} · <RelativeTime value={row.sent_at ?? row.created_at} /></span>
                {reason(row) && <Typography component="span" variant="caption" color="error.main">{reason(row)}</Typography>}
              </Stack>
            ),
            status: (row) => <StatusPill tone={deliveryWord(language, row.status).tone} label={deliveryWord(language, row.status).label} />
          }}
          empty={<EmptyState compact icon={MarkEmailReadRoundedIcon} title={pick(language, T.emptyTitle)} body={pick(language, T.emptyBody)} action={<Button href="#/alerts/rules" sx={{ minHeight: 44 }}>{pick(language, T.seeRules)}</Button>} />}
        />
      )}
    </SectionCard>
  );
}

export default DeliveriesPanel;
