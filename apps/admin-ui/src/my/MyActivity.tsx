/** «فضای من › تاریخچه» (docs/43 §3 `GET /my/activity`): every change in this workspace, in plain sentences. */
import { useCallback, useEffect, useRef, useState } from "react";
import { Box, Button, CircularProgress, Stack, Typography } from "@mui/material";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import { ApiError, isAbortError } from "../api";
import { humanizeAudit, MY_ACTIVITY, pick, say } from "../copy";
import { EmptyState, RelativeTime, ResponsiveList, SectionCard, StatusPill, useKit, type ListColumn } from "../kit";
import { Loading } from "../dnsUi";
import { fetchActivity, type MyEvent } from "./myApi";
import { MyError } from "./MyKit";

/** My space actions mirror the admin ones (`my.dns.zone.create` → `dns.zone.create`) so the audit catalog words them. */
function sentenceOf(language: "fa" | "en", event: MyEvent) {
  const action = event.action.replace(/^my\./, "");
  return humanizeAudit(language, { ...event, action }, { actorName: event.actor, targetName: event.object_id !== null && event.object_id !== undefined ? String(event.object_id) : null });
}

export default function MyActivity() {
  const { language } = useKit();
  const [items, setItems] = useState<MyEvent[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async (cursor: string | null) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      const page = await fetchActivity(cursor, current.signal);
      setItems((list) => (cursor ? [...(list ?? []), ...page.items] : page.items));
      setNext(page.next);
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(null);
    return () => controller.current?.abort();
  }, [load]);

  const columns: ListColumn<MyEvent>[] = [
    {
      key: "what",
      header: pick(language, MY_ACTIVITY.colWhat),
      render: (event) => (
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="body2" fontWeight={600}>{sentenceOf(language, event).sentence}</Typography>
          {event.on_behalf_of && <Typography variant="caption" color="warning.main">{say(language, MY_ACTIVITY.onBehalf, { name: event.on_behalf_of })}</Typography>}
        </Box>
      )
    },
    { key: "when", header: pick(language, MY_ACTIVITY.colWhen), render: (event) => <RelativeTime value={event.created_at ?? null} /> },
    {
      key: "result",
      header: pick(language, MY_ACTIVITY.colResult),
      render: (event) => {
        const result = sentenceOf(language, event).result;
        return <StatusPill tone={result.tone} label={result.label} />;
      }
    }
  ];

  return (
    <SectionCard title={pick(language, MY_ACTIVITY.title)} hint={pick(language, MY_ACTIVITY.hint)} flush>
      {error ? <Box sx={{ p: 2 }}><MyError error={error} onRetry={() => void load(null)} /></Box> : null}
      {loading && !items ? <Loading /> : null}
      {items && (
        <ResponsiveList
          label={pick(language, MY_ACTIVITY.listLabel)}
          rows={items}
          rowKey={(event) => event.id}
          columns={columns}
          card={{ title: (event) => sentenceOf(language, event).sentence, meta: (event) => <RelativeTime value={event.created_at ?? null} /> }}
          empty={<EmptyState icon={HistoryRoundedIcon} title={pick(language, MY_ACTIVITY.emptyTitle)} body={pick(language, MY_ACTIVITY.emptyBody)} />}
        />
      )}
      {next && (
        <Stack alignItems="center" sx={{ p: 1.5 }}>
          <Button disabled={loading} onClick={() => void load(next)} startIcon={loading ? <CircularProgress size={14} /> : undefined} sx={{ minHeight: 44 }}>{pick(language, MY_ACTIVITY.more)}</Button>
        </Stack>
      )}
    </SectionCard>
  );
}
