import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Box, Button, Card, CardContent, Chip, Collapse, Dialog, DialogActions, DialogContent, DialogTitle, LinearProgress, MenuItem, Skeleton,
  Stack, TextField, ToggleButton, ToggleButtonGroup, Typography, useMediaQuery, useTheme
} from "@mui/material";
import CancelRoundedIcon from "@mui/icons-material/CancelRounded";
import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import WorkHistoryRoundedIcon from "@mui/icons-material/WorkHistoryRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { Language } from "./i18n";
import { DateTime, EmptyState, FriendlyError, KeyValueList, Ltr, NoAccess, RelativeTime, StatusPill, useConfirmAction, useKit, useUndoSnackbar } from "./kit";
import { CONFIRM_COPY, CONFIRM_TOKENS, TASK_KIND_WORDS, errorSentence, pick, reasonFor, say, type Bi } from "./copy";

export type TaskState = "pending" | "running" | "succeeded" | "failed" | "cancelled";

export type TaskRecord = {
  id: string;
  kind: string;
  state: TaskState;
  progress: number;
  error_code: string | null;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
  retry_of: string | null;
  cancel_requested?: boolean;
  cancellable?: boolean;
  actor_user_id?: number | null;
  result: Record<string, unknown> | null;
};

type Filter = "all" | "active" | "failed" | "done";

const ACTIVE_POLL_MS = 3000;
const IDLE_POLL_MS = 30000;

const T = {
  title: { fa: "کارهای پس‌زمینه", en: "Background jobs" },
  hint: { fa: "کارهای طولانی مثل پیش‌دریافت، پاک کردن بسته و پشتیبان‌گیری این‌جا دیده می‌شوند.", en: "Long work like downloading ahead, removing packages and backups shows up here." },
  filterAll: { fa: "همه", en: "All" },
  filterActive: { fa: "در حال انجام", en: "Running" },
  filterFailed: { fa: "انجام نشده", en: "Didn't finish" },
  filterDone: { fa: "تمام شده", en: "Done" },
  filterLabel: { fa: "کدام کارها را نشان بدهیم", en: "Which jobs to show" },
  unknownKind: { fa: "کار پس‌زمینه", en: "Background job" },
  emptyTitle: { fa: "هنوز کاری انجام نشده", en: "No jobs yet" },
  emptyBody: { fa: "وقتی مثلاً بسته‌ها را از قبل دانلود کنید، پیشرفتش را این‌جا می‌بینید.", en: "When you, say, download packages ahead, you'll see the progress here." },
  emptyAction: { fa: "پیش‌دریافت بسته‌ها", en: "Download packages ahead" },
  emptyFilter: { fa: "در این دسته کاری نیست.", en: "No jobs in this group." },
  started: { fa: "شروع: ", en: "Started " },
  queued: { fa: "در نوبت از ", en: "Waiting since " },
  finished: { fa: "تمام شد: ", en: "Finished " },
  cancelling: { fa: "در حال لغو…", en: "Cancelling…" },
  cancel: { fa: "لغو کن", en: "Cancel" },
  retry: { fa: "دوباره انجام بده", en: "Run again" },
  noRetry: { fa: "این کار تکرار نمی‌شود؛ یک پشتیبان تازه بسازید.", en: "This job can't be repeated; start a new backup instead." },
  readOnly: { fa: "نقش شما فقط اجازه دیدن کارها را دارد.", en: "Your role can only see jobs." },
  cancelTitle: { fa: "کار «{kind}» لغو شود؟", en: "Cancel “{kind}”?" },
  cancelBody: { fa: "کار همین‌جا متوقف می‌شود. هر بخشی که انجام شده، می‌ماند.", en: "The job stops here. Whatever was already done stays." },
  cancelYes: { fa: "بله، لغو کن", en: "Yes, cancel" },
  cancelled: { fa: "درخواست لغو فرستاده شد.", en: "Cancel requested." },
  retryTitle: { fa: "«{kind}» دوباره انجام شود؟", en: "Run “{kind}” again?" },
  retryBody: { fa: "همان کار با همان ورودی دوباره شروع می‌شود. اگر دلیل مشکل برطرف نشده، باز هم انجام نمی‌شود.", en: "The same job starts again with the same input. If the cause isn't fixed, it may fail again." },
  retried: { fa: "دوباره شروع شد؛ پیشرفتش را همین‌جا ببینید.", en: "Started again; watch its progress here." },
  // purge retry
  purgeTitle: { fa: "پاک کردن دوباره بسته", en: "Remove the package again" },
  purgeBody: { fa: "این کار بسته را از ذخیره محلی پاک می‌کند. برای اطمینان، بگویید کدام بسته است.", en: "This removes the package from local copies. To be sure, say which package it is." },
  ecosystem: { fa: "نوع بسته", en: "Package type" },
  packageName: { fa: "نام بسته (مثل «requests»)", en: "Package name (like requests)" },
  purgeYes: { fa: "بله، دوباره پاک کن", en: "Yes, remove again" },
  // advanced
  details: { fa: "جزئیات فنی", en: "Technical details" },
  advId: { fa: "شناسه", en: "ID" },
  advRetryOf: { fa: "تکرارِ کار", en: "Retry of" },
  advCode: { fa: "کد خطا", en: "Error code" },
  advCreated: { fa: "ساخته شد", en: "Created" },
  advStarted: { fa: "شروع شد", en: "Started" },
  advFinished: { fa: "تمام شد", en: "Finished" },
  advKind: { fa: "نوع کار", en: "Job type" },
  advResult: { fa: "نتیجه", en: "Result" }
} satisfies Record<string, Bi>;

function kindName(language: Language, kind: string) {
  return TASK_KIND_WORDS[kind]?.[language] ?? pick(language, T.unknownKind);
}

function initialFilter(): Filter {
  const match = /[?&]state=(\w+)/.exec(window.location.hash);
  if (!match) return "all";
  if (match[1] === "failed" || match[1] === "cancelled") return "failed";
  if (match[1] === "running" || match[1] === "pending") return "active";
  if (match[1] === "succeeded") return "done";
  return "all";
}

export type JobsPanelProps = {
  permissions: string[];
  /** Accepted for compatibility with the old shell; language comes from the kit. */
  language?: Language;
  onUnauthorized?: () => void;
};

export function JobsPanel({ permissions }: JobsPanelProps) {
  const { language, isAdvanced } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const { ask, dialog: confirmDialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canRead = hasPermission(permissions, "task:read");
  const canWrite = hasPermission(permissions, "task:write");
  const [items, setItems] = useState<TaskRecord[] | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [filter, setFilter] = useState<Filter>(initialFilter);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [purge, setPurge] = useState<{ task: TaskRecord; ecosystem: string; name: string; error: unknown } | null>(null);
  const inFlight = useRef(false);
  const itemsRef = useRef<TaskRecord[]>([]);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async (background = false) => {
    if (inFlight.current && background) return;
    inFlight.current = true;
    const current = new AbortController();
    controller.current = current;
    try {
      const payload = await getJson<{ items: TaskRecord[] }>("/api/v1/tasks?limit=100", current.signal);
      itemsRef.current = payload.items ?? [];
      setItems(payload.items ?? []);
      setLoadError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setLoadError(caught);
    } finally {
      inFlight.current = false;
    }
  }, []);

  useEffect(() => {
    if (!canRead) return;
    // Poll fast only while something is running; slow down when idle; pause while hidden.
    let timer: number | undefined;
    let stopped = false;
    const schedule = () => {
      const active = itemsRef.current.some((item) => item.state === "pending" || item.state === "running");
      timer = window.setTimeout(tick, active ? ACTIVE_POLL_MS : IDLE_POLL_MS);
    };
    const tick = async () => {
      if (stopped) return;
      if (!document.hidden) await load(true);
      if (!stopped) schedule();
    };
    void load().then(() => {
      if (!stopped) schedule();
    });
    const onVisibility = () => {
      if (!document.hidden) void load(true);
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      controller.current?.abort();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [canRead, load]);

  const counts = useMemo(() => {
    const list = items ?? [];
    return {
      all: list.length,
      active: list.filter((item) => item.state === "pending" || item.state === "running").length,
      failed: list.filter((item) => item.state === "failed" || item.state === "cancelled").length,
      done: list.filter((item) => item.state === "succeeded").length
    };
  }, [items]);

  const shown = useMemo(() => {
    const list = items ?? [];
    if (filter === "active") return list.filter((item) => item.state === "pending" || item.state === "running");
    if (filter === "failed") return list.filter((item) => item.state === "failed" || item.state === "cancelled");
    if (filter === "done") return list.filter((item) => item.state === "succeeded");
    return list;
  }, [items, filter]);

  const post = async (task: TaskRecord, action: "cancel" | "retry", body?: object) => {
    setBusyId(task.id);
    try {
      await mutateJson(`/api/v1/tasks/${encodeURIComponent(task.id)}/${action}`, { method: "POST", body });
      notify({ message: pick(language, action === "cancel" ? T.cancelled : T.retried) });
      await load(true);
      return null;
    } catch (caught) {
      return caught;
    } finally {
      setBusyId(null);
    }
  };

  const cancel = async (task: TaskRecord) => {
    const ok = await ask({ title: say(language, T.cancelTitle, { kind: kindName(language, task.kind) }), body: pick(language, T.cancelBody), confirmLabel: pick(language, T.cancelYes) });
    if (!ok) return;
    const failure = await post(task, "cancel");
    if (failure) notify({ message: errorSentence(language, failure), tone: "error" });
  };

  const retry = async (task: TaskRecord) => {
    if (task.kind === "package.purge") {
      const result = task.result ?? {};
      setPurge({ task, ecosystem: typeof result.ecosystem === "string" ? result.ecosystem : "npm", name: typeof result.name === "string" ? result.name : "", error: null });
      return;
    }
    const ok = await ask({ title: say(language, T.retryTitle, { kind: kindName(language, task.kind) }), body: pick(language, T.retryBody), confirmLabel: pick(language, T.retry) });
    if (!ok) return;
    const failure = await post(task, "retry");
    if (failure) notify({ message: errorSentence(language, failure), tone: "error" });
  };

  const confirmPurge = async () => {
    if (!purge || !purge.name.trim()) return;
    const failure = await post(purge.task, "retry", { confirmation: CONFIRM_TOKENS.purge(purge.ecosystem, purge.name.trim()) });
    if (failure) setPurge({ ...purge, error: failure });
    else setPurge(null);
  };

  if (!canRead) return <NoAccess needs="task:read" variant="card" />;

  const filterLabel: Record<Filter, Bi> = { all: T.filterAll, active: T.filterActive, failed: T.filterFailed, done: T.filterDone };

  return (
    <Stack spacing={2}>
      {loadError !== null && <FriendlyError error={loadError} onRetry={() => void load()} />}
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }} justifyContent="space-between">
        <ToggleButtonGroup
          exclusive
          size="small"
          value={filter}
          onChange={(_event, next: Filter | null) => next && setFilter(next)}
          aria-label={pick(language, T.filterLabel)}
          sx={{ flexWrap: "wrap", "& .MuiToggleButton-root": { minHeight: 40, px: 1.5, gap: 0.75 } }}
        >
          {(["all", "active", "failed", "done"] as Filter[]).map((key) => (
            <ToggleButton key={key} value={key}>
              {pick(language, filterLabel[key])}
              <Chip size="small" label={new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(counts[key])} sx={{ height: 20 }} />
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
        {!canWrite && <NoAccess needs="task:write" />}
      </Stack>

      {items === null && loadError === null && <Stack spacing={1.5}>{[0, 1, 2].map((key) => <Skeleton key={key} variant="rounded" height={88} />)}</Stack>}
      {items !== null && items.length === 0 && (
        <Card>
          <EmptyState
            icon={WorkHistoryRoundedIcon}
            title={pick(language, T.emptyTitle)}
            body={pick(language, T.emptyBody)}
            action={hasPermission(permissions, "cache:write") ? <Button variant="contained" href="#/packages/prefetch" sx={{ minHeight: 44 }}>{pick(language, T.emptyAction)}</Button> : undefined}
          />
        </Card>
      )}
      {items !== null && items.length > 0 && shown.length === 0 && <Typography color="text.secondary">{pick(language, T.emptyFilter)}</Typography>}

      <Stack spacing={1.5}>
        {shown.map((item) => {
          const cancelling = Boolean(item.cancel_requested) && (item.state === "pending" || item.state === "running");
          const active = item.state === "pending" || item.state === "running";
          const progress = item.state === "succeeded" ? 100 : item.state === "pending" ? 0 : Math.max(0, Math.min(100, item.progress ?? 0));
          const canCancel = canWrite && active && !cancelling && item.cancellable !== false;
          const retryable = item.state === "failed" || item.state === "cancelled";
          const name = kindName(language, item.kind);
          return (
            <Card key={item.id}>
              <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
                  <Box sx={{ minWidth: 0, flex: 1 }}>
                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                      <Typography component="h3" sx={{ fontWeight: 760 }}>{name}</Typography>
                      {cancelling ? <StatusPill tone="busy" label={pick(language, T.cancelling)} /> : <StatusPill status={item.state} />}
                    </Stack>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
                      {item.finished_at
                        ? <>{pick(language, T.finished)}<RelativeTime value={item.finished_at} /></>
                        : item.started_at
                          ? <>{pick(language, T.started)}<RelativeTime value={item.started_at} /></>
                          : <>{pick(language, T.queued)}<RelativeTime value={item.created_at} /></>}
                    </Typography>
                    {item.state === "failed" && <Typography variant="body2" color="error.main" sx={{ mt: 0.75 }}>{reasonFor(language, item.error_code)}</Typography>}
                    {(active || item.state === "failed") && (
                      <LinearProgress
                        variant={item.state === "pending" ? "indeterminate" : "determinate"}
                        value={progress}
                        aria-label={`${name}: ${new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(progress)}%`}
                        color={item.state === "failed" ? "error" : "primary"}
                        sx={{ mt: 1.25, height: 6, borderRadius: 1 }}
                      />
                    )}
                  </Box>
                  <Stack direction="row" spacing={1} sx={{ flexShrink: 0 }}>
                    {canCancel && (
                      <Button color="warning" disabled={busyId === item.id} startIcon={<CancelRoundedIcon />} onClick={() => void cancel(item)} sx={{ minHeight: 44 }}>{pick(language, T.cancel)}</Button>
                    )}
                    {canWrite && retryable && item.kind !== "backup.create" && item.kind !== "lifecycle.cleanup" && (
                      <Button disabled={busyId === item.id} startIcon={<ReplayRoundedIcon />} onClick={() => void retry(item)} sx={{ minHeight: 44 }}>{pick(language, T.retry)}</Button>
                    )}
                  </Stack>
                </Stack>
                {canWrite && retryable && item.kind === "backup.create" && <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>{pick(language, T.noRetry)}</Typography>}
                {isAdvanced && (
                  <Box sx={{ mt: 1 }}>
                    <Button size="small" onClick={() => setOpen((current) => ({ ...current, [item.id]: !current[item.id] }))} endIcon={<ExpandMoreRoundedIcon sx={{ transform: open[item.id] ? "rotate(180deg)" : undefined }} />} aria-expanded={Boolean(open[item.id])}>
                      {pick(language, T.details)}
                    </Button>
                    <Collapse in={Boolean(open[item.id])} unmountOnExit>
                      <Box sx={{ mt: 1 }}>
                        <KeyValueList
                          dense
                          items={[
                            { label: pick(language, T.advId), value: item.id, ltr: true, copy: true },
                            { label: pick(language, T.advKind), value: item.kind, ltr: true },
                            ...(item.retry_of ? [{ label: pick(language, T.advRetryOf), value: item.retry_of, ltr: true }] : []),
                            ...(item.error_code ? [{ label: pick(language, T.advCode), value: item.error_code, ltr: true, copy: true }] : []),
                            { label: pick(language, T.advCreated), value: <DateTime value={item.created_at} /> },
                            { label: pick(language, T.advStarted), value: item.started_at ? <DateTime value={item.started_at} /> : "—" },
                            { label: pick(language, T.advFinished), value: item.finished_at ? <DateTime value={item.finished_at} /> : "—" }
                          ]}
                        />
                        {item.result && (
                          <Box component="pre" dir="ltr" sx={{ mt: 1, mb: 0, p: 1, maxHeight: 180, overflow: "auto", bgcolor: "action.hover", borderRadius: 1, fontSize: 12, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }} aria-label={pick(language, T.advResult)}>
                            {JSON.stringify(item.result, null, 2)}
                          </Box>
                        )}
                      </Box>
                    </Collapse>
                  </Box>
                )}
              </CardContent>
            </Card>
          );
        })}
      </Stack>

      <Dialog open={purge !== null} onClose={busyId ? undefined : () => setPurge(null)} fullScreen={fullScreen} fullWidth maxWidth="xs" aria-labelledby="mrk-purge-retry-title">
        {purge && (
          <>
            <DialogTitle id="mrk-purge-retry-title" sx={{ fontWeight: 760 }}>{pick(language, T.purgeTitle)}</DialogTitle>
            <DialogContent>
              <Stack spacing={1.5} sx={{ pt: 0.5 }}>
                <Typography variant="body2" sx={{ lineHeight: 1.9 }}>{pick(language, T.purgeBody)}</Typography>
                <TextField select fullWidth label={pick(language, T.ecosystem)} value={purge.ecosystem} onChange={(event) => setPurge({ ...purge, ecosystem: event.target.value, error: null })}>
                  <MenuItem value="npm">npm</MenuItem>
                  <MenuItem value="pypi">PyPI</MenuItem>
                </TextField>
                <TextField fullWidth label={pick(language, T.packageName)} value={purge.name} onChange={(event) => setPurge({ ...purge, name: event.target.value, error: null })} slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
                {isAdvanced && purge.name.trim() && <Typography variant="caption" color="text.secondary"><Ltr mono>{CONFIRM_TOKENS.purge(purge.ecosystem, purge.name.trim())}</Ltr></Typography>}
                {purge.error !== null && <FriendlyError error={purge.error} noAction />}
              </Stack>
            </DialogContent>
            <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
              <Button onClick={() => setPurge(null)} disabled={busyId !== null} autoFocus sx={{ minHeight: 44 }}>{pick(language, CONFIRM_COPY.keepIt)}</Button>
              <Button variant="contained" color="error" onClick={() => void confirmPurge()} disabled={busyId !== null || !purge.name.trim()} sx={{ minHeight: 44 }}>{pick(language, T.purgeYes)}</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
      {confirmDialog}
      {snackbar}
    </Stack>
  );
}

export default JobsPanel;
