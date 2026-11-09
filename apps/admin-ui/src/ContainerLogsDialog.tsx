import { Fragment, useEffect, useLayoutEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  InputAdornment,
  LinearProgress,
  MenuItem,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
  useMediaQuery,
  useTheme
} from "@mui/material";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import PauseRoundedIcon from "@mui/icons-material/PauseRounded";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import { ApiError, getJson, isAbortError } from "./api";
import {
  FriendlyError, Notice, helperProblemText
} from "./kit";
import { formatNumber } from "./format";
import type { Language } from "./i18n";

type LogLine = { ts?: string | null; stream?: string; text: string };
type StreamState = "idle" | "connecting" | "live" | "reconnecting" | "ended" | "failed";

const BASE = "/api/v1/agent";
const MAX_LINES = 5000;
const MAX_RECONNECTS = 3;
const TAILS = [100, 200, 500, 1000, 5000] as const;

const labels = {
  fa: {
    title: "لاگ کانتینر",
    close: "بستن",
    tail: "چند خط آخر",
    follow: "نمایش زنده",
    timestamps: "زمان هر خط",
    search: "جست‌وجو در لاگ",
    searchServer: "جست‌وجو",
    searchHintFollow: "در نمایش زنده، جست‌وجو فقط خط‌های روی صفحه را پررنگ می‌کند.",
    clearSearch: "پاک کردن جست‌وجو",
    pause: "نگه داشتن پیمایش خودکار",
    resume: "ادامه پیمایش خودکار",
    download: "دانلود فایل متنی",
    reload: "تازه کردن",
    reconnect: "وصل شدن دوباره",
    lines: "خط",
    matches: "خط پیدا شد",
    truncated: "لاگ خیلی بزرگ بود و کوتاه شد. تعداد خط‌ها را کمتر کنید.",
    capped: "فقط {n} خط آخر نگه داشته می‌شود.",
    empty: "هنوز خطی برای نمایش نیست.",
    stream_connecting: "در حال وصل شدن…",
    stream_live: "زنده",
    stream_reconnecting: "در حال وصل شدن دوباره…",
    stream_ended: "نمایش زنده تمام شد",
    stream_failed: "نمایش زنده باز نشد",
    streamFailedBody: "لاگ زنده باز نشد. شاید دستیار سرور خاموش باشد یا نقش شما اجازه دیدن لاگ نداشته باشد.",
    streamEndedBody: "سرور بعد از مدتی نمایش زنده را می‌بندد. برای ادامه دوباره وصل شوید.",
    audited: "دیدن لاگ در تاریخچه ثبت می‌شود. رمزها پیش از نمایش پنهان می‌شوند."
  },
  en: {
    title: "Container logs",
    close: "Close",
    tail: "Last lines",
    follow: "Live view",
    timestamps: "Line times",
    search: "Search logs",
    searchServer: "Search",
    searchHintFollow: "In live view, search only highlights the lines on screen.",
    clearSearch: "Clear search",
    pause: "Pause auto-scroll",
    resume: "Resume auto-scroll",
    download: "Download text file",
    reload: "Refresh",
    reconnect: "Reconnect",
    lines: "lines",
    matches: "matching lines",
    truncated: "The log was too big and was cut short. Ask for fewer lines.",
    capped: "Only the last {n} lines are kept.",
    empty: "No lines to show yet.",
    stream_connecting: "Connecting…",
    stream_live: "Live",
    stream_reconnecting: "Reconnecting…",
    stream_ended: "Live view ended",
    stream_failed: "Live view didn't open",
    streamFailedBody: "The live log didn't open. The server helper may be off, or your role may not be allowed to see logs.",
    streamEndedBody: "The server closes live view after a while. Reconnect to continue.",
    audited: "Viewing logs is recorded in the history. Passwords are hidden before they're shown."
  }
} as const;

const LOGS_MISSING = { fa: "دیدن لاگ روی نسخه فعلی سرور نیست. پیشکار را به‌روز کنید.", en: "Viewing logs isn't on your server's current version. Update Pishkar." };

/** A plain sentence for module-missing / not-paired / helper-down; null → let FriendlyError explain. */
function logsStatusText(language: Language, error: unknown): string | null {
  return helperProblemText(language, error, { module_missing: LOGS_MISSING });
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function highlight(text: string, pattern: RegExp | null): ReactNode {
  if (!pattern) return text;
  const parts = text.split(pattern);
  if (parts.length === 1) return text;
  return parts.map((part, index) => (index % 2 === 1 ? <mark key={index} style={{ background: "#facc15", color: "#111827", borderRadius: 2 }}>{part}</mark> : <Fragment key={index}>{part}</Fragment>));
}

function shortTs(ts: string | null | undefined) {
  if (!ts) return "";
  return ts.replace("T", " ").replace(/(\.\d{3})\d*/, "$1").replace(/Z$|[+-]\d{2}:\d{2}$/, "");
}

function normalizeLine(raw: unknown): LogLine | null {
  if (typeof raw === "string") return { text: raw, stream: "stdout" };
  if (raw && typeof raw === "object" && typeof (raw as LogLine).text === "string") return raw as LogLine;
  return null;
}

function LogsBody({ id, name, language }: { id: string; name: string; language: Language }) {
  const copy = labels[language];
  const theme = useTheme();
  const [tail, setTail] = useState<number>(200);
  const [follow, setFollow] = useState(false);
  const [timestamps, setTimestamps] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const [query, setQuery] = useState("");
  const [appliedSearch, setAppliedSearch] = useState("");
  const [lines, setLines] = useState<LogLine[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [stream, setStream] = useState<StreamState>("idle");
  const [reloadToken, setReloadToken] = useState(0);
  const scroller = useRef<HTMLDivElement | null>(null);

  // One-shot (non-follow) load: server-side search.
  useEffect(() => {
    if (follow) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    setStream("idle");
    const params = new URLSearchParams({ tail: String(tail), timestamps: "1" });
    if (appliedSearch) params.set("search", appliedSearch);
    void (async () => {
      try {
        const payload = await getJson<{ lines: unknown[]; truncated?: boolean }>(`${BASE}/containers/${encodeURIComponent(id)}/logs?${params.toString()}`, controller.signal);
        const parsed = (payload.lines ?? []).map(normalizeLine).filter((line): line is LogLine => line !== null);
        setLines(parsed.slice(-MAX_LINES));
        setTruncated(Boolean(payload.truncated));
      } catch (caught) {
        if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
        setError(caught);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    })();
    return () => controller.abort();
  }, [appliedSearch, follow, id, reloadToken, tail]);

  // Live follow over SSE; closed on toggle-off/unmount, limited reconnects.
  useEffect(() => {
    if (!follow) return;
    let source: EventSource | null = null;
    let attempts = 0;
    let retryTimer: number | undefined;
    let closed = false;
    let pending: LogLine[] = [];
    let resetBuffer = true;
    setError(null);
    setTruncated(false);
    setLoading(false);
    const flush = window.setInterval(() => {
      if (!resetBuffer && pending.length === 0) return;
      const batch = pending;
      const reset = resetBuffer;
      pending = [];
      resetBuffer = false;
      setLines((previous) => {
        const next = reset ? batch : previous.concat(batch);
        return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
      });
    }, 250);
    const connect = () => {
      if (closed) return;
      setStream(attempts ? "reconnecting" : "connecting");
      // Same-origin EventSource sends the session cookie automatically.
      source = new EventSource(`${BASE}/containers/${encodeURIComponent(id)}/logs/stream?tail=${tail}`);
      source.onopen = () => {
        // The server replays `tail` lines on every connect, so start the buffer over to avoid duplicates.
        pending = [];
        resetBuffer = true;
        setStream("live");
      };
      source.addEventListener("line", (event) => {
        try {
          const line = normalizeLine(JSON.parse((event as MessageEvent<string>).data));
          if (line) pending.push(line);
        } catch {
          // ignore malformed frames
        }
      });
      source.addEventListener("end", () => {
        source?.close();
        source = null;
        setStream("ended");
      });
      source.onerror = () => {
        source?.close();
        source = null;
        if (closed) return;
        if (attempts >= MAX_RECONNECTS) {
          setStream("failed");
          return;
        }
        attempts += 1;
        setStream("reconnecting");
        retryTimer = window.setTimeout(connect, 1000 * 2 ** attempts);
      };
    };
    connect();
    return () => {
      closed = true;
      source?.close();
      window.clearTimeout(retryTimer);
      window.clearInterval(flush);
    };
  }, [follow, id, reloadToken, tail]);

  useLayoutEffect(() => {
    if (!autoScroll || !scroller.current) return;
    scroller.current.scrollTop = scroller.current.scrollHeight;
  }, [autoScroll, lines, timestamps]);

  const onScroll = () => {
    const element = scroller.current;
    if (!element || !follow) return;
    const atBottom = element.scrollHeight - element.scrollTop - element.clientHeight < 40;
    if (!atBottom && autoScroll) setAutoScroll(false);
  };

  const pattern = useMemo(() => {
    const needle = (follow ? query : appliedSearch || query).trim();
    return needle ? new RegExp(`(${escapeRegExp(needle)})`, "gi") : null;
  }, [appliedSearch, follow, query]);
  const matchCount = useMemo(() => {
    if (!pattern) return null;
    const test = new RegExp(pattern.source, "i");
    return lines.reduce((count, line) => count + (test.test(line.text) ? 1 : 0), 0);
  }, [lines, pattern]);

  const submitSearch = (event: FormEvent) => {
    event.preventDefault();
    if (!follow) setAppliedSearch(query.trim());
  };

  const download = () => {
    const text = lines.map((line) => `${timestamps && line.ts ? `${line.ts} ` : ""}${line.stream === "stderr" ? "[stderr] " : ""}${line.text}`).join("\n");
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    const anchor = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    anchor.href = url;
    anchor.download = `${name.replace(/[^\w.-]+/g, "_") || "container"}-logs-${stamp}.txt`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const streamColor = stream === "live" ? "success" : stream === "failed" ? "error" : stream === "ended" ? "default" : "warning";
  const dark = theme.palette.mode === "dark";

  return (
    <Stack spacing={1.25} sx={{ height: "100%", minHeight: 0 }}>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <TextField select size="small" label={copy.tail} value={tail} onChange={(event) => setTail(Number(event.target.value))} sx={{ minWidth: 130 }}>
          {TAILS.map((value) => <MenuItem key={value} value={value}>{formatNumber(value, language)}</MenuItem>)}
        </TextField>
        <FormControlLabel control={<Switch checked={follow} onChange={(event) => { setFollow(event.target.checked); setAutoScroll(true); }} />} label={copy.follow} />
        <FormControlLabel control={<Switch checked={timestamps} onChange={(event) => setTimestamps(event.target.checked)} />} label={copy.timestamps} />
        {follow && stream !== "idle" && (
          <Chip size="small" color={streamColor} variant="outlined" role="status" label={copy[`stream_${stream}` as const]} icon={stream === "connecting" || stream === "reconnecting" ? <CircularProgress size={12} /> : undefined} />
        )}
        <Box sx={{ flex: 1 }} />
        {follow && (
          <Tooltip title={autoScroll ? copy.pause : copy.resume}>
            <IconButton aria-label={autoScroll ? copy.pause : copy.resume} aria-pressed={!autoScroll} onClick={() => setAutoScroll((value) => !value)}>
              {autoScroll ? <PauseRoundedIcon /> : <PlayArrowRoundedIcon />}
            </IconButton>
          </Tooltip>
        )}
        {!follow && (
          <Tooltip title={copy.reload}>
            <span><IconButton aria-label={copy.reload} disabled={loading} onClick={() => setReloadToken((value) => value + 1)}><RefreshRoundedIcon /></IconButton></span>
          </Tooltip>
        )}
        <Button size="small" variant="outlined" startIcon={<DownloadRoundedIcon />} disabled={lines.length === 0} onClick={download}>{copy.download}</Button>
      </Stack>

      <Box component="form" onSubmit={submitSearch} noValidate>
        <Stack direction="row" spacing={1}>
          <TextField
            fullWidth
            size="small"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={copy.search}
            helperText={follow ? copy.searchHintFollow : undefined}
            slotProps={{
              htmlInput: { "aria-label": copy.search, dir: "auto" },
              input: {
                startAdornment: <InputAdornment position="start"><SearchRoundedIcon fontSize="small" /></InputAdornment>,
                endAdornment: query ? (
                  <InputAdornment position="end">
                    <IconButton size="small" aria-label={copy.clearSearch} onClick={() => { setQuery(""); if (!follow) setAppliedSearch(""); }}><CloseRoundedIcon fontSize="small" /></IconButton>
                  </InputAdornment>
                ) : undefined
              }
            }}
          />
          {!follow && <Button type="submit" variant="contained" disabled={loading} sx={{ flexShrink: 0 }}>{copy.searchServer}</Button>}
        </Stack>
      </Box>

      {error !== null && (logsStatusText(language, error) ? <Notice tone="warning">{logsStatusText(language, error)}</Notice> : <FriendlyError error={error} onRetry={() => setReloadToken((value) => value + 1)} />)}
      {follow && stream === "failed" && <Notice tone="warning" action={<Button color="inherit" size="small" onClick={() => setReloadToken((value) => value + 1)}>{copy.reconnect}</Button>}>{copy.streamFailedBody}</Notice>}
      {follow && stream === "ended" && <Notice action={<Button color="inherit" size="small" onClick={() => setReloadToken((value) => value + 1)}>{copy.reconnect}</Button>}>{copy.streamEndedBody}</Notice>}
      {truncated && <Notice tone="warning">{copy.truncated}</Notice>}

      <Box sx={{ position: "relative", flex: 1, minHeight: 240 }}>
        {loading && <LinearProgress sx={{ position: "absolute", top: 0, insetInline: 0, zIndex: 1 }} />}
        <Box
          ref={scroller}
          dir="ltr"
          role="log"
          aria-live={follow && autoScroll ? "polite" : "off"}
          aria-label={`${copy.title}: ${name}`}
          tabIndex={0}
          onScroll={onScroll}
          sx={{
            position: "absolute",
            inset: 0,
            overflow: "auto",
            p: 1.25,
            borderRadius: 1,
            border: 1,
            borderColor: "divider",
            bgcolor: dark ? "#050b12" : "#f6f8fa",
            color: dark ? "#d1d5db" : "#1f2937",
            fontFamily: 'ui-monospace, "SFMono-Regular", Consolas, "Liberation Mono", monospace',
            fontSize: 12.5,
            lineHeight: 1.55,
            textAlign: "start",
            whiteSpace: "pre-wrap",
            overflowWrap: "anywhere"
          }}
        >
          {lines.length === 0 && !loading
            ? <Box sx={{ color: "text.secondary" }}>{copy.empty}</Box>
            : lines.map((line, index) => (
              <Box key={index} sx={{ color: line.stream === "stderr" ? (dark ? "#fca5a5" : "#b91c1c") : undefined, borderInlineStart: line.stream === "stderr" ? "2px solid" : "2px solid transparent", borderColor: line.stream === "stderr" ? (dark ? "#f87171" : "#dc2626") : "transparent", paddingInlineStart: 0.75 }}>
                {timestamps && line.ts && <Box component="span" sx={{ color: "#6b7280", marginInlineEnd: 1 }}>{shortTs(line.ts)}</Box>}
                {highlight(line.text, pattern)}
              </Box>
            ))}
        </Box>
      </Box>

      <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap>
        <Typography variant="caption" color="text.secondary">{formatNumber(lines.length, language)} {copy.lines}</Typography>
        {matchCount !== null && <Typography variant="caption" color="text.secondary">· {formatNumber(matchCount, language)} {copy.matches}</Typography>}
        {lines.length >= MAX_LINES && <Typography variant="caption" color="warning.main">· {copy.capped.replace("{n}", formatNumber(MAX_LINES, language))}</Typography>}
        <Typography variant="caption" color="text.secondary">· {copy.audited}</Typography>
      </Stack>
    </Stack>
  );
}

/** Full-height log viewer for one container. Mount only while open so streams close on dismissal. */
export function ContainerLogsDialog({ container, language, onClose }: { container: { id: string; name: string }; language: Language; onClose: () => void }) {
  const copy = labels[language];
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  return (
    <Dialog
      open
      onClose={onClose}
      fullScreen={fullScreen}
      fullWidth
      maxWidth="lg"
      aria-labelledby="mrk-logs-title"
      slotProps={{ paper: { sx: { height: fullScreen ? "100%" : "92vh" } } }}
    >
      <DialogTitle id="mrk-logs-title" sx={{ pr: 7 }}>
        {copy.title} · <bdi dir="ltr">{container.name}</bdi>
        <IconButton aria-label={copy.close} onClick={onClose} sx={{ position: "absolute", insetInlineEnd: 12, top: 12 }}><CloseRoundedIcon /></IconButton>
      </DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", minHeight: 0, pb: 2 }}>
        <LogsBody id={container.id} name={container.name} language={language} />
      </DialogContent>
    </Dialog>
  );
}
