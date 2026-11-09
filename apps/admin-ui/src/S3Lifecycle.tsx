/**
 * Files › file space › one bucket (Advanced): automatic clean-up rules and file history.
 * Rules are written by S3 tools (PutBucketLifecycleConfiguration); the panel shows them,
 * the last daily run, and a dry-run preview ("would delete N files / size") that deletes nothing.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Box, Button, CircularProgress, Stack, Typography } from "@mui/material";
import PlaylistRemoveRoundedIcon from "@mui/icons-material/PlaylistRemoveRounded";
import { ApiError, getJson, isAbortError, mutateJson } from "./api";
import { formatBytes, formatNumber } from "./format";
import { FriendlyError, Ltr, Notice, RelativeTime, SectionCard, StatGrid, StatTile, StatusPill, useKit } from "./kit";
import { pick, say, type Bi } from "./copy";

const BASE = "/api/v1/s3";

type Rule = {
  id: string;
  status: "Enabled" | "Disabled";
  prefix?: string;
  tags?: [string, string][];
  expiration_days?: number;
  expiration_date_ns?: number;
  expired_object_delete_marker?: boolean;
  noncurrent_days?: number;
  newer_noncurrent?: number;
  abort_days?: number;
};
type RunSummary = {
  objects: number;
  bytes: number;
  versions: number;
  version_bytes: number;
  markers: number;
  uploads: number;
  dry_run: boolean;
  at?: number;
  sample?: { key: string; kind: string; size: number; rule: string }[];
  truncated?: boolean;
};
type Info = { rules: Rule[]; versioning: "Enabled" | "Suspended" | null; last_run: RunSummary | null; supported: boolean };

const T = {
  title: { fa: "پاک‌سازی خودکار و تاریخچه فایل‌ها", en: "Automatic clean-up and file history" },
  hint: {
    fa: "قانون‌های پاک‌سازی را ابزارهای متصل (مثل پشتیبان‌گیرها) تعیین می‌کنند. هر روز یک بار اجرا می‌شوند.",
    en: "Clean-up rules are set by connected tools (such as backup apps). They run once a day."
  },
  history: { fa: "نگه‌داری نسخه‌های قبلی", en: "Keeps previous versions" },
  historyOn: { fa: "روشن", en: "On" },
  historyPaused: { fa: "متوقف", en: "Paused" },
  historyOff: { fa: "خاموش", en: "Off" },
  noRules: { fa: "برای این پوشه قانون پاک‌سازی تعریف نشده است.", en: "No clean-up rules for this bucket." },
  ruleOff: { fa: "غیرفعال", en: "Disabled" },
  ruleOn: { fa: "فعال", en: "Enabled" },
  everything: { fa: "همه فایل‌ها", en: "All files" },
  under: { fa: "فایل‌های داخل {prefix}", en: "Files under {prefix}" },
  withTags: { fa: "با برچسب {tags}", en: "tagged {tags}" },
  afterDays: { fa: "پاک کردن {n} روز بعد از آخرین تغییر", en: "Delete {n} days after the last change" },
  onDate: { fa: "پاک کردن در تاریخ {date}", en: "Delete on {date}" },
  oldVersions: { fa: "پاک کردن نسخه‌های قدیمی {n} روز بعد", en: "Delete old versions after {n} days" },
  keepNewest: { fa: "({n} نسخه آخر نگه داشته می‌شود)", en: "(the newest {n} are kept)" },
  markers: { fa: "پاک کردن نشانه‌های حذفِ بی‌استفاده", en: "Remove leftover delete markers" },
  uploads: { fa: "لغو بارگذاری‌های نیمه‌کاره بعد از {n} روز", en: "Cancel unfinished uploads after {n} days" },
  lastRun: { fa: "آخرین اجرا", en: "Last run" },
  lastRunBody: { fa: "{n} فایل ({size})، {v} نسخه قدیمی و {u} بارگذاری نیمه‌کاره پاک شد.", en: "{n} files ({size}), {v} old versions and {u} unfinished uploads were removed." },
  neverRun: { fa: "هنوز اجرا نشده است.", en: "Hasn't run yet." },
  preview: { fa: "اگر الان اجرا شود چه پاک می‌شود؟", en: "What would be deleted now?" },
  previewHint: { fa: "فقط شمارش است؛ چیزی پاک نمی‌شود.", en: "Only counts; nothing is deleted." },
  wouldFiles: { fa: "فایل", en: "Files" },
  wouldVersions: { fa: "نسخه قدیمی", en: "Old versions" },
  wouldUploads: { fa: "بارگذاری نیمه‌کاره", en: "Unfinished uploads" },
  wouldNothing: { fa: "الان چیزی برای پاک کردن نیست.", en: "Nothing would be deleted right now." },
  examples: { fa: "نمونه‌ها", en: "Examples" },
  truncated: { fa: "تعداد خیلی زیاد است؛ فقط بخشی شمرده شد.", en: "Very many matches; only part was counted." },
  readOnly: { fa: "پوشه فقط‌خواندنی است و پاک‌سازی خودکار ندارد.", en: "This folder is read-only and has no automatic clean-up." }
} satisfies Record<string, Bi>;

function describe(language: "fa" | "en", rule: Rule): string[] {
  const scope = rule.prefix ? say(language, T.under, { prefix: rule.prefix }) : pick(language, T.everything);
  const tags = rule.tags?.length ? ` · ${say(language, T.withTags, { tags: rule.tags.map(([key, value]) => `${key}=${value}`).join("، ") })}` : "";
  const lines = [scope + tags];
  if (rule.expiration_days) lines.push(say(language, T.afterDays, { n: formatNumber(rule.expiration_days, language) }));
  if (rule.expiration_date_ns) {
    const date = new Date(rule.expiration_date_ns / 1e6).toISOString().slice(0, 10);
    lines.push(say(language, T.onDate, { date }));
  }
  if (rule.noncurrent_days) {
    let text = say(language, T.oldVersions, { n: formatNumber(rule.noncurrent_days, language) });
    if (rule.newer_noncurrent) text += ` ${say(language, T.keepNewest, { n: formatNumber(rule.newer_noncurrent, language) })}`;
    lines.push(text);
  }
  if (rule.expired_object_delete_marker) lines.push(pick(language, T.markers));
  if (rule.abort_days) lines.push(say(language, T.uploads, { n: formatNumber(rule.abort_days, language) }));
  return lines;
}

export function S3Lifecycle({ bucket, canAdmin }: { bucket: string; canAdmin: boolean }) {
  const { language } = useKit();
  const [info, setInfo] = useState<Info | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [preview, setPreview] = useState<RunSummary | null>(null);
  const [previewError, setPreviewError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const path = `${BASE}/buckets/${encodeURIComponent(bucket)}/lifecycle`;

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      setInfo(await getJson<Info>(path, current.signal));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    }
  }, [path]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const runPreview = async () => {
    setBusy(true);
    setPreviewError(null);
    try {
      setPreview(await mutateJson<RunSummary>(`${path}/preview`, { method: "POST" }));
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setPreviewError(caught);
    } finally {
      setBusy(false);
    }
  };

  const history = info?.versioning === "Enabled" ? <StatusPill tone="ok" label={pick(language, T.historyOn)} /> : info?.versioning === "Suspended" ? <StatusPill tone="warn" label={pick(language, T.historyPaused)} /> : <StatusPill tone="off" label={pick(language, T.historyOff)} />;
  const nothing = preview && preview.objects + preview.versions + preview.markers + preview.uploads === 0;

  return (
    <SectionCard advanced collapsible defaultCollapsed title={pick(language, T.title)} hint={pick(language, T.hint)}>
      {error !== null && <FriendlyError error={error} onRetry={() => void load()} />}
      {info && (
        <Stack spacing={1.5}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="body2">{pick(language, T.history)}</Typography>
            {history}
          </Stack>
          {!info.supported && <Notice>{pick(language, T.readOnly)}</Notice>}
          {info.rules.length === 0 ? (
            <Typography variant="body2" color="text.secondary">{pick(language, T.noRules)}</Typography>
          ) : (
            <Stack spacing={1} component="ul" sx={{ m: 0, p: 0, listStyle: "none" }}>
              {info.rules.map((rule) => (
                <Box component="li" key={rule.id} sx={{ border: 1, borderColor: "divider", borderRadius: 1, p: 1.25 }}>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
                    <Typography fontWeight={700}><Ltr>{rule.id}</Ltr></Typography>
                    <StatusPill tone={rule.status === "Enabled" ? "ok" : "off"} label={pick(language, rule.status === "Enabled" ? T.ruleOn : T.ruleOff)} />
                  </Stack>
                  {describe(language, rule).map((line) => <Typography key={line} variant="body2" color="text.secondary">{line}</Typography>)}
                </Box>
              ))}
            </Stack>
          )}
          <Typography variant="body2">
            {pick(language, T.lastRun)}:{" "}
            {info.last_run ? (
              <>
                <RelativeTime value={info.last_run.at ?? null} />{" — "}
                {say(language, T.lastRunBody, {
                  n: formatNumber(info.last_run.objects, language),
                  size: formatBytes(info.last_run.bytes, language),
                  v: formatNumber(info.last_run.versions, language),
                  u: formatNumber(info.last_run.uploads, language)
                })}
              </>
            ) : pick(language, T.neverRun)}
          </Typography>
          {canAdmin && info.rules.length > 0 && (
            <Box>
              <Button variant="outlined" startIcon={busy ? <CircularProgress size={16} /> : <PlaylistRemoveRoundedIcon />} disabled={busy} onClick={() => void runPreview()} sx={{ minHeight: 44 }}>
                {pick(language, T.preview)}
              </Button>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>{pick(language, T.previewHint)}</Typography>
            </Box>
          )}
          {previewError !== null && <FriendlyError error={previewError} onRetry={() => void runPreview()} />}
          {preview && (nothing ? (
            <Notice tone="info">{pick(language, T.wouldNothing)}</Notice>
          ) : (
            <Stack spacing={1}>
              <StatGrid columns={3}>
                <StatTile label={pick(language, T.wouldFiles)} value={`${formatNumber(preview.objects, language)} · ${formatBytes(preview.bytes, language)}`} />
                <StatTile label={pick(language, T.wouldVersions)} value={`${formatNumber(preview.versions + preview.markers, language)} · ${formatBytes(preview.version_bytes, language)}`} />
                <StatTile label={pick(language, T.wouldUploads)} value={formatNumber(preview.uploads, language)} />
              </StatGrid>
              {preview.truncated && <Notice tone="warning">{pick(language, T.truncated)}</Notice>}
              {preview.sample && preview.sample.length > 0 && (
                <Box>
                  <Typography variant="caption" color="text.secondary">{pick(language, T.examples)}</Typography>
                  {preview.sample.map((item) => (
                    <Typography key={`${item.kind}:${item.key}:${item.rule}`} variant="body2"><Ltr mono>{item.key}</Ltr></Typography>
                  ))}
                </Box>
              )}
            </Stack>
          ))}
        </Stack>
      )}
    </SectionCard>
  );
}
