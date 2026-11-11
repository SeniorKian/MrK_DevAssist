/** Custom hostnames for administrator-managed S3 buckets. */
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Box, Button, CircularProgress, Stack, TextField, Typography } from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import { ApiError, getJson, isAbortError, mutateJson } from "./api";
import { pick, reasonFor, say, type Bi } from "./copy";
import { FriendlyError, Ltr, Notice, StatusPill, useConfirmAction, useKit, useUndoSnackbar } from "./kit";
import { ManualSteps } from "./ServiceDomains";
import type { ManualInstructions } from "./services";

type RouteState = "ok" | "pending" | "manual" | "failed" | "conflict" | "off" | "stale" | "none";
type DomainItem = {
  host: string;
  bucket: string;
  route: {
    state: RouteState;
    error_code: string | null;
    redeploy_required?: boolean | null;
    instructions?: ManualInstructions | null;
  };
};

const T = {
  title: { fa: "دامنه اختصاصی این باکت", en: "Custom domain for this bucket" },
  hint: {
    fa: "مثلاً files.example.com؛ مسیر /file.jpg مستقیماً فایل file.jpg همین باکت است. خصوصی بودن باکت عوض نمی‌شود.",
    en: "For example files.example.com; /file.jpg maps directly to file.jpg in this bucket. The bucket stays private."
  },
  dns: {
    fa: "ابتدا رکورد A/AAAA دامنه را به همین سرور بدهید. پنل مسیر HTTPS را در Dokploy یا Traefik می‌سازد.",
    en: "First point the domain's A/AAAA record at this server. The panel creates its HTTPS route in Dokploy or Traefik."
  },
  label: { fa: "دامنه", en: "Domain" },
  add: { fa: "اتصال دامنه", en: "Attach domain" },
  remove: { fa: "حذف", en: "Remove" },
  retry: { fa: "تلاش دوباره", en: "Retry" },
  added: { fa: "دامنه «{host}» به باکت وصل شد.", en: "“{host}” was attached to the bucket." },
  removed: { fa: "دامنه از باکت جدا شد.", en: "The domain was detached from the bucket." },
  pending: {
    fa: "دامنه در Dokploy ثبت شده است؛ از بالای همین صفحه «انتشار دوباره فضای فایل» و سپس «تلاش دوباره» را بزنید.",
    en: "The domain is registered in Dokploy; use “Redeploy S3” above, then press Retry."
  },
  private: {
    fa: "برای باکت خصوصی، باز کردن فایل همچنان به کلید دسترسی یا لینک اشتراکی امضاشده نیاز دارد.",
    en: "A private bucket still requires an access key or a signed share link."
  },
  state_ok: { fa: "وصل است", en: "Routed" },
  state_pending: { fa: "در انتظار انتشار دوباره", en: "Waiting for deploy" },
  state_manual: { fa: "نیاز به تنظیم دستی", en: "Manual setup" },
  state_failed: { fa: "ناموفق", en: "Failed" },
  state_conflict: { fa: "دامنه در استفاده است", en: "Domain in use" },
  state_off: { fa: "خاموش", en: "Off" },
  state_stale: { fa: "در حال حذف", en: "Being removed" },
  state_none: { fa: "بررسی نشده", en: "Not checked" },
  removeTitle: { fa: "دامنه «{host}» از این باکت جدا شود؟", en: "Detach “{host}” from this bucket?" },
  removeBody: {
    fa: "فایل‌های این باکت دیگر از این دامنه باز نمی‌شوند و مسیر آن در Dokploy یا Traefik برداشته می‌شود. فایل‌ها پاک نمی‌شوند.",
    en: "This bucket stops answering on the domain and its route in Dokploy or Traefik is removed. No files are deleted."
  }
} satisfies Record<string, Bi>;

const TONE: Record<RouteState, "ok" | "warn" | "error" | "info" | "off" | "busy"> = {
  ok: "ok", pending: "busy", manual: "info", failed: "error", conflict: "error",
  off: "off", stale: "warn", none: "off"
};

export function S3AdminBucketDomains({ bucket, canAdmin }: { bucket: string; canAdmin: boolean }) {
  const { language } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const { ask, dialog } = useConfirmAction();
  const base = `/api/v1/s3/buckets/${encodeURIComponent(bucket)}/domains`;
  const [items, setItems] = useState<DomainItem[] | null>(null);
  const [host, setHost] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await getJson<{ items: DomainItem[] }>(base, signal);
      setItems(result.items);
      setError(null);
    } catch (caught) {
      if (!isAbortError(caught)) setError(caught);
    }
  }, [base]);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const add = async (event: FormEvent) => {
    event.preventDefault();
    const value = host.trim().toLowerCase().replace(/\.$/, "");
    if (!value) return;
    setBusy("add");
    try {
      await mutateJson(base, { method: "POST", body: { host: value } });
      setHost("");
      notify({ message: say(language, T.added, { host: value }) });
      await load();
    } catch (caught) {
      notify({ message: reasonFor(language, caught instanceof ApiError ? caught.code : null), tone: "error" });
    } finally {
      setBusy(null);
    }
  };

  const act = async (item: DomainItem, action: "retry" | "remove") => {
    if (action === "remove") {
      const ok = await ask({
        title: say(language, T.removeTitle, { host: item.host }),
        body: pick(language, T.removeBody),
        severity: "destructive",
        confirmLabel: pick(language, T.remove)
      });
      if (!ok) return;
    }
    setBusy(item.host);
    try {
      await mutateJson(`${base}/${encodeURIComponent(item.host)}${action === "retry" ? "/retry" : ""}`, {
        method: action === "retry" ? "POST" : "DELETE",
        body: action === "retry" ? {} : undefined
      });
      if (action === "remove") notify({ message: pick(language, T.removed) });
      await load();
    } catch (caught) {
      notify({ message: reasonFor(language, caught instanceof ApiError ? caught.code : null), tone: "error" });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Box sx={{ mt: 2, pt: 2, borderTop: 1, borderColor: "divider" }}>
      <Typography variant="subtitle1" fontWeight={750}>{pick(language, T.title)}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.25 }}>{pick(language, T.hint)}</Typography>
      <Box sx={{ mt: 1.5 }}><Notice>{pick(language, T.private)}</Notice></Box>
      {canAdmin && (
        <Stack component="form" direction={{ xs: "column", sm: "row" }} gap={1} sx={{ mt: 1.5 }} onSubmit={(event) => void add(event)}>
          <TextField
            fullWidth
            size="small"
            label={pick(language, T.label)}
            placeholder="files.example.com"
            value={host}
            onChange={(event) => setHost(event.target.value)}
            slotProps={{ htmlInput: { dir: "ltr", autoCapitalize: "none", spellCheck: false } }}
          />
          <Button type="submit" variant="contained" disabled={busy !== null || !host.trim()} startIcon={busy === "add" ? <CircularProgress size={14} color="inherit" /> : <AddRoundedIcon />} sx={{ minHeight: 40, whiteSpace: "nowrap" }}>
            {pick(language, T.add)}
          </Button>
        </Stack>
      )}
      {canAdmin && <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.75 }}>{pick(language, T.dns)}</Typography>}
      {error ? <Box sx={{ mt: 1.5 }}><FriendlyError error={error} onRetry={() => void load()} /></Box> : null}
      {items === null && !error ? <CircularProgress size={20} sx={{ mt: 1.5 }} /> : null}
      <Stack spacing={1} sx={{ mt: 1.5 }}>
        {(items ?? []).map((item) => {
          const state = item.route.state ?? "none";
          const label = T[`state_${state}` as keyof typeof T];
          return (
            <Box key={item.host} sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: 1.25 }}>
              <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
                <Typography sx={{ flex: 1, minWidth: 180 }} fontWeight={650}><Ltr>{item.host}</Ltr></Typography>
                <StatusPill tone={TONE[state]} label={pick(language, label)} />
                {canAdmin && state !== "ok" && (
                  <Button size="small" disabled={busy !== null} onClick={() => void act(item, "retry")} startIcon={busy === item.host ? <CircularProgress size={14} color="inherit" /> : <RefreshRoundedIcon />}>
                    {pick(language, T.retry)}
                  </Button>
                )}
                {canAdmin && (
                  <Button size="small" color="error" disabled={busy !== null} onClick={() => void act(item, "remove")} startIcon={<DeleteOutlineRoundedIcon />}>
                    {pick(language, T.remove)}
                  </Button>
                )}
              </Stack>
              {state === "pending" && item.route.redeploy_required ? <Typography variant="body2" sx={{ mt: 0.75 }}>{pick(language, T.pending)}</Typography> : null}
              {item.route.error_code ? <Typography variant="body2" color="error" sx={{ mt: 0.75 }}>{reasonFor(language, item.route.error_code)}</Typography> : null}
              {state === "manual" && item.route.instructions ? <Box sx={{ mt: 1 }}><ManualSteps host={item.host} port={item.route.instructions.dokploy?.port ?? 9000} instructions={item.route.instructions} /></Box> : null}
            </Box>
          );
        })}
      </Stack>
      {snackbar}
      {dialog}
    </Box>
  );
}
