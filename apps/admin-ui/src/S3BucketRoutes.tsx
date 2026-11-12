/**
 * Admin S3 page › «دامنه پوشه‌های فضای من» (docs/43 §0.1 «مسیر دامنه باکت»): every proven folder
 * domain of a workspace with its public route (Dokploy / Traefik file / manual steps), why it failed,
 * and buttons to try one again or bring them all in line. Needs `domains:read` (and `domains:write`
 * for the buttons), because it shows how this server routes domains.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Box, Button, CircularProgress, Collapse, Stack, Typography } from "@mui/material";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import SyncRoundedIcon from "@mui/icons-material/SyncRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { pick, reasonFor, say, type Bi } from "./copy";
import { FriendlyError, Ltr, SectionCard, StatusPill, useKit, useUndoSnackbar } from "./kit";
import { ManualSteps, RedeployNotice } from "./ServiceDomains";
import { routingModeWord, type ManualInstructions, type SuggestedAction } from "./services";

const BASE = "/api/v1/domains/bucket-routes";

type RouteState = "ok" | "pending" | "manual" | "failed" | "conflict" | "off" | "stale" | "unverified" | "none";
type RouteItem = {
  host: string;
  bucket: string | null;
  verified: boolean;
  source: "admin" | "workspace" | null;
  workspace_slug: string | null;
  route: {
    state: RouteState;
    mode: string | null;
    error_code: string | null;
    /** Dokploy's own words for the last failure (Advanced mode). */
    upstream_message?: string | null;
    redeploy_required: boolean | null;
    suggested_action?: SuggestedAction | null;
    instructions: ManualInstructions | null;
  };
};
type RoutesPayload = { items: RouteItem[]; enabled: boolean };

const T = {
  title: { fa: "دامنه‌های اختصاصی باکت‌ها", en: "Custom bucket domains" },
  hint: {
    fa: "دامنه‌های باکت‌های مدیریتی و دامنه‌هایی که کاربران ثابت کرده‌اند، با همان روش اتصال دامنه‌ها به فضای فایل وصل می‌شوند.",
    en: "Admin bucket domains and user-proven domains are routed to file space the same way as other domains."
  },
  off: {
    fa: "وصل کردن خودکار خاموش است؛ از تنظیمات «سرویس‌ها و دامنه‌ها» روشنش کنید.",
    en: "Automatic routing is off; turn it on in the «Services and domains» settings."
  },
  reconcile: { fa: "بررسی دوباره همه", en: "Recheck all" },
  reconciled: { fa: "مسیرها بررسی شد: {added} تازه، {removed} برداشته.", en: "Routes checked: {added} added, {removed} removed." },
  retry: { fa: "دوباره امتحان کن", en: "Try again" },
  retried: { fa: "مسیر «{name}» دوباره بررسی شد.", en: "Route of “{name}” checked again." },
  steps: { fa: "مراحل دستی", en: "Manual steps" },
  hideSteps: { fa: "بستن مراحل", en: "Hide steps" },
  owner: { fa: "پوشه «{bucket}» از فضای «{space}»", en: "Folder “{bucket}” of space “{space}”" },
  adminOwner: { fa: "باکت مدیریتی «{bucket}»", en: "Admin bucket “{bucket}”" },
  noOwner: { fa: "صاحبی ندارد؛ مسیرش برداشته می‌شود", en: "No owner; its route is being removed" },
  via: { fa: "روش: {mode}", en: "Method: {mode}" },
  state_ok: { fa: "وصل است", en: "Routed" },
  state_pending: { fa: "در انتظار انتشار", en: "Waiting for a deploy" },
  state_manual: { fa: "دستی", en: "Manual" },
  state_failed: { fa: "وصل نشد", en: "Not routed" },
  state_conflict: { fa: "دامنه تکراری", en: "Domain in use" },
  state_off: { fa: "خاموش", en: "Off" },
  state_stale: { fa: "در حال برداشتن", en: "Being removed" },
  state_unverified: { fa: "هنوز ثابت نشده", en: "Not proven yet" },
  state_none: { fa: "هنوز بررسی نشده", en: "Not checked yet" }
} satisfies Record<string, Bi>;

const TONE: Record<RouteState, "ok" | "warn" | "error" | "info" | "off" | "busy"> = {
  ok: "ok", pending: "busy", manual: "info", failed: "error", conflict: "error", off: "off", stale: "warn", unverified: "off", none: "off"
};
const RETRYABLE: RouteState[] = ["pending", "manual", "failed", "conflict", "stale", "none"];

export function S3BucketRoutes({ permissions }: { permissions: string[] }) {
  const { language, isAdvanced } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const canRead = hasPermission(permissions, "domains:read");
  const canWrite = hasPermission(permissions, "domains:write");
  const [data, setData] = useState<RoutesPayload | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      setData(await getJson<RoutesPayload>(BASE, current.signal));
      setError(null);
    } catch (caught) {
      if (!isAbortError(caught)) setError(caught);
    }
  }, []);

  useEffect(() => {
    if (canRead) void load();
    return () => controller.current?.abort();
  }, [canRead, load]);

  if (!canRead) return null;
  if (!error && (!data || data.items.length === 0)) return null;

  const run = async (key: string, work: () => Promise<string>) => {
    setBusy(key);
    try {
      notify({ message: await work() });
      await load();
    } catch (caught) {
      notify({ message: reasonFor(language, caught instanceof ApiError ? caught.code : null), tone: "error" });
    } finally {
      setBusy(null);
    }
  };

  const reconcile = () => run("*", async () => {
    const result = await mutateJson<{ added?: number; removed?: number }>(`${BASE}/reconcile`, { method: "POST", body: {} });
    return say(language, T.reconciled, { added: String(result?.added ?? 0), removed: String(result?.removed ?? 0) });
  });
  const retry = (host: string) => run(host, async () => {
    await mutateJson(`${BASE}/${encodeURIComponent(host)}/retry`, { method: "POST", body: {} });
    return say(language, T.retried, { name: host });
  });

  return (
    <SectionCard
      title={pick(language, T.title)}
      hint={pick(language, T.hint)}
      action={canWrite ? (
        <Button variant="outlined" disabled={busy !== null} onClick={() => void reconcile()} startIcon={busy === "*" ? <CircularProgress size={14} color="inherit" /> : <SyncRoundedIcon />} sx={{ minHeight: 40 }}>
          {pick(language, T.reconcile)}
        </Button>
      ) : undefined}
    >
      <Stack spacing={1.5}>
        {error ? <FriendlyError error={error} onRetry={() => void load()} /> : null}
        {data && !data.enabled && <Typography variant="body2" color="text.secondary">{pick(language, T.off)}</Typography>}
        {(data?.items ?? []).map((item) => {
          const route = item.route;
          const state = route.state;
          return (
            <Box key={item.host} sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: 1.5 }}>
              <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap">
                <Typography fontWeight={650} sx={{ flex: 1, minWidth: 0 }} noWrap><Ltr>{item.host}</Ltr></Typography>
                <StatusPill tone={TONE[state] ?? "off"} label={pick(language, T[`state_${state}` as const] ?? T.state_none)} />
                {canWrite && RETRYABLE.includes(state) && (
                  <Button size="small" disabled={busy !== null} onClick={() => void retry(item.host)} startIcon={busy === item.host ? <CircularProgress size={14} color="inherit" /> : <RefreshRoundedIcon />} sx={{ minHeight: 40 }}>
                    {pick(language, T.retry)}
                  </Button>
                )}
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                {item.source === "admin" && item.bucket
                  ? say(language, T.adminOwner, { bucket: item.bucket })
                  : item.workspace_slug && item.bucket
                  ? say(language, T.owner, { bucket: item.bucket, space: item.workspace_slug })
                  : pick(language, T.noOwner)}
                {route.mode ? ` · ${say(language, T.via, { mode: routingModeWord(language, route.mode) })}` : ""}
              </Typography>
              {route.error_code && (state === "failed" || state === "conflict" || state === "stale") && (
                <Typography variant="body2" color="error" sx={{ mt: 0.5 }}>{reasonFor(language, route.error_code)}</Typography>
              )}
              {isAdvanced && route.upstream_message && (state === "failed" || state === "stale") && (
                <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 0.5 }}><Ltr>{route.upstream_message}</Ltr></Typography>
              )}
              {state === "pending" && route.redeploy_required && (
                <Box sx={{ mt: 1 }}>
                  <RedeployNotice host={item.host} action={route.suggested_action} onStarted={() => void load()} />
                </Box>
              )}
              {state === "manual" && route.instructions && (
                <Box sx={{ mt: 1 }}>
                  <Button size="small" onClick={() => setOpen(open === item.host ? null : item.host)} sx={{ minHeight: 40 }}>
                    {pick(language, open === item.host ? T.hideSteps : T.steps)}
                  </Button>
                  <Collapse in={open === item.host} unmountOnExit>
                    <Box sx={{ pt: 1 }}>
                      <ManualSteps host={item.host} port={route.instructions.dokploy?.port ?? 9000} instructions={route.instructions} />
                    </Box>
                  </Collapse>
                </Box>
              )}
            </Box>
          );
        })}
      </Stack>
      {snackbar}
    </SectionCard>
  );
}
