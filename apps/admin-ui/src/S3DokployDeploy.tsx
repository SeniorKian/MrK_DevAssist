/** Discover, select and redeploy the Dokploy Compose that runs the S3 service. */
import { useCallback, useEffect, useState } from "react";
import { Box, Button, CircularProgress, MenuItem, Stack, TextField, Typography } from "@mui/material";
import RocketLaunchRoundedIcon from "@mui/icons-material/RocketLaunchRounded";
import SaveRoundedIcon from "@mui/icons-material/SaveRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import { pick, reasonFor, say, type Bi } from "./copy";
import { FriendlyError, Ltr, Notice, useConfirmAction, useKit, useUndoSnackbar } from "./kit";

type Candidate = {
  compose_id: string;
  name: string;
  project: string | null;
  environment: string | null;
  status: string | null;
  domains: string[];
  source?: string;
};
/** `target` is certain (saved, installer or container); `suggestion` must be saved first. */
type State = { target: Candidate | null; suggestion?: Candidate | null; candidates: Candidate[]; partial: boolean };

const BASE = "/api/v1/s3/dokploy";
const T = {
  title: { fa: "انتشار سرویس فضای فایل", en: "S3 deployment" },
  hint: {
    fa: "سرویس فضای فایل را با همان اتصال و کلید ذخیره‌شده Dokploy، بدون خروج از DevAssist دوباره منتشر کنید.",
    en: "Redeploy S3 through the saved Dokploy connection and API key without leaving DevAssist."
  },
  target: { fa: "سرویس Compose در Dokploy", en: "Dokploy Compose service" },
  choose: { fa: "سرویس فضای فایل را انتخاب کنید", en: "Choose the S3 service" },
  save: { fa: "ذخیره انتخاب", en: "Save selection" },
  redeploy: { fa: "انتشار دوباره فضای فایل", en: "Redeploy S3" },
  started: {
    fa: "انتشار دوباره فضای فایل در Dokploy شروع شد.",
    en: "The S3 redeploy started in Dokploy."
  },
  saved: { fa: "سرویس فضای فایل برای انتشار دوباره ذخیره شد.", en: "The S3 redeploy target was saved." },
  detected: { fa: "سرویس انتخاب‌شده: {name}", en: "Selected: {name}" },
  suggested: {
    fa: "پیشنهاد پنل: «{name}». اگر درست است، یک بار «ذخیره انتخاب» را بزنید.",
    en: "The panel suggests “{name}”. If it is right, press Save selection once."
  },
  missing: {
    fa: "پنل نتوانست سرویس فضای فایل را قطعی تشخیص دهد. Compose درست را یک بار از فهرست انتخاب و ذخیره کنید.",
    en: "The panel could not identify S3 with certainty. Select and save the correct Compose once."
  },
  none: {
    fa: "هیچ سرویس Compose در اتصال فعلی Dokploy پیدا نشد.",
    en: "No Compose service was found through the current Dokploy connection."
  },
  noPermission: {
    fa: "برای انتشار دوباره به دسترسی انتشار برنامه‌های Dokploy نیاز دارید.",
    en: "Redeploying requires the Dokploy deployment permission."
  },
  confirmTitle: { fa: "سرویس «{name}» دوباره منتشر شود؟", en: "Redeploy “{name}”?" },
  confirmBody: {
    fa: "Dokploy این Compose را دوباره می‌سازد و اجرا می‌کند. در این چند لحظه فضای فایل ممکن است پاسخ ندهد.",
    en: "Dokploy rebuilds and restarts this Compose. File space may not answer for a few moments."
  }
} satisfies Record<string, Bi>;

export function S3DokployDeploy({ permissions }: { permissions: string[] }) {
  const { language } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const { ask, dialog } = useConfirmAction();
  const canRead = hasPermission(permissions, "s3:admin") && hasPermission(permissions, "dokploy:read");
  const canDeploy = hasPermission(permissions, "dokploy:deploy");
  const [data, setData] = useState<State | null>(null);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<"save" | "deploy" | null>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const value = await getJson<State>(BASE, signal);
      setData(value);
      setSelected(value.target?.compose_id ?? value.suggestion?.compose_id ?? "");
      setError(null);
    } catch (caught) {
      if (!isAbortError(caught)) setError(caught);
    }
  }, []);

  useEffect(() => {
    if (!canRead) return;
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [canRead, load]);

  if (!canRead) return null;

  const save = async () => {
    if (!selected) return;
    setBusy("save");
    try {
      await mutateJson(BASE, { method: "PUT", body: { compose_id: selected } });
      notify({ message: pick(language, T.saved) });
      await load();
    } catch (caught) {
      notify({ message: reasonFor(language, caught instanceof ApiError ? caught.code : null), tone: "error" });
    } finally {
      setBusy(null);
    }
  };

  const target = data?.target ?? null;
  const suggestion = target ? null : data?.suggestion ?? null;

  const redeploy = async () => {
    if (!target) return;
    const ok = await ask({
      title: say(language, T.confirmTitle, { name: target.name }),
      body: pick(language, T.confirmBody),
      severity: "disruptive",
      confirmLabel: pick(language, T.redeploy)
    });
    if (!ok) return;
    setBusy("deploy");
    try {
      await mutateJson(`${BASE}/redeploy`, { method: "POST", body: {} });
      notify({ message: pick(language, T.started) });
      await load();
    } catch (caught) {
      notify({ message: reasonFor(language, caught instanceof ApiError ? caught.code : null), tone: "error" });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Box sx={{ borderTop: 1, borderColor: "divider", pt: 1.5 }}>
      <Typography variant="subtitle2" fontWeight={750}>{pick(language, T.title)}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.25 }}>{pick(language, T.hint)}</Typography>
      {error ? <Box sx={{ mt: 1 }}><FriendlyError error={error} onRetry={() => void load()} /></Box> : null}
      {!data && !error ? <CircularProgress size={18} sx={{ mt: 1 }} /> : null}
      {data && data.candidates.length === 0 ? <Box sx={{ mt: 1 }}><Notice>{pick(language, T.none)}</Notice></Box> : null}
      {data && data.candidates.length > 0 ? (
        <Stack direction={{ xs: "column", md: "row" }} gap={1} alignItems={{ md: "center" }} sx={{ mt: 1.25 }}>
          <TextField
            select
            size="small"
            label={pick(language, T.target)}
            value={selected}
            disabled={!canDeploy || busy !== null}
            onChange={(event) => setSelected(event.target.value)}
            sx={{ minWidth: 280, flex: 1 }}
          >
            <MenuItem value="" disabled>{pick(language, T.choose)}</MenuItem>
            {data.candidates.map((item) => (
              <MenuItem key={item.compose_id} value={item.compose_id}>
                {item.name} · {item.project}{item.environment ? ` / ${item.environment}` : ""}
              </MenuItem>
            ))}
          </TextField>
          {canDeploy && (
            <Button
              variant="outlined"
              disabled={!selected || busy !== null || selected === target?.compose_id}
              onClick={() => void save()}
              startIcon={busy === "save" ? <CircularProgress size={14} color="inherit" /> : <SaveRoundedIcon />}
              sx={{ minHeight: 40, whiteSpace: "nowrap" }}
            >
              {pick(language, T.save)}
            </Button>
          )}
          {canDeploy && (
            <Button
              variant="contained"
              disabled={!target || busy !== null || selected !== target.compose_id}
              onClick={() => void redeploy()}
              startIcon={busy === "deploy" ? <CircularProgress size={14} color="inherit" /> : <RocketLaunchRoundedIcon />}
              sx={{ minHeight: 40, whiteSpace: "nowrap" }}
            >
              {pick(language, T.redeploy)}
            </Button>
          )}
        </Stack>
      ) : null}
      {suggestion ? (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.75 }}>{say(language, T.suggested, { name: suggestion.name })}</Typography>
      ) : null}
      {data && data.candidates.length > 0 && !target && !suggestion ? (
        <Typography variant="body2" color="warning.main" sx={{ mt: 0.75 }}>{pick(language, T.missing)}</Typography>
      ) : null}
      {target ? (
        <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.75 }}>
          {say(language, T.detected, { name: target.name })} · <Ltr>{target.compose_id}</Ltr>
        </Typography>
      ) : null}
      {data && !canDeploy ? <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.75 }}>{pick(language, T.noPermission)}</Typography> : null}
      {snackbar}
      {dialog}
    </Box>
  );
}
