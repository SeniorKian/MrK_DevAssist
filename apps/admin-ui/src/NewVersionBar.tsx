/**
 * «نسخه تازه آمده؛ صفحه را تازه کنید» (contract docs/41 §7).
 *
 * The panel knows its own build (package.json version + `VITE_BUILD_COMMIT`). Lightly, every minute
 * while the tab is visible (and when it becomes visible again), it compares that with
 * - the server's `build` in `GET /api/v1/system/status` (`commit`, `ui_version`), or, for roles
 *   that can't read the status (403),
 * - the main script named in the served `index.html` (its hashed file name changes with each build).
 * When they differ it shows a calm bar with a reload button; it never reloads on its own, so nothing
 * typed is lost.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Typography } from "@mui/material";
import UpdateRoundedIcon from "@mui/icons-material/UpdateRounded";
import packageMetadata from "../package.json";
import { apiGet } from "./api";
import type { Language } from "./i18n";
import { pick, type Bi } from "./copy/text";

const UI_COMMIT = import.meta.env.VITE_BUILD_COMMIT || "unknown";
const POLL_MS = 60_000;

const COPY = {
  title: { fa: "نسخه تازه پنل آمده", en: "A new version of the panel is here" },
  body: { fa: "صفحه را تازه کنید تا نسخه تازه باز شود. اگر چیزی را نیمه‌کاره نوشته‌اید، اول ذخیره‌اش کنید.", en: "Reload the page to open the new version. If you're in the middle of typing something, save it first." },
  reload: { fa: "تازه کردن صفحه", en: "Reload the page" },
  later: { fa: "بعداً", en: "Later" }
} satisfies Record<string, Bi>;

type SystemBuild = { build?: { commit?: string; ui_version?: string } };

/** The hashed main script of this page (`/assets/index-abc123.js`), or null in development. */
function currentEntry(): string | null {
  const script = document.querySelector<HTMLScriptElement>('script[type="module"][src*="/assets/"]');
  if (!script?.src) return null;
  try {
    return new URL(script.src, window.location.href).pathname;
  } catch {
    return null;
  }
}

async function servedEntry(): Promise<string | null> {
  const response = await fetch(`/?_=${Date.now()}`, { cache: "no-store", headers: { Accept: "text/html" } });
  if (!response.ok) return null;
  const html = await response.text();
  const match = /<script[^>]+type="module"[^>]+src="([^"]*\/assets\/[^"]+\.js)"/i.exec(html) ?? /<script[^>]+src="([^"]*\/assets\/[^"]+\.js)"[^>]*type="module"/i.exec(html);
  if (!match) return null;
  try {
    return new URL(match[1], window.location.href).pathname;
  } catch {
    return null;
  }
}

/** `available` once the server runs another panel build; `offline` when the status can't be reached. */
export function useBuildCheck() {
  const [available, setAvailable] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [offline, setOffline] = useState(false);
  const target = useRef("latest");

  const reloadNow = useCallback(() => {
    const url = new URL(window.location.href);
    url.searchParams.set("_ui", target.current.slice(0, 12));
    window.location.replace(url.toString());
  }, []);

  const check = useCallback(async () => {
    try {
      const response = await apiGet(`/api/v1/system/status?_=${Date.now()}`);
      if (response.status === 401) return;
      if (response.status === 403) {
        // This role can't read the status: compare the served page's main script instead.
        const mine = currentEntry();
        const served = mine ? await servedEntry().catch(() => null) : null;
        setOffline(false);
        if (mine && served && served !== mine) {
          target.current = served.replace(/^.*index-|\.js$/g, "") || "latest";
          setAvailable(true);
        }
        return;
      }
      if (!response.ok) throw new Error("status");
      const payload = (await response.json()) as SystemBuild;
      setOffline(false);
      const commit = payload.build?.commit ?? "unknown";
      const uiVersion = payload.build?.ui_version ?? packageMetadata.version;
      const sameVersion = uiVersion === packageMetadata.version;
      const sameCommit = commit === "unknown" || UI_COMMIT === "unknown" || commit === UI_COMMIT;
      if (sameVersion && sameCommit) return;
      target.current = commit !== "unknown" ? commit : uiVersion;
      setAvailable(true);
    } catch {
      setOffline(true);
    }
  }, []);

  useEffect(() => {
    void check();
    let timer = window.setInterval(() => void check(), POLL_MS);
    const onVisible = () => {
      window.clearInterval(timer);
      if (document.visibilityState === "visible") {
        void check();
        timer = window.setInterval(() => void check(), POLL_MS);
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [check]);

  return { available: available && !dismissed, offline, retry: check, reloadNow, dismiss: () => setDismissed(true) };
}

export function NewVersionBar({ language, onReload, onLater }: { language: Language; onReload: () => void; onLater: () => void }) {
  return (
    <Alert
      severity="info"
      icon={<UpdateRoundedIcon />}
      role="status"
      action={
        <>
          <Button color="inherit" size="small" onClick={onLater} sx={{ minHeight: 40 }}>{pick(language, COPY.later)}</Button>
          <Button color="inherit" size="small" variant="outlined" onClick={onReload} sx={{ minHeight: 40, mx: 0.5 }}>{pick(language, COPY.reload)}</Button>
        </>
      }
      sx={{ mb: 2.5, alignItems: "center", flexWrap: "wrap", "& .MuiAlert-action": { pt: 0, flexWrap: "wrap", gap: 0.5 } }}
    >
      <Typography fontWeight={750}>{pick(language, COPY.title)}</Typography>
      <Typography variant="body2">{pick(language, COPY.body)}</Typography>
    </Alert>
  );
}
