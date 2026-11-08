import { useEffect, useRef } from "react";

/**
 * Run `callback` every `intervalMs` while the document is visible.
 * - Pauses while the tab is hidden and runs once immediately when it becomes visible again.
 * - `intervalMs` null/0 disables polling.
 * The callback is read from a ref, so passing a new function does not restart the timer.
 */
export function useVisibleInterval(callback: () => void, intervalMs: number | null) {
  const saved = useRef(callback);
  useEffect(() => {
    saved.current = callback;
  }, [callback]);

  useEffect(() => {
    if (!intervalMs) return;
    let timer: number | undefined;
    const start = () => {
      if (timer === undefined) timer = window.setInterval(() => saved.current(), intervalMs);
    };
    const stop = () => {
      if (timer !== undefined) {
        window.clearInterval(timer);
        timer = undefined;
      }
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        saved.current();
        start();
      } else {
        stop();
      }
    };
    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [intervalMs]);
}
