import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, getJson, isAbortError } from "../../api";
import { fallbackCatalog, normalizeRole, type PermissionCatalog, type RoleRecord } from "./types";

/** `GET /api/v1/roles` (needs user:read). `roles` is null until loaded or when unavailable. */
export function useRoles(enabled = true) {
  const [roles, setRoles] = useState<RoleRecord[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(enabled);
  const controller = useRef<AbortController | null>(null);
  const reload = useCallback(async () => {
    if (!enabled) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      const payload = await getJson<{ items: RoleRecord[] }>("/api/v1/roles", current.signal);
      setRoles((payload.items ?? []).map(normalizeRole));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, [enabled]);
  useEffect(() => {
    void reload();
    return () => controller.current?.abort();
  }, [reload]);
  return { roles, error, loading, reload };
}

/** `GET /api/v1/permissions` (any signed-in person), falling back to the copy catalogue. */
export function usePermissionCatalog() {
  const [catalog, setCatalog] = useState<PermissionCatalog>(() => fallbackCatalog());
  const [fromServer, setFromServer] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    getJson<PermissionCatalog>("/api/v1/permissions", controller.signal)
      .then((payload) => {
        if (payload?.groups?.length) {
          setCatalog(payload);
          setFromServer(true);
        }
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, []);
  return { catalog, fromServer };
}
