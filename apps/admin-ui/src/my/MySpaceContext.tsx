/**
 * «فضای من» state for the whole shell (docs/43 §4): who I am in My space, my workspaces, the current
 * one (sent as `X-Workspace`), and an admin's "view as" session (sent as `X-View-As`, read-only unless
 * started with `write`). The shell uses it for the area switch, the workspace picker and the warning bar.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, apiMutate, isAbortError, setMyScope } from "../api";
import type { FeatureKey, WorkspaceRole } from "../copy/mySpace";
import { WORKSPACE_ROLE_ORDER } from "../copy/mySpace";
import { fetchMe, type MyMe, type Workspace } from "./myApi";

export type ViewAsSession = { token: string; workspaceId: string; workspaceName: string; expiresAt: number | null; write: boolean };

export type MySpaceState = {
  /** `unavailable` = My space is off or the server has no `/api/v1/my` yet. */
  status: "loading" | "ready" | "unavailable" | "error";
  error: unknown;
  me: MyMe | null;
  workspaces: Workspace[];
  workspace: Workspace | null;
  setWorkspace: (id: string) => void;
  reload: () => Promise<void>;
  viewAs: ViewAsSession | null;
  startViewAs: (session: ViewAsSession) => void;
  stopViewAs: () => void;
  /** Feature check for the current workspace (unknown = allowed, so a partial answer hides nothing). */
  has: (feature: FeatureKey | string) => boolean;
  /** Role checks in the current workspace (paused spaces and read-only "view as" can't write). */
  canWrite: boolean;
  canManage: boolean;
  isOwner: boolean;
  readOnlyReason: "suspended" | "viewer" | "viewAs" | null;
  /** The roles this person may give in the current workspace (never above their own). */
  assignableRoles: WorkspaceRole[];
};

const MySpaceContext = createContext<MySpaceState | null>(null);

function storedWorkspace(userId: number): string | null {
  try {
    return window.localStorage.getItem(`mrk-workspace:${userId}`);
  } catch {
    return null;
  }
}

function storeWorkspace(userId: number, id: string) {
  try {
    window.localStorage.setItem(`mrk-workspace:${userId}`, id);
  } catch {
    // storage may be unavailable
  }
}

/** Roles a member with `role` may give: owner → all; admin → member and viewer; others → none. */
export function rolesBelow(role: WorkspaceRole | null | undefined): WorkspaceRole[] {
  if (role === "owner") return [...WORKSPACE_ROLE_ORDER].reverse();
  if (role === "admin") return ["member", "viewer"];
  return [];
}

export function MySpaceProvider({ userId, children }: { userId: number; children: ReactNode }) {
  const [status, setStatus] = useState<MySpaceState["status"]>("loading");
  const [error, setError] = useState<unknown>(null);
  const [me, setMe] = useState<MyMe | null>(null);
  const [currentId, setCurrentId] = useState<string | null>(null);
  const [viewAs, setViewAs] = useState<ViewAsSession | null>(null);
  const viewAsRef = useRef<ViewAsSession | null>(null);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      const payload = await fetchMe(current.signal);
      const session = viewAsRef.current;
      const wanted = session?.workspaceId ?? storedWorkspace(userId);
      const chosen = payload.workspaces.find((item) => item.id === wanted)?.id ?? payload.current ?? payload.workspaces[0]?.id ?? null;
      setMyScope({ workspace: chosen });
      setMe(payload);
      setCurrentId(chosen);
      setError(null);
      setStatus("ready");
    } catch (caught) {
      if (isAbortError(caught)) return;
      if (caught instanceof ApiError && caught.status === 401) return;
      // Off (tenancy disabled) or an older server: the shell just hides My space for admins.
      if (caught instanceof ApiError && ([403, 404, 405, 501].includes(caught.status) || caught.code === "tenancy_disabled")) {
        setStatus("unavailable");
        setError(caught);
        return;
      }
      setError(caught);
      setStatus((value) => (value === "ready" ? value : "error"));
    }
  }, [userId]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  // A new signed-in user never inherits the previous user's scope.
  useEffect(() => () => setMyScope({ workspace: null, viewAs: null }), [userId]);

  const setWorkspace = useCallback((id: string) => {
    setMyScope({ workspace: id });
    setCurrentId(id);
    if (!viewAsRef.current) storeWorkspace(userId, id);
  }, [userId]);

  const startViewAs = useCallback((session: ViewAsSession) => {
    viewAsRef.current = session;
    setMyScope({ viewAs: session.token, workspace: session.workspaceId });
    setViewAs(session);
    setCurrentId(session.workspaceId);
    setStatus("loading");
    void load();
  }, [load]);

  const stopViewAs = useCallback(() => {
    // Tell the server the session is over (best effort; it also ends by itself after 30 minutes).
    if (viewAsRef.current) void apiMutate("/api/v1/admin/view-as", { method: "DELETE" }).catch(() => undefined);
    viewAsRef.current = null;
    setMyScope({ viewAs: null, workspace: storedWorkspace(userId) });
    setViewAs(null);
    setStatus("loading");
    void load();
  }, [load, userId]);

  // The session ends by itself when its time is over.
  useEffect(() => {
    if (!viewAs?.expiresAt) return;
    const left = viewAs.expiresAt - Date.now();
    if (left <= 0) {
      stopViewAs();
      return;
    }
    const timer = window.setTimeout(stopViewAs, Math.min(left, 2_147_000_000));
    return () => window.clearTimeout(timer);
  }, [viewAs, stopViewAs]);

  const value = useMemo<MySpaceState>(() => {
    const workspaces = me?.workspaces ?? [];
    const workspace = workspaces.find((item) => item.id === currentId) ?? null;
    const features = workspace?.features ?? {};
    const has = (feature: string) => (features as Record<string, boolean | undefined>)[feature] !== false;
    const role = workspace?.role ?? "viewer";
    const readOnlyReason: MySpaceState["readOnlyReason"] =
      viewAs && !viewAs.write ? "viewAs" : workspace?.status === "suspended" ? "suspended" : role === "viewer" ? "viewer" : null;
    const writable = readOnlyReason === null;
    return {
      status,
      error,
      me,
      workspaces,
      workspace,
      setWorkspace,
      reload: load,
      viewAs,
      startViewAs,
      stopViewAs,
      has,
      canWrite: writable,
      canManage: writable && (role === "owner" || role === "admin"),
      isOwner: writable && role === "owner",
      readOnlyReason,
      assignableRoles: writable ? rolesBelow(role) : []
    };
  }, [status, error, me, currentId, setWorkspace, load, viewAs, startViewAs, stopViewAs]);

  return <MySpaceContext.Provider value={value}>{children}</MySpaceContext.Provider>;
}

const EMPTY: MySpaceState = {
  status: "unavailable",
  error: null,
  me: null,
  workspaces: [],
  workspace: null,
  setWorkspace: () => undefined,
  reload: async () => undefined,
  viewAs: null,
  startViewAs: () => undefined,
  stopViewAs: () => undefined,
  has: () => false,
  canWrite: false,
  canManage: false,
  isOwner: false,
  readOnlyReason: null,
  assignableRoles: []
};

export function useMySpace(): MySpaceState {
  return useContext(MySpaceContext) ?? EMPTY;
}

/**
 * A «فضای من»-only account (docs/43 §1): role `customer`, or no admin permission at all
 * (only `my.*` scopes). Such people never see Server admin (menu, routes, home summary).
 */
export function isMySpaceOnly(user: { role: string; permissions: readonly string[] }): boolean {
  if (user.role === "customer") return true;
  return user.permissions.filter((permission) => !permission.startsWith("my.")).length === 0;
}
