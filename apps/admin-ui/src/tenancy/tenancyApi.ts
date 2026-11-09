/**
 * Admin side of «فضای من» (docs/43 §2, permission `tenancy:admin`): plans, workspaces with usage,
 * plan/override changes, pause, delete/transfer, ownership transfer, "view as", pending sign-ups.
 * Every field is optional; lists accept `[...]` or `{items: [...]}` (the backend is built in parallel).
 */
import { getJson, mutateJson } from "../api";
import { itemsOf, normalizePlan, normalizeWorkspace, type LimitValue, type Plan, type Workspace } from "../my/myApi";

const BASE = "/api/v1/admin";
const fresh = () => `_=${Date.now()}`;
const enc = encodeURIComponent;
const asObject = (value: unknown): Record<string, unknown> => (value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {});
const text = (value: unknown) => (typeof value === "string" ? value : typeof value === "number" ? String(value) : "");

// ── plans ────────────────────────────────────────────────────────────────────

export async function fetchPlans(signal?: AbortSignal): Promise<Plan[]> {
  return itemsOf<unknown>(await getJson(`${BASE}/plans?${fresh()}`, signal), "plans").map(normalizePlan).filter((plan) => plan.id);
}

export type PlanInput = Omit<Plan, "id" | "workspaces"> & { id?: string };

export function savePlan(plan: PlanInput) {
  const body = {
    name_fa: plan.name_fa ?? "",
    name_en: plan.name_en ?? "",
    description: plan.description ?? "",
    default: Boolean(plan.default),
    features: plan.features,
    quotas: plan.quotas
  };
  return plan.id
    ? mutateJson(`${BASE}/plans/${enc(plan.id)}`, { method: "PUT", body })
    : mutateJson(`${BASE}/plans`, { method: "POST", body });
}
export const deletePlan = (id: string) => mutateJson(`${BASE}/plans/${enc(id)}`, { method: "DELETE" });

// ── workspaces ───────────────────────────────────────────────────────────────

export type AdminWorkspace = Workspace & {
  owner: { username: string; display_name: string | null; email: string | null } | null;
  members: number | null;
  plan_id: string | null;
  quota_overrides: Record<string, LimitValue>;
};

function normalizeAdminWorkspace(raw: unknown): AdminWorkspace {
  const body = asObject(raw);
  const base = normalizeWorkspace(raw);
  const owner = asObject(body.owner);
  const overrides: Record<string, LimitValue> = {};
  for (const [key, value] of Object.entries(asObject(body.quota_overrides))) {
    if (Array.isArray(value)) overrides[key] = value.map(String);
    else if (value === null) overrides[key] = null;
    else if (typeof value === "number") overrides[key] = value;
  }
  // `role` means nothing on the admin list; the plan id may come flat.
  const planId = text(body.plan_id) || base.plan?.id || null;
  return {
    ...base,
    owner: Object.keys(owner).length || typeof body.owner === "string"
      ? { username: text(owner.username ?? body.owner), display_name: typeof owner.display_name === "string" ? owner.display_name : null, email: typeof owner.email === "string" ? owner.email : null }
      : null,
    members: typeof body.members_count === "number" ? body.members_count : typeof body.members === "number" ? body.members : Array.isArray(body.members) ? body.members.length : typeof body.member_count === "number" ? body.member_count : null,
    plan_id: planId,
    quota_overrides: overrides
  };
}

export async function fetchWorkspaces(query: string, status: string, signal?: AbortSignal): Promise<AdminWorkspace[]> {
  const params = new URLSearchParams();
  if (query.trim()) params.set("query", query.trim());
  if (status) params.set("status", status);
  params.set("_", String(Date.now()));
  return itemsOf<unknown>(await getJson(`${BASE}/workspaces?${params.toString()}`, signal), "workspaces").map(normalizeAdminWorkspace).filter((item) => item.id);
}

export type WorkspaceMemberRow = { user_id: string; username: string; display_name: string | null; email: string | null; role: string };
export type ResourceRow = { kind: string; resource_id: string; name: string };
export type WorkspaceDetail = { workspace: AdminWorkspace; members: WorkspaceMemberRow[]; resources: ResourceRow[] };

export async function fetchWorkspaceDetail(id: string, signal?: AbortSignal): Promise<WorkspaceDetail> {
  const body = asObject(await getJson(`${BASE}/workspaces/${enc(id)}?${fresh()}`, signal));
  const source = body.workspace && typeof body.workspace === "object" ? body.workspace : body;
  const members = itemsOf<unknown>(body.members).map((raw) => {
    const item = asObject(raw);
    const user = asObject(item.user);
    return {
      user_id: text(item.user_id ?? user.id),
      username: text(item.username ?? user.username),
      display_name: typeof (item.display_name ?? user.display_name) === "string" ? String(item.display_name ?? user.display_name) : null,
      email: typeof (item.email ?? user.email) === "string" ? String(item.email ?? user.email) : null,
      role: text(item.role)
    };
  });
  const resources = itemsOf<unknown>(body.resources).map((raw) => {
    const item = asObject(raw);
    const meta = asObject(item.meta);
    return { kind: text(item.kind), resource_id: text(item.resource_id ?? item.id), name: text(item.name ?? meta.name ?? meta.host ?? item.resource_id ?? item.id) };
  }).filter((item) => item.resource_id);
  return { workspace: normalizeAdminWorkspace(source), members, resources };
}

/** `quota_overrides`: a key with `null` removes that exception (docs/43 §0.1). */
export const patchWorkspace = (id: string, body: { plan_id?: string | null; quota_overrides?: Record<string, LimitValue>; status?: "active" | "suspended"; name?: string }) =>
  mutateJson(`${BASE}/workspaces/${enc(id)}`, { method: "PATCH", body });

export const removeWorkspace = (id: string, slug: string, mode: "delete" | "transfer") =>
  mutateJson(`${BASE}/workspaces/${enc(id)}?confirmation=${enc(slug)}&mode=${mode}`, { method: "DELETE" });

export const transferOwnership = (kind: string, resourceId: string, workspaceId: string | null) =>
  mutateJson(`${BASE}/ownership/transfer`, { method: "POST", body: { kind, resource_id: resourceId, workspace_id: workspaceId } });

export async function startViewAs(id: string, write: boolean): Promise<{ token: string; expiresAt: number | null }> {
  const body = asObject(await mutateJson(`${BASE}/workspaces/${enc(id)}/view-as`, { method: "POST", body: write ? { write: true } : {} }));
  const raw = body.expires_at;
  let expiresAt: number | null = null;
  if (typeof raw === "number") expiresAt = raw < 1e12 ? raw * 1000 : raw;
  else if (typeof raw === "string" && Number.isFinite(Date.parse(raw))) expiresAt = Date.parse(raw);
  if (expiresAt === null) expiresAt = Date.now() + 30 * 60_000;
  return { token: text(body.token ?? body.session_token), expiresAt };
}

// ── sign-ups ─────────────────────────────────────────────────────────────────

export type Signup = { id: string; username: string; display_name: string | null; email: string | null; created_at: number | string | null };

export async function fetchSignups(signal?: AbortSignal): Promise<Signup[]> {
  return itemsOf<unknown>(await getJson(`${BASE}/signups?status=pending&${fresh()}`, signal), "signups").map((raw) => {
    const item = asObject(raw);
    const user = { ...item, ...asObject(item.user) };
    return {
      id: text(item.id),
      username: text(user.username),
      display_name: typeof user.display_name === "string" ? user.display_name : null,
      email: typeof user.email === "string" ? user.email : null,
      created_at: (item.created_at as number | string | null | undefined) ?? null
    };
  }).filter((item) => item.id);
}
export const approveSignup = (id: string, planId: string | null) => mutateJson(`${BASE}/signups/${enc(id)}/approve`, { method: "POST", body: planId ? { plan_id: planId } : {} });
export const rejectSignup = (id: string) => mutateJson(`${BASE}/signups/${enc(id)}/reject`, { method: "POST", body: {} });

// ── settings (docs/43 §0.1 `GET/PUT /admin/tenancy/settings`; the same keys live in the registry) ──

export type InviteSignupMode = "follow" | "off" | "approval" | "open";
export type TenancySettings = { enabled: boolean; signup: "off" | "approval" | "open"; invite_signup: InviteSignupMode; default_plan_id: string | null; verify_domains: boolean; admin_area_local_only: boolean };

function normalizeSettings(raw: unknown): TenancySettings {
  const body = asObject(raw);
  const signup = text(body.signup);
  const invite = text(body.invite_signup);
  return {
    enabled: body.enabled === true,
    signup: signup === "approval" || signup === "open" ? signup : "off",
    invite_signup: invite === "off" || invite === "approval" || invite === "open" ? invite : "follow",
    default_plan_id: text(body.default_plan_id) || null,
    verify_domains: body.verify_domains !== false,
    admin_area_local_only: body.admin_area_local_only === true
  };
}
export const fetchTenancySettings = async (signal?: AbortSignal) => normalizeSettings(await getJson(`${BASE}/tenancy/settings?${fresh()}`, signal));
export const saveTenancySettings = async (changes: Partial<TenancySettings>) => normalizeSettings(await mutateJson(`${BASE}/tenancy/settings`, { method: "PUT", body: changes }));
