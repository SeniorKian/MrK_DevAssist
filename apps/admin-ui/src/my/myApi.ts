/**
 * «فضای من» API (docs/43 §3): `/api/v1/my/...`. The current workspace and an admin's "view as"
 * token travel as headers (`api.ts setMyScope`), so paths here never carry a workspace id unless the
 * contract puts it in the path (members, invites).
 *
 * The backend is built in parallel: every field is optional, lists accept `[...]` or `{items: [...]}`,
 * and unknown shapes degrade to empty values instead of breaking a page. Exact shapes: docs/43 §0.1.
 */
import { getJson, mutateJson } from "../api";
import { QUOTA_KEYS, type FeatureKey, type WorkspaceRole } from "../copy/mySpace";

export const MY_BASE = "/api/v1/my";
const fresh = () => `_=${Date.now()}`;
const enc = encodeURIComponent;

export function itemsOf<T>(payload: unknown, ...keys: string[]): T[] {
  if (Array.isArray(payload)) return payload as T[];
  if (!payload || typeof payload !== "object") return [];
  for (const key of ["items", ...keys]) {
    const value = (payload as Record<string, unknown>)[key];
    if (Array.isArray(value)) return value as T[];
  }
  return [];
}

const asObject = (value: unknown): Record<string, unknown> => (value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {});
const asString = (value: unknown, fallback = ""): string => (typeof value === "string" ? value : typeof value === "number" ? String(value) : fallback);
const asNumber = (value: unknown): number | null => (typeof value === "number" && Number.isFinite(value) ? value : typeof value === "string" && value.trim() && Number.isFinite(Number(value)) ? Number(value) : null);

// ── plans, usage and limits ──────────────────────────────────────────────────

/** A limit: a number, `null` = unlimited, or a list (`dns_record_types`). */
export type LimitValue = number | null | string[];
export type Plan = {
  id: string;
  name_fa?: string | null;
  name_en?: string | null;
  name?: string | null;
  description?: string | null;
  default?: boolean;
  /** Ready-made plans (basic, pro, unlimited) can be edited but not deleted. */
  builtin?: boolean;
  features: Partial<Record<FeatureKey, boolean>>;
  quotas: Record<string, LimitValue>;
  workspaces?: number | null;
};

export function normalizePlan(raw: unknown): Plan {
  const body = asObject(raw);
  const features: Partial<Record<FeatureKey, boolean>> = {};
  for (const [key, value] of Object.entries(asObject(body.features))) features[key as FeatureKey] = value === true;
  const quotas: Record<string, LimitValue> = {};
  for (const [key, value] of Object.entries(asObject(body.quotas))) {
    if (Array.isArray(value)) quotas[key] = value.map(String);
    else if (value === null) quotas[key] = null;
    else {
      const number = asNumber(value);
      if (number !== null) quotas[key] = number;
    }
  }
  return {
    id: asString(body.id),
    name_fa: typeof body.name_fa === "string" ? body.name_fa : null,
    name_en: typeof body.name_en === "string" ? body.name_en : null,
    name: typeof body.name === "string" ? body.name : null,
    description: typeof body.description === "string" ? body.description : null,
    default: body.default === true || body.is_default === true,
    builtin: body.builtin === true,
    features,
    quotas,
    workspaces: asNumber(body.workspaces ?? body.workspace_count ?? body.in_use)
  };
}

export function planName(language: "fa" | "en", plan: Pick<Plan, "name_fa" | "name_en" | "name" | "id"> | null | undefined): string {
  if (!plan) return "";
  return (language === "fa" ? plan.name_fa || plan.name_en : plan.name_en || plan.name_fa) || plan.name || plan.id;
}

// ── workspaces and me ────────────────────────────────────────────────────────

export type Workspace = {
  /** docs/43 §0.1: `limits.features` (plan features with this space's overrides). */
  features: Partial<Record<FeatureKey, boolean>>;
  id: string;
  slug: string;
  name: string;
  kind: "personal" | "team";
  role: WorkspaceRole;
  status: "active" | "suspended";
  plan: Plan | null;
  usage: Record<string, number>;
  limits: Record<string, LimitValue>;
  /** Per-zone record counts may arrive here (`{zone: n}`); optional. */
  created_at?: number | string | null;
};

const ROLES: WorkspaceRole[] = ["owner", "admin", "member", "viewer"];

export function normalizeWorkspace(raw: unknown): Workspace {
  const body = asObject(raw);
  const plan = body.plan && typeof body.plan === "object" ? normalizePlan(body.plan) : null;
  const usage: Record<string, number> = {};
  for (const [key, value] of Object.entries(asObject(body.usage))) {
    const number = asNumber(value);
    if (number !== null) usage[key] = number;
  }
  // docs/43 §0.1: `limits: {features, quotas}` (plan + overrides). Older drafts: flat `limits`, or plan quotas + `quota_overrides`.
  const limitsBody = asObject(body.limits);
  const limits: Record<string, LimitValue> = { ...(plan?.quotas ?? {}) };
  const explicit = limitsBody.quotas && typeof limitsBody.quotas === "object" ? asObject(limitsBody.quotas) : Object.fromEntries(Object.entries(limitsBody).filter(([key]) => key !== "features"));
  const overrides = asObject(body.quota_overrides);
  const features: Partial<Record<FeatureKey, boolean>> = { ...(plan?.features ?? {}) };
  for (const [key, value] of Object.entries(asObject(limitsBody.features))) features[key as FeatureKey] = value === true;
  for (const source of Object.keys(explicit).length ? [explicit] : [overrides]) {
    for (const [key, value] of Object.entries(source)) {
      if (Array.isArray(value)) limits[key] = value.map(String);
      else if (value === null) limits[key] = null;
      else {
        const number = asNumber(value);
        if (number !== null) limits[key] = number;
      }
    }
  }
  const role = asString(body.role) as WorkspaceRole;
  return {
    features,
    id: asString(body.id),
    slug: asString(body.slug),
    name: asString(body.name) || asString(body.slug),
    kind: body.kind === "team" ? "team" : "personal",
    role: ROLES.includes(role) ? role : "viewer",
    status: body.status === "suspended" ? "suspended" : "active",
    plan,
    usage,
    limits,
    created_at: (body.created_at as number | string | null | undefined) ?? null
  };
}

export type MyUser = { id?: number | string; username?: string; display_name?: string | null; email?: string | null; role?: string };
export type MyMe = { user: MyUser | null; workspaces: Workspace[]; current: string | null; viewAs?: { workspace_id?: string; write?: boolean; expires_at?: number | string | null } | null };

export async function fetchMe(signal?: AbortSignal): Promise<MyMe> {
  const body = asObject(await getJson<unknown>(`${MY_BASE}/me?${fresh()}`, signal));
  const workspaces = itemsOf<unknown>(body.workspaces).map(normalizeWorkspace).filter((item) => item.id);
  const current = typeof body.current === "string" ? body.current : asString(asObject(body.current).id) || null;
  const viewAs = body.view_as && typeof body.view_as === "object" ? (body.view_as as MyMe["viewAs"]) : null;
  return { user: (body.user as MyUser | null) ?? null, workspaces, current, viewAs };
}

export const createWorkspace = (name: string) => mutateJson<unknown>(`${MY_BASE}/workspaces`, { method: "POST", body: { name } }).then(normalizeWorkspace);
/** `POST /my/invites/accept {token}` → `{workspace_id, role}` (the invite link opens `#/my/team?accept=<token>`). */
export const acceptInvite = (token: string) => mutateJson<{ workspace_id?: string; role?: string } | null>(`${MY_BASE}/invites/accept`, { method: "POST", body: { token } });
export const renameWorkspace = (id: string, name: string) => mutateJson(`${MY_BASE}/workspaces/${enc(id)}`, { method: "PATCH", body: { name } });
export const deleteWorkspace = (id: string, slug: string) =>
  mutateJson(`${MY_BASE}/workspaces/${enc(id)}`, { method: "DELETE", body: { confirmation: slug } });

// ── usage helpers ────────────────────────────────────────────────────────────

export type UsageRow = { key: string; used: number; limit: number | null; percent: number | null; level: "ok" | "near" | "full" };

/** One row per numeric limit the workspace has (unlimited ones too), in catalog order. */
export function usageRows(workspace: Workspace, features: Partial<Record<FeatureKey, boolean>>, featureOf: (key: string) => FeatureKey | undefined): UsageRow[] {
  const rows: UsageRow[] = [];
  const keys = [...QUOTA_KEYS.filter((key) => key in workspace.limits || key in workspace.usage), ...Object.keys(workspace.limits).filter((key) => !(QUOTA_KEYS as string[]).includes(key))];
  for (const key of keys) {
    if (key === "dns_records_per_zone" || key === "dns_record_types") continue;
    const feature = featureOf(key);
    if (feature && features[feature] === false) continue;
    const raw = workspace.limits[key];
    if (Array.isArray(raw)) continue;
    const limit = raw === undefined ? null : raw;
    const used = workspace.usage[key] ?? 0;
    const percent = limit === null ? null : limit <= 0 ? 100 : Math.min(100, (used / limit) * 100);
    const level = percent === null ? "ok" : percent >= 100 ? "full" : percent >= 80 ? "near" : "ok";
    rows.push({ key, used, limit, percent, level });
  }
  return rows;
}

export function numericLimit(workspace: Workspace | null, key: string): number | null {
  const value = workspace?.limits[key];
  return typeof value === "number" ? value : null;
}

export function listLimit(workspace: Workspace | null, key: string): string[] | null {
  const value = workspace?.limits[key];
  return Array.isArray(value) && value.length ? value : null;
}

// ── DNS (docs/43 §3 «DNS»); records, templates and signing reuse dns.ts inside <DnsApiScope> ──

export const MY_DNS_BASE = `${MY_BASE}/dns`;

export type MyZone = {
  name: string;
  status: "active" | "pending_verification" | string;
  verified: boolean;
  records: number | null;
  dnssec: boolean;
  created_at?: number | string | null;
};

export function normalizeZone(raw: unknown): MyZone {
  const body = asObject(raw);
  const status = asString(body.status, "active");
  const records = Array.isArray(body.records) ? body.records.length : asNumber(body.records ?? body.record_count);
  const dnssec = body.dnssec === true || asObject(body.dnssec).enabled === true || body.signed === true;
  return {
    name: asString(body.name ?? body.zone),
    status,
    verified: body.verified === true || (body.verified === undefined && status !== "pending_verification") || Boolean(body.verified_at && status !== "pending_verification"),
    records,
    dnssec,
    created_at: (body.created_at as number | string | null | undefined) ?? null
  };
}

export async function fetchMyZones(signal?: AbortSignal): Promise<MyZone[]> {
  return itemsOf<unknown>(await getJson(`${MY_DNS_BASE}/zones?${fresh()}`, signal), "zones").map(normalizeZone).filter((zone) => zone.name);
}
export const createMyZone = (body: { name: string; template_id?: string | null; variables?: Record<string, string> }) =>
  mutateJson<unknown>(`${MY_DNS_BASE}/zones`, { method: "POST", body }).then(normalizeZone);
export const deleteMyZone = (zone: string) => mutateJson(`${MY_DNS_BASE}/zones/${enc(zone)}`, { method: "DELETE", body: { confirmation: zone } });

export type VerificationMethod = { kind: "txt" | "ns" | string; name?: string; value?: string; targets?: string[] };
export type Verification = { methods: VerificationMethod[]; verified: boolean; checked_at?: number | string | null };

export async function fetchVerification(zone: string, signal?: AbortSignal): Promise<Verification> {
  const body = asObject(await getJson(`${MY_DNS_BASE}/zones/${enc(zone)}/verification?${fresh()}`, signal));
  const methods = itemsOf<VerificationMethod>(body.methods).filter((item) => item && typeof item === "object");
  return { methods, verified: body.verified === true, checked_at: (body.checked_at as number | string | null | undefined) ?? null };
}
export async function verifyZone(zone: string): Promise<boolean> {
  const body = asObject(await mutateJson(`${MY_DNS_BASE}/zones/${enc(zone)}/verify`, { method: "POST", body: {} }));
  return body.verified === true || body.status === "active";
}

// ── file space (docs/43 §3 «فضای فایل») ──────────────────────────────────────

export const MY_S3_BASE = `${MY_BASE}/s3`;
export const MY_BUCKETS_BASE = `${MY_S3_BASE}/buckets`;

export type MyBucket = { name: string; public_read: boolean; objects: number | null; bytes: number | null; domains: string[]; created_at?: number | string | null };

export async function fetchMyBuckets(signal?: AbortSignal): Promise<{ items: MyBucket[]; endpoint: string | null; suggestedPrefix: string | null }> {
  const payload = await getJson<unknown>(`${MY_BUCKETS_BASE}?${fresh()}`, signal);
  const body = asObject(payload);
  const items = itemsOf<unknown>(payload, "buckets").map((raw) => {
    const item = asObject(raw);
    return {
      name: asString(item.name),
      public_read: item.public_read === true || item.public === true,
      objects: asNumber(item.objects),
      bytes: asNumber(item.bytes),
      domains: itemsOf<unknown>(item.domains).map((value) => (typeof value === "string" ? value : asString(asObject(value).domain))).filter(Boolean),
      created_at: (item.created_at as number | string | null | undefined) ?? null
    };
  }).filter((item) => item.name);
  return { items, endpoint: typeof body.endpoint === "string" ? body.endpoint : null, suggestedPrefix: typeof body.suggested_prefix === "string" ? body.suggested_prefix : null };
}
export const createMyBucket = (name: string) => mutateJson(MY_BUCKETS_BASE, { method: "POST", body: { name } });
export const setBucketPublic = (name: string, publicRead: boolean) => mutateJson(`${MY_BUCKETS_BASE}/${enc(name)}`, { method: "PATCH", body: { public_read: publicRead } });
export const deleteMyBucket = (name: string) => mutateJson(`${MY_BUCKETS_BASE}/${enc(name)}`, { method: "DELETE", body: { confirmation: name, force: true } });

export type BucketRouteState = "ok" | "pending" | "manual" | "failed" | "conflict" | "off" | "unverified";
export type BucketRoute = { state: BucketRouteState; errorCode: string | null };
const ROUTE_STATES: BucketRouteState[] = ["ok", "pending", "manual", "failed", "conflict", "off", "unverified"];
function routeOf(raw: unknown): BucketRoute | null {
  const item = asObject(raw);
  const state = asString(item.state) as BucketRouteState;
  if (!ROUTE_STATES.includes(state)) return null;
  return { state, errorCode: typeof item.error_code === "string" ? item.error_code : null };
}
export type BucketDomain = { domain: string; verified: boolean; verification: Verification | null; route: BucketRoute | null };
export async function fetchBucketDomains(bucket: string, signal?: AbortSignal): Promise<BucketDomain[]> {
  return itemsOf<unknown>(await getJson(`${MY_BUCKETS_BASE}/${enc(bucket)}/domains?${fresh()}`, signal), "domains").map((raw) => {
    // docs/43 §0.1: `{host, verified, verification:{name, value}}` (a TXT record).
    const item = asObject(typeof raw === "string" ? { host: raw, verified: true } : raw);
    const proof = asObject(item.verification);
    const methods = Array.isArray(proof.methods)
      ? itemsOf<VerificationMethod>(proof.methods)
      : proof.name || proof.value ? [{ kind: "txt", name: asString(proof.name), value: asString(proof.value) }] : [];
    const verified = item.verified === true;
    return { domain: asString(item.host ?? item.domain ?? item.name), verified, verification: methods.length ? { methods, verified } : null, route: routeOf(item.route) };
  }).filter((item) => item.domain);
}
export const addBucketDomain = (bucket: string, domain: string) => mutateJson(`${MY_BUCKETS_BASE}/${enc(bucket)}/domains`, { method: "POST", body: { host: domain } });
export const verifyBucketDomain = (bucket: string, domain: string) => mutateJson(`${MY_BUCKETS_BASE}/${enc(bucket)}/domains/${enc(domain)}/verify`, { method: "POST", body: {} });
/** Try the public route of a proven domain again (docs/43 §0.1). */
export const retryBucketRoute = (bucket: string, domain: string) => mutateJson(`${MY_BUCKETS_BASE}/${enc(bucket)}/domains/${enc(domain)}/route`, { method: "POST", body: {} });
export const removeBucketDomain = (bucket: string, domain: string) => mutateJson(`${MY_BUCKETS_BASE}/${enc(bucket)}/domains/${enc(domain)}`, { method: "DELETE" });

export type KeyTemplate = "read_only" | "read_write" | "admin";
/** docs/43 §0.1: one access key per entry, `{id, name, access, buckets, enabled, access_key_id, created_at}`. */
export type MyIdentity = { id: string; name: string; template: KeyTemplate; buckets: string[]; enabled: boolean; access_key_id: string; created_at?: number | string | null };
export type NewS3Key = { access_key_id: string; secret_access_key: string };

export async function fetchMyIdentities(signal?: AbortSignal): Promise<MyIdentity[]> {
  return itemsOf<unknown>(await getJson(`${MY_S3_BASE}/keys?${fresh()}`, signal), "keys").map((raw) => {
    const item = asObject(raw);
    const template = asString(item.access ?? item.policy_template ?? item.template, "read_only") as KeyTemplate;
    return {
      id: asString(item.id),
      name: asString(item.name),
      template: ["read_only", "read_write", "admin"].includes(template) ? template : "read_only",
      buckets: itemsOf<unknown>(item.buckets).map(String),
      enabled: item.enabled !== false,
      access_key_id: asString(item.access_key_id),
      created_at: (item.created_at as number | string | null | undefined) ?? null
    };
  }).filter((item) => item.id);
}

/** DevAssist builds the policy from `access` (docs/43 §3); a policy document is never sent. The secret comes back once. */
export async function createMyKey(name: string, template: KeyTemplate, buckets: string[]): Promise<NewS3Key | null> {
  const created = asObject(await mutateJson(`${MY_S3_BASE}/keys`, { method: "POST", body: { name, access: template, buckets } }));
  if (typeof created.secret_access_key === "string" && typeof created.access_key_id === "string") {
    return { access_key_id: created.access_key_id, secret_access_key: created.secret_access_key };
  }
  return null;
}
export const deleteMyIdentity = (id: string) => mutateJson(`${MY_S3_BASE}/keys/${enc(id)}`, { method: "DELETE" });

// ── packages (docs/43 §3 «بسته‌ها», §0.1) ────────────────────────────────────

export type PackageVersion = { version: string; size: number | null; created_at?: number | string | null };
export type MyPackage = { ecosystem: "npm" | "pypi"; name: string; versions: PackageVersion[]; size: number | null };
export type MyPackages = {
  npm: { enabled: boolean; publish: boolean; scope: string | null; registry: string | null; usage: number | null };
  pypi: { enabled: boolean; publish: boolean; index: string | null; indexUrl: string | null; uploadUrl: string | null; usage: number | null };
  items: MyPackage[];
};

function packagesOf(ecosystem: "npm" | "pypi", list: unknown): MyPackage[] {
  return itemsOf<unknown>(list).map((raw) => {
    const item = asObject(raw);
    const versions = itemsOf<unknown>(item.versions).map((value) => {
      const version = asObject(typeof value === "string" ? { version: value } : value);
      return { version: asString(version.version), size: asNumber(version.size ?? version.bytes), created_at: (version.created_at as number | string | null | undefined) ?? null };
    }).filter((version) => version.version);
    return { ecosystem, name: asString(item.name), versions, size: asNumber(item.bytes ?? item.size) };
  }).filter((item) => item.name);
}

export async function fetchMyPackages(signal?: AbortSignal): Promise<MyPackages> {
  const body = asObject(await getJson(`${MY_BASE}/packages?${fresh()}`, signal));
  const npm = asObject(body.npm);
  const pypi = asObject(body.pypi);
  const indexUrl = typeof pypi.index_url === "string" ? pypi.index_url : null;
  return {
    npm: {
      enabled: npm.enabled === true,
      publish: npm.publish_allowed !== false,
      scope: typeof npm.scope === "string" ? npm.scope : null,
      registry: typeof npm.registry_url === "string" ? npm.registry_url : typeof npm.registry === "string" ? npm.registry : null,
      usage: asNumber(npm.usage_bytes)
    },
    pypi: {
      enabled: pypi.enabled === true,
      publish: pypi.publish_allowed !== false,
      index: typeof pypi.index === "string" ? pypi.index : null,
      indexUrl,
      // devpi takes uploads at the index itself (`…/<slug>/dev/`), installs from `…/+simple/`.
      uploadUrl: typeof pypi.upload_url === "string" ? pypi.upload_url : indexUrl ? indexUrl.replace(/\+simple\/?$/, "") : null,
      usage: asNumber(pypi.usage_bytes)
    },
    items: [...packagesOf("npm", npm.packages), ...packagesOf("pypi", pypi.packages), ...itemsOf<unknown>(body).map((raw) => packagesOf(asObject(raw).ecosystem === "pypi" ? "pypi" : "npm", [raw])[0]).filter(Boolean)]
  };
}

export type PackageToken = { id: string; ecosystem: "npm" | "pypi"; name: string; username: string | null; created_at?: number | string | null };
export async function fetchPackageTokens(signal?: AbortSignal): Promise<PackageToken[]> {
  return itemsOf<unknown>(await getJson(`${MY_BASE}/packages/tokens?${fresh()}`, signal), "tokens").map((raw) => {
    const item = asObject(raw);
    return { id: asString(item.id), ecosystem: (item.ecosystem === "pypi" ? "pypi" : "npm") as "npm" | "pypi", name: asString(item.name), username: typeof item.username === "string" ? item.username : null, created_at: (item.created_at as number | string | null | undefined) ?? null };
  }).filter((item) => item.id);
}
export async function createPackageToken(ecosystem: "npm" | "pypi", name: string): Promise<{ token: string; username: string | null; setup: string | null }> {
  const body = asObject(await mutateJson(`${MY_BASE}/packages/tokens`, { method: "POST", body: { ecosystem, name } }));
  const setup = asObject(body.setup);
  const file = setup.npmrc ?? setup.pypirc;
  return { token: asString(body.token ?? body.secret), username: typeof body.username === "string" ? body.username : null, setup: typeof file === "string" ? file : null };
}
export const deletePackageToken = (id: string) => mutateJson(`${MY_BASE}/packages/tokens/${enc(id)}`, { method: "DELETE" });
export const deletePackageVersion = (ecosystem: string, name: string, version: string) =>
  mutateJson(`${MY_BASE}/packages/${enc(ecosystem)}/${enc(name)}/versions/${enc(version)}`, { method: "DELETE" });

// ── members and invites ──────────────────────────────────────────────────────

export type Member = { user_id: string; username: string; display_name: string | null; email: string | null; role: WorkspaceRole; joined_at?: number | string | null };
export type Invite = { id: string; who: string; role: WorkspaceRole; expires_at?: number | string | null; url?: string | null };

export async function fetchMembers(workspaceId: string, signal?: AbortSignal): Promise<Member[]> {
  return itemsOf<unknown>(await getJson(`${MY_BASE}/workspaces/${enc(workspaceId)}/members?${fresh()}`, signal), "members").map((raw) => {
    const item = asObject(raw);
    const user = asObject(item.user);
    const role = asString(item.role) as WorkspaceRole;
    return {
      user_id: asString(item.user_id ?? user.id),
      username: asString(item.username ?? user.username),
      display_name: (typeof (item.display_name ?? user.display_name) === "string" ? (item.display_name ?? user.display_name) : null) as string | null,
      email: (typeof (item.email ?? user.email) === "string" ? (item.email ?? user.email) : null) as string | null,
      role: ROLES.includes(role) ? role : "viewer",
      joined_at: (item.joined_at ?? item.created_at ?? null) as number | string | null
    };
  }).filter((item) => item.user_id);
}
/** Add an existing user by username or email (docs/43 §0.1 `{user, role}`). */
export const addMember = (workspaceId: string, who: string, role: WorkspaceRole) =>
  mutateJson<unknown>(`${MY_BASE}/workspaces/${enc(workspaceId)}/members`, { method: "POST", body: { user: who, role } });
/** Invite by email (someone without an account yet): `{id, email, role, token, expires_at}`; the token is shown once. */
export async function createInvite(workspaceId: string, email: string, role: WorkspaceRole): Promise<{ token: string | null }> {
  const body = asObject(await mutateJson(`${MY_BASE}/workspaces/${enc(workspaceId)}/invites`, { method: "POST", body: { email, role } }));
  return { token: typeof body.token === "string" ? body.token : null };
}
export const changeMemberRole = (workspaceId: string, userId: string, role: WorkspaceRole) =>
  mutateJson(`${MY_BASE}/workspaces/${enc(workspaceId)}/members/${enc(userId)}`, { method: "PATCH", body: { role } });
export const removeMember = (workspaceId: string, userId: string) => mutateJson(`${MY_BASE}/workspaces/${enc(workspaceId)}/members/${enc(userId)}`, { method: "DELETE" });

export async function fetchInvites(workspaceId: string, signal?: AbortSignal): Promise<Invite[]> {
  return itemsOf<unknown>(await getJson(`${MY_BASE}/workspaces/${enc(workspaceId)}/invites?${fresh()}`, signal), "invites").map((raw) => {
    const item = asObject(raw);
    const role = asString(item.role) as WorkspaceRole;
    return {
      id: asString(item.id),
      who: asString(item.email ?? item.username ?? item.who),
      role: ROLES.includes(role) ? role : "viewer",
      expires_at: (item.expires_at as number | string | null | undefined) ?? null,
      url: typeof item.url === "string" ? item.url : typeof item.invite_url === "string" ? item.invite_url : null
    };
  }).filter((item) => item.id);
}
export const cancelInvite = (workspaceId: string, inviteId: string) => mutateJson(`${MY_BASE}/workspaces/${enc(workspaceId)}/invites/${enc(inviteId)}`, { method: "DELETE" });

// ── API keys ─────────────────────────────────────────────────────────────────

export type MyToken = { id: string; name: string; scopes: string[]; expires_at: number | string | null; last_used_at: number | string | null; ip_allow: string[]; created_at?: number | string | null };

export async function fetchTokens(signal?: AbortSignal): Promise<MyToken[]> {
  return itemsOf<unknown>(await getJson(`${MY_BASE}/tokens?${fresh()}`, signal), "tokens").map((raw) => {
    const item = asObject(raw);
    return {
      id: asString(item.id),
      name: asString(item.name),
      scopes: itemsOf<unknown>(item.scopes).map(String),
      expires_at: (item.expires_at as number | string | null | undefined) ?? null,
      last_used_at: (item.last_used_at as number | string | null | undefined) ?? null,
      ip_allow: itemsOf<unknown>(item.ip_allow).map(String),
      created_at: (item.created_at as number | string | null | undefined) ?? null
    };
  }).filter((item) => item.id);
}
/** `POST /my/tokens {name, scopes, expires_in_seconds?, ip_allow?}`; the workspace is the `X-Workspace` header. */
export async function createToken(body: { name: string; scopes: string[]; expires_in_seconds?: number; ip_allow?: string[] }): Promise<string> {
  const result = asObject(await mutateJson(`${MY_BASE}/tokens`, { method: "POST", body }));
  return asString(result.token ?? result.secret ?? asObject(result.item).token);
}
export const revokeToken = (id: string) => mutateJson(`${MY_BASE}/tokens/${enc(id)}`, { method: "DELETE" });

// ── activity ─────────────────────────────────────────────────────────────────

export type MyEvent = {
  id: string;
  action: string;
  result?: string | null;
  object_type?: string | null;
  object_id?: string | number | null;
  actor?: string | null;
  on_behalf_of?: string | null;
  created_at?: number | string | null;
};

export async function fetchActivity(before: string | null, signal?: AbortSignal): Promise<{ items: MyEvent[]; next: string | null }> {
  const params = new URLSearchParams({ limit: "50" });
  if (before) params.set("before_id", before);
  const payload = await getJson<unknown>(`${MY_BASE}/activity?${params.toString()}&${fresh()}`, signal);
  const body = asObject(payload);
  const items = itemsOf<unknown>(payload, "events").map((raw, index) => {
    const item = asObject(raw);
    const actor = asObject(item.actor);
    return {
      id: asString(item.id, `e${index}`),
      action: asString(item.action),
      result: typeof item.result === "string" ? item.result : null,
      object_type: typeof item.object_type === "string" ? item.object_type : null,
      object_id: (item.object_id ?? item.target ?? null) as string | number | null,
      actor: asString(item.actor_username ?? item.actor_name ?? actor.display_name ?? actor.username ?? (typeof item.actor === "string" ? item.actor : "")) || null,
      on_behalf_of: (asString(item.on_behalf_of_name ?? item.on_behalf_of) || null),
      created_at: (item.occurred_at ?? item.created_at ?? item.at ?? null) as number | string | null
    };
  });
  const next = asString(body.next_before_id ?? body.next_cursor ?? body.next) || null;
  return { items, next };
}
