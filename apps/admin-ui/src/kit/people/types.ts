/**
 * People & access data shapes (docs/34 §2) and helpers that turn them into plain words.
 *
 * - `GET /api/v1/permissions` → PermissionCatalog (7 groups, each permission with danger + requires)
 * - `GET /api/v1/roles`       → { items: RoleRecord[] } (built-in cards + custom roles `custom:<id>`)
 *
 * When the API is unavailable the copy catalog (`copy/roles.ts`) is used as a fallback, so the
 * page never shows raw ids.
 */
import type { Language } from "../../i18n";
import {
  PERMISSIONS,
  PERMISSION_GROUP_NAMES,
  ROLES,
  ROLE_PERMISSIONS,
  type Danger,
  type PermissionGroup,
  type RoleKey
} from "../../copy/roles";
import { pick } from "../../copy/text";

export type PermissionSpec = {
  id: string;
  name_fa: string;
  name_en: string;
  description_fa?: string | null;
  description_en?: string | null;
  danger: Danger;
  requires: string[];
  assignable: boolean;
};

export type PermissionGroupSpec = {
  id: PermissionGroup | string;
  name_fa: string;
  name_en: string;
  permissions: PermissionSpec[];
};

export type PermissionCatalog = { groups: PermissionGroupSpec[]; danger_levels?: string[] };

export type RoleRecord = {
  id: string;
  name: string;
  builtin: boolean;
  editable: boolean;
  name_fa: string;
  name_en: string;
  description_fa?: string | null;
  description_en?: string | null;
  note_fa?: string | null;
  note_en?: string | null;
  can_fa?: string[];
  can_en?: string[];
  cannot_fa?: string[];
  cannot_en?: string[];
  permissions: string[];
  user_count?: number;
  created_at?: number;
  updated_at?: number;
};

export type UserRecord = {
  id: number;
  username: string;
  display_name?: string | null;
  email?: string | null;
  role: string;
  enabled: boolean;
  identity_provider?: string | null;
  mfa_enabled?: boolean;
  created_at: number;
  last_login_at: number | null;
  must_change_password?: boolean;
  invite_pending?: boolean;
};

/** Colour of a role avatar (MUI palette key). */
export type RoleColor = "error" | "warning" | "primary" | "secondary" | "info" | "success";

/** Everything a role card needs, already in one language. */
export type RoleView = {
  id: string;
  name: string;
  oneLiner: string;
  can: string[];
  cannot: string[];
  note?: string;
  color: RoleColor;
  builtin: boolean;
  userCount?: number;
  permissions: string[];
};

function isRoleKey(value: string): value is RoleKey {
  return Object.prototype.hasOwnProperty.call(ROLES, value);
}

/** Catalogue from the copy module (used when `GET /api/v1/permissions` is unavailable). */
export function fallbackCatalog(): PermissionCatalog {
  const order: PermissionGroup[] = ["home", "packages", "server", "files", "security", "people", "alerts"];
  return {
    groups: order.map((group) => ({
      id: group,
      name_fa: PERMISSION_GROUP_NAMES[group].fa,
      name_en: PERMISSION_GROUP_NAMES[group].en,
      permissions: Object.entries(PERMISSIONS)
        .filter(([, info]) => info.group === group)
        .map(([id, info]) => ({
          id,
          name_fa: info.name.fa,
          name_en: info.name.en,
          danger: info.danger,
          requires: info.requires ?? [],
          assignable: id !== "*"
        }))
    }))
  };
}

/** id → spec for quick lookups. */
export function indexCatalog(catalog: PermissionCatalog): Map<string, PermissionSpec> {
  const map = new Map<string, PermissionSpec>();
  for (const group of catalog.groups) for (const item of group.permissions) map.set(item.id, item);
  return map;
}

/** Plain name of a permission from the catalogue (never the raw id). */
export function permissionLabel(language: Language, id: string, index?: Map<string, PermissionSpec>): string {
  const spec = index?.get(id);
  if (spec) return language === "fa" ? spec.name_fa : spec.name_en;
  const info = PERMISSIONS[id];
  if (info) return pick(language, info.name);
  return language === "fa" ? "یک اجازه دیگر" : "Another permission";
}

/** Built-in role → card, preferring the API's words and falling back to the copy module. */
export function roleView(language: Language, record: RoleRecord | null | undefined, roleId?: string): RoleView {
  const id = record?.id ?? roleId ?? "viewer";
  const builtin = record ? record.builtin : isRoleKey(id);
  const local = isRoleKey(id) ? ROLES[id] : null;
  const fromApi = (fa?: string[] | null, en?: string[] | null) => (language === "fa" ? fa : en) ?? [];
  const apiCan = fromApi(record?.can_fa, record?.can_en);
  const apiCannot = fromApi(record?.cannot_fa, record?.cannot_en);
  const apiName = record ? (language === "fa" ? record.name_fa : record.name_en) : "";
  const apiDescription = record ? (language === "fa" ? record.description_fa : record.description_en) : "";
  const apiNote = record ? (language === "fa" ? record.note_fa : record.note_en) : "";
  const name = local ? pick(language, local.name) : apiName || (language === "fa" ? "نقش سفارشی" : "Custom role");
  return {
    id,
    name,
    oneLiner: apiDescription || (local ? pick(language, local.oneLiner) : language === "fa" ? "نقشی که خودتان ساخته‌اید" : "A role you made"),
    can: apiCan.length ? apiCan : local ? local.can[language] : [],
    cannot: apiCannot.length ? apiCannot : local ? local.cannot[language] : [],
    note: apiNote || (local?.note ? pick(language, local.note) : undefined),
    color: local ? local.color : "success",
    builtin,
    userCount: record?.user_count,
    permissions: record?.permissions ?? (isRoleKey(id) ? [...ROLE_PERMISSIONS[id]] : [])
  };
}

/** The role's plain name for a user row, using the loaded role list for custom roles. */
export function roleTitle(language: Language, roleId: string, roles?: readonly RoleRecord[] | null): string {
  if (isRoleKey(roleId)) return pick(language, ROLES[roleId].name);
  const record = roles?.find((item) => item.id === roleId || item.name === roleId);
  if (record) return language === "fa" ? record.name_fa : record.name_en;
  return language === "fa" ? "نقش سفارشی" : "Custom role";
}

/**
 * Fill gaps in a role from an older backend (`{name, permissions}` only): id, builtin, names.
 * Built-in names come from the copy catalogue; custom roles keep their own name.
 */
export function normalizeRole(raw: Partial<RoleRecord> & { name?: string; display_name?: string | null; description?: string | null }): RoleRecord {
  const id = String(raw.id ?? raw.name ?? "");
  const local = isRoleKey(id) ? ROLES[id] : null;
  const label = raw.display_name ?? (local ? null : raw.name ?? id);
  return {
    ...raw,
    id,
    name: String(raw.name ?? id),
    builtin: raw.builtin ?? Boolean(local),
    editable: raw.editable ?? !local,
    name_fa: raw.name_fa ?? (local ? local.name.fa : label ?? id),
    name_en: raw.name_en ?? (local ? local.name.en : label ?? id),
    description_fa: raw.description_fa ?? raw.description ?? null,
    description_en: raw.description_en ?? raw.description ?? null,
    permissions: Array.isArray(raw.permissions) ? raw.permissions : []
  };
}

/** Order roles for pickers: built-ins from least to most powerful, then custom roles by name. */
export function sortRoles(roles: readonly RoleRecord[]): RoleRecord[] {
  const rank: Record<string, number> = { viewer: 0, developer: 1, operator: 2, admin: 3, owner: 4 };
  return [...roles].sort((a, b) => {
    const ra = rank[a.id] ?? 10;
    const rb = rank[b.id] ?? 10;
    if (ra !== rb) return ra - rb;
    return (a.name_fa ?? a.id).localeCompare(b.name_fa ?? b.id);
  });
}

/** Does `held` cover every permission in `wanted`? (`*` covers everything.) */
export function covers(held: readonly string[], wanted: readonly string[]): boolean {
  if (held.includes("*")) return true;
  return wanted.every((item) => held.includes(item));
}

/** Add every required permission (write ⇒ read, prune ⇒ operate …) using the catalogue. */
export function closeOver(ids: Iterable<string>, index: Map<string, PermissionSpec>): Set<string> {
  const result = new Set(ids);
  const pending = [...result];
  while (pending.length) {
    const id = pending.pop() as string;
    for (const needed of index.get(id)?.requires ?? PERMISSIONS[id]?.requires ?? []) {
      if (!result.has(needed)) {
        result.add(needed);
        pending.push(needed);
      }
    }
  }
  return result;
}

/** Permissions in `ids` that need `id` (directly or through a chain). */
export function dependentsOf(id: string, ids: Iterable<string>, index: Map<string, PermissionSpec>): string[] {
  const list = [...ids];
  return list.filter((candidate) => candidate !== id && closeOver([candidate], index).has(id));
}

/** {permission: [missing requirements]} for a selection. */
export function missingDependencies(ids: Iterable<string>, index: Map<string, PermissionSpec>): Record<string, string[]> {
  const set = new Set(ids);
  const result: Record<string, string[]> = {};
  for (const id of set) {
    const lacking = (index.get(id)?.requires ?? []).filter((needed) => !set.has(needed));
    if (lacking.length) result[id] = lacking;
  }
  return result;
}

/** Initials for an avatar: «مریم رضایی» → «مر», "John Smith" → "JS". */
export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return /^[A-Za-z]/.test(parts[0]) ? parts[0].slice(0, 2).toUpperCase() : parts[0].slice(0, 1);
  return (parts[0][0] + parts[1][0]).toUpperCase();
}
