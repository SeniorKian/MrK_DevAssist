/**
 * People & access kit (docs/33 §5, §6 RoleCard / PermissionMatrix). Owned by Phase 1 agent E;
 * candidates for promotion into the main kit barrel.
 */
export { RoleCard, RolePicker, type RoleCardProps, type RolePickerProps } from "./RoleCard";
export { PermissionMatrix, type PermissionMatrixProps } from "./PermissionMatrix";
export {
  fallbackCatalog, normalizeRole, indexCatalog, permissionLabel, roleView, roleTitle, sortRoles, covers, closeOver, dependentsOf,
  missingDependencies, initials,
  type PermissionSpec, type PermissionGroupSpec, type PermissionCatalog, type RoleRecord, type UserRecord, type RoleView, type RoleColor
} from "./types";
export { fieldIssues, fieldIssueMessage, fieldMessages, type FieldIssue } from "./fieldErrors";
export { useRoles, usePermissionCatalog } from "./hooks";
