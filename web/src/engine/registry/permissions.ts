import { getSection } from "./section-registry";

/**
 * Required app-role union across requested sections — mirrors
 * Test-GraphPermissions.ps1 lines 129–147: a case-insensitive dedup union
 * (OrdinalIgnoreCase HashSet semantics) with deterministic first-seen order,
 * so the same request always yields the same role list.
 */
export function requiredRolesForSections(ids: string[]): string[] {
  const seen = new Set<string>();
  const roles: string[] = [];
  for (const id of ids) {
    for (const role of getSection(id).requiredAppRoles) {
      const key = role.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        roles.push(role);
      }
    }
  }
  return roles;
}
