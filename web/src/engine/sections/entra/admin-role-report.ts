/**
 * Port of `src/M365-Assess/Entra/Get-AdminRoleReport.ps1` (117 lines) —
 * activated directory roles and their members (plan 02-05 task 2).
 *
 * PS → TS mapping:
 * - Get-MgDirectoryRole -All (PS line 43) → getJson /v1.0/directoryRoles;
 *   failure throws → runner surfaces a section error with zero rows
 *   (PS Write-Error + return, lines 45-48).
 * - Get-MgDirectoryRoleMember -All per role (PS line 55): failure skips that
 *   role only (Write-Warning + continue); empty membership skips the role
 *   (PS lines 62-65). Raw REST members carry @odata.type/displayName/
 *   userPrincipalName at top level — the SDK's AdditionalProperties bag.
 * - Get-MgUser OnPremisesSyncEnabled probe per USER member only (PS lines
 *   84-93): True/False on success, '' left when the fetch fails.
 * - Report sorted by RoleName then MemberDisplayName (PS line 107).
 *
 * Row mapping (report collector): one Info row per role-member assignment;
 * Setting = RoleName; CurrentValue = report record Field=Value in PS property
 * order. No CheckIds exist for this report.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { asArray, kv, psStr } from "./shared";

/** Declared GET path shapes (mirrored into registry endpoints[] by plan 02-12). */
export const ADMIN_ROLE_REPORT_ENDPOINTS = {
  directoryRoles: "/v1.0/directoryRoles",
  directoryRoleMembers: "/v1.0/directoryRoles/{*}/members",
  userOnPremisesSyncEnabled: "/v1.0/users/{*}?$select=onPremisesSyncEnabled",
} as const;

const CATEGORY = "Admin Roles";

interface AssignmentRecord {
  roleName: string;
  roleId: unknown;
  memberDisplayName: unknown;
  memberUpn: unknown;
  memberType: string;
  memberId: unknown;
  onPremisesSyncEnabled: string;
}

/** OData type → friendly name (Get-AdminRoleReport.ps1:75-80). */
function friendlyMemberType(odataType: unknown): string {
  switch (odataType) {
    case "#microsoft.graph.user":
      return "User";
    case "#microsoft.graph.servicePrincipal":
      return "ServicePrincipal";
    case "#microsoft.graph.group":
      return "Group";
    default:
      return psStr(odataType);
  }
}

export const runAdminRoleReport: SectionImplementation = async (ctx) => {
  const rolesResponse = await ctx.transport.getJson(
    ADMIN_ROLE_REPORT_ENDPOINTS.directoryRoles,
    { requiredRole: "RoleManagement.Read.Directory" },
  );
  const allRoles = asArray(rolesResponse.value);

  const assignments: AssignmentRecord[] = [];
  for (const role of allRoles) {
    let members: Record<string, unknown>[];
    try {
      const membersResponse = await ctx.transport.getJson(
        `/v1.0/directoryRoles/${encodeURIComponent(psStr(role.id))}/members`,
        { requiredRole: "RoleManagement.Read.Directory" },
      );
      members = asArray(membersResponse.value);
    } catch {
      // Skip this role only (PS Write-Warning + continue).
      continue;
    }

    if (members.length === 0) continue;

    for (const member of members) {
      const memberType = friendlyMemberType(member["@odata.type"]);
      const memberId = member.id;

      // User-only property fetched via targeted call; blank for SPs/groups
      // (Get-AdminRoleReport.ps1:82-93).
      let onPremSync = "";
      if (memberType === "User") {
        try {
          const userDetail = await ctx.transport.getJson(
            `/v1.0/users/${encodeURIComponent(psStr(memberId))}?$select=onPremisesSyncEnabled`,
            { requiredRole: "User.Read.All" },
          );
          // PS parity: -eq $true → 'True', everything else → 'False'.
          onPremSync = userDetail.onPremisesSyncEnabled === true ? "True" : "False";
        } catch {
          // Leave blank (PS Write-Verbose + blank parity).
        }
      }

      assignments.push({
        roleName: psStr(role.displayName),
        roleId: role.id,
        memberDisplayName: member.displayName,
        memberUpn: member.userPrincipalName,
        memberType,
        memberId,
        onPremisesSyncEnabled: onPremSync,
      });
    }
  }

  // Sort by RoleName, MemberDisplayName (PS Sort-Object, line 107).
  assignments.sort((a, b) => {
    const ra = a.roleName < b.roleName ? -1 : a.roleName > b.roleName ? 1 : 0;
    if (ra !== 0) return ra;
    const da = psStr(a.memberDisplayName);
    const dbb = psStr(b.memberDisplayName);
    return da < dbb ? -1 : da > dbb ? 1 : 0;
  });

  for (const a of assignments) {
    ctx.addRow({
      category: CATEGORY,
      setting: a.roleName,
      currentValue: kv([
        ["RoleId", a.roleId],
        ["MemberDisplayName", a.memberDisplayName],
        ["MemberUPN", a.memberUpn],
        ["MemberType", a.memberType],
        ["MemberId", a.memberId],
        ["OnPremisesSyncEnabled", a.onPremisesSyncEnabled],
      ]),
      recommendedValue: "",
      psStatus: "Info",
    });
  }
};
