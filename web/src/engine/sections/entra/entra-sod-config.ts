/**
 * Port of `src/M365-Assess/Entra/Get-EntraSoDConfig.ps1` (127 lines)
 * — AssessmentMaps Identity entry '07e-Entra-SoD-Config' (plan 02-06 task 1).
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport:
 *   owned by the runner's addRow pipeline.
 * - Two roleAssignments fetches with $expand=principal (PS lines 52-77) → two
 *   ctx.transport.getJson calls declaring RoleManagement.Read.Directory.
 *   ($expand is carried verbatim even though only principalId — present on the
 *   assignment itself — is consumed, matching PS exactly.)
 * - Sort-Object -Unique over principalIds (PS lines 80-81) → dedupe + sort.
 * - Catch branch (PS lines 106-122): 403-family → Review row; else
 *   Write-Warning + zero rows. TransportFatalError propagates (guard breaches
 *   are never soft-failed).
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psSort, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const ENTRA_SOD_ENDPOINTS = {
  globalAdminAssignments:
    "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27&$top=999&$expand=principal",
  privRoleAdminAssignments:
    "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%27e8611ab8-c189-46e8-94e1-60213ab1f814%27&$top=999&$expand=principal",
} as const;

const CATEGORY = "Separation of Duties";
const SETTING = "Critical Role Separation (Global Admin vs Privileged Role Admin)";
const RECOMMENDED = "At least 2 Global Admins, no user holding both roles";
const CHECK_ID = "ENTRA-SOD-001";
/** PS catch matcher, Get-EntraSoDConfig.ps1:107. */
const AUTHORIZATION_ERROR = /403|Forbidden|Authorization/;

/** Unique + sorted principal ids (PS Sort-Object -Unique parity, lines 80-81). */
function uniqueSortedPrincipals(assignments: Record<string, unknown>[]): string[] {
  return psSort([
    ...new Set(
      assignments
        .map((a) => a.principalId)
        .filter((id): id is string => typeof id === "string"),
    ),
  ]);
}

export const runEntraSodConfig: SectionImplementation = async (ctx) => {
  try {
    const gaResponse = await ctx.transport.getJson(
      ENTRA_SOD_ENDPOINTS.globalAdminAssignments,
      { requiredRole: "RoleManagement.Read.Directory" },
    );
    const praResponse = await ctx.transport.getJson(
      ENTRA_SOD_ENDPOINTS.privRoleAdminAssignments,
      { requiredRole: "RoleManagement.Read.Directory" },
    );

    const gaPrincipals = uniqueSortedPrincipals(asArray(gaResponse.value));
    const praPrincipals = uniqueSortedPrincipals(asArray(praResponse.value));

    // PS line 84: overlap = principals holding BOTH roles.
    const overlap = gaPrincipals.filter((id) => praPrincipals.includes(id));

    const gaCount = gaPrincipals.length;
    const praCount = praPrincipals.length;
    const overlapCount = overlap.length;

    // PS line 91 pass criteria, verbatim thresholds.
    const separated = gaCount >= 2 && praCount >= 1 && overlapCount === 0;

    ctx.addRow({
      category: CATEGORY,
      setting: SETTING,
      currentValue: `Global Admins: ${gaCount}, Priv Role Admins: ${praCount}, Overlap: ${overlapCount}`,
      recommendedValue: RECOMMENDED,
      checkId: CHECK_ID,
      remediation:
        "Ensure Global Administrator and Privileged Role Administrator roles are assigned to separate accounts. Entra admin center > Identity > Roles & admins. Enable PIM approval workflows for role activation.",
      psStatus: separated ? "Pass" : "Fail",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      // PS lines 107-118 — Review row with catch-branch strings verbatim.
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: "Insufficient permissions",
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Requires RoleManagement.Read.Directory and Directory.Read.All permissions.",
        psStatus: "Review",
      });
      return;
    }
    // PS line 120 Write-Warning parity — zero rows, run continues.
    return;
  }
};
