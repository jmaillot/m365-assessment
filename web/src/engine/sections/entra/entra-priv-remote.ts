/**
 * Port of `src/M365-Assess/Entra/Get-EntraPrivRemoteConfig.ps1` (146 lines)
 * — AssessmentMaps Identity entry '07g-Entra-PrivRemote' (plan 02-06 task 2).
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport:
 *   owned by the runner's addRow pipeline.
 * - Permanent assignments (PS lines 57-62): GET /v1.0/roleManagement/directory/
 *   roleAssignments?$filter=roleDefinitionId eq '<GlobalAdminRoleId>'.
 * - PIM eligible assignments (PS lines 72-88): GET /v1.0/roleManagement/
 *   directory/roleEligibilityScheduleInstances?$filter=… — SOFT-FAIL: any
 *   Graph failure sets eligibleNote ('PIM eligible assignments not available
 *   (requires Entra ID P2)') and forces Review status, never fatal. This is
 *   the v1.0 surface — the /beta/.../roleAssignmentScheduleInstances entry on
 *   BETA-ENDPOINTS.md is NOT used by this collector (no beta call sites here).
 * - Status ladder (PS lines 101-112): note → Review; pimInUse && permanent ≤ 2
 *   → Pass; pimInUse → Warning; else Fail.
 * - Catch branch (PS lines 125-141): 403-family → Review row; else
 *   Write-Warning + zero rows. TransportFatalError propagates.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const ENTRA_PRIV_REMOTE_ENDPOINTS = {
  globalAdminAssignments:
    "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27",
  globalAdminEligibleInstances:
    "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27",
} as const;

const CATEGORY = "Privileged Remote Access";
const SETTING = "PIM Required for Global Admin Activation";
const RECOMMENDED = "PIM enabled with eligible assignments; max 2 permanent (break-glass)";
const CHECK_ID = "ENTRA-PRIVREMOTE-001";
/** PS catch matcher, Get-EntraPrivRemoteConfig.ps1:126. */
const AUTHORIZATION_ERROR = /403|Forbidden|Authorization/;
/** Verbatim PS degradation note (line 86). */
const ELIGIBLE_NOTE = "PIM eligible assignments not available (requires Entra ID P2)";

export const runEntraPrivRemote: SectionImplementation = async (ctx) => {
  try {
    // Permanent (standing) assignments — PS lines 53-67.
    const activeResponse = await ctx.transport.getJson(
      ENTRA_PRIV_REMOTE_ENDPOINTS.globalAdminAssignments,
      { requiredRole: "RoleManagement.Read.Directory" },
    );
    const permanentCount = activeResponse.value
      ? asArray(activeResponse.value).length
      : 0;

    // Eligible (PIM) assignments — soft-fail inner try, PS lines 69-88.
    let eligibleCount = 0;
    let eligibleNote: string | null = null;
    try {
      const eligibleResponse = await ctx.transport.getJson(
        ENTRA_PRIV_REMOTE_ENDPOINTS.globalAdminEligibleInstances,
        { requiredRole: "RoleManagement.Read.Directory" },
      );
      if (eligibleResponse.value) {
        eligibleCount = asArray(eligibleResponse.value).length;
      }
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      eligibleNote = ELIGIBLE_NOTE;
    }

    const pimInUse = eligibleCount > 0;
    const currentValue =
      eligibleNote !== null
        ? `Permanent: ${permanentCount}, Eligible (PIM): ${eligibleNote}`
        : `Permanent: ${permanentCount}, Eligible (PIM): ${eligibleCount}`;

    // PS line 99: PIM in use and permanent assignments minimal (break-glass).
    const passCondition = pimInUse && permanentCount <= 2;

    const status =
      eligibleNote !== null
        ? "Review"
        : passCondition
          ? "Pass"
          : pimInUse
            ? "Warning"
            : "Fail";

    ctx.addRow({
      category: CATEGORY,
      setting: SETTING,
      currentValue,
      recommendedValue: RECOMMENDED,
      checkId: CHECK_ID,
      remediation:
        "Enable Entra ID PIM. Convert permanent role assignments to eligible. Configure activation to require justification and MFA. Entra admin center > Identity Governance > Privileged Identity Management > Entra ID roles.",
      psStatus: status,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      // PS lines 126-137 — Review row with catch-branch strings verbatim.
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: "Insufficient permissions",
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Requires RoleManagement.Read.Directory permission. Entra ID P2 license required for PIM.",
        psStatus: "Review",
      });
      return;
    }
    // PS line 139 Write-Warning parity — zero rows, run continues.
    return;
  }
};
