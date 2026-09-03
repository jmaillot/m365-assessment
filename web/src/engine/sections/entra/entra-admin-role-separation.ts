/**
 * Port of `src/M365-Assess/Entra/Get-EntraAdminRoleSeparationConfig.ps1`
 * (194 lines) — AssessmentMaps Identity entry '07h-Entra-AdminRoleSep'
 * (plan 02-06 task 2).
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport:
 *   owned by the runner's addRow pipeline.
 * - Five privileged role ids and two Exchange plan GUIDs verbatim (lines 48-60).
 * - Per-role assignment fetch (PS lines 68-92): 404-family failures SKIP the
 *   role ('not present in this tenant'), everything else rethrows. Principal
 *   ids collected into a case-insensitive insertion-ordered unique set
 *   (HashSet(StringComparer.OrdinalIgnoreCase) parity, line 66).
 * - Zero admins → Pass 'No privileged role assignments found' + return.
 * - Per-admin licenseDetails fetch (PS lines 114-142): 404-family skips the
 *   principal (deleted user / group-assigned role); any sku whose servicePlans
 *   include an Exchange plan id marks the account mixed → break.
 * - Outer catch (PS lines 165-189): broad authorization regex → Review row.
 *   The Write-Host permission-guidance block is console UX only — omitted
 *   (SaaS events carry no console output). Else Write-Warning + zero rows.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches } from "./shared";

const PRIVILEGED_ROLE_IDS = [
  "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
  "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
  "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
  "29232cdf-9323-42fd-aeaf-7d3bbd031fae", // Exchange Administrator
  "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
] as const;

/** Exchange Online service plan GUIDs (Plan 1 and Plan 2) — PS lines 57-60. */
const EXCHANGE_PLAN_IDS = new Set([
  "efb87545-963c-4e0d-99df-69c6916d9eb0",
  "19ec0d23-8335-4cbd-94ac-6050e30712fa",
]);

/** Declared GET path builders (mirrored into registry endpoints[] by plan 02-12). */
export const ENTRA_ADMIN_ROLE_SEPARATION_ENDPOINTS = {
  roleAssignments: (roleId: string) =>
    `/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%27${roleId}%27&$top=999`,
  userLicenseDetails: (userId: string) => `/v1.0/users/${userId}/licenseDetails`,
} as const;

const CATEGORY = "Admin Role Separation";
const SETTING = "Privileged Account vs Daily-Use Account Separation";
const RECOMMENDED = "Admin accounts must not have Exchange mailbox service plans";
const CHECK_ID = "ENTRA-ADMINROLE-SEPARATION-001";
/**
 * PS outer catch matcher, Get-EntraAdminRoleSeparationConfig.ps1:166 — broader
 * than the sibling collectors ('Ensure the required', Access_Denied, …).
 */
const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization|Ensure the required|service is connected|Access_Denied|Authorization_RequestDenied/;
/** PS inner catch matchers (lines 85, 126): missing role / non-user principal. */
const NOT_FOUND_ERROR = /404|ResourceNotFound|Not Found/;

export const runEntraAdminRoleSeparation: SectionImplementation = async (ctx) => {
  try {
    // Case-insensitive insertion-ordered unique set (PS HashSet parity, line 66).
    const seen = new Set<string>();
    const adminUserIds: string[] = [];

    for (const roleId of PRIVILEGED_ROLE_IDS) {
      let assignments: Record<string, unknown>[];
      try {
        const response = await ctx.transport.getJson(
          ENTRA_ADMIN_ROLE_SEPARATION_ENDPOINTS.roleAssignments(roleId),
          { requiredRole: "RoleManagement.Read.Directory" },
        );
        assignments = asArray(response.value);
      } catch (err) {
        if (err instanceof TransportFatalError) throw err;
        if (errMatches(err, NOT_FOUND_ERROR)) {
          continue; // Role not present in this tenant — skip (PS lines 84-91).
        }
        throw err;
      }
      for (const a of assignments) {
        const principalId = a.principalId;
        if (typeof principalId === "string" && principalId.length > 0) {
          const key = principalId.toLowerCase();
          if (!seen.has(key)) {
            seen.add(key);
            adminUserIds.push(principalId);
          }
        }
      }
    }

    if (adminUserIds.length === 0) {
      // PS lines 94-107.
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: "No privileged role assignments found",
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Assign at least one user to Global Administrator or other privileged roles.",
        psStatus: "Pass",
      });
      return;
    }

    // Per-admin Exchange plan check — PS lines 109-152.
    const mixedAccounts: string[] = [];

    for (const userId of adminUserIds) {
      let licDetails: Record<string, unknown>;
      try {
        licDetails = await ctx.transport.getJson(
          ENTRA_ADMIN_ROLE_SEPARATION_ENDPOINTS.userLicenseDetails(userId),
          { requiredRole: "Directory.Read.All" },
        );
      } catch (err) {
        if (err instanceof TransportFatalError) throw err;
        if (errMatches(err, NOT_FOUND_ERROR)) {
          continue; // Not a user object or no longer exists — PS lines 124-131.
        }
        throw err;
      }
      if (!licDetails || !licDetails.value) continue;

      for (const sku of asArray(licDetails.value)) {
        const plans = Array.isArray(sku.servicePlans)
          ? (sku.servicePlans as Record<string, unknown>[])
          : [];
        const hasExchange = plans.some(
          (p) =>
            typeof p.servicePlanId === "string" &&
            EXCHANGE_PLAN_IDS.has(p.servicePlanId),
        );
        if (hasExchange) {
          mixedAccounts.push(userId);
          break;
        }
      }
    }

    const adminCount = adminUserIds.length;
    if (mixedAccounts.length === 0) {
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: `Admin accounts checked: ${adminCount} — none have Exchange Online plans`,
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Create separate cloud-only admin accounts without Exchange Online licenses. Remove mailbox service plan assignments from privileged role accounts. Entra admin center > Users > select admin user > Licenses.",
        psStatus: "Pass",
      });
    } else {
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: `${mixedAccounts.length} of ${adminCount} admin account(s) have Exchange Online mailbox plans`,
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Create separate cloud-only admin accounts without Exchange Online licenses. Remove mailbox service plan assignments from privileged role accounts. Entra admin center > Users > select admin user > Licenses.",
        psStatus: "Fail",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      // PS lines 167-176 — Review row with catch-branch strings verbatim.
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: "Insufficient permissions",
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Requires RoleManagement.Read.Directory and Directory.Read.All permissions. Grant via Entra admin center or reconnect with additional scopes.",
        psStatus: "Review",
      });
      return;
    }
    // PS line 187 Write-Warning parity — zero rows, run continues.
    return;
  }
};
