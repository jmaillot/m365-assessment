/**
 * Port of `src/M365-Assess/Entra/Get-EntraCaRemoteDevicePolicy.ps1` (141 lines)
 * — AssessmentMaps Identity entry '07i-Entra-CaRemoteDevice' (plan 02-06 task 2).
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport:
 *   owned by the runner's addRow pipeline.
 * - Invoke-MgGraphRequest GET /v1.0/identity/conditionalAccess/policies
 *   (PS lines 48-53) → ONE ctx.transport.getJson call declaring Policy.Read.All.
 * - Selection loop (PS lines 61-81) ported branch-by-branch: disabled skipped;
 *   missing grantControls skipped; compliantDevice required; non-empty
 *   excludeLocations required; first enabled match wins (break); report-only
 *   kept as fallback when no enabled match exists.
 * - Catch branch (PS lines 120-136): 403-family → Review row; else
 *   Write-Warning + zero rows. TransportFatalError propagates.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const ENTRA_CA_REMOTE_DEVICE_ENDPOINTS = {
  caPolicies: "/v1.0/identity/conditionalAccess/policies",
} as const;

const CATEGORY = "Remote Access";
const SETTING = "CA Policy: Compliant Device Required for Remote Access";
const RECOMMENDED =
  "Enabled CA policy requiring compliantDevice grant with at least one named location excluded";
const CHECK_ID = "CA-REMOTEDEVICE-001";
/** PS catch matcher, Get-EntraCaRemoteDevicePolicy.ps1:121. */
const AUTHORIZATION_ERROR = /403|Forbidden|Authorization/;

export const runEntraCaRemoteDevice: SectionImplementation = async (ctx) => {
  try {
    const caResponse = await ctx.transport.getJson(
      ENTRA_CA_REMOTE_DEVICE_ENDPOINTS.caPolicies,
      { requiredRole: "Policy.Read.All" },
    );
    const policies = asArray(caResponse.value);

    let passPolicy: Record<string, unknown> | null = null;
    let warnPolicy: Record<string, unknown> | null = null;

    for (const policy of policies) {
      const state = policy.state;
      if (state === "disabled") continue;

      const grantControls = policy.grantControls as Record<string, unknown> | undefined;
      if (!grantControls) continue;
      const builtIn = Array.isArray(grantControls.builtInControls)
        ? (grantControls.builtInControls as unknown[])
        : [];
      if (!builtIn.includes("compliantDevice")) continue;

      const conditions = policy.conditions as Record<string, unknown> | undefined;
      const locations = conditions?.locations as Record<string, unknown> | undefined;
      const excludeLocations = Array.isArray(locations?.excludeLocations)
        ? (locations.excludeLocations as unknown[])
        : [];
      if (excludeLocations.length === 0) continue;

      if (state === "enabled") {
        passPolicy = policy;
        break;
      }
      if (state === "enabledForReportingButNotEnforced" && !warnPolicy) {
        warnPolicy = policy;
      }
    }

    if (passPolicy) {
      // PS lines 83-94.
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: `Enabled: '${psStr(passPolicy.displayName)}' requires compliantDevice with named location exclusion`,
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Verify the CA policy is scoped to all users and targets remote access scenarios.",
        psStatus: "Pass",
      });
    } else if (warnPolicy) {
      // PS lines 95-106.
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: `Report-only: '${psStr(warnPolicy.displayName)}' - not enforced`,
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Change the CA policy state from report-only to enabled to enforce compliant device requirements.",
        psStatus: "Warning",
      });
    } else {
      // PS lines 107-118.
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue:
          "No CA policy found requiring compliantDevice with a named location exclusion",
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Create a Conditional Access policy that requires device compliance (compliantDevice) and excludes a named corporate network location to enforce remote access controls.",
        psStatus: "Fail",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      // PS lines 121-132 — Review row with catch-branch strings verbatim.
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: "Insufficient permissions (Policy.Read.All required)",
        recommendedValue: RECOMMENDED,
        checkId: CHECK_ID,
        remediation:
          "Requires Policy.Read.All permission and Entra ID P1 or P2 license.",
        psStatus: "Review",
      });
      return;
    }
    // PS line 134 Write-Warning parity — zero rows, run continues.
    return;
  }
};
