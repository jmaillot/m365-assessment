/**
 * Port of `src/M365-Assess/Entra/Get-EntraTouConfig.ps1` (101 lines)
 * — AssessmentMaps Identity entry '07f-Entra-ToU-Config' (plan 02-06 task 1).
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport:
 *   owned by the runner's addRow pipeline (mapStatus → sub-numbering → D-22).
 * - Invoke-MgGraphRequest GET /v1.0/agreements (PS lines 46-51) → ONE
 *   ctx.transport.getJson call declaring Agreement.Read.All.
 * - Catch branch (PS lines 80-96): 403-family errors emit the Review
 *   'Insufficient permissions' row verbatim; ANY other error is PS
 *   Write-Warning + zero rows — degraded here to a silent return, never a
 *   section error. TransportFatalError (structural violations: non-GET,
 *   ungranted role) still propagates — soft-fail applies to Graph failures,
 *   never to guard breaches.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const ENTRA_TOU_ENDPOINTS = {
  agreements: "/v1.0/agreements",
} as const;

const CATEGORY = "Terms of Use";
const SETTING = "Terms of Use Agreement Policy";
const CHECK_ID = "ENTRA-TOU-001";
/** PS catch matcher, Get-EntraTouConfig.ps1:81. */
const AUTHORIZATION_ERROR = /403|Forbidden|Authorization/;

export const runEntraTouConfig: SectionImplementation = async (ctx) => {
  let agreementList: Record<string, unknown>[];
  try {
    const agreements = await ctx.transport.getJson(ENTRA_TOU_ENDPOINTS.agreements, {
      requiredRole: "Agreement.Read.All",
    });
    agreementList = asArray(agreements.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      // PS lines 81-92 — Review row with the catch-branch strings verbatim.
      ctx.addRow({
        category: CATEGORY,
        setting: SETTING,
        currentValue: "Insufficient permissions",
        recommendedValue:
          "At least one Terms of Use agreement configured and assigned",
        checkId: CHECK_ID,
        remediation: "Requires Agreement.Read.All permission.",
        psStatus: "Review",
      });
      return;
    }
    // PS line 94 Write-Warning parity — zero rows, run continues.
    return;
  }

  // PS lines 58-67 decision ladder.
  const agreementCount = agreementList.length;
  const activeCount = agreementList.filter(
    (a) => a.isViewingBeforeAcceptanceRequired === true,
  ).length;

  const status =
    activeCount > 0 ? "Pass" : agreementCount > 0 ? "Warning" : "Fail";

  const currentValue =
    status === "Pass"
      ? `${activeCount} agreement(s) with acceptance required before viewing`
      : status === "Warning"
        ? "Agreement exists but acceptance not required before viewing"
        : "No agreements configured";

  ctx.addRow({
    category: CATEGORY,
    setting: SETTING,
    currentValue,
    recommendedValue:
      "At least one Terms of Use agreement with isViewingBeforeAcceptanceRequired = true",
    checkId: CHECK_ID,
    remediation:
      'Entra admin center > Identity Governance > Terms of use. Verify agreements have "Require users to expand the terms of use" enabled and are assigned via Conditional Access policies.',
    psStatus: status,
  });
};
