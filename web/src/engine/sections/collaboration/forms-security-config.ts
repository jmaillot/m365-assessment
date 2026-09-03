/**
 * Port of `src/M365-Assess/Collaboration/Get-FormsSecurityConfig.ps1`
 * (191 lines, 6 checks CIS 3.6.x).
 *
 * PS → TS mapping:
 * - Original PS uses Graph /beta/admin/forms/settings (OrgSettings-Forms.Read.All)
 *   — no v1.0 promotion (BETA-ENDPOINTS.md; #941 sovereign BadRequest).
 *   Tenant sharing controls under /beta/admin/forms are not served on v1.0
 *   today, so the SaaS cannot assert them via Direct evidence.
 * - Therefore this collector emits Skipped(not_implemented) for the Forms CIS
 *   surface with explicit remediation pointing to M365 admin center manual
 *   verification — parity with Collab gap-pattern (PS Write-Warning →
 *   Skipped handling at lines 147-181). A best-effort v1.0 probe is attempted
 *   first; on v1.0 success (future promotion) we would parse the payload,
 *   but until then the catch → Skipped path is exercised. This avoids
 *   silent omission (D-10) while keeping typecheck green and no /beta path.
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport are
 *   owned by the runner's addRow pipeline.
 * - No /beta paths — v1.0 probe only, fail-soft.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { errMatches, psStr } from "./shared";

/**
 * v1.0 probe path for Forms settings. As of 2026 the Forms admin surface
 * remains beta-only; this v1 probe is expected to 404 and degrade to
 * Skipped — the Skipped rows below document the gap explicitly so the
 * report surfaces the coverage note rather than hiding it.
 */
export const FORMS_SECURITY_CONFIG_ENDPOINTS = {
  settings: "/v1.0/admin/forms/settings",
} as const;

const REQUIRED_ROLE = "OrgSettings-Forms.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

function emitFormsSkipped(ctx: Parameters<SectionImplementation>[0], reason: string) {
  for (const { checkId, setting, recommendedValue } of [
    { checkId: "FORMS-CONFIG-001", setting: "External Users Can Respond to Forms", recommendedValue: "False" },
    { checkId: "FORMS-CONFIG-002", setting: "External Users Can Collaborate on Forms", recommendedValue: "False" },
    { checkId: "FORMS-CONFIG-004", setting: "Phishing Protection", recommendedValue: "True" },
    { checkId: "FORMS-CONFIG-005", setting: "Record Respondent Identity by Default", recommendedValue: "True" },
  ] as const) {
    ctx.addRow({
      category: "External Sharing",
      setting,
      currentValue: reason,
      recommendedValue,
      checkId,
      remediation: "",
      psStatus: "Skipped",
      evidenceSource: FORMS_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
}

export const runFormsSecurityConfig: SectionImplementation = async (ctx) => {
  try {
    const resp = (await ctx.transport.getJson(
      FORMS_SECURITY_CONFIG_ENDPOINTS.settings,
      { requiredRole: REQUIRED_ROLE },
    )) as Record<string, unknown>;

    // If future promotion lands and v1 returns a payload, parse the 4 primary
    // checks (CIS 3.6.1/3.6.2 parity) directly from the response.
    const externalSend = resp.isExternalSendFormEnabled as boolean | undefined;
    if (externalSend !== undefined) {
      ctx.addRow({
        category: "External Sharing",
        setting: "External Users Can Respond to Forms",
        currentValue: psStr(externalSend),
        recommendedValue: "False",
        checkId: "FORMS-CONFIG-001",
        remediation: "",
        psStatus: externalSend === false ? "Pass" : "Fail",
        evidenceSource: FORMS_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    } else {
      emitFormsSkipped(ctx, "Not available via Graph v1.0 — verify in M365 admin center > Settings > Org settings > Microsoft Forms");
      return;
    }

    const externalCollab = resp.isExternalShareCollaborationEnabled as boolean | undefined;
    ctx.addRow({
      category: "External Sharing",
      setting: "External Users Can Collaborate on Forms",
      currentValue: psStr(externalCollab),
      recommendedValue: "False",
      checkId: "FORMS-CONFIG-002",
      remediation: "",
      psStatus: externalCollab === false ? "Pass" : "Fail",
      evidenceSource: FORMS_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });

    const phishing = resp.isPhishingScanEnabled as boolean | undefined;
    ctx.addRow({
      category: "Security",
      setting: "Phishing Protection",
      currentValue: psStr(phishing),
      recommendedValue: "True",
      checkId: "FORMS-CONFIG-004",
      remediation: "",
      psStatus: phishing === true ? "Pass" : "Fail",
      evidenceSource: FORMS_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });

    const recordIdentity = resp.isRecordIdentityByDefaultEnabled as boolean | undefined;
    ctx.addRow({
      category: "Security",
      setting: "Record Respondent Identity by Default",
      currentValue: psStr(recordIdentity),
      recommendedValue: "True",
      checkId: "FORMS-CONFIG-005",
      remediation: "",
      psStatus: recordIdentity === true ? "Pass" : "Review",
      evidenceSource: FORMS_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 0.9,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, /400|BadRequest|MissingProvider/i)) {
      for (const { checkId, setting, recommendedValue } of [
        { checkId: "FORMS-CONFIG-001", setting: "External Users Can Respond to Forms", recommendedValue: "False" },
        { checkId: "FORMS-CONFIG-002", setting: "External Users Can Collaborate on Forms", recommendedValue: "False" },
        { checkId: "FORMS-CONFIG-004", setting: "Phishing Protection", recommendedValue: "True" },
        { checkId: "FORMS-CONFIG-005", setting: "Record Respondent Identity by Default", recommendedValue: "True" },
      ] as const) {
        ctx.addRow({
          category: "External Sharing",
          setting,
          currentValue: "Not available in sovereign cloud (USGov/USGovDoD) — verify in M365 admin center > Settings > Org settings > Microsoft Forms (400 BadRequest)",
          recommendedValue,
          checkId,
          remediation: "M365 admin center > Settings > Org settings > Microsoft Forms — verify external sharing and phishing protection manually (Graph returns 400 BadRequest in sovereign clouds #941)",
          psStatus: "Review",
          evidenceSource: FORMS_SECURITY_CONFIG_ENDPOINTS.settings,
          collectionMethod: "Direct",
          permissionRequired: REQUIRED_ROLE,
        });
      }
      return;
    }
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      emitFormsSkipped(ctx, "Insufficient permissions");
      return;
    }
    // Any other GraphError (404 or missing v1 promotion) → Skipped(not_implemented) with manual-verification note.
    emitFormsSkipped(
      ctx,
      "Not available via Graph v1.0 — verify in M365 admin center > Settings > Org settings > Microsoft Forms",
    );
  }
};
