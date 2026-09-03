/**
 * Port of `src/M365-Assess/Entra/Get-PasswordPolicyReport.ps1` (96 lines)
 * — AssessmentMaps Identity entry '07-Password-Policy' (plan 02-06 task 1).
 *
 * PS → TS mapping:
 * - Assert-GraphConnection / Import-Module: owned by the runner/transport.
 * - Get-MgDomain -All (PS line 44) → GET /v1.0/domains; failure = PS
 *   Write-Error + return (lines 42-49) → the fetch throws and the runner
 *   surfaces a section error with zero fabricated rows.
 * - Get-MgPolicyAuthorizationPolicy (PS line 54) → GET
 *   /v1.0/policies/authorizationPolicy; failure likewise throws (PS lines 52-59).
 * - Authorization-policy extraction (PS lines 64-73): defaults $false, then
 *   overwritten with the RAW policy values when a policy object exists —
 *   a null Graph property renders '' in CSV, so psStr(null)='' parity holds.
 *
 * Row mapping (report collector — no Add-SecuritySetting source): one Info row
 * per domain, sorted by Domain (PS line 86); Setting = domain id;
 * CurrentValue = report record Field=Value in PS property order (PS lines 76-83).
 * No CheckIds exist for this report → checkId omitted and remediation empty
 * (D-22 not applicable).
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { asArray, kv, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const PASSWORD_POLICY_ENDPOINTS = {
  domains: "/v1.0/domains",
  authorizationPolicy: "/v1.0/policies/authorizationPolicy",
} as const;

const CATEGORY = "Password Policy";

export const runPasswordPolicyReport: SectionImplementation = async (ctx) => {
  const domains = await ctx.transport.getJson(PASSWORD_POLICY_ENDPOINTS.domains, {
    requiredRole: "Domain.Read.All",
  });
  const authPolicy = await ctx.transport.getJson(
    PASSWORD_POLICY_ENDPOINTS.authorizationPolicy,
    { requiredRole: "Policy.Read.All" },
  );

  // PS lines 65-73 — raw-value assignment inside `if ($authPolicy)`.
  let allowCloudPasswordValidation: unknown = false;
  let allowEmailVerifiedJoin: unknown = false;
  if (authPolicy) {
    allowEmailVerifiedJoin = authPolicy.allowEmailVerifiedUsersToJoinOrganization;
    allowCloudPasswordValidation = authPolicy.allowedToUseSSPR;
  }

  // PS line 86: Sort-Object -Property Domain.
  const sortedDomains = [...asArray(domains.value)].sort((a, b) => {
    const ka = psStr(a.id);
    const kb = psStr(b.id);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  for (const domain of sortedDomains) {
    ctx.addRow({
      category: CATEGORY,
      setting: psStr(domain.id),
      currentValue: kv([
        ["Domain", domain.id],
        ["IsDefault", domain.isDefault],
        ["PasswordValidityPeriod", domain.passwordValidityPeriodInDays],
        ["PasswordNotificationWindowInDays", domain.passwordNotificationWindowInDays],
        ["AllowCloudPasswordValidation", allowCloudPasswordValidation],
        ["AllowEmailVerifiedUsersToJoinOrganization", allowEmailVerifiedJoin],
      ]),
      recommendedValue: "",
      psStatus: "Info",
    });
  }
};
