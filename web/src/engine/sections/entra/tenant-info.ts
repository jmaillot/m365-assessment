/**
 * Port of `src/M365-Assess/Entra/Get-TenantInfo.ps1` (110 lines) — the
 * PATTERNS "Analog B" small-collector template (plan 02-05 task 1).
 *
 * PS → TS mapping:
 * - Assert-GraphConnection: owned by the runner/transport — not repeated here.
 * - Get-MgOrganization / Get-MgDomain / Invoke-MgGraphRequest security-defaults
 *   probe (3 PS Graph call sites) → exactly 3 ctx.transport.getJson sites
 *   below, each declaring its required app role.
 * - Organization/domain retrieval failure = PS Write-Error + return
 *   (Get-TenantInfo.ps1:42-59) → the fetch throws and the runner surfaces a
 *   section error with zero fabricated rows.
 * - Security-defaults probe is SOFT-FAIL (PS lines 61-71): caught here,
 *   degrades to 'N/A'.
 *
 * Report-record → CheckRow mapping (this collector emits report objects, NOT
 * Add-SecuritySetting rows — there are no PS Category/Setting strings to
 * copy): one Info row per organization; Setting = org display name;
 * CurrentValue = the full report record shaped Field=Value in PS property
 * order, exactly as Export-Csv would render it. psStatus 'Info' per D-23
 * (inventory facts). No CheckIds exist for this report → checkId omitted
 * (passes through unsub-numbered) and remediation stays empty (no registry
 * entry to fall back on — D-22 not applicable).
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { asArray, kv, psStr, semiJoinSorted } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const TENANT_INFO_ENDPOINTS = {
  organization: "/v1.0/organization",
  domains: "/v1.0/domains",
  securityDefaults: "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
} as const;

const CATEGORY = "Tenant Info";

export const runTenantInfo: SectionImplementation = async (ctx) => {
  const organization = await ctx.transport.getJson(TENANT_INFO_ENDPOINTS.organization, {
    requiredRole: "Organization.Read.All",
  });
  const domains = await ctx.transport.getJson(TENANT_INFO_ENDPOINTS.domains, {
    requiredRole: "Domain.Read.All",
  });

  // Soft-fail probe (Get-TenantInfo.ps1:61-71) — never fatal.
  let securityDefaultsEnabled: unknown;
  try {
    const policy = await ctx.transport.getJson(
      TENANT_INFO_ENDPOINTS.securityDefaults,
      { requiredRole: "Policy.Read.All" },
    );
    securityDefaultsEnabled = policy.isEnabled;
  } catch {
    securityDefaultsEnabled = "N/A";
  }

  const domainList = asArray(domains.value);
  const verifiedDomainsJoined = semiJoinSorted(
    domainList
      .filter((d) => d.isVerified === true)
      .map((d) => psStr(d.id)),
  );
  const defaultDomain = psStr(domainList.find((d) => d.isDefault === true)?.id);

  // Handle multiple organizations (typically just one) — Get-TenantInfo.ps1:84.
  for (const org of asArray(organization.value)) {
    const provisioningErrors = org.onPremisesProvisioningErrors;
    const provisioningErrorCount = Array.isArray(provisioningErrors)
      ? provisioningErrors.length
      : 0;

    ctx.addRow({
      category: CATEGORY,
      setting: psStr(org.displayName),
      currentValue: kv([
        ["OrgDisplayName", org.displayName],
        ["TenantId", org.id],
        ["VerifiedDomains", verifiedDomainsJoined],
        ["DefaultDomain", defaultDomain],
        ["SecurityDefaultsEnabled", securityDefaultsEnabled],
        ["CreatedDateTime", org.createdDateTime],
        ["OnPremisesSyncEnabled", org.onPremisesSyncEnabled],
        ["OnPremisesLastSyncDateTime", org.onPremisesLastSyncDateTime],
        ["OnPremisesLastPasswordSyncDateTime", org.onPremisesLastPasswordSyncDateTime],
        ["OnPremisesProvisioningErrorCount", provisioningErrorCount],
      ]),
      recommendedValue: "",
      psStatus: "Info",
    });
  }
};
