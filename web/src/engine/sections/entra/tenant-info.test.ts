/**
 * Parity tests for the Get-TenantInfo.ps1 port (plan 02-05 task 1).
 *
 * PS Graph call sites being proven (documented per acceptance criteria):
 *   1. Get-MgOrganization            → GET /v1.0/organization
 *   2. Get-MgDomain                  → GET /v1.0/domains
 *   3. Invoke-MgGraphRequest probe   → GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy
 * The TS port must have ≥3 ctx.transport.getJson sites (see tenant-info.ts).
 *
 * Golden rows were traced from Get-TenantInfo.ps1 logic over these exact
 * fixtures (pwsh unavailable in this environment — regenerate via
 * scripts/Build-DualRunFixture.ps1 once a report-collector capture mode and
 * pwsh are available; see 02-05-SUMMARY.md).
 */
import { describe, expect, it } from "vitest";
import { runTenantInfo } from "./tenant-info";
import { normalizeUrlKey } from "@/engine/__fixtures__/replay";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

const SECURITY_DEFAULTS_KEY =
  "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy";

describe("runTenantInfo", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const fixtures: Record<string, unknown> = {
      "/v1.0/organization": readFixtureJson("tenant-info/v1.0_organization.json"),
      "/v1.0/domains": readFixtureJson("tenant-info/v1.0_domains.json"),
      [SECURITY_DEFAULTS_KEY]: readFixtureJson(
        "tenant-info/v1.0_policies_identitySecurityDefaultsEnforcementPolicy.json",
      ),
    };

    const { rows, sectionError } = await runCollectorOverFixtures(
      "tenant",
      runTenantInfo,
      fixtures,
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/tenant-info.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("routes every Graph call through the transport (zero direct fetch)", async () => {
    const { graphUrls } = await runCollectorOverFixtures("tenant", runTenantInfo, {
      "/v1.0/organization": { value: [] },
      "/v1.0/domains": { value: [] },
      [SECURITY_DEFAULTS_KEY]: { isEnabled: false },
    });
    // Transport events carry absolute URLs; compare as path+query keys.
    expect(graphUrls.map((u) => normalizeUrlKey(u))).toEqual([
      "/v1.0/organization",
      "/v1.0/domains",
      SECURITY_DEFAULTS_KEY,
    ]);
  });

  it("degrades SecurityDefaultsEnabled to N/A when the soft-fail probe errors (PS lines 61-71 parity)", async () => {
    // Security-defaults fixture deliberately absent → replay serves a failing
    // 404-style response; the collector must catch and continue with N/A.
    const { rows, sectionError } = await runCollectorOverFixtures(
      "tenant",
      runTenantInfo,
      {
        "/v1.0/organization": {
          value: [
            {
              id: "org-1",
              displayName: "Solo Org",
              createdDateTime: null,
              onPremisesSyncEnabled: null,
              onPremisesLastSyncDateTime: null,
              onPremisesLastPasswordSyncDateTime: null,
              onPremisesProvisioningErrors: null,
            },
          ],
        },
        "/v1.0/domains": { value: [] },
      },
    );
    expect(sectionError).toBeUndefined();
    expect(rows).toEqual([
      {
        category: "Tenant Info",
        setting: "Solo Org",
        currentValue:
          "OrgDisplayName=Solo Org; TenantId=org-1; VerifiedDomains=; " +
          "DefaultDomain=; SecurityDefaultsEnabled=N/A; CreatedDateTime=; " +
          "OnPremisesSyncEnabled=; OnPremisesLastSyncDateTime=; " +
          "OnPremisesLastPasswordSyncDateTime=; OnPremisesProvisioningErrorCount=0",
        recommendedValue: "",
        status: "Info",
        checkId: "",
        remediation: "",
        intentDesign: false,
      },
    ]);
  });

  it("surfaces a section error when organization retrieval fails (PS Write-Error + return parity)", async () => {
    // /v1.0/organization fixture missing → replay 404-style failure.
    const { rows, sectionError } = await runCollectorOverFixtures(
      "tenant",
      runTenantInfo,
      { "/v1.0/domains": { value: [] } },
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeDefined();
  });
});
