/**
 * Parity tests for the EntraAdminRoleChecks.ps1 port (plan 02-08 task 1).
 *
 * PS Graph call sites being proven:
 *   1. GET /v1.0/policies/authorizationPolicy — shared $authPolicy read via the
 *      run store (Get-EntraSecurityConfig.ps1:61-72 soft-fail pre-fetch);
 *      standalone runs perform the same soft-fail fetch and store it.
 *   2. GET /v1.0/directoryRoles?$filter=displayName eq 'Global Administrator'
 *      + /v1.0/directoryRoles/{id}/members (PS section 2, ENTRA-ADMIN-001),
 *      with break-glass exclusion via EntraHelpers Get-BreakGlassAccounts.
 *   3. GET /v1.0/subscribedSkus — P2 license detection by service plan
 *      eec0eb4f-6444-4f95-aba0-50c24d67f998 (#881).
 *   4. GET /beta/roleManagement/directory/roleAssignmentScheduleInstances →
 *      promoted to v1.0 per BETA-ENDPOINTS.md (availability probe; result
 *      discarded exactly as in PS).
 *   5. GET /v1.0/directoryRoles(roleTemplateId='62e90394-…')/members +
 *      /beta/…/roleEligibilityScheduleInstances?$filter=roleDefinitionId eq
 *      '…' → v1.0 promotion (permanent-GA subtraction logic, #886).
 *   6. GET /v1.0/identityGovernance/accessReviews/definitions?$top=100 → v1.0
 *      promotion (CIS 5.3.2/5.3.3 guest + privileged-role reviews).
 *   7. GET /v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq
 *      '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '…'
 *      &$expand=policy($expand=rules) for GA/PRA approval checks (#978).
 *   8. GET /v1.0/directoryRoles/roleTemplateId=62e90394-…/members with three
 *      distinct $select projections (cloud-only, licenses, MFA strength).
 *   9. GET /v1.0/reports/authenticationMethods/userRegistrationDetails → v1.0
 *      per resolved BETA-ENDPOINTS.md rows (phishing-resistant MFA check).
 */
import { describe, expect, it } from "vitest";
import {
  ADMIN_ROLE_ENDPOINTS as EP,
  gaEligibilityInstancesUrl,
  gaMembersSelectIdsUrl,
  gaMembersSelectLicensesUrl,
  gaMembersSelectSyncUrl,
  praPolicyAssignmentsUrl,
  runAdminRoleChecks,
} from "./admin-role-checks";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";
import { createReplayFetch, normalizeUrlKey } from "@/engine/__fixtures__/replay";

type Fixtures = Record<string, unknown>;

const GA_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10";
const GA_ROLE_MEMBERS_URL =
  "/v1.0/directoryRoles(roleTemplateId='62e90394-69f5-4237-9190-012177145e10')/members";
const ELIGIBILITY_URL = `/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27`;
const GA_POLICY_ASSIGNMENTS_URL =
  `/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId%20eq%20%27/%27%20and%20scopeType%20eq%20%27DirectoryRole%27%20and%20roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27&$expand=policy($expand=rules)`;

function fileFixture(name: string): unknown {
  return readFixtureJson(`admin-role-checks/${name}.json`);
}

/** Full happy-path fixture set (matches golden/admin-role-checks.json). */
function baseFixtures(): Fixtures {
  const fixtures: Fixtures = {};
  fixtures[EP.authorizationPolicy] = fileFixture("v1.0_policies_authorizationPolicy");
  fixtures[EP.globalAdminRoleFilter] = fileFixture("v1.0_directoryRoles_filter-GA");
  fixtures["/v1.0/directoryRoles/role-1/members"] = fileFixture(
    "v1.0_directoryRoles_role-1_members",
  );
  fixtures[EP.subscribedSkus] = fileFixture("v1.0_subscribedSkus");
  fixtures[EP.roleAssignmentScheduleInstances] = fileFixture(
    "v1.0_roleManagement_directory_roleAssignmentScheduleInstances",
  );
  fixtures[GA_ROLE_MEMBERS_URL] = fileFixture(
    "v1.0_directoryRoles_roleTemplateId-GA_members",
  );
  fixtures[ELIGIBILITY_URL] = fileFixture(
    "v1.0_roleManagement_directory_roleEligibilityScheduleInstances_filter-GA",
  );
  fixtures[EP.accessReviews] = fileFixture(
    "v1.0_identityGovernance_accessReviews_definitions_top100",
  );
  fixtures[GA_POLICY_ASSIGNMENTS_URL] = fileFixture(
    "v1.0_policies_roleManagementPolicyAssignments_GA",
  );
  fixtures[praPolicyAssignmentsUrl()] = fileFixture(
    "v1.0_policies_roleManagementPolicyAssignments_PRA",
  );
  fixtures[gaMembersSelectSyncUrl()] = fileFixture(
    "v1.0_directoryRoles_roleTemplateId-GA_members_select-sync",
  );
  fixtures[gaMembersSelectLicensesUrl()] = fileFixture(
    "v1.0_directoryRoles_roleTemplateId-GA_members_select-licenses",
  );
  fixtures[gaMembersSelectIdsUrl()] = fileFixture(
    "v1.0_directoryRoles_roleTemplateId-GA_members_select-ids",
  );
  fixtures[EP.userRegistrationDetails] = fileFixture(
    "v1.0_reports_authenticationMethods_userRegistrationDetails",
  );
  return fixtures;
}

/** Replay wrapper that fails one specific URL key with a canned response. */
function replayExcept(
  failKey: string,
  status: number,
  body: unknown,
  fixtures: Fixtures,
): typeof fetch {
  const replay = createReplayFetch(fixtures);
  return async (input: string | URL | RequestInfo, init?: RequestInit) => {
    const raw =
      typeof input === "string" || input instanceof URL ? String(input) : input.url;
    if (normalizeUrlKey(raw) === failKey) {
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    }
    return replay(input as Parameters<typeof fetch>[0], init);
  };
}

describe("runAdminRoleChecks", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runAdminRoleChecks,
      baseFixtures(),
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/admin-role-checks.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("proves every declared Graph surface was called exactly once", async () => {
    const { graphUrls } = await runCollectorOverFixtures(
      "identity",
      runAdminRoleChecks,
      baseFixtures(),
    );

    const keys = graphUrls.map((u) => normalizeUrlKey(u));
    expect(keys.filter((k) => k === EP.roleAssignmentScheduleInstances)).toHaveLength(1);
    expect(keys.filter((k) => k === ELIGIBILITY_URL)).toHaveLength(1);
    expect(keys.filter((k) => k === EP.accessReviews)).toHaveLength(1);
    expect(keys.filter((k) => k === EP.userRegistrationDetails)).toHaveLength(1);
    // Three distinct $select projections of the GA role members.
    expect(keys.filter((k) => k.startsWith("/v1.0/directoryRoles/roleTemplateId="))).toHaveLength(3);
  });

  it("emits the PS 'Role not activated' Warning row when the GA directory role has no activation", async () => {
    const fixtures = baseFixtures();
    fixtures[EP.globalAdminRoleFilter] = { value: [] };
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runAdminRoleChecks,
      fixtures,
    );

    expect(rows[0]).toMatchObject({
      category: "Admin Accounts",
      setting: "Global Administrator Count",
      currentValue: "Role not activated",
      recommendedValue: "2-4",
      status: "Warning",
      checkId: "ENTRA-ADMIN-001.1",
    });
    // The role-members fetch (and only it) is skipped when unactivated.
    expect(rows.filter((r) => r.checkId.startsWith("ENTRA-CLOUDADMIN"))).toHaveLength(2);
  });

  it("degrades all PIM checks to Review rows when no AAD_PREMIUM_P2 service plan is licensed", async () => {
    const fixtures = baseFixtures();
    fixtures[EP.subscribedSkus] = {
      value: [
        {
          capabilityStatus: "Enabled",
          skuId: "c7df2760-2c81-4ef7-b578-5b5392b571df",
          servicePlans: [
            {
              servicePlanId: "43de0ff5-c92c-492b-9116-175376d08f38",
              provisioningStatus: "Success",
            },
          ],
        },
      ],
    };
    const { rows, graphUrls } = await runCollectorOverFixtures(
      "identity",
      runAdminRoleChecks,
      fixtures,
    );

    // No PIM API calls without a P2 license (PS lines 113-118).
    expect(graphUrls.map((u) => normalizeUrlKey(u))).not.toContain(
      EP.roleAssignmentScheduleInstances,
    );
    expect(graphUrls.map((u) => normalizeUrlKey(u))).not.toContain(ELIGIBILITY_URL);

    const pimRow = rows.find((r) => r.checkId.startsWith("ENTRA-PIM-001"));
    expect(pimRow).toMatchObject({
      // Eligibility instances are NEVER queried unlicensed, so every GA
      // member counts as permanent (PS lines 161-177 + 192).
      currentValue:
        "3 Global Admin(s) — PIM not licensed so all are permanent: alice@contoso.com, bob@contoso.com, pimonly@contoso.com",
      status: "Fail",
    });
    for (const base of ["ENTRA-PIM-002", "ENTRA-PIM-003", "ENTRA-PIM-004", "ENTRA-PIM-005"]) {
      const row = rows.find((r) => r.checkId.startsWith(base));
      expect(row).toMatchObject({
        currentValue:
          "PIM not licensed (Entra ID P2 required) -- cannot verify role assignment permanence",
        status: "Review",
      });
    }
  });

  it("emits the Unknown→Review 'could not enumerate' row when the GA members query fails", async () => {
    const fetchImpl = replayExcept(
      GA_ROLE_MEMBERS_URL,
      403,
      { error: { code: "Authorization_RequestDenied", message: "Insufficient privileges" } },
      baseFixtures(),
    );
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runAdminRoleChecks,
      baseFixtures(),
      { fetchImpl },
    );

    const pimRow = rows.find((r) => r.checkId.startsWith("ENTRA-PIM-001"));
    expect(pimRow).toMatchObject({
      currentValue: "Could not enumerate Global Admin members",
      recommendedValue: "No permanent Global Admin assignments",
      status: "Review",
    });
  });
});
