/**
 * Parity tests for the EntraUserGroupChecks.ps1 port (plan 02-07 task 2).
 *
 * PS Graph call sites proven:
 *   - GET /v1.0/policies/authorizationPolicy — shared $authPolicy soft-fail
 *     pre-fetch (Get-EntraSecurityConfig.ps1:61-72) + fresh fetches in PS
 *     sections 9b and 26
 *   - GET /v1.0/policies/adminConsentRequestPolicy (PS section 6)
 *   - GET /v1.0/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'
 *     &$top=999 (PS section 9c)
 *   - GET /v1.0/users/$count?$filter=userType eq 'Guest' with
 *     ConsistencyLevel: eventual (PS line 349 — advanced query)
 *   - GET /beta/organization/{tenantId} → promoted to v1.0 (PS line 386,
 *     see BETA-ENDPOINTS.md)
 *   - GET /v1.0/reports/authenticationMethods/userRegistrationDetails probe
 *     (PS line 428; beta→v1.0 promotion per the resolved 02-05 row)
 *   - GET /v1.0/policies/crossTenantAccessPolicy/default (PS section 17)
 *   - GET /v1.0/groups dynamic/unified lists + per-group owners (PS 18/25),
 *     including multi-page @odata.nextLink traversal (D-27)
 *   - GET /v1.0/users/$count member + disabled-member counts with
 *     ConsistencyLevel: eventual (PS lines 752-758 — advanced queries)
 */
import { describe, expect, it } from "vitest";
import { runUserGroupChecks } from "./user-group-checks";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";
import {
  createReplayFetch,
  normalizeUrlKey,
} from "@/engine/__fixtures__/replay";

type Fixtures = Record<string, unknown>;

function fileFixture(name: string): unknown {
  return readFixtureJson(`user-group-checks/${name}.json`);
}

const AUTH_POLICY_URL = "/v1.0/policies/authorizationPolicy";
const GUEST_COUNT_URL = "/v1.0/users/$count?$filter=userType%20eq%20%27Guest%27";
const MEMBER_COUNT_URL = "/v1.0/users/$count?$filter=userType%20eq%20%27Member%27";
const DISABLED_COUNT_URL =
  "/v1.0/users/$count?$filter=accountEnabled%20eq%20false%20and%20userType%20eq%20%27Member%27";
const UNIFIED_P1_URL =
  "/v1.0/groups?$filter=groupTypes/any(g:g%20eq%20%27Unified%27)&$select=displayName,id,visibility&$top=999";

/** Full happy-path fixture set (matches golden/user-group-checks.json). */
function baseFixtures(): Fixtures {
  const fixtures: Fixtures = {};
  fixtures[AUTH_POLICY_URL] = fileFixture(
    "v1.0_policies_authorizationPolicy",
  );
  fixtures["/v1.0/policies/adminConsentRequestPolicy"] = fileFixture(
    "v1.0_policies_adminConsentRequestPolicy",
  );
  fixtures[
    "/v1.0/oauth2PermissionGrants?$filter=consentType%20eq%20%27AllPrincipals%27&$top=999"
  ] = fileFixture("oauth2PermissionGrants_allprincipals");
  fixtures[GUEST_COUNT_URL] = fileFixture("users_count_guests");
  fixtures[MEMBER_COUNT_URL] = fileFixture("users_count_members");
  fixtures[DISABLED_COUNT_URL] = fileFixture("users_count_disabled_members");
  fixtures["/v1.0/organization/00000000-0000-4000-8000-000000000000"] =
    fileFixture("v1.0_organization_tenant"),
  fixtures[
    "/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isMfaRegistered,isMfaCapable&$top=1"
  ] = fileFixture("userRegistrationDetails_probe");
  fixtures["/v1.0/policies/crossTenantAccessPolicy/default"] = fileFixture(
    "crossTenantAccessPolicy_default",
  );
  fixtures[
    "/v1.0/groups?$filter=groupTypes/any(g:g%20eq%20%27DynamicMembership%27)&$select=displayName,membershipRule&$top=999"
  ] = fileFixture("groups_dynamicmembership");
  fixtures[UNIFIED_P1_URL] = fileFixture("groups_unified_page1");
  fixtures[
    UNIFIED_P1_URL + "&$skiptoken=p2"
  ] = fileFixture("groups_unified_page2");
  fixtures["/v1.0/groups/a1bbbbbb-0000-4000-8000-000000000001/owners?$select=id"] =
    fileFixture("owners_a1");
  fixtures["/v1.0/groups/a2bbbbbb-0000-4000-8000-000000000002/owners?$select=id"] =
    fileFixture("owners_a2_empty");
  fixtures["/v1.0/groups/a4bbbbbb-0000-4000-8000-000000000004/owners?$select=id"] =
    fileFixture("owners_a4");
  return fixtures;
}

/** Replay wrapper that records the request headers sent for each URL key. */
function headerCapturingReplay(fixtures: Fixtures): {
  impl: typeof fetch;
  headersByUrl: Map<string, Record<string, unknown>>;
} {
  const headersByUrl = new Map<string, Record<string, unknown>>();
  const replay = createReplayFetch(fixtures);
  const impl = async (input: string | URL | RequestInfo, init?: RequestInit) => {
    const raw = typeof input === "string" || input instanceof URL ? String(input) : input.url;
    headersByUrl.set(normalizeUrlKey(raw), (init?.headers ?? {}) as Record<string, unknown>);
    return replay(input as Parameters<typeof fetch>[0], init);
  };
  return { impl: impl as unknown as typeof fetch, headersByUrl };
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
    const raw = typeof input === "string" || input instanceof URL ? String(input) : input.url;
    if (normalizeUrlKey(raw) === failKey) {
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    }
    return replay(input as Parameters<typeof fetch>[0], init);
  };
}

function errorBody(message: string): unknown {
  return { error: { code: "Authorization_RequestDenied", message } };
}

describe("runUserGroupChecks", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runUserGroupChecks,
      baseFixtures(),
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/user-group-checks.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("proves multi-page @odata.nextLink traversal through the unified-groups list (D-27)", async () => {
    const { rows, graphUrls } = await runCollectorOverFixtures(
      "identity",
      runUserGroupChecks,
      baseFixtures(),
    );

    // Both pages were fetched by the transport (not just page 1).
    expect(graphUrls.some((u) => u.includes(UNIFIED_P1_URL))).toBe(true);
    expect(
      graphUrls.some((u) => u.endsWith("$top=999&$skiptoken=p2")),
    ).toBe(true);
    // Ownerless group from page 1 was found across the merged pages.
    const owners = rows.find((r) => r.setting === "Public Groups Have Owners");
    expect(owners?.currentValue).toBe(
      "1 groups without owners: Ownerless Public Group",
    );
  });

  it("forwards ConsistencyLevel: eventual on the advanced-query $count call sites (PS lines 349 and 752-758)", async () => {
    const { impl, headersByUrl } = headerCapturingReplay(baseFixtures());
    await runCollectorOverFixtures("identity", runUserGroupChecks, baseFixtures(), {
      fetchImpl: impl,
    });

    for (const key of [GUEST_COUNT_URL, MEMBER_COUNT_URL, DISABLED_COUNT_URL]) {
      const headers = headersByUrl.get(key);
      expect(headers, `headers for ${key}`).toBeDefined();
      expect(headers?.ConsistencyLevel).toBe("eventual");
    }
  });

  it("emits the Skipped catch row when adminConsentRequestPolicy fails (PS lines 168-180)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runUserGroupChecks,
      baseFixtures(),
      {
        fetchImpl: replayExcept(
          "/v1.0/policies/adminConsentRequestPolicy",
          403,
          errorBody("Insufficient privileges to complete the operation."),
          baseFixtures(),
        ),
      },
    );

    expect(sectionError).toBeUndefined();
    const row = rows.find((r) => r.setting === "Admin Consent Workflow Enabled");
    expect(row?.status).toBe("Skipped");
    expect(row?.currentValue).toContain("Error: ");
    expect(row?.recommendedValue).toBe("True");
    expect(row?.remediation).toBe("Check Graph API permissions and retry.");
    expect(row?.checkId).toBe("ENTRA-CONSENT-002.1");
  });

  it("skips the authPolicy-gated checks when the shared policy fetch fails (PS sections 3-5/10/16)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runUserGroupChecks,
      baseFixtures(),
      {
        fetchImpl: replayExcept(
          AUTH_POLICY_URL,
          403,
          errorBody("Insufficient privileges to complete the operation."),
          baseFixtures(),
        ),
      },
    );

    expect(sectionError).toBeUndefined();
    // Gated sections emit NOTHING without $authPolicy...
    for (const setting of [
      "User Consent for Applications",
      "Users Can Register Applications",
      "Users Can Create Security Groups",
      "Non-Admin Tenant Creation Restricted",
      "Guest Invitation Policy",
      "Guest User Access Restriction",
      "Third-party Integrated Apps Restricted",
    ]) {
      expect(rows.find((r) => r.setting === setting)).toBeUndefined();
    }
    // ...but section 9b's FRESH authorizationPolicy fetch also fails → its own
    // Skipped catch row; section 26 likewise.
    const verified = rows.find(
      (r) => r.setting === "User Consent Requires Verified Publisher",
    );
    expect(verified?.status).toBe("Skipped");
    const org = rows.find((r) => r.setting === "Org-Level App Consent Restriction");
    expect(org?.status).toBe("Skipped");
    // Section 17 degrades gracefully with invitesFrom = 'unknown'.
    const guest4 = rows.find(
      (r) => r.setting === "Guest Invitation Domain Restrictions",
    );
    expect(guest4?.currentValue).toBe("Restricted (invites: unknown)");
  });

  it("maps low-impact and legacy consent policies to their PS display strings (PS lines 18-29)", async () => {
    const fixtures = baseFixtures();
    const authPolicy = fixtures[AUTH_POLICY_URL] as Record<string, unknown>;
    const durp = authPolicy.defaultUserRolePermissions as Record<string, unknown>;
    durp.permissionGrantPoliciesAssigned = [
      "ManagePermissionGrantsForSelf.microsoft-user-default-low",
    ];

    const { rows } = await runCollectorOverFixtures(
      "identity",
      runUserGroupChecks,
      fixtures,
    );
    const consent = rows.find((r) => r.checkId.startsWith("ENTRA-CONSENT-001"));
    expect(consent?.currentValue).toBe("Allow user consent for low-impact apps");
    expect(consent?.status).toBe("Fail");

    durp.permissionGrantPoliciesAssigned = [
      "ManagePermissionGrantsForSelf.microsoft-user-default-legacy",
      "something-else",
    ];
    const legacy = await runCollectorOverFixtures(
      "identity",
      runUserGroupChecks,
      fixtures,
    );
    const legacyRow = legacy.rows.find((r) =>
      r.checkId.startsWith("ENTRA-CONSENT-001"),
    );
    expect(legacyRow?.currentValue).toBe("Allow user consent (legacy)");
  });
});




