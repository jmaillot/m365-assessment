/**
 * Parity tests for the Get-EntraSecurityConfig.ps1 port (plan 02-08 task 2)
 * — AssessmentMaps entry '07b-Entra-Security-Config': the composite Entra
 * security config collector that binds all four check families.
 *
 * Composition semantics proven:
 *   - PS dot-source order (Get-EntraSecurityConfig.ps1 lines 86-90):
 *     EntraPasswordAuthChecks → EntraAdminRoleChecks →
 *     EntraConditionalAccessChecks → EntraUserGroupChecks. Row order in the
 *     composite golden is the concatenation of the four family goldens in
 *     exactly that order (deep-equal over the full 54-row sequence).
 *   - ONE fresh counter context spans the whole composite: runEngine creates
 *     a single sub-numberer for the section, mirroring Initialize-SecurityConfig
 *     being called once by the PS orchestrator.
 *   - Shared-scope state: $authPolicy is pre-fetched ONCE by the orchestrator
 *     (PS lines 59-72, soft-fail) and stored under ctx.shared("entra.authPolicy")
 *     so AdminRole/UserGroup see exactly one pre-fetch across all families;
 *     UserGroup's sections 9b/26 still re-fetch live (PS parity).
 *   - $orgSettings is stored by UserGroup AFTER PasswordAuth's section-27 read,
 *     so section 27 always sees null — identical to the PS execution order.
 */
import { describe, expect, it } from "vitest";
import { runEntraSecurityConfig } from "./entra-security-config";
import { ADMIN_ROLE_ENDPOINTS as AR_EP } from "./admin-role-checks";
import {
  gaEligibilityInstancesUrl,
  gaMembersSelectIdsUrl,
  gaMembersSelectLicensesUrl,
  gaMembersSelectSyncUrl,
  praPolicyAssignmentsUrl,
} from "./admin-role-checks";
import { CA_CHECKS_ENDPOINTS as CA_EP } from "./conditional-access-checks";
import { PASSWORD_AUTH_ENDPOINTS as PA_EP } from "./password-auth-checks";
import { USER_GROUP_ENDPOINTS as UG_EP } from "./user-group-checks";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";
import { normalizeUrlKey } from "@/engine/__fixtures__/replay";

const GA_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10";
const TENANT = "00000000-0000-4000-8000-000000000000";

function pa(name: string): unknown {
  return readFixtureJson(`password-auth-checks/${name}.json`);
}
function ar(name: string): unknown {
  return readFixtureJson(`admin-role-checks/${name}.json`);
}
function ca(name: string): unknown {
  return readFixtureJson(`conditional-access-checks/${name}.json`);
}
function ug(name: string): unknown {
  return readFixtureJson(`user-group-checks/${name}.json`);
}

/**
 * Combined fixture set: one Graph surface per key, exactly as a composed
 * tenant replay would present them. authorizationPolicy is SHARED between
 * admin-role and user-group (PS shared scope) — user-group's recording is
 * canonical and its content drives both families' rows.
 */
function combinedFixtures(): Record<string, unknown> {
  return {
    // -- password-auth-checks surfaces --
    [PA_EP.securityDefaults]: pa("v1.0_policies_identitySecurityDefaultsEnforcementPolicy"),
    [PA_EP.authenticationMethodsPolicy]: pa("v1.0_policies_authenticationMethodsPolicy"),
    [PA_EP.directorySettings]: pa("v1.0_settings"),
    [PA_EP.domains]: pa("v1.0_domains"),
    [PA_EP.organization]: pa("v1.0_organization"),
    // -- shared $authPolicy + admin-role surfaces --
    "/v1.0/policies/authorizationPolicy": ug("v1.0_policies_authorizationPolicy"),
    [AR_EP.globalAdminRoleFilter]: ar("v1.0_directoryRoles_filter-GA"),
    "/v1.0/directoryRoles/role-1/members": ar("v1.0_directoryRoles_role-1_members"),
    [AR_EP.subscribedSkus]: ar("v1.0_subscribedSkus"),
    [AR_EP.roleAssignmentScheduleInstances]:
      ar("v1.0_roleManagement_directory_roleAssignmentScheduleInstances"),
    [`/v1.0/directoryRoles(roleTemplateId='${GA_TEMPLATE}')/members`]: ar(
      "v1.0_directoryRoles_roleTemplateId-GA_members",
    ),
    [gaEligibilityInstancesUrl()]:
      ar("v1.0_roleManagement_directory_roleEligibilityScheduleInstances_filter-GA"),
    [AR_EP.accessReviews]: ar("v1.0_identityGovernance_accessReviews_definitions_top100"),
    [`/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId%20eq%20%27/%27%20and%20scopeType%20eq%20%27DirectoryRole%27%20and%20roleDefinitionId%20eq%20%27${GA_TEMPLATE}%27&$expand=policy($expand=rules)`]:
      ar("v1.0_policies_roleManagementPolicyAssignments_GA"),
    [praPolicyAssignmentsUrl()]:
      ar("v1.0_policies_roleManagementPolicyAssignments_PRA"),
    [gaMembersSelectSyncUrl()]:
      ar("v1.0_directoryRoles_roleTemplateId-GA_members_select-sync"),
    [gaMembersSelectLicensesUrl()]:
      ar("v1.0_directoryRoles_roleTemplateId-GA_members_select-licenses"),
    [gaMembersSelectIdsUrl()]:
      ar("v1.0_directoryRoles_roleTemplateId-GA_members_select-ids"),
    [AR_EP.userRegistrationDetails]:
      ar("v1.0_reports_authenticationMethods_userRegistrationDetails"),
    // -- conditional-access-checks surfaces --
    [CA_EP.caPolicies]: ca("v1.0_identity_conditionalAccess_policies"),
    [CA_EP.deviceRegistrationPolicy]: ca("v1.0_policies_deviceRegistrationPolicy"),
    // -- user-group-checks surfaces --
    [UG_EP.adminConsentRequestPolicy]: ug("v1.0_policies_adminConsentRequestPolicy"),
    [UG_EP.allPrincipalsGrants]: ug("oauth2PermissionGrants_allprincipals"),
    [UG_EP.guestCount]: ug("users_count_guests"),
    [UG_EP.memberCount]: ug("users_count_members"),
    [UG_EP.disabledMemberCount]: ug("users_count_disabled_members"),
    [`/v1.0/organization/${TENANT}`]: ug("v1.0_organization_tenant"),
    [UG_EP.userRegistrationDetailsProbe]: ug("userRegistrationDetails_probe"),
    [UG_EP.crossTenantDefault]: ug("crossTenantAccessPolicy_default"),
    [UG_EP.dynamicGroups]: ug("groups_dynamicmembership"),
    [UG_EP.unifiedGroups]: ug("groups_unified_page1"),
    [`${UG_EP.unifiedGroups}&$skiptoken=p2`]: ug("groups_unified_page2"),
    "/v1.0/groups/a1bbbbbb-0000-4000-8000-000000000001/owners?$select=id": ug("owners_a1"),
    "/v1.0/groups/a2bbbbbb-0000-4000-8000-000000000002/owners?$select=id":
      ug("owners_a2_empty"),
    "/v1.0/groups/a4bbbbbb-0000-4000-8000-000000000004/owners?$select=id": ug("owners_a4"),
  };
}

describe("runEntraSecurityConfig", () => {
  it("produces the full composite row sequence identical to the four PS helper files in dot-source order", async () => {
    const { rows, sectionError, licensingOverlayApplied } =
      await runCollectorOverFixtures(
        "identity",
        runEntraSecurityConfig,
        combinedFixtures(),
      );

    expect(sectionError).toBeUndefined();
    // subscribedSkus fetched by admin-role checks must NOT trigger the D-20
    // overlay (only the Licensing collector publishes SKU states).
    expect(licensingOverlayApplied).toBeUndefined();

    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/entra-security-config.json",
    );
    expect(golden.length).toBe(54);
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("pre-fetches the authorization policy exactly once across all four families", async () => {
    const { graphUrls } = await runCollectorOverFixtures(
      "identity",
      runEntraSecurityConfig,
      combinedFixtures(),
    );

    const keys = graphUrls.map((u) => normalizeUrlKey(u));
    const authPolicyCalls = keys.filter((k) => k === "/v1.0/policies/authorizationPolicy");
    // Orchestrator pre-fetch + UserGroup's own section 9b and 26 re-fetches.
    expect(authPolicyCalls).toHaveLength(3);
    // The orchestrator's pre-fetch happens FIRST (before any family runs).
    expect(keys.indexOf("/v1.0/policies/authorizationPolicy")).toBeLessThan(
      keys.indexOf(PA_EP.securityDefaults),
    );
  });

  it("keeps cross-family sub-numbering sequential within one fresh counter context", async () => {
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runEntraSecurityConfig,
      combinedFixtures(),
    );

    // Bases that repeat WITHIN a family continue their sequence across the
    // whole composite (single Initialize-SecurityConfig semantics).
    const smsVoice = rows.filter((r) => r.checkId.startsWith("ENTRA-AUTHMETHOD-001"));
    expect(smsVoice.map((r) => r.checkId)).toEqual([
      "ENTRA-AUTHMETHOD-001.1",
      "ENTRA-AUTHMETHOD-001.2",
    ]);
    // No base id collides across families, so every first occurrence is .1.
    const firstOccurrences = new Set<string>();
    for (const row of rows) {
      const base = row.checkId.replace(/\.\d+$/, "");
      if (!firstOccurrences.has(base)) {
        firstOccurrences.add(base);
        expect(row.checkId).toBe(`${base}.1`);
      }
    }
  });
});
