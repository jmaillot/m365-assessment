/**
 * Parity tests for the Get-CASecurityConfig.ps1 port (plan 02-09) —
 * '07c-CA-Security-Config', the largest Entra collector (1,205 PS lines).
 *
 * PS Graph call sites being proven:
 *   1. GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy (soft-fail → false, PS 44-58)
 *   2. GET /v1.0/identity/conditionalAccess/policies   (soft-fail → empty arrays, PS 60-78)
 *   3. GET /v1.0/identity/conditionalAccess/namedLocations (check 14; failure leaves $namedLocations null)
 *   4. GET /v1.0/roleManagement/directory/roleAssignments?$top=999 (check 17)
 *   5. GET /v1.0/groups/{id}?$select=id per referenced group (check 20; 404-family → stale)
 *
 * Branch parity proven per check against the PS decision ladders:
 *   - check 1 CA-MFA-ADMIN-001: admin-role Pass / All-Users-clean Pass /
 *     All-Users-excluded Review / Security-Defaults Info / Fail ladder
 *     (PS 191-258), gated by Test-TargetAdminRole / Test-TargetAllUser /
 *     Test-ExcludesAdminRole (#1000) / Test-RequiresMfa ('mfa OR x' ≠ MFA).
 *   - checks 2-3: coverage Pass / SD Info / Fail.
 *   - checks 4-10: single-threshold Pass/Fail ladders.
 */
import { describe, expect, it } from "vitest";
import { runCaSecurityConfig } from "./ca-security-config";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";
import { createReplayFetch } from "@/engine/__fixtures__/replay";

const GA = "62e90394-69f5-4237-9190-012177145e10"; // Global Administrator
const PRA = "e8611ab8-c189-46e8-94e1-60213ab1f814"; // Privileged Role Administrator
const CAA = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"; // Conditional Access Administrator

const SD_DISABLED = "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy";

function policy(overrides: Record<string, unknown>): Record<string, unknown> {
  return { id: "pol-1", displayName: "Pol", state: "enabled", ...overrides };
}

/** Zero-policy fixture set: SD disabled, no named locations/role assignments. */
function zeroPolicyFixtures(sdEnabled = false): Record<string, unknown> {
  return {
    [SD_DISABLED]: { isEnabled: sdEnabled },
    "/v1.0/identity/conditionalAccess/policies": { value: [] },
  };
}

function fetchWithStatus(status: number, body: unknown): typeof fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
}

/**
 * The seventeen rows PS emits for a tenant with zero policies: checks 1-12
 * Fail, report-only/session/risk-pattern/fallback checks Pass on 'None',
 * stale-group check Passes on 'No group-targeted policies'. Checks 14/17/19
 * emit NOTHING because their supporting fetches failed or returned no data.
 */
function zeroPolicyRows(): Array<Record<string, unknown>> {
  const failRems: Array<[string, string, string]> = [
    ["MFA Required for Admin Roles", "CA-MFA-ADMIN-001",
      "Create a CA policy: Target admin directory roles > Grant > Require multifactor authentication. Entra admin center > Protection > Conditional Access > New policy."],
    ["MFA Required for All Users", "CA-MFA-ALL-001",
      "Create a CA policy: Target All users > All cloud apps > Grant > Require multifactor authentication. Entra admin center > Protection > Conditional Access > New policy."],
    ["Legacy Authentication Blocked", "CA-LEGACYAUTH-001",
      "Create a CA policy: Target All users > Conditions > Client apps > Exchange ActiveSync clients + Other clients > Grant > Block access. Entra admin center > Protection > Conditional Access."],
    ["Sign-in Frequency for Admin Roles", "CA-SIGNIN-FREQ-001",
      "Create a CA policy: Target admin roles > Session > Sign-in frequency (e.g., 4 hours) + Persistent browser session = Never. Entra admin center > Protection > Conditional Access."],
    ["Phishing-Resistant MFA for Admins", "CA-PHISHRES-001",
      "Create a CA policy: Target admin roles > Grant > Require authentication strength > Phishing-resistant MFA. Entra admin center > Protection > Conditional Access."],
    ["User Risk Policy Configured", "CA-USERRISK-001",
      "Create a CA policy: Target All users > Conditions > User risk > High > Grant > Require password change + MFA. Entra admin center > Protection > Conditional Access."],
    ["Sign-in Risk Policy Configured", "CA-SIGNINRISK-001",
      "Create a CA policy: Target All users > Conditions > Sign-in risk > High, Medium > Grant > Require MFA. Entra admin center > Protection > Conditional Access."],
    ["Sign-in Risk Blocks Medium+High", "CA-SIGNINRISK-002",
      "Create a CA policy: Target All users > Conditions > Sign-in risk > Medium, High > Grant > Block access (or require MFA). Entra admin center > Protection > Conditional Access."],
    ["Managed Device Required", "CA-DEVICE-001",
      "Create a CA policy: Target All users > All cloud apps > Grant > Require device to be marked as compliant (or Microsoft Entra hybrid joined). Entra admin center > Protection > Conditional Access."],
    ["Managed Device for Security Info Registration", "CA-DEVICE-002",
      "Create a CA policy: User actions > Register security information > Grant > Require compliant device. Entra admin center > Protection > Conditional Access."],
    ["Sign-in Frequency for Intune Enrollment", "CA-INTUNE-001",
      "Create a CA policy: Target Microsoft Intune enrollment app > Session > Sign-in frequency = Every time. Entra admin center > Protection > Conditional Access."],
    ["Device Code Flow Blocked", "CA-DEVICECODE-001",
      "Create a CA policy: Target All users > Conditions > Authentication flows > Device code flow > Grant > Block access. Entra admin center > Protection > Conditional Access."],
  ];
  const passNones: Array<[string, string, string]> = [
    ["Report-Only Policies", "CA-REPORTONLY-001", "Review and promote or remove"],
    ["Persistent Browser Without Device Compliance", "CA-SESSION-001",
      "No persistent sessions without device compliance"],
    ["Combined Risk Policy Anti-Pattern", "CA-RISKPOLICY-001",
      "Separate sign-in risk and user risk into distinct policies"],
    ["CA Policies with Empty Include Targets", "CA-FALLBACK-001",
      "All enabled CA policies should target at least one user, group, or role"],
  ];
  return [
    ...failRems.map(([setting, baseId, remediation]) => ({
      category: "Conditional Access",
      setting,
      currentValue: "No matching CA policy found",
      recommendedValue: "At least 1 policy",
      status: "Fail",
      checkId: `${baseId}.1`,
      remediation,
      intentDesign: false,
    })),
    ...passNones.map(([setting, baseId, recommendedValue]) => ({
      category: "Conditional Access",
      setting,
      currentValue: "None",
      recommendedValue,
      status: "Pass",
      checkId: `${baseId}.1`,
      remediation: "No action needed.",
      intentDesign: false,
    })),
    {
      category: "Conditional Access",
      setting: "Stale Group References in CA Policies",
      currentValue: "No group-targeted policies",
      recommendedValue: "All referenced groups should exist",
      status: "Pass",
      checkId: "CA-STALEREF-001.1",
      remediation: "No action needed.",
      intentDesign: false,
    },
  ];
}

describe("runCaSecurityConfig — fetch semantics", () => {
  it("produces exactly the PS zero-policy rows when the tenant has no CA policies", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runCaSecurityConfig,
      zeroPolicyFixtures(),
    );

    expect(sectionError).toBeUndefined();
    expect(rows).toEqual(zeroPolicyRows());
  });

  it("soft-fails the CA policy list to empty arrays on fetch errors, like PS lines 74-78", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runCaSecurityConfig,
      {},
      // Every endpoint fails → SD probe degrades to false, policy list to [].
      { fetchImpl: fetchWithStatus(500, { error: { code: "serverError", message: "boom" } }) },
    );

    expect(sectionError).toBeUndefined();
    expect(rows).toEqual(zeroPolicyRows());
  });
});

describe("runCaSecurityConfig — check 1 decision ladder (PS 191-258)", () => {
  it.each([
    [
      "admin-role-targeted MFA policy → Pass",
      policy({
        displayName: "Admin MFA",
        conditions: { users: { includeRoles: [GA] } },
        grantControls: { builtInControls: ["mfa"] },
      }),
      "Pass",
      "Yes (1 admin-role-targeted policy: Admin MFA)",
      "No action needed.",
    ],
    [
      "clean All-Users MFA policy → Pass via All-Users branch",
      policy({
        displayName: "Everyone MFA",
        conditions: { users: { includeUsers: ["All"] } },
        grantControls: { builtInControls: ["mfa"] },
      }),
      "Pass",
      "Yes (covered by All-Users MFA policy: Everyone MFA)",
      "No action needed. Admins are covered by an All-Users MFA policy; a dedicated admin-role policy would add defense in depth.",
    ],
    [
      "All-Users MFA policy with user/group exclusions → Review",
      policy({
        displayName: "Everyone MFA",
        conditions: { users: { includeUsers: ["All"], excludeGroups: ["g9"] } },
        grantControls: { builtInControls: ["mfa"] },
      }),
      "Review",
      "All-Users MFA policy found but it excludes users/groups; verify admins are not carved out: Everyone MFA",
      "Confirm the excluded users/groups do not contain administrators, or add a dedicated Conditional Access policy targeting admin directory roles with Require multifactor authentication.",
    ],
  ])("%s", async (_label, pol, status, currentValue, remediation) => {
    const { rows } = await runCollectorOverFixtures("identity", runCaSecurityConfig, {
      ...zeroPolicyFixtures(),
      "/v1.0/identity/conditionalAccess/policies": { value: [pol] },
    });

    expect(rows[0].status).toBe(status);
    expect(rows[0].currentValue).toBe(currentValue);
    expect(rows[0].remediation).toBe(remediation);
  });

  it("does not count a role-targeted MFA policy that excludes an admin role (Test-ExcludesAdminRole, #1000)", async () => {
    const { rows } = await runCollectorOverFixtures("identity", runCaSecurityConfig, {
      ...zeroPolicyFixtures(),
      "/v1.0/identity/conditionalAccess/policies": {
        value: [
          policy({
            displayName: "Admins minus CA Admin",
            conditions: { users: { includeRoles: [GA], excludeRoles: [CAA] } },
            grantControls: { builtInControls: ["mfa"] },
          }),
        ],
      },
    });

    expect(rows[0].status).toBe("Fail");
  });

  it("does not treat 'mfa OR compliantDevice' as requiring MFA (Test-RequiresMfa operator rule)", async () => {
    const { rows } = await runCollectorOverFixtures("identity", runCaSecurityConfig, {
      ...zeroPolicyFixtures(),
      "/v1.0/identity/conditionalAccess/policies": {
        value: [
          policy({
            displayName: "MFA or compliant",
            conditions: { users: { includeRoles: [GA] } },
            grantControls: { operator: "OR", builtInControls: ["mfa", "compliantDevice"] },
          }),
        ],
      },
    });

    expect(rows[0].status).toBe("Fail");
  });

  it("emits Info 'Covered by Security Defaults' when SD is enabled and no policy covers admins", async () => {
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runCaSecurityConfig,
      zeroPolicyFixtures(true),
    );

    expect(rows[0]).toMatchObject({
      setting: "MFA Required for Admin Roles",
      status: "Info",
      currentValue: "Covered by Security Defaults",
      recommendedValue: "At least 1 policy (or Security Defaults)",
      remediation:
        "Security Defaults enforces MFA for all admin roles. For granular control, disable Security Defaults and create Conditional Access policies.",
    });
  });
});

describe("runCaSecurityConfig — Security Defaults fallback branches", () => {
  it("emits SD Info rows for checks 2, 3 and 8 when SD is enabled with zero policies", async () => {
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runCaSecurityConfig,
      zeroPolicyFixtures(true),
    );

    const bySetting = new Map(rows.map((r) => [r.setting, r]));
    expect(bySetting.get("MFA Required for All Users")).toMatchObject({
      status: "Info",
      currentValue: "Covered by Security Defaults",
      remediation:
        "Security Defaults enforces MFA for all users. For granular control, disable Security Defaults and create Conditional Access policies.",
    });
    expect(bySetting.get("Legacy Authentication Blocked")).toMatchObject({
      status: "Info",
      currentValue: "Covered by Security Defaults",
      remediation:
        "Security Defaults blocks legacy authentication protocols. For granular control, disable Security Defaults and create Conditional Access policies.",
    });
    expect(bySetting.get("Sign-in Risk Blocks Medium+High")).toMatchObject({
      status: "Info",
      currentValue:
        "Partially covered by Security Defaults (blocks high-risk sign-ins)",
      recommendedValue:
        "At least 1 policy (or Security Defaults for partial coverage)",
      remediation:
        "Security Defaults blocks high-risk sign-ins but does not provide granular medium-risk controls. For full coverage, disable Security Defaults and create Conditional Access policies with Entra ID P2.",
    });
  });
});

describe("runCaSecurityConfig — golden parity over the comprehensive fixture set", () => {
  it("matches the hand-traced PS golden rows for every ported check section", async () => {
    const fixtures =
      readFixtureJson<Record<string, unknown>>(
        "ca-security-config/comprehensive.json",
      );
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/ca-security-config.json",
    );

    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runCaSecurityConfig,
      fixtures,
    );

    expect(sectionError).toBeUndefined();
    // Full-file golden parity: ALL twenty check sections.
    expect(rows).toEqual(goldenToExpected(golden));
  });
});

describe("runCaSecurityConfig — report-only, named locations, role coverage, stale refs", () => {
  const COMPREHENSIVE = "ca-security-config/comprehensive.json";

  it("flags report-only policies with a Warning listing their names (PS check 13)", async () => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    const { rows } = await runCollectorOverFixtures("identity", runCaSecurityConfig, fixtures);
    expect(rows.find((r) => r.checkId === "CA-REPORTONLY-001.1")).toMatchObject({
      status: "Warning",
      currentValue: "1 policies in report-only: Report Only Legacy",
      recommendedValue: "Review and promote or remove",
    });
  });

  it("emits Review for trusted IP locations and Fail for stale references (PS checks 14/19)", async () => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    const { rows } = await runCollectorOverFixtures("identity", runCaSecurityConfig, fixtures);
    expect(rows.find((r) => r.checkId === "CA-NAMEDLOC-001.1")).toMatchObject({
      status: "Review",
      currentValue: "1 trusted IP locations: HQ Public IPs",
      recommendedValue: "Prefer compliant network or country-based locations",
    });
    // 'aaaa…' is not a system placeholder and not in the known-location set.
    expect(rows.find((r) => r.checkId === "CA-NAMEDLOC-002.1")).toMatchObject({
      status: "Fail",
      currentValue: "1 policies reference deleted named locations: Stale Location Ref",
    });
  });

  it("skips stale-location evaluation entirely when the namedLocations fetch fails (PS 1071-1080)", async () => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    const noNamedLocs = { ...fixtures };
    delete noNamedLocs["/v1.0/identity/conditionalAccess/namedLocations"];
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runCaSecurityConfig,
      noNamedLocs,
    );

    expect(sectionError).toBeUndefined();
    expect(rows.some((r) => r.checkId.startsWith("CA-NAMEDLOC"))).toBe(false);
  });

  it("warns when active Tier-0 roles are not covered by any role-targeted policy (PS check 17)", async () => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    const { rows } = await runCollectorOverFixtures("identity", runCaSecurityConfig, fixtures);
    // Active: Global Admin + Fabric Admin; covered: Global Admin (+ Priv Role
    // Admin, inactive) → Fabric Administrator uncovered.
    expect(rows.find((r) => r.checkId === "CA-ROLECOVERAGE-001.1")).toMatchObject({
      status: "Warning",
      currentValue: "1 of 2 active Tier-0 roles not targeted by any CA policy",
      recommendedValue: "All active privileged roles covered",
    });
  });

  it("emits Review when there are no role-targeted CA policies at all (PS 961-972)", async () => {
    const { rows } = await runCollectorOverFixtures("identity", runCaSecurityConfig, {
      [SD_DISABLED]: { isEnabled: false },
      "/v1.0/identity/conditionalAccess/policies": { value: [] },
      "/v1.0/roleManagement/directory/roleAssignments?$top=999": { value: [] },
    });

    expect(rows.find((r) => r.checkId === "CA-ROLECOVERAGE-001.1")).toMatchObject({
      status: "Review",
      currentValue: "No role-targeted CA policies found",
      remediation:
        "Consider creating CA policies that specifically target privileged directory roles with stricter controls (phishing-resistant MFA, compliant devices).",
    });
  });

  it("drops the role-coverage row without a section error when roleAssignments fails (PS catch)", async () => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    const noRoleAssignments = { ...fixtures };
    delete noRoleAssignments["/v1.0/roleManagement/directory/roleAssignments?$top=999"];
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runCaSecurityConfig,
      noRoleAssignments,
    );

    expect(sectionError).toBeUndefined();
    expect(rows.some((r) => r.checkId === "CA-ROLECOVERAGE-001.1")).toBe(false);
  });

  it("treats a failed group probe as live (not stale), yielding Pass (PS 1140-1148)", async () => {
    // Only group referenced is g333; its probe returns 500 → not added to the
    // stale set → zero stale policies → Pass 'None'.
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runCaSecurityConfig,
      {
        [SD_DISABLED]: { isEnabled: false },
        "/v1.0/identity/conditionalAccess/policies": {
          value: [
            policy({
              displayName: "Group Targeted",
              conditions: {
                users: { includeGroups: ["33333333-3333-3333-3333-333333333333"] },
              },
            }),
          ],
        },
      },
      {
        fetchImpl: async (input, init) => {
          const url = String(input);
          if (url.includes("/v1.0/groups/")) {
            return new Response(
              JSON.stringify({ error: { code: "serverError", message: "boom" } }),
              { status: 500, headers: { "content-type": "application/json" } },
            );
          }
          return createReplayFetch({
            [SD_DISABLED]: { isEnabled: false },
            "/v1.0/identity/conditionalAccess/policies": {
              value: [
                policy({
                  displayName: "Group Targeted",
                  conditions: {
                    users: { includeGroups: ["33333333-3333-3333-3333-333333333333"] },
                  },
                }),
              ],
            },
          })(url, init);
        },
      },
    );

    expect(rows.find((r) => r.checkId === "CA-STALEREF-001.1")).toMatchObject({
      status: "Pass",
      currentValue: "None",
    });
  });
});
