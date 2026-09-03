/**
 * Parity tests for the EntraPasswordAuthChecks.ps1 port (plan 02-07 task 1).
 *
 * PS Graph call sites proven:
 *   1. GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy (PS lines 14-75)
 *   2. GET /v1.0/identity/conditionalAccess/policies (PS lines 24-33, 84-89 - SD-off coverage)
 *   3. GET /v1.0/policies/authenticationMethodsPolicy (PS lines 204-227; reused by 7b/20/21)
 *   4. GET /v1.0/settings (PS lines 310-384)
 *   5. GET /v1.0/domains (PS lines 389-412)
 *   6. GET /v1.0/organization (PS lines 572-647)
 *
 * Branch parity asserted per PS section ladder, including the gap-analysis
 * ordered coverage areas (PS lines 92-148), the directory-settings
 * BadRequest-to-Info fallback (PS line 366), the absent-number-matching =
 * "enforced (mandatory)" default (#998, PS lines 425-431) and the absent /
 * 'default' system-preferred = enabled rule (#999, PS lines 485-491).
 */
import { describe, expect, it } from "vitest";
import { runPasswordAuthChecks } from "./password-auth-checks";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

type Fixtures = Record<string, unknown>;

function fileFixture(name: string): unknown {
  return readFixtureJson(`password-auth-checks/${name}.json`);
}

/** Full happy-path fixture set (matches golden/password-auth-checks.json). */
function baseFixtures(): Fixtures {
  const fixtures: Fixtures = {};
  fixtures["/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"] =
    fileFixture("v1.0_policies_identitySecurityDefaultsEnforcementPolicy");
  fixtures["/v1.0/policies/authenticationMethodsPolicy"] = fileFixture(
    "v1.0_policies_authenticationMethodsPolicy",
  );
  fixtures["/v1.0/settings"] = fileFixture("v1.0_settings");
  fixtures["/v1.0/domains"] = fileFixture("v1.0_domains");
  fixtures["/v1.0/organization"] = fileFixture("v1.0_organization");
  return fixtures;
}

function fetchWithStatus(status: number, body: unknown): typeof fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
}

describe("runPasswordAuthChecks", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runPasswordAuthChecks,
      baseFixtures(),
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/password-auth-checks.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
    // Representative CheckId-base sample incl. the SSPR-* base mandated by the plan.
    const bases = new Set(rows.map((r) => r.checkId.replace(/\.\d+$/, "")));
    expect(bases).toEqual(
      new Set([
        "ENTRA-SECDEFAULT-001",
        "ENTRA-MFA-001",
        "ENTRA-AUTHMETHOD-001",
        "ENTRA-AUTHMETHOD-002",
        "ENTRA-SSPR-001",
        "ENTRA-PASSWORD-001",
        "ENTRA-PASSWORD-002",
        "ENTRA-PASSWORD-003",
        "ENTRA-PASSWORD-004",
        "ENTRA-PASSWORD-005",
        "ENTRA-AUTHMETHOD-003",
        "ENTRA-AUTHMETHOD-004",
        "ENTRA-HYBRID-001",
      ]),
    );
  });

  it("emits a single Review row when security defaults cannot be retrieved (PS catch, lines 63-75)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runPasswordAuthChecks,
      baseFixtures(),
      {
        fetchImpl: fetchWithStatus(403, {
          error: { code: "Authorization_RequestDenied", message: "denied" },
        }),
      },
    );

    expect(sectionError).toBeUndefined();
    // PS: the secDefaults fetch failure aborts only check 1 ($isEnabled stays
    // unset so 1b never runs). Sections 7+ still execute — every fetch 403s,
    // so what survives is the check-1 Review row, the unconditional 7c SSPR
    // Review row, and the check-27 "not available" Review row.
    expect(rows).toHaveLength(3);
    expect(rows[0].status).toBe("Review");
    expect(rows[0].currentValue).toBe("Unable to retrieve");
    expect(rows[0].recommendedValue).toBe("True (if no CA)");
    expect(rows[0].checkId).toBe("ENTRA-SECDEFAULT-001.1");
    expect(rows[1].checkId).toBe("ENTRA-SSPR-001.1");
    expect(rows[2].currentValue).toBe("Password Rule Settings not available");
  });

  it("runs the ordered CA gap analysis when Security Defaults is OFF with partial coverage (PS 1b)", async () => {
    const fixtures = baseFixtures();
    fixtures["/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"] = {
      isEnabled: false,
    };
    // Two enabled CA policies covering exactly two of the four areas.
    fixtures["/v1.0/identity/conditionalAccess/policies"] = {
      value: [
        {
          state: "enabled",
          grantControls: { builtInControls: ["mfa"] },
          conditions: {
            users: { includeUsers: ["All"] },
            clientAppTypes: ["all"],
            applications: { includeApplications: ["All"] },
          },
        },
        {
          state: "enabled",
          grantControls: { builtInControls: ["block"] },
          conditions: {
            users: { includeUsers: ["All"] },
            clientAppTypes: ["exchangeActiveSync", "other"],
            applications: { includeApplications: ["All"] },
          },
        },
        { state: "disabled" }, // disabled policies are ignored (PS Where-Object)
      ],
    };

    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runPasswordAuthChecks,
      fixtures,
    );

    expect(sectionError).toBeUndefined();
    const sdRow = rows.find((r) => r.checkId === "ENTRA-SECDEFAULT-001.1");
    expect(sdRow?.status).toBe("Pass");
    expect(sdRow?.currentValue).toBe(
      "False (Conditional Access active: 2 enabled policies)",
    );
    // Gap list preserves the PS [ordered] dict insertion order.
    const gap = rows.find((r) => r.checkId === "ENTRA-SECDEFAULT-002.1");
    expect(gap?.status).toBe("Review");
    // Policy 1 (All users + mfa + All apps) covers BOTH all-user MFA and
    // Azure Management MFA; policy 2 covers legacy-auth block.
    expect(gap?.currentValue).toBe("3/4 covered. Gaps: Admin MFA");
    expect(gap?.remediation).toBe(
      "Create CA policies to cover: Admin MFA. Entra admin center > Protection > Conditional Access.",
    );
  });

  it("emits the Info fallback when directory settings are not configured (PS line 366)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runPasswordAuthChecks,
      baseFixtures(),
      {
        fetchImpl: fetchWithStatus(400, {
          error: {
            code: "BadRequest",
            message: "Resource not found for the segment 'settings'.",
          },
        }),
      },
    );

    expect(sectionError).toBeUndefined();
    // The 400 kills only the /v1.0/settings try-block: rows 002/004/003 and the
    // on-premises check degrade, everything else still emits.
    const info = rows.find((r) => r.setting === "Custom Banned Password Protection");
    expect(info?.status).toBe("Info");
    expect(info?.currentValue).toBe(
      "Directory settings not configured (using Entra defaults)",
    );
    expect(rows.find((r) => r.setting === "Smart Lockout Threshold")).toBeUndefined();
  });

  it("treats an absent numberMatchingRequiredState as enforced and a missing Authenticator as Review (PS #998)", async () => {
    const fixtures = baseFixtures();
    fixtures["/v1.0/policies/authenticationMethodsPolicy"] = {
      registrationEnforcement: {
        authenticationMethodsRegistrationCampaign: { state: "enabled" },
      },
      authenticationMethodConfigurations: [
        { id: "Sms", state: "disabled" },
        { id: "Voice", state: "disabled" },
        { id: "Email", state: "disabled" },
      ],
    };

    const absent = await runCollectorOverFixtures(
      "identity",
      runPasswordAuthChecks,
      fixtures,
    );
    const fatigueRow = absent.rows.find(
      (r) => r.setting === "Authenticator Fatigue Protection",
    );
    expect(fatigueRow?.status).toBe("Review");
    expect(fatigueRow?.currentValue).toBe("Microsoft Authenticator not configured");

    // Authenticator present but Graph omits numberMatchingRequiredState —
    // absence means "enforced (mandatory)", not failure (#998). With app
    // context enabled the check PASSES despite the absent property.
    fixtures["/v1.0/policies/authenticationMethodsPolicy"] = {
      registrationEnforcement: {
        authenticationMethodsRegistrationCampaign: { state: "enabled" },
      },
      authenticationMethodConfigurations: [
        {
          id: "MicrosoftAuthenticator",
          featureSettings: {
            displayAppInformationRequiredState: { state: "disabled" },
          },
        },
      ],
    };
    const enforced = await runCollectorOverFixtures(
      "identity",
      runPasswordAuthChecks,
      fixtures,
    );
    const row = enforced.rows.find(
      (r) => r.setting === "Authenticator Fatigue Protection",
    );
    expect(row?.status).toBe("Fail");
    expect(row?.currentValue).toBe(
      "Number matching: enforced (mandatory); App context: disabled",
    );

    // System-preferred explicitly disabled is the only failing state (#999).
    fixtures["/v1.0/policies/authenticationMethodsPolicy"] = {
      registrationEnforcement: {
        authenticationMethodsRegistrationCampaign: { state: "enabled" },
      },
      systemCredentialPreferences: { state: "disabled" },
    };
    const sysPref = await runCollectorOverFixtures(
      "identity",
      runPasswordAuthChecks,
      fixtures,
    );
    const sysRow = sysPref.rows.find((r) => r.setting === "System-Preferred MFA");
    expect(sysRow?.status).toBe("Fail");
    expect(sysRow?.currentValue).toBe("disabled");
  });
});





