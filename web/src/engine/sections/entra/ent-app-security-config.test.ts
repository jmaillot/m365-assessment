/**
 * Parity tests for the Get-EntAppSecurityConfig.ps1 port (plan 02-10) —
 * '07d-EntApp-Security-Config', the second-largest Entra collector (1,150 PS
 * lines).
 *
 * PS Graph call sites being proven:
 *   1. GET /v1.0/organization (tenant id for foreign-app detection; soft-fail → null)
 *   2. GET /v1.0/servicePrincipals?$select=…&$top=999 (soft-fail → empty, PS 168-180)
 *   3. GET /v1.0/roleManagement/directory/roleAssignments?$top=999 (soft-fail → no map)
 *   4. GET /v1.0/servicePrincipals?$filter=appId eq '00000003-…' (permission map; soft-fail)
 *   5. GET /v1.0/oauth2PermissionGrants?$top=999 (soft-fail → no map)
 *   6. GET /v1.0/servicePrincipals/{graphSpId}/appRoleAssignedTo?$top=999 (soft-fail)
 *   7. GET /v1.0/applications?$select=…&$top=999 (soft-fail → empty)
 *   8. GET /v1.0/policies/defaultAppManagementPolicy (check 007; soft-fail → Info row)
 *   9. GET /v1.0/servicePrincipals/{id}?$select=signInActivity per credentialed SP (check 002)
 *  10. GET /v1.0/servicePrincipals/{id}/owners?$select=id,displayName (checks 016/017)
 *      and ?$select=id (check 018) per target SP; probe errors skip that SP.
 *
 * Tier classification data comes from the bundled controls/tier0-permissions.json
 * and microsoft-first-party-appids.json (same files the PS collector reads).
 */
import { describe, expect, it } from "vitest";
import {
  runEntAppSecurityConfig,
  ENT_APP_SECURITY_CONFIG_ENDPOINTS as EP,
} from "./ent-app-security-config";
import { goldenToExpected, readFixtureJson, runCollectorOverFixtures } from "./test-support";

const TENANT = "aaaaaaaa-aaaa-4000-8000-aaaaaaaaaaaa";

/** Empty-tenant fixture set: org known, zero SPs/grants/apps. */
function emptyTenantFixtures(): Record<string, unknown> {
  return {
    "/v1.0/organization": { value: [{ id: TENANT }] },
    [EP.servicePrincipals]: { value: [] },
    [EP.roleAssignments]: { value: [] },
    [EP.graphSp]: { value: [] },
    [EP.oauth2Grants]: { value: [] },
    [EP.applications]: { value: [] },
    // defaultAppManagementPolicy intentionally absent → soft-fail → Info row.
  };
}

describe("runEntAppSecurityConfig — fetch semantics", () => {
  it("produces exactly the PS empty-data rows for the first half on a bare tenant", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntAppSecurityConfig,
      emptyTenantFixtures(),
    );

    expect(sectionError).toBeUndefined();
    expect(rows.slice(0, 11)).toEqual([
      {
        category: "Enterprise Applications",
        setting: "Apps with Client Credentials",
        currentValue: "0 enabled app(s) have secrets or certificates",
        recommendedValue: "Review all apps with credentials; remove unused",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-001.1",
        remediation:
          "Entra admin center > Enterprise applications > review each app with credentials. Remove secrets/certificates from apps that no longer need them.",
        intentDesign: false,
      },
      {
        category: "Enterprise Applications",
        setting: "Inactive Apps with Credentials",
        currentValue: "No inactive apps with credentials found",
        recommendedValue: "Remove credentials from inactive apps",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-002.1",
        remediation:
          "Review the following inactive apps and remove their credentials or disable them: Entra admin center > Enterprise applications > filter by last sign-in > remove secrets/certificates.",
        intentDesign: false,
      },
      {
        category: "Enterprise Applications",
        setting: "Foreign Apps with Tier 0 Permissions (GA Escalation)",
        currentValue: "No third-party apps with Tier 0 permissions",
        recommendedValue:
          "No third-party apps should hold Tier 0 (Global Admin escalation) permissions",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-003.1",
        remediation:
          "Entra admin center > Enterprise applications > review third-party apps with Tier 0 permissions. These permissions have documented attack paths to Global Administrator. Remove or replace with least-privilege alternatives. Microsoft first-party apps are listed separately in the evidence and are expected to hold these permissions.",
        intentDesign: false,
      },
      {
        category: "Enterprise Applications",
        setting: "Foreign Apps with Tier 1 Permissions (Data Access)",
        currentValue: "No third-party apps with Tier 1 data access permissions",
        recommendedValue: "Minimize third-party apps with broad data access permissions",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-011.1",
        remediation:
          "Entra admin center > Enterprise applications > review third-party apps with broad data access (Mail.ReadWrite, Files.ReadWrite.All, etc.). Scope to least-privilege or remove. Microsoft first-party apps are listed separately in the evidence.",
        intentDesign: false,
      },
      {
        category: "Enterprise Applications",
        setting: "Foreign Apps with Dangerous Delegated Permissions",
        currentValue: "No third-party apps with dangerous delegated permissions",
        recommendedValue: "No third-party apps should hold dangerous delegated permissions",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-004.1",
        remediation:
          "Entra admin center > Enterprise applications > review third-party apps with high-privilege delegated permissions. Revoke admin consent or remove the app. Microsoft first-party apps are listed separately in the evidence.",
        intentDesign: false,
      },
      {
        category: "Enterprise Applications",
        setting: "Foreign Apps with Directory Roles",
        currentValue: "No third-party apps hold directory roles",
        recommendedValue: "No third-party apps should hold Entra directory roles",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-005.1",
        remediation:
          "Entra admin center > Roles and administrators > review roles assigned to third-party service principals. Remove role assignments from untrusted external apps. Microsoft first-party apps are listed separately in the evidence.",
        intentDesign: false,
      },
      {
        category: "Enterprise Applications",
        setting: "Apps with Excessive Permissions",
        currentValue: "No apps with > 10 application permissions",
        recommendedValue: "Apps should follow least-privilege (max 10 app permissions)",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-006.1",
        remediation:
          "Review apps with > 10 application permissions. Remove unnecessary permissions to follow least-privilege. Entra admin center > App registrations > API permissions.",
        intentDesign: false,
      },
      {
        category: "Enterprise Applications",
        setting: "App Instance Property Lock",
        currentValue: "No default app management policy or disabled",
        recommendedValue:
          "App management policy enabled to prevent property modifications by app owners",
        status: "Info",
        checkId: "ENTRA-ENTAPP-007.1",
        remediation:
          "Entra admin center > Applications > App management policies > configure a default policy to lock sensitive properties on multi-tenant apps.",
        intentDesign: false,
      },
      {
        category: "Managed Identities",
        setting: "Managed Identities with Dangerous Permissions",
        currentValue: "No managed identities with dangerous permissions",
        recommendedValue: "Managed identities should follow least-privilege",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-008.1",
        remediation:
          "Review managed identity permissions. Use narrower permissions (e.g., Mail.Read instead of Mail.ReadWrite). Azure portal > Managed Identity > API permissions.",
        intentDesign: false,
      },
      {
        category: "Managed Identities",
        setting: "Managed Identities with Directory Roles",
        currentValue: "No managed identities hold directory roles",
        recommendedValue: "Managed identities should not hold Entra directory roles",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-009.1",
        remediation:
          "Review managed identities with directory roles. Use Graph API permissions instead of directory roles where possible. Entra admin center > Roles and administrators.",
        intentDesign: false,
      },
      {
        category: "Enterprise Applications",
        setting: "Internal Apps with Tier 0 Permissions (GA Escalation)",
        currentValue: "No internal apps with Tier 0 permissions",
        recommendedValue: "Minimize internal apps with Tier 0 permissions; use least-privilege",
        status: "Pass",
        checkId: "ENTRA-ENTAPP-010.1",
        remediation:
          "Entra admin center > App registrations > review internal apps with Tier 0 permissions. Each has a documented path to Global Administrator. Replace with narrower permissions or use managed identities where possible.",
        intentDesign: false,
      },
    ]);
  });

  it("soft-fails every bulk fetch to the same empty-data rows when all endpoints error", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntAppSecurityConfig,
      {},
      // Every endpoint fails like a 500 — PS Write-Warning + continue parity.
      {
        fetchImpl: async () =>
          new Response(
            JSON.stringify({ error: { code: "serverError", message: "boom" } }),
            { status: 500, headers: { "content-type": "application/json" } },
          ),
      },
    );

    expect(sectionError).toBeUndefined();
    // First-half shape identical to the bare tenant except check 001's count
    // line is unchanged ('0 enabled app(s)...'), and 003/005/006/008-010 Pass.
    const settings = rows.slice(0, 11).map((r) => r.setting);
    expect(settings).toEqual([
      "Apps with Client Credentials",
      "Inactive Apps with Credentials",
      "Foreign Apps with Tier 0 Permissions (GA Escalation)",
      "Foreign Apps with Tier 1 Permissions (Data Access)",
      "Foreign Apps with Dangerous Delegated Permissions",
      "Foreign Apps with Directory Roles",
      "Apps with Excessive Permissions",
      "App Instance Property Lock",
      "Managed Identities with Dangerous Permissions",
      "Managed Identities with Directory Roles",
      "Internal Apps with Tier 0 Permissions (GA Escalation)",
    ]);
    expect(rows.slice(0, 11).every((r) => r.status === "Pass" || r.status === "Info")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Shared foreign-app risk fixture: one third-party foreign app holding a Tier
// 0 + Tier 1 Graph app permission + a dangerous delegated grant + a directory
// role, one Microsoft first-party foreign app (allowlisted), one managed
// identity with a Tier 1 permission, and an internal app with Tier 0 + excess
// permission count.
// ---------------------------------------------------------------------------
const OTHER_TENANT = "bbbbbbbb-bbbb-4000-8000-bbbbbbbbbbbb";

function riskFixtureSet(): Record<string, unknown> {
  return {
    "/v1.0/organization": { value: [{ id: TENANT }] },
    [EP.servicePrincipals]: {
      value: [
        {
          id: "fp-1",
          appId: "11111111-1111-4000-8000-111111111111",
          displayName: "Foreign App",
          appOwnerOrganizationId: OTHER_TENANT,
          servicePrincipalType: "Application",
          keyCredentials: [],
          passwordCredentials: [{ endDateTime: "2099-01-01T00:00:00Z" }],
          accountEnabled: true,
        },
        {
          id: "msfp-1",
          appId: "cf36786e-4887-47a3-a492-dfd0e2ff32c2",
          displayName: "Microsoft Foo",
          appOwnerOrganizationId: "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
          servicePrincipalType: "Application",
          keyCredentials: [],
          passwordCredentials: [],
          accountEnabled: true,
        },
        {
          id: "mi-1",
          appId: "22222222-2222-4000-8000-222222222222",
          displayName: "MI One",
          appOwnerOrganizationId: TENANT,
          servicePrincipalType: "ManagedIdentity",
          keyCredentials: [],
          passwordCredentials: [],
          accountEnabled: true,
        },
        {
          id: "int-1",
          appId: "33333333-3333-4000-8000-333333333333",
          displayName: "Internal App",
          appOwnerOrganizationId: TENANT,
          servicePrincipalType: "Application",
          keyCredentials: [{ endDateTime: "2099-06-01T00:00:00Z" }],
          passwordCredentials: [],
          accountEnabled: true,
        },
      ],
    },
    [EP.roleAssignments]: {
      value: [{ principalId: "fp-1", roleDefinitionId: "ga-role" }],
    },
    [EP.graphSp]: {
      value: [
        {
          id: "graph-sp",
          appId: "00000003-0000-0000-c000-000000000000",
          appRoles: [
            { id: "role-tier0", value: "Application.ReadWrite.All" },
            { id: "role-tier1", value: "Mail.ReadWrite" },
          ],
          oauth2PermissionScopes: [
            { id: "scope-deleg", value: "Directory.ReadWrite.All" },
          ],
        },
      ],
    },
    [`/v1.0/servicePrincipals/graph-sp/appRoleAssignedTo?$top=999`]: {
      value: [
        { principalId: "fp-1", appRoleId: "role-tier0" },
        { principalId: "fp-1", appRoleId: "role-tier1" },
        { principalId: "mi-1", appRoleId: "role-tier1" },
        // Internal app carries its Tier 0 plus ten unmapped grants → check 006.
        { principalId: "int-1", appRoleId: "role-tier0" },
        ...Array.from({ length: 10 }, (_, i) => ({
          principalId: "int-1",
          appRoleId: `junk-${i}`,
        })),
      ],
    },
    [EP.oauth2Grants]: {
      value: [
        { clientId: "fp-1", scope: "Directory.ReadWrite.All User.Read" },
        { clientId: "msfp-1", scope: "Mail.ReadWrite" },
      ],
    },
    [EP.applications]: { value: [] },
    "/v1.0/policies/defaultAppManagementPolicy": { isEnabled: true },
    "/v1.0/servicePrincipals/fp-1?$select=signInActivity": {
      signInActivity: { lastSignInDateTime: "2000-01-01T00:00:00Z" },
    },
  };
}

describe("runEntAppSecurityConfig — first-half decision ladders", () => {
  let cachedRows: Awaited<ReturnType<typeof bootstrap>> | undefined;

  async function bootstrap() {
    return runCollectorOverFixtures("identity", runEntAppSecurityConfig, riskFixtureSet());
  }

  it.each([
    [
      "ENTRA-ENTAPP-001 counts enabled credentialed apps → Info (≤10)",
      "Apps with Client Credentials",
      "Info",
      "2 enabled app(s) have secrets or certificates",
    ],
    [
      "ENTRA-ENTAPP-002 flags stale sign-in via per-SP signInActivity probe → Fail",
      "Inactive Apps with Credentials",
      "Fail",
      "1 app(s) inactive > 90 days with credentials",
    ],
    [
      "ENTRA-ENTAPP-003 reports third-party Tier 0 findings → Fail",
      "Foreign Apps with Tier 0 Permissions (GA Escalation)",
      "Fail",
      "1 finding(s): Foreign App: Application.ReadWrite.All",
    ],
    [
      "ENTRA-ENTAPP-011 reports third-party Tier 1 findings → Warning",
      "Foreign Apps with Tier 1 Permissions (Data Access)",
      "Warning",
      "1 finding(s): Foreign App: Mail.ReadWrite",
    ],
    [
      "ENTRA-ENTAPP-004 reports dangerous delegated grants → Fail",
      "Foreign Apps with Dangerous Delegated Permissions",
      "Fail",
      "1 finding(s): Foreign App: Directory.ReadWrite.All" +
        " | 1 Microsoft first-party app(s) with these permissions (expected, not counted)",
    ],
    [
      "ENTRA-ENTAPP-005 reports role-holding foreign apps → Fail",
      "Foreign Apps with Directory Roles",
      "Fail",
      "1 third-party app(s) with roles: Foreign App (1 role(s))",
    ],
    [
      "ENTRA-ENTAPP-006 flags >10 app permissions → Warning",
      "Apps with Excessive Permissions",
      "Warning",
      "1 app(s): Internal App (11 permissions)",
    ],
    [
      "ENTRA-ENTAPP-007 honors defaultAppManagementPolicy.isEnabled → Pass",
      "App Instance Property Lock",
      "Pass",
      "Default app management policy enabled",
    ],
    [
      "ENTRA-ENTAPP-008 flags managed identity dangerous perms → Fail",
      "Managed Identities with Dangerous Permissions",
      "Fail",
      "1 finding(s): MI One: Mail.ReadWrite",
    ],
    [
      "ENTRA-ENTAPP-010 flags internal Tier 0 apps → Warning",
      "Internal Apps with Tier 0 Permissions (GA Escalation)",
      "Warning",
      "1 finding(s): Internal App: Application.ReadWrite.All",
    ],
  ])("%s", async (_label, setting, status, currentValue) => {
    cachedRows ??= await bootstrap();
    const row = cachedRows.rows.find((r) => r.setting === setting);
    expect(row).toBeDefined();
    expect(row?.status).toBe(status);
    expect(row?.currentValue).toBe(currentValue);
  });

  it("classifies the allowlisted Microsoft owner tenant as first-party, not third-party", async () => {
    cachedRows ??= await bootstrap();
    const tier0Row = cachedRows.rows.find(
      (r) => r.setting === "Foreign Apps with Tier 0 Permissions (GA Escalation)",
    );
    // msfp-1 holds no Tier 0 grants here, but must not appear in any finding.
    expect(tier0Row?.currentValue).not.toContain("Microsoft Foo");
    // The delegated check DOES see its Mail.ReadWrite grant — as the expected
    // first-party suffix, never as a Fail-driving finding.
    const delegatedRow = cachedRows.rows.find(
      (r) => r.setting === "Foreign Apps with Dangerous Delegated Permissions",
    );
    expect(delegatedRow?.currentValue).toBe(
      "1 finding(s): Foreign App: Directory.ReadWrite.All" +
        " | 1 Microsoft first-party app(s) with these permissions (expected, not counted)",
    );
  });

  it("emits Info when the default app management policy is missing entirely", async () => {
    const fixtures = riskFixtureSet();
    delete fixtures["/v1.0/policies/defaultAppManagementPolicy"];
    const { rows } = await runCollectorOverFixtures("identity", runEntAppSecurityConfig, fixtures);
    expect(rows.find((r) => r.setting === "App Instance Property Lock")).toMatchObject({
      status: "Info",
      currentValue: "No default app management policy or disabled",
    });
  });

  it("treats signInActivity probe failures as active (PS catch → Verbose skip)", async () => {
    const fixtures = riskFixtureSet();
    delete fixtures["/v1.0/servicePrincipals/fp-1?$select=signInActivity"];
    const { rows } = await runCollectorOverFixtures("identity", runEntAppSecurityConfig, fixtures);
    expect(rows.find((r) => r.setting === "Inactive Apps with Credentials")).toMatchObject({
      status: "Pass",
      currentValue: "No inactive apps with credentials found",
    });
  });
});

// ---------------------------------------------------------------------------
// Remaining sections (checks ENTRA-ENTAPP-012..021 + APPREG-002/003/004)
// proven over the committed comprehensive fixture set.
// ---------------------------------------------------------------------------
const COMPREHENSIVE = "ent-app-security-config/comprehensive.json";

describe("runEntAppSecurityConfig — credential hygiene, owners, registrations", () => {
  it.each([
    [
      "ENTRA-ENTAPP-012 lists enabled secret-only apps → Warning",
      "Apps Using Secrets Instead of Certificates",
      "Warning",
      "3 app(s): Third Party App; Expired Cred App; Internal App",
    ],
    [
      "ENTRA-ENTAPP-013 flags expired credentials (any enabled state) → Warning",
      "Apps with Expired Credentials",
      "Warning",
      "1 app(s): Expired Cred App",
    ],
    [
      "ENTRA-ENTAPP-014 flags dual credential types → Info",
      "Apps with Both Secrets and Certificates",
      "Info",
      "1 app(s): Dual Cred App",
    ],
    [
      "ENTRA-ENTAPP-015 combines secrets with directory roles → Fail",
      "SPs with Secret + Permanent Directory Role",
      "Fail",
      "2 SP(s): Third Party App (1 role(s)); Internal App (2 role(s))",
    ],
    [
      "ENTRA-ENTAPP-016 lists Tier 0 apps that have owners → Fail",
      "Tier 0 Apps with Owners Assigned",
      "Fail",
      "2 app(s): Third Party App (owners: Owner One); Microsoft Graph Helper (owners: Imp Owner)",
    ],
    [
      "ENTRA-ENTAPP-017 lists role-holding apps that have owners → Warning",
      "Role-Holding Apps with Owners",
      "Warning",
      "1 app(s): Third Party App (owners: Owner One)",
    ],
    [
      "ENTRA-ENTAPP-018 lists orphaned credentialed apps → Warning",
      "Credentialed Apps with No Owners",
      "Warning",
      "3 orphaned app(s): Expired Cred App; Internal App; Disabled Internal",
    ],
    [
      "ENTRA-ENTAPP-019 counts Tier 0 apps with no sign-in activity property → Warning",
      "Tier 0 Apps with No Sign-In Activity",
      "Warning",
      "3 app(s) with Tier 0 perms and no sign-in: Third Party App; Microsoft Graph Helper; Internal App",
    ],
    [
      "ENTRA-APPREG-002 collects localhost/loopback redirect URIs → Warning",
      "Apps with Localhost Redirect URIs",
      "Warning",
      "3 app(s): Localhost App; Public Client App; IPv6 Local",
    ],
    [
      "ENTRA-APPREG-003 flags non-localhost HTTP URIs (web/spa only) → Fail",
      "Apps with HTTP (Non-HTTPS) Redirect URIs",
      "Fail",
      "1 app(s): Webby App",
    ],
    [
      "ENTRA-APPREG-004 flags wildcard redirect URIs → Fail",
      "Apps with Wildcard Redirect URIs",
      "Fail",
      "1 app(s): Wildcard App",
    ],
    [
      "ENTRA-ENTAPP-020 catches third-party impersonation, skips first-party → Fail",
      "Foreign Apps Impersonating Microsoft Names",
      "Fail",
      "1 app(s): Microsoft Graph Helper (AppId: 44444444-4444-4000-8000-444444444444)",
    ],
    [
      "ENTRA-ENTAPP-021 lists multi-tenant audiences → Info",
      "Multi-Tenant App Registrations",
      "Info",
      "1 app(s): Multitenant App (AzureADMultipleOrgs)",
    ],
  ])("%s", async (_label, setting, status, currentValue) => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    const { rows } = await runCollectorOverFixtures("identity", runEntAppSecurityConfig, fixtures);
    const row = rows.find((r) => r.setting === setting);
    expect(row).toBeDefined();
    expect(row?.status).toBe(status);
    expect(row?.currentValue).toBe(currentValue);
  });

  it("skips an SP from the orphan scan when its owners probe errors (PS catch per SP)", async () => {
    // Dual Cred App's ?$select=id owners probe is intentionally absent from the
    // comprehensive fixture → 404 → PS Write-Verbose skip.
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    expect(fixtures["/v1.0/servicePrincipals/tp-dual/owners?$select=id"]).toBeUndefined();
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntAppSecurityConfig,
      fixtures,
    );
    expect(sectionError).toBeUndefined();
    const orphans = rows.find((r) => r.checkId === "ENTRA-ENTAPP-018.1");
    expect(orphans?.currentValue).not.toContain("Dual Cred App");
  });

  it("falls back to empty-data Pass rows when /applications fails (PS soft-fail parity)", async () => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    delete fixtures[EP.applications];
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntAppSecurityConfig,
      fixtures,
    );
    expect(sectionError).toBeUndefined();
    // Empty registrations → the PS zero-data branches, not dropped rows.
    const byCheck = new Map(rows.map((r) => [r.checkId, r]));
    expect(byCheck.get("ENTRA-APPREG-002.1")).toMatchObject({
      status: "Pass",
      currentValue: "No apps have localhost redirect URIs",
    });
    expect(byCheck.get("ENTRA-APPREG-003.1")).toMatchObject({
      status: "Pass",
      currentValue: "No apps have insecure HTTP redirect URIs",
    });
    expect(byCheck.get("ENTRA-APPREG-004.1")).toMatchObject({
      status: "Pass",
      currentValue: "No apps have wildcard redirect URIs",
    });
    expect(byCheck.get("ENTRA-ENTAPP-021.1")).toMatchObject({
      status: "Pass",
      currentValue: "No multi-tenant app registrations",
    });
  });

  it("degrades tier findings AND the resource-side grant map when the Graph SP fetch fails", async () => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    delete fixtures[EP.graphSp];
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntAppSecurityConfig,
      fixtures,
    );
    expect(sectionError).toBeUndefined();
    // No permission mapping → zero tier findings anywhere.
    for (const base of ["003", "010"]) {
      expect(
        rows.find((r) => r.checkId === `ENTRA-ENTAPP-${base}.1`)?.currentValue,
      ).not.toContain("finding");
    }
    // The appRoleAssignedTo bulk fetch is keyed on the Graph SP's id
    // ($graphSpValue['id'], PS 261-263), so it never happens either — check 006
    // sees zero assignments and Passes (PS parity).
    expect(rows.find((r) => r.checkId === "ENTRA-ENTAPP-006.1")).toMatchObject({
      status: "Pass",
      currentValue: "No apps with > 10 application permissions",
    });
  });
});

describe("runEntAppSecurityConfig — golden parity + CheckId inventory", () => {
  it("matches the hand-traced PS golden rows for ALL check sections over the comprehensive fixture set", async () => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/ent-app-security-config.json",
    );

    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntAppSecurityConfig,
      fixtures,
    );

    expect(sectionError).toBeUndefined();
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("emits every CheckId base the PS collector emits, under identical conditions", async () => {
    const fixtures = readFixtureJson<Record<string, unknown>>(COMPREHENSIVE);
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/ent-app-security-config.json",
    );
    const expectedBases = [
      "ENTRA-APPREG-002",
      "ENTRA-APPREG-003",
      "ENTRA-APPREG-004",
      ...Array.from({ length: 21 }, (_, i) => `ENTRA-ENTAPP-${String(i + 1).padStart(3, "0")}`),
    ].sort();

    const emittedBases = golden.map((g) => String(g.checkId).replace(/\.\d+$/, ""));
    expect([...new Set(emittedBases)].sort()).toEqual(expectedBases);

    const { rows } = await runCollectorOverFixtures("identity", runEntAppSecurityConfig, fixtures);
    expect(rows.map((r) => r.checkId.replace(/\.\d+$/, "")).sort()).toEqual(expectedBases);
  });
});
