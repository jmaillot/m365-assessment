/**
 * Parity tests for the Get-AdminRoleReport.ps1 port (plan 02-05 task 2).
 *
 * PS Graph call sites being proven (documented per acceptance criteria):
 *   1. Get-MgDirectoryRole -All            → GET /v1.0/directoryRoles
 *   2. Get-MgDirectoryRoleMember -All      → GET /v1.0/directoryRoles/{id}/members
 *   3. Get-MgUser -Property OnPremisesSyncEnabled → GET /v1.0/users/{id}?$select=onPremisesSyncEnabled
 *
 * Branch parity: roles-fetch failure surfaces a section error with zero rows
 * (PS Write-Error + return); a member-fetch failure skips that role only
 * (PS Write-Warning + continue); memberless roles are skipped (PS lines 62-65).
 */
import { describe, expect, it } from "vitest";
import { runAdminRoleReport } from "./admin-role-report";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

describe("runAdminRoleReport", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runAdminRoleReport,
      {
        "/v1.0/directoryRoles": readFixtureJson("admin-role-report/v1.0_directoryRoles.json"),
        "/v1.0/directoryRoles/role-1/members": readFixtureJson("admin-role-report/v1.0_directoryRoles_role-1_members.json"),
        "/v1.0/directoryRoles/role-2/members": readFixtureJson("admin-role-report/v1.0_directoryRoles_role-2_members.json"),
        "/v1.0/users/u1?$select=onPremisesSyncEnabled": readFixtureJson("admin-role-report/v1.0_users_u1_$select_onPremisesSyncEnabled.json"),
      },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/admin-role-report.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("surfaces a section error when the directory-roles retrieval fails (PS Write-Error parity)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runAdminRoleReport,
      {},
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeDefined();
  });

  it("skips roles whose members cannot be retrieved (PS continue parity) without a section error", async () => {
    // Roles resolve but every members fetch fails → each role is skipped.
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runAdminRoleReport,
      {
        "/v1.0/directoryRoles": readFixtureJson("admin-role-report/v1.0_directoryRoles.json"),
      },
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeUndefined();
  });
});
