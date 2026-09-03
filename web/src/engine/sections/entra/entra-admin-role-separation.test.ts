/**
 * Parity tests for the Get-EntraAdminRoleSeparationConfig.ps1 port
 * (plan 02-06 task 2).
 *
 * PS Graph call sites being proven:
 *   1. Per privileged role: GET /v1.0/roleManagement/directory/roleAssignments?
 *      $filter=roleDefinitionId eq '<roleId>'&$top=999 (PS lines 71-76) —
 *      404-family failures SKIP that role (PS lines 84-91), others rethrow.
 *   2. Per admin user: GET /v1.0/users/<id>/licenseDetails (PS lines 116-122) —
 *      404-family skips the principal (PS lines 124-131).
 *
 * Golden run proves the 404 role-skip inside the happy path: three of the five
 * privileged roles have NO fixture (replay 404) and are skipped without error.
 *
 * Exchange detection: any sku whose servicePlans include one of the two
 * Exchange Online plan GUIDs marks the account mixed → Fail.
 */
import { describe, expect, it } from "vitest";
import { runEntraAdminRoleSeparation } from "./entra-admin-role-separation";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

const ROLE_KEY = (roleId: string) =>
  `/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%27${roleId}%27&$top=999`;
const LIC_KEY = (userId: string) => `/v1.0/users/${userId}/licenseDetails`;

const GA_ROLE = "62e90394-69f5-4237-9190-012177145e10";
const SEC_ADMIN_ROLE = "194ae4cb-b126-40b2-bd5b-6091b380977d";

function fetchWithStatus(status: number, body: unknown): typeof fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
}

describe("runEntraAdminRoleSeparation", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraAdminRoleSeparation,
      {
        [ROLE_KEY(GA_ROLE)]: readFixtureJson(
          "entra-admin-role-separation/v1.0_roleAssignments_GA.json",
        ),
        [ROLE_KEY(SEC_ADMIN_ROLE)]: readFixtureJson(
          "entra-admin-role-separation/v1.0_roleAssignments_SecAdmin.json",
        ),
        [LIC_KEY("aaaaaaaa-1111-4000-8000-000000000001")]: readFixtureJson(
          "entra-admin-role-separation/v1.0_users_ga1_licenseDetails.json",
        ),
        [LIC_KEY("aaaaaaaa-2222-4000-8000-000000000002")]: readFixtureJson(
          "entra-admin-role-separation/v1.0_users_sec1_licenseDetails.json",
        ),
      },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/entra-admin-role-separation.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("emits Pass with zero assignments when no privileged roles resolve to users", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraAdminRoleSeparation,
      {},
    );

    expect(sectionError).toBeUndefined();
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Pass");
    expect(rows[0].currentValue).toBe("No privileged role assignments found");
  });

  it("emits Fail when an admin user carries an Exchange Online service plan", async () => {
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runEntraAdminRoleSeparation,
      {
        [ROLE_KEY(GA_ROLE)]: {
          value: [{ id: "a1", principalId: "user-exo" }],
        },
        [LIC_KEY("user-exo")]: {
          value: [
            {
              skuId: "6fd2c87f-b296-42f0-b197-1e91e994b900",
              skuPartNumber: "ENTERPRISEPACK",
              servicePlans: [
                {
                  servicePlanId: "efb87545-963c-4e0d-99df-69c6916d9eb0",
                  serviceName: "EXCHANGE_S_ENTERPRISE",
                  provisioningStatus: "Success",
                },
              ],
            },
          ],
        },
      },
    );

    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Fail");
    expect(rows[0].currentValue).toBe(
      "1 of 1 admin account(s) have Exchange Online mailbox plans",
    );
  });

  it("skips principals whose licenseDetails 404 (deleted user / group principal)", async () => {
    // licenseDetails key absent → replay 404 → skipped; remaining admin count
    // is unaffected because the skip happens before counting? PS counts
    // $adminUserIds regardless — currentValue still names both admins.
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runEntraAdminRoleSeparation,
      {
        [ROLE_KEY(GA_ROLE)]: {
          value: [{ id: "a1", principalId: "gone-user" }],
        },
        [ROLE_KEY(SEC_ADMIN_ROLE)]: {
          value: [{ id: "a2", principalId: "live-user" }],
        },
        [LIC_KEY("live-user")]: { value: [] },
      },
    );

    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Pass");
    expect(rows[0].currentValue).toBe(
      "Admin accounts checked: 2 — none have Exchange Online plans",
    );
  });

  it("emits the Review insufficient-permissions row on a 403 (PS catch branch)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraAdminRoleSeparation,
      {},
      {
        fetchImpl: fetchWithStatus(403, {
          error: {
            code: "Authorization_RequestDenied",
            message: "Insufficient privileges to complete the operation.",
          },
        }),
      },
    );

    expect(sectionError).toBeUndefined();
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Review");
    expect(rows[0].currentValue).toBe("Insufficient permissions");
    expect(rows[0].remediation).toBe(
      "Requires RoleManagement.Read.Directory and Directory.Read.All permissions. Grant via Entra admin center or reconnect with additional scopes.",
    );
  });
});
