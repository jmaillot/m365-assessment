/**
 * Parity tests for the Get-EntraSoDConfig.ps1 port (plan 02-06 task 1).
 *
 * PS Graph call sites being proven (PS lines 52-77):
 *   1. GET /v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId
 *      eq '<GlobalAdminRoleId>'&$top=999&$expand=principal
 *   2. Same URL for the Privileged Role Admin role id
 *
 * Fixture keys carry the %20/%27 encoding `new URL(...)` normalization produces
 * (replay.ts normalizeUrlKey parity — see __fixtures__/README.md).
 *
 * Branch parity: Pass requires ≥2 GA principals, ≥1 PRA principal, zero
 * overlap; else Fail. 403-family errors → Review row; other errors →
 * Write-Warning + zero rows.
 */
import { describe, expect, it } from "vitest";
import { runEntraSodConfig } from "./entra-sod-config";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

const GA_KEY =
  "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27&$top=999&$expand=principal";
const PRA_KEY =
  "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%27e8611ab8-c189-46e8-94e1-60213ab1f814%27&$top=999&$expand=principal";

function fetchWithStatus(status: number, body: unknown): typeof fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
}

describe("runEntraSodConfig", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraSodConfig,
      {
        [GA_KEY]: readFixtureJson("entra-sod-config/v1.0_roleManagement_directory_roleAssignments_GA.json"),
        [PRA_KEY]: readFixtureJson("entra-sod-config/v1.0_roleManagement_directory_roleAssignments_PRA.json"),
      },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/entra-sod-config.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("emits Fail when a single principal holds both roles (overlap > 0)", async () => {
    const { rows } = await runCollectorOverFixtures("identity", runEntraSodConfig, {
      [GA_KEY]: {
        value: [
          { id: "a1", principalId: "11111111-1111-4000-8000-000000000001" },
          { id: "a2", principalId: "22222222-2222-4000-8000-000000000002" },
        ],
      },
      [PRA_KEY]: {
        value: [{ id: "p1", principalId: "11111111-1111-4000-8000-000000000001" }],
      },
    });

    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Fail");
    expect(rows[0].currentValue).toBe("Global Admins: 2, Priv Role Admins: 1, Overlap: 1");
  });

  it("emits the Review insufficient-permissions row on a 403 (PS catch branch)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraSodConfig,
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
      "Requires RoleManagement.Read.Directory and Directory.Read.All permissions.",
    );
  });

  it("degrades to zero rows without a section error on non-authorization failures (PS Write-Warning)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraSodConfig,
      {},
      { fetchImpl: fetchWithStatus(500, { error: { code: "serverError", message: "boom" } }) },
    );

    expect(rows).toEqual([]);
    expect(sectionError).toBeUndefined();
  });
});
