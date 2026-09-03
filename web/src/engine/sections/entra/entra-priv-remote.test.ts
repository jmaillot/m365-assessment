/**
 * Parity tests for the Get-EntraPrivRemoteConfig.ps1 port (plan 02-06 task 2).
 *
 * PS Graph call sites being proven:
 *   1. GET /v1.0/roleManagement/directory/roleAssignments?$filter=
 *      roleDefinitionId eq '<GlobalAdminRoleId>' (PS lines 57-62) — permanent
 *   2. GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances?
 *      $filter=roleDefinitionId eq '<GlobalAdminRoleId>' (PS lines 73-78) —
 *      PIM eligible, SOFT-FAIL: failure sets the eligibleNote and Review status
 *      (PS lines 84-88) — never fatal.
 *
 * Status ladder (PS lines 101-112): eligibleNote → Review; PIM in use and
 * permanent ≤ 2 → Pass; PIM in use → Warning; else Fail.
 */
import { describe, expect, it } from "vitest";
import { runEntraPrivRemote } from "./entra-priv-remote";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

const ACTIVE_KEY =
  "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27";
const ELIGIBLE_KEY =
  "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27";

function fetchWithStatus(status: number, body: unknown): typeof fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
}

describe("runEntraPrivRemote", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraPrivRemote,
      {
        [ACTIVE_KEY]: readFixtureJson(
          "entra-priv-remote/v1.0_roleManagement_directory_roleAssignments_GA.json",
        ),
        [ELIGIBLE_KEY]: readFixtureJson(
          "entra-priv-remote/v1.0_roleManagement_directory_roleEligibilityScheduleInstances_GA.json",
        ),
      },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/entra-priv-remote.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("emits Review with the PIM-unavailable note when the eligible query fails (PS soft-fail)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraPrivRemote,
      { [ACTIVE_KEY]: { value: [{ id: "a1", principalId: "u1" }] } },
    );

    expect(sectionError).toBeUndefined();
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Review");
    expect(rows[0].currentValue).toBe(
      "Permanent: 1, Eligible (PIM): PIM eligible assignments not available (requires Entra ID P2)",
    );
  });

  it("emits Warning when PIM is in use but permanent assignments exceed break-glass (PS lines 107-109)", async () => {
    const { rows } = await runCollectorOverFixtures("identity", runEntraPrivRemote, {
      [ACTIVE_KEY]: {
        value: Array.from({ length: 5 }, (_, i) => ({
          id: `a${i}`,
          principalId: `user-${i}`,
        })),
      },
      [ELIGIBLE_KEY]: { value: [{ id: "e1" }] },
    });

    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Warning");
    expect(rows[0].currentValue).toBe("Permanent: 5, Eligible (PIM): 1");
  });

  it("emits Fail when no eligible (PIM) assignments exist (PS lines 110-111)", async () => {
    const { rows } = await runCollectorOverFixtures("identity", runEntraPrivRemote, {
      [ACTIVE_KEY]: { value: [{ id: "a1" }, { id: "a2" }, { id: "a3" }] },
      [ELIGIBLE_KEY]: { value: [] },
    });

    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Fail");
    expect(rows[0].currentValue).toBe("Permanent: 3, Eligible (PIM): 0");
  });

  it("emits the Review insufficient-permissions row on a 403 (PS catch branch)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraPrivRemote,
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
      "Requires RoleManagement.Read.Directory permission. Entra ID P2 license required for PIM.",
    );
  });
});
