/**
 * Parity tests for the Get-EntraTouConfig.ps1 port (plan 02-06 task 1).
 *
 * PS Graph call site being proven:
 *   1. Invoke-MgGraphRequest GET /v1.0/agreements (PS lines 46-51)
 *
 * Branch parity (PS lines 60-95):
 *   - ≥1 agreement with isViewingBeforeAcceptanceRequired → Pass
 *   - agreements exist, none require viewing before acceptance → Warning
 *   - no agreements → Fail
 *   - 403/Forbidden/Authorization error → Review 'Insufficient permissions' row
 *   - any other error → Write-Warning + zero rows, NO section error
 */
import { describe, expect, it } from "vitest";
import { runEntraTouConfig } from "./entra-tou-config";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

function fetchWithStatus(status: number, body: unknown): typeof fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
}

describe("runEntraTouConfig", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraTouConfig,
      {
        "/v1.0/agreements": readFixtureJson("entra-tou-config/v1.0_agreements.json"),
      },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/entra-tou-config.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("emits Warning when agreements exist but none require viewing before acceptance (PS line 61)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraTouConfig,
      {
        "/v1.0/agreements": {
          value: [
            { id: "a1", displayName: "Guest ToU", isViewingBeforeAcceptanceRequired: false },
          ],
        },
      },
    );

    expect(sectionError).toBeUndefined();
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Warning");
    expect(rows[0].currentValue).toBe(
      "Agreement exists but acceptance not required before viewing",
    );
    expect(rows[0].checkId).toBe("ENTRA-TOU-001.1");
  });

  it("emits Fail when no agreements are configured (PS default branch)", async () => {
    const { rows } = await runCollectorOverFixtures("identity", runEntraTouConfig, {
      "/v1.0/agreements": { value: [] },
    });

    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Fail");
    expect(rows[0].currentValue).toBe("No agreements configured");
  });

  it("emits the Review insufficient-permissions row on a 403 (PS catch branch)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraTouConfig,
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
    expect(rows[0].recommendedValue).toBe(
      "At least one Terms of Use agreement configured and assigned",
    );
    expect(rows[0].remediation).toBe("Requires Agreement.Read.All permission.");
    expect(rows[0].checkId).toBe("ENTRA-TOU-001.1");
  });

  it("degrades to zero rows without a section error on non-authorization failures (PS Write-Warning)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraTouConfig,
      {},
      { fetchImpl: fetchWithStatus(500, { error: { code: "serverError", message: "boom" } }) },
    );

    expect(rows).toEqual([]);
    expect(sectionError).toBeUndefined();
  });
});
