/**
 * Parity tests for the Get-EntraCaRemoteDevicePolicy.ps1 port
 * (plan 02-06 task 2).
 *
 * PS Graph call site being proven:
 *   1. GET /v1.0/identity/conditionalAccess/policies (PS lines 48-53)
 *
 * Selection loop parity (PS lines 61-81): disabled policies skipped; policies
 * without grantControls or compliantDevice skipped; no excludeLocations
 * skipped; first ENABLED match wins (break); report-only kept as fallback.
 */
import { describe, expect, it } from "vitest";
import { runEntraCaRemoteDevice } from "./entra-ca-remote-device";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

const POLICIES_KEY = "/v1.0/identity/conditionalAccess/policies";

function fetchWithStatus(status: number, body: unknown): typeof fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
}

describe("runEntraCaRemoteDevice", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraCaRemoteDevice,
      {
        [POLICIES_KEY]: readFixtureJson(
          "entra-ca-remote-device/v1.0_identity_conditionalAccess_policies.json",
        ),
      },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/entra-ca-remote-device.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("emits Warning when only a report-only policy matches (PS lines 95-106)", async () => {
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runEntraCaRemoteDevice,
      {
        [POLICIES_KEY]: {
          value: [
            {
              id: "p1",
              displayName: "Report only device policy",
              state: "enabledForReportingButNotEnforced",
              grantControls: { builtInControls: ["compliantDevice"] },
              conditions: { locations: { excludeLocations: ["corp"] } },
            },
          ],
        },
      },
    );

    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Warning");
    expect(rows[0].currentValue).toBe(
      "Report-only: 'Report only device policy' - not enforced",
    );
    expect(rows[0].remediation).toBe(
      "Change the CA policy state from report-only to enabled to enforce compliant device requirements.",
    );
  });

  it("emits Fail when no policy requires compliantDevice with a location exclusion", async () => {
    const { rows } = await runCollectorOverFixtures("identity", runEntraCaRemoteDevice, {
      [POLICIES_KEY]: { value: [] },
    });

    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("Fail");
    expect(rows[0].currentValue).toBe(
      "No CA policy found requiring compliantDevice with a named location exclusion",
    );
  });

  it("emits the Review insufficient-permissions row on a 403 (PS catch branch)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runEntraCaRemoteDevice,
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
    expect(rows[0].currentValue).toBe(
      "Insufficient permissions (Policy.Read.All required)",
    );
    expect(rows[0].checkId).toBe("CA-REMOTEDEVICE-001.1");
  });
});
