/**
 * Parity tests for the EntraConditionalAccessChecks.ps1 port (plan 02-08
 * task 1).
 *
 * PS Graph call sites being proven:
 *   1. GET /v1.0/identity/conditionalAccess/policies (PS section 11 — policy
 *      counts; PS routed through Invoke-SafeGraphRequest, the TS transport
 *      provides retry/backoff natively).
 *   2. GET /v1.0/policies/deviceRegistrationPolicy (PS section 13, CIS
 *      5.1.4.1-5.1.4.3: join restriction, device quota, GA local admins).
 *   3. GET /beta/policies/deviceRegistrationPolicy → promoted to v1.0 per
 *      BETA-ENDPOINTS.md (PS section 19 extended reads: additional local
 *      admins count + LAPS). The second fetch is preserved for call parity.
 */
import { describe, expect, it } from "vitest";
import {
  CA_CHECKS_ENDPOINTS as EP,
  runConditionalAccessChecks,
} from "./conditional-access-checks";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";
import { createReplayFetch, normalizeUrlKey } from "@/engine/__fixtures__/replay";

function fileFixture(name: string): unknown {
  return readFixtureJson(`conditional-access-checks/${name}.json`);
}

/** Full happy-path fixture set (matches golden/conditional-access-checks.json). */
function baseFixtures(): Record<string, unknown> {
  return {
    [EP.caPolicies]: fileFixture("v1.0_identity_conditionalAccess_policies"),
    [EP.deviceRegistrationPolicy]: fileFixture("v1.0_policies_deviceRegistrationPolicy"),
  };
}

/** Replay wrapper that fails one specific URL key with a canned response. */
function replayExcept(
  failKey: string,
  status: number,
  body: unknown,
  fixtures: Record<string, unknown>,
): typeof fetch {
  const replay = createReplayFetch(fixtures);
  return async (input: string | URL | RequestInfo, init?: RequestInit) => {
    const raw =
      typeof input === "string" || input instanceof URL ? String(input) : input.url;
    if (normalizeUrlKey(raw) === failKey) {
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    }
    return replay(input as Parameters<typeof fetch>[0], init);
  };
}

describe("runConditionalAccessChecks", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runConditionalAccessChecks,
      baseFixtures(),
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/conditional-access-checks.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("carries the D1 #785 structured evidence fields on the enabled-policies row", async () => {
    const { rows } = await runCollectorOverFixtures(
      "identity",
      runConditionalAccessChecks,
      baseFixtures(),
    );

    const enabledRow = rows.find((r) => r.checkId.startsWith("ENTRA-CA-003"));
    expect(enabledRow).toMatchObject({
      observedValue: "2",
      expectedValue: ">=1",
      evidenceSource: "/identity/conditionalAccess/policies",
      collectionMethod: "Direct",
      permissionRequired: "Policy.Read.All",
      confidence: 1,
    });
  });

  it("fetches the device registration policy twice (v1.0 + promoted beta read, PS call parity)", async () => {
    const { graphUrls } = await runCollectorOverFixtures(
      "identity",
      runConditionalAccessChecks,
      baseFixtures(),
    );

    expect(
      graphUrls.map((u) => normalizeUrlKey(u)).filter((k) => k === EP.deviceRegistrationPolicy),
    ).toHaveLength(2);
  });

  it("emits zero device rows when the device registration policy fetch fails (PS catch parity)", async () => {
    const fetchImpl = replayExcept(
      EP.deviceRegistrationPolicy,
      403,
      { error: { code: "Authorization_RequestDenied", message: "Insufficient privileges" } },
      baseFixtures(),
    );
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runConditionalAccessChecks,
      baseFixtures(),
      { fetchImpl },
    );

    // PS Write-Warning catch: no rows, run continues.
    expect(sectionError).toBeUndefined();
    expect(rows.filter((r) => r.checkId.startsWith("ENTRA-DEVICE"))).toHaveLength(0);
    expect(rows.filter((r) => r.checkId.startsWith("ENTRA-CA"))).toHaveLength(2);
  });
});
