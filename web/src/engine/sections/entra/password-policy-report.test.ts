/**
 * Parity tests for the Get-PasswordPolicyReport.ps1 port (plan 02-06 task 1).
 *
 * PS Graph call sites being proven:
 *   1. Get-MgDomain -All (PS line 44) → GET /v1.0/domains
 *   2. Get-MgPolicyAuthorizationPolicy (PS line 54) → GET
 *      /v1.0/policies/authorizationPolicy
 *
 * Degradation parity: EITHER fetch failing = PS Write-Error + return → a
 * section error with zero rows, never fabricated data.
 */
import { describe, expect, it } from "vitest";
import { runPasswordPolicyReport } from "./password-policy-report";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

describe("runPasswordPolicyReport", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runPasswordPolicyReport,
      {
        "/v1.0/domains": readFixtureJson("password-policy/v1.0_domains.json"),
        "/v1.0/policies/authorizationPolicy": readFixtureJson(
          "password-policy/v1.0_policies_authorizationPolicy.json",
        ),
      },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/password-policy-report.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("surfaces a section error when domain retrieval fails (PS Write-Error + return)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runPasswordPolicyReport,
      {},
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeDefined();
  });

  it("surfaces a section error when authorization policy retrieval fails (PS Write-Error + return)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runPasswordPolicyReport,
      {
        "/v1.0/domains": readFixtureJson("password-policy/v1.0_domains.json"),
      },
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeDefined();
  });
});
