/**
 * Parity tests for the Get-MfaReport.ps1 port (plan 02-05 task 2).
 *
 * PS Graph call sites being proven (documented per acceptance criteria):
 *   1. Get-MgReportAuthenticationMethodUserRegistrationDetail -All
 *      (Get-MfaReport.ps1:83) → GET /v1.0/reports/authenticationMethods/
 *      userRegistrationDetails — the v1.0 promotion of the beta endpoint on
 *      BETA-ENDPOINTS.md row 1 (D-15).
 *
 * Soft-fail parity (Get-MfaReport.ps1:81-96): registration-details fetch
 * failure OR an empty result yields ZERO rows and NO section error — PS
 * Write-Warning/Verbose + return. MFA-strength tiers are exercised through
 * the goldens (phishing-resistant / weak / none).
 */
import { describe, expect, it } from "vitest";
import { runMfaReport } from "./mfa-report";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

const DETAILS_KEY = "/v1.0/reports/authenticationMethods/userRegistrationDetails";

describe("runMfaReport", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runMfaReport,
      { [DETAILS_KEY]: readFixtureJson("mfa-report/v1.0_reports_authenticationMethods_userRegistrationDetails.json") },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/mfa-report.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("emits zero rows for an empty-value response (PS empty-data soft-fail parity)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runMfaReport,
      { [DETAILS_KEY]: { value: [] } },
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeUndefined();
  });

  it("degrades to zero rows without a section error when the endpoint fails", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runMfaReport,
      {},
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeUndefined();
  });
});
