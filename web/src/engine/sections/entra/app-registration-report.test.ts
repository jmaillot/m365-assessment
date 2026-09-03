/**
 * Parity tests for the Get-AppRegistrationReport.ps1 port (plan 02-05 task 2).
 *
 * PS Graph call sites being proven (documented per acceptance criteria):
 *   1. Get-MgApplication -All -Property ... (Get-AppRegistrationReport.ps1:44)
 *      → GET /v1.0/applications?$select=id,displayName,appId,createdDateTime,
 *      signInAudience,passwordCredentials,keyCredentials
 *
 * Credential-expiry math is now-relative; the suite freezes the clock at
 * 2026-08-25T12:00:00Z so expired=1 / earliest=2024-06-01 stays deterministic.
 * EarliestExpiry renders in PS 'yyyy-MM-dd HH:mm:ss' shape (UTC parts — the
 * deterministic choice; PS formats in local time, see SUMMARY deviation note).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { runAppRegistrationReport } from "./app-registration-report";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

const APPS_KEY =
  "/v1.0/applications?$select=id,displayName,appId,createdDateTime,signInAudience,passwordCredentials,keyCredentials";

afterEach(() => {
  vi.useRealTimers();
});

describe("runAppRegistrationReport", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-25T12:00:00Z"));

    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runAppRegistrationReport,
      { [APPS_KEY]: readFixtureJson("app-registration-report/v1.0_applications_$select_id_displayName_appId_createdDateTime_signInAudience_passwordCredentials_keyCredentials.json") },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/app-registration-report.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("emits zero rows for an empty-value response (PS empty-data soft-fail parity)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runAppRegistrationReport,
      { [APPS_KEY]: { value: [] } },
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeUndefined();
  });

  it("surfaces a section error when app retrieval fails (PS Write-Error + return parity)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runAppRegistrationReport,
      {},
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeDefined();
  });
});
