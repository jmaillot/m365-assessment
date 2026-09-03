/**
 * Parity tests for the Get-ConditionalAccessReport.ps1 port (plan 02-05 task 2).
 *
 * PS Graph call sites being proven (documented per acceptance criteria):
 *   1. Get-MgIdentityConditionalAccessPolicy -All → GET /v1.0/identity/conditionalAccess/policies
 *   2. Get-MgUser -Property UserPrincipalName (GUID resolution loop, PS lines 66-78)
 *      → GET /v1.0/users/{guid}?$select=userPrincipalName
 *
 * Branch parity: policies-fetch failure surfaces a section error; an empty
 * policy set yields zero rows (PS lines 53-56); unresolved GUIDs pass through
 * verbatim (PS catch fallback line 75); grant controls join with the operator
 * when multiple controls exist; session controls render in PS order.
 */
import { describe, expect, it } from "vitest";
import { runConditionalAccessReport } from "./conditional-access-report";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";

const POLICIES_KEY = "/v1.0/identity/conditionalAccess/policies";

describe("runConditionalAccessReport", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runConditionalAccessReport,
      {
        [POLICIES_KEY]: readFixtureJson(
          "conditional-access-report/v1.0_identity_conditionalAccess_policies.json",
        ),
        "/v1.0/users/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb?$select=userPrincipalName":
          readFixtureJson(
            "conditional-access-report/v1.0_users_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb_$select_userPrincipalName.json",
          ),
        // cccccccc-… GUID intentionally has NO fixture → resolves to the raw
        // GUID itself (PS catch fallback).
      },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/conditional-access-report.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("emits zero rows for an empty-value response (PS empty-data soft-fail parity)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runConditionalAccessReport,
      { [POLICIES_KEY]: { value: [] } },
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeUndefined();
  });

  it("surfaces a section error when policy retrieval fails (PS Write-Error + return parity)", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runConditionalAccessReport,
      {},
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeDefined();
  });
});
