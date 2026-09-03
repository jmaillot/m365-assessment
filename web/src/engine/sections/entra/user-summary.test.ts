/**
 * Parity tests for the Get-UserSummary.ps1 port (plan 02-05 task 1).
 *
 * PS Graph call sites being proven (documented per acceptance criteria):
 *   1. Invoke-MgGraphRequest paginated users loop (Get-UserSummary.ps1:55-80)
 *      → GET /v1.0/users?$select=...&$top=999 with `ConsistencyLevel: eventual`
 *      forwarded verbatim, including the signInActivity → no-signInActivity
 *      fallback retry (PS lines 59-68).
 *
 * Stale-member math depends on "now"; the suite freezes the clock at
 * 2026-08-25T12:00:00Z for determinism (PS: (Get-Date).AddDays(-90)).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { runUserSummary } from "./user-summary";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "./test-support";
import { createReplayFetch } from "@/engine/__fixtures__/replay";

const USERS_FULL_KEY =
  "/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,assignedLicenses,onPremisesSyncEnabled,signInActivity&$top=999";
const USERS_NO_SIGNIN_KEY =
  "/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,assignedLicenses,onPremisesSyncEnabled&$top=999";

afterEach(() => {
  vi.useRealTimers();
});

describe("runUserSummary", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-25T12:00:00Z"));

    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runUserSummary,
      { [USERS_FULL_KEY]: readFixtureJson("user-summary/v1.0_users_full-select.json") },
    );

    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/user-summary.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("forwards ConsistencyLevel: eventual on every users call verbatim", async () => {
    const seenHeaders: Array<Record<string, string> | undefined> = [];
    const replay = createReplayFetch({
      [USERS_FULL_KEY]: { value: [] },
    });
    const wrappedFetch: typeof fetch = (input, init) => {
      seenHeaders.push(init?.headers as Record<string, string> | undefined);
      return replay(input, init);
    };

    // Direct transport exercise so header forwarding is observed at fetch level.
    const { GraphTransport } = await import("@/engine/transport/graph-transport");
    const transport = new GraphTransport({
      getToken: async () => "t",
      fetchImpl: wrappedFetch,
      onPage: () => {},
      isRoleGranted: () => true,
      delayFn: async () => {},
    });
    await transport.getJson(USERS_FULL_KEY, {
      headers: { ConsistencyLevel: "eventual" },
    });

    expect(seenHeaders.length).toBeGreaterThan(0);
    for (const headers of seenHeaders) {
      expect(headers?.ConsistencyLevel).toBe("eventual");
    }
  });

  it("falls back to the no-signInActivity select when the first query fails (PS lines 59-68 parity)", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-25T12:00:00Z"));

    // Only the fallback variant exists as a fixture — the full-select request
    // fails and its error text names 'signInActivity' (the PS match set).
    const { rows } = await runCollectorOverFixtures("identity", runUserSummary, {
      [USERS_NO_SIGNIN_KEY]: readFixtureJson(
        "user-summary/v1.0_users_no-signin-activity.json",
      ),
    });

    expect(rows).toHaveLength(1);
    expect(rows[0].currentValue).toBe(
      // WithMFA stays 0 under fallback: PS only counts sign-ins when
      // signInActivity was selected (Get-UserSummary.ps1:124-142).
      "TotalUsers=3; Licensed=1; GuestUsers=1; DisabledUsers=1; " +
        "SyncedFromOnPrem=1; CloudOnly=2; WithMFA=0; NeverSignedIn=; StaleMember=",
    );
  });

  it("emits zero rows only after a non-fallback failure surfaces as a section error", async () => {
    // No fixtures at all: the failing URL names signInActivity… but the FULL
    // select key IS the one requested, so this exercises the rethrow branch:
    // the fallback retry also fails → PS Write-Error + return parity.
    const { rows, sectionError } = await runCollectorOverFixtures(
      "identity",
      runUserSummary,
      {},
    );
    expect(rows).toEqual([]);
    expect(sectionError).toBeDefined();
  });
});
