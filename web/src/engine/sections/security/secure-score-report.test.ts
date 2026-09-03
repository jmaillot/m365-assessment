import { describe, expect, it } from "vitest";
import { runSecureScoreReport, SECURE_SCORE_ENDPOINTS } from "./secure-score-report";
import { runDefenderSecurityConfig } from "./defender-security-config";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
  runSectionsOverFixtures,
} from "../entra/test-support";
import { createReplayFetch } from "@/engine/__fixtures__/replay";
import { GraphError } from "@/engine/transport/graph-transport";

const SECURE_SCORES_KEY = SECURE_SCORE_ENDPOINTS.secureScores;
const PROFILES_KEY = SECURE_SCORE_ENDPOINTS.secureScoreControlProfiles;

/**
 * Graph fixtures that hand-trace to golden/security/secure-score.json via
 * secure-score-report.ts decision ladders (no pwsh, PS logic traced manually).
 */
function secureScoreFixtures(): Record<string, unknown> {
  return {
    [SECURE_SCORES_KEY]: {
      value: [
        {
          currentScore: 42,
          maxScore: 100,
          createdDateTime: "2026-09-01T12:00:00Z",
          averageComparativeScores: [{ basis: "AllTenants", averageScore: 35 }],
          controlScores: [
            {
              controlName: "Enable MFA for admins",
              Score: 10,
              scoreInPercentage: 5,
              additionalProperties: {
                controlCategory: "Identity",
                implementationStatus: "Implemented",
                userImpact: "Low",
                threats: ["Account compromise"],
                scoreInPercentage: 5,
                maxScore: 10,
              },
            },
            {
              controlName: "Require device compliance",
              Score: 32,
              scoreInPercentage: 8,
              additionalProperties: {
                controlCategory: "Device",
                implementationStatus: "NotImplemented",
                userImpact: "Medium",
                threats: ["Device compromise"],
                scoreInPercentage: 8,
                maxScore: 8,
              },
            },
          ],
        },
        {
          currentScore: 38,
          maxScore: 100,
          createdDateTime: "2026-08-15T12:00:00Z",
          averageComparativeScores: [],
          controlScores: [],
        },
      ],
    },
    [PROFILES_KEY]: {
      value: [
        { id: "Enable MFA for admins", actionType: "ProviderGenerated" },
        { id: "Require device compliance", actionType: "Customer" },
      ],
    },
  };
}

function defenderPolicyFixtures(): Record<string, unknown> {
  return {
    [PROFILES_KEY]: {
      value: [
        {
          title: "Anti-phishing policy",
          controlCategory: "Phishing",
          actionType: "ProviderGenerated",
          implementationStatus: "Implemented",
        },
        {
          title: "Anti-spam policy",
          controlCategory: "Spam",
          actionType: "Customer",
          implementationStatus: "",
        },
      ],
    },
  };
}

describe("runSecureScoreReport", () => {
  it("produces golden rows identical to hand-traced PS over recorded fixtures", async () => {
    const { rows, sectionError } = await runCollectorOverFixtures(
      "security",
      runSecureScoreReport,
      secureScoreFixtures(),
    );
    expect(sectionError).toBeUndefined();
    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/security/secure-score.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
    // Provenance: contains DEFENDER-SECURESCORE base
    expect(golden.some((g) => String(g.checkId).startsWith("DEFENDER-SECURESCORE"))).toBe(true);
  });

  it("D-22: DEFENDER-SECURESCORE-001 vs DEFENDER-SAFELINKS-001 remain distinct when both surfaces disagree", async () => {
    // Run both collectors together — honest two rows, no dedup.
    const combined = {
      ...secureScoreFixtures(),
      // Override profiles for defender leg to force distinct surfaces
      [PROFILES_KEY]: {
        value: [
          { id: "Enable MFA for admins", actionType: "Customer" },
          { id: "Require device compliance", actionType: "Customer" },
          { title: "Anti-phishing policy", controlCategory: "Phishing", actionType: "ProviderGenerated" },
          { title: "Anti-spam policy", controlCategory: "Spam", actionType: "Customer" },
        ],
      },
    };
    // For this test we run security section with two implementations sequentially
    // via runSectionsOverFixtures — first secureScore, then defender.
    const { rows } = await runSectionsOverFixtures(
      ["security", "security2"],
      {
        security: runSecureScoreReport,
        security2: runDefenderSecurityConfig,
      },
      combined,
    );
    const baseIds = rows.map((r) => r.checkId.replace(/\.\d+$/, ""));
    expect(baseIds).toContain("DEFENDER-SECURESCORE-001");
    expect(baseIds).toContain("DEFENDER-SAFELINKS-001");
    // Distinct bases, two honest rows
    const secureRows = rows.filter((r) => r.checkId.startsWith("DEFENDER-SECURESCORE"));
    const safeLinksRows = rows.filter((r) => r.checkId.startsWith("DEFENDER-SAFELINKS"));
    expect(secureRows.length).toBeGreaterThanOrEqual(1);
    expect(safeLinksRows.length).toBeGreaterThanOrEqual(1);
    expect(secureRows[0].checkId).not.toBe(safeLinksRows[0].checkId);
    // Also verify defender-policy golden distinct from secure-score golden
    const defenderGolden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/security/defender-policy.json",
    );
    expect(defenderGolden.some((g) => String(g.checkId).startsWith("DEFENDER-SAFELINKS-001"))).toBe(true);
    const secureGolden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/security/secure-score.json",
    );
    const defenderBases = new Set(defenderGolden.map((g) => String(g.checkId).replace(/\.\d+$/, "")));
    const secureBases = new Set(secureGolden.map((g) => String(g.checkId).replace(/\.\d+$/, "")));
    // No overlap on non-empty bases
    for (const b of defenderBases) {
      if (b) expect(secureBases.has(b)).toBe(false);
    }
  });

  it("403 → Skipped with explicit copy (D-24) never silent", async () => {
    const failingFetch = async (input: string | URL | RequestInfo): Promise<Response> => {
      const key = String(input);
      if (key.includes("/security/secureScores")) {
        return new Response(
          JSON.stringify({ error: { code: "Authorization_RequestDenied", message: "Insufficient privileges 403" } }),
          { status: 403, headers: { "content-type": "application/json" } },
        );
      }
      return createReplayFetch({})(input as string);
    };
    const { rows } = await runCollectorOverFixtures("security", runSecureScoreReport, {}, { fetchImpl: failingFetch as typeof fetch });
    expect(rows.length).toBe(1);
    expect(rows[0].status).toBe("Skipped");
    expect(rows[0].checkId).toBe("DEFENDER-SECURESCORE-001.1");
    expect(rows[0].currentValue).toContain("Missing permissions — SecurityEvents.Read.All not granted; re-consent to grant");
  });

  it("empty/missing profile path → Warning with explicit copy not Skipped (D-24 defender leg)", async () => {
    const { rows } = await runCollectorOverFixtures("security", runDefenderSecurityConfig, defenderPolicyFixtures());
    const safeLinks = rows.find((r) => r.checkId === "DEFENDER-SAFELINKS-001.1");
    expect(safeLinks).toBeDefined();
    expect(safeLinks!.status).toBe("Warning");
    expect(safeLinks!.currentValue).toBe("No Safe Links policy configured — review");
    // 403 on defender should be Skipped with same explicit copy
    const failingFetch = async (input: string | URL | RequestInfo): Promise<Response> => {
      return new Response(
        JSON.stringify({ error: { code: "Authorization_RequestDenied", message: "403 Forbidden" } }),
        { status: 403, headers: { "content-type": "application/json" } },
      );
    };
    const { rows: skippedRows } = await runCollectorOverFixtures("security", runDefenderSecurityConfig, {}, { fetchImpl: failingFetch as typeof fetch });
    expect(skippedRows.every((r) => r.status === "Skipped")).toBe(true);
    expect(skippedRows[0].currentValue).toContain("Missing permissions — SecurityEvents.Read.All not granted; re-consent to grant");
  });

  it("replay uses /v1.0 surface only (no beta) and sub-numbering .1", async () => {
    const { rows, graphUrls } = await runCollectorOverFixtures("security", runSecureScoreReport, secureScoreFixtures());
    expect(rows[0].checkId).toBe("DEFENDER-SECURESCORE-001.1");
    expect(graphUrls.every((u) => !u.includes("/beta/"))).toBe(true);
  });
});
