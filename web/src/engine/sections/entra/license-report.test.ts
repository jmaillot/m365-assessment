/**
 * Parity tests for the Get-LicenseReport.ps1 port (plan 02-06 task 2).
 *
 * PS Graph call site being proven:
 *   1. Get-MgSubscribedSku -All (PS line 93) → GET /v1.0/subscribedSkus
 *      (automatic -All pagination = transport nextLink following).
 *
 * Deviations from PS (documented in the module docblock):
 *   - Live SKU-name CSV download SKIPPED: the SaaS transport is a Graph-only
 *     choke point (SSRF host pinning, T-02-06a) — no arbitrary web fetches.
 *     The bundled CSV (assets/sku-friendly-names.csv), which is PS's own
 *     fallback source, is the single name source here.
 *   - IncludeUserDetail not ported: AssessmentMaps runs this collector with
 *     Params = @{} (summary mode only).
 *
 * D-20 input contract: the collector writes ctx.shared.set("subscribedSkus",
 * skuStates) so runEngine post-processing feeds applyLicensingOverlay — proven
 * end-to-end below by gating an overlay check (CA-SIGNINRISK-001 requires
 * AAD_PREMIUM_P2 active).
 */
import { describe, expect, it } from "vitest";
import { runLicenseReport } from "./license-report";
import {
  goldenToExpected,
  readFixtureJson,
  runSectionsOverFixtures,
} from "./test-support";
import type { SectionImplementation } from "@/engine/runner/engine";

const SKUS_KEY = "/v1.0/subscribedSkus";

describe("runLicenseReport", () => {
  it("produces golden rows identical to the PS collector over recorded fixtures", async () => {
    const { rows, sectionError, licensingOverlayApplied } =
      await runSectionsOverFixtures(
        ["licensing"],
        { licensing: runLicenseReport },
        { [SKUS_KEY]: readFixtureJson("license-report/v1.0_subscribedSkus.json") },
      );

    expect(sectionError).toBeUndefined();
    // SKU data was collected → the D-20 overlay pipeline ran.
    expect(licensingOverlayApplied).toBe(true);

    const golden = readFixtureJson<Array<Record<string, unknown>>>(
      "golden/license-report.json",
    );
    expect(rows).toEqual(goldenToExpected(golden));
  });

  it("surfaces a section error when subscribedSku retrieval fails (PS Write-Error + return)", async () => {
    const { rows, sectionError, licensingOverlayApplied } =
      await runSectionsOverFixtures(
        ["licensing"],
        { licensing: runLicenseReport },
        {},
      );

    expect(rows).toEqual([]);
    expect(sectionError).toBeDefined();
    expect(licensingOverlayApplied).toBeFalsy();
  });

  it("feeds applyLicensingOverlay through shared state (D-20 input contract)", async () => {
    const gatedCheck: SectionImplementation = async (ctx) => {
      ctx.addRow({
        category: "Conditional Access",
        setting: "Sign-in risk policy",
        currentValue: "configured",
        recommendedValue: "configured",
        checkId: "CA-SIGNINRISK-001",
        remediation: "",
        psStatus: "Pass",
      });
    };

    // AAD_PREMIUM_P2 active in the fixture → the gated row stays Pass.
    const licensed = await runSectionsOverFixtures(
      ["licensing", "identity"],
      { licensing: runLicenseReport, identity: gatedCheck },
      { [SKUS_KEY]: readFixtureJson("license-report/v1.0_subscribedSkus.json") },
    );
    const licensedRow = licensed.rows.find((r) => r.checkId.startsWith("CA-SIGNINRISK"));
    expect(licensedRow?.status).toBe("Pass");

    // Empty SKU list collected → overlay applied fail-closed → Skipped(not_licensed).
    const unlicensed = await runSectionsOverFixtures(
      ["licensing", "identity"],
      { licensing: runLicenseReport, identity: gatedCheck },
      { [SKUS_KEY]: { value: [] } },
    );
    const unlicensedRow = unlicensed.rows.find((r) => r.checkId.startsWith("CA-SIGNINRISK"));
    expect(unlicensedRow?.status).toBe("Skipped");
    expect(unlicensedRow?.skipReason).toBe("not_licensed");
  });
});
