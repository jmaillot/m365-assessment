import { describe, expect, it } from "vitest";
import { applyLicensingOverlay, type SkuState } from "./licensing-overlay";
import type { CheckRow } from "./row-contract";

// Inline fixture mirroring the real entry shapes in
// src/M365-Assess/controls/licensing-overlay.json
const OVERLAY = {
  description: "M365-Assess-specific service plan gating",
  version: "1.0.0",
  checks: {
    "CA-SIGNINRISK-001": ["AAD_PREMIUM_P2"],
    "COMPLIANCE-DLP-002": [
      "INFORMATION_PROTECTION_COMPLIANCE",
      "COMMUNICATIONS_DLP",
    ],
  },
};

function makeRow(overrides: Partial<CheckRow>): CheckRow {
  return {
    category: "Conditional Access",
    setting: "Sign-in risk policy",
    currentValue: "Not configured",
    recommendedValue: "At least 1 policy",
    status: "Pass",
    checkId: "CA-SIGNINRISK-001.1",
    remediation: "Enable sign-in risk policy.",
    intentDesign: false,
    ...overrides,
  };
}

function makeSku(
  partNumber: string,
  plans: Array<{ serviceName: string; provisioningStatus: string }>,
): SkuState {
  return {
    skuId: `guid-${partNumber}`,
    skuPartNumber: partNumber,
    servicePlans: plans.map((p) => ({
      servicePlanId: `plan-${p.serviceName}`,
      serviceName: p.serviceName,
      provisioningStatus: p.provisioningStatus,
    })),
  };
}

describe("applyLicensingOverlay", () => {
  it("rewrites rows whose required plans are ALL inactive to Skipped(not_licensed), preserving original status in limitations", () => {
    const rows = [makeRow({})];
    const skus = [
      // Tenant has E3-ish SKUs but nothing containing AAD_PREMIUM_P2.
      makeSku("ENTERPRISEPACK", [
        { serviceName: "EXCHANGE_S_STANDARD", provisioningStatus: "Success" },
      ]),
    ];
    const out = applyLicensingOverlay(rows, OVERLAY, skus);
    expect(out).toHaveLength(1);
    expect(out[0].status).toBe("Skipped");
    expect(out[0].skipReason).toBe("not_licensed");
    expect(out[0].limitations).toContain("Pass");
  });

  it("leaves rows unchanged when at least one required plan is active", () => {
    const row = makeRow({
      setting: "DLP for Exchange",
      checkId: "COMPLIANCE-DLP-002.1",
      status: "Fail",
    });
    const skus = [
      makeSku("EMSPREMIUM", [
        { serviceName: "COMMUNICATIONS_DLP", provisioningStatus: "Success" },
        // INFORMATION_PROTECTION_COMPLIANCE absent/inactive — one active suffices.
        { serviceName: "INTUNE_A", provisioningStatus: "PendingActivation" },
      ]),
    ];
    const out = applyLicensingOverlay([row], OVERLAY, skus);
    expect(out[0]).toEqual(row);
  });

  it("leaves rows whose base CheckId is NOT in the overlay untouched", () => {
    const row = makeRow({ checkId: "ENTRA-PIM-999.1", status: "Warning" });
    const out = applyLicensingOverlay([row], OVERLAY, []);
    expect(out[0]).toEqual(row);
  });

  it("maps sub-numbered CheckIds back to their overlay base", () => {
    const rows = [
      makeRow({ checkId: "CA-SIGNINRISK-001.7", status: "Fail" }),
    ];
    const skus = [
      makeSku("ENTERPRISEPACK", [
        { serviceName: "EXCHANGE_S_STANDARD", provisioningStatus: "Success" },
      ]),
    ];
    const out = applyLicensingOverlay(rows, OVERLAY, skus);
    expect(out[0].status).toBe("Skipped");
    expect(out[0].skipReason).toBe("not_licensed");
    // Sub-numbered form itself is preserved.
    expect(out[0].checkId).toBe("CA-SIGNINRISK-001.7");
  });

  it("fails closed on empty SKU data — every overlaid base becomes Skipped(not_licensed)", () => {
    const rows = [
      makeRow({}),
      makeRow({ setting: "DLP", checkId: "COMPLIANCE-DLP-002.2", status: "Info" }),
      makeRow({ checkId: "NOT-IN-OVERLAY-001.1" }),
    ];
    const out = applyLicensingOverlay(rows, OVERLAY, []);
    expect(out[0].status).toBe("Skipped");
    expect(out[0].skipReason).toBe("not_licensed");
    expect(out[1].status).toBe("Skipped");
    expect(out[1].skipReason).toBe("not_licensed");
    expect(out[2].status).toBe("Pass"); // non-overlaid row unaffected
  });

  it("fails closed on null SKU data", () => {
    const rows = [makeRow({})];
    const out = applyLicensingOverlay(rows, OVERLAY, null);
    expect(out[0].status).toBe("Skipped");
    expect(out[0].skipReason).toBe("not_licensed");
  });

  it("is pure — deterministic outputs, inputs never mutated, preserves all other fields", () => {
    const rows = [
      makeRow({
        observedValue: "0 policies",
        expectedValue: ">=1",
        evidenceSource: "/identity/conditionalAccess/policies",
        confidence: 0.9,
        collectionMethod: "Direct",
        permissionRequired: "Policy.Read.All",
      }),
    ];
    const snapshot = JSON.parse(JSON.stringify(rows)) as CheckRow[];
    const skus: SkuState[] = [];

    const first = applyLicensingOverlay(rows, OVERLAY, skus);
    const second = applyLicensingOverlay(rows, OVERLAY, skus);

    expect(first).toEqual(second);
    // Input rows untouched.
    expect(rows).toEqual(snapshot);
    // All other fields carried through verbatim.
    expect(first[0].observedValue).toBe("0 policies");
    expect(first[0].expectedValue).toBe(">=1");
    expect(first[0].evidenceSource).toBe("/identity/conditionalAccess/policies");
    expect(first[0].confidence).toBe(0.9);
    expect(first[0].collectionMethod).toBe("Direct");
    expect(first[0].permissionRequired).toBe("Policy.Read.All");
  });
});
