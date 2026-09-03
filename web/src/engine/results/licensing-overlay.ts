import type { CheckRow, SkipReason } from "./row-contract";

/** Minimal shape of one subscribedSku service plan (Graph parity). */
export interface ServicePlanState {
  servicePlanId: string;
  serviceName: string;
  provisioningStatus: string;
}

/**
 * Minimal shape of one Graph `subscribedSku` — mirrors the service-plan states
 * consumed by the PS licensing report (`Get-LicenseReport.ps1`).
 */
export interface SkuState {
  skuId: string;
  skuPartNumber: string;
  servicePlans: Array<ServicePlanState>;
}

/** Overlay shape: src/M365-Assess/controls/licensing-overlay.json. */
export interface LicensingOverlay {
  checks: Record<string, string[]>;
}

const ACTIVE_PROVISIONING_STATUS = "Success";

function isActive(plan: ServicePlanState): boolean {
  return plan.provisioningStatus === ACTIVE_PROVISIONING_STATUS;
}

/** Sub-numbered CheckIds ("BASE.3") map back to their overlay base ("BASE"). */
function baseCheckId(checkId: string): string {
  const dot = checkId.indexOf(".");
  return dot === -1 ? checkId : checkId.slice(0, dot);
}

/**
 * Licensing gating as a PURE post-process (D-20): collectors contain zero
 * licensing logic; rows are rewritten here based on the overlay JSON plus the
 * tenant's subscribed SKU service-plan states.
 *
 * - A row whose base CheckId appears in the overlay is gated when NONE of its
 *   required plans is active anywhere in the tenant → status becomes
 *   `Skipped("not_licensed")`, with the original status preserved in
 *   `limitations` for auditability.
 * - At least one active required plan → row passes through untouched.
 * - Base CheckId absent from the overlay → row untouched.
 * - Empty or null SKU data fails CLOSED: every overlaid base CheckId becomes
 *   Skipped(not_licensed) — missing license evidence never yields a Pass.
 *
 * Inputs are never mutated; a new array of new row objects is returned. No I/O,
 * no imports beyond types — deterministic same-in/same-out.
 */
export function applyLicensingOverlay(
  rows: CheckRow[],
  overlay: LicensingOverlay,
  subscribedSkus: SkuState[] | null,
): CheckRow[] {
  const activeServicePlans = new Set<string>();
  if (subscribedSkus) {
    for (const sku of subscribedSkus) {
      for (const plan of sku.servicePlans ?? []) {
        if (isActive(plan)) {
          activeServicePlans.add(plan.serviceName);
        }
      }
    }
  }

  return rows.map((row) => {
    const requiredPlans = overlay.checks[baseCheckId(row.checkId)];
    if (!requiredPlans || requiredPlans.length === 0) {
      return row;
    }

    const anyActive = requiredPlans.some((plan) =>
      activeServicePlans.has(plan),
    );
    if (anyActive) {
      return row;
    }

    // Fail-closed gate: no active plan (or no SKU data at all).
    const skipReason: SkipReason = "not_licensed";
    return {
      ...row,
      status: "Skipped",
      skipReason,
      limitations: `Licensing gate (${skipReason}): requires an active service plan from [${requiredPlans.join(", ")}]; original status was ${row.status}${row.skipReason ? ` (${row.skipReason})` : ""}.`,
    };
  });
}
