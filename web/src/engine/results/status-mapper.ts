import type { PsStatus, SaasStatus, SkipReason } from "./row-contract";

export interface MappedStatus {
  status: SaasStatus;
  reason?: SkipReason;
}

/**
 * Lossless PS nine-status → SaaS six-status mapping (D-16/D-23, LOCKED).
 *
 * - Pass / Fail / Warning / Review / Info → identity
 * - Warn → Warning (PS sources emit both spellings)
 * - Unknown → Review (semantic upgrade per D-23 evidence line: automation
 *   lacked evidence, so a human must look)
 * - NotApplicable → Skipped(not_applicable)
 * - NotLicensed → Skipped(not_licensed)
 * - Error → Skipped(graph_error)
 * - Skipped → Skipped(not_applicable); caller may refine the reason
 *
 * The switch is exhaustive over PsStatus with no default branch — adding a new
 * PsStatus member without a mapping case is a compile error (return typing).
 */
export function mapStatus(psStatus: PsStatus): MappedStatus {
  switch (psStatus) {
    case "Pass":
      return { status: "Pass" };
    case "Fail":
      return { status: "Fail" };
    case "Warn":
    case "Warning":
      return { status: "Warning" };
    case "Review":
      return { status: "Review" };
    case "Info":
      return { status: "Info" };
    case "Unknown":
      return { status: "Review" };
    case "NotApplicable":
      return { status: "Skipped", reason: "not_applicable" };
    case "NotLicensed":
      return { status: "Skipped", reason: "not_licensed" };
    case "Error":
      return { status: "Skipped", reason: "graph_error" };
    case "Skipped":
      return { status: "Skipped", reason: "not_applicable" };
  }
}
