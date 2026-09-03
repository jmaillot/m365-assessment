/**
 * Typed result contract for assessment check rows (D-17).
 *
 * Mirrors the PowerShell `Add-SecuritySetting` contract field-for-field
 * (`src/M365-Assess/Common/SecurityConfigHelper.ps1:175-283`) so the Phase 3
 * report pipeline consumes rows without translation.
 */

/** Canonical SaaS status vocabulary (D-23, LOCKED). */
export type SaasStatus = "Pass" | "Fail" | "Warning" | "Review" | "Info" | "Skipped";

/**
 * Machine-readable reason mandatory on every Skipped row (D-23).
 * Locked set — do not extend without revisiting D-23.
 */
export type SkipReason =
  | "not_licensed"
  | "not_applicable"
  | "graph_error"
  | "not_implemented"
  | "circuit_broken";

/**
 * Raw PS status vocabulary as emitted by collector ports. Includes both
 * spellings "Warn" and "Warning" because PS sources emit both. The engine maps
 * these onto SaasStatus via mapStatus() (D-16/D-23) — never stored directly.
 *
 * The PS ValidateSet carries nine values (SecurityConfigHelper.ps1:199); the
 * SaaS adds "Error" so transport/collector failures can flow through rows too.
 */
export type PsStatus =
  | "Pass"
  | "Fail"
  | "Warn"
  | "Warning"
  | "Review"
  | "Info"
  | "Skipped"
  | "Unknown"
  | "NotApplicable"
  | "NotLicensed"
  | "Error";

/** How a finding's value was determined (PS ValidateSet parity). */
export type CollectionMethod = "" | "Direct" | "Derived" | "Inferred";

/**
 * A completed check result row — every field of the PS Add-SecuritySetting
 * contract (D-17). currentValue/recommendedValue are ALWAYS strings (PS
 * AllowEmptyString parity) so fixture comparison stays deterministic; numbers
 * and booleans must be stringified by collectors before addRow().
 */
export interface CheckRow {
  category: string;
  setting: string;
  /** Always string (PS AllowEmptyString parity) — never number/boolean. */
  currentValue: string;
  /** Always string; empty → registry fallback fills at result-build time (D-22). */
  recommendedValue: string;
  status: SaasStatus;
  /** Mandatory when status === "Skipped"; machine-readable WHY (D-23). */
  skipReason?: SkipReason;
  /** Sub-numbered form, e.g. "ENTRA-X-001.3". */
  checkId: string;
  remediation: string;
  intentDesign: boolean;

  // D1 #785 standardized evidence fields — all optional, never synthesized.
  observedValue?: string;
  expectedValue?: string;
  evidenceSource?: string;
  evidenceTimestamp?: string;
  collectionMethod?: CollectionMethod;
  permissionRequired?: string;
  /** Nullable 0.0–1.0; absent = unspecified. */
  confidence?: number;
  limitations?: string;
}

/**
 * What collectors pass to SectionContext.addRow(). CheckRow MINUS the three
 * fields the engine computes (status/skipReason from mapStatus, checkId via
 * sub-numberer, remediation via registry fallback — D-22), carrying the raw
 * PS status instead. Exported because plans 02-03 (SectionContext.addRow) and
 * 02-05..02-10 (collector inputs) consume it.
 */
export interface CheckRowInput {
  category: string;
  setting: string;
  /**
   * Base (pre-sub-numbering) CheckId, e.g. "ENTRA-X-001" — the sub-numberer
   * derives "ENTRA-X-001.N" per section. Empty/falsy passes through
   * unsub-numbered (PS parity). Added in 02-03: sub-numbering and the D-22
   * registry fallback are impossible without a base id on the input.
   */
  checkId?: string;
  /** Defaults to "" (PS AllowEmptyString parity). */
  currentValue?: string;
  /** Empty → registry fallback fills (D-22). */
  recommendedValue?: string;
  /** Collector-supplied remediation; empty → registry fallback fills (D-22). */
  remediation?: string;
  /** Raw PS status; engine maps via mapStatus (D-16/D-23). */
  psStatus: PsStatus;
  intentDesign?: boolean;
  observedValue?: string;
  expectedValue?: string;
  evidenceSource?: string;
  evidenceTimestamp?: string;
  collectionMethod?: CollectionMethod;
  permissionRequired?: string;
  /** Nullable 0.0–1.0. */
  confidence?: number;
  limitations?: string;
}
