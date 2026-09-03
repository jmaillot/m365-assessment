/**
 * Behavioral port of src/M365-Assess/Orchestrator/Test-GraphPermissions.ps1
 * (scope diff, lines 282-334) and its Write-PermissionDeficitsFile payload
 * shape (schemaVersion / generatedAtUtc provenance).
 *
 * PURE by design: performs no I/O — no HTTP calls, no DB access, and no auth
 * SDK usage. Token acquisition and scp-claim decoding live in Plan 01-04 and
 * feed results into computeVerification().
 *
 * Phase 04 probes (04-02): verifyAppPermissions in
 * web/src/engine/verify-permissions-app.ts extends the 02-13 sequential
 * $top=1 pattern with probes for SecurityEvents.Read.All,
 * ThreatIntelligence.Read.All, DeviceManagementManagedDevices.Read.All,
 * DeviceManagementConfiguration.Read.All via
 * GET /v1.0/security/secureScores?$top=1,
 * GET /v1.0/deviceManagement/managedDevices?$top=1 and
 * GET /beta/deviceManagement/deviceEnrollmentConfigurations?$top=1
 * (403→missing, 2xx→granted, 429/5xx→granted:null → error).
 *
 * Three-state outcome model (fail-explicit):
 *  - "all_granted": granted ⊇ required
 *  - "missing":     some required scopes absent (empty granted = none consented,
 *                   NOT an error — mirrors PS semantics)
 *  - "error":       verification itself could not run (e.g. token acquisition
 *                   failed) — built via verificationError(), never silent
 */

export type VerificationStatus = "all_granted" | "missing" | "error";

export interface VerificationResult {
  status: VerificationStatus;
  schemaVersion: "1.0";
  generatedAtUtc: string; // ISO-8601 UTC
  required: string[];
  granted: string[];
  missing: string[]; // empty unless status === "missing"
  errorMessage?: string; // present only when status === "error"
}

export function computeVerification(
  required: string[],
  granted: string[],
): VerificationResult {
  const result: VerificationResult = {
    status: "all_granted",
    schemaVersion: "1.0",
    generatedAtUtc: new Date().toISOString(),
    required: [...required],
    granted: [...granted],
    missing: [],
  };

  // Case-insensitive comparison ONLY (mirrors $grantedLower in PS);
  // report original-cased names.
  const grantedLower = new Set(granted.map((s) => s.toLowerCase()));

  // Deduplicate required names while preserving original casing.
  const seen = new Set<string>();
  const missing = new Set<string>();
  for (const scope of required) {
    if (seen.has(scope)) continue;
    seen.add(scope);
    if (!grantedLower.has(scope.toLowerCase())) {
      missing.add(scope);
    }
  }

  if (missing.size > 0) {
    result.status = "missing";
    result.missing = [...missing].sort((a, b) => a.localeCompare(b));
  }

  return result;
}

export function verificationError(message: string): VerificationResult {
  return {
    status: "error",
    schemaVersion: "1.0",
    generatedAtUtc: new Date().toISOString(),
    required: [],
    granted: [],
    missing: [],
    errorMessage: message,
  };
}

export function summarize(result: VerificationResult): {
  totalRequired: number;
  totalMissing: number;
} {
  return {
    totalRequired: result.required.length,
    totalMissing: result.missing.length,
  };
}
