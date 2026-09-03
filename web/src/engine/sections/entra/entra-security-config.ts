/**
 * Port of `src/M365-Assess/Entra/Get-EntraSecurityConfig.ps1` (95 lines)
 * — AssessmentMaps Identity entry '07b-Entra-Security-Config' (plan 02-08
 * task 2): the composite Entra security config collector binding all four
 * check families.
 *
 * PS structure → TS composition:
 * - Shared data queries (PS lines 59-81): $authPolicy is soft-fail
 *   pre-fetched ONCE here (PS lines 61-72) and stored under
 *   ctx.shared("entra.authPolicy") so EntraAdminRoleChecks section 31 and
 *   EntraUserGroupChecks sections 3-5/10/16 read the same response with
 *   exactly one pre-fetch. $sspr/$orgSettings/$pwSettings are declared null
 *   by the PS orchestrator and populated/consumed INSIDE the helper files;
 *   those flows already live in the family modules (password-auth-checks
 *   keeps them invocation-local; orgSettings crosses files via
 *   ctx.shared("entra.orgSettings") — and because UserGroup dot-sources LAST,
 *   PasswordAuth's section 27 always reads null, exactly as PS).
 * - Dot-source order (PS lines 86-90) → sequential awaits in the same order:
 *   PasswordAuth → AdminRole → ConditionalAccess → UserGroup.
 * - Initialize-SecurityConfig being called once for the whole collector maps
 *   to runEngine's single fresh sub-numberer/circuit-breaker per section —
 *   one counter context spans all four families.
 * - Assert-GraphConnection / Export-SecurityConfigReport: connection gating
 *   and CSV export are transport-layer/report-pipeline concerns owned outside
 *   the engine (Phase 3 wiring); the collector emits rows only, zero
 *   fabricated findings on failure (D-10).
 *
 * Residual glue checks: none — every Add-Setting call in the 95-line file's
 * execution path lives in one of the four helper files; the orchestrator only
 * declares shared-scope variables (handled above) and sequences execution.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { runPasswordAuthChecks } from "./password-auth-checks";
import { runAdminRoleChecks } from "./admin-role-checks";
import { runConditionalAccessChecks } from "./conditional-access-checks";
import { runUserGroupChecks } from "./user-group-checks";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const ENTRA_SECURITY_CONFIG_ENDPOINTS = {
  authorizationPolicy: "/v1.0/policies/authorizationPolicy",
} as const;

type GraphObj = Record<string, unknown>;

const POLICY_READ_ALL = "Policy.Read.All";

export const runEntraSecurityConfig: SectionImplementation = async (ctx) => {
  // ------------------------------------------------------------------
  // Shared data query used by multiple helper files (PS lines 59-72):
  // single soft-fail authorizationPolicy fetch, published to the shared
  // store. A null result propagates the PS Write-Warning degradation into
  // every consuming check ('Property not available' / null-guard branches).
  // ------------------------------------------------------------------
  let authPolicy: GraphObj | null;
  try {
    authPolicy = (await ctx.transport.getJson(
      ENTRA_SECURITY_CONFIG_ENDPOINTS.authorizationPolicy,
      { requiredRole: POLICY_READ_ALL },
    )) as GraphObj;
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    authPolicy = null;
  }
  ctx.shared.set("entra.authPolicy", authPolicy);

  // ------------------------------------------------------------------
  // Dot-source helper files in PS order (Get-EntraSecurityConfig.ps1
  // lines 86-90). All four receive the SAME SectionContext, so the engine's
  // fresh-per-section sub-numberer spans the whole composite exactly like
  // the single Initialize-SecurityConfig context in PowerShell.
  // ------------------------------------------------------------------
  await runPasswordAuthChecks(ctx);
  await runAdminRoleChecks(ctx);
  await runConditionalAccessChecks(ctx);
  await runUserGroupChecks(ctx);

  // ------------------------------------------------------------------
  // Output results (PS lines 92-95): Export-SecurityConfigReport is owned by
  // the report pipeline; the engine's RunResult carries the rows.
  // ------------------------------------------------------------------
};
