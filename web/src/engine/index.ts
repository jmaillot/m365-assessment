/**
 * Public API surface of the assessment engine — the ONLY export boundary.
 * Everything under src/engine/** not re-exported here is internal; collector
 * modules import siblings directly, external consumers import from here.
 */

// Runner
export { runEngine } from "./runner/engine";
export type {
  RunResult,
  SectionResult,
  SectionContext,
  SectionImplementation,
  RunEngineOptions,
  TransportHandlers,
  TransportFactory,
  EngineControls,
} from "./runner/engine";
export { createCircuitBreaker, CIRCUIT_BREAKER_THRESHOLD } from "./runner/circuit-breaker";

// Events
export type { EngineEvent, EngineEventSink } from "./events/engine-events";

// Result contracts & transforms
export type {
  CheckRow,
  CheckRowInput,
  SaasStatus,
  SkipReason,
  PsStatus,
  CollectionMethod,
} from "./results/row-contract";
export { mapStatus } from "./results/status-mapper";
export type { MappedStatus } from "./results/status-mapper";
export { applyLicensingOverlay } from "./results/licensing-overlay";
export type {
  LicensingOverlay,
  SkuState,
  ServicePlanState,
} from "./results/licensing-overlay";

// Registry & controls
export { SECTION_REGISTRY, getSection } from "./registry/section-registry";
export type { SectionEntry } from "./registry/section-registry";
export {
  loadRegistry,
  loadLicensingOverlay,
  loadRiskSeverity,
  loadFrameworks,
  controlsChecksum,
  controlsChecksumsMatch,
  registryRemediationText,
  controlsDir,
} from "./registry/load-controls";
export type {
  ControlRegistry,
  RegistryCheckEntry,
  FrameworkDefinition,
} from "./registry/load-controls";
export { requiredRolesForSections } from "./registry/permissions";

// Collector implementations (wired by plan 02-12) — section id → composite
// collector running the ported collectors in AssessmentMaps $collectorMap
// order. Unlisted sections remain not-yet-implemented (D-10).
import type { SectionImplementation } from "./runner/engine";
import { runTenantInfo } from "./sections/entra/tenant-info";
import { runUserSummary } from "./sections/entra/user-summary";
import { runMfaReport } from "./sections/entra/mfa-report";
import { runAdminRoleReport } from "./sections/entra/admin-role-report";
import { runConditionalAccessReport } from "./sections/entra/conditional-access-report";
import { runAppRegistrationReport } from "./sections/entra/app-registration-report";
import { runPasswordPolicyReport } from "./sections/entra/password-policy-report";
import { runEntraSecurityConfig } from "./sections/entra/entra-security-config";
import { runCaSecurityConfig } from "./sections/entra/ca-security-config";
import { runEntAppSecurityConfig } from "./sections/entra/ent-app-security-config";
import { runEntraSodConfig } from "./sections/entra/entra-sod-config";
import { runEntraTouConfig } from "./sections/entra/entra-tou-config";
import { runEntraPrivRemote } from "./sections/entra/entra-priv-remote";
import { runEntraAdminRoleSeparation } from "./sections/entra/entra-admin-role-separation";
import { runEntraCaRemoteDevice } from "./sections/entra/entra-ca-remote-device";
import { runEntraBreakglassConfig } from "./sections/entra/entra-breakglass-config";
import { runEntraPimAdditionalConfig } from "./sections/entra/entra-pim-additional-config";
import { runEntraAuthMethodAdditional } from "./sections/entra/entra-authmethod-additional";
import { runEntraGroupAdditional } from "./sections/entra/entra-group-additional";
import { runEntraMfaConsentAdditional } from "./sections/entra/entra-mfa-consent-additional";
import { runEntraFinalBatch } from "./sections/entra/entra-final-batch";
import { runLicenseReport } from "./sections/entra/license-report";
import {
  runDefenderSecurityConfig,
  runSecureScoreReport,
  runComplianceSecurityConfig,
} from "./sections/security";
import { runDefenderDropBatch } from "./sections/security/defender-drop-batch";
import {
  runIntuneSecurityConfig,
  runDeviceComplianceReport,
  runConfigProfileReport,
  runIntuneFipsConfig,
} from "./sections/intune";
import {
  runExchangeSecurityConfig,
  runDnsSecurityConfig,
} from "./sections/exchange";
import { runExchangeDropBatch } from "./sections/exchange/exchange-drop-batch";
import {
  runSharePointSecurityConfig,
  runTeamsSecurityConfig,
  runFormsSecurityConfig,
} from "./sections/collaboration";
import { runPurviewRetentionConfig } from "./sections/purview";
import { runInventory } from "./sections/inventory";
import { runPowerBISecurityConfig } from "./sections/powerbi";
import { runRemainingDropBatch } from "./sections/remaining-drop-batch";

/** Run collectors sequentially against one shared context (PS dot-source order). */
function sequence(...impls: SectionImplementation[]): SectionImplementation {
  return async (ctx) => {
    for (const impl of impls) await impl(ctx);
  };
}

/**
 * Ported-section implementations, keyed by registry section id and ordered
 * exactly like AssessmentMaps.ps1 $collectorMap:
 * - tenant: '01-Tenant-Info'
 * - identity: 02-User-Summary … 07i-Entra-CaRemoteDevice (incl. the 07b
 *   entra-security-config composite binding the four check families)
 * - licensing: '08-License-Summary'
 */
export const IMPLEMENTATIONS: Record<string, SectionImplementation> = {
  tenant: sequence(runTenantInfo),
  identity: sequence(
    runUserSummary,
    runMfaReport,
    runAdminRoleReport,
    runConditionalAccessReport,
    runAppRegistrationReport,
    runPasswordPolicyReport,
    runEntraSecurityConfig,
    runCaSecurityConfig,
    runEntAppSecurityConfig,
    runEntraSodConfig,
    runEntraTouConfig,
    runEntraPrivRemote,
    runEntraAdminRoleSeparation,
    runEntraCaRemoteDevice,
    runEntraBreakglassConfig,
    runEntraPimAdditionalConfig,
    runEntraAuthMethodAdditional,
    runEntraGroupAdditional,
    runEntraMfaConsentAdditional,
    runEntraFinalBatch,
  ),
  licensing: sequence(runLicenseReport),
  security: sequence(
    runSecureScoreReport,
    runDefenderSecurityConfig,
    runComplianceSecurityConfig,
    runDefenderDropBatch,
  ),
  intune: sequence(
    runDeviceComplianceReport,
    runConfigProfileReport,
    runIntuneSecurityConfig,
    runIntuneFipsConfig,
  ),
  exchange: sequence(runExchangeSecurityConfig, runDnsSecurityConfig, runExchangeDropBatch),
  collaboration: sequence(
    runSharePointSecurityConfig,
    runTeamsSecurityConfig,
    runFormsSecurityConfig,
  ),
  // "purview" "inventory" "powerbi" — wired (06-02)
  purview: sequence(runPurviewRetentionConfig),
  inventory: sequence(runInventory, runRemainingDropBatch),
  powerbi: sequence(runPowerBISecurityConfig),
};

// Auth
export { mintAppOnlyToken, getGrantedRoles, getTokenForTenant } from "./transport/graph-auth";
