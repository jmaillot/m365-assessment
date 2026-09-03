/**
 * Barrel for the Security section collectors (plan 04-01 task 1).
 *
 * Mirrors the Entra section barrel pattern — each collector is the direct
 * port of its PS source under `src/M365-Assess/Security/` and is re-exported
 * here for wiring via `src/engine/index.ts` IMPLEMENTATIONS.
 */

export { runDefenderSecurityConfig, DEFENDER_SECURITY_CONFIG_ENDPOINTS } from "./defender-security-config";
export { runSecureScoreReport, SECURE_SCORE_ENDPOINTS } from "./secure-score-report";
export { runComplianceSecurityConfig, COMPLIANCE_SECURITY_CONFIG_ENDPOINTS } from "./compliance-security-config";
export { runDefenderDropBatch } from "./defender-drop-batch";
