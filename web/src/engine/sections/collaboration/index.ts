/**
 * Barrel for the Collaboration section collectors (Phase 5 plan 05-01).
 *
 * Mirrors the Security/Intune/Exchange barrel patterns — each collector is
 * the direct port of its PS source under `src/M365-Assess/Collaboration/`
 * and is re-exported here for wiring via `src/engine/index.ts`
 * IMPLEMENTATIONS.
 */

export { runSharePointSecurityConfig, SHAREPOINT_SECURITY_CONFIG_ENDPOINTS } from "./sharepoint-security-config";
export { runTeamsSecurityConfig, TEAMS_SECURITY_CONFIG_ENDPOINTS } from "./teams-security-config";
export { runFormsSecurityConfig, FORMS_SECURITY_CONFIG_ENDPOINTS } from "./forms-security-config";
