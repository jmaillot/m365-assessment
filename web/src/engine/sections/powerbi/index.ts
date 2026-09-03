/**
 * Barrel for the Power BI section collectors (plan 06-01).
 *
 * Mirrors the Security/Intune/Exchange/Collaboration barrel pattern — each
 * collector is the direct port of its PS source under `src/M365-Assess/PowerBI/`
 * and is re-exported here for wiring via `src/engine/index.ts` IMPLEMENTATIONS.
 */

export {
  runPowerBISecurityConfig,
  POWERBI_SECURITY_CONFIG_ENDPOINTS,
} from "./powerbi-security-config";
