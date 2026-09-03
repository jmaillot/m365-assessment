/**
 * Barrel for the Intune section collectors (plan 04-01 task 2).
 *
 * Mirrors the Security section barrel pattern — each collector is the direct
 * port of its PS source under `src/M365-Assess/Intune/` and is re-exported
 * here for wiring via `src/engine/index.ts` IMPLEMENTATIONS.
 */

export {
  runIntuneSecurityConfig,
  INTUNE_SECURITY_CONFIG_ENDPOINTS,
} from "./intune-security-config";
export {
  runDeviceComplianceReport,
  DEVICE_COMPLIANCE_REPORT_ENDPOINTS,
} from "./device-compliance-report";
export {
  runConfigProfileReport,
  CONFIG_PROFILE_REPORT_ENDPOINTS,
} from "./config-profile-report";
export {
  runIntuneFipsConfig,
  INTUNE_FIPS_CONFIG_ENDPOINTS,
} from "./intune-fips-config";
