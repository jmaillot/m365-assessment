/**
 * Barrel for the Exchange section collectors (plan 05-01).
 *
 * Mirrors the Security/Intune barrel pattern — each collector is the direct
 * port of its PS source under `src/M365-Assess/Exchange-Online/` and is
 * re-exported here for wiring via `src/engine/index.ts` IMPLEMENTATIONS.
 */

export { runExchangeSecurityConfig, EXCHANGE_SECURITY_CONFIG_ENDPOINTS } from "./exchange-security-config";
export { runDnsSecurityConfig, DNS_SECURITY_CONFIG_ENDPOINTS } from "./dns-security-config";
