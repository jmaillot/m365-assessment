/**
 * Barrel for the Purview section collectors (plan 06-01).
 *
 * Mirrors the Security/Intune/Exchange/Collaboration barrel pattern — each
 * collector is the direct port of its PS source under `src/M365-Assess/Purview/`
 * and is re-exported here for wiring via `src/engine/index.ts` IMPLEMENTATIONS.
 */

export {
  runPurviewRetentionConfig,
  PURVIEW_RETENTION_CONFIG_ENDPOINTS,
} from "./purview-retention-config";
