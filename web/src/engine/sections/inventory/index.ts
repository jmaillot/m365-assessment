/**
 * Barrel for the Inventory section collectors (Phase 6 plan 06-01).
 *
 * Mirrors the Security/Intune/Exchange/Collaboration/Purview barrel pattern —
 * each collector is the direct port of its PS source under
 * `src/M365-Assess/Inventory/` and is re-exported here for wiring via
 * `src/engine/index.ts` IMPLEMENTATIONS. The `runInventory` composite
 * sequences them in the PS Inventory folder order (Mailbox → OneDrive →
 * SharePoint → Teams → Groups) via the engine's `sequence` helper contract.
 */

export { runMailboxInventory, MAILBOX_INVENTORY_ENDPOINTS } from "./mailbox-inventory";
export { runOneDriveInventory, ONEDRIVE_INVENTORY_ENDPOINTS } from "./onedrive-inventory";
export { runSharePointInventory, SHAREPOINT_INVENTORY_ENDPOINTS } from "./sharepoint-inventory";
export { runTeamsInventory, TEAMS_INVENTORY_ENDPOINTS } from "./teams-inventory";
export { runGroupInventory, GROUP_INVENTORY_ENDPOINTS } from "./group-inventory";

import type { SectionImplementation } from "@/engine/runner/engine";
import { runMailboxInventory } from "./mailbox-inventory";
import { runOneDriveInventory } from "./onedrive-inventory";
import { runSharePointInventory } from "./sharepoint-inventory";
import { runTeamsInventory } from "./teams-inventory";
import { runGroupInventory } from "./group-inventory";

/**
 * Composite inventory runner — sequential fail-soft per engine contract.
 * Each child is individually fail-soft; a failure in one inventory collector
 * preserves its completed rows and continues to the next.
 */
export const runInventory: SectionImplementation = async (ctx) => {
  await runMailboxInventory(ctx);
  await runOneDriveInventory(ctx);
  await runSharePointInventory(ctx);
  await runTeamsInventory(ctx);
  await runGroupInventory(ctx);
};
