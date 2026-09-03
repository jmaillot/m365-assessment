/**
 * Port of `src/M365-Assess/Inventory/Get-OneDriveInventory.ps1` (213 lines)
 * — per-user OneDrive inventory (storage usage and activity).
 *
 * PS → TS mapping:
 * - Primary path User.Read.All → GET /v1.0/users/{id}/drive per user is
 *   collapsed to the collection `GET /v1.0/drives` (Sites.Read.All) which
 *   returns the same quota/webUrl/lastModifiedDateTime objects paged by the
 *   transport (D-27) without per-user fan-out. The Reports API fallback
 *   (v1.0/reports/getOneDriveUsageAccountDetail) is retired — Graph
 *   reports anonymize by default and the SaaS prefers the direct drives
 *   surface which never obfuscates.
 * - PS output PSCustomObject per OneDrive with OwnerDisplayName/UPN/SiteUrl/
 *   StorageUsedMB/Allocated/FileCount/LastActivity — the TS emits one Info
 *   row per drive in kv parity, plus a summary row.
 * - v1.0 only; GET only; fail-soft; 403-family → Skipped via errMatches.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, kv, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const ONEDRIVE_INVENTORY_ENDPOINTS = {
  drives: "/v1.0/drives?$select=id,name,driveType,owner,quota,webUrl,createdDateTime,lastModifiedDateTime&$top=999",
  sites: "/v1.0/sites?$select=id,displayName,webUrl,createdDateTime&$top=999",
} as const;

const REQUIRED_ROLE = "Sites.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const CATEGORY = "OneDrive Inventory";

export const runOneDriveInventory: SectionImplementation = async (ctx) => {
  let drives: Record<string, unknown>[];
  try {
    const resp = await ctx.transport.getJson(ONEDRIVE_INVENTORY_ENDPOINTS.drives, {
      requiredRole: REQUIRED_ROLE,
    });
    drives = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: CATEGORY,
        setting: "OneDrive Inventory",
        currentValue: "Insufficient permissions",
        recommendedValue: "",
        psStatus: "Skipped",
        evidenceSource: ONEDRIVE_INVENTORY_ENDPOINTS.drives,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
      return;
    }
    return;
  }

  // Summary row — total drives and personal (OneDrive) subset.
  const personalDrives = drives.filter((d) => psStr(d.driveType) === "personal").length;
  ctx.addRow({
    category: CATEGORY,
    setting: "Inventory Summary",
    currentValue: kv([
      ["TotalDrives", drives.length],
      ["OneDrivePersonal", personalDrives],
    ]),
    recommendedValue: "",
    psStatus: "Info",
    evidenceSource: ONEDRIVE_INVENTORY_ENDPOINTS.drives,
    collectionMethod: "Direct",
    permissionRequired: REQUIRED_ROLE,
  });

  if (drives.length === 0) return;

  // Sort by owner UPN/displayName for determinism.
  const sorted = [...drives].sort((a, b) => {
    const oa = (a.owner as Record<string, unknown> | undefined)?.user as Record<string, unknown> | undefined;
    const ob = (b.owner as Record<string, unknown> | undefined)?.user as Record<string, unknown> | undefined;
    const ka = psStr(oa?.email ?? oa?.userPrincipalName ?? a.name);
    const kb = psStr(ob?.email ?? ob?.userPrincipalName ?? b.name);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  for (const drive of sorted) {
    const owner = drive.owner as Record<string, unknown> | undefined;
    const ownerUser = owner?.user as Record<string, unknown> | undefined;
    const ownerDisplayName = psStr(ownerUser?.displayName);
    const ownerUpn = psStr(ownerUser?.email ?? ownerUser?.userPrincipalName);
    const quota = drive.quota as Record<string, unknown> | undefined;
    const storageUsedMB =
      quota && quota.used !== null && quota.used !== undefined
        ? Math.round(Number(quota.used) / (1024 * 1024) * 100) / 100
        : "";
    const storageAllocatedMB =
      quota && quota.total !== null && quota.total !== undefined
        ? Math.round(Number(quota.total) / (1024 * 1024) * 100) / 100
        : "";

    const setting = ownerUpn || ownerDisplayName || psStr(drive.name) || psStr(drive.id) || "Unknown drive";

    ctx.addRow({
      category: CATEGORY,
      setting,
      currentValue: kv([
        ["OwnerDisplayName", ownerDisplayName],
        ["OwnerPrincipalName", ownerUpn],
        ["SiteUrl", drive.webUrl],
        ["DriveType", drive.driveType],
        ["StorageUsedMB", storageUsedMB],
        ["StorageAllocatedMB", storageAllocatedMB],
        ["LastModifiedDateTime", drive.lastModifiedDateTime],
      ]),
      recommendedValue: "",
      psStatus: "Info",
      evidenceSource: ONEDRIVE_INVENTORY_ENDPOINTS.drives,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
};
