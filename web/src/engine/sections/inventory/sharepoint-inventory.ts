/**
 * Port of `src/M365-Assess/Inventory/Get-SharePointInventory.ps1` (226 lines)
 * — per-site SharePoint inventory (storage usage and activity).
 *
 * PS → TS mapping:
 * - Primary path Sites.Read.All → GET /v1.0/sites/getAllSites with per-site
 *   drive quota calls; TS collapses pagination via transport D-27 and emits
 *   one Info row per site (kv parity) plus a summary row. The Reports API
 *   fallback (getSharePointSiteUsageDetail) is retired — it anonymizes when
 *   tenant privacy is enabled, while getAllSites returns real URLs/names.
 * - Per-site drive quota enrichment (PS lines 94-111) is omitted in minimal
 *   functional mode — site list alone satisfies inventory coverage; enrichment
 *   would require per-site fan-out and is deferred.
 * - v1.0 only; GET only; fail-soft; 403-family → Skipped.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, kv, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const SHAREPOINT_INVENTORY_ENDPOINTS = {
  sites: "/v1.0/sites/getAllSites?$select=id,displayName,webUrl,createdDateTime,lastModifiedDateTime&$top=999",
} as const;

const REQUIRED_ROLE = "Sites.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const CATEGORY = "SharePoint Inventory";

export const runSharePointInventory: SectionImplementation = async (ctx) => {
  let sites: Record<string, unknown>[];
  try {
    const resp = await ctx.transport.getJson(SHAREPOINT_INVENTORY_ENDPOINTS.sites, {
      requiredRole: REQUIRED_ROLE,
    });
    sites = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: CATEGORY,
        setting: "SharePoint Inventory",
        currentValue: "Insufficient permissions",
        recommendedValue: "",
        psStatus: "Skipped",
        evidenceSource: SHAREPOINT_INVENTORY_ENDPOINTS.sites,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
      return;
    }
    return;
  }

  ctx.addRow({
    category: CATEGORY,
    setting: "Inventory Summary",
    currentValue: kv([["TotalSites", sites.length]]),
    recommendedValue: "",
    psStatus: "Info",
    evidenceSource: SHAREPOINT_INVENTORY_ENDPOINTS.sites,
    collectionMethod: "Direct",
    permissionRequired: REQUIRED_ROLE,
  });

  if (sites.length === 0) return;

  const sorted = [...sites].sort((a, b) => {
    const ka = psStr(a.webUrl) || psStr(a.displayName);
    const kb = psStr(b.webUrl) || psStr(b.displayName);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  for (const site of sorted) {
    const siteUrl = psStr(site.webUrl) || psStr(site.displayName) || psStr(site.id) || "Unknown site";
    ctx.addRow({
      category: CATEGORY,
      setting: siteUrl,
      currentValue: kv([
        ["SiteUrl", site.webUrl],
        ["SiteId", site.id],
        ["DisplayName", site.displayName],
        ["CreatedDateTime", site.createdDateTime],
        ["LastModifiedDateTime", site.lastModifiedDateTime],
      ]),
      recommendedValue: "",
      psStatus: "Info",
      evidenceSource: SHAREPOINT_INVENTORY_ENDPOINTS.sites,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
};
