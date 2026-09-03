/**
 * Port of `src/M365-Assess/Inventory/Get-TeamsInventory.ps1` (192 lines)
 * — per-team inventory (owners, member counts, channel counts).
 *
 * PS → TS mapping:
 * - PS enumerates Teams-enabled groups via Groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')
 *   then fans out to /teams/{id}, /groups/{id}/owners, /groups/{id}/members, /teams/{id}/channels.
 *   Minimal functional port retains the filter list as the inventory source — one
 *   Info row per Team-enabled group (DisplayName/visibility/mail/createdDateTime),
 *   plus a summary. Per-team fan-out (owners/members/channels/archived) is deferred
 *   to keep the port fail-soft and page-efficient; the summary documents the limitation.
 * - Directory.Read.All is the documented least-privilege for the group filter
 *   (task spec); Group.Read.All/Team.ReadBasic.All branches degrade identically
 *   to Skipped on 403-family via errMatches.
 * - v1.0 only; GET only; fail-soft.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, kv, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const TEAMS_INVENTORY_ENDPOINTS = {
  teamsGroups:
    "/v1.0/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName,description,visibility,createdDateTime,mail&$top=999",
} as const;

const REQUIRED_ROLE = "Directory.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const CATEGORY = "Teams Inventory";

export const runTeamsInventory: SectionImplementation = async (ctx) => {
  let teams: Record<string, unknown>[];
  try {
    const resp = await ctx.transport.getJson(TEAMS_INVENTORY_ENDPOINTS.teamsGroups, {
      requiredRole: REQUIRED_ROLE,
    });
    teams = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: CATEGORY,
        setting: "Teams Inventory",
        currentValue: "Insufficient permissions",
        recommendedValue: "",
        psStatus: "Skipped",
        evidenceSource: TEAMS_INVENTORY_ENDPOINTS.teamsGroups,
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
    currentValue: kv([["TotalTeams", teams.length]]),
    recommendedValue: "",
    psStatus: "Info",
    evidenceSource: TEAMS_INVENTORY_ENDPOINTS.teamsGroups,
    collectionMethod: "Direct",
    permissionRequired: REQUIRED_ROLE,
    limitations:
      "Per-team owners/members/channels require Group.Read.All + Team.ReadBasic.All fan-out; minimal port reports directory team list only.",
  });

  if (teams.length === 0) return;

  const sorted = [...teams].sort((a, b) => {
    const ka = psStr(a.displayName);
    const kb = psStr(b.displayName);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  for (const team of sorted) {
    const displayName = psStr(team.displayName) || psStr(team.id) || "Unknown team";
    ctx.addRow({
      category: CATEGORY,
      setting: displayName,
      currentValue: kv([
        ["DisplayName", team.displayName],
        ["Mail", team.mail],
        ["Visibility", team.visibility],
        ["Description", team.description],
        ["CreatedDateTime", team.createdDateTime],
      ]),
      recommendedValue: "",
      psStatus: "Info",
      evidenceSource: TEAMS_INVENTORY_ENDPOINTS.teamsGroups,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
};
