/**
 * Port of `src/M365-Assess/Inventory/Get-GroupInventory.ps1` (174 lines)
 * — per-group inventory (distribution lists, mail-enabled security groups,
 *   Microsoft 365 groups).
 *
 * PS → TS mapping:
 * - PS uses ExchangeOnlineManagement cmdlets Get-DistributionGroup (+
 *   Get-DistributionGroupMember) and Get-UnifiedGroup — EXO-only with no
 *   v1.0 Graph parity for DL member enumeration/classic DL typing. The SaaS
 *   pivots to the v1.0 Directory group collection `GET /v1.0/groups`
 *   (Directory.Read.All) which surfaces M365 groups, security groups, and
 *   mail-enabled groups in a unified shape. DL-specific name/type distinctions
 *   and per-DL member counts (PS -SkipMemberCount switch) are documented as
 *   limitations; the directory group count and type summary satisfy inventory
 *   coverage without EXO.
 * - One Info row per group plus a summary row (kv parity with PS Export-Csv fields).
 * - v1.0 only; GET only; fail-soft; 403-family → Skipped.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, kv, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const GROUP_INVENTORY_ENDPOINTS = {
  groups:
    "/v1.0/groups?$select=id,displayName,mail,groupTypes,mailEnabled,securityEnabled,visibility,createdDateTime&$top=999",
} as const;

const REQUIRED_ROLE = "Directory.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const CATEGORY = "Group Inventory";

function groupTypeOf(group: Record<string, unknown>): string {
  const types = group.groupTypes;
  const arr = Array.isArray(types) ? (types as string[]) : [];
  if (arr.includes("Unified")) return "M365Group";
  if (group.mailEnabled === true && group.securityEnabled === true) return "MailEnabledSecurity";
  if (group.mailEnabled === true) return "DistributionList";
  if (group.securityEnabled === true) return "SecurityGroup";
  return "Group";
}

export const runGroupInventory: SectionImplementation = async (ctx) => {
  let groups: Record<string, unknown>[];
  try {
    const resp = await ctx.transport.getJson(GROUP_INVENTORY_ENDPOINTS.groups, {
      requiredRole: REQUIRED_ROLE,
    });
    groups = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: CATEGORY,
        setting: "Group Inventory",
        currentValue: "Insufficient permissions",
        recommendedValue: "",
        psStatus: "Skipped",
        evidenceSource: GROUP_INVENTORY_ENDPOINTS.groups,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
      return;
    }
    return;
  }

  const m365Count = groups.filter((g) => {
    const t = g.groupTypes;
    return Array.isArray(t) && (t as string[]).includes("Unified");
  }).length;
  const mailEnabledCount = groups.filter((g) => g.mailEnabled === true).length;
  const securityCount = groups.filter((g) => g.securityEnabled === true).length;

  ctx.addRow({
    category: CATEGORY,
    setting: "Inventory Summary",
    currentValue: kv([
      ["TotalGroups", groups.length],
      ["M365Groups", m365Count],
      ["MailEnabled", mailEnabledCount],
      ["SecurityEnabled", securityCount],
    ]),
    recommendedValue: "",
    psStatus: "Info",
    evidenceSource: GROUP_INVENTORY_ENDPOINTS.groups,
    collectionMethod: "Direct",
    permissionRequired: REQUIRED_ROLE,
    limitations:
      "Graph /v1.0/groups cannot distinguish classic EXO distribution lists nor enumerate DL members; use Exchange Online PowerShell for per-DL member counts.",
  });

  if (groups.length === 0) return;

  const sorted = [...groups].sort((a, b) => {
    const ta = groupTypeOf(a);
    const tb = groupTypeOf(b);
    if (ta < tb) return -1;
    if (ta > tb) return 1;
    const ka = psStr(a.displayName);
    const kb = psStr(b.displayName);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  for (const group of sorted) {
    const displayName = psStr(group.displayName) || psStr(group.mail) || psStr(group.id) || "Unknown group";
    ctx.addRow({
      category: CATEGORY,
      setting: displayName,
      currentValue: kv([
        ["DisplayName", group.displayName],
        ["PrimarySmtpAddress", group.mail],
        ["GroupType", groupTypeOf(group)],
        ["Visibility", group.visibility],
        ["WhenCreated", group.createdDateTime],
      ]),
      recommendedValue: "",
      psStatus: "Info",
      evidenceSource: GROUP_INVENTORY_ENDPOINTS.groups,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
};
