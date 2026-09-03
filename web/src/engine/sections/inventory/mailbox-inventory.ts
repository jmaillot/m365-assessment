/**
 * Port of `src/M365-Assess/Inventory/Get-MailboxInventory.ps1` (125 lines)
 * — per-mailbox inventory (M&A due-diligence / migration planning).
 *
 * PS → TS mapping:
 * - Original PS uses ExchangeOnlineManagement cmdlets (Get-EXOMailbox,
 *   Get-EXOMailboxStatistics) with no Graph REST equivalent for EXO sizing/
 *   forwarding/hold properties — Exchange admin surfaces remain non-v1-promoted
 *   (BETA-ENDPOINTS.md, REMOVED-CAPABILITIES §3). The SaaS pivots to the
 *   supported Graph Directory surface that reflects mailbox identity posture:
 *   `/v1.0/users` and `/v1.0/groups` (Directory.Read.All) — the directory
 *   carriers for every mail-enabled object whose mailbox inventory the PS
 *   enumerates. Sizing/forwarding/hold remain EXO-only and are documented as
 *   limitations rather than fabricated.
 * - PS output is PSCustomObject per mailbox with size/itemCount/forwarding —
 *   the TS emits one Info row per directory user (Setting = UPN/displayName)
 *   plus a summary row, using `kv` in PS property order for PS CSV parity.
 * - Read-only: GET only via ctx.transport.getJson (v1.0).
 * - Permissions: Directory.Read.All (v1.0). 403-family → Skipped via
 *   errMatches (PS permission-branch parity); TransportFatalError rethrown
 *   (isRoleGranted gate / routing bug); generic → fail-soft zero rows.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, kv, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const MAILBOX_INVENTORY_ENDPOINTS = {
  users: "/v1.0/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime&$top=999",
  groups: "/v1.0/groups?$select=id,displayName,mail,mailEnabled,securityEnabled,groupTypes,createdDateTime&$top=999",
} as const;

const REQUIRED_ROLE = "Directory.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const CATEGORY = "Mailbox Inventory";

export const runMailboxInventory: SectionImplementation = async (ctx) => {
  let users: Record<string, unknown>[];
  try {
    const resp = await ctx.transport.getJson(MAILBOX_INVENTORY_ENDPOINTS.users, {
      requiredRole: REQUIRED_ROLE,
    });
    users = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: CATEGORY,
        setting: "Mailbox Inventory (Directory)",
        currentValue: "Insufficient permissions",
        recommendedValue: "",
        psStatus: "Skipped",
        evidenceSource: MAILBOX_INVENTORY_ENDPOINTS.users,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
      return;
    }
    return;
  }

  // Optional groups probe — enriches mail-enabled group context; fail-soft per PS Write-Warning parity.
  let groupList: Record<string, unknown>[] = [];
  try {
    const gResp = await ctx.transport.getJson(MAILBOX_INVENTORY_ENDPOINTS.groups, {
      requiredRole: REQUIRED_ROLE,
    });
    groupList = asArray(gResp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      // No extra Skipped row — users branch already covers the permission gap.
    }
    groupList = [];
  }

  const mailEnabledGroups = groupList.filter((g) => g.mailEnabled === true).length;

  // Summary row — PS Write-Verbose count parity.
  ctx.addRow({
    category: CATEGORY,
    setting: "Inventory Summary",
    currentValue: kv([
      ["TotalUsers", users.length],
      ["TotalGroups", groupList.length],
      ["MailEnabledGroups", mailEnabledGroups],
    ]),
    recommendedValue: "",
    psStatus: "Info",
    evidenceSource: MAILBOX_INVENTORY_ENDPOINTS.users,
    collectionMethod: "Direct",
    permissionRequired: REQUIRED_ROLE,
    limitations:
      "Graph /v1.0/users cannot return EXO mailbox size/itemCount/forwarding/hold; use Exchange Online PowerShell for those properties (REMOVED-CAPABILITIES §3).",
  });

  // Per-user rows — one Info row per directory user (mailbox carrier), sorted by UPN like PS sort.
  const sorted = [...users].sort((a, b) => {
    const ka = psStr(a.userPrincipalName) || psStr(a.displayName);
    const kb = psStr(b.userPrincipalName) || psStr(b.displayName);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  for (const user of sorted) {
    const upn = psStr(user.userPrincipalName) || psStr(user.displayName) || psStr(user.id) || "Unknown";
    ctx.addRow({
      category: CATEGORY,
      setting: upn,
      currentValue: kv([
        ["DisplayName", user.displayName],
        ["PrimarySmtpAddress", user.mail ?? user.userPrincipalName],
        ["UserPrincipalName", user.userPrincipalName],
        ["AccountEnabled", user.accountEnabled],
        ["UserType", user.userType],
        ["WhenCreated", user.createdDateTime],
      ]),
      recommendedValue: "",
      psStatus: "Info",
      evidenceSource: MAILBOX_INVENTORY_ENDPOINTS.users,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
};
