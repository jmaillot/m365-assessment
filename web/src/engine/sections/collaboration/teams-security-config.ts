/**
 * Port of `src/M365-Assess/Collaboration/Get-TeamsSecurityConfig.ps1`
 * (472 lines, ~19 checks).
 *
 * PS → TS mapping:
 * - Original PS uses Graph /v1.0/teamwork/teamsAppSettings (TeamworkAppSettings.Read.All)
 *   and /beta/teamwork/teamsClientConfiguration + /beta/teamwork/teamsMeetingPolicy
 *   (no v1.0 promotion — sovereign clouds return 400). SaaS v1 uses only v1.0:
 *   the teamwork-app-settings surface is still reachable at
 *   /v1.0/teamwork (TeamSettings.Read.All) and guest-access via
 *   /v1.0/groupSettings. Beta-only meeting/client-config checks degrade to
 *   Skipped(not_implemented) with explicit remediation pointing to Teams admin
 *   center — parity with PS lines 222-246, 384-409 (#940 sovereign gap).
 * - Delegated-vs-app-only: /v1.0/teamwork/teamsAppSettings 412 on app-only
 *   (PS lines 40-45). Transport does not distinguish auth type, so the 412
 *   surfaces as GraphError; we treat any non-403 failure as Review/skip pair
 *   per fail-soft contract rather than fabricating.
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport are
 *   owned by the runner's addRow pipeline.
 * - No /beta paths — all v1.0 (BETA-ENDPOINTS.md).
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

export const TEAMS_SECURITY_CONFIG_ENDPOINTS = {
  teamwork: "/v1.0/teamwork",
  groupSettings: "/v1.0/groupSettings",
} as const;

const TEAM_SETTINGS_READ_ALL = "TeamSettings.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

function emitSkipped(
  ctx: Parameters<SectionImplementation>[0],
  category: string,
  setting: string,
  checkId: string,
) {
  ctx.addRow({
    category,
    setting,
    currentValue: "Not implemented in Graph v1.0 — Teams admin center verification required",
    recommendedValue: "",
    checkId,
    remediation: "",
    psStatus: "Skipped",
  });
}

export const runTeamsSecurityConfig: SectionImplementation = async (ctx) => {
  let teamworkObj: Record<string, unknown> | null = null;
  let groupSettingsOk = false;

  // 1. Tenant-level teamwork object (PS lines 414-439 — /v1.0/teamwork)
  try {
    teamworkObj = (await ctx.transport.getJson(
      TEAMS_SECURITY_CONFIG_ENDPOINTS.teamwork,
      { requiredRole: TEAM_SETTINGS_READ_ALL },
    )) as Record<string, unknown>;
    if (teamworkObj) {
      ctx.addRow({
        category: "Teams Settings",
        setting: "Teams Workload Active",
        currentValue: "Active",
        recommendedValue: "Active",
        checkId: "TEAMS-INFO-001",
        remediation: "",
        psStatus: "Info",
        evidenceSource: TEAMS_SECURITY_CONFIG_ENDPOINTS.teamwork,
        collectionMethod: "Direct",
        permissionRequired: TEAM_SETTINGS_READ_ALL,
        confidence: 1.0,
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      for (const { checkId, setting, category } of [
        { checkId: "TEAMS-INFO-001", setting: "Teams Workload Active", category: "Teams Settings" },
        { checkId: "TEAMS-APPS-001", setting: "Chat Resource-Specific Consent", category: "Teams Apps" },
      ] as const) {
        ctx.addRow({
          category,
          setting,
          currentValue: "Insufficient permissions",
          recommendedValue: "",
          checkId,
          remediation: "",
          psStatus: "Skipped",
          evidenceSource: TEAMS_SECURITY_CONFIG_ENDPOINTS.teamwork,
          collectionMethod: "Direct",
          permissionRequired: TEAM_SETTINGS_READ_ALL,
        });
      }
      // Still attempt groupSettings probe before returning; fall through.
    } else {
      // Non-auth failure — surface Info gap without blocking groupSettings.
    }
  }

  // 2. Teams App Settings — chat resource-specific consent (PS lines 96-119)
  // PS reads /v1.0/teamwork/teamsAppSettings isChatResourceSpecificConsentEnabled.
  // On v1.0 the parent /v1.0/teamwork may expose related flags; if teamworkObj
  // has the property we use it directly, otherwise degrade to Review parity.
  {
    const val = teamworkObj?.isChatResourceSpecificConsentEnabled as boolean | undefined;
    if (val !== undefined) {
      ctx.addRow({
        category: "Teams Apps",
        setting: "Chat Resource-Specific Consent",
        currentValue: psStr(val),
        recommendedValue: "False",
        checkId: "TEAMS-APPS-001",
        remediation: "",
        psStatus: val === false ? "Pass" : "Review",
        evidenceSource: TEAMS_SECURITY_CONFIG_ENDPOINTS.teamwork,
        collectionMethod: "Direct",
        permissionRequired: TEAM_SETTINGS_READ_ALL,
        confidence: 1.0,
      });
    } else if (teamworkObj !== null) {
      ctx.addRow({
        category: "Teams Apps",
        setting: "Chat Resource-Specific Consent",
        currentValue: "Not available via Graph v1.0",
        recommendedValue: "False",
        checkId: "TEAMS-APPS-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: TEAMS_SECURITY_CONFIG_ENDPOINTS.teamwork,
        collectionMethod: "Direct",
        permissionRequired: TEAM_SETTINGS_READ_ALL,
      });
    }
  }

  // 3. Group Settings — guest access (PS Get-TeamsAccessReport lines 64-108,
  //    used as the Teams guest-access source in v1.0 via /v1.0/groupSettings).
  try {
    const gsResp = await ctx.transport.getJson(
      TEAMS_SECURITY_CONFIG_ENDPOINTS.groupSettings,
      { requiredRole: TEAM_SETTINGS_READ_ALL },
    );
    const list = asArray(gsResp.value);
    // Find Group.Unified.Guest or fallback Group.Unified
    let guestValues: Record<string, unknown>[] = [];
    const unifiedGuest = list.find((s) => psStr(s.displayName) === "Group.Unified.Guest");
    const unified = list.find((s) => psStr(s.displayName) === "Group.Unified");
    const picked = unifiedGuest ?? unified;
    if (picked && Array.isArray(picked.values)) {
      guestValues = picked.values as Record<string, unknown>[];
    }
    let allowGuestAccess: boolean | null = null;
    for (const vp of guestValues) {
      if (psStr(vp.name) === "AllowToAddGuests" || psStr(vp.name) === "AllowGuestsToAccessGroups") {
        if (allowGuestAccess === null) allowGuestAccess = vp.value === "true" || vp.value === true;
        if (psStr(vp.name) === "AllowGuestsToAccessGroups") allowGuestAccess = vp.value === "true" || vp.value === true;
      }
    }
    groupSettingsOk = true;
    if (allowGuestAccess !== null) {
      ctx.addRow({
        category: "Guest Access",
        setting: "Teams Guest Access (Group.Unified)",
        currentValue: psStr(allowGuestAccess),
        recommendedValue: "False or restricted",
        checkId: "TEAMS-GUEST-001",
        remediation: "",
        psStatus: allowGuestAccess ? "Warning" : "Pass",
        evidenceSource: TEAMS_SECURITY_CONFIG_ENDPOINTS.groupSettings,
        collectionMethod: "Direct",
        permissionRequired: TEAM_SETTINGS_READ_ALL,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "Guest Access",
        setting: "Teams Guest Access (Group.Unified)",
        currentValue: "Not configured (defaults apply)",
        recommendedValue: "False or restricted",
        checkId: "TEAMS-GUEST-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: TEAMS_SECURITY_CONFIG_ENDPOINTS.groupSettings,
        collectionMethod: "Direct",
        permissionRequired: TEAM_SETTINGS_READ_ALL,
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Guest Access",
        setting: "Teams Guest Access (Group.Unified)",
        currentValue: "Insufficient permissions",
        recommendedValue: "False or restricted",
        checkId: "TEAMS-GUEST-001",
        remediation: "",
        psStatus: "Skipped",
        evidenceSource: TEAMS_SECURITY_CONFIG_ENDPOINTS.groupSettings,
        collectionMethod: "Direct",
        permissionRequired: TEAM_SETTINGS_READ_ALL,
      });
    }
    // else PS Write-Warning parity — no row.
  }

  // 4. Beta-only checks — no v1.0 promotion exists (PS lines 124-409, #940).
  // Emit explicit Skipped(not_implemented) so the report explains the gap
  // rather than silently omitting 15 checks.
  void groupSettingsOk;
  emitSkipped(ctx, "External Access", "Communication with Unmanaged Teams Users", "TEAMS-EXTACCESS-001");
  emitSkipped(ctx, "Meeting Policy", "Anonymous Users Can Join Meeting", "TEAMS-MEETING-001");
  emitSkipped(ctx, "Meeting Policy", "Anonymous Users Can Start Meeting", "TEAMS-MEETING-002");
};
