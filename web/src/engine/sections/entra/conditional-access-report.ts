/**
 * Port of `src/M365-Assess/Entra/Get-ConditionalAccessReport.ps1` (160 lines)
 * — flattened Conditional Access policy report (plan 02-05 task 2).
 *
 * PS → TS mapping:
 * - Get-MgIdentityConditionalAccessPolicy -All (PS line 43) → getJson
 *   /v1.0/identity/conditionalAccess/policies; failure throws → runner
 *   surfaces a section error (PS Write-Error + return, lines 45-48); empty
 *   set returns zero rows (PS lines 53-56).
 * - GUID→UPN resolution loop (PS lines 58-78): includeUsers+excludeUsers IDs
 *   matching the GUID pattern are resolved via getJson /v1.0/users/{guid}?
 *   $select=userPrincipalName; resolution failure keeps the raw GUID. The PS
 *   OrdinalIgnoreCase HashSet is a lowercase-keyed Map here.
 * - Resolve-UserDisplay sorts AFTER resolution and '; '-joins; null/empty
 *   lists render ''.
 * - Grant controls: >1 control + operator → joined with the operator between
 *   items, else '; '-joined (PS lines 105-118).
 * - Session controls in PS order: SignInFrequency / PersistentBrowser /
 *   CloudAppSecurity / AppEnforcedRestrictions, each only when IsEnabled
 *   (PS lines 120-135).
 * - Report sorted by DisplayName (PS line 150).
 *
 * Row mapping (report collector): one Info row per policy; Setting =
 * DisplayName; CurrentValue = report record Field=Value in PS property order.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { asArray, kv, psSort, psStr } from "./shared";

/** Declared GET path shapes (mirrored into registry endpoints[] by plan 02-12). */
export const CONDITIONAL_ACCESS_REPORT_ENDPOINTS = {
  policies: "/v1.0/identity/conditionalAccess/policies",
  userPrincipalName: "/v1.0/users/{*}?$select=userPrincipalName",
} as const;

const CATEGORY = "Conditional Access";

/** Case-insensitive GUID match (PS -match on '^[0-9a-f-]{36}$' shape). */
const GUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function stringIds(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => typeof v === "string")
    : [];
}

/** Port of Resolve-UserDisplay (PS lines 81-88): resolve, sort, join. */
function resolveUserDisplay(
  userIds: unknown,
  guidToUpn: Map<string, string>,
): string {
  const ids = stringIds(userIds);
  if (ids.length === 0) return "";
  const resolved = ids.map((uid) => guidToUpn.get(uid.toLowerCase()) ?? uid);
  return psSort(resolved).join("; ");
}

function grantControlsText(grantControls: unknown): string {
  const gc = (grantControls ?? {}) as { builtInControls?: unknown; operator?: unknown };
  const controls = stringIds(gc.builtInControls);
  if (controls.length === 0) return "";
  const operator = psStr(gc.operator);
  if (controls.length > 1 && operator) {
    // "mfa AND compliantDevice" shape (PS line 110).
    return controls.join(` ${operator} `);
  }
  return controls.join("; ");
}

interface SessionControlShape {
  isEnabled?: unknown;
  value?: unknown;
  type?: unknown;
  mode?: unknown;
  cloudAppSecurityType?: unknown;
}

function sessionControlsText(sessionControls: unknown): string {
  const sc = (sessionControls ?? {}) as Record<string, SessionControlShape | undefined>;
  const parts: string[] = [];
  if (sc.signInFrequency?.isEnabled) {
    parts.push(
      `SignInFrequency: ${psStr(sc.signInFrequency.value)} ${psStr(sc.signInFrequency.type)}`,
    );
  }
  if (sc.persistentBrowser?.isEnabled) {
    parts.push(`PersistentBrowser: ${psStr(sc.persistentBrowser.mode)}`);
  }
  if (sc.cloudAppSecurity?.isEnabled) {
    parts.push(`CloudAppSecurity: ${psStr(sc.cloudAppSecurity.cloudAppSecurityType)}`);
  }
  if (sc.applicationEnforcedRestrictions?.isEnabled) {
    parts.push("AppEnforcedRestrictions");
  }
  return parts.join("; ");
}

export const runConditionalAccessReport: SectionImplementation = async (ctx) => {
  const policiesResponse = await ctx.transport.getJson(
    CONDITIONAL_ACCESS_REPORT_ENDPOINTS.policies,
    { requiredRole: "Policy.Read.All" },
  );
  const allPolicies = asArray(policiesResponse.value);
  if (allPolicies.length === 0) return;

  // Collect user GUIDs from include + exclude lists, preserving the first
  // original-case spelling for the resolution URL (PS lines 58-65).
  const originalCase = new Map<string, string>();
  for (const policy of allPolicies) {
    const users =
      ((policy.conditions as { users?: { includeUsers?: unknown; excludeUsers?: unknown } })
        ?.users ?? {});
    for (const uid of [...stringIds(users.includeUsers), ...stringIds(users.excludeUsers)]) {
      if (GUID_PATTERN.test(uid) && !originalCase.has(uid.toLowerCase())) {
        originalCase.set(uid.toLowerCase(), uid);
      }
    }
  }
  // Resolve GUIDs to UPNs; failures keep the raw GUID (PS lines 66-78).
  const guidToUpn = new Map<string, string>();
  for (const [key, rawGuid] of originalCase) {
    try {
      const user = await ctx.transport.getJson(
        `/v1.0/users/${encodeURIComponent(rawGuid)}?$select=userPrincipalName`,
        { requiredRole: "User.Read.All" },
      );
      const upn = psStr(user.userPrincipalName);
      guidToUpn.set(key, upn !== "" ? upn : rawGuid);
    } catch {
      guidToUpn.set(key, rawGuid);
    }
  }

  const records = allPolicies.map((policy) => {
    const conditions = (policy.conditions ?? {}) as {
      users?: { includeUsers?: unknown; excludeUsers?: unknown };
      applications?: { includeApplications?: unknown };
    };
    const users = conditions.users ?? {};

    let includeApps: string;
    const appIds = stringIds(conditions.applications?.includeApplications);
    if (appIds.length > 0) {
      includeApps = psSort(appIds).join("; ");
    } else {
      includeApps = "";
    }

    return {
      displayName: psStr(policy.displayName),
      state: psStr(policy.state),
      createdDateTime: psStr(policy.createdDateTime),
      modifiedDateTime: psStr(policy.modifiedDateTime),
      includeUsers: resolveUserDisplay(users.includeUsers, guidToUpn),
      excludeUsers: resolveUserDisplay(users.excludeUsers, guidToUpn),
      includeApplications: includeApps,
      grantControls: grantControlsText(policy.grantControls),
      sessionControls: sessionControlsText(policy.sessionControls),
    };
  });

  records.sort((a, b) => (a.displayName < b.displayName ? -1 : a.displayName > b.displayName ? 1 : 0));

  for (const r of records) {
    ctx.addRow({
      category: CATEGORY,
      setting: r.displayName,
      currentValue: kv([
        ["State", r.state],
        ["CreatedDateTime", r.createdDateTime],
        ["ModifiedDateTime", r.modifiedDateTime],
        ["IncludeUsers", r.includeUsers],
        ["ExcludeUsers", r.excludeUsers],
        ["IncludeApplications", r.includeApplications],
        ["GrantControls", r.grantControls],
        ["SessionControls", r.sessionControls],
      ]),
      recommendedValue: "",
      psStatus: "Info",
    });
  }
};
