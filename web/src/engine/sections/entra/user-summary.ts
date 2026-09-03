/**
 * Port of `src/M365-Assess/Entra/Get-UserSummary.ps1` (165 lines) — aggregate
 * user counts by type and status (plan 02-05 task 1).
 *
 * PS → TS mapping:
 * - Invoke-MgGraphRequest paginated users loop (PS lines 49-80) → ONE
 *   ctx.transport.getJson call; @odata.nextLink pagination is a transport
 *   guarantee (D-27), so the do/while collapses into a single awaited call.
 *   `ConsistencyLevel: eventual` forwarded verbatim (PS line 57).
 * - signInActivity fallback retry (PS lines 59-68): on failure whose TEXT
 *   matches the PS set ('signInActivity|AuditLog|Authorization_RequestDenied|
 *   Insufficient privileges|Neither combinator', case-insensitive like
 *   -match) retry once WITHOUT signInActivity in $select; any other error —
 *   or a failing fallback retry — rethrows (PS Write-Error + return).
 * - Counting branches ported literally, INCLUDING the quirk that every
 *   non-synced user counts as CloudOnly (PS else-branch, line 120-122).
 * - NeverSignedIn/StaleMember stay null (rendered empty) when the fallback
 *   ran, exactly as PS initializes them to $null outside the fallback path.
 *
 * Row mapping: single Info row; Setting = "Aggregate Counts"; CurrentValue =
 * the report record Field=Value summary in PS property order. Stale-member
 * threshold is now-90d like PS (Get-Date).AddDays(-90); tests freeze the
 * clock for determinism.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { asArray, kv } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const USER_SUMMARY_ENDPOINTS = {
  usersFullSelect:
    "/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,assignedLicenses,onPremisesSyncEnabled,signInActivity&$top=999",
  usersNoSignInActivity:
    "/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,assignedLicenses,onPremisesSyncEnabled&$top=999",
} as const;

const CONSISTENCY_LEVEL = { ConsistencyLevel: "eventual" } as const;

const SIGNIN_FALLBACK_PATTERN =
  /signInActivity|AuditLog|Authorization_RequestDenied|Insufficient privileges|Neither combinator/i;

const CATEGORY = "User Summary";

interface UserSummaryCounts {
  totalUsers: number;
  licensedCount: number;
  guestCount: number;
  disabledCount: number;
  syncedCount: number;
  cloudOnlyCount: number;
  activeSignInCount: number;
  neverSignedInCount: number | null;
  staleMemberCount: number | null;
}

export const runUserSummary: SectionImplementation = async (ctx) => {
  let fallback = false;
  let users: Record<string, unknown>[];
  try {
    const response = await ctx.transport.getJson(
      USER_SUMMARY_ENDPOINTS.usersFullSelect,
      { headers: { ...CONSISTENCY_LEVEL }, requiredRole: "User.Read.All" },
    );
    users = asArray(response.value);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (!fallback && SIGNIN_FALLBACK_PATTERN.test(message)) {
      // signInActivity requires AuditLog.Read.All + AAD Premium; retry without it.
      fallback = true;
      const retry = await ctx.transport.getJson(
        USER_SUMMARY_ENDPOINTS.usersNoSignInActivity,
        { headers: { ...CONSISTENCY_LEVEL }, requiredRole: "User.Read.All" },
      );
      users = asArray(retry.value);
    } else {
      throw err;
    }
  }

  const totalUsers = users.length;

  // Get-UserSummary.ps1:93-143 — counting branches ported literally.
  let licensedCount = 0;
  let guestCount = 0;
  let disabledCount = 0;
  let syncedCount = 0;
  let cloudOnlyCount = 0;
  let activeSignInCount = 0;
  let neverSignedInCount: number | null = null;
  let staleMemberCount: number | null = null;

  const staleThreshold = Date.now() - 90 * 24 * 60 * 60 * 1000;

  for (const user of users) {
    const assignedLicenses = user.assignedLicenses;
    if (Array.isArray(assignedLicenses) && assignedLicenses.length > 0) {
      licensedCount += 1;
    }

    if (user.userType === "Guest") guestCount += 1;

    if (user.accountEnabled === false) disabledCount += 1;

    if (user.onPremisesSyncEnabled === true) {
      syncedCount += 1;
    } else {
      // PS parity quirk: EVERY non-synced user (incl. guests/disabled with
      // null flags) lands here — Get-UserSummary.ps1:117-122.
      cloudOnlyCount += 1;
    }

    // Sign-in activity available only with AuditLog.Read.All + AAD Premium.
    if (!fallback) {
      const signInActivity = user.signInActivity as
        | { lastSignInDateTime?: unknown }
        | undefined;
      const lastSignIn = signInActivity?.lastSignInDateTime;
      if (lastSignIn) {
        activeSignInCount += 1;
      } else {
        if (neverSignedInCount === null) neverSignedInCount = 0;
        neverSignedInCount += 1;
      }

      // Stale member: enabled member account with no sign-in in 90 days (or never).
      if (user.accountEnabled === true && user.userType !== "Guest") {
        if (staleMemberCount === null) staleMemberCount = 0;
        const lastSignInMs =
          typeof lastSignIn === "string" ? Date.parse(lastSignIn) : NaN;
        if (!lastSignIn || Number.isNaN(lastSignInMs) || lastSignInMs < staleThreshold) {
          staleMemberCount += 1;
        }
      }
    }
  }

  const counts: UserSummaryCounts = {
    totalUsers,
    licensedCount,
    guestCount,
    disabledCount,
    syncedCount,
    cloudOnlyCount,
    activeSignInCount,
    neverSignedInCount,
    staleMemberCount,
  };

  ctx.addRow({
    category: CATEGORY,
    setting: "Aggregate Counts",
    currentValue: kv([
      ["TotalUsers", counts.totalUsers],
      ["Licensed", counts.licensedCount],
      ["GuestUsers", counts.guestCount],
      ["DisabledUsers", counts.disabledCount],
      ["SyncedFromOnPrem", counts.syncedCount],
      ["CloudOnly", counts.cloudOnlyCount],
      ["WithMFA", counts.activeSignInCount],
      ["NeverSignedIn", counts.neverSignedInCount],
      ["StaleMember", counts.staleMemberCount],
    ]),
    recommendedValue: "",
    psStatus: "Info",
  });
};
