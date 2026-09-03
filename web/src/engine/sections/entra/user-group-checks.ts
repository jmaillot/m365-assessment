/**
 * Port of `src/M365-Assess/Entra/EntraUserGroupChecks.ps1` (783 lines)
 * — check-helper half of Get-EntraSecurityConfig.ps1 (plan 02-07 task 2).
 *
 * PS shared-scope state → run store + module-local logic:
 * - $authPolicy is pre-fetched ONCE by Get-EntraSecurityConfig.ps1:61-72 with
 *   soft-fail and reused by sections 3-5, 10, 16; sections 9b, 17 (reads only)
 *   and 26 re-fetch /v1.0/policies/authorizationPolicy live. The port reads
 *   ctx.shared("entra.authPolicy") first; when absent it performs the same
 *   soft-fail pre-fetch and stores the result so a composing collector
 *   (plan 02-08) sees exactly one fetch, matching PS.
 * - $orgSettings (section 14 LinkedIn fetch) is stored to
 *   ctx.shared("entra.orgSettings") for EntraPasswordAuthChecks section 27.
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting: owned by the runner's addRow
 *   pipeline (mapStatus → sub-numbering → D-22 registry fallback).
 * - Invoke-MgGraphRequest GET → ctx.transport.getJson with requiredRole;
 *   ConsistencyLevel: eventual forwarded on the advanced-query $count call
 *   sites (PS lines 349, 752-758).
 * - Beta endpoints promoted to v1.0 per BETA-ENDPOINTS.md:
 *   organization/{tenantId} and the userRegistrationDetails probe.
 * - Soft-fail semantics preserved: catch blocks emit their PS Skipped row
 *   verbatim or degrade to zero rows; TransportFatalError propagates.
 * - PS $owners persistence quirk in section 25 reproduced faithfully: with
 *   -ErrorAction SilentlyContinue a failed owners fetch keeps the PREVIOUS
 *   loop iteration's value (PS variable persistence), not an empty one.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import type { PsStatus } from "@/engine/results/row-contract";
import { asArray, errMatches, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const USER_GROUP_ENDPOINTS = {
  authorizationPolicy: "/v1.0/policies/authorizationPolicy",
  adminConsentRequestPolicy: "/v1.0/policies/adminConsentRequestPolicy",
  allPrincipalsGrants:
    "/v1.0/oauth2PermissionGrants?$filter=consentType%20eq%20%27AllPrincipals%27&$top=999",
  guestCount: "/v1.0/users/$count?$filter=userType%20eq%20%27Guest%27",
  memberCount: "/v1.0/users/$count?$filter=userType%20eq%20%27Member%27",
  disabledMemberCount:
    "/v1.0/users/$count?$filter=accountEnabled%20eq%20false%20and%20userType%20eq%20%27Member%27",
  crossTenantDefault: "/v1.0/policies/crossTenantAccessPolicy/default",
  dynamicGroups:
    "/v1.0/groups?$filter=groupTypes/any(g:g%20eq%20%27DynamicMembership%27)&$select=displayName,membershipRule&$top=999",
  unifiedGroups:
    "/v1.0/groups?$filter=groupTypes/any(g:g%20eq%20%27Unified%27)&$select=displayName,id,visibility&$top=999",
  userRegistrationDetailsProbe:
    "/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isMfaRegistered,isMfaCapable&$top=1",
} as const;

type GraphObj = Record<string, unknown>;

const POLICY_READ_ALL = "Policy.Read.All";
const DIRECTORY_READ_ALL = "Directory.Read.All";
const USER_READ_ALL = "User.Read.All";
const GROUP_READ_ALL = "Group.Read.All";

/** PS catch-row remediation used by every Skipped branch in this file. */
const PERMISSIONS_RETRY = "Check Graph API permissions and retry.";

const CONSISTENCY_EVENTUAL = { ConsistencyLevel: "eventual" };

function includes(list: unknown, item: string): boolean {
  return Array.isArray(list) && (list as unknown[]).includes(item);
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? (value as string[]) : [];
}

/** PS [math]::Round parity (.NET banker's rounding to digits decimals). */
function psRound(value: number, digits: number): number {
  const factor = 10 ** digits;
  const scaled = value * factor;
  const floor = Math.floor(scaled);
  const diff = scaled - floor;
  let rounded: number;
  if (diff > 0.5) rounded = floor + 1;
  else if (diff < 0.5) rounded = floor;
  else rounded = floor % 2 === 0 ? floor : floor + 1;
  return rounded / factor;
}

export const runUserGroupChecks: SectionImplementation = async (ctx) => {
  // Shared $authPolicy acquisition (Get-EntraSecurityConfig.ps1:60-72).
  let authPolicy = ctx.shared.get("entra.authPolicy") as GraphObj | null | undefined;
  if (authPolicy === undefined) {
    try {
      authPolicy = (await ctx.transport.getJson(USER_GROUP_ENDPOINTS.authorizationPolicy, {
        requiredRole: POLICY_READ_ALL,
      })) as GraphObj;
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      authPolicy = null;
    }
    ctx.shared.set("entra.authPolicy", authPolicy);
  }

  // ------------------------------------------------------------------
  // 3-5. Authorization Policy checks (PS lines 13-142)
  // ------------------------------------------------------------------
  if (authPolicy) {
    const durp = authPolicy.defaultUserRolePermissions as GraphObj | undefined;

    // 3. User Consent for Applications
    try {
      const consentPolicy = durp?.permissionGrantPoliciesAssigned;
      const list = Array.isArray(consentPolicy)
        ? (consentPolicy as unknown[])
        : null;
      const isEmpty = list === null || list.length === 0;

      let consentValue: string;
      if (includes(list, "ManagePermissionGrantsForSelf.microsoft-user-default-legacy")) {
        consentValue = "Allow user consent (legacy)";
      } else if (includes(list, "ManagePermissionGrantsForSelf.microsoft-user-default-low")) {
        consentValue = "Allow user consent for low-impact apps";
      } else if (isEmpty) {
        consentValue = "Do not allow user consent";
      } else {
        consentValue = stringList(list).join("; ");
      }

      ctx.addRow({
        category: "Application Consent",
        setting: "User Consent for Applications",
        currentValue: consentValue,
        recommendedValue: "Do not allow user consent",
        psStatus: isEmpty ? "Pass" : "Fail",
        checkId: "ENTRA-CONSENT-001",
        remediation:
          "Run: Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{PermissionGrantPoliciesAssigned = @()}. Entra admin center > Enterprise applications > Consent and permissions.",
      });
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      ctx.addRow({
        category: "Application Consent",
        setting: "User Consent for Applications",
        currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
        recommendedValue: "Do not allow user consent",
        psStatus: "Skipped",
        checkId: "ENTRA-CONSENT-001",
        remediation: PERMISSIONS_RETRY,
      });
    }

    // 4. Users Can Register Applications
    try {
      const canRegister = durp?.allowedToCreateApps;
      ctx.addRow({
        category: "Application Consent",
        setting: "Users Can Register Applications",
        currentValue: psStr(canRegister),
        recommendedValue: "False",
        psStatus: canRegister ? "Fail" : "Pass",
        checkId: "ENTRA-APPREG-001",
        remediation:
          "Run: Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{AllowedToCreateApps = $false}. Entra admin center > Users > User settings.",
      });
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      ctx.addRow({
        category: "Application Consent",
        setting: "Users Can Register Applications",
        currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
        recommendedValue: "False",
        psStatus: "Skipped",
        checkId: "ENTRA-APPREG-001",
        remediation: PERMISSIONS_RETRY,
      });
    }

    // 5. Users Can Create Security Groups
    try {
      const canCreateGroups = durp?.allowedToCreateSecurityGroups;
      ctx.addRow({
        category: "Directory Settings",
        setting: "Users Can Create Security Groups",
        currentValue: psStr(canCreateGroups),
        recommendedValue: "False",
        psStatus: canCreateGroups ? "Warning" : "Pass",
        checkId: "ENTRA-GROUP-001",
        remediation:
          "Run: Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{AllowedToCreateSecurityGroups = $false}. Entra admin center > Groups > General.",
      });
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      ctx.addRow({
        category: "Directory Settings",
        setting: "Users Can Create Security Groups",
        currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
        recommendedValue: "False",
        psStatus: "Skipped",
        checkId: "ENTRA-GROUP-001",
        remediation: PERMISSIONS_RETRY,
      });
    }

    // 5b. Restrict Non-Admin Tenant Creation (CIS 5.1.2.3)
    try {
      const canCreateTenants = durp?.allowedToCreateTenants;
      ctx.addRow({
        category: "Directory Settings",
        setting: "Non-Admin Tenant Creation Restricted",
        currentValue: psStr(canCreateTenants),
        recommendedValue: "False",
        psStatus: canCreateTenants ? "Warning" : "Pass",
        checkId: "ENTRA-TENANT-001",
        remediation:
          "Run: Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{AllowedToCreateTenants = $false}. Entra admin center > Users > User settings.",
      });
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      ctx.addRow({
        category: "Directory Settings",
        setting: "Non-Admin Tenant Creation Restricted",
        currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
        recommendedValue: "False",
        psStatus: "Skipped",
        checkId: "ENTRA-TENANT-001",
        remediation: PERMISSIONS_RETRY,
      });
    }
  }

  // ------------------------------------------------------------------
  // 6. Admin Consent Workflow (PS lines 147-180)
  // ------------------------------------------------------------------
  try {
    const adminConsentSettings = await ctx.transport.getJson(
      USER_GROUP_ENDPOINTS.adminConsentRequestPolicy,
      { requiredRole: POLICY_READ_ALL },
    );
    const isAdminConsentEnabled = adminConsentSettings.isEnabled;

    ctx.addRow({
      category: "Application Consent",
      setting: "Admin Consent Workflow Enabled",
      currentValue: psStr(isAdminConsentEnabled),
      recommendedValue: "True",
      psStatus: isAdminConsentEnabled ? "Pass" : "Warning",
      checkId: "ENTRA-CONSENT-002",
      remediation:
        "Run: Update-MgPolicyAdminConsentRequestPolicy -IsEnabled $true. Entra admin center > Enterprise applications > Admin consent requests.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "Application Consent",
      setting: "Admin Consent Workflow Enabled",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue: "True",
      psStatus: "Skipped",
      checkId: "ENTRA-CONSENT-002",
      remediation: PERMISSIONS_RETRY,
    });
  }

  // ------------------------------------------------------------------
  // 9b. User consent restricted to verified publishers (PS lines 185-222)
  // ------------------------------------------------------------------
  try {
    const authzPolicy = await ctx.transport.getJson(
      USER_GROUP_ENDPOINTS.authorizationPolicy,
      { requiredRole: POLICY_READ_ALL },
    );
    const consentSettings = authzPolicy.defaultUserRolePermissions as
      | GraphObj
      | undefined;
    const consentAllowed = consentSettings?.permissionGrantPoliciesAssigned;

    // CISA SCuBA MS.AAD.5.2v1: consent should require verified publisher.
    const requiresVerified =
      Array.isArray(consentAllowed) &&
      (includes(consentAllowed, "microsoft-user-default-low") ||
        includes(consentAllowed, "microsoft-application-admin"));

    const isEmpty = !Array.isArray(consentAllowed) || consentAllowed.length === 0;
    ctx.addRow({
      category: "Application Consent",
      setting: "User Consent Requires Verified Publisher",
      currentValue: requiresVerified
        ? "Restricted to verified publishers"
        : isEmpty
          ? "User consent fully blocked"
          : `Consent policies: ${stringList(consentAllowed).join(", ")}`,
      recommendedValue:
        "User consent restricted to verified publishers or fully blocked",
      psStatus: requiresVerified || isEmpty ? "Pass" : "Warning",
      checkId: "ENTRA-CONSENT-003",
      remediation:
        "Entra admin center > Enterprise applications > Consent and permissions > User consent settings > Allow consent only from verified publishers or block user consent entirely.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "Application Consent",
      setting: "User Consent Requires Verified Publisher",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue:
        "User consent restricted to verified publishers or fully blocked",
      psStatus: "Skipped",
      checkId: "ENTRA-CONSENT-003",
      remediation: PERMISSIONS_RETRY,
    });
  }

  // ------------------------------------------------------------------
  // 9c. Tenant-wide admin consent grants (PS lines 227-260)
  // ------------------------------------------------------------------
  try {
    const allPrincipalGrants = await ctx.transport.getJson(
      USER_GROUP_ENDPOINTS.allPrincipalsGrants,
      { requiredRole: DIRECTORY_READ_ALL },
    );
    const tenantWideGrants = asArray(allPrincipalGrants.value);
    const grantCount = tenantWideGrants.length;

    ctx.addRow({
      category: "Application Consent",
      setting: "Tenant-Wide Admin Consent Grants",
      currentValue:
        grantCount === 0
          ? "No tenant-wide admin consent grants"
          : `${grantCount} tenant-wide consent grant(s)`,
      recommendedValue: "Review and minimize tenant-wide admin consent grants",
      psStatus: grantCount <= 5 ? "Pass" : grantCount <= 15 ? "Info" : "Warning",
      checkId: "ENTRA-CONSENT-004",
      remediation:
        "Review tenant-wide admin consent grants. These grants apply to all users in the tenant. Remove overly broad grants that are no longer needed. Entra admin center > Enterprise applications > filter by Admin consent.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "Application Consent",
      setting: "Tenant-Wide Admin Consent Grants",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue: "Review and minimize tenant-wide admin consent grants",
      psStatus: "Skipped",
      checkId: "ENTRA-CONSENT-004",
      remediation: PERMISSIONS_RETRY,
    });
  }

  // ------------------------------------------------------------------
  // 10. External Collaboration Settings (PS lines 265-339)
  // ------------------------------------------------------------------
  if (authPolicy) {
    try {
      const guestInviteSettings = authPolicy.allowInvitesFrom as
        | string
        | undefined;
      const guestAccessRestriction = authPolicy.guestUserRoleId as
        | string
        | undefined;

      const INVITE_DISPLAY: Record<string, string> = {
        none: "No one can invite",
        adminsAndGuestInviters: "Admins and guest inviters only",
        adminsGuestInvitersAndAllMembers: "All members can invite",
        everyone: "Everyone including guests",
      };
      const inviteDisplay = guestInviteSettings
        ? (INVITE_DISPLAY[guestInviteSettings] ?? guestInviteSettings)
        : "";

      const INVITE_STATUS: Record<string, PsStatus> = {
        none: "Pass",
        adminsAndGuestInviters: "Pass",
        adminsGuestInvitersAndAllMembers: "Review",
        everyone: "Warning",
      };
      const inviteStatus: PsStatus = guestInviteSettings
        ? (INVITE_STATUS[guestInviteSettings] ?? "Review")
        : "Review";

      ctx.addRow({
        category: "External Collaboration",
        setting: "Guest Invitation Policy",
        currentValue: inviteDisplay,
        recommendedValue: "Admins and guest inviters only",
        psStatus: inviteStatus,
        checkId: "ENTRA-GUEST-002",
        remediation:
          "Run: Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom 'adminsAndGuestInviters'. Entra admin center > External Identities > External collaboration settings.",
      });

      // Guest user role
      const ROLE_DISPLAY: Record<string, string> = {
        "a0b1b346-4d3e-4e8b-98f8-753987be4970": "Same as member users",
        "10dae51f-b6af-4016-8d66-8c2a99b929b3": "Limited access (default)",
        "2af84b1e-32c8-42b7-82bc-daa82404023b": "Restricted access",
      };
      const roleDisplay = guestAccessRestriction
        ? (ROLE_DISPLAY[guestAccessRestriction] ?? guestAccessRestriction)
        : "";

      ctx.addRow({
        category: "External Collaboration",
        setting: "Guest User Access Restriction",
        currentValue: roleDisplay,
        recommendedValue: "Restricted access",
        psStatus:
          guestAccessRestriction === "2af84b1e-32c8-42b7-82bc-daa82404023b"
            ? "Pass"
            : "Warning",
        checkId: "ENTRA-GUEST-001",
        remediation:
          "Run: Update-MgPolicyAuthorizationPolicy -GuestUserRoleId '2af84b1e-32c8-42b7-82bc-daa82404023b'. Entra admin center > External Identities > External collaboration settings.",
      });
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      // PS emits BOTH catch rows in order (GUEST-002 then GUEST-001).
      ctx.addRow({
        category: "External Collaboration",
        setting: "Guest Invitation Policy",
        currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
        recommendedValue: "Admins and guest inviters only",
        psStatus: "Skipped",
        checkId: "ENTRA-GUEST-002",
        remediation: PERMISSIONS_RETRY,
      });
      ctx.addRow({
        category: "External Collaboration",
        setting: "Guest User Access Restriction",
        currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
        recommendedValue: "Restricted access",
        psStatus: "Skipped",
        checkId: "ENTRA-GUEST-001",
        remediation: PERMISSIONS_RETRY,
      });
    }
  }

  // ------------------------------------------------------------------
  // 12. Guest User Summary — advanced query w/ ConsistencyLevel (PS 344-376)
  // ------------------------------------------------------------------
  try {
    const guestCount = await ctx.transport.getJson(USER_GROUP_ENDPOINTS.guestCount, {
      headers: CONSISTENCY_EVENTUAL,
      requiredRole: USER_READ_ALL,
    });
    // Graph $count responses are bare JSON numbers (scalar non-collection body).
    ctx.addRow({
      category: "External Collaboration",
      setting: "Guest User Count",
      currentValue: psStr(guestCount),
      recommendedValue: "Review periodically",
      psStatus: "Info",
      checkId: "ENTRA-GUEST-003",
      remediation:
        "Informational — review and remove stale guest accounts periodically. Entra admin center > Users > Guest users.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "External Collaboration",
      setting: "Guest User Count",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue: "Review periodically",
      psStatus: "Skipped",
      checkId: "ENTRA-GUEST-003",
      remediation: PERMISSIONS_RETRY,
    });
  }

  // ------------------------------------------------------------------
  // 14. LinkedIn Account Connections (PS lines 381-419)
  //     PS targets /beta/organization/{tenantId}; promoted to the v1.0
  //     organization surface per BETA-ENDPOINTS.md (absent linkedInConfiguration
  //     degrades through the same null-guard to PS's default-enabled branch).
  // ------------------------------------------------------------------
  try {
    const tenantId = psStr(ctx.shared.get("tenantId"));
    const orgResponse = await ctx.transport.getJson(
      `/v1.0/organization/${tenantId}`,
      { requiredRole: DIRECTORY_READ_ALL },
    );
    const orgSettings = orgResponse as GraphObj;

    let linkedInEnabled = true; // Default assumption
    if (
      orgSettings &&
      typeof orgSettings.linkedInConfiguration === "object" &&
      orgSettings.linkedInConfiguration !== null
    ) {
      linkedInEnabled = !(
        (orgSettings.linkedInConfiguration as GraphObj).isDisabled === true
      );
    }
    // Store for EntraPasswordAuthChecks section 27 (PS shared-scope parity).
    ctx.shared.set("entra.orgSettings", orgSettings);

    ctx.addRow({
      category: "Directory Settings",
      setting: "LinkedIn Account Connections",
      currentValue: linkedInEnabled ? "Enabled" : "Disabled",
      recommendedValue: "Disabled",
      psStatus: linkedInEnabled ? "Fail" : "Pass",
      checkId: "ENTRA-LINKEDIN-001",
      remediation:
        "Entra admin center > Users > User settings > LinkedIn account connections > No. Prevents data leakage between LinkedIn and organizational directory.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "Directory Settings",
      setting: "LinkedIn Account Connections",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue: "Disabled",
      psStatus: "Skipped",
      checkId: "ENTRA-LINKEDIN-001",
      remediation: PERMISSIONS_RETRY,
    });
  }

  // ------------------------------------------------------------------
  // 15. Per-user MFA Disabled (PS lines 424-457) — API-access probe; the
  // response is discarded and a Review row is emitted either way. PS targets
  // /beta; promoted to v1.0 per the resolved BETA-ENDPOINTS.md row.
  // ------------------------------------------------------------------
  try {
    await ctx.transport.getJson(USER_GROUP_ENDPOINTS.userRegistrationDetailsProbe, {
      requiredRole: "UserAuthenticationMethod.Read.All",
    });
    ctx.addRow({
      category: "Authentication Methods",
      setting: "Per-user MFA (Legacy)",
      currentValue: "Review -- verify no per-user MFA states are set to Enforced or Enabled",
      recommendedValue: "All per-user MFA disabled (use CA policies)",
      psStatus: "Review",
      checkId: "ENTRA-PERUSER-001",
      remediation:
        "Entra admin center > Users > Per-user MFA > Ensure all users show Disabled. Use Conditional Access policies for MFA enforcement instead of per-user MFA.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "Authentication Methods",
      setting: "Per-user MFA (Legacy)",
      currentValue: "Could not query -- verify manually",
      recommendedValue: "All per-user MFA disabled (use CA policies)",
      psStatus: "Review",
      checkId: "ENTRA-PERUSER-001",
      remediation:
        "Entra admin center > Users > Per-user MFA > Ensure all users show Disabled. Use Conditional Access policies for MFA enforcement instead.",
    });
  }

  // ------------------------------------------------------------------
  // 16. Third-party Integrated Apps Blocked (PS lines 462-492)
  // ------------------------------------------------------------------
  if (authPolicy) {
    try {
      const allowedToCreateApps = (
        authPolicy.defaultUserRolePermissions as GraphObj | undefined
      )?.allowedToCreateApps;
      ctx.addRow({
        category: "Application Consent",
        setting: "Third-party Integrated Apps Restricted",
        currentValue: allowedToCreateApps ? "Allowed" : "Restricted",
        recommendedValue: "Restricted",
        psStatus: allowedToCreateApps ? "Fail" : "Pass",
        checkId: "ENTRA-APPS-001",
        remediation:
          "Entra admin center > Users > User settings > Users can register applications > No. Also review Enterprise applications > User settings > Users can consent to apps.",
      });
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      ctx.addRow({
        category: "Application Consent",
        setting: "Third-party Integrated Apps Restricted",
        currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
        recommendedValue: "Restricted",
        psStatus: "Skipped",
        checkId: "ENTRA-APPS-001",
        remediation: PERMISSIONS_RETRY,
      });
    }
  }

  // ------------------------------------------------------------------
  // 17. Guest Invitation Domain Restrictions (PS lines 497-540)
  // ------------------------------------------------------------------
  try {
    const crossTenantPolicy = await ctx.transport.getJson(
      USER_GROUP_ENDPOINTS.crossTenantDefault,
      { requiredRole: POLICY_READ_ALL },
    );

    const b2bCollabInbound = crossTenantPolicy.b2bCollaborationInbound as
      | GraphObj
      | undefined;
    let isRestricted = false;
    if (
      b2bCollabInbound &&
      typeof b2bCollabInbound.applications === "object" &&
      b2bCollabInbound.applications !== null
    ) {
      const accessType = (b2bCollabInbound.applications as GraphObj).accessType;
      isRestricted = accessType === "blocked" || accessType === "allowed";
    }

    const invitesFrom = authPolicy ? authPolicy.allowInvitesFrom : "unknown";
    const domainRestricted =
      invitesFrom !== "everyone" && Boolean(isRestricted);

    ctx.addRow({
      category: "External Collaboration",
      setting: "Guest Invitation Domain Restrictions",
      currentValue: domainRestricted
        ? `Restricted (invites: ${psStr(invitesFrom)})`
        : `Open (invites: ${psStr(invitesFrom)})`,
      recommendedValue: "Restricted to allowed domains only",
      psStatus:
        invitesFrom === "none" || domainRestricted
          ? "Pass"
          : invitesFrom !== "everyone"
            ? "Review"
            : "Fail",
      checkId: "ENTRA-GUEST-004",
      remediation:
        "Entra admin center > External Identities > External collaboration settings > Collaboration restrictions > Allow invitations only to the specified domains.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "External Collaboration",
      setting: "Guest Invitation Domain Restrictions",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue: "Restricted to allowed domains only",
      psStatus: "Skipped",
      checkId: "ENTRA-GUEST-004",
      remediation: PERMISSIONS_RETRY,
    });
  }

  // ------------------------------------------------------------------
  // 18. Dynamic Group for Guest Users (PS lines 545-596)
  // ------------------------------------------------------------------
  try {
    const dynamicGroups = await ctx.transport.getJson(
      USER_GROUP_ENDPOINTS.dynamicGroups,
      { requiredRole: GROUP_READ_ALL },
    );
    const dynamicGroupList = asArray(dynamicGroups.value);
    // PS -match parity: user.userType (-eq|-contains) <optional-char>Guest
    const GUEST_RULE = /user\.userType\s+(-eq|-contains)\s+.?Guest/;
    const guestGroups = dynamicGroupList.filter((g) => {
      if (typeof g.membershipRule !== "string") return false;
      return GUEST_RULE.test(g.membershipRule);
    });

    if (guestGroups.length > 0) {
      const names = guestGroups.map((g) => psStr(g.displayName)).join("; ");
      ctx.addRow({
        category: "External Collaboration",
        setting: "Dynamic Group for Guest Users",
        currentValue: `Yes (${guestGroups.length} group: ${names})`,
        recommendedValue: "At least 1 dynamic group for guests",
        psStatus: "Pass",
        checkId: "ENTRA-GROUP-002",
        remediation: "No action needed.",
      });
    } else {
      ctx.addRow({
        category: "External Collaboration",
        setting: "Dynamic Group for Guest Users",
        currentValue: "No dynamic guest group found",
        recommendedValue: "At least 1 dynamic group for guests",
        psStatus: "Fail",
        checkId: "ENTRA-GROUP-002",
        remediation:
          'Entra admin center > Groups > New group > Membership type = Dynamic User > Rule: (user.userType -eq "Guest"). This enables targeted policies for guest users.',
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "External Collaboration",
      setting: "Dynamic Group for Guest Users",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue: "At least 1 dynamic group for guests",
      psStatus: "Skipped",
      checkId: "ENTRA-GROUP-002",
      remediation: PERMISSIONS_RETRY,
    });
  }

  // ------------------------------------------------------------------
  // 25. Public Groups Have Owners (PS lines 601-668)
  // ------------------------------------------------------------------
  try {
    const unifiedGroups = await ctx.transport.getJson(
      USER_GROUP_ENDPOINTS.unifiedGroups,
      { requiredRole: GROUP_READ_ALL },
    );
    const publicGroupList = asArray(unifiedGroups.value).filter(
      (g) => g.visibility === "Public",
    );
    const noOwnerGroups: string[] = [];
    // PS quirk reproduced verbatim: with -ErrorAction SilentlyContinue a
    // failed owners fetch leaves $owners holding the PREVIOUS iteration's
    // value (or $null on first failure) — not an empty response.
    let ownersResponse: unknown = null;
    for (const group of publicGroupList) {
      try {
        ownersResponse = await ctx.transport.getJson(
          `/v1.0/groups/${psStr(group.id)}/owners?$select=id`,
          { requiredRole: GROUP_READ_ALL },
        );
      } catch (err) {
        if (err instanceof TransportFatalError) throw err;
        // Keep previous value (PS variable persistence).
      }
      const ownerValues =
        typeof ownersResponse === "object" && ownersResponse !== null
          ? (ownersResponse as GraphObj).value
          : undefined;
      if (!Array.isArray(ownerValues) || ownerValues.length === 0) {
        noOwnerGroups.push(psStr(group.displayName));
      }
    }

    if (noOwnerGroups.length === 0) {
      ctx.addRow({
        category: "Group Management",
        setting: "Public Groups Have Owners",
        currentValue: `${publicGroupList.length} public groups, all have owners`,
        recommendedValue: "All public groups have assigned owners",
        psStatus: "Pass",
        checkId: "ENTRA-GROUP-003",
        remediation: "No action needed.",
      });
    } else {
      const groupList = noOwnerGroups.slice(0, 5).join(", ");
      const suffix =
        noOwnerGroups.length > 5 ? ` (+${noOwnerGroups.length - 5} more)` : "";
      ctx.addRow({
        category: "Group Management",
        setting: "Public Groups Have Owners",
        currentValue: `${noOwnerGroups.length} groups without owners: ${groupList}${suffix}`,
        recommendedValue: "All public groups have assigned owners",
        psStatus: "Fail",
        checkId: "ENTRA-GROUP-003",
        remediation:
          "Assign owners to ownerless public M365 groups. Entra admin center > Groups > All groups > select group > Owners > Add owners.",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "Group Management",
      setting: "Public Groups Have Owners",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue: "All public groups have assigned owners",
      psStatus: "Skipped",
      checkId: "ENTRA-GROUP-003",
      remediation: PERMISSIONS_RETRY,
    });
  }

  // ------------------------------------------------------------------
  // 26. User Owned Apps Restricted (PS lines 673-709)
  // ------------------------------------------------------------------
  try {
    const consentPolicy = await ctx.transport.getJson(
      USER_GROUP_ENDPOINTS.authorizationPolicy,
      { requiredRole: POLICY_READ_ALL },
    );
    const consentSetting = (
      consentPolicy.defaultUserRolePermissions as GraphObj | undefined
    )?.permissionGrantPoliciesAssigned;
    const isRestricted =
      !Array.isArray(consentSetting) ||
      consentSetting.length === 0 ||
      !includes(
        consentSetting,
        "ManagePermissionGrantsForSelf.microsoft-user-default-legacy",
      );

    ctx.addRow({
      category: "Organization Settings",
      setting: "Org-Level App Consent Restriction",
      currentValue: isRestricted
        ? "Restricted"
        : `Allowed: ${stringList(consentSetting).join(", ")}`,
      recommendedValue: "Do not allow user consent",
      psStatus: isRestricted ? "Pass" : "Fail",
      checkId: "ENTRA-ORGSETTING-001",
      remediation:
        "Entra admin center > Enterprise applications > Consent and permissions > User consent settings > Do not allow user consent.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "Organization Settings",
      setting: "Org-Level App Consent Restriction",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue: "Do not allow user consent",
      psStatus: "Skipped",
      checkId: "ENTRA-ORGSETTING-001",
      remediation: PERMISSIONS_RETRY,
    });
  }

  // ------------------------------------------------------------------
  // 28-30. Organization Settings (Review-only CIS items, PS lines 714-745)
  // ------------------------------------------------------------------
  ctx.addRow({
    category: "Organization Settings",
    setting: "Forms Internal Phishing Protection",
    currentValue: "Cannot be checked via API",
    recommendedValue: "Enabled",
    psStatus: "Review",
    checkId: "ENTRA-ORGSETTING-002",
    remediation:
      "M365 admin center > Settings > Org settings > Microsoft Forms > ensure internal phishing protection is enabled.",
  });

  ctx.addRow({
    category: "Organization Settings",
    setting: "Third-Party Storage in M365 Web Apps",
    currentValue: "Cannot be checked via API",
    recommendedValue: "Restricted (all third-party storage disabled)",
    psStatus: "Review",
    checkId: "ENTRA-ORGSETTING-003",
    remediation:
      "M365 admin center > Settings > Org settings > Microsoft 365 on the web > uncheck all third-party storage services.",
  });

  ctx.addRow({
    category: "Organization Settings",
    setting: "Shared Bookings Pages Restricted",
    currentValue: "Cannot be checked via API",
    recommendedValue: "Restricted to selected users",
    psStatus: "Review",
    checkId: "ENTRA-ORGSETTING-004",
    remediation:
      "M365 admin center > Settings > Org settings > Bookings > restrict shared booking pages to selected staff members.",
  });

  // ------------------------------------------------------------------
  // Disabled Member Account Count (PS lines 750-783) — advanced queries with
  // ConsistencyLevel: eventual (PS line 752).
  // ------------------------------------------------------------------
  try {
    const totalResponse = await ctx.transport.getJson(
      USER_GROUP_ENDPOINTS.memberCount,
      { headers: CONSISTENCY_EVENTUAL, requiredRole: USER_READ_ALL },
    );
    const disabledResponse = await ctx.transport.getJson(
      USER_GROUP_ENDPOINTS.disabledMemberCount,
      { headers: CONSISTENCY_EVENTUAL, requiredRole: USER_READ_ALL },
    );
    // PS [int](...) casts over bare-number JSON bodies.
    const totalCount = Number(totalResponse);
    const disabledCount = Number(disabledResponse);
    if (!Number.isInteger(totalCount) || !Number.isInteger(disabledCount)) {
      throw new Error("Cannot convert value to int");
    }
    const pct =
      totalCount > 0
        ? psRound((disabledCount / totalCount) * 100, 1)
        : 0;
    ctx.addRow({
      category: "Directory Health",
      setting: "Disabled Member Accounts",
      currentValue: `${disabledCount} disabled of ${totalCount} total members (${pct}%)`,
      recommendedValue: "Review periodically; remove accounts no longer needed",
      psStatus: "Info",
      checkId: "ENTRA-DISABLED-001",
      remediation:
        "Review disabled accounts and remove any that are no longer needed. Entra admin center > Users > All users > filter by Account status: Disabled.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "Directory Health",
      setting: "Disabled Member Accounts",
      currentValue: `Error: ${err instanceof Error ? err.message : String(err)}`,
      recommendedValue: "Review periodically; remove accounts no longer needed",
      psStatus: "Skipped",
      checkId: "ENTRA-DISABLED-001",
      remediation:
        "Check Graph API permissions (User.Read.All) and retry.",
    });
  }
};
