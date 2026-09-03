/**
 * Port of `src/M365-Assess/Entra/Get-CASecurityConfig.ps1` (1,205 lines)
 * — AssessmentMaps Identity entry '07c-CA-Security-Config' (plan 02-09).
 *
 * The largest collector in the module: fetches all Conditional Access
 * policies plus supporting surfaces and evaluates them against CIS
 * 5.2.2.x requirements, one decision ladder per check.
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport:
 *   owned by the runner's addRow pipeline (mapStatus → sub-numbering → D-22).
 * - Invoke-MgGraphRequest GETs → ctx.transport.getJson calls declaring the
 *   PS section scope's roles (Policy.Read.All / RoleManagement.Read.Directory /
 *   Group.Read.All).
 * - Script-scope state ($securityDefaultsEnabled, $allPolicies,
 *   $enabledPolicies, $namedLocations) → module-local variables within one
 *   invocation; $namedLocations stays undefined when check 14's fetch fails so
 *   check 19 skips evaluation exactly like the PS null-guard (PS 1071-1080).
 * - Soft-fail semantics preserved per section: catch blocks degrade to zero
 *   rows (PS Write-Warning parity), never a section error;
 *   TransportFatalError (structural guard breaches) still propagates.
 * - The Evidence PSCustomObjects on checks 1-3 are intentionally not carried:
 *   CheckRowInput has no freeform-evidence slot and no decision consumes them
 *   (same disposition as plan 02-07 check 1 evidence).
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import type { CheckRowInput, PsStatus } from "@/engine/results/row-contract";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const CA_SECURITY_CONFIG_ENDPOINTS = {
  securityDefaults: "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
  caPolicies: "/v1.0/identity/conditionalAccess/policies",
  namedLocations: "/v1.0/identity/conditionalAccess/namedLocations",
  roleAssignments: "/v1.0/roleManagement/directory/roleAssignments?$top=999",
} as const;

/** Check 20 probes each referenced group directly (PS line 1141). */
export function groupSelectUrl(groupId: string): string {
  return `/v1.0/groups/${groupId}?$select=id`;
}

type GraphObj = Record<string, unknown>;

const POLICY_READ_ALL = "Policy.Read.All";
const ROLE_MGMT_READ_DIRECTORY = "RoleManagement.Read.Directory";
const GROUP_READ_ALL = "Group.Read.All";

/** Well-known admin role template IDs used by CIS checks (PS lines 81-102). */
const ADMIN_ROLE_IDS = [
  "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
  "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
  "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator
  "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
  "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
  "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", // Conditional Access Administrator
  "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
  "729827e3-9c14-49f7-bb1b-9608f156bbb8", // Helpdesk Administrator
  "966707d0-3269-4727-9be2-8c3a10f19b9d", // Password Administrator
  "fdd7a751-b60b-444a-984c-02652fe8fa1c", // Groups Administrator
  "11648597-926c-4cf3-9c36-bcebb0ba8dcc", // Power Platform Administrator
  "3a2c62db-5318-420d-8d74-23affee5d9d5", // Intune Administrator
  "158c047a-c907-4556-b7ef-446551a6b5f7", // Cloud Application Administrator
  "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
  "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", // Privileged Authentication Administrator
  "c4e39bd9-1100-46d3-8c65-fb160da0071f", // Authentication Administrator
  "b0f54661-2d74-4c50-afa3-1ec803f12efe", // Billing Administrator
  "44367163-eba1-44c3-98af-f5787879f96a", // Dynamics 365 Administrator
  "8835291a-918c-4fd7-a9ce-faa49f0cf7d9", // Teams Administrator
  "112f9a7f-7249-4951-bd88-c42b60cebe72", // Fabric Administrator
];

function includes(list: unknown, item: string): boolean {
  return Array.isArray(list) && (list as unknown[]).includes(item);
}

function nonEmptyArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.length > 0;
}

function users(policy: GraphObj): GraphObj {
  const conditions = policy.conditions as GraphObj | undefined;
  return ((conditions?.users as GraphObj | undefined) ?? {}) as GraphObj;
}

function conditions(policy: GraphObj): GraphObj {
  return (policy.conditions as GraphObj | undefined) ?? {};
}

// Helper: check if a policy targets admin roles (PS lines 105-113).
function targetsAdminRole(policy: GraphObj): boolean {
  const includeRoles = users(policy).includeRoles;
  if (!nonEmptyArray(includeRoles)) return false;
  return (includeRoles as string[]).some((role) => ADMIN_ROLE_IDS.includes(role));
}

// Helper: check if a policy targets all users (PS lines 116-120).
function targetsAllUser(policy: GraphObj): boolean {
  return includes(users(policy).includeUsers, "All");
}

// Helper: does the policy carve any tracked admin role out via excludeRoles?
// (PS lines 127-135.) Group-based admin carve-outs are not resolved to
// membership here, same limitation comment as the PS source.
function excludesAdminRole(policy: GraphObj): boolean {
  const excludeRoles = users(policy).excludeRoles;
  if (!nonEmptyArray(excludeRoles)) return false;
  return (excludeRoles as string[]).some((role) => ADMIN_ROLE_IDS.includes(role));
}

// Helper: does the policy actually REQUIRE MFA? (PS lines 141-148.)
// 'mfa' listed under an OR operator alongside other controls does NOT require
// MFA; MFA only when sole control or operator AND.
function requiresMfa(policy: GraphObj): boolean {
  const grantControls = policy.grantControls as GraphObj | undefined;
  if (!grantControls) return false;
  const controls = Array.isArray(grantControls.builtInControls)
    ? (grantControls.builtInControls as unknown[])
    : [];
  if (!controls.includes("mfa")) return false;
  return controls.length === 1 || grantControls.operator === "AND";
}

// Helper: user/group exclusions present? (PS lines 153-159.) Downgrades
// All-Users-only coverage to Review since membership cannot be resolved.
function hasUserOrGroupExclusion(policy: GraphObj): boolean {
  const u = users(policy);
  const excludeUsers = Array.isArray(u.excludeUsers) ? (u.excludeUsers as unknown[]) : [];
  const excludeGroups = Array.isArray(u.excludeGroups) ? (u.excludeGroups as unknown[]) : [];
  return excludeUsers.length > 0 || excludeGroups.length > 0;
}

/** PS `$names = ($policies | ForEach-Object { $_['displayName'] }) -join '; '`. */
function names(policies: readonly GraphObj[]): string {
  return policies.map((p) => String(p.displayName ?? "")).join("; ");
}

interface LadderRow {
  setting: string;
  currentValue: string;
  recommendedValue: string;
  status: PsStatus;
  checkId: string;
  remediation: string;
}

/** PS `$settingParams = @{...}; Add-Setting @settingParams` shape. */
function row(ladder: LadderRow): CheckRowInput {
  return {
    category: "Conditional Access",
    setting: ladder.setting,
    currentValue: ladder.currentValue,
    recommendedValue: ladder.recommendedValue,
    psStatus: ladder.status,
    checkId: ladder.checkId,
    remediation: ladder.remediation,
  };
}

export const runCaSecurityConfig: SectionImplementation = async (ctx) => {
  let securityDefaultsEnabled = false;

  // ------------------------------------------------------------------
  // Check Security Defaults status (PS lines 45-58; soft-fail → false)
  // ------------------------------------------------------------------
  try {
    const sdPolicy = await ctx.transport.getJson(
      CA_SECURITY_CONFIG_ENDPOINTS.securityDefaults,
      { requiredRole: POLICY_READ_ALL },
    );
    securityDefaultsEnabled =
      (sdPolicy as GraphObj)["isEnabled"] === true;
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Verbose parity — degrade silently to disabled.
  }

  // ------------------------------------------------------------------
  // Fetch Conditional Access policies (PS lines 60-78; soft-fail → empty)
  // ------------------------------------------------------------------
  let allPolicies: GraphObj[] = [];
  try {
    const caPolicies = await ctx.transport.getJson(
      CA_SECURITY_CONFIG_ENDPOINTS.caPolicies,
      { requiredRole: POLICY_READ_ALL },
    );
    allPolicies = asArray(caPolicies.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    allPolicies = [];
  }
  const enabledPolicies = allPolicies.filter((p) => p["state"] === "enabled");

  // Populated by check 14; stays undefined if that fetch failed (PS 1071-1080
  // null-guard then skips check 19 entirely).
  let namedLocations: GraphObj[] | undefined;

  // ------------------------------------------------------------------
  // 1. MFA Required for Admin Roles (CIS 5.2.2.1) — PS lines 162-262
  // ------------------------------------------------------------------
  try {
    const mfaAdminPolicies = enabledPolicies.filter(
      (p) =>
        (targetsAdminRole(p) || targetsAllUser(p)) &&
        !excludesAdminRole(p) &&
        requiresMfa(p),
    );

    const adminRolePolicies = mfaAdminPolicies.filter((p) => targetsAdminRole(p));
    const allUserOnly = mfaAdminPolicies.filter((p) => !targetsAdminRole(p));
    const allUserClean = allUserOnly.filter((p) => !hasUserOrGroupExclusion(p));
    const allUserExcluded = allUserOnly.filter((p) => hasUserOrGroupExclusion(p));

    if (adminRolePolicies.length > 0) {
      const n = names(adminRolePolicies);
      ctx.addRow(
        row({
          setting: "MFA Required for Admin Roles",
          currentValue: `Yes (${adminRolePolicies.length} admin-role-targeted policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-MFA-ADMIN-001",
          remediation: "No action needed.",
        }),
      );
    } else if (allUserClean.length > 0) {
      const n = names(allUserClean);
      ctx.addRow(
        row({
          setting: "MFA Required for Admin Roles",
          currentValue: `Yes (covered by All-Users MFA policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-MFA-ADMIN-001",
          remediation:
            "No action needed. Admins are covered by an All-Users MFA policy; a dedicated admin-role policy would add defense in depth.",
        }),
      );
    } else if (allUserExcluded.length > 0) {
      const n = names(allUserExcluded);
      ctx.addRow(
        row({
          setting: "MFA Required for Admin Roles",
          currentValue: `All-Users MFA policy found but it excludes users/groups; verify admins are not carved out: ${n}`,
          recommendedValue: "At least 1 policy",
          status: "Review",
          checkId: "CA-MFA-ADMIN-001",
          remediation:
            "Confirm the excluded users/groups do not contain administrators, or add a dedicated Conditional Access policy targeting admin directory roles with Require multifactor authentication.",
        }),
      );
    } else if (securityDefaultsEnabled) {
      ctx.addRow(
        row({
          setting: "MFA Required for Admin Roles",
          currentValue: "Covered by Security Defaults",
          recommendedValue: "At least 1 policy (or Security Defaults)",
          status: "Info",
          checkId: "CA-MFA-ADMIN-001",
          remediation:
            "Security Defaults enforces MFA for all admin roles. For granular control, disable Security Defaults and create Conditional Access policies.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "MFA Required for Admin Roles",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-MFA-ADMIN-001",
          remediation:
            "Create a CA policy: Target admin directory roles > Grant > Require multifactor authentication. Entra admin center > Protection > Conditional Access > New policy.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 2. MFA Required for All Users (CIS 5.2.2.2) — PS lines 264-322
  // ------------------------------------------------------------------
  try {
    const mfaAllPolicies = enabledPolicies.filter(
      (p) =>
        targetsAllUser(p) &&
        p.grantControls != null &&
        includes((p.grantControls as GraphObj).builtInControls, "mfa"),
    );

    if (mfaAllPolicies.length > 0) {
      const n = names(mfaAllPolicies);
      ctx.addRow(
        row({
          setting: "MFA Required for All Users",
          currentValue: `Yes (${mfaAllPolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-MFA-ALL-001",
          remediation: "No action needed.",
        }),
      );
    } else if (securityDefaultsEnabled) {
      ctx.addRow(
        row({
          setting: "MFA Required for All Users",
          currentValue: "Covered by Security Defaults",
          recommendedValue: "At least 1 policy (or Security Defaults)",
          status: "Info",
          checkId: "CA-MFA-ALL-001",
          remediation:
            "Security Defaults enforces MFA for all users. For granular control, disable Security Defaults and create Conditional Access policies.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "MFA Required for All Users",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-MFA-ALL-001",
          remediation:
            "Create a CA policy: Target All users > All cloud apps > Grant > Require multifactor authentication. Entra admin center > Protection > Conditional Access > New policy.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 3. Legacy Authentication Blocked (CIS 5.2.2.3) — PS lines 324-383
  // ------------------------------------------------------------------
  try {
    const legacyBlockPolicies = enabledPolicies.filter((p) => {
      const clientApps = conditions(p).clientAppTypes;
      return (
        (includes(clientApps, "exchangeActiveSync") || includes(clientApps, "other")) &&
        p.grantControls != null &&
        includes((p.grantControls as GraphObj).builtInControls, "block")
      );
    });

    if (legacyBlockPolicies.length > 0) {
      const n = names(legacyBlockPolicies);
      ctx.addRow(
        row({
          setting: "Legacy Authentication Blocked",
          currentValue: `Yes (${legacyBlockPolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-LEGACYAUTH-001",
          remediation: "No action needed.",
        }),
      );
    } else if (securityDefaultsEnabled) {
      ctx.addRow(
        row({
          setting: "Legacy Authentication Blocked",
          currentValue: "Covered by Security Defaults",
          recommendedValue: "At least 1 policy (or Security Defaults)",
          status: "Info",
          checkId: "CA-LEGACYAUTH-001",
          remediation:
            "Security Defaults blocks legacy authentication protocols. For granular control, disable Security Defaults and create Conditional Access policies.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "Legacy Authentication Blocked",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-LEGACYAUTH-001",
          remediation:
            "Create a CA policy: Target All users > Conditions > Client apps > Exchange ActiveSync clients + Other clients > Grant > Block access. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 4. Sign-in Frequency for Admins (CIS 5.2.2.4) — PS lines 385-427
  // ------------------------------------------------------------------
  try {
    const signinFreqPolicies = enabledPolicies.filter((p) => {
      const sessionControls = p.sessionControls as GraphObj | undefined;
      const signInFrequency = sessionControls?.signInFrequency as
        | GraphObj
        | undefined;
      const persistentBrowser = sessionControls?.persistentBrowser as
        | GraphObj
        | undefined;
      return (
        targetsAdminRole(p) &&
        sessionControls != null &&
        signInFrequency != null &&
        signInFrequency["isEnabled"] === true &&
        persistentBrowser != null &&
        persistentBrowser["mode"] === "never"
      );
    });

    if (signinFreqPolicies.length > 0) {
      const n = names(signinFreqPolicies);
      ctx.addRow(
        row({
          setting: "Sign-in Frequency for Admin Roles",
          currentValue: `Yes (${signinFreqPolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-SIGNIN-FREQ-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "Sign-in Frequency for Admin Roles",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-SIGNIN-FREQ-001",
          remediation:
            "Create a CA policy: Target admin roles > Session > Sign-in frequency (e.g., 4 hours) + Persistent browser session = Never. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 5. Phishing-Resistant MFA for Admins (CIS 5.2.2.5) — PS lines 429-467
  // ------------------------------------------------------------------
  try {
    const phishResPolicies = enabledPolicies.filter((p) => {
      const grantControls = p.grantControls as GraphObj | undefined;
      return (
        targetsAdminRole(p) &&
        grantControls != null &&
        grantControls.authenticationStrength != null
      );
    });

    if (phishResPolicies.length > 0) {
      const n = names(phishResPolicies);
      ctx.addRow(
        row({
          setting: "Phishing-Resistant MFA for Admins",
          currentValue: `Yes (${phishResPolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-PHISHRES-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "Phishing-Resistant MFA for Admins",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-PHISHRES-001",
          remediation:
            "Create a CA policy: Target admin roles > Grant > Require authentication strength > Phishing-resistant MFA. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 6. User Risk Policy (CIS 5.2.2.6) — PS lines 469-507
  // ------------------------------------------------------------------
  try {
    const userRiskPolicies = enabledPolicies.filter((p) => {
      const riskLevels = conditions(p).userRiskLevels;
      return nonEmptyArray(riskLevels);
    });

    if (userRiskPolicies.length > 0) {
      const n = names(userRiskPolicies);
      ctx.addRow(
        row({
          setting: "User Risk Policy Configured",
          currentValue: `Yes (${userRiskPolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-USERRISK-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "User Risk Policy Configured",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-USERRISK-001",
          remediation:
            "Create a CA policy: Target All users > Conditions > User risk > High > Grant > Require password change + MFA. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 7. Sign-in Risk Policy (CIS 5.2.2.7) — PS lines 509-547
  // ------------------------------------------------------------------
  try {
    const signinRiskPolicies = enabledPolicies.filter((p) => {
      const riskLevels = conditions(p).signInRiskLevels;
      return nonEmptyArray(riskLevels);
    });

    if (signinRiskPolicies.length > 0) {
      const n = names(signinRiskPolicies);
      ctx.addRow(
        row({
          setting: "Sign-in Risk Policy Configured",
          currentValue: `Yes (${signinRiskPolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-SIGNINRISK-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "Sign-in Risk Policy Configured",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-SIGNINRISK-001",
          remediation:
            "Create a CA policy: Target All users > Conditions > Sign-in risk > High, Medium > Grant > Require MFA. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 8. Sign-in Risk Blocks Medium and High (CIS 5.2.2.8) — PS lines 549-602
  // ------------------------------------------------------------------
  try {
    const signinRiskBlockPolicies = enabledPolicies.filter((p) => {
      const riskLevels = conditions(p).signInRiskLevels;
      const grantControls = p.grantControls as GraphObj | undefined;
      const controls = grantControls?.builtInControls;
      return (
        nonEmptyArray(riskLevels) &&
        (includes(riskLevels, "medium") || includes(riskLevels, "high")) &&
        grantControls != null &&
        (includes(controls, "block") || includes(controls, "mfa"))
      );
    });

    if (signinRiskBlockPolicies.length > 0) {
      const n = names(signinRiskBlockPolicies);
      ctx.addRow(
        row({
          setting: "Sign-in Risk Blocks Medium+High",
          currentValue: `Yes (${signinRiskBlockPolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-SIGNINRISK-002",
          remediation: "No action needed.",
        }),
      );
    } else if (securityDefaultsEnabled) {
      ctx.addRow(
        row({
          setting: "Sign-in Risk Blocks Medium+High",
          currentValue:
            "Partially covered by Security Defaults (blocks high-risk sign-ins)",
          recommendedValue:
            "At least 1 policy (or Security Defaults for partial coverage)",
          status: "Info",
          checkId: "CA-SIGNINRISK-002",
          remediation:
            "Security Defaults blocks high-risk sign-ins but does not provide granular medium-risk controls. For full coverage, disable Security Defaults and create Conditional Access policies with Entra ID P2.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "Sign-in Risk Blocks Medium+High",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-SIGNINRISK-002",
          remediation:
            "Create a CA policy: Target All users > Conditions > Sign-in risk > Medium, High > Grant > Block access (or require MFA). Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 9. Compliant/Domain-Joined Device Required (CIS 5.2.2.9) — PS 604-642
  // ------------------------------------------------------------------
  try {
    const devicePolicies = enabledPolicies.filter((p) => {
      const grantControls = p.grantControls as GraphObj | undefined;
      const controls = grantControls?.builtInControls;
      return (
        grantControls != null &&
        (includes(controls, "compliantDevice") ||
          includes(controls, "domainJoinedDevice"))
      );
    });

    if (devicePolicies.length > 0) {
      const n = names(devicePolicies);
      ctx.addRow(
        row({
          setting: "Managed Device Required",
          currentValue: `Yes (${devicePolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-DEVICE-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "Managed Device Required",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-DEVICE-001",
          remediation:
            "Create a CA policy: Target All users > All cloud apps > Grant > Require device to be marked as compliant (or Microsoft Entra hybrid joined). Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 10. Managed Device for Security Info Registration (CIS 5.2.2.10)
  // ------------------------------------------------------------------
  try {
    const secInfoDevicePolicies = enabledPolicies.filter((p) => {
      const c = conditions(p);
      let userActions = users(p).includeUserActions;
      if (!nonEmptyArray(userActions)) {
        userActions = (c.applications as GraphObj | undefined)?.includeUserActions;
      }
      const grantControls = p.grantControls as GraphObj | undefined;
      const controls = grantControls?.builtInControls;
      return (
        includes(userActions, "urn:user:registersecurityinfo") &&
        grantControls != null &&
        (includes(controls, "compliantDevice") ||
          includes(controls, "domainJoinedDevice"))
      );
    });

    if (secInfoDevicePolicies.length > 0) {
      const n = names(secInfoDevicePolicies);
      ctx.addRow(
        row({
          setting: "Managed Device for Security Info Registration",
          currentValue: `Yes (${secInfoDevicePolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-DEVICE-002",
          remediation: "No action needed.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "Managed Device for Security Info Registration",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-DEVICE-002",
          remediation:
            "Create a CA policy: User actions > Register security information > Grant > Require compliant device. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 11. Sign-in Frequency for Intune Enrollment (CIS 5.2.2.11) — PS 689-732
  // ------------------------------------------------------------------
  try {
    const intuneAppId = "d4ebce55-015a-49b5-a083-c84d1797ae8c";
    const intuneFreqPolicies = enabledPolicies.filter((p) => {
      const includeApps = conditions(p).applications &&
        ((conditions(p).applications as GraphObj).includeApplications as
          | unknown[]
          | undefined);
      const sessionControls = p.sessionControls as GraphObj | undefined;
      const signInFrequency = sessionControls?.signInFrequency as GraphObj | undefined;
      return (
        (includes(includeApps, intuneAppId) || includes(includeApps, "All")) &&
        sessionControls != null &&
        signInFrequency != null &&
        signInFrequency["isEnabled"] === true &&
        signInFrequency["type"] === "everyTime"
      );
    });

    if (intuneFreqPolicies.length > 0) {
      const n = names(intuneFreqPolicies);
      ctx.addRow(
        row({
          setting: "Sign-in Frequency for Intune Enrollment",
          currentValue: `Yes (${intuneFreqPolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-INTUNE-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "Sign-in Frequency for Intune Enrollment",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-INTUNE-001",
          remediation:
            "Create a CA policy: Target Microsoft Intune enrollment app > Session > Sign-in frequency = Every time. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 12. Device Code Flow Blocked (CIS 5.2.2.12) — PS lines 734-777
  // ------------------------------------------------------------------
  try {
    const deviceCodePolicies = enabledPolicies.filter((p) => {
      const authFlows = conditions(p).authenticationFlows as GraphObj | undefined;
      const transferMethods = authFlows ? authFlows["transferMethods"] : undefined;
      return (
        nonEmptyArray(transferMethods) &&
        includes(transferMethods, "deviceCodeFlow") &&
        p.grantControls != null &&
        includes((p.grantControls as GraphObj).builtInControls, "block")
      );
    });

    if (deviceCodePolicies.length > 0) {
      const n = names(deviceCodePolicies);
      ctx.addRow(
        row({
          setting: "Device Code Flow Blocked",
          currentValue: `Yes (${deviceCodePolicies.length} policy: ${n})`,
          recommendedValue: "At least 1 policy",
          status: "Pass",
          checkId: "CA-DEVICECODE-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      ctx.addRow(
        row({
          setting: "Device Code Flow Blocked",
          currentValue: "No matching CA policy found",
          recommendedValue: "At least 1 policy",
          status: "Fail",
          checkId: "CA-DEVICECODE-001",
          remediation:
            "Create a CA policy: Target All users > Conditions > Authentication flows > Device code flow > Grant > Block access. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 13. Report-Only Policies (stale auditing) — PS lines 779-814.
  // Scans ALL policies (any state), not just enabled ones.
  // ------------------------------------------------------------------
  try {
    const reportOnlyPolicies = allPolicies.filter(
      (p) => p["state"] === "enabledForReportingButNotEnforced",
    );

    if (reportOnlyPolicies.length === 0) {
      ctx.addRow(
        row({
          setting: "Report-Only Policies",
          currentValue: "None",
          recommendedValue: "Review and promote or remove",
          status: "Pass",
          checkId: "CA-REPORTONLY-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      const n = names(reportOnlyPolicies);
      ctx.addRow(
        row({
          setting: "Report-Only Policies",
          currentValue: `${reportOnlyPolicies.length} policies in report-only: ${n}`,
          recommendedValue: "Review and promote or remove",
          status: "Warning",
          checkId: "CA-REPORTONLY-001",
          remediation:
            "Review report-only policies and either enable enforcement or remove if no longer needed. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 14. Named Locations Risk (IP-based trusted locations) — PS 816-855.
  // Failure leaves namedLocations undefined for check 19's null-guard.
  // ------------------------------------------------------------------
  try {
    const namedLocResponse = await ctx.transport.getJson(
      CA_SECURITY_CONFIG_ENDPOINTS.namedLocations,
      { requiredRole: POLICY_READ_ALL },
    );
    namedLocations = asArray(namedLocResponse.value);
    const ipLocations = namedLocations.filter(
      (loc) =>
        loc["@odata.type"] === "#microsoft.graph.ipNamedLocation" &&
        loc["isTrusted"] === true,
    );

    if (ipLocations.length === 0) {
      ctx.addRow(
        row({
          setting: "Trusted IP Named Locations",
          currentValue: "None configured",
          recommendedValue: "Use country-based or compliant network locations",
          status: "Pass",
          checkId: "CA-NAMEDLOC-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      const n = names(ipLocations);
      ctx.addRow(
        row({
          setting: "Trusted IP Named Locations",
          currentValue: `${ipLocations.length} trusted IP locations: ${n}`,
          recommendedValue: "Prefer compliant network or country-based locations",
          status: "Review",
          checkId: "CA-NAMEDLOC-001",
          remediation:
            "IP-based trusted locations can be spoofed via VPN or proxy. Consider Global Secure Access compliant network checks or country-based locations for stronger assurance. Entra admin center > Protection > Conditional Access > Named locations.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 15. Persistent Browser Session Without Device Compliance — PS 857-902
  // ------------------------------------------------------------------
  try {
    const persistentBrowserPolicies = enabledPolicies.filter((p) => {
      const sessionControls = p.sessionControls as GraphObj | undefined;
      const persistentBrowser = sessionControls?.persistentBrowser as
        | GraphObj
        | undefined;
      return (
        persistentBrowser != null &&
        persistentBrowser["mode"] === "always" &&
        persistentBrowser["isEnabled"] === true
      );
    });

    // Of those, the ones NOT requiring device compliance.
    const persistentWithoutDevice = persistentBrowserPolicies.filter((p) => {
      const grantControls = p.grantControls as GraphObj | undefined;
      const controls =
        grantControls != null ? grantControls.builtInControls : undefined;
      return !(
        includes(controls, "compliantDevice") ||
        includes(controls, "domainJoinedDevice")
      );
    });

    if (persistentWithoutDevice.length === 0) {
      ctx.addRow(
        row({
          setting: "Persistent Browser Without Device Compliance",
          currentValue: "None",
          recommendedValue: "No persistent sessions without device compliance",
          status: "Pass",
          checkId: "CA-SESSION-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      const n = names(persistentWithoutDevice);
      ctx.addRow(
        row({
          setting: "Persistent Browser Without Device Compliance",
          currentValue: `${persistentWithoutDevice.length} policies allow persistent sessions without device compliance: ${n}`,
          recommendedValue: "No persistent sessions without device compliance",
          status: "Warning",
          checkId: "CA-SESSION-001",
          remediation:
            "Persistent browser sessions on unmanaged devices increase the risk of session hijacking. Require device compliance or remove persistent browser grants. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 16. Combined Sign-in Risk + User Risk Anti-Pattern — PS lines 904-944
  // ------------------------------------------------------------------
  try {
    const combinedRiskPolicies = enabledPolicies.filter((p) => {
      const c = conditions(p);
      return nonEmptyArray(c.signInRiskLevels) && nonEmptyArray(c.userRiskLevels);
    });

    if (combinedRiskPolicies.length === 0) {
      ctx.addRow(
        row({
          setting: "Combined Risk Policy Anti-Pattern",
          currentValue: "None",
          recommendedValue: "Separate sign-in risk and user risk into distinct policies",
          status: "Pass",
          checkId: "CA-RISKPOLICY-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      const n = names(combinedRiskPolicies);
      ctx.addRow(
        row({
          setting: "Combined Risk Policy Anti-Pattern",
          currentValue: `${combinedRiskPolicies.length} policies combine both risk types: ${n}`,
          recommendedValue: "Separate sign-in risk and user risk into distinct policies",
          status: "Warning",
          checkId: "CA-RISKPOLICY-001",
          remediation:
            "Combining sign-in risk and user risk in one CA policy creates an AND condition -- both must be true to trigger. Microsoft recommends separate policies for each risk type. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 17. Directory Role Coverage Gaps — PS lines 946-1013.
  // Active Tier-0 roles (from PIM role assignments) vs roles targeted by
  // any enabled role-targeted CA policy.
  // ------------------------------------------------------------------
  try {
    const roleAssignments = await ctx.transport.getJson(
      CA_SECURITY_CONFIG_ENDPOINTS.roleAssignments,
      { requiredRole: ROLE_MGMT_READ_DIRECTORY },
    );
    const activeRoleIds = [
      ...new Set(asArray(roleAssignments.value).map((r) => String(r.roleDefinitionId))),
    ].sort();

    // Find CA policies that target specific directory roles (not "All users").
    const roleTargetingPolicies = enabledPolicies.filter((p) =>
      nonEmptyArray(users(p).includeRoles),
    );

    if (roleTargetingPolicies.length === 0) {
      ctx.addRow(
        row({
          setting: "Tier-0 Role Coverage in CA Policies",
          currentValue: "No role-targeted CA policies found",
          recommendedValue: "Target active privileged roles",
          status: "Review",
          checkId: "CA-ROLECOVERAGE-001",
          remediation:
            "Consider creating CA policies that specifically target privileged directory roles with stricter controls (phishing-resistant MFA, compliant devices).",
        }),
      );
    } else {
      // Collect all roles covered by CA policies.
      const coveredRoles = new Set<string>();
      for (const p of roleTargetingPolicies) {
        for (const r of users(p).includeRoles as string[]) {
          coveredRoles.add(r);
        }
      }
      // Find active Tier-0 roles not covered by any CA policy.
      const tier0Roles = ADMIN_ROLE_IDS.filter((id) => activeRoleIds.includes(id));
      const uncoveredRoles = tier0Roles.filter((id) => !coveredRoles.has(id));

      if (uncoveredRoles.length === 0) {
        ctx.addRow(
          row({
            setting: "Tier-0 Role Coverage in CA Policies",
            currentValue: `All ${tier0Roles.length} active Tier-0 roles covered`,
            recommendedValue: "All active privileged roles covered",
            status: "Pass",
            checkId: "CA-ROLECOVERAGE-001",
            remediation: "No action needed.",
          }),
        );
      } else {
        ctx.addRow(
          row({
            setting: "Tier-0 Role Coverage in CA Policies",
            currentValue: `${uncoveredRoles.length} of ${tier0Roles.length} active Tier-0 roles not targeted by any CA policy`,
            recommendedValue: "All active privileged roles covered",
            status: "Warning",
            checkId: "CA-ROLECOVERAGE-001",
            remediation:
              "Add the uncovered role IDs to existing admin-targeted CA policies. Entra admin center > Protection > Conditional Access > Select policy > Users > Include roles.",
          }),
        );
      }
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 18. Empty-Target Policies (Fallback Catch-All) — PS lines 1015-1059
  // ------------------------------------------------------------------
  try {
    const emptyTargetPolicies = enabledPolicies.filter((p) => {
      const u = users(p);
      const includeUsers = Array.isArray(u.includeUsers)
        ? (u.includeUsers as unknown[])
        : [];
      const includeGroups = Array.isArray(u.includeGroups)
        ? (u.includeGroups as unknown[])
        : [];
      const includeRoles = Array.isArray(u.includeRoles)
        ? (u.includeRoles as unknown[])
        : [];
      const noUsers = includeUsers.length === 0 || includeUsers.includes("None");
      const noGroups = includeGroups.length === 0;
      const noRoles = includeRoles.length === 0;
      return noUsers && noGroups && noRoles;
    });

    if (emptyTargetPolicies.length === 0) {
      ctx.addRow(
        row({
          setting: "CA Policies with Empty Include Targets",
          currentValue: "None",
          recommendedValue:
            "All enabled CA policies should target at least one user, group, or role",
          status: "Pass",
          checkId: "CA-FALLBACK-001",
          remediation: "No action needed.",
        }),
      );
    } else {
      const n = names(emptyTargetPolicies);
      ctx.addRow(
        row({
          setting: "CA Policies with Empty Include Targets",
          currentValue: `${emptyTargetPolicies.length} enabled policies have no include targets: ${n}`,
          recommendedValue:
            "All enabled CA policies should target at least one user, group, or role",
          status: "Warning",
          checkId: "CA-FALLBACK-001",
          remediation:
            "Enabled CA policies with no include targets apply to no users and create operational noise. Configure meaningful include targets or disable the policy. Entra admin center > Protection > Conditional Access.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 19. Stale Named Location References — PS lines 1061-1120.
  // Only evaluates when authoritative location data exists (PS null-guard).
  // System placeholders ('All'/'AllTrusted'/'MFA') are never stale.
  // ------------------------------------------------------------------
  try {
    const systemLocationIds = new Set(
      ["All", "AllTrusted", "MFA"].map((s) => s.toLowerCase()),
    );
    const knownLocationIds = new Set<string>();
    if (namedLocations) {
      for (const loc of namedLocations) {
        if (typeof loc["id"] === "string") knownLocationIds.add(loc["id"] as string);
      }
    }

    if (knownLocationIds.size > 0) {
      const staleLocPolicies = enabledPolicies.filter((p) => {
        const locations = conditions(p).locations as GraphObj | undefined;
        if (!locations) return false;
        const allRefs = [
          ...(Array.isArray(locations.includeLocations)
            ? (locations.includeLocations as string[])
            : []),
          ...(Array.isArray(locations.excludeLocations)
            ? (locations.excludeLocations as string[])
            : []),
        ];
        return allRefs.some(
          (ref) =>
            typeof ref === "string" &&
            !systemLocationIds.has(ref.toLowerCase()) &&
            !knownLocationIds.has(ref),
        );
      });

      if (staleLocPolicies.length === 0) {
        ctx.addRow(
          row({
            setting: "Stale Named Location References in CA Policies",
            currentValue: "None",
            recommendedValue: "All referenced named locations should exist",
            status: "Pass",
            checkId: "CA-NAMEDLOC-002",
            remediation: "No action needed.",
          }),
        );
      } else {
        const n = names(staleLocPolicies);
        ctx.addRow(
          row({
            setting: "Stale Named Location References in CA Policies",
            currentValue: `${staleLocPolicies.length} policies reference deleted named locations: ${n}`,
            recommendedValue: "All referenced named locations should exist",
            status: "Fail",
            checkId: "CA-NAMEDLOC-002",
            remediation:
              "The referenced named locations have been deleted. These policies may not evaluate correctly, creating unpredictable enforcement. Update or remove the stale location references. Entra admin center > Protection > Conditional Access > Named locations.",
          }),
        );
      }
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 20. Stale Group References in CA Policies — PS lines 1122-1200.
  // Probes up to 50 referenced groups directly; 404-family errors mark a
  // group stale, other probe errors leave it presumed live.
  // ------------------------------------------------------------------
  try {
    // Insertion-ordered dedup across enabled policies (include then exclude).
    const groupIdList: string[] = [];
    const seenGroupIds = new Set<string>();
    for (const policyRec of enabledPolicies) {
      const u = users(policyRec);
      for (const key of ["includeGroups", "excludeGroups"] as const) {
        for (const g of Array.isArray(u[key]) ? (u[key] as string[]) : []) {
          if (!seenGroupIds.has(g)) {
            seenGroupIds.add(g);
            groupIdList.push(g);
          }
        }
      }
    }

    if (groupIdList.length > 0) {
      // Cap lookups to 50 IDs (PS 1136-1137).
      const groupIdsToCheck = groupIdList.slice(0, Math.min(groupIdList.length, 50));
      const staleGroupIds = new Set<string>();
      for (const gid of groupIdsToCheck) {
        try {
          await ctx.transport.getJson(groupSelectUrl(gid), {
            requiredRole: GROUP_READ_ALL,
          });
        } catch (probeErr) {
          if (probeErr instanceof TransportFatalError) throw probeErr;
          if (errMatches(probeErr, /404|ResourceNotFound|Request_ResourceNotFound/)) {
            staleGroupIds.add(gid);
          }
        }
      }

      // Map stale group IDs back to affected policy names.
      const stalePolicies = enabledPolicies.filter((policyRec) => {
        const u = users(policyRec);
        const allGroupRefs = [
          ...(Array.isArray(u.includeGroups) ? (u.includeGroups as string[]) : []),
          ...(Array.isArray(u.excludeGroups) ? (u.excludeGroups as string[]) : []),
        ];
        return allGroupRefs.some((g) => staleGroupIds.has(g));
      });

      if (stalePolicies.length === 0) {
        ctx.addRow(
          row({
            setting: "Stale Group References in CA Policies",
            currentValue: "None",
            recommendedValue: "All referenced groups should exist",
            status: "Pass",
            checkId: "CA-STALEREF-001",
            remediation: "No action needed.",
          }),
        );
      } else {
        const n = names(stalePolicies);
        ctx.addRow(
          row({
            setting: "Stale Group References in CA Policies",
            currentValue: `${stalePolicies.length} policies reference deleted groups: ${n}`,
            recommendedValue: "All referenced groups should exist",
            status: "Fail",
            checkId: "CA-STALEREF-001",
            remediation:
              "CA policies with deleted group references may not enforce correctly, creating silent security gaps. Remove or replace the stale group references. Entra admin center > Protection > Conditional Access.",
          }),
        );
      }
    } else {
      ctx.addRow(
        row({
          setting: "Stale Group References in CA Policies",
          currentValue: "No group-targeted policies",
          recommendedValue: "All referenced groups should exist",
          status: "Pass",
          checkId: "CA-STALEREF-001",
          remediation: "No action needed.",
        }),
      );
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }
};
