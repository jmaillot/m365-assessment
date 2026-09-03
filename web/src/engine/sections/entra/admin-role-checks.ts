/**
 * Port of `src/M365-Assess/Entra/EntraAdminRoleChecks.ps1` (611 lines)
 * — check-helper half of Get-EntraSecurityConfig.ps1 (plan 02-08 task 1).
 *
 * PS shared-scope state → module-local variables + run store within one
 * invocation: $authPolicy is pre-fetched ONCE by Get-EntraSecurityConfig.ps1
 * (lines 59-72, soft-fail) and consumed here by section 31; the port reads
 * ctx.shared("entra.authPolicy") first and, when absent (standalone runs),
 * performs the identical soft-fail pre-fetch and stores it so a composing
 * collector sees exactly one fetch. $script:pimMessage persists across the
 * PIM sections exactly like the PS script-scoped variable.
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting: owned by the runner's addRow
 *   pipeline (mapStatus → sub-numbering → D-22 registry fallback).
 * - Invoke-MgGraphRequest GET → ctx.transport.getJson with requiredRole.
 * - Get-BreakGlassAccounts (EntraHelpers.ps1): case-insensitive naming-
 *   convention regex over displayName/userPrincipalName (PowerShell -match
 *   default), inlined as a local helper.
 * - Beta endpoints promoted to v1.0 per BETA-ENDPOINTS.md:
 *   roleAssignmentScheduleInstances (availability probe — result discarded
 *   exactly as PS discards it), roleEligibilityScheduleInstances (this file's
 *   own call site; same surface family promoted during plan 02-06),
 *   identityGovernance/accessReviews/definitions, and the
 *   reports/authenticationMethods/userRegistrationDetails read (resolved
 *   02-05/02-07 rows).
 * - Soft-fail semantics preserved per section: catch blocks emit their PS row
 *   verbatim or degrade to zero rows; TransportFatalError (structural guard
 *   breaches: non-GET, ungranted role) still propagates.
 * - The Evidence PSCustomObject on ENTRA-ADMIN-001 is intentionally not
 *   carried: CheckRowInput has no freeform-evidence slot and no decision
 *   consumes it (same disposition as plans 02-07/02-09/02-10).
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const ADMIN_ROLE_ENDPOINTS = {
  authorizationPolicy: "/v1.0/policies/authorizationPolicy",
  globalAdminRoleFilter:
    "/v1.0/directoryRoles?$filter=displayName%20eq%20%27Global%20Administrator%27",
  subscribedSkus: "/v1.0/subscribedSkus",
  roleAssignmentScheduleInstances:
    "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
  accessReviews: "/v1.0/identityGovernance/accessReviews/definitions?$top=100",
  userRegistrationDetails:
    "/v1.0/reports/authenticationMethods/userRegistrationDetails",
} as const;

/** Well-known privileged role template IDs (PS lines 149, 311-316). */
const GA_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10";
const PRA_TEMPLATE_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814";

/** AAD_PREMIUM_P2 atomic service plan (PS line 96, #881). */
const AAD_P2_SERVICE_PLAN_ID = "eec0eb4f-6444-4f95-aba0-50c24d67f998";

/** E3/E5 productivity SKU part IDs (PS lines 444-449). */
const PRODUCTIVITY_SKUS = [
  "05e9a617-0261-4cee-bb36-b42c3d50e6a0", // SPE_E3 (M365 E3)
  "06ebc4ee-1bb5-47dd-8120-11324bc54e06", // SPE_E5 (M365 E5)
  "6fd2c87f-b296-42f0-b197-1e91e994b900", // ENTERPRISEPACK (O365 E3)
  "c7df2760-2c81-4ef7-b578-5b5392b571df", // ENTERPRISEPREMIUM (O365 E5)
];

/** Phishing-resistant methods (PS lines 552-558). */
const PHISHING_RESISTANT_METHODS = [
  "fido2",
  "windowsHelloForBusiness",
  "x509CertificateMultiFactor",
  "passKeyDeviceBound",
  "passKeyDeviceBoundAuthenticator",
];

/**
 * Get-BreakGlassAccounts (EntraHelpers.ps1:9-16) — PowerShell -match is
 * case-insensitive by default, hence the /i flags.
 */
function isBreakGlass(account: Record<string, unknown>): boolean {
  const pattern = /(break.?glass|emergency.?access|breakglass|emer.?admin)/i;
  return (
    pattern.test(psStr(account.displayName)) ||
    pattern.test(psStr(account.userPrincipalName))
  );
}

export function roleMembersUrl(roleId: string): string {
  return `/v1.0/directoryRoles/${roleId}/members`;
}

export function gaRoleMembersByTemplateUrl(): string {
  return `/v1.0/directoryRoles(roleTemplateId='${GA_TEMPLATE_ID}')/members`;
}

/** PS #978 shape: mandatory $filter on scopeId+scopeType+roleDefinitionId. */
export function pimPolicyAssignmentsUrl(roleId: string): string {
  return `/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId%20eq%20%27/%27%20and%20scopeType%20eq%20%27DirectoryRole%27%20and%20roleDefinitionId%20eq%20%27${roleId}%27&$expand=policy($expand=rules)`;
}

export function praPolicyAssignmentsUrl(): string {
  return pimPolicyAssignmentsUrl(PRA_TEMPLATE_ID);
}

export function gaEligibilityInstancesUrl(): string {
  return `/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId%20eq%20%27${GA_TEMPLATE_ID}%27`;
}

export function gaMembersSelectSyncUrl(): string {
  return `/v1.0/directoryRoles/roleTemplateId=${GA_TEMPLATE_ID}/members?$select=displayName,userPrincipalName,onPremisesSyncEnabled`;
}

export function gaMembersSelectLicensesUrl(): string {
  return `/v1.0/directoryRoles/roleTemplateId=${GA_TEMPLATE_ID}/members?$select=displayName,assignedLicenses`;
}

export function gaMembersSelectIdsUrl(): string {
  return `/v1.0/directoryRoles/roleTemplateId=${GA_TEMPLATE_ID}/members?$select=id,displayName,userPrincipalName`;
}

type GraphObj = Record<string, unknown>;

const POLICY_READ_ALL = "Policy.Read.All";
const DIRECTORY_READ_ALL = "Directory.Read.All";
const ROLE_MGMT_READ_DIRECTORY = "RoleManagement.Read.Directory";
const ACCESS_REVIEWS_READ_ALL = "AccessReviews.Read.All";
const USER_AUTH_METHOD_READ_ALL = "UserAuthenticationMethod.Read.All";

/** PS 403-family matcher for PIM availability degradation (PS lines 130, 238). */
const PIM_FORBIDDEN = /403|Forbidden|Authorization|license/;

export const runAdminRoleChecks: SectionImplementation = async (ctx) => {
  // Shared $authPolicy acquisition (Get-EntraSecurityConfig.ps1:59-72).
  let authPolicy = ctx.shared.get("entra.authPolicy") as GraphObj | null | undefined;
  if (authPolicy === undefined) {
    try {
      authPolicy = (await ctx.transport.getJson(ADMIN_ROLE_ENDPOINTS.authorizationPolicy, {
        requiredRole: POLICY_READ_ALL,
      })) as GraphObj;
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      authPolicy = null;
    }
    ctx.shared.set("entra.authPolicy", authPolicy);
  }

  // ------------------------------------------------------------------
  // 2. Global Admin Count (should be 2-4, excluding break-glass) — PS 13-75
  // ------------------------------------------------------------------
  try {
    const globalAdminRole = (await ctx.transport.getJson(
      ADMIN_ROLE_ENDPOINTS.globalAdminRoleFilter,
      { requiredRole: DIRECTORY_READ_ALL },
    )) as GraphObj;
    const activated = asArray(globalAdminRole.value);
    if (activated.length === 0) {
      ctx.addRow({
        category: "Admin Accounts",
        setting: "Global Administrator Count",
        currentValue: "Role not activated",
        recommendedValue: "2-4",
        psStatus: "Warning",
        checkId: "ENTRA-ADMIN-001",
        remediation:
          "The Global Administrator directory role is not activated in this tenant. Activate the role by assigning at least one user, then re-run the assessment.",
      });
    } else {
      const roleId = psStr(activated[0].id);
      const members = (await ctx.transport.getJson(roleMembersUrl(roleId), {
        requiredRole: DIRECTORY_READ_ALL,
      })) as GraphObj;
      const allAdmins = asArray(members.value);

      // Exclude break-glass accounts from the operational admin count.
      const breakGlassAdmins = allAdmins.filter(isBreakGlass);
      const operationalAdmins = allAdmins.filter((a) => !isBreakGlass(a));
      const gaCount = operationalAdmins.length;
      const bgExcluded = breakGlassAdmins.length;

      const gaStatus =
        gaCount >= 2 && gaCount <= 4 ? "Pass" : gaCount < 2 ? "Fail" : "Warning";

      const countDetail =
        bgExcluded > 0 ? `${gaCount} (excluding ${bgExcluded} break-glass)` : `${gaCount}`;

      ctx.addRow({
        category: "Admin Accounts",
        setting: "Global Administrator Count",
        currentValue: countDetail,
        recommendedValue: "2-4",
        psStatus: gaStatus,
        checkId: "ENTRA-ADMIN-001",
        remediation:
          'Run: Get-MgDirectoryRole -Filter "displayName eq \'Global Administrator\'" | Get-MgDirectoryRoleMember. Maintain 2-4 global admins using dedicated accounts (break-glass accounts are excluded from this count).',
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity — zero rows, run continues.
  }

  // ------------------------------------------------------------------
  // 22. Privileged Identity Management (CIS 5.3.x) — PS 77-382
  // ------------------------------------------------------------------
  let pimAvailable = true;
  let pimMessage: string | null = null;

  // P2/E5 license detection by atomic service plan (#881).
  let hasPimLicense = false;
  try {
    const skus = (await ctx.transport.getJson(ADMIN_ROLE_ENDPOINTS.subscribedSkus, {
      requiredRole: DIRECTORY_READ_ALL,
    })) as GraphObj;
    for (const sku of asArray(skus.value)) {
      if (sku.capabilityStatus !== "Enabled") continue;
      const servicePlans = Array.isArray(sku.servicePlans)
        ? (sku.servicePlans as GraphObj[])
        : [];
      if (
        servicePlans.some(
          (sp) =>
            sp.servicePlanId === AAD_P2_SERVICE_PLAN_ID &&
            sp.provisioningStatus === "Success",
        )
      ) {
        hasPimLicense = true;
        break;
      }
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Verbose parity.
  }

  // Skip PIM API queries entirely when no P2 license (#886 preamble).
  if (!hasPimLicense) {
    pimAvailable = false;
    pimMessage =
      "PIM not licensed (Entra ID P2 required) -- cannot verify role assignment permanence";
  } else {
    try {
      // Availability probe only — PS assigns $pimRoleAssignments and never
      // reads it. Promoted from /beta per BETA-ENDPOINTS.md.
      await ctx.transport.getJson(ADMIN_ROLE_ENDPOINTS.roleAssignmentScheduleInstances, {
        requiredRole: ROLE_MGMT_READ_DIRECTORY,
      });
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      if (errMatches(err, PIM_FORBIDDEN)) {
        pimAvailable = false;
        pimMessage = "PIM is available but not configured in this tenant";
      } else {
        pimAvailable = false;
        pimMessage = `Could not check PIM: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
  }

  // CIS 5.3.1 — permanent-GA subtraction (#886): enumerate ALL GA members
  // (direct OR PIM-elevated), subtract JIT-eligible-only principals.
  let gaMembers: GraphObj[] = [];
  let gaQueryFailed = false;
  try {
    const gaRoleResp = (await ctx.transport.getJson(gaRoleMembersByTemplateUrl(), {
      requiredRole: DIRECTORY_READ_ALL,
    })) as GraphObj;
    gaMembers = asArray(gaRoleResp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    gaQueryFailed = true;
  }

  let eligiblePrincipalIds: string[] = [];
  if (hasPimLicense && !gaQueryFailed) {
    // Promoted from /beta per BETA-ENDPOINTS.md (02-06 surface family).
    try {
      const eligibleResp = (await ctx.transport.getJson(gaEligibilityInstancesUrl(), {
        requiredRole: ROLE_MGMT_READ_DIRECTORY,
      })) as GraphObj;
      eligiblePrincipalIds = asArray(eligibleResp.value).map((e) => psStr(e.principalId));
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      // PS Write-Warning parity — eligibility list stays empty.
    }
  }

  if (gaQueryFailed) {
    ctx.addRow({
      category: "Privileged Identity Management",
      setting: "PIM Manages Privileged Roles",
      currentValue: "Could not enumerate Global Admin members",
      recommendedValue: "No permanent Global Admin assignments",
      psStatus: "Unknown",
      checkId: "ENTRA-PIM-001",
      remediation: "Verify RoleManagement.Read.Directory consent. Then re-run the assessment.",
    });
  } else {
    const permanentGAs = gaMembers.filter((m) => !eligiblePrincipalIds.includes(psStr(m.id)));
    const permanentCount = permanentGAs.length;

    let detail: string;
    if (permanentCount === 0) {
      detail = hasPimLicense
        ? "No permanent GA assignments (all GAs are PIM-eligible)"
        : "No Global Administrator members detected";
    } else {
      const upns = permanentGAs
        .slice(0, 5)
        .map((m) => psStr(m.userPrincipalName) || psStr(m.displayName) || psStr(m.id))
        .join(", ");
      const more = permanentCount > 5 ? ` (+${permanentCount - 5} more)` : "";
      detail = hasPimLicense
        ? `${permanentCount} permanent (non-PIM-eligible) GA assignment(s): ${upns}${more}`
        : `${permanentCount} Global Admin(s) — PIM not licensed so all are permanent: ${upns}${more}`;
    }

    ctx.addRow({
      category: "Privileged Identity Management",
      setting: "PIM Manages Privileged Roles",
      currentValue: detail,
      recommendedValue: "No permanent Global Admin assignments (all GAs PIM-eligible only)",
      psStatus: permanentCount === 0 ? "Pass" : "Fail",
      checkId: "ENTRA-PIM-001",
      remediation:
        "Entra admin center > Identity Governance > Privileged Identity Management > Microsoft Entra roles > Global Administrator > Remove permanent active assignments. Use eligible assignments with time-bound activation. Requires Entra ID P2 (included in M365 E5).",
    });
  }

  // CIS 5.3.2/5.3.3 — Access reviews for guests and privileged roles.
  // Promoted from /beta per BETA-ENDPOINTS.md.
  let accessReviews: GraphObj | null = null;
  if (pimAvailable) {
    try {
      accessReviews = (await ctx.transport.getJson(ADMIN_ROLE_ENDPOINTS.accessReviews, {
        requiredRole: ACCESS_REVIEWS_READ_ALL,
      })) as GraphObj;
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      if (errMatches(err, PIM_FORBIDDEN)) {
        // PS sets $pimAvailable = $false WITHOUT updating $script:pimMessage.
        pimAvailable = false;
      }
      // else: PS Write-Warning parity — zero rows below via neither branch.
    }
  }

  if (accessReviews && Array.isArray(accessReviews.value)) {
    const allReviews = asArray(accessReviews.value);

    // CIS 5.3.2 — Guest access reviews
    const guestReviews = allReviews.filter((r) => {
      const scope = r.scope as GraphObj | undefined;
      return (
        scope &&
        (/guest/i.test(psStr(scope.query)) || /guest/i.test(psStr(scope["@odata.type"])))
      );
    });
    ctx.addRow({
      category: "Privileged Identity Management",
      setting: "Access Reviews for Guest Users",
      currentValue:
        guestReviews.length > 0
          ? `${guestReviews.length} guest access review(s) configured`
          : "No guest access reviews found",
      recommendedValue: "At least 1 access review for guests",
      psStatus: guestReviews.length > 0 ? "Pass" : "Fail",
      checkId: "ENTRA-PIM-002",
      remediation:
        "Entra admin center > Identity Governance > Access reviews > New access review > Review type: Guest users only. Schedule recurring reviews.",
    });

    // CIS 5.3.3 — Privileged role access reviews
    const roleReviews = allReviews.filter((r) => {
      const scope = r.scope as GraphObj | undefined;
      return scope && /roleManagement|directoryRole/i.test(psStr(scope.query));
    });
    ctx.addRow({
      category: "Privileged Identity Management",
      setting: "Access Reviews for Privileged Roles",
      currentValue:
        roleReviews.length > 0
          ? `${roleReviews.length} privileged role review(s) configured`
          : "No privileged role access reviews found",
      recommendedValue: "At least 1 access review for admin roles",
      psStatus: roleReviews.length > 0 ? "Pass" : "Fail",
      checkId: "ENTRA-PIM-003",
      remediation:
        "Entra admin center > Identity Governance > Access reviews > New access review > Review type: Members of a group or Users assigned to a privileged role.",
    });
  } else if (!pimAvailable) {
    ctx.addRow({
      category: "Privileged Identity Management",
      setting: "Access Reviews for Guest Users",
      currentValue: psStr(pimMessage),
      recommendedValue: "At least 1 access review for guests",
      psStatus: "Review",
      checkId: "ENTRA-PIM-002",
      remediation:
        "This check requires Entra ID P2 (included in M365 E5). Entra admin center > Identity Governance > Access reviews.",
    });

    ctx.addRow({
      category: "Privileged Identity Management",
      setting: "Access Reviews for Privileged Roles",
      currentValue: psStr(pimMessage),
      recommendedValue: "At least 1 access review for admin roles",
      psStatus: "Review",
      checkId: "ENTRA-PIM-003",
      remediation:
        "This check requires Entra ID P2 (included in M365 E5). Entra admin center > Identity Governance > Access reviews.",
    });
  }

  // CIS 5.3.4/5.3.5 — GA/PRA activation approval (#978 v1.0 filtered shape).
  const pimApprovalRoles = [
    {
      checkId: "ENTRA-PIM-004",
      setting: "GA Activation Requires Approval",
      roleId: GA_TEMPLATE_ID,
      roleName: "Global Administrator",
    },
    {
      checkId: "ENTRA-PIM-005",
      setting: "PRA Activation Requires Approval",
      roleId: PRA_TEMPLATE_ID,
      roleName: "Privileged Role Administrator",
    },
  ];

  if (pimAvailable) {
    for (const role of pimApprovalRoles) {
      let approvalRequired: boolean | null = null; // null = could not determine → Review
      try {
        const assignmentsResp = (await ctx.transport.getJson(
          pimPolicyAssignmentsUrl(role.roleId),
          { requiredRole: ROLE_MGMT_READ_DIRECTORY },
        )) as GraphObj;
        const assignment = asArray(assignmentsResp.value)[0] ?? null;
        const rules =
          assignment &&
          typeof assignment.policy === "object" &&
          assignment.policy !== null &&
          Array.isArray((assignment.policy as GraphObj).rules)
            ? ((assignment.policy as GraphObj).rules as GraphObj[])
            : [];
        const approvalRule = rules.find((r) =>
          /ApprovalRule/i.test(psStr(r["@odata.type"])),
        );
        if (approvalRule && approvalRule.setting !== null && approvalRule.setting !== undefined) {
          approvalRequired = Boolean((approvalRule.setting as GraphObj).isApprovalRequired);
        } else if (assignment) {
          // Policy resolved but carries no approval rule → not required.
          approvalRequired = false;
        }
      } catch (err) {
        if (err instanceof TransportFatalError) throw err;
        approvalRequired = null;
      }

      if (approvalRequired === null) {
        ctx.addRow({
          category: "Privileged Identity Management",
          setting: role.setting,
          currentValue: "Unable to read PIM activation policy",
          recommendedValue: "Yes",
          psStatus: "Review",
          checkId: role.checkId,
          remediation: `Entra admin center > Identity Governance > PIM > Microsoft Entra roles > Settings > ${role.roleName} > Require approval to activate > Yes.`,
        });
      } else {
        ctx.addRow({
          category: "Privileged Identity Management",
          setting: role.setting,
          currentValue: approvalRequired ? "Yes" : "No",
          recommendedValue: "Yes",
          psStatus: approvalRequired ? "Pass" : "Fail",
          checkId: role.checkId,
          remediation: `Entra admin center > Identity Governance > PIM > Microsoft Entra roles > Settings > ${role.roleName} > Require approval to activate > Yes.`,
        });
      }
    }
  } else {
    for (const role of pimApprovalRoles) {
      ctx.addRow({
        category: "Privileged Identity Management",
        setting: role.setting,
        currentValue: psStr(pimMessage),
        recommendedValue: "Yes",
        psStatus: "Review",
        checkId: role.checkId,
        remediation:
          "This check requires Entra ID P2 (included in M365 E5). Entra admin center > Identity Governance > PIM > Microsoft Entra roles > Settings.",
      });
    }
  }

  // ------------------------------------------------------------------
  // 23. Cloud-Only Admin Accounts (CIS 1.1.1) — PS 384-428
  // ------------------------------------------------------------------
  try {
    const gaMembersResp = (await ctx.transport.getJson(gaMembersSelectSyncUrl(), {
      requiredRole: DIRECTORY_READ_ALL,
    })) as GraphObj;
    const gaList = asArray(gaMembersResp.value);
    const syncedAdmins = gaList.filter((m) => m.onPremisesSyncEnabled === true);

    if (syncedAdmins.length === 0) {
      ctx.addRow({
        category: "Admin Accounts",
        setting: "Cloud-Only Global Admins",
        currentValue: `All ${gaList.length} GA accounts are cloud-only`,
        recommendedValue: "All admin accounts cloud-only",
        psStatus: "Pass",
        checkId: "ENTRA-CLOUDADMIN-001",
        remediation: "No action needed.",
      });
    } else {
      const syncedNames = syncedAdmins.map((m) => psStr(m.displayName)).join(", ");
      ctx.addRow({
        category: "Admin Accounts",
        setting: "Cloud-Only Global Admins",
        currentValue: `${syncedAdmins.length} synced: ${syncedNames}`,
        recommendedValue: "All admin accounts cloud-only",
        psStatus: "Fail",
        checkId: "ENTRA-CLOUDADMIN-001",
        remediation:
          "Create cloud-only admin accounts instead of using on-premises synced accounts. Entra admin center > Users > New user > Create user (cloud identity).",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }

  // ------------------------------------------------------------------
  // 24. Admin License Footprint (CIS 1.1.4) — PS 430-485
  // ------------------------------------------------------------------
  try {
    const gaUsersLicense = (await ctx.transport.getJson(gaMembersSelectLicensesUrl(), {
      requiredRole: DIRECTORY_READ_ALL,
    })) as GraphObj;
    const gaLicenseList = asArray(gaUsersLicense.value);
    const heavyLicensed = gaLicenseList.filter((m) =>
      asArray(m.assignedLicenses).some((l) =>
        PRODUCTIVITY_SKUS.includes(psStr(l.skuId)),
      ),
    );

    if (heavyLicensed.length === 0) {
      ctx.addRow({
        category: "Admin Accounts",
        setting: "Admin License Footprint",
        currentValue: "No GA accounts have full productivity licenses",
        recommendedValue: "Admins use minimal license (Entra P2 only)",
        psStatus: "Pass",
        checkId: "ENTRA-CLOUDADMIN-002",
        remediation: "No action needed.",
      });
    } else {
      const names = heavyLicensed.map((m) => psStr(m.displayName)).join(", ");
      ctx.addRow({
        category: "Admin Accounts",
        setting: "Admin License Footprint",
        currentValue: `${heavyLicensed.length} GA with productivity license: ${names}`,
        recommendedValue: "Admins use minimal license (Entra P2 only)",
        psStatus: "Warning",
        checkId: "ENTRA-CLOUDADMIN-002",
        remediation:
          "Assign admin accounts minimal licenses (Entra ID P2). Do not assign E3/E5 productivity suites. M365 admin center > Users > Active users > Licenses.",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }

  // ------------------------------------------------------------------
  // 31. Entra Admin Center Access Restriction (CIS 5.1.2.4) — PS 487-520
  // ------------------------------------------------------------------
  try {
    if (authPolicy && authPolicy.restrictNonAdminUsers !== null && authPolicy.restrictNonAdminUsers !== undefined) {
      const restricted = authPolicy.restrictNonAdminUsers;
      ctx.addRow({
        category: "Access Control",
        setting: "Entra Admin Center Restricted",
        currentValue: psStr(restricted),
        recommendedValue: "True",
        psStatus: restricted ? "Pass" : "Fail",
        checkId: "ENTRA-ADMIN-002",
        remediation:
          'Entra admin center > Identity > Users > User settings > Administration center > set "Restrict access to Microsoft Entra admin center" to Yes.',
      });
    } else {
      ctx.addRow({
        category: "Access Control",
        setting: "Entra Admin Center Restricted",
        currentValue: "Property not available",
        recommendedValue: "True",
        psStatus: "Review",
        checkId: "ENTRA-ADMIN-002",
        remediation:
          'Entra admin center > Identity > Users > User settings > Administration center > verify "Restrict access to Microsoft Entra admin center" is set to Yes.',
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }

  // ENTRA-ADMIN-003 (Emergency Access Accounts) removed upstream in #888 —
  // duplicate of ENTRA-BREAKGLASS-001 (Get-StrykerIncidentReadiness.ps1).

  // ------------------------------------------------------------------
  // 33. Admin MFA Method Strength (phishing-resistant required) — PS 529-611
  // ------------------------------------------------------------------
  try {
    const adminMembers = (await ctx.transport.getJson(gaMembersSelectIdsUrl(), {
      requiredRole: DIRECTORY_READ_ALL,
    })) as GraphObj;
    const adminList = asArray(adminMembers.value);

    if (adminList.length > 0) {
      // Promoted from /beta per resolved BETA-ENDPOINTS.md rows.
      const mfaDetails = (await ctx.transport.getJson(
        ADMIN_ROLE_ENDPOINTS.userRegistrationDetails,
        { requiredRole: USER_AUTH_METHOD_READ_ALL },
      )) as GraphObj;
      const mfaList = asArray(mfaDetails.value);

      const adminIds = adminList.map((m) => psStr(m.id));
      const adminMfa = mfaList.filter((m) => adminIds.includes(psStr(m.id)));

      const adminsWithoutPhishRes = adminMfa.filter((m) => {
        const methods = Array.isArray(m.methodsRegistered)
          ? (m.methodsRegistered as unknown[])
          : [];
        return !methods.some((method) =>
          PHISHING_RESISTANT_METHODS.includes(String(method)),
        );
      });
      const adminsNoMfa = adminMfa.filter((m) => !m.isMfaRegistered);

      if (adminsNoMfa.length > 0) {
        const names = adminsNoMfa.map((m) => psStr(m.userDisplayName)).join(", ");
        ctx.addRow({
          category: "Admin Accounts",
          setting: "Admin MFA Method Strength",
          currentValue: `${adminsNoMfa.length} admin(s) without MFA: ${names}`,
          recommendedValue: "All admins use phishing-resistant MFA",
          psStatus: "Fail",
          checkId: "ENTRA-ADMIN-004",
          remediation:
            "Enroll all Global Administrators in phishing-resistant MFA (FIDO2, Windows Hello for Business, or certificate-based). Entra admin center > Protection > Authentication methods > Policies.",
        });
      } else if (adminsWithoutPhishRes.length > 0) {
        const names = adminsWithoutPhishRes.map((m) => psStr(m.userDisplayName)).join(", ");
        ctx.addRow({
          category: "Admin Accounts",
          setting: "Admin MFA Method Strength",
          currentValue: `${adminsWithoutPhishRes.length} admin(s) without phishing-resistant MFA: ${names}`,
          recommendedValue: "All admins use phishing-resistant MFA",
          psStatus: "Warning",
          checkId: "ENTRA-ADMIN-004",
          remediation:
            "Upgrade admin MFA to phishing-resistant methods (FIDO2, Windows Hello for Business, or certificate-based). Standard MFA (push/TOTP) is vulnerable to adversary-in-the-middle attacks. Entra admin center > Protection > Authentication methods > Policies.",
        });
      } else {
        ctx.addRow({
          category: "Admin Accounts",
          setting: "Admin MFA Method Strength",
          currentValue: `All ${adminMfa.length} admin(s) have phishing-resistant MFA`,
          recommendedValue: "All admins use phishing-resistant MFA",
          psStatus: "Pass",
          checkId: "ENTRA-ADMIN-004",
          remediation: "No action needed.",
        });
      }
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }
};
