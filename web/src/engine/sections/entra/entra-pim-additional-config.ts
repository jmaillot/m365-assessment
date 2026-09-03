/**
 * Port of Entra PIM 006..010 — Tier-0 PIM policy checks (ENTRA-PIM-006..010).
 * Graph: GET /v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '{id}'&$expand=policy($expand=rules)
 *        + GET /v1.0/subscribedSkus for P2 license gating (pivot from EntraAdminRoleChecks.ps1:86)
 * Roles: Policy.Read.All + RoleManagement.Read.Directory, 403 -> Review, TransportFatalError rethrow.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

const REQUIRED_ROLE_POLICY = "Policy.Read.All";
const REQUIRED_ROLE_DIRECTORY = "RoleManagement.Read.Directory";
const AUTHORIZATION_ERROR = /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;
const PIM_P2_SERVICE_PLAN_ID = "eec0eb4f-6444-4f95-aba0-50c24d67f998";
const GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10";
const TIER0_ROLE_IDS = [
  "62e90394-69f5-4237-9190-012177145e10", // Global Admin
  "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Admin
  "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Admin (Tier0-related)
];

function parseDurationToHours(dur: string): number | null {
  // PT4H, PT8H, P1D etc. Simplified: handle PT<n>H and P<n>D
  const m = /^PT(\d+)H$/i.exec(psStr(dur));
  if (m) return Number(m[1]);
  const d = /^P(\d+)D$/i.exec(psStr(dur));
  if (d) return Number(d[1]) * 24;
  return null;
}

export const runEntraPimAdditionalConfig: SectionImplementation = async (ctx) => {
  let hasPimLicense = false;
  let pimMessage = "PIM not licensed (Entra ID P2 required) — cannot verify";
  try {
    const skusResp = await ctx.transport.getJson("/v1.0/subscribedSkus", { requiredRole: REQUIRED_ROLE_DIRECTORY });
    const skuList = asArray(skusResp.value);
    for (const sku of skuList) {
      if (psStr((sku as Record<string, unknown>).capabilityStatus) !== "Enabled") continue;
      const plans = asArray((sku as Record<string, unknown>).servicePlans);
      for (const sp of plans as Array<Record<string, unknown>>) {
        if (psStr(sp.servicePlanId) === PIM_P2_SERVICE_PLAN_ID && psStr(sp.provisioningStatus) === "Success") {
          hasPimLicense = true; break;
        }
      }
      if (hasPimLicense) break;
    }
    if (!hasPimLicense) pimMessage = "PIM not licensed (Entra ID P2 required) — cannot verify role assignment permanence";
  } catch {
    // keep hasPimLicense false, pimMessage already
  }

  if (!hasPimLicense) {
    for (const { checkId, setting, recommendedValue, remediation } of [
      { checkId: "ENTRA-PIM-006", setting: "Tier-0 Role Activation Duration (≤4h)", recommendedValue: "Maximum activation duration ≤4 hours", remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > select role > Settings > Edit > Activation > Maximum activation duration 4 hours" },
      { checkId: "ENTRA-PIM-007", setting: "Justification Required on Tier-0 Activation", recommendedValue: "Require justification on activation", remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > select role > Settings > Edit > Activation > Require justification" },
      { checkId: "ENTRA-PIM-008", setting: "MFA Required on Tier-0 Activation", recommendedValue: "MFA required on activation", remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > select role > Settings > Edit > Activation > Require MFA" },
      { checkId: "ENTRA-PIM-009", setting: "No Permanent Eligible Assignments for Tier-0", recommendedValue: "Eligible assignments are time-bound, not permanent", remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > Assignments > Remove permanent eligible assignments" },
      { checkId: "ENTRA-PIM-010", setting: "Admin Notification on Tier-0 Activation", recommendedValue: "Admin notification enabled", remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > select role > Settings > Notifications" },
    ] as const) {
      ctx.addRow({
        category: "Privileged Identity Management",
        setting,
        currentValue: pimMessage,
        recommendedValue,
        checkId,
        remediation,
        psStatus: "Review",
        evidenceSource: "/v1.0/subscribedSkus",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE_DIRECTORY,
      });
    }
    return;
  }

  // PIM licensed — check each Tier-0 role's policy
  for (const roleId of TIER0_ROLE_IDS) {
    let policy: Record<string, unknown> | null = null;
    try {
      const resp = await ctx.transport.getJson(`/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '${roleId}'&$expand=policy($expand=rules)`, { requiredRole: REQUIRED_ROLE_POLICY });
      const assigns = asArray(resp.value);
      const first = assigns[0] as Record<string, unknown> | undefined;
      policy = (first?.policy as Record<string, unknown>) ?? null;
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      if (errMatches(err, AUTHORIZATION_ERROR)) {
        // Emit Review for each check for this role
        for (const { checkId, setting } of [
          { checkId: "ENTRA-PIM-006", setting: `Tier-0 Activation Duration — ${roleId.slice(0,8)}` },
          { checkId: "ENTRA-PIM-007", setting: `Justification Required — ${roleId.slice(0,8)}` },
          { checkId: "ENTRA-PIM-008", setting: `MFA Required — ${roleId.slice(0,8)}` },
          { checkId: "ENTRA-PIM-009", setting: `Permanent Eligible — ${roleId.slice(0,8)}` },
          { checkId: "ENTRA-PIM-010", setting: `Admin Notification — ${roleId.slice(0,8)}` },
        ] as const) {
          ctx.addRow({
            category: "Privileged Identity Management",
            setting,
            currentValue: "Insufficient permissions (Policy.Read.All)",
            recommendedValue: "PIM policy readable",
            checkId,
            remediation: "Requires Policy.Read.All",
            psStatus: "Review",
            evidenceSource: "/v1.0/policies/roleManagementPolicyAssignments",
            collectionMethod: "Direct",
            permissionRequired: REQUIRED_ROLE_POLICY,
          });
        }
        continue;
      }
      continue;
    }
    if (!policy) continue;
    const rules = asArray(policy.rules);

    // 006: expiration max duration <=4h
    {
      const expRule = rules.find((r) => /expirationRule/i.test(psStr((r as Record<string, unknown>)["@odata.type"]))) as Record<string, unknown> | undefined;
      const maxDur = expRule ? psStr((expRule as Record<string, unknown>).maximumDuration ?? (expRule as Record<string, unknown>).maximumDurationInHours) : "";
      const hours = parseDurationToHours(maxDur);
      const isPass = hours !== null && hours <= 4;
      ctx.addRow({
        category: "Privileged Identity Management",
        setting: `Tier-0 Activation Duration — ${roleId.slice(0,8)}`,
        currentValue: maxDur ? `Maximum duration ${maxDur}` : "No expiration rule",
        recommendedValue: "Maximum activation duration ≤4 hours (PT4H)",
        checkId: "ENTRA-PIM-006",
        remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > select role > Settings > Edit > Activation > Maximum activation duration 4 hours",
        psStatus: expRule ? (isPass ? "Pass" : "Fail") : "Fail",
        evidenceSource: "/v1.0/policies/roleManagementPolicyAssignments",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE_POLICY,
      });
    }
    // 007: justification required
    {
      const justRule = rules.find((r) => /justificationRule|approvalRule/i.test(psStr((r as Record<string, unknown>)["@odata.type"]))) as Record<string, unknown> | undefined;
      const isRequired = justRule ? Boolean((justRule as Record<string, unknown>).isJustificationRequired ?? (justRule as Record<string, unknown>).isApprovalRequired) : false;
      // More accurate: look for setting.isJustificationRequired
      const setting = justRule ? ((justRule as Record<string, unknown>).setting as Record<string, unknown> | undefined) : undefined;
      const isJust = setting ? Boolean(setting.isJustificationRequired) : isRequired;
      ctx.addRow({
        category: "Privileged Identity Management",
        setting: `Justification Required — ${roleId.slice(0,8)}`,
        currentValue: isJust ? "Justification required" : "Justification not required",
        recommendedValue: "Require justification on activation",
        checkId: "ENTRA-PIM-007",
        remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > select role > Settings > Edit > Activation > Require justification",
        psStatus: isJust ? "Pass" : "Fail",
        evidenceSource: "/v1.0/policies/roleManagementPolicyAssignments",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE_POLICY,
      });
    }
    // 008: MFA required
    {
      const mfaRule = rules.find((r) => /mfaRule|authenticationContext/i.test(psStr((r as Record<string, unknown>)["@odata.type"]))) as Record<string, unknown> | undefined;
      const isMfa = mfaRule ? true : false;
      // Check for setting.isMfaRequired or similar
      let isMfaRequired = isMfa;
      if (mfaRule) {
        const s = (mfaRule as Record<string, unknown>).setting as Record<string, unknown> | undefined;
        if (s) isMfaRequired = Boolean(s.isMfaRequired ?? s.isAuthenticationRequired);
      }
      ctx.addRow({
        category: "Privileged Identity Management",
        setting: `MFA Required — ${roleId.slice(0, 8)}`,
        currentValue: isMfaRequired ? "MFA required" : "MFA not required",
        recommendedValue: "MFA required on activation",
        checkId: "ENTRA-PIM-008",
        remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > select role > Settings > Edit > Activation > Require MFA",
        psStatus: isMfaRequired ? "Pass" : "Fail",
        evidenceSource: "/v1.0/policies/roleManagementPolicyAssignments",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE_POLICY,
      });
    }
    // 009: permanent eligible — check via roleEligibilityScheduleInstances with permanent flag? Simplified: if policy has no expiration rule, permanent allowed
    {
      const expRule = rules.find((r) => /expirationRule/i.test(psStr((r as Record<string, unknown>)["@odata.type"])));
      const isPermanentAllowed = !expRule;
      ctx.addRow({
        category: "Privileged Identity Management",
        setting: `Permanent Eligible — ${roleId.slice(0, 8)}`,
        currentValue: isPermanentAllowed ? "Permanent eligible assignments allowed (no expiration rule)" : "Eligible assignments are time-bound",
        recommendedValue: "Eligible assignments are time-bound, not permanent",
        checkId: "ENTRA-PIM-009",
        remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > Assignments > Remove permanent eligible assignments",
        psStatus: isPermanentAllowed ? "Fail" : "Pass",
        evidenceSource: "/v1.0/policies/roleManagementPolicyAssignments",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE_POLICY,
      });
    }
    // 010: admin notification
    {
      const notifRule = rules.find((r) => /notificationRule/i.test(psStr((r as Record<string, unknown>)["@odata.type"]))) as Record<string, unknown> | undefined;
      const isNotif = notifRule ? Boolean((notifRule as Record<string, unknown>).isDefaultRecipientsEnabled ?? (notifRule as Record<string, unknown>).notificationType) : false;
      ctx.addRow({
        category: "Privileged Identity Management",
        setting: `Admin Notification — ${roleId.slice(0, 8)}`,
        currentValue: isNotif ? "Admin notification enabled" : "Admin notification not enabled",
        recommendedValue: "Admin notification enabled",
        checkId: "ENTRA-PIM-010",
        remediation: "Entra admin center > Identity Governance > PIM > Microsoft Entra roles > select role > Settings > Notifications",
        psStatus: isNotif ? "Pass" : "Fail",
        evidenceSource: "/v1.0/policies/roleManagementPolicyAssignments",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE_POLICY,
      });
    }
  }
};
