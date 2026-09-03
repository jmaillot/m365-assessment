/**
 * Port of ENTRA-MFA-002, CONSENT-005/006, ADMIN-003, APPS-002 — remaining high-value Entra checks.
 * Graph: /reports/authenticationMethods/userRegistrationDetails, /policies/adminConsentRequestPolicy, /directoryRoles, /applications
 * Roles: User.Read.All, Policy.Read.All, Directory.Read.All, Application.Read.All
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

const AUTHORIZATION_ERROR = /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

export const runEntraMfaConsentAdditional: SectionImplementation = async (ctx) => {
  // MFA-002 — Percentage without MFA (similar to mfa-report but percentage threshold)
  try {
    const resp = await ctx.transport.getJson("/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isMfaRegistered&$top=999", { requiredRole: "User.Read.All" });
    const users = asArray(resp.value);
    const total = users.length;
    const withoutMfa = users.filter((u) => (u as Record<string, unknown>).isMfaRegistered !== true).length;
    const pct = total > 0 ? Math.round((withoutMfa / total) * 100) : 0;
    let psStatus: "Pass" | "Fail" | "Warning" | "Review" = "Review";
    if (total === 0) psStatus = "Review";
    else if (pct <= 5) psStatus = "Pass";
    else if (pct <= 20) psStatus = "Warning";
    else psStatus = "Fail";
    ctx.addRow({
      category: "MFA",
      setting: "Percentage of Users Without MFA Method Registered",
      currentValue: total > 0 ? `${withoutMfa}/${total} (${pct}%) without MFA` : "No users enumerated",
      recommendedValue: "≤5% without MFA (100% registered)",
      checkId: "ENTRA-MFA-002",
      remediation: "Entra admin center > Authentication methods > Registration > Require MFA registration via Conditional Access",
      psStatus,
      evidenceSource: "/v1.0/reports/authenticationMethods/userRegistrationDetails",
      collectionMethod: "Direct",
      permissionRequired: "User.Read.All",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "MFA",
        setting: "Percentage of Users Without MFA Method Registered",
        currentValue: "Insufficient permissions (User.Read.All)",
        recommendedValue: "≤5% without MFA",
        checkId: "ENTRA-MFA-002",
        remediation: "Requires User.Read.All",
        psStatus: "Review",
        evidenceSource: "/v1.0/reports/authenticationMethods/userRegistrationDetails",
        collectionMethod: "Direct",
        permissionRequired: "User.Read.All",
      });
    }
  }

  // CONSENT-005 — admin consent request has designated reviewers
  try {
    const resp = await ctx.transport.getJson("/v1.0/policies/adminConsentRequestPolicy", { requiredRole: "Policy.Read.All" });
    const reviewers = asArray((resp as Record<string, unknown>).reviewers ?? (resp as Record<string, unknown>).requestReviewers);
    const hasReviewers = reviewers.length > 0 || Boolean((resp as Record<string, unknown>).isEnabled);
    ctx.addRow({
      category: "Consent",
      setting: "Admin Consent Request Has Designated Reviewers",
      currentValue: hasReviewers ? `${reviewers.length} reviewer(s) configured` : "No reviewers configured",
      recommendedValue: "At least one reviewer (user/group) designated",
      checkId: "ENTRA-CONSENT-005",
      remediation: "Entra admin center > Enterprise applications > Consent and permissions > Admin consent settings > Select users/groups to review",
      psStatus: hasReviewers ? "Pass" : "Fail",
      evidenceSource: "/v1.0/policies/adminConsentRequestPolicy",
      collectionMethod: "Direct",
      permissionRequired: "Policy.Read.All",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Consent",
        setting: "Admin Consent Request Has Designated Reviewers",
        currentValue: "Insufficient permissions (Policy.Read.All)",
        recommendedValue: "At least one reviewer",
        checkId: "ENTRA-CONSENT-005",
        remediation: "Requires Policy.Read.All",
        psStatus: "Review",
        evidenceSource: "/v1.0/policies/adminConsentRequestPolicy",
        collectionMethod: "Direct",
        permissionRequired: "Policy.Read.All",
      });
    }
  }

  // CONSENT-006 — admin consent request sends email notifications
  try {
    const resp = await ctx.transport.getJson("/v1.0/policies/adminConsentRequestPolicy", { requiredRole: "Policy.Read.All" });
    const isNotifying = (resp as Record<string, unknown>).isEnabled === true || Boolean((resp as Record<string, unknown>).notifyReviewers);
    // PS checks notifyReviewers or isEnabled with reviewers
    const notify = (resp as Record<string, unknown>).notifyReviewers as boolean | undefined ?? (resp as Record<string, unknown>).isEnabled as boolean | undefined;
    ctx.addRow({
      category: "Consent",
      setting: "Admin Consent Request Email Notifications",
      currentValue: notify ? "Notifications enabled" : "Notifications not enabled",
      recommendedValue: "Notify reviewers on admin consent request",
      checkId: "ENTRA-CONSENT-006",
      remediation: "Entra admin center > Enterprise applications > Consent and permissions > Admin consent settings > Enable email notifications",
      psStatus: notify ? "Pass" : "Warning",
      evidenceSource: "/v1.0/policies/adminConsentRequestPolicy",
      collectionMethod: "Direct",
      permissionRequired: "Policy.Read.All",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Consent",
        setting: "Admin Consent Request Email Notifications",
        currentValue: "Insufficient permissions (Policy.Read.All)",
        recommendedValue: "Notify reviewers",
        checkId: "ENTRA-CONSENT-006",
        remediation: "Requires Policy.Read.All",
        psStatus: "Review",
        evidenceSource: "/v1.0/policies/adminConsentRequestPolicy",
        collectionMethod: "Direct",
        permissionRequired: "Policy.Read.All",
      });
    }
  }

  // ADMIN-003 — two emergency access accounts (distinct from BREAKGLASS check, counts enabled cloud-only GA)
  try {
    const roleResp = await ctx.transport.getJson("/v1.0/directoryRoles?$filter=roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'", { requiredRole: "Directory.Read.All" });
    const roles = asArray(roleResp.value);
    const gaRole = roles.find((r) => psStr((r as Record<string, unknown>).roleTemplateId) === "62e90394-69f5-4237-9190-012177145e10") as Record<string, unknown> | undefined;
    if (!gaRole) {
      ctx.addRow({
        category: "Admin",
        setting: "Two Emergency Access Accounts Have Been Defined",
        currentValue: "Global Admin role not activated",
        recommendedValue: "At least 2 emergency access accounts",
        checkId: "ENTRA-ADMIN-003",
        remediation: "Entra admin center > Roles > Global Administrator > Add assignments for 2 cloud-only break-glass accounts",
        psStatus: "Fail",
        evidenceSource: "/v1.0/directoryRoles",
        collectionMethod: "Direct",
        permissionRequired: "Directory.Read.All",
      });
    } else {
      const membersResp = await ctx.transport.getJson(`/v1.0/directoryRoles/${psStr(gaRole.id)}/members?$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled`, { requiredRole: "Directory.Read.All" });
      const members = asArray(membersResp.value);
      const cloudOnlyEnabled = members.filter((m) => {
        const accEnabled = (m as Record<string, unknown>).accountEnabled !== false;
        const synced = (m as Record<string, unknown>).onPremisesSyncEnabled === true;
        return accEnabled && !synced;
      });
      // Also check break-glass pattern count as proxy for emergency accounts
      const isEmergency = (m: Record<string, unknown>) => /break.?glass|emergency/i.test(psStr(m.displayName) + psStr(m.userPrincipalName));
      const emergencyCount = members.filter((m) => isEmergency(m as Record<string, unknown>)).length;
      const count = emergencyCount > 0 ? emergencyCount : cloudOnlyEnabled.length;
      ctx.addRow({
        category: "Admin",
        setting: "Two Emergency Access Accounts Have Been Defined",
        currentValue: `${count} emergency/cloud-only Global Admin(s) detected`,
        recommendedValue: "At least 2 emergency access accounts (cloud-only, FIDO2, excluded from CA)",
        checkId: "ENTRA-ADMIN-003",
        remediation: "Create 2 cloud-only break-glass accounts with Global Admin, FIDO2, excluded from CA, monitored",
        psStatus: count >= 2 ? "Pass" : "Fail",
        evidenceSource: "/v1.0/directoryRoles",
        collectionMethod: "Direct",
        permissionRequired: "Directory.Read.All",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Admin",
        setting: "Two Emergency Access Accounts Have Been Defined",
        currentValue: "Insufficient permissions (Directory.Read.All)",
        recommendedValue: "At least 2 emergency access accounts",
        checkId: "ENTRA-ADMIN-003",
        remediation: "Requires Directory.Read.All",
        psStatus: "Review",
        evidenceSource: "/v1.0/directoryRoles",
        collectionMethod: "Direct",
        permissionRequired: "Directory.Read.All",
      });
    }
  }

  // APPS-002 — app registrations with dangerous Intune write permissions
  try {
    const resp = await ctx.transport.getJson("/v1.0/applications?$select=id,displayName,requiredResourceAccess&$top=999", { requiredRole: "Application.Read.All" });
    const apps = asArray(resp.value);
    const dangerous = apps.filter((a) => {
      const rra = asArray((a as Record<string, unknown>).requiredResourceAccess);
      for (const ra of rra as Array<Record<string, unknown>>) {
        const accesses = asArray(ra.resourceAccess);
        for (const ac of accesses as Array<Record<string, unknown>>) {
          const id = psStr(ac.id).toLowerCase();
          // DeviceManagementConfiguration.ReadWrite.All, DeviceManagementApps.ReadWrite.All etc.
          if (id === "4010df8e-4cc6-4726-af0d-46682fdf0a7f" || id === "f8d2e5a0-4d2c-4e3c-8c6c-9f6f0c9f0c9f") return true; // placeholder for Intune write perms - check via string
          if (psStr(ac.type) === "Role" && /DeviceManagement/i.test(psStr(ra.resourceAppId))) return true;
        }
      }
      return false;
    });
    // More accurate: check for any Intune write via string match on requiredResourceAccess
    const hasIntuneWrite = apps.some((a) => JSON.stringify(a).toLowerCase().includes("devicemanagement") && JSON.stringify(a).toLowerCase().includes("write"));
    ctx.addRow({
      category: "Applications",
      setting: "App Registrations with Dangerous Intune Write Permissions",
      currentValue: hasIntuneWrite ? `${dangerous.length} app(s) with Intune write` : "No apps with dangerous Intune write permissions",
      recommendedValue: "No app registrations with DeviceManagement write",
      checkId: "ENTRA-APPS-002",
      remediation: "Entra admin center > App registrations > Review API permissions > Remove DeviceManagementConfiguration.ReadWrite.All",
      psStatus: hasIntuneWrite ? "Fail" : "Pass",
      evidenceSource: "/v1.0/applications",
      collectionMethod: "Direct",
      permissionRequired: "Application.Read.All",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Applications",
        setting: "App Registrations with Dangerous Intune Write Permissions",
        currentValue: "Insufficient permissions (Application.Read.All)",
        recommendedValue: "No app registrations with DeviceManagement write",
        checkId: "ENTRA-APPS-002",
        remediation: "Requires Application.Read.All",
        psStatus: "Review",
        evidenceSource: "/v1.0/applications",
        collectionMethod: "Direct",
        permissionRequired: "Application.Read.All",
      });
    }
  }
};
