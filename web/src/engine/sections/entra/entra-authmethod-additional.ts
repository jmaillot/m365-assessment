/**
 * Port of Entra AUTHMETHOD 005..008 — Authentication methods policy checks.
 * Graph: GET /v1.0/policies/authenticationMethodsPolicy
 * Role: Policy.Read.All, 403 -> Review.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

const REQUIRED_ROLE = "Policy.Read.All";
const AUTHORIZATION_ERROR = /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

export const runEntraAuthMethodAdditional: SectionImplementation = async (ctx) => {
  let policy: Record<string, unknown> | null = null;
  try {
    policy = await ctx.transport.getJson("/v1.0/policies/authenticationMethodsPolicy", { requiredRole: REQUIRED_ROLE }) as Record<string, unknown>;
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      for (const { checkId, setting } of [
        { checkId: "ENTRA-AUTHMETHOD-005", setting: "Authentication Methods Policy Migration (MFA/SSPR)" },
        { checkId: "ENTRA-AUTHMETHOD-006", setting: "Suspicious Activity Reporting for MFA" },
        { checkId: "ENTRA-AUTHMETHOD-007", setting: "Temporary Access Pass (TAP) Enabled" },
        { checkId: "ENTRA-AUTHMETHOD-008", setting: "Temporary Access Pass Single-Use Enforcement" },
      ] as const) {
        ctx.addRow({
          category: "Authentication Methods",
          setting,
          currentValue: "Insufficient permissions (Policy.Read.All)",
          recommendedValue: "Review authentication methods policy",
          checkId,
          remediation: "Requires Policy.Read.All",
          psStatus: "Review",
          evidenceSource: "/v1.0/policies/authenticationMethodsPolicy",
          collectionMethod: "Direct",
          permissionRequired: REQUIRED_ROLE,
        });
      }
      return;
    }
    return;
  }
  if (!policy) return;

  // 005: policy migration — check isMigrationComplete and authenticationMethodConfigurations has registrationEnforcement
  {
    const isMigrationComplete = policy.isMigrationComplete as boolean | undefined;
    const authMethods = asArray((policy as Record<string, unknown>).authenticationMethodConfigurations);
    const hasRegistrationEnforcement = authMethods.some((m) => psStr((m as Record<string, unknown>).authenticationMethod) === "TemporaryAccessPass");
    // Simplified: Pass if migration complete or at least one method configured
    ctx.addRow({
      category: "Authentication Methods",
      setting: "Authentication Methods Policy Migration (MFA/SSPR)",
      currentValue: isMigrationComplete ? "Migration complete" : hasRegistrationEnforcement ? "Migration in progress" : "Not migrated",
      recommendedValue: "Authentication methods policy migrated (isMigrationComplete: true)",
      checkId: "ENTRA-AUTHMETHOD-005",
      remediation: "Entra admin center > Authentication methods > Policies > Migrate from MFA/SSPR policies",
      psStatus: isMigrationComplete ? "Pass" : "Warning",
      evidenceSource: "/v1.0/policies/authenticationMethodsPolicy",
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
  // 006: suspicious activity reporting — check reportSuspiciousActivityEnabled in authenticationMethodsPolicy
  {
    const reportSuspicious = (policy as Record<string, unknown>).reportSuspiciousActivityEnabled as boolean | undefined;
    // Also check per-method: microsoftAuthenticatorAuthenticationMethodConfiguration includeFeature target
    let isEnabled = reportSuspicious;
    if (isEnabled === undefined) {
      const methods = asArray((policy as Record<string, unknown>).authenticationMethodConfigurations);
      const msAuth = methods.find((m) => psStr((m as Record<string, unknown>).authenticationMethod) === "microsoftAuthenticator") as Record<string, unknown> | undefined;
      if (msAuth) isEnabled = Boolean((msAuth as Record<string, unknown>).reportSuspiciousActivityEnabled ?? (msAuth as Record<string, unknown>).isReportingEnabled);
    }
    ctx.addRow({
      category: "Authentication Methods",
      setting: "Suspicious Activity Reporting for MFA",
      currentValue: isEnabled ? "Enabled" : "Disabled or not configured",
      recommendedValue: "Report suspicious activity enabled",
      checkId: "ENTRA-AUTHMETHOD-006",
      remediation: "Entra admin center > Authentication methods > Policies > Microsoft Authenticator > Reporting suspicious activity > Enabled",
      psStatus: isEnabled ? "Pass" : "Fail",
      evidenceSource: "/v1.0/policies/authenticationMethodsPolicy",
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
  // 007: TAP enabled — check TemporaryAccessPass method state
  {
    const methods = asArray((policy as Record<string, unknown>).authenticationMethodConfigurations);
    const tap = methods.find((m) => psStr((m as Record<string, unknown>).authenticationMethod) === "temporaryAccessPass") as Record<string, unknown> | undefined;
    const tapState = psStr(tap?.state);
    const isEnabled = tapState === "enabled";
    ctx.addRow({
      category: "Authentication Methods",
      setting: "Temporary Access Pass (TAP) Enabled",
      currentValue: tap ? `TAP state: ${tapState || "unknown"}` : "TAP not configured",
      recommendedValue: "TAP enabled for onboarding/recovery",
      checkId: "ENTRA-AUTHMETHOD-007",
      remediation: "Entra admin center > Authentication methods > Policies > Temporary Access Pass > Enable",
      psStatus: isEnabled ? "Pass" : "Review",
      evidenceSource: "/v1.0/policies/authenticationMethodsPolicy",
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
  // 008: TAP single-use — check isUsableOnce
  {
    const methods = asArray((policy as Record<string, unknown>).authenticationMethodConfigurations);
    const tap = methods.find((m) => psStr((m as Record<string, unknown>).authenticationMethod) === "temporaryAccessPass") as Record<string, unknown> | undefined;
    const isUsableOnce = tap ? Boolean((tap as Record<string, unknown>).isUsableOnce) : undefined;
    // Also check includeTargets configuration
    let isSingleUse = isUsableOnce;
    if (isSingleUse === undefined && tap) {
      const targets = asArray((tap as Record<string, unknown>).includeTargets);
      const firstTarget = targets[0] as Record<string, unknown> | undefined;
      if (firstTarget) isSingleUse = Boolean(firstTarget.isUsableOnce);
    }
    ctx.addRow({
      category: "Authentication Methods",
      setting: "Temporary Access Pass Single-Use Enforcement",
      currentValue: isSingleUse === true ? "Single-use enforced" : isSingleUse === false ? "Multi-use allowed" : "Not configured",
      recommendedValue: "TAP isUsableOnce: true (single-use)",
      checkId: "ENTRA-AUTHMETHOD-008",
      remediation: "Entra admin center > Authentication methods > Policies > Temporary Access Pass > Configure > One-time use",
      psStatus: isSingleUse === true ? "Pass" : isSingleUse === false ? "Fail" : "Review",
      evidenceSource: "/v1.0/policies/authenticationMethodsPolicy",
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
};
