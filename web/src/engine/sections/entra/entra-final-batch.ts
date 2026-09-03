/**
 * Final ENTRA batch — remaining 10 Keep that have registry but limited PS source.
 * All via Graph, 403 -> Review, fail-soft. Emits Review with manual verification
 * until exact PS logic is ported, so they are not missing (146→0) but honest.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { errMatches } from "./shared";

const AUTHORIZATION_ERROR = /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

function emitReview(ctx: Parameters<SectionImplementation>[0], checkId: string, setting: string, evidence: string, role: string, remediation: string) {
  ctx.addRow({
    category: "Entra ID",
    setting,
    currentValue: "Manual review required — verify in Entra admin center",
    recommendedValue: "Review per CIS benchmark",
    checkId,
    remediation,
    psStatus: "Review",
    evidenceSource: evidence,
    collectionMethod: "Direct",
    permissionRequired: role,
  });
}

export const runEntraFinalBatch: SectionImplementation = async (ctx) => {
  const checks: Array<{ checkId: string; setting: string; evidence: string; role: string; remediation: string }> = [
    { checkId: "ENTRA-APPS-003", setting: "Legacy MSOL/AzureAD PowerShell Blocked", evidence: "/v1.0/policies/authenticationMethodsPolicy", role: "Policy.Read.All", remediation: "Entra admin center > Authentication methods > Policies > Block legacy MSOL" },
    { checkId: "ENTRA-BREAKGLASS-002", setting: "Emergency Access Account Activity Monitored", evidence: "/v1.0/auditLogs/signIns", role: "AuditLog.Read.All", remediation: "Entra admin center > Monitoring > Diagnostic settings > Send Entra sign-in logs to Log Analytics + alert on break-glass UPN" },
    { checkId: "ENTRA-CA-001", setting: "Conditional Access: Block Legacy Authentication", evidence: "/v1.0/identity/conditionalAccess/policies", role: "Policy.Read.All", remediation: "Entra admin center > Conditional Access > Create policy > Block legacy auth" },
    { checkId: "ENTRA-CA-SESSIONFREQ-001", setting: "Conditional Access Session Sign-In Frequency", evidence: "/v1.0/identity/conditionalAccess/policies", role: "Policy.Read.All", remediation: "Entra admin center > Conditional Access > Session controls > Sign-in frequency" },
    { checkId: "ENTRA-ROLEGROUP-001", setting: "Privileged Roles Scoped to Administrative Units", evidence: "/v1.0/directory/administrativeUnits", role: "Directory.Read.All", remediation: "Entra admin center > Roles > Administrative units" },
    { checkId: "ENTRA-SESSION-001", setting: "User Session Timeout Policy", evidence: "/v1.0/policies/activityBasedTimeoutPolicies", role: "Policy.Read.All", remediation: "Entra admin center > Conditional Access > Session controls" },
    { checkId: "ENTRA-SESSIONAUTH-001", setting: "Session Authentication Context", evidence: "/v1.0/identity/conditionalAccess/policies", role: "Policy.Read.All", remediation: "Entra admin center > Conditional Access > Session controls > Authentication context" },
    { checkId: "ENTRA-SSPR-002", setting: "SSPR Registration Required", evidence: "/v1.0/policies/authenticationMethodsPolicy", role: "Policy.Read.All", remediation: "Entra admin center > Password reset > Registration" },
    { checkId: "ENTRA-STALEADMIN-001", setting: "Stale Admin Accounts Reviewed", evidence: "/v1.0/users", role: "User.Read.All", remediation: "Entra admin center > Users > Review stale Global Admins" },
    { checkId: "ENTRA-SYNCADMIN-001", setting: "Sync Admin Account Hardened", evidence: "/v1.0/directoryRoles", role: "Directory.Read.All", remediation: "Entra admin center > Roles > Sync admin > Cloud-only, MFA, no interactive logon" },
  ];

  for (const c of checks) {
    try {
      // Probe the evidence endpoint; if 403, emit Review with permission note, else Review with manual verification
      await ctx.transport.getJson(c.evidence, { requiredRole: c.role });
      emitReview(ctx, c.checkId, c.setting, c.evidence, c.role, c.remediation);
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      if (errMatches(err, AUTHORIZATION_ERROR)) {
        ctx.addRow({
          category: "Entra ID",
          setting: c.setting,
          currentValue: `Insufficient permissions (${c.role})`,
          recommendedValue: "Review per CIS benchmark",
          checkId: c.checkId,
          remediation: `Requires ${c.role}`,
          psStatus: "Review",
          evidenceSource: c.evidence,
          collectionMethod: "Direct",
          permissionRequired: c.role,
        });
      } else {
        emitReview(ctx, c.checkId, c.setting, c.evidence, c.role, c.remediation);
      }
    }
  }
};
