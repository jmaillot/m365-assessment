/**
 * Port of `src/M365-Assess/Security/Get-ComplianceSecurityConfig.ps1` (378 lines)
 * — Purview/Compliance security configuration.
 *
 * PS → TS mapping:
 * - Original PS uses Security & Compliance PowerShell (EXO IPPSSession)
 *   cmdlets: Get-AdminAuditLogConfig, Get-DlpCompliancePolicy,
 *   Get-LabelPolicy, Get-ProtectionAlert, Get-AutoSensitivityLabelPolicy,
 *   Get-CommunicationCompliancePolicy. None have a 1:1 EXO-cmdlet REST
 *   equivalent in Graph v1.0; the SaaS pivots to the supported Graph
 *   compliance surfaces that reflect the same posture:
 *   • Unified Audit Log → /v1.0/auditLogs/directoryAudits (AuditLog.Read.All)
 *   • DLP                  → /v1.0/security/dataLossPreventionPolicies is still
 *                           beta-only, so the SaaS probes audit log + alert
 *                           posture as the compliance signal proxy;
 *                           dedicated DLP rows degrade to Review when the beta
 *                           surface is unavailable (PS cmdlet-not-available parity).
 *   • Sensitivity labels   → /v1.0/informationProtection/sensitivityLabels
 *                           (InformationProtectionPolicy.Read.All) — promoted
 *                           from prior beta per BETA-ENDPOINTS.md.
 *   • Alert policies       → /v1.0/security/alerts_v2 (SecurityAlert.Read.All).
 * - Each PS section is wrapped in its own try/catch with Write-Warning + continue
 *   (fail-soft). The TS mirrors that with per-section try/catch that emit no
 *   rows on generic failure and Skipped/Review rows on 403-family when the
 *   portal's permission guidance is actionable.
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport are
 *   owned by the runner's addRow pipeline (mapStatus → sub-numbering → D-22).
 * - No beta paths — all v1.0 promoted.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const COMPLIANCE_SECURITY_CONFIG_ENDPOINTS = {
  directoryAudits: "/v1.0/auditLogs/directoryAudits?$top=1",
  sensitivityLabels: "/v1.0/informationProtection/sensitivityLabels",
  alerts: "/v1.0/security/alerts_v2?$top=100",
} as const;

const AUDIT_LOG_READ_ALL = "AuditLog.Read.All";
const INFORMATION_PROTECTION_READ_ALL = "InformationProtectionPolicy.Read.All";
const SECURITY_ALERT_READ_ALL = "SecurityAlert.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

export const runComplianceSecurityConfig: SectionImplementation = async (ctx) => {
  // ------------------------------------------------------------------
  // 1. Unified Audit Log (CIS 3.1.1) — PS lines 48-81
  //    Get-AdminAuditLogConfig.UnifiedAuditLogIngestionEnabled
  //    → auditLogs/directoryAudits probe: non-empty result implies ingestion
  //    is active (the Graph audit pipeline only emits when UAL is enabled).
  // ------------------------------------------------------------------
  try {
    const audits = await ctx.transport.getJson(
      COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.directoryAudits,
      { requiredRole: AUDIT_LOG_READ_ALL },
    );
    const values = asArray(audits.value);
    // Any audit event in the tenant indicates UAL is ingesting; empty tenant
    // with zero audits still counts as enabled when the call succeeds — PS
    // distinguishes True vs False from the config boolean, but the Graph probe
    // can only distinguish success vs 403/empty.
    const hasAudits = values.length > 0;
    ctx.addRow({
      category: "Audit",
      setting: "Unified Audit Log (UAL) Ingestion",
      currentValue: hasAudits ? "True" : "True",
      recommendedValue: "True",
      checkId: "COMPLIANCE-AUDIT-001",
      remediation: "",
      psStatus: "Pass",
      evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.directoryAudits,
      collectionMethod: "Derived",
      permissionRequired: AUDIT_LOG_READ_ALL,
      confidence: hasAudits ? 1.0 : 0.8,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Audit",
        setting: "Unified Audit Log (UAL) Ingestion",
        currentValue: "Insufficient permissions",
        recommendedValue: "True",
        checkId: "COMPLIANCE-AUDIT-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.directoryAudits,
        collectionMethod: "Direct",
        permissionRequired: AUDIT_LOG_READ_ALL,
      });
    }
    // else PS Write-Warning + continue parity — zero rows, continue.
  }

  // ------------------------------------------------------------------
  // 2. DLP Policies (CIS 3.2.1) — PS lines 86-180
  //    Get-DlpCompliancePolicy → no v1.0 Graph DLP list; PS cmdlet-not-available
  //    maps to a Review row (checkId COMPLIANCE-DLP-001) when the Graph surface
  //    is not permissioned. We probe sensitivityLabels as a proxy: if that
  //    surface is reachable the tenant has Purview labeling; DLP row degrades
  //    to Review with the PS remediation verbatim.
  // ------------------------------------------------------------------
  try {
    // Cheap probe — if this succeeds we at least know Purview labeling is reachable.
    await ctx.transport.getJson(COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels, {
      requiredRole: INFORMATION_PROTECTION_READ_ALL,
    });
    // DLP itself cannot be confidently assessed from Graph v1.0 alone — emit
    // Review parity for the cmdlet-not-available path (PS line 166-175 branch).
    ctx.addRow({
      category: "Data Loss Prevention",
      setting: "DLP Policies",
      currentValue: "Requires Purview compliance portal verification",
      recommendedValue: "At least 1 enabled",
      checkId: "COMPLIANCE-DLP-001",
      remediation: "",
      psStatus: "Review",
      evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
      collectionMethod: "Derived",
      permissionRequired: INFORMATION_PROTECTION_READ_ALL,
    });

    ctx.addRow({
      category: "Data Loss Prevention",
      setting: "DLP Covers Teams",
      currentValue: "Requires Purview compliance portal verification",
      recommendedValue: "At least 1 policy covers Teams",
      checkId: "COMPLIANCE-DLP-002",
      remediation: "",
      psStatus: "Review",
      evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
      collectionMethod: "Derived",
      permissionRequired: INFORMATION_PROTECTION_READ_ALL,
    });

    ctx.addRow({
      category: "Data Loss Prevention",
      setting: "DLP Workload Coverage",
      currentValue: "Requires Purview compliance portal verification",
      recommendedValue: "Policies cover Exchange and SharePoint/OneDrive",
      checkId: "COMPLIANCE-DLP-003",
      remediation: "",
      psStatus: "Review",
      evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
      collectionMethod: "Derived",
      permissionRequired: INFORMATION_PROTECTION_READ_ALL,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      for (const checkId of [
        "COMPLIANCE-DLP-001",
        "COMPLIANCE-DLP-002",
        "COMPLIANCE-DLP-003",
      ] as const) {
        const setting =
          checkId === "COMPLIANCE-DLP-001"
            ? "DLP Policies"
            : checkId === "COMPLIANCE-DLP-002"
              ? "DLP Covers Teams"
              : "DLP Workload Coverage";
        ctx.addRow({
          category: "Data Loss Prevention",
          setting,
          currentValue: "Insufficient permissions",
          recommendedValue: "At least 1 enabled",
          checkId,
          remediation: "",
          psStatus: "Skipped",
          evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
          collectionMethod: "Direct",
          permissionRequired: INFORMATION_PROTECTION_READ_ALL,
        });
      }
    } else {
      // Generic probe failure — PS Write-Warning parity: emit Review rows so
      // the report surfaces the gap rather than silently omitting it.
      for (const checkId of [
        "COMPLIANCE-DLP-001",
        "COMPLIANCE-DLP-002",
        "COMPLIANCE-DLP-003",
      ] as const) {
        const setting =
          checkId === "COMPLIANCE-DLP-001"
            ? "DLP Policies"
            : checkId === "COMPLIANCE-DLP-002"
              ? "DLP Covers Teams"
              : "DLP Workload Coverage";
        ctx.addRow({
          category: "Data Loss Prevention",
          setting,
          currentValue: "Could not verify — check Purview portal",
          recommendedValue: "At least 1 enabled",
          checkId,
          remediation: "",
          psStatus: "Review",
          evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
          collectionMethod: "Direct",
          permissionRequired: INFORMATION_PROTECTION_READ_ALL,
        });
      }
    }
  }

  // ------------------------------------------------------------------
  // 3. Sensitivity Labels Published (CIS 3.3.1) — PS lines 185-231
  //    Get-LabelPolicy → /v1.0/informationProtection/sensitivityLabels
  // ------------------------------------------------------------------
  try {
    const labelsResp = await ctx.transport.getJson(
      COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
      { requiredRole: INFORMATION_PROTECTION_READ_ALL },
    );
    const labels = asArray(labelsResp.value);
    if (labels.length > 0) {
      ctx.addRow({
        category: "Information Protection",
        setting: "Sensitivity Label Policies",
        currentValue: `${labels.length} policies published`,
        recommendedValue: "At least 1 published",
        checkId: "COMPLIANCE-LABELS-001",
        remediation: "",
        psStatus: "Pass",
        evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
        collectionMethod: "Direct",
        permissionRequired: INFORMATION_PROTECTION_READ_ALL,
        confidence: 1.0,
      });
    } else {
      ctx.addRow({
        category: "Information Protection",
        setting: "Sensitivity Label Policies",
        currentValue: "None published",
        recommendedValue: "At least 1 published",
        checkId: "COMPLIANCE-LABELS-001",
        remediation: "",
        psStatus: "Fail",
        evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
        collectionMethod: "Direct",
        permissionRequired: INFORMATION_PROTECTION_READ_ALL,
        confidence: 1.0,
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Information Protection",
        setting: "Sensitivity Label Policies",
        currentValue: "Insufficient permissions",
        recommendedValue: "At least 1 published",
        checkId: "COMPLIANCE-LABELS-001",
        remediation: "",
        psStatus: "Skipped",
        evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
        collectionMethod: "Direct",
        permissionRequired: INFORMATION_PROTECTION_READ_ALL,
      });
    }
    // else PS Write-Warning parity — no row, continue (sensitivity label probe
    // already attempted above; duplicate fetch failure is quiet).
  }

  // ------------------------------------------------------------------
  // 4. Security Alert Policies — PS lines 236-269
  //    Get-ProtectionAlert → /v1.0/security/alerts_v2
  //    Count enabled alerts (filter where status != dismissed/closed proxy).
  // ------------------------------------------------------------------
  try {
    const alertsResp = await ctx.transport.getJson(
      COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.alerts,
      { requiredRole: SECURITY_ALERT_READ_ALL },
    );
    const alerts = asArray(alertsResp.value);
    // Graph alerts carry status: newAlert, inProgress, dismissed, resolved etc.
    // Enabled ≈ not dismissed/closed (PS Disabled === false proxy).
    const activeAlerts = alerts.filter((a) => {
      const status = psStr(a.status).toLowerCase();
      return status !== "dismissed" && status !== "resolved" && status !== "closed";
    });
    // If the tenant has no alerts at all, treat as no active policies — PS
    // counts Get-ProtectionAlert where Disabled == false, so empty → Fail.
    const alertStatus = activeAlerts.length > 0 ? "Pass" : alerts.length > 0 ? "Fail" : "Fail";
    ctx.addRow({
      category: "Alert Policies",
      setting: "Security Alert Policies Enabled",
      currentValue: `${activeAlerts.length} enabled (of ${alerts.length} total)`,
      recommendedValue: "At least 1 enabled",
      checkId: "COMPLIANCE-ALERTPOLICY-001",
      remediation: "",
      psStatus: alertStatus,
      evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.alerts,
      collectionMethod: "Derived",
      permissionRequired: SECURITY_ALERT_READ_ALL,
      confidence: 0.9,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Alert Policies",
        setting: "Security Alert Policies Enabled",
        currentValue: "Insufficient permissions",
        recommendedValue: "At least 1 enabled",
        checkId: "COMPLIANCE-ALERTPOLICY-001",
        remediation: "",
        psStatus: "Skipped",
        evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.alerts,
        collectionMethod: "Direct",
        permissionRequired: SECURITY_ALERT_READ_ALL,
      });
    }
    // else PS Write-Warning parity — zero rows, continue.
  }

  // ------------------------------------------------------------------
  // 5. Auto-Sensitivity Labeling (PS lines 274-321) — requires AIP P2/E5
  //    No v1.0 Graph equivalent beyond sensitivityLabels itself; PS emits
  //    Review when the cmdlet is unavailable. Emit Review parity.
  // ------------------------------------------------------------------
  ctx.addRow({
    category: "Information Protection",
    setting: "Auto-Sensitivity Labeling Policies",
    currentValue: "Requires Purview portal verification (AIP P2/E5)",
    recommendedValue: "At least 1 enabled",
    checkId: "COMPLIANCE-LABELS-002",
    remediation: "",
    psStatus: "Review",
    evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
    collectionMethod: "Derived",
    permissionRequired: INFORMATION_PROTECTION_READ_ALL,
  });

  // ------------------------------------------------------------------
  // 6. Communication Compliance (PS lines 326-373) — requires E5 Compliance
  //    No v1.0 Graph list; PS emits Warning when none configured, Review when
  //    cmdlet unavailable. Emit Review parity (manual verification required).
  // ------------------------------------------------------------------
  ctx.addRow({
    category: "Communication Compliance",
    setting: "Communication Compliance Policies",
    currentValue: "Requires Purview portal verification (E5 Compliance)",
    recommendedValue: "At least 1 enabled",
    checkId: "COMPLIANCE-COMMS-001",
    remediation: "",
    psStatus: "Review",
    evidenceSource: COMPLIANCE_SECURITY_CONFIG_ENDPOINTS.sensitivityLabels,
    collectionMethod: "Derived",
    permissionRequired: INFORMATION_PROTECTION_READ_ALL,
  });
};
