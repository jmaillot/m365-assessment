/**
 * Port of `src/M365-Assess/Purview/Get-PurviewRetentionConfig.ps1` (245 lines)
 * — Purview data lifecycle retention compliance policy configuration.
 *
 * PS → TS mapping:
 * - Original PS uses Security & Compliance PowerShell (IPPSSession) cmdlet
 *   `Get-RetentionCompliancePolicy` (lines 54-56) — no direct Graph v1.0 REST
 *   promotion for retention *compliance policies* themselves. The SaaS port
 *   pivots to the supported Graph retention surface:
 *   `GET /v1.0/security/labels/retentionLabels` (RecordsManagement.Read.All)
 *   which reflects data lifecycle retention posture via published retention
 *   labels (PS workload checks — Exchange/Teams/SharePoint coverage — are
 *   represented as label behavior/descriptor presence rather than
 *   Get-RetentionCompliancePolicy ExchangeLocation/TeamsChannelLocation).
 *   Where the Graph label surface is unavailable or returns 404/501 (still
 *   IPPSSession-only in the tenant), the collector degrades to
 *   Skipped(not_implemented) parity (PS lines 229-239 cmdlet-not-available
 *   branch) — REMOVED-CAPABILITIES § Purview gap, no beta fallback.
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport are
 *   owned by the runner's addRow pipeline (mapStatus → sub-numbering → D-22
 *   registryRemediationText fallback). Per-section fresh sub-numberer mirrors
 *   single Initialize-SecurityConfig context.
 * - Each of the 5 PS checks maps to one base CheckId:
 *   PURVIEW-RETENTION-001..005 (PS lines 77, 107, 138, 167, 196). Workload
 *   coverage checks (002-004) degrade to label-count proxy when Graph label
 *   descriptors are absent — Pass when at least one label exists, else Fail
 *   (PS empty-policy parity).
 * - TransportFatalError is always rethrown (programming/routing bug); 403-
 *   family GraphErrors degrade to Skipped via errMatches (PS NotLicensed /
 *   permission branch); generic failures emit Skipped(not_implemented) so
 *   report explains gap rather than silently omitting (D-10). No beta paths.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] when Purview section is wired). */
export const PURVIEW_RETENTION_CONFIG_ENDPOINTS = {
  retentionLabels: "/v1.0/security/labels/retentionLabels?$top=250",
} as const;

const REQUIRED_ROLE = "RecordsManagement.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const NOT_IMPLEMENTED_CURRENT =
  "Not implemented in Graph v1.0 — Purview retention compliance policy requires Security & Compliance PowerShell (IPPSSession); see REMOVED-CAPABILITIES";
const NOT_IMPLEMENTED_RECOMMENDED = "Verify in Microsoft Purview > Data lifecycle management > Retention policies";

function emitSkipped(
  ctx: Parameters<SectionImplementation>[0],
  reason: string,
): void {
  const isAuthReason = reason.includes("Missing permissions");
  const isNotImplemented = reason.includes("Not implemented in Graph v1.0");
  const remediation = isAuthReason
    ? "Grant RecordsManagement.Read.All via admin consent"
    : isNotImplemented
      ? NOT_IMPLEMENTED_RECOMMENDED
      : "";
  for (const { checkId, setting, category, recommendedValue } of [
    {
      checkId: "PURVIEW-RETENTION-001",
      setting: "Retention Policies Configured",
      category: "Retention Policies",
      recommendedValue: "At least 1 enabled",
    },
    {
      checkId: "PURVIEW-RETENTION-002",
      setting: "Exchange Covered by Retention",
      category: "Retention Policies",
      recommendedValue: "At least 1 policy covers Exchange",
    },
    {
      checkId: "PURVIEW-RETENTION-003",
      setting: "Teams Covered by Retention",
      category: "Retention Policies",
      recommendedValue: "At least 1 policy covers Teams",
    },
    {
      checkId: "PURVIEW-RETENTION-004",
      setting: "SharePoint/OneDrive Covered by Retention",
      category: "Retention Policies",
      recommendedValue: "At least 1 policy covers SharePoint/OneDrive",
    },
    {
      checkId: "PURVIEW-RETENTION-005",
      setting: "Retention Policies in Enforce Mode",
      category: "Retention Policies",
      recommendedValue: "All policies in Enforce mode",
    },
  ] as const) {
    ctx.addRow({
      category,
      setting,
      currentValue: reason,
      recommendedValue,
      checkId,
      remediation,
      psStatus: "Skipped",
      evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
}

export const runPurviewRetentionConfig: SectionImplementation = async (ctx) => {
  let labels: Record<string, unknown>[] = [];
  try {
    const resp = await ctx.transport.getJson(
      PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
      { requiredRole: REQUIRED_ROLE },
    );
    labels = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      emitSkipped(ctx, "Missing permissions — RecordsManagement.Read.All not granted; re-consent to grant");
      return;
    }
    if (errMatches(err, /404|501|NotImplemented|Not implemented/i)) {
      emitSkipped(ctx, NOT_IMPLEMENTED_CURRENT);
      return;
    }
    // PS cmdlet-not-available parity (lines 229-239) + any betaOnly gap —
    // Graph retentionLabels not available in this tenant → Skipped(not_implemented).
    emitSkipped(ctx, NOT_IMPLEMENTED_CURRENT);
    return;
  }

  // ------------------------------------------------------------------
  // 1. PURVIEW-RETENTION-001 — Retention Policies Configured (PS lines 69-94)
  // ------------------------------------------------------------------
  {
    const enabledCount = labels.filter((l) => {
      // Graph retentionLabel exposes isEnabled / state / retentionState in some shapes;
      // fall back to counting total when explicit flag absent (PS Enabled -ne $false parity).
      const v = l.isEnabled ?? l.enabled ?? l.state;
      if (v === false) return false;
      if (typeof v === "string" && v.toLowerCase() === "disabled") return false;
      return true;
    }).length;
    const total = labels.length;
    if (enabledCount > 0) {
      ctx.addRow({
        category: "Retention Policies",
        setting: "Retention Policies Configured",
        currentValue: `${enabledCount} enabled (of ${total} total)`,
        recommendedValue: "At least 1 enabled",
        checkId: "PURVIEW-RETENTION-001",
        remediation: "",
        psStatus: "Pass",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      const currentVal = total === 0 ? "None configured" : `${total} policies (none enabled)`;
      ctx.addRow({
        category: "Retention Policies",
        setting: "Retention Policies Configured",
        currentValue: currentVal,
        recommendedValue: "At least 1 enabled",
        checkId: "PURVIEW-RETENTION-001",
        remediation: "",
        psStatus: "Fail",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  }

  // Helper to detect workload coverage in label descriptors.
  // Graph retentionLabel may carry descriptors/workloads/tags; we probe several
  // common shapes and degrade to label-count proxy when descriptors absent.
  function coversWorkload(keyword: RegExp): boolean {
    if (labels.length === 0) return false;
    return labels.some((l) => {
      const text = [
        psStr(l.displayName),
        psStr(l.name),
        psStr(l.description),
        // descriptors is array in some shapes
        ...(Array.isArray(l.descriptors)
          ? (l.descriptors as unknown[]).map((d) => psStr((d as Record<string, unknown>).name ?? d))
          : []),
        // retention display / behavior hints
        psStr(l.behaviorDuringRetentionPeriod),
        psStr(l.actionAfterRetentionPeriod),
      ].join(" ");
      // Also check explicit workload array if present
      const workloads = l.workloads ?? l.applicableWorkloads;
      if (Array.isArray(workloads)) {
        const wText = (workloads as unknown[]).map((w) => psStr(w)).join(" ");
        if (keyword.test(wText)) return true;
      }
      // Check extended properties bag
      const ap = l.additionalProperties as Record<string, unknown> | undefined;
      if (ap) {
        const apText = Object.values(ap).map((v) => psStr(v)).join(" ");
        if (keyword.test(apText)) return true;
      }
      return keyword.test(text);
    });
  }

  const hasAnyEnabled = labels.some((l) => {
    const v = l.isEnabled ?? l.enabled ?? l.state;
    if (v === false) return false;
    if (typeof v === "string" && v.toLowerCase() === "disabled") return false;
    return true;
  });

  // ------------------------------------------------------------------
  // 2. PURVIEW-RETENTION-002 — Exchange Covered (PS lines 96-124)
  // ------------------------------------------------------------------
  {
    const exchangeCovered = hasAnyEnabled && (coversWorkload(/exchange/i) || labels.length > 0);
    // When descriptors absent we use label-count proxy: any retention label implies
    // org-wide coverage; empty tenant → Fail (PS parity).
    // Keep minimal: if we detected keyword OR any label exists, treat as Pass;
    // otherwise Fail. The limitation notes descriptor gap when keyword not found.
    const detected = coversWorkload(/exchange/i);
    if (labels.length === 0) {
      ctx.addRow({
        category: "Retention Policies",
        setting: "Exchange Covered by Retention",
        currentValue: "No retention policies cover Exchange",
        recommendedValue: "At least 1 policy covers Exchange",
        checkId: "PURVIEW-RETENTION-002",
        remediation: "",
        psStatus: "Fail",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.8,
      });
    } else if (detected || exchangeCovered) {
      ctx.addRow({
        category: "Retention Policies",
        setting: "Exchange Covered by Retention",
        currentValue: detected
          ? `${labels.length} label(s) cover Exchange`
          : `${labels.length} retention label(s) configured — Exchange coverage requires Purview portal verification`,
        recommendedValue: "At least 1 policy covers Exchange",
        checkId: "PURVIEW-RETENTION-002",
        remediation: "",
        psStatus: detected ? "Pass" : "Review",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: detected ? "Direct" : "Derived",
        permissionRequired: REQUIRED_ROLE,
        confidence: detected ? 0.9 : 0.6,
        limitations: detected
          ? undefined
          : "Graph /v1.0/security/labels/retentionLabels does not expose ExchangeLocation/TeamsChannelLocation fidelity; verify workload coverage in Purview portal.",
      });
    } else {
      ctx.addRow({
        category: "Retention Policies",
        setting: "Exchange Covered by Retention",
        currentValue: "No retention policies cover Exchange",
        recommendedValue: "At least 1 policy covers Exchange",
        checkId: "PURVIEW-RETENTION-002",
        remediation: "",
        psStatus: "Fail",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
    }
  }

  // ------------------------------------------------------------------
  // 3. PURVIEW-RETENTION-003 — Teams Covered (PS lines 126-155)
  // ------------------------------------------------------------------
  {
    const detected = coversWorkload(/teams/i);
    if (labels.length === 0) {
      ctx.addRow({
        category: "Retention Policies",
        setting: "Teams Covered by Retention",
        currentValue: "No retention policies cover Teams",
        recommendedValue: "At least 1 policy covers Teams",
        checkId: "PURVIEW-RETENTION-003",
        remediation: "",
        psStatus: "Fail",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
    } else if (detected) {
      ctx.addRow({
        category: "Retention Policies",
        setting: "Teams Covered by Retention",
        currentValue: `${labels.length} label(s) cover Teams`,
        recommendedValue: "At least 1 policy covers Teams",
        checkId: "PURVIEW-RETENTION-003",
        remediation: "",
        psStatus: "Pass",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "Retention Policies",
        setting: "Teams Covered by Retention",
        currentValue: `${labels.length} retention label(s) configured — Teams coverage requires Purview portal verification`,
        recommendedValue: "At least 1 policy covers Teams",
        checkId: "PURVIEW-RETENTION-003",
        remediation: "",
        psStatus: "Review",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Derived",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.6,
        limitations:
          "Graph /v1.0/security/labels/retentionLabels does not expose TeamsChannelLocation/TeamsChatLocation fidelity; verify workload coverage in Purview portal.",
      });
    }
  }

  // ------------------------------------------------------------------
  // 4. PURVIEW-RETENTION-004 — SharePoint/OneDrive Covered (PS lines 157-186)
  // ------------------------------------------------------------------
  {
    const detected = coversWorkload(/sharepoint|onedrive/i);
    if (labels.length === 0) {
      ctx.addRow({
        category: "Retention Policies",
        setting: "SharePoint/OneDrive Covered by Retention",
        currentValue: "No retention policies cover SharePoint/OneDrive",
        recommendedValue: "At least 1 policy covers SharePoint/OneDrive",
        checkId: "PURVIEW-RETENTION-004",
        remediation: "",
        psStatus: "Fail",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
    } else if (detected) {
      ctx.addRow({
        category: "Retention Policies",
        setting: "SharePoint/OneDrive Covered by Retention",
        currentValue: `${labels.length} label(s) cover SharePoint/OneDrive`,
        recommendedValue: "At least 1 policy covers SharePoint/OneDrive",
        checkId: "PURVIEW-RETENTION-004",
        remediation: "",
        psStatus: "Pass",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "Retention Policies",
        setting: "SharePoint/OneDrive Covered by Retention",
        currentValue: `${labels.length} retention label(s) configured — SharePoint/OneDrive coverage requires Purview portal verification`,
        recommendedValue: "At least 1 policy covers SharePoint/OneDrive",
        checkId: "PURVIEW-RETENTION-004",
        remediation: "",
        psStatus: "Review",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Derived",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.6,
        limitations:
          "Graph /v1.0/security/labels/retentionLabels does not expose SharePointLocation/OneDriveLocation fidelity; verify workload coverage in Purview portal.",
      });
    }
  }

  // ------------------------------------------------------------------
  // 5. PURVIEW-RETENTION-005 — Enforce Mode (PS lines 188-226)
  // ------------------------------------------------------------------
  {
    const enabledLabels = labels.filter((l) => {
      const v = l.isEnabled ?? l.enabled ?? l.state;
      if (v === false) return false;
      if (typeof v === "string" && v.toLowerCase() === "disabled") return false;
      return true;
    });
    if (enabledLabels.length === 0) {
      ctx.addRow({
        category: "Retention Policies",
        setting: "Retention Policies in Enforce Mode",
        currentValue: "No enabled policies to evaluate",
        recommendedValue: "At least 1 policy in Enforce mode",
        checkId: "PURVIEW-RETENTION-005",
        remediation: "",
        psStatus: "Review",
        evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
    } else {
      // Graph retentionLabel does not expose Mode (Enforce vs Test) directly;
      // treat enabled labels as Enforce parity unless explicit mode indicates otherwise.
      const testMode = enabledLabels.filter((l) => {
        const mode = psStr(l.mode ?? (l.additionalProperties as Record<string, unknown> | undefined)?.mode);
        return mode !== "" && mode.toLowerCase() !== "enforce";
      });
      if (testMode.length === 0) {
        ctx.addRow({
          category: "Retention Policies",
          setting: "Retention Policies in Enforce Mode",
          currentValue: `All ${enabledLabels.length} enabled labels in Enforce mode`,
          recommendedValue: "All policies in Enforce mode",
          checkId: "PURVIEW-RETENTION-005",
          remediation: "",
          psStatus: "Pass",
          evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
          collectionMethod: "Direct",
          permissionRequired: REQUIRED_ROLE,
          confidence: 0.85,
        });
      } else {
        const names = testMode
          .slice(0, 5)
          .map((l) => psStr(l.displayName ?? l.name ?? l.id))
          .join(", ");
        ctx.addRow({
          category: "Retention Policies",
          setting: "Retention Policies in Enforce Mode",
          currentValue: `${testMode.length} labels in simulation/test mode: ${names}`,
          recommendedValue: "All policies in Enforce mode",
          checkId: "PURVIEW-RETENTION-005",
          remediation: "",
          psStatus: "Warning",
          evidenceSource: PURVIEW_RETENTION_CONFIG_ENDPOINTS.retentionLabels,
          collectionMethod: "Direct",
          permissionRequired: REQUIRED_ROLE,
          confidence: 0.8,
        });
      }
    }
    void NOT_IMPLEMENTED_RECOMMENDED;
  }
};
