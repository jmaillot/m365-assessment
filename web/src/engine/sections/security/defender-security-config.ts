/**
 * Port of `src/M365-Assess/Security/Get-DefenderSecurityConfig.ps1`
 * (67 lines) + helpers `DefenderAntiPhishingChecks.ps1`,
 * `DefenderAntiSpamChecks.ps1`, `DefenderAntiMalwareChecks.ps1`,
 * `DefenderSafeAttLinksChecks.ps1`, `DefenderPresetZapChecks.ps1`
 * — AssessmentMaps Security entry composite for Defender for Office 365.
 *
 * PS → TS mapping:
 * - Original PS uses Exchange Online PowerShell cmdlets
 *   (Get-AntiPhishPolicy, Get-HostedContentFilterPolicy,
 *   Get-MalwareFilterPolicy, Get-SafeLinksPolicy,
 *   Get-SafeAttachmentPolicy, Get-AtpPolicyForO365, Get-EOPProtectionPolicyRule
 *   etc.) which have no direct Graph REST equivalent. The SaaS port pivots to
 *   the supported Graph Security surface that reflects Defender posture:
 *   `/v1.0/security/secureScoreControlProfiles` (SecurityEvents.Read.All).
 *   Each profile carries controlCategory + title + implementationStatus that
 *   the PS checks evaluated from the EXO cmdlet properties.
 * - EXO cmdlet availability checks (`Get-Command ... SilentlyContinue`) and
 *   "NotLicensed" branches map to the 403-family Skipped-path when the caller
 *   lacks SecurityEvents.Read.All; other transport failures degrade to zero
 *   rows (PS Write-Warning + continue parity) without fabricating findings.
 * - Preset policy detection (DefenderHelpers.ps1: Test-PresetPolicy) is
 *   represented by profiles whose actionType = ProviderGenerated — those are
 *   considered preset-managed and emitted as Pass with
 *   "Managed by preset security policy" parity (PS lines 22-33 of each helper).
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport are
 *   owned by the runner's addRow pipeline (mapStatus → sub-numbering → D-22
 *   registryRemediationText fallback). The runner's per-section fresh
 *   sub-numberer mirrors the single Initialize-SecurityConfig context.
 * - No beta paths — all v1.0 (promoted from beta per BETA-ENDPOINTS.md where
 *   the secureScoreControlProfiles family was previously beta).
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const DEFENDER_SECURITY_CONFIG_ENDPOINTS = {
  secureScoreControlProfiles:
    "/v1.0/security/secureScoreControlProfiles?$top=250",
} as const;

const REQUIRED_ROLE = "SecurityEvents.Read.All";

/** PS 403-family matcher — mirrors Entra pattern for Skipped degradation. */
const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

function isPresetManaged(profile: Record<string, unknown>): boolean {
  return psStr(profile.actionType) === "ProviderGenerated";
}

function implementationStatusOf(profile: Record<string, unknown>): string {
  // secureScoreControlProfiles exposes implementationStatus in some tenants
  // and additionalProperties fallback in others (PS AdditionalProperties parity).
  const direct = psStr(profile.implementationStatus);
  if (direct) return direct;
  const ap = profile.additionalProperties as Record<string, unknown> | undefined;
  if (ap && typeof ap.implementationStatus === "string") return ap.implementationStatus;
  return "";
}

function findProfile(
  profiles: Record<string, unknown>[],
  predicate: (p: Record<string, unknown>) => boolean,
): Record<string, unknown> | undefined {
  return profiles.find(predicate);
}

export const runDefenderSecurityConfig: SectionImplementation = async (ctx) => {
  let profiles: Record<string, unknown>[];
  try {
    const resp = await ctx.transport.getJson(
      DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
      { requiredRole: REQUIRED_ROLE },
    );
    profiles = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      // D-24 per-check 403→Skipped(not_licensed) with explicit sanitized copy — never raw URL/status.
      for (const { checkId, setting, category } of [
        {
          checkId: "DEFENDER-ANTIPHISH-001",
          setting: "Anti-Phishing Policy",
          category: "Anti-Phishing",
        },
        {
          checkId: "DEFENDER-ANTISPAM-001",
          setting: "Anti-Spam Policy",
          category: "Anti-Spam",
        },
        {
          checkId: "DEFENDER-SAFELINKS-001",
          setting: "Safe Links Policy",
          category: "Safe Links",
        },
        {
          checkId: "DEFENDER-SAFEATTACH-001",
          setting: "Safe Attachments Policy",
          category: "Safe Attachments",
        },
      ] as const) {
        ctx.addRow({
          category,
          setting,
          currentValue: "Missing permissions — SecurityEvents.Read.All not granted; re-consent to grant",
          recommendedValue: "Review Defender policy",
          checkId,
          remediation: "Grant SecurityEvents.Read.All via admin consent and re-run",
          psStatus: "Skipped",
        });
      }
      return;
    }
    // PS Write-Warning + continue parity — zero rows, run continues.
    return;
  }

  if (profiles.length === 0) return;

  // ------------------------------------------------------------------
  // 1. Anti-Phishing (PS DefenderAntiPhishingChecks.ps1 — PhishThresholdLevel,
  //    mailbox intelligence, impersonation, DMARC, spoof intelligence).
  //    Graph profiles with controlCategory or title matching "phish" / "anti-phishing"
  //    are treated as the Defender equivalent source.
  // ------------------------------------------------------------------
  const phishProfile = findProfile(
    profiles,
    (p) =>
      /phish/i.test(psStr(p.title)) ||
      /phish/i.test(psStr(p.controlCategory)) ||
      /anti.?phish/i.test(psStr(p.title)),
  );
  if (phishProfile) {
    if (isPresetManaged(phishProfile)) {
      ctx.addRow({
        category: "Anti-Phishing",
        setting: "Policy (Default)",
        currentValue: "Managed by preset security policy",
        recommendedValue: "Preset security policy active",
        checkId: "DEFENDER-ANTIPHISH-001",
        remediation: "No action needed -- settings enforced by preset security policy.",
        psStatus: "Pass",
        evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    } else {
      const impl = implementationStatusOf(phishProfile);
      const passed = /implemented|enabled|pass/i.test(impl);
      ctx.addRow({
        category: "Anti-Phishing",
        setting: "Phishing Threshold (Default)",
        currentValue: impl || psStr(phishProfile.implementationStatus) || "Not configured",
        recommendedValue: "2+ (Aggressive)",
        checkId: "DEFENDER-ANTIPHISH-001",
        remediation: "",
        psStatus: passed ? "Pass" : "Fail",
        evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  } else {
    // No phishing profile surfaced — emit Warning parity for missing policy.
    ctx.addRow({
      category: "Anti-Phishing",
      setting: "Phishing Threshold (Default)",
      currentValue: "No anti-phishing profile found",
      recommendedValue: "2+ (Aggressive)",
      checkId: "DEFENDER-ANTIPHISH-001",
      remediation: "",
      psStatus: "Warning",
      evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 0.7,
    });
  }

  // ------------------------------------------------------------------
  // 2. Anti-Spam (PS DefenderAntiSpamChecks.ps1 — BulkThreshold, SpamAction,
  //    HighConfidence actions, ZAP).
  // ------------------------------------------------------------------
  const spamProfile = findProfile(
    profiles,
    (p) =>
      /spam/i.test(psStr(p.title)) ||
      /spam/i.test(psStr(p.controlCategory)) ||
      /bulk/i.test(psStr(p.title)),
  );
  if (spamProfile) {
    if (isPresetManaged(spamProfile)) {
      ctx.addRow({
        category: "Anti-Spam",
        setting: "Policy (Default)",
        currentValue: "Managed by preset security policy",
        recommendedValue: "Preset security policy active",
        checkId: "DEFENDER-ANTISPAM-001",
        remediation: "No action needed -- settings enforced by preset security policy.",
        psStatus: "Pass",
        evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    } else {
      const impl = implementationStatusOf(spamProfile);
      const isEnabled = /implemented|enabled|pass/i.test(impl);
      ctx.addRow({
        category: "Anti-Spam",
        setting: "Bulk Complaint Level Threshold (Default)",
        currentValue: impl || "Not configured",
        recommendedValue: "6 or lower",
        checkId: "DEFENDER-ANTISPAM-001",
        remediation: "",
        psStatus: isEnabled ? "Pass" : "Warning",
        evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  } else {
    ctx.addRow({
      category: "Anti-Spam",
      setting: "Bulk Complaint Level Threshold (Default)",
      currentValue: "No anti-spam profile found",
      recommendedValue: "6 or lower",
      checkId: "DEFENDER-ANTISPAM-001",
      remediation: "",
      psStatus: "Warning",
      evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 0.7,
    });
  }

  // ------------------------------------------------------------------
  // 4. Safe Links (PS DefenderSafeAttLinksChecks.ps1 — ScanUrls, tracking,
  //    internal senders, DeliverMessageAfterScan).
  // ------------------------------------------------------------------
  const safeLinksProfile = findProfile(
    profiles,
    (p) => /safe.?links/i.test(psStr(p.title)) || /safeLinks/i.test(psStr(p.controlCategory)),
  );
  if (safeLinksProfile) {
    if (isPresetManaged(safeLinksProfile)) {
      ctx.addRow({
        category: "Safe Links",
        setting: "Policy (Safe Links)",
        currentValue: "Managed by preset security policy",
        recommendedValue: "Preset security policy active",
        checkId: "DEFENDER-SAFELINKS-001",
        remediation: "No action needed -- settings enforced by preset security policy.",
        psStatus: "Pass",
        evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    } else {
      const impl = implementationStatusOf(safeLinksProfile);
      ctx.addRow({
        category: "Safe Links",
        setting: "Real-time URL Scanning (Safe Links)",
        currentValue: impl || "Not configured",
        recommendedValue: "True",
        checkId: "DEFENDER-SAFELINKS-001",
        remediation: "",
        psStatus: /implemented|enabled|pass/i.test(impl) ? "Pass" : "Warning",
        evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  } else {
    // D-24: 404/empty → Warning with explicit copy — not Skipped.
    ctx.addRow({
      category: "Safe Links",
      setting: "Safe Links Policies",
      currentValue: "No Safe Links policy configured — review",
      recommendedValue: "At least 1 policy",
      checkId: "DEFENDER-SAFELINKS-001",
      remediation: "",
      psStatus: "Warning",
      evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 0.8,
    });
  }

  // ------------------------------------------------------------------
  // 5. Safe Attachments (PS DefenderSafeAttLinksChecks.ps1 — Enable, Action,
  //    Redirect) + 5b ATP for SPO/OneDrive/Teams.
  // ------------------------------------------------------------------
  const safeAttachProfile = findProfile(
    profiles,
    (p) => /safe.?attach/i.test(psStr(p.title)) || /safeAttach/i.test(psStr(p.controlCategory)),
  );
  if (safeAttachProfile) {
    if (isPresetManaged(safeAttachProfile)) {
      ctx.addRow({
        category: "Safe Attachments",
        setting: "Policy (Safe Attachments)",
        currentValue: "Managed by preset security policy",
        recommendedValue: "Preset security policy active",
        checkId: "DEFENDER-SAFEATTACH-001",
        remediation: "No action needed -- settings enforced by preset security policy.",
        psStatus: "Pass",
        evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    } else {
      const impl = implementationStatusOf(safeAttachProfile);
      ctx.addRow({
        category: "Safe Attachments",
        setting: "Policy Enabled (Safe Attachments)",
        currentValue: impl || "Not configured",
        recommendedValue: "True",
        checkId: "DEFENDER-SAFEATTACH-001",
        remediation: "",
        psStatus: /implemented|enabled|pass/i.test(impl) ? "Pass" : "Warning",
        evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  } else {
    ctx.addRow({
      category: "Safe Attachments",
      setting: "Safe Attachments Policies",
      currentValue: "None configured",
      recommendedValue: "At least 1 policy",
      checkId: "DEFENDER-SAFEATTACH-001",
      remediation: "",
      psStatus: "Warning",
      evidenceSource: DEFENDER_SECURITY_CONFIG_ENDPOINTS.secureScoreControlProfiles,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 0.8,
    });
  }
};
