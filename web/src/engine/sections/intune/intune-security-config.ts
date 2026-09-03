/**
 * Port of `src/M365-Assess/Intune/Get-IntuneSecurityConfig.ps1` (183 lines)
 * — Intune/Endpoint Manager security settings (CIS 4.x).
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport are
 *   owned by the runner's addRow pipeline (mapStatus → sub-numbering → D-22
 *   registryRemediationText fallback).
 * - Invoke-MgGraphRequest 'beta/deviceManagement/settings' → getJson
 *   '/v1.0/deviceManagement/settings' (promoted per BETA-ENDPOINTS) with
 *   DeviceManagementConfiguration.Read.All. The PS reads the single settings
 *   object property deviceComplianceCheckinThresholdDays; empty/missing degrades
 *   to Review parity (PS lines 77-88). A numeric threshold <=30 → Pass else
 *   Warning (PS line 64).
 * - Invoke-MgGraphRequest 'beta/deviceManagement/deviceEnrollmentConfigurations'
 *   → getJson 'beta/deviceManagement/deviceEnrollmentConfigurations' with the
 *   same role — D-23: no v1.0 equivalent — keep beta, allowlist + BETA-ENDPOINTS row beta→keep.
 *   PS filters @odata.type == deviceEnrollmentPlatformRestrictionsConfiguration
 *   and checks personalDeviceEnrollmentBlocked on iosRestriction / androidRestriction /
 *   windowsRestriction. Blocked on all → Pass else Fail; no restriction
 *   policies → Fail (PS lines 149-160). Both 403 branches map to Skipped via
 *   errMatches (PS lines 91-106, 162-178) with D-24 explicit copy.
 * - Each check is isolated in its own try/catch (fail-soft): 403-family
 *   → Skipped(not_licensed) with explicit copy, generic → no row (PS Write-Warning parity),
 *   TransportFatalError rethrown so the runner can surface a section error without breaking other sections.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
// D-23: no v1.0 equivalent — keep beta, allowlist + BETA-ENDPOINTS row beta->keep
export const INTUNE_SECURITY_CONFIG_ENDPOINTS = {
  settings: "/v1.0/deviceManagement/settings",
  enrollmentConfigurations:
    "/beta/deviceManagement/deviceEnrollmentConfigurations",
} as const;

const DEVICE_MGMT_CONFIG_READ_ALL = "DeviceManagementConfiguration.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

export const runIntuneSecurityConfig: SectionImplementation = async (ctx) => {
  // ------------------------------------------------------------------
  // 1. Device Compliance - Non-compliant default (CIS 4.1) — PS lines 44-106
  //    GET /v1.0/deviceManagement/settings → deviceComplianceCheckinThresholdDays
  // ------------------------------------------------------------------
  try {
    const settingsResp = (await ctx.transport.getJson(
      INTUNE_SECURITY_CONFIG_ENDPOINTS.settings,
      { requiredRole: DEVICE_MGMT_CONFIG_READ_ALL },
    )) as Record<string, unknown>;

    // The settings endpoint returns a singleton object (non-collection) — getJson
    // rebuilds it as firstPage metadata, so the property lives at top level.
    // Fall back to value[0] if the tenant returns it as a collection edge case.
    let markNonCompliant: unknown = settingsResp.deviceComplianceCheckinThresholdDays;
    if (markNonCompliant === undefined && Array.isArray(settingsResp.value)) {
      const first = (settingsResp.value[0] ?? {}) as Record<string, unknown>;
      markNonCompliant = first.deviceComplianceCheckinThresholdDays ?? first["deviceComplianceCheckinThresholdDays"];
    }
    // Also check AdditionalProperties bag parity (some SDK shapes nest there).
    if (markNonCompliant === undefined) {
      const ap = settingsResp.additionalProperties as Record<string, unknown> | undefined;
      if (ap) markNonCompliant = ap.deviceComplianceCheckinThresholdDays;
    }

    if (markNonCompliant !== null && markNonCompliant !== undefined && psStr(markNonCompliant) !== "") {
      const threshold = Number(markNonCompliant);
      const isPass = Number.isFinite(threshold) ? threshold <= 30 : false;
      ctx.addRow({
        category: "Device Compliance",
        setting: "Non-Compliant Default Threshold",
        currentValue: `${psStr(markNonCompliant)} days`,
        recommendedValue: "Devices without policy marked non-compliant",
        checkId: "INTUNE-COMPLIANCE-001",
        remediation: "",
        psStatus: isPass ? "Pass" : "Warning",
        observedValue: String(Number.isFinite(threshold) ? Math.trunc(threshold) : psStr(markNonCompliant)),
        expectedValue: "<=30",
        evidenceSource: INTUNE_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: DEVICE_MGMT_CONFIG_READ_ALL,
        confidence: 1.0,
      });
    } else {
      ctx.addRow({
        category: "Device Compliance",
        setting: "Non-Compliant Default Threshold",
        currentValue: "Setting not available",
        recommendedValue: "Devices without policy marked non-compliant",
        checkId: "INTUNE-COMPLIANCE-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: INTUNE_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: DEVICE_MGMT_CONFIG_READ_ALL,
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Device Compliance",
        setting: "Non-Compliant Default Threshold",
        currentValue: "Missing permissions — DeviceManagementConfiguration.Read.All not granted; re-consent to grant",
        recommendedValue: "Devices without policy marked non-compliant",
        checkId: "INTUNE-COMPLIANCE-001",
        remediation: "Grant DeviceManagementConfiguration.Read.All via admin consent and re-run",
        psStatus: "Skipped",
        evidenceSource: INTUNE_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: DEVICE_MGMT_CONFIG_READ_ALL,
      });
    }
    // else PS Write-Warning + continue parity — zero rows, continue.
  }

  // ------------------------------------------------------------------
  // 2. Device Enrollment Restrictions (CIS 4.2) — PS lines 108-178
  //    GET beta/deviceManagement/deviceEnrollmentConfigurations — D-23 keep
  // ------------------------------------------------------------------
  try {
    const enrollResp = await ctx.transport.getJson(
      INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations,
      { requiredRole: DEVICE_MGMT_CONFIG_READ_ALL },
    );
    const enrollList = asArray(enrollResp.value);

    const platformRestrictions = enrollList.filter(
      (c) => psStr(c["@odata.type"]) === "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
    );

    if (platformRestrictions.length > 0) {
      let personalBlocked = true;
      for (const restriction of platformRestrictions) {
        for (const platform of ["iosRestriction", "androidRestriction", "windowsRestriction"] as const) {
          const config = restriction[platform] as Record<string, unknown> | undefined;
          if (config && config.personalDeviceEnrollmentBlocked !== true) {
            personalBlocked = false;
          }
        }
      }

      ctx.addRow({
        category: "Device Enrollment",
        setting: "Personal Device Enrollment Blocked",
        currentValue: personalBlocked ? "Blocked on all platforms" : "Allowed on some platforms",
        recommendedValue: "Block personal device enrollment",
        checkId: "INTUNE-ENROLL-001",
        remediation: "",
        psStatus: personalBlocked ? "Pass" : "Fail",
        evidenceSource: INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations,
        collectionMethod: "Direct",
        permissionRequired: DEVICE_MGMT_CONFIG_READ_ALL,
      });
    } else {
      ctx.addRow({
        category: "Device Enrollment",
        setting: "Personal Device Enrollment Blocked",
        currentValue: "No platform restriction policies found",
        recommendedValue: "Block personal device enrollment",
        checkId: "INTUNE-ENROLL-001",
        remediation: "",
        psStatus: "Fail",
        evidenceSource: INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations,
        collectionMethod: "Direct",
        permissionRequired: DEVICE_MGMT_CONFIG_READ_ALL,
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Device Enrollment",
        setting: "Personal Device Enrollment Blocked",
        currentValue: "Missing permissions — DeviceManagementConfiguration.Read.All not granted; re-consent to grant",
        recommendedValue: "Block personal device enrollment",
        checkId: "INTUNE-ENROLL-001",
        remediation: "Grant DeviceManagementConfiguration.Read.All via admin consent and re-run",
        psStatus: "Skipped",
        evidenceSource: INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations,
        collectionMethod: "Direct",
        permissionRequired: DEVICE_MGMT_CONFIG_READ_ALL,
      });
    }
    // else PS Write-Warning + continue parity — zero rows, continue.
  }
};
