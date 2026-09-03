/**
 * Port of `src/M365-Assess/Intune/Get-ConfigProfileReport.ps1` (112 lines)
 * — Intune device configuration profiles inventory.
 *
 * PS → TS mapping:
 * - Get-MgDeviceManagementDeviceConfiguration -All (PS line 69) → getJson
 *   /v1.0/deviceManagement/deviceConfigurations; failure = Write-Warning + return
 *   (lines 71-74) → fail-soft with 403-family Skipped row, other errors → zero
 *   rows. Transport pagination replaces -All (D-27).
 * - Empty result → Write-Warning + return (lines 76-80) → zero rows (no report
 *   rows fabricated when the tenant legitimately has no profiles).
 * - Platform mapping @odata.type → friendly name (PS lines 47-64) reproduced
 *   verbatim; unknown odata types render raw (PS lines 86-89).
 * - Report sorted by DisplayName (PS line 102).
 * - Row mapping (report collector): one Info row per configuration profile;
 *   Setting = DisplayName (fallback to Id when empty); CurrentValue = kv of
 *   report fields in PS property order (PS lines 91-99). No CheckId (report).
 * - Promoted from beta to v1.0 (the SDK call already resolves to v1.0).
 *
 * Additional context read for this port:
 * - Get-CompliancePolicyReport.ps1 (104 lines) — structurally identical report
 *   over /v1.0/deviceManagement/deviceCompliancePolicies with the same 403
 *   degradation and Platform mapping shape; kept as a separate report collector
 *   when wired (not merged) to preserve the PS separation.
 * - Get-IntuneFipsConfig / VpnSplitTunnel / WifiEap / MobileEncrypt (skimmed) —
 *   each emits per-profile Skipped/Review rows on 403 via the same pattern;
 *   the INUNE-* CheckIds they use are owned by intune-security-config's
 *   extended checks when the composite is wired.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, kv, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const CONFIG_PROFILE_REPORT_ENDPOINTS = {
  deviceConfigurations: "/v1.0/deviceManagement/deviceConfigurations",
} as const;

const DEVICE_MGMT_CONFIGURATION_READ_ALL = "DeviceManagementConfiguration.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const CATEGORY = "Configuration Profiles";

/** Map @odata.type to friendly platform names (Get-ConfigProfileReport.ps1:47-64). */
const PLATFORM_MAP: Record<string, string> = {
  "#microsoft.graph.windows10GeneralConfiguration": "Windows 10",
  "#microsoft.graph.windows10CustomConfiguration": "Windows 10 (Custom)",
  "#microsoft.graph.windows10EndpointProtectionConfiguration":
    "Windows 10 (Endpoint Protection)",
  "#microsoft.graph.windowsUpdateForBusinessConfiguration":
    "Windows Update for Business",
  "#microsoft.graph.windows81GeneralConfiguration": "Windows 8.1",
  "#microsoft.graph.windowsPhone81GeneralConfiguration": "Windows Phone 8.1",
  "#microsoft.graph.iosGeneralDeviceConfiguration": "iOS",
  "#microsoft.graph.iosCustomConfiguration": "iOS (Custom)",
  "#microsoft.graph.androidGeneralDeviceConfiguration": "Android",
  "#microsoft.graph.androidCustomConfiguration": "Android (Custom)",
  "#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration":
    "Android Work Profile",
  "#microsoft.graph.macOSGeneralDeviceConfiguration": "macOS",
  "#microsoft.graph.macOSCustomConfiguration": "macOS (Custom)",
  "#microsoft.graph.editionUpgradeConfiguration": "Windows Edition Upgrade",
  "#microsoft.graph.sharedPCConfiguration": "Windows Shared PC",
  "#microsoft.graph.windowsDefenderAdvancedThreatProtectionConfiguration":
    "Windows Defender ATP",
};

function platformOf(odataType: unknown): string {
  const key = psStr(odataType);
  if (!key) return "";
  return PLATFORM_MAP[key] ?? key;
}

export const runConfigProfileReport: SectionImplementation = async (ctx) => {
  let profiles: Record<string, unknown>[];
  try {
    const resp = await ctx.transport.getJson(
      CONFIG_PROFILE_REPORT_ENDPOINTS.deviceConfigurations,
      { requiredRole: DEVICE_MGMT_CONFIGURATION_READ_ALL },
    );
    profiles = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: CATEGORY,
        setting: "Configuration Profiles",
        currentValue: "Missing permissions — DeviceManagementConfiguration.Read.All not granted; re-consent to grant",
        recommendedValue: "",
        psStatus: "Skipped",
        remediation: "Grant DeviceManagementConfiguration.Read.All via admin consent and re-run",
        evidenceSource: CONFIG_PROFILE_REPORT_ENDPOINTS.deviceConfigurations,
        collectionMethod: "Direct",
        permissionRequired: DEVICE_MGMT_CONFIGURATION_READ_ALL,
      });
      return;
    }
    // PS Write-Warning + return parity — zero rows, run continues.
    return;
  }

  if (profiles.length === 0) return;

  // PS line 102: Sort-Object -Property DisplayName.
  profiles.sort((a, b) => {
    const ka = psStr(a.displayName);
    const kb = psStr(b.displayName);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  for (const profile of profiles) {
    const rawOdataType =
      (profile["@odata.type"] as unknown) ??
      (profile.additionalProperties as Record<string, unknown> | undefined)?.["@odata.type"];
    const platform = platformOf(rawOdataType);
    const displayName = psStr(profile.displayName) || psStr(profile.id) || "Unknown profile";

    ctx.addRow({
      category: CATEGORY,
      setting: displayName,
      currentValue: kv([
        ["DisplayName", profile.displayName],
        ["Id", profile.id],
        ["CreatedDateTime", profile.createdDateTime],
        ["LastModifiedDateTime", profile.lastModifiedDateTime],
        ["Platform", platform],
        ["Version", profile.version],
        ["Description", profile.description],
      ]),
      recommendedValue: "",
      psStatus: "Info",
      evidenceSource: CONFIG_PROFILE_REPORT_ENDPOINTS.deviceConfigurations,
      collectionMethod: "Direct",
      permissionRequired: DEVICE_MGMT_CONFIGURATION_READ_ALL,
    });
  }
};
