/**
 * Port of `src/M365-Assess/Intune/Get-DeviceComplianceReport.ps1` (122 lines)
 * — Intune managed device compliance status report.
 *
 * PS → TS mapping:
 * - Get-MgDeviceManagementManagedDevice -All (PS line 65) → getJson
 *   /v1.0/deviceManagement/managedDevices; failure = PS Write-Error + return
 *   (lines 67-70) → fail-soft with 403-family Skipped row, other errors → zero
 *   rows (no fabricated findings). The transport's automatic nextLink following
 *   is the -All pagination (D-27).
 * - Platform filter (PS lines 72-77) and ComplianceState filter (PS lines 79-88)
 *   are CLI-only (-Platform / -ComplianceState params) and not replicated in the
 *   SaaS scheduled run — the SaaS always reports All × All.
 * - Report sorted by ComplianceState, DeviceName (PS line 108).
 * - Each device carries: DeviceName, UserDisplayName, UPN, OperatingSystem,
 *   OSVersion, ComplianceState, IsEncrypted, LastSyncDateTime, EnrolledDateTime,
 *   Model, Manufacturer, SerialNumber, ManagementAgent. The SaaS renders them
 *   as a kv Field=Value CurrentValue in PS property order (PS lines 90-105).
 * - Row mapping (report collector): one Info row per managed device;
 *   Setting = DeviceName (fallback to id when DeviceName is empty); no CheckId
 *   (report collectors never fabricate one). Promoted from beta to v1.0 (none in
 *   this collector — endpoint was already v1.0 via SDK).
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, kv, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const DEVICE_COMPLIANCE_REPORT_ENDPOINTS = {
  managedDevices: "/v1.0/deviceManagement/managedDevices",
} as const;

const DEVICE_MGMT_MANAGED_DEVICES_READ_ALL = "DeviceManagementManagedDevices.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const CATEGORY = "Device Compliance";

export const runDeviceComplianceReport: SectionImplementation = async (ctx) => {
  let devices: Record<string, unknown>[];
  try {
    const resp = await ctx.transport.getJson(
      DEVICE_COMPLIANCE_REPORT_ENDPOINTS.managedDevices,
      { requiredRole: DEVICE_MGMT_MANAGED_DEVICES_READ_ALL },
    );
    devices = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: CATEGORY,
        setting: "Managed Devices",
        currentValue: "Missing permissions — DeviceManagementManagedDevices.Read.All not granted; re-consent to grant",
        recommendedValue: "",
        psStatus: "Skipped",
        remediation: "Grant DeviceManagementManagedDevices.Read.All via admin consent and re-run",
        evidenceSource: DEVICE_COMPLIANCE_REPORT_ENDPOINTS.managedDevices,
        collectionMethod: "Direct",
        permissionRequired: DEVICE_MGMT_MANAGED_DEVICES_READ_ALL,
      });
      return;
    }
    // PS Write-Error + return parity — zero rows, run continues.
    return;
  }

  if (devices.length === 0) return;

  // Sort by ComplianceState, DeviceName (PS line 108).
  devices.sort((a, b) => {
    const ca = psStr(a.complianceState);
    const cb = psStr(b.complianceState);
    if (ca < cb) return -1;
    if (ca > cb) return 1;
    const da = psStr(a.deviceName);
    const db = psStr(b.deviceName);
    return da < db ? -1 : da > db ? 1 : 0;
  });

  for (const device of devices) {
    const deviceName = psStr(device.deviceName) || psStr(device.id) || "Unknown device";
    ctx.addRow({
      category: CATEGORY,
      setting: deviceName,
      currentValue: kv([
        ["DeviceName", device.deviceName],
        ["UserDisplayName", device.userDisplayName],
        ["UserPrincipalName", device.userPrincipalName],
        ["OperatingSystem", device.operatingSystem],
        ["OSVersion", device.osVersion],
        ["ComplianceState", device.complianceState],
        ["IsEncrypted", device.isEncrypted],
        ["LastSyncDateTime", device.lastSyncDateTime],
        ["EnrolledDateTime", device.enrolledDateTime],
        ["Model", device.model],
        ["Manufacturer", device.manufacturer],
        ["SerialNumber", device.serialNumber],
        ["ManagementAgent", device.managementAgent],
      ]),
      recommendedValue: "",
      psStatus: "Info",
      evidenceSource: DEVICE_COMPLIANCE_REPORT_ENDPOINTS.managedDevices,
      collectionMethod: "Direct",
      permissionRequired: DEVICE_MGMT_MANAGED_DEVICES_READ_ALL,
    });
  }
};
