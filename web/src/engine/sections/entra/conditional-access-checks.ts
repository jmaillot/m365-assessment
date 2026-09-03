/**
 * Port of `src/M365-Assess/Entra/EntraConditionalAccessChecks.ps1` (179
 * lines) — check-helper half of Get-EntraSecurityConfig.ps1 (plan 02-08
 * task 1).
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting: owned by the runner's addRow
 *   pipeline (mapStatus → sub-numbering → D-22 registry fallback).
 * - Invoke-SafeGraphRequest / Invoke-MgGraphRequest GET → ctx.transport.getJson
 *   with requiredRole (the transport provides retry/backoff natively, #952).
 * - /beta/policies/deviceRegistrationPolicy (PS section 19) promoted to v1.0
 *   per BETA-ENDPOINTS.md — the second fetch is PRESERVED so Graph-call counts
 *   stay identical to PS (v1.0 read + extended read were separate requests).
 * - Soft-fail semantics preserved per section: catch blocks degrade to zero
 *   rows (PS Write-Warning parity); TransportFatalError still propagates.
 * - PS $null-comparison quirks reproduced: `$maxDevices -le 15` treats a null
 *   quota as 0 (Pass), and a non-numeric quota aborts the section mid-try so
 *   already-emitted rows stay while remaining rows are dropped.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const CA_CHECKS_ENDPOINTS = {
  caPolicies: "/v1.0/identity/conditionalAccess/policies",
  deviceRegistrationPolicy: "/v1.0/policies/deviceRegistrationPolicy",
} as const;

type GraphObj = Record<string, unknown>;

const POLICY_READ_ALL = "Policy.Read.All";

export const runConditionalAccessChecks: SectionImplementation = async (ctx) => {
  // ------------------------------------------------------------------
  // 11. Conditional Access Policy Count — PS lines 14-55
  // ------------------------------------------------------------------
  try {
    const caPolicies = await ctx.transport.getJson(CA_CHECKS_ENDPOINTS.caPolicies, {
      requiredRole: POLICY_READ_ALL,
    });
    const policyList = asArray((caPolicies as GraphObj).value);
    const caCount = policyList.length;
    const enabledCount = policyList.filter((p) => p["state"] === "enabled").length;

    ctx.addRow({
      category: "Conditional Access",
      setting: "Total CA Policies",
      currentValue: `${caCount}`,
      recommendedValue: "1+",
      psStatus: "Info",
      checkId: "ENTRA-CA-002",
      remediation:
        "Informational — review Conditional Access policy coverage for your organization.",
    });

    ctx.addRow({
      category: "Conditional Access",
      setting: "Enabled CA Policies",
      currentValue: `${enabledCount}`,
      recommendedValue: "1+",
      psStatus: enabledCount > 0 ? "Pass" : "Warning",
      checkId: "ENTRA-CA-003",
      remediation:
        "Run: Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.State -eq 'enabled'}. Ensure policies are set to On, not Report-only.",
      // D1 #785 — structured evidence.
      observedValue: `${enabledCount}`,
      expectedValue: ">=1",
      evidenceSource: "/identity/conditionalAccess/policies",
      collectionMethod: "Direct",
      permissionRequired: "Policy.Read.All",
      confidence: 1.0,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }

  // ------------------------------------------------------------------
  // 13. Device Registration Policy (CIS 5.1.4.1-5.1.4.3) — PS 57-116
  // ------------------------------------------------------------------
  try {
    const devicePolicy = (await ctx.transport.getJson(
      CA_CHECKS_ENDPOINTS.deviceRegistrationPolicy,
      { requiredRole: POLICY_READ_ALL },
    )) as GraphObj;

    if (devicePolicy) {
      // CIS 5.1.4.1 -- Device join restricted
      const azureADJoin = devicePolicy.azureADJoin as GraphObj | undefined;
      const allowedToJoin = azureADJoin?.allowedToJoin as GraphObj | undefined;
      const joinType = allowedToJoin ? allowedToJoin["@odata.type"] : undefined;
      const joinRestricted = joinType !== "#microsoft.graph.allDeviceRegistrationMembership";
      ctx.addRow({
        category: "Device Management",
        setting: "Microsoft Entra Join Restriction",
        currentValue: joinRestricted ? "Restricted" : "All users allowed",
        recommendedValue: "Restricted to specific users/groups",
        psStatus: joinRestricted ? "Pass" : "Fail",
        checkId: "ENTRA-DEVICE-001",
        remediation:
          "Entra admin center > Devices > Device settings > Users may join devices to Microsoft Entra > Selected. Restrict to a specific group of authorized users.",
      });

      // CIS 5.1.4.2 -- Max devices per user. PS `$maxDevices -le 15` coerces
      // $null to 0 (Pass); a non-numeric value throws mid-try so DEVICE-001's
      // row stays and 002/003 are dropped.
      const maxDevicesRaw = devicePolicy.userDeviceQuota;
      const maxDevicesNum =
        maxDevicesRaw === null || maxDevicesRaw === undefined ? 0 : Number(maxDevicesRaw);
      if (!Number.isFinite(maxDevicesNum)) {
        throw new Error(`Cannot convert value "${psStr(maxDevicesRaw)}" to number`);
      }
      ctx.addRow({
        category: "Device Management",
        setting: "Maximum Devices Per User",
        currentValue: psStr(maxDevicesRaw),
        recommendedValue: "15 or fewer",
        psStatus: maxDevicesNum <= 15 ? "Pass" : "Fail",
        checkId: "ENTRA-DEVICE-002",
        remediation:
          "Entra admin center > Devices > Device settings > Maximum number of devices per user. Set to 15 or lower.",
      });

      // CIS 5.1.4.3 -- Global admins not added as local admin on join
      const localAdmins = azureADJoin?.localAdmins as GraphObj | undefined;
      let gaLocalAdmin: unknown = true; // Default assumption
      if (localAdmins) {
        gaLocalAdmin = localAdmins.enableGlobalAdmins;
      }
      ctx.addRow({
        category: "Device Management",
        setting: "Global Admins as Local Admin on Join",
        currentValue: gaLocalAdmin ? "Enabled" : "Disabled",
        recommendedValue: "Disabled",
        psStatus: !gaLocalAdmin ? "Pass" : "Fail",
        checkId: "ENTRA-DEVICE-003",
        remediation:
          "Entra admin center > Devices > Device settings > Global administrator is added as local administrator on the device during Microsoft Entra join > No.",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }

  // ------------------------------------------------------------------
  // 19. Device Registration Extensions (CIS 5.1.4.4-5.1.4.6) — PS 118-179.
  // PS queried the beta surface for the extended reads; promoted to v1.0 per
  // BETA-ENDPOINTS.md. The SECOND fetch is kept for call-count parity with PS
  // (which issued one v1.0 and one beta request).
  // ------------------------------------------------------------------
  try {
    const devicePolicyExtended = (await ctx.transport.getJson(
      CA_CHECKS_ENDPOINTS.deviceRegistrationPolicy,
      { requiredRole: POLICY_READ_ALL },
    )) as GraphObj;

    if (devicePolicyExtended) {
      const azureADJoin = devicePolicyExtended.azureADJoin as GraphObj | undefined;
      const localAdminSettings = azureADJoin?.localAdmins as GraphObj | undefined;

      // CIS 5.1.4.4 -- Local admin assignment limited during Entra join
      const registeredUsers = localAdminSettings?.registeredUsers as
        | GraphObj
        | undefined;
      let additionalAdminsRaw: unknown = 0;
      if (localAdminSettings && registeredUsers) {
        additionalAdminsRaw = registeredUsers.additionalLocalAdminsCount;
      }
      const additionalAdminsNum =
        additionalAdminsRaw === null || additionalAdminsRaw === undefined
          ? 0
          : Number(additionalAdminsRaw);
      ctx.addRow({
        category: "Device Management",
        setting: "Local Admin Assignment on Entra Join",
        currentValue: `Additional local admins configured: ${psStr(additionalAdminsRaw)}`,
        recommendedValue: "Minimal local admin assignment",
        psStatus: !(additionalAdminsNum > 0) ? "Pass" : "Review",
        checkId: "ENTRA-DEVICE-004",
        remediation:
          "Entra admin center > Devices > Device settings > Manage Additional local administrators on all Microsoft Entra joined devices. Minimize additional local admins.",
      });

      // CIS 5.1.4.5 -- LAPS enabled
      const localAdminPassword = devicePolicyExtended.localAdminPassword as
        | GraphObj
        | undefined;
      let lapsEnabled = false;
      if (localAdminPassword) {
        lapsEnabled = Boolean(localAdminPassword.isEnabled);
      }
      ctx.addRow({
        category: "Device Management",
        setting: "Local Administrator Password Solution (LAPS)",
        currentValue: lapsEnabled ? "Enabled" : "Disabled",
        recommendedValue: "Enabled",
        psStatus: lapsEnabled ? "Pass" : "Fail",
        checkId: "ENTRA-DEVICE-005",
        remediation:
          "Entra admin center > Devices > Device settings > Enable Microsoft Entra Local Administrator Password Solution (LAPS) > Yes.",
      });

      // CIS 5.1.4.6 -- BitLocker recovery key restricted (manual-review item)
      ctx.addRow({
        category: "Device Management",
        setting: "BitLocker Recovery Key Restriction",
        currentValue: "Review -- verify users cannot read own BitLocker keys",
        recommendedValue: "Users restricted from recovering BitLocker keys",
        psStatus: "Review",
        checkId: "ENTRA-DEVICE-006",
        remediation:
          "Entra admin center > Devices > Device settings > Restrict users from recovering the BitLocker key(s) for their owned devices > Yes.",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }
};
