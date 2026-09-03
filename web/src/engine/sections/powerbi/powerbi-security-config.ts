/**
 * Port of `src/M365-Assess/PowerBI/Get-PowerBISecurityConfig.ps1` (253 lines)
 * — Power BI security and tenant configuration (CIS 9.x, 11 checks).
 *
 * PS → TS mapping:
 * - Original PS uses MicrosoftPowerBIMgmt + Invoke-PowerBIRestMethod against
 *   the Power BI admin API `https://api.powerbi.com/v1.0/myorg/admin/tenantSettings`
 *   (PS lines 57-59). The SaaS port issues the same tenant-settings probe via
 *   the Graph-channeled transport. In Graph v1.0 there is no promoted Power BI
 *   namespace, so the probe is represented as
 *   `GET /v1.0/myorg/admin/tenantSettings` with requiredRole `Tenant.Read.All`
 *   (task spec). The evidenceSource retains the canonical Power BI host URL for
 *   auditability (`https://api.powerbi.com/v1.0/myorg/admin/tenantSettings`).
 *   On tenants where the Power BI admin surface is not licensed or not enabled,
 *   the call 403/404 degrades to Skipped(not_licensed) parity (PS Web PowerBI
 *   branch: tenant not licensed → PS NotLicensed → SaaS Skipped/not_licensed).
 * - PS helper Get-TenantSetting(settingName → isEnabled) maps to local
 *   getTenantSetting() over the merged tenantSettings array; null/missing
 *   → Review per PS lines 100-105, 114-118, etc. Boolean isEnabled strings
 *   are compared exactly as PS does (Verbose False/True handling).
 * - PS $script:settingsError sentinel Warning row (PS lines 77-86) is mirrored
 *   as per-check Skipped/Review degradation rather than a single sentinel —
 *   the SaaS cannot emit an empty-CheckId row (runner expects base ids), so
 *   each CIS check carries its own Skipped row on fetch failure.
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport are
 *   owned by the runner's addRow pipeline (mapStatus → sub-numbering → D-22).
 * - No beta paths — all v1.0. TransportFatalError: the role-not-granted case
 *   (Tenant.Read.All typically absent from the app registration) degrades to
 *   NotLicensed rows so the section never silently vanishes; genuine transport
 *   bugs (SSRF guard, non-GET, bad path) still rethrow. 403-family → Skipped via
 *   errMatches with psStatus NotLicensed (→ not_licensed per D-16), generic
 *   404/5xx → Skipped(not_implemented) generic probe failure; fail-soft.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

/**
 * Declared GET path for the Power BI tenant-settings probe.
 * Absolute Power BI host — routed via PowerBiTransport (api.powerbi.com) with
 * resource https://analysis.windows.net/powerbi/api. EvidenceSource retains
 * the same canonical host for auditability.
 */
export const POWERBI_SECURITY_CONFIG_ENDPOINTS = {
  /** Absolute Power BI admin API path; PowerBiTransport host-pinned. */
  tenantSettings: "https://api.powerbi.com/v1.0/myorg/admin/tenantSettings",
  /** Canonical evidence source — same host. */
  tenantSettingsEvidence: "https://api.powerbi.com/v1.0/myorg/admin/tenantSettings",
} as const;

const REQUIRED_ROLE = "Tenant.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const NOT_LICENSED_CURRENT = "Power BI not licensed or tenant settings unavailable";
const NOT_IMPLEMENTED_EVIDENCE = POWERBI_SECURITY_CONFIG_ENDPOINTS.tenantSettingsEvidence;

function emitNotLicensed(ctx: Parameters<SectionImplementation>[0]): void {
  for (const { checkId, setting, category, recommendedValue } of [
    {
      checkId: "POWERBI-GUEST-001",
      setting: "Guest User Access Restricted",
      category: "Power BI - Guest Access",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-GUEST-002",
      setting: "External User Invitations Restricted",
      category: "Power BI - Guest Access",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-GUEST-003",
      setting: "Guest Access to Content Restricted",
      category: "Power BI - Guest Access",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-SHARING-001",
      setting: "Publish to Web Restricted",
      category: "Power BI - Sharing",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-SHARING-002",
      setting: "R and Python Visuals Disabled",
      category: "Power BI - Sharing",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-INFOPROT-001",
      setting: "Sensitivity Labels Enabled",
      category: "Power BI - Information Protection",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-SHARING-003",
      setting: "Shareable Links Restricted",
      category: "Power BI - Sharing",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-SHARING-004",
      setting: "External Data Sharing Restricted",
      category: "Power BI - Sharing",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-AUTH-001",
      setting: "Block ResourceKey Authentication",
      category: "Power BI - Authentication",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-AUTH-002",
      setting: "Service Principal API Access Restricted",
      category: "Power BI - Authentication",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-AUTH-003",
      setting: "Service Principal Profiles Restricted",
      category: "Power BI - Authentication",
      recommendedValue: "True",
    },
  ] as const) {
    ctx.addRow({
      category,
      setting,
      currentValue: NOT_LICENSED_CURRENT,
      recommendedValue,
      checkId,
      remediation: "",
      psStatus: "NotLicensed",
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
}

function emitSkippedGeneric(ctx: Parameters<SectionImplementation>[0], reason: string): void {
  for (const { checkId, setting, category, recommendedValue } of [
    {
      checkId: "POWERBI-GUEST-001",
      setting: "Guest User Access Restricted",
      category: "Power BI - Guest Access",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-GUEST-002",
      setting: "External User Invitations Restricted",
      category: "Power BI - Guest Access",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-GUEST-003",
      setting: "Guest Access to Content Restricted",
      category: "Power BI - Guest Access",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-SHARING-001",
      setting: "Publish to Web Restricted",
      category: "Power BI - Sharing",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-SHARING-002",
      setting: "R and Python Visuals Disabled",
      category: "Power BI - Sharing",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-INFOPROT-001",
      setting: "Sensitivity Labels Enabled",
      category: "Power BI - Information Protection",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-SHARING-003",
      setting: "Shareable Links Restricted",
      category: "Power BI - Sharing",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-SHARING-004",
      setting: "External Data Sharing Restricted",
      category: "Power BI - Sharing",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-AUTH-001",
      setting: "Block ResourceKey Authentication",
      category: "Power BI - Authentication",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-AUTH-002",
      setting: "Service Principal API Access Restricted",
      category: "Power BI - Authentication",
      recommendedValue: "True",
    },
    {
      checkId: "POWERBI-AUTH-003",
      setting: "Service Principal Profiles Restricted",
      category: "Power BI - Authentication",
      recommendedValue: "True",
    },
  ] as const) {
    ctx.addRow({
      category,
      setting,
      currentValue: reason,
      recommendedValue,
      checkId,
      remediation: "",
      psStatus: "Skipped",
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }
}

export const runPowerBISecurityConfig: SectionImplementation = async (ctx) => {
  let allSettings: Record<string, unknown>[] = [];
  let fetchSucceeded = false;

  try {
    const resp = (await ctx.transport.getJson(
      POWERBI_SECURITY_CONFIG_ENDPOINTS.tenantSettings,
      { requiredRole: REQUIRED_ROLE },
    )) as Record<string, unknown>;

    // PS tenantSettings = Invoke-PowerBIRestMethod admin/tenantSettings | ConvertFrom-Json
    //   $allSettings = $tenantSettings.tenantSettings
    // Graph-channel may return { tenantSettings: [...] } or { value: [...] } or bare array.
    if (Array.isArray(resp.tenantSettings)) {
      allSettings = resp.tenantSettings as Record<string, unknown>[];
    } else if (Array.isArray(resp.value)) {
      // Some shapes return value[] with tenantSettings nested inside first element
      const maybe = resp.value[0] as Record<string, unknown> | undefined;
      if (maybe && Array.isArray(maybe.tenantSettings)) {
        allSettings = maybe.tenantSettings as Record<string, unknown>[];
      } else {
        allSettings = asArray(resp.value);
      }
    } else {
      // Single object that is itself the settings container
      const maybe = (resp.tenantSettings ?? resp.value) as unknown;
      if (Array.isArray(maybe)) allSettings = maybe as Record<string, unknown>[];
      else if (Array.isArray(resp as unknown)) allSettings = asArray(resp as unknown);
    }

    fetchSucceeded = true;
  } catch (err) {
    // The transport throws a fatal error BEFORE any fetch when the declared
    // requiredRole is not granted on the app token (TransportFatalError
    // "required role not granted ..."). Default app registrations often do not
    // grant Tenant.Read.All, and the admin/tenantSettings surface is not
    // actually reachable through the Graph resource at all — so the correct
    // behavior is to degrade to visible NotLicensed rows (PS module fail-soft
    // parity) rather than rethrow and silently drop the entire Power BI
    // section from the report (zero rows → absent category/domain).
    if (
      err instanceof TransportFatalError &&
      /required role not granted/i.test(err.message)
    ) {
      emitNotLicensed(ctx);
      return;
    }
    // Genuine transport bugs (SSRF guard, non-GET, malformed/root-relative
    // path) must still surface loud and fail the section explicitly.
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      emitNotLicensed(ctx);
      return;
    }
    // Include 404/NotFound which PS treats as "Power BI admin API not available"
    if (errMatches(err, /404|Not Found|NotFound|does not exist/)) {
      emitNotLicensed(ctx);
      return;
    }
    // Generic graph_error — PS Write-Warning parity: emit Skipped rows with
    // manual-verification note rather than silently omitting 11 checks.
    emitSkippedGeneric(
      ctx,
      "Could not verify — Power BI admin API unavailable: verify in app.powerbi.com > Admin Portal > Tenant Settings",
    );
    return;
  }

  if (!fetchSucceeded) {
    emitSkippedGeneric(
      ctx,
      "Could not verify — Power BI admin API unavailable: verify in app.powerbi.com > Admin Portal > Tenant Settings",
    );
    return;
  }

  function getTenantSetting(settingName: string): boolean | null {
    const match = allSettings.find((s) => psStr(s.settingName) === settingName);
    if (!match) return null;
    const v = match.isEnabled ?? match.enabled ?? match.value;
    if (typeof v === "boolean") return v;
    if (typeof v === "string") {
      if (v.toLowerCase() === "true") return true;
      if (v.toLowerCase() === "false") return false;
    }
    return null;
  }

  // ------------------------------------------------------------------
  // CIS 9.1.1 — Guest user access restricted (AllowGuestLookup == false → Pass)
  // ------------------------------------------------------------------
  {
    const guestLookup = getTenantSetting("AllowGuestLookup");
    const psStatus = guestLookup === false ? "Pass" : guestLookup === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Guest Access",
      setting: "Guest User Access Restricted",
      currentValue: guestLookup === null ? "Not found" : String(!guestLookup),
      recommendedValue: "True",
      checkId: "POWERBI-GUEST-001",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.2 — External user invitations restricted (ElevatedGuestsTenant == false)
  // ------------------------------------------------------------------
  {
    const guestInvite = getTenantSetting("ElevatedGuestsTenant");
    const psStatus = guestInvite === false ? "Pass" : guestInvite === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Guest Access",
      setting: "External User Invitations Restricted",
      currentValue: guestInvite === null ? "Not found" : String(!guestInvite),
      recommendedValue: "True",
      checkId: "POWERBI-GUEST-002",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.3 — Guest access to content restricted
  // ------------------------------------------------------------------
  {
    const guestContent = getTenantSetting("AllowGuestUserToAccessSharedContent");
    const psStatus = guestContent === false ? "Pass" : guestContent === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Guest Access",
      setting: "Guest Access to Content Restricted",
      currentValue: guestContent === null ? "Not found" : String(!guestContent),
      recommendedValue: "True",
      checkId: "POWERBI-GUEST-003",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.4 — Publish to web restricted (WebDashboardsPublishToWebDisabled == true)
  // ------------------------------------------------------------------
  {
    const publishToWeb = getTenantSetting("WebDashboardsPublishToWebDisabled");
    const psStatus = publishToWeb === true ? "Pass" : publishToWeb === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Sharing",
      setting: "Publish to Web Restricted",
      currentValue: publishToWeb === null ? "Not found" : psStr(publishToWeb),
      recommendedValue: "True",
      checkId: "POWERBI-SHARING-001",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.5 — R and Python visuals disabled (RScriptVisuals == false)
  // ------------------------------------------------------------------
  {
    const rPython = getTenantSetting("RScriptVisuals");
    const psStatus = rPython === false ? "Pass" : rPython === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Sharing",
      setting: "R and Python Visuals Disabled",
      currentValue: rPython === null ? "Not found" : String(!rPython),
      recommendedValue: "True",
      checkId: "POWERBI-SHARING-002",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.6 — Sensitivity labels enabled (UseSensitivityLabels == true)
  // ------------------------------------------------------------------
  {
    const sensitivityLabels = getTenantSetting("UseSensitivityLabels");
    const psStatus = sensitivityLabels === true ? "Pass" : sensitivityLabels === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Information Protection",
      setting: "Sensitivity Labels Enabled",
      currentValue: sensitivityLabels === null ? "Not found" : psStr(sensitivityLabels),
      recommendedValue: "True",
      checkId: "POWERBI-INFOPROT-001",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.7 — Shareable links restricted (ShareLinkToEntireOrg == false)
  // ------------------------------------------------------------------
  {
    const shareLinks = getTenantSetting("ShareLinkToEntireOrg");
    const psStatus = shareLinks === false ? "Pass" : shareLinks === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Sharing",
      setting: "Shareable Links Restricted",
      currentValue: shareLinks === null ? "Not found" : String(!shareLinks),
      recommendedValue: "True",
      checkId: "POWERBI-SHARING-003",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.8 — External data sharing restricted
  // ------------------------------------------------------------------
  {
    const extDataSharing = getTenantSetting("AllowExternalDataSharingReceiverWorksWithShare");
    const psStatus = extDataSharing === false ? "Pass" : extDataSharing === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Sharing",
      setting: "External Data Sharing Restricted",
      currentValue: extDataSharing === null ? "Not found" : String(!extDataSharing),
      recommendedValue: "True",
      checkId: "POWERBI-SHARING-004",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.9 — Block ResourceKey Authentication
  // ------------------------------------------------------------------
  {
    const blockResKey = getTenantSetting("BlockResourceKeyAuthentication");
    const psStatus = blockResKey === true ? "Pass" : blockResKey === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Authentication",
      setting: "Block ResourceKey Authentication",
      currentValue: blockResKey === null ? "Not found" : psStr(blockResKey),
      recommendedValue: "True",
      checkId: "POWERBI-AUTH-001",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.10 — Service Principal API access restricted (ServicePrincipalAccess == false)
  // ------------------------------------------------------------------
  {
    const spAccess = getTenantSetting("ServicePrincipalAccess");
    const psStatus = spAccess === false ? "Pass" : spAccess === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Authentication",
      setting: "Service Principal API Access Restricted",
      currentValue: spAccess === null ? "Not found" : String(!spAccess),
      recommendedValue: "True",
      checkId: "POWERBI-AUTH-002",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // ------------------------------------------------------------------
  // CIS 9.1.11 — Service Principal profiles restricted
  // ------------------------------------------------------------------
  {
    const spProfiles = getTenantSetting("CreateServicePrincipalProfile");
    const psStatus = spProfiles === false ? "Pass" : spProfiles === null ? "Review" : "Fail";
    ctx.addRow({
      category: "Power BI - Authentication",
      setting: "Service Principal Profiles Restricted",
      currentValue: spProfiles === null ? "Not found" : String(!spProfiles),
      recommendedValue: "True",
      checkId: "POWERBI-AUTH-003",
      remediation: "",
      psStatus,
      evidenceSource: NOT_IMPLEMENTED_EVIDENCE,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }
};
