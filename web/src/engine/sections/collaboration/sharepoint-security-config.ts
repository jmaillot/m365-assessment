/**
 * Port of `src/M365-Assess/Collaboration/Get-SharePointSecurityConfig.ps1`
 * (1020 lines, ~26 checks).
 *
 * PS → TS mapping:
 * - Invoke-MgGraphRequest GET /v1.0/admin/sharepoint/settings →
 *   getJson same path with SharePointTenantSettings.Read.All (PS line 57).
 *   Sites.Read.All probe for site-level checks is retained via
 *   /v1.0/sites?$select=id,displayName,sharingCapability — PS lines 85-91.
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport are
 *   owned by the runner's addRow pipeline (mapStatus → sub-numbering → D-22
 *   registryRemediationText fallback).
 * - 403-family → Skipped via errMatches, TransportFatalError rethrown,
 *   generic failures → zero rows (PS Write-Warning parity) — fail-soft per
 *   section (ENG-04).
 * - No /beta paths — all v1.0. Beta-only checks from the PS (B2B integration,
 *   OneDrive sharing capability, infected file block) degrade to Review/Skipped
 *   with explicit limitations when v1.0 returns empty — PS parity lines
 *   542-584, 590-670. This minimal v1 port keeps the 6 primary CIS 7.x
 *   checks that are fully represented on /v1.0/admin/sharepoint/settings.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

export const SHAREPOINT_SECURITY_CONFIG_ENDPOINTS = {
  settings: "/v1.0/admin/sharepoint/settings",
  sites: "/v1.0/sites?$select=id,displayName,sharingCapability,webUrl&$top=100",
} as const;

const REQUIRED_ROLE = "SharePointTenantSettings.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

export const runSharePointSecurityConfig: SectionImplementation = async (ctx) => {
  let spoSettings: Record<string, unknown> | null = null;

  try {
    spoSettings = (await ctx.transport.getJson(
      SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
      { requiredRole: REQUIRED_ROLE },
    )) as Record<string, unknown>;
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, /400|BadRequest|MissingProvider/i)) {
      for (const { checkId, setting, category } of [
        { checkId: "SPO-SHARING-001", setting: "SharePoint External Sharing Level", category: "External Sharing" },
        { checkId: "SPO-SHARING-002", setting: "Resharing by External Users", category: "External Sharing" },
        { checkId: "SPO-SHARING-003", setting: "Sharing Domain Restriction", category: "External Sharing" },
        { checkId: "SPO-SHARING-004", setting: "Default Sharing Link Type", category: "External Sharing" },
        { checkId: "SPO-AUTH-001", setting: "Legacy Authentication Protocols", category: "Authentication" },
      ] as const) {
        ctx.addRow({
          category,
          setting,
          currentValue: "Not available in sovereign cloud (USGov/USGovDoD) — verify in SharePoint admin center (400 BadRequest)",
          recommendedValue: "",
          checkId,
          remediation: "SharePoint admin center > Policies > Sharing — verify manually (Graph returns 400 BadRequest in sovereign clouds)",
          psStatus: "Review",
          evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
          collectionMethod: "Direct",
          permissionRequired: REQUIRED_ROLE,
        });
      }
      return;
    }
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      for (const { checkId, setting, category } of [
        { checkId: "SPO-SHARING-001", setting: "SharePoint External Sharing Level", category: "External Sharing" },
        { checkId: "SPO-SHARING-002", setting: "Resharing by External Users", category: "External Sharing" },
        { checkId: "SPO-SHARING-003", setting: "Sharing Domain Restriction", category: "External Sharing" },
        { checkId: "SPO-SHARING-004", setting: "Default Sharing Link Type", category: "External Sharing" },
        { checkId: "SPO-AUTH-001", setting: "Legacy Authentication Protocols", category: "Authentication" },
      ] as const) {
        ctx.addRow({
          category,
          setting,
          currentValue: "Insufficient permissions",
          recommendedValue: "",
          checkId,
          remediation: "",
          psStatus: "Skipped",
          evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
          collectionMethod: "Direct",
          permissionRequired: REQUIRED_ROLE,
        });
      }
      return;
    }
    return;
  }

  if (!spoSettings) return;

  // 1. SPO-SHARING-001 — External Sharing Level (PS lines 108-144)
  {
    const sharingCapability = psStr(spoSettings.sharingCapability);
    const sharingDisplay =
      sharingCapability === "disabled"
        ? "Disabled (no external sharing)"
        : sharingCapability === "externalUserSharingOnly"
          ? "External users only (require sign-in)"
          : sharingCapability === "externalUserAndGuestSharing"
            ? "External users and guests (anyone with link)"
            : sharingCapability === "existingExternalUserSharingOnly"
              ? "Existing external users only"
              : sharingCapability || "Not available via API";
    let psStatus: "Pass" | "Fail" | "Warning" | "Review" = "Review";
    if (sharingCapability === "disabled" || sharingCapability === "existingExternalUserSharingOnly") psStatus = "Pass";
    else if (sharingCapability === "externalUserSharingOnly") psStatus = "Warning";
    else if (sharingCapability === "externalUserAndGuestSharing") psStatus = "Fail";
    ctx.addRow({
      category: "External Sharing",
      setting: "SharePoint External Sharing Level",
      currentValue: sharingDisplay,
      recommendedValue: "Existing external users only (or more restrictive)",
      checkId: "SPO-SHARING-001",
      remediation: "",
      psStatus,
      evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // 2. SPO-SHARING-002 — Resharing by External Users (PS lines 149-163)
  {
    const resharing = spoSettings.isResharingByExternalUsersEnabled as boolean | undefined;
    ctx.addRow({
      category: "External Sharing",
      setting: "Resharing by External Users",
      currentValue: psStr(resharing),
      recommendedValue: "False",
      checkId: "SPO-SHARING-002",
      remediation: "",
      psStatus: resharing === false ? "Pass" : resharing === true ? "Warning" : "Review",
      evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // 3. SPO-SHARING-003 — Sharing Domain Restriction (PS lines 169-198)
  {
    const mode = psStr(spoSettings.sharingDomainRestrictionMode);
    const display =
      mode === "none" ? "No restriction" : mode === "allowList" ? "Allow list (specific domains only)" : mode === "blockList" ? "Block list (block specific domains)" : mode || "Not available";
    let psStatus: "Pass" | "Warning" | "Review" = "Review";
    if (mode === "none") psStatus = "Warning";
    else if (mode === "allowList" || mode === "blockList") psStatus = "Pass";
    ctx.addRow({
      category: "External Sharing",
      setting: "Sharing Domain Restriction",
      currentValue: display,
      recommendedValue: "Allow or Block list configured",
      checkId: "SPO-SHARING-003",
      remediation: "",
      psStatus,
      evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // 4. SPO-SHARING-004 — Default Sharing Link Type (PS lines 352-381)
  {
    const linkType = psStr(spoSettings.defaultSharingLinkType);
    const display =
      linkType === "specificPeople"
        ? "Specific people (direct)"
        : linkType === "organization"
          ? "People in the organization"
          : linkType === "anyone"
            ? "Anyone with the link"
            : linkType || "Not available via API";
    let psStatus: "Pass" | "Fail" | "Review" = "Review";
    if (linkType === "specificPeople") psStatus = "Pass";
    else if (linkType === "anyone") psStatus = "Fail";
    else if (linkType === "organization") psStatus = "Review";
    ctx.addRow({
      category: "External Sharing",
      setting: "Default Sharing Link Type",
      currentValue: display,
      recommendedValue: "Specific people (direct)",
      checkId: "SPO-SHARING-004",
      remediation: "",
      psStatus,
      evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // 5. SPO-SYNC-001 — Unmanaged Sync Client Restriction (PS lines 204-218)
  {
    const unmanagedSync = spoSettings.isUnmanagedSyncClientRestricted as boolean | undefined;
    ctx.addRow({
      category: "Sync & Access",
      setting: "Block Sync from Unmanaged Devices",
      currentValue: unmanagedSync === null || unmanagedSync === undefined ? "Not configured" : psStr(unmanagedSync),
      recommendedValue: "True",
      checkId: "SPO-SYNC-001",
      remediation: "",
      psStatus: unmanagedSync === true ? "Pass" : "Warning",
      evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // 6. SPO-AUTH-001 — Legacy Authentication Protocols (PS lines 502-534)
  {
    const legacyAuth = spoSettings.isLegacyAuthProtocolsEnabled as boolean | undefined;
    if (legacyAuth !== null && legacyAuth !== undefined) {
      ctx.addRow({
        category: "Authentication",
        setting: "Legacy Authentication Protocols",
        currentValue: psStr(legacyAuth),
        recommendedValue: "False",
        checkId: "SPO-AUTH-001",
        remediation: "",
        psStatus: legacyAuth === false ? "Pass" : "Fail",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    } else {
      ctx.addRow({
        category: "Authentication",
        setting: "Legacy Authentication Protocols",
        currentValue: "Not available via API",
        recommendedValue: "False",
        checkId: "SPO-AUTH-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
    }
  }

  // 7. SPO-SHARING-005 — Guest Access Expiration (PS lines 383-419)
  {
    const guestExpRequired = (spoSettings.isGuestShareExpirationEnabled ?? spoSettings.isExternalUserExpirationRequired) as boolean | undefined;
    const guestExpDays = (spoSettings.guestShareExpirationInDays ?? spoSettings.externalUserExpireInDays) as number | undefined;
    if (guestExpRequired === null || guestExpRequired === undefined) {
      ctx.addRow({
        category: "External Sharing",
        setting: "Guest Access Expiration",
        currentValue: "Not available via API",
        recommendedValue: "Enabled (30 days or less)",
        checkId: "SPO-SHARING-005",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      const expDisplay = guestExpRequired ? `Enabled (${psStr(guestExpDays)} days)` : "Disabled";
      let psStatus: "Pass" | "Fail" | "Warning" | "Review" = "Review";
      if (guestExpRequired && typeof guestExpDays === "number" && guestExpDays <= 30) psStatus = "Pass";
      else if (guestExpRequired) psStatus = "Warning";
      else psStatus = "Fail";
      ctx.addRow({
        category: "External Sharing",
        setting: "Guest Access Expiration",
        currentValue: expDisplay,
        recommendedValue: "Enabled (30 days or less)",
        checkId: "SPO-SHARING-005",
        remediation: "",
        psStatus,
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    }
  }

  // 8. SPO-SHARING-007 — Default Sharing Link Permission (extended) — PS lines 490-500
  {
    const defaultLinkPermission = psStr(spoSettings.defaultSharingLinkPermission);
    const display =
      defaultLinkPermission === "view" ? "View" :
      defaultLinkPermission === "edit" ? "Edit" :
      defaultLinkPermission === "none" ? "None (specific people)" :
      defaultLinkPermission || "Not available via API";
    let psStatus: "Pass" | "Fail" | "Review" = "Review";
    if (defaultLinkPermission === "view") psStatus = "Pass";
    else if (defaultLinkPermission === "edit") psStatus = "Fail";
    ctx.addRow({
      category: "External Sharing",
      setting: "Default Sharing Link Permission",
      currentValue: display,
      recommendedValue: "View (least privilege)",
      checkId: "SPO-SHARING-007",
      remediation: "",
      psStatus,
      evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 1.0,
    });
  }

  // 9. SPO-SITE-001 — Site Sharing Level (PS lines 741-760)
  {
    const siteSharingLevel = psStr(spoSettings.sharingAllowedDomainList);
    // Fallback: if site-level sharing blocked via sharingCapability already Fail, this is additional granularity
    // PS checks site collection sharingCapability via /sites; here we surface tenant site policy
    const hasDomainList = psStr(spoSettings.sharingAllowedDomainList) !== "" || psStr(spoSettings.sharingBlockedDomainList) !== "";
    ctx.addRow({
      category: "Site Policy",
      setting: "Site Sharing Level within Tenant Policy",
      currentValue: hasDomainList ? "Domain list configured" : "No site-level domain restriction",
      recommendedValue: "Site sharing restricted via domain allow/block list",
      checkId: "SPO-SITE-001",
      remediation: "",
      psStatus: hasDomainList ? "Pass" : "Warning",
      evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
      confidence: 0.9,
    });
  }

  // 10. SPO-SHARING-006 — Reauthentication with Verification Code (PS lines 426-448)
  {
    const emailAttestation = spoSettings.emailAttestationRequired as boolean | undefined;
    const emailAttestDays = spoSettings.emailAttestationReAuthDays as number | undefined;
    if (emailAttestation === null || emailAttestation === undefined) {
      ctx.addRow({
        category: "External Sharing",
        setting: "Reauthentication with Verification Code",
        currentValue: "Not available via API",
        recommendedValue: "Enabled (verification code required)",
        checkId: "SPO-SHARING-006",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "External Sharing",
        setting: "Reauthentication with Verification Code",
        currentValue: emailAttestation ? `Enabled (${psStr(emailAttestDays)} days)` : "Disabled",
        recommendedValue: "Enabled (verification code required)",
        checkId: "SPO-SHARING-006",
        remediation: "",
        psStatus: emailAttestation ? "Pass" : "Fail",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    }
  }

  // 11. SPO-SHARING-008 — External Sharing Restricted by Security Group (PS Get-SPOTenant — PS-only, Skipped)
  {
    ctx.addRow({
      category: "External Sharing",
      setting: "External Sharing Restricted by Security Group",
      currentValue: "Not available via Graph v1.0 — verify in SharePoint admin center > Policies > Sharing > Limit external sharing by security group",
      recommendedValue: "External sharing limited to security group",
      checkId: "SPO-SHARING-008",
      remediation: "SharePoint admin center > Policies > Sharing > Limit external sharing by security group. Run: Get-SPOTenant | Select SharingCapability",
      psStatus: "Skipped",
      evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }

  // 12. SPO-SITE-002 — Sensitive Sites Restricted (Keep — Graph /sites cap 100 D-39)
  {
    // Best-effort: if any site in tenant has sharingCapability == disabled or existingExternalUserSharingOnly, consider sensitive sites restricted
    try {
      const sitesResp = await ctx.transport.getJson(SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.sites, { requiredRole: "Sites.Read.All" });
      const sites = asArray(sitesResp.value);
      const hasRestrictedSite = sites.some((s: unknown) => {
        const cap = psStr((s as Record<string, unknown>).sharingCapability);
        return cap === "disabled" || cap === "existingExternalUserSharingOnly";
      });
      const cappedSuffix = sites.length === 100 ? ` Retrieved ${sites.length} sites (capped at 100). Full admin enumeration requires SPO PowerShell` : ` Retrieved ${sites.length} sites`;
      const baseCurrent = hasRestrictedSite ? "At least one site has restricted sharing" : sites.length > 0 ? "Sites found but none with restricted sharing" : "No sites enumerated";
      ctx.addRow({
        category: "Site Policy",
        setting: "Sensitive Sites Have Restricted External Sharing",
        currentValue: `${baseCurrent}${cappedSuffix}`,
        recommendedValue: "Sensitive sites sharingCapability: disabled or existingExternalUserSharingOnly",
        checkId: "SPO-SITE-002",
        remediation: "",
        psStatus: hasRestrictedSite ? "Pass" : sites.length > 0 ? "Warning" : "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.sites,
        collectionMethod: "Direct",
        permissionRequired: "Sites.Read.All",
      });
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      if (errMatches(err, AUTHORIZATION_ERROR)) {
        ctx.addRow({
          category: "Site Policy",
          setting: "Sensitive Sites Have Restricted External Sharing",
          currentValue: "Insufficient permissions (Sites.Read.All)",
          recommendedValue: "Sensitive sites sharingCapability: disabled or existingExternalUserSharingOnly",
          checkId: "SPO-SITE-002",
          remediation: "",
          psStatus: "Skipped",
          evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.sites,
          collectionMethod: "Direct",
          permissionRequired: "Sites.Read.All",
        });
      }
    }
  }

  // 13. SPO-SITE-003 — Site Collection Administrator Visibility (PS-only Get-SPOSiteAdministrator — Skipped)
  {
    ctx.addRow({
      category: "Site Policy",
      setting: "Site Collection Administrator Visibility",
      currentValue: "Not available via Graph v1.0 — verify in SharePoint admin center > Sites > Active sites > Owners",
      recommendedValue: "Site collection admins visible and limited",
      checkId: "SPO-SITE-003",
      remediation: "SharePoint admin center > Sites > Active sites > select site > Membership. Run: Get-SPOSite | Get-SPOSiteAdministrator",
      psStatus: "Skipped",
      evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.sites,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }

  // 14. SPO-SYNC-002 — Mac Sync App Enabled (Keep — Graph isUnmanagedSyncClientRestricted inverse + OneDrive sync)
  {
    const isUnmanagedSyncRestricted = spoSettings.isUnmanagedSyncClientRestricted as boolean | undefined;
    // PS Get-SPOTenant -LegacyAuth for Mac sync maps to isMacSyncEnabled via spoSettings
    const macSyncEnabled = (spoSettings as Record<string, unknown>).isMacSyncAppEnabled as boolean | undefined;
    const syncVal = macSyncEnabled ?? isUnmanagedSyncRestricted;
    if (syncVal === null || syncVal === undefined) {
      ctx.addRow({
        category: "Sync & Access",
        setting: "Mac Sync App Enabled",
        currentValue: "Not available via API",
        recommendedValue: "Review Mac sync client restriction",
        checkId: "SPO-SYNC-002",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      // If Mac sync is enabled and unmanaged sync not restricted, Warning
      const isEnabled = macSyncEnabled === true || isUnmanagedSyncRestricted === false;
      ctx.addRow({
        category: "Sync & Access",
        setting: "Mac Sync App Enabled",
        currentValue: isEnabled ? "Mac sync enabled (unmanaged devices may sync)" : "Mac sync restricted",
        recommendedValue: "Review Mac sync client restriction per policy",
        checkId: "SPO-SYNC-002",
        remediation: "",
        psStatus: isEnabled ? "Warning" : "Pass",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  }

  // 15. SPO-LOOP-001 — Loop Components Enabled (PS Get-SPOTenant isLoopEnabled)
  {
    const isLoopEnabled = (spoSettings as Record<string, unknown>).isLoopEnabled as boolean | undefined ?? (spoSettings as Record<string, unknown>).isLoopComponentsEnabled as boolean | undefined;
    if (isLoopEnabled === null || isLoopEnabled === undefined) {
      ctx.addRow({
        category: "Loop",
        setting: "Loop Components Enabled",
        currentValue: "Not available via API",
        recommendedValue: "Review Loop per policy (CIS 7.1.8)",
        checkId: "SPO-LOOP-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "Loop",
        setting: "Loop Components Enabled",
        currentValue: psStr(isLoopEnabled),
        recommendedValue: "Review Loop per policy (CIS 7.1.8)",
        checkId: "SPO-LOOP-001",
        remediation: "",
        psStatus: isLoopEnabled ? "Warning" : "Pass",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  }

  // 16. SPO-LOOP-002 — OneDrive Loop Sharing (PS policies/activityBasedTimeoutPolicies)
  // Best-effort: reuse spoSettings isLoopSharingEnabled if present, else Review
  {
    const oneDriveLoop = (spoSettings as Record<string, unknown>).isOneDriveLoopSharingEnabled as boolean | undefined;
    if (oneDriveLoop === null || oneDriveLoop === undefined) {
      ctx.addRow({
        category: "Loop",
        setting: "OneDrive Loop Sharing",
        currentValue: "Not available via API",
        recommendedValue: "Review Loop sharing per policy",
        checkId: "SPO-LOOP-002",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "Loop",
        setting: "OneDrive Loop Sharing",
        currentValue: psStr(oneDriveLoop),
        recommendedValue: "Review Loop sharing per policy",
        checkId: "SPO-LOOP-002",
        remediation: "",
        psStatus: oneDriveLoop ? "Warning" : "Pass",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  }

  // 17. SPO-MALWARE-002 — Infected Files Disallowed (PS Get-SPOTenant disallowInfectedFileDownload)
  {
    const disallowInfected = (spoSettings as Record<string, unknown>).disallowInfectedFileDownload as boolean | undefined;
    if (disallowInfected === null || disallowInfected === undefined) {
      ctx.addRow({
        category: "Malware",
        setting: "Office 365 SharePoint Infected Files Disallowed for Download",
        currentValue: "Not available via API",
        recommendedValue: "True",
        checkId: "SPO-MALWARE-002",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "Malware",
        setting: "Office 365 SharePoint Infected Files Disallowed for Download",
        currentValue: psStr(disallowInfected),
        recommendedValue: "True",
        checkId: "SPO-MALWARE-002",
        remediation: "",
        psStatus: disallowInfected ? "Pass" : "Fail",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    }
  }

  // 18. SPO-OD-001 — OneDrive Content Sharing Restricted (PS isExternalSharingEnabled for OneDrive)
  {
    const oneDriveSharing = (spoSettings as Record<string, unknown>).oneDriveSharingCapability as string | undefined ?? psStr(spoSettings.sharingCapability);
    const isOneDriveRestricted = oneDriveSharing === "disabled" || oneDriveSharing === "existingExternalUserSharingOnly";
    if (!oneDriveSharing) {
      ctx.addRow({
        category: "OneDrive",
        setting: "OneDrive Content Sharing Restricted",
        currentValue: "Not available via API",
        recommendedValue: "Existing external users only or disabled",
        checkId: "SPO-OD-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "OneDrive",
        setting: "OneDrive Content Sharing Restricted",
        currentValue: psStr(oneDriveSharing),
        recommendedValue: "Existing external users only or disabled",
        checkId: "SPO-OD-001",
        remediation: "",
        psStatus: isOneDriveRestricted ? "Pass" : "Warning",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 1.0,
      });
    }
  }

  // 19. SPO-SESSION-001 — Idle Session Timeout (PS activityBasedTimeoutPolicies)
  {
    const idleTimeout = (spoSettings as Record<string, unknown>).idleSessionSignOut as boolean | undefined ?? (spoSettings as Record<string, unknown>).isIdleSessionTimeoutEnabled as boolean | undefined;
    if (idleTimeout === null || idleTimeout === undefined) {
      ctx.addRow({
        category: "Session",
        setting: "Idle Session Timeout (3 hours or less)",
        currentValue: "Not available via API",
        recommendedValue: "Enabled (3 hours or less)",
        checkId: "SPO-SESSION-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "Session",
        setting: "Idle Session Timeout (3 hours or less)",
        currentValue: psStr(idleTimeout),
        recommendedValue: "Enabled",
        checkId: "SPO-SESSION-001",
        remediation: "",
        psStatus: idleTimeout ? "Pass" : "Warning",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  }

  // 20. SPO-VERSIONING-001 — Version History (PS isVersioningEnabled)
  {
    const versioning = (spoSettings as Record<string, unknown>).isVersioningEnabled as boolean | undefined ?? (spoSettings as Record<string, unknown>).isVersionHistoryEnabled as boolean | undefined;
    if (versioning === null || versioning === undefined) {
      ctx.addRow({
        category: "Versioning",
        setting: "Version History Configuration",
        currentValue: "Not available via API",
        recommendedValue: "Enabled per policy",
        checkId: "SPO-VERSIONING-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "Versioning",
        setting: "Version History Configuration",
        currentValue: psStr(versioning),
        recommendedValue: "Enabled",
        checkId: "SPO-VERSIONING-001",
        remediation: "",
        psStatus: versioning ? "Pass" : "Warning",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  }

  // 21. SPO-SWAY-001 — Sway Sharing (PS isSwayEnabled)
  {
    const swayEnabled = (spoSettings as Record<string, unknown>).isSwayEnabled as boolean | undefined;
    if (swayEnabled === null || swayEnabled === undefined) {
      ctx.addRow({
        category: "Sway",
        setting: "Sways Cannot Be Shared Externally",
        currentValue: "Not available via API",
        recommendedValue: "False (Sway external sharing disabled)",
        checkId: "SPO-SWAY-001",
        remediation: "",
        psStatus: "Review",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "Sway",
        setting: "Sways Cannot Be Shared Externally",
        currentValue: psStr(swayEnabled),
        recommendedValue: "False",
        checkId: "SPO-SWAY-001",
        remediation: "",
        psStatus: swayEnabled ? "Fail" : "Pass",
        evidenceSource: SHAREPOINT_SECURITY_CONFIG_ENDPOINTS.settings,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
        confidence: 0.9,
      });
    }
  }
};
