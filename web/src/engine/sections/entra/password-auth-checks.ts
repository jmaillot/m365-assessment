/**
 * Port of `src/M365-Assess/Entra/EntraPasswordAuthChecks.ps1` (647 lines)
 * — check-helper half of Get-EntraSecurityConfig.ps1 (plan 02-07 task 1).
 *
 * PS shared-scope state → module-local variables within one invocation:
 * - $sspr (section 7 fetch, reused by 7b/20/21), $secDefaultsCaPolicies
 *   (check 1 pre-fetch reused by 1b), $isEnabled, $pwSettings (check 8,
 *   reused by 27).
 * - $orgSettings is populated by EntraUserGroupChecks.ps1 section 14 — which
 *   runs AFTER this file in Get-EntraSecurityConfig's dot-source order — so at
 *   section-27 time it is always null in a composed run. The TS port reads it
 *   from ctx.shared("entra.orgSettings") to preserve the branch structure;
 *   with the PS execution order the value is null and the null-guard branch
 *   (`isCloudOnly = null) is taken, exactly as in PowerShell.
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting: owned by the runner's addRow
 *   pipeline (mapStatus → sub-numbering → D-22 registry fallback).
 * - Invoke-MgGraphRequest GET → ctx.transport.getJson with requiredRole.
 * - Soft-fail semantics preserved per section: catch blocks emit their PS row
 *   verbatim or degrade to zero rows; TransportFatalError (structural guard
 *   breaches: non-GET, ungranted role) still propagates.
 * - PS check 1 carries an Evidence PSCustomObject; CheckRowInput has no
 *   freeform-evidence slot (D1 #785 fields are typed and never synthesized),
 *   so the evidence payload is not carried — no decision consumes it.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const PASSWORD_AUTH_ENDPOINTS = {
  securityDefaults:
    "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
  caPolicies: "/v1.0/identity/conditionalAccess/policies",
  authenticationMethodsPolicy: "/v1.0/policies/authenticationMethodsPolicy",
  directorySettings: "/v1.0/settings",
  domains: "/v1.0/domains",
  organization: "/v1.0/organization",
} as const;

type GraphObj = Record<string, unknown>;

const POLICY_READ_ALL = "Policy.Read.All";
const DIRECTORY_READ_ALL = "Directory.Read.All";

/** PS line 366 matcher for the no-directory-settings tenant state. */
const SETTINGS_NOT_CONFIGURED =
  /400 Bad Request|BadRequest|Resource not found for the segment/;

/** Well-known admin role template IDs (PS lines 100-106, CIS-recommended subset). */
const SD_ADMIN_ROLES = [
  "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
  "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
  "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator
  "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
  "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
];

/** Azure Management well-known app ID (PS line 109). */
const AZURE_MGMT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013";

function includes(list: unknown, item: string): boolean {
  return Array.isArray(list) && (list as unknown[]).includes(item);
}

export const runPasswordAuthChecks: SectionImplementation = async (ctx) => {
  // Shared-scope mirrors of the PS file's cross-section variables.
  let sspr: GraphObj | null = null;
  let secDefaultsCaPolicies: GraphObj[] | null = null;
  let sdEnabled: boolean | undefined;
  let pwSettings: GraphObj | null = null;

  // ------------------------------------------------------------------
  // 1. Security Defaults (PS lines 13-75)
  // ------------------------------------------------------------------
  try {
    const secDefaults = await ctx.transport.getJson(
      PASSWORD_AUTH_ENDPOINTS.securityDefaults,
      { requiredRole: POLICY_READ_ALL },
    );
    if (!secDefaults || typeof secDefaults !== "object") {
      throw new Error("API returned null response");
    }
    const isEnabled = Boolean((secDefaults as GraphObj).isEnabled);
    sdEnabled = isEnabled;

    // When SD is disabled, check whether CA policies provide equivalent
    // coverage (PS lines 20-33).
    let caEnabledCount = 0;
    if (!isEnabled) {
      try {
        const caResp = await ctx.transport.getJson(
          PASSWORD_AUTH_ENDPOINTS.caPolicies,
          { requiredRole: POLICY_READ_ALL },
        );
        secDefaultsCaPolicies = asArray(caResp.value);
      } catch (err) {
        if (err instanceof TransportFatalError) throw err;
        secDefaultsCaPolicies = [];
      }
      if (secDefaultsCaPolicies.length > 0) {
        caEnabledCount = secDefaultsCaPolicies.filter(
          (p) => p.state === "enabled",
        ).length;
      }
    }

    const sdStatus = isEnabled
      ? "Pass"
      : caEnabledCount > 0
        ? "Pass"
        : "Fail";

    const sdCurrentValue = isEnabled
      ? "True"
      : caEnabledCount > 0
        ? `False (Conditional Access active: ${caEnabledCount} enabled policies)`
        : "False";

    ctx.addRow({
      category: "Security Defaults",
      setting: "Security Defaults Enabled",
      currentValue: sdCurrentValue,
      recommendedValue: "True (if no Conditional Access)",
      psStatus: sdStatus,
      checkId: "ENTRA-SECDEFAULT-001",
      remediation:
        "Run: Update-MgPolicyIdentitySecurityDefaultsEnforcementPolicy -IsEnabled $true. Entra admin center > Properties > Manage security defaults.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    ctx.addRow({
      category: "Security Defaults",
      setting: "Security Defaults Enabled",
      currentValue: "Unable to retrieve",
      recommendedValue: "True (if no CA)",
      psStatus: "Review",
      checkId: "ENTRA-SECDEFAULT-001",
      remediation:
        "Run: Update-MgPolicyIdentitySecurityDefaultsEnforcementPolicy -IsEnabled $true. Entra admin center > Properties > Manage security defaults.",
    });
  }

  // ------------------------------------------------------------------
  // 1b. Security Defaults Gap Analysis (CA Coverage) (PS lines 80-199)
  // ------------------------------------------------------------------
  if (sdEnabled === false) {
    try {
      // Reuse policies pre-fetched in check 1; fall back to a fresh call.
      const caPolicies =
        secDefaultsCaPolicies ??
        asArray(
          (
            await ctx.transport.getJson(PASSWORD_AUTH_ENDPOINTS.caPolicies, {
              requiredRole: POLICY_READ_ALL,
            })
          ).value,
        );
      const caEnabled = caPolicies.filter((p) => p.state === "enabled");

      // [ordered] insertion order is load-bearing: gap lists render in it.
      const coverageAreas: Array<[string, boolean]> = [
        ["MFA for all users", false],
        ["Legacy auth blocked", false],
        ["Admin MFA", false],
        ["Azure Management MFA", false],
      ];
      const setCovered = (name: string): void => {
        const entry = coverageAreas.find(([key]) => key === name);
        if (entry) entry[1] = true;
      };

      for (const policy of caEnabled) {
        const grantControls = policy.grantControls as GraphObj | undefined;
        const grants = grantControls?.builtInControls;
        const users = ((policy.conditions as GraphObj | undefined)?.users ??
          {}) as GraphObj;
        const clientApps = (policy.conditions as GraphObj | undefined)
          ?.clientAppTypes;
        const apps = ((policy.conditions as GraphObj | undefined)
          ?.applications ?? {}) as GraphObj;

        if (includes(users.includeUsers, "All") && includes(grants, "mfa")) {
          setCovered("MFA for all users");
        }
        if (
          (includes(clientApps, "exchangeActiveSync") ||
            includes(clientApps, "other")) &&
          includes(grants, "block")
        ) {
          setCovered("Legacy auth blocked");
        }
        const includeRoles = users.includeRoles;
        if (Array.isArray(includeRoles)) {
          const hasAdminRole = (includeRoles as string[]).some((role) =>
            SD_ADMIN_ROLES.includes(role),
          );
          if (hasAdminRole && includes(grants, "mfa")) {
            setCovered("Admin MFA");
          }
        }
        const includeApps = apps.includeApplications;
        if (
          (includes(includeApps, AZURE_MGMT_APP_ID) ||
            includes(includeApps, "All")) &&
          includes(grants, "mfa")
        ) {
          setCovered("Azure Management MFA");
        }
      }

      const coveredCount = coverageAreas.filter(([, v]) => v).length;
      const totalAreas = coverageAreas.length;
      const gaps = coverageAreas
        .filter(([, v]) => !v)
        .map(([key]) => key);

      if (coveredCount === totalAreas) {
        ctx.addRow({
          category: "Security Defaults",
          setting: "Security Defaults Gap Analysis",
          currentValue: `All ${totalAreas} areas covered by Conditional Access`,
          recommendedValue: "Full CA coverage when Security Defaults is OFF",
          psStatus: "Pass",
          checkId: "ENTRA-SECDEFAULT-002",
          remediation:
            "No action needed. Conditional Access policies provide equivalent coverage to Security Defaults.",
        });
      } else if (coveredCount > 0) {
        const gapList = gaps.join(", ");
        ctx.addRow({
          category: "Security Defaults",
          setting: "Security Defaults Gap Analysis",
          currentValue: `${coveredCount}/${totalAreas} covered. Gaps: ${gapList}`,
          recommendedValue: "Full CA coverage when Security Defaults is OFF",
          psStatus: "Review",
          checkId: "ENTRA-SECDEFAULT-002",
          remediation: `Create CA policies to cover: ${gapList}. Entra admin center > Protection > Conditional Access.`,
        });
      } else {
        ctx.addRow({
          category: "Security Defaults",
          setting: "Security Defaults Gap Analysis",
          currentValue: `0/${totalAreas} areas covered -- no CA policy protection`,
          recommendedValue: "Full CA coverage when Security Defaults is OFF",
          psStatus: "Fail",
          checkId: "ENTRA-SECDEFAULT-002",
          remediation:
            "Either enable Security Defaults or create CA policies for: MFA for all users, legacy auth block, admin MFA, Azure Management MFA. Entra admin center > Protection > Conditional Access.",
        });
      }
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      ctx.addRow({
        category: "Security Defaults",
        setting: "Security Defaults Gap Analysis",
        currentValue: "Unable to evaluate",
        recommendedValue: "Full CA coverage when Security Defaults is OFF",
        psStatus: "Review",
        checkId: "ENTRA-SECDEFAULT-002",
        remediation:
          "Verify CA policies are configured. Entra admin center > Protection > Conditional Access.",
      });
    }
  }

  // ------------------------------------------------------------------
  // 7. Self-Service Password Reset (PS lines 204-227)
  // ------------------------------------------------------------------
  try {
    sspr = (await ctx.transport.getJson(
      PASSWORD_AUTH_ENDPOINTS.authenticationMethodsPolicy,
      { requiredRole: POLICY_READ_ALL },
    )) as GraphObj;
    const registrationEnforcement = sspr.registrationEnforcement as
      | GraphObj
      | undefined;
    const campaign = registrationEnforcement
      ?.authenticationMethodsRegistrationCampaign as GraphObj | undefined;
    const ssprRegistration = psStr(campaign?.state);

    ctx.addRow({
      category: "Password Management",
      setting: "Auth Method Registration Campaign",
      currentValue: ssprRegistration,
      recommendedValue: "enabled",
      psStatus: ssprRegistration === "enabled" ? "Pass" : "Warning",
      checkId: "ENTRA-MFA-001",
      remediation:
        "Run: Update-MgBetaPolicyAuthenticationMethodPolicy with RegistrationEnforcement settings. Entra admin center > Protection > Authentication methods > Registration campaign.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity — zero rows, run continues.
  }

  // ------------------------------------------------------------------
  // 7b. Authentication Methods -- SMS/Voice/Email (PS lines 232-282)
  // ------------------------------------------------------------------
  if (sspr) {
    const authMethods = sspr.authenticationMethodConfigurations;
    if (authMethods) {
      const methods = Array.isArray(authMethods)
        ? (authMethods as GraphObj[])
        : [];

      const methodState = (id: string): string => {
        const method = methods.find((m) => m.id === id);
        return method ? psStr(method.state) : "not found";
      };

      // CIS 5.2.3.5 -- SMS sign-in disabled
      const smsState = methodState("Sms");
      ctx.addRow({
        category: "Authentication Methods",
        setting: "SMS Authentication",
        currentValue: smsState,
        recommendedValue: "disabled",
        psStatus: smsState === "disabled" ? "Pass" : "Fail",
        checkId: "ENTRA-AUTHMETHOD-001",
        remediation:
          "Entra admin center > Protection > Authentication methods > SMS > Disable. SMS is vulnerable to SIM-swapping attacks.",
      });

      // CIS 5.2.3.5 -- Voice call disabled
      const voiceState = methodState("Voice");
      ctx.addRow({
        category: "Authentication Methods",
        setting: "Voice Call Authentication",
        currentValue: voiceState,
        recommendedValue: "disabled",
        psStatus: voiceState === "disabled" ? "Pass" : "Fail",
        checkId: "ENTRA-AUTHMETHOD-001",
        remediation:
          "Entra admin center > Protection > Authentication methods > Voice call > Disable. Voice is vulnerable to telephony-based attacks.",
      });

      // CIS 5.2.3.7 -- Email OTP disabled
      const emailState = methodState("Email");
      ctx.addRow({
        category: "Authentication Methods",
        setting: "Email OTP Authentication",
        currentValue: emailState,
        recommendedValue: "disabled",
        psStatus: emailState === "disabled" ? "Pass" : "Fail",
        checkId: "ENTRA-AUTHMETHOD-002",
        remediation:
          "Entra admin center > Protection > Authentication methods > Email OTP > Disable. Email OTP is a weaker authentication factor.",
      });
    }
  }

  // ------------------------------------------------------------------
  // 7c. SSPR Enabled for All Users — static Review row (PS lines 296-305).
  //     See #878: the legacy toggle is not exposed via Microsoft Graph.
  // ------------------------------------------------------------------
  ctx.addRow({
    category: "SSPR",
    setting: "Ensure 'Self service password reset enabled' is set to 'All'",
    currentValue: "Not auto-measurable via Microsoft Graph",
    recommendedValue: "Enabled for all users",
    psStatus: "Review",
    checkId: "ENTRA-SSPR-001",
    remediation:
      "Microsoft Entra admin center > Password reset > Properties > Self service password reset enabled: All. See https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr for the full enablement walkthrough.",
  });

  // ------------------------------------------------------------------
  // 8. Password Protection / Banned Passwords (PS lines 310-384)
  // ------------------------------------------------------------------
  try {
    const passwordProtection = await ctx.transport.getJson(
      PASSWORD_AUTH_ENDPOINTS.directorySettings,
      { requiredRole: DIRECTORY_READ_ALL },
    );
    const settingsList = asArray(passwordProtection.value);
    pwSettings =
      settingsList.find((s) => s.displayName === "Password Rule Settings") ??
      null;

    if (pwSettings) {
      const values = Array.isArray(pwSettings.values)
        ? (pwSettings.values as GraphObj[])
        : [];
      const namedValue = (name: string): unknown =>
        values.find((v) => v.name === name)?.value;

      const enforceCustom = namedValue("EnableBannedPasswordCheck");
      ctx.addRow({
        category: "Password Management",
        setting: "Custom Banned Password List Enforced",
        currentValue: psStr(enforceCustom),
        recommendedValue: "True",
        psStatus: enforceCustom === "True" ? "Pass" : "Warning",
        checkId: "ENTRA-PASSWORD-002",
        remediation:
          "Run: Update-MgBetaDirectorySetting for Password Rule Settings with CustomBannedPasswordsEnforced = true. Entra admin center > Protection > Password protection.",
      });

      const bannedList = namedValue("BannedPasswordList");
      // PS ($bannedList -split ',').Count parity: any non-null value (even "")
      // splits into >= 1 element; only $null yields 0.
      const bannedCount =
        bannedList === null || bannedList === undefined
          ? 0
          : psStr(bannedList).split(",").length;
      ctx.addRow({
        category: "Password Management",
        setting: "Custom Banned Password Count",
        currentValue: String(bannedCount),
        recommendedValue: "1+",
        psStatus: bannedCount > 0 ? "Pass" : "Warning",
        checkId: "ENTRA-PASSWORD-004",
        remediation:
          "Run: Update-MgBetaDirectorySetting for Password Rule Settings to add organization-specific terms. Entra admin center > Protection > Password protection.",
      });

      const lockoutThreshold = namedValue("LockoutThreshold");
      // PS [int]$lockoutThreshold parity: $null casts to 0; a non-numeric
      // string throws mid-try so rows already emitted stay and the remaining
      // row is dropped (outer catch writes only a warning).
      const lockoutNum =
        lockoutThreshold === null || lockoutThreshold === undefined
          ? 0
          : Number(lockoutThreshold);
      if (!Number.isFinite(lockoutNum) || !Number.isInteger(lockoutNum)) {
        throw new Error(`Cannot convert value "${psStr(lockoutThreshold)}" to int`);
      }
      ctx.addRow({
        category: "Password Management",
        setting: "Smart Lockout Threshold",
        currentValue: psStr(lockoutThreshold),
        recommendedValue: "10",
        psStatus: lockoutNum <= 10 ? "Pass" : "Review",
        checkId: "ENTRA-PASSWORD-003",
        remediation:
          "Run: Update-MgBetaDirectorySetting for Password Rule Settings with LockoutThreshold. Entra admin center > Protection > Password protection.",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, SETTINGS_NOT_CONFIGURED)) {
      // Tenant has never customized Entra password protection (#366 comment):
      // one Info item so the check appears rather than silently disappearing.
      ctx.addRow({
        category: "Password Management",
        setting: "Custom Banned Password Protection",
        currentValue: "Directory settings not configured (using Entra defaults)",
        recommendedValue: "Configured",
        psStatus: "Info",
        checkId: "ENTRA-PASSWORD-002",
        remediation:
          "Entra admin center > Protection > Authentication methods > Password protection. Configure a custom banned password list and smart lockout threshold.",
      });
    }
    // else: PS Write-Warning parity — zero rows.
  }

  // ------------------------------------------------------------------
  // 9. Password Expiration Policy (PS lines 389-412)
  // ------------------------------------------------------------------
  try {
    const domains = await ctx.transport.getJson(PASSWORD_AUTH_ENDPOINTS.domains, {
      requiredRole: "Domain.Read.All",
    });
    const domainList = asArray(domains.value);
    for (const domain of domainList) {
      if (!domain.isVerified) continue;
      const validityDays = domain.passwordValidityPeriodInDays;
      const neverExpires = validityDays === 2147483647;
      ctx.addRow({
        category: "Password Management",
        setting: `Password Expiration: ${psStr(domain.id)}`,
        currentValue: neverExpires ? "Never expires" : `${validityDays} days`,
        recommendedValue: "Never expires (with MFA)",
        psStatus: neverExpires ? "Pass" : "Fail",
        checkId: "ENTRA-PASSWORD-001",
        remediation:
          "Run: Update-MgDomain -DomainId {domain} -PasswordValidityPeriodInDays 2147483647. M365 admin center > Settings > Password expiration policy.",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }

  // ------------------------------------------------------------------
  // 20. Authenticator Fatigue Protection (PS lines 417-478)
  // ------------------------------------------------------------------
  try {
    if (sspr) {
      const authMethods = Array.isArray(sspr.authenticationMethodConfigurations)
        ? (sspr.authenticationMethodConfigurations as GraphObj[])
        : [];
      const authenticator = authMethods.find(
        (m) => m.id === "MicrosoftAuthenticator",
      );

      if (authenticator) {
        const featureSettings = authenticator.featureSettings;
        if (featureSettings !== null && featureSettings !== undefined) {
          const fs = featureSettings as GraphObj;
          const numberMatchState = fs.numberMatchingRequiredState as
            | GraphObj
            | undefined;
          const appInfoState = fs.displayAppInformationRequiredState as
            | GraphObj
            | undefined;
          // Absent numberMatchingRequiredState means enforced tenant-wide
          // since May 2023 (#998) — absence is ON, not failure.
          const numberMatch = numberMatchState
            ? psStr(numberMatchState.state)
            : "enforced (mandatory)";
          const appInfo = appInfoState
            ? psStr(appInfoState.state)
            : "not configured";
          // 'default' is the Microsoft-managed advancedConfigState (= on).
          const numberMatchOn = ["enabled", "enforced (mandatory)", "default"].includes(
            numberMatch,
          );
          const fatiguePassed = numberMatchOn && appInfo === "enabled";
          ctx.addRow({
            category: "Authentication Methods",
            setting: "Authenticator Fatigue Protection",
            currentValue: `Number matching: ${numberMatch}; App context: ${appInfo}`,
            recommendedValue: "Both enabled",
            psStatus: fatiguePassed ? "Pass" : "Fail",
            checkId: "ENTRA-AUTHMETHOD-003",
            remediation:
              "Entra admin center > Protection > Authentication methods > Microsoft Authenticator > Configure > Require number matching = Enabled, Show application name = Enabled.",
          });
        } else {
          ctx.addRow({
            category: "Authentication Methods",
            setting: "Authenticator Fatigue Protection",
            currentValue: "Feature settings not available for Microsoft Authenticator",
            recommendedValue: "Both enabled",
            psStatus: "Review",
            checkId: "ENTRA-AUTHMETHOD-003",
            remediation:
              "Verify Microsoft Authenticator feature settings in Entra admin center > Protection > Authentication methods > Microsoft Authenticator > Configure.",
          });
        }
      } else {
        ctx.addRow({
          category: "Authentication Methods",
          setting: "Authenticator Fatigue Protection",
          currentValue: "Microsoft Authenticator not configured",
          recommendedValue: "Both enabled",
          psStatus: "Review",
          checkId: "ENTRA-AUTHMETHOD-003",
          remediation:
            "Enable Microsoft Authenticator and configure number matching + application context display.",
        });
      }
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }

  // ------------------------------------------------------------------
  // 21. System-Preferred MFA (PS lines 483-507)
  // ------------------------------------------------------------------
  try {
    if (sspr) {
      const systemPreferred = sspr.systemCredentialPreferences as
        | GraphObj
        | undefined;
      // Absent or 'default' state means enabled (#999); only an explicit
      // 'disabled' fails.
      const sysState = systemPreferred
        ? psStr(systemPreferred.state)
        : "default (enabled)";
      const sysEnabled = ["enabled", "default", "default (enabled)"].includes(
        sysState,
      );
      ctx.addRow({
        category: "Authentication Methods",
        setting: "System-Preferred MFA",
        currentValue: sysState,
        recommendedValue: "enabled",
        psStatus: sysEnabled ? "Pass" : "Fail",
        checkId: "ENTRA-AUTHMETHOD-004",
        remediation:
          "Entra admin center > Protection > Authentication methods > Settings > System-preferred multifactor authentication > Enabled.",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }

  // ------------------------------------------------------------------
  // 27. Password Protection On-Premises (PS lines 512-567)
  // ------------------------------------------------------------------
  try {
    // Reuse $orgSettings from user-group-checks' LinkedIn fetch via the run
    // store. With the PS dot-source order it is ALWAYS null here (that file
    // runs later), so the null-guard branch below is the live path.
    const orgSettings = (ctx.shared.get("entra.orgSettings") as GraphObj) ?? null;

    let isCloudOnly: boolean | null = true;
    if (orgSettings && orgSettings.onPremisesSyncEnabled === true) {
      isCloudOnly = false;
    } else if (!orgSettings) {
      isCloudOnly = null; // Org data not available — fall through to normal check
    }

    if (isCloudOnly === true) {
      ctx.addRow({
        category: "Password Management",
        setting: "Password Protection On-Premises",
        currentValue: "Not applicable (cloud-only tenant)",
        recommendedValue: "True (if hybrid)",
        psStatus: "Info",
        checkId: "ENTRA-PASSWORD-005",
        remediation:
          "Not applicable for cloud-only tenants. If you configure hybrid identity in the future, enable on-premises password protection.",
      });
    } else if (pwSettings) {
      const values = Array.isArray(pwSettings.values)
        ? (pwSettings.values as GraphObj[])
        : [];
      const onPremEntry = values.find(
        (v) => v.name === "EnableBannedPasswordCheckOnPremises",
      );
      const onPremEnabled = onPremEntry ? onPremEntry.value : null;
      ctx.addRow({
        category: "Password Management",
        setting: "Password Protection On-Premises",
        currentValue: psStr(onPremEnabled),
        recommendedValue: "True",
        psStatus: onPremEnabled === "True" ? "Pass" : "Fail",
        checkId: "ENTRA-PASSWORD-005",
        remediation:
          "Entra admin center > Protection > Authentication methods > Password protection > Enable password protection on Windows Server Active Directory > Yes.",
      });
    } else {
      ctx.addRow({
        category: "Password Management",
        setting: "Password Protection On-Premises",
        currentValue: "Password Rule Settings not available",
        recommendedValue: "True",
        psStatus: "Review",
        checkId: "ENTRA-PASSWORD-005",
        remediation:
          "Entra admin center > Protection > Authentication methods > Password protection. Verify on-premises password protection is enabled.",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }

  // ------------------------------------------------------------------
  // 33. Password Hash Sync (PS lines 572-647)
  // ------------------------------------------------------------------
  try {
    const orgInfo = await ctx.transport.getJson(
      PASSWORD_AUTH_ENDPOINTS.organization,
      { requiredRole: "Organization.Read.All" },
    );
    const orgValue = asArray(orgInfo.value);
    const org = orgValue.length > 0 ? orgValue[0] : null;

    if (org === null) {
      ctx.addRow({
        category: "Hybrid Identity",
        setting: "Password Hash Sync",
        currentValue: "Organization data not available",
        recommendedValue: "Enabled (if hybrid)",
        psStatus: "Review",
        checkId: "ENTRA-HYBRID-001",
        remediation:
          "Verify Password Hash Sync status in Microsoft Entra Connect. Entra admin center > Identity > Hybrid management > Microsoft Entra Connect.",
      });
    } else {
      const onPremSync = org.onPremisesSyncEnabled;
      if (onPremSync === null || onPremSync === undefined || onPremSync === false) {
        // Cloud-only tenant, PHS not applicable.
        ctx.addRow({
          category: "Hybrid Identity",
          setting: "Password Hash Sync",
          currentValue: "Cloud-only tenant (no directory sync)",
          recommendedValue: "Enabled (if hybrid)",
          psStatus: "Info",
          checkId: "ENTRA-HYBRID-001",
          remediation:
            "Not applicable for cloud-only tenants. If you configure hybrid identity in the future, enable Password Hash Sync in Microsoft Entra Connect or Microsoft Entra Cloud Sync.",
        });
      } else {
        const phsEnabled = org.onPremisesLastPasswordSyncDateTime;
        if (phsEnabled) {
          ctx.addRow({
            category: "Hybrid Identity",
            setting: "Password Hash Sync",
            currentValue: `Enabled (last sync: ${psStr(phsEnabled)})`,
            recommendedValue: "Enabled",
            psStatus: "Pass",
            checkId: "ENTRA-HYBRID-001",
            remediation:
              "Password Hash Sync is enabled. Verify it remains active in Microsoft Entra Connect or Microsoft Entra Cloud Sync.",
          });
        } else {
          // Warning (not Fail): Cloud Sync may not populate this field, or PHS
          // was recently enabled with no password changes since.
          ctx.addRow({
            category: "Hybrid Identity",
            setting: "Password Hash Sync",
            currentValue:
              "Directory sync active - no PHS timestamp found; verify in Microsoft Entra Connect or Entra Cloud Sync",
            recommendedValue: "Enabled",
            psStatus: "Warning",
            checkId: "ENTRA-HYBRID-001",
            remediation:
              "Verify Password Hash Sync is enabled in Microsoft Entra Connect (Optional Features) or Microsoft Entra Cloud Sync. PHS provides leaked credential detection and backup authentication.",
          });
        }
      }
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity.
  }
};
