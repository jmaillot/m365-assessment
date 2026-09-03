/**
 * Data-driven section registry (D-10) — TS mirror of
 * `src/M365-Assess/Orchestrator/AssessmentMaps.ps1`.
 *
 * - requiredAppRoles are copied VERBATIM from $sectionScopeMap (lines 24–37).
 *   Downstream comparisons are case-insensitive (OrdinalIgnoreCase parity,
 *   Test-GraphPermissions.ps1:142). Domains with no scope-map entry (Email,
 *   PowerBI, ActiveDirectory) carry empty arrays.
 * - endpoints[] is the declared GET-path list — the single source of truth
 *   for the CI read-only allowlist gate (D-26, T-02-03a; enforced by
 *   __tests__/read-only-allowlist.test.ts). Dynamic segments are declared
 *   with a `{*}` placeholder — the same normalization the allowlist test
 *   applies to source template literals (`${...}` → `{*}`), so comparisons
 *   stay exact-string.
 * - implemented=true for Tenant/Identity/Licensing (wired by plan 02-12);
 *   unported sections still surface explicit not-yet-implemented errors in
 *   runEngine (D-10) and never fabricate rows.
 */
export interface SectionEntry {
  /** LowerCamel id, e.g. "identity" / "activeDirectory". */
  id: string;
  /** Display name mirroring AssessmentMaps $sectionServiceMap keys exactly. */
  displayName: string;
  /** Graph application permissions verbatim from AssessmentMaps $sectionScopeMap. */
  requiredAppRoles: string[];
  /** Declared GET paths — CI read-only allowlist source (D-26). */
  endpoints: string[];
  /** True once a SectionImplementation is wired in IMPLEMENTATIONS. */
  implemented: boolean;
}

export const SECTION_REGISTRY: readonly SectionEntry[] = [
  {
    id: "tenant",
    displayName: "Tenant",
    requiredAppRoles: [
      "Organization.Read.All",
      "Domain.Read.All",
      "Policy.Read.All",
      "User.Read.All",
      "Group.Read.All",
    ],
    // TENANT_INFO_ENDPOINTS (02-05)
    endpoints: [
      "/v1.0/domains",
      "/v1.0/organization",
      "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
    ],
    implemented: true,
  },
  {
    id: "identity",
    displayName: "Identity",
    requiredAppRoles: [
      "User.Read.All",
      "AuditLog.Read.All",
      "UserAuthenticationMethod.Read.All",
      "RoleManagement.Read.Directory",
      "Policy.Read.All",
      "Application.Read.All",
      "Domain.Read.All",
      "Directory.Read.All",
      "Agreement.Read.All",
    ],
    // Merged from collector plans 02-05..02-10 (deduped, sorted):
    // user-summary, mfa-report, admin-role-report, conditional-access-report,
    // app-registration-report, password-policy-report, entra-security-config
    // composite (password-auth-checks + admin-role-checks +
    // conditional-access-checks + user-group-checks), ca-security-config,
    // ent-app-security-config, entra-sod-config, entra-tou-config,
    // entra-priv-remote, entra-admin-role-separation, entra-ca-remote-device.
    endpoints: [
      "/v1.0/agreements",
      "/v1.0/applications",
      "/v1.0/applications?$select=id,appId,displayName,signInAudience,web,spa,publicClient&$top=999",
      "/v1.0/applications?$select=id,displayName,appId,createdDateTime,signInAudience,passwordCredentials,keyCredentials",
      "/v1.0/applications?$select=id,displayName,requiredResourceAccess&$top=999",
      "/v1.0/auditLogs/signIns",
      "/v1.0/directory/administrativeUnits",
      "/v1.0/directoryRoles",
      "/v1.0/directoryRoles?$filter=displayName%20eq%20%27Global%20Administrator%27",
      "/v1.0/directoryRoles?$filter=roleTemplateId eq '{*}'",
      "/v1.0/directoryRoles?$filter=roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'",
      "/v1.0/directoryRoles(roleTemplateId='{*}')/members",
      "/v1.0/directoryRoles/roleTemplateId={*}/members?$select=displayName,assignedLicenses",
      "/v1.0/directoryRoles/roleTemplateId={*}/members?$select=displayName,userPrincipalName,onPremisesSyncEnabled",
      "/v1.0/directoryRoles/roleTemplateId={*}/members?$select=id,displayName,userPrincipalName",
      "/v1.0/directoryRoles/{*}/members",
      "/v1.0/directoryRoles/{*}/members?$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled",
      "/v1.0/domains",
      "/v1.0/groups",
      "/v1.0/groups?$filter=groupTypes/any(g:g%20eq%20%27DynamicMembership%27)&$select=displayName,membershipRule&$top=999",
      "/v1.0/groups?$filter=groupTypes/any(g:g%20eq%20%27Unified%27)&$select=displayName,id,visibility&$top=999",
      "/v1.0/groups?$select=id,displayName,groupTypes,isAssignableToRole&$top=999",
      "/v1.0/groups/{*}/owners?$select=id",
      "/v1.0/groups/{*}?$select=id",
      "/v1.0/identity/conditionalAccess/namedLocations",
      "/v1.0/identity/conditionalAccess/policies",
      "/v1.0/identityGovernance/accessReviews/definitions?$top=100",
      "/v1.0/oauth2PermissionGrants?$filter=consentType%20eq%20%27AllPrincipals%27&$top=999",
      "/v1.0/oauth2PermissionGrants?$top=999",
      "/v1.0/organization",
      "/v1.0/organization/{*}",
      "/v1.0/policies/activityBasedTimeoutPolicies",
      "/v1.0/policies/adminConsentRequestPolicy",
      "/v1.0/policies/authenticationMethodsPolicy",
      "/v1.0/policies/authorizationPolicy",
      "/v1.0/policies/crossTenantAccessPolicy/default",
      "/v1.0/policies/defaultAppManagementPolicy",
      "/v1.0/policies/deviceRegistrationPolicy",
      "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
      "/v1.0/policies/roleManagementPolicyAssignments",
      "/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '{*}'&$expand=policy($expand=rules)",
      "/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId%20eq%20%27/%27%20and%20scopeType%20eq%20%27DirectoryRole%27%20and%20roleDefinitionId%20eq%20%27{*}%27&$expand=policy($expand=rules)",
      "/v1.0/reports/authenticationMethods/userRegistrationDetails",
      "/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isMfaRegistered&$top=999",
      "/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isMfaRegistered,isMfaCapable&$top=1",
      "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
      "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27",
      "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27&$top=999&$expand=principal",
      "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%27e8611ab8-c189-46e8-94e1-60213ab1f814%27&$top=999&$expand=principal",
      "/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%27{*}%27&$top=999",
      "/v1.0/roleManagement/directory/roleAssignments?$top=999",
      "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId%20eq%20%2762e90394-69f5-4237-9190-012177145e10%27",
      "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId%20eq%20%27{*}%27",
      "/v1.0/servicePrincipals/{*}/appRoleAssignedTo?$top=999",
      "/v1.0/servicePrincipals/{*}/owners?$select=id",
      "/v1.0/servicePrincipals/{*}/owners?$select=id,displayName",
      "/v1.0/servicePrincipals/{*}?$select=signInActivity",
      "/v1.0/servicePrincipals?$filter=appId%20eq%20%2700000003-0000-0000-c000-000000000000%27&$select=id,appRoles,oauth2PermissionScopes",
      "/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,keyCredentials,passwordCredentials,accountEnabled&$top=999",
      "/v1.0/settings",
      "/v1.0/subscribedSkus",
      "/v1.0/users",
      "/v1.0/users/$count?$filter=accountEnabled%20eq%20false%20and%20userType%20eq%20%27Member%27",
      "/v1.0/users/$count?$filter=userType%20eq%20%27Guest%27",
      "/v1.0/users/$count?$filter=userType%20eq%20%27Member%27",
      "/v1.0/users?$filter=onPremisesSyncEnabled eq true&$select=id,displayName,userPrincipalName,onPremisesSyncEnabled&$top=999",
      "/v1.0/users/{*}/licenseDetails",
      "/v1.0/users/{*}?$select=onPremisesSyncEnabled",
      "/v1.0/users/{*}?$select=userPrincipalName",
      "/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,assignedLicenses,onPremisesSyncEnabled&$top=999",
      "/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,assignedLicenses,onPremisesSyncEnabled,signInActivity&$top=999",
    ],
    implemented: true,
  },
  {
    id: "licensing",
    displayName: "Licensing",
    requiredAppRoles: ["Organization.Read.All", "User.Read.All"],
    // LICENSE_REPORT_ENDPOINTS (02-06)
    endpoints: ["/v1.0/subscribedSkus"],
    implemented: true,
  },
  {
    id: "email",
    displayName: "Email",
    requiredAppRoles: [],
    endpoints: [],
    implemented: false,
  },
  {
    id: "exchange",
    displayName: "Exchange",
    requiredAppRoles: [
      "Organization.Read.All",
      "Directory.Read.All",
      "User.Read.All",
    ],
    // EXCHANGE_SECURITY_CONFIG_ENDPOINTS + DNS_SECURITY_CONFIG_ENDPOINTS (05-01)
    endpoints: [
      "/v1.0/organization",
      "/v1.0/organization/{*}?$select=verifiedDomains,displayName",
      "/v1.0/subscribedSkus",
      "/v1.0/users?$select=accountEnabled,userPrincipalName,displayName&$top=100",
      "/v1.0/domains",
      // D-27 beta keep — see BETA-ENDPOINTS.md
      "/beta/admin/exchange/settings",
    ],
    implemented: true,
  },
  {
    id: "intune",
    displayName: "Intune",
    requiredAppRoles: [
      "DeviceManagementManagedDevices.Read.All",
      "DeviceManagementConfiguration.Read.All",
      "DeviceManagementServiceConfig.Read.All",
    ],
    endpoints: [
      "/v1.0/deviceManagement/managedDevices",
      "/v1.0/deviceManagement/deviceConfigurations",
      "/v1.0/deviceManagement/deviceConfigurations?$expand=assignments",
      "/v1.0/deviceManagement/deviceCompliancePolicies",
      "/v1.0/deviceManagement/settings",
      "/beta/deviceManagement/deviceEnrollmentConfigurations",
      "/v1.0/deviceManagement/deviceEnrollmentConfigurations",
      "/v1.0/deviceManagement/windowsAutopilotDeploymentProfiles",
    ],
    implemented: true,
  },
  {
    id: "security",
    displayName: "Security",
    requiredAppRoles: [
      "SecurityEvents.Read.All",
      "ThreatIntelligence.Read.All",
      "AuditLog.Read.All",
      "InformationProtectionPolicy.Read.All",
      "SecurityAlert.Read.All",
    ],
    endpoints: [
      "/v1.0/security/secureScores?$top=180",
      "/v1.0/security/secureScores",
      "/v1.0/security/secureScoreControlProfiles?$top=250",
      "/v1.0/security/secureScoreControlProfiles",
      "/v1.0/auditLogs/directoryAudits?$top=1",
      "/v1.0/informationProtection/sensitivityLabels",
      "/v1.0/security/alerts_v2?$top=100",
    ],
    implemented: true,
  },
  {
    id: "collaboration",
    displayName: "Collaboration",
    requiredAppRoles: [
      "SharePointTenantSettings.Read.All",
      "TeamSettings.Read.All",
      "TeamworkAppSettings.Read.All",
      "OrgSettings-Forms.Read.All",
    ],
    // SHAREPOINT_SECURITY_CONFIG_ENDPOINTS + TEAMS_SECURITY_CONFIG_ENDPOINTS + FORMS_SECURITY_CONFIG_ENDPOINTS (05-01)
    endpoints: [
      "/v1.0/admin/forms/settings",
      "/v1.0/admin/sharepoint/settings",
      "/v1.0/groupSettings",
      "/v1.0/sites?$select=id,displayName,sharingCapability,webUrl&$top=100",
      "/v1.0/teamwork",
    ],
    implemented: true,
  },
  {
    id: "purview",
    displayName: "Purview",
    requiredAppRoles: ["RecordsManagement.Read.All"],
    // PURVIEW_RETENTION_CONFIG_ENDPOINTS (06-01)
    endpoints: ["/v1.0/security/labels/retentionLabels?$top=250"],
    implemented: true,
  },
  {
    id: "powerbi",
    displayName: "PowerBI",
    requiredAppRoles: [],
    // POWERBI_SECURITY_CONFIG_ENDPOINTS (06-01) — Power BI admin API is
    // https://api.powerbi.com/v1.0/myorg/admin/* with resource
    // https://analysis.windows.net/powerbi/api, not Graph — no Graph app role
    // required. Collector handles NotLicensed fail-soft via Tenant.Read.All
    // probe tolerance; keep Graph role empty so verify doesn't block.
    endpoints: ["/v1.0/myorg/admin/tenantSettings"],
    implemented: true,
  },
  {
    id: "hybrid",
    displayName: "Hybrid",
    requiredAppRoles: ["Organization.Read.All", "Domain.Read.All"],
    endpoints: [],
    implemented: false,
  },
  {
    id: "inventory",
    displayName: "Inventory",
    requiredAppRoles: ["Directory.Read.All", "Sites.Read.All"],
    // Deduped union of MAILBOX/ONEDRIVE/SHAREPOINT/TEAMS/GROUP inventory endpoints (06-01)
    endpoints: [
      "/v1.0/drives?$select=id,name,driveType,owner,quota,webUrl,createdDateTime,lastModifiedDateTime&$top=999",
      "/v1.0/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName,description,visibility,createdDateTime,mail&$top=999",
      "/v1.0/groups?$select=id,displayName,mail,groupTypes,mailEnabled,securityEnabled,visibility,createdDateTime&$top=999",
      "/v1.0/groups?$select=id,displayName,mail,mailEnabled,securityEnabled,groupTypes,createdDateTime&$top=999",
      "/v1.0/sites/getAllSites?$select=id,displayName,webUrl,createdDateTime,lastModifiedDateTime&$top=999",
      "/v1.0/sites?$select=id,displayName,webUrl,createdDateTime&$top=999",
      "/v1.0/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime&$top=999",
    ],
    implemented: true,
  },
  {
    id: "activeDirectory",
    displayName: "ActiveDirectory",
    requiredAppRoles: [],
    endpoints: [],
    implemented: false,
  },
  {
    id: "soc2",
    displayName: "SOC2",
    requiredAppRoles: [
      "Policy.Read.All",
      "RoleManagement.Read.Directory",
      "SecurityEvents.Read.All",
      "SecurityAlert.Read.All",
      "AuditLog.Read.All",
      "User.Read.All",
      "Reports.Read.All",
      "Directory.Read.All",
    ],
    endpoints: [],
    implemented: false,
  },
  {
    id: "valueOpportunity",
    displayName: "ValueOpportunity",
    requiredAppRoles: ["Organization.Read.All"],
    endpoints: [],
    implemented: false,
  },
];

/** Resolve one registry entry by id (case-insensitive); throws on unknown ids. */
export function getSection(id: string): SectionEntry {
  const entry = SECTION_REGISTRY.find(
    (e) => e.id.toLowerCase() === id.toLowerCase(),
  );
  if (!entry) {
    throw new Error(`Unknown section: ${id}`);
  }
  return entry;
}
