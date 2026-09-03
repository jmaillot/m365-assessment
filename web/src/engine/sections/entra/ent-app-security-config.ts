/**
 * Port of `src/M365-Assess/Entra/Get-EntAppSecurityConfig.ps1` (1,150 lines)
 * — AssessmentMaps Identity entry '07d-EntApp-Security-Config' (plan 02-10).
 *
 * Evaluates enterprise application / service principal security posture:
 * credentials, foreign-app permission tiers (tier0-permissions.json), delegated
 * grants, directory roles, managed identities, owners, and app-registration
 * redirect hygiene — one row per CheckId base.
 *
 * PS → TS mapping:
 * - Initialize-SecurityConfig / Add-Setting / Export-SecurityConfigReport:
 *   owned by the runner's addRow pipeline (mapStatus → sub-numbering → D-22).
 * - Invoke-MgGraphRequest / Invoke-SafeGraphRequest GETs → ctx.transport.getJson
 *   declaring per-call requiredRole from the PS section scope
 *   (Application.Read.All / Directory.Read.All / RoleManagement.Read.Directory).
 * - Script-scope fetch state ($tenantId, $allServicePrincipals, $spRoleAssignments,
 *   $graphPermissionMap, $spOAuth2Map, $spAppRoleMap, $allAppRegistrations) →
 *   invocation-local variables; the PS helper functions
 *   (Test-MicrosoftFirstPartyApp, Get-SpTierPermissionFindings,
 *   Get-SpAppRoleAssignments, Get-SpOAuth2Grants) become closures over those
 *   locals with zero additional Graph calls, exactly as PS.
 * - Tier classification + Microsoft first-party allowlist load from the same
 *   bundled control files PS reads (controls/tier0-permissions.json,
 *   controls/microsoft-first-party-appids.json); unreadable file → PS inline
 *   fallback lists preserved verbatim.
 * - Soft-fail semantics preserved per check: catch blocks degrade exactly like
 *   PS Write-Warning/Write-Verbose (skip the row or emit the empty-data branch),
 *   never a section error; TransportFatalError still propagates.
 * - Evidence PSCustomObjects (checks 003/011/004/005) intentionally dropped —
 *   no freeform-evidence slot in CheckRowInput and no decision consumes them
 *   (same disposition as plans 02-07/02-09).
 * - PS case-insensitive string operators (-in/-eq/-ne/-match/-like) are ported
 *   as explicit lowercased comparisons/regexes.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
import type { SectionImplementation } from "@/engine/runner/engine";
import type { CheckRowInput, PsStatus } from "@/engine/results/row-contract";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const ENT_APP_SECURITY_CONFIG_ENDPOINTS = {
  organization: "/v1.0/organization",
  servicePrincipals:
    "/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,keyCredentials,passwordCredentials,accountEnabled&$top=999",
  roleAssignments: "/v1.0/roleManagement/directory/roleAssignments?$top=999",
  graphSp:
    "/v1.0/servicePrincipals?$filter=appId%20eq%20%2700000003-0000-0000-c000-000000000000%27&$select=id,appRoles,oauth2PermissionScopes",
  oauth2Grants: "/v1.0/oauth2PermissionGrants?$top=999",
  applications:
    "/v1.0/applications?$select=id,appId,displayName,signInAudience,web,spa,publicClient&$top=999",
  defaultAppManagementPolicy: "/v1.0/policies/defaultAppManagementPolicy",
} as const;

/** Per-SP signInActivity probe (check 002; PS line 347). */
export function spSignInActivityUrl(spId: string): string {
  return `/v1.0/servicePrincipals/${spId}?$select=signInActivity`;
}

/** Owners probe used by checks 016/017 (PS lines 836/875). */
export function spOwnersUrl(spId: string): string {
  return `/v1.0/servicePrincipals/${spId}/owners?$select=id,displayName`;
}

/** Owners probe used by check 018 (id-only select, PS line 916). */
export function spOwnersIdOnlyUrl(spId: string): string {
  return `/v1.0/servicePrincipals/${spId}/owners?$select=id`;
}

/** Resource-side app-role grants on the Microsoft Graph SP (PS line 263). */
export function graphSpAppRoleAssignedToUrl(graphSpId: string): string {
  return `/v1.0/servicePrincipals/${graphSpId}/appRoleAssignedTo?$top=999`;
}

type GraphObj = Record<string, unknown>;

const APPLICATION_READ_ALL = "Application.Read.All";
const DIRECTORY_READ_ALL = "Directory.Read.All";
const ROLE_MGMT_READ_DIRECTORY = "RoleManagement.Read.Directory";
const POLICY_READ_ALL = "Policy.Read.All";

/** PS inline fallback when tier0-permissions.json is absent (lines 62-74). */
const FALLBACK_TIER0 = [
  "RoleManagement.ReadWrite.Directory",
  "AppRoleAssignment.ReadWrite.All",
  "Application.ReadWrite.All",
  "Directory.ReadWrite.All",
  "User.ReadWrite.All",
  "Group.ReadWrite.All",
];
const FALLBACK_TIER1 = [
  "Mail.ReadWrite",
  "Mail.Send",
  "Files.ReadWrite.All",
  "Sites.FullControl.All",
];

/** Historical 4-tenant allowlist fallback (PS lines 111-120). */
const FALLBACK_FIRST_PARTY_TENANTS = [
  "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
  "72f988bf-86f1-41af-91ab-2d7cd011db47",
  "ea8a4392-515e-481f-879e-6571ff2a8a36",
  "cdc5aeea-15c5-4db6-b079-fcadd2505dc2",
];

/** Dangerous DELEGATED permissions — hardcoded in PS (lines 79-86), not data-driven. */
const DANGEROUS_DELEGATED_PERMISSIONS = [
  "Directory.ReadWrite.All",
  "RoleManagement.ReadWrite.Directory",
  "Mail.ReadWrite",
  "Files.ReadWrite.All",
  "User.ReadWrite.All",
  "AppRoleAssignment.ReadWrite.All",
];

function repoRoot(): string {
  try {
    // web/src/engine/sections/entra/ent-app-security-config.ts → up 5 = repo root.
    return fileURLToPath(new URL("../../../../..", import.meta.url));
  } catch {
    return resolve(process.cwd(), "..");
  }
}

/**
 * Tiered application-permission classification from the bundled
 * controls/tier0-permissions.json (same file PS reads at lines 54-74);
 * unreadable/absent file degrades to PS's inline fallback lists.
 */
export function loadTieredPermissions(): { tier0: string[]; tier1: string[] } {
  try {
    const parsed = JSON.parse(
      readFileSync(
        join(repoRoot(), "src", "M365-Assess", "controls", "tier0-permissions.json"),
        "utf8",
      ),
    ) as GraphObj;
    const tier0 = Array.isArray(parsed.permissions)
      ? (parsed.permissions as GraphObj[])
          .map((p) => p.permission)
          .filter((p): p is string => typeof p === "string")
      : [];
    const tier1 = Array.isArray(parsed.tier1DataAccess)
      ? (parsed.tier1DataAccess as unknown[]).filter(
          (p): p is string => typeof p === "string",
        )
      : [];
    if (tier0.length === 0 && tier1.length === 0) {
      return { tier0: FALLBACK_TIER0, tier1: FALLBACK_TIER1 };
    }
    return { tier0, tier1 };
  } catch {
    return { tier0: FALLBACK_TIER0, tier1: FALLBACK_TIER1 };
  }
}

/**
 * Microsoft first-party allowlist from the bundled
 * controls/microsoft-first-party-appids.json (PS lines 98-110); parse failure
 * yields an empty appIds list and the historical tenant-ID fallback applies.
 */
export function loadMicrosoftFirstPartyAllowlist(): { appIds: string[]; tenantIds: string[] } {
  try {
    const parsed = JSON.parse(
      readFileSync(
        join(repoRoot(), "src", "M365-Assess", "controls", "microsoft-first-party-appids.json"),
        "utf8",
      ),
    ) as GraphObj;
    return {
      appIds: Array.isArray(parsed.appIds)
        ? (parsed.appIds as GraphObj[])
            .map((a) => a.appId)
            .filter((a): a is string => typeof a === "string")
        : [],
      tenantIds: Array.isArray(parsed.ownerTenantIds)
        ? (parsed.ownerTenantIds as GraphObj[])
            .map((t) => t.id)
            .filter((t): t is string => typeof t === "string")
        : [],
    };
  } catch {
    return { appIds: [], tenantIds: [] };
  }
}

/** Treat non-array credential collections as absent (PS @($null)-guard parity). */
function credList(value: unknown): GraphObj[] {
  return Array.isArray(value) ? (value as GraphObj[]) : [];
}

function hasEntries(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0;
}

/** Case-insensitive equality for PS `-eq`/`-in`/`-ne` parity. */
function equalsCI(a: unknown, b: string): boolean {
  return typeof a === "string" && a.toLowerCase() === b.toLowerCase();
}

/** Collect redirectUris across the given app-property buckets
 * (PS lines 995-998 / 1029-1031 / 1062-1064). */
function redirectUrisOf(
  app: GraphObj,
  buckets: readonly ("web" | "spa" | "publicClient")[],
): string[] {
  const uris: string[] = [];
  for (const bucket of buckets) {
    const holder = app[bucket] as GraphObj | null | undefined;
    const list = holder?.["redirectUris"];
    if (Array.isArray(list)) {
      for (const uri of list) {
        if (typeof uri === "string") uris.push(uri);
      }
    }
  }
  return uris;
}

interface LadderRow {
  category: string;
  setting: string;
  currentValue: string;
  recommendedValue: string;
  status: PsStatus;
  checkId: string;
  remediation: string;
}

/** PS `$settingParams = @{...}; Add-Setting @settingParams` shape. */
function row(ladder: LadderRow): CheckRowInput {
  const { status, ...rest } = ladder;
  return { ...rest, psStatus: status };
}

export const runEntAppSecurityConfig: SectionImplementation = async (ctx) => {
  // ------------------------------------------------------------------
  // Dangerous permissions — loaded from tiered classification file
  // (PS lines 51-86)
  // ------------------------------------------------------------------
  const { tier0: tier0AppPermissions, tier1: tier1AppPermissions } =
    loadTieredPermissions();
  const dangerousAppPermissions = [...tier0AppPermissions, ...tier1AppPermissions];
  void dangerousAppPermissions; // combined list exists for parity documentation; sets below drive checks
  const tier0Set = new Set(tier0AppPermissions.map((p) => p.toLowerCase()));
  const tier1Set = new Set(tier1AppPermissions.map((p) => p.toLowerCase()));
  const dangerousSet = new Set(dangerousAppPermissions.map((p) => p.toLowerCase()));
  const dangerousDelegatedSet = new Set(
    DANGEROUS_DELEGATED_PERMISSIONS.map((p) => p.toLowerCase()),
  );

  // ------------------------------------------------------------------
  // Microsoft first-party allowlist (#1001; PS lines 88-127)
  // ------------------------------------------------------------------
  const loadedAllowlist = loadMicrosoftFirstPartyAllowlist();
  const msFirstPartyTenantIds =
    loadedAllowlist.tenantIds.length > 0
      ? loadedAllowlist.tenantIds
      : FALLBACK_FIRST_PARTY_TENANTS;
  const msFirstPartyAppIdSet = new Set(loadedAllowlist.appIds.map((a) => a.toLowerCase()));
  const msFirstPartyTenantIdSet = new Set(msFirstPartyTenantIds.map((t) => t.toLowerCase()));

  // ------------------------------------------------------------------
  // Fetch tenant organization ID for foreign app detection (PS 151-163)
  // ------------------------------------------------------------------
  let tenantId: string | null = null;
  try {
    const orgResponse = await ctx.transport.getJson(
      ENT_APP_SECURITY_CONFIG_ENDPOINTS.organization,
      { requiredRole: DIRECTORY_READ_ALL },
    );
    const firstOrg = asArray(orgResponse.value)[0];
    if (firstOrg && typeof firstOrg["id"] === "string") tenantId = firstOrg["id"];
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity — tenant id stays null.
  }

  // ------------------------------------------------------------------
  // Fetch all service principals (PS 165-180)
  // ------------------------------------------------------------------
  let allServicePrincipals: GraphObj[] = [];
  try {
    const spResponse = await ctx.transport.getJson(
      ENT_APP_SECURITY_CONFIG_ENDPOINTS.servicePrincipals,
      { requiredRole: APPLICATION_READ_ALL },
    );
    allServicePrincipals = asArray(spResponse.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    allServicePrincipals = [];
  }

  // Separate regular apps from managed identities (PS 182-184; PS -ne is CI).
  const regularApps = allServicePrincipals.filter(
    (sp) => !equalsCI(sp["servicePrincipalType"], "ManagedIdentity"),
  );
  const managedIdentities = allServicePrincipals.filter((sp) =>
    equalsCI(sp["servicePrincipalType"], "ManagedIdentity"),
  );

  // ------------------------------------------------------------------
  // Fetch role assignments for all SPs (directory roles; PS 186-207)
  // ------------------------------------------------------------------
  const spRoleAssignments = new Map<string, GraphObj[]>();
  try {
    const roleResponse = await ctx.transport.getJson(
      ENT_APP_SECURITY_CONFIG_ENDPOINTS.roleAssignments,
      { requiredRole: ROLE_MGMT_READ_DIRECTORY },
    );
    for (const assignment of asArray(roleResponse.value)) {
      const principalId = assignment["principalId"];
      if (typeof principalId !== "string") continue;
      const existing = spRoleAssignments.get(principalId);
      if (existing) existing.push(assignment);
      else spRoleAssignments.set(principalId, [assignment]);
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    spRoleAssignments.clear();
  }

  // ------------------------------------------------------------------
  // Well-known Graph permission IDs → names lookup (PS 209-229)
  // ------------------------------------------------------------------
  const graphPermissionMap = new Map<string, { name: string; type: string }>();
  let graphSpValue: GraphObj | null = null;
  try {
    const graphSp = await ctx.transport.getJson(ENT_APP_SECURITY_CONFIG_ENDPOINTS.graphSp, {
      requiredRole: APPLICATION_READ_ALL,
    });
    graphSpValue = asArray(graphSp.value)[0] ?? null;
    if (graphSpValue) {
      for (const roleRec of credList(graphSpValue["appRoles"])) {
        if (typeof roleRec["id"] === "string") {
          graphPermissionMap.set(roleRec["id"], {
            name: String(roleRec["value"] ?? ""),
            type: "Application",
          });
        }
      }
      for (const scopeRec of credList(graphSpValue["oauth2PermissionScopes"])) {
        if (typeof scopeRec["id"] === "string") {
          graphPermissionMap.set(scopeRec["id"], {
            name: String(scopeRec["value"] ?? ""),
            type: "Delegated",
          });
        }
      }
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    graphSpValue = null;
  }

  // ------------------------------------------------------------------
  // Bulk-fetch oauth2PermissionGrants (PS 231-250)
  // ------------------------------------------------------------------
  const spOAuth2Map = new Map<string, GraphObj[]>();
  try {
    const oauthResponse = await ctx.transport.getJson(
      ENT_APP_SECURITY_CONFIG_ENDPOINTS.oauth2Grants,
      { requiredRole: DIRECTORY_READ_ALL },
    );
    for (const grant of asArray(oauthResponse.value)) {
      const clientId = grant["clientId"];
      if (typeof clientId !== "string") continue;
      const existing = spOAuth2Map.get(clientId);
      if (existing) existing.push(grant);
      else spOAuth2Map.set(clientId, [grant]);
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    spOAuth2Map.clear();
  }

  // ------------------------------------------------------------------
  // Bulk-fetch appRoleAssignments from the RESOURCE side (PS 252-277).
  // PS reads $graphSpValue['id'] even when null (null-indexing → falsy skip).
  // ------------------------------------------------------------------
  const spAppRoleMap = new Map<string, GraphObj[]>();
  try {
    const graphSpIdValue =
      graphSpValue && typeof graphSpValue["id"] === "string"
        ? (graphSpValue["id"] as string)
        : null;
    if (graphSpIdValue) {
      const araResponse = await ctx.transport.getJson(
        graphSpAppRoleAssignedToUrl(graphSpIdValue),
        { requiredRole: APPLICATION_READ_ALL },
      );
      for (const a of asArray(araResponse.value)) {
        const principalId = a["principalId"];
        if (typeof principalId !== "string") continue;
        const existing = spAppRoleMap.get(principalId);
        if (existing) existing.push(a);
        else spAppRoleMap.set(principalId, [a]);
      }
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    spAppRoleMap.clear();
  }

  // ------------------------------------------------------------------
  // Fetch app registrations (PS 279-292)
  // ------------------------------------------------------------------
  let allAppRegistrations: GraphObj[] = [];
  try {
    const appResponse = await ctx.transport.getJson(
      ENT_APP_SECURITY_CONFIG_ENDPOINTS.applications,
      { requiredRole: APPLICATION_READ_ALL },
    );
    allAppRegistrations = asArray(appResponse.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    allAppRegistrations = [];
  }

  // ------------------------------------------------------------------
  // Helpers over cached maps — zero API calls (PS 294-307, 122-149)
  // ------------------------------------------------------------------
  const getSpAppRoleAssignments = (spId: unknown): GraphObj[] =>
    typeof spId === "string" ? (spAppRoleMap.get(spId) ?? []) : [];

  const getSpOAuth2Grants = (spId: unknown): GraphObj[] =>
    typeof spId === "string" ? (spOAuth2Map.get(spId) ?? []) : [];

  // Test-MicrosoftFirstPartyApp (PS 123-127): AppId primary, owner-tenant secondary.
  const isFirstPartyApp = (sp: GraphObj): boolean => {
    const appId = sp["appId"];
    const owner = sp["appOwnerOrganizationId"];
    return (
      (typeof appId === "string" && msFirstPartyAppIdSet.has(appId.toLowerCase())) ||
      (typeof owner === "string" && msFirstPartyTenantIdSet.has(owner.toLowerCase()))
    );
  };

  // Get-SpTierPermissionFindings (PS 129-149): "DisplayName: Permission" strings.
  const tierFindings = (sp: GraphObj): { tier0: string[]; tier1: string[] } => {
    const tier0: string[] = [];
    const tier1: string[] = [];
    const displayName = String(sp["displayName"] ?? "");
    for (const roleRec of getSpAppRoleAssignments(sp["id"])) {
      const permId = roleRec["appRoleId"];
      const mapped = typeof permId === "string" ? graphPermissionMap.get(permId) : undefined;
      if (!mapped) continue;
      const permNameLower = mapped.name.toLowerCase();
      if (tier0Set.has(permNameLower)) tier0.push(`${displayName}: ${mapped.name}`);
      else if (tier1Set.has(permNameLower)) tier1.push(`${displayName}: ${mapped.name}`);
    }
    return { tier0, tier1 };
  };

  /** Apps with any credential, enabled only — reused by checks 001 and 002
   * (PS script-scope persistence of $appsWithCreds, lines 314-318 → 345). */
  const enabledAppsWithCreds = regularApps.filter(
    (sp) =>
      sp["accountEnabled"] === true &&
      (hasEntries(sp["keyCredentials"]) || hasEntries(sp["passwordCredentials"])),
  );

  // Foreign apps partition (PS 375-391).
  let foreignApps: GraphObj[] = [];
  if (tenantId) {
    foreignApps = regularApps.filter(
      (sp) =>
        typeof sp["appOwnerOrganizationId"] === "string" &&
        sp["appOwnerOrganizationId"] !== tenantId &&
        sp["accountEnabled"] === true,
    );
  }
  const msFirstPartyForeignApps = foreignApps.filter(isFirstPartyApp);
  const thirdPartyForeignApps = foreignApps.filter((sp) => !isFirstPartyApp(sp));

  // ------------------------------------------------------------------
  // 1. ENTRA-ENTAPP-001: Enabled apps with client credentials (PS 309-333)
  // ------------------------------------------------------------------
  try {
    ctx.addRow(
      row({
        category: "Enterprise Applications",
        setting: "Apps with Client Credentials",
        currentValue: `${enabledAppsWithCreds.length} enabled app(s) have secrets or certificates`,
        recommendedValue: "Review all apps with credentials; remove unused",
        status:
          enabledAppsWithCreds.length === 0
            ? "Pass"
            : enabledAppsWithCreds.length <= 10
              ? "Info"
              : "Warning",
        checkId: "ENTRA-ENTAPP-001",
        remediation:
          "Entra admin center > Enterprise applications > review each app with credentials. Remove secrets/certificates from apps that no longer need them.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 2. ENTRA-ENTAPP-002: Inactive apps with credentials (PS 335-372).
  // Cutoff rendered from UTC parts (PS local-time rendering is not
  // cross-machine deterministic — precedent plan 02-05 EarliestExpiry).
  // ------------------------------------------------------------------
  try {
    const cutoffDate =
      new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().slice(0, 19) + "Z";
    const inactiveWithCreds: string[] = [];

    for (const sp of enabledAppsWithCreds) {
      try {
        const signInData = await ctx.transport.getJson(
          spSignInActivityUrl(String(sp["id"])),
          { requiredRole: APPLICATION_READ_ALL },
        );
        const activity = signInData["signInActivity"] as GraphObj | null | undefined;
        const lastSignIn =
          activity && typeof activity["lastSignInDateTime"] === "string"
            ? (activity["lastSignInDateTime"] as string)
            : null;
        // PS compares ISO strings lexically ($lastSignIn -lt $cutoffDate).
        if (!lastSignIn || lastSignIn < cutoffDate) {
          inactiveWithCreds.push(String(sp["displayName"]));
        }
      } catch (probeErr) {
        if (probeErr instanceof TransportFatalError) throw probeErr;
        // PS Write-Verbose parity — probe failures leave the SP out.
      }
    }

    ctx.addRow(
      row({
        category: "Enterprise Applications",
        setting: "Inactive Apps with Credentials",
        currentValue:
          inactiveWithCreds.length === 0
            ? "No inactive apps with credentials found"
            : `${inactiveWithCreds.length} app(s) inactive > 90 days with credentials`,
        recommendedValue: "Remove credentials from inactive apps",
        status: inactiveWithCreds.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-ENTAPP-002",
        remediation:
          "Review the following inactive apps and remove their credentials or disable them: Entra admin center > Enterprise applications > filter by last sign-in > remove secrets/certificates.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 3. ENTRA-ENTAPP-003 (+011): Foreign apps with Tier 0/Tier 1 application
  // permissions (PS 393-449)
  // ------------------------------------------------------------------
  try {
    const foreignTier0: string[] = [];
    const foreignTier1: string[] = [];
    for (const sp of thirdPartyForeignApps) {
      const hits = tierFindings(sp);
      foreignTier0.push(...hits.tier0);
      foreignTier1.push(...hits.tier1);
    }

    const msFpTier0: string[] = [];
    const msFpTier1: string[] = [];
    for (const sp of msFirstPartyForeignApps) {
      const hits = tierFindings(sp);
      msFpTier0.push(...hits.tier0);
      msFpTier1.push(...hits.tier1);
    }

    // Tier 0 findings (Critical -- escalation paths)
    let tier0Current =
      foreignTier0.length === 0
        ? "No third-party apps with Tier 0 permissions"
        : `${foreignTier0.length} finding(s): ${foreignTier0.join("; ")}`;
    if (msFpTier0.length > 0) {
      tier0Current += ` | ${msFpTier0.length} Microsoft first-party app(s) with Tier 0 permissions (expected, not counted)`;
    }
    ctx.addRow(
      row({
        category: "Enterprise Applications",
        setting: "Foreign Apps with Tier 0 Permissions (GA Escalation)",
        currentValue: tier0Current,
        recommendedValue:
          "No third-party apps should hold Tier 0 (Global Admin escalation) permissions",
        status: foreignTier0.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-ENTAPP-003",
        remediation:
          "Entra admin center > Enterprise applications > review third-party apps with Tier 0 permissions. These permissions have documented attack paths to Global Administrator. Remove or replace with least-privilege alternatives. Microsoft first-party apps are listed separately in the evidence and are expected to hold these permissions.",
      }),
    );

    // Tier 1 findings (High -- data access risk)
    let tier1Current =
      foreignTier1.length === 0
        ? "No third-party apps with Tier 1 data access permissions"
        : `${foreignTier1.length} finding(s): ${foreignTier1.join("; ")}`;
    if (msFpTier1.length > 0) {
      tier1Current += ` | ${msFpTier1.length} Microsoft first-party app(s) with Tier 1 permissions (expected, not counted)`;
    }
    ctx.addRow(
      row({
        category: "Enterprise Applications",
        setting: "Foreign Apps with Tier 1 Permissions (Data Access)",
        currentValue: tier1Current,
        recommendedValue: "Minimize third-party apps with broad data access permissions",
        status: foreignTier1.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-ENTAPP-011",
        remediation:
          "Entra admin center > Enterprise applications > review third-party apps with broad data access (Mail.ReadWrite, Files.ReadWrite.All, etc.). Scope to least-privilege or remove. Microsoft first-party apps are listed separately in the evidence.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 4. ENTRA-ENTAPP-004: Foreign apps with dangerous delegated
  // permissions (PS 451-492)
  // ------------------------------------------------------------------
  try {
    const collectDelegated = (sps: readonly GraphObj[]): string[] => {
      const findings: string[] = [];
      for (const sp of sps) {
        for (const grant of getSpOAuth2Grants(sp["id"])) {
          const scopeStr = grant["scope"];
          const scopes = typeof scopeStr === "string" ? scopeStr.split(/\s+/) : [];
          for (const scope of scopes) {
            if (dangerousDelegatedSet.has(scope.toLowerCase())) {
              findings.push(`${String(sp["displayName"])}: ${scope}`);
            }
          }
        }
      }
      return findings;
    };

    const foreignDangerousDelegated = collectDelegated(thirdPartyForeignApps);
    const msFpDelegated = collectDelegated(msFirstPartyForeignApps);

    let delegatedCurrent =
      foreignDangerousDelegated.length === 0
        ? "No third-party apps with dangerous delegated permissions"
        : `${foreignDangerousDelegated.length} finding(s): ${foreignDangerousDelegated.join("; ")}`;
    if (msFpDelegated.length > 0) {
      delegatedCurrent += ` | ${msFpDelegated.length} Microsoft first-party app(s) with these permissions (expected, not counted)`;
    }
    ctx.addRow(
      row({
        category: "Enterprise Applications",
        setting: "Foreign Apps with Dangerous Delegated Permissions",
        currentValue: delegatedCurrent,
        recommendedValue: "No third-party apps should hold dangerous delegated permissions",
        status: foreignDangerousDelegated.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-ENTAPP-004",
        remediation:
          "Entra admin center > Enterprise applications > review third-party apps with high-privilege delegated permissions. Revoke admin consent or remove the app. Microsoft first-party apps are listed separately in the evidence.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 5. ENTRA-ENTAPP-005: Foreign apps with Entra directory roles
  // (PS 494-529)
  // ------------------------------------------------------------------
  try {
    const collectRoles = (sps: readonly GraphObj[]): string[] => {
      const findings: string[] = [];
      for (const sp of sps) {
        const spId = sp["id"];
        if (typeof spId === "string" && spRoleAssignments.has(spId)) {
          findings.push(
            `${String(sp["displayName"])} (${spRoleAssignments.get(spId)?.length ?? 0} role(s))`,
          );
        }
      }
      return findings;
    };

    const foreignWithRoles = collectRoles(thirdPartyForeignApps);
    const msFpWithRoles = collectRoles(msFirstPartyForeignApps);

    let rolesCurrent =
      foreignWithRoles.length === 0
        ? "No third-party apps hold directory roles"
        : `${foreignWithRoles.length} third-party app(s) with roles: ${foreignWithRoles.join("; ")}`;
    if (msFpWithRoles.length > 0) {
      rolesCurrent += ` | ${msFpWithRoles.length} Microsoft first-party app(s) with roles (expected, not counted)`;
    }
    ctx.addRow(
      row({
        category: "Enterprise Applications",
        setting: "Foreign Apps with Directory Roles",
        currentValue: rolesCurrent,
        recommendedValue: "No third-party apps should hold Entra directory roles",
        status: foreignWithRoles.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-ENTAPP-005",
        remediation:
          "Entra admin center > Roles and administrators > review roles assigned to third-party service principals. Remove role assignments from untrusted external apps. Microsoft first-party apps are listed separately in the evidence.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 6. ENTRA-ENTAPP-006: Apps with excessive permission count (PS 531-558)
  // ------------------------------------------------------------------
  try {
    const excessivePerms: string[] = [];
    for (const sp of regularApps) {
      if (sp["accountEnabled"] !== true) continue;
      const appRoles = getSpAppRoleAssignments(sp["id"]);
      if (appRoles.length > 10) {
        excessivePerms.push(`${String(sp["displayName"])} (${appRoles.length} permissions)`);
      }
    }

    ctx.addRow(
      row({
        category: "Enterprise Applications",
        setting: "Apps with Excessive Permissions",
        currentValue:
          excessivePerms.length === 0
            ? "No apps with > 10 application permissions"
            : `${excessivePerms.length} app(s): ${excessivePerms.join("; ")}`,
        recommendedValue: "Apps should follow least-privilege (max 10 app permissions)",
        status: excessivePerms.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-ENTAPP-006",
        remediation:
          "Review apps with > 10 application permissions. Remove unnecessary permissions to follow least-privilege. Entra admin center > App registrations > API permissions.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 7. ENTRA-ENTAPP-007: App instance property lock (PS 560-590)
  // ------------------------------------------------------------------
  try {
    let defaultPolicy: GraphObj | null = null;
    try {
      defaultPolicy = (await ctx.transport.getJson(
        ENT_APP_SECURITY_CONFIG_ENDPOINTS.defaultAppManagementPolicy,
        { requiredRole: POLICY_READ_ALL },
      )) as GraphObj;
    } catch (policyErr) {
      if (policyErr instanceof TransportFatalError) throw policyErr;
      // PS Write-Verbose parity — default policy unavailable.
    }

    const lockEnabled = defaultPolicy != null && defaultPolicy["isEnabled"] === true;

    ctx.addRow(
      row({
        category: "Enterprise Applications",
        setting: "App Instance Property Lock",
        currentValue: lockEnabled
          ? "Default app management policy enabled"
          : "No default app management policy or disabled",
        recommendedValue:
          "App management policy enabled to prevent property modifications by app owners",
        status: lockEnabled ? "Pass" : "Info",
        checkId: "ENTRA-ENTAPP-007",
        remediation:
          "Entra admin center > Applications > App management policies > configure a default policy to lock sensitive properties on multi-tenant apps.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 8. ENTRA-ENTAPP-008: Managed identities with dangerous application
  // permissions (PS 592-625)
  // ------------------------------------------------------------------
  try {
    const miDangerousPerms: string[] = [];
    for (const mi of managedIdentities) {
      for (const roleRec of getSpAppRoleAssignments(mi["id"])) {
        const permId = roleRec["appRoleId"];
        const mapped = typeof permId === "string" ? graphPermissionMap.get(permId) : undefined;
        if (!mapped) continue;
        if (dangerousSet.has(mapped.name.toLowerCase())) {
          miDangerousPerms.push(`${String(mi["displayName"])}: ${mapped.name}`);
        }
      }
    }

    ctx.addRow(
      row({
        category: "Managed Identities",
        setting: "Managed Identities with Dangerous Permissions",
        currentValue:
          miDangerousPerms.length === 0
            ? "No managed identities with dangerous permissions"
            : `${miDangerousPerms.length} finding(s): ${miDangerousPerms.join("; ")}`,
        recommendedValue: "Managed identities should follow least-privilege",
        status: miDangerousPerms.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-ENTAPP-008",
        remediation:
          "Review managed identity permissions. Use narrower permissions (e.g., Mail.Read instead of Mail.ReadWrite). Azure portal > Managed Identity > API permissions.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 9. ENTRA-ENTAPP-009: Managed identities with Entra directory roles
  // (PS 627-654)
  // ------------------------------------------------------------------
  try {
    const miWithRoles: string[] = [];
    for (const mi of managedIdentities) {
      const miId = mi["id"];
      if (typeof miId === "string" && spRoleAssignments.has(miId)) {
        miWithRoles.push(
          `${String(mi["displayName"])} (${spRoleAssignments.get(miId)?.length ?? 0} role(s))`,
        );
      }
    }

    ctx.addRow(
      row({
        category: "Managed Identities",
        setting: "Managed Identities with Directory Roles",
        currentValue:
          miWithRoles.length === 0
            ? "No managed identities hold directory roles"
            : `${miWithRoles.length} managed identity/ies with roles: ${miWithRoles.join("; ")}`,
        recommendedValue: "Managed identities should not hold Entra directory roles",
        status: miWithRoles.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-ENTAPP-009",
        remediation:
          "Review managed identities with directory roles. Use Graph API permissions instead of directory roles where possible. Entra admin center > Roles and administrators.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 10. ENTRA-ENTAPP-010: Internal apps with Tier 0 permissions
  // (PS 656-694). PS `-eq $null` matches SPs whose owner is ALSO null when
  // the org fetch failed — reproduced via ?? null comparison.
  // ------------------------------------------------------------------
  try {
    const internalTier0: string[] = [];
    const internalApps = allServicePrincipals.filter(
      (sp) =>
        (sp["appOwnerOrganizationId"] ?? null) === (tenantId ?? null) &&
        !equalsCI(sp["servicePrincipalType"], "ManagedIdentity"),
    );

    for (const sp of internalApps) {
      for (const roleRec of getSpAppRoleAssignments(sp["id"])) {
        const permId = roleRec["appRoleId"];
        const mapped = typeof permId === "string" ? graphPermissionMap.get(permId) : undefined;
        if (!mapped) continue;
        if (tier0Set.has(mapped.name.toLowerCase())) {
          internalTier0.push(`${String(sp["displayName"])}: ${mapped.name}`);
        }
      }
    }

    ctx.addRow(
      row({
        category: "Enterprise Applications",
        setting: "Internal Apps with Tier 0 Permissions (GA Escalation)",
        currentValue:
          internalTier0.length === 0
            ? "No internal apps with Tier 0 permissions"
            : `${internalTier0.length} finding(s): ${internalTier0.join("; ")}`,
        recommendedValue: "Minimize internal apps with Tier 0 permissions; use least-privilege",
        status: internalTier0.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-ENTAPP-010",
        remediation:
          "Entra admin center > App registrations > review internal apps with Tier 0 permissions. Each has a documented path to Global Administrator. Replace with narrower permissions or use managed identities where possible.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  /** PS `$list[0..N-1] -join '; '` + `'...'` overflow shaping (PS lines 710/746/
   * 771/802/852/891/931/975/1009/1042/1075/1111/1135). The slices are only ever
   * rendered when the count exceeds the slice length, so no out-of-range nulls. */
  function summarize(items: readonly string[], n: number): string {
    const head = items.slice(0, n).join("; ");
    return items.length > n ? `${head}...` : head;
  }

  // ------------------------------------------------------------------
  // 12. ENTRA-ENTAPP-012: Apps using client secrets instead of certificates
  // (PS 696-720)
  // ------------------------------------------------------------------
  try {
    const secretOnlyApps = regularApps
      .filter(
        (sp) =>
          sp["accountEnabled"] === true &&
          hasEntries(sp["passwordCredentials"]) &&
          !hasEntries(sp["keyCredentials"]),
      )
      .map((sp) => String(sp["displayName"]));

    ctx.addRow(
      row({
        category: "Credential Hygiene",
        setting: "Apps Using Secrets Instead of Certificates",
        currentValue:
          secretOnlyApps.length === 0
            ? "No apps rely solely on client secrets"
            : `${secretOnlyApps.length} app(s): ${summarize(secretOnlyApps, 5)}`,
        recommendedValue: "Use certificates or managed identities instead of client secrets",
        status: secretOnlyApps.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-ENTAPP-012",
        remediation:
          "Migrate app credentials from client secrets to certificates or managed identities. Secrets are extractable from memory and logs. Entra admin center > App registrations > Certificates & secrets.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 13. ENTRA-ENTAPP-013: Apps with expired credentials still present
  // (PS 722-756)
  // ------------------------------------------------------------------
  try {
    const now = new Date();
    const expiredCredApps: string[] = [];

    for (const sp of regularApps) {
      let hasExpired = false;
      for (const passCred of credList(sp["passwordCredentials"])) {
        const end = passCred?.["endDateTime"];
        if (end && typeof end === "string" && new Date(end) < now) {
          hasExpired = true;
          break;
        }
      }
      if (!hasExpired) {
        for (const key of credList(sp["keyCredentials"])) {
          const end = key?.["endDateTime"];
          if (end && typeof end === "string" && new Date(end) < now) {
            hasExpired = true;
            break;
          }
        }
      }
      if (hasExpired) expiredCredApps.push(String(sp["displayName"]));
    }

    ctx.addRow(
      row({
        category: "Credential Hygiene",
        setting: "Apps with Expired Credentials",
        currentValue:
          expiredCredApps.length === 0
            ? "No apps have expired credentials"
            : `${expiredCredApps.length} app(s): ${summarize(expiredCredApps, 5)}`,
        recommendedValue: "Remove expired credentials from all app registrations",
        status: expiredCredApps.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-ENTAPP-013",
        remediation:
          "Remove expired credentials. Expired secrets/certs are attack surface -- they indicate poor credential lifecycle management. Entra admin center > App registrations > Certificates & secrets.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 14. ENTRA-ENTAPP-014: Apps with both secret and certificate credentials
  // (PS 758-781; NOT gated on accountEnabled)
  // ------------------------------------------------------------------
  try {
    const dualCredApps = regularApps
      .filter(
        (sp) =>
          hasEntries(sp["passwordCredentials"]) && hasEntries(sp["keyCredentials"]),
      )
      .map((sp) => String(sp["displayName"]));

    ctx.addRow(
      row({
        category: "Credential Hygiene",
        setting: "Apps with Both Secrets and Certificates",
        currentValue:
          dualCredApps.length === 0
            ? "No apps have dual credential types"
            : `${dualCredApps.length} app(s): ${summarize(dualCredApps, 5)}`,
        recommendedValue: "Use a single credential type per app (prefer certificates)",
        status: dualCredApps.length === 0 ? "Pass" : "Info",
        checkId: "ENTRA-ENTAPP-014",
        remediation:
          "Remove the client secret if a certificate is also configured. Dual credential types widen the attack surface. Entra admin center > App registrations > Certificates & secrets.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 15. ENTRA-ENTAPP-015: SPs with client secret AND directory role
  // (PS 783-812)
  // ------------------------------------------------------------------
  try {
    const secretPermanentRole: string[] = [];
    for (const sp of regularApps) {
      if (!hasEntries(sp["passwordCredentials"])) continue;
      const spId = sp["id"];
      if (typeof spId === "string" && spRoleAssignments.has(spId)) {
        secretPermanentRole.push(
          `${String(sp["displayName"])} (${spRoleAssignments.get(spId)?.length ?? 0} role(s))`,
        );
      }
    }

    ctx.addRow(
      row({
        category: "Credential Hygiene",
        setting: "SPs with Secret + Permanent Directory Role",
        currentValue:
          secretPermanentRole.length === 0
            ? "No SPs combine secrets with permanent roles"
            : `${secretPermanentRole.length} SP(s): ${summarize(secretPermanentRole, 3)}`,
        recommendedValue: "Privileged SPs should use certificates, not secrets",
        status: secretPermanentRole.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-ENTAPP-015",
        remediation:
          "Migrate privileged service principals from client secrets to certificates or managed identities. A secret on a permanently privileged SP is a persistent backdoor risk.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 16. ENTRA-ENTAPP-016: Privileged (Tier 0) apps with owners
  // (PS 814-862)
  // ------------------------------------------------------------------
  try {
    const privilegedWithOwners: string[] = [];

    for (const sp of regularApps) {
      const hasTier0 = getSpAppRoleAssignments(sp["id"]).some((roleRec) => {
        const permId = roleRec["appRoleId"];
        const mapped = typeof permId === "string" ? graphPermissionMap.get(permId) : undefined;
        return mapped != null && tier0Set.has(mapped.name.toLowerCase());
      });
      if (!hasTier0) continue;

      try {
        const ownersResp = await ctx.transport.getJson(spOwnersUrl(String(sp["id"])), {
          requiredRole: APPLICATION_READ_ALL,
        });
        const owners = asArray(ownersResp.value);
        if (owners.length > 0) {
          const ownerNames = owners.map((o) => String(o["displayName"] ?? "")).join(", ");
          privilegedWithOwners.push(`${String(sp["displayName"])} (owners: ${ownerNames})`);
        }
      } catch (probeErr) {
        if (probeErr instanceof TransportFatalError) throw probeErr;
        // PS Write-Verbose parity — owners unavailable for this SP.
      }
    }

    ctx.addRow(
      row({
        category: "Owner Risk",
        setting: "Tier 0 Apps with Owners Assigned",
        currentValue:
          privilegedWithOwners.length === 0
            ? "No Tier 0 apps have owners"
            : `${privilegedWithOwners.length} app(s): ${summarize(privilegedWithOwners, 3)}`,
        recommendedValue: "Tier 0 apps should not have owners (owners can add credentials and impersonate)",
        status: privilegedWithOwners.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-ENTAPP-016",
        remediation:
          "Remove owners from apps with Tier 0 permissions. An owner of a Tier 0 app can add credentials and impersonate it to escalate to Global Admin. Entra admin center > App registrations > Owners.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 17. ENTRA-ENTAPP-017: Role-holding apps with owners (PS 864-901)
  // ------------------------------------------------------------------
  try {
    const roleAppsWithOwners: string[] = [];

    for (const sp of regularApps) {
      const spId = sp["id"];
      if (typeof spId !== "string" || !spRoleAssignments.has(spId)) continue;

      try {
        const ownersResp = await ctx.transport.getJson(spOwnersUrl(spId), {
          requiredRole: APPLICATION_READ_ALL,
        });
        const owners = asArray(ownersResp.value);
        if (owners.length > 0) {
          const ownerNames = owners.map((o) => String(o["displayName"] ?? "")).join(", ");
          roleAppsWithOwners.push(`${String(sp["displayName"])} (owners: ${ownerNames})`);
        }
      } catch (probeErr) {
        if (probeErr instanceof TransportFatalError) throw probeErr;
      }
    }

    ctx.addRow(
      row({
        category: "Owner Risk",
        setting: "Role-Holding Apps with Owners",
        currentValue:
          roleAppsWithOwners.length === 0
            ? "No role-holding apps have owners"
            : `${roleAppsWithOwners.length} app(s): ${summarize(roleAppsWithOwners, 3)}`,
        recommendedValue: "Apps with directory roles should not have owners",
        status: roleAppsWithOwners.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-ENTAPP-017",
        remediation:
          "Remove owners from apps holding Entra directory roles. Owners can add credentials and impersonate the SP to exercise those roles. Entra admin center > App registrations > Owners.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 18. ENTRA-ENTAPP-018: Orphaned credentialed apps (PS 903-941).
    // NOTE: this $appsWithCreds is NOT gated on accountEnabled — it is a
  // separate PS local redefinition (lines 909-912), unlike checks 1-2's.
  // ------------------------------------------------------------------
  try {
    const orphanedApps: string[] = [];
    const credentialedApps = regularApps.filter(
      (sp) => hasEntries(sp["passwordCredentials"]) || hasEntries(sp["keyCredentials"]),
    );

    for (const sp of credentialedApps) {
      try {
        const ownersResp = await ctx.transport.getJson(
          spOwnersIdOnlyUrl(String(sp["id"])),
          { requiredRole: APPLICATION_READ_ALL },
        );
        if (asArray(ownersResp.value).length === 0) {
          orphanedApps.push(String(sp["displayName"]));
        }
      } catch (probeErr) {
        if (probeErr instanceof TransportFatalError) throw probeErr;
      }
    }

    ctx.addRow(
      row({
        category: "Owner Risk",
        setting: "Credentialed Apps with No Owners",
        currentValue:
          orphanedApps.length === 0
            ? "All credentialed apps have at least one owner"
            : `${orphanedApps.length} orphaned app(s): ${summarize(orphanedApps, 5)}`,
        recommendedValue: "All apps with credentials should have at least one owner for accountability",
        status: orphanedApps.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-ENTAPP-018",
        remediation:
          "Assign owners to orphaned app registrations. Without owners, no one is accountable for credential rotation or permission review. Entra admin center > App registrations > Owners > Add owner.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 19. ENTRA-ENTAPP-019: Tier 0 apps with no sign-in activity
  // (PS 943-985). PS reads $sp['lastSignInActivity'] straight off the bulk
  // select — which never includes that property — so EVERY Tier 0 app is
  // counted; reproduced verbatim via property lookup.
  // ------------------------------------------------------------------
  try {
    const unusedPrivileged: string[] = [];

    for (const sp of regularApps) {
      const hasTier0 = getSpAppRoleAssignments(sp["id"]).some((roleRec) => {
        const permId = roleRec["appRoleId"];
        const mapped = typeof permId === "string" ? graphPermissionMap.get(permId) : undefined;
        return mapped != null && tier0Set.has(mapped.name.toLowerCase());
      });
      if (!hasTier0) continue;

      const lastSignIn = sp["lastSignInActivity"];
      if (!lastSignIn) unusedPrivileged.push(String(sp["displayName"]));
    }

    ctx.addRow(
      row({
        category: "Permission Hygiene",
        setting: "Tier 0 Apps with No Sign-In Activity",
        currentValue:
          unusedPrivileged.length === 0
            ? "All Tier 0 apps show recent sign-in activity"
            : `${unusedPrivileged.length} app(s) with Tier 0 perms and no sign-in: ${summarize(unusedPrivileged, 5)}`,
        recommendedValue: "Remove Tier 0 permissions from apps that never use them",
        status: unusedPrivileged.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-ENTAPP-019",
        remediation:
          "Review apps with Tier 0 permissions that show no sign-in activity. These permissions may have been granted but never used -- remove them to reduce attack surface. Entra admin center > Enterprise applications > Sign-in logs.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 20. ENTRA-APPREG-002: Localhost redirect URIs (PS 987-1019)
  // ------------------------------------------------------------------
  try {
    const localhostApps: string[] = [];
    for (const app of allAppRegistrations) {
      const allUris = redirectUrisOf(app, ["web", "spa", "publicClient"]);
      if (allUris.some((uri) => /localhost|127\.0\.0\.1|\[::1\]/i.test(uri))) {
        localhostApps.push(String(app["displayName"]));
      }
    }

    ctx.addRow(
      row({
        category: "App Registration Security",
        setting: "Apps with Localhost Redirect URIs",
        currentValue:
          localhostApps.length === 0
            ? "No apps have localhost redirect URIs"
            : `${localhostApps.length} app(s): ${summarize(localhostApps, 5)}`,
        recommendedValue: "Remove localhost redirect URIs from production apps",
        status: localhostApps.length === 0 ? "Pass" : "Warning",
        checkId: "ENTRA-APPREG-002",
        remediation:
          "Remove localhost redirect URIs from production app registrations. In shared environments, tokens redirected to localhost can be intercepted. Entra admin center > App registrations > Authentication.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 21. ENTRA-APPREG-003: HTTP (non-HTTPS) redirect URIs (web/spa only;
  // PS 1021-1052)
  // ------------------------------------------------------------------
  try {
    const httpApps: string[] = [];
    for (const app of allAppRegistrations) {
      const allUris = redirectUrisOf(app, ["web", "spa"]);
      const hasHttp = allUris.some(
        (uri) => /^http:\/\//i.test(uri) && !/localhost|127\.0\.0\.1/i.test(uri),
      );
      if (hasHttp) httpApps.push(String(app["displayName"]));
    }

    ctx.addRow(
      row({
        category: "App Registration Security",
        setting: "Apps with HTTP (Non-HTTPS) Redirect URIs",
        currentValue:
          httpApps.length === 0
            ? "No apps have insecure HTTP redirect URIs"
            : `${httpApps.length} app(s): ${summarize(httpApps, 5)}`,
        recommendedValue: "All redirect URIs should use HTTPS",
        status: httpApps.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-APPREG-003",
        remediation:
          "Update HTTP redirect URIs to HTTPS. Non-HTTPS URIs allow token interception via MITM attacks. Entra admin center > App registrations > Authentication.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 22. ENTRA-APPREG-004: Wildcard redirect URIs (web/spa; PS 1054-1085)
  // ------------------------------------------------------------------
  try {
    const wildcardApps: string[] = [];
    for (const app of allAppRegistrations) {
      const allUris = redirectUrisOf(app, ["web", "spa"]);
      if (allUris.some((uri) => uri.includes("*"))) {
        wildcardApps.push(String(app["displayName"]));
      }
    }

    ctx.addRow(
      row({
        category: "App Registration Security",
        setting: "Apps with Wildcard Redirect URIs",
        currentValue:
          wildcardApps.length === 0
            ? "No apps have wildcard redirect URIs"
            : `${wildcardApps.length} app(s): ${summarize(wildcardApps, 5)}`,
        recommendedValue: "Avoid wildcard redirect URIs",
        status: wildcardApps.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-APPREG-004",
        remediation:
          "Replace wildcard redirect URIs with explicit URIs. Wildcards enable open redirect attacks for token theft. Entra admin center > App registrations > Authentication.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 23. ENTRA-ENTAPP-020: Foreign apps impersonating Microsoft display
  // names (PS 1087-1121). First-party apps are already excluded from
  // $thirdPartyForeignApps (#887/#1001).
  // ------------------------------------------------------------------
  try {
    const msNames = [
      "Microsoft Teams",
      "Microsoft Graph",
      "Microsoft Office",
      "Microsoft Azure",
      "Microsoft Intune",
      "Microsoft Exchange",
      "Microsoft SharePoint",
      "Microsoft Outlook",
      "Microsoft OneDrive",
      "Microsoft Defender",
    ];
    const impersonators: string[] = [];

    for (const sp of thirdPartyForeignApps) {
      const name = String(sp["displayName"] ?? "");
      for (const msName of msNames) {
        // PS `-eq` / `-like "$msName *"` are case-insensitive.
        if (
          name.toLowerCase() === msName.toLowerCase() ||
          name.toLowerCase().startsWith(`${msName.toLowerCase()} `)
        ) {
          impersonators.push(`${name} (AppId: ${String(sp["appId"] ?? "")})`);
          break;
        }
      }
    }

    ctx.addRow(
      row({
        category: "App Registration Security",
        setting: "Foreign Apps Impersonating Microsoft Names",
        currentValue:
          impersonators.length === 0
            ? "No foreign apps impersonate Microsoft display names"
            : `${impersonators.length} app(s): ${summarize(impersonators, 3)}`,
        recommendedValue: "No foreign apps should use Microsoft product names",
        status: impersonators.length === 0 ? "Pass" : "Fail",
        checkId: "ENTRA-ENTAPP-020",
        remediation:
          "Investigate foreign apps using Microsoft product names -- they may be social engineering attempts. Verify the publisher and appId against known Microsoft first-party apps. Remove if suspicious.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }

  // ------------------------------------------------------------------
  // 24. ENTRA-ENTAPP-021: Multi-tenant app registrations (PS 1123-1145)
  // ------------------------------------------------------------------
  try {
    const multiTenantAudiences = ["azureadmultipleorgs", "azureadandpersonalmicrosoftaccount"];
    const multiTenantApps = allAppRegistrations
      .filter((app) => {
        const audience = app["signInAudience"];
        return typeof audience === "string" && multiTenantAudiences.includes(audience.toLowerCase());
      })
      .map((app) => `${String(app["displayName"])} (${String(app["signInAudience"])})`);

    ctx.addRow(
      row({
        category: "App Registration Security",
        setting: "Multi-Tenant App Registrations",
        currentValue:
          multiTenantApps.length === 0
            ? "No multi-tenant app registrations"
            : `${multiTenantApps.length} app(s): ${summarize(multiTenantApps, 5)}`,
        recommendedValue: "Use single-tenant (AzureADMyOrg) unless external access is required",
        status: multiTenantApps.length === 0 ? "Pass" : "Info",
        checkId: "ENTRA-ENTAPP-021",
        remediation:
          "Review multi-tenant apps and restrict to AzureADMyOrg if they do not need cross-tenant access. Multi-tenant apps can be accessed by users from any Entra ID tenant. Entra admin center > App registrations > Authentication > Supported account types.",
      }),
    );
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
  }
};
