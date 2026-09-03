import {
  getGrantedRoles,
  mintAppOnlyToken,
  safeErrorMessage,
} from "@/engine/transport/graph-auth";
import { computeVerification } from "@/lib/graph/verify-permissions";

/**
 * App-only Graph permission verification for the assessment engine (D-04).
 *
 * Behavioral port of the app-role path in
 * src/M365-Assess/Orchestrator/Test-GraphPermissions.ps1 (per-section
 * inversion + explicit could-not-validate state): after admin consent, the
 * app must PROVE its application permissions before any assessment runs.
 *
 * Two independent checks, merged into one three-state result:
 * 1. Roles diff — mint a .default client_credentials token and decode its
 *    `roles` claim via plan 02-02's getGrantedRoles (app tokens carry roles,
 *    NEVER scp), then compare case-insensitively against required roles using
 *    Phase 1's computeVerification() (reused, not rewritten).
 * 2. Live probes — one cheap GET per critical Graph area. A token alone can
 *    miss consent gaps (role assigned but consent never propagated), so a
 *    403 proves missing consent regardless of what the roles claim says.
 *
 * Fail-explicit discipline: a probe that cannot run (network error or
 * unexpected status) yields granted:null and forces overall status "error" —
 * it is NEVER silently treated as granted.
 */

export interface AppPermissionProbe {
  /** Stable area key (e.g. "organization", "users"). */
  area: string;
  /** Cheap Graph endpoint probed with the minted bearer token. */
  endpoint: string;
  /** Application role this probe is designed to validate. */
  requiredRole: string;
  /** true = 2xx; false = 403 (missing consent); null = probe errored. */
  granted: boolean | null;
}

export interface AppPermissionVerification {
  /** Same three-state model as computeVerification(). */
  status: "all_granted" | "missing" | "error";
  /** Application roles decoded from the minted token's `roles` claim. */
  rolesFromToken: string[];
  probes: AppPermissionProbe[];
  /** Case-insensitive diff vs required roles (empty unless status === "missing"). */
  missingRoles: string[];
  /** Safe single-line message; present only when status === "error". */
  errorMessage?: string;
}

/** One cheap GET per critical area (D-04) — $top=1 where lists apply, never paginated. */
const PROBE_ENDPOINTS: ReadonlyArray<{
  area: string;
  endpoint: string;
  requiredRole: string;
}> = [
  {
    area: "organization",
    endpoint: "/v1.0/organization",
    requiredRole: "Organization.Read.All",
  },
  {
    area: "identitySecurityDefaults",
    endpoint: "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
    requiredRole: "Policy.Read.All",
  },
  {
    area: "users",
    endpoint: "/v1.0/users?$top=1",
    requiredRole: "User.Read.All",
  },
  {
    area: "servicePrincipals",
    endpoint: "/v1.0/servicePrincipals?$top=1",
    requiredRole: "Application.Read.All",
  },
  {
    area: "secureScores",
    endpoint: "/v1.0/security/secureScores?$top=1",
    requiredRole: "SecurityEvents.Read.All",
  },
  {
    area: "directoryAudits",
    endpoint: "/v1.0/auditLogs/directoryAudits?$top=1",
    requiredRole: "AuditLog.Read.All",
  },
  {
    area: "sensitivityLabels",
    endpoint: "/v1.0/informationProtection/sensitivityLabels",
    requiredRole: "InformationProtectionPolicy.Read.All",
  },
  {
    area: "securityAlerts",
    endpoint: "/v1.0/security/alerts_v2?$top=1",
    requiredRole: "SecurityAlert.Read.All",
  },
  {
    area: "managedDevices",
    endpoint: "/v1.0/deviceManagement/managedDevices?$top=1",
    requiredRole: "DeviceManagementManagedDevices.Read.All",
  },
  {
    area: "deviceConfigurations",
    endpoint: "/v1.0/deviceManagement/deviceConfigurations?$top=1",
    requiredRole: "DeviceManagementConfiguration.Read.All",
  },
  {
    area: "deviceEnrollmentConfigurations",
    endpoint: "/beta/deviceManagement/deviceEnrollmentConfigurations?$top=1",
    requiredRole: "DeviceManagementConfiguration.Read.All",
  },
  {
    area: "windowsAutopilotDeploymentProfiles",
    endpoint: "/v1.0/deviceManagement/windowsAutopilotDeploymentProfiles?$top=1",
    requiredRole: "DeviceManagementServiceConfig.Read.All",
  },
  {
    area: "threatIntelligence",
    endpoint: "/v1.0/security/secureScores?$top=1",
    requiredRole: "ThreatIntelligence.Read.All",
  },
  {
    area: "sharepointSettings",
    endpoint: "/v1.0/admin/sharepoint/settings",
    requiredRole: "SharePointTenantSettings.Read.All",
  },
  {
    area: "teamwork",
    endpoint: "/v1.0/teamwork",
    requiredRole: "TeamSettings.Read.All",
  },
  {
    area: "teamworkAppSettings",
    endpoint: "/v1.0/teamwork/teamsAppSettings?$top=1",
    requiredRole: "TeamworkAppSettings.Read.All",
  },
  {
    area: "formsSettings",
    endpoint: "/v1.0/admin/forms/settings",
    requiredRole: "OrgSettings-Forms.Read.All",
  },
  {
    area: "retentionLabels",
    endpoint: "/v1.0/security/labels/retentionLabels?$top=1",
    requiredRole: "RecordsManagement.Read.All",
  },
  {
    area: "groups",
    endpoint: "/v1.0/groups?$top=1",
    requiredRole: "Directory.Read.All",
  },
  {
    area: "sites",
    endpoint: "/v1.0/sites?$top=1",
    requiredRole: "Sites.Read.All",
  },
  {
    area: "powerBiTenantSettings",
    endpoint: "https://api.powerbi.com/v1.0/myorg/admin/tenantSettings",
    requiredRole: "Directory.Read.All",
  },
];

/** Graph API origin used for live probes. */
const GRAPH_BASE = "https://graph.microsoft.com";

export async function verifyAppPermissions(opts: {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  requiredRoles: string[];
  fetchImpl?: typeof fetch; // injectable for tests
}): Promise<AppPermissionVerification> {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;

  // 1. Mint + decode. Any failure here is an explicit verification error —
  //    a silent [] would render every permission as missing without cause.
  let accessToken: string;
  let rolesFromToken: string[];
  try {
    const token = await mintAppOnlyToken(
      opts.tenantId,
      opts.clientId,
      opts.clientSecret,
    );
    accessToken = token.accessToken;
    rolesFromToken = getGrantedRoles(accessToken);
  } catch (err) {
    return {
      status: "error",
      rolesFromToken: [],
      probes: [],
      missingRoles: [],
      errorMessage: safeErrorMessage(err),
    };
  }

  // 2. Case-insensitive roles diff — reused from Phase 1, not rewritten.
  const rolesDiff = computeVerification(opts.requiredRoles, rolesFromToken);

  // 3. Live probes: one cheap GET per area carrying the bearer token.
  //    Sequential by design — tiny GETs, no rate-limit pressure. Only probe areas whose requiredRole is in the requested union (D-40).
  const probes: AppPermissionProbe[] = [];
  const probeErrors: string[] = [];
  const requiredLower = new Set(opts.requiredRoles.map((r) => r.toLowerCase()));
  const filteredEndpoints = PROBE_ENDPOINTS.filter((def) => requiredLower.has(def.requiredRole.toLowerCase()));
  for (const def of filteredEndpoints) {
    let granted: boolean | null = null;
    try {
      const url = def.endpoint.startsWith("https://") ? def.endpoint : `${GRAPH_BASE}${def.endpoint}`;
      const response = await fetchImpl(url, {
        method: "GET",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (response.ok) {
        granted = true;
      } else if (response.status === 403) {
        // AuthorizationError from Graph proves the consent gap (D-04).
        granted = false;
      } else if (
        (response.status === 412 && def.area === "teamworkAppSettings") ||
        ((response.status === 400 || response.status === 404) &&
          [
            "sensitivityLabels",
            "sharepointSettings",
            "teamwork",
            "teamworkAppSettings",
            "formsSettings",
            "retentionLabels",
            "powerBiTenantSettings",
            "managedDevices",
            "deviceConfigurations",
            "deviceEnrollmentConfigurations",
            "windowsAutopilotDeploymentProfiles",
          ].includes(def.area))
      ) {
        // 400/404: tenant without service (no E5 / no SharePoint admin / no Forms)
        // still proves role granted via rolesFromToken. 412: /v1.0/teamwork/teamsAppSettings
        // returns 412 on app-only by design (Graph does not support app-only for
        // Teams app settings — src/M365-Assess/Collaboration/Get-TeamsSecurityConfig.ps1:38-45).
        // Collector web/src/engine/sections/collaboration/teams-security-config.ts:14
        // already avoids this endpoint and uses /v1.0/teamwork instead; treat 412 as granted.
        granted = true;
      } else {
        // Inconclusive (429/5xx/…): cannot run ⇒ error, never silent grant.
        probeErrors.push(
          safeErrorMessage(
            new Error(
              `probe ${def.area} (${def.endpoint}) returned unexpected status ${response.status}`,
            ),
          ),
        );
      }
    } catch (err) {
      probeErrors.push(safeErrorMessage(err));
    }
    probes.push({
      area: def.area,
      endpoint: def.endpoint,
      requiredRole: def.requiredRole,
      granted,
    });
  }

  // 4. Merge outcomes into the final three-state status:
  //    any null probe → "error"; else any missing role or 403 → "missing";
  //    else "all_granted".
  if (probes.some((p) => p.granted === null)) {
    const detail = probeErrors.length > 0 ? `: ${probeErrors.join("; ")}` : "";
    return {
      status: "error",
      rolesFromToken,
      probes,
      missingRoles: [...rolesDiff.missing],
      errorMessage: safeErrorMessage(
        new Error(
          `could not validate application permissions${detail || ": one or more probes failed to run"}`,
        ),
      ).slice(0, 500),
    };
  }

  const deniedAreas = probes.filter((p) => p.granted === false);
  if (
    rolesDiff.status === "missing" ||
    (rolesDiff.status === "all_granted" && deniedAreas.length > 0)
  ) {
    return {
      status: "missing",
      rolesFromToken,
      probes,
      missingRoles: [...rolesDiff.missing],
    };
  }

  // Defensive: computeVerification only returns all_granted | missing, but
  // keep the merge total rather than trusting that invariant blindly.
  if (rolesDiff.status !== "all_granted") {
    return {
      status: rolesDiff.status,
      rolesFromToken,
      probes,
      missingRoles: [...rolesDiff.missing],
    };
  }

  return {
    status: "all_granted",
    rolesFromToken,
    probes,
    missingRoles: [],
  };
}
