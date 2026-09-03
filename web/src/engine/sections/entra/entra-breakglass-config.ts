/**
 * Port of Security/Get-StrykerIncidentReadiness.ps1 CHECK 8 — Break-glass emergency access (ENTRA-BREAKGLASS-001).
 * Graph: GET /v1.0/directoryRoles?$filter=roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10' (Global Admin)
 *        GET /v1.0/directoryRoles/{id}/members, GET /v1.0/identity/conditionalAccess/policies (CA exclusion fallback)
 * Role: Directory.Read.All (members) + Policy.Read.All (CA fallback), 403 -> Review.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

const REQUIRED_ROLE_DIRECTORY = "Directory.Read.All";
const REQUIRED_ROLE_POLICY = "Policy.Read.All";
const AUTHORIZATION_ERROR = /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;
const GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10";
const BREAKGLASS_PATTERN = /break.?glass|emergency.?access|breakglass|bg.?admin/i;

export const ENTRA_BREAKGLASS_CONFIG_ENDPOINTS = {
  directoryRoles: `/v1.0/directoryRoles?$filter=roleTemplateId eq '${GLOBAL_ADMIN_TEMPLATE_ID}'`,
  capPolicies: "/v1.0/identity/conditionalAccess/policies",
} as const;

export const runEntraBreakglassConfig: SectionImplementation = async (ctx) => {
  let roleId: string | null = null;
  let globalAdminIds: string[] = [];
  let members: Array<Record<string, unknown>> = [];
  let roleFound = false;

  try {
    const roleResp = await ctx.transport.getJson(ENTRA_BREAKGLASS_CONFIG_ENDPOINTS.directoryRoles, { requiredRole: REQUIRED_ROLE_DIRECTORY });
    const roles = asArray(roleResp.value);
    const role = roles.find((r) => psStr((r as Record<string, unknown>).roleTemplateId) === GLOBAL_ADMIN_TEMPLATE_ID) as Record<string, unknown> | undefined;
    if (!role) {
      ctx.addRow({
        category: "Break Glass",
        setting: "Emergency Access Accounts",
        currentValue: "Global Administrator role not activated",
        recommendedValue: "At least 2 enabled break-glass accounts with Global Admin role",
        checkId: "ENTRA-BREAKGLASS-001",
        remediation: "Create 2 cloud-only break-glass accounts with Global Admin, excluded from all CA policies, with FIDO2 keys, monitored.",
        psStatus: "Fail",
        evidenceSource: ENTRA_BREAKGLASS_CONFIG_ENDPOINTS.directoryRoles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE_DIRECTORY,
      });
      return;
    }
    roleFound = true;
    roleId = psStr(role.id);
    const membersResp = await ctx.transport.getJson(`/v1.0/directoryRoles/${roleId}/members`, { requiredRole: REQUIRED_ROLE_DIRECTORY });
    members = asArray(membersResp.value) as Array<Record<string, unknown>>;
    globalAdminIds = members.map((m) => psStr((m as Record<string, unknown>).id)).filter(Boolean);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Break Glass",
        setting: "Emergency Access Accounts",
        currentValue: "Insufficient permissions (Directory.Read.All)",
        recommendedValue: "At least 2 enabled break-glass accounts with Global Admin role",
        checkId: "ENTRA-BREAKGLASS-001",
        remediation: "Requires Directory.Read.All and Policy.Read.All",
        psStatus: "Review",
        evidenceSource: ENTRA_BREAKGLASS_CONFIG_ENDPOINTS.directoryRoles,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE_DIRECTORY,
      });
      return;
    }
    ctx.addRow({
      category: "Break Glass",
      setting: "Emergency Access Accounts",
      currentValue: `Error: ${err instanceof Error ? err.message.split("\n")[0].slice(0,120) : String(err).slice(0,120)}`,
      recommendedValue: "At least 2 enabled break-glass accounts with Global Admin role",
      checkId: "ENTRA-BREAKGLASS-001",
      remediation: "Requires Directory.Read.All and Policy.Read.All",
      psStatus: "Review",
      evidenceSource: ENTRA_BREAKGLASS_CONFIG_ENDPOINTS.directoryRoles,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE_DIRECTORY,
    });
    return;
  }

  // High-confidence: name match
  const detectedHigh: Array<Record<string, unknown>> = [];
  for (const m of members) {
    const dn = psStr((m as Record<string, unknown>).displayName);
    const upn = psStr((m as Record<string, unknown>).userPrincipalName);
    if (BREAKGLASS_PATTERN.test(dn) || BREAKGLASS_PATTERN.test(upn)) detectedHigh.push(m);
  }

  let detected = detectedHigh;
  let confidence: "High" | "Medium" = "High";
  if (detectedHigh.length === 0) {
    // Medium-confidence fallback: CA exclusion
    try {
      const caResp = await ctx.transport.getJson(ENTRA_BREAKGLASS_CONFIG_ENDPOINTS.capPolicies, { requiredRole: REQUIRED_ROLE_POLICY });
      const policies = asArray(caResp.value);
      const enabled = policies.filter((p) => psStr((p as Record<string, unknown>).state) === "enabled");
      const mediumDetected: Array<Record<string, unknown>> = [];
      for (const pol of enabled) {
        const cond = (pol as Record<string, unknown>).conditions as Record<string, unknown> | undefined;
        const users = cond?.users as Record<string, unknown> | undefined;
        const excludeUsers = asArray(users?.excludeUsers);
        for (const uid of excludeUsers) {
          const id = psStr(uid);
          if (globalAdminIds.includes(id)) {
            const member = members.find((m) => psStr((m as Record<string, unknown>).id) === id);
            if (member) mediumDetected.push(member);
          }
        }
      }
      // Deduplicate
      const seen = new Set<string>();
      detected = mediumDetected.filter((m) => {
        const id = psStr((m as Record<string, unknown>).id);
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
      });
      if (detected.length > 0) confidence = "Medium";
    } catch {
      // CA fallback failure: keep high-confidence result (empty)
    }
  }

  const list = detected.map((m) => `${psStr((m as Record<string, unknown>).displayName)} (${psStr((m as Record<string, unknown>).userPrincipalName)})`).join(", ");

  if (!roleFound) {
    // Already handled above
    return;
  }
  if (detected.length >= 2) {
    const isHigh = confidence === "High";
    ctx.addRow({
      category: "Break Glass",
      setting: "Emergency Access Accounts",
      currentValue: `${detected.length} account(s) detected (confidence: ${confidence}): ${list} ${isHigh ? "[name match]" : "[CA exclusion pattern]"}`,
      recommendedValue: "At least 2 enabled break-glass accounts with Global Admin role",
      checkId: "ENTRA-BREAKGLASS-001",
      remediation: isHigh ? "Monitor and test quarterly; ensure FIDO2 and excluded from CA." : "Verify intentional & rename to include BreakGlass/EmergencyAccess; ensure FIDO2 and excluded from CA.",
      psStatus: isHigh ? "Pass" : "Warning",
      evidenceSource: ENTRA_BREAKGLASS_CONFIG_ENDPOINTS.directoryRoles,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE_DIRECTORY,
    });
  } else if (detected.length === 1) {
    ctx.addRow({
      category: "Break Glass",
      setting: "Emergency Access Accounts",
      currentValue: `1 account detected (confidence: ${confidence}): ${list}. Single break-glass account is a single point of failure.`,
      recommendedValue: "At least 2 enabled break-glass accounts with Global Admin role",
      checkId: "ENTRA-BREAKGLASS-001",
      remediation: "Create second cloud-only break-glass account with Global Admin, FIDO2 security keys, excluded from all CA policies, monitored, stored in separate location.",
      psStatus: "Warning",
      evidenceSource: ENTRA_BREAKGLASS_CONFIG_ENDPOINTS.directoryRoles,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE_DIRECTORY,
    });
  } else {
    ctx.addRow({
      category: "Break Glass",
      setting: "Emergency Access Accounts",
      currentValue: "No break-glass account detected among Global Admins",
      recommendedValue: "At least 2 enabled break-glass accounts with Global Admin role",
      checkId: "ENTRA-BREAKGLASS-001",
      remediation: "Create 2 cloud-only break-glass accounts with Global Admin, excluded from all CA policies, with FIDO2 security keys, monitored.",
      psStatus: "Fail",
      evidenceSource: ENTRA_BREAKGLASS_CONFIG_ENDPOINTS.directoryRoles,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE_DIRECTORY,
    });
  }
};
