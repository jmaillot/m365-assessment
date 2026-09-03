/**
 * Port of Entra GROUP 004..006 + HYBRID 002 — Group and hybrid checks.
 * Graph: GET /v1.0/groups, /v1.0/users, /v1.0/directoryRoles
 * Roles: Group.Read.All, User.Read.All, Directory.Read.All, 403 -> Review.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, psStr } from "./shared";

const REQUIRED_GROUP = "Group.Read.All";
const REQUIRED_USER = "User.Read.All";
const REQUIRED_DIRECTORY = "Directory.Read.All";
const AUTHORIZATION_ERROR = /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

export const runEntraGroupAdditional: SectionImplementation = async (ctx) => {
  // GROUP-004 — Dynamic groups with user-controllable membership rule
  try {
    const resp = await ctx.transport.getJson("/v1.0/groups?$filter=groupTypes/any(g:g eq 'DynamicMembership')&$select=id,displayName,membershipRule,groupTypes&$top=999", { requiredRole: REQUIRED_GROUP });
    const groups = asArray(resp.value);
    const controllable = groups.filter((g) => {
      const rule = psStr((g as Record<string, unknown>).membershipRule).toLowerCase();
      return rule.includes("user.") && (rule.includes("department") || rule.includes("jobtitle"));
    });
    ctx.addRow({
      category: "Group",
      setting: "Dynamic Groups with User-Controllable Membership",
      currentValue: controllable.length > 0 ? `${controllable.length} dynamic groups with user-controllable rules` : "No dynamic groups with user-controllable rules",
      recommendedValue: "No dynamic groups where users can control membership via department/jobTitle",
      checkId: "ENTRA-GROUP-004",
      remediation: "Entra admin center > Groups > Dynamic groups > Review membership rules for user.department/jobTitle",
      psStatus: controllable.length > 0 ? "Fail" : "Pass",
      evidenceSource: "/v1.0/groups",
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_GROUP,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Group",
        setting: "Dynamic Groups with User-Controllable Membership",
        currentValue: "Insufficient permissions (Group.Read.All)",
        recommendedValue: "No dynamic groups where users can control membership",
        checkId: "ENTRA-GROUP-004",
        remediation: "Requires Group.Read.All",
        psStatus: "Review",
        evidenceSource: "/v1.0/groups",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_GROUP,
      });
    }
  }

  // GROUP-005 — Sensitive groups not protected with role-assignable
  try {
    const resp = await ctx.transport.getJson("/v1.0/groups?$select=id,displayName,groupTypes,isAssignableToRole&$top=999", { requiredRole: REQUIRED_GROUP });
    const groups = asArray(resp.value);
    const sensitive = groups.filter((g) => {
      const name = psStr((g as Record<string, unknown>).displayName).toLowerCase();
      return /admin|privileged|security|all users|all company/i.test(name);
    });
    const unprotected = sensitive.filter((g) => (g as Record<string, unknown>).isAssignableToRole !== true);
    ctx.addRow({
      category: "Group",
      setting: "Sensitive Groups Role-Assignable Protection",
      currentValue: unprotected.length > 0 ? `${unprotected.length} sensitive groups not role-assignable` : "All sensitive groups are role-assignable or none found",
      recommendedValue: "Sensitive groups should be role-assignable (isAssignableToRole: true)",
      checkId: "ENTRA-GROUP-005",
      remediation: "Entra admin center > Groups > recreate sensitive groups with isAssignableToRole true",
      psStatus: unprotected.length > 0 ? "Fail" : "Pass",
      evidenceSource: "/v1.0/groups",
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_GROUP,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Group",
        setting: "Sensitive Groups Role-Assignable Protection",
        currentValue: "Insufficient permissions (Group.Read.All)",
        recommendedValue: "Sensitive groups should be role-assignable",
        checkId: "ENTRA-GROUP-005",
        remediation: "Requires Group.Read.All",
        psStatus: "Review",
        evidenceSource: "/v1.0/groups",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_GROUP,
      });
    }
  }

  // GROUP-006 — Public M365 groups count
  try {
    const resp = await ctx.transport.getJson("/v1.0/groups?$filter=groupTypes/any(g:g eq 'Unified')&$select=id,displayName,visibility&$top=999", { requiredRole: REQUIRED_GROUP });
    const groups = asArray(resp.value);
    const publicGroups = groups.filter((g) => psStr((g as Record<string, unknown>).visibility) === "Public");
    ctx.addRow({
      category: "Group",
      setting: "Public M365 Groups Count",
      currentValue: `${publicGroups.length} public Unified groups`,
      recommendedValue: "Review public groups — limit to necessity",
      checkId: "ENTRA-GROUP-006",
      remediation: "Entra admin center > Groups > Review public M365 groups visibility",
      psStatus: publicGroups.length > 5 ? "Warning" : publicGroups.length > 0 ? "Review" : "Pass",
      evidenceSource: "/v1.0/groups",
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_GROUP,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Group",
        setting: "Public M365 Groups Count",
        currentValue: "Insufficient permissions (Group.Read.All)",
        recommendedValue: "Review public groups",
        checkId: "ENTRA-GROUP-006",
        remediation: "Requires Group.Read.All",
        psStatus: "Review",
        evidenceSource: "/v1.0/groups",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_GROUP,
      });
    }
  }

  // HYBRID-002 — On-prem synced users holding Tier-0 roles
  try {
    const usersResp = await ctx.transport.getJson("/v1.0/users?$filter=onPremisesSyncEnabled eq true&$select=id,displayName,userPrincipalName,onPremisesSyncEnabled&$top=999", { requiredRole: REQUIRED_USER });
    const syncedUsers = asArray(usersResp.value);
    const syncedIds = new Set(syncedUsers.map((u) => psStr((u as Record<string, unknown>).id)));
    // Check Global Admin members that are synced
    const roleResp = await ctx.transport.getJson(`/v1.0/directoryRoles?$filter=roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'`, { requiredRole: REQUIRED_DIRECTORY });
    const roles = asArray(roleResp.value);
    const gaRole = roles.find((r) => psStr((r as Record<string, unknown>).roleTemplateId) === "62e90394-69f5-4237-9190-012177145e10") as Record<string, unknown> | undefined;
    let syncedAdminCount = 0;
    if (gaRole) {
      const membersResp = await ctx.transport.getJson(`/v1.0/directoryRoles/${psStr(gaRole.id)}/members`, { requiredRole: REQUIRED_DIRECTORY });
      const members = asArray(membersResp.value);
      for (const m of members) if (syncedIds.has(psStr((m as Record<string, unknown>).id))) syncedAdminCount++;
    }
    ctx.addRow({
      category: "Hybrid Identity",
      setting: "On-Prem Synced Tier-0 Accounts",
      currentValue: syncedAdminCount > 0 ? `${syncedAdminCount} synced users hold Global Admin` : "No synced users hold Global Admin",
      recommendedValue: "No on-prem synced accounts should hold Tier-0 roles",
      checkId: "ENTRA-HYBRID-002",
      remediation: "Entra admin center > Roles > Convert synced Tier-0 accounts to cloud-only or remove assignment",
      psStatus: syncedAdminCount > 0 ? "Fail" : "Pass",
      evidenceSource: "/v1.0/users",
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_USER,
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Hybrid Identity",
        setting: "On-Prem Synced Tier-0 Accounts",
        currentValue: "Insufficient permissions (User.Read.All, Directory.Read.All)",
        recommendedValue: "No on-prem synced accounts should hold Tier-0 roles",
        checkId: "ENTRA-HYBRID-002",
        remediation: "Requires User.Read.All and Directory.Read.All",
        psStatus: "Review",
        evidenceSource: "/v1.0/users",
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_USER,
      });
    }
  }
};
