/**
 * Port of `src/M365-Assess/Exchange-Online/Get-ExoSecurityConfig.ps1` (679 lines)
 * — Exchange Online security configuration (AssessmentMaps Exchange entry).
 *
 * PS → TS mapping per D-22/D-27/D-28/D-29/D-30:
 * - Original PS uses Exchange Online PowerShell cmdlets exclusively.
 *   Graph v1.0 has no admin exchange promotion for most surfaces; one vetted
 *   beta keep is retained per D-27 (BETA-ENDPOINTS.md).
 *   All other PS-only CheckIds without v1 or vetted beta surface as Review with
 *   manual CurrentValue and Exchange admin center remediation per D-28.
 * - Mailbox trio EXO-AUDIT-003 / EXO-SHAREDMBX-001 / EXO-HIDDEN-001 approximated
 *   via Graph GET /v1.0/users?$select=... per D-29; where recipientTypeDetails
 *   typing unavailable degrade to Review with limitations.
 * - Per-check 403 → Skipped(not_licensed) with Missing permissions — {Role} not granted; re-consent to grant
 *   + Grant {Role} via admin consent remediation; 404/empty → Warning No {policy} configured — review per D-30 verbatim.
 * - Initialize-SecurityConfig / Add-Setting owned by runner's addRow pipeline.
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
// D-27 beta→keep — see BETA-ENDPOINTS.md
export const EXCHANGE_SECURITY_CONFIG_ENDPOINTS = {
  /** Probe used to assert User.Read.All / Directory.Read.All for mailbox checks. */
  users: "/v1.0/users?$select=accountEnabled,userPrincipalName,displayName&$top=100",
  /** Subscribed SKUs probe supporting the EXO-LOCKBOX-001 license rationale. */
  subscribedSkus: "/v1.0/subscribedSkus",
  /** Vetted beta keep covering OrganizationConfig surface where v1.0 has no equivalent. */
  orgSettings: "/beta/admin/exchange/settings",
} as const;

const DIRECTORY_READ_ALL = "Directory.Read.All";
const USER_READ_ALL = "User.Read.All";
const ORGANIZATION_READ_ALL = "Organization.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

function emitReview(
  ctx: Parameters<SectionImplementation>[0],
  category: string,
  setting: string,
  checkId: string,
  recommendedValue: string,
  remediation: string,
) {
  ctx.addRow({
    category,
    setting,
    currentValue: `Requires manual verification in Exchange admin center — ${setting} cannot be read via Graph`,
    recommendedValue,
    checkId,
    remediation,
    psStatus: "Review",
    evidenceSource: "/v1.0/organization",
    collectionMethod: "Direct",
    permissionRequired: ORGANIZATION_READ_ALL,
  });
}

export const runExchangeSecurityConfig: SectionImplementation = async (ctx) => {
  // ------------------------------------------------------------------
  // Vetted beta keep — OrganizationConfig surface via beta admin exchange settings
  // Covers EXO-AUTH-001 / EXO-AUDIT-001 family where beta surface exists.
  // Per-check 403 → Skipped with Missing permissions copy, 404/empty → Warning.
  // ------------------------------------------------------------------
  try {
    const orgResp = (await ctx.transport.getJson(
      EXCHANGE_SECURITY_CONFIG_ENDPOINTS.orgSettings,
      { requiredRole: DIRECTORY_READ_ALL },
    )) as Record<string, unknown>;

    // EXO-AUTH-001 — Modern Authentication
    const modernAuth = orgResp.modernAuthEnabled as boolean | undefined ?? orgResp.OAuth2ClientProfileEnabled as boolean | undefined;
    if (modernAuth === true) {
      ctx.addRow({
        category: "Authentication",
        setting: "Modern Authentication Enabled",
        currentValue: "True",
        recommendedValue: "True",
        checkId: "EXO-AUTH-001",
        remediation: "",
        psStatus: "Pass",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.orgSettings,
        collectionMethod: "Direct",
        permissionRequired: DIRECTORY_READ_ALL,
        confidence: 1.0,
      });
    } else if (modernAuth === false) {
      ctx.addRow({
        category: "Authentication",
        setting: "Modern Authentication Enabled",
        currentValue: "False",
        recommendedValue: "True",
        checkId: "EXO-AUTH-001",
        remediation: "Exchange admin center > Settings > Modern authentication — enable Modern Authentication",
        psStatus: "Fail",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.orgSettings,
        collectionMethod: "Direct",
        permissionRequired: DIRECTORY_READ_ALL,
      });
    } else {
      ctx.addRow({
        category: "Authentication",
        setting: "Modern Authentication Enabled",
        currentValue: "No Modern Authentication policy configured — review",
        recommendedValue: "True",
        checkId: "EXO-AUTH-001",
        remediation: "Exchange admin center > Settings > Modern authentication — verify Modern Authentication",
        psStatus: "Warning",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.orgSettings,
        collectionMethod: "Direct",
        permissionRequired: DIRECTORY_READ_ALL,
      });
    }

    // EXO-AUDIT-001 — Organization Audit
    const auditEnabled = orgResp.auditEnabled as boolean | undefined ?? orgResp.UnifiedAuditLogIngestionEnabled as boolean | undefined;
    if (auditEnabled === true) {
      ctx.addRow({
        category: "Auditing",
        setting: "Exchange Org Audit Config",
        currentValue: "Enabled",
        recommendedValue: "Enabled",
        checkId: "EXO-AUDIT-001",
        remediation: "",
        psStatus: "Pass",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.orgSettings,
        collectionMethod: "Direct",
        permissionRequired: DIRECTORY_READ_ALL,
        confidence: 1.0,
      });
    } else if (auditEnabled === false) {
      ctx.addRow({
        category: "Auditing",
        setting: "Exchange Org Audit Config",
        currentValue: "Disabled",
        recommendedValue: "Enabled",
        checkId: "EXO-AUDIT-001",
        remediation: "Exchange admin center > Compliance > Audit log — enable Unified Audit Log",
        psStatus: "Fail",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.orgSettings,
        collectionMethod: "Direct",
        permissionRequired: DIRECTORY_READ_ALL,
      });
    } else {
      ctx.addRow({
        category: "Auditing",
        setting: "Exchange Org Audit Config",
        currentValue: "No audit policy configured — review",
        recommendedValue: "Enabled",
        checkId: "EXO-AUDIT-001",
        remediation: "Exchange admin center > Compliance > Audit log — verify audit is enabled",
        psStatus: "Warning",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.orgSettings,
        collectionMethod: "Direct",
        permissionRequired: DIRECTORY_READ_ALL,
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      for (const { checkId, setting, category } of [
        { checkId: "EXO-AUTH-001", setting: "Modern Authentication Enabled", category: "Authentication" },
        { checkId: "EXO-AUDIT-001", setting: "Exchange Org Audit Config", category: "Auditing" },
      ] as const) {
        ctx.addRow({
          category,
          setting,
          currentValue: `Missing permissions — ${DIRECTORY_READ_ALL} not granted; re-consent to grant`,
          recommendedValue: setting.includes("Modern") ? "True" : "Enabled",
          checkId,
          remediation: `Grant ${DIRECTORY_READ_ALL} via admin consent and re-run`,
          psStatus: "Skipped",
          evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.orgSettings,
          collectionMethod: "Direct",
          permissionRequired: DIRECTORY_READ_ALL,
        });
      }
    } else if (errMatches(err, /404|NotFound|does not exist/i)) {
      for (const { checkId, setting, category, recommended } of [
        { checkId: "EXO-AUTH-001", setting: "Modern Authentication Enabled", category: "Authentication", recommended: "True" },
        { checkId: "EXO-AUDIT-001", setting: "Exchange Org Audit Config", category: "Auditing", recommended: "Enabled" },
      ] as const) {
        ctx.addRow({
          category,
          setting,
          currentValue: `No ${setting} configured — review`,
          recommendedValue: recommended,
          checkId,
          remediation: `Exchange admin center — verify ${setting}`,
          psStatus: "Warning",
          evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.orgSettings,
          collectionMethod: "Direct",
          permissionRequired: DIRECTORY_READ_ALL,
        });
      }
    } else {
      // PS Write-Warning parity — no rows for transient failures beyond beta keep
    }
  }

  // ------------------------------------------------------------------
  // Customer Lockbox — subscribedSkus E5 probe per D-30, success Review where org-flag unavailable
  // ------------------------------------------------------------------
  try {
    const skusResp = await ctx.transport.getJson(
      EXCHANGE_SECURITY_CONFIG_ENDPOINTS.subscribedSkus,
      { requiredRole: DIRECTORY_READ_ALL },
    );
    const skus = asArray(skusResp.value);
    const e5Ids = new Set([
      "06ebc4ee-1bb5-47dd-8120-11324bc54e06",
      "cd2925a3-5076-4233-8931-638a8c94f773",
      "d17b27af-3f49-4822-99f9-56a661538792",
    ]);
    const hasE5 = skus.some(
      (s) => typeof s.skuId === "string" && e5Ids.has(s.skuId as string) && s.capabilityStatus === "Enabled",
    );
    // Org flag unavailable via Graph v1.0 — surface as Review with E5 context
    ctx.addRow({
      category: "Security",
      setting: "Customer Lockbox Enabled",
      currentValue: hasE5
        ? "Requires manual verification in Exchange admin center — Customer Lockbox cannot be read via Graph (E5 license detected — lockbox available)"
        : "Requires manual verification in Exchange admin center — Customer Lockbox cannot be read via Graph",
      recommendedValue: "True (E5 license)",
      checkId: "EXO-LOCKBOX-001",
      remediation: "Exchange admin center > Roles > Customer Lockbox — verify Enabled, or run Get-OrganizationConfig | Select CustomerLockboxEnabled in Exchange Online PowerShell",
      psStatus: "Review",
      evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.subscribedSkus,
      collectionMethod: "Derived",
      permissionRequired: DIRECTORY_READ_ALL,
      confidence: 0.6,
      limitations: "Graph /v1.0/subscribedSkus can assert E5 licensing but not OrganizationConfig CustomerLockboxEnabled; verify via Get-OrganizationConfig.",
    });
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      ctx.addRow({
        category: "Security",
        setting: "Customer Lockbox Enabled",
        currentValue: `Missing permissions — ${DIRECTORY_READ_ALL} not granted; re-consent to grant`,
        recommendedValue: "True (E5 license)",
        checkId: "EXO-LOCKBOX-001",
        remediation: `Grant ${DIRECTORY_READ_ALL} via admin consent and re-run`,
        psStatus: "Skipped",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.subscribedSkus,
        collectionMethod: "Direct",
        permissionRequired: DIRECTORY_READ_ALL,
      });
    } else {
      ctx.addRow({
        category: "Security",
        setting: "Customer Lockbox Enabled",
        currentValue: "Requires manual verification in Exchange admin center — Customer Lockbox cannot be read via Graph",
        recommendedValue: "True (E5 license)",
        checkId: "EXO-LOCKBOX-001",
        remediation: "Exchange admin center > Roles > Customer Lockbox — verify Enabled, or run Get-OrganizationConfig in Exchange Online PowerShell",
        psStatus: "Review",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.subscribedSkus,
        collectionMethod: "Direct",
        permissionRequired: DIRECTORY_READ_ALL,
      });
    }
  }

  // ------------------------------------------------------------------
  // Dropped PS-only checks — no v1 and no vetted beta → Review with manual remediation per D-28
  // ------------------------------------------------------------------
  emitReview(ctx, "Mail Tips", "All MailTips Enabled", "EXO-MAILTIPS-001", "True", "Exchange admin center > Policies & rules > MailTips — verify All MailTips, or run Get-OrganizationConfig in Exchange Online PowerShell");
  emitReview(ctx, "Mail Tips", "External Recipients Tips Enabled", "EXO-MAILTIPS-001", "True", "Exchange admin center > Policies & rules > MailTips — verify External Recipients Tips, or run Get-OrganizationConfig in Exchange Online PowerShell");
  emitReview(ctx, "Mail Tips", "Group Metrics Enabled", "EXO-MAILTIPS-001", "True", "Exchange admin center > Policies & rules > MailTips — verify Group Metrics, or run Get-OrganizationConfig in Exchange Online PowerShell");
  emitReview(ctx, "Mail Tips", "Large Audience Threshold", "EXO-MAILTIPS-001", "25 or less", "Exchange admin center > Policies & rules > MailTips — verify Large Audience Threshold, or run Get-OrganizationConfig in Exchange Online PowerShell");
  emitReview(ctx, "Email Security", "External Sender Tagging", "EXO-EXTTAG-001", "True", "Exchange admin center > Policies & rules > Threat policies > External tagging — verify External Sender Tagging, or run Get-ExternalInOutlook in Exchange Online PowerShell");
  emitReview(ctx, "Email Security", "Auto-Forward to External (Default Domain)", "EXO-FORWARD-001", "False", "Exchange admin center > Policies & rules > Remote domains — verify Auto-Forward, or run Get-RemoteDomain in Exchange Online PowerShell");
  emitReview(ctx, "OWA Policy", "OWA Additional Storage", "EXO-OWA-001", "False", "Exchange admin center > Policies & rules > OWA mailbox policy — verify Additional Storage Providers, or run Get-OwaMailboxPolicy in Exchange Online PowerShell");
  emitReview(ctx, "Sharing", "Default Calendar External Sharing", "EXO-SHARING-001", "Restricted", "Exchange admin center > Policies & rules > Sharing — verify Calendar Sharing, or run Get-SharingPolicy in Exchange Online PowerShell");
  emitReview(ctx, "Auditing", "Mailboxes with Audit Bypass", "EXO-AUDIT-002", "0", "Exchange admin center > Compliance > Audit log — verify Mailbox Audit Bypass, or run Get-MailboxAuditBypassAssociation in Exchange Online PowerShell");
  emitReview(ctx, "Authentication", "SMTP AUTH Disabled (Org-Wide)", "EXO-AUTH-002", "True", "Exchange admin center > Settings > Mail flow > SMTP AUTH — verify Disabled, or run Get-TransportConfig in Exchange Online PowerShell");
  emitReview(ctx, "Applications", "Outlook Add-ins Allowed", "EXO-ADDINS-001", "Restricted", "Exchange admin center > Roles > Outlook add-ins — verify Add-ins, or run Get-RoleAssignmentPolicy in Exchange Online PowerShell");
  emitReview(ctx, "Connection Filter", "IP Allow List", "EXO-CONNFILTER-001", "Empty (0 IPs)", "Exchange admin center > Policies & rules > Threat policies > Anti-spam inbound policy — verify IP allow list, or run Get-HostedConnectionFilterPolicy in Exchange Online PowerShell");
  emitReview(ctx, "Connection Filter", "Enable Safe List", "EXO-CONNFILTER-002", "False", "Exchange admin center > Policies & rules > Threat policies > Anti-spam inbound policy — verify Safe List, or run Get-HostedConnectionFilterPolicy in Exchange Online PowerShell");
  emitReview(ctx, "Transport Rules", "Domain whitelist transport rules", "EXO-TRANSPORT-001", "No rules whitelisting domains", "Exchange admin center > Policies & rules > Mail flow > Rules — verify Domain whitelist, or run Get-TransportRule in Exchange Online PowerShell");
  emitReview(ctx, "Mail Flow", "Inbound Connectors - Unauthenticated Relay", "EXO-DIRECTSEND-001", "No open relay connectors", "Exchange admin center > Mail flow > Connectors — verify Inbound Connectors, or run Get-InboundConnector in Exchange Online PowerShell");

  // ------------------------------------------------------------------
  // Mailbox trio — Graph /v1.0/users approximation per D-29
  // ------------------------------------------------------------------
  try {
    const usersResp = await ctx.transport.getJson(EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users, {
      requiredRole: USER_READ_ALL,
    });
    const users = asArray(usersResp.value);
    const enabledCount = users.filter((u) => u.accountEnabled === true).length;

    // EXO-SHAREDMBX-001 — Shared Mailbox Sign-In Blocked
    if (users.length === 0) {
      ctx.addRow({
        category: "Mailbox Security",
        setting: "Shared Mailbox Sign-In Blocked",
        currentValue: "No directory users returned — requires Exchange verification",
        recommendedValue: "All shared mailbox accounts disabled",
        checkId: "EXO-SHAREDMBX-001",
        remediation: "Exchange admin center > Recipients > Shared mailboxes — verify Sign-In Blocked, or run Get-Mailbox -RecipientTypeDetails SharedMailbox | Select AccountEnabled in Exchange Online PowerShell",
        psStatus: "Review",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users,
        collectionMethod: "Derived",
        permissionRequired: USER_READ_ALL,
        confidence: 0.6,
        limitations: "Graph /v1.0/users cannot filter by recipientTypeDetails SharedMailbox; verify via Get-Mailbox -RecipientTypeDetails SharedMailbox.",
      });
    } else if (enabledCount === 0) {
      ctx.addRow({
        category: "Mailbox Security",
        setting: "Shared Mailbox Sign-In Blocked",
        currentValue: `All ${users.length} directory accounts disabled — shared typing requires Exchange verification`,
        recommendedValue: "All shared mailbox accounts disabled",
        checkId: "EXO-SHAREDMBX-001",
        remediation: "Exchange admin center > Recipients > Shared mailboxes — verify Sign-In Blocked, or run Get-Mailbox -RecipientTypeDetails SharedMailbox in Exchange Online PowerShell",
        psStatus: "Pass",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users,
        collectionMethod: "Derived",
        permissionRequired: USER_READ_ALL,
        confidence: 0.7,
        limitations: "Graph /v1.0/users cannot filter by recipientTypeDetails SharedMailbox; verify via Get-Mailbox -RecipientTypeDetails SharedMailbox + Graph accountEnabled per PS lines 533-541.",
      });
    } else {
      ctx.addRow({
        category: "Mailbox Security",
        setting: "Shared Mailbox Sign-In Blocked",
        currentValue: `${enabledCount}/${users.length} directory accounts enabled — shared mailbox accounts require Exchange verification`,
        recommendedValue: "All shared mailbox accounts disabled",
        checkId: "EXO-SHAREDMBX-001",
        remediation: "Exchange admin center > Recipients > Shared mailboxes — verify Sign-In Blocked, or run Get-Mailbox -RecipientTypeDetails SharedMailbox | Select AccountEnabled in Exchange Online PowerShell",
        psStatus: "Review",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users,
        collectionMethod: "Derived",
        permissionRequired: USER_READ_ALL,
        confidence: 0.6,
        limitations: "Graph /v1.0/users cannot filter by recipientTypeDetails SharedMailbox; verify via Get-Mailbox -RecipientTypeDetails SharedMailbox + Graph accountEnabled per PS lines 533-541.",
      });
    }

    // EXO-AUDIT-003 — Mailbox Auditing (sample)
    if (users.length === 0) {
      ctx.addRow({
        category: "Mailbox Security",
        setting: "Mailbox Auditing (sample)",
        currentValue: "Requires manual verification in Exchange admin center — Mailbox Auditing cannot be read via Graph",
        recommendedValue: "AuditEnabled = True",
        checkId: "EXO-AUDIT-003",
        remediation: "Exchange admin center > Compliance > Audit log — verify Mailbox Auditing, or run Get-Mailbox | Select AuditEnabled in Exchange Online PowerShell",
        psStatus: "Review",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users,
        collectionMethod: "Derived",
        permissionRequired: USER_READ_ALL,
        confidence: 0.6,
        limitations: "Graph /v1.0/users cannot filter by recipientTypeDetails UserMailbox nor assert AuditEnabled; verify via Get-Mailbox -RecipientTypeDetails UserMailbox.",
      });
    } else {
      ctx.addRow({
        category: "Mailbox Security",
        setting: "Mailbox Auditing (sample)",
        currentValue: `Requires manual verification in Exchange admin center — Mailbox Auditing cannot be read via Graph; ${users.length} users enumerated via Graph`,
        recommendedValue: "AuditEnabled = True",
        checkId: "EXO-AUDIT-003",
        remediation: "Exchange admin center > Compliance > Audit log — verify Mailbox Auditing, or run Get-Mailbox | Select AuditEnabled in Exchange Online PowerShell",
        psStatus: "Review",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users,
        collectionMethod: "Derived",
        permissionRequired: USER_READ_ALL,
        confidence: 0.6,
        limitations: "Graph /v1.0/users cannot filter by recipientTypeDetails UserMailbox; verify via Get-Mailbox -RecipientTypeDetails UserMailbox.",
      });
    }

    // EXO-HIDDEN-001 — Hidden User Mailboxes
    if (users.length === 0) {
      ctx.addRow({
        category: "Mailbox Security",
        setting: "Hidden User Mailboxes",
        currentValue: "Requires manual verification in Exchange admin center — HiddenFromAddressListsEnabled cannot be read via Graph",
        recommendedValue: "No hidden mailboxes unless intentional",
        checkId: "EXO-HIDDEN-001",
        remediation: "Exchange admin center > Recipients > Mailboxes — verify HiddenFromAddressListsEnabled, or run Get-Mailbox | Select HiddenFromAddressListsEnabled in Exchange Online PowerShell",
        psStatus: "Review",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users,
        collectionMethod: "Derived",
        permissionRequired: USER_READ_ALL,
        confidence: 0.6,
        limitations: "Graph /v1.0/users cannot filter by recipientTypeDetails UserMailbox nor assert HiddenFromAddressListsEnabled; verify via Get-Mailbox -RecipientTypeDetails UserMailbox.",
      });
    } else {
      ctx.addRow({
        category: "Mailbox Security",
        setting: "Hidden User Mailboxes",
        currentValue: `Requires manual verification in Exchange admin center — HiddenFromAddressListsEnabled cannot be read via Graph; ${users.length} users enumerated`,
        recommendedValue: "No hidden mailboxes unless intentional",
        checkId: "EXO-HIDDEN-001",
        remediation: "Exchange admin center > Recipients > Mailboxes — verify HiddenFromAddressListsEnabled, or run Get-Mailbox | Select HiddenFromAddressListsEnabled in Exchange Online PowerShell",
        psStatus: "Review",
        evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users,
        collectionMethod: "Derived",
        permissionRequired: USER_READ_ALL,
        confidence: 0.6,
        limitations: "Graph /v1.0/users cannot filter by recipientTypeDetails UserMailbox; verify via Get-Mailbox -RecipientTypeDetails UserMailbox.",
      });
    }
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      for (const { checkId, setting } of [
        { checkId: "EXO-SHAREDMBX-001", setting: "Shared Mailbox Sign-In Blocked" },
        { checkId: "EXO-AUDIT-003", setting: "Mailbox Auditing (sample)" },
        { checkId: "EXO-HIDDEN-001", setting: "Hidden User Mailboxes" },
      ] as const) {
        ctx.addRow({
          category: "Mailbox Security",
          setting,
          currentValue: `Missing permissions — ${USER_READ_ALL} not granted; re-consent to grant`,
          recommendedValue: setting.includes("Auditing") ? "AuditEnabled = True" : setting.includes("Hidden") ? "No hidden mailboxes unless intentional" : "All shared mailbox accounts disabled",
          checkId,
          remediation: `Grant ${USER_READ_ALL} via admin consent and re-run`,
          psStatus: "Skipped",
          evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users,
          collectionMethod: "Direct",
          permissionRequired: USER_READ_ALL,
        });
      }
    } else {
      for (const { checkId, setting, recommended } of [
        { checkId: "EXO-SHAREDMBX-001", setting: "Shared Mailbox Sign-In Blocked", recommended: "All shared mailbox accounts disabled" },
        { checkId: "EXO-AUDIT-003", setting: "Mailbox Auditing (sample)", recommended: "AuditEnabled = True" },
        { checkId: "EXO-HIDDEN-001", setting: "Hidden User Mailboxes", recommended: "No hidden mailboxes unless intentional" },
      ] as const) {
        ctx.addRow({
          category: "Mailbox Security",
          setting,
          currentValue: "Requires manual verification in Exchange admin center — HiddenFromAddressListsEnabled cannot be read via Graph",
          recommendedValue: recommended,
          checkId,
          remediation: "Exchange admin center > Recipients > Mailboxes — verify via Get-Mailbox in Exchange Online PowerShell",
          psStatus: "Review",
          evidenceSource: EXCHANGE_SECURITY_CONFIG_ENDPOINTS.users,
          collectionMethod: "Direct",
          permissionRequired: USER_READ_ALL,
          limitations: "Graph /v1.0/users cannot filter by recipientTypeDetails; verify via Get-Mailbox -RecipientTypeDetails.",
        });
      }
    }
  }
};
