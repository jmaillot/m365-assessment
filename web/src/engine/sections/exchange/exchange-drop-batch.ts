/**
 * Drop batch — remaining EXO PS-only checks with no Graph v1.0 parity.
 * Per D-28 all emit Review with manual verification copy, per D-27 one vetted
 * beta keep (/beta/admin/exchange/settings) is NOT in this batch.
 */
import type { SectionImplementation } from "@/engine/runner/engine";

const EXO_DROP = [
  { checkId: "EXO-ADDINS-001", setting: "Outlook Add-ins Installation Not Allowed", category: "Applications", remediation: "Exchange admin center > Policies & rules > Outlook add-ins — verify Outlook Add-ins, or run Get-RoleAssignmentPolicy in Exchange Online PowerShell" },
  { checkId: "EXO-ANTIPHISH-001", setting: "Anti-Phishing Policy Configuration", category: "AntiPhish", remediation: "Exchange admin center > Policies & rules > Threat policies > Anti-phishing — verify Anti-Phishing Policy, or run Get-AntiPhishPolicy in Exchange Online PowerShell" },
  { checkId: "EXO-ANTISPAM-001", setting: "Anti-Spam Policy Configuration", category: "AntiSpam", remediation: "Exchange admin center > Policies & rules > Threat policies > Anti-spam — verify Anti-Spam Policy, or run Get-HostedContentFilterPolicy in Exchange Online PowerShell" },
  { checkId: "EXO-AUDIT-002", setting: "AuditBypassEnabled Not Enabled on Mailboxes", category: "Auditing", remediation: "Exchange admin center > Compliance > Audit log — verify AuditBypassEnabled, or run Get-MailboxAuditBypassAssociation in Exchange Online PowerShell" },
  { checkId: "EXO-AUTH-002", setting: "SMTP AUTH Disabled", category: "Authentication", remediation: "Exchange admin center > Settings > Mail flow > SMTP AUTH — verify Disabled, or run Get-TransportConfig in Exchange Online PowerShell" },
  { checkId: "EXO-CONNFILTER-001", setting: "Connection Filter IP Allow List Not Used", category: "Connection Filter", remediation: "Exchange admin center > Policies & rules > Threat policies > Anti-spam > Connection filter — verify IP Allow List, or run Get-HostedConnectionFilterPolicy in Exchange Online PowerShell" },
  { checkId: "EXO-CONNFILTER-002", setting: "Connection Filter Safe List Off", category: "Connection Filter", remediation: "Exchange admin center > Policies & rules > Threat policies > Anti-spam > Connection filter — verify Safe List, or run Get-HostedConnectionFilterPolicy in Exchange Online PowerShell" },
  { checkId: "EXO-DIRECTSEND-001", setting: "Direct Send Not Allowed for Unauthorized Relay", category: "Mail Flow", remediation: "Exchange admin center > Mail flow > Connectors — verify Inbound Connectors, or run Get-InboundConnector in Exchange Online PowerShell" },
  { checkId: "EXO-DKIM-001", setting: "DKIM Signing Configuration", category: "DKIM", remediation: "Exchange admin center > DKIM — verify DKIM Signing, or run Get-DkimSigningConfig in Exchange Online PowerShell" },
  { checkId: "EXO-EXTTAG-001", setting: "Email From External Senders Identified", category: "Email Security", remediation: "Exchange admin center > Policies & rules > Threat policies > External tagging — verify External Sender Tagging, or run Get-ExternalInOutlook in Exchange Online PowerShell" },
  { checkId: "EXO-FORWARD-001", setting: "Mail Forwarding Blocked", category: "Email Security", remediation: "Exchange admin center > Policies & rules > Remote domains — verify Mail Forwarding, or run Get-RemoteDomain in Exchange Online PowerShell" },
  { checkId: "EXO-MALWARE-001", setting: "Malware Filter Policy Configuration", category: "Malware", remediation: "Exchange admin center > Policies & rules > Threat policies > Anti-malware — verify Malware Filter, or run Get-MalwareFilterPolicy in Exchange Online PowerShell" },
  { checkId: "EXO-OWA-001", setting: "Additional Storage Providers Restricted in OWA", category: "OWA Policy", remediation: "Exchange admin center > Settings > OWA mailbox policy — verify Additional Storage Providers, or run Get-OwaMailboxPolicy in Exchange Online PowerShell" },
  { checkId: "EXO-SHARING-001", setting: "External Sharing of Calendars Not Available", category: "Sharing", remediation: "Exchange admin center > Sharing — verify Calendar Sharing, or run Get-SharingPolicy in Exchange Online PowerShell" },
  { checkId: "EXO-TRANSPORT-001", setting: "Mail Transport Rules Do Not Whitelist Domains", category: "Transport Rules", remediation: "Exchange admin center > Policies & rules > Mail flow > Rules — verify Domain Whitelist, or run Get-TransportRule in Exchange Online PowerShell" },
  { checkId: "EXO-TRANSPORT-002", setting: "Transport Rule for External Forwarding", category: "Transport Rules", remediation: "Exchange admin center > Policies & rules > Mail flow > Rules — verify External Forwarding Rule, or run Get-TransportRule in Exchange Online PowerShell" },
  { checkId: "EXO-SHAREDMBX-001", setting: "Shared Mailbox Sign-In Blocked", category: "Mailbox Security", remediation: "Exchange admin center > Recipients > Shared mailboxes — verify Sign-In Blocked, or run Get-Mailbox -RecipientTypeDetails SharedMailbox in Exchange Online PowerShell" },
  { checkId: "EXO-AUDIT-003", setting: "Mailbox Audit Actions Configured", category: "Audit", remediation: "Exchange admin center > Compliance > Audit log — verify Mailbox Audit, or run Get-Mailbox in Exchange Online PowerShell" },
  { checkId: "EXO-HIDDEN-001", setting: "No User Mailboxes Hidden from GAL", category: "Mailbox Security", remediation: "Exchange admin center > Recipients > Mailboxes — verify HiddenFromAddressListsEnabled, or run Get-Mailbox in Exchange Online PowerShell" },
] as const;

export const runExchangeDropBatch: SectionImplementation = async (ctx) => {
  for (const { checkId, setting, category, remediation } of EXO_DROP) {
    ctx.addRow({
      category,
      setting,
      currentValue: `Requires manual verification in Exchange admin center — ${setting} cannot be read via Graph`,
      recommendedValue: "Review per CIS benchmark",
      checkId,
      remediation,
      psStatus: "Review",
      evidenceSource: "/v1.0/organization",
      collectionMethod: "Direct",
      permissionRequired: "Organization.Read.All",
    });
  }
};
