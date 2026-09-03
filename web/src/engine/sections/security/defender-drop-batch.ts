/**
 * Drop batch — remaining DEFENDER PS-only checks with no Graph v1.0 parity.
 * All emit Skipped with portal remediation, closing 146 gap for DEFENDER.
 */
import type { SectionImplementation } from "@/engine/runner/engine";

const DEFENDER_DROP = [
  { checkId: "DEFENDER-ANTIMALWARE-001", setting: "Common Attachment Types Filter Enabled", category: "AntiMalware", remediation: "Defender portal > Policies & rules > Threat policies > Anti-malware" },
  { checkId: "DEFENDER-ANTIMALWARE-002", setting: "Notifications for Internal Users Sending Malware Enabled", category: "AntiMalware", remediation: "Defender portal > Policies & rules > Threat policies > Anti-malware" },
  { checkId: "DEFENDER-ANTISPAM-002", setting: "Inbound Anti-Spam Policies Do Not Contain Allowed Domains", category: "AntiSpam", remediation: "Defender portal > Policies & rules > Threat policies > Anti-spam" },
  { checkId: "DEFENDER-CFGDETECT-001", setting: "Automated Detection of Misconfigured Components", category: "Config Detect", remediation: "Defender portal > Policies & rules" },
  { checkId: "DEFENDER-CLOUDAPPS-001", setting: "Microsoft Defender for Cloud Apps Enabled", category: "Cloud Apps", remediation: "Defender portal > Cloud Apps" },
  { checkId: "DEFENDER-MALWARE-002", setting: "Comprehensive Attachment Filtering Applied", category: "Malware", remediation: "Defender portal > Policies & rules > Threat policies > Anti-malware" },
  { checkId: "DEFENDER-OUTBOUND-001", setting: "Outbound Anti-Spam Message Limits In Place", category: "Outbound", remediation: "Defender portal > Policies & rules > Threat policies > Anti-spam > Outbound" },
  { checkId: "DEFENDER-PRIORITY-001", setting: "Priority Account Protection Enabled", category: "Priority", remediation: "Defender portal > Policies & rules > Threat policies > Priority account protection" },
  { checkId: "DEFENDER-PRIORITY-002", setting: "Priority Accounts Have Strict Protection Presets Applied", category: "Priority", remediation: "Defender portal > Policies & rules > Threat policies > Priority account protection" },
  { checkId: "DEFENDER-REALTIMESCAN-001", setting: "Defender Antivirus Real-Time Protection Enabled", category: "RealTimeScan", remediation: "Intune admin center > Endpoint security > Antivirus" },
  { checkId: "DEFENDER-SAFEATTACH-002", setting: "Safe Attachments for SharePoint OneDrive and Teams Enabled", category: "Safe Attach", remediation: "Defender portal > Policies & rules > Threat policies > Safe Attachments" },
  { checkId: "DEFENDER-SECUREMON-001", setting: "Continuous Security Monitoring via Secure Score", category: "Secure Monitor", remediation: "Defender portal > Secure Score" },
  { checkId: "DEFENDER-VULNSCAN-001", setting: "Vulnerability Scanning Active via Defender", category: "Vuln Scan", remediation: "Defender portal > Vulnerability management" },
  { checkId: "DEFENDER-ZAP-001", setting: "Zero-Hour Auto Purge for Teams Enabled", category: "ZAP", remediation: "Defender portal > Policies & rules > Threat policies > Zero-hour auto purge" },
] as const;

export const runDefenderDropBatch: SectionImplementation = async (ctx) => {
  for (const { checkId, setting, category, remediation } of DEFENDER_DROP) {
    ctx.addRow({
      category,
      setting,
      currentValue: "Not available via Graph v1.0 — verify in Defender portal",
      recommendedValue: "Review per CIS benchmark",
      checkId,
      remediation,
      psStatus: "Skipped",
      evidenceSource: "/v1.0/security/secureScores",
      collectionMethod: "Direct",
      permissionRequired: "SecurityEvents.Read.All",
    });
  }
};
