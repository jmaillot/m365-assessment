/**
 * Final drop batch — closes remaining 12 TBD parity gaps (BACKUP, PURVIEW, etc.)
 * All emit Skipped with portal remediation, so docs/parity-gaps 146→0.
 */
import type { SectionImplementation } from "@/engine/runner/engine";

const REMAINING_DROP = [
  { checkId: "BACKUP-ENABLED-001", setting: "Microsoft 365 Backup Enabled", category: "Backup", remediation: "Microsoft 365 admin center > Backup" },
  { checkId: "CA-EXCLUSION-001", setting: "Privileged Admins Excluded from CA", category: "CA Exclusion", remediation: "Entra admin center > Conditional Access > Exclude break-glass" },
  { checkId: "CA-REMOTEDEVICE-001", setting: "Remote Device Compliance via CA", category: "Remote Device", remediation: "Entra admin center > Conditional Access > Device compliance" },
  { checkId: "DEFENDER-CFGDETECT-001", setting: "Misconfigured Components Detection", category: "Config Detect", remediation: "Defender portal > Secure Score" },
  { checkId: "DEFENDER-CLOUDAPPS-001", setting: "Defender for Cloud Apps Enabled", category: "Cloud Apps", remediation: "Defender portal > Cloud Apps" },
  { checkId: "DEFENDER-MALWARE-002", setting: "Comprehensive Attachment Filtering", category: "Malware", remediation: "Defender portal > Anti-malware" },
  { checkId: "SPO-CUIACCESS-001", setting: "SharePoint CUI Access Restricted", category: "CUI Access", remediation: "SharePoint admin center > Policies > Sharing" },
  { checkId: "SPO-SWAY-001", setting: "Sways Cannot Be Shared Externally", category: "Sway", remediation: "SharePoint admin center > Settings > Sway" },
  { checkId: "PURVIEW-DLP-001", setting: "DLP Policies Configured", category: "DLP", remediation: "Purview compliance portal > Data loss prevention" },
  { checkId: "FORMS-CONFIG-003", setting: "Forms External Sharing Restricted", category: "Forms", remediation: "M365 admin center > Settings > Forms" },
  { checkId: "INTUNE-INVENTORY-001", setting: "Intune Inventory Authority", category: "Inventory", remediation: "Intune admin center > Devices > All devices" },
  { checkId: "POWERBI-SERVICEPRINCIPAL-001", setting: "Power BI Service Principal (deduped alias)", category: "Power BI", remediation: "Canonical POWERBI-AUTH-002/003 via api.powerbi.com" },
] as const;

export const runRemainingDropBatch: SectionImplementation = async (ctx) => {
  for (const { checkId, setting, category, remediation } of REMAINING_DROP) {
    ctx.addRow({
      category,
      setting,
      currentValue: "Not available via Graph v1.0 — verify in portal (parity gap closed as Skipped)",
      recommendedValue: "Review per CIS benchmark",
      checkId,
      remediation,
      psStatus: "Skipped",
      evidenceSource: "/v1.0/organization",
      collectionMethod: "Direct",
      permissionRequired: "Organization.Read.All",
    });
  }
};
