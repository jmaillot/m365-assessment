/**
 * Port of `src/M365-Assess/Entra/Get-LicenseReport.ps1` (172 lines)
 * — AssessmentMaps LICENSING section entry '08-License-Summary'
 * (plan 02-06 task 2).
 *
 * PS → TS mapping:
 * - Assert-GraphConnection / Import-Module: owned by the runner/transport.
 * - Get-MgSubscribedSku -All (PS line 93) → GET /v1.0/subscribedSkus with
 *   automatic nextLink pagination (D-27). Failure = PS Write-Error + return
 *   (lines 91-98) → throws; runner surfaces a section error, zero rows.
 * - SKU friendly names: PS tries Microsoft's LIVE CSV download first
 *   (lines 66-75) then falls back to the bundled assets/sku-friendly-names.csv.
 *   The SaaS SKIPS the live download — the transport is a Graph-only choke
 *   point (SSRF host pinning, T-02-06a) and arbitrary web fetches are outside
 *   its contract. The bundled CSV (PS's own fallback source) is used directly;
 *   unknown SkuPartNumbers fall back to the raw part number exactly as PS does.
 * - IncludeUserDetail is NOT ported: AssessmentMaps runs this collector with
 *   Params = @{} (summary mode only). Per-user detail would be a separate
 *   collector if ever needed.
 * - Report rows sorted by License name (PS line 117), one Info row per SKU,
 *   CurrentValue = report record Field=Value in PS property order (lines 106-114).
 *
 * D-20 input contract: writes ctx.shared.set("subscribedSkus", skuStates)
 * where each SkuState carries {skuId, skuPartNumber, servicePlans[]} so
 * runEngine's post-run applyLicensingOverlay consumes REAL service-plan
 * provisioning states — never guesses them.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
import type { SectionImplementation } from "@/engine/runner/engine";
import type { SkuState } from "@/engine/results/licensing-overlay";
import { asArray, kv, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const LICENSE_REPORT_ENDPOINTS = {
  subscribedSkus: "/v1.0/subscribedSkus",
} as const;

const CATEGORY = "License Summary";

/** Quote-aware single-line CSV field splitter (bundled CSV has quoted fields). */
function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

function repoRoot(): string {
  try {
    // web/src/engine/sections/entra/license-report.ts → up 5 = repo root.
    return fileURLToPath(new URL("../../../../..", import.meta.url));
  } catch {
    return resolve(process.cwd(), "..");
  }
}

/**
 * Bundled-CPU friendly-name lookup: String_Id → Product_Display_Name, first
 * occurrence wins (PS Import-SkuCsv parity, Get-LicenseReport.ps1:55-64).
 * Unreadable/unparseable file degrades to {} (PS catch → Verbose + continue);
 * callers then fall back to raw SkuPartNumber. Overridable in tests via
 * createRunLicenseReport({ loadSkuFriendlyNames }).
 */
export function loadBundledSkuFriendlyNames(): Record<string, string> {
  try {
    const csvPath = join(
      repoRoot(),
      "src",
      "M365-Assess",
      "assets",
      "sku-friendly-names.csv",
    );
    const text = readFileSync(csvPath, "utf8").replace(/^\uFEFF/, "");
    const lines = text.split(/\r?\n/).filter((l) => l.length > 0);
    if (lines.length === 0) return {};
    const header = parseCsvLine(lines[0]);
    const nameIdx = header.indexOf("Product_Display_Name");
    const idIdx = header.indexOf("String_Id");
    if (nameIdx === -1 || idIdx === -1) return {};
    const map: Record<string, string> = {};
    for (const line of lines.slice(1)) {
      const fields = parseCsvLine(line);
      const id = fields[idIdx];
      const name = fields[nameIdx];
      if (id && name && !(id in map)) map[id] = name;
    }
    return map;
  } catch {
    return {};
  }
}

export interface LicenseReportDeps {
  /** Injectable friendly-name source (tests); defaults to the bundled CSV. */
  loadSkuFriendlyNames?: () => Record<string, string>;
}

export function createRunLicenseReport(
  deps?: LicenseReportDeps,
): SectionImplementation {
  const loadSkuNames = deps?.loadSkuFriendlyNames ?? loadBundledSkuFriendlyNames;
  return runLicenseReportImpl.bind(null, loadSkuNames) as SectionImplementation;
}

async function runLicenseReportImpl(
  loadSkuNames: () => Record<string, string>,
  ctx: Parameters<SectionImplementation>[0],
): Promise<void> {
  const skus = await ctx.transport.getJson(LICENSE_REPORT_ENDPOINTS.subscribedSkus, {
    requiredRole: "Organization.Read.All",
  });
  const skuList = asArray(skus.value);

  // D-20 input contract: expose real service-plan states to runEngine's
  // overlay post-processing BEFORE any row shaping.
  const skuStates: SkuState[] = skuList.map((sku) => ({
    skuId: typeof sku.skuId === "string" ? sku.skuId : "",
    skuPartNumber: typeof sku.skuPartNumber === "string" ? sku.skuPartNumber : "",
    servicePlans: (Array.isArray(sku.servicePlans)
      ? (sku.servicePlans as Record<string, unknown>[])
      : []
    ).map((plan) => ({
      servicePlanId:
        typeof plan.servicePlanId === "string" ? plan.servicePlanId : "",
      serviceName: typeof plan.serviceName === "string" ? plan.serviceName : "",
      provisioningStatus:
        typeof plan.provisioningStatus === "string" ? plan.provisioningStatus : "",
    })),
  }));
  ctx.shared.set("subscribedSkus", skuStates);

  // Friendly-name resolution (PS lines 46-89 + 103-104): bundled CSV only,
  // raw SkuPartNumber fallback when unmapped.
  const friendlyNames = loadSkuNames();

  const prepaidUnitsOf = (sku: Record<string, unknown>) =>
    (sku.prepaidUnits as Record<string, unknown> | undefined) ?? {};

  // PS line 117: Sort-Object -Property License.
  const licenseNameOf = (sku: Record<string, unknown>): string => {
    const partNumber = psStr(sku.skuPartNumber);
    return friendlyNames[partNumber] ?? partNumber;
  };
  const sorted = [...skuList].sort((a, b) => {
    const ka = licenseNameOf(a);
    const kb = licenseNameOf(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  for (const sku of sorted) {
    const prepaid = prepaidUnitsOf(sku);
    const enabled = Number(prepaid.enabled ?? 0);
    const consumed = Number(sku.consumedUnits ?? 0);
    const licenseName = licenseNameOf(sku);

    ctx.addRow({
      category: CATEGORY,
      setting: licenseName,
      currentValue: kv([
        ["License", licenseName],
        ["SkuPartNumber", sku.skuPartNumber],
        ["Total", prepaid.enabled],
        ["Assigned", sku.consumedUnits],
        ["Available", enabled - consumed],
        ["Suspended", prepaid.suspended],
        ["Warning", prepaid.warning],
      ]),
      recommendedValue: "",
      psStatus: "Info",
    });
  }
}

/** Default export instance wired to the bundled SKU CSV. */
export const runLicenseReport: SectionImplementation =
  createRunLicenseReport();
