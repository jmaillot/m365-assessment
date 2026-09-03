import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
import type { LicensingOverlay } from "../results/licensing-overlay";

/**
 * Unmodified controls loading (FRM-01): registry.json / licensing-overlay.json /
 * risk-severity.json / frameworks/*.json are READ IN PLACE from the PowerShell
 * module's source tree and never copied, transformed at write-time, or edited.
 * The drift guarantee (T-02-03d) is enforced by byte-level checksum comparison.
 *
 * Resolution order for the controls directory:
 *   1. `CONTROLS_DIR` env var (tests / standalone runs point at any directory)
 *   2. repo-root-relative default resolved from this module's URL
 *      (<repo>/src/M365-Assess/controls)
 */

/** One entry of registry.json's checks[] array (subset consumed by the engine). */
export interface RegistryCheckEntry {
  checkId: string;
  name?: string;
  category?: string;
  remediation?:
    | string
    | {
        notes?: string;
        portal?: { path?: string; steps?: string[] };
        powershell?: { command?: string };
        graph?: { endpoint?: string; method?: string; notes?: string };
        [key: string]: unknown;
      };
  [key: string]: unknown;
}

export interface ControlRegistry {
  schemaVersion?: string;
  dataVersion?: string;
  generatedFrom?: string;
  checks: RegistryCheckEntry[];
}

/** Auto-discovered compliance framework definition (frameworks/<file>.json). */
export interface FrameworkDefinition {
  /** Filename-derived id, e.g. "cis-m365-v6" for cis-m365-v6.json. */
  id: string;
  data: Record<string, unknown>;
}

export function controlsDir(): string {
  const fromEnv = process.env.CONTROLS_DIR;
  if (fromEnv && fromEnv.length > 0) {
    return resolve(fromEnv);
  }
  try {
    // web/src/engine/registry/load-controls.ts → up 4 = repo root.
    // In Next.js builds import.meta.url may not be a file URL — fallback to cwd.
    const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
    return join(repoRoot, "src", "M365-Assess", "controls");
  } catch {
    return resolve(process.cwd(), "..", "src", "M365-Assess", "controls");
  }
}

function readJson(fileName: string): unknown {
  const filePath = join(controlsDir(), fileName);
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch (err) {
    throw new Error(
      `controls file unreadable at ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch (err) {
    throw new Error(
      `controls file ${fileName} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/** Load src/M365-Assess/controls/registry.json unmodified; throws if malformed. */
export function loadRegistry(): ControlRegistry {
  const parsed = readJson("registry.json") as ControlRegistry | null;
  if (!parsed || !Array.isArray(parsed.checks)) {
    throw new Error("registry.json malformed: expected a top-level checks array");
  }
  return parsed;
}

export const POWERBI_CANONICAL = new Set([
  "POWERBI-GUEST-001",
  "POWERBI-GUEST-002",
  "POWERBI-GUEST-003",
  "POWERBI-SHARING-001",
  "POWERBI-SHARING-002",
  "POWERBI-SHARING-003",
  "POWERBI-SHARING-004",
  "POWERBI-INFOPROT-001",
  "POWERBI-AUTH-001",
  "POWERBI-AUTH-002",
  "POWERBI-AUTH-003",
]);

/**
 * D-34: Return registry checks with Power BI duplicates canonicalized (PBI-* dropped,
 * POWERBI-SERVICEPRINCIPAL-001 alias dropped) — 26 → 11. Non-Power BI checks pass through.
 * Scoring and risk lookups should use this filtered view; loadRegistry() stays byte-unmodified for FRM-01.
 */
export function canonicalRegistryChecks(registry: ControlRegistry): RegistryCheckEntry[] {
  return registry.checks.filter((entry) => {
    const id = typeof entry?.checkId === "string" ? entry.checkId : "";
    if (id.startsWith("PBI-")) return false;
    if (id === "POWERBI-SERVICEPRINCIPAL-001") return false;
    return true;
  });
}

/** Load licensing-overlay.json unmodified ({ description, version, checks{} }). */
export function loadLicensingOverlay(): LicensingOverlay {
  const parsed = readJson("licensing-overlay.json") as LicensingOverlay | null;
  if (!parsed || typeof parsed.checks !== "object" || parsed.checks === null) {
    throw new Error("licensing-overlay.json malformed: expected a top-level checks object");
  }
  return parsed;
}

/** Load risk-severity.json unmodified (opaque to the engine beyond parseability). */
export function loadRiskSeverity(): Record<string, unknown> {
  const parsed = readJson("risk-severity.json");
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("risk-severity.json malformed: expected a JSON object");
  }
  return parsed as Record<string, unknown>;
}

export function canonicalRiskChecks(riskSeverity: Record<string, unknown>): Record<string, unknown> {
  const checks = (riskSeverity as { checks?: Record<string, string> }).checks;
  if (!checks) return riskSeverity;
  const filtered: Record<string, string> = {};
  for (const [k, v] of Object.entries(checks)) if (!k.startsWith("PBI-") && k !== "POWERBI-SERVICEPRINCIPAL-001") filtered[k] = v as string;
  return { ...riskSeverity, checks: filtered };
}

/**
 * Auto-discovery mirroring Import-FrameworkDefinitions.ps1 semantics: every
 * *.json under controls/frameworks/ is parsed and returned with its
 * filename-derived id. An unparseable file THROWS — silent framework loss is
 * never acceptable (fail-explicit pattern).
 */
export function loadFrameworks(): FrameworkDefinition[] {
  const dir = join(controlsDir(), "frameworks");
  const definitions: FrameworkDefinition[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    const raw = readFileSync(join(dir, name), "utf8");
    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch (err) {
      throw new Error(
        `framework definition ${name} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error(`framework definition ${name} must be a JSON object`);
    }
    definitions.push({ id: name.replace(/\.json$/, ""), data: data as Record<string, unknown> });
  }
  return definitions;
}

/** sha256 hex digest of one controls file's raw bytes. */
export function controlsChecksum(fileName: string): string {
  return createHash("sha256")
    .update(readFileSync(join(controlsDir(), fileName)))
    .digest("hex");
}

/**
 * Drift check (T-02-03d / FRM-01): true when every named controls file's
 * current bytes hash exactly to the caller-pinned checksum. Any edit to a
 * pinned file fails this comparison — CI pins the source-tree hashes so a
 * hand-edit to controls JSON can never slip through silently.
 */
export function controlsChecksumsMatch(expected: Record<string, string>): boolean {
  for (const [fileName, pinned] of Object.entries(expected)) {
    if (controlsChecksum(fileName) !== pinned) {
      return false;
    }
  }
  return true;
}

/**
 * Flatten a registry entry's structured remediation into a deterministic
 * single string for the D-22 result-build fallback (SecurityConfigHelper.ps1
 * lines 256–263 semantics: empty collector Remediation ← registry entry).
 * Order is fixed: notes → portal path → powershell command → graph endpoint.
 */
export function registryRemediationText(entry: RegistryCheckEntry | undefined): string {
  const r = entry?.remediation;
  if (r === undefined || r === null) return "";
  if (typeof r === "string") return r;
  const parts: string[] = [];
  if (typeof r.notes === "string" && r.notes.length > 0) parts.push(r.notes);
  if (r.portal && typeof r.portal.path === "string" && r.portal.path.length > 0) {
    parts.push(`Portal: ${r.portal.path}`);
  }
  if (
    r.powershell &&
    typeof r.powershell.command === "string" &&
    r.powershell.command.length > 0
  ) {
    parts.push(`PowerShell: ${r.powershell.command}`);
  }
  if (
    r.graph &&
    typeof r.graph.method === "string" &&
    typeof r.graph.endpoint === "string"
  ) {
    parts.push(`Graph: ${r.graph.method} ${r.graph.endpoint}`);
  }
  return parts.join(" ");
}
