#!/usr/bin/env tsx
/**
 * Export last completed run's 48 Fail (or evaluated) prioritized by severity critical→high→medium→low
 * Usage: npx tsx --tsconfig web/tsconfig.json scripts/export-fail-prioritized.ts [--run <runId>] [--out /tmp/fail.csv]
 * Reads web/data/m365-assess.db (or DATABASE_PATH) and web/src/M365-Assess/controls/risk-severity.json
 */
import { readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import * as schema from "../web/src/db/schema";
import { desc, eq } from "drizzle-orm";

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function severityRank(s?: string): number { return s ? (SEVERITY_RANK[s.toLowerCase()] ?? 99) : 99; }

function parseArgs(): { runId?: string; out?: string } {
  const args = process.argv.slice(2);
  const runIdx = args.indexOf("--run");
  const outIdx = args.indexOf("--out");
  return { runId: runIdx !== -1 ? args[runIdx + 1] : undefined, out: outIdx !== -1 ? args[outIdx + 1] : undefined };
}

const { runId: argRunId, out } = parseArgs();
const dbPath = process.env.DATABASE_PATH ?? resolve(process.cwd(), "web/data/m365-assess.db");
let dbFile = dbPath;
try { readFileSync(dbFile); } catch { dbFile = resolve(process.cwd(), "data/m365-assess.db"); }

const sqlite = new Database(dbFile, { readonly: true });
const db = drizzle(sqlite, { schema } as never);

// Find last completed run if not specified
let runId = argRunId;
if (!runId) {
  const row = sqlite.prepare("SELECT id FROM runs WHERE status='completed' ORDER BY started_at DESC LIMIT 1").get() as { id: string } | undefined;
  if (!row) { console.error("No completed runs found in", dbFile); process.exit(1); }
  runId = row.id;
}

const rows = sqlite.prepare("SELECT checkId, category, setting, currentValue, recommendedValue, status, remediation, sectionId FROM check_rows WHERE run_id=? AND status='Fail' ORDER BY checkId").all(runId) as Array<Record<string, string>>;

// Load risk severity
let riskSeverity: Record<string, string> = {};
try {
  const riskPath = resolve(process.cwd(), "src/M365-Assess/controls/risk-severity.json");
  const raw = JSON.parse(readFileSync(riskPath, "utf8")) as { checks?: Record<string, string> };
  riskSeverity = raw.checks ?? {};
} catch {
  try {
    const alt = resolve(process.cwd(), "web/src/M365-Assess/controls/risk-severity.json");
    const raw2 = JSON.parse(readFileSync(alt, "utf8")) as { checks?: Record<string, string> };
    riskSeverity = raw2.checks ?? {};
  } catch {}
}

// Enrich with severity and domain (via getCheckDomain inline to avoid alias)
function getCheckDomain(checkId: string): string {
  const b = checkId.split(".")[0] ?? checkId;
  if (b.startsWith("CA-")) return "Conditional Access";
  if (b.startsWith("ENTRA-ENTAPP-")) return "Enterprise Apps";
  if (b.startsWith("ENTRA-")) return "Entra ID";
  if (b.startsWith("EXO-")) return "Exchange Online";
  if (b.startsWith("DNS-")) return "Exchange Online";
  if (b.startsWith("INTUNE-")) return "Intune";
  if (b.startsWith("DEFENDER-")) return "Defender";
  if (b.startsWith("SPO-")) return "SharePoint & OneDrive";
  if (b.startsWith("TEAMS-")) return "Teams";
  if (b.startsWith("PURVIEW-")) return "Purview / Compliance";
  if (b.startsWith("POWERBI-")) return "Power BI";
  return "Other";
}

const enriched = rows.map((r) => {
  const base = r.checkId.split(".")[0] ?? r.checkId;
  return { ...r, severity: riskSeverity[base] ?? "unknown", domain: getCheckDomain(r.checkId), base };
});
enriched.sort((a, b) => {
  const ra = severityRank(a.severity), rb = severityRank(b.severity);
  if (ra !== rb) return ra - rb;
  return a.checkId.localeCompare(b.checkId);
});

const header = ["severity","domain","checkId","category","setting","currentValue","recommendedValue","remediation","sectionId"];
const csvLines = [header.join(",")];
for (const r of enriched) {
  const esc = (s: string) => `"${String(s).replace(/"/g, '""')}"`;
  csvLines.push([esc(r.severity), esc(r.domain), esc(r.checkId), esc(r.category), esc(r.setting), esc(r.currentValue), esc(r.recommendedValue), esc(r.remediation), esc(r.sectionId)].join(","));
}
const csv = csvLines.join("\n");
if (out) {
  const fs = await import("node:fs");
  fs.writeFileSync(out, csv, "utf8");
  console.log(`Wrote ${enriched.length} Fail rows prioritized critical→high to ${out} (run ${runId})`);
} else {
  console.log(csv);
}
console.error(`\n# ${enriched.length} Fail rows for run ${runId} — severity critical→high, domain via getCheckDomain, evidence: check_rows + risk-severity.json`);
