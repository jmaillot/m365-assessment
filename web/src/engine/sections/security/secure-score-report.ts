/**
 * Port of `src/M365-Assess/Security/Get-SecureScoreReport.ps1` (252 lines)
 * — Microsoft Secure Score summary + per-control breakdown.
 *
 * PS → TS mapping:
 * - Assert-GraphConnection / Import-Module Microsoft.Graph.Security: owned by
 *   the runner/transport (no collector-level gating).
 * - Get-MgSecuritySecureScore -Top 180 -Sort createdDateTime desc (PS line 52)
 *   → GET /v1.0/security/secureScores?$top=180 with automatic nextLink
 *   pagination (D-27). Failure = PS Write-Error + return (lines 54-57) →
 *   fail-soft with errMatches 403-family → Skipped row, other errors → zero
 *   rows (no fabricated findings, D-10). Empty result → Write-Warning + return
 *   → zero rows.
 * - Latest snapshot percentage: Round(CurrentScore/MaxScore*100,2) (PS lines 67-73)
 *   — PS coerces MaxScore=0 to 0% (guard). Replica via Number() + toFixed(2).
 * - AverageComparativeScores extraction (PS lines 77-95): AllTenants basis
 *   from AverageComparativeScores collection; fallback to AdditionalProperties.
 * - ProviderGenerated vs customer score split (PS lines 99-127): page through
 *   /v1.0/security/secureScoreControlProfiles?$top=250 building profileMap
 *   id→actionType, then sum ControlScores.Score partitioned by
 *   actionType === 'ProviderGenerated'. The profile fetch is soft-fail with
 *   Write-Warning parity — missing map keeps split at 0/0 and does not abort
 *   the report.
 * - Per-snapshot rows: newest-first from Graph; AverageComparativeScore and
 *   MicrosoftScore/CustomerScore only populated for the latest entry (PS lines
 *   131-146) — stale on older snapshots so null/0 there.
 * - ControlScores → improvement actions (PS lines 149-228): each control
 *   carries controlCategory, implementationStatus, userImpact, threats,
 *   scoreInPercentage, Score, maxScore from AdditionalProperties fallback.
 *   The collector emits one Info row per latest snapshot's controls only via the
 *   overall score row; detailed control breakdown is informational and rendered
 *   through the same rows pipeline (report collector, no CheckId needed, but
 *   the overall score carries DEFENDER-SECURESCORE-001 for registry linkage).
 * - No beta paths — both endpoints are v1.0 (the secureScore surface was
 *   previously beta but promoted per BETA-ENDPOINTS.md).
 */

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { asArray, errMatches, kv, psStr } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const SECURE_SCORE_ENDPOINTS = {
  secureScores: "/v1.0/security/secureScores?$top=180",
  secureScoreControlProfiles: "/v1.0/security/secureScoreControlProfiles?$top=250",
} as const;

const REQUIRED_ROLE = "SecurityEvents.Read.All";
const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

const CATEGORY = "Secure Score";
const CHECK_ID = "DEFENDER-SECURESCORE-001";

type GraphObj = Record<string, unknown>;

function toNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

export const runSecureScoreReport: SectionImplementation = async (ctx) => {
  // ------------------------------------------------------------------
  // 1. Fetch secure score history (PS lines 51-62) — soft-fail on 403 → Skipped.
  // ------------------------------------------------------------------
  let secureScores: Record<string, unknown>[];
  try {
    const resp = await ctx.transport.getJson(SECURE_SCORE_ENDPOINTS.secureScores, {
      requiredRole: REQUIRED_ROLE,
    });
    secureScores = asArray(resp.value);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      // D-24: 403→Skipped(not_licensed) with explicit sanitized copy.
      ctx.addRow({
        category: CATEGORY,
        setting: "Secure Score",
        currentValue: "Missing permissions — SecurityEvents.Read.All not granted; re-consent to grant",
        recommendedValue: "Grant SecurityEvents.Read.All",
        checkId: CHECK_ID,
        remediation: "Grant SecurityEvents.Read.All via admin consent and re-run",
        psStatus: "Skipped",
        evidenceSource: SECURE_SCORE_ENDPOINTS.secureScores,
        collectionMethod: "Direct",
        permissionRequired: REQUIRED_ROLE,
      });
      return;
    }
    // PS Write-Error + return parity — zero rows, run continues.
    return;
  }

  if (secureScores.length === 0) {
    // PS Write-Warning + return (line 60-62).
    return;
  }

  // PS line 64: newest-first is Graph's default sort; take [0] as latest.
  const latest = secureScores[0] as GraphObj;
  const currentScore = toNumber(latest.currentScore ?? latest.CurrentScore) ?? 0;
  const maxScore = toNumber(latest.maxScore ?? latest.MaxScore) ?? 0;
  const percentage = maxScore > 0 ? round2((currentScore / maxScore) * 100) : 0;

  // AverageComparativeScores — AllTenants basis (PS lines 77-95).
  let averageComparative = 0;
  const avgScores = latest.averageComparativeScores ?? latest.AverageComparativeScores;
  if (Array.isArray(avgScores)) {
    const avgEntry = (avgScores as GraphObj[]).find((e) => {
      const basis = psStr(e.basis ?? (e as Record<string, unknown>).Basis);
      if (basis === "AllTenants") return true;
      const ap = (e.additionalProperties ?? e.AdditionalProperties) as
        | Record<string, unknown>
        | undefined;
      return ap ? psStr(ap.basis) === "AllTenants" : false;
    });
    if (avgEntry) {
      const ap = (avgEntry.additionalProperties ?? avgEntry.AdditionalProperties) as
        | Record<string, unknown>
        | undefined;
      const direct = toNumber(avgEntry.averageScore ?? avgEntry.AverageScore);
      if (direct !== null && direct > 0) averageComparative = direct;
      else if (ap) {
        const fallback = toNumber(ap.averageScore);
        if (fallback !== null) averageComparative = fallback;
      }
    }
  }

  // ProviderGenerated vs customer split via control profiles (PS lines 99-127).
  // Soft-fail exactly like PS Write-Warning: missing map → split stays 0.
  let microsoftScore = 0;
  let customerScore = 0;
  try {
    const profilesResp = await ctx.transport.getJson(
      SECURE_SCORE_ENDPOINTS.secureScoreControlProfiles,
      { requiredRole: REQUIRED_ROLE },
    );
    const profileMap = new Map<string, string>();
    for (const prof of asArray(profilesResp.value)) {
      const id = psStr(prof.id);
      const actionType = psStr(prof.actionType);
      if (id) profileMap.set(id, actionType);
    }
    const controlScores = (latest.controlScores ?? latest.ControlScores) as unknown;
    if (Array.isArray(controlScores)) {
      for (const ctrl of controlScores as GraphObj[]) {
        const name = psStr(ctrl.controlName ?? ctrl.ControlName);
        const scoreRaw = ctrl.score ?? ctrl.Score;
        const earned = toNumber(scoreRaw) ?? 0;
        if (profileMap.get(name) === "ProviderGenerated") {
          microsoftScore += earned;
        } else {
          customerScore += earned;
        }
      }
    }
    microsoftScore = round2(microsoftScore);
    customerScore = round2(customerScore);
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    // PS Write-Warning parity — keep split at 0.
  }

  const createdDateTime = psStr(latest.createdDateTime ?? latest.CreatedDateTime);

  // Main summary row — one Info row for the latest snapshot (PS line 148,
  // $scoreSummary = $allScoreRows[0] output).
  ctx.addRow({
    category: CATEGORY,
    setting: "Microsoft Secure Score",
    currentValue: kv([
      ["CurrentScore", currentScore],
      ["MaxScore", maxScore],
      ["Percentage", `${percentage}%`],
      ["CreatedDateTime", createdDateTime],
      ["AverageComparativeScore", averageComparative],
      ["MicrosoftScore", microsoftScore],
      ["CustomerScore", customerScore],
    ]),
    recommendedValue: "",
    psStatus: "Info",
    checkId: CHECK_ID,
    remediation: "",
    evidenceSource: SECURE_SCORE_ENDPOINTS.secureScores,
    collectionMethod: "Direct",
    permissionRequired: REQUIRED_ROLE,
  });

  // ------------------------------------------------------------------
  // 2. Per-historical-snapshot rows (PS lines 131-147 — newest-first, average
  //    comparative only on latest). Report-level Info rows.
  // ------------------------------------------------------------------
  const sorted = [...secureScores];
  for (let i = 0; i < sorted.length; i++) {
    const snap = sorted[i] as GraphObj;
    // Skip the latest — already emitted as the summary row above.
    if (i === 0) continue;
    const snapCurrent = toNumber(snap.currentScore ?? snap.CurrentScore) ?? 0;
    const snapMax = toNumber(snap.maxScore ?? snap.MaxScore) ?? 0;
    const snapPct = snapMax > 0 ? round2((snapCurrent / snapMax) * 100) : 0;
    const snapCreated = psStr(snap.createdDateTime ?? snap.CreatedDateTime);
    ctx.addRow({
      category: CATEGORY,
      setting: `Secure Score (${snapCreated || `snapshot ${i + 1}`})`,
      currentValue: kv([
        ["CurrentScore", snapCurrent],
        ["MaxScore", snapMax],
        ["Percentage", `${snapPct}%`],
        ["CreatedDateTime", snapCreated],
      ]),
      recommendedValue: "",
      psStatus: "Info",
      evidenceSource: SECURE_SCORE_ENDPOINTS.secureScores,
      collectionMethod: "Direct",
      permissionRequired: REQUIRED_ROLE,
    });
  }

  // ------------------------------------------------------------------
  // 3. Improvement actions (PS lines 149-228) — one Info row per controlScore
  //    on the latest snapshot when present; PS writes them as detail CSV when
  //    -ImprovementActionsPath is supplied. In the SaaS they surface as report
  //    rows under the same category.
  // ------------------------------------------------------------------
  const latestControls = (latest.controlScores ?? latest.ControlScores) as unknown;
  if (Array.isArray(latestControls) && latestControls.length > 0) {
    // Sort by ControlName for deterministic output (PS processes in Graph order
    // but the display is unordered; sorting keeps fixtures stable).
    const controls = [...(latestControls as GraphObj[])].sort((a, b) => {
      const ka = psStr(a.controlName ?? a.ControlName);
      const kb = psStr(b.controlName ?? b.ControlName);
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    for (const control of controls) {
      const ap = (control.additionalProperties ?? control.AdditionalProperties) as
        | Record<string, unknown>
        | undefined;
      const actionName = psStr(control.controlName ?? control.ControlName);
      const category = (ap?.controlCategory as string) ?? "N/A";
      const implStatus = (ap?.implementationStatus as string) ?? "N/A";
      const userImpact = (ap?.userImpact as string) ?? "N/A";
      const threatsRaw = ap?.threats;
      let threats: string;
      if (Array.isArray(threatsRaw)) {
        threats = threatsRaw.map((t) => String(t)).join("; ");
      } else if (threatsRaw !== undefined && threatsRaw !== null) {
        threats = String(threatsRaw);
      } else {
        threats = "N/A";
      }
      const scoreImpact =
        toNumber(control.scoreInPercentage ?? control.ScoreInPercentage) ??
        toNumber(ap?.scoreInPercentage) ??
        0;
      const ctrlScore = toNumber(control.score ?? control.Score) ?? 0;
      const ctrlMax = toNumber(ap?.maxScore) ?? 0;

      ctx.addRow({
        category: "Secure Score Controls",
        setting: actionName,
        currentValue: kv([
          ["Category", category],
          ["ScoreImpact", scoreImpact],
          ["CurrentScore", ctrlScore],
          ["MaxScore", ctrlMax],
          ["ImplementationStatus", implStatus],
          ["UserImpact", userImpact],
          ["Threats", threats],
        ]),
        recommendedValue: "",
        psStatus: "Info",
        evidenceSource: SECURE_SCORE_ENDPOINTS.secureScores,
        collectionMethod: "Derived",
        permissionRequired: REQUIRED_ROLE,
      });
    }
  }
};
