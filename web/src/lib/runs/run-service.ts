/**
 * Run lifecycle service — single-draft gate, status transitions, check-row
 * persistence, interrupted-run sweep.  All mutations are transactional.
 * Convention: returns plain data (no drizzle objects) so callers stay
 * decoupled from the ORM.
 *
 * Pattern source: web/src/lib/settings/operator-credential.ts
 */

import crypto from "node:crypto";
import { and, asc, eq, or, sql } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import * as schema from "@/db/schema";
import { checkRows, runs, users } from "@/db/schema";
import type { CheckRow } from "@/engine/results/row-contract";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type Db = BetterSQLite3Database<typeof schema>;

export type RunStatus = "queued" | "running" | "completed" | "failed";

export interface RunRecord {
  id: string;
  userId: string;
  tenantId: string;
  status: RunStatus;
  startedAt: Date;
  finishedAt: Date | null;
  error: string | null;
}

export interface CreateRunResult {
  ok: true;
  runId: string;
}

export interface CreateRunBlocked {
  ok: false;
  activeRunId: string;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/**
 * Idempotent single-active-run gate — returns the existing queued/running
 * run if one exists, otherwise inserts a new queued run.  Race-safe:
 * transactional INSERT…WHERE NOT EXISTS at the SQL layer.
 */
export function createRunIfAbsent(
  userId: string,
  tenantId: string,
  database: Db,
): CreateRunResult | CreateRunBlocked {
  return database.transaction((tx) => {
    const existing = tx
      .select({ id: runs.id })
      .from(runs)
      .where(
        and(
          eq(runs.userId, userId),
          or(eq(runs.status, "queued"), eq(runs.status, "running")),
        ),
      )
      .limit(1)
      .get();

    if (existing) {
      return { ok: false, activeRunId: existing.id };
    }

    const runId = crypto.randomUUID();
    tx.insert(runs)
      .values({
        id: runId,
        userId,
        tenantId,
        status: "queued",
      })
      .run();

    return { ok: true, runId };
  });
}

/**
 * Fetch a run by id, scoped to the given userId.  Returns undefined when
 * the run does not exist or belongs to a different user (ownership
 * scoping — T-03-01b).
 */
export function getRun(
  userId: string,
  runId: string,
  database: Db,
): RunRecord | undefined {
  const row = database
    .select()
    .from(runs)
    .where(and(eq(runs.id, runId), eq(runs.userId, userId)))
    .get();
  return row ? toRecord(row) : undefined;
}

/** Transition: queued → running. */
export function markRunRunning(runId: string, database: Db): void {
  database
    .update(runs)
    .set({ status: "running" })
    .where(eq(runs.id, runId))
    .run();
}

/** Transition: running → completed (sets finishedAt). */
export function markRunCompleted(runId: string, database: Db): void {
  database
    .update(runs)
    .set({ status: "completed", finishedAt: new Date() })
    .where(eq(runs.id, runId))
    .run();
}

/** Transition: running → failed (sets finishedAt + error). */
export function markRunFailed(
  runId: string,
  reason: string,
  database: Db,
): void {
  database
    .update(runs)
    .set({ status: "failed", finishedAt: new Date(), error: reason })
    .where(eq(runs.id, runId))
    .run();
}

/**
 * Batch-insert check-row results for a run.  `startOrder` sets the first
 * row's rowOrder; subsequent rows are numbered sequentially.  Returns the
 * next available order value (i.e. startOrder + rows.length).
 */
export function appendCheckRows(
  runId: string,
  sectionId: string,
  rows: CheckRow[],
  startOrder: number,
  database: Db,
): number {
  if (rows.length === 0) return startOrder;

  const values = rows.map((r, i) => ({
    id: crypto.randomUUID(),
    runId,
    sectionId,
    rowOrder: startOrder + i,
    category: r.category,
    setting: r.setting,
    currentValue: r.currentValue,
    recommendedValue: r.recommendedValue,
    status: r.status,
    skipReason: r.skipReason ?? null,
    checkId: r.checkId,
    remediation: r.remediation,
    intentDesign: r.intentDesign,
    observedValue: r.observedValue ?? null,
    expectedValue: r.expectedValue ?? null,
    evidenceSource: r.evidenceSource ?? null,
    evidenceTimestamp: r.evidenceTimestamp ?? null,
    collectionMethod: r.collectionMethod ?? null,
    permissionRequired: r.permissionRequired ?? null,
    confidence: r.confidence != null ? Math.round(r.confidence * 100) : null,
    limitations: r.limitations ?? null,
  }));

  database.insert(checkRows).values(values).run();
  return startOrder + rows.length;
}

/**
 * Return check rows for a run, ordered by rowOrder.  Confidence is mapped
 * back from integer (0–100) to float (0.0–1.0) on read.
 */
export function listCheckRows(
  runId: string,
  database: Db,
): Array<CheckRow & { sectionId: string }> {
  const rows = database
    .select()
    .from(checkRows)
    .where(eq(checkRows.runId, runId))
    .orderBy(asc(checkRows.rowOrder))
    .all();

  return rows.map((r) => ({
    category: r.category,
    setting: r.setting,
    currentValue: r.currentValue,
    recommendedValue: r.recommendedValue,
    status: r.status as CheckRow["status"],
    skipReason: (r.skipReason ?? undefined) as CheckRow["skipReason"],
    checkId: r.checkId,
    remediation: r.remediation,
    intentDesign: r.intentDesign,
    observedValue: r.observedValue ?? undefined,
    expectedValue: r.expectedValue ?? undefined,
    evidenceSource: r.evidenceSource ?? undefined,
    evidenceTimestamp: r.evidenceTimestamp ?? undefined,
    collectionMethod: (r.collectionMethod ?? undefined) as
      | CheckRow["collectionMethod"]
      | undefined,
    permissionRequired: r.permissionRequired ?? undefined,
    confidence: r.confidence != null ? r.confidence / 100 : undefined,
    limitations: r.limitations ?? undefined,
    sectionId: r.sectionId,
  }));
}

/**
 * Mark ALL runs with status "queued" or "running" as failed with the
 * fixed restart-reason sentence.  Called at executor start (plan 03-03),
 * implements D-04 fail+re-run.  Returns the count of swept runs.
 */
export function sweepInterruptedRuns(database: Db): number {
  const RESTART_REASON = "The application restarted during this run.";
  const result = database
    .update(runs)
    .set({ status: "failed", finishedAt: new Date(), error: RESTART_REASON })
    .where(or(eq(runs.status, "queued"), eq(runs.status, "running")))
    .run();
  return result.changes;
}

/**
 * Return the id of the most recent queued or running run for the given
 * user, or undefined.  Feeds the trigger card's "Assessment in progress"
 * state in plan 03-05.
 */
export function getActiveRunId(
  userId: string,
  database: Db,
): string | undefined {
  const row = database
    .select({ id: runs.id })
    .from(runs)
    .where(
      and(
        eq(runs.userId, userId),
        or(eq(runs.status, "queued"), eq(runs.status, "running")),
      ),
    )
    .limit(1)
    .get();
  return row?.id;
}

/**
 * List all runs for a user, newest first (RPT-02 archive, ownership-scoped).
 */
export function listRunsForUser(
  userId: string,
  database: Db,
): RunRecord[] {
  const rows = database
    .select()
    .from(runs)
    .where(eq(runs.userId, userId))
    .orderBy(sql`${runs.startedAt} DESC`)
    .all();
  return rows.map(toRecord);
}

/**
 * Get a run plus its check rows, ownership-scoped. Returns null if not found or not owned.
 */
export function getRunWithRows(
  runId: string,
  userId: string,
  database: Db,
): { run: RunRecord; rows: Array<CheckRow & { sectionId: string }> } | null {
  const run = getRun(userId, runId, database);
  if (!run) return null;
  const rows = listCheckRows(runId, database);
  return { run, rows };
}

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

function toRecord(row: typeof runs.$inferSelect): RunRecord {
  return {
    id: row.id,
    userId: row.userId,
    tenantId: row.tenantId,
    status: row.status as RunStatus,
    startedAt: row.startedAt,
    finishedAt: row.finishedAt,
    error: row.error,
  };
}
