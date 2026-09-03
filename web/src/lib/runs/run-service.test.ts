/**
 * run-service tests — proves gated creation, ownership-scoped reads,
 * terminal transitions, row persistence round-trip, and restart sweeping
 * against a fresh :memory: database.
 *
 * Uses the same env-before-import + raw exec() migration harness as
 * migrations-apply.test.ts.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { describe, expect, beforeEach, it } from "vitest";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import * as schema from "@/db/schema";
import type { CheckRow } from "@/engine/results/row-contract";

const { runs, checkRows, users } = schema;

const MIGRATIONS_FOLDER =
  process.env.DRIZZLE_MIGRATIONS_FOLDER ??
  path.resolve(process.cwd(), "src/db/migrations");

function readJournal(): string[] {
  const journalPath = path.join(MIGRATIONS_FOLDER, "meta", "_journal.json");
  const journal = JSON.parse(fs.readFileSync(journalPath, "utf-8")) as {
    entries: Array<{ tag: string }>;
  };
  return journal.entries.map((e) => `${e.tag}.sql`);
}

function createIsolatedDb() {
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = MEMORY");
  sqlite.pragma("foreign_keys = ON");

  const files = readJournal();
  for (const file of files) {
    const sqlPath = path.join(MIGRATIONS_FOLDER, file);
    const sql = fs.readFileSync(sqlPath, "utf-8");
    sqlite.exec(sql);
  }

  const database = drizzle(sqlite, { schema });
  return database;
}

type Db = ReturnType<typeof createIsolatedDb>;

// Lazy import of the service under test — must be imported AFTER the
// :memory: DATABASE_PATH is set (but we pass the db directly, so no
// env hack needed for this suite).
async function loadService() {
  return await import("@/lib/runs/run-service");
}

/* ------------------------------------------------------------------ */
/*  Fixtures                                                           */
/* ------------------------------------------------------------------ */

const USER_A = {
  id: crypto.randomUUID(),
  entraObjectId: crypto.randomUUID(),
  email: "a@test.invalid",
  displayName: "User A",
};

const USER_B = {
  id: crypto.randomUUID(),
  entraObjectId: crypto.randomUUID(),
  email: "b@test.invalid",
  displayName: "User B",
};

const TENANT_ID = "11111111-1111-1111-1111-111111111111";

function seedUser(db: Db, user: typeof USER_A) {
  db.insert(users).values(user).run();
}

function makeCheckRow(overrides: Partial<CheckRow> = {}): CheckRow {
  return {
    category: "Identity",
    setting: "MFA enabled",
    currentValue: "false",
    recommendedValue: "true",
    status: "Fail",
    checkId: "ENTRA-MFA-001.1",
    remediation: "Enable MFA for all users",
    intentDesign: false,
    ...overrides,
  };
}

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */

describe("run-service", () => {
  let db: Db;

  beforeEach(() => {
    db = createIsolatedDb();
    seedUser(db, USER_A);
    seedUser(db, USER_B);
  });

  /* ---- createRunIfAbsent ---- */

  describe("createRunIfAbsent", () => {
    it("inserts a new queued run when no active run exists", async () => {
      const svc = await loadService();
      const result = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error("expected ok:true");

      const run = svc.getRun(USER_A.id, result.runId, db);
      expect(run).toBeDefined();
      expect(run!.status).toBe("queued");
      expect(run!.userId).toBe(USER_A.id);
      expect(run!.tenantId).toBe(TENANT_ID);
    });

    it("returns existing active run without inserting when one exists", async () => {
      const svc = await loadService();
      const first = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(first.ok).toBe(true);
      if (!first.ok) throw new Error("expected ok:true");

      const second = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(second.ok).toBe(false);
      if (second.ok) throw new Error("expected ok:false");
      expect(second.activeRunId).toBe(first.runId);
    });

    it("does not block when existing run is completed", async () => {
      const svc = await loadService();
      const first = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(first.ok).toBe(true);
      if (!first.ok) throw new Error("expected ok:true");

      svc.markRunCompleted(first.runId, db);

      const second = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(second.ok).toBe(true);
      if (!second.ok) throw new Error("expected ok:true");
      expect(second.runId).not.toBe(first.runId);
    });

    it("does not block when existing run is failed", async () => {
      const svc = await loadService();
      const first = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(first.ok).toBe(true);
      if (!first.ok) throw new Error("expected ok:true");

      svc.markRunFailed(first.runId, "test error", db);

      const second = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(second.ok).toBe(true);
      if (!second.ok) throw new Error("expected ok:true");
    });

    it("blocks when existing run is running", async () => {
      const svc = await loadService();
      const first = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(first.ok).toBe(true);
      if (!first.ok) throw new Error("expected ok:true");

      svc.markRunRunning(first.runId, db);

      const second = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(second.ok).toBe(false);
      if (second.ok) throw new Error("expected ok:false");
      expect(second.activeRunId).toBe(first.runId);
    });
  });

  /* ---- getRun (ownership scoping) ---- */

  describe("getRun", () => {
    it("returns the run when userId matches", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      const run = svc.getRun(USER_A.id, created.runId, db);
      expect(run).toBeDefined();
      expect(run!.id).toBe(created.runId);
    });

    it("returns undefined when userId does not match (IDOR prevention)", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      const run = svc.getRun(USER_B.id, created.runId, db);
      expect(run).toBeUndefined();
    });

    it("returns undefined for non-existent runId", async () => {
      const svc = await loadService();
      const run = svc.getRun(USER_A.id, crypto.randomUUID(), db);
      expect(run).toBeUndefined();
    });
  });

  /* ---- Status transitions ---- */

  describe("status transitions", () => {
    it("markRunRunning sets status to running", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      svc.markRunRunning(created.runId, db);
      const run = svc.getRun(USER_A.id, created.runId, db);
      expect(run!.status).toBe("running");
    });

    it("markRunCompleted sets status to completed and finishedAt", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      svc.markRunRunning(created.runId, db);
      svc.markRunCompleted(created.runId, db);

      const run = svc.getRun(USER_A.id, created.runId, db);
      expect(run!.status).toBe("completed");
      expect(run!.finishedAt).toBeInstanceOf(Date);
    });

    it("markRunFailed sets status to failed, finishedAt, and error", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      svc.markRunRunning(created.runId, db);
      svc.markRunFailed(created.runId, "Graph API timeout", db);

      const run = svc.getRun(USER_A.id, created.runId, db);
      expect(run!.status).toBe("failed");
      expect(run!.finishedAt).toBeInstanceOf(Date);
      expect(run!.error).toBe("Graph API timeout");
    });
  });

  /* ---- appendCheckRows + listCheckRows ---- */

  describe("check rows", () => {
    it("persists rows and returns them in rowOrder", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      const rows: CheckRow[] = [
        makeCheckRow({ checkId: "ENTRA-MFA-001.1", setting: "MFA" }),
        makeCheckRow({ checkId: "ENTRA-CA-002.1", setting: "CA policy" }),
      ];

      const nextOrder = svc.appendCheckRows(
        created.runId,
        "identity",
        rows,
        0,
        db,
      );
      expect(nextOrder).toBe(2);

      const loaded = svc.listCheckRows(created.runId, db);
      expect(loaded).toHaveLength(2);
      expect(loaded[0].checkId).toBe("ENTRA-MFA-001.1");
      expect(loaded[0].sectionId).toBe("identity");
      expect(loaded[1].checkId).toBe("ENTRA-CA-002.1");
    });

    it("confidence is stored as integer and read back as 0–1 float", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      const rows: CheckRow[] = [
        makeCheckRow({ confidence: 0.87 }),
      ];

      svc.appendCheckRows(created.runId, "identity", rows, 0, db);

      const loaded = svc.listCheckRows(created.runId, db);
      expect(loaded).toHaveLength(1);
      expect(loaded[0].confidence).toBeCloseTo(0.87, 2);
    });

    it("optional fields round-trip correctly (null ↔ undefined)", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      const rows: CheckRow[] = [
        makeCheckRow({
          observedValue: "MFA registered",
          skipReason: undefined,
          limitations: undefined,
        }),
      ];

      svc.appendCheckRows(created.runId, "identity", rows, 0, db);

      const loaded = svc.listCheckRows(created.runId, db);
      expect(loaded).toHaveLength(1);
      expect(loaded[0].observedValue).toBe("MFA registered");
      expect(loaded[0].skipReason).toBeUndefined();
      expect(loaded[0].limitations).toBeUndefined();
    });

    it("returns startOrder unchanged when rows array is empty", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      const nextOrder = svc.appendCheckRows(
        created.runId,
        "identity",
        [],
        5,
        db,
      );
      expect(nextOrder).toBe(5);
    });

    it("cascading delete removes check_rows when run is deleted", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      svc.appendCheckRows(
        created.runId,
        "identity",
        [makeCheckRow()],
        0,
        db,
      );

      // Delete the user (cascades to runs → check_rows)
      db.delete(users).where(eq(users.id, USER_A.id)).run();

      const orphanRows = db
        .select()
        .from(checkRows)
        .where(eq(checkRows.runId, created.runId))
        .all();
      expect(orphanRows).toHaveLength(0);
    });
  });

  /* ---- sweepInterruptedRuns ---- */

  describe("sweepInterruptedRuns", () => {
    it("marks queued and running runs as failed with fixed reason", async () => {
      const svc = await loadService();
      const r1 = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(r1.ok).toBe(true);
      if (!r1.ok) throw new Error("expected ok:true");

      const r2 = svc.createRunIfAbsent(USER_B.id, TENANT_ID, db);
      expect(r2.ok).toBe(true);
      if (!r2.ok) throw new Error("expected ok:true");
      svc.markRunRunning(r2.runId, db);

      const count = svc.sweepInterruptedRuns(db);
      expect(count).toBe(2);

      const run1 = svc.getRun(USER_A.id, r1.runId, db);
      expect(run1!.status).toBe("failed");
      expect(run1!.error).toBe(
        "The application restarted during this run.",
      );

      const run2 = svc.getRun(USER_B.id, r2.runId, db);
      expect(run2!.status).toBe("failed");
      expect(run2!.error).toBe(
        "The application restarted during this run.",
      );
    });

    it("does not touch completed or failed runs", async () => {
      const svc = await loadService();
      const r1 = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(r1.ok).toBe(true);
      if (!r1.ok) throw new Error("expected ok:true");
      svc.markRunRunning(r1.runId, db);
      svc.markRunCompleted(r1.runId, db);

      const r2 = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(r2.ok).toBe(true);
      if (!r2.ok) throw new Error("expected ok:true");
      svc.markRunRunning(r2.runId, db);
      svc.markRunFailed(r2.runId, "original error", db);

      const count = svc.sweepInterruptedRuns(db);
      expect(count).toBe(0);

      const run1 = svc.getRun(USER_A.id, r1.runId, db);
      expect(run1!.status).toBe("completed");
      const run2check = svc.getRun(USER_A.id, r2.runId, db);
      expect(run2check!.status).toBe("failed");
      expect(run2check!.error).toBe("original error");
    });

    it("returns 0 when no active runs exist", async () => {
      const svc = await loadService();
      const count = svc.sweepInterruptedRuns(db);
      expect(count).toBe(0);
    });
  });

  /* ---- getActiveRunId ---- */

  describe("getActiveRunId", () => {
    it("returns the active run id for the given user", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      const activeId = svc.getActiveRunId(USER_A.id, db);
      expect(activeId).toBe(created.runId);
    });

    it("returns undefined when user has no active runs", async () => {
      const svc = await loadService();
      const activeId = svc.getActiveRunId(USER_A.id, db);
      expect(activeId).toBeUndefined();
    });

    it("returns undefined when user's run is completed", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");
      svc.markRunRunning(created.runId, db);
      svc.markRunCompleted(created.runId, db);

      const activeId = svc.getActiveRunId(USER_A.id, db);
      expect(activeId).toBeUndefined();
    });

    it("does not return another user's active run", async () => {
      const svc = await loadService();
      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");

      const activeId = svc.getActiveRunId(USER_B.id, db);
      expect(activeId).toBeUndefined();
    });
  });

  /* ---- E2E archive: queued → running → completed with 8-domain rows → list → getRunWithRows → ReportData ---- */

  describe("E2E archive", () => {
    it("E2E archive: queued → running → completed with 8-domain rows → listRuns → getRunWithRows → ReportData parity", async () => {
      const svc = await loadService();
      const { buildReportData } = await import("@/report/build-report-data");

      const created = svc.createRunIfAbsent(USER_A.id, TENANT_ID, db);
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("expected ok:true");
      const runId = created.runId;

      svc.markRunRunning(runId, db);

      // 8-domain synthetic rows (mix Pass/Fail/Warning/Review + one PBI dupe that must be ignored at scoring)
      const eightRows: CheckRow[] = [
        makeCheckRow({ checkId: "ENTRA-TEST-001.1", status: "Pass", category: "Identity" }),
        makeCheckRow({ checkId: "EXO-TEST-001.1", status: "Fail", category: "Email" }),
        makeCheckRow({ checkId: "INTUNE-TEST-001.1", status: "Warning", category: "Intune" }),
        makeCheckRow({ checkId: "DEFENDER-TEST-001.1", status: "Review", category: "Security" }),
        makeCheckRow({ checkId: "SPO-TEST-001.1", status: "Pass", category: "Collaboration" }),
        makeCheckRow({ checkId: "TEAMS-TEST-001.1", status: "Fail", category: "Collaboration" }),
        makeCheckRow({ checkId: "PURVIEW-TEST-001.1", status: "Pass", category: "Purview" }),
        makeCheckRow({ checkId: "POWERBI-GUEST-001.1", status: "Pass", category: "Power BI" }),
      ];
      // Add one PBI dupe that should NOT contribute to framework scoring (canonical 11)
      const pbiDupe: CheckRow = makeCheckRow({ checkId: "PBI-GUEST-001.1", status: "Pass", category: "Power BI" });

      let order = 0;
      order = svc.appendCheckRows(runId, "identity", eightRows.slice(0, 2), order, db);
      order = svc.appendCheckRows(runId, "exchange", eightRows.slice(2, 4), order, db);
      order = svc.appendCheckRows(runId, "intune", eightRows.slice(4, 6), order, db);
      order = svc.appendCheckRows(runId, "purview", eightRows.slice(6, 8), order, db);
      // Append the PBI dupe as separate section — it will be stored but ignored at scoring
      order = svc.appendCheckRows(runId, "powerbi", [pbiDupe], order, db);

      svc.markRunCompleted(runId, db);

      // Archive list
      const listed = svc.listRunsForUser(USER_A.id, db);
      expect(listed).toHaveLength(1);
      expect(listed[0]!.id).toBe(runId);
      expect(listed[0]!.status).toBe("completed");

      // Ownership: other user sees 0
      expect(svc.listRunsForUser(USER_B.id, db)).toHaveLength(0);

      const withRows = svc.getRunWithRows(runId, USER_A.id, db);
      expect(withRows).not.toBeNull();
      expect(withRows!.rows).toHaveLength(9); // 8 + 1 PBI dupe
      expect(withRows!.run.id).toBe(runId);

      // Cross-user getRunWithRows must be null
      expect(svc.getRunWithRows(runId, USER_B.id, db)).toBeNull();

      const mapped = withRows!.rows.map((r) => ({ row: r, sectionId: r.sectionId }));
      const report = buildReportData(mapped);

      expect(report.summary.totalChecks).toBe(9);
      // 8 canonical + 1 PBI dupe stored, but PBI scoring must be 0 covered
      expect(report.coverage.domainsPresent).toContain("Entra ID");
      expect(report.coverage.domainsPresent).toContain("Power BI");
      expect(report.coverage.domainsPresent.length).toBeGreaterThanOrEqual(5);
      expect(report.coverage.label).toMatch(/Full score — includes|Partial score — includes/);
      expect(report.frameworks).toHaveLength(15);
      // PBI dupe must not contribute to any framework covered count
      const pbiCovered = report.frameworks.reduce((a, f) => a + f.checks.filter((c) => c.checkId.includes("PBI-GUEST")).length, 0);
      expect(pbiCovered).toBe(0);
      const powerbiCovered = report.frameworks.reduce((a, f) => a + f.checks.filter((c) => c.checkId.includes("POWERBI-GUEST")).length, 0);
      expect(powerbiCovered).toBeGreaterThan(0);
    });
  });
});
