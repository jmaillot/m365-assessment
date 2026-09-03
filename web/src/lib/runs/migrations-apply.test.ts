/**
 * Proves that all project migrations — including the runs + check_rows
 * additions — apply cleanly against a fresh :memory: database and that
 * cascade-delete semantics work end-to-end.
 *
 * Uses raw SQLite exec() to apply each migration SQL file in journal order
 * rather than drizzle-orm's migrate() to avoid shared-state issues with
 * in-memory databases in test processes.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import * as schema from "@/db/schema";

const { runs, checkRows, users } = schema;

const MIGRATIONS_FOLDER =
  process.env.DRIZZLE_MIGRATIONS_FOLDER ??
  path.resolve(process.cwd(), "src/db/migrations");

/** Read the journal to discover migration SQL files in order. */
function readJournal(): string[] {
  const journalPath = path.join(MIGRATIONS_FOLDER, "meta", "_journal.json");
  const journal = JSON.parse(fs.readFileSync(journalPath, "utf-8")) as {
    entries: Array<{ tag: string }>;
  };
  return journal.entries.map((e) => `${e.tag}.sql`);
}

/**
 * Fresh :memory: database with all project migrations applied via raw exec.
 * Each migration SQL is read from disk and executed in journal order.
 */
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

describe("migrations — fresh :memory: database", () => {
  it("creates runs and check_rows tables alongside earlier tables", () => {
    const database = createIsolatedDb();
    const sqlite = (database as any).$client as InstanceType<typeof Database>;
    const tables = sqlite
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
      )
      .all()
      .map((r: any) => r.name as string);

    expect(tables).toContain("runs");
    expect(tables).toContain("check_rows");
    expect(tables).toContain("users");
  });

  it("inserts a user, run, and check_row and selects them back", () => {
    const database = createIsolatedDb();

    const userId = crypto.randomUUID();
    const runId = crypto.randomUUID();
    const checkRowId = crypto.randomUUID();

    database
      .insert(users)
      .values({
        id: userId,
        entraObjectId: crypto.randomUUID(),
        email: "test@YOUR-HOST.example",
        displayName: "Migrations Test User",
      })
      .run();

    database
      .insert(runs)
      .values({
        id: runId,
        userId,
        tenantId: crypto.randomUUID(),
        status: "queued",
      })
      .run();

    database
      .insert(checkRows)
      .values({
        id: checkRowId,
        runId,
        sectionId: "ENTRA",
        category: "Identity",
        setting: "MFA Status",
        status: "Pass",
        checkId: "ENTRA-MFA-001.1",
        rowOrder: 0,
      })
      .run();

    const selectedRuns = database
      .select()
      .from(runs)
      .where(eq(runs.id, runId))
      .all();
    expect(selectedRuns).toHaveLength(1);
    expect(selectedRuns[0].status).toBe("queued");

    const selectedRows = database
      .select()
      .from(checkRows)
      .where(eq(checkRows.id, checkRowId))
      .all();
    expect(selectedRows).toHaveLength(1);
    expect(selectedRows[0].checkId).toBe("ENTRA-MFA-001.1");
  });

  it("cascade-deletes check_rows when the parent run is deleted", () => {
    const database = createIsolatedDb();

    const userId = crypto.randomUUID();
    const runId = crypto.randomUUID();

    database
      .insert(users)
      .values({
        id: userId,
        entraObjectId: crypto.randomUUID(),
        email: "cascade@YOUR-HOST.example",
        displayName: "Cascade Test User",
      })
      .run();

    database
      .insert(runs)
      .values({
        id: runId,
        userId,
        tenantId: crypto.randomUUID(),
      })
      .run();

    database
      .insert(checkRows)
      .values([
        {
          id: crypto.randomUUID(),
          runId,
          sectionId: "ENTRA",
          category: "A",
          setting: "S1",
          status: "Pass",
          checkId: "A-001.1",
          rowOrder: 0,
        },
        {
          id: crypto.randomUUID(),
          runId,
          sectionId: "ENTRA",
          category: "B",
          setting: "S2",
          status: "Fail",
          checkId: "B-001.1",
          rowOrder: 1,
        },
      ])
      .run();

    database.delete(runs).where(eq(runs.id, runId)).run();

    const survivingRows = database
      .select()
      .from(checkRows)
      .where(eq(checkRows.runId, runId))
      .all();
    expect(survivingRows).toHaveLength(0);
  });

  it("cascade-deletes runs and check_rows when the owning user is deleted", () => {
    const database = createIsolatedDb();

    const userId = crypto.randomUUID();
    const runId = crypto.randomUUID();

    database
      .insert(users)
      .values({
        id: userId,
        entraObjectId: crypto.randomUUID(),
        email: "user-cascade@YOUR-HOST.example",
        displayName: "User Cascade Test",
      })
      .run();

    database
      .insert(runs)
      .values({
        id: runId,
        userId,
        tenantId: crypto.randomUUID(),
      })
      .run();

    database
      .insert(checkRows)
      .values({
        id: crypto.randomUUID(),
        runId,
        sectionId: "ENTRA",
        category: "C",
        setting: "S3",
        status: "Warning",
        checkId: "C-001.1",
        rowOrder: 0,
      })
      .run();

    database.delete(users).where(eq(users.id, userId)).run();

    expect(
      database.select().from(runs).where(eq(runs.userId, userId)).all(),
    ).toHaveLength(0);
    expect(
      database.select().from(checkRows).where(eq(checkRows.runId, runId)).all(),
    ).toHaveLength(0);
  });
});
