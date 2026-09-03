import { describe, it, expect, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { eq } from "drizzle-orm";
import * as schema from "@/db/schema";
import { startRun, getRunBus, getActiveExecutions } from "./run-executor";
import type { EngineEvent } from "@/engine/events/engine-events";
import type { CheckRow } from "@/engine/results/row-contract";

const { runs, users, checkRows } = schema;

const MIGRATIONS_FOLDER = path.resolve(process.cwd(), "src/db/migrations");

function readJournal(): string[] {
  const journalPath = path.join(MIGRATIONS_FOLDER, "meta", "_journal.json");
  const journal = JSON.parse(fs.readFileSync(journalPath, "utf-8")) as {
    entries: Array<{ tag: string }>;
  };
  return journal.entries.map((e) => `${e.tag}.sql`);
}

function createIsolatedDb() {
  const sqlite = new Database(":memory:");
  sqlite.pragma("foreign_keys = ON");
  const files = readJournal();
  for (const file of files) {
    const sqlPath = path.join(MIGRATIONS_FOLDER, file);
    const sql = fs.readFileSync(sqlPath, "utf-8");
    sqlite.exec(sql);
  }
  return drizzle(sqlite, { schema });
}

type Db = ReturnType<typeof createIsolatedDb>;

function seedUserAndRun(database: Db, opts?: { status?: string; tenantId?: string }) {
  const userId = crypto.randomUUID();
  const runId = crypto.randomUUID();
  const tenantId = opts?.tenantId ?? crypto.randomUUID();
  database
    .insert(users)
    .values({
      id: userId,
      entraObjectId: crypto.randomUUID(),
      email: `test-${userId.slice(0, 8)}@example.com`,
      displayName: "Test User",
    })
    .run();
  database
    .insert(runs)
    .values({
      id: runId,
      userId,
      tenantId,
      status: opts?.status ?? "queued",
    })
    .run();
  return { userId, runId, tenantId };
}

function makeCheckRow(overrides?: Partial<CheckRow>): CheckRow {
  return {
    category: "C",
    setting: "S",
    currentValue: "v",
    recommendedValue: "r",
    status: "Pass",
    checkId: "ENTRA-TEST-001.1",
    remediation: "rem",
    intentDesign: false,
    ...overrides,
  };
}

describe("run-executor", () => {
  it("startRun on queued run sweeps, marks running, executes runEngine with identity against stored tenantId", async () => {
    const db = createIsolatedDb();
    const tenantId = crypto.randomUUID();
    const { runId } = seedUserAndRun(db, { tenantId, status: "queued" });
    // seed an interrupted run to be swept
    const { runId: interruptedId } = seedUserAndRun(db, { status: "running" });

    const createTransportStub = vi.fn((_handlers: unknown) => ({}) as unknown);
    const runEngineFn = vi.fn(async (opts: { tenantId: string; sectionIds: string[]; sink: { emit: (e: EngineEvent) => void } }) => {
      expect(opts.tenantId).toBe(tenantId);
      expect(opts.sectionIds).toEqual(["identity", "security", "intune", "exchange", "collaboration", "purview", "inventory", "powerbi"]);
      // emit a couple events
      opts.sink.emit({ type: "section-started", sectionId: "identity" });
      opts.sink.emit({ type: "check-completed", sectionId: "identity", row: makeCheckRow() });
      opts.sink.emit({ type: "section-finished", sectionId: "identity" });
      opts.sink.emit({ type: "run-finished", result: { tenantId, sections: [{ sectionId: "identity", rows: [] }] } });
      return { tenantId, sections: [] };
    });

    await startRun(runId, {
      database: db as unknown as Db,
      createTransport: createTransportStub as unknown as never,
      runEngineFn: runEngineFn as unknown as never,
    });

    expect(runEngineFn).toHaveBeenCalledTimes(1);
    // interrupted run should have been swept to failed
    const swept = db.select().from(runs).where(eq(runs.id, interruptedId)).get() as { status: string; error: string | null };
    expect(swept.status).toBe("failed");
    expect(swept.error).toBe("The application restarted during this run.");

    const completed = db.select().from(runs).where(eq(runs.id, runId)).get() as { status: string };
    expect(completed.status).toBe("completed");
  });

  it("every EngineEvent is forwarded to bus BEFORE any await; graph-call and page-cap-warning are forwarded but NOT persisted", async () => {
    const db = createIsolatedDb();
    const { runId } = seedUserAndRun(db);

    const bus = getRunBus();
    const busEvents: EngineEvent[] = [];
    const unsub = bus.subscribe(runId, (e) => busEvents.push(e));

    const runEngineFn = vi.fn(async (opts: { sink: { emit: (e: EngineEvent) => void } }) => {
      opts.sink.emit({ type: "graph-call", method: "GET", url: "https://graph.microsoft.com/v1.0/users", status: 200 });
      opts.sink.emit({ type: "page-cap-warning", url: "https://graph.microsoft.com/v1.0/users", maxPages: 5 });
      opts.sink.emit({ type: "check-completed", sectionId: "identity", row: makeCheckRow() });
      opts.sink.emit({ type: "run-finished", result: { tenantId: "t", sections: [] } });
      return { tenantId: "t", sections: [] };
    });

    await startRun(runId, {
      database: db as unknown as Db,
      createTransport: (() => ({}) as unknown) as never,
      runEngineFn: runEngineFn as unknown as never,
    });

    // graph-call and page-cap-warning were forwarded to bus
    expect(busEvents.some((e) => e.type === "graph-call")).toBe(true);
    expect(busEvents.some((e) => e.type === "page-cap-warning")).toBe(true);
    expect(busEvents.some((e) => e.type === "check-completed")).toBe(true);

    // Only check-completed persisted, not ephemeral telemetry
    const rows = db.select().from(checkRows).where(eq(checkRows.runId, runId)).all();
    expect(rows).toHaveLength(1);
    expect(rows[0].checkId).toBe("ENTRA-TEST-001.1");

    unsub();
  });

  it("each check-completed persists its row immediately via appendCheckRows", async () => {
    const db = createIsolatedDb();
    const { runId } = seedUserAndRun(db);

    const runEngineFn = vi.fn(async (opts: { sink: { emit: (e: EngineEvent) => void } }) => {
      opts.sink.emit({ type: "check-completed", sectionId: "identity", row: makeCheckRow({ checkId: "ENTRA-A-001.1" }) });
      opts.sink.emit({ type: "check-completed", sectionId: "identity", row: makeCheckRow({ checkId: "ENTRA-B-001.1" }) });
      opts.sink.emit({ type: "run-finished", result: { tenantId: "t", sections: [] } });
      return { tenantId: "t", sections: [] };
    });

    await startRun(runId, {
      database: db as unknown as Db,
      createTransport: (() => ({}) as unknown) as never,
      runEngineFn: runEngineFn as unknown as never,
    });

    const rows = db.select().from(checkRows).where(eq(checkRows.runId, runId)).all().sort((a, b) => a.rowOrder - b.rowOrder);
    expect(rows).toHaveLength(2);
    expect(rows[0].checkId).toBe("ENTRA-A-001.1");
    expect(rows[1].checkId).toBe("ENTRA-B-001.1");
    expect(rows[0].rowOrder).toBe(0);
    expect(rows[1].rowOrder).toBe(1);
  });

  it("section-error messages are retained per-section and run-finished SectionResult errors are handled", async () => {
    const db = createIsolatedDb();
    const { runId } = seedUserAndRun(db);

    const bus = getRunBus();
    const busEvents: EngineEvent[] = [];
    const unsub = bus.subscribe(runId, (e) => busEvents.push(e));

    const runEngineFn = vi.fn(async (opts: { sink: { emit: (e: EngineEvent) => void } }) => {
      opts.sink.emit({ type: "section-error", sectionId: "identity", message: "section boom" });
      opts.sink.emit({
        type: "run-finished",
        result: {
          tenantId: "t",
          sections: [{ sectionId: "identity", rows: [], error: "fail-soft error" }],
        },
      });
      return {
        tenantId: "t",
        sections: [{ sectionId: "identity", rows: [], error: "fail-soft error" }],
      };
    });

    await startRun(runId, {
      database: db as unknown as Db,
      createTransport: (() => ({}) as unknown) as never,
      runEngineFn: runEngineFn as unknown as never,
    });

    expect(busEvents.some((e) => e.type === "section-error" && (e as { message: string }).message === "section boom")).toBe(true);
    expect(busEvents.some((e) => e.type === "run-finished")).toBe(true);
    const completed = db.select().from(runs).where(eq(runs.id, runId)).get() as { status: string };
    expect(completed.status).toBe("completed");
    unsub();
  });

  it("successful completion marks completed; thrown failure marks failed with safeErrorMessage", async () => {
    const db = createIsolatedDb();
    const { runId: okId } = seedUserAndRun(db);
    await startRun(okId, {
      database: db as unknown as Db,
      createTransport: (() => ({}) as unknown) as never,
      runEngineFn: (async () => {
        return { tenantId: "t", sections: [] };
      }) as unknown as never,
    });
    expect((db.select().from(runs).where(eq(runs.id, okId)).get() as { status: string }).status).toBe("completed");

    const { runId: failId } = seedUserAndRun(db);
    await startRun(failId, {
      database: db as unknown as Db,
      createTransport: (() => ({}) as unknown) as never,
      runEngineFn: (async () => {
        throw new Error("engine\nmultiline boom that should be sanitized to single line and truncated if overly long " + "x".repeat(300));
      }) as unknown as never,
    });
    const failed = db.select().from(runs).where(eq(runs.id, failId)).get() as { status: string; error: string | null };
    expect(failed.status).toBe("failed");
    expect(failed.error).toBeDefined();
    expect(failed.error!.includes("\n")).toBe(false);
    expect(failed.error!.length).toBeLessThanOrEqual(200);
    expect(failed.error).toContain("engine");
  });

  it("startRun refuses when not queued and when already executing", async () => {
    const db = createIsolatedDb();
    const { runId: completedId } = seedUserAndRun(db, { status: "completed" });
    const runEngineFn = vi.fn(async () => ({ tenantId: "t", sections: [] }));
    await startRun(completedId, {
      database: db as unknown as Db,
      createTransport: (() => ({}) as unknown) as never,
      runEngineFn: runEngineFn as unknown as never,
    });
    expect(runEngineFn).not.toHaveBeenCalled();

    // Already executing guard
    const { runId: queuedId } = seedUserAndRun(db, { status: "queued" });
    // Simulate active execution via manual set (internal)
    // Start two concurrent calls: first should proceed, second should be refused due to active set
    let firstStarted = false;
    const slowEngine = vi.fn(async (opts: { sink: { emit: (e: EngineEvent) => void } }) => {
      firstStarted = true;
      // keep execution active briefly to allow second call to race
      await new Promise((r) => setTimeout(r, 50));
      opts.sink.emit({ type: "run-finished", result: { tenantId: "t", sections: [] } });
      return { tenantId: "t", sections: [] };
    });
    const p1 = startRun(queuedId, {
      database: db as unknown as Db,
      createTransport: (() => ({}) as unknown) as never,
      runEngineFn: slowEngine as unknown as never,
    });
    // Give p1 a moment to acquire the active slot
    await new Promise((r) => setTimeout(r, 10));
    expect(getActiveExecutions().has(queuedId)).toBe(true);
    const runEngineFn2 = vi.fn(async () => ({ tenantId: "t", sections: [] }));
    await startRun(queuedId, {
      database: db as unknown as Db,
      createTransport: (() => ({}) as unknown) as never,
      runEngineFn: runEngineFn2 as unknown as never,
    });
    expect(runEngineFn2).not.toHaveBeenCalled();
    await p1;
    expect(getActiveExecutions().has(queuedId)).toBe(false);
    expect(firstStarted).toBe(true);
  });

  it("injectable deps allow offline testing with :memory: DB and zero network calls", async () => {
    const db = createIsolatedDb();
    const { runId } = seedUserAndRun(db);
    const createTransport = vi.fn(() => ({}) as unknown);
    const runEngineFn = vi.fn(async (opts: { sink: { emit: (e: EngineEvent) => void } }) => {
      opts.sink.emit({ type: "check-completed", sectionId: "identity", row: makeCheckRow() });
      opts.sink.emit({ type: "run-finished", result: { tenantId: "t", sections: [] } });
      return { tenantId: "t", sections: [] };
    });
    // loadOperatorSecret and getClientId should NOT be called when createTransport is stubbed
    const loadOperatorSecret = vi.fn(async () => "secret");
    const getClientId = vi.fn(() => "client-id");

    await startRun(runId, {
      database: db as unknown as Db,
      loadOperatorSecret,
      getClientId,
      createTransport: createTransport as unknown as never,
      runEngineFn: runEngineFn as unknown as never,
    });

    expect(loadOperatorSecret).not.toHaveBeenCalled();
    expect(getClientId).not.toHaveBeenCalled();
    expect(createTransport).not.toHaveBeenCalled(); // stub is passed through, not invoked to mint
    expect(runEngineFn).toHaveBeenCalled();
    const rows = db.select().from(checkRows).where(eq(checkRows.runId, runId)).all();
    expect(rows).toHaveLength(1);
  });
});
