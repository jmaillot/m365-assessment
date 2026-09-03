import crypto from "node:crypto";
import path from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";

// The singleton "@/db" module opens DATABASE_PATH and applies migrations at
// import time. Static imports are hoisted, so neutralize that side effect by
// pointing it at an ephemeral in-memory database BEFORE any app module loads
// (app modules are imported dynamically below).
process.env.DATABASE_PATH = ":memory:";

const { disconnectTenant } = await import("./disconnect");
const schema = await import("../../db/schema");
const { sessions, tenantConnections, users } = schema;

const MIGRATIONS_FOLDER = path.resolve(process.cwd(), "src/db/migrations");

/** Fresh :memory: database with the project migrations applied. */
function createIsolatedDb() {
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = MEMORY");
  sqlite.pragma("foreign_keys = ON");
  const database = drizzle(sqlite, { schema });
  migrate(database, { migrationsFolder: MIGRATIONS_FOLDER });
  return database;
}

type Db = ReturnType<typeof createIsolatedDb>;

interface Seed {
  userId: string;
  sessionId: string;
}

async function seedUserWithConnection(database: Db): Promise<Seed> {
  const userId = crypto.randomUUID();
  const sessionId = crypto.randomBytes(32).toString("hex");

  await database.insert(users).values({
    id: userId,
    entraObjectId: crypto.randomUUID(),
    email: "admin@YOUR-HOST.example",
    displayName: "Disconnect Test User",
  });
  await database.insert(sessions).values({
    id: sessionId,
    userId,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });
  // refreshTokenEnc holds AES-256-GCM ciphertext in production; the value
  // here only needs to satisfy the NOT NULL contract.
  await database.insert(tenantConnections).values({
    id: crypto.randomUUID(),
    userId,
    tenantId: crypto.randomUUID(),
    tenantName: "Disconnected Test Tenant",
    primaryDomain: "disconnected.YOUR-HOST.example",
    refreshTokenEnc: "enc:v1:dummy-ciphertext",
  });

  return { userId, sessionId };
}

describe("disconnectTenant", () => {
  it("returns true and deletes the connection row when an owned connection existed", async () => {
    const database = createIsolatedDb();
    const { userId } = await seedUserWithConnection(database);

    await expect(disconnectTenant(userId, database)).resolves.toBe(true);

    const remaining = await database
      .select()
      .from(tenantConnections)
      .where(eq(tenantConnections.userId, userId));
    expect(remaining).toHaveLength(0); // no row remains for that userId
  });

  it("returns false when no connection existed for the user", async () => {
    const database = createIsolatedDb();
    const { userId } = await seedUserWithConnection(database);

    await expect(disconnectTenant(userId, database)).resolves.toBe(true);
    // Second disconnect for the same user: nothing left to remove.
    await expect(disconnectTenant(userId, database)).resolves.toBe(false);
    // Unknown user id: also false, never an error.
    await expect(disconnectTenant(crypto.randomUUID(), database)).resolves.toBe(
      false,
    );
  });

  it("leaves users and sessions untouched (user can still sign in)", async () => {
    const database = createIsolatedDb();
    const { userId, sessionId } = await seedUserWithConnection(database);

    await disconnectTenant(userId, database);

    const survivingUsers = await database
      .select()
      .from(users)
      .where(eq(users.id, userId));
    expect(survivingUsers).toHaveLength(1);

    const survivingSessions = await database
      .select()
      .from(sessions)
      .where(eq(sessions.id, sessionId));
    expect(survivingSessions).toHaveLength(1);
  });

  it("only deletes the targeted user's row (other connections survive)", async () => {
    const database = createIsolatedDb();
    const first = await seedUserWithConnection(database);
    const second = await seedUserWithConnection(database);

    await disconnectTenant(first.userId, database);

    const secondConnection = await database
      .select()
      .from(tenantConnections)
      .where(eq(tenantConnections.userId, second.userId));
    expect(secondConnection).toHaveLength(1);
  });
});
