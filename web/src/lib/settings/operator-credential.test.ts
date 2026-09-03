import path from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";

// The singleton "@/db" module opens DATABASE_PATH and applies migrations at
// import time. Static imports are hoisted, so neutralize that side effect by
// pointing it at an ephemeral in-memory database BEFORE any app module loads
// (app modules are imported dynamically below). encryptString requires a real
// key, so provide a deterministic test key too.
process.env.DATABASE_PATH = ":memory:";
process.env.ENCRYPTION_KEY = "a".repeat(64); // 32 bytes hex

const {
  hasOperatorCredential,
  saveOperatorCredentialIfAbsent,
  decryptOperatorSecret,
  rotateOperatorCredential,
} = await import("./operator-credential");
const schema = await import("../../db/schema");
const { operatorCredential } = schema;

const MIGRATIONS_FOLDER = path.resolve(process.cwd(), "src/db/migrations");

const SECRET = "operator-secret-DO-NOT-LOG-0123456789";
const ACCOUNT_ID = "0f8f7e1a-1111-2222-3333-444455556666";

interface Isolated {
  database: ReturnType<typeof drizzle<typeof schema>>;
  sqlite: Database.Database;
}

/** Fresh :memory: database with the project migrations applied. */
function createIsolatedDb(): Isolated {
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = MEMORY");
  sqlite.pragma("foreign_keys = ON");
  const database = drizzle(sqlite, { schema });
  migrate(database, { migrationsFolder: MIGRATIONS_FOLDER });
  return { database, sqlite };
}

describe("saveOperatorCredentialIfAbsent", () => {
  it("stores the secret encrypted on an empty table (first-use claim wins)", async () => {
    const { database, sqlite } = createIsolatedDb();

    await expect(
      saveOperatorCredentialIfAbsent(SECRET, ACCOUNT_ID, database),
    ).resolves.toEqual({ saved: true });

    const rows = database.select().from(operatorCredential).all();
    expect(rows).toHaveLength(1);
    // Ciphertext envelope shape — never the plaintext.
    expect(rows[0]!.secretEnc).toMatch(/^v1\./);
    expect(rows[0]!.configuredByAccountId).toBe(ACCOUNT_ID);
    expect(typeof rows[0]!.configuredAt).toBe("number");

    // T-02-04a: plaintext must not appear anywhere in the raw DB bytes.
    const bytes = Buffer.from(sqlite.serialize()).toString("latin1");
    expect(bytes).not.toContain(SECRET);
  });

  it("rejects the second save with already_configured and keeps the original row", async () => {
    const { database } = createIsolatedDb();

    await expect(
      saveOperatorCredentialIfAbsent(SECRET, ACCOUNT_ID, database),
    ).resolves.toEqual({ saved: true });

    await expect(
      saveOperatorCredentialIfAbsent(
        "second-attacker-secret",
        "other-account",
        database,
      ),
    ).resolves.toEqual({ saved: false, reason: "already_configured" });

    const rows = database.select().from(operatorCredential).all();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.configuredByAccountId).toBe(ACCOUNT_ID); // original intact
    // Original ciphertext unchanged (decryption round-trips the FIRST secret).
    await expect(decryptOperatorSecret(database)).resolves.toBe(SECRET);
  });

  it("lets exactly one of two racing saves win (transactional claim)", async () => {
    const { database } = createIsolatedDb();

    const [first, second] = await Promise.all([
      saveOperatorCredentialIfAbsent(SECRET, ACCOUNT_ID, database),
      saveOperatorCredentialIfAbsent("racer-secret", "racer", database),
    ]);

    const winners = [first, second].filter((r) => r.saved);
    expect(winners).toHaveLength(1);

    const rows = database.select().from(operatorCredential).all();
    expect(rows).toHaveLength(1);
  });
});

describe("hasOperatorCredential", () => {
  it("reports the false → true lifecycle", async () => {
    const { database } = createIsolatedDb();
    await expect(hasOperatorCredential(database)).resolves.toBe(false);

    await saveOperatorCredentialIfAbsent(SECRET, ACCOUNT_ID, database);
    await expect(hasOperatorCredential(database)).resolves.toBe(true);
  });

  it("returns false after every row is removed (rotation re-entry)", async () => {
    const { database } = createIsolatedDb();
    await saveOperatorCredentialIfAbsent(SECRET, ACCOUNT_ID, database);
    database.delete(operatorCredential).run();
    await expect(hasOperatorCredential(database)).resolves.toBe(false);
  });
});

describe("decryptOperatorSecret", () => {
  it("round-trips the original plaintext", async () => {
    const { database } = createIsolatedDb();
    await saveOperatorCredentialIfAbsent(SECRET, ACCOUNT_ID, database);
    await expect(decryptOperatorSecret(database)).resolves.toBe(SECRET);
  });

  it("throws an explicit error when no credential exists", async () => {
    const { database } = createIsolatedDb();
    await expect(decryptOperatorSecret(database)).rejects.toThrow(
      /no operator credential/i,
    );
  });
});

describe("rotateOperatorCredential", () => {
  it("reports rotated:false on an empty table (nothing to rotate)", async () => {
    const { database } = createIsolatedDb();
    await expect(
      rotateOperatorCredential(SECRET, ACCOUNT_ID, database),
    ).resolves.toEqual({ rotated: false });
    await expect(hasOperatorCredential(database)).resolves.toBe(false);
  });

  it("replaces the secret in place and updates provenance", async () => {
    const { database, sqlite } = createIsolatedDb();
    await saveOperatorCredentialIfAbsent(SECRET, ACCOUNT_ID, database);
    const before = database.select().from(operatorCredential).all()[0]!;

    const NEW_SECRET = "rotated-secret-DO-NOT-LOG-fedcba9876543210";
    const result = await rotateOperatorCredential(
      NEW_SECRET,
      "rotator-account",
      database,
    );
    expect(result).toEqual({ rotated: true });

    const after = database.select().from(operatorCredential).all();
    expect(after).toHaveLength(1); // still exactly one row — no zero-row window
    await expect(decryptOperatorSecret(database)).resolves.toBe(NEW_SECRET);
    expect(after[0]!.configuredByAccountId).toBe("rotator-account");
    expect(after[0]!.configuredAt).toBeGreaterThanOrEqual(before.configuredAt);

    // Old ciphertext gone from raw DB bytes.
    const bytes = Buffer.from(sqlite.serialize()).toString("latin1");
    expect(bytes).not.toContain(before.secretEnc);
    expect(bytes).not.toContain(NEW_SECRET);
  });

  it("rolls back atomically when a step fails mid-rotation (original row survives)", async () => {
    const { database } = createIsolatedDb();
    await saveOperatorCredentialIfAbsent(SECRET, ACCOUNT_ID, database);
    const before = database.select().from(operatorCredential).all()[0]!;

    // Proxy the transaction so `update` throws AFTER the claim check ran —
    // proving a failure inside the rotation leaves the original row intact.
    const failing = Object.create(database) as typeof database;
    failing.transaction = ((cb: (tx: never) => Promise<void>) =>
      database.transaction((tx) =>
        cb(
          new Proxy(tx as object, {
            get(target, prop, receiver) {
              if (prop === "update") {
                return () => {
                  throw new Error("injected failure");
                };
              }
              return Reflect.get(target, prop, receiver);
            },
          }) as never,
        ),
      )) as typeof database.transaction;

    await expect(
      rotateOperatorCredential("new-secret", "rotator", failing),
    ).rejects.toThrow(/injected failure/);

    const after = database.select().from(operatorCredential).all();
    expect(after).toHaveLength(1);
    expect(after[0]!.secretEnc).toBe(before.secretEnc); // ORIGINAL ciphertext
    await expect(decryptOperatorSecret(database)).resolves.toBe(SECRET);
  });
});
