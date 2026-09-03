import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";

import * as schema from "./schema";
import { encryptString } from "../lib/crypto/encrypt";

/**
 * Singleton SQLite client (D-10). The database file lives at DATABASE_PATH
 * (default ./data/m365-assess.db for local dev; /app/data/m365-assess.db in
 * the Docker image). Pending migrations are applied at startup so container
 * boot always yields an up-to-date schema.
 */

const dbPath = process.env.DATABASE_PATH ?? "./data/m365-assess.db";

// Ensure the parent directory exists before better-sqlite3 opens the file.
fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });

const sqlite = new Database(dbPath);

// WAL journal mode for durability under Docker volume I/O.
sqlite.pragma("journal_mode = WAL");
// Enforce FK constraints (cascade deletes for sessions/tenant_connections).
sqlite.pragma("foreign_keys = ON");

export const db = drizzle(sqlite, { schema });

// Applied at startup so container boot always yields an up-to-date schema.
// Override DRIZZLE_MIGRATIONS_FOLDER when the app runs from a bundled
// location whose cwd differs from the source tree.
const migrationsFolder =
  process.env.DRIZZLE_MIGRATIONS_FOLDER ??
  path.resolve(process.cwd(), "src/db/migrations");
migrate(db, { migrationsFolder });

// Provider multi-tenant bootstrap (SaaS intent): if the deployment ships a
// client secret via env and no operator credential is stored yet, claim it
// automatically so customers never see a secret screen. The wizard remains
// only for rotation. Runs synchronously at import time so first request
// never races it. Best-effort — missing ENCRYPTION_KEY just leaves the
// credential unclaimed and the wizard surfaces the gated state.
try {
  const envSecret = process.env.AZURE_CLIENT_SECRET;
  if (envSecret && envSecret.trim().length > 0) {
    const existing = sqlite.prepare("SELECT 1 FROM operator_credential LIMIT 1").get();
    if (!existing) {
      const secretEnc = encryptString(envSecret);
      sqlite
        .prepare(
          "INSERT INTO operator_credential (id, secret_enc, configured_by_account_id, configured_at) VALUES (?, ?, ?, ?)",
        )
        .run(crypto.randomUUID(), secretEnc, "env-bootstrap", Date.now());
    }
  }
} catch {
  // Never crash boot over bootstrap failure; wizard will handle manual claim.
}
