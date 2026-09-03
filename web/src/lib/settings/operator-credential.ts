import crypto from "node:crypto";
import { eq, sql } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";

import { db } from "@/db";
import * as schema from "@/db/schema";
import { operatorCredential } from "@/db/schema";
import { decryptString, encryptString } from "@/lib/crypto/encrypt";

/**
 * Operator credential storage (D-01/D-02) — the ONE Graph client secret the
 * deployment authenticates assessments with (client_credentials, app-only).
 *
 * Security contract:
 * - Plaintext exists ONLY inside a single call chain; storage is exclusively
 *   AES-256-GCM ciphertext via lib/crypto/encrypt.ts (T-02-04a). Nothing in
 *   this module ever logs or returns the secret.
 * - FIRST-USE CLAIM: `saveOperatorCredentialIfAbsent` is enforced at the SQL
 *   level (`INSERT ... SELECT ... WHERE NOT EXISTS`) so two racing requests
 *   cannot both succeed — the claim is transactional, not UI-gated (T-02-04b,
 *   Pitfall 7). Silent overwrite is impossible; rotation happens only through
 *   the explicit `rotateOperatorCredential` path (D-05).
 * - Provenance: configured_by_account_id + configured_at persist who set it
 *   and when (T-02-04f).
 */

type Db = BetterSQLite3Database<typeof schema>;

export interface OperatorCredentialStatus {
  configured: boolean;
  configuredByEmail?: string;
  configuredAt?: number;
}

export interface SaveResult {
  saved: boolean;
  /** Present only when saved === false. */
  reason?: "already_configured";
}

export interface RotateResult {
  rotated: boolean;
}

/**
 * True when at least one credential row exists. Injectable database for
 * tests (same pattern as disconnect.ts); defaults to the app singleton.
 */
export async function hasOperatorCredential(
  database: Db = db,
): Promise<boolean> {
  const rows = await database.select().from(operatorCredential).limit(1);
  return rows.length > 0;
}

/** Status for pre-consent UI gating (never exposes any secret material). */
export async function getOperatorCredentialStatus(
  database: Db = db,
): Promise<OperatorCredentialStatus> {
  const rows = await database.select().from(operatorCredential).limit(1);
  const row = rows[0];
  if (!row) return { configured: false };
  return {
    configured: true,
    configuredAt: row.configuredAt,
  };
}

/**
 * Transactional first-use claim (D-02): insert-if-absent at the SQL level.
 * Returns {saved:true} for exactly one of any number of racing callers;
 * everyone else gets {saved:false, reason:"already_configured"}.
 */
export async function saveOperatorCredentialIfAbsent(
  clientSecretPlain: string,
  configuredByAccountId: string,
  database: Db = db,
): Promise<SaveResult> {
  // Encrypt BEFORE touching the DB — a key failure must leave no state change.
  const secretEnc = encryptString(clientSecretPlain);
  const result = await database.run(sql`
    INSERT INTO operator_credential (id, secret_enc, configured_by_account_id, configured_at)
    SELECT ${crypto.randomUUID()}, ${secretEnc}, ${configuredByAccountId}, ${Date.now()}
    WHERE NOT EXISTS (SELECT 1 FROM operator_credential)
  `);
  if (result.changes > 0) {
    return { saved: true };
  }
  return { saved: false, reason: "already_configured" };
}

/**
 * Decrypts the stored secret for engine use (minting client_credentials
 * tokens). NEVER logged, never returned to the client. Throws an explicit
 * error when nothing is configured — callers surface that as a distinct
 * state instead of a silent failure.
 */
export async function decryptOperatorSecret(
  database: Db = db,
): Promise<string> {
  const rows = await database.select().from(operatorCredential).limit(1);
  if (!rows[0]) {
    throw new Error(
      "no operator credential configured — set the client secret first",
    );
  }
  return decryptString(rows[0].secretEnc);
}

/**
 * Explicit rotation (D-05 "wizard re-entry anytime"): transactional
 * replace-in-place. The NEW secret is encrypted BEFORE the transaction opens
 * and swapped in with a single UPDATE — an in-place update can never
 * transiently leave zero credential rows (unlike delete+insert), so any
 * failure inside the rotation rolls back to the original row untouched.
 * This is the ONLY path that changes a stored secret; a plain POST stays
 * rejected with 409 already_configured (no silent overwrite).
 */
export async function rotateOperatorCredential(
  clientSecretPlain: string,
  rotatedByAccountId: string,
  database: Db = db,
): Promise<RotateResult> {
  // Key/encryption failures surface before any state change is attempted.
  const secretEnc = encryptString(clientSecretPlain);

  let rotated = false;
  // better-sqlite3 drives transactions synchronously — the callback must not
  // be async (drizzle throws on a returned promise).
  await database.transaction((tx) => {
    const existing = tx.select().from(operatorCredential).limit(1).get();
    if (!existing) {
      // Nothing to rotate — the first-use claim simply stays un-armed.
      return;
    }
    tx.update(operatorCredential)
      .set({
        secretEnc,
        configuredByAccountId: rotatedByAccountId,
        configuredAt: Date.now(),
      })
      .where(eq(operatorCredential.id, existing.id))
      .run();
    rotated = true;
  });
  return { rotated };
}

/**
 * Removes the stored credential entirely. Used by the session-gated DELETE
 * handler as step one of the guarded two-step rotation flow (DELETE → POST).
 * @returns true when a row existed and was deleted.
 */
export async function deleteOperatorCredential(
  database: Db = db,
): Promise<boolean> {
  const result = await database.delete(operatorCredential);
  return result.changes > 0;
}
