import { eq } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";

import { db } from "@/db";
import * as schema from "@/db/schema";
import { tenantConnections } from "@/db/schema";

/**
 * Soft disconnect (ONB-03, D-08): deleting the tenant_connections row IS the
 * revocation. The row holds the only copy of the encrypted refresh token, so
 * a hard delete removes every stored credential in one atomic statement.
 *
 * NOTE — deliberately NO Microsoft Graph calls anywhere in this module:
 * MS Graph has no per-app refresh-token revocation endpoint for delegated
 * consents. Full removal of the consent object happens on the CUSTOMER side
 * by deleting the M365-Assess enterprise application in their own Entra
 * tenant — exactly what the S6 dialog copy and the post-disconnect cleanup
 * alert instruct (accepted D-08 design, threat register T-05-03).
 *
 * @param userId   Owning user — the delete is STRICTLY scoped to this id
 *                 (T-05-01: no caller can remove another user's connection).
 * @param database Injectable for tests; defaults to the app singleton.
 * @returns true when an owned connection existed and was deleted,
 *          false when there was nothing to delete.
 */
type Db = BetterSQLite3Database<typeof schema>;

export async function disconnectTenant(
  userId: string,
  database: Db = db,
): Promise<boolean> {
  const result = await database
    .delete(tenantConnections)
    .where(eq(tenantConnections.userId, userId));
  return result.changes > 0;
}
