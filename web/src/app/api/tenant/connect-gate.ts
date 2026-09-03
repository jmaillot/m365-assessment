import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";

import type * as schema from "@/db/schema";
import { hasOperatorCredential } from "@/lib/settings/operator-credential";

/**
 * Connect gate helper (D-06) — shared server-side read that tells connect
 * surfaces whether the deployment still lacks an operator credential.
 *
 * This is a UX-layer gate only: while `gated` is true, tenant-connect actions
 * render disabled behind CredentialStatusBanner. Actual enforcement is
 * fail-closed at the engine boundary — assessments mint tokens with
 * decryptOperatorSecret(), which throws when nothing is configured
 * (T-02-11c), so a crafted request gains nothing.
 *
 * Injectable database param mirrors disconnect.ts / operator-credential.ts so
 * a :memory: DB can unit-test callers; defaults to the app singleton.
 */
export interface CredentialGate {
  /** True when NO operator credential is configured — connect actions gated. */
  gated: boolean;
}

export async function getCredentialGate(
  database?: BetterSQLite3Database<typeof schema>,
): Promise<CredentialGate> {
  const configured = await hasOperatorCredential(database);
  return { gated: !configured };
}
