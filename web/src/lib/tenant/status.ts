import { eq } from "drizzle-orm";

import { db } from "@/db";
import { tenantConnections } from "@/db/schema";
import type { VerificationResult } from "@/lib/graph/verify-permissions";

/**
 * Tenant connection status loader — the single data source behind
 * /api/tenant/status AND the S3/S5 server pages (no HTTP self-calls).
 * Every query filters by the session userId — cross-user access is
 * impossible by construction (T-04-03).
 */

export interface TenantStatus {
  connected: boolean;
  tenant?: {
    id: string;
    name: string | null;
    primaryDomain: string | null;
    connectedAt: string; // ISO-8601 UTC
  };
  verification?: VerificationResult;
}

export async function getTenantStatus(userId: string): Promise<TenantStatus> {
  const rows = await db
    .select()
    .from(tenantConnections)
    .where(eq(tenantConnections.userId, userId))
    .limit(1);

  const row = rows[0];
  if (!row) {
    return { connected: false };
  }

  let verification: VerificationResult | undefined;
  if (row.verificationJson) {
    try {
      const parsed = JSON.parse(row.verificationJson) as VerificationResult;
      if (
        parsed &&
        (parsed.status === "all_granted" ||
          parsed.status === "missing" ||
          parsed.status === "error")
      ) {
        verification = parsed;
      }
    } catch {
      // Corrupt payload → treated as "not yet verified" (S5 loading state).
      verification = undefined;
    }
  }

  return {
    connected: true,
    tenant: {
      id: row.tenantId,
      name: row.tenantName,
      primaryDomain: row.primaryDomain,
      connectedAt: row.connectedAt.toISOString(),
    },
    ...(verification ? { verification } : {}),
  };
}
