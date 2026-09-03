import { NextResponse } from "next/server";

import { getSession } from "@/lib/auth/session";
import { getTenantStatus } from "@/lib/tenant/status";

/**
 * GET /api/tenant/status — connection status for the signed-in user.
 *
 * Response shape (contract for Plan 01-05):
 * {
 *   connected: boolean;
 *   tenant?: { id, name, primaryDomain, connectedAt };
 *   verification?: VerificationResult;
 * }
 *
 * Reads OWN-row only (filtered by session userId, T-04-03). No tokens are
 * ever included in the response.
 */
export const runtime = "nodejs";

export async function GET() {
  const { user } = await getSession();
  if (!user) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  const status = await getTenantStatus(user.id);
  return NextResponse.json(status);
}
