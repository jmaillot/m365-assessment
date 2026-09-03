import { NextResponse, type NextRequest } from "next/server";
import { eq } from "drizzle-orm";

import { requiredRolesForSections } from "@/engine/registry/permissions";
import { verifyAppPermissions } from "@/engine/verify-permissions-app";
import { db } from "@/db";
import { tenantConnections } from "@/db/schema";
import { appBaseUrl } from "@/lib/auth/entra-client";
import { getSession } from "@/lib/auth/session";
import {
  safeErrorMessage,
  toPersistableVerification,
} from "@/lib/graph/token-client";
import { decryptOperatorSecret } from "@/lib/settings/operator-credential";

/**
 * POST /api/tenant/verify — re-run the application-permission verification on
 * demand (D-03/D-07). Powers the "Try again" button for the explicit
 * could-not-verify state and manual re-checks on S5. Reads/writes the
 * caller's OWN row only (userId filter, T-04-03). Result is persisted
 * (three-state: all_granted / missing / error) and returned as JSON.
 *
 * Since the delegated flow was retired, verification mints a fresh app-only
 * token from the operator credential (client_credentials) and diffs granted
 * app roles + live probes via plan 02-13's verifyAppPermissions — a stranded
 * Phase 1 delegated connection flips to the current three-state result on
 * this next check (no destructive migration, D-03).
 *
 * CSRF guard (T-03-05 pattern): mutating POSTs verify the Origin host.
 */
export const runtime = "nodejs";

/** Sections whose app-role union the connect flow consents to (D-03, D-21: +security/intune, D-40: +exchange/collaboration). */
const CONNECT_SECTIONS = ["tenant", "identity", "licensing", "security", "intune", "exchange", "collaboration"] as const;

function sameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false; // form posts from our own pages always send Origin in modern browsers
  try {
    const originHost = new URL(origin).host;
    const appHost =
      process.env.APP_BASE_URL !== undefined && process.env.APP_BASE_URL !== ""
        ? new URL(appBaseUrl()).host
        : request.headers.get("host");
    return appHost !== null && originHost === appHost;
  } catch {
    return false;
  }
}

export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) {
    return NextResponse.json(
      { error: "cross-origin request rejected" },
      { status: 403 },
    );
  }

  const { user } = await getSession();
  if (!user) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  const rows = await db
    .select()
    .from(tenantConnections)
    .where(eq(tenantConnections.userId, user.id))
    .limit(1);
  const row = rows[0];
  if (!row) {
    return NextResponse.json(
      { error: "no tenant connection — connect a tenant first" },
      { status: 404 },
    );
  }

  let clientSecret: string;
  try {
    clientSecret = await decryptOperatorSecret();
  } catch (err) {
    // Missing or undecryptable operator secret — fail explicitly, never as
    // zero-missing (D-05).
    console.error(
      "[tenant] verify failed: operator credential:",
      safeErrorMessage(err),
    );
    return NextResponse.json(
      { error: "operator credential unavailable — set it in settings first" },
      { status: 500 },
    );
  }

  const clientId = process.env.AZURE_CLIENT_ID;
  if (!clientId) {
    console.error("[tenant] verify failed: AZURE_CLIENT_ID is not set");
    return NextResponse.json(
      { error: "server is not configured for Graph authentication" },
      { status: 500 },
    );
  }

  // Fail-explicit three-state (D-04): mint failures surface as status
  // "error" inside the result and ARE persisted — never silent.
  const requiredRoles = requiredRolesForSections([...CONNECT_SECTIONS]);
  const verification = await verifyAppPermissions({
    tenantId: row.tenantId,
    clientId,
    clientSecret,
    requiredRoles,
  });

  const persisted = toPersistableVerification(verification, requiredRoles);

  await db
    .update(tenantConnections)
    .set({
      verificationJson: JSON.stringify(persisted),
      verifiedAt: new Date(),
    })
    .where(eq(tenantConnections.userId, user.id));

  return NextResponse.json(persisted);
}
