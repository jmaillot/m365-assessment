import { NextResponse, type NextRequest } from "next/server";

import { appBaseUrl } from "@/lib/auth/entra-client";
import { disconnectTenant } from "@/lib/graph/disconnect";
import { getSession } from "@/lib/auth/session";

/**
 * POST /api/tenant/disconnect — soft disconnect (ONB-03, D-08).
 *
 * Deletes the signed-in user's OWN tenant_connections row (which carries the
 * only copy of the encrypted refresh token — T-05-03). The delete is strictly
 * scoped to the session userId (T-05-01); there is no request parameter that
 * could target another user's connection.
 *
 * Guards:
 * - Session required → 401 JSON when absent.
 * - CSRF (T-05-02): Origin-header check, same guard as /api/auth/signout
 *   (cookies are SameSite=Lax; modern browsers always send Origin on POST).
 * - Never echoes any token material in responses or logs.
 */
export const runtime = "nodejs";

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
  const { user } = await getSession();
  if (!user) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  if (!sameOrigin(request)) {
    return NextResponse.json(
      { error: "cross-origin request rejected" },
      { status: 403 },
    );
  }

  await disconnectTenant(user.id);
  return NextResponse.json({ ok: true });
}
