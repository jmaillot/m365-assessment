import { NextResponse, type NextRequest } from "next/server";

import { appBaseUrl } from "@/lib/auth/entra-client";
import { destroySession } from "@/lib/auth/session";

/**
 * POST /api/auth/signout — delete the server session row and clear the
 * cookie, then return to the sign-in screen (S1).
 *
 * CSRF guard (T-03-05): cookies are SameSite=Lax, but mutating POSTs still
 * verify that the Origin host matches this app's host. Redirect target is a
 * hardcoded literal — never user input (T-03-07).
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
  if (!sameOrigin(request)) {
    return NextResponse.json({ error: "cross-origin sign-out rejected" }, { status: 403 });
  }

  await destroySession();
  // 303 so the browser follows with a GET of the target.
  return NextResponse.redirect(new URL("/", appBaseUrl()), 303);
}
