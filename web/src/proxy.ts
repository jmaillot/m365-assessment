import { NextResponse, type NextRequest } from "next/server";

/**
 * Layer 1 of /dashboard protection (defense in depth).
 *
 * Edge-safe cookie-PRESENCE check ONLY: better-sqlite3 cannot run here, so
 * full DB session validation happens server-side in the dashboard layout.
 * Cookie name must stay in sync with SESSION_COOKIE in lib/auth/session.ts.
 *
 * Note: this file uses the Next.js 16 `proxy.ts` convention (the old
 * `middleware.ts` name is deprecated — same behavior, new export name).
 */

const SESSION_COOKIE = "m365a_session";

export function proxy(request: NextRequest) {
  const hasSessionCookie = Boolean(request.cookies.get(SESSION_COOKIE)?.value);
  if (!hasSessionCookie) {
    return NextResponse.redirect(
      new URL("/?notice=session_expired", request.url),
    );
  }
  return NextResponse.next();
}

export const config = {
  matcher: "/dashboard/:path*",
};
