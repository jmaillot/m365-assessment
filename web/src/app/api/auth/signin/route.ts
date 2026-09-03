import { NextResponse, type NextRequest } from "next/server";

import {
  OIDC_STATE_COOKIE,
  OIDC_STATE_COOKIE_MAX_AGE,
  appBaseUrl,
  buildSignInUrl,
  createOidcState,
  secureCookies,
} from "@/lib/auth/entra-client";

/**
 * GET /api/auth/signin — start the Entra work-account SSO flow (D-01).
 * Generates a fresh state + PKCE verifier bound into an HMAC-signed
 * single-use httpOnly cookie, then 302s to the /organizations authorize
 * endpoint. No user-controlled redirect targets are accepted (T-03-07).
 */
export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  try {
    const { state, codeChallenge, cookieValue } = createOidcState();
    const authorizeUrl = await buildSignInUrl(state, codeChallenge);

    const response = NextResponse.redirect(authorizeUrl);
    response.cookies.set({
      name: OIDC_STATE_COOKIE,
      value: cookieValue,
      httpOnly: true,
      sameSite: "lax",
      secure: secureCookies(),
      path: "/",
      maxAge: OIDC_STATE_COOKIE_MAX_AGE,
    });
    return response;
  } catch (err) {
    // Log route + outcome only — never secrets or tokens (T-03-06).
    console.error(
      "[auth] signin failed:",
      err instanceof Error ? err.message : "unknown error",
    );
    return NextResponse.redirect(new URL("/", appBaseUrl()));
  }
}
