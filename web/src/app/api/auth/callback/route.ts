import crypto from "node:crypto";

import { NextResponse, type NextRequest } from "next/server";

import { db } from "@/db";
import { users } from "@/db/schema";
import {
  OIDC_STATE_COOKIE,
  appBaseUrl,
  exchangeCode,
  readOidcState,
} from "@/lib/auth/entra-client";
import { createSession } from "@/lib/auth/session";

/** Microsoft personal-account (MSA) tenant id — presence rejects sign-in (D-04). */
export const MSA_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad";

/**
 * GET /api/auth/callback — finish the Entra work-account SSO flow.
 *
 * 1. Validate the HMAC-signed state cookie (freshness + signature, T-03-02);
 *    consumed exactly once — cleared on every outgoing response.
 * 2. Exchange the code with PKCE; openid-client verifies the ID token
 *    (issuer incl. Azure `{tenantid}` template, audience, expiry).
 * 3. D-04: reject personal Microsoft accounts by ID-token claims
 *    (MSA tenant GUID, idp live.com, acct !== 0) — server-side check that a
 *    client cannot bypass (T-03-04).
 * 4. Upsert the user (D-02 open signup — no invite/approval) and create a
 *    server-side session (D-03), then redirect to /dashboard.
 *
 * Redirect targets are hardcoded literals only (T-03-07). No tokens are ever
 * logged — route + outcome only (T-03-06).
 */
export const runtime = "nodejs";

/** Extract a stringly claim defensively — claims are untrusted input shape-wise. */
function stringClaim(
  claims: Record<string, unknown> | null,
  key: string,
): string | undefined {
  const value = claims?.[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberClaim(
  claims: Record<string, unknown> | null,
  key: string,
): number | undefined {
  const value = claims?.[key];
  return typeof value === "number" ? value : undefined;
}

/** Every exit clears the OIDC binding cookie so state is strictly single-use. */
function finish(request: NextRequest, targetPath: string): NextResponse {
  const response = NextResponse.redirect(new URL(targetPath, appBaseUrl()));
  response.cookies.set({
    name: OIDC_STATE_COOKIE,
    value: "",
    httpOnly: true,
    sameSite: "lax",
    secure:
      process.env.NODE_ENV === "production" ||
      appBaseUrl().startsWith("https://"),
    path: "/",
    maxAge: 0,
  });
  return response;
}

export async function GET(request: NextRequest) {
  const params = Object.fromEntries(new URL(request.url).searchParams);

  const state = readOidcState(request.cookies.get(OIDC_STATE_COOKIE)?.value);
  if (!state || !params.code || params.state !== state.state) {
    // Missing/expired/forged state or malformed response — restart sign-in.
    console.error("[auth] callback failed: state validation");
    return finish(request, "/");
  }

  try {
    const { idTokenClaims, userInfo } = await exchangeCode(params, state.codeVerifier);

    // --- D-04 enforcement: work/school accounts only -----------------------
    const tid = stringClaim(idTokenClaims, "tid");
    const idp = stringClaim(idTokenClaims, "idp");
    const acct = numberClaim(idTokenClaims, "acct");
    if (
      tid === MSA_TENANT_ID ||
      idp === "live.com" ||
      (acct !== undefined && acct !== 0)
    ) {
      return finish(request, "/?error=account_type");
    }

    const entraObjectId = stringClaim(idTokenClaims, "oid");
    const email =
      stringClaim(userInfo, "email") ??
      stringClaim(idTokenClaims, "email") ??
      stringClaim(idTokenClaims, "preferred_username");

    if (!entraObjectId || !email) {
      console.error("[auth] callback failed: missing required claims");
      return finish(request, "/");
    }

    const displayName =
      stringClaim(userInfo, "name") ?? stringClaim(idTokenClaims, "name") ?? email;

    // D-02 open signup: first successful sign-in upserts the user row.
    const inserted = await db
      .insert(users)
      .values({
        id: crypto.randomUUID(),
        entraObjectId,
        email,
        displayName,
      })
      .onConflictDoUpdate({
        target: users.entraObjectId,
        set: { email, displayName },
      })
      .returning({ id: users.id });

    await createSession(inserted[0].id);
    return finish(request, "/dashboard");
  } catch (err) {
    console.error(
      "[auth] callback failed:",
      err instanceof Error ? err.message.split("\n")[0] : "unknown error",
    );
    return finish(request, "/");
  }
}
