import crypto from "node:crypto";

import { Issuer, generators } from "openid-client";

/**
 * Microsoft Entra ID OIDC client (work/school accounts only — D-04).
 *
 * Authority is the multi-tenant `/organizations` endpoint, so personal
 * Microsoft accounts never complete sign-in at Entra itself; the callback
 * route additionally enforces D-04 by inspecting ID-token claims.
 *
 * openid-client v5 natively validates Azure AD tokens against the
 * `{tenantid}` issuer template returned by tenantless discovery endpoints.
 */

export const SESSION_SCOPE = "openid profile email offline_access";

const OIDC_STATE_COOKIE_MAX_AGE_SECONDS = 600; // 10 min single-use window

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.length === 0) {
    throw new Error(
      `${name} is not set. Copy .env.example to .env and fill in the values.`,
    );
  }
  return value;
}

/** Canonical app origin used to build absolute redirect/return URLs. */
export function appBaseUrl(): string {
  return (process.env.APP_BASE_URL ?? "http://localhost:3000").replace(
    /\/+$/,
    "",
  );
}

export function authRedirectUri(): string {
  return `${appBaseUrl()}/api/auth/callback`;
}

/**
 * Secure cookie flag: on when running in production or when APP_BASE_URL is
 * an https origin (T-03-03). Dev on http://localhost stays usable.
 */
export function secureCookies(): boolean {
  return (
    process.env.NODE_ENV === "production" ||
    appBaseUrl().startsWith("https://")
  );
}

let clientPromise: ReturnType<typeof initClient> | null = null;

async function initClient() {
  const authority =
    process.env.AZURE_AUTHORITY ??
    "https://login.microsoftonline.com/organizations";
  const issuer = await Issuer.discover(`${authority.replace(/\/+$/, "")}/v2.0`);
  return new issuer.Client({
    client_id: requireEnv("AZURE_CLIENT_ID"),
    client_secret: requireEnv("AZURE_CLIENT_SECRET"),
    redirect_uris: [authRedirectUri()],
    response_types: ["code"],
  });
}

async function getClient() {
  if (!clientPromise) {
    clientPromise = initClient();
  }
  return clientPromise;
}

/** Authorization-endpoint URL with state + PKCE S256 challenge bound in. */
export async function buildSignInUrl(
  state: string,
  codeChallenge: string,
): Promise<string> {
  const client = await getClient();
  return client.authorizationUrl({
    scope: SESSION_SCOPE,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
}

export interface ExchangeResult {
  /** Validated ID-token claims (iss/aud/exp verified by openid-client). */
  idTokenClaims: Record<string, unknown>;
  /** UserInfo response when reachable; claims are always present as fallback. */
  userInfo: Record<string, unknown> | null;
}

/**
 * Exchange the authorization code for tokens via the token endpoint.
 * Validates state and PKCE verifier server-side (T-03-02).
 */
export async function exchangeCode(
  params: { code?: string; state?: string },
  codeVerifier: string,
): Promise<ExchangeResult> {
  const client = await getClient();
  const tokenSet = await client.callback(authRedirectUri(), params, {
    code_verifier: codeVerifier,
    ...(params.state ? { state: params.state } : {}),
  });

  // UserInfo is enrichment only — sign-in proceeds from ID-token claims
  // if the userinfo endpoint is unavailable. Never log token contents.
  let userInfo: Record<string, unknown> | null = null;
  if (tokenSet.access_token) {
    try {
      userInfo = (await client.userinfo(tokenSet)) as Record<string, unknown>;
    } catch {
      userInfo = null;
    }
  }

  return { idTokenClaims: tokenSet.claims(), userInfo };
}

// ---------------------------------------------------------------------------
// One-time OIDC state binding (T-03-02)
//
// The signed state + PKCE verifier travel in an httpOnly cookie instead of a
// server-side store so the flow survives multiple processes. HMAC-signed with
// SESSION_SECRET, time-boxed to 10 minutes, and consumed (cookie cleared)
// exactly once at the callback.
// ---------------------------------------------------------------------------

export const OIDC_STATE_COOKIE = "m365a_oidc";
export const OIDC_STATE_COOKIE_MAX_AGE = OIDC_STATE_COOKIE_MAX_AGE_SECONDS;

interface OidcStatePayload {
  state: string;
  codeVerifier: string;
  iat: number;
}

function hmacSign(payload: string): string {
  return crypto
    .createHmac("sha256", requireEnv("SESSION_SECRET"))
    .update(payload)
    .digest("base64url");
}

export function createOidcState(): {
  state: string;
  codeChallenge: string;
  cookieValue: string;
} {
  const payload: OidcStatePayload = {
    state: generators.state(),
    codeVerifier: generators.codeVerifier(),
    iat: Date.now(),
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return {
    state: payload.state,
    codeChallenge: generators.codeChallenge(payload.codeVerifier),
    cookieValue: `${encoded}.${hmacSign(encoded)}`,
  };
}

/** Verify signature + freshness; returns null on any tamper/expiry. */
export function readOidcState(cookieValue: string | undefined):
  | { state: string; codeVerifier: string }
  | null {
  if (!cookieValue) return null;
  const dot = cookieValue.lastIndexOf(".");
  if (dot <= 0) return null;
  const encoded = cookieValue.slice(0, dot);
  const signature = cookieValue.slice(dot + 1);

  const expected = hmacSign(encoded);
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  let payload: OidcStatePayload;
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString()) as OidcStatePayload;
  } catch {
    return null;
  }
  if (!payload.state || !payload.codeVerifier || typeof payload.iat !== "number") {
    return null;
  }
  const ageMs = Date.now() - payload.iat;
  if (ageMs < 0 || ageMs > OIDC_STATE_COOKIE_MAX_AGE_SECONDS * 1000) {
    return null;
  }
  return { state: payload.state, codeVerifier: payload.codeVerifier };
}
