import crypto from "node:crypto";

/**
 * One-time consent-state binding for the tenant connect flow (T-04-01).
 *
 * Same mechanism as the OIDC sign-in state in entra-client.ts: the signed
 * binding travels in an httpOnly cookie instead of a server-side store so
 * the flow survives multiple processes. HMAC-signed with SESSION_SECRET,
 * time-boxed to 10 minutes, and consumed (cookie cleared) exactly once at
 * the callback.
 */

export const CONNECT_STATE_COOKIE = "m365a_connect";
export const CONNECT_STATE_MAX_AGE_SECONDS = 600; // 10 min single-use window

interface ConnectStatePayload {
  /** Session user that initiated the connect — bound at callback (T-04-03). */
  userId: string;
  purpose: "connect";
  nonce: string;
  iat: number;
}

function hmacSign(payload: string): string {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length === 0) {
    throw new Error(
      "SESSION_SECRET is not set. Copy .env.example to .env and fill in the values.",
    );
  }
  return crypto.createHmac("sha256", secret).update(payload).digest("base64url");
}

function secureCookies(): boolean {
  return (
    process.env.NODE_ENV === "production" ||
    (process.env.APP_BASE_URL ?? "http://localhost:3000").startsWith("https://")
  );
}

/** Cookie options for setting (connect) and clearing (callback) the state. */
export function connectStateCookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: secureCookies(),
    path: "/",
    maxAge,
  } as const;
}

export function createConnectState(userId: string): {
  state: string;
  cookieValue: string;
} {
  const payload: ConnectStatePayload = {
    userId,
    purpose: "connect",
    nonce: crypto.randomBytes(16).toString("hex"),
    iat: Date.now(),
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return { state: payload.nonce, cookieValue: `${encoded}.${hmacSign(encoded)}` };
}

/** Verify signature + freshness + purpose; returns null on any tamper/expiry. */
export function readConnectState(
  cookieValue: string | undefined,
): ConnectStatePayload | null {
  if (!cookieValue) return null;
  const dot = cookieValue.lastIndexOf(".");
  if (dot <= 0) return null;
  const encoded = cookieValue.slice(0, dot);
  const signature = cookieValue.slice(dot + 1);

  const expected = hmacSign(encoded);
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (
    sigBuf.length !== expBuf.length ||
    !crypto.timingSafeEqual(sigBuf, expBuf)
  ) {
    return null;
  }

  let payload: ConnectStatePayload;
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString()) as ConnectStatePayload;
  } catch {
    return null;
  }
  if (
    !payload.userId ||
    payload.purpose !== "connect" ||
    typeof payload.nonce !== "string" ||
    typeof payload.iat !== "number"
  ) {
    return null;
  }
  const ageMs = Date.now() - payload.iat;
  if (ageMs < 0 || ageMs > CONNECT_STATE_MAX_AGE_SECONDS * 1000) {
    return null;
  }
  return payload;
}
