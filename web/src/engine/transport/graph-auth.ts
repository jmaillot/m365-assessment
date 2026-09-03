import { Issuer, type Client } from "openid-client";

/**
 * App-only (client_credentials) Graph authentication for the assessment
 * engine (D-01). One operator-held client secret on the multi-tenant app
 * registration mints per-tenant tokens via each tenant's stored tenantId —
 * no per-customer app registrations.
 *
 * Security notes:
 * - `.default` is MANDATORY for client_credentials: individual permission
 *   names are invalid scopes for this grant. Consent comes from app-role
 *   assignments, so a minted token can never exceed what was consented.
 * - `getGrantedRoles` decodes the JWT payload WITHOUT signature verification
 *   of our own: the token just arrived over TLS directly from Microsoft and
 *   is validated by USING it against Graph. App-only tokens carry application
 *   permissions in the `roles` array claim — NEVER `scp` (Pitfall 1), so this
 *   reader is separate from lib/graph's delegated `getGrantedScopes`.
 * - The client secret is only ever passed as a grant parameter; it is never
 *   serialized into errors, cache keys, or events.
 */

/** Graph resource scope used with `.default` (all consented app roles). */
export const GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default";

/** Power BI resource scope used with `.default` — analysis.windows.net audience. */
export const POWERBI_DEFAULT_SCOPE = "https://analysis.windows.net/powerbi/api/.default";

/**
 * Tokens are reused until their remaining lifetime drops below this margin —
 * covers clock skew plus one in-flight assessment call.
 */
export const TOKEN_EXPIRY_MARGIN_MS = 120_000;

/** Entra tenant ids are GUIDs; enforced before interpolating into the issuer URL. */
const GUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface AppToken {
  accessToken: string;
  /** Epoch ms at which the access token expires (from expires_in). */
  expiresAt: number;
}

// Discovered clients cached per process (evicted on failure so a transient
// discovery outage is retried later) — same discipline as token-client.ts.
const issuerClients = new Map<string, Promise<Client>>();

async function getIssuerClient(
  tenantId: string,
  clientId: string,
  clientSecret: string,
): Promise<Client> {
  let pending = issuerClients.get(tenantId);
  if (!pending) {
    pending = (async () => {
      const issuer = await Issuer.discover(
        `https://login.microsoftonline.com/${tenantId}/v2.0`,
      );
      return new issuer.Client({ client_id: clientId, client_secret: clientSecret });
    })();
    issuerClients.set(tenantId, pending);
    // Evict on failure so a transient discovery outage is retried later.
    pending.catch(() => issuerClients.delete(tenantId));
  }
  return pending;
}

export async function mintAppOnlyTokenWithScope(
  tenantId: string,
  clientId: string,
  clientSecret: string,
  scope: string,
): Promise<AppToken> {
  if (!GUID_PATTERN.test(tenantId)) {
    throw new Error(
      `tenantId is not a GUID; refusing to mint against '${tenantId.slice(0, 64)}'`,
    );
  }
  const client = await getIssuerClient(tenantId, clientId, clientSecret);
  const tokenSet = await client.grant({
    grant_type: "client_credentials",
    scope,
  });
  if (!tokenSet.access_token) {
    throw new Error("token endpoint returned no access_token");
  }
  const expiresAt =
    typeof tokenSet.expires_at === "number" ? tokenSet.expires_at * 1000 : 0;
  return { accessToken: tokenSet.access_token, expiresAt };
}

/**
 * Mint a fresh app-only access token for one tenant via client_credentials
 * with the mandatory `.default` scope. Throws on any token-endpoint failure,
 * including an explicit error when the grant response carries no access_token.
 */
export async function mintAppOnlyToken(
  tenantId: string,
  clientId: string,
  clientSecret: string,
): Promise<AppToken> {
  return mintAppOnlyTokenWithScope(tenantId, clientId, clientSecret, GRAPH_DEFAULT_SCOPE);
}

// Minted tokens cached per tenant+client+resource until near expiry. Keys never
// contain the secret (T-02-02f). Resource is the .default scope.
const tokenCache = new Map<string, AppToken>();

export async function getTokenForResource(
  tenantId: string,
  clientId: string,
  clientSecret: string,
  scope: string,
): Promise<AppToken> {
  const key = `${tenantId}|${clientId}|${scope}`;
  const cached = tokenCache.get(key);
  if (cached && cached.expiresAt - TOKEN_EXPIRY_MARGIN_MS > Date.now()) {
    return cached;
  }
  const token = await mintAppOnlyTokenWithScope(tenantId, clientId, clientSecret, scope);
  tokenCache.set(key, token);
  return token;
}

export async function getPowerBiTokenForTenant(
  tenantId: string,
  clientId: string,
  clientSecret: string,
): Promise<AppToken> {
  return getTokenForResource(tenantId, clientId, clientSecret, POWERBI_DEFAULT_SCOPE);
}

/**
 * Cached front for mintAppOnlyToken: returns the stored AppToken while it
 * outlives TOKEN_EXPIRY_MARGIN_MS, otherwise re-mints.
 */
export async function getTokenForTenant(
  tenantId: string,
  clientId: string,
  clientSecret: string,
): Promise<AppToken> {
  return getTokenForResource(tenantId, clientId, clientSecret, GRAPH_DEFAULT_SCOPE);
}

/**
 * Extract granted application permissions from an app-only Graph access
 * token by decoding the JWT payload WITHOUT signature verification (see
 * module docblock). Reads the `roles` array claim. Throws on ANY
 * malformation — a silent [] would render every permission as missing
 * without explanation, which is exactly the Pitfall-1 bug class.
 */
export function getGrantedRoles(accessToken: string): string[] {
  const parts = accessToken.split(".");
  if (parts.length !== 3 || !parts[1]) {
    throw new Error("malformed access token: expected three JWT segments");
  }
  let claims: { roles?: unknown };
  try {
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    claims = JSON.parse(Buffer.from(payload, "base64").toString()) as {
      roles?: unknown;
    };
  } catch (err) {
    throw new Error("malformed access token: undecodable payload", {
      cause: err,
    });
  }
  if (!Array.isArray(claims.roles) || !claims.roles.every((r) => typeof r === "string")) {
    throw new Error("access token carries no roles claim or it is malformed");
  }
  return claims.roles;
}

/** Safe single-line message for persistence/logging — never token contents. */
export function safeErrorMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.split("\n")[0]?.slice(0, 200) ?? "unknown error";
}
