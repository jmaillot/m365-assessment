import { Issuer, type Client } from "openid-client";

import { appBaseUrl } from "@/lib/auth/entra-client";
import type { AppPermissionVerification } from "@/engine/verify-permissions-app";
import type { VerificationResult } from "./verify-permissions";

/**
 * Graph auth helpers for the tenant connect flow (Plan 02-04, D-03).
 *
 * The DELEGATED consent flow (authorization-code + refresh-token grants) was
 * retired in favor of APPLICATION permissions (app roles): assessments
 * authenticate with the single operator-held client secret via
 * client_credentials (see @/engine/transport/graph-auth), so no delegated
 * refresh token is stored or redeemed anywhere anymore. Stranded delegated
 * refresh tokens from Phase 1 connections are left inert as bytes in existing
 * rows — D-03 re-verification overwrites their verification status on next
 * check; no destructive migration is written.
 *
 * What remains here:
 * - GRAPH_SCOPE / tenantCallbackUri / getTenantClient — OIDC client plumbing
 *   still referenced by the connect-flow configuration surface.
 * - safeErrorMessage — single-line, secret-free error strings for persistence
 *   and logs (T-02-04c).
 * - toPersistableVerification — maps plan 02-13's AppPermissionVerification
 *   onto the Phase 1 VerificationResult shape (plus an `appPermissions`
 *   detail block) so status consumers keep working while the wizard UI
 *   catches up.
 */

/** Graph resource scope used with `.default` (all consented app roles). */
export const GRAPH_SCOPE = "https://graph.microsoft.com/.default";

/** Redirect URI registered for the tenant connect flow. */
export function tenantCallbackUri(): string {
  return `${appBaseUrl()}/api/tenant/callback`;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.length === 0) {
    throw new Error(
      `${name} is not set. Copy .env.example to .env and fill in the values.`,
    );
  }
  return value;
}

const tenantClients = new Map<string, Promise<Client>>();

async function createTenantClient(tenantId: string): Promise<Client> {
  const issuer = await Issuer.discover(
    `https://login.microsoftonline.com/${tenantId}/v2.0`,
  );
  return new issuer.Client({
    client_id: requireEnv("AZURE_CLIENT_ID"),
    client_secret: requireEnv("AZURE_CLIENT_SECRET"),
    redirect_uris: [tenantCallbackUri()],
    response_types: ["code"],
  });
}

/** Tenant-specific OIDC client, discovered once per tenant per process. */
export async function getTenantClient(tenantId: string): Promise<Client> {
  let pending = tenantClients.get(tenantId);
  if (!pending) {
    pending = createTenantClient(tenantId);
    tenantClients.set(tenantId, pending);
    // Evict on failure so a transient discovery outage is retried later.
    pending.catch(() => tenantClients.delete(tenantId));
  }
  return pending;
}

/** Safe single-line message for persistence/logging — never token contents. */
export function safeErrorMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.split("\n")[0]?.slice(0, 200) ?? "unknown error";
}

/**
 * Map an app-only permission verification (plan 02-13) onto the persisted
 * verification shape: the three-state status and required/granted/missing
 * arrays stay compatible with Phase 1 consumers (status.ts validation,
 * verification-view), while the full D-04 detail (rolesFromToken, probes)
 * rides along under `appPermissions` for the wizard UI.
 */
export function toPersistableVerification(
  verification: AppPermissionVerification,
  requiredRoles: string[],
): VerificationResult & { appPermissions: AppPermissionVerification } {
  return {
    status: verification.status,
    schemaVersion: "1.0",
    generatedAtUtc: new Date().toISOString(),
    required: [...requiredRoles],
    granted: [...verification.rolesFromToken],
    missing: [...verification.missingRoles],
    ...(verification.errorMessage
      ? { errorMessage: verification.errorMessage }
      : {}),
    appPermissions: verification,
  };
}
