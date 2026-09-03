import crypto from "node:crypto";

import { NextResponse, type NextRequest } from "next/server";
import { eq } from "drizzle-orm";

import { verifyAppPermissions } from "@/engine/verify-permissions-app";
import { requiredRolesForSections } from "@/engine/registry/permissions";
import { mintAppOnlyToken } from "@/engine/transport/graph-auth";
import { db } from "@/db";
import { tenantConnections } from "@/db/schema";
import {
  CONNECT_STATE_COOKIE,
  connectStateCookieOptions,
  readConnectState,
} from "@/lib/auth/connect-state";
import { appBaseUrl } from "@/lib/auth/entra-client";
import { getSession } from "@/lib/auth/session";
import { toPersistableVerification, safeErrorMessage } from "@/lib/graph/token-client";
import { decryptOperatorSecret } from "@/lib/settings/operator-credential";

/**
 * GET /api/tenant/callback — finish the admin-consent flow (D-03/D-06/D-07).
 *
 * The connect flow now requests APPLICATION permissions via the adminconsent
 * endpoint, so this callback no longer redeems an authorization code:
 *
 * 1. Handle Microsoft error params FIRST (T-04-04): declined/failed consent
 *    redirects to an explicit destructive state on S5 — never treated as
 *    success.
 * 2. Validate the HMAC-signed single-use ≤10 min state cookie bound to the
 *    session userId BEFORE any DB write (T-04-01/T-04-03); cleared on every
 *    exit so replays fail.
 * 3. Require the operator credential (D-01) — without it nothing can be
 *    verified and no connection row is written.
 * 4. Verify application permissions with plan 02-13's verifyAppPermissions
 *    (roles diff + four live probes, three-state fail-explicit). A mint
 *    failure (e.g. invalid_client_secret) surfaces as an explicit persisted
 *    `error` verification — never silent (D-05).
 * 5. Fetch minimal tenant metadata from Graph (`displayName` +
 *    `verifiedDomains` only, T-04-07) using an app-only token; enrichment
 *    only, never blocks the connection.
 * 6. Replace any existing connection row (delete-before-insert = 1 account :
 *    1 tenant even across tenants, D-06). No delegated refresh token exists
 *    anymore — the NOT NULL column carries an inert placeholder instead
 *    (stranded Phase 1 tokens stay as bytes in old rows; no destructive
 *    migration).
 *
 * Redirect targets are hardcoded literals + fixed error codes only
 * (no open redirect). Secrets are never logged or sent to the client.
 */
export const runtime = "nodejs";

/** Entra tenant GUID shape check — the adminconsent `tenant` query param. */
const TENANT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Placeholder for the retired delegated refresh-token column: assessments
 * authenticate client_credentials with the operator secret, so there is no
 * delegated refresh token to store (D-03).
 */
const APP_ONLY_REFRESH_TOKEN_PLACEHOLDER = "app-only:no-delegated-refresh-token";

/** Sections whose app-role union the connect flow consents to (D-03, D-21: +security/intune). */
const CONNECT_SECTIONS = ["tenant", "identity", "licensing", "security", "intune"] as const;

interface VerifiedDomainsResponse {
  displayName?: string;
  verifiedDomains?: { name?: string; isDefault?: boolean }[];
}

function finish(request: NextRequest, targetPath: string): NextResponse {
  const response = NextResponse.redirect(
    new URL(targetPath, appBaseUrl()),
  );
  // Single-use: the binding cookie is consumed on EVERY exit.
  response.cookies.set({
    name: CONNECT_STATE_COOKIE,
    value: "",
    ...connectStateCookieOptions(0),
  });
  return response;
}

async function fetchTenantMetadata(
  tenantId: string,
  clientId: string,
  clientSecret: string,
): Promise<{ displayName: string | null; primaryDomain: string | null }> {
  const token = await mintAppOnlyToken(tenantId, clientId, clientSecret);
  const url =
    "https://graph.microsoft.com/v1.0/organization/" +
    encodeURIComponent(tenantId) +
    "?$select=" +
    encodeURIComponent("displayName,verifiedDomains");
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token.accessToken}` },
  });
  if (!response.ok) {
    throw new Error(`Graph organization lookup failed (${response.status})`);
  }
  const body = (await response.json()) as VerifiedDomainsResponse;
  const defaultDomain =
    body.verifiedDomains?.find((domain) => domain.isDefault === true)?.name ??
    null;
  return { displayName: body.displayName ?? null, primaryDomain: defaultDomain };
}

export async function GET(request: NextRequest) {
  const params = Object.fromEntries(new URL(request.url).searchParams);

  // --- 1. Consent errors first (T-04-04) ----------------------------------
  if (typeof params.error === "string" && params.error.length > 0) {
    console.error(`[tenant] callback: consent error: ${params.error}`);
    return finish(request, "/dashboard/tenant?error=consent_declined");
  }

  // --- 2. State + session validation before ANY DB write ------------------
  const state = readConnectState(request.cookies.get(CONNECT_STATE_COOKIE)?.value);
  if (!state) {
    console.error("[tenant] callback: state validation");
    return finish(request, "/dashboard/tenant?error=connect_failed");
  }

  const { user } = await getSession();
  if (!user || state.userId !== user.id) {
    return finish(request, "/dashboard/tenant?error=connect_failed");
  }

  // Adminconsent redirects carry the consented tenant id (no code, no
  // id_token — permission proof happens via verifyAppPermissions below).
  const tenantId =
    typeof params.tenant === "string" && TENANT_ID_PATTERN.test(params.tenant)
      ? params.tenant
      : undefined;
  if (!tenantId) {
    console.error("[tenant] callback: missing tenant param");
    return finish(request, "/dashboard/tenant?error=connect_failed");
  }

  try {
    // --- 3. Operator credential is mandatory (D-01/D-02) ------------------
    let clientSecret: string;
    try {
      clientSecret = await decryptOperatorSecret();
    } catch {
      console.error("[tenant] callback: no operator credential configured");
      return finish(
        request,
        "/dashboard/tenant?error=no_operator_credential",
      );
    }
    const clientId = process.env.AZURE_CLIENT_ID;
    if (!clientId) {
      throw new Error("AZURE_CLIENT_ID is not set");
    }

    // --- 4. App-permission verification (plan 02-13, D-04/D-07) ----------
    // Fail-explicit: mint failures (invalid_client_secret etc.) come back as
    // status "error" and ARE persisted — a bad secret is never silent.
    const requiredRoles = requiredRolesForSections([...CONNECT_SECTIONS]);
    const verification = await verifyAppPermissions({
      tenantId,
      clientId,
      clientSecret,
      requiredRoles,
    });

    let tenantName: string | null = null;
    let primaryDomain: string | null = null;
    try {
      const metadata = await fetchTenantMetadata(tenantId, clientId, clientSecret);
      tenantName = metadata.displayName;
      primaryDomain = metadata.primaryDomain;
    } catch (err) {
      // Metadata is enrichment only — never block the connection itself.
      console.error(
        "[tenant] metadata lookup failed:",
        safeErrorMessage(err),
      );
    }

    // --- 5. D-06 replace-row upsert (delete-before-insert) ---------------
    // better-sqlite3 transactions are synchronous — callback must not be async
    await db.transaction((tx) => {
      // Re-consent (possibly to a DIFFERENT tenant) replaces the row.
      tx.delete(tenantConnections).where(eq(tenantConnections.userId, user.id)).run();
      tx.insert(tenantConnections)
        .values({
          id: crypto.randomUUID(),
          userId: user.id,
          tenantId,
          tenantName,
          primaryDomain,
          // Delegated refresh tokens are retired (D-03); the column keeps its
          // NOT NULL contract with an inert placeholder.
          refreshTokenEnc: APP_ONLY_REFRESH_TOKEN_PLACEHOLDER,
          verificationJson: JSON.stringify(
            toPersistableVerification(verification, requiredRoles),
          ),
          verifiedAt: new Date(),
        })
        .run();
    });

    return finish(request, "/dashboard/tenant");
  } catch (err) {
    console.error(
      "[tenant] callback failed:",
      err instanceof Error ? safeErrorMessage(err) : "unknown error",
    );
    return finish(request, "/dashboard/tenant?error=connect_failed");
  }
}
