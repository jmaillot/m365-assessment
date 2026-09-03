import { NextResponse, type NextRequest } from "next/server";

import { requiredRolesForSections } from "@/engine/registry/permissions";
import { appBaseUrl } from "@/lib/auth/entra-client";
import {
  CONNECT_STATE_COOKIE,
  CONNECT_STATE_MAX_AGE_SECONDS,
  connectStateCookieOptions,
  createConnectState,
} from "@/lib/auth/connect-state";
import { getSession } from "@/lib/auth/session";

/**
 * GET /api/tenant/connect — start the tenant connect flow (D-05, D-03).
 *
 * Full-page redirect to Microsoft's **adminconsent** endpoint: the flow now
 * requests APPLICATION permissions (app roles) instead of delegated scopes.
 * The adminconsent screen presents the app registration's configured app
 * roles statically — it accepts no dynamic permission input — so the
 * authoritative request set is the SECTION_REGISTRY-derived role union below,
 * which MUST be configured on the app registration exactly as listed in
 * docs/web/APP-REGISTRATION-SETUP.md. Post-consent, the callback verifies the
 * granted roles with verifyAppPermissions (plan 02-13) rather than redeeming
 * a code — the adminconsent redirect carries only `tenant` + `admin_consent`.
 *
 * The state nonce is HMAC-signed into a short-lived httpOnly cookie bound to
 * the session userId (T-04-01). Re-consent is always allowed: the callback
 * replaces the stored connection row, enforcing one account : one tenant even
 * when switching tenants (D-06).
 *
 * NOTE for deployment: `{APP_BASE_URL}/api/tenant/callback` must be registered
 * as a Web redirect URI on the app registration.
 */
export const runtime = "nodejs";

const ADMIN_CONSENT_ENDPOINT =
  "https://login.microsoftonline.com/organizations/adminconsent";

// T-02-04d / D-03/D-21: single source of truth for the consented application
// permissions = the registry-derived app-role union for the ported sections.
// First-seen order, case-insensitively deduped:
//   Organization.Read.All, Domain.Read.All, Policy.Read.All, User.Read.All,
//   Group.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All,
//   RoleManagement.Read.Directory, Application.Read.All, Directory.Read.All,
//   Agreement.Read.All, SecurityEvents.Read.All, ThreatIntelligence.Read.All,
//   DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
//   DeviceManagementServiceConfig.Read.All
const CONNECT_SECTIONS = ["tenant", "identity", "licensing", "security", "intune", "exchange", "collaboration"] as const;
const REQUIRED_APP_ROLES = requiredRolesForSections([...CONNECT_SECTIONS]);

// Fail fast if the table is ever emptied or loses a baseline role — an empty
// or probe-incompatible consent would silently produce an unverifiable
// connection (verifyAppPermissions probes Policy/User/Organization/Application).
if (
  REQUIRED_APP_ROLES.length === 0 ||
  !REQUIRED_APP_ROLES.includes("Policy.Read.All") ||
  !REQUIRED_APP_ROLES.includes("RoleManagement.Read.Directory")
) {
  throw new Error(
    "registry-derived app-role union for the connect flow is missing baseline application permissions",
  );
}

export async function GET(request: NextRequest) {
  const { user } = await getSession();
  if (!user) {
    // Session ended mid-flow — back to sign-in (hardcoded literal, T-03-07).
    return NextResponse.redirect(new URL("/", appBaseUrl()));
  }

  try {
    const { state, cookieValue } = createConnectState(user.id);
    const clientId = process.env.AZURE_CLIENT_ID;
    if (!clientId) {
      throw new Error("AZURE_CLIENT_ID is not set");
    }

    // Application permissions cannot be passed as dynamic scope input; the
    // REQUIRED_APP_ROLES union above documents and validates what the consent
    // screen presents (configured statically on the app registration).
    const consentUrl =
      `${ADMIN_CONSENT_ENDPOINT}` +
      `?client_id=${encodeURIComponent(clientId)}` +
      `&redirect_uri=${encodeURIComponent(`${appBaseUrl()}/api/tenant/callback`)}` +
      `&state=${encodeURIComponent(state)}`;

    const response = NextResponse.redirect(consentUrl);
    response.cookies.set({
      name: CONNECT_STATE_COOKIE,
      value: cookieValue,
      ...connectStateCookieOptions(CONNECT_STATE_MAX_AGE_SECONDS),
    });
    return response;
  } catch (err) {
    // Route + outcome only — never secrets or tokens.
    console.error(
      "[tenant] connect failed:",
      err instanceof Error ? err.message.split("\n")[0] : "unknown error",
    );
    void request;
    return NextResponse.redirect(new URL("/dashboard", appBaseUrl()));
  }
}
