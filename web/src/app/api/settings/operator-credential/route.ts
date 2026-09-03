import { NextResponse, type NextRequest } from "next/server";

import { getSession } from "@/lib/auth/session";
import {
  deleteOperatorCredential,
  saveOperatorCredentialIfAbsent,
} from "@/lib/settings/operator-credential";

/**
 * POST /api/settings/operator-credential — first-use claim endpoint (D-01/D-02).
 *
 * Session check FIRST (T-02-04e): only a signed-in account may attempt the
 * claim, and the claim itself is re-checked server-side by
 * saveOperatorCredentialIfAbsent (transactional INSERT-if-absent) — a race
 * between two sign-ins resolves at the DB layer, never in the UI.
 *
 * Outcomes:
 * - 200 {ok:true}                       — caller won the first-use claim
 * - 409 {error:"already_configured"}    — credential exists; silent overwrite
 *                                         is impossible (rotation is an
 *                                         explicit DELETE→POST path, D-05)
 * - 400 {error:"invalid_body"}          — missing/malformed clientSecret
 * - 401 {error:"unauthenticated"}       — no session
 *
 * Logging discipline (T-02-04c): route + outcome only. The secret is never
 * logged and never echoed in any response body.
 */
export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  const { user } = await getSession();
  if (!user) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }
  const { isOperatorAdmin } = await import("@/lib/auth/allowlist");
  if (!isOperatorAdmin(user.email)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "invalid_body" }, { status: 400 });
  }

  const clientSecret =
    typeof body === "object" && body !== null && "clientSecret" in body
      ? (body as { clientSecret?: unknown }).clientSecret
      : undefined;
  if (typeof clientSecret !== "string" || clientSecret.trim().length === 0) {
    return NextResponse.json({ error: "invalid_body" }, { status: 400 });
  }

  const result = await saveOperatorCredentialIfAbsent(
    clientSecret.trim(),
    user.id,
  );
  if (!result.saved && result.reason === "already_configured") {
    return NextResponse.json({ error: "already_configured" }, { status: 409 });
  }
  return NextResponse.json({ ok: true });
}

/**
 * DELETE /api/settings/operator-credential — step one of the guarded rotation
 * flow (D-05): authenticated delete, then an authenticated POST of the new
 * secret re-arms the first-use claim. Silent overwrite via plain POST stays
 * rejected with 409 already_configured.
 *
 * Outcomes:
 * - 200 {ok:true}              — credential removed
 * - 404 {error:"not_configured"} — nothing to delete
 * - 401 {error:"unauthenticated"}
 */
export async function DELETE() {
  const { user } = await getSession();
  if (!user) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }
  const { isOperatorAdmin: isAdminDel } = await import("@/lib/auth/allowlist");
  if (!isAdminDel(user.email)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const deleted = await deleteOperatorCredential();
  if (!deleted) {
    return NextResponse.json({ error: "not_configured" }, { status: 404 });
  }
  return NextResponse.json({ ok: true });
}
