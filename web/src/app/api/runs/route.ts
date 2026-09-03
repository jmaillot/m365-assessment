import { NextResponse, type NextRequest } from "next/server";

import { getSession } from "@/lib/auth/session";
import { getTenantStatus } from "@/lib/tenant/status";
import { hasOperatorCredential } from "@/lib/settings/operator-credential";
import { getCredentialGate } from "@/app/api/tenant/connect-gate";
import { createRunIfAbsent, getActiveRunId } from "@/lib/runs/run-service";
import { startRun } from "@/lib/runs/run-executor";
import { db } from "@/db";

export const dynamic = "force-dynamic";

/**
 * POST /api/runs — create + start an Entra assessment run (ENG-01).
 * Outcomes:
 *   201 { runId }                        — run created, execution kicked off in-process (D-01)
 *   401 { error: "unauthenticated" }
 *   403 { error: "no_tenant" }           — caller has no connected tenant
 *   403 { error: "credential_missing" }  — operator credential not configured
 *   403 { error: "permissions_missing" } — app-permission verification not fully granted (ONB-02)
 *   403 { error: "client_id_missing" }   — AZURE_CLIENT_ID not set in deployment env
 *   409 { error: "run_in_progress", activeRunId } — one-active-run-per-tenant (D-02)
 *   400 { error: "invalid_body" }        — non-empty body rejected (defensive)
 *   500 { error: "start_failed", message } — sanitized reason only
 *
 * Logging discipline: route + outcome only. Never log tokens, secrets, or tenant content.
 */
export const runtime = "nodejs";

/**
 * GET /api/runs — return the active run for the signed-in user, if any.
 * Used by the tenant trigger card to self-correct stale bfcache / router-cache
 * props on back-navigation (S5). Returns { activeRunId: string | null }.
 */
export async function GET() {
  const { user } = await getSession();
  if (!user) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }
  const activeRunId = getActiveRunId(user.id, db);
  return NextResponse.json({ activeRunId: activeRunId ?? null });
}

export async function POST(request: NextRequest) {
  const { user } = await getSession();
  if (!user) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  // Defensive body validation: accept only empty body
  let bodyText = "";
  try {
    bodyText = await request.text();
  } catch {
    bodyText = "";
  }
  if (bodyText.trim().length > 0) {
    return NextResponse.json({ error: "invalid_body" }, { status: 400 });
  }

  // Gate chain — session already verified above
  const status = await getTenantStatus(user.id);
  if (!status.connected || !status.tenant) {
    return NextResponse.json({ error: "no_tenant" }, { status: 403 });
  }

  const hasCredential = await hasOperatorCredential();
  if (!hasCredential) {
    return NextResponse.json({ error: "credential_missing" }, { status: 403 });
  }

  const gate = await getCredentialGate();
  if (gate.gated) {
    return NextResponse.json({ error: "credential_missing" }, { status: 403 });
  }

  // Permission verification fail-closed: only all_granted passes (D-42 consolidated code)
  const verification = status.verification as unknown as { status?: string; missing?: string[]; missingRoles?: string[] } | null;
  if (!verification || verification.status !== "all_granted") {
    return NextResponse.json(
      {
        error: "permissions_missing",
        code: "permissions_missing",
        missing: (verification as unknown as { missing?: string[]; missingRoles?: string[] })?.missing ?? (verification as unknown as { missingRoles?: string[] })?.missingRoles ?? [],
        verification,
      },
      { status: 403 },
    );
  }

  if (!process.env.AZURE_CLIENT_ID) {
    return NextResponse.json({ error: "client_id_missing" }, { status: 403 });
  }

  // One-active-run-per-tenant transactional gate (D-02)
  let createResult: ReturnType<typeof createRunIfAbsent>;
  try {
    createResult = createRunIfAbsent(user.id, status.tenant.id, db);
  } catch {
    return NextResponse.json({ error: "start_failed", message: "could not create run" }, { status: 500 });
  }

  if (!createResult.ok) {
    return NextResponse.json(
      { error: "run_in_progress", activeRunId: createResult.activeRunId },
      { status: 409 },
    );
  }

  const runId = createResult.runId;

  // Fire-and-forget: never awaited by the request (D-01); failures already persisted as failed-run states (D-04)
  void startRun(runId, { database: db }).catch(() => {});

  return NextResponse.json({ runId }, { status: 201 });
}
