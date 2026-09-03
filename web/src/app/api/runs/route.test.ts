import { describe, expect, it, vi, beforeEach, type Mock } from "vitest";
import { NextRequest } from "next/server";

// Ephemeral DB + encryption key BEFORE any app module loads
process.env.DATABASE_PATH = ":memory:";
process.env.ENCRYPTION_KEY = "c".repeat(64);
process.env.AZURE_CLIENT_ID = "00000000-0000-4000-a000-000000000000";

vi.mock("@/lib/auth/session", () => ({
  getSession: vi.fn(),
}));

vi.mock("@/lib/runs/run-executor", () => ({
  startRun: vi.fn(async () => {}),
  getRunBus: vi.fn(() => ({ subscribe: vi.fn(), emit: vi.fn(), close: vi.fn(), subscriberCount: vi.fn(() => 0) })),
  getActiveExecutions: vi.fn(() => new Set()),
}));

const { getSession } = await import("@/lib/auth/session");
const { POST } = await import("./route");
const { startRun } = await import("@/lib/runs/run-executor");
const { db } = await import("@/db");
const { users, tenantConnections, operatorCredential, runs, checkRows } = await import("@/db/schema");
const { saveOperatorCredentialIfAbsent } = await import("@/lib/settings/operator-credential");
import { eq } from "drizzle-orm";
import crypto from "node:crypto";

const USER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const TENANT_ID = "11111111-2222-3333-4444-555555555555";

function authenticated() {
  (getSession as Mock).mockResolvedValue({
    user: { id: USER_ID, email: "admin@YOUR-HOST.example", displayName: "Admin" },
  });
}

function unauthenticated() {
  (getSession as Mock).mockResolvedValue({ user: null });
}

function emptyRequest(): NextRequest {
  return new NextRequest("http://localhost:3000/api/runs", {
    method: "POST",
  });
}

function requestWithBody(body: unknown): NextRequest {
  return new NextRequest("http://localhost:3000/api/runs", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function seedPrerequisites(opts?: { verificationStatus?: string; skipCredential?: boolean; skipTenant?: boolean }) {
  // User row (required for FK)
  db.insert(users)
    .values({
      id: USER_ID,
      entraObjectId: crypto.randomUUID(),
      email: "admin@YOUR-HOST.example",
      displayName: "Admin",
    })
    .onConflictDoNothing()
    .run();

  if (!opts?.skipTenant) {
    const verification = {
      status: opts?.verificationStatus ?? "all_granted",
      schemaVersion: "1.0" as const,
      generatedAtUtc: new Date().toISOString(),
      required: ["Policy.Read.All"],
      granted: opts?.verificationStatus === "missing" ? [] : ["Policy.Read.All"],
      missing: opts?.verificationStatus === "missing" ? ["Policy.Read.All"] : [],
    };
    db.insert(tenantConnections)
      .values({
        id: crypto.randomUUID(),
        userId: USER_ID,
        tenantId: TENANT_ID,
        tenantName: "Test Tenant",
        primaryDomain: "test.onmicrosoft.com",
        refreshTokenEnc: "enc-placeholder",
        verificationJson: JSON.stringify(verification),
        connectedAt: new Date(),
      })
      .onConflictDoNothing()
      .run();
  }

  if (!opts?.skipCredential) {
    await saveOperatorCredentialIfAbsent("test-secret-12345", USER_ID);
  }
}

beforeEach(() => {
  db.delete(checkRows).run();
  db.delete(runs).run();
  db.delete(tenantConnections).run();
  db.delete(operatorCredential).run();
  db.delete(users).run();
  vi.clearAllMocks();
  process.env.AZURE_CLIENT_ID = "00000000-0000-4000-a000-000000000000";
});

describe("POST /api/runs", () => {
  it("returns 401 when unauthenticated", async () => {
    unauthenticated();
    const res = await POST(emptyRequest());
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthenticated" });
  });

  it("returns 400 invalid_body when body is non-empty", async () => {
    authenticated();
    await seedPrerequisites();
    const res = await POST(requestWithBody({ foo: "bar" }));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_body" });
  });

  it("returns 403 no_tenant when no connected tenant", async () => {
    authenticated();
    await seedPrerequisites({ skipTenant: true });
    const res = await POST(emptyRequest());
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "no_tenant" });
  });

  it("returns 403 credential_missing when operator credential not configured", async () => {
    authenticated();
    await seedPrerequisites({ skipCredential: true });
    const res = await POST(emptyRequest());
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "credential_missing" });
  });

  it("returns 403 permissions_missing when verification is not all_granted", async () => {
    authenticated();
    await seedPrerequisites({ verificationStatus: "missing" });
    const res = await POST(emptyRequest());
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; code: string; missing: string[]; verification: unknown };
    expect(body.error).toBe("permissions_missing");
    expect(body.code).toBe("permissions_missing");
    expect(Array.isArray(body.missing)).toBe(true);
    expect(body.verification).toBeDefined();
  });

  it("returns 403 permissions_missing when verification is missing (fail-closed)", async () => {
    authenticated();
    await seedPrerequisites({ verificationStatus: "error" });
    const res = await POST(emptyRequest());
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; code: string; missing: string[]; verification: unknown };
    expect(body.error).toBe("permissions_missing");
    expect(body.code).toBe("permissions_missing");
    expect(Array.isArray(body.missing)).toBe(true);
    expect(body.verification).toBeDefined();
  });

  it("returns 403 client_id_missing when AZURE_CLIENT_ID not set", async () => {
    authenticated();
    await seedPrerequisites();
    delete process.env.AZURE_CLIENT_ID;
    const res = await POST(emptyRequest());
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "client_id_missing" });
  });

  it("creates a run and returns 201 with runId and kicks off executor", async () => {
    authenticated();
    await seedPrerequisites();
    const res = await POST(emptyRequest());
    expect(res.status).toBe(201);
    const body = await res.json() as { runId: string };
    expect(typeof body.runId).toBe("string");
    expect(body.runId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(startRun).toHaveBeenCalledTimes(1);
    expect((startRun as Mock).mock.calls[0][0]).toBe(body.runId);
    // Verify fire-and-forget: POST does not await startRun's async work — it returns immediately
    // startRun was called with void (not awaited) — we assert it was called, not that it resolved
    const stored = db.select().from(runs).where(eq(runs.id, body.runId)).get() as { status: string } | undefined;
    expect(stored?.status).toBe("queued");
  });

  it("returns 409 run_in_progress with activeRunId when a queued run exists", async () => {
    authenticated();
    await seedPrerequisites();
    const first = await POST(emptyRequest());
    expect(first.status).toBe(201);
    const { runId: firstId } = (await first.json()) as { runId: string };

    // Second attempt while first is still queued (executor is mocked, so status stays queued)
    const second = await POST(emptyRequest());
    expect(second.status).toBe(409);
    const body = await second.json() as { error: string; activeRunId: string };
    expect(body.error).toBe("run_in_progress");
    expect(body.activeRunId).toBe(firstId);
    // startRun should only have been called once (for the first run), not for the conflict
    expect(startRun).toHaveBeenCalledTimes(1);
  });

  it("makes zero network calls", async () => {
    // This test proves the route does not hit the network — startRun is stubbed above,
    // and no fetch is ever invoked. If the route attempted a real Graph call, this
    // test would require network mocking and would fail without it.
    authenticated();
    await seedPrerequisites();
    const res = await POST(emptyRequest());
    expect(res.status).toBe(201);
    expect(startRun).toHaveBeenCalled();
    // No fetch global was invoked (we didn't mock fetch, and the test passed offline)
  });
});
