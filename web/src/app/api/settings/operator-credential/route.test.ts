import { describe, expect, it, vi, beforeEach, type Mock } from "vitest";
import { NextRequest } from "next/server";

// The route module reads the DB singleton at import time (via the settings
// lib). Point it at an ephemeral in-memory database and provide an
// ENCRYPTION_KEY BEFORE any app module loads (static imports are hoisted;
// app modules are imported dynamically below).
process.env.DATABASE_PATH = ":memory:";
process.env.ENCRYPTION_KEY = "b".repeat(64); // 32 bytes hex

// Session is mocked (cookie machinery is out of scope here) — each test
// controls who is signed in via this mock.
vi.mock("@/lib/auth/session", () => ({
  getSession: vi.fn(),
}));

const { getSession } = await import("@/lib/auth/session");
const { POST, DELETE } = await import("./route");
const { hasOperatorCredential } = await import(
  "@/lib/settings/operator-credential"
);

const SECRET = "route-test-secret-DO-NOT-ECHO-987654321";
const USER_ID = "11111111-2222-3333-4444-555555555555";

// The :memory: DB is a per-file singleton shared by every test in this suite
// — start each test from an empty credential table.
const { db } = await import("@/db");
const { operatorCredential } = await import("@/db/schema");
beforeEach(() => {
  db.delete(operatorCredential).run();
});

function postRequest(body: unknown): NextRequest {
  return new NextRequest("http://localhost:3000/api/settings/operator-credential", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function authenticated() {
  (getSession as Mock).mockResolvedValue({
    user: { id: USER_ID, email: "admin@YOUR-HOST.example", displayName: "Admin" },
  });
}

describe("POST /api/settings/operator-credential", () => {
  it("returns 401 when unauthenticated", async () => {
    (getSession as Mock).mockResolvedValue({ user: null });
    const response = await POST(postRequest({ clientSecret: SECRET }));
    expect(response.status).toBe(401);
  });

  it("stores the secret on first use — response never echoes it", async () => {
    authenticated();
    const response = await POST(postRequest({ clientSecret: SECRET }));
    expect(response.status).toBe(200);

    const payload = await response.text();
    expect(payload).not.toContain(SECRET); // no echo of the secret anywhere
    await expect(hasOperatorCredential()).resolves.toBe(true);
  });

  it("rejects a second claim with 409 already_configured", async () => {
    authenticated();
    const first = await POST(postRequest({ clientSecret: SECRET }));
    expect(first.status).toBe(200);

    const second = await POST(
      postRequest({ clientSecret: "different-secret" }),
    );
    const secondBody = await second.text();
    expect(second.status).toBe(409);
    expect(JSON.parse(secondBody)).toEqual({ error: "already_configured" });
    // No echo of either secret on the rejection path either.
    expect(secondBody).not.toContain("different-secret");
  });

  it("returns 400 when the body field is missing or malformed", async () => {
    authenticated();
    for (const bad of [{}, { clientSecret: "" }, { wrong: true }, null]) {
      const request =
        bad === null
          ? new NextRequest(
              "http://localhost:3000/api/settings/operator-credential",
              { method: "POST", headers: { "content-type": "application/json" }, body: "not-json" },
            )
          : postRequest(bad);
      const response = await POST(request);
      expect(response.status).toBe(400);
    }
    await expect(hasOperatorCredential()).resolves.toBe(false);
  });
});

describe("DELETE /api/settings/operator-credential", () => {
  it("returns 401 when unauthenticated", async () => {
    (getSession as Mock).mockResolvedValue({ user: null });
    const response = await DELETE();
    expect(response.status).toBe(401);
  });

  it("returns 404 not_configured when no credential exists", async () => {
    authenticated();
    const response = await DELETE();
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_configured" });
  });

  it("removes the credential when one exists (wizard re-entry contract)", async () => {
    authenticated();
    expect((await POST(postRequest({ clientSecret: SECRET }))).status).toBe(
      200,
    );

    const response = await DELETE();
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    await expect(hasOperatorCredential()).resolves.toBe(false);
  });
});

describe("rotation flow: authenticated DELETE → authenticated POST", () => {
  it("re-arms the first-use claim after an explicit delete", async () => {
    authenticated();
    expect((await POST(postRequest({ clientSecret: SECRET }))).status).toBe(
      200,
    );
    expect((await DELETE()).status).toBe(200);

    // The plain POST that used to be rejected now succeeds — this is exactly
    // the wizard re-entry path; silent overwrite WITHOUT delete stays a 409.
    const second = await POST(postRequest({ clientSecret: "new-secret" }));
    expect(second.status).toBe(200);
    expect(await second.text()).not.toContain("new-secret");
    await expect(hasOperatorCredential()).resolves.toBe(true);
  });

  it("still rejects silent overwrite when no delete happened between POSTs", async () => {
    authenticated();
    expect((await POST(postRequest({ clientSecret: SECRET }))).status).toBe(
      200,
    );
    const overwrite = await POST(postRequest({ clientSecret: "sneaky" }));
    expect(overwrite.status).toBe(409);
    expect(await overwrite.text()).not.toContain("sneaky");
  });
});
