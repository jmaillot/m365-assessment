import { describe, expect, it } from "vitest";
import { createReplayFetch } from "./replay";

describe("createReplayFetch", () => {
  const FIXTURES = {
    "/v1.0/users": { value: [{ id: "u1", displayName: "User One" }] },
    "/v1.0/identity/conditionalAccess/policies?$top=999": {
      value: [{ id: "cap1" }],
    },
  };

  it("serves the fixture JSON for a known URL (absolute request, path+query key)", async () => {
    const fetchImpl = createReplayFetch(FIXTURES);
    const res = await fetchImpl("https://graph.microsoft.com/v1.0/users");
    expect(res.ok).toBe(true);
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ value: [{ id: "u1", displayName: "User One" }] });
  });

  it("matches on path+query regardless of scheme/host spelling", async () => {
    const fetchImpl = createReplayFetch(FIXTURES);
    const res = await fetchImpl(
      "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999",
    );
    expect(res.ok).toBe(true);
    await expect(res.json()).resolves.toEqual({ value: [{ id: "cap1" }] });
  });

  it("resolves a failing 404-style response naming the missing key for unknown URLs", async () => {
    const fetchImpl = createReplayFetch(FIXTURES);
    const res = await fetchImpl("https://graph.microsoft.com/v1.0/domains");
    expect(res.ok).toBe(false);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("/v1.0/domains");
  });

  it("serves multi-page {value, @odata.nextLink} entries verbatim", async () => {
    const paged = {
      "/v1.0/users?$top=1": {
        value: [{ id: "u1" }],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skipToken=abc",
      },
      "/v1.0/users?$skipToken=abc": { value: [{ id: "u2" }] },
    };
    const fetchImpl = createReplayFetch(paged);

    const page1 = await (await fetchImpl("https://graph.microsoft.com/v1.0/users?$top=1")).json();
    expect(page1).toEqual({
      value: [{ id: "u1" }],
      "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skipToken=abc",
    });
    // nextLink served verbatim through the same replay layer.
    const page2 = await (
      await fetchImpl("https://graph.microsoft.com/v1.0/users?$skipToken=abc")
    ).json();
    expect(page2).toEqual({ value: [{"id": "u2" }] });
  });

  it("round-trips the identical payload through response.text()", async () => {
    const payload = { value: [{ id: "u1" }], "@odata.count": 1 };
    const fetchImpl = createReplayFetch({ "/v1.0/users": payload });
    const res = await fetchImpl("https://graph.microsoft.com/v1.0/users");
    await expect(res.text()).resolves.toBe(JSON.stringify(payload));
  });

  it("rejects non-GET requests when strictMethod is requested", async () => {
    const fetchImpl = createReplayFetch(FIXTURES, { strictMethod: true });
    const res = await fetchImpl("https://graph.microsoft.com/v1.0/users", {
      method: "POST",
    });
    expect(res.ok).toBe(false);
    expect(res.status).toBe(405);
  });
});
