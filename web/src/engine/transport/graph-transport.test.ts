import { describe, expect, it, vi } from "vitest";
import {
  GraphTransport,
  TransportFatalError,
  type GraphCallEvent,
  type GraphResponse,
} from "./graph-transport";

/**
 * All behaviors proven with an injected fetchImpl backed by inline fixture
 * objects keyed by URL — no network (D-21 recorded-replay readiness).
 */

interface FakeResponse {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): FakeResponse {
  const lowered = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => lowered[name.toLowerCase()] ?? null },
    json: async () => body,
  };
}

const TOKEN = "test-app-token";

/** Minimal deps with recording fetch + instant injected delay. */
function makeTransport(options?: {
  fetchImpl?: typeof fetch;
  isRoleGranted?: (role: string) => boolean;
  maxPages?: number;
  maxRetries?: number;
}) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const delaysMs: number[] = [];
  const warnings: string[] = [];
  const events: GraphCallEvent[] = [];

  const fetchImpl =
    options?.fetchImpl ??
    (vi.fn(async () => jsonResponse(200, { value: [] })) as unknown as typeof fetch);

  const transport = new GraphTransport({
    getToken: async () => TOKEN,
    fetchImpl,
    onPage: (e) => events.push(e),
    onWarning: (w) => warnings.push(w),
    isRoleGranted: options?.isRoleGranted ?? (() => true),
    maxRetries: options?.maxRetries,
    maxPages: options?.maxPages,
    delayFn: async (ms) => {
      delaysMs.push(ms);
    },
  });

  return {
    transport,
    fetchMock: fetchImpl as unknown as ReturnType<typeof vi.fn>,
    calls,
    delaysMs,
    warnings,
    events,
  };
}

/** Wrap the fetch mock so every invocation is recorded with its init. */
function recordingFetch(
  handler: (url: string, init?: RequestInit) => Promise<FakeResponse>,
): { impl: typeof fetch; mock: ReturnType<typeof vi.fn> } {
  const inner = vi.fn(async (url: string | URL | Request, init?: RequestInit) =>
    handler(String(url), init),
  );
  return { impl: inner as unknown as typeof fetch, mock: inner };
}

describe("GraphTransport.getJson", () => {
  it("GETs a single-page endpoint and returns its merged value[]", async () => {
    const { impl, mock } = recordingFetch(() =>
      Promise.resolve(jsonResponse(200, { value: [{ id: "u1" }, { id: "u2" }] })),
    );
    const t = makeTransport({ fetchImpl: impl });

    const res = await t.transport.getJson("/v1.0/users");

    expect(res.value).toEqual([{ id: "u1" }, { id: "u2" }]);
    expect(mock).toHaveBeenCalledTimes(1);
    expect(mock.mock.calls[0]?.[0]).toBe("https://graph.microsoft.com/v1.0/users");
  });

  it("follows @odata.nextLink across pages, merging value[] and keeping first-page metadata", async () => {
    const { impl, mock } = recordingFetch((url) => {
      if (url.endsWith("/v1.0/users")) {
        return Promise.resolve(
          jsonResponse(200, {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
            value: [{ id: "p1-a" }, { id: "p1-b" }],
            "@odata.nextLink":
              "https://graph.microsoft.com/v1.0/users?$skiptoken=abc",
          }),
        );
      }
      return Promise.resolve(
        jsonResponse(200, { value: [{ id: "p2-a" }] }),
      );
    });
    const t = makeTransport({ fetchImpl: impl });

    const res: GraphResponse = await t.transport.getJson("/v1.0/users");

    expect(res.value).toEqual([
      { id: "p1-a" },
      { id: "p1-b" },
      { id: "p2-a" },
    ]);
    // First-page metadata keys survive the merge (PS response-rebuild parity).
    expect(res["@odata.context"]).toBe(
      "https://graph.microsoft.com/v1.0/$metadata#users",
    );
    // The consumed nextLink must not leak into the rebuilt response.
    expect(res["@odata.nextLink"]).toBeUndefined();
    expect(mock).toHaveBeenCalledTimes(2);
  });

  it("fatally rejects cross-host absolute nextLinks without fetching them (SSRF guard)", async () => {
    const { impl, mock } = recordingFetch(() =>
      Promise.resolve(
        jsonResponse(200, {
          value: [{ id: "x" }],
          "@odata.nextLink": "https://evil.example.com/v1.0/users?$skiptoken=1",
        }),
      ),
    );
    const t = makeTransport({ fetchImpl: impl });

    await expect(t.transport.getJson("/v1.0/users")).rejects.toThrow(
      TransportFatalError,
    );

    // Exactly one fetch happened: the legitimate first page. The hostile
    // nextLink was never requested.
    expect(mock).toHaveBeenCalledTimes(1);
  });

  it("follows absolute nextLinks pinned to graph.microsoft.com", async () => {
    const { impl, mock } = recordingFetch((url) => {
      if (url.endsWith("/v1.0/users")) {
        return Promise.resolve(
          jsonResponse(200, {
            value: [{ id: "p1" }],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=2",
          }),
        );
      }
      return Promise.resolve(jsonResponse(200, { value: [{ id: "p2" }] }));
    });
    const t = makeTransport({ fetchImpl: impl });

    const res = await t.transport.getJson("/v1.0/users");
    expect(res.value).toEqual([{ id: "p1" }, { id: "p2" }]);
    expect(mock).toHaveBeenCalledTimes(2);
  });

  it("throws when the input path does not start with '/'", async () => {
    const { impl, mock } = recordingFetch(() =>
      Promise.resolve(jsonResponse(200, { value: [] })),
    );
    const t = makeTransport({ fetchImpl: impl });

    await expect(t.transport.getJson("v1.0/users")).rejects.toThrow(
      TransportFatalError,
    );
    expect(mock).not.toHaveBeenCalled();
  });

  it("fatally rejects non-GET methods BEFORE any fetch and emits no events (D-24)", async () => {
    const { impl, mock } = recordingFetch(() =>
      Promise.resolve(jsonResponse(200, { value: [] })),
    );
    const t = makeTransport({ fetchImpl: impl });

    await expect(
      t.transport.getJson("/v1.0/users", { method: "POST" as never }),
    ).rejects.toThrow(TransportFatalError);

    await expect(
      t.transport.getJson("/v1.0/users", { method: "DELETE" as never }),
    ).rejects.toThrow(TransportFatalError);

    expect(mock).not.toHaveBeenCalled();
    expect(t.events).toHaveLength(0);
  });

  it("refuses dispatch pre-fetch when the declared requiredRole is not granted (D-26)", async () => {
    const { impl, mock } = recordingFetch(() =>
      Promise.resolve(jsonResponse(200, { value: [] })),
    );
    const t = makeTransport({
      fetchImpl: impl,
      isRoleGranted: (role) => role !== "Policy.Read.All",
    });

    await expect(
      t.transport.getJson("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", {
        requiredRole: "Policy.Read.All",
      }),
    ).rejects.toThrow(/Policy\.Read\.All/);

    expect(mock).not.toHaveBeenCalled();
    expect(t.events).toHaveLength(0);
  });

  it("retries a 429 once via retryDelaySeconds, emitting an event per attempt and honoring the injected delay", async () => {
    let call = 0;
    const { impl, mock } = recordingFetch(() => {
      call += 1;
      if (call === 1) return Promise.resolve(jsonResponse(429, { error: "throttled" }));
      return Promise.resolve(jsonResponse(200, { value: [{ id: "ok" }] }));
    });
    const t = makeTransport({ fetchImpl: impl });

    const res = await t.transport.getJson("/v1.0/users");

    expect(res.value).toEqual([{ id: "ok" }]);
    // First transient failure: exponential backoff attempt 1 → min(2^1,60)s.
    expect(t.delaysMs).toEqual([2000]);
    expect(mock).toHaveBeenCalledTimes(2);
    expect(t.events.map((e) => e.status)).toEqual([429, 200]);
    expect(t.events.every((e) => e.method === "GET")).toBe(true);
  });

  it("honors the Retry-After header over pure backoff when present", async () => {
    let call = 0;
    const { impl } = recordingFetch(() => {
      call += 1;
      if (call === 1) {
        return Promise.resolve(
          jsonResponse(429, { error: "throttled" }, { "Retry-After": "30" }),
        );
      }
      return Promise.resolve(jsonResponse(200, { value: [] }));
    });
    const t = makeTransport({ fetchImpl: impl });

    await t.transport.getJson("/v1.0/users");

    // ceil(30)+1 = 31 seconds, per Get-GraphRetryDelay parity.
    expect(t.delaysMs).toEqual([31000]);
  });

  it("throws immediately on 404 with no retry", async () => {
    const { impl, mock } = recordingFetch(() =>
      Promise.resolve(jsonResponse(404, { error: { code: "NotFound" } })),
    );
    const t = makeTransport({ fetchImpl: impl });

    await expect(t.transport.getJson("/v1.0/users/missing")).rejects.toThrow();

    expect(mock).toHaveBeenCalledTimes(1);
    expect(t.delaysMs).toHaveLength(0);
    expect(t.events.map((e) => e.status)).toEqual([404]);
  });

  it("surfaces a GraphError carrying the final status after exhausting retries", async () => {
    const { impl } = recordingFetch(() =>
      Promise.resolve(jsonResponse(503, { error: "unavailable" })),
    );
    const t = makeTransport({ fetchImpl: impl, maxRetries: 2 });

    await expect(t.transport.getJson("/v1.0/users")).rejects.toThrow(
      expect.objectContaining({ status: 503 }),
    );
    // Initial call + 2 retries.
    expect(t.fetchMock).toHaveBeenCalledTimes(3);
    expect(t.events.map((e) => e.status)).toEqual([503, 503, 503]);
  });

  it("stops at the page cap, returning the merged pages WITH a loud truncation warning", async () => {
    let skip = 0;
    const { impl, mock } = recordingFetch(() => {
      skip += 1;
      const body: Record<string, unknown> = { value: [{ id: `page-${skip}` }] };
      if (skip < 3) {
        body["@odata.nextLink"] = `https://graph.microsoft.com/v1.0/users?page=${skip + 1}`;
      }
      return Promise.resolve(jsonResponse(200, body));
    });
    const t = makeTransport({ fetchImpl: impl, maxPages: 2 });

    const res = await t.transport.getJson("/v1.0/users");

    // First two pages merged, third never fetched.
    expect(res.value).toEqual([{ id: "page-1" }, { id: "page-2" }]);
    expect(mock).toHaveBeenCalledTimes(2);
    // Truncation is NEVER silent (the #952 lesson).
    expect(t.warnings).toHaveLength(1);
    expect(t.warnings[0]).toMatch(/cap|incomplete|truncat/i);
  });

  it("forwards extra headers verbatim alongside the bearer Authorization header", async () => {
    const { impl, mock } = recordingFetch(() =>
      Promise.resolve(jsonResponse(200, { value: [] })),
    );
    const t = makeTransport({ fetchImpl: impl });

    await t.transport.getJson("/v1.0/users?$count=true", {
      headers: { ConsistencyLevel: "eventual" },
    });

    const init = mock.mock.calls[0]?.[1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers.ConsistencyLevel).toBe("eventual");
    expect(headers.Authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("returns scalar JSON bodies (Graph $count endpoints) as-is without pagination", async () => {
    const { impl } = recordingFetch(() =>
      Promise.resolve(jsonResponse(200, 42)),
    );
    const t = makeTransport({ fetchImpl: impl });

    const result = await t.transport.getJson(
      "/v1.0/users/$count?$filter=userType eq 'Guest'",
    );
    expect(result).toBe(42);
  });

  it("emits a null-status event for network failures and surfaces the transport error", async () => {
    const { impl } = recordingFetch(() =>
      Promise.reject(new TypeError("fetch failed")),
    );
    const t = makeTransport({ fetchImpl: impl, maxRetries: 1 });

    await expect(t.transport.getJson("/v1.0/users")).rejects.toThrow();

    expect(t.events).toEqual([
      { method: "GET", url: "https://graph.microsoft.com/v1.0/users", status: null },
      { method: "GET", url: "https://graph.microsoft.com/v1.0/users", status: null },
    ]);
    expect(t.delaysMs).toEqual([2000]);
  });
});
