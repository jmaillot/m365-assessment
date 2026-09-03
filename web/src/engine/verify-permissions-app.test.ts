import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for engine app-only permission verification (D-04).
 * openid-client is fully mocked and every probe runs through an injected
 * fetchImpl returning canned statuses — no test performs network I/O.
 */

const grantMock = vi.hoisted(() => vi.fn());
const discoverMock = vi.hoisted(() => vi.fn());

vi.mock("openid-client", () => ({
  Issuer: { discover: discoverMock },
}));

function issuerStub() {
  return {
    Client: class {
      grant = grantMock;
    },
  };
}

/** Valid GUID-shaped tenant id (graph-auth gates non-GUIDs fatally). */
const TENANT_ID = "11111111-2222-3333-4444-555555555555";

/** Build a real-shaped JWT (unsigned — decode-only discipline, like Phase 1). */
function makeJwt(payload: object): string {
  const encode = (o: object) =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  return `header.${encode(payload)}.signature`;
}

function epochSecondsIn(seconds: number): number {
  return Math.floor(Date.now() / 1000) + seconds;
}

type FetchCall = { url: string; init?: RequestInit };

/** fetchImpl stub returning a fixed status for every call, recording calls. */
function fetchStub(
  status: number,
): ReturnType<typeof vi.fn> & { calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const fn = Object.assign(
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response(null, { status });
    }),
    { calls },
  );
  return fn as unknown as ReturnType<typeof vi.fn> & { calls: FetchCall[] };
}

/** fetchImpl stub that always throws (network failure). */
function fetchThrows(err: unknown) {
  return vi.fn(async () => {
    throw err;
  });
}

const REQUIRED = [
  "Organization.Read.All",
  "Policy.Read.All",
  "User.Read.All",
  "Application.Read.All",
];

beforeEach(() => {
  vi.resetModules();
  discoverMock.mockReset();
  grantMock.mockReset();
  discoverMock.mockResolvedValue(issuerStub());
});

describe("verifyAppPermissions", () => {
  it("reports missing when the token lacks a required role (case-insensitive diff)", async () => {
    grantMock.mockResolvedValue({
      access_token: makeJwt({
        roles: ["User.Read.All", "Directory.Read.All"],
      }),
      expires_at: epochSecondsIn(3600),
    });
    const { verifyAppPermissions } = await import("./verify-permissions-app");
    const fetchImpl = fetchStub(200);

    const result = await verifyAppPermissions({
      tenantId: TENANT_ID,
      clientId: "client-id",
      clientSecret: "client-secret",
      requiredRoles: REQUIRED,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.status).toBe("missing");
    expect(result.missingRoles).toContain("Policy.Read.All");
    // Case-insensitive compare: User.Read.All IS granted.
    expect(result.missingRoles).not.toContain("User.Read.All");
  });

  it("treats differently-cased but equivalent roles as granted", async () => {
    grantMock.mockResolvedValue({
      access_token: makeJwt({
        roles: [
          "organization.read.all",
          "policy.read.all",
          "user.read.all",
          "application.read.all",
        ],
      }),
      expires_at: epochSecondsIn(3600),
    });
    const { verifyAppPermissions } = await import("./verify-permissions-app");

    const result = await verifyAppPermissions({
      tenantId: TENANT_ID,
      clientId: "client-id",
      clientSecret: "client-secret",
      requiredRoles: REQUIRED,
      fetchImpl: fetchStub(200) as unknown as typeof fetch,
    });

    expect(result.status).toBe("all_granted");
    expect(result.missingRoles).toEqual([]);
  });

  it("returns all_granted with four passing probes when everything checks out", async () => {
    grantMock.mockResolvedValue({
      access_token: makeJwt({ roles: REQUIRED }),
      expires_at: epochSecondsIn(3600),
    });
    const { verifyAppPermissions } = await import("./verify-permissions-app");
    const fetchImpl = fetchStub(200);

    const result = await verifyAppPermissions({
      tenantId: TENANT_ID,
      clientId: "client-id",
      clientSecret: "client-secret",
      requiredRoles: REQUIRED,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.status).toBe("all_granted");
    expect(result.rolesFromToken).toEqual(REQUIRED);
    expect(result.missingRoles).toEqual([]);
    expect(result.probes).toHaveLength(4);
    expect(result.probes.every((p) => p.granted === true)).toBe(true);

    // One cheap GET per area (D-04), bearer-token authenticated.
    const byArea = new Map(result.probes.map((p) => [p.area, p]));
    expect(byArea.get("organization")?.endpoint).toBe("/v1.0/organization");
    expect(byArea.get("identitySecurityDefaults")?.endpoint).toBe(
      "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
    );
    expect(byArea.get("users")?.endpoint).toBe("/v1.0/users?$top=1");
    expect(byArea.get("servicePrincipals")?.endpoint).toBe(
      "/v1.0/servicePrincipals?$top=1",
    );
    expect(byArea.get("users")?.requiredRole).toBe("User.Read.All");
    expect(byArea.get("servicePrincipals")?.requiredRole).toBe(
      "Application.Read.All",
    );
    expect(fetchImpl.calls).toHaveLength(4);
    expect(fetchImpl.calls[0]?.init?.headers).toMatchObject({
      Authorization: `Bearer ${makeJwt({ roles: REQUIRED })}`,
    });
    // Never follow pagination here.
    expect(fetchImpl.calls.every((c) => !c.url.includes("$skip"))).toBe(true);
  });

  it("maps a 403 probe to granted:false and overall missing", async () => {
    grantMock.mockResolvedValue({
      access_token: makeJwt({ roles: REQUIRED }),
      expires_at: epochSecondsIn(3600),
    });
    const { verifyAppPermissions } = await import("./verify-permissions-app");
    const calls: FetchCall[] = [];
    const fetchImpl = Object.assign(
      vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        const status = String(url).includes("identitySecurityDefaults")
          ? 403
          : 200;
        return new Response(null, { status });
      }),
      { calls },
    );

    const result = await verifyAppPermissions({
      tenantId: TENANT_ID,
      clientId: "client-id",
      clientSecret: "client-secret",
      requiredRoles: REQUIRED,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.status).toBe("missing");
    const defaultsProbe = result.probes.find(
      (p) => p.area === "identitySecurityDefaults",
    );
    expect(defaultsProbe?.granted).toBe(false);
    expect(
      result.probes.filter((p) => p.granted === true).map((p) => p.area),
    ).toEqual(["organization", "users", "servicePrincipals"]);
    expect(result.missingRoles).toEqual([]);
  });

  it("maps a probe network failure to granted:null and overall error", async () => {
    grantMock.mockResolvedValue({
      access_token: makeJwt({ roles: REQUIRED }),
      expires_at: epochSecondsIn(3600),
    });
    const { verifyAppPermissions } = await import("./verify-permissions-app");
    let callCount = 0;
    const fetchImpl = vi.fn(async (url: string | URL | Request) => {
      callCount += 1;
      if (String(url).includes("/v1.0/users")) {
        throw new TypeError("fetch failed: ECONNRESET");
      }
      return new Response(null, { status: 200 });
    });

    const result = await verifyAppPermissions({
      tenantId: TENANT_ID,
      clientId: "client-id",
      clientSecret: "client-secret",
      requiredRoles: REQUIRED,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(callCount).toBe(4); // a failed probe does not abort the others
    const usersProbe = result.probes.find((p) => p.area === "users");
    expect(usersProbe?.granted).toBeNull();
    expect(result.status).toBe("error"); // explicit could-not-verify, never silent
    expect(result.errorMessage).toBeTruthy();
  });

  it("surfaces mint failure as status:error with a safe message", async () => {
    grantMock.mockRejectedValue(new Error("token endpoint unreachable"));
    const { verifyAppPermissions } = await import("./verify-permissions-app");

    const result = await verifyAppPermissions({
      tenantId: TENANT_ID,
      clientId: "client-id",
      clientSecret: "client-secret",
      requiredRoles: REQUIRED,
      fetchImpl: fetchStub(200) as unknown as typeof fetch,
    });

    expect(result.status).toBe("error");
    expect(result.errorMessage).toBe("token endpoint unreachable");
    expect(result.rolesFromToken).toEqual([]);
    expect(result.probes).toEqual([]);
  });

  it("surfaces a malformed token (getGrantedRoles throw) as status:error", async () => {
    grantMock.mockResolvedValue({
      access_token: "not-a-jwt",
      expires_at: epochSecondsIn(3600),
    });
    const { verifyAppPermissions } = await import("./verify-permissions-app");

    const result = await verifyAppPermissions({
      tenantId: TENANT_ID,
      clientId: "client-id",
      clientSecret: "client-secret",
      requiredRoles: REQUIRED,
      fetchImpl: fetchStub(200) as unknown as typeof fetch,
    });

    expect(result.status).toBe("error");
    expect(result.errorMessage).toMatch(/malformed access token/i);
  });

  it("defaults fetchImpl to global fetch (smoke: callable without injection)", async () => {
    grantMock.mockResolvedValue({
      access_token: makeJwt({ roles: REQUIRED }),
      expires_at: epochSecondsIn(3600),
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 200 }));

    try {
      const { verifyAppPermissions } = await import("./verify-permissions-app");
      const result = await verifyAppPermissions({
        tenantId: TENANT_ID,
        clientId: "client-id",
        clientSecret: "client-secret",
        requiredRoles: REQUIRED,
      });
      expect(result.status).toBe("all_granted");
      expect(fetchSpy).toHaveBeenCalledTimes(4);
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
