import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for engine app-only auth (D-01). openid-client is fully mocked —
 * no test performs network I/O against login.microsoftonline.com.
 */

const grantMock = vi.hoisted(() => vi.fn());
const clientOptionsMock = vi.hoisted(() => vi.fn());
const discoverMock = vi.hoisted(() => vi.fn());

vi.mock("openid-client", () => ({
  Issuer: { discover: discoverMock },
}));

function issuerStub() {
  return {
    Client: class {
      constructor(options: unknown) {
        clientOptionsMock(options);
      }
      grant = grantMock;
    },
  };
}

/** Valid GUID-shaped tenant id (threat T-02-02e requires GUID gating). */
const TENANT_ID = "11111111-2222-3333-4444-555555555555";

function epochSecondsIn(seconds: number): number {
  return Math.floor(Date.now() / 1000) + seconds;
}

/** Build a real-shaped JWT (unsigned — decode-only discipline, like Phase 1). */
function makeJwt(payload: object): string {
  const encode = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `header.${encode(payload)}.signature`;
}

beforeEach(() => {
  vi.resetModules();
  discoverMock.mockReset();
  clientOptionsMock.mockReset();
  grantMock.mockReset();
  discoverMock.mockResolvedValue(issuerStub());
});

describe("mintAppOnlyToken", () => {
  it("discovers the tenant-specific v2.0 authority and grants client_credentials with .default", async () => {
    grantMock.mockResolvedValue({
      access_token: "app-token",
      expires_at: epochSecondsIn(3600),
    });
    const { mintAppOnlyToken } = await import("./graph-auth");

    const token = await mintAppOnlyToken(TENANT_ID, "client-id", "client-secret");

    expect(discoverMock).toHaveBeenCalledWith(
      `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
    );
    expect(clientOptionsMock).toHaveBeenCalledWith({
      client_id: "client-id",
      client_secret: "client-secret",
    });
    // `.default` is MANDATORY for client_credentials — individual permission
    // names are invalid scopes for this grant.
    expect(grantMock).toHaveBeenCalledWith({
      grant_type: "client_credentials",
      scope: "https://graph.microsoft.com/.default",
    });
    expect(token.accessToken).toBe("app-token");
    expect(token.expiresAt).toBeGreaterThan(Date.now());
  });

  it("throws an explicit error when the grant response carries no access_token", async () => {
    grantMock.mockResolvedValue({ expires_at: epochSecondsIn(3600) });
    const { mintAppOnlyToken } = await import("./graph-auth");

    await expect(
      mintAppOnlyToken(TENANT_ID, "client-id", "client-secret"),
    ).rejects.toThrow(/no access_token/);
  });

  it("rejects non-GUID tenant ids before any discovery request (T-02-02e)", async () => {
    const { mintAppOnlyToken } = await import("./graph-auth");

    await expect(
      mintAppOnlyToken("../../evil.example.com", "client-id", "client-secret"),
    ).rejects.toThrow(/GUID/i);
    await expect(
      mintAppOnlyToken("organizations", "client-id", "client-secret"),
    ).rejects.toThrow(/GUID/i);
    expect(discoverMock).not.toHaveBeenCalled();
    expect(grantMock).not.toHaveBeenCalled();
  });
});

describe("getGrantedRoles", () => {
  it("decodes an app-token payload's roles claim into the permission array", async () => {
    const { getGrantedRoles } = await import("./graph-auth");
    const jwt = makeJwt({
      aud: "https://graph.microsoft.com",
      roles: ["Policy.Read.All", "User.Read.All"],
    });

    expect(getGrantedRoles(jwt)).toEqual(["Policy.Read.All", "User.Read.All"]);
  });

  it("throws on tokens without three JWT segments", async () => {
    const { getGrantedRoles } = await import("./graph-auth");
    expect(() => getGrantedRoles("only.two")).toThrow(/three JWT segments/);
  });

  it("throws on undecodable base64url payloads", async () => {
    const { getGrantedRoles } = await import("./graph-auth");
    expect(() => getGrantedRoles("header.@@@@not-base64@@@@.signature")).toThrow(
      /undecodable payload/,
    );
  });

  it("throws explicitly when the payload has no roles claim (never silent [])", async () => {
    const { getGrantedRoles } = await import("./graph-auth");
    // A delegated token shape (scp instead of roles) must fail loud, not
    // silently report zero granted permissions (Pitfall 1).
    expect(() => getGrantedRoles(makeJwt({ scp: "User.Read" }))).toThrow(
      /no roles claim/,
    );
  });

  it("throws when roles claim is present but not an array of strings", async () => {
    const { getGrantedRoles } = await import("./graph-auth");
    expect(() => getGrantedRoles(makeJwt({ roles: "User.Read.All" }))).toThrow(
      /malformed/,
    );
    expect(() =>
      getGrantedRoles(makeJwt({ roles: ["User.Read.All", 42] })),
    ).toThrow(/malformed/);
  });
});

describe("safeErrorMessage", () => {
  it("reduces errors to a single line capped at 200 characters", async () => {
    const { safeErrorMessage } = await import("./graph-auth");

    const multiline = safeErrorMessage(
      new Error("first line\nSECRET SHOULD NOT LEAK\nthird line"),
    );
    expect(multiline).toBe("first line");

    const long = safeErrorMessage(new Error("x".repeat(500)));
    expect(long.length).toBeLessThanOrEqual(200);

    expect(safeErrorMessage("plain string error")).toBe("plain string error");
  });
});

describe("getTokenForTenant", () => {
  it("caches the minted token and does not re-grant while fresh", async () => {
    grantMock.mockResolvedValue({
      access_token: "app-token",
      expires_at: epochSecondsIn(3600),
    });
    const { getTokenForTenant } = await import("./graph-auth");

    const first = await getTokenForTenant(TENANT_ID, "client-id", "secret");
    const second = await getTokenForTenant(TENANT_ID, "client-id", "secret");

    expect(grantMock).toHaveBeenCalledTimes(1);
    expect(second).toBe(first);
  });

  it("re-mints once the remaining lifetime drops under the expiry margin", async () => {
    // 60s left < 120s TOKEN_EXPIRY_MARGIN_MS → every call re-mints.
    grantMock.mockResolvedValue({
      access_token: "short-lived-token",
      expires_at: epochSecondsIn(60),
    });
    const { getTokenForTenant } = await import("./graph-auth");

    await getTokenForTenant(TENANT_ID, "client-id", "secret");
    await getTokenForTenant(TENANT_ID, "client-id", "secret");

    expect(grantMock).toHaveBeenCalledTimes(2);
  });

  it("caches per tenant+client pair, never sharing across tenants", async () => {
    grantMock.mockResolvedValue({
      access_token: "app-token",
      expires_at: epochSecondsIn(3600),
    });
    const { getTokenForTenant } = await import("./graph-auth");
    const otherTenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    await getTokenForTenant(TENANT_ID, "client-id", "secret");
    await getTokenForTenant(otherTenant, "client-id", "secret");

    expect(discoverMock).toHaveBeenCalledTimes(2);
    expect(grantMock).toHaveBeenCalledTimes(2);
  });
});
