/**
 * Regression tests for the Power BI security-config port (06-01).
 *
 * The Power BI admin surface (`/v1.0/myorg/admin/tenantSettings`) is NOT a
 * Microsoft Graph endpoint — it lives on the separate Power BI resource
 * (`https://api.powerbi.com`, token scope `analysis.windows.net/powerbi/api`).
 * Because the SaaS currently routes everything through the Graph transport and
 * mints a single Graph-scoped app token, this call cannot actually succeed in
 * the current transport model, and `Tenant.Read.All` is typically not granted
 * on the app registration.
 *
 * Prior behavior: when `Tenant.Read.All` was not granted, `GraphTransport`
 * threw a `TransportFatalError` ("required role not granted ...") which the
 * collector rethrew → the section emitted ZERO rows → the Power BI domain and
 * category silently disappeared from the report.
 *
 * This suite locks in the fix: the role-not-granted fatal error must degrade to
 * visible NotLicensed (→ Skipped/not_licensed) rows so the Power BI section
 * always shows up, while genuine transport bugs (SSRF guard, non-GET) still
 * fail loudly and rethrow.
 */
import { describe, expect, it, vi } from "vitest";
import { runEngine } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { PowerBiTransport } from "@/engine/transport/powerbi-transport";
import { runPowerBISecurityConfig } from "./powerbi-security-config";

const TENANT_ID = "00000000-0000-4000-8000-000000000000";

/** Build a Power BI transport whose role gate returns the given predicate. */
function makeTransport(isRoleGranted: (role: string) => boolean): PowerBiTransport {
  return new PowerBiTransport({
    getToken: async () => "test-token",
    fetchImpl: vi.fn(async () => {
      throw new Error("fetch should never be called when the role is not granted");
    }),
    onPage: () => {},
    isRoleGranted,
    delayFn: async () => {},
  });
}

/** Run the Power BI collector through the real engine runner. */
async function runPowerBi(isRoleGranted: (role: string) => boolean) {
  const transport = makeTransport(isRoleGranted);
  const events: unknown[] = [];
  const result = await runEngine({
    tenantId: TENANT_ID,
    sectionIds: ["powerbi"],
    transport,
    sink: { emit: (e) => events.push(e) },
    implementations: { powerbi: runPowerBISecurityConfig },
  });
  const section = result.sections.find((s) => s.sectionId === "powerbi");
  return { section, rows: section?.rows ?? [], events };
}

describe("runPowerBISecurityConfig — fail-soft when role not granted", () => {
  it("emits 11 NotLicensed rows instead of vanishing when Tenant.Read.All is not granted", async () => {
    // Tenant.Read.All is not granted → transport throws TransportFatalError
    // before any fetch. The collector must degrade to visible rows.
    const { section, rows } = await runPowerBi(() => false);

    // Section must NOT record an error, and must carry the 11 CIS checks.
    expect(section?.error).toBeUndefined();
    expect(rows).toHaveLength(11);
    for (const row of rows) {
      expect(row.status).toBe("Skipped");
      expect(row.skipReason).toBe("not_licensed");
    }

    const baseIds = rows.map((r) => r.checkId.split(".")[0]);
    expect(baseIds).toEqual([
      "POWERBI-GUEST-001",
      "POWERBI-GUEST-002",
      "POWERBI-GUEST-003",
      "POWERBI-SHARING-001",
      "POWERBI-SHARING-002",
      "POWERBI-INFOPROT-001",
      "POWERBI-SHARING-003",
      "POWERBI-SHARING-004",
      "POWERBI-AUTH-001",
      "POWERBI-AUTH-002",
      "POWERBI-AUTH-003",
    ]);
  });

  it("collects settings normally when the role IS granted and the endpoint responds", async () => {
    // Realistic tenantSettings payload; all settings present and enforced.
    const fetchImpl = vi.fn(async () =>
      new Response(
        JSON.stringify({
          tenantSettings: [
            { settingName: "AllowGuestLookup", isEnabled: false },
            { settingName: "ElevatedGuestsTenant", isEnabled: false },
            { settingName: "AllowGuestUserToAccessSharedContent", isEnabled: false },
            { settingName: "WebDashboardsPublishToWebDisabled", isEnabled: true },
            { settingName: "RScriptVisuals", isEnabled: false },
            { settingName: "UseSensitivityLabels", isEnabled: true },
            { settingName: "ShareLinkToEntireOrg", isEnabled: false },
            { settingName: "AllowExternalDataSharingReceiverWorksWithShare", isEnabled: false },
            { settingName: "BlockResourceKeyAuthentication", isEnabled: true },
            { settingName: "ServicePrincipalAccess", isEnabled: false },
            { settingName: "CreateServicePrincipalProfile", isEnabled: false },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );

    const transport = new PowerBiTransport({
      getToken: async () => "test-token",
      fetchImpl,
      onPage: () => {},
      isRoleGranted: () => true,
      delayFn: async () => {},
    });

    const result = await runEngine({
      tenantId: TENANT_ID,
      sectionIds: ["powerbi"],
      transport,
      sink: { emit: () => {} },
      implementations: { powerbi: runPowerBISecurityConfig },
    });
    const section = result.sections.find((s) => s.sectionId === "powerbi");
    const rows = section?.rows ?? [];

    expect(section?.error).toBeUndefined();
    expect(rows).toHaveLength(11);
    // All 11 settings match a Pass posture in this fixture.
    for (const row of rows) {
      expect(row.status).toBe("Pass");
    }
  });

  it("still rethrows genuine transport bugs (non-GET) so they surface loudly", async () => {
    // A non-GET attempt is a programming bug (D-24) — must NOT be swallowed
    // into NotLicensed rows. Prove the guard-by-message deliberation stays
    // narrow by simulating a malformed/root-relative path fatal error, which
    // must propagate as a section error rather than degrade.
    const transport = new PowerBiTransport({
      getToken: async () => "test-token",
      fetchImpl: vi.fn(async () => {
        throw new Error("should not fetch");
      }),
      onPage: () => {},
      // Role granted so the role-gate does not short-circuit first.
      isRoleGranted: () => true,
      delayFn: async () => {},
    });

    // Force a genuine transport bug path: an invalid Power BI URL aborts
    // fatally BEFORE fetch, distinct from the role-not-granted condition.
    const buggyGetJson = async () => {
      throw new TransportFatalError("PowerBiTransport accepts absolute");
    };
    const original = transport.getJson;
    (transport as unknown as { getJson: unknown }).getJson = buggyGetJson;
    try {
      const result = await runEngine({
        tenantId: TENANT_ID,
        sectionIds: ["powerbi"],
        transport,
        sink: { emit: () => {} },
        implementations: { powerbi: runPowerBISecurityConfig },
      });
      const section = result.sections.find((s) => s.sectionId === "powerbi");
      expect(section?.error).toMatch(/PowerBiTransport accepts absolute/i);
      expect(section?.rows).toHaveLength(0);
    } finally {
      (transport as unknown as { getJson: unknown }).getJson = original;
    }
  });
});
