import { describe, expect, it } from "vitest";
import { runIntuneSecurityConfig, INTUNE_SECURITY_CONFIG_ENDPOINTS } from "./intune-security-config";
import {
  goldenToExpected,
  readFixtureJson,
  runCollectorOverFixtures,
} from "../entra/test-support";
import { createReplayFetch } from "@/engine/__fixtures__/replay";

describe("runIntuneSecurityConfig", () => {
  it("produces golden rows identical to hand-traced PS over recorded fixtures (INTUNE-COMPLIANCE + INTUNE-ENROLL)", async () => {
    const fixtures: Record<string, unknown> = {
      [INTUNE_SECURITY_CONFIG_ENDPOINTS.settings]: {
        deviceComplianceCheckinThresholdDays: 30,
      },
      [INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations]: {
        value: [
          {
            "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
            iosRestriction: { personalDeviceEnrollmentBlocked: true },
            androidRestriction: { personalDeviceEnrollmentBlocked: true },
            windowsRestriction: { personalDeviceEnrollmentBlocked: true },
          },
        ],
      },
    };
    const { rows, sectionError } = await runCollectorOverFixtures(
      "intune",
      runIntuneSecurityConfig,
      fixtures,
    );
    expect(sectionError).toBeUndefined();
    // Two goldens: compliance and enrollment — combined assertion
    const complianceGolden = readFixtureJson<Array<Record<string, unknown>>>("golden/intune/compliance.json");
    const enrollmentGolden = readFixtureJson<Array<Record<string, unknown>>>("golden/intune/enrollment.json");
    const combinedGolden = [...complianceGolden, ...enrollmentGolden];
    expect(rows).toEqual(goldenToExpected(combinedGolden));
    expect(rows.some((r) => r.checkId === "INTUNE-ENROLL-001.1")).toBe(true);
    expect(rows.some((r) => r.checkId === "INTUNE-COMPLIANCE-001.1")).toBe(true);
  });

  it("uses /beta/deviceManagement/deviceEnrollmentConfigurations (D-23 keep) and provenance notes it", async () => {
    const fixtures: Record<string, unknown> = {
      [INTUNE_SECURITY_CONFIG_ENDPOINTS.settings]: { deviceComplianceCheckinThresholdDays: 14 },
      [INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations]: {
        value: [
          {
            "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
            iosRestriction: { personalDeviceEnrollmentBlocked: true },
            androidRestriction: { personalDeviceEnrollmentBlocked: true },
            windowsRestriction: { personalDeviceEnrollmentBlocked: true },
          },
        ],
      },
    };
    const { graphUrls } = await runCollectorOverFixtures("intune", runIntuneSecurityConfig, fixtures);
    expect(graphUrls.some((u) => u.includes(INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations))).toBe(true);
    expect(INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations).toBe(
      "/beta/deviceManagement/deviceEnrollmentConfigurations",
    );
    const enrollmentGolden = readFixtureJson<Array<Record<string, unknown>>>("golden/intune/enrollment.json");
    const provenance = JSON.stringify(enrollmentGolden);
    expect(provenance).toContain("/beta/deviceManagement/deviceEnrollmentConfigurations");
    // Also endpoint declared as keep
    expect(graphUrls.some((u) => u.includes("/beta/deviceManagement/deviceEnrollmentConfigurations"))).toBe(true);
  });

  it("empty tenant → INTUNE-ENROLL Fail and compliance Review (fail-closed, not_licensed style handled via 403 Skipped)", async () => {
    const fixtures: Record<string, unknown> = {
      [INTUNE_SECURITY_CONFIG_ENDPOINTS.settings]: {},
      [INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations]: { value: [] },
    };
    const { rows } = await runCollectorOverFixtures("intune", runIntuneSecurityConfig, fixtures);
    const compliance = rows.find((r) => r.checkId === "INTUNE-COMPLIANCE-001.1");
    const enroll = rows.find((r) => r.checkId === "INTUNE-ENROLL-001.1");
    expect(compliance).toBeDefined();
    expect(compliance!.status).toBe("Review");
    expect(enroll).toBeDefined();
    expect(enroll!.status).toBe("Fail");
    expect(enroll!.currentValue).toBe("No platform restriction policies found");
  });

  it("403 → Skipped(not_licensed) with explicit copy — both checks", async () => {
    const failingFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({ error: { code: "Authorization_RequestDenied", message: "403 Forbidden" } }),
        { status: 403, headers: { "content-type": "application/json" } },
      );
    };
    const { rows } = await runCollectorOverFixtures("intune", runIntuneSecurityConfig, {}, { fetchImpl: failingFetch as typeof fetch });
    expect(rows.length).toBe(2);
    expect(rows.every((r) => r.status === "Skipped")).toBe(true);
    for (const r of rows) {
      expect(r.currentValue).toContain("Missing permissions — DeviceManagementConfiguration.Read.All not granted; re-consent to grant");
    }
    expect(rows.map((r) => r.checkId).sort()).toEqual(["INTUNE-COMPLIANCE-001.1", "INTUNE-ENROLL-001.1"]);
  });

  it("personalDeviceEnrollmentBlocked false on any platform → Fail (D-17)", async () => {
    const fixtures: Record<string, unknown> = {
      [INTUNE_SECURITY_CONFIG_ENDPOINTS.settings]: { deviceComplianceCheckinThresholdDays: 30 },
      [INTUNE_SECURITY_CONFIG_ENDPOINTS.enrollmentConfigurations]: {
        value: [
          {
            "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
            iosRestriction: { personalDeviceEnrollmentBlocked: false },
            androidRestriction: { personalDeviceEnrollmentBlocked: true },
            windowsRestriction: { personalDeviceEnrollmentBlocked: true },
          },
        ],
      },
    };
    const { rows } = await runCollectorOverFixtures("intune", runIntuneSecurityConfig, fixtures);
    const enroll = rows.find((r) => r.checkId === "INTUNE-ENROLL-001.1");
    expect(enroll!.status).toBe("Fail");
    expect(enroll!.currentValue).toBe("Allowed on some platforms");
  });
});
