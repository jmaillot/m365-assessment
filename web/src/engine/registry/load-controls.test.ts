import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  controlsChecksumsMatch,
  loadFrameworks,
  loadLicensingOverlay,
  loadRegistry,
  loadRiskSeverity,
  registryRemediationText,
} from "./load-controls";
import { SECTION_REGISTRY, getSection } from "./section-registry";
import { requiredRolesForSections } from "./permissions";

// Independent absolute path to the PS module's controls tree — the loader must
// read THIS directory in place (FRM-01), so tests verify against it directly.
// web/src/engine/registry/ → up 4 = repo root.
const REPO_ROOT = fileURLToPath(new URL("../../../..", import.meta.url));
const SOURCE_CONTROLS = join(REPO_ROOT, "src", "M365-Assess", "controls");

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

describe("loadRegistry", () => {
  it("loads registry.json unmodified with exactly 293 checks (FRM-01)", () => {
    const registry = loadRegistry();
    expect(registry.checks).toHaveLength(293);
    expect(typeof registry.schemaVersion).toBe("string");
    // Spot-check parity against the source file parsed independently.
    const independent = JSON.parse(readFileSync(join(SOURCE_CONTROLS, "registry.json"), "utf8"));
    expect(registry.checks.length).toBe(independent.checks.length);
    expect(registry.checks[0]).toEqual(independent.checks[0]);
    expect(registry.checks.at(-1)).toEqual(independent.checks.at(-1));
  });
});

describe("loadLicensingOverlay", () => {
  it("loads licensing-overlay.json with 19 entries under checks{} (FRM-01)", () => {
    const overlay = loadLicensingOverlay();
    expect(Object.keys(overlay.checks)).toHaveLength(19);
  });
});

describe("loadRiskSeverity", () => {
  it("parses risk-severity.json into an object", () => {
    const severity = loadRiskSeverity();
    expect(typeof severity).toBe("object");
    expect(severity).not.toBeNull();
  });
});

describe("loadFrameworks", () => {
  it("auto-discovers all 15 framework files byte-unmodified (FRM-01)", () => {
    const frameworks = loadFrameworks();
    expect(frameworks).toHaveLength(15);
    const ids = new Set(frameworks.map((f) => f.id));
    // Filename-derived ids.
    expect(ids.has("cis-m365-v6")).toBe(true);
    expect(ids.has("soc2-tsc")).toBe(true);
    expect(ids.has("stig")).toBe(true);
    // Every parsed object equals its source file's content parsed independently.
    for (const def of frameworks) {
      const independent = JSON.parse(
        readFileSync(join(SOURCE_CONTROLS, "frameworks", `${def.id}.json`), "utf8"),
      );
      expect(def.data).toEqual(independent);
    }
  });

  it("honors the CONTROLS_DIR override with a fixture directory", () => {
    const fixtureDir = mkdtempSync(join(tmpdir(), "controls-fixture-"));
    try {
      mkdirSync(join(fixtureDir, "frameworks"));
      writeFileSync(
        join(fixtureDir, "registry.json"),
        JSON.stringify({ schemaVersion: "fixture", checks: [{ checkId: "FIX-001" }] }),
      );
      writeFileSync(
        join(fixtureDir, "frameworks", "mini-framework.json"),
        JSON.stringify({ name: "Mini" }),
      );
      writeFileSync(join(fixtureDir, "frameworks", "notes.txt"), "ignored");

      process.env.CONTROLS_DIR = fixtureDir;
      const registry = loadRegistry();
      expect(registry.checks).toHaveLength(1);
      expect(registry.checks[0].checkId).toBe("FIX-001");
      const frameworks = loadFrameworks();
      expect(frameworks).toHaveLength(1);
      expect(frameworks[0].id).toBe("mini-framework");
    } finally {
      delete process.env.CONTROLS_DIR;
      rmSync(fixtureDir, { recursive: true, force: true });
    }
  });
});

describe("controlsChecksumsMatch (T-02-03d drift check)", () => {
  it("matches when pinned checksums equal current file bytes", () => {
    const pinned = sha256File(join(SOURCE_CONTROLS, "registry.json"));
    expect(controlsChecksumsMatch({ "registry.json": pinned })).toBe(true);
  });

  it("detects any modification of a pinned controls file", () => {
    expect(
      controlsChecksumsMatch({
        "registry.json": "0".repeat(64),
      }),
    ).toBe(false);
  });
});

describe("registryRemediationText (D-22 fallback source)", () => {
  it("passes plain-string remediation through", () => {
    expect(registryRemediationText({ checkId: "X", remediation: "Do it" })).toBe("Do it");
  });

  it("flattens structured remediation deterministically", () => {
    expect(
      registryRemediationText({
        checkId: "X",
        remediation: {
          notes: "Enable the thing",
          portal: { path: "Entra admin center > Properties" },
          powershell: { command: "Update-MgPolicy..." },
        },
      }),
    ).toBe("Enable the thing Portal: Entra admin center > Properties PowerShell: Update-MgPolicy...");
  });

  it("returns empty string for absent entries or remediation", () => {
    expect(registryRemediationText(undefined)).toBe("");
    expect(registryRemediationText({ checkId: "X" })).toBe("");
  });
});

describe("SECTION_REGISTRY (D-10)", () => {
  const ALL_DOMAINS = [
    "Tenant",
    "Identity",
    "Licensing",
    "Email",
    "Exchange",
    "Intune",
    "Security",
    "Collaboration",
    "Purview",
    "PowerBI",
    "Hybrid",
    "Inventory",
    "ActiveDirectory",
    "SOC2",
    "ValueOpportunity",
  ];

  it("declares ALL 15 roadmap domains up front, Tenant/Identity/Licensing wired", () => {
    expect(SECTION_REGISTRY.map((e) => e.displayName)).toEqual(ALL_DOMAINS);
    // Phases 05-06 wired Exchange/Intune/Security/Collaboration/Purview/PowerBI/Inventory; the remaining five stay
    // not-yet-implemented (D-10: explicit surfaced errors, never fabricated rows) until their domain phases land.
    expect(
      SECTION_REGISTRY.filter((e) => e.implemented).map((e) => e.id),
    ).toEqual(["tenant", "identity", "licensing", "exchange", "intune", "security", "collaboration", "purview", "powerbi", "inventory"]);
    expect(
      SECTION_REGISTRY.filter((e) => !e.implemented).map((e) => e.displayName),
    ).toEqual([
      "Email",
      "Hybrid",
      "ActiveDirectory",
      "SOC2",
      "ValueOpportunity",
    ]);
    expect(SECTION_REGISTRY.every((e) => Array.isArray(e.endpoints))).toBe(true);
  });

  it("carries requiredAppRoles copied VERBATIM from AssessmentMaps $sectionScopeMap", () => {
    expect(getSection("tenant").requiredAppRoles).toEqual([
      "Organization.Read.All",
      "Domain.Read.All",
      "Policy.Read.All",
      "User.Read.All",
      "Group.Read.All",
    ]);
    expect(getSection("identity").requiredAppRoles).toEqual([
      "User.Read.All",
      "AuditLog.Read.All",
      "UserAuthenticationMethod.Read.All",
      "RoleManagement.Read.Directory",
      "Policy.Read.All",
      "Application.Read.All",
      "Domain.Read.All",
      "Directory.Read.All",
      "Agreement.Read.All",
    ]);
    expect(getSection("soc2").requiredAppRoles).toEqual([
      "Policy.Read.All",
      "RoleManagement.Read.Directory",
      "SecurityEvents.Read.All",
      "SecurityAlert.Read.All",
      "AuditLog.Read.All",
      "User.Read.All",
      "Reports.Read.All",
      "Directory.Read.All",
    ]);
    // Domains without a scope-map entry (Email, PowerBI, ActiveDirectory) are empty.
    expect(getSection("email").requiredAppRoles).toEqual([]);
    expect(getSection("powerbi").requiredAppRoles).toEqual([]);
    expect(getSection("activeDirectory").requiredAppRoles).toEqual([]);
  });

  it("throws 'Unknown section' on unknown ids", () => {
    expect(() => getSection("nonexistent")).toThrow(/Unknown section/);
  });
});

describe("requiredRolesForSections", () => {
  it("computes a case-insensitive dedup union across sections", () => {
    // Policy.Read.All appears in both Tenant and Identity; Organization.Read.All
    // in both Tenant and Licensing — dedup keeps ONE occurrence each.
    const roles = requiredRolesForSections(["tenant", "identity", "licensing"]);
    expect(roles.filter((r) => r === "Policy.Read.All")).toHaveLength(1);
    expect(roles.filter((r) => r === "Organization.Read.All")).toHaveLength(1);
    expect(roles).toContain("Agreement.Read.All");
    expect(roles).toContain("UserAuthenticationMethod.Read.All");
  });

  it("matches requested ids case-insensitively", () => {
    expect(requiredRolesForSections(["SOC2"])).toEqual(requiredRolesForSections(["soc2"]));
  });

  it("throws on unknown section ids", () => {
    expect(() => requiredRolesForSections(["nope"])).toThrow(/Unknown section/);
  });
});
