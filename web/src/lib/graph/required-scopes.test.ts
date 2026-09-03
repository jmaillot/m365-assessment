import { describe, it, expect } from "vitest";
import { REQUIRED_GRAPH_SCOPES } from "./required-scopes";

describe("REQUIRED_GRAPH_SCOPES", () => {
  it("contains exactly 25 scopes", () => {
    expect(REQUIRED_GRAPH_SCOPES).toHaveLength(25);
  });

  it("has case-insensitively unique names", () => {
    const lower = REQUIRED_GRAPH_SCOPES.map((s) => s.name.toLowerCase());
    expect(new Set(lower).size).toBe(lower.length);
  });

  it("gives every entry a non-empty purpose", () => {
    for (const scope of REQUIRED_GRAPH_SCOPES) {
      expect(scope.name.trim().length).toBeGreaterThan(0);
      expect(scope.purpose.trim().length).toBeGreaterThan(0);
    }
  });

  it("matches source strings exactly on spot-checked entries", () => {
    const byName = new Map(REQUIRED_GRAPH_SCOPES.map((s) => [s.name, s]));
    expect(byName.get("Organization.Read.All")).toEqual({
      name: "Organization.Read.All",
      purpose: "Tenant org details, verified domains, hybrid config",
    });
    expect(byName.get("OrgSettings-Forms.Read.All")).toEqual({
      name: "OrgSettings-Forms.Read.All",
      purpose: "Microsoft Forms tenant-level settings",
    });
    expect(byName.get("MailboxSettings.Read")).toEqual({
      name: "MailboxSettings.Read",
      purpose: "Mailbox-level settings (forwarding, audit, locale) via Graph",
    });
  });

  it("is read-only only: no ReadWrite/Write scopes anywhere", () => {
    for (const { name } of REQUIRED_GRAPH_SCOPES) {
      expect(name).not.toMatch(/ReadWrite|\.Write\./i);
    }
  });

  it("every name ends with .All or is a known non-.All exception", () => {
    const exceptions = new Set([
      "RoleManagement.Read.Directory",
      "MailboxSettings.Read",
    ]);
    for (const { name } of REQUIRED_GRAPH_SCOPES) {
      expect(name.endsWith(".All") || exceptions.has(name)).toBe(true);
    }
  });
});
