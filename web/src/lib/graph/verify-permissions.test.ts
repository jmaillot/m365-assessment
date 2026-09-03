import { describe, it, expect } from "vitest";
import {
  computeVerification,
  verificationError,
  summarize,
} from "./verify-permissions";

describe("computeVerification", () => {
  it("all_granted when granted ⊇ required (case-insensitive match)", () => {
    const result = computeVerification(
      ["A", "B"],
      ["b", "a", "C"],
    );
    expect(result.status).toBe("all_granted");
    expect(result.missing).toEqual([]);
    expect(result.errorMessage).toBeUndefined();
  });

  it("missing lists original-cased required names not granted (any input casing)", () => {
    const result = computeVerification(
      ["A", "B", "C"],
      ["a"],
    );
    expect(result.status).toBe("missing");
    expect(result.missing).toEqual(["B", "C"]);
  });

  it("treats empty granted as missing, never as an error", () => {
    const result = computeVerification(["A"], []);
    expect(result.status).toBe("missing");
    expect(result.missing).toEqual(["A"]);
  });

  it("sorts missing alphabetically", () => {
    const result = computeVerification(
      ["Zeta.Scope", "Alpha.Scope", "Mid.Scope"],
      [],
    );
    expect(result.missing).toEqual([
      "Alpha.Scope",
      "Mid.Scope",
      "Zeta.Scope",
    ]);
  });

  it("handles duplicates in either input without corrupting counts", () => {
    const dupRequired = computeVerification(
      ["A", "A", "B"],
      ["a"],
    );
    expect(dupRequired.status).toBe("missing");
    // duplicate required names deduplicated in output
    expect(dupRequired.missing).toEqual(["B"]);

    const dupGranted = computeVerification(
      ["A", "B"],
      ["a", "a", "b", "B"],
    );
    expect(dupGranted.status).toBe("all_granted");
  });

  it("always emits payload provenance fields", () => {
    const result = computeVerification(["X"], ["x"]);
    expect(result.schemaVersion).toBe("1.0");
    expect(() => new Date(result.generatedAtUtc)).not.toThrow();
    expect(result.generatedAtUtc.endsWith("Z")).toBe(true);
    expect(result.required).toEqual(["X"]);
    expect(result.granted).toEqual(["x"]);
  });
});

describe("verificationError", () => {
  it("returns an explicit error result for token acquisition failures", () => {
    const result = verificationError("MSAL token acquisition failed: timeout");
    expect(result.status).toBe("error");
    expect(result.errorMessage).toBe("MSAL token acquisition failed: timeout");
    expect(result.missing).toEqual([]);
    expect(result.schemaVersion).toBe("1.0");
    expect(result.generatedAtUtc.endsWith("Z")).toBe(true);
  });
});

describe("summarize", () => {
  it("counts required vs missing for the S5 banner", () => {
    const result = computeVerification(["A", "B", "C"], ["c"]);
    expect(summarize(result)).toEqual({ totalRequired: 3, totalMissing: 2 });
  });

  it("reports zero missing on all_granted", () => {
    const result = computeVerification(["A"], ["a"]);
    expect(summarize(result)).toEqual({ totalRequired: 1, totalMissing: 0 });
  });
});
