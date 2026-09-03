import { describe, expect, it } from "vitest";
import { mapStatus } from "./status-mapper";
import type { PsStatus } from "./row-contract";

describe("mapStatus", () => {
  it('maps "Pass" to Pass with no skip reason', () => {
    expect(mapStatus("Pass")).toEqual({ status: "Pass" });
  });

  it('maps "Fail" to Fail with no skip reason', () => {
    expect(mapStatus("Fail")).toEqual({ status: "Fail" });
  });

  it('maps "Warning" identity through unchanged', () => {
    expect(mapStatus("Warning")).toEqual({ status: "Warning" });
  });

  it('maps "Review" identity through unchanged', () => {
    expect(mapStatus("Review")).toEqual({ status: "Review" });
  });

  it('maps "Info" identity through unchanged', () => {
    expect(mapStatus("Info")).toEqual({ status: "Info" });
  });

  it('maps PS "Warn" spelling onto SaaS "Warning"', () => {
    // PS sources emit both Warn and Warning; Warn is the identity of Warning.
    expect(mapStatus("Warn")).toEqual({ status: "Warning" });
  });

  it('upgrades "Unknown" to Review per D-23 evidence line', () => {
    // Semantic upgrade: automation lacked evidence -> human must look.
    expect(mapStatus("Unknown")).toEqual({ status: "Review" });
  });

  it('maps "NotApplicable" to Skipped with reason not_applicable', () => {
    expect(mapStatus("NotApplicable")).toEqual({
      status: "Skipped",
      reason: "not_applicable",
    });
  });

  it('maps "NotLicensed" to Skipped with reason not_licensed', () => {
    expect(mapStatus("NotLicensed")).toEqual({
      status: "Skipped",
      reason: "not_licensed",
    });
  });

  it('maps "Error" to Skipped with reason graph_error', () => {
    expect(mapStatus("Error")).toEqual({
      status: "Skipped",
      reason: "graph_error",
    });
  });

  it('maps bare "Skipped" to Skipped with default reason not_applicable (caller may refine)', () => {
    expect(mapStatus("Skipped")).toEqual({
      status: "Skipped",
      reason: "not_applicable",
    });
  });

  it("covers every member of the PsStatus union", () => {
    const allStatuses: PsStatus[] = [
      "Pass",
      "Fail",
      "Warn",
      "Warning",
      "Review",
      "Info",
      "Skipped",
      "Unknown",
      "NotApplicable",
      "NotLicensed",
      "Error",
    ];
    for (const ps of allStatuses) {
      const mapped = mapStatus(ps);
      expect(mapped.status).toBeDefined();
    }
  });
});
