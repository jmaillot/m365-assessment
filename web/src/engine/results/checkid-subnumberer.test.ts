import { describe, expect, it } from "vitest";
import { createCheckIdSubnumberer } from "./checkid-subnumberer";

describe("createCheckIdSubnumberer", () => {
  it("sub-numbers the first call of a base CheckId with .1", () => {
    const sub = createCheckIdSubnumberer();
    expect(sub.subNumber("CA-MFA-ADMIN-001")).toBe("CA-MFA-ADMIN-001.1");
  });

  it("increments per base: second call .2, third .3", () => {
    const sub = createCheckIdSubnumberer();
    expect(sub.subNumber("CA-MFA-ADMIN-001")).toBe("CA-MFA-ADMIN-001.1");
    expect(sub.subNumber("CA-MFA-ADMIN-001")).toBe("CA-MFA-ADMIN-001.2");
    expect(sub.subNumber("CA-MFA-ADMIN-001")).toBe("CA-MFA-ADMIN-001.3");
  });

  it("keeps interleaved bases on independent counters", () => {
    const sub = createCheckIdSubnumberer();
    expect(sub.subNumber("A-001")).toBe("A-001.1");
    expect(sub.subNumber("B-002")).toBe("B-002.1");
    expect(sub.subNumber("A-001")).toBe("A-001.2");
    expect(sub.subNumber("B-002")).toBe("B-002.2");
  });

  it("passes empty-string CheckId through unsub-numbered", () => {
    const sub = createCheckIdSubnumberer();
    expect(sub.subNumber("")).toBe("");
    // Empty passthrough must not seed a counter entry either.
    expect(sub.subNumber("")).toBe("");
  });

  it("gives each factory-created instance independent counters (per-section isolation)", () => {
    const first = createCheckIdSubnumberer();
    const second = createCheckIdSubnumberer();
    expect(first.subNumber("EXO-AUTH-001")).toBe("EXO-AUTH-001.1");
    expect(first.subNumber("EXO-AUTH-001")).toBe("EXO-AUTH-001.2");
    // Second instance starts fresh — never shares module-level state.
    expect(second.subNumber("EXO-AUTH-001")).toBe("EXO-AUTH-001.1");
  });
});
