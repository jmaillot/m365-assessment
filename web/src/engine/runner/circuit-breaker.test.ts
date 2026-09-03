import { describe, expect, it } from "vitest";
import { CIRCUIT_BREAKER_THRESHOLD, createCircuitBreaker } from "./circuit-breaker";

describe("createCircuitBreaker", () => {
  it(`trips only after ${"N"}=${5} consecutive surfaced failures`, () => {
    // Default threshold is the named constant (planner discretion: N=5).
    expect(CIRCUIT_BREAKER_THRESHOLD).toBe(5);

    const breaker = createCircuitBreaker();
    for (let i = 0; i < CIRCUIT_BREAKER_THRESHOLD - 1; i += 1) {
      breaker.recordFailure();
      expect(breaker.shouldTrip()).toBe(false);
    }
    breaker.recordFailure();
    expect(breaker.shouldTrip()).toBe(true);
  });

  it("resets the consecutive-failure streak on any success", () => {
    const breaker = createCircuitBreaker();
    for (let i = 0; i < CIRCUIT_BREAKER_THRESHOLD - 1; i += 1) {
      breaker.recordFailure();
    }
    breaker.recordSuccess();
    expect(breaker.shouldTrip()).toBe(false);
    // Streak restarted: needs a full N again after the reset.
    for (let i = 0; i < CIRCUIT_BREAKER_THRESHOLD - 1; i += 1) {
      breaker.recordFailure();
    }
    expect(breaker.shouldTrip()).toBe(false);
    breaker.recordFailure();
    expect(breaker.shouldTrip()).toBe(true);
  });

  it("never trips on non-consecutive failures however numerous in total", () => {
    // Contract (RESEARCH Pitfall 6): only SURFACED errors reach the breaker —
    // retries absorbed upstream by the transport never count. And only a
    // CONSECUTIVE streak trips it: alternating success/failure never accumulates.
    const breaker = createCircuitBreaker();
    for (let i = 0; i < 25; i += 1) {
      breaker.recordFailure();
      breaker.recordSuccess();
      expect(breaker.shouldTrip()).toBe(false);
    }
  });

  it("honors an explicit threshold override", () => {
    const breaker = createCircuitBreaker(2);
    breaker.recordFailure();
    expect(breaker.shouldTrip()).toBe(false);
    breaker.recordFailure();
    expect(breaker.shouldTrip()).toBe(true);
  });
});
