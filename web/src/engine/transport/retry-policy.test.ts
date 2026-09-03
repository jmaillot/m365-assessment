import { describe, expect, it } from "vitest";
import { retryDelaySeconds } from "./retry-policy";

/**
 * Byte-parity port of Get-GraphRetryDelay from
 * src/M365-Assess/Common/Invoke-SafeGraphRequest.ps1 lines 131–168:
 * - statuses outside {429,503,504} → null (not retryable)
 * - Retry-After header wins when present: ceil(seconds)+1
 * - otherwise exponential backoff min(2^attempt, 60)
 */
describe("retryDelaySeconds", () => {
  it("returns null for non-transient success status", () => {
    expect(retryDelaySeconds(200, null, 1)).toBeNull();
  });

  it("returns null for non-retryable client error (403)", () => {
    // Permission failures must surface immediately, never retry.
    expect(retryDelaySeconds(403, null, 1)).toBeNull();
  });

  it("returns null for other non-retryable statuses (404, 500)", () => {
    expect(retryDelaySeconds(404, null, 1)).toBeNull();
    expect(retryDelaySeconds(500, null, 1)).toBeNull();
  });

  it("backs off exponentially for 429 without Retry-After", () => {
    expect(retryDelaySeconds(429, null, 1)).toBe(2);
    expect(retryDelaySeconds(429, null, 3)).toBe(8);
  });

  it("caps backoff at 60 seconds", () => {
    expect(retryDelaySeconds(429, null, 10)).toBe(60);
  });

  it("honors Retry-After header over exponential backoff (ceil+1)", () => {
    expect(retryDelaySeconds(503, 30, 2)).toBe(31);
  });

  it("rounds fractional Retry-After up via ceil before adding 1", () => {
    expect(retryDelaySeconds(503, 0.5, 2)).toBe(2);
  });

  it("computes backoff for 504 at attempt 0 as 1 second", () => {
    expect(retryDelaySeconds(504, null, 0)).toBe(1);
  });

  it("retries all of the transient set 429/503/504 with backoff", () => {
    for (const status of [429, 503, 504]) {
      expect(retryDelaySeconds(status, null, 2)).toBe(4);
    }
  });
});
