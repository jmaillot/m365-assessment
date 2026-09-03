/**
 * Circuit breaker for surfaced Graph errors within one section (D-13).
 *
 * Semantics locked by RESEARCH Pitfall 6:
 * - Only SURFACED errors are recorded here: retries absorbed upstream by
 *   GraphTransport (throttle/backoff exhaustion is what surfaces a GraphError)
 *   never reach this counter — collectors record a failure only when an error
 *   actually materializes as a row outcome or collector throw.
 * - The streak counts CONSECUTIVE failures; any success resets it to zero.
 *   One flaky 429 storm must not kill a whole section.
 * - Threshold N is planner discretion (default CIRCUIT_BREAKER_THRESHOLD = 5).
 * - Tripping NEVER kills the run: it only flips subsequent addRow() calls in
 *   the affected section to Skipped("circuit_broken") (D-13).
 *
 * A fresh breaker is created per section execution (fresh-context isolation,
 * mirroring Initialize-SecurityConfig's per-collector reset).
 */

export const CIRCUIT_BREAKER_THRESHOLD = 5;

export interface CircuitBreaker {
  /** Record one surfaced Graph error (post-retry, non-transient). */
  recordFailure(): void;
  /** Any successful evaluation resets the consecutive-failure streak. */
  recordSuccess(): void;
  /** True once the consecutive-failure streak has reached the threshold. */
  shouldTrip(): boolean;
}

export function createCircuitBreaker(
  threshold: number = CIRCUIT_BREAKER_THRESHOLD,
): CircuitBreaker {
  let consecutiveFailures = 0;

  return {
    recordFailure(): void {
      consecutiveFailures += 1;
    },
    recordSuccess(): void {
      consecutiveFailures = 0;
    },
    shouldTrip(): boolean {
      return consecutiveFailures >= threshold;
    },
  };
}
