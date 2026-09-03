/**
 * Pure retry-delay computation for transient Graph errors (D-28).
 *
 * Byte-parity port of Get-GraphRetryDelay from
 * src/M365-Assess/Common/Invoke-SafeGraphRequest.ps1 lines 131–168:
 * - Only 429 (throttling), 503 and 504 are retryable — anything else returns
 *   null so callers surface the error immediately (PS parity: permission or
 *   request failures never retry).
 * - A Retry-After header wins whenever present: ceil(seconds) + 1.
 * - Otherwise exponential backoff min(2^attempt, 60) seconds, with `attempt`
 *   being the 1-based retry attempt number (0 yields the PS floor of 1s).
 *
 * Deliberately zero-import and I/O-free: callers drive real waits, tests
 * assert values directly (D-28 deterministic fake-clock testing).
 */

/** Statuses Graph throttles / fails transiently on and we retry. */
const RETRYABLE_STATUSES = [429, 503, 504];

/** Upper bound on exponential backoff, matching the PS cap. */
const MAX_BACKOFF_SECONDS = 60;

export function retryDelaySeconds(
  status: number,
  retryAfterHeaderSeconds: number | null,
  attempt: number,
): number | null {
  if (!RETRYABLE_STATUSES.includes(status)) return null;

  if (retryAfterHeaderSeconds != null && retryAfterHeaderSeconds >= 0) {
    return Math.ceil(retryAfterHeaderSeconds) + 1;
  }

  return Math.min(Math.pow(2, attempt), MAX_BACKOFF_SECONDS);
}
