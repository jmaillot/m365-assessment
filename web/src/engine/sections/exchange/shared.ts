/**
 * Shared string-shaping helpers for the Exchange collector ports.
 *
 * Mirrors `src/engine/sections/entra/shared.ts` deterministically so
 * CurrentValue summaries stay PS-comparable:
 * - booleans → 'True'/'False' (PowerShell capitalization)
 * - null/missing → '' (PS CSV renders $null as empty)
 * - multi-value fields → sorted, '; '-joined (PS Sort-Object | -join '; ')
 */

export function psStr(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "boolean") return value ? "True" : "False";
  return String(value);
}

/** Deterministic sort (code-unit order — fixtures are ASCII, matching PS). */
export function psSort(values: readonly string[]): string[] {
  return [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

export function semiJoinSorted(values: readonly string[]): string {
  return psSort(values.filter((v) => typeof v === "string")).join("; ");
}

/** Build a `Field=Value; Field=Value` summary from an ordered pair list. */
export function kv(pairs: ReadonlyArray<[string, unknown]>): string {
  return pairs.map(([key, value]) => `${key}=${psStr(value)}`).join("; ");
}

/** Narrow an unknown response value to an array (empty when absent). */
export function asArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? (value as Record<string, unknown>[]) : [];
}

/**
 * PS `$_.Exception.Message -match '<pattern>'` parity over surfaced transport
 * errors. GraphError messages embed the HTTP status and the response-body
 * code/message, so the PS regex sets match identically (plan 02-05 GraphError
 * enrichment is what makes this possible).
 */
export function errMatches(err: unknown, pattern: RegExp): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return pattern.test(message);
}
