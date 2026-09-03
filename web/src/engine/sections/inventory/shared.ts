/**
 * Shared helpers for the Inventory collector ports.
 *
 * Mirrors `src/engine/sections/entra/shared.ts` deterministically:
 * - booleans → 'True'/'False' (PowerShell capitalization)
 * - null/missing → '' (PS CSV renders $null as empty)
 * - multi-value fields → sorted, '; '-joined
 */

export function psStr(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "boolean") return value ? "True" : "False";
  return String(value);
}

export function psSort(values: readonly string[]): string[] {
  return [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

export function semiJoinSorted(values: readonly string[]): string {
  return psSort(values.filter((v) => typeof v === "string")).join("; ");
}

export function kv(pairs: ReadonlyArray<[string, unknown]>): string {
  return pairs.map(([key, value]) => `${key}=${psStr(value)}`).join("; ");
}

export function asArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? (value as Record<string, unknown>[]) : [];
}

/**
 * PS `$_.Exception.Message -match '<pattern>'` parity over surfaced transport
 * errors. GraphError messages embed HTTP status and response-body code/message.
 */
export function errMatches(err: unknown, pattern: RegExp): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return pattern.test(message);
}
