/**
 * CheckId auto-sub-numbering (D-19) — verbatim port of the PowerShell
 * algorithm in `src/M365-Assess/Common/SecurityConfigHelper.ps1:248-254`:
 *
 *   $subCheckId = $CheckId
 *   if ($CheckId) {
 *       if (-not $CheckIdCounter.ContainsKey($CheckId)) { $CheckIdCounter[$CheckId] = 0 }
 *       $CheckIdCounter[$CheckId]++
 *       $subCheckId = "$CheckId.$($CheckIdCounter[$CheckId])"
 *   }
 *
 * Semantics locked by unit tests:
 * - Counter starts absent → 0; increment happens BEFORE formatting (.1, .2, …)
 * - Empty/falsy base CheckId passes through unchanged (no suffix, no counter)
 * - Factory-per-call: each section execution creates a fresh instance so
 *   counters are isolated per section context — NEVER a module-level singleton
 *   (RESEARCH Pitfall 5: a shared counter breaks D-21 dual-run parity).
 */
export function createCheckIdSubnumberer(): {
  subNumber(baseCheckId: string): string;
} {
  const counters = new Map<string, number>();

  return {
    subNumber(baseCheckId: string): string {
      if (!baseCheckId) {
        return baseCheckId;
      }
      let count = counters.get(baseCheckId);
      if (count === undefined) {
        count = 0;
      }
      count += 1;
      counters.set(baseCheckId, count);
      return `${baseCheckId}.${count}`;
    },
  };
}
