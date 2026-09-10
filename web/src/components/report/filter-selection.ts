/**
 * Shared filter-selection merge helpers for the report tab components.
 *
 * Each tab keeps user-toggleable `selectedDomains` / `selectedCategories` state
 * that must resync when the underlying report data changes. The merge runs as a
 * render-phase adjustment (compare-then-setState during render — the sanctioned
 * derived-state pattern), never as a synchronous setState inside an effect, so
 * it satisfies `react-hooks/set-state-in-effect` without cascading renders.
 */

/** Keep user picks, add newly-appeared values, drop values gone from data. */
export function mergeDomainSelection(
  prev: Set<string>,
  domains: string[],
): Set<string> {
  if (prev.size === 0 && domains.length > 0) return new Set(domains);
  const next = new Set(prev);
  let changed = false;
  for (const d of domains)
    if (!next.has(d)) {
      next.add(d);
      changed = true;
    }
  for (const d of Array.from(next))
    if (!domains.includes(d)) {
      next.delete(d);
      changed = true;
    }
  return changed ? next : prev;
}

/** Merge a category selection against fresh availability, guarding non-empty. */
export function mergeCategorySelection(
  prev: Set<string>,
  available: Set<string>,
): Set<string> {
  if (prev.size === 0 && available.size > 0) return new Set(available);
  const next = new Set<string>();
  // Keep only categories still available
  for (const c of prev) if (available.has(c)) next.add(c);
  // Add newly available categories
  for (const c of available) if (!prev.has(c)) next.add(c);
  // Guard non-empty
  if (next.size === 0 && available.size > 0) return new Set(available);
  // Compare
  if (next.size !== prev.size) return next;
  for (const c of next) if (!prev.has(c)) return next;
  return prev;
}
