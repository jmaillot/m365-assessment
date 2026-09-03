/**
 * Collector-test support: runs one SectionImplementation through the REAL
 * engine runner over a recorded-replay fixture set, so collector suites prove
 * their rows through the production addRow pipeline (mapStatus → sub-numbering
 * → D-22 registry fallback → events) rather than a hand-rolled stub context.
 *
 * Golden-row convention (plan 02-03): golden files carry camelCase CheckRow
 * keys with the RAW PS status; comparisons map them through mapStatus first.
 */
import { readFileSync } from "node:fs";
import { mapStatus } from "@/engine/results/status-mapper";
import type { CheckRow, PsStatus } from "@/engine/results/row-contract";
import { runEngine } from "@/engine/runner/engine";
import type { SectionImplementation } from "@/engine/runner/engine";
import type { EngineEvent } from "@/engine/events/engine-events";
import { createReplayFetch } from "@/engine/__fixtures__/replay";
import { GraphTransport } from "@/engine/transport/graph-transport";

export interface SectionRunOutcome {
  rows: CheckRow[];
  sectionError?: string;
  /** Every Graph URL the transport dispatched (D-25 audit surface for asserts). */
  graphUrls: string[];
  events: EngineEvent[];
  /** Whether runEngine applied the D-20 overlay post-run (SKUs were collected). */
  licensingOverlayApplied?: boolean;
}

/** Run one or more collectors through runEngine over an inline fixture set. */
export async function runSectionsOverFixtures(
  sectionIds: string[],
  implementations: Record<string, SectionImplementation>,
  fixtures: Record<string, unknown>,
  /** Optional fetch override (error-path tests wrap createReplayFetch). */
  opts?: { fetchImpl?: typeof fetch },
): Promise<SectionRunOutcome> {
  const events: EngineEvent[] = [];
  const graphUrls: string[] = [];
  const transport = new GraphTransport({
    getToken: async () => "test-token",
    fetchImpl: opts?.fetchImpl ?? createReplayFetch(fixtures),
    onPage: (e) => graphUrls.push(e.url),
    isRoleGranted: () => true,
    delayFn: async () => {},
  });
  const result = await runEngine({
    tenantId: "00000000-0000-4000-8000-000000000000",
    sectionIds,
    transport,
    sink: { emit: (event) => events.push(event) },
    implementations,
  });
  const rows = sectionIds.flatMap(
    (id) => result.sections.find((s) => s.sectionId === id)?.rows ?? [],
  );
  const errored = result.sections.find((s) => s.error !== undefined);
  return {
    rows,
    ...(errored?.error !== undefined && { sectionError: errored.error }),
    graphUrls,
    events,
    ...(result.licensingOverlayApplied && {
      licensingOverlayApplied: true,
    }),
  };
}

/** Run one collector through runEngine over an inline fixture record set. */
export async function runCollectorOverFixtures(
  sectionId: string,
  impl: SectionImplementation,
  fixtures: Record<string, unknown>,
  /** Optional fetch override (error-path tests wrap createReplayFetch). */
  opts?: { fetchImpl?: typeof fetch },
): Promise<SectionRunOutcome> {
  return runSectionsOverFixtures([sectionId], { [sectionId]: impl }, fixtures, opts);
}

/** Read a fixture/golden JSON file from web/src/engine/__fixtures__/. */
export function readFixtureJson<T>(relPath: string): T {
  const root = new URL("../../__fixtures__/", import.meta.url);
  return JSON.parse(readFileSync(new URL(relPath, root), "utf8")) as T;
}

/**
 * Convert golden rows (raw PS status) into the post-mapStatus shape addRow
 * produces, so a plain toEqual against engine output works. Our six report
 * collectors carry no CheckIds, so sub-numbering passes "" through and the
 * D-22 registry fallback never fires (empty base id).
 */
export function goldenToExpected(
  golden: ReadonlyArray<Record<string, unknown>>,
): CheckRow[] {
  return golden.map((g) => ({
    category: g.category as string,
    setting: g.setting as string,
    currentValue: g.currentValue as string,
    recommendedValue: (g.recommendedValue as string) ?? "",
    status: mapStatus(g.status as PsStatus).status,
    checkId: (g.checkId as string) ?? "",
    remediation: (g.remediation as string) ?? "",
    intentDesign: Boolean(g.intentDesign),
    // D1 #785 evidence fields (plan 02-08): carried when the golden carries
    // them so deep-equal covers rows that populate standardized evidence.
    ...(g.observedValue !== undefined && { observedValue: g.observedValue as string }),
    ...(g.expectedValue !== undefined && { expectedValue: g.expectedValue as string }),
    ...(g.evidenceSource !== undefined && { evidenceSource: g.evidenceSource as string }),
    ...(g.evidenceTimestamp !== undefined && {
      evidenceTimestamp: g.evidenceTimestamp as string,
    }),
    ...(g.collectionMethod !== undefined && g.collectionMethod !== "" && {
      collectionMethod: g.collectionMethod as CheckRow["collectionMethod"],
    }),
    ...(g.permissionRequired !== undefined && {
      permissionRequired: g.permissionRequired as string,
    }),
    ...(g.confidence !== undefined && { confidence: g.confidence as number }),
    ...(g.limitations !== undefined && { limitations: g.limitations as string }),
  }));
}
