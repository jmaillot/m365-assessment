import { mapStatus } from "../results/status-mapper";
import { createCheckIdSubnumberer } from "../results/checkid-subnumberer";
import { applyLicensingOverlay } from "../results/licensing-overlay";
import type { LicensingOverlay, SkuState } from "../results/licensing-overlay";
import type { CheckRow, CheckRowInput } from "../results/row-contract";
import type {
  ControlRegistry,
  RegistryCheckEntry,
} from "../registry/load-controls";
import {
  loadLicensingOverlay,
  loadRegistry,
  registryRemediationText,
} from "../registry/load-controls";
import type { GraphTransport, GetJsonOptions as GraphGetJsonOptions } from "../transport/graph-transport";
import type { GraphCallEvent } from "../transport/graph-transport";
import { safeErrorMessage } from "../transport/graph-auth";

export interface Transport {
  getJson(pathOrUrl: string, opts?: GraphGetJsonOptions): Promise<Record<string, unknown>>;
}
import type { EngineEvent, EngineEventSink } from "../events/engine-events";
import { createCircuitBreaker } from "./circuit-breaker";

/**
 * Sequential fail-soft section runner (ENG-04 / D-12 / D-13).
 *
 * - Sections execute strictly sequentially via for..of — never parallel
 *   (D-12 deterministic order; RESEARCH Anti-Patterns).
 * - A failing collector keeps its completed rows, emits a safeErrorMessage-
 *   sanitized section-error event, records the error on its SectionResult,
 *   and the run continues to the remaining sections.
 * - A per-section fresh circuit breaker + fresh CheckId sub-numberer mirror
 *   Initialize-SecurityConfig's fresh-context-per-collector isolation
 *   (Pitfall 5: a shared counter breaks dual-run parity; D-19 lock tests).
 * - Every Graph call reaches the event stream as method/url/status (D-25):
 *   when constructed via createTransport, the engine wires the transport's
 *   onPage/onWarning channels into graph-call / page-cap-warning events.
 * - After the loop and BEFORE run-finished, runEngine applies the licensing
 *   overlay (D-20) over every section's rows using subscribedSkus states from
 *   the shared store. If no subscribedSkus were collected (Licensing not run),
 *   overlay application is skipped and reported in RunResult — SKU state is
 *   never guessed (fail-explicit pattern).
 * - The engine is an in-memory library: sections in → result object out;
 *   no runs/results persistence here (D-08, schema deferred to Phase 3).
 */

/** Result of one section's execution (D-13 partials preserved). */
export interface SectionResult {
  sectionId: string;
  rows: CheckRow[];
  /** safeErrorMessage-sanitized collector/section failure, if any. */
  error?: string;
}

export interface RunResult {
  tenantId: string;
  sections: SectionResult[];
  /**
   * Whether the D-20 licensing overlay was applied post-run. False means no
   * subscribedSkus were collected (Licensing section absent) — never guessed.
   */
  licensingOverlayApplied?: boolean;
}

/**
 * Collector-facing execution context for one section. Collectors call addRow()
 * to emit findings; all Graph access goes through the guarded transport.
 */
export interface SectionContext {
  transport: Transport;
  /** This section's id (mirrors AssessmentMaps keys). */
  sectionId: string;
  /**
   * Emit a completed check row. Applies, in order: circuit-breaker
   * short-circuit → mapStatus(psStatus) → fresh-per-section CheckId
   * sub-numbering → D-22 registry remediation fallback → check-completed
   * event. Returns the immutable row appended to the result.
   */
  addRow(input: CheckRowInput): CheckRow;
  /** Emit an engine event into the run's stream (D-09). */
  emit(event: EngineEvent): void;
  /**
   * Cross-section scratch store shared by ALL sections of one run. The
   * Licensing collector writes ctx.shared.set("subscribedSkus", skus) so
   * runEngine post-processing can feed applyLicensingOverlay (D-20).
   */
  shared: Map<string, unknown>;
}

/** A ported collector: async function that emits rows through the context. */
export type SectionImplementation = (ctx: SectionContext) => Promise<void>;

/** Handlers the engine injects into a caller-supplied transport factory. */
export interface TransportHandlers {
  onPage(event: GraphCallEvent): void;
  onWarning(message: string): void;
}

/** Factory so the engine can wire transport channels into the event sink. */
export type TransportFactory = (handlers: TransportHandlers) => Transport;

/** Pre-loaded controls (dependency-injected by tests); defaults read from disk. */
export interface EngineControls {
  registry: ControlRegistry;
  overlay: LicensingOverlay;
}

export interface RunEngineOptions {
  tenantId: string;
  sectionIds: string[];
  /** Exactly one of transport / createTransport must be provided. */
  transport?: Transport;
  createTransport?: TransportFactory;
  sink: EngineEventSink;
  /** Injected by the caller/wiring plan; missing entries are unported sections. */
  implementations: Record<string, SectionImplementation>;
  /** Defaults to loading src/M365-Assess/controls/{registry,licensing-overlay}.json. */
  controls?: EngineControls;
}

const SUBSCRIBED_SKUS_KEY = "subscribedSkus";

/** Matches GraphTransport's page-cap warning format (stable in-repo). */
const PAGE_CAP_PATTERN =
  /^GraphTransport: page cap \((\d+)\) reached for '([^']+)' — results may be incomplete\./;

function buildLookupMap(registry: ControlRegistry): Map<string, RegistryCheckEntry> {
  const map = new Map<string, RegistryCheckEntry>();
  for (const entry of registry.checks ?? []) {
    if (entry && typeof entry.checkId === "string") {
      map.set(entry.checkId, entry);
    }
  }
  return map;
}

export async function runEngine(opts: RunEngineOptions): Promise<RunResult> {
  // Transport resolution: exactly one channel.
  if (opts.transport && opts.createTransport) {
    throw new TypeError(
      "runEngine accepts either transport or createTransport, not both",
    );
  }
  if (!opts.transport && !opts.createTransport) {
    throw new TypeError("runEngine requires a transport or createTransport");
  }

  let graphCallsWired = false;
  let transport: Transport;
  if (opts.createTransport) {
    const factory = opts.createTransport;
    transport = factory({
      onPage: (event) => {
        graphCallsWired = true;
        opts.sink.emit({
          type: "graph-call",
          method: "GET", // GET-guard upstream guarantees this
          url: event.url,
          status: event.status,
        });
      },
      onWarning: (message) => {
        // Convert our own transport's page-cap warnings into typed events —
        // truncation is never silent (#952 lesson). Other warnings stay loud
        // on console rather than being swallowed.
        const match = PAGE_CAP_PATTERN.exec(message);
        if (match) {
          opts.sink.emit({
            type: "page-cap-warning",
            url: match[2],
            maxPages: Number(match[1]),
          });
        } else {
          console.warn(message);
        }
      },
    });
    void graphCallsWired;
  } else {
    // Caller-owned transport: they wired onPage themselves at construction.
    transport = opts.transport as Transport;
  }

  // Controls: injected (tests) or loaded unmodified from the source tree.
  const controls = opts.controls ?? {
    registry: loadRegistry(),
    overlay: loadLicensingOverlay(),
  };
  const registryLookup = buildLookupMap(controls.registry);

  const shared = new Map<string, unknown>();
  // Connected-tenant id available to collectors that need tenant-scoped URLs
  // (e.g. /v1.0/organization/{tenantId} in the LinkedIn check). Mirrors the PS
  // shared-scope $context.TenantId.
  shared.set("tenantId", opts.tenantId);
  const results: SectionResult[] = [];

  opts.sink.emit({
    type: "run-started",
    tenantIds: [opts.tenantId],
    sections: [...opts.sectionIds],
  });

  for (const sectionId of opts.sectionIds) {
    opts.sink.emit({ type: "section-started", sectionId });

    const impl = opts.implementations[sectionId];
    const rows: CheckRow[] = [];
    let sectionError: string | undefined;

    if (!impl) {
      // D-10: unported sections throw not-yet-implemented semantics as an
      // explicit surfaced error — never silently produce zero rows with no
      // explanation, and never fabricate placeholder findings.
      sectionError = `Section '${sectionId}' is registered but not implemented yet`;
      opts.sink.emit({ type: "section-error", sectionId, message: sectionError });
    } else {
      // Fresh isolation per section execution (Pitfall 5 / D-19).
      const breaker = createCircuitBreaker();
      const subnumberer = createCheckIdSubnumberer();

      const ctx: SectionContext = {
        transport,
        sectionId,
        shared,
        emit: (event: EngineEvent) => opts.sink.emit(event),
        addRow(input: CheckRowInput): CheckRow {
          // Circuit breaker short-circuit: once tripped, subsequent rows are
          // Skipped(circuit_broken) without further evaluation (D-13). The
          // run itself is NEVER killed.
          if (breaker.shouldTrip()) {
            const row: CheckRow = {
              category: input.category,
              setting: input.setting,
              currentValue: input.currentValue ?? "",
              recommendedValue: input.recommendedValue ?? "",
              status: "Skipped",
              skipReason: "circuit_broken",
              checkId: subnumberer.subNumber(input.checkId ?? ""),
              remediation: input.remediation ?? "",
              intentDesign: input.intentDesign ?? false,
            };
            rows.push(row);
            opts.sink.emit({ type: "check-completed", sectionId, row });
            return row;
          }

          const mapped = mapStatus(input.psStatus);
          const baseCheckId = input.checkId ?? "";
          let remediation = input.remediation ?? "";
          // D-22: empty remediation falls back to the registry entry text.
          if (remediation.trim() === "" && baseCheckId !== "") {
            remediation = registryRemediationText(registryLookup.get(baseCheckId));
          }
          const row: CheckRow = {
            category: input.category,
            setting: input.setting,
            currentValue: input.currentValue ?? "",
            recommendedValue: input.recommendedValue ?? "",
            status: mapped.status,
            skipReason: mapped.reason,
            checkId: subnumberer.subNumber(baseCheckId),
            remediation,
            intentDesign: input.intentDesign ?? false,
            ...(input.observedValue !== undefined && { observedValue: input.observedValue }),
            ...(input.expectedValue !== undefined && { expectedValue: input.expectedValue }),
            ...(input.evidenceSource !== undefined && { evidenceSource: input.evidenceSource }),
            ...(input.evidenceTimestamp !== undefined && {
              evidenceTimestamp: input.evidenceTimestamp,
            }),
            ...(input.collectionMethod !== undefined &&
              input.collectionMethod !== "" && {
                collectionMethod: input.collectionMethod,
              }),
            ...(input.permissionRequired !== undefined && {
              permissionRequired: input.permissionRequired,
            }),
            ...(input.confidence !== undefined && { confidence: input.confidence }),
            ...(input.limitations !== undefined && { limitations: input.limitations }),
          };
          rows.push(row);
          opts.sink.emit({ type: "check-completed", sectionId, row });

          // Breaker accounting: only SURFACED errors count (Pitfall 6) —
          // retries absorbed by the transport never reach here. A row whose
          // PS status mapped to Skipped(graph_error) IS a surfaced error
          // (D-16); any other completed row resets the streak.
          if (mapped.status === "Skipped" && mapped.reason === "graph_error") {
            breaker.recordFailure();
          } else {
            breaker.recordSuccess();
          }
          return row;
        },
      };

      try {
        await impl(ctx);
      } catch (err) {
        // Fail-soft (ENG-04 / Invoke-M365Assessment.ps1 catch parity):
        // keep partials, surface a sanitized error, continue the run.
        sectionError = safeErrorMessage(err);
        opts.sink.emit({ type: "section-error", sectionId, message: sectionError });
      }
    }

    results.push({ sectionId, rows, ...(sectionError !== undefined && { error: sectionError }) });
    opts.sink.emit({ type: "section-finished", sectionId });
  }

  // D-20 post-processing: gating executes in EVERY run without caller
  // involvement — but only when the Licensing collector actually collected
  // subscribedSkus. Missing SKU data skips application (never guessed).
  let licensingOverlayApplied = false;
  const skuStates = shared.get(SUBSCRIBED_SKUS_KEY);
  if (Array.isArray(skuStates)) {
    for (const section of results) {
      section.rows = applyLicensingOverlay(
        section.rows,
        controls.overlay,
        skuStates as SkuState[],
      );
    }
    licensingOverlayApplied = true;
  }

  const result: RunResult = {
    tenantId: opts.tenantId,
    sections: results,
    licensingOverlayApplied,
  };
  opts.sink.emit({ type: "run-finished", result });
  return result;
}
