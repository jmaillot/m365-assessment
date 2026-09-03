import type { CheckRow } from "../results/row-contract";
import type { RunResult } from "../runner/engine";

/**
 * Typed engine event stream (D-09 + D-25) — shapes LOCKED by the plan's
 * <interfaces> block (use RESEARCH example verbatim).
 *
 * Ordering guarantees under runEngine's sequential execution (D-12):
 *   run-started →
 *     (section-started → graph-call* / page-cap-warning* interleaved with
 *      check-completed* → section-error? → section-finished)* →
 *   run-finished
 *
 * Events carry method/url/status only — never tokens or tenant content
 * (T-02-02c / T-02-03c: all section-error messages are safeErrorMessage-
 * sanitized before emission).
 */
export type EngineEvent =
  | { type: "run-started"; tenantIds: string[]; sections: string[] }
  | { type: "section-started"; sectionId: string }
  | { type: "check-completed"; sectionId: string; row: CheckRow }
  | { type: "graph-call"; method: "GET"; url: string; status: number | null }
  | { type: "section-error"; sectionId: string; message: string }
  | { type: "section-finished"; sectionId: string }
  | { type: "page-cap-warning"; url: string; maxPages: number }
  | { type: "run-finished"; result: RunResult };

export interface EngineEventSink {
  emit(event: EngineEvent): void;
}
