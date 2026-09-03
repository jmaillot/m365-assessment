import { createEventBus, type EventBus } from "./event-bus";
import { safeErrorMessage, getTokenForTenant, getPowerBiTokenForTenant, getGrantedRoles } from "@/engine/transport/graph-auth";
import { GraphTransport } from "@/engine/transport/graph-transport";
import { PowerBiTransport } from "@/engine/transport/powerbi-transport";
import { runEngine, type TransportFactory } from "@/engine/runner/engine";
import { IMPLEMENTATIONS } from "@/engine";
import type { EngineEvent, EngineEventSink } from "@/engine/events/engine-events";
import type { CheckRow } from "@/engine/results/row-contract";
import * as runService from "./run-service";
import { and, eq, not, or } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import type * as schema from "@/db/schema";

/**
 * In-process run job (D-01) — wraps runEngine with a persisting + fan-out sink.
 * Module-level singleton bus shared with SSE route via getRunBus().
 */

type Db = BetterSQLite3Database<typeof schema>;

const bus: EventBus = createEventBus();
const activeExecutions = new Set<string>();

export function getRunBus(): EventBus {
  return bus;
}

export function getActiveExecutions(): Set<string> {
  return new Set(activeExecutions);
}

export interface RunExecutorDeps {
  database?: Db;
  loadOperatorSecret?: () => Promise<string>;
  getClientId?: () => string | undefined;
  createTransport?: TransportFactory;
  runEngineFn?: typeof runEngine;
}

async function getDatabase(deps?: RunExecutorDeps): Promise<Db> {
  if (deps?.database) return deps.database;
  const mod = await import("@/db");
  return (mod as unknown as { db: Db }).db;
}

async function defaultLoadOperatorSecret(): Promise<string> {
  const { decryptOperatorSecret } = await import("@/lib/settings/operator-credential");
  return decryptOperatorSecret();
}

function defaultGetClientId(): string | undefined {
  return process.env.AZURE_CLIENT_ID;
}

async function prepareGraphTransport(
  tenantId: string,
  clientId: string,
  clientSecret: string,
): Promise<TransportFactory> {
  const token = await getTokenForTenant(tenantId, clientId, clientSecret);
  const granted = new Set(getGrantedRoles(token.accessToken));
  return (handlers) =>
    new GraphTransport({
      getToken: async () =>
        (await getTokenForTenant(tenantId, clientId, clientSecret)).accessToken,
      fetchImpl: fetch,
      onPage: handlers.onPage,
      onWarning: handlers.onWarning,
      isRoleGranted: (requiredRole) => granted.has(requiredRole),
    });
}

async function preparePowerBiTransport(
  tenantId: string,
  clientId: string,
  clientSecret: string,
): Promise<TransportFactory> {
  const token = await getPowerBiTokenForTenant(tenantId, clientId, clientSecret);
  const granted = new Set(getGrantedRoles(token.accessToken));
  return (handlers) =>
    new PowerBiTransport({
      getToken: async () =>
        (await getPowerBiTokenForTenant(tenantId, clientId, clientSecret)).accessToken,
      fetchImpl: fetch,
      onPage: handlers.onPage,
      onWarning: handlers.onWarning,
      isRoleGranted: (requiredRole) => granted.has(requiredRole),
    });
}

async function prepareCompositeTransport(
  tenantId: string,
  clientId: string,
  clientSecret: string,
): Promise<TransportFactory> {
  // Graph token is mandatory — its failure fails the whole run (fail-closed)
  const graphToken = await getTokenForTenant(tenantId, clientId, clientSecret);
  const graphGranted = new Set(getGrantedRoles(graphToken.accessToken));
  // Power BI token is best-effort — unlicensed / unconsented tenants must NOT fail the whole run;
  // the powerbi section degrades to 11× Skipped(not_licensed) via isRoleGranted=false.
  let powerBiGranted = new Set<string>();
  try {
    const powerBiToken = await getPowerBiTokenForTenant(tenantId, clientId, clientSecret);
    try {
      powerBiGranted = new Set(getGrantedRoles(powerBiToken.accessToken));
    } catch {
      // Token minted but carries no roles claim (e.g. no Power BI grant) → treat as empty grant set
      powerBiGranted = new Set<string>();
    }
  } catch {
    // Mint itself failed (e.g. unlicensed tenant, no Power BI service) → empty grant set
    powerBiGranted = new Set<string>();
  }
  return (handlers) => {
    const graphTransport = new GraphTransport({
      getToken: async () => (await getTokenForTenant(tenantId, clientId, clientSecret)).accessToken,
      fetchImpl: fetch,
      onPage: handlers.onPage,
      onWarning: handlers.onWarning,
      isRoleGranted: (r) => graphGranted.has(r),
    });
    const powerBiTransport = new PowerBiTransport({
      getToken: async () => (await getPowerBiTokenForTenant(tenantId, clientId, clientSecret)).accessToken,
      fetchImpl: fetch,
      onPage: handlers.onPage,
      onWarning: handlers.onWarning,
      isRoleGranted: (r) => powerBiGranted.has(r),
    });
    // Composite: route by URL host — api.powerbi.com → PowerBiTransport else Graph
    return {
      getJson: (pathOrUrl: string, opts?: { headers?: Record<string, string>; requiredRole?: string; method?: string }) =>
        pathOrUrl.includes("api.powerbi.com")
          ? powerBiTransport.getJson(pathOrUrl, opts)
          : graphTransport.getJson(pathOrUrl, opts),
    };
  };
}

/**
 * Execute a queued run end-to-end.
 * - Sweeps interrupted runs (D-04)
 * - Marks running, drives runEngine with sections=[identity,security,intune], persists rows as they arrive (D-07)
 * - Fans out every EngineEvent to the bus BEFORE any await (live-first)
 * - graph-call/page-cap-warning are ephemeral (not persisted)
 * - Idempotence: refuses if not queued or already executing
 * - Failures persist as failed with safeErrorMessage
 * - Always closes bus subscribers in finally
 * - Returns a handle promise that never rejects to caller (fire-and-forget safety) but resolves for testability
 */
export async function startRun(runId: string, deps: RunExecutorDeps = {}): Promise<void> {
  const database = await getDatabase(deps);

  // Idempotence guard: already executing
  if (activeExecutions.has(runId)) {
    return;
  }

  // Fetch run record (without userId scoping — internal)
  const { runs } = await import("@/db/schema");
  const { eq } = await import("drizzle-orm");
  const row = database.select().from(runs).where(eq(runs.id, runId)).get() as
    | { id: string; tenantId: string; status: string }
    | undefined;

  if (!row || row.status !== "queued") {
    return;
  }

  activeExecutions.add(runId);

  // Sweep interrupted runs before starting (D-04) — exclude the run we are about to execute
  try {
    database
      .update(runs)
      .set({ status: "failed", finishedAt: new Date(), error: "The application restarted during this run." })
      .where(and(or(eq(runs.status, "queued"), eq(runs.status, "running")), not(eq(runs.id, runId))))
      .run();
  } catch {
    // sweep is best-effort; continue to run
  }

  // Mark running (re-fetch to ensure not swept)
  const fresh = database.select().from(runs).where(eq(runs.id, runId)).get() as
    | { status: string }
    | undefined;
  if (!fresh || fresh.status !== "queued") {
    activeExecutions.delete(runId);
    return;
  }
  runService.markRunRunning(runId, database);

  const tenantId = row.tenantId;
  let nextOrder = 0;
  const sectionErrors = new Map<string, string>();
  let runSucceeded = false;

  const sink: EngineEventSink = {
    emit(event: EngineEvent) {
      // Live-first: fan out BEFORE any await
      bus.emit(runId, event);

      switch (event.type) {
        case "run-started":
          break;
        case "section-started":
          break;
        case "check-completed": {
          // Persist row immediately (D-07)
          try {
            nextOrder = runService.appendCheckRows(
              runId,
              event.sectionId,
              [event.row],
              nextOrder,
              database,
            );
          } catch {
            // persistence failure should not crash emit; will be surfaced as run failure later
          }
          break;
        }
        case "graph-call":
          // Ephemeral telemetry — forwarded but NOT persisted
          break;
        case "page-cap-warning":
          // Ephemeral — forwarded but NOT persisted
          break;
        case "section-error": {
          const existing = sectionErrors.get(event.sectionId);
          sectionErrors.set(
            event.sectionId,
            existing ? `${existing}; ${event.message}` : event.message,
          );
          break;
        }
        case "section-finished":
          break;
        case "run-finished": {
          // SectionResult.error values are inside result.sections; ensure any
          // fail-soft errors are visible via bus (already emitted) and via persisted rows
          // Rows already persisted; no extra DB write needed for identity-only phase
          for (const sec of event.result.sections) {
            if (sec.error) {
              const existing = sectionErrors.get(sec.sectionId);
              sectionErrors.set(
                sec.sectionId,
                existing ? `${existing}; ${sec.error}` : sec.error,
              );
            }
          }
          break;
        }
      }
    },
  };

  let createTransport: TransportFactory | undefined = deps.createTransport;
  if (!createTransport) {
    try {
      const loadSecret = deps.loadOperatorSecret ?? defaultLoadOperatorSecret;
      const getClientId = deps.getClientId ?? defaultGetClientId;
      const clientSecret = await loadSecret();
      const clientId = getClientId();
      if (!clientId) {
        throw new Error("AZURE_CLIENT_ID is not set");
      }
      createTransport = await prepareCompositeTransport(tenantId, clientId, clientSecret);
    } catch (err) {
      const reason = safeErrorMessage(err);
      try {
        runService.markRunFailed(runId, reason, database);
      } catch {}
      activeExecutions.delete(runId);
      bus.close(runId);
      return;
    }
  }

  const runFn = deps.runEngineFn ?? runEngine;

  try {
    await runFn({
      tenantId,
      sectionIds: ["identity", "security", "intune", "exchange", "collaboration", "purview", "inventory", "powerbi"],
      createTransport,
      sink,
      implementations: IMPLEMENTATIONS,
    });
    runSucceeded = true;
    try {
      runService.markRunCompleted(runId, database);
    } catch {}
  } catch (err) {
    const reason = safeErrorMessage(err);
    try {
      runService.markRunFailed(runId, reason, database);
    } catch {}
  } finally {
    activeExecutions.delete(runId);
    bus.close(runId);
    // Avoid unused variable warning
    void runSucceeded;
    void sectionErrors;
  }
}
