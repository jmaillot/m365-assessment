/**
 * Dev CLI harness (plan 02-12 task 2, D-14) — the hands-on verification path
 * for the assessment engine:
 *
 *   npm run assess -- --tenant <tenant-guid> --section entra [--section licensing]
 *
 * Flow: parse/validate args → load the stored operator credential →
 * decryptOperatorSecret → clientId from AZURE_CLIENT_ID → GraphTransport with
 * getToken = cached client_credentials mint (getTokenForTenant wrapper) →
 * runEngine({ sink }) with IMPLEMENTATIONS → RunResult JSON on stdout.
 *
 * Credential ownership split (RESEARCH A4): the environment variable owns the
 * app/client-id bootstrap (it is deployment identity, not a secret); the ONE
 * client secret lives ONLY in the encrypted operator_credential row — never
 * in an env var, never printed (T-02-12c).
 *
 * Exit codes: 0 success · 2 usage/config errors (invalid GUID, unknown
 * section, missing credential/env). Usage errors fail BEFORE any network or
 * database access (T-02-12d: GUID validated before minting; the tenant id is
 * echoed in the run-started progress line for confirmation).
 */
import { pathToFileURL } from "node:url";

import {
  IMPLEMENTATIONS,
  type TransportFactory,
} from "@/engine";
import { runEngine } from "@/engine/runner/engine";
import type { EngineEvent, EngineEventSink } from "@/engine/events/engine-events";
import type { RunEngineOptions, RunResult } from "@/engine/runner/engine";
import { SECTION_REGISTRY } from "@/engine/registry/section-registry";
import {
  getGrantedRoles,
  getTokenForTenant,
  safeErrorMessage,
} from "@/engine/transport/graph-auth";
import { GraphTransport } from "@/engine/transport/graph-transport";

/** Entra tenant ids are GUIDs; enforced before anything touches the network. */
const GUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** "entra" is the operator-facing alias for the identity section's collectors. */
const SECTION_ALIASES: Record<string, string> = { entra: "identity" };

/** Usage/config error: always exit 2, never a stack trace. */
export class CliUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliUsageError";
  }
}

export interface ParsedArgs {
  tenantId: string;
  sections: string[];
}

/** Pure flag parsing: --tenant <guid> (required), --section <id> (repeatable). */
export function parseArgs(argv: string[]): ParsedArgs {
  let tenantId: string | undefined;
  const sections: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--tenant") {
      tenantId = argv[++i];
      if (!tenantId) throw new CliUsageError("--tenant requires a value");
    } else if (flag === "--section") {
      const value = argv[++i];
      if (!value) throw new CliUsageError("--section requires a value");
      sections.push(value);
    } else {
      throw new CliUsageError(`Unknown argument '${flag ?? ""}'`);
    }
  }

  if (!tenantId) {
    throw new CliUsageError(
      "--tenant <guid> is required (run with --help for usage)",
    );
  }
  if (!GUID_PATTERN.test(tenantId)) {
    throw new CliUsageError(
      "--tenant expects a GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
    );
  }
  return { tenantId, sections: sections.length > 0 ? sections : ["entra"] };
}

/**
 * Map aliases, normalize case, dedupe, and reject unknown ids with the list
 * of valid ones — all before any credential/network work.
 */
export function resolveSectionIds(requested: string[]): string[] {
  const valid = SECTION_REGISTRY.map((e) => e.id);
  const resolved: string[] = [];
  for (const raw of requested) {
    const lower = raw.toLowerCase();
    const id = SECTION_ALIASES[lower] ?? lower;
    if (!valid.includes(id)) {
      throw new CliUsageError(
        `Unknown section '${raw}'. Valid sections: ${valid.join(", ")}` +
          ` (alias: entra → identity)`,
      );
    }
    if (!resolved.includes(id)) resolved.push(id);
  }
  return resolved;
}

interface CliStreams {
  stdout: NodeJS.WriteStream | { write(s: string): void };
  stderr: NodeJS.WriteStream | { write(s: string): void };
}

export interface CliDeps {
  /** Defaults to process.stdout/stderr. */
  streams?: Partial<CliStreams>;
  /** Defaults to process.env. */
  env?: Record<string, string | undefined>;
  /**
   * Loads + decrypts the stored operator secret. Default reads the
   * operator_credential row via lib/settings (dynamic import — importing the
   * db singleton opens SQLite, which unit tests must never trigger).
   */
  loadOperatorSecret?: () => Promise<string>;
  /**
   * Lazy transport factory passed through to runEngine unchanged (the engine
   * invokes it once per run to wire onPage/onWarning into the event sink).
   * The default mints the first token eagerly so getGrantedRoles can back
   * the transport's sync isRoleGranted gate.
   */
  createTransport?: TransportFactory;
  /** Injectable engine entry point (tests stub it; default is real runEngine). */
  runEngineFn?: typeof runEngine;
}

function helpText(): string {
  return [
    "M365-Assess dev CLI — run assessment sections app-only against a tenant.",
    "",
    "Usage:",
    "  npm run assess -- --tenant <guid> [--section <id>]...",
    "",
    "Flags:",
    "  --tenant <guid>     Target Entra tenant id (GUID; validated before any",
    "                      network call). Echoed in the run-started line.",
    "  --section <id>      Repeatable. Registry section id or the 'entra' alias",
    "                      (= identity). Default: entra.",
    "  --help              Show this help.",
    "",
    "Credential ownership split:",
    "  - AZURE_CLIENT_ID (environment variable) owns the app/client-id bootstrap;",
    "    it is deployment identity, not a secret.",
    "  - The client secret comes exclusively from the stored OPERATOR CREDENTIAL",
    "    (encrypted row configured via Settings) — never an env var, never printed.",
    "  - App-role consent must be granted beforehand (see docs/web/APP-REGISTRATION-SETUP.md).",
    "",
    "Exit codes: 0 success · 2 usage/config errors.",
    "",
  ].join("\n");
}

/**
 * Default transport factory: mints the token up front (fail-fast on bad
 * credentials/consent), decodes its roles once for the transport's sync
 * isRoleGranted gate (D-26), then returns a factory whose getToken reuses
 * the cached near-expiry-aware mint.
 */
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

async function defaultLoadOperatorSecret(): Promise<string> {
  // Dynamic import ONLY: the settings module pulls the @/db singleton, which
  // opens SQLite and applies migrations at import time.
  const { decryptOperatorSecret } = await import(
    "@/lib/settings/operator-credential"
  );
  return decryptOperatorSecret();
}

function progressSink(streams: CliStreams): EngineEventSink {
  const rowsPerSection: Record<string, number> = {};
  const line = (message: string) => streams.stderr.write(`[assess] ${message}\n`);
  return {
    emit(event: EngineEvent) {
      switch (event.type) {
        case "run-started":
          // Tenant echoed for confirmation (T-02-12d).
          line(
            `run started tenant=${event.tenantIds[0]} sections=${event.sections.join(",")}`,
          );
          break;
        case "section-started":
          rowsPerSection[event.sectionId] = 0;
          line(`section started: ${event.sectionId}`);
          break;
        case "check-completed":
          rowsPerSection[event.sectionId] =
            (rowsPerSection[event.sectionId] ?? 0) + 1;
          break;
        case "graph-call":
          // Per-call audit stays in the engine event stream; too noisy for CLI.
          break;
        case "page-cap-warning":
          line(`page cap warning (${event.maxPages} pages): ${event.url}`);
          break;
        case "section-error":
          line(`section error (${event.sectionId}): ${event.message}`);
          break;
        case "section-finished":
          line(
            `section finished: ${event.sectionId} (${rowsPerSection[event.sectionId] ?? 0} rows)`,
          );
          break;
        case "run-finished":
          line("run finished");
          break;
      }
    },
  };
}

/**
 * Runs one CLI invocation end-to-end and returns the process exit code
 * (never calls process.exit directly so buffered stdout flushes normally).
 */
export async function runCli(argv: string[], deps: CliDeps = {}): Promise<number> {
  const streams: CliStreams = {
    stdout: deps.streams?.stdout ?? process.stdout,
    stderr: deps.streams?.stderr ?? process.stderr,
  };
  const errLine = (message: string) => streams.stderr.write(`${message}\n`);

  if (argv.includes("--help") || argv.includes("-h")) {
    streams.stdout.write(helpText());
    return 0;
  }

  // ---- usage validation (pre-network, pre-database) --------------------
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    errLine(err instanceof Error ? err.message : String(err));
    return 2;
  }
  let sectionIds: string[];
  try {
    sectionIds = resolveSectionIds(parsed.sections);
  } catch (err) {
    errLine(err instanceof Error ? err.message : String(err));
    return 2;
  }

  // ---- configuration: operator secret (DB) + client id (env) ----------
  let clientSecret: string;
  try {
    const load = deps.loadOperatorSecret ?? defaultLoadOperatorSecret;
    clientSecret = await load();
  } catch (err) {
    errLine(
      err instanceof CliUsageError
        ? err.message
        : `operator credential not configured (${safeErrorMessage(err)})`,
    );
    return 2;
  }

  const env = deps.env ?? process.env;
  const clientId = env.AZURE_CLIENT_ID;
  if (!clientId) {
    errLine(
      "AZURE_CLIENT_ID is not set — the environment variable owns the app " +
        "(client) id bootstrap while the operator secret stays in the database.",
    );
    return 2;
  }

  // ---- transport --------------------------------------------------------
  let createTransport: TransportFactory;
  if (deps.createTransport) {
    createTransport = deps.createTransport;
  } else {
    try {
      createTransport = await prepareGraphTransport(
        parsed.tenantId,
        clientId,
        clientSecret,
      );
    } catch (err) {
      errLine(`cannot start: ${safeErrorMessage(err)}`);
      return 2;
    }
  }

  // ---- run ---------------------------------------------------------------
  const opts: RunEngineOptions = {
    tenantId: parsed.tenantId,
    sectionIds,
    createTransport,
    sink: progressSink(streams),
    implementations: IMPLEMENTATIONS,
  };
  const runFn = deps.runEngineFn ?? runEngine;
  let result: RunResult;
  try {
    result = await runFn(opts);
  } catch (err) {
    errLine(`error: ${safeErrorMessage(err)}`);
    return 2;
  }

  streams.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return 0;
}

/** Process entry point: sets exit code, prints nothing extra. */
export async function main(argv: string[] = process.argv.slice(2)): Promise<void> {
  process.exitCode = await runCli(argv);
}

/* v8 ignore next -- executed only under `npm run assess`, not when imported. */
const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) void main();
