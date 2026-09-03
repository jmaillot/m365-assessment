import { retryDelaySeconds } from "./retry-policy";

/**
 * The single Graph choke point for the assessment engine (ENG-03).
 *
 * Every Graph call routes through GraphTransport.getJson, which enforces:
 * - GET-only (D-24): any other method is a programming bug — fatal, before
 *   any fetch.
 * - Roles assertion (D-26): when a call declares a requiredRole, the token's
 *   coverage is asserted pre-dispatch via the injected isRoleGranted check
 *   (registry-driven at the call site; the transport never parses tokens
 *   itself, keeping it mockable and Graph-shape-only).
 * - Automatic pagination (D-27): @odata.nextLink is always followed with
 *   value[] merged across pages and first-page metadata preserved — callers
 *   cannot make an unpaged list call. Absolute nextLinks are host-pinned to
 *   graph.microsoft.com (SSRF guard); anything else aborts fatally without
 *   being fetched. Page caps warn loudly — truncation is never silent
 *   (the #952 lesson).
 * - Throttle-aware retry (D-28): 429/503/504 retried up to maxRetries with
 *   Retry-After precedence else exponential backoff, computed by the pure
 *   retryDelaySeconds() port of Get-GraphRetryDelay.
 * - Per-call events (D-25): onPage fires after EVERY page attempt (including
 *   failures) carrying method/url/status only — never tokens or bodies
 *   (T-02-02c).
 *
 * The transport speaks Graph REST only in v1 (D-29); its shape keeps the
 * request pipeline generic enough for non-Graph M365 REST endpoints to slot
 * in during later domain phases.
 */

/** Base URL every relative path is resolved against in v1. */
const GRAPH_BASE = "https://graph.microsoft.com";

/** Fatal errors: bugs or hostile input — callers must abort the entire run. */
export class TransportFatalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransportFatalError";
  }
}

/** Surfaced after retries are exhausted or a non-retryable HTTP failure. */
export class GraphError extends Error {
  readonly status: number;
  readonly url: string;

  constructor(status: number, url: string, detail: string) {
    super(`Graph request failed (${status}) for ${url}: ${detail}`);
    this.name = "GraphError";
    this.status = status;
    this.url = url;
  }
}

/** Audit event per page attempt — method/url/status only (T-02-02c). */
export interface GraphCallEvent {
  method: string;
  url: string;
  status: number | null;
}

/** Rebuilt response: first-page metadata + merged value[] across pages. */
export interface GraphResponse {
  [key: string]: unknown;
  value?: unknown[];
}

export interface GraphTransportDeps {
  getToken: () => Promise<string>;
  /** Injected → recorded-replay fixtures (D-21). */
  fetchImpl: typeof fetch;
  /** Every page call logged (D-25). */
  onPage: (e: GraphCallEvent) => void;
  /** Loud channel for truncation warnings — never silent caps. */
  onWarning?: (message: string) => void;
  /** Registry-driven roles check (D-26). */
  isRoleGranted: (requiredRole: string) => boolean;
  /** Retries per page for transient statuses (PS parity default 4). */
  maxRetries?: number;
  /** Safety cap on pages followed (PS parity default 100). */
  maxPages?: number;
  /**
   * Injectable wait so tests advance instantly; defaults to setTimeout.
   * Receives milliseconds (delay seconds × 1000 from retryDelaySeconds).
   */
  delayFn?: (ms: number) => Promise<void>;
}

export interface GetJsonOptions {
  headers?: Record<string, string>;
  requiredRole?: string;
  /**
   * Present ONLY so misuse fails fatally at the guard instead of as a type
   * error on untyped call sites — the transport dispatches GET exclusively.
   */
  method?: string;
}

/** Minimal response surface the transport consumes (duck-typed fixtures OK). */
interface FetchLikeResponse {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}

const RETRYABLE_STATUSES = new Set([429, 503, 504]);

/**
 * Best-effort extraction of the Graph error body for the surfaced message.
 * Collector ports match on error TEXT exactly like PowerShell does
 * (Get-UserSummary.ps1:61 matches 'signInActivity|AuditLog|
 * Authorization_RequestDenied|Insufficient privileges|Neither combinator'),
 * which is impossible when GraphError carries only a generic detail string.
 * Method/url/status-only hygiene still holds for events; this text flows in
 * Error messages only and is length-capped.
 */
async function describeErrorBody(response: FetchLikeResponse): Promise<string> {
  try {
    const body = (await response.json()) as {
      error?: { code?: unknown; message?: unknown };
    };
    const code =
      typeof body?.error?.code === "string" ? body.error.code : undefined;
    const message =
      typeof body?.error?.message === "string" ? body.error.message : undefined;
    const detail = [code, message].filter(Boolean).join(": ").trim();
    return detail.length > 0 ? detail.slice(0, 300) : "opaque error body";
  } catch {
    return "unreadable error body";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class GraphTransport {
  private readonly getToken: () => Promise<string>;
  private readonly fetchImpl: typeof fetch;
  private readonly onPage: (e: GraphCallEvent) => void;
  private readonly onWarning: (message: string) => void;
  private readonly isRoleGranted: (requiredRole: string) => boolean;
  private readonly maxRetries: number;
  private readonly maxPages: number;
  private readonly delayFn: (ms: number) => Promise<void>;

  constructor(deps: GraphTransportDeps) {
    this.getToken = deps.getToken;
    this.fetchImpl = deps.fetchImpl;
    this.onPage = deps.onPage;
    this.onWarning = deps.onWarning ?? ((message) => console.warn(message));
    this.isRoleGranted = deps.isRoleGranted;
    this.maxRetries = deps.maxRetries ?? 4;
    this.maxPages = deps.maxPages ?? 100;
    this.delayFn = deps.delayFn ?? sleep;
  }

  async getJson(
    pathAndQuery: string,
    opts?: GetJsonOptions,
  ): Promise<GraphResponse> {
    // 1. Relative-of-root input only — anything else is rejected before it
    // can influence which host we talk to.
    if (!pathAndQuery.startsWith("/")) {
      throw new TransportFatalError(
        `transport accepts root-relative paths only (must start with '/'), got: ${pathAndQuery.slice(0, 128)}`,
      );
    }

    // 2. GET-only guard FIRST (D-24): a non-GET attempt is always a
    // programming bug — fatal, before any fetch or event.
    const method = opts?.method ?? "GET";
    if (method.toUpperCase() !== "GET") {
      throw new TransportFatalError(
        `non-GET method '${method}' refused by read-only transport (D-24)`,
      );
    }

    // 3. Roles assertion pre-dispatch (D-26): zero fetches when uncovered.
    if (opts?.requiredRole && !this.isRoleGranted(opts.requiredRole)) {
      throw new TransportFatalError(
        `required role not granted for this call: ${opts.requiredRole}`,
      );
    }

    let url = `${GRAPH_BASE}${pathAndQuery}`;
    let firstPage: Record<string, unknown> | null = null;
    const allValues: unknown[] = [];
    let pageCount = 0;

    while (url) {
      pageCount += 1;
      if (pageCount > this.maxPages) {
        // Never silent truncation (#952 lesson).
        this.onWarning(
          `GraphTransport: page cap (${this.maxPages}) reached for '${pathAndQuery.slice(0, 256)}' — results may be incomplete. Raise maxPages if the tenant legitimately has more data.`,
        );
        break;
      }

      const response = await this.fetchPageWithRetry(url, opts?.headers);

      if (!firstPage) firstPage = response;

      // Non-collection response: nothing to merge, return as-is (PS parity).
      // Scalar JSON bodies are valid non-collection responses too — Graph
      // $count endpoints return bare numbers — so the membership probe must
      // be guarded before applying the in-operator (primitives would throw).
      const isCollection =
        typeof response === "object" && response !== null && "value" in response;
      if (!isCollection) {
        if (pageCount === 1) return response as GraphResponse;
        break;
      }

      if (Array.isArray(response.value)) allValues.push(...response.value);

      const nextLink = response["@odata.nextLink"];
      url =
        typeof nextLink === "string" && nextLink.length > 0
          ? this.resolveNextUrl(nextLink)
          : "";
    }

    // Rebuild the familiar response shape: first-page metadata + merged value.
    const result: GraphResponse = {};
    if (firstPage) {
      for (const [key, val] of Object.entries(firstPage)) {
        if (key !== "value" && key !== "@odata.nextLink") result[key] = val;
      }
    }
    result.value = allValues;
    return result;
  }

  /**
   * Host-pinning SSRF guard (T-02-02b): relative nextLinks resolve against
   * GRAPH_BASE; absolute ones must be https://graph.microsoft.com or the run
   * aborts fatally WITHOUT fetching the hostile URL.
   */
  private resolveNextUrl(nextLink: string): string {
    if (nextLink.startsWith("/")) return `${GRAPH_BASE}${nextLink}`;
    let parsed: URL;
    try {
      parsed = new URL(nextLink);
    } catch {
      throw new TransportFatalError(
        `unparseable @odata.nextLink refused: ${nextLink.slice(0, 128)}`,
      );
    }
    if (parsed.protocol !== "https:" || parsed.host !== "graph.microsoft.com") {
      throw new TransportFatalError(
        `cross-host @odata.nextLink refused (host pinning): ${parsed.host}`,
      );
    }
    return parsed.toString();
  }

  /** One page fetch with D-28 throttle-aware retry and per-attempt events. */
  private async fetchPageWithRetry(
    url: string,
    extraHeaders?: Record<string, string>,
  ): Promise<Record<string, unknown>> {
    const token = await this.getToken();
    let attempt = 0;

    while (true) {
      let response: FetchLikeResponse;
      try {
        response = (await this.fetchImpl(url, {
          method: "GET",
          // Extra headers forwarded verbatim alongside the bearer token
          // (Pitfall 2: ConsistencyLevel: eventual for advanced queries).
          headers: { Authorization: `Bearer ${token}`, ...extraHeaders },
        })) as FetchLikeResponse;
      } catch (err) {
        // Network-level failure: transient-shaped, retry like a 5xx.
        this.onPage({ method: "GET", url, status: null });
        attempt += 1;
        const delaySeconds = retryDelaySeconds(503, null, attempt);
        if (delaySeconds === null || attempt > this.maxRetries) {
          throw err instanceof Error ? err : new Error(String(err));
        }
        await this.delayFn(delaySeconds * 1000);
        continue;
      }

      this.onPage({ method: "GET", url, status: response.status });

      if (!response.ok) {
        if (!RETRYABLE_STATUSES.has(response.status)) {
          throw new GraphError(
            response.status,
            url,
            await describeErrorBody(response),
          );
        }
        attempt += 1;
        const retryAfterHeader = response.headers.get("retry-after");
        const retryAfterSeconds =
          retryAfterHeader !== null && /^\d+(\.\d+)?$/.test(retryAfterHeader.trim())
            ? Number(retryAfterHeader)
            : null;
        const delaySeconds = retryDelaySeconds(
          response.status,
          retryAfterSeconds,
          attempt,
        );
        if (delaySeconds === null || attempt > this.maxRetries) {
          throw new GraphError(
            response.status,
            url,
            `retries exhausted: ${await describeErrorBody(response)}`,
          );
        }
        await this.delayFn(delaySeconds * 1000);
        continue;
      }

      return (await response.json()) as Record<string, unknown>;
    }
  }
}
