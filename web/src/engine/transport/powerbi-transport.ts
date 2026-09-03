import { retryDelaySeconds } from "./retry-policy";
import { TransportFatalError } from "./graph-transport";

/**
 * Power BI admin API choke point — mirrors GraphTransport (D-24..D-28)
 * but host-pinned to api.powerbi.com and scoped to analysis.windows.net.
 *
 * Accepts absolute https://api.powerbi.com URLs or root-relative /v1.0/… paths
 * which are resolved to POWERBI_BASE. Pagination + retry + events identical.
 */

const POWERBI_BASE = "https://api.powerbi.com";

export class PowerBiError extends Error {
  readonly status: number;
  readonly url: string;
  constructor(status: number, url: string, detail: string) {
    super(`Power BI request failed (${status}) for ${url}: ${detail}`);
    this.name = "PowerBiError";
    this.status = status;
    this.url = url;
  }
}

export interface PowerBiCallEvent {
  method: string;
  url: string;
  status: number | null;
}

export interface PowerBiResponse {
  [key: string]: unknown;
  value?: unknown[];
}

export interface PowerBiTransportDeps {
  getToken: () => Promise<string>;
  fetchImpl: typeof fetch;
  onPage: (e: PowerBiCallEvent) => void;
  onWarning?: (message: string) => void;
  isRoleGranted: (requiredRole: string) => boolean;
  maxRetries?: number;
  maxPages?: number;
  delayFn?: (ms: number) => Promise<void>;
}

export interface GetJsonOptions {
  headers?: Record<string, string>;
  requiredRole?: string;
  method?: string;
}

interface FetchLikeResponse {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}

const RETRYABLE_STATUSES = new Set([429, 503, 504]);

async function describeErrorBody(response: FetchLikeResponse): Promise<string> {
  try {
    const body = (await response.json()) as { error?: { code?: unknown; message?: unknown } };
    const code = typeof body?.error?.code === "string" ? body.error.code : undefined;
    const message = typeof body?.error?.message === "string" ? body.error.message : undefined;
    const detail = [code, message].filter(Boolean).join(": ").trim();
    return detail.length > 0 ? detail.slice(0, 300) : "opaque error body";
  } catch {
    return "unreadable error body";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class PowerBiTransport {
  private readonly getToken: () => Promise<string>;
  private readonly fetchImpl: typeof fetch;
  private readonly onPage: (e: PowerBiCallEvent) => void;
  private readonly onWarning: (message: string) => void;
  private readonly isRoleGranted: (requiredRole: string) => boolean;
  private readonly maxRetries: number;
  private readonly maxPages: number;
  private readonly delayFn: (ms: number) => Promise<void>;

  constructor(deps: PowerBiTransportDeps) {
    this.getToken = deps.getToken;
    this.fetchImpl = deps.fetchImpl;
    this.onPage = deps.onPage;
    this.onWarning = deps.onWarning ?? ((m) => console.warn(m));
    this.isRoleGranted = deps.isRoleGranted;
    this.maxRetries = deps.maxRetries ?? 4;
    this.maxPages = deps.maxPages ?? 100;
    this.delayFn = deps.delayFn ?? sleep;
  }

  async getJson(pathOrUrl: string, opts?: GetJsonOptions): Promise<PowerBiResponse> {
    // Accept absolute Power BI URL or root-relative path; anything else fatal
    let baseUrl: string;
    if (pathOrUrl.startsWith("https://")) {
      let parsed: URL;
      try { parsed = new URL(pathOrUrl); } catch {
        throw new TransportFatalError(`unparseable Power BI URL refused: ${pathOrUrl.slice(0,128)}`);
      }
      if (parsed.host !== "api.powerbi.com") {
        throw new TransportFatalError(`cross-host Power BI URL refused (host pinning): ${parsed.host}`);
      }
      baseUrl = parsed.toString();
    } else if (pathOrUrl.startsWith("/")) {
      baseUrl = `${POWERBI_BASE}${pathOrUrl}`;
    } else {
      throw new TransportFatalError(
        `PowerBiTransport accepts absolute https://api.powerbi.com URLs or root-relative paths only, got: ${pathOrUrl.slice(0, 128)}`,
      );
    }

    const method = opts?.method ?? "GET";
    if (method.toUpperCase() !== "GET") {
      throw new TransportFatalError(`non-GET method '${method}' refused by read-only transport (D-24)`);
    }
    if (opts?.requiredRole && !this.isRoleGranted(opts.requiredRole)) {
      throw new TransportFatalError(`required role not granted for this call: ${opts.requiredRole}`);
    }

    let url = baseUrl;
    let firstPage: Record<string, unknown> | null = null;
    const allValues: unknown[] = [];
    let pageCount = 0;

    while (url) {
      pageCount += 1;
      if (pageCount > this.maxPages) {
        this.onWarning(
          `PowerBiTransport: page cap (${this.maxPages}) reached for '${pathOrUrl.slice(0,256)}' — results may be incomplete.`,
        );
        break;
      }
      const response = await this.fetchPageWithRetry(url, opts?.headers);
      if (!firstPage) firstPage = response;
      const isCollection = typeof response === "object" && response !== null && "value" in response;
      if (!isCollection) {
        if (pageCount === 1) return response as PowerBiResponse;
        break;
      }
      if (Array.isArray(response.value)) allValues.push(...response.value);
      const nextLink = response["@odata.nextLink"];
      url = typeof nextLink === "string" && nextLink.length > 0 ? this.resolveNextUrl(nextLink) : "";
    }

    const result: PowerBiResponse = {};
    if (firstPage) {
      for (const [k,v] of Object.entries(firstPage)) if (k !== "value" && k !== "@odata.nextLink") result[k]=v;
    }
    result.value = allValues;
    return result;
  }

  private resolveNextUrl(nextLink: string): string {
    if (nextLink.startsWith("/")) return `${POWERBI_BASE}${nextLink}`;
    let parsed: URL;
    try { parsed = new URL(nextLink); } catch {
      throw new TransportFatalError(`unparseable @odata.nextLink refused: ${nextLink.slice(0,128)}`);
    }
    if (parsed.protocol !== "https:" || parsed.host !== "api.powerbi.com") {
      throw new TransportFatalError(`cross-host @odata.nextLink refused (host pinning): ${parsed.host}`);
    }
    return parsed.toString();
  }

  private async fetchPageWithRetry(url: string, extraHeaders?: Record<string, string>): Promise<Record<string, unknown>> {
    const token = await this.getToken();
    let attempt = 0;
    while (true) {
      let response: FetchLikeResponse;
      try {
        response = (await this.fetchImpl(url, {
          method: "GET",
          headers: { Authorization: `Bearer ${token}`, ...extraHeaders },
        })) as FetchLikeResponse;
      } catch (err) {
        this.onPage({ method: "GET", url, status: null });
        attempt += 1;
        const delaySeconds = retryDelaySeconds(503, null, attempt);
        if (delaySeconds === null || attempt > this.maxRetries) throw err instanceof Error ? err : new Error(String(err));
        await this.delayFn(delaySeconds * 1000);
        continue;
      }
      this.onPage({ method: "GET", url, status: response.status });
      if (!response.ok) {
        if (!RETRYABLE_STATUSES.has(response.status)) throw new PowerBiError(response.status, url, await describeErrorBody(response));
        attempt += 1;
        const retryAfterHeader = response.headers.get("retry-after");
        const retryAfterSeconds = retryAfterHeader !== null && /^\d+(\.\d+)?$/.test(retryAfterHeader.trim()) ? Number(retryAfterHeader) : null;
        const delaySeconds = retryDelaySeconds(response.status, retryAfterSeconds, attempt);
        if (delaySeconds === null || attempt > this.maxRetries) throw new PowerBiError(response.status, url, `retries exhausted: ${await describeErrorBody(response)}`);
        await this.delayFn(delaySeconds * 1000);
        continue;
      }
      return (await response.json()) as Record<string, unknown>;
    }
  }
}
