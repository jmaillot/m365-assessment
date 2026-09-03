/**
 * Recorded-replay fixture fetch factory (D-21).
 *
 * Returns a `typeof fetch` that replays recorded Graph JSON responses keyed by
 * request URL (normalized to path+query, scheme/host-insensitive). Collector
 * tests inject this into GraphTransport's fetchImpl so recorded real-tenant
 * payloads drive the exact same transport code path as live runs.
 *
 * - Multi-page entries ({value, "@odata.nextLink"}) are served VERBATIM; the
 *   nextLink URL is just another fixture key.
 * - Unknown URLs resolve a failing 404-style response whose error message
 *   names the missing key (and lists known keys) so tests fail loudly instead
 *   of silently returning empty collections — the #952 truncation lesson
 *   applied to test fixtures.
 * - opts.strictMethod rejects non-GET requests with a 405-style response,
 *   mirroring the read-only guarantee at the fixture layer too.
 */

export interface ReplayFetchOptions {
  /** Reject non-GET requests with a 405-style failing response. */
  strictMethod?: boolean;
}

interface ReplayResponseOptions {
  status: number;
  body: unknown;
}

/**
 * Normalize any request URL to "path?query" so absolute Graph URLs match
 * path-keyed fixtures ("/v1.0/users?$top=999"). Query order is preserved as
 * written in both key and request — keep fixture keys byte-stable.
 */
export function normalizeUrlKey(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Already-relative key: normalize leading slash only.
    return url.startsWith("/") ? url : `/${url}`;
  }
  return `${parsed.pathname}${parsed.search}`;
}

function createReplayResponse(options: ReplayResponseOptions): Response {
  const bodyText = JSON.stringify(options.body);
  const response = new Response(bodyText, {
    status: options.status,
    headers: { "content-type": "application/json" },
  });
  return response;
}

export function createReplayFetch(
  fixtures: Record<string, unknown>,
  opts?: ReplayFetchOptions,
): typeof fetch {
  return async function replayFetch(
    input: string | URL | RequestInfo,
    init?: RequestInit,
  ): Promise<Response> {
    const method = (init?.method ?? "GET").toUpperCase();
    if (opts?.strictMethod && method !== "GET") {
      return createReplayResponse({
        status: 405,
        body: {
          error: {
            code: "methodNotAllowed",
            message: `Replay fixtures serve GET only; received ${method} (read-only parity)`,
          },
        },
      });
    }

    const rawUrl =
      typeof input === "string" || input instanceof URL ? String(input) : input.url;
    const key = normalizeUrlKey(rawUrl);

    if (!(key in fixtures)) {
      const known = Object.keys(fixtures).join(", ");
      return createReplayResponse({
        status: 404,
        body: {
          error: {
            code: "fixtureNotFound",
            message:
              `No fixture recorded for '${key}'. ` +
              (known.length > 0 ? `Known fixture keys: [${known}]` : "Fixture set is empty."),
          },
        },
      });
    }

    return createReplayResponse({ status: 200, body: fixtures[key] });
  };
}
