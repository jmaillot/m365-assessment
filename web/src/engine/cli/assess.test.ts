/**
 * Tests for the dev CLI harness (plan 02-12 task 2, D-14).
 *
 * Contract under test:
 * - parseArgs: flag parsing + GUID validation + repeatable --section.
 * - resolveSectionIds: "entra" alias → identity, unknown ids rejected with a
 *   listing of valid ids.
 * - runCli: usage/config errors exit 2 BEFORE any network call; a missing
 *   operator credential surfaces the explicit "operator credential not
 *   configured" message without a stack trace; the happy path emits one
 *   stderr progress line per engine lifecycle event and prints the RunResult
 *   JSON to stdout.
 * All external effects (credential loading, transport creation, runEngine)
 * are injected — these tests never touch the network or the database.
 */
import { describe, expect, it } from "vitest";

import type { RunEngineOptions, RunResult } from "@/engine/runner/engine";

import {
  CliUsageError,
  parseArgs,
  resolveSectionIds,
  runCli,
} from "./assess";

const VALID_GUID = "00000000-0000-0000-0000-000000000000";

function makeRunResult(sections: string[]): RunResult {
  return {
    tenantId: VALID_GUID,
    sections: sections.map((sectionId) => ({
      sectionId,
      rows: [],
    })),
    licensingOverlayApplied: false,
  };
}

/** Captures stream writes so assertions stay string-based. */
function captureStreams() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    stdout: { write: (s: string) => void out.push(s) },
    stderr: { write: (s: string) => void err.push(s) },
  };
}

describe("parseArgs", () => {
  it("parses --tenant and --section into tenantId + sections array", () => {
    expect(
      parseArgs(["--tenant", VALID_GUID, "--section", "entra"]),
    ).toEqual({ tenantId: VALID_GUID, sections: ["entra"] });
  });

  it("accepts repeated --section flags in order", () => {
    expect(
      parseArgs([
        "--tenant",
        VALID_GUID,
        "--section",
        "tenant",
        "--section",
        "licensing",
      ]),
    ).toEqual({ tenantId: VALID_GUID, sections: ["tenant", "licensing"] });
  });

  it("defaults to the entra section when --section is omitted", () => {
    expect(parseArgs(["--tenant", VALID_GUID])).toEqual({
      tenantId: VALID_GUID,
      sections: ["entra"],
    });
  });

  it("rejects an invalid tenant GUID before anything else can happen", () => {
    expect(() =>
      parseArgs(["--tenant", "../../etc/passwd", "--section", "entra"]),
    ).toThrow(CliUsageError);
    expect(() =>
      parseArgs(["--tenant", "not-a-guid", "--section", "entra"]),
    ).toThrow(/--tenant expects a GUID/i);
  });

  it("rejects missing --tenant", () => {
    expect(() => parseArgs([])).toThrow(CliUsageError);
    expect(() => parseArgs(["--section", "entra"])).toThrow(/--tenant/);
  });

  it("rejects unknown flags", () => {
    expect(() =>
      parseArgs(["--tenant", VALID_GUID, "--wat"]),
    ).toThrow(CliUsageError);
  });
});

describe("resolveSectionIds", () => {
  it("maps the entra alias onto the identity section", () => {
    expect(resolveSectionIds(["entra"])).toEqual(["identity"]);
    expect(resolveSectionIds(["ENTRA"])).toEqual(["identity"]);
  });

  it("passes registry ids through case-insensitively and dedupes", () => {
    expect(resolveSectionIds(["Tenant", "tenant", "Licensing"])).toEqual([
      "tenant",
      "licensing",
    ]);
  });

  it("errors on unknown sections listing the valid ids", () => {
    let message = "";
    try {
      resolveSectionIds(["nope"]);
    } catch (err) {
      message = err instanceof Error ? err.message : "";
    }
    expect(message).toMatch(/unknown section/i);
    expect(message).toMatch(/tenant/);
    expect(message).toMatch(/identity/);
    expect(message).toMatch(/licensing/);
  });
});

describe("runCli", () => {
  it("exits 2 with the usage error and NO network activity on a bad GUID", async () => {
    const streams = captureStreams();
    let transportCreated = false;
    let engineRan = false;
    const exit = await runCli(["--tenant", "bad-guid"], {
      streams,
      loadOperatorSecret: async () => {
        throw new Error("must not be called");
      },
      createTransport: () => {
        transportCreated = true;
        throw new Error("transport must not be created");
      },
      runEngineFn: async () => {
        engineRan = true;
        throw new Error("engine must not run");
      },
    });
    expect(exit).toBe(2);
    expect(streams.err.join("")).toMatch(/--tenant expects a GUID/i);
    // No stack trace dump — clean single-line usage error.
    expect(streams.err.join("")).not.toMatch(/\n\s+at /);
    expect(transportCreated).toBe(false);
    expect(engineRan).toBe(false);
  });

  it('exits 2 with "operator credential not configured" when the DB row is absent', async () => {
    const streams = captureStreams();
    let transportCreated = false;
    const exit = await runCli(["--tenant", VALID_GUID], {
      streams,
      loadOperatorSecret: async () => {
        throw new Error(
          "no operator credential configured — set the client secret first",
        );
      },
      createTransport: () => {
        transportCreated = true;
        throw new Error("transport must not be created");
      },
      runEngineFn: async () => makeRunResult(["identity"]),
    });
    expect(exit).toBe(2);
    const stderr = streams.err.join("");
    expect(stderr).toContain("operator credential not configured");
    expect(stderr).not.toMatch(/\n\s+at /); // never a stack trace
    expect(transportCreated).toBe(false);
  });

  it("exits 2 when AZURE_CLIENT_ID is unset (env owns clientId bootstrap)", async () => {
    const streams = captureStreams();
    const exit = await runCli(["--tenant", VALID_GUID], {
      streams,
      env: {},
      loadOperatorSecret: async () => "secret-value",
      createTransport: () => {
        throw new Error("transport must not be created");
      },
      runEngineFn: async () => makeRunResult(["identity"]),
    });
    expect(exit).toBe(2);
    expect(streams.err.join("")).toMatch(/AZURE_CLIENT_ID/i);
    expect(streams.err.join("")).not.toMatch(/\n\s+at /);
  });

  it("happy path: progress lines to stderr, RunResult JSON to stdout, exit 0", async () => {
    const streams = captureStreams();
    // Stub engine that drives the sink exactly like runEngine does.
    const runEngineFn = async (opts: RunEngineOptions): Promise<RunResult> => {
      opts.sink.emit({
        type: "run-started",
        tenantIds: [opts.tenantId],
        sections: [...opts.sectionIds],
      });
      for (const sectionId of opts.sectionIds) {
        opts.sink.emit({ type: "section-started", sectionId });
        opts.sink.emit({ type: "section-finished", sectionId });
      }
      const result = makeRunResult(opts.sectionIds);
      opts.sink.emit({ type: "run-finished", result });
      return result;
    };

    const seenImplementations: Array<RunEngineOptions["implementations"]> = [];
    const seenSectionIds: string[] = [];
    const exit = await runCli(
      ["--tenant", VALID_GUID, "--section", "entra"],
      {
        streams,
        env: { AZURE_CLIENT_ID: "client-id-value" },
        loadOperatorSecret: async () => "secret-value",
        createTransport: () => {
          throw new Error(
            "stubbed engine means no transport is ever constructed",
          );
        },
        runEngineFn: async (opts) => {
          seenImplementations.push(opts.implementations);
          seenSectionIds.push(...opts.sectionIds);
          return runEngineFn(opts);
        },
      },
    );

    expect(exit).toBe(0);

    // Sections resolved through the entra alias.
    expect(seenSectionIds).toEqual(["identity"]);
    // IMPLEMENTATIONS wired into the engine.
    expect(Object.keys(seenImplementations[0] as object)).toEqual(
      expect.arrayContaining(["tenant", "identity", "licensing"]),
    );
    // Stderr progress lines: run-started … section-started … section-finished … run-finished.
    const stderr = streams.err.join("");
    expect(stderr).toContain("run started");
    expect(stderr).toContain(VALID_GUID); // T-02-12d: tenant echoed for confirmation
    expect(stderr).toContain("section started: identity");
    expect(stderr).toContain("section finished: identity");

    // Stdout carries ONLY the RunResult JSON.
    expect(streams.out).toHaveLength(1);
    const parsed = JSON.parse(streams.out[0]) as RunResult;
    expect(parsed.tenantId).toBe(VALID_GUID);
    expect(parsed.sections.map((s) => s.sectionId)).toEqual(["identity"]);
  });

  it("prints --help documenting flags and the env-vs-DB credential split", async () => {
    const streams = captureStreams();
    const exit = await runCli(["--help"], { streams });
    expect(exit).toBe(0);
    const text = streams.out.join("") + streams.err.join("");
    expect(text).toMatch(/--tenant <guid>/);
    expect(text).toMatch(/--section <id>/);
    expect(text).toMatch(/AZURE_CLIENT_ID/);
    // Env-vs-DB ownership split documented (RESEARCH A4).
    expect(text).toMatch(/environment variable/i);
    expect(text).toMatch(/operator credential/i);
  });
});
