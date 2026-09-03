/**
 * CI read-only allowlist gate (plan 02-12 task 3, D-24/D-26 / T-02-12a/b).
 *
 * PS precedent: tests/Smoke/Collector-ReadOnly.Tests.ps1 scans sources for
 * forbidden patterns and asserts ZERO violations. This is the TS half of
 * D-26, generated FROM the section registry (single source of truth):
 *
 * 1. Every Graph URL string literal ("/v1.0/..." | "/beta/...") appearing in
 *    ported collector sources must be declared in some SECTION_REGISTRY
 *    entry's endpoints[]. Dynamic segments compare equal via the `{*}`
 *    placeholder convention (source template literals `${...}` normalize to
 *    `{*}`, matching how the registry declares templated paths).
 * 2. No non-GET HTTP method literal may appear in a fetch/method context —
 *    defense in depth behind the transport's fatal runtime GET-guard.
 * 3. Positive+negative self-check ("guards the guard"): a temp fixture with
 *    an undeclared URL MUST be reported by the extractor/diff pipeline.
 *
 * Pure fs+regex — runs in well under 5s. A new collector call site with an
 * undeclared endpoint turns this test red at CI time.
 */
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { SECTION_REGISTRY } from "@/engine/registry/section-registry";

const SECTIONS_DIR = join(fileURLToPath(import.meta.url), "..", "..", "sections");

/** Collector sources only — tests/fixtures are not Graph call sites. */
const EXCLUDED_FILES = new Set(["test-support.ts"]);

function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      // Recurse into subdirectories (sections live under entra/).
      out.push(...listTsFiles(full));
      continue;
    }
    if (!name.endsWith(".ts") || name.endsWith(".test.ts")) continue;
    if (EXCLUDED_FILES.has(name)) continue;
    out.push(full);
  }
  return out.sort();
}

export function listSectionSourceFiles(dir: string = SECTIONS_DIR): string[] {
  return listTsFiles(dir);
}

/**
 * Matches Graph-path literals per delimiter class: backtick templates may
 * legally contain quote characters inside interpolations/paths (e.g.
 * roleTemplateId='…'), so they scan to the next backtick; quoted strings
 * terminate at their own quote without crossing newlines.
 */
const BACKTICK_GRAPH_URL = /`(\/(?:v1\.0|beta)\/[^`]*)`/g;
const QUOTED_GRAPH_URL = /(["'])(\/(?:v1\.0|beta)\/[^"'\n]*)\1/g;

/** Non-GET verbs in a fetch/method context are forbidden in collectors. */
const NON_GET_METHOD_LITERAL =
  /\bmethod\s*:\s*(["'`])(POST|PATCH|PUT|DELETE)\1/i;

/**
 * Extracts Graph URL literals from source text, normalizing template-literal
 * interpolations (`${expr}`) to the `{*}` placeholder used by the registry.
 */
export function extractGraphUrls(source: string): string[] {
  const urls: string[] = [];
  const push = (raw: string) => urls.push(raw.replace(/\$\{[^}]*\}/g, "{*}"));
  let match: RegExpExecArray | null;
  while ((match = QUOTED_GRAPH_URL.exec(source)) !== null) push(match[2]);
  while ((match = BACKTICK_GRAPH_URL.exec(source)) !== null) push(match[1]);
  return urls;
}
/** Registry-declared surface, deduplicated across sections (case-exact). */
export function declaredEndpoints(): Set<string> {
  return new Set(SECTION_REGISTRY.flatMap((e) => e.endpoints));
}

/** Final path segment of a POSIX/Windows path, for readable failure output. */
function basename(path: string): string {
  return path.replace(/\\/g, "/").split("/").pop() ?? path;
}

describe("read-only allowlist (D-26, registry-generated)", () => {
  const files = listSectionSourceFiles();

  it("scanned a non-empty set of ported collector sources", () => {
    expect(files.length).toBeGreaterThan(15);
  });

  it("declares EVERY Graph URL literal found in collector sources", () => {
    const declared = declaredEndpoints();
    const undeclared = new Map<string, string[]>(); // url -> files
    for (const file of files) {
      for (const url of extractGraphUrls(readFileSync(file, "utf8"))) {
        if (!declared.has(url)) {
          undeclared.set(url, [...(undeclared.get(url) ?? []), file]);
        }
      }
    }
    expect(
      [...undeclared.entries()].map(
        ([url, src]) => `${url}  (${src.map(basename).join(", ")})`,
      ),
    ).toEqual([]);
  });

  it("contains no non-GET method literal in any collector source", () => {
    const violations: string[] = [];
    for (const file of files) {
      if (NON_GET_METHOD_LITERAL.test(readFileSync(file, "utf8"))) {
        violations.push(file);
      }
    }
    expect(violations).toEqual([]);
  });
});

describe("allowlist guard self-check (guards the guard)", () => {
  it("reports an undeclared URL from a temp fixture file (negative case)", () => {
    const dir = mkdtempSync(join(tmpdir(), "allowlist-selfcheck-"));
    try {
      const fixture = join(dir, "rogue-collector.ts");
      const UNDECLARED_STATIC = '/v1.0/undocumented/staticEndpoint';
      // Escaped so the WRITTEN fixture contains a real template placeholder.
      const UNDECLARED_DYNAMIC = `/v1.0/undocumented/\${"id"}/children`;
      writeFixture(fixture, UNDECLARED_STATIC, UNDECLARED_DYNAMIC);

      const extracted = extractGraphUrls(readFileSync(fixture, "utf8"));
      expect(extracted).toContain(UNDECLARED_STATIC);
      expect(extracted).toContain("/v1.0/undocumented/{*}/children");

      const declared = declaredEndpoints();
      const undeclared = extracted.filter((u) => !declared.has(u));
      expect(undeclared).toContain(UNDECLARED_STATIC);
      expect(undeclared).toContain("/v1.0/undocumented/{*}/children");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("accepts a declared URL through the same pipeline (positive case)", () => {
    const declared = declaredEndpoints();
    const sample = SECTION_REGISTRY.find((e) => e.endpoints.length > 0)!
      .endpoints[0];
    expect(sample.startsWith("/v1.0/") || sample.startsWith("/beta/")).toBe(true);
    expect(declared.has(sample)).toBe(true);
  });
});

/** Minimal realistic collector-shaped fixture for the negative case. */
function writeFixture(path: string, staticUrl: string, dynamicUrl: string): void {
  const body = [
    "import type { SectionImplementation } from '@/engine/runner/engine';",
    "",
    `const STATIC_URL = '${staticUrl}';`,
    "",
    `export const runRogue: SectionImplementation = async (ctx) => {`,
    "  await ctx.transport.getJson(STATIC_URL, {});",
    `  await ctx.transport.getJson(\`${dynamicUrl}\`, {});`,
    "};",
    "",
  ].join("\n");
  writeFileSync(path, body);
}
