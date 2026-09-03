# Recorded-Replay Fixtures (D-21)

Parity fixtures for the assessment engine: captured real Graph JSON responses
replayed through **both** the PowerShell collector (golden rows) and the
TypeScript port — outputs asserted identical. Deterministic; no live tenant in
CI.

## Layout

```text
__fixtures__/
├── replay.ts            # createReplayFetch() — fetchImpl factory for GraphTransport
├── replay.test.ts       # suite for the factory itself
├── <section>/           # fixture JSON files, named by URL slug
│   ├── v1.0_users.json
│   └── v1.0_identity_conditionalAccess_policies_$top=999.json
└── golden/              # PS-generated golden row files (one per collector)
    └── tenant-info.json
```

## URL → slug rule

Fixture keys are normalized to **path+query** (scheme/host-insensitive), the
same normalization as `normalizeUrlKey()` in `replay.ts` and
`Get-GraphUrlKey` in `scripts/Build-DualRunFixture.ps1`:

```
https://graph.microsoft.com/v1.0/users?$top=999  →  /v1.0/users?$top=999
```

The file slug replaces every character outside `[A-Za-z0-9._-]` with `_`:

```
/v1.0/users?$top=999  →  v1.0_users_$top_999.json
```

Multi-page responses are stored verbatim as separate fixtures — one per page,
keyed by their `@odata.nextLink`:

```json
{ "value": [ ... ], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skipToken=abc" }
```

## The 3-step golden-file workflow

**Step 1 — Author fixtures.** Capture real responses during a live CLI run
(D-14) or hand-write them, one `<slug>.json` per Graph call the collector
makes, under `__fixtures__/<section>/`.

**Step 2 — Generate PS golden rows.**

```bash
pwsh -File scripts/Build-DualRunFixture.ps1 \
  -CollectorScript src/M365-Assess/Entra/Get-TenantInfo.ps1 \
  -EntryFunction <EntryFunctionName> \
  -FixtureDir web/src/engine/__fixtures__/<section> \
  -OutGolden web/src/engine/__fixtures__/golden/<collector>.json
```

The script installs an `Invoke-MgGraphRequest` shim that reads the same
fixture slugs by URI, minimal `Initialize-SecurityConfig` / `Add-Setting`
shims capturing rows with the exact sub-numbering algorithm, then invokes the
collector over recorded data only.

**Step 3 — Assert parity in vitest.** Replay the same fixtures through the TS
port via `createReplayFetch(fixtures)` injected into `GraphTransport`, run the
collector, map its raw statuses through `mapStatus`, and deep-equal the result
against the golden JSON.

## Extending the PS harness

The shim set covers collectors that call raw `Invoke-MgGraphRequest`. If a
collector uses SDK cmdlets (`Get-MgOrganization`, …) or additional Common
helpers, add narrow stubs to `$installShims` in
`scripts/Build-DualRunFixture.ps1` that read from the same fixture directory.
Never let the harness touch the network — a missing fixture must throw loudly,
not fall back to live calls.
