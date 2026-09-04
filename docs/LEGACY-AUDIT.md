# Legacy Retirement Audit — M365-Assess PS → SaaS (LEGACY-AUDIT)

Date: 2026-09-04 (backfilled from disk evidence; plans executed outside GSD without summaries)
Scope: every `src/M365-Assess/<bucket>/` classified per D-48/D-49. Superseded PS code lives only in local `legacy/` (gitignored via `legacy/` in `.gitignore`); GitHub archive is git history + prior tags. PSGallery untouched per D-47.

Machine source: `.planning/phases/08-legacy-retirement/08-AUDIT.json` (18 entries).

| Bucket | Classification | Rationale | SaaS Equivalent | Files |
|---|---|---|---|---|
| ActiveDirectory | superseded | On-prem AD unreachable from public SaaS without agent | n/a (REMOVED-CAPABILITIES.md §1) | 6 |
| Collaboration | superseded | SPO/OneDrive/Teams/Forms ported (05-03) | web/src/engine/sections/collaboration/ | 5 |
| Common | superseded | Helpers reimplemented in TS; no runtime PS imports (see exceptions) | web/src/report/** + web/src/lib/graph/** | 31 |
| controls | still-needed | Live SaaS scoring data, byte-unmodified (FRM-01, D-51) | src/M365-Assess/controls/** via load-controls.ts controlsDir() | 292 checks |
| Entra | superseded | Full parity port (02/03) | web/src/engine/sections/entra/ | 22 |
| Exchange-Online | superseded | Ported with Graph equivalents (05-01; §3 for PS-only) | web/src/engine/sections/exchange/ | 6 |
| Intune | superseded | Ported at parity (04-01, D-23 beta keep) | web/src/engine/sections/intune/ | 15 |
| Inventory | superseded | Ported (06-*) | web/src/engine/sections/inventory/ | 5 |
| Networking | superseded | No SaaS equivalent in v1 scope | n/a (REMOVED-CAPABILITIES.md §1/§2) | 1 |
| Orchestrator | superseded | Orchestration reimplemented / baseline deferred to v2 (see exceptions) | web/src/lib/runs/run-executor.ts | 12 |
| PowerBI | superseded | Ported; 06b real api.powerbi.com transport (06b-03 live checkpoint pending) | web/src/engine/sections/powerbi/ | 1 |
| Purview | superseded | Graph-channeled where exists (06-*; §3 remainder) | web/src/engine/sections/purview/ | 3 |
| Security | superseded | Ported at parity (04-01, D-22 distinct surfaces) | web/src/engine/sections/security/ | 17 |
| Setup | superseded | Superseded by web consent flow | web/src/lib/tenant/** + docs/web/APP-REGISTRATION-SETUP.md | 4 |
| SOC2 | superseded | Consultant scripts, not tenant checks; scored via frameworks/ | n/a (frameworks/soc2-tsc.json) | 4 |
| ValueOpportunity | superseded | Deferred with drift/history (out of scope v1) | n/a (deferred to v2) | 4 |
| Windows | superseded | WIN-* outside M365 cloud surface | n/a (REMOVED-CAPABILITIES.md §2) | 1 |
| assets | superseded | Report experience ported to ReportView pipeline | web/src/report/** + web/src/components/report/** | 15 |

## Per-helper exceptions (Common/Orchestrator)

- `web/src/lib/graph/verify-permissions.ts` is a behavioral port of `Orchestrator/Test-GraphPermissions.ps1` (no runtime import).
- `web/src/engine/results/checkid-subnumberer.ts` ports the `Common/SecurityConfigHelper.ps1:248-254` sub-numbering algorithm (comment reference only).
- `controls/*.json` stay tracked and live (not exceptions — the `controls` bucket itself is still-needed).

## Conservative gate (D-46/D-49)

A bucket is superseded only with a SaaS pointer or a REMOVED-CAPABILITIES §1/§2/§3 drop entry. Zero undecided: every bucket is either ported or §-dropped above.

## Residual domains (D-50)

ActiveDirectory, Windows, Networking, SOC2, ValueOpportunity are superseded-for-SaaS: archived to local `legacy/`, no Graph coverability or out of v1 scope.

## Controls ownership (D-51)

`web/src/engine/registry/load-controls.ts` resolves `join(repoRoot, src/M365-Assess/controls)` with `CONTROLS_DIR` override; registry stays byte-unmodified per FRM-01.

## CI (D-53)

Existing CI gates kept; no PS execution in SaaS pipelines.

## Undecided → next decision

None. All 18 buckets classified; no deferred bucket decisions outstanding.

---
*GitHub archive: git history + prior tag v2.13.0. Machine source: `.planning/phases/08-legacy-retirement/08-AUDIT.json`.*
