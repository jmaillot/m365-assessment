# Control Registry

The control registry maps security checks to compliance frameworks. It is a **committed data artifact** consumed from the upstream [CheckID](https://github.com/Galvnyz/CheckID) project.

## Data Flow

```
CheckID repo (source of truth) — thank you to Galvnyz for the CheckID project
  └─ data/registry.json
  └─ data/frameworks/*.json
       │
       ▼
M365-Assess repo
  └─ controls/registry.json        ← committed for offline use
  └─ controls/frameworks/*.json    ← committed for offline use
       │
       ▼  loaded at runtime
  web/src/engine/registry/load-controls.ts
```

**Key points:**
- `registry.json` and framework JSONs are committed so `git clone` works offline
- Special thanks to [Galvnyz/CheckID](https://github.com/Galvnyz/CheckID) for maintaining the upstream registry

## Files

| File | Purpose |
|------|---------|
| `registry.json` | M365-scoped security checks with inline framework mappings (counts below) |
| `sync-scope.json` | Collector allowlist applied when syncing the registry from CheckID |
| `frameworks/cis-controls-v8.json` | CIS Controls v8 mappings |
| `frameworks/cis-m365-v6.json` | CIS M365 v6 profile definitions (E3/E5, L1/L2) |
| `frameworks/cis-m365-v7.json` | CIS M365 v7 Ensures (155, admin-center sections) — added 2026-09 from CIS PDF via `scripts/cis-pdf-to-framework.py`, mapped to existing `CheckId`s (no new collectors) |
| `frameworks/cisa-scuba.json` | CISA SCuBA baseline definitions |
| `frameworks/cmmc.json` | CMMC 2.0 practice/domain definitions |
| `frameworks/essential-eight.json` | Australian Essential Eight maturity model |
| `frameworks/fedramp.json` | FedRAMP control baselines |
| `frameworks/hipaa.json` | HIPAA Security Rule safeguards |
| `frameworks/iso-27001.json` | ISO 27001:2022 Annex A controls |
| `frameworks/mitre-attack.json` | MITRE ATT&CK technique mappings |
| `frameworks/nist-800-53-r5.json` | NIST 800-53 Rev 5 with Low/Moderate/High/Privacy baselines |
| `frameworks/nist-csf.json` | NIST CSF 2.0 function/category mappings |
| `frameworks/pci-dss-v4.json` | PCI DSS v4.0.1 requirement definitions |
| `frameworks/soc2-tsc.json` | SOC 2 Trust Services Criteria |
| `frameworks/stig.json` | DISA STIG M365 rules |

<!-- registry-stats:files:begin -->
`registry.json` currently contains **292 checks** across **16 collector families**, including **5 local extension checks**. Mappings span **21 framework keys**, 16 of which have report-view definitions in `frameworks/` (added `cis-m365-v7` 155 Ensures locally from CIS PDF — upstream CheckID not yet at v7).
<!-- registry-stats:files:end -->
