/**
 * Port of `src/M365-Assess/Exchange-Online/Get-DnsSecurityConfig.ps1` (469 lines)
 * — DNS authentication evaluation (SPF, DKIM, DMARC, MX) for authoritative
 * accepted domains (CIS 2.1.8-2.1.10, DNS-MX-001, DNS-ZONE-001, DNS-LOCKDOWN-001).
 *
 * PS → TS mapping per D-31..D-35:
 * - Domain source = Graph GET /v1.0/domains + GET /v1.0/organization/{tenantId}?$select=verifiedDomains (fresh authoritative list, isVerified + exclude *.onmicrosoft.com).
 * - DNS probes run sequentially with 1 retry, 2s timeout per probe, cached per run in engine shared store (dnsCache), SERVFAIL pre-pass preserves DNS-ZONE-001 Fail and suppresses SPF/DKIM/DMARC/MX for those zones.
 * - Verdicts verbatim PS: aggregated X/Y have SPF, null SPF excluded from DKIM, null MX 0 . → Pass, DMARC p=reject/quarantine/none staging, DNS gaps surface as Review except DNS-ZONE-001 Fail, DKIM probes both selector1 and selector2.
 */

import { resolveMx, resolveTxt } from "node:dns/promises";

import type { SectionImplementation } from "@/engine/runner/engine";
import { TransportFatalError } from "@/engine/transport/graph-transport";
import { errMatches } from "./shared";

/** Declared GET paths (mirrored into registry endpoints[] by plan 02-12). */
export const DNS_SECURITY_CONFIG_ENDPOINTS = {
  organization: "/v1.0/organization",
  organizationByTenantId: (tenantId: string) => `/v1.0/organization/${tenantId}?$select=verifiedDomains,displayName`,
  domains: "/v1.0/domains",
} as const;

const ORGANIZATION_READ_ALL = "Organization.Read.All";

const AUTHORIZATION_ERROR =
  /403|Forbidden|Authorization_RequestDenied|Insufficient privileges|Authorization/;

function flattenTxt(records: string[][]): string[] {
  return records.map((chunks) => chunks.join(""));
}

function isServFail(err: unknown): boolean {
  const e = err as { code?: string; message?: string };
  if (e && typeof e.code === "string" && /SERVFAIL/i.test(e.code)) return true;
  const msg = e && typeof e.message === "string" ? e.message : String(err);
  return /SERVFAIL/i.test(msg);
}

function getDnsCache(ctx: Parameters<SectionImplementation>[0]): Map<string, unknown> {
  let cache = ctx.shared.get("dnsCache") as Map<string, unknown> | undefined;
  if (!cache) {
    cache = new Map<string, unknown>();
    ctx.shared.set("dnsCache", cache);
  }
  return cache;
}

async function txtHasRecordWithRetry(
  ctx: Parameters<SectionImplementation>[0],
  name: string,
  predicate: (record: string) => boolean,
): Promise<{ found: boolean; raw: string | null; servFail: boolean }> {
  const cache = getDnsCache(ctx);
  const cacheKey = `txt:${name}`;
  const cached = cache.get(cacheKey) as { found: boolean; raw: string | null; servFail: boolean } | undefined;
  if (cached) return cached;

  let lastResult: { found: boolean; raw: string | null; servFail: boolean } = { found: false, raw: null, servFail: false };
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const result = await Promise.race([
        (async () => {
          const records = await resolveTxt(name);
          const flat = flattenTxt(records);
          for (const r of flat) {
            if (predicate(r)) return { found: true, raw: r, servFail: false };
          }
          const joined = flat.join("");
          if (predicate(joined)) return { found: true, raw: joined, servFail: false };
          return { found: false, raw: flat[0] ?? null, servFail: false };
        })(),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(Object.assign(new Error("ETIMEOUT"), { code: "ETIMEOUT" })), 2000),
        ),
      ]);
      cache.set(cacheKey, result);
      return result;
    } catch (err) {
      lastResult = isServFail(err) ? { found: false, raw: null, servFail: true } : { found: false, raw: null, servFail: false };
      const isRetryable = isServFail(err) || /ETIMEOUT/.test(String((err as Error).message ?? String(err)));
      if (attempt === 1 || !isRetryable) {
        cache.set(cacheKey, lastResult);
        return lastResult;
      }
      // retry once on SERVFAIL or ETIMEOUT
    }
  }
  cache.set(cacheKey, lastResult);
  return lastResult;
}

async function resolveMxWithRetry(
  ctx: Parameters<SectionImplementation>[0],
  domain: string,
): Promise<{ exchange: string; priority: number }[] | null> {
  const cache = getDnsCache(ctx);
  const cacheKey = `mx:${domain}`;
  const cached = cache.get(cacheKey) as { exchange: string; priority: number }[] | null | undefined;
  if (cached !== undefined) return cached;

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const result = await Promise.race([
        resolveMx(domain) as Promise<{ exchange: string; priority: number }[]>,
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(Object.assign(new Error("ETIMEOUT"), { code: "ETIMEOUT" })), 2000),
        ),
      ]);
      cache.set(cacheKey, result);
      return result;
    } catch (err) {
      const isRetryable = isServFail(err) || /ETIMEOUT/.test(String((err as Error).message ?? String(err)));
      if (attempt === 1 || !isRetryable) {
        if (isServFail(err)) throw err;
        cache.set(cacheKey, null);
        return null;
      }
    }
  }
  cache.set(cacheKey, null);
  return null;
}

async function dkimEnabled(
  ctx: Parameters<SectionImplementation>[0],
  domain: string,
): Promise<{ enabled: boolean; servFail: boolean }> {
  const selectors = [`selector1._domainkey.${domain}`, `selector2._domainkey.${domain}`];
  let sawServFail = false;
  for (const sel of selectors) {
    const cache = getDnsCache(ctx);
    const cacheKey = `dkim:${sel}`;
    const cached = cache.get(cacheKey) as boolean | undefined;
    if (cached !== undefined) {
      if (cached) return { enabled: true, servFail: false };
      continue;
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const records = await Promise.race([
          resolveTxt(sel) as Promise<string[][]>,
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(Object.assign(new Error("ETIMEOUT"), { code: "ETIMEOUT" })), 2000),
          ),
        ]);
        const flat = flattenTxt(records);
        const hasTxt = flat.length > 0 && flat.some((r) => r.length > 0);
        cache.set(cacheKey, hasTxt);
        if (hasTxt) return { enabled: true, servFail: false };
        break;
      } catch (err) {
        if (isServFail(err)) sawServFail = true;
        const isRetryable = isServFail(err) || /ETIMEOUT/.test(String((err as Error).message ?? String(err)));
        if (attempt === 1 || !isRetryable) break;
      }
    }
    // ENOTFOUND/ENODATA → continue to next selector
  }
  return { enabled: false, servFail: sawServFail };
}

export const runDnsSecurityConfig: SectionImplementation = async (ctx) => {
  // ------------------------------------------------------------------
  // Fetch authoritative verified domains (PS lines 62-82) — D-31 union
  // ------------------------------------------------------------------
  let verifiedNames: string[] = [];
  try {
    const tenantId = (ctx.shared.get("tenantId") as string | undefined) ?? "";
    const path =
      tenantId && /^[0-9a-fA-F-]{36}$/.test(tenantId)
        ? DNS_SECURITY_CONFIG_ENDPOINTS.organizationByTenantId(tenantId)
        : DNS_SECURITY_CONFIG_ENDPOINTS.organization;

    const orgResp = (await ctx.transport.getJson(path, {
      requiredRole: ORGANIZATION_READ_ALL,
    })) as Record<string, unknown>;

    // Singleton org object vs collection shape: { verifiedDomains: [...] } vs { value: [{ verifiedDomains: [...] }] }
    let domainsRaw: unknown = orgResp.verifiedDomains;
    if (!domainsRaw && Array.isArray(orgResp.value) && orgResp.value.length > 0) {
      const first = orgResp.value[0] as Record<string, unknown>;
      domainsRaw = first.verifiedDomains ?? first["verifiedDomains"];
    }
    const allDomains = Array.isArray(domainsRaw) ? (domainsRaw as Record<string, unknown>[]) : [];
    const orgNames = allDomains
      .map((d) => (typeof d.name === "string" ? d.name : typeof d.id === "string" ? (d.id as string) : typeof d.domainName === "string" ? (d.domainName as string) : ""))
      .filter((n) => n && !n.toLowerCase().endsWith(".onmicrosoft.com"));

    // D-31: second Graph call GET /v1.0/domains union with isVerified filter
    let domainsNames: string[] = [];
    try {
      const domainsResp = (await ctx.transport.getJson(DNS_SECURITY_CONFIG_ENDPOINTS.domains, {
        requiredRole: ORGANIZATION_READ_ALL,
      })) as Record<string, unknown>;
      const domainList = Array.isArray(domainsResp.value) ? (domainsResp.value as Record<string, unknown>[]) : [];
      domainsNames = domainList
        .filter((d) => d.isVerified === true)
        .map((d) => (typeof d.id === "string" ? (d.id as string) : typeof d.name === "string" ? (d.name as string) : ""))
        .filter((n) => n && !n.toLowerCase().endsWith(".onmicrosoft.com"));
    } catch (err) {
      if (err instanceof TransportFatalError) throw err;
      if (errMatches(err, AUTHORIZATION_ERROR)) throw err;
      // transient domains fetch failure → keep orgNames only
    }

    // Merge union dedup case-insensitive preserving first-seen order
    const seen = new Set<string>();
    const merged: string[] = [];
    for (const n of [...orgNames, ...domainsNames]) {
      const key = n.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(n);
      }
    }
    verifiedNames = merged;
  } catch (err) {
    if (err instanceof TransportFatalError) throw err;
    if (errMatches(err, AUTHORIZATION_ERROR)) {
      for (const { checkId, setting, recommended } of [
        { checkId: "DNS-SPF-001", setting: "SPF Records", recommended: "SPF for all domains" },
        { checkId: "DNS-DKIM-001", setting: "DKIM Signing", recommended: "DKIM for all domains" },
        { checkId: "DNS-DMARC-001", setting: "DMARC Records", recommended: "DMARC for all domains" },
        { checkId: "DNS-MX-001", setting: "MX Records", recommended: "MX pointing to *.mail.protection.outlook.com for all sending domains" },
      ] as const) {
        ctx.addRow({
          category: "DNS Authentication",
          setting,
          currentValue: "Requires manual verification in Microsoft 365 admin center — DNS check requires Organization.Read.All",
          recommendedValue: recommended,
          checkId,
          remediation: "Grant Organization.Read.All via admin consent and re-run; or verify DNS manually in Microsoft 365 admin center > Settings > Domains",
          psStatus: "Review",
          evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
          collectionMethod: "Direct",
          permissionRequired: ORGANIZATION_READ_ALL,
        });
      }
      return;
    }
    // PS Write-Warning parity — zero rows, run continues.
    return;
  }

  if (verifiedNames.length === 0) {
    ctx.addRow({
      category: "DNS Authentication",
      setting: "SPF Records",
      currentValue: "No authoritative domains found",
      recommendedValue: "SPF for all domains",
      checkId: "DNS-SPF-001",
      remediation: "Connect the tenant and verify verifiedDomains.",
      psStatus: "Review",
      evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
      collectionMethod: "Direct",
      permissionRequired: ORGANIZATION_READ_ALL,
    });
    ctx.addRow({
      category: "DNS Authentication",
      setting: "DKIM Signing",
      currentValue: "No authoritative domains found",
      recommendedValue: "DKIM for all domains",
      checkId: "DNS-DKIM-001",
      remediation: "Connect the tenant and verify verifiedDomains.",
      psStatus: "Review",
      evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
      collectionMethod: "Direct",
      permissionRequired: ORGANIZATION_READ_ALL,
    });
    ctx.addRow({
      category: "DNS Authentication",
      setting: "DMARC Records",
      currentValue: "No authoritative domains found",
      recommendedValue: "DMARC for all domains",
      checkId: "DNS-DMARC-001",
      remediation: "Connect the tenant and verify verifiedDomains.",
      psStatus: "Review",
      evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
      collectionMethod: "Direct",
      permissionRequired: ORGANIZATION_READ_ALL,
    });
    // DNS-MX-001 is also emitted in the PS empty branch via the MX block — keep parity.
    ctx.addRow({
      category: "DNS Authentication",
      setting: "MX Records",
      currentValue: "No authoritative domains found",
      recommendedValue: "MX pointing to *.mail.protection.outlook.com for all sending domains",
      checkId: "DNS-MX-001",
      remediation: "Connect the tenant and verify verifiedDomains.",
      psStatus: "Review",
      evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
      collectionMethod: "Direct",
      permissionRequired: ORGANIZATION_READ_ALL,
    });
    return;
  }

  // Ensure dnsCache initialized per run
  getDnsCache(ctx);

  // ------------------------------------------------------------------
  // Tracking sets (PS lines 124-133 parity)
  // ------------------------------------------------------------------
  const servfailDomains = new Set<string>();
  const spfNullDomains = new Set<string>();
  const nullMxDomains = new Set<string>();
  const dmarcEnforcingDomains = new Set<string>();

  // ------------------------------------------------------------------
  // SERVFAIL pre-pass (PS lines 137-157) — sequential with retry/timeout/cache
  // ------------------------------------------------------------------
  for (const domain of verifiedNames) {
    const probe = await txtHasRecordWithRetry(ctx, domain, () => true);
    if (probe.servFail) servfailDomains.add(domain.toLowerCase());
    // Also probe MX for zones that only fail on MX class
    if (!servfailDomains.has(domain.toLowerCase())) {
      try {
        const mx = await resolveMxWithRetry(ctx, domain);
        if (mx === null) {
          // null handled as missing, not SERVFAIL; SERVFAIL would have thrown
        }
      } catch (err) {
        if (isServFail(err)) servfailDomains.add(domain.toLowerCase());
      }
    }
  }

  if (servfailDomains.size > 0) {
    const list = [...servfailDomains].join(", ");
    ctx.addRow({
      category: "DNS Authentication",
      setting: "DNS Zone Health",
      currentValue: `SERVFAIL: ${list}`,
      recommendedValue: "All accepted domain zones must respond to DNS queries",
      checkId: "DNS-ZONE-001",
      remediation: `Investigate DNS zone failures for: ${list}. Contact your DNS provider -- the authoritative nameservers are not responding. SPF, DKIM, DMARC, and MX checks for these domains are suppressed to avoid false positives.`,
      psStatus: "Fail",
      evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
      collectionMethod: "Derived",
      permissionRequired: ORGANIZATION_READ_ALL,
      confidence: 1.0,
    });
  }

  const eligibleDomains = verifiedNames.filter((d) => !servfailDomains.has(d.toLowerCase()));

  // ------------------------------------------------------------------
  // 1. SPF Records (CIS 2.1.8) — PS lines 162-211
  // ------------------------------------------------------------------
  {
    const spfMissing: string[] = [];
    const spfPresent: string[] = [];
    for (const domain of eligibleDomains) {
      const r = await txtHasRecordWithRetry(ctx, domain, (txt) => txt.startsWith("v=spf1"));
      if (r.found) {
        spfPresent.push(domain);
        const full = r.raw ?? "";
        if (/^v=spf1\s+-all\s*$/.test(full.trim())) spfNullDomains.add(domain.toLowerCase());
      } else if (!r.servFail) {
        spfMissing.push(domain);
      }
    }
    const spfTotal = spfPresent.length + spfMissing.length;
    if (spfMissing.length === 0) {
      ctx.addRow({
        category: "DNS Authentication",
        setting: "SPF Records",
        currentValue: `${spfPresent.length}/${spfTotal} domains have SPF`,
        recommendedValue: "SPF for all domains",
        checkId: "DNS-SPF-001",
        remediation: "No action needed.",
        psStatus: "Pass",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Direct",
        permissionRequired: ORGANIZATION_READ_ALL,
        confidence: 1.0,
      });
    } else {
      ctx.addRow({
        category: "DNS Authentication",
        setting: "SPF Records",
        currentValue: `${spfPresent.length}/${spfTotal} domains -- missing: ${spfMissing.join(", ")}`,
        recommendedValue: "SPF for all domains",
        checkId: "DNS-SPF-001",
        remediation: `Add SPF TXT records for: ${spfMissing.join(", ")}. Example: v=spf1 include:spf.protection.outlook.com -all`,
        psStatus: "Fail",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Direct",
        permissionRequired: ORGANIZATION_READ_ALL,
      });
    }
  }

  // ------------------------------------------------------------------
  // 2. DKIM Signing (CIS 2.1.9) — PS lines 216-275
  // ------------------------------------------------------------------
  {
    const dkimMissing: string[] = [];
    const dkimEnabledList: string[] = [];
    let dkimServFailCount = 0;
    for (const domain of eligibleDomains) {
      if (spfNullDomains.has(domain.toLowerCase())) continue;
      const { enabled, servFail } = await dkimEnabled(ctx, domain);
      if (servFail) dkimServFailCount++;
      if (enabled) dkimEnabledList.push(domain);
      else if (!servFail) dkimMissing.push(domain);
    }
    const dkimTotal = dkimEnabledList.length + dkimMissing.length;
    if (dkimTotal === 0) {
      ctx.addRow({
        category: "DNS Authentication",
        setting: "DKIM Signing",
        currentValue: "No sending domains to evaluate (all non-sending or SERVFAIL)",
        recommendedValue: "DKIM for all sending domains",
        checkId: "DNS-DKIM-001",
        remediation: "No action needed for non-sending domains.",
        psStatus: dkimServFailCount > 0 ? "Review" : "Pass",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Derived",
        permissionRequired: ORGANIZATION_READ_ALL,
      });
    } else if (dkimMissing.length === 0) {
      ctx.addRow({
        category: "DNS Authentication",
        setting: "DKIM Signing",
        currentValue: `${dkimEnabledList.length}/${dkimTotal} domains have DKIM enabled`,
        recommendedValue: "DKIM for all sending domains",
        checkId: "DNS-DKIM-001",
        remediation: "No action needed.",
        psStatus: "Pass",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Derived",
        permissionRequired: ORGANIZATION_READ_ALL,
        confidence: 0.9,
      });
    } else {
      ctx.addRow({
        category: "DNS Authentication",
        setting: "DKIM Signing",
        currentValue: `${dkimEnabledList.length}/${dkimTotal} domains -- missing: ${dkimMissing.join(", ")}`,
        recommendedValue: "DKIM for all sending domains",
        checkId: "DNS-DKIM-001",
        remediation: `Enable DKIM for: ${dkimMissing.join(", ")}. Run: New-DkimSigningConfig -DomainName <domain> -Enabled $true. Microsoft 365 Defender > Email & collaboration > Policies > DKIM.`,
        psStatus: "Fail",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Derived",
        permissionRequired: ORGANIZATION_READ_ALL,
      });
    }
  }

  // ------------------------------------------------------------------
  // 3. DMARC Records (CIS 2.1.10) — PS lines 280-356
  // ------------------------------------------------------------------
  {
    const dmarcMissing: string[] = [];
    const dmarcNone: string[] = [];
    const dmarcQuarantine: string[] = [];
    const dmarcReject: string[] = [];
    for (const domain of eligibleDomains) {
      const r = await txtHasRecordWithRetry(ctx, `_dmarc.${domain}`, (txt) => txt.startsWith("v=DMARC1"));
      if (!r.found) {
        if (!r.servFail) dmarcMissing.push(domain);
      } else {
        const policy = r.raw ?? "";
        if (/p=reject/i.test(policy)) {
          dmarcReject.push(domain);
          dmarcEnforcingDomains.add(domain.toLowerCase());
        } else if (/p=quarantine/i.test(policy)) {
          dmarcQuarantine.push(domain);
          dmarcEnforcingDomains.add(domain.toLowerCase());
        } else {
          dmarcNone.push(domain);
        }
      }
    }
    const total = dmarcReject.length + dmarcQuarantine.length + dmarcNone.length + dmarcMissing.length;
    if (dmarcMissing.length === 0 && dmarcNone.length === 0 && dmarcQuarantine.length === 0) {
      ctx.addRow({
        category: "DNS Authentication",
        setting: "DMARC Records",
        currentValue: `${dmarcReject.length}/${total} domains at p=reject`,
        recommendedValue: "DMARC p=reject for all domains",
        checkId: "DNS-DMARC-001",
        remediation: "No action needed.",
        psStatus: "Pass",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Direct",
        permissionRequired: ORGANIZATION_READ_ALL,
        confidence: 1.0,
      });
    } else if (dmarcMissing.length === 0 && dmarcNone.length === 0) {
      ctx.addRow({
        category: "DNS Authentication",
        setting: "DMARC Records",
        currentValue: `${dmarcReject.length}/${total} at p=reject; ${dmarcQuarantine.length} at p=quarantine (staged): ${dmarcQuarantine.join(", ")}`,
        recommendedValue: "DMARC p=reject for all domains",
        checkId: "DNS-DMARC-001",
        remediation: `Advance p=quarantine domains to p=reject once DMARC reports confirm no legitimate mail is failing: ${dmarcQuarantine.join(", ")}`,
        psStatus: "Warning",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Direct",
        permissionRequired: ORGANIZATION_READ_ALL,
      });
    } else {
      const issues: string[] = [];
      if (dmarcMissing.length > 0) issues.push(`missing: ${dmarcMissing.join(", ")}`);
      if (dmarcNone.length > 0) issues.push(`p=none: ${dmarcNone.join(", ")}`);
      if (dmarcQuarantine.length > 0) issues.push(`p=quarantine (staged): ${dmarcQuarantine.join(", ")}`);
      ctx.addRow({
        category: "DNS Authentication",
        setting: "DMARC Records",
        currentValue: `${dmarcReject.length}/${total} at p=reject -- ${issues.join("; ")}`,
        recommendedValue: "DMARC p=reject for all domains",
        checkId: "DNS-DMARC-001",
        remediation: `Add/update DMARC for: ${issues.join("; ")}. Start with p=none + rua= to gather reports, then advance to p=quarantine, then p=reject. Example: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com`,
        psStatus: "Fail",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Direct",
        permissionRequired: ORGANIZATION_READ_ALL,
      });
    }
  }

  // ------------------------------------------------------------------
  // 4. MX Records (DNS-MX-001) — PS lines 361-439
  // ------------------------------------------------------------------
  {
    const mxPass: string[] = [];
    const mxNullMx: string[] = [];
    const mxWarning: string[] = [];
    const mxFail: string[] = [];
    for (const domain of eligibleDomains) {
      try {
        const mxRecords = await resolveMxWithRetry(ctx, domain);
        if (!mxRecords || mxRecords.length === 0) {
          mxFail.push(domain);
          continue;
        }
        const isNullMx = mxRecords.some((r) => r.exchange === "." || r.exchange === "");
        if (isNullMx) {
          mxNullMx.push(domain);
          nullMxDomains.add(domain.toLowerCase());
          continue;
        }
        const pointsToExo = mxRecords.some((r) => r.exchange.toLowerCase().includes("mail.protection.outlook.com"));
        if (pointsToExo) mxPass.push(domain);
        else mxWarning.push(`${domain} (${mxRecords[0]?.exchange ?? "unknown"})`);
      } catch (err) {
        if (isServFail(err)) {
          continue;
        }
        mxFail.push(domain);
      }
    }
    const total = mxPass.length + mxNullMx.length + mxWarning.length + mxFail.length;
    if (mxFail.length === 0 && mxWarning.length === 0) {
      const nullNote = mxNullMx.length > 0 ? `; ${mxNullMx.length} null MX (non-sending)` : "";
      ctx.addRow({
        category: "DNS Authentication",
        setting: "MX Records",
        currentValue: `${mxPass.length}/${total} domains route to Exchange Online${nullNote}`,
        recommendedValue: "MX pointing to *.mail.protection.outlook.com for all sending domains",
        checkId: "DNS-MX-001",
        remediation: "No action needed.",
        psStatus: "Pass",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Direct",
        permissionRequired: ORGANIZATION_READ_ALL,
        confidence: 1.0,
      });
    } else if (mxFail.length > 0) {
      const details: string[] = [];
      if (mxPass.length > 0) details.push(`${mxPass.length} EXO`);
      if (mxNullMx.length > 0) details.push(`${mxNullMx.length} null MX`);
      if (mxWarning.length > 0) details.push(`${mxWarning.length} third-party`);
      if (mxFail.length > 0) details.push(`missing: ${mxFail.join(", ")}`);
      ctx.addRow({
        category: "DNS Authentication",
        setting: "MX Records",
        currentValue: `${mxPass.length}/${total} to EXO -- ${details.join("; ")}`,
        recommendedValue: "MX pointing to *.mail.protection.outlook.com for all sending domains",
        checkId: "DNS-MX-001",
        remediation: `Add MX records for: ${mxFail.join(", ")}. Required value: <domain>-com.mail.protection.outlook.com`,
        psStatus: "Fail",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Direct",
        permissionRequired: ORGANIZATION_READ_ALL,
      });
    } else {
      ctx.addRow({
        category: "DNS Authentication",
        setting: "MX Records",
        currentValue: `${mxPass.length}/${total} to EXO; third-party relay: ${mxWarning.join("; ")}`,
        recommendedValue: "MX pointing to *.mail.protection.outlook.com for all sending domains",
        checkId: "DNS-MX-001",
        remediation: "Verify third-party relay is intentional (e.g. Proofpoint, Mimecast). If not, update MX to <domain>-com.mail.protection.outlook.com.",
        psStatus: "Warning",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Direct",
        permissionRequired: ORGANIZATION_READ_ALL,
      });
    }
  }

  // ------------------------------------------------------------------
  // Defensive lockdown Info (PS lines 441-461)
  // ------------------------------------------------------------------
  {
    const lockdownDomains = eligibleDomains.filter(
      (d) =>
        spfNullDomains.has(d.toLowerCase()) &&
        nullMxDomains.has(d.toLowerCase()) &&
        dmarcEnforcingDomains.has(d.toLowerCase()),
    );
    if (lockdownDomains.length > 0) {
      ctx.addRow({
        category: "DNS Authentication",
        setting: "Non-Sending Domain Lockdown",
        currentValue: `${lockdownDomains.length} domain(s) fully locked down: ${lockdownDomains.join(", ")}`,
        recommendedValue: "v=spf1 -all, null MX (0 . per RFC 7505), DMARC p=reject for non-sending domains",
        checkId: "DNS-LOCKDOWN-001",
        remediation: "No action needed.",
        psStatus: "Pass",
        evidenceSource: DNS_SECURITY_CONFIG_ENDPOINTS.organization,
        collectionMethod: "Derived",
        permissionRequired: ORGANIZATION_READ_ALL,
        confidence: 1.0,
      });
    }
  }
};
