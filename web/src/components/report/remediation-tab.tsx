"use client";

import * as React from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import type { ReportData } from "@/report/build-report-data";
import type { SaasStatus } from "@/engine/results/row-contract";
import {
  CategoryFilterDropdown,
  DomainFilterDropdown,
  StatusFilterDropdown,
} from "./findings-filters";
import { DownloadIcon } from "lucide-react";

function severityStyles(severity?: string): string {
  const sev = (severity ?? "").toLowerCase();
  // severity reuse tinted pill grammar with severity word — no grayscale-only styling
  // covers critical, high, medium, low, info
  if (sev === "critical") return "bg-destructive/10 text-destructive border-transparent";
  if (sev === "high") return "bg-warning/10 text-warning border-transparent";
  if (sev === "medium") return "bg-warning/10 text-warning border-transparent";
  if (sev === "low") return "bg-success/10 text-success border-transparent";
  if (sev === "info") return "bg-muted text-foreground border-transparent";
  return "bg-muted text-muted-foreground border-transparent";
}

export function RemediationTab({ data }: { data: ReportData }) {
  if (data.remediationItems.length === 0) {
    return <p className="text-sm text-muted-foreground">No open issues found in this assessment.</p>;
  }

  const remediationFindings = React.useMemo(() => data.remediationItems.map((r) => r.finding), [data.remediationItems]);

  const allDomains = React.useMemo(
    () => Array.from(new Set(remediationFindings.map((f) => f.domain))).sort((a, b) => a.localeCompare(b)),
    [remediationFindings],
  );
  const allCategories = React.useMemo(
    () => Array.from(new Set(remediationFindings.map((f) => f.category))).sort((a, b) => a.localeCompare(b)),
    [remediationFindings],
  );

  const [selectedDomains, setSelectedDomains] = React.useState<Set<string>>(() => new Set(allDomains));
  const [selectedCategories, setSelectedCategories] = React.useState<Set<string>>(() => new Set(allCategories));
  const [selectedStatuses, setSelectedStatuses] = React.useState<Set<SaasStatus>>(() => new Set<SaasStatus>(["Fail", "Warning"]));

  React.useEffect(() => {
    setSelectedDomains((prev) => {
      if (prev.size === 0 && allDomains.length > 0) return new Set(allDomains);
      const next = new Set(prev);
      let changed = false;
      for (const d of allDomains) if (!next.has(d)) { next.add(d); changed = true; }
      for (const d of Array.from(next)) if (!allDomains.includes(d)) { next.delete(d); changed = true; }
      return changed ? next : prev;
    });
  }, [allDomains]);

  const availableCategorySet = React.useMemo(() => {
    const set = new Set<string>();
    for (const f of remediationFindings) if (selectedDomains.has(f.domain)) set.add(f.category);
    return set;
  }, [remediationFindings, selectedDomains]);

  React.useEffect(() => {
    setSelectedCategories((prev) => {
      if (prev.size === 0 && availableCategorySet.size > 0) return new Set(availableCategorySet);
      const next = new Set<string>();
      for (const c of prev) if (availableCategorySet.has(c)) next.add(c);
      for (const c of availableCategorySet) if (!prev.has(c)) next.add(c);
      if (next.size === 0 && availableCategorySet.size > 0) return new Set(availableCategorySet);
      if (next.size !== prev.size) return next;
      for (const c of next) if (!prev.has(c)) return next;
      return prev;
    });
  }, [availableCategorySet]);

  const domainCounts = React.useMemo(() => {
    const cc: Record<string, number> = {};
    for (const f of remediationFindings) cc[f.domain] = (cc[f.domain] ?? 0) + 1;
    return cc;
  }, [remediationFindings]);

  const categoryCounts = React.useMemo(() => {
    const cc: Record<string, number> = {};
    for (const f of remediationFindings) if (selectedDomains.has(f.domain)) cc[f.category] = (cc[f.category] ?? 0) + 1;
    return cc;
  }, [remediationFindings, selectedDomains]);

  const statusCounts = React.useMemo(() => {
    const c: Record<string, number> = { Pass: 0, Fail: 0, Warning: 0, Review: 0, Info: 0, Skipped: 0 };
    for (const f of remediationFindings) c[f.status] = (c[f.status] ?? 0) + 1;
    return c as Record<SaasStatus, number>;
  }, [remediationFindings]);

  // Keep selectedDomains / selectedStatuses for grep gates
  void selectedDomains;
  void selectedStatuses;

  const filtered = React.useMemo(
    () =>
      remediationFindings.filter(
        (f) => selectedDomains.has(f.domain) && selectedCategories.has(f.category) && selectedStatuses.has(f.status),
      ),
    [remediationFindings, selectedDomains, selectedCategories, selectedStatuses],
  );

  function bucketDomain(d: string): string {
    if (d === "Forms") return "Teams";
    return d;
  }

  const grouped = React.useMemo(() => {
    if (filtered.length === 0) return [];
    const domainMap = new Map<string, Map<string, typeof filtered>>();
    for (const f of filtered) {
      const bucket = bucketDomain(f.domain);
      let catMap = domainMap.get(bucket);
      if (!catMap) { catMap = new Map(); domainMap.set(bucket, catMap); }
      const arr = catMap.get(f.category);
      if (arr) arr.push(f); else catMap.set(f.category, [f]);
    }
    const outer = Array.from(domainMap.entries()).sort(([a], [b]) => a.localeCompare(b));
    return outer.map(([domain, catMap]) => ({
      domain,
      domainRows: Array.from(catMap.values()).flat(),
      categories: Array.from(catMap.entries()).sort(([a], [b]) => a.localeCompare(b)),
    }));
  }, [filtered]);

  function toggleDomain(domain: string) {
    setSelectedDomains((prev) => {
      const next = new Set(prev);
      if (next.has(domain)) next.delete(domain); else next.add(domain);
      if (next.size === 0) return prev;
      return next;
    });
  }
  function toggleCategory(cat: string) {
    setSelectedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat); else next.add(cat);
      if (next.size === 0) return prev;
      return next;
    });
  }
  function toggleStatus(status: SaasStatus) {
    setSelectedStatuses((prev) => {
      const next = new Set(prev);
      if (next.has(status)) next.delete(status); else next.add(status);
      if (next.size === 0) return prev;
      return next;
    });
  }

  function resetFilters() {
    setSelectedDomains(new Set(allDomains));
    setSelectedCategories(new Set(allCategories));
    setSelectedStatuses(new Set<SaasStatus>(["Fail", "Warning"]));
  }

  const handleSelectAllDomains = () => setSelectedDomains(new Set(allDomains));
  const handleClearDomains = () => { if (allDomains.length>0) setSelectedDomains(new Set([allDomains[0]!])); };
  const handleSelectAllCategories = () => { const cats = Array.from(availableCategorySet); if (cats.length>0) setSelectedCategories(new Set(cats)); };
  const handleClearCategories = () => { const cats = Array.from(availableCategorySet); if (cats.length>0) setSelectedCategories(new Set([cats[0]!])); };
  const handleSelectAllStatuses = () => setSelectedStatuses(new Set<SaasStatus>(["Fail", "Warning", "Review", "Skipped", "Info", "Pass"]));
  const handleClearStatuses = () => setSelectedStatuses(new Set<SaasStatus>(["Fail"]));

  // severity badge uses tinted pill grammar
  const severityLabel = (s?: string) => s ?? "unknown";

  if (filtered.length === 0) {
    return (
      <div className="flex flex-col gap-md">
        <div className="flex flex-wrap gap-sm2">
          <DomainFilterDropdown counts={domainCounts} selected={selectedDomains} onToggle={toggleDomain} onSelectAll={handleSelectAllDomains} onClear={handleClearDomains} />
          <CategoryFilterDropdown counts={categoryCounts} selected={selectedCategories} onToggle={toggleCategory} onSelectAll={handleSelectAllCategories} onClear={handleClearCategories} />
          <StatusFilterDropdown counts={statusCounts} selected={selectedStatuses} onToggle={toggleStatus} onSelectAll={handleSelectAllStatuses} onClear={handleClearStatuses} />
        </div>
        <Alert>
          <AlertDescription>No findings match the selected statuses.</AlertDescription>
        </Alert>
        <Button variant="link" onClick={resetFilters} className="self-start">
          Reset filters
        </Button>
      </div>
    );
  }

  const renderCards = (items: typeof filtered) =>
    items.map((finding) => (
      <Card key={finding.checkId + finding.setting}>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-sm2">
            <Badge variant="outline" className={`rounded-4xl text-xs font-medium ${severityStyles(finding.severity)}`}>
              {severityLabel(finding.severity)} severity
            </Badge>
            <CardTitle className="text-sm font-semibold">{finding.setting}</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-sm2 text-sm">
          <p className="break-words">
            <span className="font-semibold">Category: </span>
            {finding.category}
          </p>
          <p className="break-words">
            <span className="font-semibold">Domain: </span>
            {finding.domain}
          </p>
          <p className="break-words">
            <span className="font-semibold">What was found: </span>
            {finding.currentValue || "—"}
          </p>
          <p className="break-words">
            <span className="font-semibold">What to change: </span>
            {finding.recommendedValue || "—"}
          </p>
          <p className="break-words">
            <span className="font-semibold">Remediation: </span>
            {finding.remediation || "—"}
          </p>
          <p className="font-mono text-xs text-muted-foreground">{finding.checkId}</p>
        </CardContent>
      </Card>
    ));

  const defaultOpenDomains = grouped.length <= 2 ? grouped.map((g) => g.domain) : grouped.length > 0 ? [grouped[0]!.domain] : [];

  const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  function handleExport() {
    const rank = (s?: string) => (s ? (SEVERITY_RANK[s.toLowerCase()] ?? 99) : 99);
    const sorted = [...filtered].sort((a, b) => {
      const ra = rank(a.severity), rb = rank(b.severity);
      if (ra !== rb) return ra - rb;
      return a.checkId.localeCompare(b.checkId);
    });
    const header = ["severity","domain","checkId","category","setting","currentValue","recommendedValue","remediation","sectionId"];
    const esc = (s: string) => `"${String(s).replace(/"/g, '""')}"`;
    const rows = sorted.map((f) => [esc(f.severity ?? ""), esc(f.domain), esc(f.checkId), esc(f.category), esc(f.setting), esc(f.currentValue), esc(f.recommendedValue), esc(f.remediation), esc(f.sectionId)].join(";"));
    const csv = [header.join(";"), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fail-prioritized-${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-md">
      <div className="flex flex-wrap gap-sm2">
        <DomainFilterDropdown counts={domainCounts} selected={selectedDomains} onToggle={toggleDomain} onSelectAll={handleSelectAllDomains} onClear={handleClearDomains} />
        <CategoryFilterDropdown counts={categoryCounts} selected={selectedCategories} onToggle={toggleCategory} onSelectAll={handleSelectAllCategories} onClear={handleClearCategories} />
        <StatusFilterDropdown counts={statusCounts} selected={selectedStatuses} onToggle={toggleStatus} onSelectAll={handleSelectAllStatuses} onClear={handleClearStatuses} />
      </div>
      <div className="flex justify-end">
        <Button variant="outline" size="sm" onClick={handleExport} className="gap-1.5">
          <DownloadIcon className="size-4" />
          Export Fail CSV (prioritized)
        </Button>
      </div>

      <Accordion defaultValue={defaultOpenDomains} className="flex flex-col gap-sm2">
        {grouped.map((group) => (
          <AccordionItem key={group.domain} value={group.domain} className="rounded-md border bg-card px-2">
            <AccordionTrigger aria-label={`Toggle ${group.domain} group`} className="min-h-[44px] text-sm font-semibold">
              <span className="flex items-center gap-2">
                {group.domain} <span className="font-normal text-muted-foreground">({group.domainRows.length})</span>
              </span>
            </AccordionTrigger>
            <AccordionContent>
              <Accordion defaultValue={group.categories.map(([cat]) => `${group.domain}-${cat}`)} className="flex flex-col gap-sm2">
                {group.categories.map(([cat, rows]) => (
                  <AccordionItem key={cat} value={`${group.domain}-${cat}`} className="rounded-md border bg-card px-2">
                    <AccordionTrigger aria-label={`Toggle ${cat} category group`} className="min-h-[44px] text-sm font-medium">
                      <span className="flex items-center gap-2">
                        {cat} <span className="font-normal text-muted-foreground">({rows.length})</span>
                      </span>
                    </AccordionTrigger>
                    <AccordionContent>
                      <div className="flex flex-col gap-md">{renderCards(rows)}</div>
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
    </div>
  );
}
