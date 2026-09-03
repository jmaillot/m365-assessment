"use client";

import * as React from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { StatusBadge } from "@/components/runs/status-badge";
import type { SaasStatus } from "@/engine/results/row-contract";
import type { ReportData } from "@/report/build-report-data";
import { DownloadIcon } from "lucide-react";
import {
  CategoryFilterDropdown,
  DomainFilterDropdown,
  StatusFilterDropdown,
  DEFAULT_SELECTED_STATUSES,
} from "./findings-filters";

export function FindingsTab({ data }: { data: ReportData }) {
  const allDomains = React.useMemo(
    () => Array.from(new Set(data.findings.map((f) => f.domain))).sort((a, b) => a.localeCompare(b)),
    [data.findings],
  );
  const allCategories = React.useMemo(
    () => Array.from(new Set(data.findings.map((f) => f.category))).sort((a, b) => a.localeCompare(b)),
    [data.findings],
  );
  const [selectedDomains, setSelectedDomains] = React.useState<Set<string>>(() => new Set(allDomains));
  const [selectedCategories, setSelectedCategories] = React.useState<Set<string>>(() => new Set(allCategories));
  const [selectedStatuses, setSelectedStatuses] = React.useState<Set<SaasStatus>>(
    () => new Set<SaasStatus>(DEFAULT_SELECTED_STATUSES),
  );
  const [expandedId, setExpandedId] = React.useState<string | null>(null);

  // Sync domain selection when data changes
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

  // Available categories filtered by selected domains
  const availableCategorySet = React.useMemo(() => {
    const set = new Set<string>();
    for (const f of data.findings) if (selectedDomains.has(f.domain)) set.add(f.category);
    return set;
  }, [data.findings, selectedDomains]);

  React.useEffect(() => {
    setSelectedCategories((prev) => {
      if (prev.size === 0 && availableCategorySet.size > 0) return new Set(availableCategorySet);
      const next = new Set<string>();
      // Keep only categories still available
      for (const c of prev) if (availableCategorySet.has(c)) next.add(c);
      // Add newly available categories
      for (const c of availableCategorySet) if (!prev.has(c)) next.add(c);
      // Guard non-empty
      if (next.size === 0 && availableCategorySet.size > 0) return new Set(availableCategorySet);
      // Compare
      if (next.size !== prev.size) return next;
      for (const c of next) if (!prev.has(c)) return next;
      return prev;
    });
  }, [availableCategorySet]);

  const statusCounts = React.useMemo(() => {
    const c: Record<string, number> = { Pass: 0, Fail: 0, Warning: 0, Review: 0, Info: 0, Skipped: 0 };
    for (const f of data.findings) c[f.status] = (c[f.status] ?? 0) + 1;
    return c as Record<SaasStatus, number>;
  }, [data.findings]);

  const domainCounts = React.useMemo(() => {
    const cc: Record<string, number> = {};
    for (const f of data.findings) cc[f.domain] = (cc[f.domain] ?? 0) + 1;
    return cc;
  }, [data.findings]);

  const categoryCounts = React.useMemo(() => {
    const cc: Record<string, number> = {};
    for (const f of data.findings) if (selectedDomains.has(f.domain)) cc[f.category] = (cc[f.category] ?? 0) + 1;
    return cc;
  }, [data.findings, selectedDomains]);

  // Maintain for reference: selectedCategories and selectedStatuses drive filtering
  const filtered = React.useMemo(
    () =>
      data.findings.filter(
        (f) => selectedDomains.has(f.domain) && selectedCategories.has(f.category) && selectedStatuses.has(f.status),
      ),
    [data.findings, selectedDomains, selectedCategories, selectedStatuses],
  );

  function bucketDomain(d: string): string {
    if (d === "Forms") return "Teams";
    return d;
  }

  // Nested grouping: domain -> category -> rows (D-43 3-bucket normalization: Forms → Teams)
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

  // For testing selectedDomains / selectedCategories presence
  void selectedDomains;
  void selectedCategories;

  function toggleStatus(status: SaasStatus) {
    setSelectedStatuses((prev) => {
      const next = new Set(prev);
      if (next.has(status)) next.delete(status); else next.add(status);
      if (next.size === 0) return prev;
      return next;
    });
  }
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

  function resetFilters() {
    setSelectedDomains(new Set(allDomains));
    setSelectedCategories(new Set(allCategories));
    setSelectedStatuses(new Set<SaasStatus>(DEFAULT_SELECTED_STATUSES));
  }

  const handleSelectAllDomains = () => setSelectedDomains(new Set(allDomains));
  const handleClearDomains = () => {
    // Keep one to respect non-empty guard
    if (allDomains.length > 0) setSelectedDomains(new Set([allDomains[0]!]));
  };
  const handleSelectAllCategories = () => {
    const cats = Array.from(availableCategorySet);
    if (cats.length > 0) setSelectedCategories(new Set(cats));
  };
  const handleClearCategories = () => {
    const cats = Array.from(availableCategorySet);
    if (cats.length > 0) setSelectedCategories(new Set([cats[0]!]));
  };
  const handleSelectAllStatuses = () => setSelectedStatuses(new Set<SaasStatus>(["Fail", "Warning", "Review", "Skipped", "Info", "Pass"]));
  const handleClearStatuses = () => setSelectedStatuses(new Set<SaasStatus>(["Fail"]));

  // Ensure default selection excludes Info (Info not in DEFAULT_SELECTED_STATUSES)
  // skipReason is passed through to StatusBadge for Skipped rows

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

  const renderRows = (rows: typeof filtered) =>
    rows.map((f) => (
      <React.Fragment key={f.checkId + f.setting}>
        <TableRow
          className="cursor-pointer"
          onClick={() => setExpandedId((prev) => (prev === f.checkId ? null : f.checkId))}
        >
          <TableCell className="whitespace-normal break-words text-sm">{f.category}</TableCell>
          <TableCell className="whitespace-normal break-words text-sm font-medium">{f.setting}</TableCell>
          <TableCell className="whitespace-normal break-words text-sm">{f.currentValue || "—"}</TableCell>
          <TableCell className="whitespace-normal break-words text-sm">{f.recommendedValue || "—"}</TableCell>
          <TableCell>
            <StatusBadge status={f.status} skipReason={f.skipReason} />
          </TableCell>
          <TableCell className="font-mono text-sm">{f.checkId}</TableCell>
        </TableRow>
        {expandedId === f.checkId ? (
          <TableRow>
            <TableCell colSpan={6} className="bg-muted/30 whitespace-normal">
              <div className="flex flex-col gap-sm2 p-2 text-sm break-words">
                <p className="break-words">
                  <span className="font-semibold">Remediation: </span>
                  {f.remediation || "No remediation guidance available."}
                </p>
                {f.observedValue ? (
                  <p className="break-words">
                    <span className="font-semibold">Observed: </span>
                    {f.observedValue}
                  </p>
                ) : null}
                {f.expectedValue ? (
                  <p className="break-words">
                    <span className="font-semibold">Expected: </span>
                    {f.expectedValue}
                  </p>
                ) : null}
                {f.evidenceSource ? (
                  <p className="break-words">
                    <span className="font-semibold">Source: </span>
                    {f.evidenceSource}
                  </p>
                ) : null}
                {f.skipReason ? (
                  <p className="break-words">
                    <span className="font-semibold">Skip reason: </span>
                    {f.skipReason}
                  </p>
                ) : null}
              </div>
            </TableCell>
          </TableRow>
        ) : null}
      </React.Fragment>
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
    const header = ["severity","domain","checkId","category","setting","currentValue","recommendedValue","status","remediation","sectionId"];
    const esc = (s: string) => `"${String(s).replace(/"/g, '""')}"`;
    const rows = sorted.map((f) => [esc(f.severity ?? ""), esc(f.domain), esc(f.checkId), esc(f.category), esc(f.setting), esc(f.currentValue), esc(f.recommendedValue), esc(f.status), esc(f.remediation), esc(f.sectionId)].join(";"));
    const csv = [header.join(";"), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `findings-${new Date().toISOString().slice(0,10)}.csv`;
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
          Export CSV (filtered, prioritized)
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
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Category</TableHead>
                            <TableHead>Setting</TableHead>
                            <TableHead>Current value</TableHead>
                            <TableHead>Recommended value</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>CheckId</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>{renderRows(rows)}</TableBody>
                      </Table>
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
