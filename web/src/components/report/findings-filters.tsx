"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { SaasStatus } from "@/engine/results/row-contract";
import { ChevronDownIcon } from "lucide-react";

const ALL_STATUSES: SaasStatus[] = ["Fail", "Warning", "Review", "Skipped", "Info", "Pass"];

export interface FindingsFiltersProps {
  counts: Record<SaasStatus, number>;
  selected: Set<SaasStatus>;
  onToggle: (status: SaasStatus) => void;
}

export function FindingsFilters({ counts, selected, onToggle }: FindingsFiltersProps) {
  return (
    <div className="flex flex-wrap gap-sm2">
      {ALL_STATUSES.map((status) => {
        const active = selected.has(status);
        const count = counts[status] ?? 0;
        return (
          <TooltipProvider key={status}>
            <Tooltip>
              <TooltipTrigger>
                <button
                  type="button"
                  aria-label={`Toggle ${status} filter`}
                  data-testid={`filter-chip-${status}`}
                  onClick={() => onToggle(status)}
                  className={`inline-flex min-h-[44px] min-w-[44px] items-center justify-center gap-1 rounded-4xl border px-3 text-sm font-medium transition-colors ${active ? "bg-primary text-primary-foreground border-primary" : "bg-card text-muted-foreground border-border"}`}
                >
                  <span>{status}</span>
                  <Badge variant="secondary" className="ml-1 bg-muted text-foreground">
                    {count}
                  </Badge>
                </button>
              </TooltipTrigger>
              <TooltipContent>
                <p className="text-xs">{active ? `Hide ${status}` : `Show ${status}`} findings</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        );
      })}
    </div>
  );
}

export interface CategoryFiltersProps {
  counts: Record<string, number>;
  selected: Set<string>;
  onToggle: (category: string) => void;
}

export function CategoryFilters({ counts, selected, onToggle }: CategoryFiltersProps) {
  const categories = Object.keys(counts).sort((a, b) => a.localeCompare(b));
  if (categories.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-sm2">
      {categories.map((cat) => {
        const active = selected.has(cat);
        const count = counts[cat] ?? 0;
        return (
          <TooltipProvider key={cat}>
            <Tooltip>
              <TooltipTrigger>
                <button
                  type="button"
                  aria-label={`Toggle ${cat} category filter`}
                  data-testid={`filter-chip-category-${cat}`}
                  onClick={() => onToggle(cat)}
                  className={`inline-flex min-h-[44px] min-w-[44px] items-center justify-center gap-1 rounded-4xl border px-3 text-sm font-medium transition-colors ${active ? "bg-primary text-primary-foreground border-primary" : "bg-card text-muted-foreground border-border"}`}
                >
                  <span>{cat}</span>
                  <Badge variant="secondary" className="ml-1 bg-muted text-foreground">
                    {count}
                  </Badge>
                </button>
              </TooltipTrigger>
              <TooltipContent>
                <p className="text-xs">{active ? `Hide ${cat}` : `Show ${cat}`} findings</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        );
      })}
    </div>
  );
}

// Helper exported for default selection logic verification
export const DEFAULT_SELECTED_STATUSES: SaasStatus[] = ["Fail", "Warning", "Review", "Skipped", "Pass"];
// Note: Default filter excludes Info — initial selection is the five non-Info statuses above

// ---- New Azure-style multi-select dropdowns (03-06b D-17) ----

export interface DomainFilterDropdownProps {
  counts: Record<string, number>;
  selected: Set<string>;
  onToggle: (domain: string) => void;
  onSelectAll: () => void;
  onClear: () => void;
}

export function DomainFilterDropdown({ counts, selected, onToggle, onSelectAll, onClear }: DomainFilterDropdownProps) {
  const domains = Object.keys(counts).sort((a, b) => a.localeCompare(b));
  if (domains.length === 0) return null;
  const allSelected = domains.every((d) => selected.has(d));
  const label = allSelected ? `Domain (All)` : `Domain (${selected.size}/${domains.length})`;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        data-testid="filter-dropdown-domain"
        aria-label="Filter by domain"
        className="inline-flex min-h-[44px] items-center justify-center gap-1.5 rounded-md border bg-card px-3 text-sm font-medium text-foreground transition-colors hover:bg-accent"
      >
        <span>{label}</span>
        <ChevronDownIcon className="size-4 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-[220px]">
        <DropdownMenuLabel>Domain</DropdownMenuLabel>
        <div className="flex gap-1 px-1.5 pb-1">
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onSelectAll}>
            Select all
          </Button>
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onClear}>
            Clear
          </Button>
        </div>
        <DropdownMenuSeparator />
        {domains.map((domain) => (
          <DropdownMenuCheckboxItem
            key={domain}
            checked={selected.has(domain)}
            onCheckedChange={() => onToggle(domain)}
            data-testid={`filter-dropdown-domain-${domain}`}
          >
            <span className="flex w-full items-center justify-between gap-2">
              <span>{domain}</span>
              <Badge variant="secondary" className="ml-2 bg-muted text-foreground">
                {counts[domain] ?? 0}
              </Badge>
            </span>
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export interface CategoryFilterDropdownProps {
  counts: Record<string, number>;
  selected: Set<string>;
  onToggle: (category: string) => void;
  onSelectAll: () => void;
  onClear: () => void;
  disabled?: boolean;
}

export function CategoryFilterDropdown({ counts, selected, onToggle, onSelectAll, onClear, disabled }: CategoryFilterDropdownProps) {
  const categories = Object.keys(counts).sort((a, b) => a.localeCompare(b));
  if (categories.length === 0) return null;
  const allSelected = categories.every((c) => selected.has(c));
  const label = allSelected ? `Category (All)` : `Category (${selected.size}/${categories.length})`;
  const triggerDisabled = disabled || categories.length === 0;
  if (triggerDisabled) {
    return (
      <DropdownMenu>
        <DropdownMenuTrigger
          data-testid="filter-dropdown-category"
          aria-label="Filter by category"
          disabled={triggerDisabled}
          title="Select a domain first"
          className="inline-flex min-h-[44px] items-center justify-center gap-1.5 rounded-md border bg-card px-3 text-sm font-medium text-foreground transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          <span>{label}</span>
          <ChevronDownIcon className="size-4 text-muted-foreground" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="min-w-[220px]">
          <DropdownMenuLabel>Category</DropdownMenuLabel>
          <div className="flex gap-1 px-1.5 pb-1">
            <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onSelectAll}>
              Select all
            </Button>
            <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onClear}>
              Clear
            </Button>
          </div>
          <DropdownMenuSeparator />
          {categories.map((cat) => (
            <DropdownMenuCheckboxItem
              key={cat}
              checked={selected.has(cat)}
              onCheckedChange={() => onToggle(cat)}
              data-testid={`filter-dropdown-category-${cat}`}
            >
              <span className="flex w-full items-center justify-between gap-2">
                <span>{cat}</span>
                <Badge variant="secondary" className="ml-2 bg-muted text-foreground">
                  {counts[cat] ?? 0}
                </Badge>
              </span>
            </DropdownMenuCheckboxItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    );
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        data-testid="filter-dropdown-category"
        aria-label="Filter by category"
        className="inline-flex min-h-[44px] items-center justify-center gap-1.5 rounded-md border bg-card px-3 text-sm font-medium text-foreground transition-colors hover:bg-accent"
      >
        <span>{label}</span>
        <ChevronDownIcon className="size-4 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-[220px]">
        <DropdownMenuLabel>Category</DropdownMenuLabel>
        <div className="flex gap-1 px-1.5 pb-1">
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onSelectAll}>
            Select all
          </Button>
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onClear}>
            Clear
          </Button>
        </div>
        <DropdownMenuSeparator />
        {categories.map((cat) => (
          <DropdownMenuCheckboxItem
            key={cat}
            checked={selected.has(cat)}
            onCheckedChange={() => onToggle(cat)}
            data-testid={`filter-dropdown-category-${cat}`}
          >
            <span className="flex w-full items-center justify-between gap-2">
              <span>{cat}</span>
              <Badge variant="secondary" className="ml-2 bg-muted text-foreground">
                {counts[cat] ?? 0}
              </Badge>
            </span>
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export interface StatusFilterDropdownProps {
  counts: Record<SaasStatus, number>;
  selected: Set<SaasStatus>;
  onToggle: (status: SaasStatus) => void;
  onSelectAll: () => void;
  onClear: () => void;
}

export function StatusFilterDropdown({ counts, selected, onToggle, onSelectAll, onClear }: StatusFilterDropdownProps) {
  const allSelected = ALL_STATUSES.every((s) => selected.has(s));
  const label = allSelected ? `Status (All)` : `Status (${selected.size}/${ALL_STATUSES.length})`;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        data-testid="filter-dropdown-status"
        aria-label="Filter by status"
        className="inline-flex min-h-[44px] items-center justify-center gap-1.5 rounded-md border bg-card px-3 text-sm font-medium text-foreground transition-colors hover:bg-accent"
      >
        <span>{label}</span>
        <ChevronDownIcon className="size-4 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-[200px]">
        <DropdownMenuLabel>Status</DropdownMenuLabel>
        <div className="flex gap-1 px-1.5 pb-1">
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onSelectAll}>
            Select all
          </Button>
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onClear}>
            Clear
          </Button>
        </div>
        <DropdownMenuSeparator />
        {ALL_STATUSES.map((status) => (
          <DropdownMenuCheckboxItem
            key={status}
            checked={selected.has(status)}
            onCheckedChange={() => onToggle(status)}
            data-testid={`filter-dropdown-status-${status}`}
          >
            <span className="flex w-full items-center justify-between gap-2">
              <span>{status}</span>
              <Badge variant="secondary" className="ml-2 bg-muted text-foreground">
                {counts[status] ?? 0}
              </Badge>
            </span>
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
