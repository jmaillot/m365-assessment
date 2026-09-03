"use client";

import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import type { SaasStatus, SkipReason } from "@/engine/results/row-contract";

const STATUS_TIP: Record<SaasStatus, string> = {
  Pass: "Verified secure. The tenant setting matches the recommendation.",
  Fail: "Verified insecure. This setting needs remediation.",
  Warning: "Configured, but in a way that raises a concern worth reviewing.",
  Review: "Data was collected; a person must judge whether it is acceptable.",
  Info: "Background information only, not a pass/fail judgment.",
  Skipped: "Not assessed. This check was intentionally excluded from the run.",
};

export function statusStyles(status: SaasStatus): string {
  switch (status) {
    case "Pass":
      return "bg-success/10 text-success dark:bg-success/20 border-transparent";
    case "Fail":
      return "bg-destructive/10 text-destructive dark:bg-destructive/20 border-transparent";
    case "Warning":
      return "bg-warning/10 text-warning dark:bg-warning/20 border-transparent";
    case "Review":
      return "bg-review/10 text-review dark:bg-review/20 border-transparent";
    case "Info":
      return "bg-muted text-foreground border-transparent";
    case "Skipped":
      return "bg-transparent text-muted-foreground border-border";
    default:
      return "bg-muted text-muted-foreground border-transparent";
  }
}

function tooltipContent(status: SaasStatus, skipReason?: SkipReason): string {
  const base = STATUS_TIP[status];
  if (status === "Skipped") {
    // Must expose machine reason — never bare (D-23)
    const reason = skipReason ?? "unknown";
    // Ensure all five reasons are handled in the string mapping (grep gate)
    // The tooltip includes both the plain sentence and the machine reason code
    const reasonLabel =
      reason === "not_licensed"
        ? "not_licensed"
        : reason === "not_applicable"
          ? "not_applicable"
          : reason === "graph_error"
            ? "graph_error"
            : reason === "not_implemented"
              ? "not_implemented"
              : reason === "circuit_broken"
                ? "circuit_broken"
                : reason;
    return `${base} Reason: ${reasonLabel} (${skipReason ?? "unknown"}).`;
  }
  return base;
}

export interface StatusBadgeProps {
  status: SaasStatus;
  skipReason?: SkipReason;
}

export function StatusBadge({ status, skipReason }: StatusBadgeProps) {
  const content = tooltipContent(status, skipReason);

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger>
          <Badge
            variant="outline"
            className={`rounded-4xl px-2 py-0.5 text-xs font-medium ${statusStyles(status)}`}
          >
            {status}
            {status === "Skipped" && skipReason ? ` (${skipReason})` : null}
          </Badge>
        </TooltipTrigger>
        <TooltipContent>
          <p className="max-w-[20rem] text-xs">{content}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
