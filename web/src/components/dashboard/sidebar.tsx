"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/utils";
import {
  HistoryIcon,
  LayoutDashboardIcon,
  Link2Icon,
  SettingsIcon,
} from "lucide-react";

/**
 * Dashboard sidebar — UI-SPEC S2: Secondary surface (#18181b), ~240px fixed
 * width, exactly three nav items — nav entries for future phases are added
 * only when those phases ship. Active item indicator uses the accent color.
 */

const linkClass = (active: boolean) =>
  cn(
    "flex items-center gap-3 rounded-lg px-3 py-2 text-base transition-colors",
    active
      ? "bg-primary/15 font-semibold text-primary"
      : "text-secondary-foreground hover:bg-secondary-foreground/10",
  );

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex w-14 shrink-0 flex-col border-r border-border bg-secondary lg:w-60">
      <nav className="flex flex-col gap-1 p-sm" aria-label="Dashboard">
        <Link
          href="/dashboard"
          aria-current={pathname === "/dashboard" ? "page" : undefined}
          className={linkClass(pathname === "/dashboard")}
          title="Dashboard"
        >
          <LayoutDashboardIcon className="size-4 shrink-0" aria-hidden="true" />
          <span className="hidden lg:inline">Dashboard</span>
        </Link>
        <Link
          href="/dashboard/tenant"
          aria-current={pathname.startsWith("/dashboard/tenant") ? "page" : undefined}
          className={linkClass(pathname.startsWith("/dashboard/tenant"))}
          title="Tenant connection"
        >
          <Link2Icon className="size-4 shrink-0" aria-hidden="true" />
          <span className="hidden lg:inline">Tenant connection</span>
        </Link>
        <Link
          href="/dashboard/settings"
          aria-current={pathname.startsWith("/dashboard/settings") ? "page" : undefined}
          className={linkClass(pathname.startsWith("/dashboard/settings"))}
          title="Settings"
        >
          <SettingsIcon className="size-4 shrink-0" aria-hidden="true" />
          <span className="hidden lg:inline">Settings</span>
        </Link>
        <Link
          href="/dashboard/runs"
          aria-current={pathname.startsWith("/dashboard/runs") ? "page" : undefined}
          className={linkClass(pathname.startsWith("/dashboard/runs"))}
          title="Assessment history"
        >
          <HistoryIcon className="size-4 shrink-0" aria-hidden="true" />
          <span className="hidden lg:inline">History</span>
        </Link>
      </nav>
    </aside>
  );
}
