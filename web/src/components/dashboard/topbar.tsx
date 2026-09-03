"use client";

import {
  Avatar,
  AvatarFallback,
} from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  ChevronDownIcon,
  LogOutIcon,
  UnlinkIcon,
} from "lucide-react";
import { useState } from "react";

import { DisconnectDialog } from "@/components/tenant/disconnect-dialog";

/**
 * Dashboard top bar — UI-SPEC S2: Secondary surface showing the signed-in
 * user's name + work email and an avatar user menu.
 * - "Disconnect tenant" appears only when a tenant connection exists
 *   (real `connected` state from Plan 01-04); since Plan 01-05 it opens the
 *   S6 destructive confirmation dialog instead of navigating.
 * - "Sign out" POSTs to /api/auth/signout (Origin-checked server side).
 */

export interface TopbarProps {
  displayName: string;
  email: string;
  connected?: boolean;
  /** Tenant primary domain for the S6 dialog title (connected users only). */
  tenantDomain?: string;
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]!.toUpperCase())
    .join("");
}

export function Topbar({
  displayName,
  email,
  connected = false,
  tenantDomain,
}: TopbarProps) {
  const [disconnectOpen, setDisconnectOpen] = useState(false);

  return (
    <header className="flex items-center justify-between border-b border-border bg-secondary px-md py-sm">
      <span className="text-base font-semibold">M365-Assess</span>

      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button variant="ghost" aria-label="User menu">
              <Avatar size="sm">
                <AvatarFallback>{initials(displayName)}</AvatarFallback>
              </Avatar>
              <span className="hidden flex-col items-start leading-tight sm:flex">
                <span className="text-sm font-semibold">{displayName}</span>
                <span className="text-xs text-muted-foreground">{email}</span>
              </span>
              <ChevronDownIcon className="size-4 text-muted-foreground" />
            </Button>
          }
        />
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel>{email}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {/* "Disconnect tenant" only appears with a live connection
              (UI-SPEC S2); opens the S6 confirmation dialog. */}
          {connected ? (
            <DropdownMenuItem
              variant="destructive"
              onSelect={() => setDisconnectOpen(true)}
            >
              <UnlinkIcon aria-hidden="true" />
              Disconnect tenant
            </DropdownMenuItem>
          ) : null}
          <DropdownMenuItem
            variant="destructive"
            render={
              <form action="/api/auth/signout" method="post" className="w-full">
                <button type="submit" className="flex w-full items-center gap-1.5">
                  <LogOutIcon aria-hidden="true" />
                  Sign out
                </button>
              </form>
            }
          />
        </DropdownMenuContent>
      </DropdownMenu>

      {connected && tenantDomain ? (
        <DisconnectDialog
          domain={tenantDomain}
          open={disconnectOpen}
          onOpenChange={setDisconnectOpen}
        />
      ) : null}
    </header>
  );
}
