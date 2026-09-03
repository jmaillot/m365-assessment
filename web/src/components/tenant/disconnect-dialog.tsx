"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { LoaderCircleIcon, UnlinkIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

/**
 * S6 — Disconnect confirmation dialog (UI-SPEC, ONB-03/D-08).
 *
 * Destructive two-step confirm opened by BOTH entry points: the topbar
 * user-menu item and the Disconnect button on the tenant status card.
 * Copy matches the UI-SPEC Copywriting Contract verbatim; Cancel is
 * default-focused so an accidental Enter cancels instead of destroying
 * data (T-05-06). Confirm POSTs /api/tenant/disconnect and routes back to
 * S3 (/dashboard) with ?cleanup=1 so the optional Entra cleanup guidance
 * renders above the empty state.
 */

// Copywriting Contract strings kept as constants for exact-match guarantees.
const DISCONNECT_BODY_COPY =
  "This revokes M365-Assess's access tokens and permanently deletes your tenant data from our database. To fully remove access, you'll also need to delete the M365-Assess enterprise application in your own Entra tenant — we'll show you how.";
const ACTION_ERROR_COPY =
  "We couldn't reach the server. Check your connection and try again.";

export interface DisconnectDialogProps {
  /** Tenant primary domain interpolated into the title. */
  domain: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function DisconnectDialog({
  domain,
  open,
  onOpenChange,
}: DisconnectDialogProps) {
  const router = useRouter();
  const [pending, setPending] = useState(false);

  async function handleDisconnect() {
    setPending(true);
    try {
      const response = await fetch("/api/tenant/disconnect", {
        method: "POST",
      });
      if (!response.ok) {
        if (response.status === 401) {
          // Session expired mid-dialog: send to sign-in with expiry notice.
          router.push("/?notice=session_expired");
          return;
        }
        throw new Error(`disconnect failed (${response.status})`);
      }
      onOpenChange(false);
      router.push("/dashboard?cleanup=1");
    } catch {
      toast.error(ACTION_ERROR_COPY);
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Disconnect {domain}?</DialogTitle>
          <DialogDescription>{DISCONNECT_BODY_COPY}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          {/* Cancel receives default focus (UI-SPEC S6): accidental Enter or
              opening-and-Enter never destroys data (T-05-06). */}
          <Button
            variant="outline"
            autoFocus
            disabled={pending}
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={pending}
            onClick={() => void handleDisconnect()}
          >
            {pending ? (
              <LoaderCircleIcon className="animate-spin" aria-hidden="true" />
            ) : (
              <UnlinkIcon aria-hidden="true" />
            )}
            Disconnect tenant
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Self-contained status-card entry point: destructive-styled "Disconnect"
 * button + its dialog (S6 second entry point).
 */
export function DisconnectTenantButton({ domain }: { domain: string }) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button variant="destructive" onClick={() => setOpen(true)}>
        <UnlinkIcon aria-hidden="true" />
        Disconnect
      </Button>
      <DisconnectDialog domain={domain} open={open} onOpenChange={setOpen} />
    </>
  );
}
