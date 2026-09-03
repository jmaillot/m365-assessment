import { Link2Icon } from "lucide-react";

import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * S3/S4 CTA — "Connect tenant". Renders a PLAIN ANCHOR styled with
 * buttonVariants (NOT a client-side navigation, NOT a render-prop button)
 * so clicking always triggers a full-page GET to /api/tenant/connect,
 * which 302s to Microsoft's /organizations adminconsent endpoint —
 * Microsoft owns the consent UX (UI-SPEC S4, D-05).
 *
 * History: a Base UI `render={<a>}` prop here silently produced a
 * non-navigating element in production builds; a real <a> is immune.
 *
 * D-06 connect gate: when `disabled` is true (no operator credential
 * configured — parent reads getCredentialGate()) the anchor is replaced by
 * a non-interactive, visually-disabled span so no navigation can start.
 */
export function ConnectTenantButton({
  variant = "default",
  className,
  disabled = false,
}: {
  variant?: "default" | "outline" | "secondary";
  className?: string;
  disabled?: boolean;
}) {
  if (disabled) {
    return (
      <span
        role="button"
        aria-disabled="true"
        title="Configure an operator credential in Settings first"
        data-testid="connect-tenant-gated"
        className={cn(
          buttonVariants({ variant }),
          "cursor-not-allowed opacity-50",
          className,
        )}
      >
        <Link2Icon aria-hidden="true" />
        Connect tenant
      </span>
    );
  }
  return (
    <a
      href="/api/tenant/connect"
      className={cn(buttonVariants({ variant }), className)}
    >
      <Link2Icon aria-hidden="true" />
      Connect tenant
    </a>
  );
}
