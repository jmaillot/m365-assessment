"use client";

import { useState, useTransition, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import {
  CheckIcon,
  CircleCheckIcon,
  LoaderCircleIcon,
  TriangleAlertIcon,
} from "lucide-react";

import { ConnectTenantButton } from "@/components/tenant/connect-button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";

import type { TenantStatus } from "@/lib/tenant/status";
import { REQUIRED_GRAPH_SCOPES } from "@/lib/graph/required-scopes";
import type { VerificationResult } from "@/lib/graph/verify-permissions";

/**
 * S5 — Permission verification view (UI-SPEC, ONB-02/D-07).
 *
 * Three-state summary banner (all_granted / missing / error) above a scope
 * checklist sorted missing-first then alphabetical. The `error` state is
 * DISTINCT from zero-missing: a token-acquisition failure renders the
 * could-not-verify banner with a retry affordance — never a green checklist.
 */

// Copywriting Contract strings kept as constants for exact-match guarantees.
const ALL_GRANTED_COPY =
  "All required permissions are granted. Your tenant is ready — assessments will be available soon.";
const MISSING_BODY_COPY =
  "A Global Administrator must grant admin consent again before assessments can run.";
const ERROR_BANNER_COPY =
  "We couldn't reach the server. Check your connection and try again.";
const CONSENT_DECLINED_COPY =
  "Consent wasn't completed. A Global Administrator must approve admin consent before M365-Assess can connect your tenant.";

export interface VerificationViewProps {
  tenant: NonNullable<TenantStatus["tenant"]>;
  verification?: VerificationResult;
  /** ?error=consent_declined — Microsoft returned an explicit decline. */
  consentDeclined?: boolean;
  /**
   * D-06 connect gate (from getCredentialGate() in the server parent):
   * disables the reconnect CTA while no operator credential is configured.
   */
  connectGated?: boolean;
  /**
   * Optional action area rendered on the tenant status card (UI-SPEC S6
   * second entry point: the destructive "Disconnect" button).
   */
  actions?: ReactNode;
}

export function VerificationView({
  tenant,
  verification,
  consentDeclined = false,
  connectGated = false,
  actions,
}: VerificationViewProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [retrying, setRetrying] = useState(false);

  if (!verification) {
    // Verification absent (transient post-consent window): accent spinner +
    // skeleton of the target card layout (loading convention).
    return (
      <div className="flex max-w-[42rem] flex-col gap-md" aria-busy="true">
        <p className="flex items-center gap-sm text-sm text-muted-foreground">
          <LoaderCircleIcon
            className="size-4 animate-spin text-primary"
            aria-hidden="true"
          />
          Verifying permissions…
        </p>
        <Card>
          <CardHeader>
            <Skeleton className="h-5 w-48" />
            <Skeleton className="h-4 w-64" />
          </CardHeader>
          <CardContent className="flex flex-col gap-sm">
            {Array.from({ length: 5 }).map((_, index) => (
              <div key={index} className="flex items-start gap-sm">
                <Skeleton className="mt-0.5 size-4 shrink-0 rounded-full" />
                <div className="flex flex-col gap-1">
                  <Skeleton className="h-3.5 w-56" />
                  <Skeleton className="h-3.5 w-80" />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    );
  }

  async function retryVerification() {
    setRetrying(true);
    try {
      const response = await fetch("/api/tenant/verify", { method: "POST" });
      if (!response.ok) {
        throw new Error(`verify request failed (${response.status})`);
      }
      startTransition(() => router.refresh());
    } catch {
      toast.error(ERROR_BANNER_COPY);
    } finally {
      setRetrying(false);
    }
  }

  const granted = verification.status === "all_granted";
  const missingCount = verification.missing.length;
  const totalCount = verification.required.length;
  const isMissing = verification.status === "missing";
  const isError = verification.status === "error";

  // Checklist rows: merge REQUIRED_GRAPH_SCOPES purposes with the missing[]
  // list; sorted MISSING FIRST, then alphabetical by scope name. Names render
  // monospaced and never truncate.
  const missingLower = new Set(
    verification.missing.map((scope) => scope.toLowerCase()),
  );
  const checklistRows = REQUIRED_GRAPH_SCOPES.map(({ name, purpose }) => ({
    name,
    purpose,
    missing: missingLower.has(name.toLowerCase()),
  })).sort((a, b) => {
    if (a.missing !== b.missing) return a.missing ? -1 : 1; // missing first
    return a.name.localeCompare(b.name); // then alphabetical
  });

  return (
    <section className="flex max-w-[42rem] flex-col gap-lg">
      {/* Header card: tenant name + domain + connection badge */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-md">
            <CardTitle className="text-xl font-semibold">
              {tenant.name ?? tenant.primaryDomain ?? "Microsoft 365 tenant"}
            </CardTitle>
            <Badge>Connected</Badge>
          </div>
          <CardDescription className="break-all whitespace-normal">
            {tenant.primaryDomain ?? tenant.id}
          </CardDescription>
        </CardHeader>
        {actions ? <CardContent>{actions}</CardContent> : null}
      </Card>

      {/* Consent-declined guidance (returned from /api/tenant/callback) */}
      {consentDeclined ? (
        <Alert variant="destructive">
          <TriangleAlertIcon aria-hidden="true" />
          <AlertTitle>Admin consent wasn&apos;t completed</AlertTitle>
          <AlertDescription>{CONSENT_DECLINED_COPY}</AlertDescription>
        </Alert>
      ) : null}

      {/* Summary banner — three states, fail-explicit */}
      {granted ? (
        <Alert className="border-success/40">
          <CircleCheckIcon className="text-success" aria-hidden="true" />
          <AlertTitle>{ALL_GRANTED_COPY}</AlertTitle>
        </Alert>
      ) : null}
      {isMissing ? (
        <Alert variant="destructive">
          <TriangleAlertIcon className="text-warning" aria-hidden="true" />
          <AlertTitle className="font-semibold">
            {missingCount} of {totalCount} required permissions are missing.
          </AlertTitle>
          <AlertDescription className="flex flex-col gap-md">
            {MISSING_BODY_COPY}
            <div>
              <ConnectTenantButton variant="secondary" disabled={connectGated} />
            </div>
          </AlertDescription>
        </Alert>
      ) : null}
      {isError ? (
        <Alert variant="destructive">
          <TriangleAlertIcon aria-hidden="true" />
          <AlertTitle>We couldn&apos;t verify your permissions</AlertTitle>
          <AlertDescription className="flex flex-col gap-md">
            {ERROR_BANNER_COPY}
            <div>
              <Button
                variant="outline"
                onClick={() => void retryVerification()}
                disabled={retrying || isPending}
              >
                Try again
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      ) : null}

      {/* Scope checklist: green ✓ granted / amber ⚠ missing */}
      <Card>
        <CardContent className="flex flex-col divide-y divide-border">
          {checklistRows.map((row) => (
            <div key={row.name} className="flex items-start gap-sm py-sm first:pt-0 last:pb-0">
              {row.missing ? (
                <TriangleAlertIcon
                  className="mt-0.5 size-4 shrink-0 text-warning"
                  aria-hidden="true"
                />
              ) : (
                <CheckIcon
                  className="mt-0.5 size-4 shrink-0 text-success"
                  aria-hidden="true"
                />
              )}
              <div className="min-w-0 flex flex-col gap-0.5">
                <span className="font-mono text-xs font-medium break-all whitespace-normal">
                  {row.name}
                </span>
                <span className="text-sm text-muted-foreground break-all whitespace-normal">
                  {row.purpose}
                </span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </section>
  );
}
