"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";

import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const CARD_TITLE = "Entra ID assessment";
const CARD_BODY = "Runs read-only checks against your Microsoft 365 tenant and produces a scored report.";
const BUTTON_RUN = "Run assessment";
const BUTTON_IN_PROGRESS = "Assessment in progress";
const BUTTON_VIEW_RUN = "View run";
const HELPER_GATED = "Configure the operator credential in Settings first.";
const HELPER_PERMISSIONS = "Resolve the permission verification alert above before running an assessment.";
const ERROR_GENERIC = "We couldn't reach the server. Check your connection and try again.";

export interface RunTriggerCardProps {
  gated: boolean;
  permissionsMissing: boolean;
  activeRunId?: string;
}

export function RunTriggerCard({ gated, permissionsMissing, activeRunId: initialActiveRunId }: RunTriggerCardProps) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [resolvedActiveRunId, setResolvedActiveRunId] = useState<string | undefined>(initialActiveRunId);

  // Keep in sync if server prop changes (e.g. after router.refresh())
  useEffect(() => {
    setResolvedActiveRunId(initialActiveRunId);
  }, [initialActiveRunId]);

  const refreshActiveRun = useCallback(async () => {
    try {
      const res = await fetch("/api/runs", { method: "GET", cache: "no-store" });
      if (!res.ok) return;
      const data = (await res.json()) as { activeRunId: string | null };
      const fresh = data.activeRunId ?? undefined;
      setResolvedActiveRunId((prev) => {
        if (fresh !== prev) {
          if (fresh) router.refresh();
          return fresh;
        }
        return prev;
      });
    } catch {
      // ignore - stale UI is preferable to an error toast on back-navigation
    }
  }, [router]);

  // Self-correct stale bfcache / Next router-cache on back-navigation.
  // The tenant page is force-dynamic server-side, but the browser may restore
  // a cached DOM snapshot on `back` without re-running the server component.
  useEffect(() => {
    // Only poll when we think there is no active run - if the prop already
    // says active, the in-progress UI is already correct.
    if (!initialActiveRunId) {
      void refreshActiveRun();
    }

    const onPageShow = () => {
      void refreshActiveRun();
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") void refreshActiveRun();
    };

    window.addEventListener("pageshow", onPageShow);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("pageshow", onPageShow);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [initialActiveRunId, refreshActiveRun]);

  const activeRunId = resolvedActiveRunId;
  const isActive = !!activeRunId;
  const isGated = gated;
  const isPermissionsMissing = permissionsMissing && !isGated && !isActive;

  const disabled = pending || isGated || isPermissionsMissing || isActive;

  const handleRun = async () => {
    if (disabled) return;
    setPending(true);
    try {
      const res = await fetch("/api/runs", { method: "POST", cache: "no-store" });
      if (res.status === 201) {
        const data = (await res.json()) as { runId: string };
        router.push(`/dashboard/runs/${data.runId}`);
        return;
      }
      if (res.status === 409) {
        try {
          const data = (await res.json()) as { activeRunId: string };
          if (data.activeRunId) {
            setResolvedActiveRunId(data.activeRunId);
            router.push(`/dashboard/runs/${data.activeRunId}`);
            return;
          }
        } catch {
          // fall through to refresh check below
        }
        // Even if payload is unreadable, we know a run is active — re-check server truth
        await refreshActiveRun();
        toast.error("An assessment is already in progress.");
        return;
      }
      let message: string | undefined;
      try {
        const body = (await res.json()) as { error?: string; message?: string };
        if (body.error) {
          message = body.error === "run_in_progress" ? "An assessment is already in progress." : body.message ?? body.error;
        }
      } catch {}
      toast.error(message ?? ERROR_GENERIC);
    } catch {
      toast.error(ERROR_GENERIC);
    } finally {
      setPending(false);
    }
  };

  let helper: string | null = null;
  if (isGated) {
    helper = HELPER_GATED;
  } else if (isPermissionsMissing) {
    helper = HELPER_PERMISSIONS;
  }

  // Active run state: disabled button swapped to in-progress label + secondary link
  if (isActive) {
    return (
      <Card className="max-w-[32rem]">
        <CardHeader>
          <CardTitle>{CARD_TITLE}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-md">
          <p className="text-base leading-relaxed text-muted-foreground">{CARD_BODY}</p>
          <div className="flex flex-col gap-sm2">
            <span
              role="button"
              aria-disabled="true"
              title="An assessment is already running for this tenant"
              data-testid="run-trigger-active"
              className={cn(buttonVariants({ variant: "default" }), "cursor-not-allowed opacity-50")}
            >
              {BUTTON_IN_PROGRESS}
            </span>
            <Link
              href={`/dashboard/runs/${activeRunId}`}
              className={cn(buttonVariants({ variant: "secondary" }))}
              data-testid="view-run-link"
            >
              {BUTTON_VIEW_RUN}
            </Link>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="max-w-[32rem]">
      <CardHeader>
        <CardTitle>{CARD_TITLE}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-md">
        <p className="text-base leading-relaxed text-muted-foreground">{CARD_BODY}</p>
        <div className="flex flex-col gap-sm2">
          <Button
            onClick={handleRun}
            disabled={disabled}
            aria-disabled={disabled}
            title={helper ?? undefined}
            data-testid={isGated ? "run-trigger-gated" : isPermissionsMissing ? "run-trigger-permissions-missing" : "run-assessment-button"}
            className={cn(disabled && "cursor-not-allowed opacity-50")}
          >
            {pending ? (
              <>
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                {BUTTON_RUN}
              </>
            ) : (
              BUTTON_RUN
            )}
          </Button>
          {helper ? <p className="text-sm text-muted-foreground">{helper}</p> : null}
        </div>
      </CardContent>
    </Card>
  );
}
