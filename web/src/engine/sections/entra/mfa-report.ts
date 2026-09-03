/**
 * Port of `src/M365-Assess/Entra/Get-MfaReport.ps1` (131 lines) — per-user
 * MFA/SSPR registration report (plan 02-05 task 2).
 *
 * PS → TS mapping:
 * - Get-MgReportAuthenticationMethodUserRegistrationDetail -All (PS line 83)
 *   → ONE ctx.transport.getJson call; the SDK's -All pagination is the
 *   transport's automatic nextLink following (D-27). The endpoint is v1.0 —
 *   BETA-ENDPOINTS.md row 1 resolves as promote-to-v1.0 (D-15).
 * - Fetch failure = PS Write-Warning + return (PS lines 85-88) and empty
 *   result = Write-Verbose + return (PS lines 93-96): both degrade to ZERO
 *   rows with no section error — soft-fail parity, never a fabricated row.
 * - Get-MfaMethodStrength classification ported exactly: phishing-resistant
 *   set wins over standard, standard over weak, else Unknown; None when no
 *   methods registered.
 * - Report sorted by UserPrincipalName; MethodsRegistered sorted '; '-joined
 *   or '' when absent (PS lines 99-104).
 *
 * Row mapping (report collector — no Add-SecuritySetting source): one Info
 * row per registration record; Setting = UPN; CurrentValue = report record
 * Field=Value in PS property order. No CheckIds exist for this report.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { asArray, kv, psSort, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const MFA_REPORT_ENDPOINTS = {
  userRegistrationDetails:
    "/v1.0/reports/authenticationMethods/userRegistrationDetails",
} as const;

const CATEGORY = "MFA Registration";

/** Verbatim method tiers from Get-MfaReport.ps1:48-65. */
const PHISHING_RESISTANT = new Set([
  "fido2",
  "windowsHelloForBusiness",
  "x509CertificateMultiFactor",
  "passKeyDeviceBound",
  "passKeyDeviceBoundAuthenticator",
]);
const STANDARD = new Set([
  "microsoftAuthenticatorPush",
  "microsoftAuthenticatorPasswordless",
  "softwareOneTimePasscode",
]);
const WEAK = new Set(["mobilePhone", "alternateMobilePhone", "voiceAlternateMobile", "email"]);

/** Exact port of Get-MfaMethodStrength (Get-MfaReport.ps1:36-72). */
export function getMfaMethodStrength(methods: readonly unknown[]): string {
  if (!methods || methods.length === 0) return "None";
  const has = (set: Set<string>) =>
    methods.some((m) => typeof m === "string" && set.has(m));
  if (has(PHISHING_RESISTANT)) return "Phishing-Resistant";
  if (has(STANDARD)) return "Standard";
  if (has(WEAK)) return "Weak";
  return "Unknown";
}

function sortByUpn<T extends Record<string, unknown>>(items: readonly T[]): T[] {
  return [...items].sort((a, b) => {
    const ka = psStr(a.userPrincipalName);
    const kb = psStr(b.userPrincipalName);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

export const runMfaReport: SectionImplementation = async (ctx) => {
  let details: Record<string, unknown>[];
  try {
    const response = await ctx.transport.getJson(
      MFA_REPORT_ENDPOINTS.userRegistrationDetails,
      { requiredRole: "UserAuthenticationMethod.Read.All" },
    );
    details = asArray(response.value);
  } catch {
    // Soft-fail (PS Write-Warning + return, lines 85-88).
    return;
  }

  if (details.length === 0) {
    // PS Write-Verbose + return (lines 93-96).
    return;
  }

  for (const detail of sortByUpn(details)) {
    const methodsRegistered = Array.isArray(detail.methodsRegistered)
      ? detail.methodsRegistered
      : [];
    const methodsJoined =
      methodsRegistered.length > 0
        ? psSort(methodsRegistered.map((m) => String(m))).join("; ")
        : "";

    ctx.addRow({
      category: CATEGORY,
      setting: psStr(detail.userPrincipalName),
      currentValue: kv([
        ["UserDisplayName", detail.userDisplayName],
        ["IsMfaRegistered", detail.isMfaRegistered],
        ["IsMfaCapable", detail.isMfaCapable],
        ["IsPasswordlessCapable", detail.isPasswordlessCapable],
        ["IsSsprRegistered", detail.isSsprRegistered],
        ["IsSsprCapable", detail.isSsprCapable],
        ["MethodsRegistered", methodsJoined],
        ["DefaultMfaMethod", detail.defaultMfaMethod],
        ["MfaStrength", getMfaMethodStrength(methodsRegistered)],
        ["IsAdmin", detail.isAdmin],
      ]),
      recommendedValue: "",
      psStatus: "Info",
    });
  }
};
