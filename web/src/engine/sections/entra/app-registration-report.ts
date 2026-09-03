/**
 * Port of `src/M365-Assess/Entra/Get-AppRegistrationReport.ps1` (123 lines)
 * — app registrations with credential expiry status (plan 02-05 task 2).
 *
 * PS → TS mapping:
 * - Get-MgApplication -All -Property ... (PS line 44) → ONE getJson call with
 *   the same field list in $select; failure throws → runner surfaces a
 *   section error (PS Write-Error + return, lines 47-49); empty set returns
 *   zero rows (PS lines 54-57).
 * - Credential loops ported literally (PS lines 61-91): counts per credential
 *   kind; EndDateTime present → contributes to allExpiries and increments
 *   expiredCount when earlier than now.
 * - Earliest expiry renders 'yyyy-MM-dd HH:mm:ss' (PS line 95) — formatted
 *   from UTC parts here because PS formats local time, which is not
 *   deterministic across machines (deviation documented in SUMMARY).
 * - Report sorted by DisplayName (PS line 113).
 *
 * Row mapping (report collector): one Info row per app registration;
 * Setting = DisplayName; CurrentValue = report record Field=Value in PS
 * property order. Expiry comparisons are now-relative — tests freeze the
 * clock.
 */
import type { SectionImplementation } from "@/engine/runner/engine";
import { asArray, kv, psStr } from "./shared";

/** Declared GET path (mirrored into registry endpoints[] by plan 02-12). */
export const APP_REGISTRATION_REPORT_ENDPOINTS = {
  applications:
    "/v1.0/applications?$select=id,displayName,appId,createdDateTime,signInAudience,passwordCredentials,keyCredentials",
} as const;

const CATEGORY = "App Registrations";

interface AppRegistrationRecord {
  displayName: string;
  appId: unknown;
  createdDateTime: unknown;
  signInAudience: unknown;
  passwordCredentialCount: number;
  keyCredentialCount: number;
  earliestExpiry: string;
  expiredCredentials: number;
}

/** PS 'yyyy-MM-dd HH:mm:ss' shape from UTC parts (deterministic). */
function formatPsDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const p2 = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())} ` +
    `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`
  );
}

function credentialList(value: unknown): Array<{ endDateTime?: unknown }> {
  return Array.isArray(value)
    ? (value as Array<{ endDateTime?: unknown }>)
    : [];
}

export const runAppRegistrationReport: SectionImplementation = async (ctx) => {
  const appsResponse = await ctx.transport.getJson(
    APP_REGISTRATION_REPORT_ENDPOINTS.applications,
    { requiredRole: "Application.Read.All" },
  );
  const allApps = asArray(appsResponse.value);
  if (allApps.length === 0) return;

  const nowMs = Date.now();
  const records: AppRegistrationRecord[] = [];

  for (const app of allApps) {
    let passwordCredCount = 0;
    let keyCredCount = 0;
    let expiredCount = 0;
    const allExpiries: number[] = [];

    // Password credentials (client secrets) — PS lines 67-78.
    const passwordCredentials = credentialList(app.passwordCredentials);
    passwordCredCount = passwordCredentials.length;
    for (const cred of passwordCredentials) {
      if (cred.endDateTime !== null && cred.endDateTime !== undefined && cred.endDateTime !== "") {
        const ms = Date.parse(psStr(cred.endDateTime));
        if (!Number.isNaN(ms)) {
          allExpiries.push(ms);
          if (ms < nowMs) expiredCount += 1;
        }
      }
    }

    // Key credentials (certificates) — PS lines 80-91.
    const keyCredentials = credentialList(app.keyCredentials);
    keyCredCount = keyCredentials.length;
    for (const cred of keyCredentials) {
      if (cred.endDateTime !== null && cred.endDateTime !== undefined && cred.endDateTime !== "") {
        const ms = Date.parse(psStr(cred.endDateTime));
        if (!Number.isNaN(ms)) {
          allExpiries.push(ms);
          if (ms < nowMs) expiredCount += 1;
        }
      }
    }

    // Earliest expiry across all credentials (PS lines 93-99).
    const earliestExpiry =
      allExpiries.length > 0
        ? formatPsDateTime(new Date(Math.min(...allExpiries)).toISOString())
        : "";

    records.push({
      displayName: psStr(app.displayName),
      appId: app.appId,
      createdDateTime: app.createdDateTime,
      signInAudience: app.signInAudience,
      passwordCredentialCount: passwordCredCount,
      keyCredentialCount: keyCredCount,
      earliestExpiry,
      expiredCredentials: expiredCount,
    });
  }

  records.sort((a, b) =>
    a.displayName < b.displayName ? -1 : a.displayName > b.displayName ? 1 : 0,
  );

  for (const r of records) {
    ctx.addRow({
      category: CATEGORY,
      setting: r.displayName,
      currentValue: kv([
        ["AppId", r.appId],
        ["CreatedDateTime", r.createdDateTime],
        ["SignInAudience", r.signInAudience],
        ["PasswordCredentialCount", r.passwordCredentialCount],
        ["KeyCredentialCount", r.keyCredentialCount],
        ["EarliestExpiry", r.earliestExpiry],
        ["ExpiredCredentials", r.expiredCredentials],
      ]),
      recommendedValue: "",
      psStatus: "Info",
    });
  }
};
