# App Registration Setup

You (operator) register **one** multi-tenant app. Customers only click **Connect tenant → Accept** — no secret, no app.

## Operator — once

**Prerequisites:** Entra `Application Administrator` or `Global Administrator` + your `APP_BASE_URL` (`https://assess.example.com` or `http://localhost:3000`).

**1. App registrations → + New registration**
- Name `M365-Assess`, **Accounts in any organizational directory (Multitenant)**, Register → copy **Application (client) ID**.

**2. Authentication → + Add a platform → Web**
```
https://YOUR-HOST/api/auth/callback
https://YOUR-HOST/api/tenant/callback
# local also:
http://localhost:3000/api/auth/callback
http://localhost:3000/api/tenant/callback
```
Web (not SPA), production HTTPS.

**3. API permissions → Microsoft Graph → Application permissions (25)**
```
Organization.Read.All, Domain.Read.All, Policy.Read.All, User.Read.All, Group.Read.All,
AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory,
Application.Read.All, Directory.Read.All, Agreement.Read.All, SecurityEvents.Read.All,
ThreatIntelligence.Read.All, SecurityAlert.Read.All, InformationProtectionPolicy.Read.All,
DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All,
DeviceManagementServiceConfig.Read.All, SharePointTenantSettings.Read.All,
TeamSettings.Read.All, TeamworkAppSettings.Read.All, OrgSettings-Forms.Read.All,
Sites.Read.All, RecordsManagement.Read.All
Tenant.Read.All  # Power BI Service (not Graph) — only if you use Power BI
```
Remove default Delegated `User.Read`. Grant admin consent if you want.

**4. Certificates & secrets → + New client secret → Value → put in `.env`:**
```dotenv
AZURE_CLIENT_ID=<Application ID>
AZURE_CLIENT_SECRET=<Value>
```
Server encrypts at rest on first boot; `Settings` is only for rotation.

## Customer — per tenant (2 clicks)

1. Sign in to your hosted app.
2. **Connect tenant → Accept** as Global Admin.

No secret, no permission add. Re-consent if roles show `missing`.

## Notes

- **Read-only** `GET` only — never writes.
- `Disconnect` deletes tenant rows; customer also deletes **Enterprise application** in their tenant to revoke consent.
