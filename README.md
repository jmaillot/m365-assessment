# M365-Assess Web — Self-hosted M365 Security Assessment

Multi-tenant SaaS (Next.js + TypeScript) — customers sign up, consent via Entra **admin consent**, run a **read-only** Graph assessment and get a scored **self-contained HTML report** (15 frameworks) — no agent, no PowerShell.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)](docker-compose.yml)

## 1. What you need
- Docker + Docker Compose
- Microsoft 365 tenant with **Global Administrator**
- Public HTTPS URL (`APP_BASE_URL`, e.g. `https://assess.example.com` or `http://localhost:3000` for local)
- Operator email for `Settings` allowlist

## 2. Clone & configure `.env`
```bash
git clone <your-repo-url> m365-assess && cd m365-assess
cp .env.example .env
# edit .env — see below
```

`.env` (`gitignored`, `docker-compose.yml` `env_file: .env`):

```dotenv
APP_BASE_URL=http://localhost:3000
AZURE_CLIENT_ID=<Application (client) ID>
AZURE_CLIENT_SECRET=<client secret Value>
AZURE_AUTHORITY=https://login.microsoftonline.com/organizations
SESSION_SECRET=<openssl rand -base64 32>
ENCRYPTION_KEY=<openssl rand -hex 32>   # 64 hex, AES-256-GCM
DATABASE_PATH=/app/data/m365-assess.db
OPERATOR_ADMIN_EMAILS=admin@your-tenant.onmicrosoft.com
```
```bash
openssl rand -base64 32   # SESSION_SECRET
openssl rand -hex 32      # ENCRYPTION_KEY
```

## 3. Create the Entra app (once)
**Entra → App registrations → + New registration:**
- Name `M365-Assess`, **Accounts in any organizational directory (Multitenant)** — work/school only
- **Authentication → + Add a platform → Web** — add:
```
https://YOUR-HOST/api/auth/callback
https://YOUR-HOST/api/tenant/callback
# local also:
http://localhost:3000/api/auth/callback
http://localhost:3000/api/tenant/callback
```
- **API permissions → Add → Microsoft Graph → Application permissions (25):**
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
- **Grant admin consent** (optional, customers consent per tenant anyway)
- **Certificates & secrets → + New client secret** → copy **Value** → put in `.env` `AZURE_CLIENT_SECRET`

## 4. Run with Docker
```bash
docker compose up --build -d
docker compose logs -f
curl -i http://localhost:3000/   # health
# dev without Docker: cd web && npm ci && npm run dev
```

## 5. Use it
1. Sign in as `OPERATOR_ADMIN_EMAILS` at `APP_BASE_URL`
2. **Connect tenant → Accept** as Global Admin in customer tenant
3. **Run assessment** → Report at `/dashboard/runs/[id]` (`Overview`/`Findings`/`Remediation`/`Reviews`/`Frameworks`, `Export HTML` self-contained, `Export CSV` `;`)

Settings → Rotate is allowlisted to `OPERATOR_ADMIN_EMAILS` only.

## License
MIT — see [LICENSE](LICENSE).
