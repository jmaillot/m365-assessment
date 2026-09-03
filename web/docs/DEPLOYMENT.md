# M365-Assess Web — Deployment Guide

Run M365-Assess as a self-hosted Docker container in front of your own
reverse proxy with TLS (D-13). One container serves the whole app
(Next.js + SQLite on a persistent volume); there is no other service to run.

> **Audience:** whoever operates the server (IT consultant / internal IT).
> Customer-facing Entra app registration steps live in
> [`APP-REGISTRATION-SETUP.md`](APP-REGISTRATION-SETUP.md).

---

## 1. Prerequisites

- A Linux host (or any Docker-capable machine) with **Docker Engine** and the
  **Compose plugin**.
- A public hostname with DNS pointed at the host (production), e.g.
  `https://YOUR-HOST`.
- An Azure app registration per [`APP-REGISTRATION-SETUP.md`](APP-REGISTRATION-SETUP.md).

## 2. Configure environment

```bash
git clone <this repository>
cd M365-Assess
cp .env.example .env
```

Generate strong secrets and fill in `.env`:

```bash
# Session signing secret (SESSION_SECRET)
openssl rand -base64 32

# Refresh-token encryption key (ENCRYPTION_KEY) — must be exactly 64 hex chars
openssl rand -hex 32
```

| Variable | Production value |
|---|---|
| `APP_BASE_URL` | `https://YOUR-HOST` (public URL — drives OAuth redirect URIs; https also enables `Secure` cookies) |
| `AZURE_CLIENT_ID` | Application (client) ID from the app registration |
| `AZURE_CLIENT_SECRET` | Client secret from the app registration |
| `SESSION_SECRET` | Output of `openssl rand -base64 32` |
| `ENCRYPTION_KEY` | Output of `openssl rand -hex 32` (AES-256-GCM key for stored refresh tokens) |
| `DATABASE_PATH` | Leave at `/app/data/m365-assess.db` — inside the persistent volume |

## 3. Build and run

```bash
docker compose up -d --build
docker compose logs -f web   # wait for "Ready"
```

The image is built from `web/Dockerfile` with the repo root as build context
(`docker-compose.yml` sets this — the workspace install needs the root
lockfile). The runner stage is non-root (`USER node`) and includes a
container `HEALTHCHECK` against the app root; check it with
`docker inspect --format '{{.State.Health.Status}}' <container>`.

Verify: open `http://YOUR-HOST:3000` behind your proxy (next section) and
confirm the sign-in screen renders.

## 4. TLS via reverse proxy (required in production)

Never expose plain HTTP beyond localhost evaluation. Pick ONE of:

### Option A — Caddy (automatic HTTPS, recommended)

```caddyfile
YOUR-HOST {
    reverse_proxy 127.0.0.1:3000
}
```

Caddy obtains and renews certificates automatically. Compose the container
to publish only on loopback so traffic must traverse the proxy — in
`docker-compose.yml` replace the ports mapping with:

```yaml
    ports:
      - "127.0.0.1:3000:3000"
```

### Option B — Traefik labels

```yaml
services:
  web:
    # ...existing compose service config...
    networks: [proxy]
    labels:
      - traefik.enable=true
      - traefik.http.routers.m365assess.rule=Host(`YOUR-HOST`)
      - traefik.http.routers.m365assess.entrypoints=websecure
      - traefik.http.routers.m365assess.tls.certresolver=myresolver
      - traefik.http.services.m365assess.loadbalancer.server.port=3000
networks:
  proxy:
    external: true
```

(Run Traefik separately with an ACME certificate resolver named
`myresolver`; remove the `ports:` mapping entirely.)

### Option C — Cloudflare Tunnel

No inbound ports needed:

```bash
cloudflared tunnel create m365-assess
cloudflared tunnel route dns m365-assess YOUR-HOST
cloudflared tunnel run --url http://127.0.0.1:3000 m365-assess
```

Run as a service per Cloudflare's docs. TLS terminates at Cloudflare's edge.

## 5. Data, backups, upgrades

**Storage:** all state lives in one SQLite file on the `web-data` volume,
mounted at `/app/data` (D-12). WAL journaling is enabled.

**Backup:** SQLite files cannot be safely copied mid-write while the app is
running. Either stop briefly or snapshot consistently:

```bash
# Safe backup (brief downtime)
docker compose stop web
docker run --rm -v m365-assess_web-data:/data -v "$PWD":/backup alpine \
  cp /data/m365-assess.db /backup/
docker compose start web
```

Note the `-v` suffix is the Compose project name prefix; adjust if your
project directory is named differently (`docker volume ls` lists it). Do not
copy the `-wal`/`-shm` sidecar files independently of the main database.

**Upgrade:**

```bash
git pull
docker compose up -d --build
```

Database migrations run automatically at container boot, so upgrades need no
manual migration step.

## 6. Entra redirect URIs after go-live

Once real customers onboard, your app registration MUST use public HTTPS
redirect URIs:

```text
https://YOUR-HOST/api/auth/callback
https://YOUR-HOST/api/tenant/callback
```

`localhost` variants are for development only. If you change `APP_BASE_URL`,
update both redirect URIs in the Entra app registration to match exactly —
see [`APP-REGISTRATION-SETUP.md`](APP-REGISTRATION-SETUP.md).
