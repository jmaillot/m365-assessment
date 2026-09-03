
# BUILD-CONTEXT NOTE: this image is built with the REPO ROOT as the context
#   docker compose build web      (docker-compose.yml sets context: .)
# because the npm-workspaces install requires the root package-lock.json
# (D-11 monorepo). A root-level .dockerignore keeps the context small.

# ---- Stage 1: deps — workspace-aware install -------------------------------
# Debian slim (glibc), NOT alpine: better-sqlite3 prefers prebuilt binaries
# for glibc. Toolchain (python3/make/g++) is installed anyway so the source
# build succeeds when the prebuild download is unavailable (offline hosts,
# blocked GitHub releases, NAS appliances). Only this stage carries it.
FROM node:22-slim AS deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
COPY web/package.json web/
RUN npm ci --workspace web

# ---- Stage 2: build — Next.js standalone output ----------------------------
FROM node:22-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY package.json package-lock.json ./
COPY web/package.json web/
COPY --from=deps /app/node_modules ./node_modules
COPY web/ web/
# Controls JSONs are read at runtime (load-controls.ts) — must exist at build
# time for outputFileTracing to snapshot them into the standalone.
COPY src/M365-Assess/controls ./src/M365-Assess/controls
RUN npm run build --workspace web

# ---- Stage 3: runner — slim non-root production image ----------------------
FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    DATABASE_PATH=/app/data/m365-assess.db \
    NEXT_TELEMETRY_DISABLED=1

# SQLite data directory — created and owned by the node user so the named
# volume mounted here stays writable as non-root.
RUN mkdir -p /app/data && chown node:node /app/data

# Standalone output mirrors the workspace layout; server.js lives at web/server.js
COPY --from=builder --chown=node:node /app/web/.next/standalone ./
COPY --from=builder --chown=node:node /app/web/.next/static ./web/.next/static
COPY --from=builder --chown=node:node /app/web/public ./web/public
# Fallback for load-controls.ts resolve(process.cwd(),"..","src",...) which
# expects /app/src/M365-Assess/controls when WORKDIR is /app/web
COPY --from=builder --chown=node:node /app/src/M365-Assess/controls /app/src/M365-Assess/controls

USER node
EXPOSE 3000
WORKDIR /app/web

# Node-based healthcheck (slim image ships no curl/wget): the root route
# must answer HTTP 200 (the sign-in screen). Compose `depends_on` consumers
# and orchestrators can gate on this status.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
