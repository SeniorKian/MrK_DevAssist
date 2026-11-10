# syntax=docker/dockerfile:1.7

ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"
# Package sources used while building the image. Empty = use the hosts recorded in
# the lockfiles / default PyPI.
# - npm: package-lock.json sha512 integrity hashes are still enforced, so an npm
#   mirror cannot change package contents.
# - pip: the direct runtime packages are version-pinned, but pip does NOT verify
#   hashes and transitive dependencies are resolved at build time, so a
#   PIP_INDEX_URL mirror must be trusted as much as PyPI itself.
#   TODO: generate a hashed lock (pip-compile --generate-hashes for linux/py3.13,
#   amd64 and arm64) and install it with --require-hashes --no-deps.
#   docker build --build-arg NPM_REGISTRY=https://registry.npmjs.org/ ...
#   docker build --build-arg PIP_INDEX_URL=https://pypi.org/simple/ ...
ARG NPM_REGISTRY=""
ARG PIP_INDEX_URL=""
# - go: go.sum pins every module hash, so a GOPROXY mirror cannot change module
#   contents (like the npm lockfile integrity hashes).
#   docker build --build-arg GOPROXY=https://proxy.golang.org,direct ...
ARG GOPROXY=""
# - apt: package lists are signed by the Debian archive keys already in the base
#   image, so a mirror cannot change package contents. It must serve both
#   /debian and /debian-security.
#   docker build --build-arg APT_MIRROR=http://deb.debian.org ...
ARG APT_MIRROR=""

FROM node:24.18.0-trixie-slim@sha256:ae91dcc111a68c9d2d81ff2a17bda61be126426176fde6fe7d08ab13b7f50573 AS admin-builder
ARG NPM_REGISTRY
WORKDIR /build/admin-ui
COPY apps/admin-ui/package.json apps/admin-ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY" && npm config set replace-registry-host always; fi; npm ci --ignore-scripts
COPY apps/admin-ui/ ./
# Build metadata comes after `npm ci` so a new commit keeps the dependency layer cached.
ARG VCS_REF
ARG BUILD_DATE
ENV VITE_BUILD_COMMIT=$VCS_REF \
    VITE_BUILD_DATE=$BUILD_DATE
RUN npm run build

FROM node:24.18.0-trixie-slim@sha256:ae91dcc111a68c9d2d81ff2a17bda61be126426176fde6fe7d08ab13b7f50573 AS verdaccio-builder
ARG NPM_REGISTRY
WORKDIR /opt/verdaccio
COPY deploy/verdaccio/package.json deploy/verdaccio/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY" && npm config set replace-registry-host always; fi; npm ci --omit=dev --ignore-scripts
# docs/43 §0.1: pre-publish size quota for «My space» scopes (no dependencies).
COPY deploy/verdaccio/plugins ./plugins

FROM node:24.18.0-trixie-slim@sha256:ae91dcc111a68c9d2d81ff2a17bda61be126426176fde6fe7d08ab13b7f50573 AS pglite-builder
ARG NPM_REGISTRY
WORKDIR /opt/pglite
COPY deploy/pglite/package.json deploy/pglite/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY" && npm config set replace-registry-host always; fi; npm ci --omit=dev --ignore-scripts

# MRK DNS engine (docs/36, docs/37): static Go binaries, built here and copied into
# the runtime image (no separate image, no Go toolchain at runtime).
FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS dns-builder
ARG GOPROXY
ENV CGO_ENABLED=0 \
    GOFLAGS=-trimpath \
    GOTOOLCHAIN=local
WORKDIR /build/dns-engine
COPY apps/dns-engine/go.mod apps/dns-engine/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod if [ -n "$GOPROXY" ]; then export GOPROXY; else unset GOPROXY; fi; \
    go mod download && go mod verify
COPY apps/dns-engine/ ./
ARG VCS_REF
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -buildvcs=false -ldflags "-s -w -X mrk/dns-engine/internal/version.Commit=${VCS_REF:-unknown}" \
      -o /out/mrk-dns ./cmd/mrk-dns \
    && go build -buildvcs=false -ldflags "-s -w" -o /out/mrk-dnsbench ./cmd/mrk-dnsbench \
    && /out/mrk-dns version

FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS runtime

ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"
ARG SOURCE_URL="unknown"
ARG PIP_INDEX_URL
ARG APT_MIRROR

LABEL org.opencontainers.image.title="MrK DevAssist" \
      org.opencontainers.image.description="Self-hosted server and DevOps assistant next to Dokploy: npm/PyPI mirrors, S3, DNS, backups, monitoring" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="$SOURCE_URL" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MRK_ENV=production \
    MRK_DATA_DIR=/data \
    MRK_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:5433/postgres?sslmode=disable \
    MRK_ADMIN_UI_DIR=/opt/mrk/admin-ui \
    MRK_NPM_ENABLED=true \
    MRK_NPM_HEALTH_PORT=4873 \
    MRK_PYPI_ENABLED=true \
    MRK_PYPI_HEALTH_PORT=3141 \
    MRK_PYPI_SERVER_DIR=/data/pypi/server \
    MRK_PYPI_BOOTSTRAP_STATE_FILE=/data/pypi/auth/upstream-configured \
    MRK_PYPI_UPSTREAM_URL=http://127.0.0.1:3142/simple/ \
    MRK_PYPI_PRIMARY_UPSTREAM=https://pypi.org/simple/ \
    MRK_PYPI_FALLBACK_UPSTREAM=https://package-mirror.liara.ir/repository/pypi/simple/ \
    MRK_PYPI_ROUTER_PORT=3142 \
    MRK_PYPI_ROUTER_HEALTH_HOST=127.0.0.1 \
    MRK_PYPI_ROUTER_READ_TIMEOUT=90 \
    MRK_PYPI_REQUEST_TIMEOUT=900 \
    MRK_AUTH_COOKIE_SECURE=true \
    MRK_SESSION_TTL_SECONDS=28800 \
    MRK_BUILD_COMMIT=$VCS_REF \
    MRK_BUILD_DATE=$BUILD_DATE \
    MRK_HOST=0.0.0.0 \
    MRK_PORT=8080

RUN groupadd --gid 10001 mrk \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin mrk

# Gate 19 S7: the nft CLI for the optional mrk-firewall helper. Only that service
# gets CAP_NET_ADMIN; in every other process the binary is inert. No service is
# enabled (there is no init system in the image).
# apt-get upgrade pulls Debian security fixes newer than the pinned base image.
RUN if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|http://deb.debian.org|${APT_MIRROR%/}|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/mrk
COPY LICENSE /opt/mrk/LICENSE
COPY apps/control-plane/pyproject.toml /tmp/control-plane/pyproject.toml
COPY apps/control-plane/src /tmp/control-plane/src
# Single source of truth for the runtime pins (also used by CI, tracked by Dependabot).
COPY deploy/appliance/requirements.txt /tmp/runtime-requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} /tmp/control-plane \
      -r /tmp/runtime-requirements.txt \
    && python -c "import importlib.metadata as md, sys; pins = [line.strip().split('==') for line in open('/tmp/runtime-requirements.txt') if '==' in line and not line.startswith('#')]; bad = [(name, want, md.version(name)) for name, want in pins if md.version(name) != want]; sys.exit(f'runtime pin mismatch: {bad}' if bad else 0)" \
    && python -m pip uninstall --yes pip wheel \
    && rm -rf /tmp/control-plane /tmp/runtime-requirements.txt /usr/local/lib/python3.13/ensurepip

COPY --from=verdaccio-builder /usr/local/bin/node /usr/local/bin/node
COPY --from=verdaccio-builder /opt/verdaccio /opt/verdaccio
COPY --from=pglite-builder /opt/pglite /opt/pglite
COPY --from=admin-builder /build/admin-ui/dist /opt/mrk/admin-ui
# MRK DNS engine. No file capabilities: with no-new-privileges the kernel ignores
# them on execve. The mrk-dns service starts as uid 0 with only NET_BIND_SERVICE,
# SETUID and SETGID and the engine immediately drops to MRK_DNS_RUN_AS (10001)
# keeping only NET_BIND_SERVICE (docs/37 §0.2).
COPY --from=dns-builder /out/mrk-dns /out/mrk-dnsbench /usr/local/bin/
COPY deploy/appliance/supervisord.conf /opt/mrk/supervisord.conf
COPY deploy/appliance/devpi-start.sh /opt/mrk/devpi-start.sh
COPY deploy/appliance/devpi-configure.sh /opt/mrk/devpi-configure.sh
COPY deploy/appliance/entrypoint.py /opt/mrk/entrypoint.py
# Application files stay root-owned and read-only for the runtime user, so a
# compromised service cannot rewrite entrypoint.py that the next start runs as root.
# The sed is a CRLF guard: a CRLF checkout would otherwise break `set -eu`.
# /data/modules exists in the image so a fresh named volume gets it owned by 10001;
# otherwise Docker creates it as root for the /data/modules/s3 mount point of
# compose.split-storage.yaml and the panel cannot add its other module folders.
RUN sed -i 's/\r$//' /opt/mrk/devpi-start.sh /opt/mrk/devpi-configure.sh /opt/mrk/supervisord.conf \
    && mkdir -p /data/modules /var/lib/mrk-agent /mnt/links /var/lib/mrk-dns /run/mrk-dns \
    && chown 10001:10001 /data /data/modules /var/lib/mrk-agent /mnt/links /var/lib/mrk-dns /run/mrk-dns \
    && chmod 0750 /var/lib/mrk-dns /run/mrk-dns \
    && chown -R root:root /opt/mrk \
    && chmod -R u=rwX,go=rX /opt/mrk

# 9000 = native S3 API (s3-engine); /mnt/links = mount point for linked-folder buckets.
EXPOSE 8080 4873 3141 9000
VOLUME ["/data"]

# First boot (PGlite initdb, devpi-init, migrations, mirror bootstrap) can take
# minutes on slow disks; failed probes inside the start period do not count.
HEALTHCHECK --interval=30s --timeout=8s --start-period=300s --retries=3 \
  CMD ["python", "-m", "mrk_control_plane.healthcheck"]

ENTRYPOINT ["python", "/opt/mrk/entrypoint.py"]
