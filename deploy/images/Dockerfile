# syntax=docker/dockerfile:1.7
#
# MrK DevAssist split images (docs/44). One target per image; the panel runs alone
# and every other service is added later from the panel's add-service wizard.
#
#   docker build -f deploy/images/Dockerfile --target panel    -t mrk-panel .
#   docker build -f deploy/images/Dockerfile --target agent    -t mrk-agent .
#   docker build -f deploy/images/Dockerfile --target firewall -t mrk-firewall .
#   docker build -f deploy/images/Dockerfile --target dns      -t mrk-dns .
#   docker build -f deploy/images/Dockerfile --target s3       -t mrk-s3 .
#
# Published as ghcr.io/<owner>/mrk-<target>:<version>. The panel image records its
# own version in MRK_IMAGE_TAG, so the wizard always offers matching service images.
#   docker build -f deploy/images/Dockerfile --target npm      -t mrk-npm .
#   docker build -f deploy/images/Dockerfile --target pypi     -t mrk-pypi .
#
# Package sources (all optional):
# NPM_REGISTRY (lockfile hashes enforced), PIP_INDEX_URL (trusted like PyPI),
# GOPROXY (go.sum enforced), APT_MIRROR (signed lists, serves /debian + /debian-security).

ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"
ARG IMAGE_TAG="latest"
ARG NPM_REGISTRY=""
ARG PIP_INDEX_URL=""
ARG GOPROXY=""
ARG APT_MIRROR=""

FROM node:24.18.0-trixie-slim@sha256:ae91dcc111a68c9d2d81ff2a17bda61be126426176fde6fe7d08ab13b7f50573 AS admin-builder
ARG NPM_REGISTRY
WORKDIR /build/admin-ui
COPY apps/admin-ui/package.json apps/admin-ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY" && npm config set replace-registry-host always; fi; npm ci --ignore-scripts
COPY apps/admin-ui/ ./
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
# Pre-publish size quota for «My space» scopes (no dependencies).
COPY deploy/verdaccio/plugins ./plugins

FROM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS dns-builder
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

# ----------------------------------------------------------------------------- bases

# The DNS engine is a static Go binary. Keep Python and its package metadata out
# of this runtime so unused Python dependencies cannot introduce vulnerabilities.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS dns-base
ARG APT_MIRROR
ARG DEBIAN_FRONTEND=noninteractive
RUN if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|http://deb.debian.org|${APT_MIRROR%/}|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && groupadd --gid 10001 mrk \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin mrk \
    && rm -rf /var/lib/apt/lists/*
COPY LICENSE /opt/mrk/LICENSE

# Python runtime with the unprivileged user and current security updates.
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS os-base
ARG APT_MIRROR
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN groupadd --gid 10001 mrk \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin mrk \
    && if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|http://deb.debian.org|${APT_MIRROR%/}|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update \
    && apt-get upgrade --yes \
    && rm -rf /var/lib/apt/lists/*
COPY LICENSE /opt/mrk/LICENSE

# The control-plane Python package (panel, agent and firewall entry points).
FROM os-base AS python-base
ARG PIP_INDEX_URL
COPY apps/control-plane/pyproject.toml /tmp/control-plane/pyproject.toml
COPY apps/control-plane/src /tmp/control-plane/src
COPY deploy/images/requirements.txt /tmp/runtime-requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} /tmp/control-plane \
      -r /tmp/runtime-requirements.txt \
    && python -c "import importlib.metadata as md, sys; pins = [line.strip().split('==') for line in open('/tmp/runtime-requirements.txt') if '==' in line and not line.startswith('#')]; bad = [(name, want, md.version(name)) for name, want in pins if md.version(name) != want]; sys.exit(f'runtime pin mismatch: {bad}' if bad else 0)" \
    && python -m pip uninstall --yes pip wheel \
    && rm -rf /tmp/control-plane /tmp/runtime-requirements.txt /usr/local/lib/python3.13/ensurepip

# ----------------------------------------------------------------------------- agent

FROM python-base AS agent
ARG VCS_REF
ARG BUILD_DATE
LABEL org.opencontainers.image.title="MrK DevAssist agent" \
      org.opencontainers.image.description="Server agent for the MrK DevAssist panel (Docker and host facts, allowlisted actions)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE"
# A fresh named volume on /data copies this 10001-owned directory.
RUN mkdir -p /data/agent && chown -R 10001:10001 /data
USER 10001:10001
ENTRYPOINT ["mrk-agent"]

# ----------------------------------------------------------------------------- firewall

FROM python-base AS firewall
ARG VCS_REF
ARG BUILD_DATE
ARG APT_MIRROR
LABEL org.opencontainers.image.title="MrK DevAssist firewall" \
      org.opencontainers.image.description="nftables helper for the MrK DevAssist panel (one table, dry-run by default)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE"
RUN if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|http://deb.debian.org|${APT_MIRROR%/}|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update \
    && apt-get install --yes --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["mrk-firewall"]

# ----------------------------------------------------------------------------- s3

FROM python-base AS s3
ARG VCS_REF
ARG BUILD_DATE
LABEL org.opencontainers.image.title="MrK DevAssist S3" \
      org.opencontainers.image.description="S3-compatible file storage managed by the MrK DevAssist panel" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE"
# Buckets, the pushed config (0600) and engine metadata live in /data/s3. A fresh
# named volume copies these 10001-owned directories; /mnt/links = linked folders.
ENV MRK_DATA_DIR=/data \
    MRK_S3_DATA_DIR=/data/s3 \
    MRK_S3_LISTEN=0.0.0.0:9000 \
    MRK_S3_ADMIN_LISTEN=0.0.0.0:9001
RUN mkdir -p /data/s3 /mnt/links && chown -R 10001:10001 /data /mnt/links
USER 10001:10001
EXPOSE 9000
ENTRYPOINT ["mrk-s3-engine"]

# ----------------------------------------------------------------------------- npm

FROM python-base AS npm
ARG VCS_REF
ARG BUILD_DATE
LABEL org.opencontainers.image.title="MrK DevAssist npm" \
      org.opencontainers.image.description="npm registry (Verdaccio) managed by the MrK DevAssist panel" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE"
COPY --from=verdaccio-builder /usr/local/bin/node /usr/local/bin/node
COPY --from=verdaccio-builder /opt/verdaccio /opt/verdaccio
# /data/npm is the volume shared with the panel (config, storage, auth). A fresh
# named volume copies these 10001-owned directories.
RUN mkdir -p /data/npm/config /data/npm/storage /data/npm/auth \
    && chown -R 10001:10001 /data \
    && chown -R root:root /opt/verdaccio && chmod -R u=rwX,go=rX /opt/verdaccio
USER 10001:10001
ENV HOME=/tmp
EXPOSE 4873
ENTRYPOINT ["mrk-npm-runner"]

# ----------------------------------------------------------------------------- pypi

FROM python-base AS pypi
ARG VCS_REF
ARG BUILD_DATE
LABEL org.opencontainers.image.title="MrK DevAssist PyPI" \
      org.opencontainers.image.description="PyPI registry (devpi) managed by the MrK DevAssist panel" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE"
# devpi fetches through the panel's PyPI router (MRK_PYPI_UPSTREAM_URL, on mrk-net).
ENV MRK_DATA_DIR=/data \
    MRK_PYPI_SERVER_DIR=/data/pypi/server \
    MRK_PYPI_AUTH_DIR=/data/pypi/auth \
    MRK_PYPI_UPSTREAM_URL=http://mrk-panel:3142/simple/ \
    MRK_PYPI_REQUEST_TIMEOUT=900 \
    HOME=/tmp
COPY deploy/images/pypi/devpi-start.sh deploy/images/pypi/devpi-configure.sh deploy/images/pypi/entrypoint.sh /opt/mrk/
# The CRLF guard keeps a Windows checkout from breaking `set -eu`.
RUN sed -i 's/\r$//' /opt/mrk/*.sh \
    && mkdir -p /data/pypi/server /data/pypi/auth \
    && chown -R 10001:10001 /data \
    && chown -R root:root /opt/mrk && chmod -R u=rwX,go=rX /opt/mrk
USER 10001:10001
EXPOSE 3141
ENTRYPOINT ["/bin/sh", "/opt/mrk/entrypoint.sh"]

# ----------------------------------------------------------------------------- dns

FROM dns-base AS dns
ARG VCS_REF
ARG BUILD_DATE
LABEL org.opencontainers.image.title="MrK DevAssist DNS" \
      org.opencontainers.image.description="DNS engine for the MrK DevAssist panel" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE"
# No file capabilities: with no-new-privileges the kernel ignores them. The engine
# starts as uid 0 with NET_BIND_SERVICE/SETUID/SETGID and drops to 10001 at once.
COPY --from=dns-builder /out/mrk-dns /out/mrk-dnsbench /usr/local/bin/
RUN mkdir -p /var/lib/mrk-dns /run/mrk-dns \
    && chown 10001:10001 /var/lib/mrk-dns /run/mrk-dns \
    && chmod 0750 /var/lib/mrk-dns /run/mrk-dns
ENTRYPOINT ["mrk-dns"]
CMD ["serve"]

# ----------------------------------------------------------------------------- panel (default)

FROM python-base AS panel
ARG VCS_REF
ARG BUILD_DATE
ARG SOURCE_URL="unknown"
ARG IMAGE_TAG
LABEL org.opencontainers.image.title="MrK DevAssist panel" \
      org.opencontainers.image.description="Admin panel of MrK DevAssist; add npm, PyPI, S3, DNS and more from its wizard" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="$SOURCE_URL" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE"
ENV MRK_ENV=production \
    MRK_DATA_DIR=/data \
    MRK_DATABASE_URL=postgresql+psycopg://devassist@mrk-db:5432/devassist?sslmode=disable \
    MRK_DATABASE_PASSWORD_FILE=/run/mrk-db/password \
    MRK_ADMIN_UI_DIR=/opt/mrk/admin-ui \
    MRK_NPM_ENABLED=false \
    MRK_PYPI_ENABLED=false \
    MRK_PYPI_ROUTER_HOST=0.0.0.0 \
    MRK_PYPI_UPSTREAM_URL=http://127.0.0.1:3142/simple/ \
    MRK_AUTH_COOKIE_SECURE=true \
    MRK_SESSION_TTL_SECONDS=28800 \
    MRK_BUILD_COMMIT=$VCS_REF \
    MRK_BUILD_DATE=$BUILD_DATE \
    MRK_IMAGE_TAG=$IMAGE_TAG \
    MRK_HOST=0.0.0.0 \
    MRK_PORT=8080
COPY --from=admin-builder /build/admin-ui/dist /opt/mrk/admin-ui
COPY deploy/images/panel/supervisord.conf /opt/mrk/supervisord.conf
COPY deploy/images/panel/entrypoint.py /opt/mrk/entrypoint.py
# Application files stay root-owned and read-only for the runtime user. The CRLF
# guard keeps a Windows checkout from breaking supervisord. /run/mrk-dns is created
# 10001-owned so the shared mrk-dns-run volume (created by this stack first) is
# writable by the DNS engine, which runs as 10001 too. /data/npm and /data/pypi are
# the mount points of the volumes shared with the npm and PyPI services (docs/44).
RUN sed -i 's/\r$//' /opt/mrk/supervisord.conf \
    && mkdir -p /data/modules /mnt/links /run/mrk-dns /run/mrk-db /data/tmp/pypi-router \
       /data/npm/config /data/npm/storage /data/npm/auth /data/pypi/server /data/pypi/auth \
    && chown -R 10001:10001 /data \
    && chown 10001:10001 /mnt/links /run/mrk-dns /run/mrk-db \
    && chmod 0750 /run/mrk-dns \
    && chown -R root:root /opt/mrk \
    && chmod -R u=rwX,go=rX /opt/mrk
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=8s --start-period=300s --retries=3 \
  CMD ["python", "-m", "mrk_control_plane.healthcheck"]
ENTRYPOINT ["python", "/opt/mrk/entrypoint.py"]
