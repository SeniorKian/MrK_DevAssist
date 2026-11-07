# syntax=docker/dockerfile:1.7

ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"

FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS admin-builder
ARG VCS_REF
ARG BUILD_DATE
ENV VITE_BUILD_COMMIT=$VCS_REF \
    VITE_BUILD_DATE=$BUILD_DATE
WORKDIR /build/admin-ui
COPY apps/admin-ui/package.json apps/admin-ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts
COPY apps/admin-ui/ ./
RUN npm run build

FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS verdaccio-builder
WORKDIR /opt/verdaccio
COPY deploy/verdaccio/package.json deploy/verdaccio/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev --ignore-scripts

FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS pglite-builder
WORKDIR /opt/pglite
COPY deploy/pglite/package.json deploy/pglite/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev --ignore-scripts

FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72 AS runtime

ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"
ARG SOURCE_URL="unknown"

LABEL org.opencontainers.image.title="MRK Package Mirror" \
      org.opencontainers.image.description="Single-container npm and PyPI mirror appliance" \
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
    MRK_PYPI_REQUEST_TIMEOUT=90 \
    MRK_AUTH_COOKIE_SECURE=true \
    MRK_SESSION_TTL_SECONDS=28800 \
    MRK_BUILD_COMMIT=$VCS_REF \
    MRK_BUILD_DATE=$BUILD_DATE \
    MRK_HOST=0.0.0.0 \
    MRK_PORT=8080

RUN groupadd --gid 10001 mrk \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin mrk

WORKDIR /opt/mrk
COPY LICENSE /opt/mrk/LICENSE
COPY apps/control-plane/pyproject.toml /tmp/control-plane/pyproject.toml
COPY apps/control-plane/src /tmp/control-plane/src
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install /tmp/control-plane supervisor==4.3.0 \
      setuptools==80.9.0 devpi-server==6.21.0 devpi-web==5.2.0 devpi-client==7.3.0 \
    && rm -rf /tmp/control-plane

COPY --from=verdaccio-builder /usr/local/bin/node /usr/local/bin/node
COPY --from=verdaccio-builder /opt/verdaccio /opt/verdaccio
COPY --from=pglite-builder /opt/pglite /opt/pglite
COPY --from=admin-builder /build/admin-ui/dist /opt/mrk/admin-ui
COPY deploy/verdaccio/config.yaml /opt/mrk/verdaccio/config.yaml
COPY deploy/appliance/supervisord.conf /opt/mrk/supervisord.conf
COPY deploy/appliance/devpi-start.sh /opt/mrk/devpi-start.sh
COPY deploy/appliance/devpi-configure.sh /opt/mrk/devpi-configure.sh
RUN mkdir -p /data \
    && chown -R 10001:10001 /data /opt/mrk

USER 10001:10001
EXPOSE 8080 4873 3141
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=8s --start-period=20s --retries=3 \
  CMD ["python", "-m", "mrk_control_plane.healthcheck"]

ENTRYPOINT ["supervisord", "-c", "/opt/mrk/supervisord.conf"]
