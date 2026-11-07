# Docker Appliance

## Deployment contract

- one image and one container;
- one writable bind mount at `/data`;
- container processes run as UID/GID `10001`;
- the root filesystem is read-only in Compose;
- no Docker socket, SSH key, or host root mount;
- ports `8080`, `4873`, and `3141` are reserved for admin, npm, and PyPI.

Before Linux deployment, provision the host directory with ownership `10001:10001` and mode
`0700`. The hardened Compose forces UID/GID `10001`, so its entrypoint only validates and creates
the fixed application subdirectories and never changes host ownership. A standalone container
without that user override may start as root only long enough to initialize an empty `/data`
mount; the entrypoint performs a non-recursive ownership fix on the fixed directory layout,
drops permanently to UID/GID `10001`, and only then starts Supervisor and network services.
Automated environments can instead run `/opt/mrk/entrypoint.py --prepare-only` in a networkless,
read-only one-shot container with only `CAP_CHOWN` and `CAP_DAC_OVERRIDE`, then remove it and start
the appliance with `--user 10001:10001`, all capabilities dropped, and `no-new-privileges`; the
soak workflow continuously verifies this path. The bootstrap capabilities never reach Supervisor
or a network-facing process.

Gate 3 contains the control plane, built admin shell, Verdaccio, devpi, and Supervisor. Fresh devpi
data is initialized with persistent secrets and an authenticated loopback-only bootstrap. Existing
devpi data is never switched to another upstream automatically.

`compose.production.yaml` pulls the single GHCR image and mounts the requested host path
`/opt/mirrors/pypi` at `/data`. `MRK_IMAGE` is mandatory and must be an immutable digest such as
`ghcr.io/OWNER/mrk-package-mirror@sha256:...`; the Compose file deliberately has no `latest`
fallback.

The production Compose file uses `expose` rather than publishing host ports. In Dokploy, create
three proxy routes to the same service: the admin domain to container port `8080`, the npm domain
to `4873`, and the PyPI domain to `3141`. Do not add host port mappings unless a non-proxied LAN
client explicitly requires them. TLS terminates at the PaaS reverse proxy.

Before starting, set `MRK_CORS_ORIGINS`, `MRK_TRUSTED_HOSTS`, and `MRK_PYPI_OUTSIDE_URL` to the
actual HTTPS domains. The runtime is forced to UID/GID `10001`, drops every capability, uses a
read-only root filesystem, limits process count, and mounts `/tmp` with `noexec,nosuid,nodev`.

Client endpoints are:

- admin/API: `http://HOST:8080`;
- npm: `http://HOST:4873`;
- PyPI simple API: `http://HOST:3141/root/pypi/+simple/`.
