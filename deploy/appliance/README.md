# Docker Appliance

## Deployment contract

- one image and one container;
- one writable mount at `/data` (a host bind mount in production);
- container processes run as UID/GID `10001`;
- the root filesystem is read-only in Compose;
- no Docker socket, SSH key, or host root mount;
- ports `8080`, `4873`, and `3141` are reserved for admin, npm, and PyPI.

Before Linux deployment, provision the host directory with ownership `10001:10001`. The hardened
Compose forces UID/GID `10001`, so its entrypoint only validates and creates the fixed application
subdirectories and never changes host ownership; it does set `/data` and those subdirectories to
mode `0750` on every start. A standalone container
without that user override may start as root only long enough to initialize an empty `/data`
mount; the entrypoint performs a non-recursive ownership fix on the fixed directory layout,
drops permanently to UID/GID `10001`, and only then starts Supervisor and network services.
Automated environments can instead run `/opt/mrk/entrypoint.py --prepare-only` in a networkless,
read-only one-shot container with only `CAP_CHOWN` and `CAP_DAC_OVERRIDE`, then remove it and start
the appliance with `--user 10001:10001`, all capabilities dropped, and `no-new-privileges`; the
soak workflow continuously verifies this path. The bootstrap capabilities never reach Supervisor
or a network-facing process.

The image contains the control plane, built admin shell, embedded PGlite (loopback port 5433),
Verdaccio, devpi, the PyPI failover router (loopback port 3142), and Supervisor. Fresh devpi data is
initialized with persistent secrets and an authenticated loopback-only bootstrap; the root password
reaches `devpi-init` only as an argon2 hash. An interrupted first init is detected through
`/data/pypi/server/.mrk-init-in-progress` and retried from an empty directory; a non-empty server
directory without that sentinel is never deleted. Existing devpi data is never switched to another
upstream automatically.

`compose.production.yaml` pulls the single GHCR image and mounts the requested host path
`/opt/mirrors/pypi` at `/data`. `MRK_IMAGE` is mandatory and must be an immutable digest such as
`ghcr.io/OWNER/mrk-devassist@sha256:...`; the Compose file deliberately has no `latest`
fallback.

The production Compose file uses `expose` rather than publishing host ports. In Dokploy, create
three proxy routes to the same service: the admin domain to container port `8080`, the npm domain
to `4873`, and the PyPI domain to `3141`. Do not add host port mappings unless a non-proxied LAN
client explicitly requires them. TLS terminates at the PaaS reverse proxy.

Before starting, set `MRK_CORS_ORIGINS`, `MRK_TRUSTED_HOSTS`, and `MRK_PYPI_OUTSIDE_URL` to the
actual HTTPS domains. The runtime is forced to UID/GID `10001`, drops every capability, uses a
read-only root filesystem, limits memory/CPU/process count (`MRK_MEM_LIMIT`, default `2g`;
`MRK_CPUS`, default `2.0`; `pids_limit: 512`), and mounts `/tmp` with `noexec,nosuid,nodev`.

## Lifecycle

- **First boot** (PGlite initdb, devpi-init, migrations, mirror bootstrap) can take minutes; the
  healthcheck start period is 300 s. Do not let a PaaS replace the container for being unhealthy
  inside that window.
- **Stopping**: Supervisor stops services one priority group at a time and stops PGlite last
  (worst case about 115 s). Compose uses `stop_grace_period: 180s`; for plain Docker use
  `docker run --stop-timeout 180 ...` or `docker stop --time 180`. Docker's default of 10 s can
  SIGKILL PGlite mid-shutdown.
- **Restart policy**: when a service exhausts its start retries (FATAL), an event listener stops
  Supervisor and the container exits with status 0 so the platform restarts it. Use
  `restart: unless-stopped`/`always` (Swarm: `condition: any`), not `on-failure`.
- **Large PyPI artifacts**: the router downloads and verifies a whole artifact before devpi sends
  the first byte, so clients need a long timeout for big wheels (for example `pip --timeout 900`).
  devpi runs `MRK_PYPI_THREADS` (default 16) worker threads.
- **Maintenance and upgrades**: see `docs/18-operations-runbooks.md` (PGlite `VACUUM`, PGlite
  version upgrades, PyPI bootstrap recovery).

## Optional Host Agent (Gates 16-17)

`mrk-agent` is the same image with `entrypoint: ["mrk-agent"]`, defined under the
`agent` Compose profile, so it never starts unless asked:

```bash
export MRK_DOCKER_GID="$(getent group docker | cut -d: -f3)"
docker compose -f deploy/appliance/compose.production.yaml --profile agent up -d mrk-agent
docker compose -f deploy/appliance/compose.production.yaml logs mrk-agent | grep "pairing key"
```

The first start generates a 32-byte key in the `mrk-agent-state` volume
(`/data/agent/agent.key`, mode 0600) and logs it once. Paste
`http://mrk-agent:7070` and that key into Admin UI -> Host Agent, or set
`MRK_AGENT_URL` and `MRK_AGENT_KEY_FILE` (env wins and locks the UI form).

- It listens only on the internal `mrk-agent` network (`internal: true`); no ports
  are published. Every request except `GET /v1/health` must be HMAC-signed
  (30 s clock window, single-use nonces), so keep host clocks in sync (NTP).
- Docker socket access is equivalent to root on the host. The agent only sends the
  calls on its in-code allowlist. Read: `GET /version`, `/info`, `/containers/json`,
  `/containers/{id}/json`, `/containers/{id}/logs` (stdout+stderr, `tail` <= 5000),
  `/images/json`, `/volumes`, `/networks`, `/system/df`. Gate 17 writes: `POST
  /containers/{id}/start|stop|restart`, `POST /images/create` (validated
  `fromImage` + `tag` only), `POST /build/prune`, and `DELETE` of a single
  container (`v=0`), image (`noprune=0`) or network by full id, never `force`.
  No exec, create, volume removal or Docker's bulk `*/prune` endpoints (they would
  also delete stopped Dokploy containers). Mounting the socket `:ro` would not limit
  the API, so it is not pretended.
- Gate 17 agent API (all signed; POST only on these routes):
  `GET /v1/docker/containers/{id}/logs` (JSON, 5 MB cap; `follow=1` streams NDJSON
  and closes after 600 s), `GET /v1/metrics`, `POST /v1/docker/containers/{id}/
  start|stop|restart` (protected containers need `allow_protected: true`, otherwise
  `403 protected`), `POST /v1/docker/images/pull` (public images or daemon-configured
  mirrors/credentials only; 600 s cap), `POST /v1/docker/prune/preview` and
  `POST /v1/docker/prune` (token of the previewed plan; `409 plan_changed` if
  anything moved). Prune plans never contain protected containers/networks, swarm
  task containers, images used by any container (even stopped), default or
  swarm-scoped networks, networks in use, or volumes.
- Metrics: host CPU % is the delta between two `/v1/metrics` calls (the first
  returns `null`). Host network totals are read from `/host/proc/1/net/dev`: the
  host's PID 1 lives in the host network namespace, while `/host/proc/net/dev`
  is a symlink to `self/net/dev` and would show the agent's own private network.
  Loopback, veth, docker/br- bridges and similar virtual interfaces are skipped.
  Per-container CPU/memory/IO comes from the read-only cgroup v2 mount
  `/sys/fs/cgroup:/host/cgroup:ro` (`MRK_AGENT_HOST_CGROUP`), both
  `system.slice/docker-<id>.scope` and `docker/<id>` layouts; on a cgroup v1 host
  or without the mount `containers` is `null`.
- Dokploy containers are reported `protected: true` (name, compose project or
  `com.dokploy*`/`dokploy*` labels; configurable via `MRK_AGENT_PROTECTED_*`).
- `/:/host/root:ro` is optional and only used for disk usage and the host name;
  delete that line to keep the host filesystem out of the agent.
- Unpair with `DELETE /api/v1/agent/config`; rotate by deleting `agent.key` in the
  volume, restarting the agent and pairing again.

## Optional firewall helper (Gate 19 S7)

`mrk-firewall` is the same image with `entrypoint: ["mrk-firewall"]` under the
`firewall` Compose profile. It is the only MRK component allowed to change the
host's packet filter, and it only ever touches its own nftables table `inet mrk`.

```bash
docker compose -f deploy/appliance/compose.production.yaml --profile firewall up -d mrk-firewall
docker compose -f deploy/appliance/compose.production.yaml logs mrk-firewall | grep "pairing key"
```

Paste the key into Admin UI -> Firewall -> Pair (the URL defaults to
`unix:/run/mrk-firewall/firewall.sock`), or set `MRK_FIREWALL_URL` and
`MRK_FIREWALL_KEY_FILE` on `mrk-mirror`. The module starts in **dry-run**: it
detects and records what it would block (`GET /api/v1/firewall/preview`) and
installs nothing. Switching to enforce needs the typed confirmation `ENFORCE`
and auto-adds your current IP to the allowlist.

- **Privileges (why root):** `user: "0:0"` with `cap_drop: ALL` + `cap_add:
  NET_ADMIN` only, `no-new-privileges`, read-only root filesystem. Docker hands
  added capabilities to root only, and nftables needs netlink with
  `CAP_NET_ADMIN`. `network_mode: host` is required because nftables rules are
  per network namespace. There are no other capabilities (no DAC override): it
  reads root-owned logs as their owner.
- **Transport:** no ports at all. The helper listens on a Unix socket in the
  `mrk-firewall-run` volume, mounted only by `mrk-firewall` and (read-only,
  enough to connect) `mrk-mirror`. A TCP listener on `127.0.0.1:7071` in the host
  namespace would not be reachable from bridge containers, and binding the
  bridge gateway (`host-gateway`/`host.docker.internal`) or `0.0.0.0` would
  expose it to every container and possibly the LAN, so the socket is the
  default. Every request is HMAC-signed with the helper's own key (state volume
  `mrk-firewall-state`, `firewall.key`, mode 0600, logged once).
- **Rules installed (enforce only):** `add table inet mrk; delete table inet mrk;
  table inet mrk {...}` in one atomic `nft -f` transaction, with sets
  `mrk_allow_v4/v6` and `mrk_block_v4/v6` (timeouts) and one chain hooked at
  `prerouting priority raw`: allow sets first, then `counter drop`. `accept` only
  ends our chain, so Docker/Dokploy/distro tables keep working untouched. This
  also covers traffic to published Docker ports. Every automatic ban expires.
- **Off / kill switch:** `mode: off` (or dry-run) deletes the table; `POST
  /api/v1/firewall/blocks/clear` with `UNBLOCK ALL` removes every block at once.
  `MRK_FIREWALL_FORCE_DRY_RUN=true` on the helper refuses to install rules
  whatever the panel says. If you remove the helper entirely, its last table
  stays in the kernel until you run `nft delete table inet mrk` (bans still
  expire on their own).
- **Never blocked:** loopback, the requesting admin's IP, the host's own
  addresses and Docker bridge gateways (read from the host's `/proc/net`),
  private ranges (unless `allow_private_blocks`), allowlisted ranges, and
  anything wider than /16 (IPv4) or /32 (IPv6).
- **Log sources (read-only):** `/var/log` is mounted at `/host/log/system`
  (sshd default `/host/log/system/auth.log`; RHEL-style hosts: set
  `/host/log/system/secure`). Only parsed signals (IP, kind, short detail) leave
  the helper. For Traefik (Dokploy) mount its access log, e.g.
  `/etc/dokploy/traefik/dynamic/access.log:/host/log/traefik/access.log:ro`,
  enable the `traefik` source and make sure Traefik writes real client IPs
  (`forwardedHeaders.trustedIPs` behind a CDN). **journald-only hosts** (no
  auth.log): install `rsyslog`, or run a host unit such as
  `journalctl -f -o short -u ssh --no-hostname >> /var/log/mrk-sshd.log` and set
  the sshd path to `/host/log/system/mrk-sshd.log`; the binary journal is not
  parsed natively.
- MRK's own failed logins are read from the control plane's audit log; behind
  Traefik set `MRK_TRUSTED_PROXIES` so the audit log holds client IPs, not the
  proxy's (private addresses are never blocked).
- Requires an nftables-capable kernel (5.x+; interval sets with timeouts) and
  the image's Debian 13 (trixie) `nftables` package (`/usr/sbin/nft`, v1.1.x).

## Native S3 object storage (Gate 18)

Supervisor program `s3-engine` (`mrk-s3-engine`) serves an S3-compatible API on
container port `9000`, published on `127.0.0.1:${MRK_S3_PORT:-9000}`. Our own
implementation (docs/30, docs/31 §2); no MinIO/Garage code.

- Configuration: the engine never touches PGlite. The control plane writes
  `/data/modules/s3/config.json` atomically (buckets, identities, policies; secrets
  stay in the encrypted `SecretStore` as `{"access_key_id", "secret_access_key"}`).
  The engine polls its mtime every 2 s; an invalid file is ignored and the last good
  snapshot stays active. No snapshot or `enabled: false` → `503 ServiceUnavailable`.
- Domains: route `s3.<domain>` (path-style; what Dokploy/rclone use) and optionally
  `*.s3.<domain>` (virtual-hosted, suffix = `virtual_host_suffix`) to port 9000.
  The proxy **must preserve the original `Host`** (it is part of the SigV4
  signature), pass `Expect: 100-continue`, not buffer request bodies and not
  compress responses. TLS terminates at the proxy.
- Auth: SigV4 header and presigned URLs, signed/unsigned aws-chunked uploads with
  checksum trailers (current boto3/aws-cli defaults). No SigV2. Anonymous reads only
  on buckets marked `public_read`.
- Storage: managed buckets in `/data/modules/s3/buckets/<bucket>/` (content files by
  UUID), per-bucket SQLite index in `/data/modules/s3/meta/<bucket>.sqlite`.
  Exclude `buckets/` from appliance backups if it is large.
- Linked folders: mount host folders under `/mnt/links` (example in
  `compose.production.yaml`), readable (ro) or writable (rw) by UID 10001, e.g.
  `setfacl -R -m u:10001:rwX -m d:u:10001:rwX /srv/files`. Files are plain files:
  anything copied there over SSH appears in the next listing. Symlinks, special
  files and nested mounts are never exposed; `ro` buckets reject every write.
- Admin API (loopback `127.0.0.1:9001`, header `X-MRK-Admin-Token` = content of
  `/data/modules/s3/admin.token`, mode 0600): `GET /admin/health`,
  `GET /admin/buckets/{b}/stats`, `POST /admin/buckets/{b}/ensure`,
  `DELETE /admin/buckets/{b}?force=0|1`, `GET /admin/links`, `POST /admin/reload`,
  `POST /admin/gc`, `POST /admin/buckets/{b}/rescan`.
- Tunables (`MRK_S3_*`, defaults): `LISTEN` 0.0.0.0:9000, `LINK_ROOTS` /mnt/links,
  `CLOCK_SKEW_SECONDS` 900, `ACCEPT_ANY_REGION` true, `MAX_SINGLE_PUT_BYTES` 5 GiB,
  `MULTIPART_MIN_PART_BYTES` 5 MiB, `MULTIPART_UPLOAD_TTL_DAYS` 7,
  `FSYNC_POLICY` object (`none`/`strict`), `GC_INTERVAL_SECONDS` 300,
  `DISK_BLOCK_PERCENT` 90, `MAX_HEADER_BYTES` 16 KiB, `MAX_XML_BODY_BYTES` 2 MiB,
  `IDLE_BODY_TIMEOUT_SECONDS` 120, `HASH_RATE_BYTES` 50 MiB/s (lazy MD5 of linked
  files), `TRUSTED_PROXIES` (peers whose `X-Forwarded-For/-Proto` are used for
  policy conditions), `DEBUG_SIGNATURES` false.
- Dokploy destination: Endpoint `https://s3.<domain>`, Region `us-east-1`, Bucket,
  Access Key / Secret from the panel; Dokploy already forces path-style.

## Local development

`compose.yaml` at the repository root builds the image and runs it as `10001:10001` on the named
volume `mrk-dev-data`. To bind-mount instead, set `MRK_HOST_DATA_PATH` to an existing host
directory owned by `10001:10001`; Docker creates a missing bind path as root, which the
unprivileged container cannot use. Optional build mirrors are `MRK_BUILD_NPM_REGISTRY` (lockfile
integrity hashes still enforced) and `MRK_BUILD_PIP_INDEX_URL` (versions pinned in
`requirements.txt`, but no hash verification yet: trust it like PyPI).

Client endpoints are:

- admin/API: `http://HOST:8080`;
- npm: `http://HOST:4873`;
- PyPI simple API: `http://HOST:3141/root/pypi/+simple/`.
