# Install DevAssist with Docker

**English** · [فارسی](install-docker.fa.md)

This guide collects the Docker instructions that were spread over
[`deploy/appliance/README.md`](../deploy/appliance/README.md), [docs/12](12-ci-cd-and-release.md),
[docs/18](18-operations-runbooks.md) and the DNS user stories ([docs/03, Epic E18](03-user-stories.md)).
Those files stay the detailed reference.

## 1. What runs

One image (`mrk-package-mirror`) and up to four containers:

| Compose service | Profile | What it is | Privileges |
|---|---|---|---|
| `mrk-mirror` | always | panel + API, PGlite, Verdaccio (npm), devpi (PyPI), PyPI failover router, S3 engine, under Supervisor | uid 10001, no capabilities, read-only root fs |
| `mrk-dns` | `dns` | the DNS engine, host network | starts as uid 0 with `NET_BIND_SERVICE`+`SETUID`+`SETGID`, drops at once to 10001 keeping only `NET_BIND_SERVICE` |
| `mrk-firewall` | `firewall` | nftables helper, host network, Unix socket only | root with only `NET_ADMIN` |
| `mrk-agent` | `agent` | Host Agent (Docker socket, read-only host views) | root with only `DAC_READ_SEARCH`+`DAC_OVERRIDE` (or `MRK_AGENT_USER=10001:<docker gid>`) |

All data of the main container lives in one mount at `/data`. Ports: `8080` panel, `4873` npm,
`3141` PyPI, `9000` S3. Internal only: `5433` PGlite, `3142` PyPI router, `9001` S3 admin.

## 2. Quick start (build from source)

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist
cd devassist
cp .env.example .env        # optional: ports, memory, build mirrors
docker compose up -d --build
docker compose ps           # wait until mrk-mirror is "healthy" (first start: a few minutes)
```

`compose.yaml` builds the image locally, runs it as `10001:10001` on the named volume
`mrk-dev-data` and binds every port to `127.0.0.1`. Open the panel through an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 you@your-server   # then open http://localhost:8080
```

The first visit shows **First Time Setup**. Create the owner account immediately: until then,
anyone who reaches the panel can.

Build mirrors (useful where Docker Hub, npmjs or PyPI are slow): set `MRK_BUILD_NPM_REGISTRY`
(lockfile integrity hashes are still enforced) and `MRK_BUILD_PIP_INDEX_URL` (versions are
pinned, but pip checks no hashes: trust it like PyPI) in `.env`.

To use a host folder instead of the named volume, create it owned by `10001:10001` and set
`MRK_HOST_DATA_PATH`:

```bash
sudo install -d -o 10001 -g 10001 -m 0750 /srv/devassist-data
echo 'MRK_HOST_DATA_PATH=/srv/devassist-data' >> .env
```

## 3. Production (published image)

`deploy/appliance/compose.production.yaml` pulls a published image. `MRK_IMAGE` is required and
must be an immutable digest (no `latest`):

```bash
export MRK_IMAGE=ghcr.io/seniorkian/mrk-package-mirror@sha256:<digest>
sudo install -d -o 10001 -g 10001 -m 0750 /opt/mirrors/pypi    # the /data mount of this file
export MRK_TRUSTED_HOSTS=panel.example.com,npm.example.com,pypi.example.com
export MRK_CORS_ORIGINS=https://panel.example.com
export MRK_PYPI_OUTSIDE_URL=https://pypi.example.com
docker compose -f deploy/appliance/compose.production.yaml up -d
```

Images are published to GHCR by `.github/workflows/publish-image.yml` for `v*` tags
(amd64 and arm64, with SBOM and provenance); the digest is in the workflow summary
([docs/12](12-ci-cd-and-release.md)). Until a release exists, build from source (section 2).

The production file uses `expose`, not published ports. In Dokploy, create proxy routes to the
service: the panel domain to port `8080`, npm to `4873`, PyPI to `3141`, S3 (`s3.<domain>` and
optionally `*.s3.<domain>`) to `9000`. TLS terminates at Dokploy's Traefik. For S3 the proxy must
keep the original `Host` header and must not buffer request bodies. The panel can also create
these routes for you (Services → domains; US-158 in [docs/03](03-user-stories.md)).

Hardening already in the Compose files: fixed uid `10001`, `cap_drop: ALL`, `read_only: true`,
`no-new-privileges`, `/tmp` as `noexec,nosuid,nodev` tmpfs, memory/CPU/PID limits
(`MRK_MEM_LIMIT` default `2g`, `MRK_CPUS` default `2.0`, `pids_limit: 512`).

## 4. Lifecycle

- **First start** (PGlite initdb, devpi-init, migrations, mirror bootstrap) can take minutes; the
  health check has a 300 s start period.
- **Stopping**: Supervisor stops PGlite last. Compose uses `stop_grace_period: 180s`; with plain
  Docker use `docker stop --time 180`. The default 10 s can kill PGlite mid-shutdown.
- **Restart policy**: when the database or panel goes FATAL the container exits so Docker restarts
  it. Use `restart: unless-stopped` or `always`, not `on-failure`. npm, PyPI and S3 are retried by
  the panel's watchdog instead.
- **Large PyPI files**: clients need a long timeout for big wheels, e.g. `pip --timeout 900`.

## 5. Upgrade

1. In the panel, create an encrypted backup (data lifecycle → backup) and keep the passphrase
   outside `/data`.
2. Source install: `git pull && docker compose up -d --build`.
   Production: set `MRK_IMAGE` to the new digest and run `docker compose -f deploy/appliance/compose.production.yaml up -d`.
3. Migrations run on start. Check `docker compose ps` and the panel.

Before an image whose PGlite version changed, also do a restore drill ([docs/18](18-operations-runbooks.md)).

## 6. Optional profiles

### Host Agent (`agent`)

```bash
export MRK_DOCKER_GID="$(getent group docker | cut -d: -f3)"
docker compose --profile agent up -d mrk-agent
docker compose logs mrk-agent | grep "pairing key"
```

Paste `http://mrk-agent:7070` and the key into the panel (Server → Host Agent). The agent has no
published port; it is reachable only on the internal `mrk-agent` network. Details and the exact
Docker API allowlist: [deploy/appliance/README.md](../deploy/appliance/README.md#optional-host-agent-gates-16-17).

### Firewall helper (`firewall`)

```bash
docker compose --profile firewall up -d mrk-firewall
docker compose logs mrk-firewall | grep "pairing key"
```

Pair in the panel (Security → Firewall; URL `unix:/run/mrk-firewall/firewall.sock`). It starts
in dry-run. Enforcing needs the typed confirmation `ENFORCE`. Removing the helper leaves its last
table in the kernel until `sudo nft delete table inet mrk`.

### DNS engine (`dns`)

```bash
docker compose --profile dns up -d mrk-dns
docker compose --profile dns ps mrk-dns
docker compose --profile dns logs --tail=50 mrk-dns
```

On the first start it listens on `MRK_DNS_LISTEN` (default `127.0.0.1:53,172.17.0.1:53`);
afterwards the addresses come from the DNS settings in the panel. Recursion is limited to
private networks and is never offered to the Internet. Limits: `MRK_DNS_CPUS` (2),
`MRK_DNS_MEMORY` (512m), `MRK_DNS_PIDS` (256).

## 7. DNS and port 53

The panel's **DNS → Setup** page checks each step and shows the exact commands for your server
(it needs the Host Agent to read the host). The steps are:

1. **Engine running**: `docker compose --profile dns up -d mrk-dns`.
2. **Port 53 free.** See who holds it:
   ```bash
   sudo ss -lntup 'sport = :53'
   ```
   systemd-resolved's stub on `127.0.0.53` does **not** conflict with `127.0.0.1:53`. Another
   server (dnsmasq, bind9, ...) on `0.0.0.0:53` does; stop it only if nothing needs it:
   `sudo systemctl disable --now <unit>`.
3. **Host resolver uses DevAssist** (systemd-resolved hosts), with a public DNS as backup:
   ```bash
   sudo mkdir -p /etc/systemd/resolved.conf.d
   sudo tee /etc/systemd/resolved.conf.d/mrk.conf >/dev/null <<'EOF'
   [Resolve]
   DNS=127.0.0.1 1.1.1.1
   FallbackDNS=1.1.1.1 9.9.9.9
   DNSStubListener=no
   EOF
   sudo cp -P /etc/resolv.conf /etc/resolv.conf.mrk-backup
   sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
   sudo systemctl restart systemd-resolved
   ```
   Start the engine before this step. Undo: remove `mrk.conf`, move `/etc/resolv.conf.mrk-backup`
   back and restart systemd-resolved. Hosts without systemd-resolved get a static
   `/etc/resolv.conf` with `nameserver 127.0.0.1` plus a backup (the panel shows it).
4. **Containers use DevAssist**: add only the `dns` key to `/etc/docker/daemon.json`, keeping
   every other key, for example `"dns": ["172.17.0.1", "1.1.1.1"]`, then
   `sudo systemctl restart docker`. **This restarts every container on the server**, including
   Dokploy and its apps; do it at a quiet time.
5. **Check**:
   ```bash
   dig @127.0.0.1 localhost +short
   docker run --rm busybox:1.36 nslookup localhost
   ```

## 8. Backup and restore

Restore is offline and is never run from the panel. The panel validates a backup and prepares a
one-hour plan; then, with the service stopped:

```bash
docker compose run --rm --no-deps \
  -v "$PWD/restore-passphrase:/run/secrets/mrk-restore-passphrase:ro" \
  --entrypoint mrk-restore mrk-mirror apply \
  --plan '<plan-id>' \
  --passphrase-file /run/secrets/mrk-restore-passphrase \
  --confirmation 'APPLY <backup-id>' \
  --offline-confirm I_HAVE_STOPPED_MRK
```

The full procedure (receipts, rollback backup, `MRK_UPSTREAM_SECRET_KEY_FILE`) is in
[docs/18](18-operations-runbooks.md#encrypted-backup-and-offline-restore).

## 9. Uninstall

```bash
docker compose --profile dns --profile firewall --profile agent down        # keeps volumes
docker compose --profile dns --profile firewall --profile agent down -v     # also deletes data volumes
sudo nft delete table inet mrk 2>/dev/null || true                         # if the firewall helper enforced rules
```

Undo the DNS steps of section 7 first if you made them, or the host and containers lose DNS.
