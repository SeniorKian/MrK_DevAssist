# Native install (without Docker)

**English** · [فارسی](install-native.fa.md)

`scripts/install-native.sh` installs DevAssist directly on the host as systemd services. It builds
the same components as [`deploy/appliance/Dockerfile`](../deploy/appliance/Dockerfile), at the
versions pinned in [`versions.lock.yaml`](../versions.lock.yaml), and runs the same processes
with the same environment and the same restrictions as the containers.

Use it when you cannot or do not want to run the appliance in Docker. On a Dokploy server the
[Docker install](install-docker.md) is simpler and is what CI tests end to end; the native
mode is newer and less tested (see [Known differences](#known-differences)).

## Supported systems

- Debian 12 (bookworm), Debian 13 (trixie), Ubuntu 22.04, Ubuntu 24.04
- amd64 or arm64, with systemd as init
- 2 GB of RAM for the main service, at least 5 GB of free disk for the build plus your data
- Internet access during the install (or mirrors, below)

## Quick start

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist
cd devassist
sudo bash scripts/install-native.sh install --dry-run      # print every step, change nothing
sudo bash scripts/install-native.sh install                # panel, npm, PyPI, S3
# optional parts, now or later (re-run install with the flag):
sudo bash scripts/install-native.sh install --with-dns --with-firewall --with-agent
```

When it finishes, open the panel through an SSH tunnel and create the owner account:

```bash
ssh -L 8080:127.0.0.1:8080 you@your-server            # then open http://localhost:8080
```

## What the script does

1. **Checks** (it stops instead of guessing): root, the OS and architecture, systemd, free disk
   space (`--min-free-gb`, default 5), RAM (warning under 2 GB), the ports below, and that the
   Docker version of DevAssist is not running on the same host. It refuses to touch `/opt/mrk`
   if that folder was not created by this script.
2. **System packages** (only missing ones): `ca-certificates curl xz-utils tar gzip coreutils
   util-linux iproute2 git`, plus `nftables` with `--with-firewall`.
3. **User**: a system user and group `devassist`, with uid/gid `10001` (the image's) when free, so a
   data folder can move between Docker and native installs.
4. **Runtimes**, downloaded over HTTPS and checked against the publisher's SHA-256:
   - Python (pinned version) through [uv](https://github.com/astral-sh/uv) (pinned version) into
     `/opt/mrk/runtimes/python`; uv itself stays in `/var/cache/devassist` and is used only here;
   - Node.js (pinned) into `/opt/mrk/runtimes/node-v<version>-linux-<arch>`;
   - Go (pinned) into `/var/cache/devassist/tools`, only to build the DNS engine.
5. **A release** in `/opt/mrk/releases/<commit>` with the same steps as the Dockerfile:
   - a venv with `apps/control-plane` and `deploy/appliance/requirements.txt`, the same
     runtime pin check, then `pip`/`wheel` removed;
   - Verdaccio and PGlite with `npm ci --omit=dev --ignore-scripts` from their lockfiles;
   - the admin UI with `npm ci --ignore-scripts && npm run build`;
   - with `--with-dns`: `mrk-dns` and `mrk-dnsbench` with `CGO_ENABLED=0`, `-trimpath`,
     `GOTOOLCHAIN=local`, `go mod verify` and the same `-ldflags`;
   - the **unchanged** `supervisord.conf`, `devpi-start.sh` and `devpi-configure.sh`.

   Everything in the release is `root:root`, read-only for the service user (like `/opt/mrk` in
   the image). A release is built completely before it is used; a failed build is never activated
   and is removed on the next run.
6. **Configuration** in `/etc/devassist` (written once, never overwritten): `devassist.env`, and
   `dns.env`, `firewall.env`, `agent.env` for the optional parts.
7. **systemd units** from [`deploy/native/systemd/`](../deploy/native/systemd/) into
   `/etc/systemd/system`, the helper `/usr/local/sbin/devassist-exec`, then it switches
   `/opt/mrk/current` to the new release, starts the services and waits for the same health
   check the container uses (`python -m mrk_control_plane.healthcheck`).

Running `install` again is safe: existing users, config files and data are kept, an already
built commit is reused (`--rebuild` forces a new build), and options chosen earlier stay on.

## Layout

| Path | Contents | Owner |
|---|---|---|
| `/opt/mrk/releases/<id>/` | venv, admin UI, Verdaccio, PGlite, `bin/`, supervisord config | root, read-only |
| `/opt/mrk/current` | link to the active release; `/opt/mrk/{venv,bin,admin-ui,...}` point through it | root |
| `/opt/mrk/runtimes/` | Python and Node runtimes | root |
| `/etc/devassist/` | `devassist.env` and the optional env files, `install.conf` | root:devassist 0750 |
| `/var/lib/devassist/` (`--data-dir`) | all appliance data (the container's `/data`) | devassist 0750 |
| `/var/lib/mrk-dns`, `/run/mrk-dns` | DNS state, admin socket and token | devassist |
| `/var/lib/mrk-firewall`, `/run/mrk-firewall` | firewall helper state and socket | root (socket dir root:devassist 0750) |
| `/var/lib/mrk-agent` | Host Agent pairing key | root 0700 |
| `/var/cache/devassist/` | downloads, build caches, uv, Go | root |

### How the container paths are kept

The code and `supervisord.conf` use container paths (`/data`, `/usr/local/bin/...`,
`/opt/verdaccio`, `/opt/pglite`). Instead of patching them, `devassist.service` gives the service
its own mount namespace:

| Inside the service | Comes from |
|---|---|
| `/data` | `/var/lib/devassist` (or `--data-dir`) |
| `/usr/local/bin` | `/opt/mrk/bin` (supervisord, supervisorctl, `mrk-*`, node) |
| `/opt/verdaccio`, `/opt/pglite` | `/opt/mrk/verdaccio`, `/opt/mrk/pglite` |
| `/tmp` | a private 64 MB tmpfs, `noexec,nosuid,nodev` |

The host's own `/usr/local/bin` and `/data` are not changed (empty mount-point folders are
created for `/data`, `/opt/verdaccio` and `/opt/pglite` if missing, and removed on uninstall).
`supervisord` is started by a small wrapper (`deploy/native/devassist_supervise.py`) that gives it
a pipe for its logs, because the shared config writes to `/dev/fd/1`, which cannot be reopened
when it is the journal socket.

## Services

| Unit | Same as | Runs as | Ports |
|---|---|---|---|
| `devassist.service` | `mrk-mirror` (supervisord: pglite, s3-engine, pypi-router, verdaccio, devpi, devpi-configure, control-plane, fatal-exit listener) | `devassist`, no capabilities | 8080, 4873, 3141, 9000; loopback 5433, 3142, 9001 |
| `devassist-dns.service` | `mrk-dns` | `devassist`, only `CAP_NET_BIND_SERVICE` (ambient) | 53 UDP/TCP (+ DoT/DoH/DoQ if enabled) |
| `devassist-firewall.service` | `mrk-firewall` | root, only `CAP_NET_ADMIN` | none (Unix socket) |
| `devassist-agent.service` | `mrk-agent` | root, only `CAP_DAC_READ_SEARCH` + `CAP_DAC_OVERRIDE` | 127.0.0.1:7070 |

Hardening in every unit, mirroring the Compose files: `NoNewPrivileges=yes` (=
`no-new-privileges`), an explicit `CapabilityBoundingSet` (= `cap_drop: ALL` + `cap_add`),
`ProtectSystem=strict` (= read-only root filesystem), `ProtectHome`, `PrivateTmp`/
`TemporaryFileSystem`, `PrivateDevices`, kernel and cgroup protection, `RestrictSUIDSGID`,
`RestrictNamespaces`, a native-only system call architecture, and the same resource ceilings
(`MemoryMax`, `CPUQuota`, `TasksMax`, `LimitNOFILE`). The main service has a 180 s stop timeout
and only its main process receives `SIGTERM` (`KillMode=mixed`), so Supervisor stops PGlite last,
like in the container.

The DNS engine: in Docker it starts as uid 0 and drops to uid 10001 keeping only
`NET_BIND_SERVICE`. Natively systemd starts it directly as `devassist` with
`AmbientCapabilities=CAP_NET_BIND_SERVICE`; the engine only drops privileges when started as
root, so the end state is the same.

## Ports and firewall

| Port | Service | Listens on (native default) | Change with |
|---|---|---|---|
| 8080 | panel and API | `127.0.0.1` | `MRK_HOST`, `MRK_PORT` |
| 4873 | npm (Verdaccio) | `127.0.0.1` | `MRK_NPM_LISTEN_HOST` |
| 3141 | PyPI (devpi) | `127.0.0.1` | `MRK_PYPI_LISTEN_HOST` |
| 9000 | S3 API | `127.0.0.1` | `MRK_S3_LISTEN` |
| 9001, 5433, 3142 | S3 admin, PGlite, PyPI router | `127.0.0.1` only | – |
| 53 | DNS | `127.0.0.1`, `172.17.0.1` (first start) | panel DNS settings |
| 7070 | Host Agent | `127.0.0.1` | `MRK_AGENT_LISTEN` |

In Docker, Compose publishes ports only on `127.0.0.1`; the native env file keeps the same rule by
binding everything to `127.0.0.1`. If you change any of these to a public address, **block it from the
Internet** with your host firewall, e.g.:

```bash
sudo ufw deny 4873/tcp
sudo ufw deny 3141/tcp
```

or with nftables in your own table. Do not add rules to the `inet mrk` table: it belongs to the
firewall helper, which replaces it as a whole.

### Reverse proxy and domains

Put a TLS reverse proxy in front of the panel, npm, PyPI and S3, set `MRK_TRUSTED_HOSTS`,
`MRK_CORS_ORIGINS`, `MRK_PYPI_OUTSIDE_URL` and `MRK_TRUSTED_PROXIES` in
`/etc/devassist/devassist.env`, then `sudo systemctl restart devassist`. For S3 the proxy must keep the
original `Host` header and must not buffer request bodies. Keep `MRK_AUTH_COOKIE_SECURE=true`:
sign-in works over HTTPS or `localhost`, not over plain HTTP on another address.

Dokploy's Traefik runs in Docker and cannot reach services that listen only on the host's
`127.0.0.1`. To route Dokploy domains to a native install you need the services to listen on an
address Traefik can reach (for example the Docker bridge gateway) and firewall rules that keep
them away from the Internet. The panel's automatic domain routing was written for the
`mrk-mirror` container (see `target_host` under US-158 in [docs/03](03-user-stories.md)); with a native
install, check the generated routes or use the manual mode.

## DNS (port 53)

```bash
sudo bash scripts/install-native.sh install --with-dns
dig @127.0.0.1 localhost +short
journalctl -u devassist-dns -n 50
```

The checks and steps are the same as in the [Docker guide, section 7](install-docker.md#7-dns-and-port-53)
(port 53 free, systemd-resolved drop-in, Docker `daemon.json`, verification), with one change:
the engine is managed with `systemctl start|stop|restart devassist-dns`, not `docker compose`. The
panel's setup page shows Compose commands for the engine step; use the systemctl ones instead.
systemd-resolved's stub listener on `127.0.0.53` does not conflict with `127.0.0.1:53`.

## Host Agent and firewall helper

```bash
sudo bash scripts/install-native.sh install --with-agent --with-firewall
journalctl -u devassist-agent | grep "pairing key"        # pair with URL http://127.0.0.1:7070
journalctl -u devassist-firewall | grep "pairing key"     # URL unix:/run/mrk-firewall/firewall.sock
```

- The agent needs Docker on the host. The host views it expects are bind-mounted read-only under
  `/opt/mrk/agent-host` (`/proc`, `/sys/fs/cgroup`, `/var/lib/docker/volumes`, and `/` without
  sub-mounts). Delete the `/` line in the unit (`systemctl edit --full devassist-agent`) to hide the
  host filesystem.
- The firewall helper reads `/var/log` read-only (the panel default `/host/log/system/auth.log`
  works). It is in the `adm` group so it can read Ubuntu's `auth.log`. For Traefik's access log,
  add the bind mount shown in the unit with `systemctl edit devassist-firewall`.

## Everyday commands

```bash
systemctl status devassist                    # state
journalctl -u devassist -f                    # all program logs (Supervisor output)
sudo systemctl restart devassist              # after editing /etc/devassist/devassist.env
sudo devassist-exec supervisorctl -c /opt/mrk/supervisord.conf status
sudo bash scripts/install-native.sh status
```

`devassist-exec` runs a command with the service's view of the system (the namespace above and its
environment) as the `devassist` user: inside the running service when it runs, otherwise in a
temporary unit with the same mounts. Runbook commands that start with
`docker compose exec mrk-mirror ...` ([docs/18](18-operations-runbooks.md)) become
`sudo devassist-exec ...`, for example the PGlite `VACUUM`:

```bash
sudo devassist-exec supervisorctl -c /opt/mrk/supervisord.conf stop control-plane
sudo devassist-exec python -c "import psycopg; c = psycopg.connect('postgresql://postgres:postgres@127.0.0.1:5433/postgres?sslmode=disable', autocommit=True); c.execute('VACUUM (ANALYZE)'); c.close()"
sudo devassist-exec supervisorctl -c /opt/mrk/supervisord.conf start control-plane
```

### Offline restore

Prepare the plan in the panel ([docs/18](18-operations-runbooks.md#encrypted-backup-and-offline-restore)), then:

```bash
sudo systemctl stop devassist
sudo install -m 0400 -o devassist -g devassist /dev/null /run/devassist-restore-passphrase
sudoedit /run/devassist-restore-passphrase           # paste the passphrase; never on the command line
sudo devassist-exec mrk-restore apply --plan '<plan-id>' \
  --passphrase-file /run/devassist-restore-passphrase \
  --confirmation 'APPLY <backup-id>' --offline-confirm I_HAVE_STOPPED_MRK
sudo shred -u /run/devassist-restore-passphrase
sudo systemctl start devassist
```

## Upgrade

```bash
cd devassist
git pull
sudo bash scripts/install-native.sh upgrade
```

Take an encrypted backup in the panel first. `upgrade` keeps the options of the first install,
builds the new release **while the old one keeps running**, then stops the service (up to 3
minutes), switches `/opt/mrk/current`, starts it again (migrations run on start) and waits for
the health check. The previous release stays in `/opt/mrk/releases` (older ones are removed).
Going back to an older release after a database migration is not supported without restoring
the backup you took.

## Uninstall

```bash
sudo bash scripts/install-native.sh uninstall            # programs, units, /opt/mrk, caches
sudo bash scripts/install-native.sh uninstall --purge    # also data, /etc/devassist and the user
```

Without `--purge`, the data directory, `/var/lib/mrk-*` and `/etc/devassist` are kept, so a later
`install` continues where you left off. `--purge` asks you to type `DELETE` (or pass `--yes`) and
cannot be undone. Uninstall also deletes the firewall helper's `inet mrk` nftables table if it
exists. Undo the DNS steps (resolved drop-in, `daemon.json`) yourself before removing the DNS
engine.

## Options

| Option | Meaning |
|---|---|
| `--with-dns`, `--with-firewall`, `--with-agent` | optional parts |
| `--data-dir DIR` | data folder (default `/var/lib/devassist`; fixed after the first install) |
| `--dns-binary PATH`, `--dnsbench-binary PATH` | use prebuilt engine binaries instead of Go (e.g. copied from the image with `docker cp`) |
| `--python PATH` | an existing Python 3.13 (e.g. Debian 13's `/usr/bin/python3.13`) instead of the pinned build |
| `--pip-index-url URL` | PyPI mirror for the build (pip checks no hashes: trust it like PyPI) |
| `--npm-registry URL` | npm mirror (lockfile integrity hashes are still enforced) |
| `--goproxy URL` | Go module proxy (`go.sum` is still enforced) |
| `--rebuild`, `--no-start`, `--skip-port-check`, `--skip-os-check`, `--min-free-gb N` | build and check control |
| `--yes`, `--dry-run`, `--lang fa\|en\|both` | prompts, preview, message language |

Download mirrors for the runtimes, through the environment: `DEVASSIST_NODE_DIST` (default
`https://nodejs.org/dist`), `DEVASSIST_GO_DIST` (default `https://dl.google.com/go`),
`DEVASSIST_UV_DIST` (default the uv GitHub releases) and uv's `UV_PYTHON_INSTALL_MIRROR`. A mirror
must serve the same files and checksum files as the original.

## Known differences

- The Docker image and Compose files are what CI builds and tests; the native mode reuses the same
  code and configuration but has no CI job yet. Please report problems.
- pip resolves transitive Python dependencies at install time, like the Dockerfile; they can
  differ from the image built on another day (the direct pins are checked).
- Verdaccio and devpi listen on all addresses (see [Ports and firewall](#ports-and-firewall)).
- Image update tracking and vulnerability scanning look at Docker containers through the Host
  Agent; the native DevAssist processes themselves are not an image and are not tracked.
- The DNS engine's pressure controller reads cgroup v2 data designed for a container; under
  systemd the limits come from the unit (`MemoryMax`, and `MRK_DNS_GOMEMLIMIT` is set explicitly
  in `dns.env`).
