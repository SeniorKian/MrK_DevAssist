# Pishkar

**English** · [فارسی](README.fa.md)

**Pishkar** (Persian «پیشکار», the steward who runs the house for you) is a free,
self-hosted server assistant that runs next to [Dokploy](https://dokploy.com).
It keeps your builds working when the Internet does not: private npm and PyPI
mirrors with automatic failover, a native S3 store, a native DNS server, backups,
monitoring, a firewall and Docker tools, all in one Persian-first admin panel.

> The project was developed under the name *MRK*. Repository, package, image and
> container names (`mrk-mirror`, `mrk-dns`, `MRK_*` variables, `/opt/mrk`) keep that
> prefix; only the product name changed.

- License: [MIT](LICENSE). Free for everyone, no paid edition.
- Status: active development (version 0.1). Read [SECURITY.md](SECURITY.md) before exposing it to the Internet.

## Screenshots

Screenshots are not in the repository yet. They will live in [`docs/images/`](docs/images/):

| Planned file | Shows |
|---|---|
| `docs/images/home.png` | home page: only what needs attention |
| `docs/images/services.png` | "My services": state, usage, domains |
| `docs/images/packages.png` | npm/PyPI sources and failover |
| `docs/images/dns.png` | DNS names, test and monitor |
| `docs/images/files.png` | S3 file manager |

<!-- When the images exist, replace the table with e.g.:
![Home](docs/images/home.png)
-->

## Features

**Package mirrors**
- npm registry ([Verdaccio](https://verdaccio.org) 6) and PyPI mirror ([devpi](https://devpi.net)), served from your server.
- Several upstreams per registry with health checks and failover (e.g. npmjs.org first, a regional mirror second); timeouts, network errors and 5xx move to the next one.
- Cached packages install even with the Internet fully down.
- Package policies and quarantine, integrity scan, purge with a trash, private npm sources.
- Works with `npm`, `pnpm`, `yarn`, `pip`, `uv` and `poetry`.

**Native services** (written for this project, no third-party server inside)
- **S3-compatible object storage**: SigV4 and presigned URLs, multipart uploads, managed buckets and *linked folders* (a host folder exposed as a bucket), tagging, lifecycle rules, versioning, a file manager in the panel. Usable as a Dokploy backup destination.
- **DNS server** (Go): authoritative zones, overrides, forwarding and full recursion with DNSSEC validation, DoT/DoH/DoQ in and out, a compressed query log, statistics, flood detection with automatic, reversible mitigations. It is never an open resolver.

**Server control next to Dokploy**
- Dokploy integration through its official API; domains for every service through Dokploy without touching ports 80/443.
- Optional Host Agent: containers, live logs, start/stop/restart, image pull, safe prune with a preview (Dokploy's own containers are protected).
- Resource monitoring, image update tracking, vulnerability scanning (OSV) with CycloneDX/SPDX SBOM export.
- Database admin for PostgreSQL, MySQL/MariaDB, MongoDB and Redis (read-only by default).
- Optional nftables firewall helper: brute-force detection from sshd/Traefik/panel logs, dry-run by default, every ban expires.

**Operations**
- Encrypted appliance backups (AES-256-GCM, scrypt) with an offline, journaled restore.
- Server and database backups to a folder, any S3 service or the built-in S3, on a schedule, with restore tests.
- Notifications: Telegram, Bale, email and signed webhooks, with rules and quiet hours.
- Users, built-in and custom roles, invites, sessions, audit log with CSV export.
- Outbound proxy profiles (HTTP, SOCKS5) per service.
- Every tunable is listed in **Settings → All settings**, with a description, its default and where it is set.
- Persian (RTL) and English interface, with a *Simple* and an *Advanced* mode on every page.

## Quick install (Docker)

Requirements: a Linux server (amd64 or arm64) with Docker Engine and the Compose plugin
(Dokploy servers already have both), 2 GB of free RAM and disk space for your package cache.

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git pishkar && cd pishkar && docker compose up -d --build
```

This builds the image from source and starts the panel, npm, PyPI and S3. Every port is bound
to `127.0.0.1` only. From your computer, open a tunnel and visit <http://localhost:8080>:

```bash
ssh -L 8080:127.0.0.1:8080 you@your-server
```

The first visit shows **First Time Setup**: create the owner account right away.
For production (published image, real domains, TLS through Dokploy, the DNS/firewall/agent
profiles and the port 53 guide) read **[docs/install-docker.md](docs/install-docker.md)**.

## Native install (without Docker)

Pishkar can also run directly on Debian 12/13 or Ubuntu 22.04/24.04 as systemd services,
with the same processes, versions and hardening as the container:

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git pishkar && cd pishkar
sudo bash scripts/install-native.sh install --dry-run   # see the plan first
sudo bash scripts/install-native.sh install            # add --with-dns, --with-firewall, --with-agent
```

Read **[docs/install-native.md](docs/install-native.md)** first.

## Requirements

| | Docker install | Native install |
|---|---|---|
| OS | any Linux with Docker Engine and the Compose v2 plugin | Debian 12/13, Ubuntu 22.04/24.04 with systemd |
| CPU | amd64 or arm64 | amd64 or arm64 |
| RAM | 2 GB for the main container (+512 MB DNS, +256 MB agent) | same limits as systemd `MemoryMax` |
| Disk | a few GB plus your npm/PyPI/S3 data | the same, plus about 3 GB for the build |
| Ports | 8080 panel, 4873 npm, 3141 PyPI, 9000 S3; 53 for DNS (optional) | the same |

## Configuration overview

- Settings come in three layers: the **panel** (most settings, applied without a restart),
  **environment variables** `MRK_*` (read at start-up), and **build arguments** (download mirrors
  for the image build). An explicit environment variable always wins.
- **Settings → All settings** in the panel lists every setting with its description, default,
  current source and whether it needs a restart. The source of truth is the settings registry in
  `apps/control-plane/src/mrk_control_plane/settings_registry_entries_*.py`.
- Docker: values Compose reads are in [`.env.example`](.env.example) (copy it to `.env`); the
  container settings are in `compose.yaml` / `deploy/appliance/compose.production.yaml`.
- Native: `/etc/pishkar/pishkar.env` (template: [`deploy/native/pishkar.env.example`](deploy/native/pishkar.env.example)).
- Before going public set at least `MRK_TRUSTED_HOSTS`, `MRK_CORS_ORIGINS` and
  `MRK_PYPI_OUTSIDE_URL` (or the domains in the panel) to your real HTTPS names.
- Embedded PGlite is the default database; set `MRK_DATABASE_URL` to an external PostgreSQL
  (`postgresql+psycopg://...`) for larger installs. More: [docs/27](docs/27-configurability-and-settings.md).

## Security notes

- **Claim the panel first.** Until an owner exists, whoever reaches the panel first can create it.
  Keep the panel on `127.0.0.1` (the default) until you have done First Time Setup.
- Put the panel behind TLS (Dokploy/Traefik or another reverse proxy) before using it over the
  Internet, and set `MRK_TRUSTED_PROXIES` so the audit log sees real client addresses.
- The main container runs as uid `10001`, with every capability dropped, a read-only root
  filesystem and `no-new-privileges`. The native systemd units apply the same rules.
- The optional **Host Agent** talks to the Docker socket, which is equivalent to root on the host.
  It only sends calls on an in-code allowlist and only answers HMAC-signed requests.
- The optional **firewall helper** runs as root with only `CAP_NET_ADMIN` and touches only its own
  nftables table `inet mrk`. It starts in dry-run mode.
- Keep the backup passphrase and `MRK_UPSTREAM_SECRET_KEY_FILE` outside the data directory.
- Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## Documentation

- [Install with Docker](docs/install-docker.md) · [Native install](docs/install-native.md)
- [Operations runbooks](docs/18-operations-runbooks.md) (restore, PGlite maintenance, PyPI bootstrap)
- [Process supervision and health](docs/11-process-supervision-and-health.md)
- [CI/CD and releases](docs/12-ci-cd-and-release.md)
- [Settings](docs/27-configurability-and-settings.md) · [Appliance details](deploy/appliance/README.md)
- Design documents and contracts: `docs/01` to `docs/43` (mostly in Persian); finished ones are
  archived as user stories in [docs/03](docs/03-user-stories.md).

## Contributing

Contributions are welcome: bug reports, fixes, translations, docs and new modules.
Start with [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).
Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Support the project

Pishkar is and will stay free. If it saves you time or money, you can support its development
with a donation. Donation links will be published here and in the GitHub *Sponsor* button
(`.github/FUNDING.yml`) as soon as they are set up. Starring the repository, reporting bugs and
sharing it with others help a lot too.

## License

[MIT](LICENSE). Third-party components keep their own licenses (Verdaccio MIT, devpi MIT,
PGlite Apache-2.0/PostgreSQL, miekg/dns BSD-3-Clause, and others listed by
`scripts/check_licenses.py`).
