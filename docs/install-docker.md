# Install DevAssist with Docker

**English** · [فارسی](install-docker.fa.md)

DevAssist is a **panel** plus optional **services**. Install the panel first; it is the only
thing you set up by hand. Every other service is added from inside the panel, which gives you a
ready `compose.yaml` and `.env` for it and connects to it afterwards.

## 1. Panel (required)

Requirements: Linux server (amd64/arm64) with Docker and the Compose plugin, 2 GB free RAM for the panel (each service shows its own needs on its card).

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist
cd devassist && docker compose up -d
```

- **Dokploy:** Create Service → Compose → this repository, Compose Path `./compose.yaml`.
- **Coolify:** New Resource → Docker Compose → this repository's `compose.yaml`.
- **Without Docker** (panel only, systemd): see [install-native.md](install-native.md).

The stack is the panel plus its PostgreSQL (`mrk-db`, data in the volume `mrk-db-data`, or a host
folder with `MRK_HOST_DB_PATH`); the database password is generated on first start. The panel listens
on `127.0.0.1:8080`. Open it through an SSH tunnel and create the owner account
right away:

```bash
ssh -L 8080:127.0.0.1:8080 you@your-server   # then open http://localhost:8080
```

To give it a domain later, add it in the panel (My services → Add a domain).

## 2. Services (optional, from the panel)

Open **My services → Add a service**, pick a service and where to run it (Dokploy, Coolify or plain
`docker compose`). The wizard shows the files, the exact steps for that tool, and then checks the
connection. Or pick **Automatic install**: with Dokploy or Coolify connected, the panel creates the
service through their API, deploys it and connects it by itself.

| Service | What it does | Image |
|---|---|---|
| Server agent | Server health, Docker apps, backups, updates, vulnerability checks | `mrk-agent` |
| DNS | DNS server for the host, containers and network, with blocking | `mrk-dns` |
| Firewall | Spots attacks and failed logins, blocks the addresses (dry-run first) | `mrk-firewall` |
| File storage (S3) | S3-compatible buckets for apps and backups | `mrk-s3` |
| npm registry | Private npm registry and cache, with upstream failover | `mrk-npm` |
| PyPI registry | Private PyPI mirror; fetches through the panel (failover, proxies, quarantine) | `mrk-pypi` |
| Git | Your code repositories and mirrors of GitHub/GitLab (Gitea) | `gitea/gitea` |
| Docker image registry | Private images and a Docker Hub/ghcr.io mirror with fallbacks (Zot) | `project-zot/zot` |

Images are `ghcr.io/seniorkian/mrk-<name>` with the same version as the panel. Every service runs
on the same server as the panel (they share its internal network `mrk-net`; npm and PyPI also share
their data folders with it).

## 3. Upgrade

The easiest way: **My services → Versions & updates** in the panel (docs/47). By hand:

```bash
git pull && docker compose pull && docker compose up -d
```

For each service, redeploy it in Dokploy/Coolify (or `docker compose pull && docker compose up -d`
in its folder) after updating `MRK_IMAGE` to the new version.

## 4. Backup and uninstall

- Backup: **Files & backups → Panel backup** in the panel; restore steps are in
  [18-operations-runbooks.md](18-operations-runbooks.md#encrypted-backup-and-offline-restore).
- Uninstall: `docker compose down` (keeps data) or `docker compose down -v` (deletes it). Remove each
  service stack the same way from where you deployed it.
