# Native install of the panel (without Docker)

**English** · [فارسی](install-native.fa.md)

`scripts/install-native.sh` installs **only the MrK DevAssist panel** as one systemd service
(`devassist`): PGlite and the control plane, the same as the `panel` image of
[`deploy/images/Dockerfile`](../deploy/images/Dockerfile), built from this checkout at the
versions in [`versions.lock.yaml`](../versions.lock.yaml). npm and PyPI are off in the panel.
Every other service (server agent, DNS, firewall, S3, …) runs in Docker and is added from
the panel ([docs/44](44-split-services-and-install-wizard.md)). For an all-Docker setup see
[install-docker.md](install-docker.md).

## Requirements

- Debian 12/13 or Ubuntu 22.04/24.04, amd64 or arm64, with systemd
- 1 GiB of RAM for the panel, 3 GiB free disk for the build, Internet access while installing
- Ports 8080 (panel) and 5433 (PGlite, loopback) free
- Docker, only for the services you add later

## Install

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist && cd devassist
sudo bash scripts/install-native.sh install --dry-run   # print every step, change nothing
sudo bash scripts/install-native.sh install
```

The panel listens on `127.0.0.1:8080`. Open it with `ssh -L 8080:127.0.0.1:8080 <server>` and
`http://localhost:8080`, create the owner account, then go to **My services → Add a service**.
Settings live in `/etc/devassist/devassist.env` (`sudo systemctl restart devassist` after a
change), data in `/var/lib/devassist`, logs in `journalctl -u devassist -f`.
Mirrors for the build: `--pip-index-url`, `--npm-registry`, `DEVASSIST_NODE_DIST`, `DEVASSIST_UV_DIST`.

## Docker services next to a native panel

The env file sets `MRK_PANEL_RUNTIME=native`, so the wizard publishes service ports on
127.0.0.1 (agent `http://127.0.0.1:7070`, S3 admin `http://127.0.0.1:9001`) and bind-mounts
the DNS and firewall socket directories at `/run/mrk-dns` and `/run/mrk-firewall`. The
installer creates both at boot (`/etc/tmpfiles.d/devassist.conf`, mode `2750`, owner uid
10001 like the images, group `devassist`). The `devassist` user gets uid/gid 10001 when that
id is free, so the panel can use the sockets as is; if the installer warns that another id
was used, make the sockets group-writable for `devassist` or give the user uid 10001.

## Upgrade, status, uninstall

```bash
git pull && sudo bash scripts/install-native.sh upgrade   # builds, then restarts (take a backup first)
sudo bash scripts/install-native.sh status
sudo bash scripts/install-native.sh uninstall             # keeps data and /etc/devassist
sudo bash scripts/install-native.sh uninstall --purge     # also deletes data, config and the user
```

Uninstall also stops and removes the `devassist-agent`, `devassist-dns` and
`devassist-firewall` units left by older native installs. Docker services are not touched:
remove them in Dokploy/Coolify or with `docker compose down`.
