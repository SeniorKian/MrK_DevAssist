<div align="center">
  <img src="apps/admin-ui/public/favicon.svg" alt="DevAssist" width="96" />
  <h1><sub>MrK</sub> DevAssist</h1>
  <p><strong>Your self-hosted server and DevOps assistant.</strong><br />
  Package mirrors, S3 storage, DNS, backups and monitoring — in one panel, next to Dokploy.</p>
  <p>
    <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-14b8a6" /></a>
    <img alt="Docker" src="https://img.shields.io/badge/docker-ready-38bdf8" />
    <img alt="Self-hosted" src="https://img.shields.io/badge/self--hosted-100%25-0f766e" />
  </p>
  <p><a href="README.fa.md">فارسی</a> · <a href="docs/install-docker.md">Docs</a> · <a href="CONTRIBUTING.md">Contributing</a> · <a href="SECURITY.md">Security</a></p>
</div>

---

**DevAssist** is a free, open-source server and DevOps assistant by MrK. It keeps your builds and services working even when the Internet doesn't,
and gives the people you host a simple space of their own — without handing them the keys
to the server.

## Features

- **Package mirrors** — private npm and PyPI registries with automatic upstream failover; cached packages install even offline.
- **S3 storage** — native S3-compatible object store with a file manager, presigned links, versioning and lifecycle rules.
- **DNS server** — authoritative and recursive DNS with DNSSEC, DoT/DoH/DoQ, zone transfer, ad/malware blocking, domain templates and flood protection.
- **My space** — workspaces for users and teams with plans and quotas: their own domains, buckets, keys and packages, fully isolated.
- **Next to Dokploy** — domains for every service through Dokploy, container tools, resource monitoring, vulnerability scanning and SBOM export.
- **Operations** — encrypted backups and restore, notifications (Telegram, email, webhooks), roles and audit log, firewall helper.
- **Made to be simple** — Persian and English interface, a *Simple* and an *Advanced* mode on every page, and every setting documented in the panel.

## Install

DevAssist is a **panel** plus optional **services**. The panel is the only thing you install by hand;
everything else is added from inside it.

**1. Panel** — one command on a Linux server with Docker:

```bash
git clone https://github.com/SeniorKian/MrK_DevAssist.git devassist
cd devassist && docker compose up -d
```

Dokploy / Coolify: create a Compose service from this repository's `compose.yaml`.
No Docker? `sudo bash scripts/install-native.sh install` installs the panel with systemd.
Then open <http://localhost:8080> through `ssh -L 8080:127.0.0.1:8080 you@your-server` and create the owner account.

**2. Services** — in the panel, **My services → Add a service**. The wizard gives a ready
`compose.yaml` and `.env` for Dokploy, Coolify or `docker compose`, then connects and checks it.

| Service | Image |
|---|---|
| Panel (required) | `ghcr.io/seniorkian/mrk-panel` |
| Server agent | `ghcr.io/seniorkian/mrk-agent` |
| DNS | `ghcr.io/seniorkian/mrk-dns` |
| Firewall | `ghcr.io/seniorkian/mrk-firewall` |
| File storage (S3) | `ghcr.io/seniorkian/mrk-s3` |
| npm / PyPI mirrors | coming as their own images; for now `deploy/appliance/compose.yaml` |

More: [Docker install](docs/install-docker.md) · [Native install](docs/install-native.md)

## Security

- Create the owner account right after the first start — until then, whoever reaches the panel can claim it.
- Put the panel behind TLS before exposing it. Containers run unprivileged with a read-only root filesystem.
- Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) for the setup,
tests and project conventions. What is built and planned: [user stories](docs/03-user-stories.md).

## Support

DevAssist is free and has no paid edition. If it helps you, you can support it with a donation
(links coming soon in [FUNDING.yml](.github/FUNDING.yml)).

## License

[MIT](LICENSE) © Mohammad Kiani
