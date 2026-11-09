# Changelog

All notable changes to DevAssist are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (0.x: anything may still change).
No version has been tagged yet; everything below is in the first release, 0.1.0.

## [Unreleased]

### Added
- Open-source release files: new README (English and Persian), CONTRIBUTING, Code of Conduct,
  Security policy, issue and pull request templates, funding placeholder, this changelog.
- Product name **MrK DevAssist**: product "DevAssist" with the maker signature "MrK", and a new
  D+A logo. Code and container identifiers keep the `mrk` prefix; the published image is
  `ghcr.io/<owner>/mrk-devassist`.
- Native install without Docker for Debian 12/13 and Ubuntu 22.04/24.04:
  `scripts/install-native.sh` (install, upgrade, status, uninstall, `--dry-run`) and systemd units
  in `deploy/native/systemd/` that mirror the containers' processes, environment and hardening.
- Install guides: `docs/install-docker.md` and `docs/install-native.md`, with Persian versions.

## 0.1.0 — development history (2026-11-07 to 2026-11-09)

### Backups, users, audit, S3, SBOM (ad0c88e)
- Server backups: restore a run to a new folder (hash check, decrypt, traversal-safe unpack),
  test restore and scheduled verification, panel UI.
- Users: delete, admin password reset through a one-time link, sign out everywhere; guards for
  the last owner and for yourself.
- Audit history: cursor paging, server-side filters, full CSV export.
- S3: object and bucket tagging, lifecycle rules with a daily job and dry-run preview, versioning
  for managed buckets with ListObjectVersions.
- Vulnerability scanning: CycloneDX 1.5 and SPDX 2.3 SBOM export, whole server or per image.

### DNS D4 and new sign-in page (9df9787)
- DNS engine: forward, recursive and forward-then-recursive modes (root priming, QNAME
  minimisation, 0x20, bailiwick checks, query budgets); DNSSEC validation in every mode with
  RFC 5011 trust-anchor updates, NSEC/NSEC3, negative trust anchors and Extended DNS Errors;
  incoming DoT, DoH and DoQ with certificates and DoH access tokens; outbound `quic://` upstreams.
- Control plane and panel: validation and warnings for the new settings, resolve trace, DNSSEC
  and encrypted-connection pages, per-device setup guides with QR codes, a `dns-doh` service so a
  domain can reach DoH through Traefik.
- A simpler, centered sign-in page shared by setup, invite and password change.

### My services, domains, native DNS engine D1/D2, crash recovery (1a568bf)
- "My services": one page with every service, its state, start/stop/restart, usage, ports and
  domains; unlimited domains per service through Dokploy (API, an opt-in Traefik file written by
  the Host Agent, or a manual guide) without touching ports 80/443; DNS/TLS/reach checks.
- Crash recovery: only database or panel failures restart the container; npm, PyPI and S3 are
  retried by a watchdog with growing waits and notifications.
- Native Go DNS engine in its own hardened container: authoritative zones, overrides, forwarding
  with cache, DoT/DoH upstreams, ACLs and rate limits, never an open resolver; binds port 53 and
  drops to uid 10001 with only `NET_BIND_SERVICE`. Query log, statistics, pressure levels with
  automatic reversible actions, attack detection and mitigations. Panel DNS section.

### Server control modules, native S3, security, panel redesign (9b03bd3)
- Review and hardening: PyPI router spooling and failover, Supervisor FATAL handling, CSRF,
  rate limits, chunked encrypted backups (MRKBKP2), restore rollback, quarantine enforcement,
  integrity scan, devpi init safety, Debian 13 base images; configurable DNS resolver, outbound
  proxy profiles per service, private-upstream policy, simpler password policy.
- Host Agent (HMAC-signed, Docker API allowlist) and a notification center (Telegram, Bale,
  email, signed webhooks).
- Dokploy integration through its API, resource monitoring, live container logs, Docker actions
  and safe prune with preview.
- Native S3-compatible object storage (SigV4, multipart, managed and linked-folder buckets),
  server and database backups, image update tracking.
- nftables firewall helper, OSV-based vulnerability scanning, read-only-by-default database
  administration.
- Panel redesign: seven navigation groups, attention-only home page, shared UI kit, plain Persian
  copy with a blocking CI check, Simple/Advanced mode, a registry of every setting, role cards,
  custom roles, three-step invites and forced password change.

### Package mirror appliance (1e6bd3b to 7bc1288)
- First appliance: one hardened container with the control plane, admin panel, embedded PGlite,
  Verdaccio (npm), devpi (PyPI) with a failover router, Supervisor, encrypted backups and offline
  restore; CI with image build, Trivy, soak and load gates; GHCR publishing workflow.
- Fixes: data-volume initialization and ownership hand-off, log pipe hand-off, PyPI response
  lengths, runtime image vulnerabilities, license metadata, development data directory.
- CI: hardened non-root soak start, isolated test hostnames, capability-minimal volume bootstrap.
- Docs: completed gates archived into the user stories.
