# Changelog

All notable changes to DevAssist are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (0.x: anything may still change).
No version has been tagged yet; everything below is in the first release, 0.1.0.

## [Unreleased]

## [0.3.0] - 2026-11-12

### Added
- The add-service wizard asks where each service keeps its data: a Docker volume or a folder
  on the server. Folders shared with the panel (registry config, npm/PyPI data, DNS and firewall
  sockets) follow the panel's own mount, read from its container or its compose in Dokploy.
  Chosen folders are checked through the server agent (exists, owner, free space) with the exact
  commands to fix them, and updates keep them.
- Every user-facing password or secret key (panel users, S3 keys, registry and Git users) can be
  typed by the user; the panel suggests a strong one that can be edited, and passwords can be
  changed later.
- Firewall quick actions: one-line commands in Persian or English ("open 8080", "allow
  10.0.0.0/8 -> 5432", "only me to 22 for 1h"), presets, per-port actions on listening ports,
  temporary rules that expire, undo, and a preview before applying.
- The real SSH port is found from the server's listening sockets (SSH banner), then ssh.socket
  and sshd_config; the admin can confirm or set it.
- S3: a browser opening a public bucket's root gets its index.html or a short page instead of
  an XML error, and a `/<bucket>/<key>` link opened on the bucket's own domain still finds the
  file.
- Two-step sign-in with an authenticator app (TOTP): set up from «My sign-in security» with a QR
  code, ten one-time backup codes (stored hashed), new codes, turn off with password + code.
  Admins can require it for everyone or chosen roles (forced setup after sign-in) and reset it
  for a person (`POST /api/v1/users/{id}/mfa/reset`).
- Single sign-on with OpenID Connect (Google, Microsoft, Keycloak, Authentik, ...): owner
  settings under People › Public sign-up, PKCE + state + nonce, ID tokens verified against the
  provider's keys, link by verified email, optional automatic accounts with a chosen role,
  allowed email domains, and an "SSO only" mode for everyone except owners.
- «My sign-in security» lists where you are signed in and can sign out other devices.

### Changed
- Sessions no longer end while you work: the idle window slides with activity (default 12 h,
  `MRK_SESSION_TTL_SECONDS`), "Keep me signed in" (on by default) keeps a persistent cookie and
  allows 7 days idle (`MRK_SESSION_REMEMBER_TTL_SECONDS`), and every sign-in ends after at most
  30 days (`MRK_SESSION_MAX_AGE_SECONDS`). After an expired session the panel returns to the
  page you were on.

### Fixed
- Domain checks recognise the image registry (Zot) and Git (Gitea) instead of reporting that
  their domain reaches another service.

## [0.2.1] - 2026-11-12

### Fixed
- The panel and Dokploy agree: Dokploy is the source of truth. A service's Compose is found by
  the service it runs (stale ids from re-created stacks, stacks pasted by hand), domains added in
  Dokploy are read back (manual rows become managed, unknown ones are imported), the service's own
  Dokploy domain is adopted instead of refused, and a domain that needs a deploy says so with a
  "Deploy now" button instead of raising alarms.
- Updates keep the admin's setup: an image line like `${{project.MRK_VERSION}}` moves that
  project variable instead of becoming a literal, an edited compose file is kept, a deploy counts
  as done only when the new deployment is, and "needs update" reads the running container.
- Automatic install reuses the existing stack or project instead of creating duplicates, and
  refuses to start a second copy of a service in another project.
- No false alarms: domain checks go to Traefik inside the Docker network (the server's own
  public IP is often unreachable from inside Docker), Dokploy statuses map correctly ("done" is
  deployed, not "in progress"), and the agent, firewall, S3 and Dokploy are marked unreachable
  only after repeated failures. Dokploy's own error message is shown and logged.
- Bucket custom domains route to the S3 service's stack, not the panel's.
- The firewall healthcheck uses only the standard library (fast at 0.25 CPU); the DNS
  container defaults to 1 CPU so it starts on 1-vCPU servers.

## [0.2.0] - 2026-11-11

### Added
- Unified firewall management (docs/45): the panel is the one place for port policy and dynamic
  defense. The firewall helper owns only its own nftables table (`inet mrk`), with an input chain
  for host services and a forward chain for published Docker ports, applied atomically; Docker
  and Dokploy chains are left alone.
- Versioned releases (docs/47): `VERSION` is the single version; `scripts/release.py X.Y.Z`
  writes it everywhere (including the pinned panel image in compose.yaml), cuts the changelog
  section and tags `vX.Y.Z`. The tag publishes every image as X.Y.Z / X.Y / latest and creates
  a GitHub release; CI refuses a tag that does not match VERSION. The panel's "Versions &
  updates" page finds new releases and updates the panel and its services (one click when they
  were installed through Dokploy/Coolify; exact steps otherwise), keeping pairing keys.
- Git service (Gitea) and Docker image registry (Zot), both added from the wizard (docs/46).
  Gitea keeps its own SQLite database; the panel creates its admin, keeps only an API token and
  manages repositories, mirrors of GitHub/GitLab, users and organizations. Zot is a private
  registry plus an on-demand mirror of Docker Hub, ghcr.io, quay.io and registry.k8s.io with
  fallback URLs; the panel writes its config and bcrypt htpasswd (Zot reloads them). New
  permissions git:read/write and registry:read/write and the page "Code & images".
- Split install (docs/44): the panel runs alone first (`compose.yaml` at the repository root,
  image `mrk-panel`), and every other service is added from **My services → Add a service**. The
  wizard gives a ready `compose.yaml` and `.env` for Dokploy, Coolify or `docker compose`, with the
  steps for that tool, then connects to the service and checks it. Separate images `mrk-agent`,
  `mrk-firewall` and `mrk-dns` from `deploy/images/Dockerfile`, published to GHCR with the panel's
  version. The agent and firewall take their pairing key from the wizard's `.env`
  (`MRK_AGENT_PAIRING_KEY`, `MRK_FIREWALL_PAIRING_KEY`) instead of printing it in their logs.
- PostgreSQL instead of the embedded PGlite: the panel stack runs `mrk-db` (PostgreSQL 17, data
  in the volume `mrk-db-data` or `MRK_HOST_DB_PATH`); a one-shot `mrk-db-init` generates the
  password into a private volume (`MRK_DATABASE_PASSWORD_FILE`), so no password lives in `.env`.
  The native install uses the distro's PostgreSQL. Node and PGlite left the panel image.
- npm (`mrk-npm`) and PyPI (`mrk-pypi`) as their own images, added from the wizard. They share
  their data volumes with the panel, which writes Verdaccio's config (the container restarts
  Verdaccio on change) and keeps the PyPI router; devpi mirrors through it over `mrk-net`.
  Domains of separate services route to their own containers. The old all-in-one image
  (`deploy/appliance`) is gone; CI builds, scans and smoke-tests the whole split stack.
- Automatic install: with Dokploy or Coolify connected, the panel creates, deploys and connects
  a service itself through their API (`/api/v1/install/{id}/auto`).
- The native install (`scripts/install-native.sh`) installs only the panel; every other
  service is Docker, from the wizard, which adapts its stacks to a native panel
  (`MRK_PANEL_RUNTIME=native`: loopback ports and host socket folders instead of `mrk-net`).
- Shorter install docs: one page per install type, one row per service. Implemented design
  documents were removed (listed in `docs/03-user-stories.md`, full text in git history), as
  were unused files (e2e fixtures, the egress note, `compose.split-storage.yaml`).
- S3 file storage as its own image (`mrk-s3`), added from the same wizard. The panel pushes
  buckets, users and keys to it over the internal network (`PUT /admin/config`) instead of a
  shared config file, re-sends them if the engine missed them, and the file manager, backups
  and «My space» follow the engine's address.
- Open-source release files: new README (English and Persian), CONTRIBUTING, Code of Conduct,
  Security policy, issue and pull request templates, funding placeholder, this changelog.
- Product name **MrK DevAssist**: product "DevAssist" with the maker signature "MrK", and a new
  D+A logo. Code and container identifiers keep the `mrk` prefix; the published image is
  `ghcr.io/<owner>/mrk-devassist`.
- Native install without Docker for Debian 12/13 and Ubuntu 22.04/24.04:
  `scripts/install-native.sh` (install, upgrade, status, uninstall, `--dry-run`) and systemd units
  in `deploy/native/systemd/` that mirror the containers' processes, environment and hardening.
- Install guides: `docs/install-docker.md` and `docs/install-native.md`, with Persian versions.

### Changed
- Node 26.13 in the image builds (the npm image now ships libatomic, which Node 26 needs),
  fastapi 0.162.2, hatchling, ruff and the pinned GitHub Actions updated. setuptools stays
  below 82 (devpi still imports `pkg_resources`) and the base image stays on Python 3.13.

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
