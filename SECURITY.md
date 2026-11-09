# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub Security Advisories:
**[Report a vulnerability](https://github.com/SeniorKian/MrK_DevAssist/security/advisories/new)**
(repository → *Security* → *Report a vulnerability*).
<!-- TODO(owner): enable "Private vulnerability reporting" in Settings → Code security. -->

If you cannot use GitHub, email **`<SECURITY_EMAIL>`**.
<!-- TODO(owner): replace <SECURITY_EMAIL> with a real, monitored address. -->

Please include:

- the affected component (control plane, admin UI, DNS engine, S3 engine, Host Agent, firewall
  helper, install scripts, image) and version or commit;
- the install type (Docker or native) and relevant settings;
- steps to reproduce or a proof of concept, and the impact you expect.

What to expect: an acknowledgement within 7 days, an assessment and plan within 30 days, and
credit in the advisory and changelog if you want it. This is a volunteer project, so please give
us reasonable time to release a fix before you publish details. You may write in Persian or English.

> فارسی: مشکل امنیتی را در issue عمومی ننویسید؛ از لینک «Report a vulnerability» بالا گزارش
> خصوصی بدهید. گزارش فارسی یا انگلیسی پذیرفته می‌شود.

## Supported versions

DevAssist is in its 0.x series. Only the latest release and the current `main` branch receive
security fixes; there are no backports to older 0.x releases.

| Version | Supported |
|---|---|
| latest 0.x release | yes |
| `main` | yes |
| older releases | no |

## Scope

In scope:

- the code in this repository: `apps/control-plane` (API, auth, modules, PyPI router, S3 engine,
  Host Agent, firewall helper, restore CLI), `apps/admin-ui`, `apps/dns-engine`;
- the image build and runtime configuration (`deploy/appliance`, Compose files) and the native
  install (`scripts/install-native.sh`, `deploy/native`);
- privilege boundaries: escaping the unprivileged user, the Host Agent's Docker API allowlist,
  the firewall helper's nftables scope, DNS acting as an open resolver or amplifier, S3 signature
  or policy bypass, authentication, CSRF, session and permission bypass, secrets in logs or the UI.

Out of scope:

- vulnerabilities in upstream projects we use unmodified (Verdaccio, devpi, PGlite, Python, Node,
  Go, libraries): report them upstream; tell us if DevAssist's use makes them exploitable;
- issues that need an already compromised host, root access or the owner account;
- missing hardening on deployments that changed the documented defaults (for example a panel
  published without TLS or with `MRK_AUTH_COOKIE_SECURE=false`);
- denial of service by sheer traffic volume, and findings from automated scanners without a
  demonstrated impact.

## Security design notes

- The main container runs as uid 10001 with every capability dropped, a read-only root
  filesystem and `no-new-privileges`; the native systemd units do the same.
- Access to the Docker socket (Host Agent) is equivalent to root on the host. The agent only
  sends allowlisted Docker API calls and only answers HMAC-signed requests.
- Backups are encrypted with AES-256-GCM (scrypt key derivation); restore is offline only.
- Details: [docs/09-security-access-review.md](docs/09-security-access-review.md),
  [docs/05-api-data-security.md](docs/05-api-data-security.md),
  [deploy/appliance/README.md](deploy/appliance/README.md).
