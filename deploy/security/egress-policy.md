# Runtime network policy

MRK needs no unrestricted outbound access. The application policy and the host/PaaS firewall should
permit only the destinations below. DNS answers for public package CDNs change, so enforcement should
use an FQDN-aware firewall or an egress proxy; static CDN IP rules are intentionally not provided.

| Direction | Source | Destination | Port | Purpose |
| --- | --- | --- | --- | --- |
| egress | MRK | configured DNS resolvers | UDP/TCP 53 | name resolution |
| egress | MRK | `registry.npmjs.org` | TCP 443 | primary npm uplink |
| egress | MRK | `package-mirror.liara.ir` | TCP 443 | npm/PyPI fallback |
| egress | MRK | `pypi.org` | TCP 443 | PyPI index |
| egress | MRK | `files.pythonhosted.org` | TCP 443 | PyPI artifacts |
| egress | MRK | configured external PostgreSQL | TCP 5432 | only in external DB mode |
| ingress | reverse proxy | MRK | TCP 8080 | admin UI and API |
| ingress | reverse proxy | MRK | TCP 4873 | npm registry |
| ingress | reverse proxy | MRK | TCP 3141 | PyPI simple API |

All other runtime ingress and egress should be denied. Port 5433 is the embedded PGlite wire endpoint
and must remain loopback-only inside the container. Port 3142 is the internal PyPI failover router and
must also remain loopback-only.

Application enforcement is defense in depth:

- npm uplinks are generated atomically from the validated upstream store and require TLS validation;
- private npm bearer tokens are injected through per-uplink process environment names and never written to generated YAML;
- PyPI index and artifact destinations are HTTPS-only and host-allowlisted;
- DNS results that are private, loopback, link-local, reserved or multicast are rejected;
- every PyPI redirect is revalidated and credential-bearing URLs are rejected;
- admin upstream probes use the same public-IP and TLS requirements and `trust_env=False`.

If an administrator adds a custom public upstream, its hostname and artifact host must be added to the
infrastructure FQDN policy before enabling it. Private upstream support requires an explicit future
policy and must not be enabled with `MRK_PYPI_ROUTER_ALLOW_PRIVATE` in production.
