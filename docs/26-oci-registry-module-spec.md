# MRK OCI/Docker Registry Module — Engineering Spec (research draft)

Date: 2026-11-08 · Status: research / pre-ADR · Scope: a clean-room module written in our own code that implements the OCI Distribution protocol inside the existing MRK appliance (one image, supervisord, FastAPI control plane, PGlite/PostgreSQL, `/data` bind mount).

Read before this: `README.md`, `docs/02`, `docs/16` (PyPI failover router), `docs/20` (modular appliance + hostname routing).

---

## 0. Executive summary

- **What we build:** module `registry-oci`. It runs as its own process (`oci-engine`, uvicorn on `127.0.0.1:5000`) under supervisord and is published only through the Edge Gateway at `registry.<domain>`, with an optional `hub.<domain>`. Our own Python code covers the protocol, storage, GC, auth and pull-through. **No distribution/registry, Harbor, Zot or Nexus binaries ship in the image.** Trivy is an optional external scanner only.
- **Why it is feasible:** the OCI Distribution Spec is small: about 13 endpoints, JSON manifests and opaque content-addressed blobs. The hard parts are not the protocol. They are (a) streaming multi-GB bodies without buffering, (b) GC that is safe while pushes run, (c) upstream token negotiation and redirects with SSRF control, and (d) the client quirks of docker, containerd and podman.
- **Key Iran-specific insight:** blobs, and manifests addressed by digest, are content-addressed. **Any** upstream or mirror can serve them safely once the digest is verified, so failover is trust-free for them. Only *tag → digest* resolution needs a trust policy.
- **Python is adequate** for the target users (a solo DevOps person or a small team). International bandwidth is the real bottleneck. The design keeps a seam to hand blob GETs off to the gateway (X-Accel-Redirect style sendfile) later, if benchmarks require it. Go or Rust is not justified at MVP (§5.6).
- **Effort:** MVP about 7–9 engineer-weeks, P1 about 5–7, P2 about 6–8 (§9).

---

## 1. Protocol: OCI Distribution Spec v1.1

Reference: opencontainers/distribution-spec `spec.md` v1.1.x. `docker/distribution` docs cover Docker-only extensions such as `_catalog`.

### 1.1 Grammar (enforced before any other logic)

| Item | Rule |
|---|---|
| `<name>` | `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*` — full match, plus a total length limit of **≤ 255** (our own limit, applied together with the hostname per Docker convention). Reject `..`, empty components, uppercase, `%`-encoded slashes. |
| `<reference>` tag | `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}` |
| `<reference>` digest | `algorithm:encoded`. Accept `sha256` (`[a-f0-9]{64}`) and optionally `sha512` (`[a-f0-9]{128}`). Return `DIGEST_INVALID` / `UNSUPPORTED` for anything else. |

Routing note: `<name>` contains slashes, so FastAPI cannot express `/v2/{name}/manifests/{ref}` with a normal path param. Implement **one ASGI catch-all route** with a hand-written matcher. Match the suffix from the right (`/manifests/<ref>`, `/blobs/<digest>`, `/blobs/uploads/[<uuid>]`, `/tags/list`, `/referrers/<digest>`) and validate the remaining prefix as `<name>`.

### 1.2 Endpoints

| ID | Method & path | Success | Notes |
|---|---|---|---|
| end-1 | `GET /v2/` | 200 `{}` | Always send `Docker-Distribution-API-Version: registry/2.0`. With auth enabled, return 401 + `WWW-Authenticate` when no valid token is present. Docker login probes this. |
| end-2 | `GET/HEAD /v2/<name>/blobs/<digest>` | 200 / 307 | Headers `Docker-Content-Digest`, `Content-Length`, `Content-Type: application/octet-stream`, `Accept-Ranges: bytes`. Support `Range` → 206 / 416. 404 `BLOB_UNKNOWN`. The blob **must be linked to `<name>`** (§4.2). |
| end-3 | `GET/HEAD /v2/<name>/manifests/<ref>` | 200 | Return the **exact stored bytes**. `Content-Type` = stored media type. `Docker-Content-Digest` = sha256 of those bytes. 404 `MANIFEST_UNKNOWN`. |
| end-4a | `POST /v2/<name>/blobs/uploads/` | 202 | `Location: /v2/<name>/blobs/uploads/<uuid>`, `Docker-Upload-UUID`, `Range: 0-0`, `OCI-Chunk-Min-Length: <bytes>` (v1.1, advertise e.g. 5 MiB or 0). |
| end-4b | `POST …/uploads/?digest=<d>` (monolithic, body = blob) | 201 | `Location: /v2/<name>/blobs/<digest>`. Optional per spec; podman/skopeo/crane may use it. |
| end-5 | `PATCH /v2/<name>/blobs/uploads/<uuid>` | 202 | Body is appended. `Content-Range: <start>-<end>` is optional for streamed PATCH (docker sends chunked with no Content-Range). If `start != current_offset`, return **416** + `Range` with the current state. Response: `Location`, `Range: 0-<last>`, `Docker-Upload-UUID`. |
| end-6 | `PUT /v2/<name>/blobs/uploads/<uuid>?digest=<d>` | 201 | Optional final body chunk. Verify the digest; on mismatch return 400 `DIGEST_INVALID` and discard the session. Atomic rename into CAS. `Location: /v2/<name>/blobs/<d>`, `Docker-Content-Digest`. |
| end-7 | `PUT /v2/<name>/manifests/<ref>` | 201 | `Content-Type` is required. Max size **4 MiB** (spec: registries SHOULD accept ≥ 4 MiB; we reject larger with 413/`SIZE_INVALID`). Validate (§1.5). Headers `Location`, `Docker-Content-Digest`, and `OCI-Subject: <digest>` when the manifest has a `subject`. If `<ref>` is a digest, it must equal the computed digest. |
| end-8a | `GET /v2/<name>/tags/list` | 200 `{"name":…, "tags":[…]}` | Lexically sorted. |
| end-8b | `GET …/tags/list?n=<int>&last=<tag>` | 200 | Pagination. Return `Link: </v2/<name>/tags/list?n=<n>&last=<t>>; rel="next"` when more tags exist. Cap `n` at e.g. 1000. |
| end-9 | `DELETE /v2/<name>/manifests/<digest>` | 202 | Deletes the manifest and all tags pointing to it. Gated by the `delete` permission and the immutability policy. |
| end-9b | `DELETE /v2/<name>/manifests/<tag>` | 202 | v1.1 allows tag deletion. Optional; we support it (untag). |
| end-10 | `DELETE /v2/<name>/blobs/<digest>` | 202 | Unlinks the blob from the repo only. Physical removal is GC's job. Disabled by default (`405 UNSUPPORTED`) except for admins. |
| end-11 | `POST /v2/<name>/blobs/uploads/?mount=<d>&from=<other>` | 201 / 202 | Cross-repo mount. Requires **pull on `from`** and push on `<name>`. If unauthorized or the blob is missing, *fall back* to a normal 202 upload session (do not error). Automatic mount without `from` (v1.1 optional) is P1: we may mount when the caller can read *any* repo holding the blob. |
| end-12 | `GET /v2/<name>/referrers/<digest>[?artifactType=]` | 200 | Returns an OCI image index (`application/vnd.oci.image.index.v1+json`) of descriptors whose `subject` = `<digest>`, including `artifactType` and `annotations`. With a filter, also send `OCI-Filters-Applied: artifactType`. Return an empty index (not 404) for an unknown subject. |
| end-13 | `GET /v2/<name>/blobs/uploads/<uuid>` | 204 | Upload status: `Range`, `Location`, `Docker-Upload-UUID`. |
| ext | `DELETE /v2/<name>/blobs/uploads/<uuid>` | 204 | Cancel upload. |
| ext | `GET /v2/_catalog?n=&last=` | 200 `{"repositories":[…]}` | Docker extension, not OCI. Filter it to the repos the caller may pull. Disable for anonymous users. |
| int | `GET /v2/token` (or `/auth/token`) | 200 | Token server (§2). Same hostname so clients need one TLS name. |

**Referrers tag-schema fallback:** clients (oras, cosign, notation) that do not see the referrers API push an index tagged `sha256-<hex>`. Because we implement end-12, they should use the API. Still, store `sha256-*` tags as ordinary tags and never treat them as special for GC beyond normal reachability.

### 1.3 Errors

Body: `{"errors":[{"code":"…","message":"…","detail":…}]}` with `Content-Type: application/json`.

| Code | HTTP | When |
|---|---|---|
| `BLOB_UNKNOWN` | 404 | Blob not in repo |
| `BLOB_UPLOAD_INVALID` | 400/416 | Bad chunk or offset |
| `BLOB_UPLOAD_UNKNOWN` | 404 | UUID unknown, expired or owned by someone else |
| `DIGEST_INVALID` | 400 | Mismatch or bad grammar |
| `MANIFEST_BLOB_UNKNOWN` | 400 | Manifest references a missing blob or child |
| `MANIFEST_INVALID` | 400 | Parse or schema failure, media type mismatch |
| `MANIFEST_UNKNOWN` | 404 | |
| `NAME_INVALID` | 400 | Regex failure |
| `NAME_UNKNOWN` | 404 | Repo does not exist (only to callers allowed to know) |
| `SIZE_INVALID` | 400/413 | Content-Length mismatch, over limit |
| `UNAUTHORIZED` | 401 | No or invalid credentials, plus a `WWW-Authenticate` challenge |
| `DENIED` | 403 | Authenticated but forbidden (immutable tag, quota, policy) |
| `UNSUPPORTED` | 405/415 | Disabled op, schema1, unknown algorithm |
| `TOOMANYREQUESTS` | 429 | Rate limit (send `Retry-After`) |

Information-leak rule: for a private repo the caller cannot read, return **401 with challenge** (anonymous) or **404 `NAME_UNKNOWN`** (authenticated without pull). Use the same body and timing whether or not the repo exists.

### 1.4 Media types

Accept and serve:

| Type | Use |
|---|---|
| `application/vnd.docker.distribution.manifest.v2+json` | Docker schema2 image manifest |
| `application/vnd.docker.distribution.manifest.list.v2+json` | Docker manifest list (multi-arch) |
| `application/vnd.oci.image.manifest.v1+json` | OCI manifest (also artifacts via `artifactType` / `config.mediaType`) |
| `application/vnd.oci.image.index.v1+json` | OCI index |
| `application/vnd.docker.container.image.v1+json`, `application/vnd.oci.image.config.v1+json` | Config blobs (parse for UI: arch/os/created/history) |
| `application/vnd.oci.empty.v1+json` | Empty config for artifacts (`{}`, sha256:44136fa3…) |
| layers: `…rootfs.diff.tar.gzip`, `application/vnd.oci.image.layer.v1.tar[+gzip|+zstd]`, nondistributable/foreign layers | Opaque. Never decompress in the request path. |

Reject: schema1 (`application/vnd.docker.distribution.manifest.v1+json` / `+prettyjws`) → 400/415 `MANIFEST_INVALID`/`UNSUPPORTED`. Schema1 is deprecated, and recent Docker Engines no longer pull it by default. For the pull-through cache, do not request schema1 upstream.

Content negotiation: always store and serve the original bytes. **Never re-serialize JSON**, because that changes the digest. Upstream fetches send the full Accept list: OCI index, Docker list, OCI manifest, Docker v2. Clients that do not accept the stored type (very old docker) get the stored type anyway. Do not implement schema conversion.

Foreign layers (Windows base images) carry `urls`. Do not fetch or push them. On manifest PUT, allow missing blobs only when the descriptor has `urls` and a nondistributable media type. Make this a policy flag that defaults to allow, since Windows images otherwise fail.

### 1.5 Manifest PUT validation

1. Size ≤ 4 MiB. Read the body with a hard cap (do not trust `Content-Length`).
2. Parse JSON (stdlib `json` with a nesting-depth guard via `object_pairs_hook` counter, or reject when depth > 64). Check `schemaVersion == 2`.
3. Determine the media type: the `mediaType` field must equal `Content-Type` when present. An OCI manifest without `mediaType` uses the header.
4. Image manifest: `config` and every `layers[]` descriptor must have a valid digest and size ≥ 0, and exist **and be linked in this repo** (or be mountable from a readable repo, P1). Otherwise return `MANIFEST_BLOB_UNKNOWN`. Verify the stored blob size equals `descriptor.size`.
5. Index/list: every `manifests[]` child must already exist in the repo. That matches distribution behavior and the push order docker/buildx use. Validate `platform` fields loosely.
6. `subject` (v1.1): record the referrer edge. Accept it even when the subject does not exist yet (spec allows this). Return `OCI-Subject`.
7. Compute sha256 over the raw bytes. If `<ref>` is a digest, it must match.
8. In one DB transaction: insert the manifest row, insert manifest→blob edges, upsert the tag (check the immutability policy), update repo size counters, audit row.

### 1.6 Digest verification everywhere

- **Upload:** hash incrementally per PATCH (in-memory `hashlib.sha256()` object per session). If the process restarts, re-hash the partial file on the next PATCH or PUT. Compare on PUT.
- **Pull-through:** tee upstream bytes → temp file + hasher. Commit to the CAS only when the digest matches the requested digest, so a bad mirror is rejected and quarantined, as in the Gate 4 `checksum_mismatch` behavior.
- **Serving:** CAS files are trusted after commit. A periodic `fsck` task re-hashes a random sample (P1) and quarantines corrupt files.

---

## 2. Authentication & authorization

### 2.1 Docker token auth flow (what clients actually do)

```
client → GET /v2/                        ← 401 WWW-Authenticate: Bearer realm="https://registry.d.com/v2/token",service="registry.d.com"
client → GET /v2/token?service=registry.d.com&scope=repository:team/app:pull,push[&account=user][&offline_token=true]
         Authorization: Basic base64(user:secret)            (omitted when anonymous)
       ← 200 {"token":"<jwt>","access_token":"<jwt>","expires_in":300,"issued_at":"…"}
client → any /v2/... with Authorization: Bearer <jwt>
       ← 401 with WWW-Authenticate …,scope="repository:team/app:pull,push",error="insufficient_scope" when scope is missing
```

- The challenge on resource endpoints **must include `scope="repository:<name>:<actions>"`** for the needed actions so clients request the right token. `docker push` requests `pull,push`. Mount requests also request `repository:<from>:pull`.
- **Clients treat the token as opaque.** docker, containerd and podman never validate the JWT, so the format is entirely ours. Use a compact JWT (`EdDSA` or `HS256`, key in the existing `secret_store`), `aud=service`, `exp` = 5 min, and claim `access=[{type:"repository",name,actions}]`. Validate in-process, with no network hop.
- **POST variant (OAuth2):** containerd and some podman paths POST `application/x-www-form-urlencoded` `grant_type=password|refresh_token&service=&scope=&client_id=&username=&password=` (or `refresh_token=`) to the realm. They expect `{"access_token","refresh_token"?, "expires_in"}`. Some fall back to GET on 404/405. **Implement both GET and POST on the realm.**
- **Refresh tokens:** with `offline_token=true` / password grant we may return `refresh_token`. Recommendation: do **not** issue separate refresh tokens. The user's long-lived credential *is* the MRK API token (below), so it acts as the refresh token.
- **Basic auth directly on /v2:** some tools (curl, older scripts) send Basic to resource endpoints. Accept Basic on resource endpoints too, as a convenience; the cost is a hash lookup per request, so cache it with a short TTL.
- `GET /v2/` with a valid token and no scope → 200. `docker login` succeeds as soon as `/v2/` returns 200 with the token obtained using `account=<user>`. Give that "login" token the empty scope.

### 2.2 Client credential handling

| Client | Credential source | Notes |
|---|---|---|
| docker CLI/dockerd | `docker login registry.d.com` → `~/.docker/config.json` (base64, or credential helper) | The daemon performs the token dance. For **`registry-mirrors`**, the daemon talks to the mirror with Docker Hub's auth context, not a separate login for the mirror host (verify in PoC). Plan for anonymous or CIDR-allowed pulls on the Hub-mirror hostname. |
| containerd / nerdctl / k8s | `nerdctl login`; CRI `config.toml` `registry.configs."host".auth` or hosts.toml + kubelet image-pull secrets | Uses the POST OAuth grant first. Kubernetes `imagePullSecrets` give per-namespace credentials. |
| podman / buildah / skopeo / CRI-O | `podman login` → `${XDG_RUNTIME_DIR}/containers/auth.json` | Mirrors in `registries.conf`. The mirror host gets its own auth.json entry. |
| crane / oras / regctl / cosign | docker config.json | |

### 2.3 Mapping to MRK identity (reuse `auth.py`)

- **Password field = MRK API token** (`ApiToken` table, hashed). Username = MRK username, which the token's user must match. Interactive user passwords on the registry are **off by default**: docker stores the secret in near-plaintext, and password login bypasses future MFA. Make it an Owner toggle.
- New permission strings, following the `<module>:<resource>:<action>` convention from doc 20:
  - `oci:repo:pull`, `oci:repo:push`, `oci:repo:delete`, `oci:repo:admin` (tags immutability, policies), `oci:cache:write` (purge proxy cache), `oci:gc:operate`.
  - Role defaults: owner `*`. admin gets all `oci:*`. operator gets pull, cache:write, gc:operate. developer gets pull + push. viewer gets pull.
- **Namespace grants (P1):** table `registry_oci_grants(subject_type user|role, subject_id, namespace_glob, actions[], created_by)`. The effective actions in a token are the intersection of (requested scope) ∩ (token scopes) ∩ (role permissions) ∩ (namespace grants if any exist for that namespace, else role defaults). That is the same intersection rule `AuthStore` already applies to token scopes.
- **Personal namespace convention (optional):** `u/<username>/…` is pushable by that user alone.
- Lockout/rate-limit on the token endpoint, shared with the panel login throttling. Audit `oci.token.issued` (sampled) and **every push, delete and policy change**.

### 2.4 Anonymous pull policy

Repository `visibility` ∈ `private` (default) | `internal` (any authenticated principal) | `public` (anonymous pull).

- Proxy namespaces (`docker.io/…`, `ghcr.io/…`) default to **internal**. Anonymous pull-through on a public hostname turns the appliance into an open egress proxy and lets anyone burn our Docker Hub quota.
- Hub-mirror hostname (`hub.<domain>`) for dockerd `registry-mirrors`: allow anonymous pull **only from configured CIDRs** (office/VPN/k8s node ranges), enforced on the client IP that the gateway forwards from trusted proxies (doc 20 rule).
- Anonymous principal: the token endpoint issues anonymous tokens with pull-only scope, filtered by visibility. A request with no `Authorization` gets a 401 challenge first. The client then fetches an anonymous token, so public pulls still go through the token flow.

---

## 3. Pull-through cache with multi-upstream failover

### 3.1 How clients are pointed at a mirror

| Client | Mechanism | Scope |
|---|---|---|
| **dockerd** | `/etc/docker/daemon.json` → `"registry-mirrors": ["https://hub.d.com"]` | **Docker Hub only.** The daemon sends `GET /v2/library/nginx/manifests/latest` (with `library/` added) to the mirror, with no host prefix. If the mirror fails, dockerd silently falls back to `registry-1.docker.io`, which in Iran usually fails with 403. Pulls only; never used for push. For ghcr.io/quay.io, docker users must **rewrite the image reference**: `registry.d.com/ghcr.io/owner/img:tag`. |
| **containerd** (≥1.5, k8s, nerdctl) | `/etc/containerd/certs.d/<upstream-host>/hosts.toml` with `[host."https://registry.d.com/v2/ghcr.io"]` `capabilities=["pull","resolve"]` `override_path = true`. Simpler alternative: `[host."https://registry.d.com"]`, which makes containerd append **`?ns=ghcr.io`** to every request | Any registry. **Support both:** the `ns` query parameter and path-prefix mapping. |
| **podman / CRI-O / buildah / skopeo** | `/etc/containers/registries.conf`: `[[registry]] prefix="ghcr.io" location="ghcr.io"` + `[[registry.mirror]] location="registry.d.com/ghcr.io"` | Any registry. Uses a path prefix. |
| **Docker Desktop / BuildKit** | buildkitd.toml `[registry."docker.io"] mirrors=["hub.d.com"]` | |

### 3.2 Namespace mapping (our routing contract)

On `registry.<domain>`:

- **First path component contains a dot (or is a configured alias)** → proxy namespace. Example: `/v2/ghcr.io/stefanprodan/podinfo/manifests/6.5.0` → upstream group `ghcr.io`, remote name `stefanprodan/podinfo`. This is the same heuristic Docker reference parsing uses for "is this a registry host".
  - Only **configured** upstream groups are valid. `/v2/evil.com/x/manifests/y` → `NAME_UNKNOWN`. **Never derive an upstream host from the request**, or we become an SSRF/open proxy.
  - Aliases: `docker.io`, `hub` → Docker Hub. For Docker Hub, single-component names get `library/` added.
- `?ns=<host>` (containerd) → same as the prefix, matched against the configured groups. Ignore `ns` on private paths.
- Otherwise → **private** repo (push/pull locally). Private names must not start with a dotted component, so a private push can never shadow an upstream namespace.

On `hub.<domain>` (optional, pull-only): every name maps to the Docker Hub group (`nginx` → `library/nginx`). Pushes return 405 `UNSUPPORTED`.

Optional "single host" mode: `registry.<domain>` may also accept unprefixed Hub names when no private repo by that name exists. This is **off by default** because of the ambiguity and dependency-confusion risk.

### 3.3 Upstream groups & failover (reuse the Gate 4 model)

An upstream group = an ordered list of endpoints that all serve the same logical registry. Example `docker.io`:

| Order | Endpoint | Path mapping | Auth (observed 2026-11-08 from the dev workstation) |
|---|---|---|---|
| 1 | `https://registry-1.docker.io` (token realm `auth.docker.io`, service `registry.docker.io`) | `library/` rule | Bearer, anonymous or Docker ID PAT. Geo-blocked (403) from Iranian IPs. |
| 2 | `https://docker.arvancloud.ir` (ArvanCloud) | same as Hub | Challenge realm `https://docker.arvancloud.ir/v2/token`. **Anonymous HEAD manifest returned 200.** |
| 3 | `https://focker.ir` (Sotoon CDN) | same | realm `/v2/token`. Anonymous HEAD 200. |
| 4 | `https://registry.docker.ir` (Nexus 3.59 OSS) | same | realm `/v2/token`. Anonymous HEAD 200. |
| 5 | `https://docker.iranserver.com` (Nexus 3.98) | same | Anonymous HEAD 200. |
| 6 | `https://docker-mirror.liara.ir` (Harbor) | same | Bearer realm `/service/token`, service `harbor-registry`. Anonymous HEAD → 401, so it **needs the token dance**. |
| 7 | `https://hub.hamdocker.ir` (Hamravesh, Artifactory) | same | realm `/artifactory/api/docker/hub/v2/token`. 401 without a token. |
| 8 | `https://docker.mobinhost.com`, `https://mirror-docker.runflare.com`, `https://docker.kernel.ir` | same | `/v2/` 200 without auth. Anonymous HEAD alpine 200. |

**Verification notes (honest):**
- The resolution and `/v2/` probes above were made from this workstation on 2026-11-08, and its network location is unknown. Several Iranian mirrors restrict access to Iranian IPs or change frequently. Treat the list as **seed defaults that the admin can edit**, re-validated by the existing upstream probe (`upstream_probe.py`).
- `repo.docker.ir:5000` (an old gist) answered 404 on `/v2/`, so it is not a working registry. Do not seed it.
- Non-Hub mirrors: **registry.k8s.io** → `https://mirror-k8s.runflare.com` (verified: `pause:3.10` HEAD 200). Liara documents `liara.ir/mirrors/{github,quay,k8s,microsoft}` and Kargadan has `mirror.kargadan.ir/mcr`, but I did not verify the exact registry hostnames for ghcr/quay mirrors. For **ghcr.io and quay.io, assume no reliable Iranian mirror**. The appliance's own cache, plus an optional outbound HTTP/SOCKS proxy per upstream (a P1 admin setting; it never comes from the environment), is the answer.
- Upstream challenges observed: `quay.io` realm `https://quay.io/v2/auth` service `quay.io`. `registry.k8s.io` realm `https://registry.k8s.io/token`. `ghcr.io` issues anonymous tokens at `https://ghcr.io/token?scope=repository:<n>:pull&service=ghcr.io`.

**Failover rules (extends docs/02 §7):**

| Condition | Blob / manifest-by-digest | Tag resolution |
|---|---|---|
| DNS / connect / read timeout / reset / 5xx / 408/425/429 | next endpoint, circuit++ | next endpoint, circuit++ |
| **403 from Docker Hub with a geo/sanctions body** or 451 | next (per-endpoint flag `geo_block_403_is_failure=true`, on by default for registry-1.docker.io) | next |
| 401 after a successful token negotiation | next (mirror may need creds) | next |
| 404 `MANIFEST_UNKNOWN` / `BLOB_UNKNOWN` | try the next endpoint (content-addressed, so this is safe) | **primary 404 is authoritative** by default (the tag really does not exist). Configurable `tag_404_failover` for when the primary is a stale mirror. |
| Digest mismatch | quarantine the endpoint for this digest, next, alert | n/a |
| Rate limited (429 or `ratelimit-remaining: 0`) | next; mark the endpoint "throttled until window reset" | next |

Circuit breaker state, threshold, cooldown, manual block and offline flag: reuse `CircuitState` and the upstream config store (`upstreams.json` / `upstream_store.py`) with a new `ecosystem: "oci"`. Status UI shows the same fields, plus **Docker Hub quota remaining** (parsed from the `ratelimit-remaining` header, `100;w=21600`).

**Tag-trust policy** (the only real risk of using third-party mirrors): a mirror could return a malicious digest for `nginx:latest`.
- Record `source_endpoint` on every tag→digest resolution and show a "resolved via fallback mirror" badge in the UI.
- Group policy `tag_resolution: any | primary_only | quorum(2)`. `quorum` asks two endpoints with **HEAD** (cheap, and on Docker Hub HEAD does not count as a pull) and accepts the digest only on agreement. Default `any`, because a solo DevOps user in Iran needs it to just work. Recommend `primary_only` or digest pinning for production deploys.
- Pulls by digest (`image@sha256:…`) are always safe through any mirror.
- Optional P2: cosign signature verification of upstream images before caching tags.

### 3.4 Upstream token negotiation

1. Request the target. On 401, parse `WWW-Authenticate` (RFC 7235: handle quoted strings, commas inside quotes, `Basic` vs `Bearer`).
2. **Validate the realm URL**: it must be HTTPS, and the host must be in the endpoint's `auth_hosts` allowlist (e.g. `auth.docker.io` for `registry-1.docker.io`; same host for most mirrors). This is an SSRF control, because the realm comes from the network.
3. `GET realm?service=<service>&scope=repository:<remote-name>:pull`, with Basic auth if a credential is configured (Docker Hub PAT, ghcr PAT). Credentials come from `secret_store`, never from URLs (as in the Gate 4 rule).
4. Cache `(endpoint, scope) → token` until `expires_in - 30s` (default 60 s if absent). Coalesce concurrent fetches (single-flight).
5. Retry the original request once with `Bearer`.
6. **Blob redirects:** upstreams return 307 to CDNs: Docker Hub → `production.cloudflare.docker.com`; ghcr → `pkg-containers.githubusercontent.com`; quay → `cdn*.quay.io` / S3; registry.k8s.io → regional `*.pkg.dev` / S3 buckets. Follow redirects manually (≤ 3), re-validate every hop against the endpoint's `blob_redirect_hosts` (exact hosts or anchored suffix rules, e.g. `.pkg.dev`), and **drop `Authorization` on cross-host hops**. That reuses the existing `_validate_destination` pattern from `pypi_router.py`.

### 3.5 What gets cached and for how long

| Object | Key | Freshness |
|---|---|---|
| Blob | digest | Immutable forever (until eviction) |
| Manifest by digest | digest | Immutable |
| Tag → digest | (group, remote name, tag) | TTL, default **10 min** (configurable per group or regex, e.g. `latest` 5 min, `^v?\d+\.\d+\.\d+$` 24 h). After TTL: revalidate with **HEAD** upstream (free on Docker Hub). If the digest is unchanged, refresh the timestamp; if changed, GET the new manifest. |
| Index children | digest | Fetched lazily when a client asks for a platform manifest by digest. Optional prefetch of `linux/amd64` + `linux/arm64` (P1). |
| Referrers / sig tags | subject digest | TTL 1 h (P1) |
| Negative (404) | (group, name, ref) | 60 s, to protect the quota against typos and CI retries |

**Stale-if-error:** if revalidation fails on every endpoint (or offline mode is on), serve the last known digest with a `Warning`-style log/metric. Never fail a pull that we can answer from cache.

**Offline mode:** a per-group flag file, as in Gate 4, plus a global switch. Cached objects are served; misses get `MANIFEST_UNKNOWN`/`BLOB_UNKNOWN` (or 503 `UNAVAILABLE` text) and never leak to the internet.

**Single-flight for cold blobs:** the first request streams from upstream into `tmp/<digest>.<rand>` while hashing and tees bytes to the client. Concurrent requests for the same digest wait on an asyncio Event, or (P1) tail-read the growing temp file. The temp file is promoted only after the digest verifies. If verification fails, the first client has already received bad bytes, but docker/containerd verify layer digests themselves and will error. Nothing poisoned enters the CAS. For manifests (small), buffer fully and verify **before** responding.

### 3.6 Docker Hub rate limits (verify periodically)

- Docker's docs pages fetched on 2026-11-08 state: **unauthenticated 100 pulls / 6 h per IPv4 or IPv6 /64**, **Personal (authenticated) 200 / 6 h**, Pro/Team/Business unlimited with fair use.
- A stricter policy (10/h unauthenticated, from 2025-04-01) was announced earlier and widely reported. Secondary sources conflict, so read the limits from the response headers rather than hard-coding them.
- A "pull" = a manifest **GET**. **HEAD is not counted.** Blob downloads are not counted separately. Docker's page says multi-arch pulls count per architecture.
- Headers: `ratelimit-limit`, `ratelimit-remaining` (`N;w=21600`), `docker-ratelimit-source`.
- Design consequences:
  - revalidate tags with HEAD;
  - add a negative cache;
  - support an optional Docker Hub PAT per group;
  - show quota in the UI;
  - when remaining < threshold, prefer mirrors for tag GETs.

---

## 4. Storage

### 4.1 Disk layout

```
/data/modules/registry/docker/
├─ blobs/sha256/<aa>/<full-hex>        # CAS, one file per blob (manifests too), mode 0640, never modified
├─ uploads/<uuid>/data                 # in-progress upload (append-only)
├─ uploads/<uuid>/meta.json            # optional mirror of DB row for crash recovery
├─ tmp/                                # pull-through spools; same filesystem as blobs/ (atomic rename)
├─ quarantine/<digest>.<ts>            # corrupt / mismatched
├─ trash/<gc-run-id>/                  # sweep stage before unlink (allows abort)
└─ export/                             # optional OCI-layout exports for scanners
```

- Paths are built **only** from a validated digest (`^[a-f0-9]{64}$`) and a server-generated UUID4. Repository names never touch the filesystem, so path traversal cannot happen.
- Atomic write: write to `tmp/` (same FS), `flush`+`fsync(file)`, `os.link` or `os.rename` → `blobs/…`, then `fsync(dir)`. If the target already exists (dedup race), just delete the temp file, because identical digest means identical content.
- Manifests are stored in the CAS too, and mirrored in the DB (`content` column, ≤ 4 MiB) so the hot GET path is one indexed DB read with no FS hit. Keep both, or store only in the CAS plus an LRU; decide in the PoC.
- Dedup is inherent: the same layer across repos, private and proxy, is stored once.

### 4.2 Metadata (PGlite/PostgreSQL, `registry_oci_*` namespace)

| Table | Key columns |
|---|---|
| `registry_oci_repositories` | id, name (unique), kind `private|proxy`, upstream_group, visibility, immutable_tag_rules JSON, quota_bytes, created_at, last_push_at, last_pull_at |
| `registry_oci_blobs` | digest PK, size, created_at, last_accessed_at, state `ready|quarantined` |
| `registry_oci_repo_blobs` | (repo_id, digest) PK, linked_at. **Authorization link**: a blob GET in repo X succeeds only when linked to X, which prevents digest-guessing across private repos. |
| `registry_oci_manifests` | (repo_id, digest) PK, media_type, artifact_type, size, subject_digest (indexed), config_digest, total_size (computed), platforms JSON, content BYTEA, created_at, pushed_by, last_pulled_at |
| `registry_oci_manifest_refs` | (repo_id, parent_digest, child_digest, kind `blob|manifest`) for GC + "image size" |
| `registry_oci_tags` | (repo_id, tag) PK, digest, updated_at, updated_by, source_endpoint, upstream_checked_at, immutable bool |
| `registry_oci_uploads` | uuid PK, repo_id, principal_id, offset, started_at, last_activity_at, expected_digest? |
| `registry_oci_gc_runs`, `registry_oci_policies`, `registry_oci_scans` (P1) | |

**PGlite caveat:** the appliance runs `pglite-server --max-connections=1`. Registry traffic is HEAD-heavy: one `docker pull` of a 10-layer image ≈ 1 manifest + index + 10 blob HEAD/GET plus the token request.
- Hot-path reads (tag→digest, repo_blob link, manifest bytes) go through an **in-process LRU with write-through invalidation**. A single `oci-engine` process owns all writes, so there are no coherency issues.
- Writes batch `last_accessed_at` updates (flush every 60 s).
- Load-test this early. If PGlite becomes the bottleneck, `MRK_DATABASE_URL` (external Postgres) is the documented escape hatch.
- A fallback would be a per-module SQLite/WAL file under `/data/modules/registry/docker/meta.db`. That departs from the "one DB" principle, so it would need an ADR.

### 4.3 Upload sessions

- UUID4. Bound to principal + repo. Max concurrent sessions per principal (e.g. 32). Idle expiry 1 h (configurable). Absolute max 24 h. A janitor task deletes expired sessions.
- Byte limits: `max_blob_bytes` (default 20 GiB) checked progressively. Disk reserve: refuse with 507/`DENIED` when free space < reserve (reuse `SPOOL_RESERVE_BYTES` logic).
- PATCH must be serialized per session: an asyncio lock per UUID. A concurrent PATCH to the same session gets 416.

### 4.4 Garbage collection (online, safe with concurrent pushes)

Mark-and-sweep with a **grace window + touch** protocol, no global stop-the-world:

1. `gc_start = now`. Take a DB advisory/row lock `gc_running` (only one GC at a time; pushes continue).
2. **Mark roots**: all tagged manifests; untagged manifests younger than `untagged_retention`; manifests referenced as children by kept indexes; **referrers whose subject is kept** (signatures/SBOMs survive with their image); manifests in active retention holds.
3. **Mark closure**: walk `manifest_refs` → set of live blob digests, plus all blobs referenced by active upload sessions.
4. **Sweep candidates**: blobs not marked **and** `created_at < gc_start - grace` **and** `last_accessed_at < gc_start - grace` (grace default 24 h; a push touches a blob on HEAD/mount/upload). This closes the classic race (client HEADs an existing blob → skips upload → GC deletes it → manifest PUT), because the HEAD touched the blob inside the grace window.
5. Delete DB rows first (`repo_blobs` links for unreferenced blobs in each repo, then the `blobs` row) in small transactions. Each transaction re-checks that no new manifest_ref appeared (`NOT EXISTS`). Then move files to `trash/<run>` and unlink.
6. Manifest PUT always verifies blob existence inside its transaction (`SELECT … FOR SHARE` on blobs in Postgres; in PGlite the single connection already serializes). In the worst case a push fails with `MANIFEST_BLOB_UNKNOWN` and the client retries. **Corruption is impossible.**
7. Report: bytes reclaimed, counts, duration. Audit entry. `dry_run` mode shows the candidates.

Proxy cache eviction is separate from GC: an LRU by `last_pulled_at` per upstream group with `max_bytes` and `max_age_unpulled` (e.g. 30 days). Evicting removes tags, manifests and links. The next GC reclaims the blobs. Never evict private content automatically.

### 4.5 Quotas, retention, growth

- **Size accounting:** the "image size" shown is the sum of config + layer sizes (compressed). The repo's **unique** size counts blobs not shared with any other repo. The repo's **attributed** size counts all linked blobs. Quotas use *attributed* size per repo or namespace, because it is predictable for users. Global disk is governed by free-space watermarks:
  - 80% warning;
  - 90% blocks pushes and proxy fills, while serving continues;
  - 95% triggers emergency proxy eviction.
- **Retention policies** (P1), evaluated by the existing `tasks.py` worker with a preview/dry-run, typed confirmation for destructive changes, and audit:
  - keep the last N tags matching a regex (sorted by push time or semver);
  - delete tags older than D days unless pulled in the last P days;
  - protect a regex (`^latest$|^v\d+`);
  - delete untagged manifests after X days;
  - keep referrers attached to kept subjects.
- **Growth expectations:** a typical CI that pushes 1 image per commit with 300 MB of mostly-shared layers adds ~5–50 MB/commit of new layers. The proxy cache for a k8s cluster plus base images is typically 20–100 GB. Show a 30-day growth chart and a projected days-to-full metric.
- Backups: the module contributes to the central backup manifest. DB rows go in the logical snapshot. Blob CAS is **opt-in** (it can be huge), with an "include proxy cache" checkbox defaulting to false, because proxy content is re-downloadable.

---

## 5. Streaming large blobs in Python ASGI

### 5.1 Process model

- A separate supervisord program `oci-engine` (uvicorn `--loop uvloop --http httptools`, 1 worker at first, 2–4 later with SO_REUSEPORT). The panel and control plane are never starved by registry traffic, matching the doc 20 failure-isolation requirement.
- The worker count is >1 only if the upload-session state and the LRU move to shared storage. Keep 1 worker for MVP and measure.

### 5.2 Downloads (blob GET)

- Serve from disk with a custom streaming response:
  - `os.open`, then `os.pread` in a thread (`anyio.to_thread`) in **1–4 MiB chunks**;
  - honor `Range: bytes=a-b` (single range only; multi-range → ignore and return 200, or 416);
  - set `Content-Length`, `Content-Range`, `ETag: "<digest>"`, `Cache-Control: max-age=31536000, immutable`.
- Starlette's `FileResponse` supports Range in current versions and could be used. A small custom class gives control over chunk size and accounting.
- **Zero-copy sendfile:** uvicorn does not implement the ASGI `http.response.zerocopysend` extension, so Python copies bytes through userspace. To get sendfile, use the **gateway offload seam**:
  - `oci-engine` authorizes the request, then returns `X-Accel-Redirect: /_internal/oci-blobs/sha256/aa/<hex>` (nginx), or the equivalent via Caddy's `intercept` handler (decide in the Gateway ADR);
  - the gateway serves the file from the same `/data` mount with sendfile + Range;
  - only the gateway can reach the internal location.
  - This keeps all logic in our code and makes the data plane C-speed. Ship it behind a flag in P1.
- `HEAD` must not open the file. Answer from DB/LRU (size) + `os.stat` existence check.

### 5.3 Uploads (PATCH/PUT)

- `async for chunk in request.stream()`: hasher.update(chunk), then write.
  - `hashlib.sha256().update` releases the GIL for large buffers, at ~1.5–2 GB/s per core with SHA-NI.
  - Coalesce small ASGI chunks (httptools yields ~64 KiB) into 1–4 MiB buffers before the thread-offloaded `os.write`, to cut thread hops.
- No `await request.body()` anywhere on blob paths. Enforce the size cap progressively.
- Gateway: request buffering **off**, unlimited or per-route body size (e.g. 20 GiB), read/idle timeouts ≥ 15 min for uploads, HTTP/1.1 chunked passthrough. Doc 20 already requires "streaming package artifact without forced buffer".

### 5.4 Pull-through streaming

- `httpx.AsyncClient` (HTTP/2 off for blobs; HTTP/1.1 with keepalive pool per endpoint), `stream("GET")`, `aiter_raw()` (no decoding; layers are already compressed and upstreams don't use Content-Encoding).
- Tee into temp file + hasher + client send queue (bounded `asyncio.Queue`, e.g. 8 × 1 MiB, for backpressure).
  - If the client disconnects, keep filling the cache in the background (configurable), so the next attempt is a cache hit. That matters on flaky Iranian links.
- **Upstream resume:** if the upstream connection drops mid-blob, retry with `Range: bytes=<received>-` against the same or the next endpoint. This is safe because the content is addressed by digest. It is a big reliability win over plain proxies on unstable international links.

### 5.5 Expected throughput (estimates, to validate in the PoC benchmark)

| Path | Python (uvicorn+uvloop, 1 worker, page-cache warm) | With gateway sendfile |
|---|---|---|
| Blob GET, few large streams | ~300–800 MB/s aggregate (CPU-bound on memcpy and the event loop; TLS at the gateway) | Disk/NIC-bound (multi-GB/s) |
| Blob PUT with sha256 | ~200–500 MB/s | n/a (still Python) |
| Manifest/HEAD small requests | ~2–5k req/s (DB/LRU-bound) | |
| Pull-through fill | Upstream-bound (typically 1–50 MB/s from Iran) | |

### 5.6 Honest assessment: Python vs a Go/Rust component

- For the stated users (a solo DevOps person, CI runners, a small k8s cluster on a 1 Gbps LAN = ~120 MB/s), **Python is adequate.** The limits that matter are the international link, disk, and Docker Hub quota, not the language.
- Python's weak spots are high-concurrency, high-bandwidth fan-out (many nodes pulling a fresh multi-GB image at the same time) and memory overhead per connection. The sendfile offload removes the largest gap without a new language.
- A Go component would be justified only if a measured target exceeds what offload achieves (e.g. >2 Gbps sustained uploads or >200 concurrent large pulls). Even then, write it as **our own** minimal blob data-plane (≈1–2k LOC Go, net/http + `io.Copy` uses sendfile/splice), not as distribution/registry. It also means a second toolchain in CI, SBOM, and CVE watch, so it is not recommended for MVP.

---

## 6. Admin features (parity with the npm/PyPI modules)

| Feature | Phase | Notes |
|---|---|---|
| Repository list (private / proxy groups) with size (attributed/unique), tag count, last push/pull, visibility | MVP | Server-side pagination |
| Tag table: digest (short), media type, platforms (from the index), compressed size, created (from config), pushed by, source endpoint, immutable badge | MVP | |
| Manifest viewer (raw JSON, pretty), layer list with sizes and config `history` (Dockerfile-like steps) | MVP | Parse config blobs ≤ 1 MiB only |
| Copy-to-clipboard commands: `docker pull`, `crane digest`, `podman pull`; a client-setup wizard that generates `daemon.json`, `hosts.toml` and `registries.conf` snippets for the configured hostnames | MVP | Very high value for the solo user |
| Upstream groups: endpoints, order, circuit state, last success, error code, **Docker Hub quota remaining**, offline toggle, probe now | MVP | Reuse the Gate 4 panels |
| Delete tag / manifest (typed confirmation, audit) | MVP | |
| Proxy cache purge (by repo/tag/group) | MVP | Queued task + tombstone (docs/02 §8) |
| GC run with dry-run preview and history | MVP | |
| Disk usage + growth chart, watermark alerts | MVP | |
| Upload sessions in progress (cancel) | P1 | |
| Immutable tag rules (regex per repo/namespace). An overwrite attempt gets 403 `DENIED` "tag is immutable" | P1 | |
| Retention/cleanup policies with preview | P1 | |
| Referrers tree: signatures (cosign/notation), SBOM (CycloneDX/SPDX), attestations (in-toto), each with artifactType and annotations | P1 | |
| Namespace grants and visibility UI | P1 | |
| **Vulnerability scanning (optional)**: Trivy binary bundled or downloaded by the admin (Apache-2.0) and run as a sandboxed subprocess (`trivy image --image-src remote` against our own registry with a short-lived internal pull token, or `--input` on an exported OCI layout). Limits: timeout, `ulimit`, memory, a dedicated temp dir. Results are stored in `registry_oci_scans` **and** pushed as a referrer artifact (`application/vnd.cyclonedx+json` / `application/sarif+json`), so they are portable. The Trivy DB is itself an OCI artifact (`ghcr.io/aquasecurity/trivy-db`, `mirror.gcr.io/aquasec/trivy-db`), so it can be fetched **through our own pull-through cache**, which helps in Iran. Grype is an alternative. Scan on push / on schedule / on demand. A "block pull if critical" policy is P2. | P1/P2 | Not native vuln logic, by design |
| Signature verification policy (cosign public key / keyless identity per namespace). Show verified/unverified. Optionally require it for proxy tag acceptance. | P2 | Use the `sigstore-python` library, or shell out to the cosign binary |
| Pull/push metrics per repo (Prometheus): `mrk_oci_requests_total{op,status}`, bytes in/out, cache hit ratio, upstream latency, quota remaining, GC reclaimed | MVP (basic) / P1 | |
| Replication / scheduled sync of selected images (prefetch for air-gap) | P2 | Like the "bandersnatch-style" prefetch idea |
| Helm OCI charts and generic OCI artifacts browsing (oras) | P1 (works automatically; UI labels by artifactType) | |

---

## 7. Conformance & client testing

### 7.1 OCI distribution-spec conformance suite

- Source: `github.com/opencontainers/distribution-spec/conformance`. Build with `go test -c` (produces `conformance.test`), or use the published GitHub Action / container image, pinned by commit.
- Env:
  - `OCI_ROOT_URL=https://registry.test`, `OCI_NAMESPACE=conformance/a`, `OCI_CROSSMOUNT_NAMESPACE=conformance/b`, `OCI_USERNAME` / `OCI_PASSWORD` (an API token);
  - `OCI_TEST_PULL=1`, `OCI_TEST_PUSH=1`, `OCI_TEST_CONTENT_DISCOVERY=1`, `OCI_TEST_CONTENT_MANAGEMENT=1`;
  - optional `OCI_AUTOMATIC_CROSSMOUNT`, `OCI_DELETE_MANIFEST_BEFORE_BLOBS`, `OCI_HIDE_SKIPPED_WORKFLOWS=1`, `OCI_DEBUG=1`, `OCI_REPORT_DIR`.
- Output: `junit.xml` + `report.html`. CI gate: 100% pass on all four workflows. Track the suite version in `docs/`.
- Run it against: (a) private namespace with token auth, (b) anonymous public namespace, (c) a proxy namespace (pull workflow only, against a local mock upstream).

### 7.2 Client matrix (CI job inside an isolated network, using the existing "isolated hostnames" CI pattern)

| Tool | Scenarios |
|---|---|
| docker (current + previous major) / buildx | login with API token, push/pull single + multi-arch (`buildx --platform linux/amd64,linux/arm64 --push`), `registry-mirrors` against `hub.test`, pull by digest, logout, `docker manifest inspect` |
| containerd / nerdctl / ctr | hosts.toml **both** with `override_path` prefix and the `?ns=` mode; push/pull; k3s/kind node pulling via mirror |
| podman / buildah | registries.conf mirror with a path prefix; push with `--format oci` and `v2s2`; `podman login` |
| skopeo | `copy docker://… docker://registry.test/…` (exercises monolithic uploads and mount), `inspect --raw`, `sync` |
| crane (go-containerregistry) | `crane copy`, `crane ls` (pagination), `crane validate --remote`, `crane delete`, `crane manifest`, chunked upload behavior |
| oras | push artifact with `artifactType`, `oras attach` (referrers), `oras discover`, blob fetch with Range |
| cosign / notation | sign, verify, `cosign tree`; both tag-schema and referrers modes |
| helm | `helm push oci://registry.test/charts`, `helm pull` |
| regctl (regclient) | `regctl image check-base`, referrers, tag ls; good extra spec coverage |
| trivy | `trivy image` against the registry (scanner integration) |

### 7.3 Our own tests (pytest, matching the Gate 4 style)

- Protocol unit tests per endpoint and error code; name/tag/digest grammar fuzzing (Hypothesis).
- Upload: out-of-order PATCH → 416; resume after process restart (re-hash); digest mismatch discards; concurrent PATCH; size cap; disk-full simulation.
- GC: race test (HEAD blob → GC → PUT manifest), referrer retention, dry-run equality with the real run, crash mid-sweep.
- Pull-through chaos (reuse the Gate 4 harness): DNS failure, connect/read timeout, reset mid-blob → Range resume on the next endpoint, 403 geo-block, 429 + ratelimit headers, digest-mismatching mirror → quarantine, offline mode hit/miss, stale-if-error tag serving, token realm pointing to a non-allowlisted host → refused, redirect to a private IP → refused.
- Load: k6 or locust, 50 parallel pulls of a 2 GB image (cold + warm), 10 parallel pushes; record MB/s, p99, RSS, PGlite latency.

---

## 8. Security

| Threat | Control |
|---|---|
| **SSRF / open proxy via namespace** | Upstream groups exist only from the admin config. The request path selects a *group alias*, never a host. Every outbound URL (base, token realm, redirect hop) passes the existing `_validate_destination` (HTTPS only, host allowlist, no userinfo, resolve-and-reject private/loopback/link-local/reserved/multicast unless `allow_private_networks`). No proxy env vars (`trust_env=False`). |
| DNS rebinding between check and connect | Use a custom httpx transport that connects to the validated IP with the original SNI/Host (pin the resolution), or re-validate the peer address after connect via `get_extra_info("server_addr")`. This is an improvement over the current router, which resolves then connects separately. |
| Credential leakage to mirrors/CDNs | Upstream credentials apply only to their configured host + realm host. Strip `Authorization` on cross-host redirects. Client credentials are **never** forwarded upstream (we terminate auth). |
| Malicious mirror content | Digest verification before commit (blobs and digest-addressed manifests). Tag-trust policy (§3.3). Quarantine + alert on mismatch. |
| Manifest bombs | 4 MiB cap, JSON depth ≤ 64, max descriptors per manifest (e.g. 10k layers / 2k index entries), reject duplicate keys (`object_pairs_hook`). Annotation size caps. |
| "Zip-bomb" layers | The registry never decompresses layers in the request path. Features that do (layer file browser, scanner) run in a sandboxed subprocess with limits on decompressed bytes, entry count, path length, symlink handling, CPU time and memory. Treat tar paths as hostile (no extraction to disk outside a private temp dir; no following symlinks). |
| Huge or slowloris uploads | Progressive size cap, per-principal session limits, idle timeouts, disk reserve, gateway rate limits per route, max concurrent uploads. |
| Path traversal in names | Strict regex full-match + length. Names never map to paths (CAS by digest only; uploads by server UUID). Reject `%2F` and other encoded slashes before routing. Normalize nothing silently. |
| Cross-repo blob access by digest guessing | `repo_blobs` link check on every blob GET/HEAD. Mount requires pull on the source. Auto-mount only from repos the caller can read. |
| Repo enumeration | Uniform 401/404 behavior (§1.3). `_catalog` filtered and disabled for anonymous users. |
| Upload session hijack | 128-bit random UUID bound to principal + repo. Mismatch → `BLOB_UPLOAD_UNKNOWN`. |
| Token forgery/replay | Signed JWT with 5 min exp, `aud`=service, `jti` (optional replay cache), key rotation via `kid`. Tokens scoped to the intersection of permissions. Token endpoint brute-force throttling + audit. |
| Tag overwrite / supply-chain | Immutable tag rules, push audit with actor, optional signature-required policy (P2), digest pinning guidance. |
| **TLS** | Docker requires HTTPS for any registry except `localhost`/`127.0.0.0/8` or hosts listed in `insecure-registries` (that also applies to `registry-mirrors` URLs). Production: TLS terminates at the Edge Gateway (ACME or external reverse proxy, per the pending cert-policy ADR). The engine listens on loopback only (`127.0.0.1:5000`, never published), as for devpi/Verdaccio. HSTS is fine on the registry host. Do not offer HTTP at all except in the dev profile. |
| Hostname routing | Add route kinds `oci-registry` (`registry.<domain>`) and `oci-hub-mirror` (`hub.<domain>`) to the doc 20 route registry. The gateway forwards `X-Forwarded-Host/Proto` only from trusted proxies. **Absolute URLs we emit** (`WWW-Authenticate realm`, `Location` if absolute) come from the *route configuration*, never from the request Host, which prevents realm spoofing and cache poisoning. Prefer relative `Location` headers (the spec allows them, and clients resolve them). |
| Gateway behavior for registry routes | No request/response buffering, large body limit, long timeouts, preserve `Range`/`Content-Range`/`Docker-*`/`OCI-*` headers, no compression of `application/octet-stream`, allow `PATCH`/`DELETE`, no CORS (CLI clients), and a separate rate limit for `/v2/token`. |
| Resource exhaustion of the appliance | Registry in a separate process, with its own memory limit if a cgroup is available (doc 20 ADR #6). Disk watermarks stop growth before `/data` fills and breaks npm/PyPI/DB. Ideally put `/data/modules/registry` on its own volume or quota, and document this. |
| Secrets | Upstream PATs in `secret_store` (encrypted). Never logged. Redact `Authorization` and `token=` in access logs. |

---

## 9. Phasing & effort

Assumptions: one experienced Python engineer familiar with this codebase. Estimates include tests and docs and exclude the Gateway ADR work, which is shared with other modules.

### MVP (≈ 7–9 engineer-weeks)

1. Module skeleton: manifest, `oci-engine` supervisord program, loopback listener, health live/ready, metrics, Alembic migrations for `registry_oci_*`. (0.5 w)
2. Router + grammar + error model + `/v2/` + catalog. (0.5 w)
3. CAS store, atomic writes, upload sessions (POST/PATCH/PUT/monolithic/status/cancel), streaming with incremental digest, size limits, disk reserve. (1.5 w)
4. Manifests GET/HEAD/PUT/DELETE with validation, tags/list pagination, referrers API (the data model is simple once `subject` is indexed), cross-repo mount with `from`. (1.5 w)
5. Token server (GET+POST), JWT, Basic fallback, API-token mapping, `oci:*` permissions, visibility (private/internal/public). (1 w)
6. Pull-through: upstream groups (Docker Hub + seeded Iranian mirrors + ghcr/quay/k8s primaries), challenge parsing, token cache, redirect allowlist, failover/circuit reuse, tag TTL + HEAD revalidation, negative cache, stale-if-error, offline mode, single-flight, digest-verified commit, Range-resume. Path-prefix + `?ns=` + `hub.` hostname mapping. (2 w)
7. GC (online mark-sweep with grace, dry-run) + proxy LRU eviction. (1 w)
8. Admin UI MVP: repos, tags, manifest/layers view, upstream status + Hub quota, delete/purge/GC tasks, client-setup snippets. (1–1.5 w)
9. Conformance suite in CI (4 workflows green) + docker/containerd/podman/skopeo/crane smoke matrix + chaos tests. (1 w, overlapping)

Exit criteria (Gate-style):
- conformance 100%;
- `docker pull nginx` through `hub.test` with the primary forced to 403 succeeds via a mirror;
- a cached image pulls in offline mode;
- a 5 GB push/pull completes with RSS < 300 MB;
- the GC race test passes;
- no engine port reachable externally.

### P1 (≈ 5–7 engineer-weeks)

- Namespace grants. Immutable tag rules. Retention/cleanup policies with preview.
- Upload-session UI. Automatic cross-mount (no `from`).
- Gateway sendfile offload (X-Accel/intercept). Multi-worker readiness. Background cache fill on client disconnect; tail-read for concurrent cold pulls.
- Referrers tree UI. Proxying referrers / `sha256-*` sig tags from upstreams.
- Optional Trivy integration (scan on push/schedule, results as referrers, Trivy DB via own cache).
- Per-upstream outbound proxy setting. Index child prefetch for chosen platforms. Quorum tag resolution.
- fsck sampler. Backup contributor (DB + optional private CAS). Prometheus dashboards. Load-test report.

### P2 (≈ 6–8 engineer-weeks)

- Signature policy (cosign keys/keyless, notation) incl. "verify before caching upstream tags".
- Scheduled replication/prefetch lists for air-gap. Pull-blocking on scan severity.
- Quotas per namespace with enforcement UI. Webhooks/events (push, delete, scan done). Layer file browser (sandboxed).
- Optional Go blob data-plane **only if** benchmarks demand it. External object storage (S3-compatible) backend behind the CAS interface for the HA future (docs/02 §9).
- Storage-growth forecasting. Multi-tenant org namespaces.

### Main risks

1. Client quirks (containerd POST auth fallback, dockerd mirror auth context, Range behaviors). Mitigate with the matrix CI from week 2.
2. PGlite single-connection throughput on HEAD-heavy traffic. Mitigate with the LRU and an early load test, with external Postgres as the escape hatch.
3. Iranian mirror churn and geo-restriction. Mitigate by keeping the list editable, probing automatically and showing status in the UI.
4. Gateway ADR not yet decided. Its streaming and offload capabilities are a dependency, so put a "registry route" requirement into that ADR now.
5. Scope creep toward Harbor parity. Hold the line at the phases above.

---

## Appendix A — Client configuration snippets (for the setup wizard)

```json
// /etc/docker/daemon.json  (Docker Hub only)
{ "registry-mirrors": ["https://hub.example.com"] }
```

```toml
# /etc/containerd/certs.d/ghcr.io/hosts.toml   (path-prefix mode)
server = "https://ghcr.io"
[host."https://registry.example.com/v2/ghcr.io"]
  capabilities = ["pull", "resolve"]
  override_path = true

# /etc/containerd/certs.d/docker.io/hosts.toml (ns mode; containerd appends ?ns=docker.io)
server = "https://registry-1.docker.io"
[host."https://registry.example.com"]
  capabilities = ["pull", "resolve"]
```

```toml
# /etc/containers/registries.conf  (podman / CRI-O)
[[registry]]
prefix = "quay.io"
location = "quay.io"
[[registry.mirror]]
location = "registry.example.com/quay.io"
```

Docker users without containerd mirroring for non-Hub registries: `docker pull registry.example.com/ghcr.io/owner/image:tag`.

## Appendix B — Sources consulted

- OCI distribution-spec v1.1 (`spec.md`, `conformance/README.md`), from memory of the published spec. Verify the details against the pinned tag during implementation.
- Docker Hub usage & pull limits: https://docs.docker.com/docker-hub/usage/ and https://docs.docker.com/docker-hub/usage/pulls/ (fetched 2026-11-08: 100/6h anon, 200/6h personal; HEAD not counted; `ratelimit-*` headers).
- Earlier stricter-limit reporting: https://github.com/docker/docs/pull/22081 , https://gitlab.com/gitlab-org/gitlab/-/issues/526605
- Iranian mirror lists: https://mirrors.arash-hatami.ir/ , https://gh.r-mj.com/MiravaOrg/Mirava , https://liara.ir/mirrors/docker/ (docker-mirror.liara.ir), https://git.parchlinux.com/documention/wikibackup/src/branch/main/Docker.md , https://gist.github.com/aliva/06cb2e0d7a2a5990d4d682dab57fb302
- Live probes from the dev workstation, 2026-11-08: `/v2/` + anonymous `HEAD /v2/library/alpine/manifests/latest` against each candidate mirror (results in §3.3), plus the upstream challenges of quay.io, registry.k8s.io, registry-1.docker.io and ghcr.io.
- Existing code reused: `apps/control-plane/src/mrk_control_plane/pypi_router.py` (destination validation, spool + verify, circuit), `auth.py` (ROLE_PERMISSIONS, API token scope intersection), `upstream_store.py`, `upstream_probe.py`, `tasks.py`, `secret_store.py`, `deploy/appliance/supervisord.conf`.
