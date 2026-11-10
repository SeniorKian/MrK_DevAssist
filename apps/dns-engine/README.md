# MRK DNS engine (`mrk-dns`)

The DNS server of the MRK appliance, phases D1, D2, D4, D5 and D6 (query log, statistics, critical monitoring, recursion, DNSSEC,
encrypted DNS, zone transfers, filtering, backup; behaviour from docs/25). The archived design contracts
(docs/36–41) are summarised in docs/03-user-stories.md, Epic E18; their full text is in git history.
It is a Go program that lives in the appliance image and runs as its own container (`mrk-dns`
Compose service, profile `dns`). The control plane manages it through a Unix-socket admin API.

Clean-room: the code is written from the RFCs and docs/25, not from Technitium, BIND, Unbound or
CoreDNS source. The only protocol dependency is the
[`github.com/miekg/dns`](https://github.com/miekg/dns) library (BSD-3-Clause). The other
dependencies are `golang.org/x/sys` (socket options, capabilities), `golang.org/x/net`
(pulled in by miekg/dns) and `github.com/klauspost/compress` v1.20.3 (zstd for the query log and
statistics), all BSD-3-Clause.

## Binaries

| Binary | Purpose |
|---|---|
| `mrk-dns serve` | the server (env below) |
| `mrk-dns health` | Docker healthcheck: admin socket answers and one UDP listener answers a `localhost. A` probe |
| `mrk-dns version` | print version and commit |
| `mrk-dnsbench` | UDP load generator (QPS, latency percentiles, rcodes, timeouts) |

Environment variables (all optional):

| Variable | Default | Meaning |
|---|---|---|
| `MRK_DNS_RUN_AS` | `10001:10001` | uid:gid a root start drops to, keeping only `CAP_NET_BIND_SERVICE` (uid 0 refused) |
| `MRK_DNS_DATA_DIR` | `/var/lib/mrk-dns` | settings, zones (+history), overrides |
| `MRK_DNS_ADMIN_SOCKET` | `/run/mrk-dns/admin.sock` | admin API socket (mode 0660) |
| `MRK_DNS_ADMIN_TOKEN_FILE` | `<socket dir>/admin.token` | bearer token, created on first start (mode 0640) |
| `MRK_DNS_LISTEN` | `127.0.0.1:53,172.17.0.1:53` | listen addresses on the **first** start only; afterwards they come from the settings |
| `MRK_DNS_GOMEMLIMIT` | 85% of the cgroup memory limit | Go soft memory limit, e.g. `400MiB` |
| `MRK_DNS_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` (JSON logs on stdout) |

## Privileges

With `no-new-privileges` the kernel ignores file capabilities, and Docker gives a non-root
user no permitted capabilities. So the `mrk-dns` service starts as `0:10001` with only
`NET_BIND_SERVICE`, `SETUID` and `SETGID`. Before doing anything else, `serve` does the
following on every OS thread:

1. sets `PR_SET_KEEPCAPS`;
2. calls `setgroups`, `setresgid` and `setresuid` to `MRK_DNS_RUN_AS`;
3. calls `capset` to keep exactly `CAP_NET_BIND_SERVICE` (permitted and effective; nothing
   inheritable or ambient).

Verified on the compose stack: every thread runs as `Uid 10001` with `CapPrm=CapEff=0x400`.
Rebinding port 53 later (settings changes, retries) keeps working.

## Architecture

```
UDP sockets (SO_REUSEPORT, one reader per CPU)   TCP listeners (connection cap, idle timeout, pipelining)
        │                                                 │
        └──────────────► engine.Fast (no allocation) ◄────┘
                          wire.ParseQuery → ACL → client token bucket → fresh cache hit → patched template
                          │ anything else
                          ▼
                     engine.Slow (bounded worker pool)
                          miekg decode + sanity (FORMERR/NOTIMP/BADVERS, CHAOS/AXFR refused)
                          → overrides → authoritative zones (deepest zone wins) | forwarder zones
                          → locally served names (RFC 6761/6303) → recursion ACL → cache → upstreams
                          → EDNS / truncation → RRL (outsiders, UDP) → pack
```

* **Policy snapshot.** Settings, ACLs, compiled zones, overrides, upstream groups and limiters
  are compiled into an immutable `policy` and swapped with `atomic.Pointer`. Queries never take
  a lock on state; admin changes rebuild and swap, so a reload never drops a query. Listeners
  are reconciled live (new sockets start before removed ones stop; failed binds such as
  `172.17.0.1` before `docker0` exists are retried every 10 s).
* **Fast path.** Cache entries are stored as packed responses (`wire.Template`) with the TTL
  offsets recorded. A hit copies the bytes and patches the ID, flags, question case
  (0x20-safe), decayed TTLs and OPT. Nothing is decoded and almost nothing is allocated.
* **Monitoring never slows the hot path.** Every answer (and every refusal or drop) is recorded
  without allocation into a sharded lock-free ring (Vyukov bounded queues, 2×GOMAXPROCS shards)
  and sharded statistics counters. When the ring is full the record is dropped and counted. A
  pipeline goroutine drains it every 50 ms into the statistics top-k, the 10 s hot lists, the
  attack detector and the query log. Once a second the pressure controller samples CPU (cgroup
  v2), memory (vs GOMEMLIMIT), QPS (vs `capacity_qps`) and host metrics, moves between
  normal/warning/critical/emergency with hysteresis and publishes reversible actions (log
  sampling, no prefetch, prefer stale, tighter client limits, refusing recursion to heavy
  clients, minimal ANY) that the query path reads atomically.
* **Mitigations** (manual or automatic after a detected random-subdomain / NXDOMAIN flood) are
  checked right after the ACL: a CIDR trie for clients, a wire-form suffix map for domains.
  Domain throttles cap upstream work only, so cached names keep answering.
* **Never an open resolver.** `query_allow` is the outer gate (REFUSED). Recursion, forwarder
  zones and overrides need `recursion.enabled` and a client in `recursion.allow`.
  `0.0.0.0/0` and `::/0` are rejected in `recursion.allow`. Authoritative data is served to
  anyone in `query_allow`.

## Packages

| Package | Responsibility |
|---|---|
| `internal/wire` | strict fast query parser, cache templates (TTL patching, EDE, truncation), error responses |
| `internal/acl` | ordered CIDR lists with `!` negation (first match wins), private-address test for rebinding protection |
| `internal/config` | settings document, defaults, validation with field errors, upstream address syntax |
| `internal/zone` | records and typed `data`, validation (CNAME rules, occlusion, duplicates, apex NS), compiled lookup (AA, NXDOMAIN/NODATA with SOA, RFC 4592 wildcards, empty non-terminals, CNAME chasing across local zones, delegations with glue), RFC 1035 import/export, YYYYMMDDnn serials (RFC 1982) |
| `internal/cache` | 64-shard LRU with a byte cap, negative entries, serve-stale window, subtree flush |
| `internal/resolver` | UDP (random port, ID and question checks, TCP on TC), TCP and DoT connection pools, DoH (RFC 8484, POST, bootstrap without the system resolver), EWMA RTT, health checks, `fastest`/`parallel`/`in_order`, global in-flight limiter, single-flight |
| `internal/limits` | per-client token bucket (IPv4 /32, IPv6 /64) and BIND-style RRL (prefix aggregation, slip), both with bounded memory |
| `internal/engine` | state, policy compilation, the query pipeline (`Fast`/`Slow`), recursion with negative caching (RFC 2308), serve-stale (RFC 8767, EDE 3), prefetch, rebinding filter, admin operations |
| `internal/server` | listeners: SO_REUSEPORT, `IP_PKTINFO` for wildcard binds, TCP limits, graceful shutdown |
| `internal/admin` | HTTP API on the Unix socket: token auth, 4 MiB body cap, strict JSON, error envelope |
| `internal/store` | atomic writes (temp file, fsync, rename, directory fsync), 50 zone versions, crash recovery |
| `internal/metrics` | counters, 1 s / 1 min QPS, Prometheus text |
| `internal/querylog` | hot-path ring; columnar zstd segments (per-segment dictionaries, varints, index with time range, counts and Bloom filters on name suffixes/labels and clients); WAL with crash recovery; retention by age/bytes; disk-free guard; privacy (full/mask/hash/none) and exclusions; sampling; newest-first search with cursor and 2 s budget; live streams; export; delete with atomic rewrite |
| `internal/stats` | sharded counters → minute buckets (rcode, source, qtype, latency histogram) → hour/day rollups; Space-Saving top-k; persisted |
| `internal/pressure` | CPU/memory sampler, level controller with hysteresis and dwell, actions per level, 10 s hot domains/clients and heavy-client set |
| `internal/attack` | random-subdomain detection (HyperLogLog per parent, bounded) and NXDOMAIN floods per client |
| `internal/mitigate` | expiring client/domain mitigations (throttle/block/refuse), trie + suffix map, hit counters, persisted |
| `internal/events` | 1000-event ring with sequence cursor |
| `internal/topk`, `internal/hll` | Space-Saving summaries, HyperLogLog |

On-disk layout (`MRK_DNS_DATA_DIR`): `settings.json` (`config_version` + settings),
`overrides.json`, `zones/<zone>.json` and `zones/<zone>.history/<version>.json`,
`querylog/` (`*.seg`, `active-<seq>.wal`, `hash.key` 0600), `stats/stats.json.zst`,
`mitigations.json`.

## Admin API

See the archived contracts in git history: `git show 1a568bf:docs/37-dns-d1-contract.md` §2 and §0.2 (D1),
`git show 1a568bf:docs/38-dns-d2-contract.md` §3 and §0.2 (D2: `/v1/querylog[/stream|/export|/status]`,
`/v1/stats`, `/v1/pressure`, `/v1/host-metrics`, `/v1/mitigations`, `/v1/events`). Every request needs `Authorization: Bearer
<token>` except `GET /v1/health`. Mutating requests may send `X-MRK-Actor: <user>`, which is
recorded in zone history.

## Test, fuzz, benchmark

Go is not needed on the host. Use the pinned toolchain image from `deploy/images/Dockerfile`:

```sh
GO="docker run --rm -v $PWD:/src -v mrk-go-cache:/go -w /src golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80"
$GO go test -race ./...
$GO go test -run='^$' -fuzz='^FuzzHandle$' -fuzztime=60s ./internal/engine
$GO go test -run='^$' -fuzz='^FuzzParseQuery$' -fuzztime=60s ./internal/wire
$GO go test -run='^$' -fuzz='^FuzzTemplate$' -fuzztime=60s ./internal/wire
$GO go test -run='^$' -fuzz='^FuzzImport$' -fuzztime=60s ./internal/zone
$GO go test -run='^$' -fuzz='^FuzzSegment$' -fuzztime=60s ./internal/querylog
$GO go test -run='^$' -fuzz='^FuzzParseFilter$' -fuzztime=60s ./internal/querylog
# search latency over 5M stored rows (opt-in)
docker run --rm --cpus 2 -e MRK_QL_BENCH_ROWS=5000000 ... go test -run TestSearchLatencyLarge -v ./internal/querylog
$GO go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The tests cover:

* zone semantics as table tests;
* cache TTL, negative and stale behaviour;
* limits and RRL;
* the open-resolver refusal;
* admin validation and concurrency (one winner among concurrent `PUT /v1/settings`);
* crash recovery of the store;
* import/export round trip;
* DoT and DoH against TLS test servers;
* an integration test that starts the server on a free port and queries it over UDP and TCP
  with the miekg client;
* D2: segment/WAL encoding round trips and corruption detection, Bloom filters, retention, the
  disk guard with a fake statfs, privacy modes, search filters and cursors, stream sampling and
  limits, delete rewrite, crash recovery, stats rollups and percentiles, Space-Saving accuracy,
  HyperLogLog, pressure hysteresis with a fake clock, actions applied and reverted in the query
  path, attack detection, mitigation matching/expiry, an allocation-free fast path with logging
  on, and an integration test that floods random subdomains and checks detection, the automatic
  mitigation, that normal clients are still answered, and recovery.

Benchmark (cached answers), with the engine at the production limits:

```sh
docker network create bench
docker run -d --name dns --network bench --cpus 2 --memory 512m --init --user 0:10001 \
  --cap-drop ALL --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges:true --read-only \
  -e MRK_DNS_LISTEN=0.0.0.0:53 -v dnsdata:/var/lib/mrk-dns -v dnsrun:/run/mrk-dns \
  --entrypoint mrk-dns <image> serve
# lift client_qps (PUT /v1/settings) for a single-source benchmark, warm the cache, then:
docker run --rm --network bench --cpus 2 --entrypoint mrk-dnsbench <image> \
  -server dns:53 -names google.com,github.com,example.com -c 64 -window 16 -d 20s
```

Results on a 4-core Docker Desktop host, engine `--cpus 2`, load generator `--cpus 2`, 20 cached names:

| Load | QPS | p50 | p99 | loss |
|---|---|---|---|---|
| saturation, c=64 window=16 | **120,400** | 6.7 ms | 32 ms | 0 |
| saturation, c=16 window=8 | 107,600 | 0.72 ms | 10.3 ms | 0 |
| open loop at 80k | 79,800 | 0.57 ms | 16 ms | 0 |
| open loop at 50k (D1 target) | 50,000 | 0.31 ms | 6.5 ms | 0 |

At saturation, p99 is dominated by CFS CPU throttling (2-CPU quota) and queueing.

Rate-limit demo with the defaults (`client_qps 200`, `client_burst 400`), two containers at the same time:

* the flooding client got 3,343 answers in 15 s (200 qps plus the burst) and 7.7k queries were
  dropped (`mrk_dns_dropped_total{reason="client_rate_limit"}`);
* the normal 100-qps client got all 1,202 answers, p99 0.8 ms.

### D2 results (same host and limits)

| Measurement | Result |
|---|---|
| saturation c=64 window=16, query log `off` (median of 4 alternating runs) | ≈87k qps |
| same with query log `all` | ≈94k qps (run-to-run noise ±15%: no measurable cost); 11.6M rows stored, 0.03% dropped from the ring at saturation |
| storage | 9 bytes/row for varied traffic, ~1.6 bytes/row for repetitive traffic |
| search over 5M rows (36 segments, `--cpus 2`) | first page 11 ms; rare suffix or client 16–18 ms cold (Bloom filters skip 35/36 segments); CIDR / time range ~13 ms; full scan with no match 0.54 s |
| overload: `capacity_qps` 20000, one client flooding at 46k qps | emergency after 2 s with all six actions; the flooder got REFUSED / was rate limited; a normal 100-qps client got 7000/7000 NOERROR (p50 0.35 ms, p99 34 ms); memory flat at 72–83 MiB; after the flood emergency → critical → warning → normal, one level per 10 s dwell |
| random subdomains at 2000 qps (`attack_detection.mode: auto`) | `attack.detected` and automatic domain + client throttles at the first evaluation |

Load test: `mrk-dnsbench -random victim.example ...` sends random 12-character labels.
