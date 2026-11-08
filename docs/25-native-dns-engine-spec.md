# Clean-room DNS engine for MRK Appliance — behavioural study of Technitium DNS Server and implementation spec

Status: research / engineering spec (2026-11-08). Target: `dns-engine` module of the single-container MRK appliance (see `docs/20-modular-appliance-and-domain-routing.md`, `docs/22-dns-management-module.md`).

## 0. Clean-room ground rules (read first)

- Technitium DNS Server is **GPL-3.0**. This document describes only **observable behaviour, public documentation (APIDOCS.md, CHANGELOG.md, help page, blog), configuration semantics and the IETF standards** it implements. No source code was read, copied or translated, and none should be during implementation.
- Implementers of the MRK engine **must not open Technitium source files** (`DnsServerCore/**`, `TechnitiumLibrary.Net/**`). Use the RFCs and this spec. Keep a record (ADR + commit trailer) stating the implementation is derived from RFCs and the behavioural spec.
- Parameter/setting *names* below are cited so the MRK adapter can offer API-level parity mapping; names are facts about the interface, not code. Our own API should use MRK naming (`snake_case`, `/api/v1/dns/...`), with an optional mapping table.
- Defaults listed as "Technitium default" come from APIDOCS.md; where APIDOCS shows only an example value it is marked "(example)". Items marked **[verify]** are recollection/inference not confirmed by a fetched doc during this research and must be re-checked by black-box testing against a pinned Technitium build before being relied on for parity.
- Consequence for doc 22: §1 of doc 22 assumes Technitium is embedded as a separate GPL process. This spec is the alternative path: native MRK engine, which removes the GPL/source-offer/.NET-runtime blockers in doc 22 §13.

Primary sources consulted:
- APIDOCS.md — <https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md>
- CHANGELOG.md — <https://github.com/TechnitiumSoftware/DnsServer/blob/master/CHANGELOG.md> (latest observed: **v15.6.2, 2026-10-17**)
- Help page — <https://technitium.com/dns/help.html>
- Blog — <https://blog.technitium.com/> (self-hosting a domain, secondary/notify notes)

---

## 1. Architecture

### 1.1 Observed Technitium architecture (behavioural)

- Single long-running .NET process: DNS server core + embedded HTTP(S) web service (admin console + REST API on `5380/http`, optional TLS port e.g. `53443`), optional DHCP server, DNS Apps (plugin assemblies loaded in-process), clustering service.
- Listeners (settings): `dnsServerLocalEndPoints` (default `0.0.0.0:53`, `[::]:53`, UDP+TCP), `enableDnsOverTls`/`dnsOverTlsPort` (853), `enableDnsOverHttps`/`dnsOverHttpsPort` (443), `enableDnsOverHttp3`, `enableDnsOverQuic`/`dnsOverQuicPort` (853/udp), `enableDnsOverHttp`/`dnsOverHttpPort` (80, plain HTTP intended behind a TLS reverse proxy), `enableDnsOverUdpProxy`/`enableDnsOverTcpProxy` (port 538, HAProxy PROXY protocol), and DoH/DoH-plain over **Unix sockets**. A `dnsReverseProxyNetworkACL` restricts which sources may use the proxy-protocol/real-IP paths; `dnsOverHttpRealIpHeader` names the trusted header.
- Concurrency knobs exposed: `maxConcurrentResolutionsPerCore` (default 100; a resolver queue was added in v13.3), `resolverConcurrency` (example 2 — parallel queries to different NS of a zone), `forwarderConcurrency` (example 2), `concurrentForwarding` (query forwarders in parallel), `enableUdpSocketPool` (pre-bound random-port UDP sockets for outbound, with `socketPoolExcludedPorts`), `udpSendBufferSizeKB`/`udpReceiveBufferSizeKB` (2048), `listenBacklog` (100), `quicMaxInboundStreams` (100), `quicIdleTimeout` (60000 ms), `tcpSendTimeout`/`tcpReceiveTimeout` (10000 ms), `clientTimeout` (range 1000–10000 ms; time after which the client gets SERVFAIL while resolution may continue in background).
- Persistence: a config folder containing the server config, one file per zone, cache snapshot (when `saveCache=true`, written at shutdown and re-loaded at start — v11.0), stats files (hourly/daily aggregates, `maxStatFileDays`), text log files (`logFolder`, `maxLogFileDays`), installed apps, TLS certs, DHCP scopes. Formats are Technitium-proprietary binary [verify]; export is RFC 1035 zone file (`/api/zones/export`) and backup is a zip (`/api/settings/backup` with selectable items). We do **not** need format compatibility; import via RFC 1035 zone files and AXFR is sufficient for migration.

### 1.2 Request pipeline (behavioural order, to replicate)

```
listener (UDP | TCP | DoT | DoH(1.1/2/3) | DoQ | PROXY-proto | Unix-socket DoH)
  └─ decode + basic sanity (opcode, QDCOUNT=1, class, EDNS parse, cookie parse)
  └─ client identity: src IP; if from trusted proxy ACL → PROXY header / real-IP header;
     optionally ECS source address (enableEDnsClientSubnetSourceAddress, v15.0)
  └─ QPM rate limit per prefix (UDP: drop or TC=1 by percentage; TCP: drop) — bypass list
  └─ opcode dispatch: QUERY | NOTIFY (→ secondary zone) | UPDATE (→ primary zone, RFC 2136) | other → NOTIMP
  └─ DNS Apps "request controller" hooks (may drop/allow)     [P2 for MRK]
  └─ AXFR/IXFR (TCP/TLS/QUIC only) → zone-transfer ACL + TSIG
  └─ authoritative lookup (closest enclosing enabled zone, incl. query-access ACL per zone)
       ├─ Primary/Secondary: answer AA=1 / referral / NXDOMAIN+SOA / NODATA+SOA (+DNSSEC proofs)
       ├─ Stub: use stored NS set to recurse (not AA)
       ├─ Forwarder / SecondaryForwarder zone: local overrides first, then FWD records → forward
       └─ APP records → DNS App handler (P2)
  └─ allowed zones (allow list) short-circuit blocking
  └─ blocked zones / block lists (unless client in blockingBypassList or blocking temporarily disabled)
       → blocking response (AnyAddress | NxDomain | CustomAddress), TXT report optional
  └─ locally served zones (RFC 6303 reverse private ranges, RFC 6761 special-use names) if locallyServedDnsZones
  └─ recursion permission (recursion = Deny | Allow | AllowOnlyForPrivateNetworks | UseSpecifiedNetworkACL)
       → REFUSED if not permitted
  └─ cache lookup (positive, negative, stale)
  └─ resolve: global forwarders (if configured) else iterative from root hints; DNSSEC validation
  └─ post-processing: CNAME chasing across sources, ANAME resolution, minimal responses,
     truncation for UDP (payload size from EDNS, server max `udpPayloadSize` default 1232),
     EDNS options (cookies, ECS echo, EDE RFC 8914), stats + query-log record
```

Notes:
- Blocking is applied *before* recursion but *after* local authoritative zones — local zones always win over block lists (observed: blocked/allowed are themselves modelled as special internal zones; "UpstreamBlocked" and "CacheBlocked" response types exist in the query-log enum, i.e. upstream answers of 0.0.0.0/NXDOMAIN-with-blocking-EDE are classified as blocked).
- The query-log/stat `responseType` enum is: `Authoritative, Recursive, Cached, Blocked, UpstreamBlocked, CacheBlocked` (plus `Dropped` in stats). We should reproduce this classification exactly — it drives dashboard charts.

### 1.3 MRK target architecture

```
dns-engine (supervisord program, uid 10001)
  ├─ asyncio event loop (uvloop) — N worker processes via SO_REUSEPORT (default N = 1, opt-in >1)
  │   ├─ UDP/TCP 53 listener          (MVP)
  │   ├─ DoT 853 listener (ssl)        (P1)
  │   ├─ DoH plain-HTTP on 127.0.0.1:8053 behind Edge Gateway (TLS at gateway)  (MVP/P1)
  │   └─ DoQ 853/udp via aioquic       (P2)
  ├─ core: Pipeline → ZoneStore → BlockEngine → Cache → Resolver/Forwarder → Validator
  ├─ control socket: Unix socket /run/mrk/dns-engine.sock (JSON-RPC/HTTP) for Control Plane adapter
  ├─ background tasks: blocklist refresh, secondary refresh/retry/expire, NOTIFY sender, DNSSEC
  │   re-sign/rollover scheduler, prefetch, stats rollup, log retention, cache snapshot
  └─ persistence under /data/modules/dns/
        zones/<zone>.zone       canonical RFC 1035 text (authoritative copy) + zones/<zone>.meta.json
        zones/<zone>.journal    IXFR journal (RFC 1995 diff sequences), bounded
        keys/<zone>/<tag>.key.enc  DNSSEC private keys, AES-GCM wrapped by appliance KEK
        tsig.json.enc           TSIG secrets (encrypted)
        config.json             server settings (schema-versioned, atomic write+fsync+rename)
        blocklists/<sha>.txt    downloaded lists + ETag/Last-Modified metadata
        cache.snapshot          optional msgpack/CBOR snapshot (P1)
        stats/YYYY/MM/DD/HH.json hourly aggregates; daily rollups
        querylog.sqlite         query log (WAL), retention job
```

Design decisions:
- **Control Plane is source of truth for desired config and change sets (doc 22 §5); engine is source of truth for runtime zone data and serials.** Zone writes go through an engine API that performs validation + atomic apply + serial bump; the Control Plane keeps snapshots/revisions in `dns_*` tables.
- Zone storage: text RFC 1035 files are human-diffable, backup-friendly, and make "raw zone editor with parse/validate/diff" (doc 22 §4) trivial. Load into an in-memory tree on start; write via temp file + `os.replace`. For zones > ~100k RRs, P2: SQLite-backed zone store.
- Config writes: atomic replace, keep last N generations (`config.json.1..5`) for "safe mode: last good config" (doc 22 §8).

---

## 2. Authoritative server

### 2.1 Zone types (Technitium semantics)

API `type` values: `Primary, Secondary, Stub, Forwarder, SecondaryForwarder, Catalog, SecondaryCatalog`. Conversion between types via `/api/zones/convert`; clone via `/api/zones/clone`; enable/disable (disabled zone ⇒ name resolved as if zone didn't exist, i.e. recursively).

| Type | Behaviour | Standards | MRK priority |
|---|---|---|---|
| Primary | Locally edited, AA answers, SOA serial managed, may be DNSSEC-signed, sends NOTIFY, serves AXFR/IXFR, accepts RFC 2136 UPDATE per policy | RFC 1034/1035, 1995, 1996, 2136, 5936 | **MVP** |
| Secondary | Copy pulled from `primaryNameServerAddresses` via AXFR/IXFR over `zoneTransferProtocol` = `Tcp`/`Tls`(XoT RFC 9103)/`Quic`(RFC 9250 XoQ), optional TSIG (`tsigKeyName`). SOA refresh/retry/expire timers honoured with floors `minSoaRefresh`/`minSoaRetry` (300 s). Expired zone ⇒ SERVFAIL. Accepts NOTIFY from primary/`notifyAllowedNetworks`. Optional `validateZone` = ZONEMD validation (RFC 8976, v13.0). Updates may be forwarded to primary (RFC 2136 §6 forwarding) [verify]. | RFC 1996, 5936, 1995, 9103, 8976 | P1 (TCP+TSIG), P2 (XoT/XoQ, ZONEMD) |
| Stub | Holds only SOA + NS (+glue) of a zone fetched from primary; queries under it are resolved recursively *using those NS*, bypassing global forwarders (help page). Not authoritative (AA=0). | RFC 1034 §4.2 concept | P1 |
| Forwarder (conditional forwarder) | Zone that contains `FWD` pseudo-records (protocol, forwarder, priority, dnssecValidation, proxy) and *may also contain real records that override* the upstream answer. Matching names are forwarded to the listed forwarders, by priority. Supports dynamic updates since v12.0 [changelog]. Special forwarder value `this-server` means "recurse locally" [verify]. | — (operational) | **MVP** (core use case: split-horizon / internal domains) |
| SecondaryForwarder | Forwarder zone replicated from another Technitium server (via catalog / proprietary transfer of FWD records) | Technitium-specific | P2 / not-applicable |
| Catalog / SecondaryCatalog | Catalog zone (RFC 9432) listing member zones; secondaries auto-provision members. Member zones reference a `catalog`; `overrideCatalog*` flags allow per-member overrides of query access, zone transfer and notify. Secondary zones as members since v14.3. | RFC 9432 | P2 |

Zone options (from `/api/zones/options/set`): `disabled`, `catalog`, `queryAccess` (+`queryAccessNetworkACL`), `zoneTransfer` (Deny/Allow/AllowOnlyZoneNameServers/UseSpecifiedNetworkACL/… [verify exact enum]) + `zoneTransferNetworkACL` + `zoneTransferTsigKeyNames`, `notify` (None/ZoneNameServers/SpecifiedNameServers/BothZoneAndSpecified [verify]) + `notifyNameServers`, `update` (Deny/Allow/AllowOnlyZoneNameServers/UseSpecifiedNetworkACL [verify]) + `updateNetworkACL` + `updateSecurityPolicies` (per TSIG key: allowed domain names (wildcards) and record types — added v10.0), `primaryNameServerAddresses`, `primaryZoneTransferProtocol`, `primaryZoneTransferTsigKeyName`, `validateZone`. Per-zone user/group permissions via `/api/zones/permissions/*`.

MRK note: defaults must be **deny** for transfer and update (doc 22 §9). Network ACL semantics in Technitium: ordered list of `addr/prefix` entries, `!` prefix = deny, first match wins [verify]; we adopt exactly that (simple, documented) model.

### 2.2 SOA and serial handling

- One SOA per zone at apex; SOA MINIMUM is the negative-caching TTL (RFC 2308 §4, help page). Defaults for new primary zones: `defaultSoaRecordTtl` 900, `defaultNsRecordTtl` 14400, `defaultRecordTtl` 3600, `defaultResponsiblePerson`.
- Serial: incremented automatically on every change set. `useSoaSerialDateScheme` (global default + per-zone at create) = `YYYYMMDDnn` (RFC 1912 §2.2 convention); if the date-based value ≤ current serial, fall back to +1. Serial arithmetic per **RFC 1982** (wrap-around at 2^32, comparisons modulo).
- Import option `overwriteSoaSerial`; on import/overwrite the serial must still strictly increase so secondaries pick it up.
- Engine invariant (MRK): one change set ⇒ one serial bump ⇒ one IXFR journal entry ⇒ one NOTIFY round. Change sets are atomic (all-or-nothing) and DNSSEC re-signing of touched RRsets is part of the same commit.

### 2.3 Zone transfer, NOTIFY, TSIG

- **AXFR** RFC 5936: TCP only (also XoT RFC 9103, XoQ RFC 9250 §4.4/§7); multi-message responses; SOA first and last; transfer ACL check + TSIG required if configured; global `zoneTransferAllowedNetworks` permits without TSIG.
- **IXFR** RFC 1995: serve from journal of (old SOA, deletions, new SOA, additions) sequences; if journal does not cover the requested serial ⇒ fall back to AXFR-style full response. Condensed diffs allowed. UDP IXFR returns SOA only (RFC 1995 §2) → client retries TCP.
- **NOTIFY** RFC 1996: on serial change, send NOTIFY(SOA) to NS of zone (excluding the primary MNAME itself) and/or specified servers; retry with backoff (e.g. 5 retries, 15 s interval) until NOTIFY response; track per-target status (Technitium UI shows "Notify Failed" when the target doesn't host the zone — blog comment). Receiving: secondary validates source (primary addresses / `notifyAllowedNetworks`), schedules immediate SOA check.
- **TSIG** RFC 8945 (obsoletes 2845): global key list `tsigKeys` (name, shared secret base64, algorithm). Algorithms to support: `hmac-sha256` (MVP default), `hmac-sha384`, `hmac-sha512`, `hmac-sha1`, `hmac-md5.sig-alg.reg.int` (legacy; allow but warn), truncated variants optional. Time-signed fudge 300 s, BADTIME/BADSIG/BADKEY handling, multi-message TSIG on AXFR (every message signed, or at least every 100th per RFC 8945 §5.3.1). `/api/settings/getTsigKeyNames` lists key names only (secret never re-shown — matches doc 22 secret policy).
- Secondary refresh loop: SOA query at `refresh`; on failure retry at `retry`; zone expires after `expire` without success; `/api/zones/resync` forces full re-transfer.

### 2.4 Dynamic update (RFC 2136, RFC 3007)

- Prerequisite section evaluation (RFC 2136 §3.2: RRset exists value-independent/dependent, RRset does not exist, name in use / not in use) → YXDOMAIN/NXDOMAIN/YXRRSET/NXRRSET/NOTZONE.
- Update section processing §3.4: add RR, delete RRset, delete all RRsets at name, delete RR; SOA/NS apex rules (cannot delete last NS / the SOA; SOA updates only if serial increases).
- Authorisation: zone `update` policy + network ACL + TSIG (RFC 3007 secure update) + per-key `updateSecurityPolicies` (allowed names incl. wildcard `*.example.com`, allowed types). Server bumps serial, re-signs if DNSSEC, journals, notifies.
- Supported on Primary and Forwarder zones (v12.0); on Secondary zones forwarded to primary [verify]. DHCP integration uses internal update path (not wire RFC 2136).
- MRK priority: **P1** (needed for ACME DNS-01 automation with TSIG — high value for the appliance's own certs).

### 2.5 Record types and validation

Types with first-class API params (records/add): A, AAAA, NS, CNAME, PTR, MX, TXT, SRV, NAPTR, RP, DNAME, DS, SSHFP, TLSA, SVCB, HTTPS, URI, CAA, ANAME, FWD, APP, plus SOA (edit only) and **unknown types as hex RDATA** (RFC 3597). DNSSEC types DNSKEY/RRSIG/NSEC/NSEC3/NSEC3PARAM are server-managed in signed zones (read-only to users). Common record fields: `ttl`, `comments`, `disabled` (per-record disable), `expiryTtl` (auto-delete the record after N seconds — added in recent versions [verify semantics]), `overwrite` (replace RRset vs append).

Validation rules to implement (from RFCs; mirrors observed behaviour):
- Owner names: RFC 1035 length limits (label ≤ 63, name ≤ 255 octets wire), IDNA2008 U-label → A-label conversion (RFC 5891) in API layer; underscore labels allowed (SRV/TLSA/DKIM); case-insensitive compare, case preserved.
- **CNAME** (RFC 1034 §3.6.2, RFC 2181 §10.1): no other data at a CNAME owner except DNSSEC types; not at apex; only one CNAME per owner.
- **DNAME** (RFC 6672): at most one per owner; no descendants under DNAME owner in the same zone; server synthesises CNAME for queries below it (TTL of DNAME); DNAME at apex allowed (but not with CNAME).
- **NS**: at apex = zone's NS set (cannot delete last); below apex = delegation → creates zone cut; data below cut is glue only (occluded otherwise); `glue` param adds A/AAAA glue for in-bailiwick NS.
- **MX/SRV/NS/PTR targets** must be names, not IPs; RFC 2181 §10.3 — MX/NS targets must not be CNAME aliases (warn; Technitium allows [verify]); SRV `target` "." means service unavailable (RFC 2782); priority/weight/port 0–65535.
- **TXT**: each character-string ≤ 255 octets; `splitText` auto-splits long text; `characterStringsBase64` for binary strings.
- **CAA** (RFC 8659): flags 0–255 (critical bit 128), tag `issue|issuewild|iodef|...` alnum, value.
- **TLSA** (RFC 6698), **SSHFP** (RFC 4255/6594/7479), **DS** (RFC 4034 §5; digest types 1/2/4 with length check), **URI** (RFC 7553), **NAPTR** (RFC 3403), **RP** (RFC 1183), **SVCB/HTTPS** (RFC 9460: AliasMode priority 0 vs ServiceMode; SvcParam keys mandatory/alpn/no-default-alpn/port/ipv4hint/ech/ipv6hint/dohpath; keys sorted, no duplicates; `autoIpv4Hint`/`autoIpv6Hint` = server fills hints from the target's A/AAAA in-zone; `updateSvcbHints` on A/AAAA add refreshes them).
- **A/AAAA**: `ptr=true` + `createPtrZone` creates reverse PTR (and reverse zone if missing) — convenience we should keep. `ipAddress=request-ip-address` sets record to the API caller's IP (DDNS-style helper).
- TTL range 0..2^31-1 (RFC 2181 §8); RRset TTL uniformity (RFC 2181 §5.2) — all RRs in an RRset share TTL; editing one changes set TTL.
- Duplicate RR in RRset rejected/ignored (RFC 2181 §5).
- Apex rules: SOA + NS required; CNAME prohibited at apex (use ANAME).

### 2.6 Special semantics

- **Wildcards** (RFC 4592): `*` as leftmost label only; matches when QNAME does not exist (no closest-encloser exact match, including empty non-terminals blocking synthesis); wildcard does not match across zone cuts; synthesised answers carry the QNAME as owner; DNSSEC: RRSIG labels field < owner labels; NSEC/NSEC3 proof that QNAME doesn't exist accompanies wildcard answer. Empty non-terminals must return NODATA (NOERROR, no answer), not NXDOMAIN (RFC 8020 consistency).
- **CNAME chasing**: authoritative server follows CNAME chain within its own zones (and per Technitium, also across local zones and then into recursion if client allowed recursion) [verify extent]; loop detection (max chain length ~16, cf `resolverMaxStackCount` 16).
- **ANAME** (pre-standard draft-ietf-dnsop-aname, expired): apex-capable alias. On A/AAAA (and ANY) query for the owner, server resolves the ANAME target (via recursion/its own zones) and returns synthesised A/AAAA records at the owner name with TTL = min(ANAME TTL, target TTL). Multiple ANAME records allowed (results merged) [verify]. Not transferable semantics to other vendors: in AXFR the ANAME is transferred as its own type code (Technitium uses a private-use type number [verify]); secondaries from other vendors won't understand it. Under DNSSEC online signing the synthesised RRset is signed on the fly. MRK: **P1**; implement as "alias with on-query resolution + short cache".
- **FWD** (Technitium pseudo-record): only valid in Forwarder zones; fields `protocol` (Udp/Tcp/Tls/Https/Quic), `forwarder` (addr[:port], DoT `host:853 (ip)`, DoH URL), `forwarderPriority` (lower first; same priority used concurrently), `dnssecValidation`, proxy settings. Owner can be apex or a subdomain → per-subtree forwarding.
- **APP** record: binds a name to an installed DNS App (`appName`, `classPath`, `recordData` JSON) that computes the answer (geo, failover, split-horizon, weighted). MRK: **P2**, only as built-in "dynamic answer" handlers we write ourselves (failover by health check, split-horizon by client subnet, weighted round-robin). No third-party plugin loading (doc 22 explicitly forbids arbitrary upload).

---

## 3. Recursive resolver

### 3.1 Iterative algorithm (RFC 1034 §5.3.3, RFC 1035 §7)

1. Find the deepest cached delegation (NS set + addresses) for QNAME; start from root hints if none (priming query `. NS` at start-up and on hints expiry, RFC 8109).
2. Select NS server: prefer ones with known addresses; latency-based selection with smoothed RTT and decaying penalties (Technitium: "latency-based server selection" v13.0); query up to `resolverConcurrency` servers in parallel (staggered), `resolverRetries` (example 2) and `resolverTimeout` (example 1500 ms) per attempt.
3. On referral: validate bailiwick (accept only NS/glue within the delegated zone's parent bailiwick — anti-poisoning, RFC 5452 §6), cache NS and glue as lower trust (RFC 2181 §5.4.1 ranking), descend.
4. On CNAME/DNAME: restart for target (bounded by `resolverMaxStackCount` 16).
5. Missing NS addresses (glueless): sub-resolve with depth limit; cap total outbound queries per client query (e.g. 50–100) to bound amplification (cf. NXNSAttack mitigations, “max fetches per query”).
6. Lame/broken servers: mark and back off; SERVFAIL caching (`cacheFailureRecordTtl`, example 10, documented initial 60; help page mentions ≥300 s for failures in older versions — settle on configurable default 30 s).
7. Return answer; validate DNSSEC if enabled (§4.1).

Transport and spoof resistance:
- Random source port per query (RFC 5452) — use an outbound UDP socket pool or per-query ephemeral sockets; random 16-bit ID; match (ID, server addr, port, question).
- **0x20 / QNAME case randomisation** (`randomizeName`, default true, UDP only; draft-vixie-dnsext-dns0x20): randomise case of QNAME letters, require exact case echo; on mismatch treat as spoofed/ignore; fall back to no-0x20 for servers that don't preserve case (track per-server).
- TC=1 ⇒ retry over TCP. EDNS0 (RFC 6891) with advertised payload 1232 (DNS Flag Day 2020); on FORMERR/timeouts retry without EDNS for that server.
- **QNAME minimisation** (`qnameMinimization`, default true; RFC 9156): send only one more label than the known zone cut, using QTYPE=A (RFC 9156 recommends A, or NS) for intermediate steps; stop minimising on NXDOMAIN? — per RFC 9156 §2.3, NXDOMAIN on an intermediate name means the whole subtree doesn't exist (RFC 8020), but fall back to full QNAME on errors/NOERROR-NODATA quirks; limit `MAX_MINIMISE_COUNT` (10) and `MINIMISE_ONE_LAB` (4) to bound long names. CHANGELOG v12.2 notes a fix around NSEC3 iteration counts — relevant to aggressive use of negative proofs.
- **Locally served zones** (`locallyServedDnsZones`, default true): RFC 6303 (RFC1918/link-local/loopback reverse zones, etc.) and RFC 6761/8375/9462 special-use names (`localhost`, `invalid`, `test`, `home.arpa`, `resolver.arpa`…) answered locally (NXDOMAIN/loopback) so they never leak upstream.
- **Root hints**: ship IANA `named.root` (public domain) as data; refresh by priming. P2: local root zone mirror (RFC 8806) using secondary zone of `.` with ZONEMD validation (Technitium supports via ZONEMD v13.0).

### 3.2 Cache

Semantics (settings + RFCs):
- Keyed by (qname lowercased, qtype, qclass) storing RRsets with absolute expiry and trust rank (RFC 2181 §5.4.1); separate negative entries.
- `cacheMinimumRecordTtl` (example 10), `cacheMaximumRecordTtl` (example 604800; documented initial 86400) clamp TTLs; `cacheNegativeRecordTtl` (300) used when no SOA in negative answer; `cacheFailureRecordTtl` for SERVFAIL caching (RFC 2308 §7.1 allows ≤ 5 min).
- **Negative caching RFC 2308**: NXDOMAIN cached per name (covers all types), NODATA per (name,type); TTL = min(SOA TTL, SOA MINIMUM). RFC 8020: NXDOMAIN means nothing below exists → may answer NXDOMAIN for descendants from cache. Aggressive NSEC/NSEC3 use (RFC 8198) — P2.
- **Max entries**: `cacheMaximumEntries` (example 10000; 0 = unlimited [verify]). Eviction: when over limit, remove expired/stale first then least-recently-used [verify order]. MRK: LRU with a byte budget too (memory safety in a shared container), default 100k entries / 128 MiB.
- **Serve-stale RFC 8767** (`serveStale` default true): keep expired records up to `serveStaleTtl` (259200 s = 3 days — matches RFC 8767 §4 recommendation 1–3 days); if refresh fails or takes longer than `serveStaleMaxWaitTime` (1800 ms; RFC 8767 "client response timer" suggests 1.8 s), answer stale with TTL `serveStaleAnswerTtl` (30 s, RFC 8767 recommends 30 s) and set EDE 3 "Stale Answer" (RFC 8914); on refresh failure, reset the stale record's next-try timer `serveStaleResetTtl` (30 s, "failure recheck timer"). Settings added in v12.2.
- **Prefetch** (`enableCachePrefetch`, `cachePrefetchEligibility` example 2 s = minimum original TTL to be eligible, `cachePrefetchTrigger` example 9 s = remaining TTL that triggers refresh): when a hit sees remaining TTL ≤ trigger, answer from cache and refresh in background (single-flight). "Auto prefetch" (help page): a sampled set of popular names is kept refreshed even without hits [verify algorithm: popularity sampling over last hour]. MRK: implement on-hit prefetch (MVP-P1) + top-N popular auto-prefetch (P2).
- **Persistence** (`saveCache`, v11.0): dump on graceful shutdown, reload with remaining TTLs on start (discard expired beyond serve-stale window). MRK P1; format: our own versioned CBOR/msgpack with header {schema, created_at}; ignore on mismatch.
- Cache API: list cached zones/records by name hierarchy (`/api/cache/list`), delete a subtree (`/api/cache/delete`), flush (`/api/cache/flush`).
- Single-flight: coalesce concurrent identical upstream queries (important for QPS and to avoid upstream storms).

### 3.3 Forwarders

- Global `forwarders` list (empty ⇒ full recursion), `forwarderProtocol` = `Udp|Tcp|Tls|Https|Quic` (default Udp), `forwarderRetries` (example 3), `forwarderTimeout` (example 2000 ms), `forwarderConcurrency` (example 2), `concurrentForwarding` (true ⇒ send to `forwarderConcurrency` forwarders at once, first valid answer wins; false ⇒ sequential failover). Latency-based ordering across forwarders.
- Forwarder address syntax: `1.1.1.1`, `[2606:4700::1111]:53`, DoT `cloudflare-dns.com:853 (1.1.1.1)` (hostname for SNI/cert check + bootstrap IP), DoH `https://cloudflare-dns.com/dns-query (1.1.1.1)`, DoQ `dns.adguard-dns.com:853 (ip)`. Bootstrap IP avoids chicken-and-egg resolution.
- Outbound proxy: `proxyType` None/Http (CONNECT)/Socks5 (incl. UDP associate) with `proxyBypass` list — P2 for MRK.
- Conditional forwarding via Forwarder zones (§2.1) — **MVP**.
- DNSSEC validation still applies to forwarded answers if enabled (forwarder must return DO-bit data); per-FWD `dnssecValidation` toggle.
- MRK presets per doc 22 Simple Mode: Cloudflare, Google, Quad9 (+ DoT/DoH variants) with latency test (`/api/dnsClient/resolve` equivalent).

### 3.4 EDNS Client Subnet (RFC 7871)

- Off by default (`eDnsClientSubnet` false). When on: add ECS to *outbound* queries with client prefix truncated to `eDnsClientSubnetIPv4PrefixLength` (24) / `IPv6PrefixLength` (56); optional fixed override subnets; never send ECS for private client addresses (RFC 7871 §11.3 privacy); cache entries scoped by returned SCOPE PREFIX-LENGTH (cache must be keyed by subnet when scope > 0). `enableEDnsClientSubnetSourceAddress` (v15.0): trust ECS in incoming UDP/TCP queries as client address (only from trusted proxies!).
- MRK: P2 (privacy-negative, cache complexity). Keep outbound ECS stripped by default; reject/ignore inbound ECS except from configured trusted forwarder ACL.

### 3.5 DNS Cookies (RFC 7873, RFC 9018)

- Not mentioned in Technitium changelog/docs found in this research [verify by packet capture]. Spec for MRK: implement server cookies per RFC 9018 (SipHash-2-4 based, version 1, timestamp, rotating secret) — P1. Benefits: lets the rate-limiter treat cookie-validated UDP clients as non-spoofed (exempt from TC slip), and outbound client cookies improve resolver spoof resistance. Python: `siphash24` is not in stdlib; implement SipHash-2-4 (small, public algorithm) or use HMAC-SHA256 truncated (RFC 7873 allows implementation-specific server cookie; RFC 9018 is interop recommendation for anycast clusters — single node can use HMAC).

### 3.6 Rate limiting / open-resolver protection

Technitium model (v12.0, redesigned v14.0):
- `qpmPrefixLimitsIPv4` / `qpmPrefixLimitsIPv6`: list of (prefix length, UDP QPM, TCP QPM) — e.g. /32 → 600 qpm; /24 → 6000 qpm; 0 = unlimited. Sliding window of `qpmLimitSampleMinutes` (5). Over limit: UDP requests are answered TC=1 for `qpmLimitUdpTruncationPercentage` (50 %) of them (forcing legit clients to TCP; spoofed sources can't complete TCP) and dropped otherwise; TCP over limit dropped. `qpmLimitBypassList` ACL. Dropped counts appear in stats ("Dropped"), `getTop` supports `onlyRateLimitedClients`.
- `recursion` modes (Deny / Allow / AllowOnlyForPrivateNetworks / UseSpecifiedNetworkACL) — the core open-resolver protection; non-permitted recursive queries get REFUSED (authoritative data still served).
- MRK additions (beyond parity, from BIND/Knot practice): Response Rate Limiting (RRL) for authoritative answers by (client /24, qname/type, response kind) with SLIP (TC every N) — P1; refuse ANY over UDP with minimal response (RFC 8482) — MVP; cap response size for unauthenticated UDP clients without cookies; max outstanding recursive fetches per client; deny `version.bind`/`id.server` CHAOS unless configured (RFC 4892) — MVP.
- Default (doc 22 §9): `AllowOnlyForPrivateNetworks` semantics = RFC 1918, RFC 4193 ULA, loopback, link-local, CGNAT 100.64/10 [verify CGNAT included]; MRK should show the effective ACL list in UI.

---

## 4. DNSSEC

### 4.1 Validation (RFC 4033, 4034, 4035, 5155, 6840)

Setting: `dnssecValidation` (global; per-forwarder override). Behaviour to implement:
- Trust anchor: root KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696) as DS/DNSKEY data; RFC 5011 automated trust anchor updates (P2; for MVP ship anchors with the image and update via release, plus admin-replaceable anchor file — doc 22 requires typed confirmation for trust-anchor changes).
- Chain of trust: for each zone cut from root down: fetch DS from parent (validated), fetch DNSKEY RRset of child, require a DNSKEY matching a DS (digest type 2 SHA-256 / 4 SHA-384; 1 SHA-1 accepted per RFC 8624 "MUST validate" but deprecated) that signs the DNSKEY RRset; then validate RRSIGs over answer RRsets with ZSKs.
- RRSIG checks (RFC 4035 §5.3): signer name = zone, labels count (wildcard expansion detection), inception ≤ now ≤ expiration (with small clock skew allowance), original TTL caps cached TTL, algorithm supported. Canonical form/ordering RFC 4034 §6.
- Algorithms (RFC 8624 / RFC 9904 update guidance): validate 8 RSASHA256, 10 RSASHA512, 13 ECDSAP256SHA256, 14 ECDSAP384SHA384, 15 ED25519, 16 ED448 (Technitium added Ed25519/Ed448 v13.5); 5/7 RSASHA1(-NSEC3) — treat as insecure per current guidance (RFC 9904 [verify RFC number for 2025 algorithm update]), configurable.
- Denial of existence: NSEC (RFC 4035 §5.4) — NXDOMAIN needs proof of QNAME non-existence + no wildcard; NODATA needs NSEC at QNAME without the type bit (and without CNAME). NSEC3 (RFC 5155 §8): closest-encloser proof, next-closer name covered, wildcard at closest encloser covered; opt-out handling for insecure delegations. **RFC 9276**: treat NSEC3 iterations > 0 limit — resolvers may treat high-iteration (e.g. > 100 or > 150) responses as insecure/SERVFAIL; set limit 100 → insecure, cf. CHANGELOG v12.2 fix about "unsupported iteration counts".
- Result states (RFC 4033 §5): Secure (set AD=1 when client sent DO or AD), Insecure (provable unsigned delegation via NSEC/NSEC3 for DS), Bogus (SERVFAIL + EDE code e.g. 6 DNSSEC Bogus, 7 Signature Expired, 9 DNSKEY Missing, 10 RRSIGs Missing, 1 Unsupported DNSKEY Algorithm), Indeterminate. CD=1 from client ⇒ return data without validation.
- Negative trust anchors (RFC 7646) — P2.
- Validation result is cached alongside the RRset (don't re-validate on each hit).

### 4.2 Online signing of primary zones (Technitium behaviour)

API `/api/zones/dnssec/sign`: `algorithm` = `RSA` (with `hashAlgorithm` SHA256/SHA512, `kskKeySize`, `zskKeySize`) | `ECDSA` (`curve` P256/P384) | `EDDSA` (`curve` ED25519/ED448); `dnsKeyTtl`; `zskRolloverDays`; `nxProof` = `NSEC`|`NSEC3` (+ `iterations`, `saltLength`); optional user-supplied PEM private keys (`pemKskPrivateKey`, `pemZskPrivateKey`, v13.5). Other ops: `unsign`, `viewDS`, `properties/get`, `convertToNSEC`, `convertToNSEC3`, `updateNSEC3Params`, `updateDnsKeyTtl`, `addPrivateKey` (KSK/ZSK, algorithm, size, `rolloverDays`), `updatePrivateKey` (`rolloverDays`), `deletePrivateKey` (only in Generated state), `publishAllPrivateKeys`, `rolloverDnsKey`, `retireDnsKey`. v15.0 added manual activation of KSK ("Ready → Active" without waiting for parent DS check).

Key lifecycle (states as visible in the UI/API; timing behaviour partly [verify]):
`Generated` (key exists, not in zone) → `Published` (DNSKEY in zone, not signing; waits ≥ DNSKEY TTL + propagation) → `Ready` (KSK only: published and signing DNSKEY RRset; waits for DS at parent) → `Active` (signing) → `Retired` (still published, no longer signing; waits ≥ max TTL of signatures) → removed; `Revoked` (KSK with REVOKE bit, RFC 5011) as optional exit. This matches the RFC 6781 / RFC 7583 key-timing model.
- **ZSK automatic rollover** every `zskRolloverDays` (prepublish method, RFC 6781 §4.1.1.1 / RFC 7583 §3.2): new ZSK Generated→Published; after DNSKEY TTL, becomes Active and old ZSK Retired; after max zone TTL, old removed.
- **KSK rollover** (double-KSK / double-DS, RFC 7583 §3.3): new KSK goes to Ready; server **polls parent for DS** matching the new KSK (Technitium's "Ready" state automatically transitions to Active when DS is seen at parent [verify polling interval]); then old KSK is retired. Manual activation exists (v15.0) for parents that can't be queried. MRK should additionally support CDS/CDNSKEY publication (RFC 7344, RFC 8078) so parents/registrars supporting automated DS maintenance pick it up — P2.
- Signature maintenance: RRSIG validity window (e.g. inception now−1h, expiration +N days, refresh when < ¼ remaining) [verify Technitium values]; re-sign changed RRsets synchronously in the change commit; background re-sign scheduler spreads refresh (jitter) across zone.
- Denial: NSEC chain or NSEC3 chain (RFC 5155) maintained incrementally on change; NSEC3PARAM published; RFC 9276 recommends iterations = 0, empty salt — MRK default. Opt-out not needed for small zones.
- Online signing must also cover dynamic answers (ANAME synthesis) — sign on the fly with ZSK and cache signatures.
- `viewDS`: returns DS for each KSK with digest types (SHA-256 + SHA-384) + DNSKEY for registrar paste.
- MRK workflow (doc 22 "DS/DNSKEY workflow and expiry/rollover warnings"): Sign → show DS → "I have published DS" or auto-detected DS at parent (validated query) → zone status "Secure". Alerts: DS mismatch, signature expiry < 3 days, KSK in Ready > 7 days, parent DS references missing key (would cause bogus). Unsign requires removing DS from parent first (warn and check).

Algorithm defaults for MRK: ECDSAP256SHA256 (13) KSK+ZSK (or CSK option), NSEC (or NSEC3 iter 0 if zone-walking concern), DNSKEY TTL 3600, ZSK rollover 30 days [verify Technitium default], KSK manual/annual.

---

## 5. Encrypted transports

| Transport | Standard | Technitium settings | MRK plan |
|---|---|---|---|
| DoT | RFC 7858 (+ RFC 8310 profiles), TCP framing RFC 1035 §4.2.2 + RFC 7766 pipelining/out-of-order | `enableDnsOverTls`, `dnsOverTlsPort` 853, `dnsTlsCertificatePath`/`Password` (PKCS#12 .pfx) | P1: Python `ssl` server on 853, TLS 1.2+ (1.3 preferred), ALPN `dot`, idle timeout, max queries per connection, pipelining with out-of-order replies |
| DoH | RFC 8484: `GET /dns-query?dns=<base64url no padding>` and `POST` with `application/dns-message`; HTTP/2 strongly recommended; cache-control max-age = min TTL | `enableDnsOverHttps` 443, `enableDnsOverHttp` 80 (behind proxy), `enableDnsOverHttp3`, Unix-socket variants, `dnsOverHttpRealIpHeader`, `enableDnsOverHttpHelpRedirect` (browser visits to /dns-query redirect to help page) | **MVP/P1**: engine serves plain HTTP/1.1+h2c DoH on loopback/Unix socket; MRK Edge Gateway (Caddy) terminates TLS for `dns.domain.com/dns-query` (doc 20 §2) and passes real client IP via trusted header. JSON API (`application/dns-json`, Google/Cloudflare style `?name=&type=`) is non-standard — Technitium supports it [verify]; MRK P2. |
| DoH3 | RFC 9114 HTTP/3 | `enableDnsOverHttp3` | P2 via gateway (Caddy supports HTTP/3) — no engine work |
| DoQ | RFC 9250: ALPN `doq`, one query per bidirectional stream, 2-byte length prefix, Message ID MUST be 0, error codes DOQ_NO_ERROR etc., 0-RTT only for safe queries | `enableDnsOverQuic`, `dnsOverQuicPort` 853, `quicMaxInboundStreams`, `quicIdleTimeout` | P2 via `aioquic` |
| XoT / XoQ | RFC 9103, RFC 9250 §4.4 | `zoneTransferProtocol` Tls/Quic | P2 |
| PROXY protocol | HAProxy PROXY v1/v2 | `enableDnsOverUdpProxy/TcpProxy` 538, `dnsReverseProxyNetworkACL` | P2 (only if fronted by L4 LB) |

Certificate handling:
- Technitium uses a .pfx file path + password and a self-signed fallback for the web service (`webServiceUseSelfSignedTlsCertificate`), reloads on file change [verify].
- MRK: the appliance gateway already owns ACME/certs. DoT needs the same cert for `dns.domain.com` inside the engine: Control Plane writes PEM cert+key to `/data/modules/dns/tls/` (0600, uid 10001) and signals reload (`SSLContext` rebuilt, new connections only). Support PEM (not PFX). Expose cert expiry in health. DNS-01 ACME via own engine + TSIG/RFC 2136 is a nice synergy (P1).
- Padding: EDNS(0) Padding option (RFC 7830) with block-length policy RFC 8467 (pad responses to 468 bytes) on encrypted transports — P1.

---

## 6. Blocking

Technitium built-in behaviour:
- **Blocked zones** (manual list) and **Allowed zones** (manual allow list, overrides block lists) — each entry blocks/allows the domain *and all subdomains*. APIs: `/api/blocked/{list,add,delete,flush,import,export}`, `/api/allowed/...` same.
- **Block list URLs** (`blockListUrls`), refreshed every `blockListUpdateIntervalHours` (24); `blockListNextUpdatedOn`; `/api/settings/forceUpdateBlockLists`; `/api/settings/temporaryDisableBlocking` (minutes) for "pause blocking"; `blockingBypassList` (client ACL never blocked). A URL prefixed with `!` is an allow-list URL [verify].
- Supported list formats (built-in) [verify each with fixtures]: hosts-file (`0.0.0.0 domain`, `127.0.0.1 domain`), plain domain-per-line, comment lines `#`, and simple Adblock Plus syntax `||domain^` (+ `@@||domain^` exceptions). Regex and full AdGuard syntax are handled by the separate **Advanced Blocking** DNS App (per-client-group policies, regex, adblock lists) — P2 for MRK as native "policy groups".
- `blockingType`: `AnyAddress` (documented default; A → 0.0.0.0, AAAA → ::, help page), `NxDomain`, `CustomAddress` (`customBlockingAddresses`, e.g. a block-page IP). `blockingAnswerTtl` (example 30). Blocked responses for NXDOMAIN mode include SOA of the blocked zone and an **EDE 15 "Blocked"** (RFC 8914) with the list source [verify EDE]; `allowTxtBlockingReport`: TXT query to a blocked name returns a TXT describing which list blocked it.
- Stats/query log classify `Blocked` (local), `UpstreamBlocked` (upstream returned 0.0.0.0/:: or blocking-style NXDOMAIN), `CacheBlocked`.

MRK implementation:
- Data structure: reversed-label hash set (`set` of normalised names) + suffix walk (≤ 127 lookups, typically 2–5) — O(labels). 1M-domain lists ≈ 80–120 MB in CPython `set[str]`; to cap memory, store as sorted array of reversed names in a `bytes` blob with bisect, or use a compact `marisa-trie` (MIT/LGPL dual? — check; prefer our own sorted-blob approach, no dependency). Target MVP: up to 2M entries < 150 MB.
- Download with SSRF guard (doc 20 §10), size limit (e.g. 64 MB), ETag/If-Modified-Since, atomic swap of the in-memory set (build new, swap reference), keep last good copy on failure.
- Precedence: authoritative zones > allow list > bypass client > block list > recursion. Blocking applies to CNAME targets too (block if any name in the resolved chain is blocked — Technitium does this [verify]; important for CNAME-cloaked trackers).
- Priority: manual block/allow + URL lists + AnyAddress/NXDOMAIN/Custom = **P1** (doc 22 lists blocklist in D3). Regex/per-client groups = P2.

---

## 7. Query logging and statistics

Technitium:
- Logging: `loggingType` None/File/Console/FileAndConsole; `logQueries` (default false) logs every query/answer to the text log; `ignoreResolverLogs`; `useLocalTime`; `maxLogFileDays`. Logs APIs `/api/logs/{list,download,delete,deleteAll}`.
- Queryable query log is provided by a DNS App (e.g. "Query Logs (Sqlite)") and accessed via `/api/logs/query` with `name`+`classPath` of the app; filters: `start`, `end` (ISO 8601), `clientIpAddress`, `protocol` (Udp/Tcp/Tls/Https/Quic), `responseType` (Authoritative/Recursive/Cached/Blocked/UpstreamBlocked/CacheBlocked), `rcode`, `qname`, `qtype`, `qclass`; paging `pageNumber`, `entriesPerPage`, `descendingOrder`. Entry fields: `rowNumber, timestamp, clientIpAddress, protocol, responseType, responseRtt, rcode, qname, qtype, qclass, answer`. `/api/logs/export` → CSV.
- Stats: `/api/dashboard/stats/get?type=LastHour|LastDay|LastWeek|LastMonth|LastYear|Custom&start&end&utc`. Counters + `mainChartData` time series datasets: **Total, No Error, Server Failure, NX Domain, Refused, Authoritative, Recursive, Cached, Blocked, Dropped, Clients** (unique clients); pie charts `queryResponseChartData` (by response type), `queryTypeChartData` (by QTYPE, top N with "others" unless `dontTrimQueryTypeData`), `protocolTypeChartData`; top lists `topClients`, `topDomains`, `topBlockedDomains` (`/api/dashboard/stats/getTop` with `limit`, `noReverseLookup`, `onlyRateLimitedClients`). Also counters for zones, cached entries, allowed/blocked zones count. Resolution: per-minute buckets for LastHour, hourly for day/week, daily for month/year (inferred from chart granularity) [verify]. Stats retained `maxStatFileDays` (example 365); `enableInMemoryStats` (no disk). `/api/dashboard/stats/deleteAll`. Experimental `/api/dashboard/metrics/json` and `/metrics/text` (Prometheus exposition, lifetime counters).

MRK:
- Hot path: increment in-process counters only (per-minute bucket struct: totals per rcode, per response type, per qtype, per protocol, HyperLogLog or capped set for unique clients, Space-Saving/Count-Min top-K for domains/clients/blocked). Flush minute buckets to `stats/` (JSON or SQLite table `minute_stats`), roll minutes → hours (keep 48 h of minutes) → days (keep per retention). Avoid writing per-query rows when query logging off.
- Query log (opt-in, doc 22 §9 privacy): async batched inserts into SQLite WAL via a dedicated thread (queue with bounded size; on overflow drop + count drops — never block DNS); fields as above plus `latency_ms`, `dnssec_status`, `blocked_by_list`, `upstream`; retention by days and by max rows; optional IP redaction (truncate to /24 and /48) and per-role access in Control Plane. Export CSV.
- Prometheus metrics endpoint on control socket (QPS, latency histograms, cache hit ratio, SERVFAIL, upstream RTT, event-loop lag, memory) — feeds doc 22 §8 metrics.
- Priority: stats + dashboard = **MVP** (doc 22 Simple Mode Dashboard), query log = P1, Prometheus = P1.

---

## 8. DHCP and clustering (brief; P2)

DHCP (Technitium): DHCPv4 server (RFC 2131/2132) with multiple scopes (`/api/dhcp/scopes/{list,get,set,enable,disable,delete,addReservedLease,removeReservedLease}`, leases list/remove/convertToReserved/convertToDynamic). Scope params: range/mask, lease time, offer delay (for secondary DHCP), ping-check before offer, domain name & search list (RFC 3397), `dnsUpdates` (auto-create A/PTR in local zones with `dnsTtl`, `dnsOverwriteForDynamicLease`), router, DNS/WINS/NTP servers, static routes (RFC 3442 option 121), vendor info, CAPWAP, TFTP (option 150), PXE fields (`serverAddress`, `bootFileName`), generic options, exclusions, reservations, `allowOnlyReservedLeases`, `blockLocallyAdministeredMacAddresses`, `ignoreClientIdentifierOption`. Requires raw broadcast UDP 67 on the LAN ⇒ container needs host networking or macvlan + `NET_BIND_SERVICE`/`NET_RAW` — conflicts with cap_drop ALL. **MRK: defer (P2), not in single-container default.** If needed, implement only reservation-less DDNS ingestion from an external DHCP server via RFC 2136 + TSIG instead.

Clustering (Technitium v14.0+): one Primary node + Secondary nodes; join via `initJoin` with primary URL + admin credentials (+TOTP); config replicated (settings, zones as catalog-backed secondaries, users, blocklists) with heartbeat/config refresh intervals; nodes identified by certificate; aggregate dashboards (`node` param on stats/sessions); `promote` secondary to primary for failover. **MRK: P2 / out of scope** for single-node appliance (doc 22 says no HA claim without second member). Native equivalent later: standard primary/secondary zones via AXFR/IXFR + catalog zones (RFC 9432) + Control Plane-level config sync — standards-based, no proprietary protocol.

---

## 9. HTTP admin API surface — parity groups

Technitium API style: `GET/POST /api/<group>/<action>?token=…` returning `{"status":"ok"|"error"|"invalid-token", "response":{…}, "errorMessage":…}`. MRK should **not** copy the style; expose REST under Control Plane `/api/v1/dns/...` (doc 22 §7 adapter, allowlisted, DTOs) and an internal engine API over Unix socket. Grouped capability list for parity mapping (`native/adapted/mrk/deferred/not-applicable`, doc 22 §12):

| Group | Technitium endpoints | MRK need |
|---|---|---|
| Auth/users/sessions/2FA/SSO/groups/permissions | `user/login, logout, createToken, createSingleUseToken, session/get|delete, changePassword, 2fa/init|enable|disable, profile/get|set, checkForUpdate`; `admin/sessions/*`, `admin/users/*`, `admin/groups/*`, `admin/permissions/*`, `admin/sso/*` | **not-applicable** — MRK core auth/RBAC (`dns:<resource>:<action>`) replaces |
| Status/health | `status`, `dnsClient/healthCheck` | MVP (health/ready) |
| Dashboard | `dashboard/stats/get`, `stats/getTop`, `stats/deleteAll`, `metrics/json`, `metrics/text` | MVP (stats, top), P1 (metrics) |
| Zones | `zones/list, catalogs/list, create, import, export, clone, convert, enable, disable, delete, resync, options/get, options/set, permissions/get|set` | MVP: list/create/delete/enable/disable/import/export/options; P1: clone/convert/resync; permissions → MRK RBAC |
| Records | `zones/records/add, get, update, delete` (all types §2.5) | MVP (+ atomic batch change set — MRK addition) |
| DNSSEC | `zones/dnssec/sign, unsign, viewDS, properties/get, convertToNSEC|NSEC3, updateNSEC3Params, updateDnsKeyTtl, addPrivateKey, updatePrivateKey, deletePrivateKey, publishAllPrivateKeys, rolloverDnsKey, retireDnsKey` (+ manual KSK activate v15.0) | P1 |
| Cache | `cache/list, delete, flush` | MVP |
| Allowed/Blocked | `allowed/*`, `blocked/*` (list/add/delete/flush/import/export) | P1 |
| Settings | `settings/get, set, getTsigKeyNames, forceUpdateBlockLists, temporaryDisableBlocking, backup, restore` | MVP (subset: listeners, recursion ACL, forwarders, cache, logging), P1 rest; backup/restore → MRK module backup contract |
| DNS client | `dnsClient/resolve` (any server, any protocol, optional import into zone) | MVP (query test tool, doc 22 D2) |
| Apps | `apps/list, listStoreApps, downloadAndInstall, downloadAndUpdate, install, update, uninstall, config/get|set` | not-applicable (built-in handlers only, P2) |
| Logs | `logs/list, download, delete, deleteAll, query, export` | P1 |
| DHCP | `dhcp/leases/*`, `dhcp/scopes/*` | deferred P2 |
| Cluster | `admin/cluster/*` (state, init, join, leave, promote, resync, transferConfig, …) | deferred P2 |

Settings parity subset for MVP (MRK names in parentheses suggested): `dnsServerLocalEndPoints` (listeners), `recursion` + `recursionNetworkACL`, `forwarders` + `forwarderProtocol` + `concurrentForwarding` + retries/timeout/concurrency, `qnameMinimization`, `randomizeName`, `dnssecValidation`, `udpPayloadSize`, `clientTimeout`, cache (`cacheMaximumEntries`, min/max/negative/failure TTL, `serveStale*`, prefetch), zone defaults (default TTLs, responsible person, serial date scheme), `locallyServedDnsZones`, QPM limits, logging/stats retention.

---

## 10. Python implementation approach (clean-room engine)

### 10.1 Runtime design

- **asyncio + uvloop** (MIT/Apache-2.0). UDP via `loop.create_datagram_endpoint` with a `DatagramProtocol` whose `datagram_received` does the **synchronous fast path** (cache/authoritative hit → `transport.sendto` without creating a Task); only misses spawn a Task. TCP/DoT via `asyncio.start_server` with length-prefixed framing, pipelining, per-connection concurrency cap, idle timeouts (RFC 7766 §6.2).
- **Multi-process scaling**: N workers each binding UDP/TCP 53 with `SO_REUSEPORT` (Linux kernel load-balances by 4-tuple hash). Caches are per worker (simple, no locks); authoritative zone data is loaded per worker from the same files and reloaded on a control-socket "zone changed" broadcast (or mmap'd read-only snapshot, P2). Stats aggregated by the control process. MVP: N=1 (single process) — enough for an appliance.
- CPU-bound crypto (RSA signing of large zones, NSEC3 hashing on bulk import) runs in a `ProcessPoolExecutor`/thread (cryptography releases the GIL for OpenSSL calls).
- Python 3.13 free-threaded build: not recommended yet (C extension readiness); revisit.
- Blocking I/O (SQLite query log, file writes) on dedicated threads with bounded queues.

### 10.2 Libraries (permissive only — verify licences in SBOM at pin time)

| Need | Library | Licence | Use |
|---|---|---|---|
| Wire format, rdata types, zone file parse/emit, TSIG, DNSSEC sign/validate primitives, EDNS options, IXFR/AXFR helpers | **dnspython** ≥ 2.7 | ISC | Core codec + `dns.zone`, `dns.tsig`, `dns.dnssec` (sign/validate RRsets, `make_ds`, NSEC3 hash), `dns.message`, `dns.asyncquery` (for outbound UDP/TCP/DoT/DoH/DoQ client side), `dns.versioned.Zone` (transactional zone with versions — good basis for change sets + IXFR journal). Wire parsing in pure Python is the main CPU cost. |
| Crypto | **cryptography** | Apache-2.0 / BSD | RSA, ECDSA P-256/384, Ed25519/Ed448 (used by dnspython DNSSEC), AES-GCM key wrapping, HMAC |
| DoQ / HTTP/3 | **aioquic** | BSD-3-Clause | DoQ server (RFC 9250) and DoQ forwarder client; dnspython already uses it for client DoQ |
| DoH client (forwarders) | **httpx** (BSD-3) + **h2** (MIT) | permissive | dnspython's DoH client uses httpx |
| DoH server | `aiohttp` (Apache-2.0) or `hypercorn` (MIT) or minimal own HTTP/1.1 handler on Unix socket behind gateway | permissive | gateway terminates TLS/h2; engine needs only HTTP/1.1 |
| Event loop | **uvloop** | MIT / Apache-2.0 | 2–4× loop throughput |
| Serialisation | `msgpack` (Apache-2.0) or `cbor2` (MIT) | permissive | cache snapshot |
| Storage | stdlib `sqlite3` | public domain | query log, stats |
| IDNA | `idna` | BSD-3 | IDNA2008 for API inputs |
| SipHash for cookies | implement (≈40 lines) or HMAC | — | RFC 9018 |

Avoid: Twisted names (MIT, fine licence but heavy), any GPL resolver lib, `pycares` not needed.

### 10.3 Build ourselves vs library

Build ourselves (core value, small):
- Request pipeline, ACL engine, rate limiter (token/sliding window per prefix), blocking engine (compact suffix set), cache (LRU, serve-stale, prefetch, single-flight, negative cache, ECS scoping), iterative resolver state machine (QNAME minimisation, server selection/RTT, bailiwick, 0x20, fetch limits), forwarder manager, DNSSEC **validator orchestration** (chain building, NSEC/NSEC3 proof logic; use dnspython only for RRSIG/DS crypto verify and NSEC3 hash), signer **policy/key lifecycle scheduler**, NOTIFY/refresh state machines, IXFR journal, RFC 2136 processor, stats aggregation, query log writer, control API.
- A hand-written **fast-path codec** for the hot query path: parse header + single question + OPT directly from bytes (≈ 2–5 µs vs ≈ 40–80 µs for `dns.message.from_wire`), cache answers as pre-rendered wire bytes per (qname-lower, qtype, DO-bit, class) with TTL offsets recorded so TTLs are decremented by patching bytes, and the ID + question case (0x20 inbound echo) patched in place. Fall back to dnspython for everything non-trivial.

Use library: all rdata type codecs and text presentation (dnspython), zone file parsing, TSIG signing/verifying, DNSSEC primitive crypto, outbound DoT/DoH/DoQ clients, QUIC stack.

### 10.4 Performance expectations (CPython 3.12/3.13, single core, uvloop) — estimates, to be benchmarked with `dnsperf`/`flamethrower`

| Path | Est. QPS per core |
|---|---|
| Naive: `dns.message.from_wire` + `make_response` + `to_wire` per query | ~3k–8k |
| Optimised fast path (raw-bytes cache hit, no Task) | ~25k–50k |
| Authoritative hit via pre-rendered wire cache | ~25k–40k |
| Cache miss (recursion) | bound by upstream latency; 1–3k concurrent resolutions per process fine |
| DoT/TCP (pipelined) | ~10k–20k |
| DoH via gateway | ~3k–8k (HTTP overhead) |

Need: an appliance serving an office/LAN is typically 50–2,000 QPS; even a busy SMB < 10k QPS. MVP with single process and fast path has 10× headroom; SO_REUSEPORT workers scale linearly-ish. It will not match Technitium/.NET (~100k+ QPS) or Unbound/Knot, which is acceptable; document the limit and keep the rate-limiter in front of expensive paths. Memory budget: base ~60–80 MB + cache (~1 KB/entry incl. Python overhead → 100k entries ≈ 100 MB) + block lists.

Load-test plan: dnsperf cached-hit test, resperf for recursive ramp, authoritative 100k-RR zone, 1M blocklist, soak 24 h, event-loop lag < 10 ms p99 at 5k QPS.

### 10.5 Container constraints (uid 10001, cap_drop ALL)

Binding ports < 1024 (53, 853, 443) without root:
1. **Preferred: `sysctls: net.ipv4.ip_unprivileged_port_start: "53"`** in `compose.production.yaml`. This sysctl is network-namespaced (Linux ≥ 4.11), allowed by Docker/containerd as a "safe" namespaced sysctl, requires no capability, applies only inside the container's netns, and also covers IPv6 sockets. Does **not** work with `network_mode: host` (would change host setting — and Docker rejects it). Kubernetes: allowed as safe sysctl since 1.22.
2. **Alternative: listen on high ports (5353/udp+tcp, 8853) and publish `53:5353/udp`, `53:5353/tcp`, `853:8853/tcp`** — zero privilege, works everywhere except host networking; source IPs preserved with default userland-proxy disabled/iptables DNAT (Docker's iptables mode preserves client IP for UDP; `userland-proxy` for loopback may hide it). Good fallback and default for dev `compose.yaml`.
3. **CAP_NET_BIND_SERVICE**: `cap_add: [NET_BIND_SERVICE]` alone is insufficient for a non-root uid (capabilities are dropped on exec for non-root unless ambient/file caps). Would require `setcap cap_net_bind_service=+ep` on the Python interpreter (grants every Python process in the image the cap — poor least-privilege, and file caps break with `no-new-privileges`). Not recommended.
4. DHCP (P2) would additionally need host networking/`NET_RAW` — reason to keep DHCP out.

Other constraints: read-only root FS compatible (all writes under `/data/modules/dns` and `/run`); supervisord program `dns-engine` with its own health (`/internal/health/ready` = loopback DNS probe of a canary record in an internal zone `health.mrk.internal.` + upstream reachability), crash-loop policy per doc 20 §5; graceful shutdown: stop accepting, drain TCP/DoT ≤ 5 s, snapshot cache, flush stats.

Security defaults: recursion = private networks only; transfers/updates deny; CHAOS version queries refused; ANY minimal; no ECS outbound; query log off; QPM default 600/min per /32 IPv4, /56 IPv6 [MRK choice]; SSRF guard on blocklist URLs and forwarders' DoH bootstrap.

---

## 11. Feature ranking for a single-node appliance

### MVP (D2 "Simple DNS" — engine usable on a LAN)
- UDP/TCP 53 listener (sysctl or port-map), EDNS0, truncation, RFC 7766 TCP, ANY minimal (RFC 8482), CHAOS refusal.
- Network ACLs; recursion modes with default private-only; REFUSED otherwise.
- Primary zones: create/delete/enable/disable, import/export RFC 1035, records CRUD for A, AAAA, CNAME, MX, TXT, NS (delegation+glue), PTR (+auto PTR), SRV, CAA, SOA edit; wildcard, CNAME rules, empty non-terminals; serial auto-increment (RFC 1982), atomic change sets + snapshot/revision.
- Forwarder (conditional forwarder) zones with FWD over UDP/TCP + local overrides.
- Recursive resolver: iterative from root hints with QNAME minimisation, 0x20, bailiwick checks, fetch limits; global forwarders UDP/TCP/DoT with sequential or concurrent mode; presets + latency test.
- Cache: positive/negative (RFC 2308), min/max TTL clamp, max entries LRU, serve-stale (RFC 8767), on-hit prefetch, single-flight, list/delete/flush.
- DNSSEC validation (RFC 4033–4035, 5155, RFC 9276 limits) with built-in root anchors; AD/CD handling; EDE codes (RFC 8914).
- Locally served zones (RFC 6303/6761).
- QPM rate limiting with UDP TC slip.
- Stats aggregation + dashboard API (time series, response/qtype/protocol breakdown, top clients/domains), health/readiness, DNS client query tool.
- DoH (RFC 8484 GET/POST) on loopback behind Edge Gateway `dns.domain.com/dns-query`.

### P1 (D3 "Advanced DNS")
- Secondary and Stub zones; AXFR/IXFR serve + pull; NOTIFY send/receive; TSIG (RFC 8945); IXFR journal.
- RFC 2136 dynamic update with TSIG + per-key name/type policies (ACME DNS-01).
- DNSSEC online signing: ECDSA P-256/P-384, Ed25519, RSA-SHA256; NSEC and NSEC3 (iter 0); ZSK auto rollover; KSK double-DS with parent DS polling + manual activate; viewDS; expiry alerts; key encryption at rest.
- ANAME, DNAME, SVCB/HTTPS (with auto hints), TLSA, SSHFP, DS, URI, NAPTR, RP, unknown-type RFC 3597; per-record disable/comment/expiry.
- DoT listener (RFC 7858) with gateway-issued cert + reload; EDNS padding (RFC 7830/8467); DoH/DoQ forwarders.
- Blocking: manual block/allow, URL lists (hosts/domain/adblock-basic), AnyAddress/NXDOMAIN/Custom, bypass ACL, temporary disable, TXT report, CNAME-chain blocking.
- Query log (SQLite, retention, redaction, CSV export), Prometheus metrics, cache persistence across restart, DNS cookies (RFC 7873/9018), authoritative RRL.
- Zone clone/convert/resync; zone file raw editor with parse/validate/diff.

### P2 (D4/D5 and beyond)
- DoQ server (RFC 9250), DoH3 (via gateway), XoT/XoQ (RFC 9103), PROXY protocol listeners.
- Catalog zones (RFC 9432), ZONEMD (RFC 8976), local root mirror (RFC 8806), RFC 5011 trust-anchor maintenance, NTA (RFC 7646), aggressive NSEC (RFC 8198), CDS/CDNSKEY (RFC 7344/8078).
- EDNS Client Subnet (RFC 7871), outbound HTTP/SOCKS5 proxy, auto-prefetch of popular names, JSON DoH API.
- Advanced blocking (regex, per-client-group policies), built-in dynamic-answer handlers (failover/geo/split-horizon/weighted) replacing "APP" records.
- Multi-worker SO_REUSEPORT scaling; SQLite-backed large zones.
- DHCP (or DDNS ingestion only), clustering / multi-node (standards-based secondaries + catalog + Control Plane sync).

Not applicable: Technitium user/session/2FA/SSO/permission APIs (MRK core), DNS App store / arbitrary assemblies, SecondaryForwarder proprietary replication, Technitium cluster protocol.

---

## 12. Open items / verification backlog

1. Black-box verify [verify]-tagged behaviours against a pinned Technitium v15.6.x in a throwaway container (packet captures, API responses) — **without reading source**: ACL syntax/first-match, blocklist formats accepted, CNAME-chain blocking, EDE codes emitted, cookie support, ANAME AXFR type code, DNSSEC key-timing intervals and DS polling interval, ZSK rollover default, RRSIG validity window, stats bucket granularity, auto-prefetch algorithm, JSON DoH support.
2. Confirm RFC number of the 2025 DNSSEC algorithm-recommendation update replacing RFC 8624 (cited above as RFC 9904 — verify).
3. Benchmark the fast-path codec design early (PoC: 1-day spike) to validate the 25k+ QPS/core estimate.
4. Decide Compose default: sysctl `ip_unprivileged_port_start=53` (production) vs port-map (dev); update doc 22 §6/§13 accordingly.
5. ADR: "native clean-room DNS engine instead of embedded Technitium" — records licence rationale, scope (this spec), and clean-room process (no source access, RFC-derived tests).
