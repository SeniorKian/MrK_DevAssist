# Uptime Kuma 2.x behavioural spec for a clean-room re-implementation

Target: a native MRK module (`uptime_*` namespace, Python/FastAPI + SQLAlchemy + React) inside the single-container appliance. The container runs `cap_drop: ALL` as uid 10001. Scope comes from `docs/21-uptime-monitoring-module.md` and docs/20 (archived, see docs/03) (module id `uptime`, dataRoot `/data/modules/uptime`, routes `panel/uptime/*` and `status.domain.com`, PGlite/PostgreSQL namespace `uptime_*`).

Source: `louislam/uptime-kuma` `master` branch (2.x line), read on 2026-11-08 through raw.githubusercontent.com. Uptime Kuma is MIT-licensed. This document describes **behaviour only**; it contains no code to copy. Base URL for references: `https://github.com/louislam/uptime-kuma/blob/master/`. Each item is marked:

- **[V]**: verified in the source file named.
- **[I]**: inferred, or from memory of earlier versions, or from secondary sources. Re-check these against the pinned tag before relying on them.

> Note on doc 21: that document plans to run upstream behind a `UptimeAdapter`. This research supports the alternative, a native re-implementation. The two approaches conflict, and an ADR should record the decision.

---

## 0. Status constants and vocabulary [V] (`src/util.ts`)

| Constant | Value |
|---|---|
| DOWN | 0 |
| UP | 1 |
| PENDING | 2 |
| MAINTENANCE | 3 |
| STATUS_PAGE_ALL_DOWN / ALL_UP / PARTIAL_DOWN / MAINTENANCE | 0 / 1 / 2 / 3 |
| MIN_INTERVAL_SECOND | 1. The UI warns when the interval is under 20 s. Demo mode forces at least 20 s. |
| INCIDENT_PAGE_SIZE | 10 |
| RESPONSE_BODY_LENGTH_DEFAULT / MAX | 1024 / 1 048 576 bytes |
| Ping packet size | min 1, max 65500, default 56 |
| Ping global timeout (deadline), seconds | min 1, max 300, default 10 |
| Ping count | min 1, max 100. The backend default is 1; the UI default for a new monitor is 3. |
| Ping per-request timeout, seconds | min 1, max 60, default 2 |
| Badge colours | up `#66c20a`, warn `#eed202`, down `#c2290a`, pending `#f8a306`, maintenance `#1747f5`, N/A `#999`, ping `blue`; default style `flat` |
| Cert badge thresholds | warn at 14 days, down at 7 days |
| SQL datetime format | `YYYY-MM-DD HH:mm:ss` (UTC) |

---

## 1. Scheduling loop and state machine

Primary source: `server/model/monitor.js` [V], with `server/server.js` and `server/start-monitors.ts` [V].

### 1.1 Process model
- There is one Node process. Every active monitor is an in-memory object in `server.monitorList[id]` that owns a single `setTimeout` chain. There is no worker pool, queue or global concurrency cap. Concurrency equals however many timers fire at once, and all I/O is async on one event loop.
- **Boot** [V] (`server.js`):
  - Runs `R.find("monitor", "active = 1")`.
  - Processes the list in **chunks of 50**. Within a chunk it calls `Promise.allSettled(monitor.start(io, firstBeatDelayMs(interval)))`. Chunks run one after another with no sleep between them.
  - Background jobs start after that.
- **First-beat jitter** [V] (`start-monitors.ts`): `delay = min(max, floor(random()*(max+1)))`, where `max = max(1, interval)*1000` ms. The first check of each monitor therefore lands uniformly within `[0, interval]` after boot.
  - **Push monitors** do not use this jitter. Their first evaluation always waits `interval*1000` ms, which gives the client time to push.
  - When the user starts or edits a monitor, it beats immediately (`firstBeatDelayMs` = 0).
- **Restart semantics:** no scheduler state is persisted. The only state carried across a restart is restored lazily on the first beat from the **latest heartbeat row** (`SELECT … ORDER BY id DESC LIMIT 1`): `retries`, `downCount` and the previous `status` used for importance.
  - Because of this, a restart does **not** re-notify if the status is unchanged. Exception: "first beat" logic applies only when the monitor has *no* heartbeat at all.
  - **[I]** Checks that were in flight when the process stopped are simply lost. No catch-up runs for missed intervals.
- **Shutdown** [V]:
  - `graceful-shutdown` on SIGINT/SIGTERM with a 30 s timeout and force-exit.
  - Sequence: `server.stop()` → stop every monitor (`clearTimeout`, `isStop = true`) → sleep 2 s → close the DB (`PRAGMA wal_checkpoint(TRUNCATE)` on SQLite) → stop embedded MariaDB → stop jobs.
- **Pause and resume** [V]:
  - Pause sets `monitor.active = 0` and calls `stop()`.
  - Resume (`startMonitor`) sets `active = 1`, stops any old instance, creates a new object and calls `start()`.
  - Edit restarts the monitor when it is active **and all its ancestors are active** (`Monitor.isActive` = `active && isParentActive`, recursive).

### 1.2 beat() algorithm [V]
Each tick runs the following steps:

1. **Effective interval.** `beatInterval = interval || 1`.
2. **Default timeout.** If `timeout` is unset or ≤ 0, use `interval * 0.8` seconds. The UI also clamps timeout to `floor(interval*8)/10` for non-ping types.
   - UI defaults per type: 48 s for most types, 10 for ping, 5 for snmp, 1 for kafka-producer.
   - For ping, the UI *raises the interval* rather than clamping the timeout.
3. **Load the previous beat.** Use the cached value if present. Push monitors always reload it. Set `retries = previousBeat?.retries ?? 0` and `isFirstBeat = !previousBeat`.
4. **Create the bean.** Start with `status = DOWN` by default and `time = now (UTC)`. Copy `downCount` from the previous beat.
5. **Maintenance check.** If `Monitor.isUnderMaintenance(id)` is true, set `status = MAINTENANCE`, `msg = "Monitor under maintenance"` and **skip the actual check**.
   - The check is true if any linked maintenance (`monitor_maintenance`) has `getStatus() == "under-maintenance"`, or, recursively, if the **parent** group monitor is under maintenance.
6. **Otherwise, run the check** for the monitor's type (section 2). A check *succeeds* by setting `bean.status = UP`, `bean.msg` and `bean.ping` (ms). It *fails* by throwing; the exception message becomes `bean.msg`.
   - Plugin-style types (`monitorTypeList`) may set a non-UP status only when `allowCustomStatus` is set; otherwise a non-UP result is converted to an error.
   - **Upside-down mode** applies after a *successful* check: UP flips to DOWN by throwing `"Flip UP to DOWN"`. In the catch path, a failure under upside-down becomes UP with `retries = 0`. Effectively the status is inverted and the original error text is kept as the message.
   - An abort or timeout produces `msg = "timeout by AbortSignal (<timeout>s)"`. HTTP uses an extra signal at `(timeout+10)` s as a hard stop in addition to the axios timeout.
7. **Retry state machine.** This runs in the catch block, after any upside-down UP short-circuit.
   - **json-query with `retry_only_on_status_code_failure`:** a "JSON query does not pass" error sets `retries = 0` and goes **DOWN immediately**.
   - **Otherwise:**
     - If `maxretries > 0 && retries < maxretries`: `retries++` and `status = PENDING`.
     - Else: `retries++` and the status stays DOWN. The counter keeps growing while DOWN.
   - On success, `retries = 0` **[I]**: the success path resets it.
   - `bean.retries = retries` is persisted.
8. **Importance and notifications.** See §1.3.
9. **Persist the beat.**
   - `bean.end_time = UptimeCalculator.update(status, ping)`.
   - Emit the heartbeat over Socket.IO, then `sendStats` (only if clients are subscribed to the room).
   - Store the bean, then update Prometheus gauges. Cache it as `previousBeat`.
   - **Push monitors that remain UP store nothing** (see §2.4).
10. **Schedule the next beat.**
    - If the status is PENDING and `retryInterval > 0`, use `beatInterval = retryInterval`.
    - `next = max(1, beatInterval*1000 - (now - bean.time))` ms. The interval is measured from beat *start*, so check duration is subtracted. A check that takes longer than the interval runs back-to-back after a 1 ms gap. Overlap is impossible because the next timer is armed only after the current beat finishes.
    - `safeBeat` wraps `beat`. On an unexpected exception it logs and re-arms after `interval*1000`.

### 1.3 Importance, notifications, resend [V]
`isImportantBeat(isFirstBeat, prev, cur)` decides whether `heartbeat.important = 1`. These rows are kept long-term (see §3.4). It is true when any of these hold:

- first beat;
- DOWN→MAINT, UP→MAINT, MAINT→DOWN, MAINT→UP;
- UP→DOWN, DOWN→UP;
- PENDING→DOWN.

The following transitions are **not** important: UP→PENDING, PENDING→UP, PENDING→PENDING, same→same, PENDING→MAINT, MAINT→PENDING.

`isImportantForNotification` decides when a notification is sent. It is true for:

- first beat;
- MAINT→DOWN, UP→DOWN, DOWN→UP, PENDING→DOWN.

Entering or leaving maintenance into UP is important but does **not** notify. Recovery from PENDING to UP never notifies; this is the "flap absorbed by retries" behaviour.

Additional rules:

- `sendNotification` runs only when `!isFirstBeat || status == DOWN`. A brand-new monitor that comes up UP does not announce itself.
- On an important beat:
  - Set `important = true`.
  - Notify if qualifying.
  - Reset `downCount = 0`.
  - Clear the API response cache (status pages and badges).
  - Push the maintenance list to dashboards.
- On a non-important beat:
  - Set `important = false`.
  - If `status == DOWN && resendInterval > 0`, increment `downCount`. When `downCount >= resendInterval`, re-send the DOWN notification and reset `downCount = 0`.
  - `resendInterval` is therefore measured in **number of consecutive DOWN beats**, not minutes. `0` means never resend.
- Message text is `"[<monitor name>] [✅ Up|🔴 Down] <bean.msg>"`.
  - `heartbeatJSON` is augmented with `msg` (default "N/A"), `timezone`, `timezoneOffset` and `localDateTime`.
  - On UP, it also gets `lastDownTime`, the time of the last important DOWN beat.
- Recipients: `SELECT notification.* FROM notification JOIN monitor_notification WHERE monitor_id = ?`. Each provider is called independently. A failure is logged and **not retried**.
- Separate expiry channels:
  - TLS certificate expiry: §2.1.
  - Domain expiry (`domainExpiryNotification`, WHOIS/RDAP-based, skipped in MAINTENANCE).

### 1.4 State machine summary

```
               check ok                         check fail
 (any) ───────────────────────► UP      ──► retries<max ? PENDING(retries+1) : DOWN(retries+1)
 under maintenance window ────► MAINTENANCE (check not executed)
 upsideDown: invert ok/fail before the retry step; fail-as-up resets retries
 next delay = (PENDING && retryInterval>0) ? retryInterval : interval
```

---

## 2. Monitor types

The type registry is `server/monitor-types/*.js` [V]:

> dns, gamedig, globalping, group, grpc (gRPC keyword), manual, mongodb, mqtt, mssql (sqlserver), mysql, ntp, oracledb, ping, pm2, postgres, rabbitmq, real-browser, redis, sftp, sip-options, smtp, snmp, steam, system-service, tailscale-ping, tcp ("port"), websocket-upgrade

`monitor.js` itself handles `http`, `keyword`, `json-query`, `push`, `docker`, `radius` and `kafka-producer`.

UI groups (`src/pages/EditMonitor.vue`):

- **General:** HTTP(s), HTTP(s)-Keyword, TCP Port, Ping, DNS, Docker Container, System Service (hidden in a container), PM2, HTTP(s)-Browser Engine, Websocket Upgrade, SFTP.
- **Special:** Group.
- **Passive:** Push, Manual.
- **Specific:** Globalping, gRPC(s)-Keyword, HTTP(s)-Json Query, Kafka Producer, MQTT, NTP, RabbitMQ, SIP Options, SMTP, SNMP, Tailscale Ping (hidden in a container).
- **Database:** MSSQL, MongoDB, MySQL/MariaDB, Oracle, PostgreSQL, Radius, Redis.
- **Game:** GameDig, Steam.

New-monitor UI defaults [V]:

| Field | Default |
|---|---|
| type | http |
| interval | 60 |
| retryInterval | 60 (follows interval while still equal to it) |
| resendInterval | 0 |
| maxretries | 0 |
| maxredirects | 10 |
| accepted_statuscodes | `["200-299"]` |
| ignoreTls | false |
| upsideDown | false |
| expiryNotification | false |
| dns_resolve_type | A |
| dns_resolve_server | "" (UI suggests `1.1.1.1`) [I] |
| ping_count | 3 |
| ping_numeric | true |
| packetSize | 56 |
| ping_per_request_timeout | 2 |
| notificationIDList | pre-checked with every notification where `isDefault = true` (new monitors only; not on edit or clone) |

**Framework note [V/I]:** plugin `check()` implementations (tcp, smtp, postgres, redis, grpc and others) mostly **do not enforce `monitor.timeout` themselves**; they rely on library defaults. The native version should wrap *every* check in `asyncio.wait_for(timeout)` as a deliberate improvement.

### 2.1 HTTP / keyword / json-query [V] (`monitor.js`)
- **Request:** method, URL, JSON `headers`, and `body`.
  - `httpBodyEncoding` = `json` (default) parses the body, sends `application/json` and errors with "Your JSON body is invalid". `form` sends `application/x-www-form-urlencoded`. `xml` sends `text/xml; charset=utf-8`.
  - `cacheBust` adds a random `uptime_kuma_cachebuster` query parameter.
- **Client options:**
  - `timeout = timeout*1000`, plus an abort signal at `(timeout+10)` s.
  - `maxRedirects = maxredirects`; 0 means do not follow.
  - `validateStatus = checkStatusCode(status, accepted_statuscodes_json)`.
  - Keep-alive agents are cached per monitor.
  - HTTPS agent: `rejectUnauthorized = !ignoreTls`, `maxCachedSessions: 0`, legacy-renegotiation allowed (`SSL_OP_LEGACY_SERVER_CONNECT`), `autoSelectFamily`.
  - `ipFamily` = `ipv4` forces family 4; `ipv6` forces 6.
  - Proxy: `proxy_id` points at the `proxy` table (http/https/socks*), optionally with auth.
- **checkStatusCode** [V] (`server/util.ts`): the accepted list holds strings. `"200"` is an exact match and `"200-299"` is an inclusive range. Invalid entries are skipped, and an empty list never matches.
- **Auth methods** (`auth_method`):
  - `null`: none.
  - `basic`: `Authorization: Basic b64(user:pass)`.
  - `bearer`: `Authorization: Bearer <token>`.
  - `oauth2-cc`: client-credentials token from `oauth_token_url`, with `oauth_client_id/secret`, `oauth_scopes`, `oauth_audience` and `oauth_auth_method` (`client_secret_basic` or `client_secret_post`) [I]. The token is cached until `expires_at`. On a 401 the token is refreshed once and the request retried once.
  - `ntlm`: user and password plus `authDomain` and `authWorkstation`.
  - `mtls`: `tlsCert`, `tlsKey` and `tlsCa` PEMs on the agent.
- **Results:**
  - `http`: UP with `msg = "<code> - <statusText>"` and `ping` = elapsed ms.
  - `keyword`: the body is stringified and checked with `includes(keyword)`, which is case-sensitive [I]. `invertKeyword` negates it. On failure it throws with a body excerpt, tags stripped and truncated to 47 characters plus "...".
  - `json-query`: parse the body as JSON, then run a **JSONata** expression `jsonPath` that must yield a primitive. Compare it with `expectedValue` using `jsonPathOperator` ∈ {`==`, `!=`, `<`, `<=`, `>`, `>=`, `contains`}. Numeric operators coerce with `$number`. Pass gives UP; fail throws "JSON query does not pass (comparing …)".
- **Response capture** (2.x): `save_response` and `save_error_response` store a body truncated to `response_max_length` (default 1024) as base64 brotli in `heartbeat.response`.
- **Content-length quirk:** a "maxContentLength size of -1 exceeded" error retries once with `Accept-Encoding: gzip, deflate`.
- **TLS info:** after an https request, read the peer certificate chain. The fallback for proxied connections reads it from the response socket.
  - Store it in `monitor_tls_info.info_json`. If `fingerprint256` changed, delete `notification_sent_history` rows of type `certificate` for the monitor so expiry warnings restart for the new certificate.
  - Chain parsing [V] (`server/util.ts checkCertificate`):
    - `valid = socket.authorized`.
    - For each cert in the chain: `validTo`, `validFor` (SANs), `daysRemaining = floor-diff(validTo − now, days)` in UTC, `fingerprint256`, issuer.
    - `certType` ∈ {`self-signed`, `server`, `intermediate CA`, `root CA`}.
- **Certificate expiry notification** [V], when `expiryNotification` is enabled and `!ignoreTls`:
  - Thresholds come from the setting `tlsExpiryNotifyDays`, default `[7, 14, 21]`.
  - For each threshold `d`, walk the chain from the leaf. Stop at certificates whose fingerprint is a known root (Node's root store plus two ISRG cross-sign fingerprints).
  - If `daysRemaining <= d` and `notification_sent_history` has no row `(type="certificate", monitor_id, days<=d)`, send to all of the monitor's notifications and insert a row.
  - Each threshold therefore fires once per certificate.
  - `daysRemaining == 0` short-circuits the check, which looks like a bug; avoid copying it.
- **Max response, redirects, TLS** errors all flow through the generic retry path.

### 2.2 TCP port ("port") [V] (`monitor-types/tcp.js`)
- Uses `tcp-ping` with `attempts: 1`. The **library's default timeout applies** (about 5 s [I]); `monitor.timeout` is not used.
- UP sets `ping = round(max rtt)` and `msg = "<ms> ms"`. Any failure throws `"Connection failed"`; the cause is discarded.
- No TLS, STARTTLS or ipFamily support in this file. The `expected_tls_alert` column (migration 2026-01-05) suggests TLS-alert expectations are being added. **[I]** Treat TCP+TLS as an MRK extension.

### 2.3 Ping [V] (`monitor-types/ping.js`, `server/modules/ping/lib/*`)
- **Spawns the system `ping` binary** with `child_process.spawn`, `shell: false` and `LANG=C`. It is a vendored, trimmed fork of `node-ping`.
  - On Linux the executable is `ping` from PATH (fallback `/bin/ping`); for v6 it is `ping6` (fallback `/bin/ping6`).
  - macOS uses `/sbin/ping` or `ping6`. Windows uses `%SystemRoot%/system32/ping.exe`.
- **Linux arguments, in order:** `-n` (when `ping_numeric`), `-W <ping_per_request_timeout>`, `-w <monitor.timeout>` (deadline), `-c <ping_count>`, `[-I src]`, `-s <packetSize>`, then the target.
- **Hostname normalisation:** the target is parsed with `new URL("http://"+host).hostname`, and brackets are stripped from IPv6 literals.
- **Result:** the output is parsed per platform. If `alive`, set `ping = time` (avg rtt), `msg = ""` and UP. Otherwise throw with the raw ping output as the message.
- **IPv6 retry:** the probe is retried with v6=true only when the v4 error message is empty.
- **Validation:** `timeout` (deadline) must be ≥ `per_request_timeout`. The UI raises the interval so that interval > deadline.
- **Container privileges:** Debian `iputils-ping` uses an unprivileged `SOCK_DGRAM/IPPROTO_ICMP` socket when the process GID is inside `net.ipv4.ping_group_range`; otherwise it needs `CAP_NET_RAW`. See §7.3.

### 2.4 Push (passive) [V] (`routers/api-router.js`, `monitor.js`)
- **Token:** `push_token` is a 32-character random string; migration `2023-10-11 push-token-to-32` widened it. The URL is `/api/push/<token>?status=up|down&msg=OK&ping=<ms>`, using `router.all`, so any HTTP method works.
- **Push request handling:**
  - Look up `monitor WHERE push_token=? AND active=1`. If none, return HTTP 404 `{ok:false,msg:"Monitor not found or not active."}`.
  - `status` defaults to "up". Any value other than "up" counts as DOWN.
  - `msg` defaults to "OK".
  - `ping` is parsed as a float, must be within `0..1e11`, and defaults to null.
  - If the monitor is under maintenance, the status becomes MAINTENANCE.
  - `duration` = seconds since the previous beat.
- **Status determination for a push request:**
  - Upside-down flips the status first.
  - An explicit `down` that remains DOWN goes **DOWN immediately** with `retries = 0`; it bypasses retries.
  - On UP→DOWN with retries available, the status is PENDING with `retries+1`; otherwise DOWN with `retries = 0`.
  - With no previous beat, DOWN with `maxretries > 0` becomes PENDING with `retries = 1`.
  - Any non-DOWN status resets retries.
- **Push request effects:** the uptime calculator is updated, importance and notification rules apply (same as §1.3), the beat is stored and emitted, and the response is `{ok:true}`.
- **Missing push becomes DOWN** (scheduled side, in `beat()` for type `push`):
  - `bufferTime = 1000` ms.
  - If the previous beat has the "expected" status (UP, or DOWN when upside-down) and `now - prev.time <= interval*1000 + buffer`, re-arm the timer and **do not write a beat**.
  - Otherwise set `bean.duration` and throw `"No heartbeat in the time window"`. The normal retry flow then yields PENDING and later DOWN.
  - Each tick fires `interval` after the previous evaluation, and PENDING retries use `retryInterval`.

### 2.5 DNS [V] (`monitor-types/dns.js`)
- **Resolver:** a new Node `dns/promises.Resolver` per check, with servers from `dns_resolve_server`.
  - The setting is a comma list of IPs or hostnames. Hostnames are resolved to A/AAAA first, and unresolved entries are skipped; if none remain, the check fails.
  - The port is `monitor.port` (53).
  - No explicit timeout; the c-ares defaults apply (about 5 s × 4 tries [I]).
- **Record types:** A, AAAA, CAA, CNAME, MX, NS, PTR (`reverse()`), SOA, SRV, TXT.
- **Message formats:**
  - A/AAAA/PTR/TXT/NS records are joined with `" | "`.
  - MX shows `exchange (priority)`-style text.
  - SOA lists its fields; SRV shows name, port, priority and weight.
  - CNAME uses the first record; CAA shows only the `issue` values.
- **`dns_last_result`:** updated on the monitor row when the message changes.
- **Conditions** (2.x generic condition engine, §2.13): the variable is `record` (string operators). Multi-record results pass if **any** record matches. The field used per type is the record itself, `.issue` for CAA, `.exchange` for MX, `.name` for SRV and `.nsname` for SOA. With no conditions, any successful answer is UP. A failed condition throws with the formatted message.
- **ping:** wall-clock ms of the resolve call.

### 2.6 Docker container [V] (`monitor.js`)
- Calls `GET /containers/<docker_container>/json` on the `docker_host` (`docker_type` = socket path or TCP/HTTPS URL; ignoreTls applies). The timeout is `interval*0.8` s.
- **Results:**
  - Not running or paused: throw (DOWN).
  - `Restarting`: PENDING.
  - With a health check: `healthy` is UP, `unhealthy` throws, and other states (`starting`) are PENDING.
  - No health check: UP with an explanatory message.
- **MRK note:** doc 21 forbids mounting the raw socket and requires a socket-proxy or agent.

### 2.7 Database and broker monitors [V]
In all of these, success sets UP and `ping` = connect+query ms. Any error throws (DOWN or retry).

- **postgres:** `databaseConnectionString` (pg URL; `ssl` string coerced to bool). `databaseQuery` defaults to `SELECT 1`. An empty password is rejected. No conditions, no explicit timeout.
- **mysql:** connection URI with the password in the legacy `radiusPassword` column; default query `SELECT 1`.
  - With conditions, the result must be exactly 1 row × 1 column, and that value is evaluated as a string.
  - Without conditions, `msg = "Rows: N"`.
- **mssql, oracledb, mongodb:** same pattern. MongoDB `databaseQuery` is a JSON command [V validate].
- **redis:** `redis` client `url = connection string`, `rejectUnauthorized = !ignoreTls`, `PING`. `msg` is the reply (`PONG`).
- **mqtt:**
  - Connects to `mqtt://host:port`, or ws/wss with `mqttWebsocketPath`, using user/pass and client id `uptime-kuma_<rand>`. It subscribes to `mqttTopic` and waits for the **first message**.
  - The timeout is `interval*0.8` s ("Timeout, Message not received").
  - `mqttCheckType`:
    - `keyword` (default): the message must contain `mqttSuccessMessage`.
    - `json-query`: JSONata `jsonPath`, with the string compared to `expectedValue`.
    - Conditions override both. Variables: `topic`, `message`, `json_value`.
- **kafka-producer:** produces `kafkaProducerMessage` to a topic on the brokers (SSL and SASL optional). The timeout is `interval*0.8`. Success means the message was sent.
- **rabbitmq:** management API health check over `rabbitmqNodes` with user and password [I].
- **radius:** Access-Request with user, password, secret and called/calling station IDs. Port 1812, timeout `interval*0.4` s, 1 retry. Any reply that does not throw is UP [I].
- **smtp:** nodemailer `verify()` on `hostname:port` (default 25). `smtpSecurity`: `secure` means implicit TLS, `starttls` means require STARTTLS, `nostarttls` means ignore TLS.
- **ntp** (2026-03): thresholds `ntp_stratum_threshold`, `ntp_time_offset_threshold` and `ntp_root_dispersion_threshold` [V fields].
- **sftp:** ssh password or key auth, then checks `sftpPath` [V fields].

### 2.8 gRPC keyword [V] (`monitor-types/grpc.js`)
- Uses `@grpc/grpc-js` with `protobufjs.parse(grpcProtobuf)`, then `lookupService(grpcServiceName)`.
- Makes a unary call to `grpcMethod` with `JSON.parse(grpcBody)` against `grpcUrl`. TLS uses `createSsl()` when `grpcEnableTls`; otherwise insecure.
- No deadline is set (a bug). gRPC code 1 (CANCELLED) is treated as an OK string.
- **Results:**
  - The response is stringified and checked with `includes(keyword)` (`invertKeyword` supported).
  - UP message shows the response and whether the keyword was found.
  - `grpcMetadata` exists as a column but is unused in this file.

### 2.9 WebSocket upgrade [V] (`monitor-types/websocket-upgrade.js`)
- Uses the `ws` client with `handshakeTimeout = timeout` s. Supports headers JSON, basic/bearer/oauth2-cc/mTLS auth, and `wsSubprotocol` (comma list).
- **Results:**
  - On open, close the connection with 1000. The close code must be in `accepted_statuscodes_json` (default `["1000"]`).
  - The option `wsIgnoreSecWebsocketAcceptHeader` treats an invalid accept header as success.
  - Errors with no close code are DOWN.

### 2.10 SNMP [V] (`monitor-types/snmp.js`)
- Uses `net-snmp`. `snmpVersion` is 1, 2c or 3. v3 supports only `noAuthNoPriv` with `snmp_v3_username`.
- The community string for v1 and v2c is in `radiusPassword`. Port 161, `timeout` s, `retries = maxretries`.
- Sends a single `GET snmpOid`. NoSuchInstance or empty results throw.
- The value is then evaluated with `evaluateJsonQuery(value, jsonPath, operator, expectedValue)`, using the same JSONata comparison as json-query.

### 2.11 Group monitor [V] (`monitor-types/group.js`)
- A group monitor is a monitor row with `type = "group"`. Children point to it with `monitor.parent`, and groups can nest.
- **Evaluation:** the group "beats" on its own interval and computes the **worst** status of its *active* children's latest beats, with priority DOWN > PENDING > UP.
  - A child with no beats yet counts as PENDING.
  - **MAINTENANCE children count as UP.** Paused children are ignored.
- **Results:**
  - No children: PENDING, "Group empty".
  - All children OK: UP, "All children up and running".
  - Worst is PENDING: PENDING, "Pending child monitors: …".
  - Any DOWN: throws "Child monitors down: …; pending: …", which feeds the group's **own** retry and notification flow.
- **Parent effects on children:**
  - Maintenance on the parent puts all descendants into MAINTENANCE.
  - Pausing the parent stops the children (`isParentActive`).
  - Deleting a group deletes recursively.

### 2.12 Real browser ("real-browser") [V]
- Uses Playwright Chromium.
  - With a `remote_browser` row (a `remote_browser` table holds a ws endpoint URL), it connects to that remote browser.
  - Otherwise it uses **one shared local Chromium process** that stays resident.
  - In the container image it uses `/usr/bin/chromium`; if absent, it tries `apt install` at runtime.
- **Per check:** new context and page, `goto(url, waitUntil: "domcontentloaded", timeout: interval*0.8)`, optional `screenshot_delay`, then a full-page PNG saved to `data/screenshots/<id>.png`.
- **Results:** status 200–399 is UP (`ping = responseEnd` timing); anything else throws.
- **MRK:** sandboxed process with resource limits, per doc 21. This is the most memory-hungry type.

### 2.13 Conditions engine (2.x) [V] (`server/monitor-conditions/*`)
- Conditions are a JSON expression tree (`conditions` column) of groups and expressions with AND/OR. Each expression is `{variable, operator, value}`.
- **String operators:** `equals`, `not_equals`, `contains`, `not_contains` (also works on arrays), `starts_with`, `not_starts_with`, `ends_with`, `not_ends_with`.
- **Number operators** (coerce with `Number()`): `num_equals`, `num_not_equals`, `lt`, `gt`, `lte`, `gte`.
- Each monitor type declares the variables it exposes: DNS `record`, MQTT `topic`/`message`/`json_value`, SQL result value, and so on.

### 2.14 Other types (low priority)
| Type | Behaviour |
|---|---|
| manual | Status comes from `manual_status`; null means PENDING. |
| steam / gamedig | Game server queries. |
| globalping | Remote probes through the Globalping API, subtypes ping/http/dns. |
| pm2 | Local PM2 process. |
| system-service | systemd/Windows service; disabled in containers. |
| tailscale-ping | Spawns `tailscale ping`; disabled in containers. |
| sip-options | Spawns `sipsak`. |

---

## 3. Data model

The schema starts from `db/kuma.db` and `db/old_migrations/*.sql`, followed by `db/knex_migrations/*.js` (65 migrations up to 2026-11-08).

### 3.1 Tables (key columns)

**monitor**
- **Core:** id, name, description, parent (FK monitor, group nesting), type, subtype, active, user_id, weight, created_date.
- **Scheduling:** interval, retryInterval, resendInterval, timeout, maxretries.
- **Target:** url, method, hostname, port, headers, body, httpBodyEncoding, maxredirects, accepted_statuscodes_json, ignoreTls, upsideDown, keyword, invertKeyword.
- **json-query:** jsonPath, jsonPathOperator, expectedValue, retry_only_on_status_code_failure.
- **Expiry:** expiryNotification, domainExpiryNotification.
- **Auth:** auth_method, basic_auth_user, basic_auth_pass, bearer_token, oauth_client_id, oauth_client_secret, oauth_token_url, oauth_scopes, oauth_audience, oauth_auth_method, authDomain, authWorkstation, tlsCert, tlsKey, tlsCa.
- **Network:** proxy_id, ipFamily, cacheBust.
- **Ping:** packetSize, ping_count, ping_numeric, ping_per_request_timeout.
- **DNS:** dns_resolve_type, dns_resolve_server, dns_last_result (TEXT).
- **Push:** push_token (32 characters).
- **Docker:** docker_container, docker_host.
- **Database:** databaseConnectionString, databaseQuery.
- **MQTT:** mqtt* fields.
- **gRPC:** grpc* fields.
- **Radius:** radius* fields.
- **Kafka:** kafkaProducer* fields.
- **SNMP:** snmpOid, snmpVersion, snmp_v3_username.
- **SMTP:** smtpSecurity.
- **RabbitMQ:** rabbitmq* fields.
- **NTP:** ntp_* fields.
- **SFTP:** sftpPath, ssh* fields.
- **Game:** game, gamedig*.
- **Browser:** remote_browser, screenshot_delay.
- **Other:** conditions (JSON), manual_status, save_response, save_error_response, response_max_length, expected_tls_alert, config (JSON blob, added 2026-10 for new types).
- Fields that `toJSON(includeSensitiveData)` hides by default: headers, body, every credential and secret, and pushToken. Use the same split for MRK's write-only secrets.

**heartbeat**
- Columns: id, monitor_id (FK cascade), status, msg, time (UTC datetime), ping (ms, float), important (bool), duration (seconds; push only), down_count, retries, end_time, response (base64 brotli; 2.x).
- Indexes: on (monitor_id, time) and (monitor_id, important, time). On SQLite, the important indexes are **partial** `WHERE important = 1` (2025-12-22).

**stat_minutely / stat_hourly / stat_daily**
- Columns: id, monitor_id (FK cascade), timestamp (int unix seconds, bucket start), ping (avg ms of UP beats), ping_min, ping_max, up (int), down (int), extras (JSON text; holds `maintenance` counts).
- Constraint: UNIQUE(monitor_id, timestamp).
- `stat_daily` was widened against overflow in 2026-07.

**notification**
- Columns: id, name, config (TEXT, **the whole provider form as JSON**, including type and secrets), active, user_id, is_default.

**monitor_notification**
- Columns: id, monitor_id, notification_id. Unique pair [I].

**notification_sent_history**
- Columns: id, type ("certificate", domain-expiry types), monitor_id, days.
- Constraint: UNIQUE(type, monitor_id, days).

**monitor_tls_info**
- Columns: id, monitor_id (FK), info_json.

**tag / monitor_tag** [I]
- `tag`: id, name, color, created_date.
- `monitor_tag`: id, monitor_id, tag_id, value. A tag can carry an optional value per monitor.

**group / monitor_group** (status-page sections, not group monitors)
- `group`: id, name, created_date, public, active, weight (default 1000), status_page_id.
- `monitor_group`: id, monitor_id, group_id, weight, send_url (bool: show a link on the status page), custom_url.

**status_page**
- Columns: id, slug (UNIQUE, lowercased), title, description (markdown), icon, theme, published, search_engine_index, show_tags, password (legacy, unused), created_date, modified_date, footer_text, custom_css, show_powered_by, show_certificate_expiry, show_only_last_heartbeat, auto_refresh_interval (seconds; default 300 [I]), analytics_id, analytics_script_url, analytics_type, rss_title.

**status_page_cname**
- Columns: id, status_page_id, domain (UNIQUE).

**incident**
- Columns: id, title, content (markdown), style (`info|warning|danger|primary|light|dark` [I]), created_date, last_updated_date, pin, active, status_page_id.

**maintenance**
- Columns: id, title, description, user_id, active, strategy, start_date, end_date, start_time, end_time, weekdays (JSON, ISO 1–7), days_of_month (JSON; ints or "lastDay1"), interval_day, cron, duration (seconds), timezone (IANA name or `SAME_AS_SERVER`), last_start_date.

**monitor_maintenance / maintenance_status_page**
- Link tables between maintenance and monitors, and between maintenance and status pages.
- `maintenance_timeslot` is legacy from 1.x and no longer used in 2.x [I].

**Other tables**
- `proxy`, `api_key`, `remote_browser`, `docker_host`, `setting` (key, value JSON, type).
- better-auth tables replace `user` in 2.x late.

### 3.2 UptimeCalculator algorithm [V] (`server/uptime-calculator.js`)
- **Per-monitor singleton.** It keeps in-memory ring buffers, `LimitQueue`s keyed by bucket-start unix seconds:
  - minutely: 1440 buckets (24 h);
  - hourly: 720 buckets (30 d);
  - daily: 365 buckets (1 y).
  - Bucket keys come from `startOf(minute|hour)` and from UTC `startOf(day)` for daily.
- **`update(status, ping)`:**
  - Status mapping:
    - MAINTENANCE increments `maintenance` only, so it is **neither up nor down**.
    - UP increments `up`.
    - DOWN **and PENDING** increment `down`, so **PENDING counts as downtime**.
  - Ping is aggregated **only for UP beats**: `avg = (avg*(up-1)+ping)/up`, with running min and max.
  - All three buckets are updated.
  - Persistence:
    - `stat_minutely` is upserted on every beat.
    - `stat_hourly` and `stat_daily` are upserted at most once per wall-clock minute per monitor.
    - The upsert writes `up, down, ping, ping_min, ping_max` and puts any other key in `extras` JSON.
  - Returns `end_time` (the stored heartbeat `end_time`).
- **Pruning:** at most once per hour per monitor, delete `stat_minutely` rows older than 24 h and `stat_hourly` rows older than 30 d. `stat_daily` is pruned by the retention job (§3.4).
- **Queries:** `getData(num, type)` sums `up`, `down` and `avgPing*up` over the last `num` buckets ending at the current bucket.
  - `uptime = up/(up+down)`, or 0 if there is no data.
  - `avgPing = Σ(avg*up)/Σup`, or null.
  - If the window is empty, it falls back to the last touched bucket.
- **Standard windows:**
  - 24 h = 1440 minute buckets;
  - 7 d = 168 hour buckets;
  - 30 d = **30 daily buckets**;
  - 1 y = 365 daily buckets.
  - Badge durations: `Nh` ≤ 720, `Nd` ≤ 365, `w`, `M` (30 d), `y`.
  - The calendar-aligned day buckets make 30 d slightly coarse, because the current partial day counts as one bucket.
- **History load:** on demand, the last 24 h of minutely, 30 d of hourly and 365 d of daily rows. Charts use `getDataArray` (bucket list, newest first).
- **Migration 1.x→2.x:** `migrateAggregateTable` replays heartbeats per monitor per day into the stat tables, then `clearHeartbeatData`. The state is kept in the setting `migrateAggregateTableState`.
- **MRK mapping:** this maps cleanly to SQL. One upsert per beat into a minute table goes in the same transaction as the heartbeat insert. Either roll up hour and day tables, or derive them with continuous upserts as upstream does.
  - Doc 21 asks for p50/p95/p99, which upstream **cannot** compute from stored data; it keeps only avg/min/max.
  - Add either a per-bucket histogram (for example fixed log-scale bins in a JSON or array column) or a t-digest.
  - Doc 21 also asks for 90 d and custom ranges. Daily buckets kept 365 d cover those.

### 3.3 Status heartbeat bar
- The status page fetches the last **100** heartbeats per public monitor (`ORDER BY time DESC LIMIT 100`, reversed) plus `uptimeList["<id>_24"]` = 24 h uptime.
- Option `show_only_last_heartbeat` shows only the latest beat.

### 3.4 Retention and cleanup [V] (`server/jobs/clear-old-data.js`, `server/database.js`, `server/jobs.js`)
- **`clear-old-data` job:** runs daily at **03:14** server time (cron `14 03 * * *`, croner).
  1. `clearHeartbeatData`: for each monitor, delete heartbeats with `important = 0 AND time < now-24h`, but keep the newest 100 rows. In 2.x, non-important beats therefore live only 24 h, and only important beats plus aggregates last.
  2. Read `keepDataPeriodDays`. The **default is 365** (stored if unset). If it is < 1, deletion is disabled. Otherwise delete `heartbeat WHERE time < now - days` and `stat_daily WHERE timestamp < startOfDay(now - days)`.
  3. SQLite only: `PRAGMA optimize`.
- **`incremental-vacuum` job:** every 5 minutes (`*/5 * * * *`); SQLite `auto_vacuum=INCREMENTAL`.
- The UI offers "Clear heartbeats", "Clear statistics" per monitor and "Shrink database" (VACUUM).

---

## 4. Notifications [V] (`server/notification.js`, `server/notification-providers/*`)
- **Provider abstraction:** each provider is a class with a unique `name` and an `async send(notification, msg, monitorJSON|null, heartbeatJSON|null)` method that returns a success string or throws.
  - The registry is built at init; duplicate names are an error.
  - The `notification.config` JSON carries `type` (provider name) plus provider-specific fields.
  - There are about 120 providers. Important for us: SMTP, Webhook, Slack, Discord, Telegram, Teams, Matrix, Mattermost, ntfy, Gotify, Pushover, PagerDuty, Opsgenie, Google Chat, Signal, Apprise, Home Assistant, SendGrid, Brevo, Resend, Twilio and Microsoft Graph.
- **Test notification [I]:** sent over socket `testNotification`. It calls `send(notification, "Uptime Kuma Testing, Hi!" style text, null, null)`, so providers must accept null monitor and heartbeat.
- **Base helpers:**
  - `extractAddress(monitor)`:
    - push: "Heartbeat";
    - ping and dns: hostname;
    - port, gamedig and steam: host:port;
    - otherwise: URL.
  - `renderTemplate`: LiquidJS with includes disabled. Variables: `status` ("🔴 Down"/"✅ Up"/"⚠️ Test"), `name`, `hostnameOrURL`, `monitorJSON`, `heartbeatJSON` and `msg`. Legacy uppercase aliases exist.
  - `throwGeneralAxiosError`: builds a detailed error.
  - Optional egress proxy via the `NOTIFICATION_PROXY` environment variable.
- **Webhook payload:**
  - Default JSON POST `{heartbeat, monitor, msg}`.
  - `webhookContentType = form-data` sends one multipart field `data` holding that JSON.
  - `custom` sends a Liquid-rendered `webhookCustomBody`.
  - GET sends `?msg=&heartbeat=&monitor=`, with JSON strings in the query parameters.
  - `webhookAdditionalHeaders` is a JSON object merged last.
- **heartbeatJSON shape:** `{monitorID, status, time, msg, ping, important, duration, retries, timezone, timezoneOffset, localDateTime, lastDownTime?}`.
- **monitorJSON:** the monitor's non-sensitive `toJSON`.
- **Default enabled (`is_default`):** only pre-ticks the notification in the **new-monitor** UI form; there is no server-side auto-attach.
- **Apply on all existing monitors (`applyExisting`):** a one-shot flag at save time that inserts missing `monitor_notification` rows for every monitor. It is not stored.
- **Retry:** **none.** A failure is logged and dropped. There is no queue, delivery log or dedupe beyond the importance rules.
  - Doc 21 asks for retry/backoff, dedupe, quiet hours, escalation and a delivery log. These are MRK additions: use an outbox table with a status per attempt.
- **Events that trigger notifications:**
  - status notifications (§1.3: down, up, first-beat down, and resend every N DOWN beats);
  - TLS certificate expiry thresholds;
  - domain expiry thresholds.
  - Maintenance start and end do **not** notify.

---

## 5. Maintenance [V] (`server/model/maintenance.js`)
- **Strategies:**
  - `manual`: active while `active = 1`; always "under-maintenance".
  - `single`: from `start_date` to `end_date` (datetimes in the window's timezone).
  - `recurring-interval`: every `interval_day` days at `start_time`→`end_time`, within the `start_date`..`end_date` range. Implemented as a daily cron `M H * * *` plus an "elapsed ≥ interval_day since `last_start_date`" check.
    - The code reads camelCase `this.startDate`/`startTime` fields, which looks like a bug; implement the intent.
  - `recurring-weekday`: cron `M H * * <sorted weekday list>`.
  - `recurring-day-of-month`: cron day field from `days_of_month`; `lastDay1` maps to `L`. `lastDay2`–`lastDay4` are dropped as unsupported.
  - `cron`: user cron expression plus `durationMinutes`, validated with croner.
- **Duration:** `duration = end_time − start_time` in seconds; a negative value gets +24 h, which allows windows that cross midnight. `inferDuration` caps it at `end_date`.
- **Timezone:**
  - Each window stores an IANA `timezone`, or `SAME_AS_SERVER`, which resolves to the server timezone (`TZ` or the setting).
  - Croner jobs run in that timezone, so DST is handled by croner.
  - `getTimezoneOffset` is for display. Datetimes are stored without offset and interpreted in that timezone.
- **Runtime:**
  - On load or save, `run()` creates a croner job. On each fire, `startEvent` sets an in-memory status of "under-maintenance", stores `last_start_date` (UTC) and, after `duration`, reverts to "scheduled".
  - At boot, `getRunningTimeslot()` (`job.nextRun(now − duration)`) detects a window that is already in progress and starts it with the remaining duration.
  - **The status is in memory.** A restart recomputes it from cron. MRK can compute it purely from the definition and the current time, which is preferable.
- **getStatus order:**
  1. `inactive` (not active);
  2. manual: `under-maintenance`;
  3. before `start_date`: `scheduled`;
  4. after `end_date`: `ended`;
  5. single: `under-maintenance`;
  6. otherwise the runtime status, or `unknown`.
- **Effect:**
  - Linked monitors, and descendants of linked groups, record MAINTENANCE beats **without executing the check**.
  - MAINTENANCE beats count as neither up nor down.
  - The transitions are important beats but send no notification.
  - Push requests during a window are recorded as MAINTENANCE.
  - Status pages linked through `maintenance_status_page` list the active window and show overall status MAINTENANCE.
- **Doc 21 asks for "suppress notification without faking uptime".** Upstream does both suppression and exclusion (MAINT is excluded from the ratio). Keep that semantics; it is not faking.
- **Possible improvement:** optionally keep executing checks during maintenance so data is recorded while alerts stay muted. This is a design choice.

---

## 6. Status pages [V] (`server/model/status_page.js`, `server/routers/status-page-router.js`, `server/routers/api-router.js`)
- **Routing:**
  - `/status/:slug` serves the SPA shell with server-side injection: `<title>`, meta description (markdown stripped, 155 characters), og:* tags, icon, analytics script, `window.preloadData` (the full page data, escaped) and manifest link.
  - `/status` and `/status-page` serve slug `default`.
  - Slugs are lowercased.
- **Custom domains:**
  - `status_page_cname.domain` entries are loaded into a static domain→slug map.
  - Requests whose Host matches a mapped domain get that status page at `/`. The `/api/entry-page` endpoint returns the matching slug.
  - Domains are unique across pages; assigning a domain to one page removes it from the others.
  - `X-Forwarded-Host` and `X-Forwarded-Proto` are honoured only when the `trustProxy` setting is on.
- **Content:**
  - `publicGroupList`: groups with `public = 1`, ordered by weight. Each group lists monitors ordered by `monitor_group.weight`, with `sendUrl` and `customUrl`.
  - Public monitor JSON fields: id, name, type; optional tags; optional cert expiry; url when send_url is set.
  - `incidents`: pinned and active incidents, newest first. Incident history uses cursor pagination by `created_date`, 10 per page, returning `{incidents, total, nextCursor, hasMore}`.
  - `maintenanceList`: windows that are currently under maintenance.
- **Overall status** (from the latest beat of each public monitor):
  - none: −1 ("No Services");
  - any MAINTENANCE: MAINTENANCE ("Under maintenance");
  - no UP at all: ALL_DOWN ("Degraded Service");
  - some non-UP: PARTIAL ("Partially Degraded Service");
  - else ALL_UP ("All Systems Operational").
- **Public API** (GET, unauthenticated, cached with apicache in memory):

| Endpoint | Cache | Returns |
|---|---|---|
| `/api/status-page/:slug` | 5 min | `{config, incidents, publicGroupList, maintenanceList}` |
| `/api/status-page/heartbeat/:slug` | 1 min | `{heartbeatList: {id: [≤100 beats oldest→newest]}, uptimeList: {"id_24": ratio}}` |
| `/api/status-page/:slug/manifest.json` | 24 h | PWA manifest |
| `/api/status-page/:slug/incident-history?cursor=` | 5 min | paginated incidents |
| `/api/status-page/:slug/badge` | 5 min | SVG; params `label, upColor, downColor, partialColor(#F6BE00), maintenanceColor(#808080), style`; values Up/Degraded/Down/Maintenance/N/A |
| `/status/:slug/rss` | 5 min | RSS: pinned active incidents plus currently DOWN monitors ("<name> is down") |

  - **Cache invalidation:** `apicache.clear()` on every important beat, monitor delete and status-page save. The frontend auto-refreshes every `autoRefreshInterval` seconds.
  - **Private pages:** there is no real access control; `published` and the legacy password are not enforced in these routes. Doc 21 requires signed links; that is an MRK addition.
- **Monitor badges:** `/api/badge/:id/<kind>` returns `image/svg+xml` (shields-style `badge-maker`). Responses are cached 5 min with `Access-Control-Allow-Origin: *`. A monitor that is **not** in any public group gets a grey "N/A" badge.

| Kind | Path | Query params | Value |
|---|---|---|---|
| status | `/status` | `label` (Status), `upLabel`, `downLabel`, `pendingLabel`, `maintenanceLabel`, `upColor`, `downColor`, `pendingColor`, `maintenanceColor`, `style`, `value` | latest beat status |
| uptime | `/uptime/:duration?` | duration default 24h (bare number = hours; `d/w/M/y` supported); `label`, `labelPrefix`, `labelSuffix`, `prefix`, `suffix` (%), `color`, `labelColor`, `style`, `value` | `(uptime*100).toPrecision(4)`; colour from `percentageToColor` |
| ping | `/ping/:duration?` | same as uptime | avg ping ms |
| avg-response | `/avg-response/:duration?` | hours, capped at 720 | avg response |
| cert-exp | `/cert-exp` | `warnDays` (14), `downDays` (7), `date` (show validTo), plus colours | days remaining; "No/Bad Cert" or "Bad Cert" |
| response | `/response` | — | latest beat ping |

- **Other endpoints:**
  - `/metrics` serves Prometheus metrics behind basic auth or an API key [I]. Gauges include `monitor_status`, `monitor_response_time`, `monitor_cert_days_remaining` and `monitor_cert_is_valid`.
  - The 2.x REST surface is small: `/api/info` and `/api/monitors` (API key), plus OpenAPI docs. Everything else (CRUD, beats, charts) is Socket.IO.

---

## 7. Resource footprint, scaling limits, container privileges

### 7.1 Database
- **SQLite (default):**
  - better-sqlite3 with **a single connection** (pool 1/1) by default. `UPTIME_KUMA_SQLITE_SINGLE_CONNECTION=false` gives a pool of up to 20, with a warning about SQLITE_BUSY.
  - Pragmas: WAL, `synchronous=NORMAL`, `busy_timeout=5000`, `cache_size=-12000` (about 12 MB), `auto_vacuum=INCREMENTAL`, `foreign_keys=ON`.
  - Every beat costs about three writes (heartbeat insert, minutely upsert, and hourly/daily upserts once a minute) plus a read of the previous beat when it is not cached.
- **MariaDB:** external or embedded, pool max 10 (env, ≤ 100). **No PostgreSQL support upstream.** MRK's PGlite/PostgreSQL target is therefore a re-design anyway.
- **Known pitfalls:**
  - Issue #7338 (2.3.0, 53 monitors at 60 s): `SQLITE_BUSY` produced *false DOWN alerts*, because DB errors inside the check path were treated as monitor failures. **Lesson:** never let persistence errors become check failures.
  - Issues #4709 and #4747 (1.x): UI hangs around 100 monitors and multi-GB heartbeat tables. The 2.x aggregate tables and 24 h raw retention fix most of this.
  - Community-reported practical ceilings for 2.x [I, unverified]: about 1.5k regular monitors (UI n+1 loading), about 500 ping monitors (CPU, because each ping spawns a process), and about 50 real-browser monitors (memory).

### 7.2 CPU and memory characteristics
- **Per-monitor RAM:**
  - a JS object;
  - a keep-alive agent (HTTP);
  - an UptimeCalculator with up to 1440+720+365 bucket objects (about 2.5k small objects, roughly 100–300 KB per monitor in JS [I]) once history is loaded;
  - the last heartbeat.
- **Ping:** `fork/exec` of `/bin/ping` for every check (count 3 by default). At 1 k monitors on a 60 s interval that is about 17 spawns per second. **A native Python implementation should use ICMP datagram sockets (for example `icmplib` with `privileged=False`, or a custom asyncio socket) instead of spawning.**
- **Real browser:** a resident Chromium process of about 150–300 MB, plus about 50–100 MB per concurrent context [I].
- **Socket.IO:** `sendStats` costs grow with the number of connected admin clients and monitors. Cert and domain info is sent at most once per 60 s per monitor.
- **Event loop:** there is no backpressure. Mass failures, such as an upstream network outage with many monitors timing out at once, cause synchronized retries on `retryInterval`. The jitter applies only at boot.
- **MRK recommendations:**
  - Add per-monitor jitter on every reschedule, or keep the phase from the first beat.
  - Use a global semaphore, for example 50–200 concurrent checks.
  - Add a per-host concurrency cap.
  - Expose queue-lag and event-loop-lag metrics, per doc 21 §6.

### 7.3 Privileged operations in a `cap_drop: ALL`, uid 10001 container

| Feature | Requirement | Plan |
|---|---|---|
| ICMP ping | Raw socket needs **CAP_NET_RAW**. Unprivileged ICMP (`socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` and the ICMPv6 equivalent) needs the process GID inside `net.ipv4.ping_group_range` (this sysctl covers both v4 and v6). | Docker ≥ 20.10 / moby sets `net.ipv4.ping_group_range=0 2147483647` by default in non-host-network containers [I: moby #41030], so unprivileged ICMP works even with cap_drop ALL. Otherwise set `sysctls: net.ipv4.ping_group_range: "0 2147483647"` (a namespaced, "safe" sysctl in Kubernetes). With `network_mode: host` the host's value applies; many distros default to `1 0` (disabled). File capabilities on `/bin/ping` do **not** help under `cap_drop: ALL` with `no-new-privileges`. Implement natively with DGRAM ICMP: the kernel overwrites the identifier, so match replies on sequence number and payload. Show a capability probe in the health UI; when ping is unavailable, report "ICMP unavailable" instead of DOWN. |
| TCP, HTTP, DNS, SMTP, DB, MQTT, gRPC, WebSocket, SNMP (UDP 161 client), RADIUS, NTP client | none (unprivileged outbound sockets) | — |
| Docker monitor | access to the Docker API socket | Not a capability, but the socket is root-equivalent. Use a socket-proxy (read-only `GET /containers/*/json`) or an agent, per doc 21. |
| Real browser | Chromium sandbox needs user namespaces or `SYS_ADMIN`; otherwise `--no-sandbox` | Run in a separate sandboxed worker or on a remote browser endpoint, with memory and CPU cgroup limits. |
| system-service, tailscale-ping, pm2, sip-options | host or other binaries | Mark `not-applicable` in the appliance. |
| Binding ports < 1024 | NET_BIND_SERVICE | Not needed; the reverse proxy fronts the module. |

---

## 8. Divergences and bugs to avoid, or deliberate MRK improvements
1. Enforce `timeout` uniformly for all types; upstream TCP, DNS, gRPC, SQL and SMTP do not.
2. Never convert storage or DB errors into DOWN beats (#7338).
3. `daysRemaining == 0` skips the certificate-expiry check upstream; treat 0 and negative values as expired.
4. Upstream group status ignores MAINTENANCE children (counted as UP). Keep this for parity.
5. Notifications have no retry or outbox upstream. Add an outbox with backoff, dedupe and a delivery log.
6. Status-page "private" is not enforced upstream. Implement signed and private access.
7. Upstream has no percentiles. Add histogram buckets per minute and hour.
8. SSRF policy (doc 21 §5) is absent upstream. Validate on resolve, connect and every redirect hop.
9. Upstream keeps maintenance state in memory. Compute it from the definition and the current time so it is deterministic across restarts.
10. `resendInterval` counts beats, not time. Keep the semantics but label it clearly in the UI ("every N checks").

## 9. Parity checklist (P0 for U2/U3)
- [ ] Scheduler: per-monitor timer, boot jitter, retryInterval while PENDING, interval measured from beat start, no overlap.
- [ ] State machine and importance rules (§1.3), exactly.
- [ ] HTTP, keyword and json-query, including accepted codes, redirects, ignoreTls, auth (basic, bearer, oauth2-cc, mTLS; NTLM P2), cert info and expiry thresholds [7, 14, 21].
- [ ] TCP, ping (DGRAM ICMP), DNS with conditions, push (token URL and the no-heartbeat window), group.
- [ ] Heartbeat plus minute, hour and day aggregates; 24 h, 7 d, 30 d and 1 y uptime; retention (raw non-important beats 24 h, keep the last 100, important beats and daily stats `keepDataPeriodDays` = 365).
- [ ] Notifications: provider interface, default, apply-existing, test, resend.
- [ ] Maintenance: six strategies, IANA timezone, MAINTENANCE beats.
- [ ] Status pages: slug and domains, groups, incidents, overall status, heartbeat API (100 beats), badges (six kinds plus the page badge), RSS, cache invalidation on important beats.

## References
- https://github.com/louislam/uptime-kuma/blob/master/server/model/monitor.js
- https://github.com/louislam/uptime-kuma/blob/master/server/uptime-calculator.js
- https://github.com/louislam/uptime-kuma/blob/master/server/start-monitors.ts
- https://github.com/louislam/uptime-kuma/blob/master/server/server.js
- https://github.com/louislam/uptime-kuma/blob/master/server/util.ts
- https://github.com/louislam/uptime-kuma/blob/master/src/util.ts
- https://github.com/louislam/uptime-kuma/tree/master/server/monitor-types (ping.js, tcp.js, dns.js, group.js, grpc.js, mqtt.js, snmp.js, websocket-upgrade.js, postgres.js, mysql.js, redis.js, smtp.js, manual.js, real-browser-monitor-type.js)
- https://github.com/louislam/uptime-kuma/tree/master/server/modules/ping/lib (builder/linux.js, builder/factory.js, ping-promise.js)
- https://github.com/louislam/uptime-kuma/tree/master/server/monitor-conditions (operators.js)
- https://github.com/louislam/uptime-kuma/blob/master/server/notification.js
- https://github.com/louislam/uptime-kuma/blob/master/server/notification-providers/notification-provider.js
- https://github.com/louislam/uptime-kuma/blob/master/server/notification-providers/webhook.js
- https://github.com/louislam/uptime-kuma/blob/master/server/model/maintenance.js
- https://github.com/louislam/uptime-kuma/blob/master/server/model/status_page.js
- https://github.com/louislam/uptime-kuma/blob/master/server/model/group.js
- https://github.com/louislam/uptime-kuma/blob/master/server/model/incident.js
- https://github.com/louislam/uptime-kuma/blob/master/server/routers/api-router.js
- https://github.com/louislam/uptime-kuma/blob/master/server/routers/status-page-router.js
- https://github.com/louislam/uptime-kuma/blob/master/server/jobs.js
- https://github.com/louislam/uptime-kuma/blob/master/server/jobs/clear-old-data.js
- https://github.com/louislam/uptime-kuma/blob/master/server/database.js
- https://github.com/louislam/uptime-kuma/tree/master/db/knex_migrations (create-uptime, heartbeat, hourly-uptime, optimize-important-indexes, add-tls-monitor, …)
- https://github.com/louislam/uptime-kuma/tree/master/db/old_migrations (patch-group-table, patch-maintenance-table2, patch-status-page, patch-notification_sent_history)
- https://github.com/louislam/uptime-kuma/blob/master/src/pages/EditMonitor.vue
- https://github.com/louislam/uptime-kuma/blob/master/docker/debian-base.dockerfile
- Issues: https://github.com/louislam/uptime-kuma/issues/7338, https://github.com/louislam/uptime-kuma/issues/4709, https://github.com/louislam/uptime-kuma/issues/4747
