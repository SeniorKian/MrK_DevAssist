# 06 — تست، مشاهده‌پذیری و عملیات

## 1. Test Pyramid

### Unit

- policy evaluation
- URL/SSRF validation
- error classification
- circuit breaker state machine
- permission checks
- secret redaction
- package name normalization

### Contract

- Control Plane ↔ Verdaccio stable pinned version
- Control Plane ↔ devpi pinned version
- config reload behavior
- metrics/log schema
- backup manifest schema

### Integration

- PostgreSQL migrations
- secret provider
- task queue/idempotency
- adapter با engine واقعی
- atomic cache operations

### End-to-End

- npm install/publish/dist-tag
- pnpm frozen lockfile
- Yarn install
- pip، uv، Poetry install
- twine publish
- UI upstream CRUD
- offline cached install
- failover و recovery

## 2. Client Matrix

در هر release، آخرین stable و یک نسخه قبلی clientها تست می‌شوند:

- npm
- pnpm
- Yarn modern
- pip
- uv
- Poetry
- twine

نسخه‌ها در فایل compatibility manifest pin می‌شوند و با release تغییر می‌کنند.

## 3. Failure Injection Matrix

| Failure | انتظار |
|---|---|
| DNS NXDOMAIN | failover و circuit update |
| IPv4 timeout، IPv6 available | اتصال موفق یا failover کنترل‌شده |
| IPv6 unavailable | fallback شبکه بدون hang نامحدود |
| TCP refused/reset | failover |
| TLS expired/mismatch | fail امن، بدون bypass |
| HTTP 500/502/503/504 | failover |
| HTTP 401/403 | config error، بدون retry storm |
| HTTP 404 | طبق policy، پیش‌فرض نتیجه package-not-found |
| body truncated | artifact discard |
| checksum mismatch | quarantine و alert |
| disk full | cached read حفظ، write محدود |
| DB unavailable | readiness fail، پاسخ کنترل‌شده |
| restart وسط download | فایل ناقص publish نشود |

## 4. Performance Scenarios

- cached small metadata request
- cached 100MB artifact
- concurrent cold misses برای packageهای متفاوت
- thundering herd برای یک artifact
- upstream کند
- cleanup هم‌زمان با download
- backup هم‌زمان با read traffic

خروجی هر benchmark:

- throughput
- p50/p95/p99
- error rate
- CPU/RAM/disk IO
- upstream bytes و cache bytes
- baseline comparison

## 5. Metrics

### HTTP

- `mrk_http_requests_total`
- `mrk_http_request_duration_seconds`
- `mrk_http_inflight_requests`

### Upstream

- `mrk_upstream_state`
- `mrk_upstream_probe_duration_seconds`
- `mrk_upstream_failovers_total`
- `mrk_upstream_circuit_transitions_total`

### Cache

- `mrk_cache_requests_total{result=hit|miss|stale}`
- `mrk_cache_bytes`
- `mrk_cache_artifacts`
- `mrk_cache_evictions_total`
- `mrk_cache_integrity_failures_total`

### Jobs

- `mrk_tasks_total{type,state}`
- `mrk_task_duration_seconds`
- `mrk_task_queue_depth`

### Storage/Backup

- `mrk_storage_free_bytes`
- `mrk_storage_used_bytes{service}`
- `mrk_backup_last_success_timestamp`
- `mrk_backup_duration_seconds`

قانون: package name، user ID و URL کامل label متریک نمی‌شوند تا cardinality کنترل شود.

## 6. Alertهای پایه

- هر دو upstream یک ecosystem unavailable
- failover failure rate بالا
- disk free کمتر از warning/critical
- integrity mismatch
- backup missed/failed
- task queue stuck
- 5xx rate بالا
- certificate نزدیک expiry
- DB migration pending
- cache growth غیرعادی

هر alert باید severity، owner، runbook URL و dashboard link داشته باشد.

## 7. Logging

فرمت JSON:

```json
{
  "timestamp": "...",
  "level": "INFO",
  "service": "control-plane",
  "event": "upstream_failover",
  "correlation_id": "...",
  "ecosystem": "pypi",
  "upstream_id": "...",
  "error_code": "CONNECT_TIMEOUT"
}
```

ممنوع در log:

- password/token/cookie
- Authorization header
- query حاوی credential
- full request body برای login/publish
- مسیر host حساس در support bundle عمومی

## 8. Health Contracts

### Liveness

فقط زنده بودن process؛ وابسته به upstream نیست.

### Readiness

قابلیت پاسخ سرویس و اتصال به dependency ضروری محلی. قطعی upstream خارجی نباید cached reads را unready کند.

### Deep/Synthetic

برای monitoring و پنل؛ شامل probe upstream و نصب package نمونه. در orchestrator readiness استفاده نمی‌شود.

## 9. Backup Strategy

- PostgreSQL: backup سازگار و versioned
- Verdaccio/devpi volumes: snapshot یا file backup با consistency strategy
- config و policy: export versioned
- secrets: backup جداگانه با کنترل دسترسی متفاوت
- manifest: checksum، versions، timestamps و dependencies

Restore drill دوره‌ای الزامی است؛ backup بدون restore test «سالم» محسوب نمی‌شود.

## 10. Runbookها

حداقل runbookهای مورد نیاز:

- primary upstream down
- تمام upstreamها down
- disk pressure/full
- checksum mismatch
- DB unavailable
- failed migration
- cache corruption
- leaked token
- expired TLS certificate
- backup failure
- rollback release

## 11. Production Guardrails

- debug خاموش
- default password ممنوع
- anonymous publish ممنوع
- outbound network allowlist
- container privilege escalation ممنوع
- read-only root filesystem در سرویس‌های سازگار
- resource limits و log rotation
- image digest pin و signature verification
- admin panel فقط HTTPS

## 12. تست Modular Edge

- hostname canonicalization، duplicate/conflict و wildcard blast radius
- Host/X-Forwarded-Host spoofing از trusted و untrusted proxy
- route reload atomic و rollback به snapshot سالم
- WebSocket/SSE و artifact streaming
- unknown host، disabled module و engine timeout
- failure isolation و restart/crash-loop state machine
- ثبت sample module بدون تغییر core

## 13. تست Uptime

- contract snapshot همه operationهای adapter در برابر tag pin‌شده
- fake DNS/connect/TLS/HTTP server برای timeout/reset/redirect/invalid certificate
- SSRF و DNS rebinding برای private/link-local/metadata address
- notification retry/dedupe/recovery/quiet-hours با provider mock
- maintenance و timezone/DST
- incident publish و public/private data boundary
- status page custom domain، cache invalidation، RTL/LTR و accessibility
- load شامل تعداد monitor هدف، scheduler lag و false-positive rate
- restart حین check و جلوگیری از notification تکراری

## 14. تست DNS

- protocol conformance برای UDP/TCP/DoH/DoT/DoQ فعال
- zone/record import، semantic validation، transfer و dynamic update
- DNSSEC positive/negative/bogus chain و rollover rehearsal
- open-resolver، ACL order، amplification/rate limit و rebinding
- change-set idempotency، stale revision و rollback
- config corruption و safe-mode startup
- backup/restore روی engine ایزوله با sample query verification
- QPS/latency/cache-hit/SERVFAIL load و soak
- adapter contract در برابر API نسخه pin‌شده

## 15. Metrics و Alertهای moduleها

- `mrk_module_ready{module}` و `mrk_module_restarts_total{module,reason}`
- `mrk_module_crash_loop{module}` و process resource usage
- uptime: check duration/status، scheduler lag، notification delivery و certificate days
- DNS: query rate/duration، rcode، cache hit، DNSSEC failure و change-set failure
- hostname، URL کامل، monitor name، zone، record و client IP label متریک نمی‌شوند.

Runbookهای جدید: module crash-loop، stale public status، notification storm، DNS SERVFAIL spike، DNSSEC failure، open-resolver exposure، failed zone change و engine API incompatibility.

