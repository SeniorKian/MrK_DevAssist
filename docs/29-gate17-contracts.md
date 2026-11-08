# 29 — قراردادهای Gate 17 (Dokploy، مانیتورینگ، لاگ، مدیریت Docker)

وضعیت: **قرارداد مرجع پیاده‌سازی — 2026-11-08**. هر تغییر در این قرارداد باید هم‌زمان در backend و پنل اعمال شود.

## 1. مجوزها (auth.py)

| مجوز | owner | admin | operator | developer | viewer |
|---|---|---|---|---|---|
| `metrics:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `logs:read` | ✓ | ✓ | ✓ | – | – |
| `docker:operate` (start/stop/restart/pull) | ✓ | ✓ | ✓ | – | – |
| `docker:prune` | ✓ | ✓ | – | – | – |
| `dokploy:read` | ✓ | ✓ | ✓ | ✓ | – |
| `dokploy:deploy` (deploy/redeploy/start/stop) | ✓ | ✓ | ✓ | – | – |
| `dokploy:write` (تنظیم اتصال) | ✓ | ✓ | – | – | – |

## 2. Host Agent — endpointهای جدید (امضاشده، طبق `agent/signing.py`)

Agent همچنان فقط درخواست‌های allowlist‌شده را به Docker می‌فرستد. POST فقط برای مسیرهای زیر مجاز می‌شود.

- `GET /v1/docker/containers/{id}/logs?tail=200&since=<unix>&until=<unix>&timestamps=1&follow=0|1`
  - `tail` حداکثر 5000؛ پاسخ `follow=0`: `{"lines":[{"ts":"RFC3339","stream":"stdout"|"stderr","text":"..."}],"truncated":bool}` با سقف 5MB.
  - `follow=1`: پاسخ `application/x-ndjson` (هر خط یک JSON مثل بالا)؛ حداکثر 600 ثانیه، سپس بسته می‌شود.
  - multiplexing هدر 8 بایتی Docker برای کانتینرهای بدون TTY decode می‌شود.
- `GET /v1/metrics` →
  ```json
  {"ts": 1731050000.0,
   "host": {"cpu_percent": 12.5, "load1": 0.4, "mem_total_bytes": 0, "mem_used_bytes": 0,
            "disks": [{"path": "/", "total_bytes": 0, "used_bytes": 0}],
            "net_rx_bytes": 0, "net_tx_bytes": 0},
   "containers": [{"id": "..", "name": "..", "protected": false, "cpu_usage_usec": 0,
                   "mem_bytes": 0, "mem_limit_bytes": null, "io_read_bytes": 0, "io_write_bytes": 0}]
                 | null}
  ```
  `cpu_percent` میزبان از اختلاف `/proc/stat` با نمونه قبلی agent محاسبه می‌شود (اولین فراخوانی `null`).
  شمارنده‌های کانتینر از cgroup v2 در `MRK_AGENT_HOST_CGROUP` (پیش‌فرض `/host/cgroup`)، هر دو چیدمان
  `system.slice/docker-<id>.scope` و `docker/<id>`؛ در نبود cgroup مقدار `containers: null`.
- `POST /v1/docker/containers/{id}/start|stop|restart` body `{"timeout_seconds": 10, "allow_protected": false}`
  → `{"ok": true}`؛ کانتینر محافظت‌شده بدون `allow_protected` → 403 `{"error":"protected"}`.
- `POST /v1/docker/images/pull` body `{"image": "repo[:tag|@digest]"}` → `{"ok": true, "digest": ".."}`؛
  اعتبارسنجی مرجع image؛ سقف زمان 600 ثانیه.
- `POST /v1/docker/prune/preview` body `{"targets": ["containers","images","build_cache","networks"], "images_mode": "dangling"|"unused"}`
  → `{"token": "<sha256 of plan>", "containers": [{"id","name","size_bytes"}], "images": [{"id","tags","size_bytes"}],
  "networks": [{"id","name"}], "build_cache_bytes": 0, "reclaimable_bytes": 0}`.
  - کانتینرها و networkهای محافظت‌شده (Dokploy) و imageهای مورد استفاده هر کانتینر (حتی متوقف) هرگز در plan نیستند.
  - **volumeها در Gate 17 هرگز حذف نمی‌شوند.**
- `POST /v1/docker/prune` body `{"token": "..", same targets/images_mode}` → plan دوباره محاسبه می‌شود؛ اگر token
  برابر نبود 409 `{"error":"plan_changed"}`. اجرا فقط حذف تک‌به‌تک موارد plan است (نه API کلی prune Docker، چون
  کانتینرهای متوقف Dokploy را هم پاک می‌کند)؛ build cache با `/build/prune`.
  → `{"removed": {"containers": n, "images": n, "networks": n}, "reclaimed_bytes": n, "errors": [..]}`.

## 3. Control Plane — API برای پنل

### مدیریت Docker (ماژول host_agent)
- `POST /api/v1/agent/containers/{id}/action` `{action:"start"|"stop"|"restart", allow_protected?:bool, confirmation?:string}`
  (`docker:operate` + CSRF)؛ برای محافظت‌شده: `allow_protected:true` و `confirmation` برابر نام کانتینر، و audit.
- `POST /api/v1/agent/images/pull` `{image}` (`docker:operate`) → 202 `{job_id}`؛ `GET /api/v1/agent/jobs/{job_id}`
  → `{id, kind, state:"running"|"succeeded"|"failed", result?, error_code?, started_at, finished_at}`.
- `POST /api/v1/agent/prune/preview` (`docker:prune`) → plan agent؛ `POST /api/v1/agent/prune`
  `{token, targets, images_mode, confirmation:"PRUNE"}` (`docker:prune` + CSRF) → نتیجه agent.
- `GET /api/v1/agent/containers/{id}/logs?tail&since&until&search` (`logs:read`) → `{lines, truncated}`؛ search فیلتر سمت سرور.
- `GET /api/v1/agent/containers/{id}/logs/stream?tail=200` (`logs:read`) → `text/event-stream`؛ event `line`
  با data JSON خط، event `end` در پایان؛ همه متن‌ها از `redact_text` عبور می‌کنند. مشاهده لاگ audit می‌شود (`logs.view`).

### مانیتورینگ (ماژول monitoring)
- جمع‌آوری هر `interval_seconds` (پیش‌فرض 15) از `/v1/metrics`؛ تجمیع دقیقه‌ای در حافظه و **یک insert در دقیقه**؛
  rollup ساعتی؛ retention قابل تنظیم.
- `GET /api/v1/metrics/host?range=1h|6h|24h|7d|30d` (`metrics:read`) →
  `{"resolution":"minute"|"hour","points":[{"ts":0,"cpu_percent":0,"mem_percent":0,"disk_percent":0,"load1":0,"net_rx_bps":0,"net_tx_bps":0}]}`
- `GET /api/v1/metrics/containers?range=1h` → `{"items":[{"name","protected","latest":{"cpu_percent","mem_bytes","mem_limit_bytes"},"points":[{"ts","cpu_percent","mem_bytes"}]}]}`
- `GET /api/v1/metrics/top?by=cpu|mem&limit=5` → `{"items":[{"name","cpu_percent","mem_bytes"}]}`
- `GET /api/v1/metrics/settings` (`metrics:read`) و `PUT` (`agent:write` + CSRF) →
  `{"enabled":true,"interval_seconds":15,"minute_retention_days":7,"hour_retention_days":90,
    "alerts":{"enabled":true,"cpu_percent":90,"mem_percent":90,"disk_percent":85,"duration_minutes":5}}`
- هشدارها رویداد `metrics.cpu_high|mem_high|disk_high` (warning) و `*_recovered` (info) با dedupe منتشر می‌کنند.

### Dokploy (ماژول dokploy)
- `GET /api/v1/dokploy/config` (`dokploy:read`) → `{configured, url, source:"panel"|"env"|null, last_error}`؛
  `PUT` `{url, api_key?}` (`dokploy:write` + CSRF)؛ `DELETE` `{confirmation:"DISCONNECT"}`؛ `POST /api/v1/dokploy/test` → `{ok, latency_ms, version?, error_code?}`.
- `GET /api/v1/dokploy/projects` → `{"items":[{"id","name","description","services":[{"id","type":"application"|"compose"|"postgres"|"mysql"|"mariadb"|"mongo"|"redis","name","status","domains":[".."],"last_deployment":{"status","created_at","title"}|null}]}]}`
- `GET /api/v1/dokploy/services/{type}/{id}` → جزئیات + `deployments:[{"id","status","title","created_at","finished_at"}]`
- `POST /api/v1/dokploy/services/{type}/{id}/{deploy|redeploy|start|stop}` (`dokploy:deploy` + CSRF؛ `stop` نیازمند
  `{confirmation: <service name>}`) → `{ok}`؛ audit.
- `GET /api/v1/dokploy/deployments/{id}/log` → `{"available":bool,"lines":[..]}` اگر API Dokploy پشتیبانی کند.
- خطاها: 409 `dokploy_not_configured`، 502 `dokploy_unreachable`/`dokploy_auth_failed`، 429 `dokploy_rate_limited`.
- رویدادها: `dokploy.deploy_failed` (error) و `dokploy.unreachable` با polling هر 60 ثانیه.
