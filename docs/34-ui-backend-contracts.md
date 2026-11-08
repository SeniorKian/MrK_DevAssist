# 34 — قراردادهای بک‌اند برای بازطراحی پنل (خانه، دسترسی‌ها، مرکز تنظیمات)

وضعیت: **پیاده‌سازی‌شده — 2026-11-08**. پنل بازطراحی‌شده (`docs/33`) بر اساس این APIها ساخته می‌شود.
API ماژول‌های Gate 19 در `docs/32` (§3.1 فایروال، §4.1 اسکن آسیب‌پذیری، §5.1 مدیریت دیتابیس) آمده است.

## 1. صفحه خانه

`GET /api/v1/home` (هر کاربر واردشده) →
`{verdict:{level: ok|attention|problem, count}, attention:[{id, rule, severity, title_key, params, action:{kind, route}}],
quick_actions:[{id, route}], checklist:[{id, done, route, optional, detected}], checklist_progress:{done,total},
checklist_dismissed, generated_at, sources?, must_change_password?}`؛ `GET /api/v1/home/rules` همه شناسه‌ها؛
`PATCH /api/v1/home/checklist {dismissed?, steps?:{id: bool}}`.

| rule | شدت | params | مسیر |
|---|---|---|---|
| `component_unavailable` | critical | component | `#/packages/sources` |
| `disk_almost_full` | warning/critical | percent, threshold, source | `#/files/maintenance` |
| `upstreams_all_failing` | error | ecosystem, blocked, failing | `#/packages/sources` |
| `ecosystem_offline` | warning | ecosystem | `#/packages/sources` |
| `agent_not_paired` | info | — | `#/server/overview?connect=agent` |
| `agent_unreachable` | error | since | `#/server/overview` |
| `backup_failed` | error | job_id, job_name, last_success_at, failed_at, error_code | `#/files/app-backups` |
| `backup_overdue` | error | job_id, job_name, last_success_at, interval_seconds | `#/files/app-backups` |
| `no_backup_jobs` | warning | — | `#/files/app-backups?new=1` |
| `updates_available` | info | count | `#/server/updates` |
| `vulnerabilities_found` | critical/error | count, critical, high | `#/security/vuln` |
| `firewall_dry_run` | warning | days, since | `#/security/firewall` |
| `no_notification_channel` | warning | — | `#/alerts/channels?new=1` |
| `jobs_failed` | warning | count | `#/alerts/jobs?state=failed` |
| `s3_public_endpoint_missing` | info | buckets | `#/files/storage?settings=1` |

quick actions: `connect_project`، `search_package`، `backup_now`، `invite_teammate`، `check_updates`، `view_server_usage`.
checklist: `owner_account`، `connect_project`، `add_notification_channel`، `connect_agent`، `create_backup`،
`invite_teammate`، `set_public_address` (اختیاری).

## 2. افراد و دسترسی

- `GET /api/v1/permissions` → `{groups:[{id, name_fa, name_en, permissions:[{id, name_fa, name_en, description_fa, description_en, danger, requires[], assignable}]}], danger_levels}` (گروه‌ها: home, packages, server, files, security, people, alerts).
- `GET /api/v1/roles` (user:read) → `{items:[{id, name, builtin, editable, name_fa, name_en, description_fa, description_en, note_fa, note_en, can_fa[], can_en[], cannot_fa[], cannot_en[], permissions[], user_count}]}`؛ `GET /api/v1/roles/{id}`.
- نقش سفارشی (فقط owner، CSRF): `POST /api/v1/roles {name, description?, permissions[]}`، `PATCH`، `DELETE` (409 `role_in_use` با `error.users`)؛ خطاها: `invalid_role`، `permission_dependency_missing` (`params:{permission, requires}`)، `role_name_exists`، `builtin_role_immutable`، `permission_escalation` (`error.permissions`). نقش کاربر: `custom:<id>`.
- دعوت: `POST /api/v1/users/invite {display_name, email?, role, username?, create_link=true}` → `{user, one_time_password, must_change_password:true, invite:{id, token, path:"/#/invite/<token>", expires_at}|null}`؛ عمومی: `GET /api/v1/auth/invite/{token}` (`invite_invalid` 404، `invite_used`/`invite_expired` 410)، `POST /api/v1/auth/invite/{token}/accept {password}`.
- تغییر رمز: `POST /api/v1/auth/change-password {current_password, new_password}`؛ کاربر با `must_change_password` تا تغییر رمز فقط به `/auth/me`، تغییر رمز، logout و `/home` دسترسی دارد (بقیه 403 `password_change_required`).
- خطاهای فرم: `{error:{code, message, fields:[{field, reason_code, params?}]}}`؛ reason_codeها: required، too_short، too_long، too_small، too_large، invalid_format، invalid_choice، invalid_type، unknown_field، incorrect، missing_letter، missing_digit، same_as_current.
- `GET /api/v1/auth/setup-status` → `{required, password_policy:{min_length, require_letters, require_digits}}`.

## 3. مرکز تنظیمات (همه تنظیمات، حالت پیشرفته)

- `GET /api/v1/settings/registry` → `{groups:[{id, key, name_fa, name_en, label, nav, items:[{key, group, type, default, min, max, step, enum, unit, source: runtime|startup|constant|build, restart_required, processes, danger, read/write permission, depends_on, secret, label_fa, label_en, description_fa, description_en, env, env_only_reason, edit_in, value, effective_source, locked_by_env, pending_restart, overridden, editable, secret_configured?, count?}]}], restart}` (۲۸۷ مورد در ۱۶ گروه).
- `PUT /api/v1/settings/registry/{key} {value}` → `{item, restart}`؛ `DELETE` = بازگشت به پیش‌فرض؛ `GET /api/v1/settings/registry/restart` → `{pending, keys, processes, container_restart_recommended}`.
- خطاها: 404 `unknown_setting`، 409 `setting_locked_by_env` / `setting_env_only` / `setting_read_only` / `setting_edited_elsewhere`، 422 `invalid_setting_value`.
- ویرایش تنظیمات startup فقط owner (`settings:write`)؛ تقدم: متغیر محیطی > فایل override > پیش‌فرض.

## 4. شکاف‌های بک‌اند پنل (2026-11-08)

- **دانلود پشتیبان پنل:** `GET /api/v1/backups/{filename|backup_id}/download` (مجوز `backup:write`، چون فایل کل وضعیت appliance است) → فایل رمزنگاری‌شده `MRKBKP` به‌صورت بایت‌به‌بایت (`application/octet-stream`، `Content-Disposition: attachment`، `Content-Length`)؛ هرگز در سرور رمزگشایی نمی‌شود. audit: `backup.download` (موفق/ناموفق). خطاها: 404 `backup_not_found`، 409 `backup_download_rejected`.
- **آزادسازی فضا در سرور:** `POST /api/v1/lifecycle/cleanup` (مجوز `task:write` + CSRF) با دقیقاً یکی از `candidates:[{ecosystem, name}]` (حداکثر 500)، `target_bytes` یا `target_percent` (20..90، مثل preview) و `confirmation` = `CLEANUP <n> PACKAGES` (n = تعداد نامزدهای قابل حذف؛ `GET /api/v1/lifecycle/cleanup-preview` اکنون فیلد `confirmation` را هم برمی‌گرداند) → 202 `{task_id, state, kind:"lifecycle.cleanup", candidate_count, candidate_reclaim_bytes, skipped[]}`. یک task از نوع `lifecycle.cleanup` همه را در سرور purge می‌کند؛ قبل از هر بسته pin/قرنطینه دوباره بررسی می‌شود؛ npm به سطل بازیافت می‌رود. `result`: `{requested, target_bytes, purged:[{ecosystem, name, size_bytes, recoverable, trash_id}], skipped:[{ecosystem, name, reason: package_pinned|package_quarantined|not_cached|target_reached}], failed:[{ecosystem, name, error_code}], purged_count, reclaimed_bytes, trashed_bytes, freed_immediately_bytes, cancelled}`. قابل لغو بین بسته‌ها؛ retry نیاز به همان confirmation دارد. خطاها: 422 `cleanup_target_required`، 409 `confirmation_mismatch` (`expected_confirmation`, `candidate_count`)، 409 `nothing_to_clean`. audit: `lifecycle.cleanup`، `lifecycle.cleanup.enqueue` و برای هر بسته `package.purge`.
- **مقادیر مطلق میزبان:** `GET /api/v1/metrics/host` علاوه بر `resolution`/`points` فیلد `latest` دارد: `{ts, source: agent|minute, cpu_percent, load1, mem_total_bytes, mem_used_bytes, mem_percent, disk_path, disk_total_bytes, disk_used_bytes, disk_percent}` (دیسک = پرترین دیسک؛ `null` اگر نمونه‌ای در 10 دقیقه اخیر نباشد؛ از ردیف دقیقه‌ای فقط حافظه و درصد دیسک معلوم است).
- **لینک Dokploy:** `GET /api/v1/dokploy/config` فیلد `panel_url` دارد. `GET /api/v1/updates/images` روی هر item و هر container فیلد `dokploy_url` (یا `null`) و روی container فیلد `dokploy_service:{type, id, name, project_id}` دارد، به‌علاوه `dokploy:{configured, panel_url, matched, error_code}` در ریشه. تطبیق best-effort با `appName` سرویس Dokploy از روی label `com.docker.compose.project` / `com.docker.swarm.service.name` یا پیشوند نام container؛ بدون مجوز `dokploy:read` لینکی داده نمی‌شود.
