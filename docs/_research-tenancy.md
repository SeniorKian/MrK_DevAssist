# Research: Multi-tenancy & "customer area" models for Pishkar

Status: research note (no code changes). Date: 2026-11.
Question: how do established products split *infrastructure admin* (DevOps) from *limited users/customers* who manage only their own domains, records, buckets, keys and files — and what fits Pishkar (single-server, self-hosted, MIT, next to Dokploy)?

> Confidence notes: facts marked *(verified)* were checked against docs/advisories during this research; others are from well-established product knowledge and the linked official docs. CVE identifiers from 2026 were seen only in aggregator feeds and should be re-checked before being cited externally.

---

## 1. Hosting control panels

### cPanel / WHM
- **Panels:** Two UIs, same daemon (`cpsrvd`), different ports/URLs: WHM (`:2087`, root + resellers) and cPanel (`:2083`, end-user accounts). Webmail is a third surface (`:2096`). Separate login per tier.
- **Tenancy:** Every cPanel account is a **real Linux user** — isolation is OS-level (file ownership, optional CageFS/CloudLinux, jailshell). Resellers *own* accounts they create (`OWNER` field); root owns resellers.
- **Admin definition:** **Packages** (quotas: disk, bandwidth, # domains/addon/subdomains, email accounts, DBs, FTP) + **Feature Lists** (toggle each cPanel UI feature on/off, e.g. "Zone Editor", "Terminal"). A package points to a feature list. Resellers get an **ACL list** of WHM privileges (create accounts, edit DNS, suspend, "all" = effectively root — docs warn about this).
- **Quotas:** Per package; resellers additionally get *resource limits* and may be allowed to *overselling*.
- **Impersonation:** WHM → "List Accounts" → cPanel icon logs root/reseller into the user's cPanel (session created server-side, no password).
- **API tokens:** WHM API tokens can be restricted to an ACL subset; cPanel API tokens (since v88) per account, optional expiry. Not per-resource, per-account.
- **Sub-users:** cPanel "Manage Team" / "User Manager" (sub-accounts for email/FTP/web-disk; Team roles: Admin, Database, Email, Web).
- **Audit:** `/usr/local/cpanel/logs/access_log`, `session_log`, API logs; no rich UI audit.
- **Pitfalls:** "all" reseller privilege = root equivalence; reseller-owned DNS zones colliding with other users' zones (cPanel added *DNS cluster* and "allow creating subdomains of other users' domains" toggles for this reason — a classic **domain-takeover-by-another-tenant** issue).
- Sources: [Packages](https://docs.cpanel.net/whm/packages/add-a-package/), [Feature Manager](https://docs.cpanel.net/whm/packages/feature-manager/), [Reseller privileges](https://docs.cpanel.net/whm/resellers/edit-reseller-nameservers-and-privileges/), [cPanel API tokens](https://docs.cpanel.net/cpanel/security/manage-api-tokens-in-cpanel/), [Manage Team](https://docs.cpanel.net/cpanel/preferences/manage-team/).

### Plesk
- **Panels:** **One app, one URL (`:8443`)**, but different *views*: "Service Provider view" (admin/reseller/customer hierarchy) vs "Power User view" (single owner). Customers log into the same URL and get the **Customer Panel** with only their subscriptions.
- **Tenancy:** Admin → Resellers → Customers → **Subscriptions** (a subscription = a system user + webspace + domains). Additional "auxiliary users" with roles inside a customer account.
- **Admin definition:** **Service Plans** (resources + permissions + hosting params) and **Add-on plans**; subscriptions are *synced* to plans (or "unlocked" for custom overrides — a known source of drift). Permissions list includes "DNS zone management", "Hosting settings", "Scheduled tasks", "Access to server file system"…
- **Quotas:** Disk, traffic, domains, subdomains, mailboxes, DBs, overuse policy (block/notify).
- **Impersonation:** "Log in as customer" from admin/reseller panels.
- **API:** XML-RPC / REST API with admin credentials or API keys bound to an IP; mostly admin-level, not per-subscription.
- **Audit:** Action log (configurable event types) in Tools & Settings.
- **Pitfalls:** Permissions like "manage scheduled tasks" or "SSH access" for customers effectively break isolation; a 2026 Plesk advisory describes a **reseller→root auth bypass** ([Plesk KB, CVE-2026-64637](https://support.plesk.com/hc/en-us/articles/42432168683799-CVE-2026-64637-Authentication-Bypass-Leading-to-Privilege-Escalation-in-Plesk)) *(seen, re-verify)*.
- Sources: [Customers and resellers](https://docs.plesk.com/en-US/obsidian/administrator-guide/customers-and-resellers.70447/), [Service plans & subscriptions](https://docs.plesk.com/en-US/obsidian/administrator-guide/customers-and-resellers/service-plans-and-subscriptions.70456/).

### DirectAdmin
- **Panels:** One app/URL (`:2222`); three **levels** (Admin, Reseller, User) — a level switcher in the UI; admin/reseller also have a user level for their own sites.
- **Tenancy:** Linux user per account; reseller owns users (`users.list`).
- **Admin definition:** **User packages** and **Reseller packages** (bandwidth, quota, domains, subdomains, email, DBs, feature flags like SSH, cron, DNS control, "catch-all"). Per-user **feature sets**/skin options.
- **Impersonation:** "Login as" via `reseller|user` login syntax and **Login Keys** (scoped, expiring keys usable for API; can be restricted to specific `CMD_*` commands and IPs).
- **API tokens:** Login Keys = the best example of **command-scoped tokens** in the hosting world.
- **Audit:** `/var/log/directadmin/*` (system/login/error logs).
- **Pitfalls:** Historic XSS → admin takeover (CVE-2019-11193 via `CMD_SHOW_RESELLER` etc.). XSS in a shared admin/user UI is a recurring risk because admins view user-controlled data.
- Sources: [DirectAdmin docs](https://docs.directadmin.com/), [Login keys](https://docs.directadmin.com/directadmin/general-usage/login-keys.html), [CVE-2019-11193](https://intel.intruder.io/cves/CVE-2019-11193).

### ISPConfig
- **Panels:** Single app; Admin, Reseller, Client roles; client sees reduced modules. Multi-server (master/slaves).
- **Tenancy:** Every DB record has `sys_userid`, `sys_groupid`, `sys_perm_user/group/other` (Unix-like row permissions) — **row-level ownership in the data model** is the core isolation mechanism.
- **Admin definition:** **Client templates** (limits: max web domains, DNS zones, mail domains, DBs, cron types, allowed PHP modes, *which servers*), "main" + "additional" templates combinable.
- **Impersonation:** "Login as client" from client list.
- **API:** SOAP remote API with **remote users** having per-function permission checkboxes.
- Source: [ISPConfig manual/docs](https://www.ispconfig.org/documentation/).

### HestiaCP (Vesta fork)
- **Panels:** Single app (`:8083`); `admin` vs users; users see only their section.
- **Tenancy:** Linux user per account; CLI scripts `v-*` run via **sudo** for the panel.
- **Admin definition:** **Packages** (web/DNS/mail domains, DB, cron jobs, disk, bandwidth, backups, shell type).
- **Impersonation:** Admin "Login as user".
- **API:** Access keys with **permission lists** (since 1.6) restricting which `v-*` commands a key may call.
- **Pitfalls (very relevant):** Repeated **low-priv user → root** bugs because user input reaches sudo-run scripts: CVE-2025-30007 (command injection via **DNS record type**), CVE-2023-5839 (privilege chaining), CVE-2022-2626, CVE-2026-12196 (cron job → passwordless sudo scripts). Lesson: **every user-editable DNS/cron/file field is a root-injection surface** if it reaches a privileged helper.
- Sources: [Packages](https://hestiacp.com/docs/user-guide/packages.html), [Users](https://hestiacp.com/docs/user-guide/users.html), [CVE list (OpenCVE)](https://app.opencve.io/cve/?vendor=hestiacp), [CVE-2023-5839](https://recordedfuture.com/vulnerability-database/CVE-2023-5839).

### Virtualmin / Webmin / Usermin
- **Panels:** Webmin (root sysadmin) + Virtualmin module (virtual servers) + **Usermin** (separate end-user app, `:20000`). Virtualmin domain owners log into Webmin but see only Virtualmin pages for their domains.
- **Admin definition:** **Account plans** (quotas, limits) + **Server templates** (how features are configured) + per-domain **"Edit owner limits"** (allowed features, allowed Webmin modules, DNS edit allowed?). **Resellers** in Virtualmin Pro.
- **Webmin ACLs:** per-module ACLs per user (e.g., BIND module restricted to specific zones) — fine-grained but notoriously complex.
- **Impersonation:** "Switch to domain owner" / Login as.
- **Pitfalls:** Webmin had several RCEs (CVE-2019-15107 backdoor in password change; CVE-2022-0824 file manager authz bypass → RCE for low-priv users). Again: low-privileged module access → root.
- Sources: [Virtualmin docs](https://www.virtualmin.com/docs/), [Webmin ACLs](https://doxfer.webmin.com/Webmin/Webmin_Users), [CVE-2022-0824](https://nvd.nist.gov/vuln/detail/CVE-2022-0824).

### CloudPanel
- **Panels:** Single app; roles **Admin**, **Site Manager**, **User** (User is restricted to assigned sites). Site users (SSH/SFTP) separate.
- **Admin definition:** Role + list of sites; no quotas/packages.
- Source: [CloudPanel users](https://www.cloudpanel.io/docs/v2/admin-area/users/).

### aaPanel
- Essentially single-admin; no real customer tier (sub-accounts only in paid/limited form). Not a model for tenancy; history of panel-level RCEs. Low relevance.

---

## 2. DNS-specific

### PowerDNS-Admin
- **Panels:** Single app; roles **Administrator**, **Operator**, **User**.
- **Tenancy:** Zones are assigned to **Users** directly or to **Accounts** (a group/customer). Users see only zones they're granted. Settings: "allow users to create domains", "allow users to remove domains", "allow users to view history".
- **API keys:** Keys have a role and can be **scoped to domains or accounts** — good precedent for resource-scoped tokens.
- **Audit:** "History" of zone changes (who/what/diff).
- **Pitfalls:** IDOR / authorization-bypass where the guard checks the zone in the URL but the handler uses a zone from the body (reported 2026: zone `update` route, [VulnCheck](https://www.vulncheck.com/advisories/powerdns-admin-through-2026.08.1-authorization-bypass-via-domain-domain-name-update), [write-up](https://hackmd.io/@hieuPenguinnn/powerdns-admin-record-update-body-domain-override-cross-zone-idor)). Sister project Poweradmin had the same class: zone owner editing records in **other** zones ([GHSA-rm67-g9ch-vxff](https://advisories.gitlab.com/composer/poweradmin/poweradmin/GHSA-rm67-g9ch-vxff/)). Also classic risk: a user creating a zone (or sub-zone) for a domain they don't own → **shadowing/hijack**.
- Sources: [GitHub](https://github.com/PowerDNS-Admin/PowerDNS-Admin), [Poweradmin users & roles](https://docs.poweradmin.org/user-guide/users-roles/).

### Technitium DNS Server
- **Panels:** Single web console; multi-user since v10/11 with **groups** (Administrators, DNS Administrators, DHCP Administrators, Everyone).
- **Permissions:** Two layers: **section permissions** (Dashboard, Zones, Cache, Settings, Logs, Apps…: View/Modify/Delete) and **per-zone permissions** for users and groups (canView/canModify/canDelete), via `/api/zones/permissions/get|set` *(verified)*. The zone creator gets permissions on it. No per-record permissions.
- **Tokens:** Users can create non-expiring **API tokens** inheriting the user's permissions (so scope = make a dedicated user).
- **Audit:** Logs of admin actions (limited).
- Sources: [APIDOCS.md](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md), [community thread on non-admin zone updates](https://redlib.hbubli.cc/r/technitium/comments/1iueo5t/zone_updates_by_nonadmin_users_via_api).

### Cloudflare (accounts, members, tokens)
- **Panels:** One dashboard; resources belong to an **Account**; users are **Members** of accounts with **roles** (Super Admin, Administrator, DNS, Firewall, Billing, Read-only…), and roles can be **scoped to specific zones (domains)** or the whole account.
- **API tokens:** The reference design: token = *permission groups* (e.g. `Zone.DNS:Edit`) × *resources* (specific zones / all zones in account) × optional IP filter × TTL. Separate "user tokens" vs "account-owned tokens".
- **Domain ownership:** A zone becomes active only after NS delegation is verified — prevents one tenant claiming another's domain. Cloudflare for SaaS uses TXT/HTTP **verification** for custom hostnames.
- **Audit:** Account audit logs (who, what, when, from where), API-accessible.
- Sources: [Roles](https://developers.cloudflare.com/fundamentals/manage-members/roles/), [Scope roles to domains](https://developers.cloudflare.com/fundamentals/manage-members/scope/), [Create API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/), [Audit logs](https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/).

---

## 3. Object storage

### MinIO
- **Panels:** One Console; admin vs non-admin users see what their **IAM policy** allows (Console just calls the S3/admin API with the user's creds). Note: in 2025 the community Console was stripped of most admin features (moved to commercial AIStor), and the community repo went into maintenance/source-only mode — relevant if Pishkar depends on it.
- **Tenancy:** Flat namespace; isolation purely by **IAM policies** (AWS-compatible JSON) attached to users/groups. Per-user buckets via policy variables: `arn:aws:s3:::${aws:username}/*`.
- **Service accounts / access keys:** Children of a user, optionally with an **inline session policy** that further restricts them.
- **Quotas:** Bucket quota (hard), no per-user quota.
- **Audit:** Audit webhook / Kafka target (structured per-request).
- **Pitfalls:** CVE-2025-62506 — restricted service/STS accounts could **create an unrestricted service account** and inherit full parent rights *(verified)*; CVE-2022-24842 — non-admin could create service accounts for **root** *(verified)*. Lesson: "create a key" is itself a privileged operation; child keys must be ⊆ parent.
- Sources: [PBAC](https://min.io/docs/minio/linux/administration/identity-access-management/policy-based-access-control.html), [Access keys](https://min.io/docs/minio/linux/administration/identity-access-management/minio-user-management.html), [CVE-2025-62506 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2025-62506), [CVE-2022-24842](https://vulert.com/vuln-db/CVE-2022-24842).

### Garage
- **Panels:** No built-in UI (third-party UIs exist); admin API only.
- **Model:** **Keys** are the identities; each key has per-bucket flags **read / write / owner** plus a global "allow create bucket" flag. Bucket **quotas**: max size and max objects. Global & local (per-key) **bucket aliases**. No IAM policy language.
- **Pitfall:** `AllowBucketKey` / `DenyBucketKey` have additive semantics (false ≠ revoke) — easy to mis-implement *(verified)*.
- Sources: [Admin API reference](https://garagehq.deuxfleurs.fr/documentation/reference-manual/admin-api/), [Permission API](https://git.deuxfleurs.fr/garage-sdk/garage-admin-sdk-python/src/branch/main-v2/docs/PermissionApi.md).

### Ceph RGW
- **Model:** **Tenants** namespace users and buckets (`tenant$user`, `tenant:bucket`) so names don't collide; since Squid, **Accounts** (IAM-style: account root + IAM users/groups/roles/policies within the account). **Subusers** with access levels (read/write/readwrite/full).
- **Quotas:** Per user and per bucket (max size, max objects); account quotas.
- **Audit:** Ops log.
- Sources: [Multitenancy](https://docs.ceph.com/en/latest/radosgw/multitenancy/), [Accounts](https://docs.ceph.com/en/latest/radosgw/account/), [Quota management](https://docs.ceph.com/en/latest/radosgw/admin/#quota-management).

### Cloudflare R2 / AWS IAM
- **R2:** API tokens: Admin R/W, Admin Read, **Object R/W scoped to specific buckets**, Object Read; S3 creds derived from token.
- **AWS:** Users/roles + identity & resource policies, permission boundaries (to stop "create a more-powerful user" escalation), ABAC via tags.
- Sources: [R2 tokens](https://developers.cloudflare.com/r2/api/tokens/), [IAM permission boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html).

---

## 4. PaaS / platform tools

### Dokploy
- **Panels:** Single app. Hierarchy **Organization → Project → Environment → Service** *(verified)*. Roles **Owner, Admin (can't manage other admins/owner), Member** with configurable grants; **Custom roles, SSO and Audit logs are Enterprise** *(verified)*.
- **Member grants:** accessible projects/environments/services; flags like create/delete projects/services, access to Traefik files, SSH keys, API.
- **Users can create orgs**; each resource belongs to exactly one org.
- Sources: [Multi-tenancy](https://docs.dokploy.com/docs/core/multi-tenancy), [Permissions](https://docs.dokploy.com/docs/core/permissions), [Custom roles](https://docs.dokploy.com/docs/core/enterprise/custom-roles).

### Coolify
- **Panels:** Single app. **Teams** own servers/projects; roles Owner/Admin/Member; a special **root team** (instance admin).
- **Pitfalls:** CVE-2025-22611 — any authenticated user could **change roles (incl. own) up to owner**, kick admins, then use Terminal → RCE (CVSS ~9.9, fixed 4.0.0-beta.361) *(verified)*; later invitation-flow escalations (CVE-2025-64421/64422/64423, member reading/redeeming admin invites). Lesson: role/membership/invite endpoints are the #1 target.
- Sources: [Coolify teams docs](https://coolify.io/docs/knowledge-base/teams), [NVD CVE-2025-22611](https://nvd.nist.gov/vuln/detail/CVE-2025-22611).

### Portainer
- **Panels:** Single app. CE: Administrator / Standard user, **teams**, environment access per user/team, and **resource ownership** on Docker objects: *Administrators only*, *Restricted* (specific users/teams), *Public* (labels on resources). BE: real RBAC roles (Environment admin, Operator, Helpdesk, Standard, Read-only), namespace mapping for K8s, audit/activity logs, registry access per team.
- **Pitfalls:** Ownership is enforced by Portainer's proxy, not Docker — direct socket access bypasses it; Standard users who can deploy stacks with bind mounts/privileged mode can escape (Portainer added "disable bind mounts / privileged mode for non-admins" toggles for this).
- Sources: [Access control](https://docs.portainer.io/advanced/access-control), [User roles](https://docs.portainer.io/admin/user/roles), [Security settings](https://docs.portainer.io/admin/environments/update) .

### Grafana
- **Panels:** Single app. **Server Admin** (instance) vs **Organization** roles (Admin/Editor/Viewer) per org; **Teams**; **Folder/dashboard permissions**; fine-grained RBAC (Enterprise/Cloud). Orgs are *soft* isolation (shared DB, shared plugins).
- **Tokens:** **Service accounts** with role per org; tokens belong to service account.
- **Audit:** Enterprise only.
- **Pitfalls:** Multiple cross-org / privilege bugs historically (e.g., org-admin escalation, data source proxy permission bypasses); Grafana itself recommends separate instances when strong isolation is required.
- Sources: [Organizations](https://grafana.com/docs/grafana/latest/administration/organization-management/), [Roles & permissions](https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/), [Service accounts](https://grafana.com/docs/grafana/latest/administration/service-accounts/).

### GitLab
- **Panels:** Single app, but the **Admin Area** (`/admin`) is a distinct section, optionally behind **Admin Mode** (re-authentication before admin actions; admins act as normal users otherwise).
- **Tenancy:** Groups/subgroups/projects; roles Guest/Planner/Reporter/Developer/Maintainer/Owner inherited downward; custom roles (Ultimate).
- **Tokens:** PATs with **scopes** (`api`, `read_api`, `read_repository`…), **project/group access tokens** (bot users bound to one project/group with a role), expiry enforced.
- **Impersonation:** Admins can impersonate users; impersonation tokens; events are audited and the user can be notified.
- **Quotas:** storage/repo size limits, CI minutes, project limits per user.
- **Audit:** Audit events at instance/group/project level (rich in Premium).
- **Pitfalls:** Many authz CVEs (e.g., CVE-2023-7028 password-reset account takeover; CVE-2024-6385/5655 running pipelines as another user). Large surface → continuous IDOR/authz findings.
- Sources: [Permissions](https://docs.gitlab.com/user/permissions/), [Admin Mode](https://docs.gitlab.com/administration/settings/sign_in_restrictions/#admin-mode), [Impersonation](https://docs.gitlab.com/administration/admin_area/#user-impersonation), [Project access tokens](https://docs.gitlab.com/user/project/settings/project_access_tokens/).

---

## 5. Comparison table

| Product | Panels | Ownership unit | How limits are defined | Quotas | Login-as | Resource-scoped tokens | Audit |
|---|---|---|---|---|---|---|---|
| cPanel/WHM | **2 UIs/ports** | Linux account; reseller owner | Package + Feature List; reseller ACL | Yes, rich | Yes | Per account (ACL for WHM) | Logs |
| Plesk | 1 URL, role views | Subscription (customer) | Service plan (+add-ons) | Yes | Yes | No (admin keys) | Action log |
| DirectAdmin | 1 URL, 3 levels | Linux user; reseller | User/Reseller packages | Yes | Yes | **Login Keys (cmd-scoped)** | Logs |
| ISPConfig | 1 app | Row owner (`sys_userid`) | Client templates | Yes | Yes | Remote user per function | Partial |
| HestiaCP | 1 app | Linux user | Packages | Yes | Yes | Key → command list | Logs |
| Virtualmin | Webmin + Usermin | Virtual server owner | Plans + owner limits + ACL | Yes | Yes | No | Webmin log |
| CloudPanel | 1 app | Site assignment | Role + sites | No | No | No | Limited |
| PowerDNS-Admin | 1 app | User/Account → zone | Roles + global toggles | No | No | **Key → zones/accounts** | History |
| Technitium | 1 app | User/group → zone | Section + zone perms | No | No | Token = user perms | Limited |
| Cloudflare | 1 app | Account | Roles, scoped to zones | Plan | No (support only) | **Perm × resource × IP × TTL** | Yes |
| MinIO | 1 console | Policy-based | IAM JSON policies | Bucket | No | Child key + session policy | Webhook |
| Garage | API only | Key ↔ bucket flags | read/write/owner | Bucket | n/a | Key = scope | No |
| Ceph RGW | API/dashboard | Tenant / Account | Caps, IAM in accounts | User/bucket/account | n/a | Subusers, IAM | Ops log |
| Dokploy | 1 app | Org → project → env | Owner/Admin/Member grants (custom=EE) | No | No | User API keys | EE |
| Coolify | 1 app | Team | Roles | No | No | Team tokens w/ abilities | Limited |
| Portainer | 1 app | Env + resource ownership | Teams, roles (BE) | No | No | User tokens | BE |
| Grafana | 1 app | Org / folder | Roles, teams, RBAC | No | No | Service accounts | EE |
| GitLab | 1 app + Admin Area/Admin Mode | Group/project | Roles inherited | Yes | **Yes, audited** | **Project/group tokens + scopes** | Yes |

---

## 6. Recurring patterns

1. **Three-level hierarchy is near-universal:** *instance admin* → (optional *reseller/org admin*) → *user/customer*, plus sub-users inside a customer. The reseller tier is a business feature; most self-hosted tools drop it.
2. **Ownership is stored on every resource row** (cPanel `OWNER`, ISPConfig `sys_userid`, PowerDNS-Admin account↔zone, Dokploy org/project). Isolation is enforced in the **query/service layer**, not the UI.
3. **Two knobs define a customer:** a *capabilities list* (feature toggles: "may edit DNS", "may create buckets", "may use terminal") and *numeric quotas* (N zones, N records, N buckets, GB storage, N keys). Packaged together as a **plan/package/template** and assigned to users. Overrides per user are allowed but cause drift (Plesk "unlocked").
4. **Resource-scoped tokens** (Cloudflare, PowerDNS-Admin, GitLab project tokens, R2 bucket tokens, DirectAdmin login keys) — token = permissions ∩ resources ∩ expiry, never more than its creator.
5. **Domain ownership verification** before a tenant can claim a zone/bucket domain (Cloudflare NS/TXT; cPanel "prevent creating subdomains of other users' domains").
6. **Impersonation** is standard in hosting panels and GitLab, always admin-initiated, ideally **audited and visible to the user**.
7. **Audit** of who-changed-what per resource, visible to the resource owner for their own resources (PowerDNS-Admin history, Cloudflare).

### Recurring vulnerabilities (what to design against)
- **Role/membership/invite endpoints** letting a user raise their own role (Coolify CVE-2025-22611, invite CVEs).
- **IDOR / mismatched identifiers**: guard checks resource ID from URL, handler uses ID from body (PowerDNS-Admin 2026, Poweradmin).
- **Key/sub-account creation not bounded by parent rights** (MinIO CVE-2022-24842, CVE-2025-62506).
- **User-controlled fields reaching privileged helpers** (HestiaCP DNS record type → root, cron → sudo; Webmin file manager).
- **Stored XSS in shared admin/user UI** — admin views tenant data (DirectAdmin CVE-2019-11193).
- **Namespace collisions / takeover**: tenant creates zone or bucket alias for someone else's domain/name.
- **Soft isolation leaks** via shared features (Grafana data sources, Portainer bind mounts).

---

## 7. Separate customer panel vs single panel with scoped roles

### Separate customer panel (cPanel/WHM, Usermin style)
**Pros:** smallest attack surface for customers (admin routes simply not deployed/mounted on the customer listener); can be exposed publicly while the admin panel stays on VPN/localhost; clean, simple UX; easy mental model ("the customer port").
**Cons:** two UIs to build/maintain/translate (Pishkar is RTL/Persian — double the copy work); feature duplication (record editor, bucket browser exist in both); diverging behaviour; admins need login-as to see what users see.

### Single app, scoped roles, simplified user view (Plesk, DirectAdmin, Dokploy, GitLab)
**Pros:** one codebase and component kit; admin sees the same screens (easy support); RBAC already exists in Pishkar (`dns:read/write/admin`); the same API serves UI and tokens.
**Cons:** every route must enforce *both* permission and ownership — one forgotten check = cross-tenant leak; admin-only pages are shipped to user browsers (must be server-enforced anyway); risk of "permission soup" UX if users see disabled admin items.

### Hybrid used by the most secure single-apps
- **One backend, one auth, two "surfaces":** an *Admin area* (`/admin/*`, like GitLab Admin Area + Admin Mode re-auth) and a *My area* (`/my/*` or "Workspace"), with separate navigation, routed to **separate API namespaces** (`/api/admin/...` requiring admin permission, `/api/my/...` always filtered by `owner_id = current principal`).
- Optional: bind admin API/listener to localhost/VPN only, expose the "my" surface publicly (gives the cPanel-style network separation without a second app).

---

## 8. Recommendation for Pishkar (single-server appliance)

**Single app, single login, two surfaces ("Server" admin area vs "My space" user area), backed by ownership-enforced API namespaces and plans.** Concretely:

1. **Tenancy model:** add `owner_id` (user or *workspace*) to every tenant-ownable resource: DNS zones, records (inherit zone), buckets, S3 keys, bucket domains, registry packages/tokens, backups of own resources. Keep a light **Workspace** (= customer/org) so a customer can have sub-users later; skip a reseller tier.
2. **Two API namespaces:** `/api/admin/*` (infrastructure: DNS server settings, recursion/DNSSEC globals, storage engine, firewall, upstreams, monitoring, Dokploy) guarded by admin permissions; `/api/my/*` where **every query is filtered by owner** in a shared repository/service layer (no per-handler checks), IDs taken only from the path and re-validated.
3. **Plans (packages):** feature toggles (`dns.zones`, `dns.records.types` allowed, `s3.buckets`, `s3.keys`, `s3.public_buckets`, `s3.bucket_domains`, `registry.npm/pypi`) + quotas (max zones, max records/zone, max buckets, storage GB, max objects, max keys, max bucket domains). Assign to users/workspaces; allow per-user override but show "differs from plan".
4. **Domain verification** before a user can add a zone or bind a domain to a bucket (TXT challenge or NS delegation check), and forbid zones overlapping another tenant's zone or Pishkar's own system names.
5. **Scoped tokens:** token = actions ∩ resources (zone/bucket IDs) ∩ expiry ∩ optional IP; enforce **child ⊆ parent** for both API tokens and S3 access keys (avoid MinIO's bugs); S3 keys created by users get policies generated server-side, never user-supplied JSON.
6. **Impersonation:** admin "View as user" (read-only by default, write needs re-auth), banner in UI, audited, visible in the user's own activity log.
7. **Audit:** existing audit log gets `actor`, `on_behalf_of`, `owner_id`; users see audit entries of their own resources.
8. **Hardening:** role/invite endpoints admin-only and cannot grant ≥ own role; strict validation of record types/values before anything reaches the DNS engine or a privileged helper (HestiaCP lesson); escape all tenant data in admin views; optional setting to bind the admin surface to localhost/VPN while exposing "My space" publicly; cross-tenant tests (user A tries every `/api/my` route with user B's IDs) in CI.

Why not a separate panel: Pishkar is one-person-maintainable, RTL/Persian-copy heavy, and already has RBAC and a component kit; a second app doubles UI and copy for little gain on a single server, while the hybrid (separate API namespaces + optional network binding) delivers most of the isolation benefit.
