# Contributing to DevAssist

Thank you for helping! Bug reports, fixes, documentation, translations and new modules are all
welcome. You can write issues and pull requests in **Persian or English**.

> فارسی: می‌توانید issue و pull request را به فارسی یا انگلیسی بنویسید. قواعد این صفحه برای هر
> دو یکسان است؛ اگر جایی مبهم بود، در یک issue بپرسید.

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE)
and you follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go through
[SECURITY.md](SECURITY.md), never a public issue.

## Repository layout

| Path | What |
|---|---|
| `apps/control-plane` | FastAPI control plane (panel API, modules, PyPI router, S3 engine, Host Agent, firewall helper), Python 3.13 |
| `apps/admin-ui` | React 19 + TypeScript + Material UI admin panel (Persian/RTL first) |
| `apps/dns-engine` | Go DNS engine (`mrk-dns`, `mrk-dnsbench`) |
| `deploy/images` | the images: one Dockerfile, one target per service (panel, agent, firewall, dns, s3, npm, pypi), runtime pins |
| `deploy/native` | systemd unit and helpers for the native (panel-only) install |
| `deploy/verdaccio` | pinned npm packages of Verdaccio |
| `scripts` | CI checks, smoke/e2e tests, release validation, `install-native.sh` |
| `docs` | install guides, user stories (what is built), plans for what is not built yet |
| `versions.lock.yaml` | every pinned component and base image digest |

## Development setup

### Control plane (Python 3.13)

```bash
python3.13 -m venv .venv
. .venv/bin/activate                      # Windows: .venv\Scripts\activate
pip install -e "./apps/control-plane[dev]"
pip install -r deploy/images/requirements.txt
```

Run it against a local SQLite database in `./.data` (no PostgreSQL needed for development):

```bash
MRK_ENV=development MRK_AUTH_COOKIE_SECURE=false MRK_HOST=127.0.0.1 MRK_PORT=8080 \
MRK_TRUSTED_HOSTS=localhost,127.0.0.1 MRK_CORS_ORIGINS=http://localhost:5173 \
mrk-control-plane
```

### Admin UI (Node 24)

```bash
cd apps/admin-ui
npm ci --ignore-scripts
npm run dev                               # http://localhost:5173, proxies /api to 127.0.0.1:8080
```

Set `VITE_PROXY_TARGET` to point the dev server at another control plane.

### Verdaccio (for end-to-end tests)

```bash
(cd deploy/verdaccio && npm ci --omit=dev --ignore-scripts)
python scripts/e2e_local_engines.py       # real npm/PyPI engines across restart and offline mode
```

### DNS engine (Go, in Docker)

Use the same pinned toolchain as CI and the Dockerfile; no local Go is needed:

```bash
docker run --rm -v "$PWD/apps/dns-engine:/src" -w /src \
  -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local \
  golang:1.27.3-trixie sh -c 'go mod verify && test -z "$(gofmt -l .)" && go vet ./... && go test -race -count=1 ./...'
```

### The whole appliance

```bash
docker compose up -d --build              # see docs/install-docker.md
```

## Checks before a pull request

CI (`.github/workflows/ci.yml`) runs these; please run the ones for the parts you touched.

**Python**

```bash
python -m ruff check apps/control-plane scripts
python -m pytest
python scripts/rehearse_migrations.py     # downgrade/upgrade every Alembic migration
python scripts/validate_release.py        # pins, digests, Compose limits, line endings, DNS service rules
python scripts/check_licenses.py --output build/license-report.json
python scripts/check_lockfile_hosts.py    # npm lockfiles may only use approved hosts
```

**Admin UI** (in `apps/admin-ui`)

```bash
npm run typecheck
npm run build
npm run check:copy                        # Persian copy rules, see below; CI fails on any finding
```

**DNS engine**: the Docker command above (CI also runs short fuzz tests and `govulncheck`).

**Native install script**: `bash -n scripts/install-native.sh`, [ShellCheck](https://www.shellcheck.net)
if you have it, and `bash scripts/install-native.sh install --dry-run` on a supported system.

## Project rules

### 1. Everything is configurable: the settings registry

No behaviour is forced on the user (docs/27 §1). Every number, address, timeout or limit that
changes behaviour is a **default**, read from settings.

- Every `MRK_*` environment variable must have an entry in the settings registry
  (`apps/control-plane/src/mrk_control_plane/settings_registry_entries_startup.py`, or `_runtime.py`
  for module settings), with a plain Persian and English description, type, default, range/unit,
  danger level, permission and source. `tests/test_settings_registry.py` scans `src`, `deploy`,
  `scripts`, `compose.yaml` and `.env.example` and fails on any unregistered name.
- Every key in a module's `DEFAULT_SETTINGS` needs a registry entry with the same default.
- Read startup values with `config.setting_env(name, default)`, not `os.getenv`, so panel overrides work.
- Secrets are never returned by the API, written to the overrides file or logged; audit entries
  record the key, never the value.
- A new module ships its own settings page in the panel. That is part of "done".

### 2. Persian copy: the copy catalog

The panel is Persian first and must read like a person wrote it (docs/33 §2, §3).

- Shared words and messages live in `apps/admin-ui/src/copy/` (`common.ts`, `glossary.ts`,
  `errors.ts`, `audit.ts`, `kinds.ts`, ...). Reuse them instead of new strings for the same thing.
- No Latin words inside Persian strings, except product names and glossary terms listed in
  `src/copy/latin-allowlist.json` (`brands`, `parenthetical`), technical literals (hosts, paths,
  versions, env names) and examples in «…».
- Never show raw permission ids such as `upstream:write` to users; show role/permission names.
- Technical text for Advanced mode goes in keys starting with `adv_`. A `copy-ok` comment skips one
  line; use it rarely, reviewers will ask why.
- `npm run check:copy` must pass. Add English text next to every Persian string.

### 3. Pinned dependencies

- Every component version and base-image digest is pinned in `versions.lock.yaml` and in the
  file that uses it (Dockerfile, `requirements.txt`, `pyproject.toml`, lockfiles, `go.mod`/`go.sum`).
  No `latest`, no pre-releases. `validate_release.py` checks the Dockerfile and CI agree.
- New dependencies need a permissive license (MIT, BSD, Apache-2.0, ISC, ...), an entry in
  `versions.lock.yaml`, and must pass `check_licenses.py`. Explain why in the PR.
- npm lockfiles may only resolve from the hosts in `NPM_LOCKFILE_ALLOWED_HOSTS` (CI env).
- Verdaccio and devpi are used unmodified; integrate through plugins, APIs, config or sidecars.

### 4. Security defaults

- Processes run unprivileged; any new capability, mount or port needs a reason in the PR and the
  same change in the native systemd units (`deploy/native/systemd/`).
- Host networking is reserved for `mrk-dns` and `mrk-firewall` (`validate_release.py` enforces it).
- Shell scripts and configs use LF line endings (`.gitattributes`); they break in the image with CRLF.

### 5. Docs and contracts first

Larger features follow the workflow used for every gate so far:

1. **Design/contract doc**: add `docs/NN-<topic>.md` with the next free number (Persian is fine).
   Describe the engine ↔ backend ↔ panel contract: endpoints, payloads, error codes, settings,
   permissions, audit events, limits. Open a PR or issue to discuss it before large code.
2. **Implement** against the contract, with tests.
3. **Record changes** in the contract's "changes" section (a «changes» section at the top) when the
   implementation differs, so the doc stays true.
4. **Update user-facing docs** (README, install guides) and the
   settings registry. Completed gates are later summarised into `docs/03-user-stories.md`
   and the finished design doc is deleted (its full text stays in git history).

Small fixes do not need a design doc.

## Commits and pull requests

- Commit subjects follow the style already in the history (Conventional Commits):
  `feat: ...`, `fix: ...`, `docs: ...`, `ci: ...`, `chore: ...`, `test: ...`, `refactor: ...`.
  Imperative, lower case after the type, about 72 characters at most. Add a scope if it helps:
  `fix(dns): ...`.
- The body explains *why* and lists the main changes as short bullets.
- Keep pull requests focused: one feature or fix per PR. Rebase on `main` before review.
- Fill in the pull request template: what changed, how you tested it, settings/docs/migrations.
- UI changes: add screenshots (RTL Persian; Simple and Advanced mode if both changed).
- Database changes come with an Alembic migration that also downgrades
  (`rehearse_migrations.py` tests both directions).
- CI must be green. A maintainer reviews and merges; please be patient, this is a volunteer project.

## Reporting bugs and asking for features

Use the issue templates. For bugs include the install type (Docker or native), the version or
commit, the OS, what you expected, what happened and the relevant logs
(`docker compose logs mrk-panel` or `journalctl -u devassist`). Remove secrets, tokens and
domain names you do not want to share before posting.
