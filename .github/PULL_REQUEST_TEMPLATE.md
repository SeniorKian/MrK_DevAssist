<!--
Thanks for contributing! Persian or English is fine. / فارسی یا انگلیسی بنویسید.
Please read CONTRIBUTING.md. Security fixes: coordinate through SECURITY.md first.
-->

## What and why / چه چیزی و چرا

<!-- What does this change, and which problem does it solve? Link issues: "Fixes #123". -->

## How it was tested / چطور آزمایش شد

<!-- Commands you ran and what you checked by hand. Screenshots for UI changes (RTL Persian). -->

## Checklist

- [ ] Commit subjects follow `type: summary` (`feat`, `fix`, `docs`, `ci`, `chore`, ...)
- [ ] Python: `ruff check`, `pytest`, `scripts/rehearse_migrations.py`, `scripts/validate_release.py` pass (if touched)
- [ ] Admin UI: `npm run typecheck`, `npm run build`, `npm run check:copy` pass (if touched)
- [ ] DNS engine: `gofmt`, `go vet`, `go test -race ./...` pass in the pinned Go image (if touched)
- [ ] Every new `MRK_*` variable / module setting has a settings-registry entry (Persian + English)
- [ ] New Persian text follows the copy rules and reuses `src/copy/` where possible
- [ ] Database changes include an Alembic migration that also downgrades
- [ ] New dependencies are pinned, permissively licensed and recorded in `versions.lock.yaml`
- [ ] New privileges, mounts or ports are explained and mirrored in `deploy/native/systemd/`
- [ ] Docs updated (README, install guides, contract in `docs/`), CHANGELOG entry under *Unreleased*
