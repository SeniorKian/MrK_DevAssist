# Professional bilingual admin UI

## Delivered foundation

- Responsive operations shell for desktop, tablet, and mobile.
- Native Persian RTL and English LTR modes with persisted user preference.
- Self-hosted Vazirmatn and Inter variable fonts; no font CDN is required.
- Persisted dark and light themes.
- Live control-plane, npm, PyPI, uptime, and mounted `/data` filesystem status.
- Honest feature states: unfinished screens are disabled and labeled as upcoming.
- npm setup commands, verified registry fallback order, and current security posture.

## Stale UI protection

The Docker build injects the same `VCS_REF` and `BUILD_DATE` into the static UI
and the control plane. The browser compares its embedded UI version and commit
with `/api/v1/system/status` on initial load, every 60 seconds, and whenever the
tab becomes visible.

On a mismatch, the UI performs one cache-busted replacement navigation. A
session-scoped guard prevents reload loops. If the versions still differ, the
dashboard displays a persistent manual update action. Status requests use
`cache: no-store`, and the security middleware sends `Cache-Control: no-store`
for the delivered shell and API responses. No service worker is registered.

CI and release builds already pass `${{ github.sha }}` as `VCS_REF`, so the
comparison is commit-accurate for published GHCR images.

## Security boundary

The dashboard contains operational information and should be protected by the
reverse proxy until application authentication and RBAC are implemented. Do
not expose port `8080` publicly without access control and TLS.

## Verification

- TypeScript typecheck and production Vite build.
- Python Ruff and seven control-plane tests.
- npm audit with zero reported vulnerabilities at implementation time.
- Docker runtime health, npm ping, Persian RTL, English LTR, light theme, dark
  theme, and browser console checks.
