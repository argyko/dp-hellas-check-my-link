# DP Hellas Check My Link — Complete Application

This package contains the production web stack plus the Windows desktop client.

## Components
- `frontend/` Next.js web UI + server-side BFF
- `backend/` FastAPI scan engine, Risk Engine, browser/TI/AI layers
- `deploy/` production Docker Compose/Caddy configuration
- `desktop/` Tauri Windows application
- `.github/workflows/windows-desktop.yml` reproducible Windows installer build

## Production prerequisites
- Cloud Linux VM or equivalent isolated environment
- Domain/subdomain, e.g. `check.techniac.gr`
- PostgreSQL + Redis
- HTTPS
- OpenAI / Google Web Risk / VirusTotal keys as applicable
- Controlled outbound egress for scanner workers

No secrets are included in this package.
