# DP Hellas Check My Link — v1.5 Production Infrastructure

This version upgrades persistence to PostgreSQL, keeps Redis/Celery as the async queue, adds dependency health reporting, and removes hard-coded database credentials.

## Local production-like setup
1. Copy `.env.example` to `.env`.
2. Set a strong `POSTGRES_PASSWORD` and set `DATABASE_URL` to use the same password.
3. Run `docker compose up --build`.
4. API: `http://localhost:8000/health`.

Do not commit `.env`, API keys, database passwords, or Redis credentials.
