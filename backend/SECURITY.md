# Security notes — v1.9

## API authentication
Production API routes require `X-API-Key`. Client secrets are compared with constant-time digest comparison.

`/api/v1/scan/{scan_id}/audit` requires the separate `X-Admin-Key`; a normal client key cannot access audit data.

## Scan ownership
Each scan is stored with an `owner_id` derived from the authenticated API key. A client can only retrieve its own scan IDs. Admin access can retrieve any scan.

## Abuse controls
- IP rate limiting remains in Redis.
- Daily per-key quota is stored in Redis.
- Per-key active queued/running scan limit is enforced from PostgreSQL/SQLite.
- Request body and URL limits remain enabled.

## Browser clients
Do not put an admin key in browser code. A browser-visible client key is effectively public and must be treated as an abuse-control credential, not as a secret. For a stronger deployment, expose a server-side BFF/proxy that issues or attaches scoped credentials.

## Secret handling
Do not commit `.env`, API keys, database passwords, Redis credentials, or admin credentials.
