# DP Hellas Check My Link

Frontend συνδεδεμένο με το FastAPI scan API.

## Local

1. `npm install`
2. `npm run dev`
3. Backend στο `http://localhost:8000`

Προαιρετικά `.env.local`:
`NEXT_PUBLIC_API_BASE_URL=http://localhost:8000`

Flow: `POST /api/v1/scan` → `scan_id` → polling `GET /api/v1/scan/{scan_id}` → πραγματικό αποτέλεσμα.

## v2.0 BFF
The browser never receives the backend API key. Next.js server routes under `/api/scan` proxy requests to the protected FastAPI API using `CHECK_MY_LINK_API_KEY`.

Required server environment:
- `CHECK_MY_LINK_API_URL`
- `CHECK_MY_LINK_API_KEY`

Do not use `NEXT_PUBLIC_` for either value.
For deployments behind a trusted reverse proxy, configure the platform to provide `X-Real-IP` and configure the backend's trusted proxy settings accordingly.

## Windows Desktop BFF
The desktop client uses `/api/desktop/scan` and `/api/desktop/scan/{scanId}`. These routes never expose `CHECK_MY_LINK_API_KEY`; they forward server-side. Keep the BFF behind the configured WAF/rate limits and HTTPS.
