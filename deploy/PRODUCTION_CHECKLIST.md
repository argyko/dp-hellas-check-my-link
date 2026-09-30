# Production deployment checklist

1. Point DNS A/AAAA for DOMAIN to the server.
2. Create `.env.production` from `.env.production.example` and use long random secrets.
3. Do not commit `.env.production`.
4. Ensure only TCP 80/443 are publicly exposed; PostgreSQL/Redis stay private.
5. Configure controlled outbound egress for scanner traffic. Keep REQUIRE_EGRESS_PROXY=true in production.
6. Set API keys only on the server.
7. Start with `docker compose -f deploy/docker-compose.production.yml up -d --build`.
8. Verify Caddy obtains TLS and the frontend loads over HTTPS.
9. Verify `/health` through the backend's internal network path.
10. Submit a harmless test URL and confirm QUEUED -> RUNNING -> COMPLETED.
11. Confirm audit endpoint is not exposed through the public frontend.
12. Back up PostgreSQL and Redis persistence according to the chosen hosting policy.
13. Rotate API/admin secrets periodically.
14. Add external monitoring for uptime, queue depth, provider errors and scan latency.
