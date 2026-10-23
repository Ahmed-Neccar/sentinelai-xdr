# Troubleshooting

## Compose will not start

- Confirm Docker Desktop is running.
- Ports `8080`, `8000`, and `5432` on `127.0.0.1` must be free.
- Run `docker compose logs backend` and look for migration or `SECRET_KEY` errors.

## `/api/v1/ready` returns 503

PostgreSQL is not reachable. Wait for the `postgres` healthcheck. Default URL is in `.env.example`.

## Cannot log in after first start

Bootstrap admin is created **only** when the user table is empty and `SENTINEL_BOOTSTRAP_ADMIN_EMAIL` / `SENTINEL_BOOTSTRAP_ADMIN_PASSWORD` are set. If you started once without them, create a user via a one-off script:

```text
docker compose exec backend python -m app.core.bootstrap
```

## Jobs stay queued

The worker container must be running, or `SENTINEL_JOB_RUNNER=thread` must be set on the backend so it processes jobs in-process. Check `GET /api/v1/ingest/jobs/{id}`.

## Frontend cannot reach API

The SPA expects the API at `/api` via Nginx in Compose, or Vite proxy in `npm run dev`. CORS allowlist must include the UI origin.

## ML page shows unavailable

Optional extras are in `backend/requirements-ml.txt`. Train with `python -m app.detection.ml.train`. Missing sklearn is a documented fallback, not a hidden failure.

## Node not installed on Windows

Use the frontend Docker service, or install Node.js 22 LTS, then `npm ci` in `frontend/`.
