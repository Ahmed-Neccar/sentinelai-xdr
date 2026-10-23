import secrets
from typing import Annotated

from fastapi import APIRouter, Header
from fastapi.responses import PlainTextResponse
from sqlalchemy import text

from app.api.deps import DbDep
from app.core.config import settings
from app.core.errors import AppError

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": settings.app_name}


@router.get("/ready")
def ready(db: DbDep) -> dict:
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        raise AppError(503, "not_ready", "Database is not ready") from exc
    redis_ok = True
    if settings.redis_url:
        try:
            import redis

            client = redis.from_url(settings.redis_url, socket_connect_timeout=1)
            client.ping()
        except Exception:
            redis_ok = False
    if settings.job_runner == "celery" and not redis_ok:
        raise AppError(503, "not_ready", "Redis is not ready")
    return {"status": "ready", "database": True, "redis": redis_ok}


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(authorization: Annotated[str | None, Header()] = None) -> PlainTextResponse:
    if not settings.metrics_token:
        raise AppError(404, "not_found", "Metrics endpoint is disabled")
    if not secrets.compare_digest(authorization or "", f"Bearer {settings.metrics_token}"):
        raise AppError(401, "unauthenticated", "Metrics access is unauthorized")
    from app.core.metrics import http_metrics

    return PlainTextResponse(http_metrics.render(), media_type="text/plain; version=0.0.4")
