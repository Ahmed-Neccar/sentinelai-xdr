import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.v1.router import api_router
from app.core.bootstrap import initialize_data
from app.core.config import settings
from app.core.errors import (
    error_body,
    http_exception_handler,
    unhandled_exception_handler,
)
from app.core.metrics import http_metrics
from app.db.session import SessionLocal


@asynccontextmanager
async def lifespan(app: FastAPI):
    Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.ml_artifact_dir).mkdir(parents=True, exist_ok=True)
    db = SessionLocal()
    try:
        initialize_data(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.app_name,
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs" if settings.is_development else None,
    redoc_url=None,
    # The schema lists every route and field; outside development it is not
    # served either, not just the page that renders it.
    openapi_url="/openapi.json" if settings.is_development else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
)


@app.middleware("http")
async def limit_request_rate(request: Request, call_next):
    from fastapi.responses import JSONResponse
    from starlette.concurrency import run_in_threadpool

    from app.core import api_rate_limit
    from app.core.client_address import client_ip

    kind = api_rate_limit.classify(request.method, request.url.path)
    if kind is not None and api_rate_limit.enabled():
        authorization = request.headers.get("authorization", "")
        # One counter per session: hashing the token keeps the secret out of the counter store.
        session = hashlib.sha256(authorization.encode()).hexdigest()[:32] if authorization else None
        if await run_in_threadpool(
            api_rate_limit.over_limit, kind, client_ip(request) or "unknown", session
        ):
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(api_rate_limit.WINDOW_SECONDS)},
                content=error_body("rate_limited", "Too many requests. Slow down and try again."),
            )
    return await call_next(request)


@app.middleware("http")
async def record_http_metrics(request: Request, call_next):
    started = perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        route_name = getattr(route, "path", "unmatched")
        http_metrics.observe(request.method, route_name, status, perf_counter() - started)

app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)


@app.exception_handler(RequestValidationError)
async def request_validation_handler(request: Request, exc: RequestValidationError):
    from fastapi.responses import JSONResponse

    fields = [
        {
            "location": ".".join(str(part) for part in error.get("loc", ())),
            "message": error.get("msg", "Invalid value"),
            "type": error.get("type", "validation_error"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content=error_body("validation_error", "Request validation failed", {"fields": fields}),
    )


@app.exception_handler(ValidationError)
async def pydantic_validation_handler(request: Request, exc: ValidationError):
    from fastapi.responses import JSONResponse

    fields = [
        {
            "location": ".".join(str(part) for part in error.get("loc", ())),
            "message": error.get("msg", "Invalid value"),
            "type": error.get("type", "validation_error"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content=error_body("validation_error", "Request validation failed", {"fields": fields}),
    )


app.include_router(api_router, prefix="/api/v1")


@app.get("/")
def root() -> dict:
    return {
        "service": settings.app_name,
        "version": __version__,
        "time": datetime.now(UTC).isoformat(),
    }


def retention_cutoff() -> datetime:
    return datetime.now(UTC) - timedelta(days=settings.retention_days)
