"""Shared login and MFA attempt throttling backed by Redis in production."""

import hashlib
from collections import defaultdict
from threading import Lock
from time import time

import redis

from app.core.config import settings
from app.core.errors import AppError

_local: dict[str, list[float]] = defaultdict(list)
_local_lock = Lock()


def enforce_auth_rate_limit(scope: str, *, limit: int, window_seconds: int = 300) -> None:
    digest = hashlib.sha256(scope.encode()).hexdigest()
    if settings.redis_url:
        try:
            client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1)
            key = f"sentinel:auth-rate:{digest}"
            pipeline = client.pipeline()
            pipeline.incr(key)
            pipeline.expire(key, window_seconds, nx=True)
            count, _ = pipeline.execute()
            client.close()
        except redis.RedisError as exc:
            if not settings.is_development:
                raise AppError(
                    503,
                    "auth_throttling_unavailable",
                    "Authentication is temporarily unavailable",
                ) from exc
            count = _local_count(digest, limit, window_seconds)
    else:
        if not settings.is_development:
            raise AppError(
                503,
                "auth_throttling_unavailable",
                "Authentication is temporarily unavailable",
            )
        count = _local_count(digest, limit, window_seconds)
    if count > limit:
        raise AppError(429, "rate_limited", "Too many authentication attempts. Try again later.")


def _local_count(scope: str, limit: int, window_seconds: int) -> int:
    now = time()
    with _local_lock:
        current = [stamp for stamp in _local[scope] if now - stamp < window_seconds]
        current.append(now)
        _local[scope] = current
        if len(_local) > 10_000:
            for key in tuple(_local):
                if not any(now - stamp < window_seconds for stamp in _local[key]):
                    del _local[key]
        return len(current)
