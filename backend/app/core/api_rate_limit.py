"""Rate limits for the API as a whole.

Sign-in has its own, stricter limits (`auth_rate_limit`). These cover everything else so a stolen
token or a runaway client cannot hit the server without bound: one counter per signed-in session,
one per client address, and a smaller one for calls that are expensive to serve (uploads and
exports). Counters live in Redis when it is configured; if Redis is unreachable the limiter
falls back to counting in this process instead of refusing requests, because an outage of the
counter must not become an outage of the product.
"""

import hashlib
from collections import defaultdict
from threading import Lock
from time import time

import redis

from app.core.config import settings

_local: dict[str, list[float]] = defaultdict(list)
_lock = Lock()
WINDOW_SECONDS = 60

# Paths that are never limited here: probes and the provisioning interface (own limiter).
EXEMPT_PREFIXES = ("/api/v1/health", "/api/v1/ready", "/api/v1/metrics", "/api/v1/scim/")
HEAVY = (("POST", "/api/v1/ingest/upload"), ("GET", "/api/v1/audit-logs/export"))


def enabled() -> bool:
    if settings.api_rate_limit_enabled is not None:
        return settings.api_rate_limit_enabled
    return not settings.is_development


def classify(method: str, path: str) -> str | None:
    """'heavy', 'normal', or None when the path is not limited."""
    if not path.startswith("/api/v1/") or path.startswith(EXEMPT_PREFIXES):
        return None
    if any(method == m and path == p for m, p in HEAVY):
        return "heavy"
    return "normal"


def _count(scope: str) -> int:
    digest = hashlib.sha256(scope.encode()).hexdigest()
    if settings.redis_url:
        try:
            client = redis.Redis.from_url(
                settings.redis_url, socket_connect_timeout=0.5, socket_timeout=0.5
            )
            key = f"sentinel:api-rate:{digest}"
            pipeline = client.pipeline()
            pipeline.incr(key)
            pipeline.expire(key, WINDOW_SECONDS, nx=True)
            count, _ = pipeline.execute()
            client.close()
            return int(count)
        except redis.RedisError:
            pass
    now = time()
    with _lock:
        current = [t for t in _local[digest] if now - t < WINDOW_SECONDS]
        current.append(now)
        _local[digest] = current
        if len(_local) > 20_000:
            for key in tuple(_local):
                if not any(now - t < WINDOW_SECONDS for t in _local[key]):
                    del _local[key]
        return len(current)


def over_limit(kind: str, address: str, session: str | None) -> bool:
    """Count this request against every limit that applies; True if any is exceeded."""
    exceeded = _count(f"addr:{address}") > settings.api_address_limit_per_minute
    if session:
        exceeded |= _count(f"sess:{session}") > settings.api_session_limit_per_minute
    if kind == "heavy":
        who = session or address
        exceeded |= _count(f"heavy:{who}") > settings.api_heavy_limit_per_minute
    return exceeded
