"""Redis caching utilities for FastAPI endpoints."""

from functools import wraps
from typing import Optional, Callable, Any, List
import json
import hashlib

from fastapi import Request
from app.database.redis_client import get_redis_client, invalidate_pattern
from app.core.logging import get_logger

logger = get_logger(__name__)

# Prefixes used by @cache_response — bust these on incident mutations
INCIDENT_CACHE_PATTERNS: List[str] = [
    "incidents:list*",
    "incidents:detail*",
    "dashboard:stats*",
    "dashboard:timeline*",
]


def cache_response(
    ttl: int = 60,
    key_prefix: str = "cache",
    include_query: bool = True,
    include_path: bool = True,
):
    """Decorator to cache FastAPI endpoint responses (cache-aside)."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request: Optional[Request] = kwargs.get("request") or (
                args[0] if args and hasattr(args[0], "url") else None
            )

            cache_key_parts = [key_prefix]

            if include_path and request:
                cache_key_parts.append(request.url.path)

            if include_query and request:
                query_params = dict(request.query_params)
                if query_params:
                    sorted_params = sorted(query_params.items())
                    param_str = "&".join(f"{k}={v}" for k, v in sorted_params)
                    cache_key_parts.append(param_str)

            if args or kwargs:
                arg_hash = hashlib.md5(
                    json.dumps(
                        {str(k): str(v) for k, v in kwargs.items()},
                        sort_keys=True,
                        default=str,
                    ).encode()
                ).hexdigest()[:8]
                cache_key_parts.append(arg_hash)

            cache_key = ":".join(cache_key_parts)

            redis = get_redis_client()
            try:
                cached = await redis.get(cache_key)
                if cached:
                    logger.debug(f"Cache hit: {cache_key}")
                    return json.loads(cached)
            except Exception as e:
                logger.warning(f"Cache read error: {e}")

            result = await func(*args, **kwargs)

            try:
                if hasattr(result, "model_dump"):
                    serializable_result = result.model_dump()
                elif isinstance(result, list):
                    serializable_result = [
                        item.model_dump() if hasattr(item, "model_dump") else item
                        for item in result
                    ]
                else:
                    serializable_result = result

                await redis.setex(
                    cache_key,
                    ttl,
                    json.dumps(serializable_result, default=str),
                )
                logger.debug(f"Cache set: {cache_key} (TTL: {ttl}s)")
            except Exception as e:
                logger.warning(f"Cache write error: {e}")

            return result

        return wrapper

    return decorator


async def invalidate_cache(pattern: str) -> int:
    """Invalidate cache keys matching pattern via SCAN (non-blocking)."""
    try:
        count = await invalidate_pattern(pattern)
        if count:
            logger.info(f"Invalidated {count} cache keys: {pattern}")
        return count
    except Exception as e:
        logger.warning(f"Cache invalidation error: {e}")
        return 0


async def invalidate_incident_caches() -> None:
    """Bust list/detail/dashboard caches after incident writes."""
    for pattern in INCIDENT_CACHE_PATTERNS:
        await invalidate_cache(pattern)


def cache_key(*parts: str) -> str:
    """Build a cache key from parts."""
    return ":".join(str(p) for p in parts)


async def get_or_set(
    key: str,
    fetch_func: Callable,
    ttl: int = 60,
    default: Any = None,
) -> Any:
    """Async get-or-set cache helper."""
    redis = get_redis_client()
    try:
        cached = await redis.get(key)
        if cached:
            return json.loads(cached)
    except Exception:
        pass

    try:
        value = await fetch_func() if asyncio_iscoroutinefunction(fetch_func) else fetch_func()
        if value is not None:
            try:
                await redis.setex(key, ttl, json.dumps(value, default=str))
            except Exception:
                pass
            return value
    except Exception as e:
        logger.error(f"Fetch function error: {e}")

    return default


def asyncio_iscoroutinefunction(func: Callable) -> bool:
    import asyncio
    import inspect

    return asyncio.iscoroutinefunction(func) or inspect.iscoroutinefunction(func)
