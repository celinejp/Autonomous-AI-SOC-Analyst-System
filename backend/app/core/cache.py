"""Redis caching utilities for FastAPI endpoints."""

from functools import wraps
from typing import Optional, Callable, Any
import json
import hashlib
from datetime import timedelta

from fastapi import Request
from app.database.redis_client import get_redis_client
from app.core.logging import get_logger

logger = get_logger(__name__)


def cache_response(
    ttl: int = 60,
    key_prefix: str = "cache",
    include_query: bool = True,
    include_path: bool = True,
):
    """
    Decorator to cache FastAPI endpoint responses.
    
    Args:
        ttl: Time to live in seconds
        key_prefix: Prefix for cache key
        include_query: Include query parameters in cache key
        include_path: Include path parameters in cache key
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from kwargs if present
            request: Optional[Request] = kwargs.get("request") or (
                args[0] if args and hasattr(args[0], "__class__") else None
            )
            
            # Build cache key
            cache_key_parts = [key_prefix]
            
            if include_path and request:
                cache_key_parts.append(request.url.path)
            
            if include_query and request:
                query_params = dict(request.query_params)
                if query_params:
                    # Sort params for consistent keys
                    sorted_params = sorted(query_params.items())
                    param_str = "&".join(f"{k}={v}" for k, v in sorted_params)
                    cache_key_parts.append(param_str)
            
            # Include function arguments in key
            if args or kwargs:
                arg_hash = hashlib.md5(
                    json.dumps(
                        {str(k): str(v) for k, v in kwargs.items()},
                        sort_keys=True,
                        default=str
                    ).encode()
                ).hexdigest()[:8]
                cache_key_parts.append(arg_hash)
            
            cache_key = ":".join(cache_key_parts)
            
            # Try to get from cache
            redis = get_redis_client()
            if redis:
                try:
                    cached = redis.get(cache_key)
                    if cached:
                        logger.debug(f"Cache hit: {cache_key}")
                        return json.loads(cached)
                except Exception as e:
                    logger.warning(f"Cache read error: {e}")
            
            # Execute function
            result = await func(*args, **kwargs)
            
            # Store in cache
            if redis:
                try:
                    redis.setex(
                        cache_key,
                        ttl,
                        json.dumps(result, default=str)
                    )
                    logger.debug(f"Cache set: {cache_key} (TTL: {ttl}s)")
                except Exception as e:
                    logger.warning(f"Cache write error: {e}")
            
            return result
        
        return wrapper
    return decorator


def invalidate_cache(pattern: str):
    """Invalidate all cache keys matching pattern."""
    redis = get_redis_client()
    if redis:
        try:
            keys = redis.keys(pattern)
            if keys:
                redis.delete(*keys)
                logger.info(f"Invalidated {len(keys)} cache keys: {pattern}")
        except Exception as e:
            logger.warning(f"Cache invalidation error: {e}")


def cache_key(*parts: str) -> str:
    """Build a cache key from parts."""
    return ":".join(str(p) for p in parts)


def get_or_set(
    key: str,
    fetch_func: Callable[[], Any],
    ttl: int = 60,
    default: Any = None,
) -> Any:
    """Get value from cache or fetch and cache it."""
    redis = get_redis_client()
    
    # Try cache
    if redis:
        try:
            cached = redis.get(key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass
    
    # Fetch
    try:
        value = fetch_func()
        if value is not None:
            # Cache it
            if redis:
                try:
                    redis.setex(key, ttl, json.dumps(value, default=str))
                except Exception:
                    pass
            return value
    except Exception as e:
        logger.error(f"Fetch function error: {e}")
    
    return default

