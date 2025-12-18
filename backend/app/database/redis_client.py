"""Redis client for caching and messaging."""

from typing import Optional
import json
import redis.asyncio as redis

from app.core.config import settings

_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    """Get or create Redis client."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


async def cache_get(key: str) -> Optional[str]:
    """Get value from cache."""
    client = get_redis_client()
    return await client.get(key)


async def cache_set(key: str, value: str, ttl: int = 3600) -> None:
    """Set value in cache with TTL."""
    client = get_redis_client()
    await client.setex(key, ttl, value)


async def cache_get_json(key: str) -> Optional[dict]:
    """Get JSON value from cache."""
    value = await cache_get(key)
    if value:
        return json.loads(value)
    return None


async def cache_set_json(key: str, value: dict, ttl: int = 3600) -> None:
    """Set JSON value in cache."""
    await cache_set(key, json.dumps(value), ttl)

