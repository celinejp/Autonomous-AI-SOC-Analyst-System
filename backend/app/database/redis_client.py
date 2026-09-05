"""Async Redis client for caching, locks, status, and job streams."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
from typing import Any, Dict, List, Optional, Union

import redis.asyncio as redis

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# One client per event loop — sharing an async Redis across loops raises
# "Future attached to a different loop" (LangChain sync tools spawn a loop).
_redis_clients: dict[int, redis.Redis] = {}


def _loop_key() -> int:
    try:
        return id(asyncio.get_running_loop())
    except RuntimeError:
        return 0


def get_redis_client() -> redis.Redis:
    """Get or create async Redis client for the current event loop."""
    key = _loop_key()
    client = _redis_clients.get(key)
    if client is None:
        client = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=10,
            retry_on_timeout=True,
        )
        _redis_clients[key] = client
    return client


async def close_redis() -> None:
    """Close Redis connections on shutdown."""
    for client in list(_redis_clients.values()):
        try:
            await client.aclose()
        except Exception:
            pass
    _redis_clients.clear()


async def connect_with_retry(max_attempts: int = 10, base_delay: float = 0.5) -> redis.Redis:
    """Ping Redis with exponential backoff (startup resilience)."""
    client = get_redis_client()
    last_err: Optional[Exception] = None
    for attempt in range(1, max_attempts + 1):
        try:
            await client.ping()
            if attempt > 1:
                logger.info("Redis connected after retry", attempt=attempt)
            return client
        except Exception as e:
            last_err = e
            delay = min(base_delay * (2 ** (attempt - 1)), 8.0)
            logger.warning("Redis not ready, retrying", attempt=attempt, error=str(e), delay=delay)
            await asyncio.sleep(delay)
    raise ConnectionError(f"Redis unavailable after {max_attempts} attempts: {last_err}")


def run_coro_sync(coro):
    """Run an async coroutine from sync LangChain tools safely."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result(timeout=30)


async def cache_get(key: str) -> Optional[str]:
    client = get_redis_client()
    return await client.get(key)


async def cache_set(key: str, value: str, ttl: int = 3600) -> None:
    client = get_redis_client()
    await client.setex(key, ttl, value)


async def cache_get_json(key: str) -> Optional[Any]:
    value = await cache_get(key)
    if value:
        return json.loads(value)
    return None


async def cache_set_json(key: str, value: Any, ttl: int = 3600) -> None:
    await cache_set(key, json.dumps(value, default=str), ttl)


async def hset_mapping(key: str, mapping: Dict[str, Any], ttl: Optional[int] = None) -> None:
    client = get_redis_client()
    str_mapping = {k: str(v) for k, v in mapping.items()}
    await client.hset(key, mapping=str_mapping)
    if ttl is not None:
        await client.expire(key, ttl)


async def hgetall(key: str) -> Dict[str, str]:
    client = get_redis_client()
    data = await client.hgetall(key)
    return data or {}


async def delete_keys(*keys: str) -> int:
    if not keys:
        return 0
    client = get_redis_client()
    return await client.delete(*keys)


async def scan_keys(pattern: str, count: int = 100) -> List[str]:
    """SCAN-based key discovery (avoids blocking KEYS)."""
    client = get_redis_client()
    found: List[str] = []
    cursor: Union[int, str] = 0
    while True:
        cursor, keys = await client.scan(cursor=cursor, match=pattern, count=count)
        found.extend(keys)
        if cursor == 0 or cursor == "0":
            break
    return found


async def invalidate_pattern(pattern: str) -> int:
    keys = await scan_keys(pattern)
    if not keys:
        return 0
    return await delete_keys(*keys)


async def acquire_lock(lock_key: str, ttl_seconds: int = 300, token: str = "1") -> bool:
    """Distributed lock via SET NX EX."""
    client = get_redis_client()
    result = await client.set(lock_key, token, nx=True, ex=ttl_seconds)
    return bool(result)


async def release_lock(lock_key: str, token: str = "1") -> bool:
    """Release lock only if we still own it (compare-and-del)."""
    client = get_redis_client()
    script = """
    if redis.call('get', KEYS[1]) == ARGV[1] then
        return redis.call('del', KEYS[1])
    else
        return 0
    end
    """
    return bool(await client.eval(script, 1, lock_key, token))


async def rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    """
    Sliding fixed-window rate limit.
    Returns True if request is allowed, False if over limit.
    """
    client = get_redis_client()
    pipe = client.pipeline()
    pipe.incr(key)
    pipe.expire(key, window_seconds)
    count, _ = await pipe.execute()
    return int(count) <= limit


async def redis_info() -> Dict[str, Any]:
    client = get_redis_client()
    info = await client.info()
    dbsize = await client.dbsize()
    return {
        "memory_used_mb": info.get("used_memory", 0) / (1024 * 1024),
        "connected_clients": info.get("connected_clients", 0),
        "keyspace": dbsize,
    }
