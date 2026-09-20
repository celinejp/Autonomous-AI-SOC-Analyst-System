"""Shared fixtures: an in-memory Redis (fakeredis) wired in wherever the app fetches its Redis client."""

import sys

import fakeredis.aioredis
import pytest_asyncio


@pytest_asyncio.fixture
async def fake_redis(monkeypatch):
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    getter = lambda: client  # noqa: E731
    # get_redis_client is imported by name into several modules; replace it in all of them
    for module in list(sys.modules.values()):
        if module and getattr(module, "__name__", "").startswith("app.") and hasattr(module, "get_redis_client"):
            monkeypatch.setattr(module, "get_redis_client", getter)
    yield client
    await client.aclose()
