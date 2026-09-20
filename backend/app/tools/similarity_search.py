"""Tool for semantic similarity search of past incidents (pgvector in Postgres)."""

import hashlib
from typing import Any, Dict, List

from langchain.tools import tool
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.database.redis_client import cache_get_json, cache_set_json, run_coro_sync
from app.services.embedding_service import get_embedding

MIN_SIMILARITY = 0.4


@tool
def search_similar_incidents(description: str, limit: int = 5) -> str:
    """Search historical incidents by meaning (pgvector cosine similarity over incident summaries)."""
    limit = max(1, min(int(limit), 10))
    cache_key = f"similar_incidents:{hashlib.md5(description.encode()).hexdigest()}:{limit}"

    cached = run_coro_sync(cache_get_json(cache_key))
    if cached:
        return f"Similar Incidents for '{description[:50]}...' (cached): {cached}"

    async def _search() -> List[Dict[str, Any]]:
        vec = "[" + ",".join(map(str, await get_embedding(description))) + "]"
        # This tool runs in its own event loop (run_coro_sync), so it must not borrow a connection from the
        # main loop's pool (asyncpg connections are bound to the loop that created them): use a private one.
        engine = create_async_engine(settings.database_url.replace("postgresql://", "postgresql+asyncpg://"), poolclass=NullPool)
        try:
            async with AsyncSession(engine) as session:
                rows = (await session.execute(
                    text("""
                        SELECT id, severity, search_text, 1 - (embedding <=> CAST(:v AS vector)) AS similarity
                        FROM incidents
                        WHERE embedding IS NOT NULL
                        ORDER BY embedding <=> CAST(:v AS vector)
                        LIMIT :n
                    """),
                    {"v": vec, "n": limit},
                )).fetchall()
        finally:
            await engine.dispose()
        results = [
            {
                "incident_id": str(r.id),
                "severity": getattr(r.severity, "value", r.severity),
                "similarity_score": round(float(r.similarity), 3),
                "summary": (r.search_text or "")[:200],
            }
            for r in rows
            if r.similarity >= MIN_SIMILARITY
        ]
        return results or [{"incident_id": None, "summary": "No similar incidents indexed yet."}]

    try:
        results = run_coro_sync(_search())
    except Exception as e:
        return f"Similar incident search unavailable: {e}"

    run_coro_sync(cache_set_json(cache_key, results, ttl=3600))
    return f"Similar Incidents for '{description[:50]}...': {results}"
