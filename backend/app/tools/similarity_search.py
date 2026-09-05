"""Tool for semantic similarity search of past incidents (pgvector via Qdrant mirror)."""

from typing import Any, Dict, List
import hashlib

from langchain.tools import tool

from app.database.vector_store import search_vectors
from app.database.redis_client import cache_get_json, cache_set_json, run_coro_sync
from app.services.embedding_service import get_embedding


@tool
def search_similar_incidents(description: str, limit: int = 5) -> str:
    """Search historical incidents using semantic similarity (Qdrant incidents collection)."""
    cache_key = f"similar_incidents:{hashlib.md5(description.encode()).hexdigest()}:{limit}"

    cached = run_coro_sync(cache_get_json(cache_key))
    if cached:
        return f"Similar Incidents for '{description[:50]}...' (cached): {cached}"

    async def _search() -> List[Dict[str, Any]]:
        embedding = await get_embedding(description)
        hits = await search_vectors(
            "incidents",
            embedding,
            limit=limit,
            score_threshold=0.4,
        )
        results = []
        for hit in hits:
            payload = hit.get("payload") or {}
            results.append(
                {
                    "incident_id": payload.get("incident_id", hit.get("id")),
                    "similarity_score": round(float(hit.get("score", 0)), 3),
                    "summary": (payload.get("search_text") or "")[:200],
                    "resolution": payload.get("resolution", ""),
                    "mitre_techniques": payload.get("mitre_techniques", []),
                }
            )
        if not results:
            return [
                {
                    "incident_id": None,
                    "similarity_score": 0.0,
                    "summary": "No similar incidents indexed yet. Embeddings sync after analysis completes.",
                    "resolution": "",
                    "mitre_techniques": [],
                }
            ]
        return results

    try:
        results = run_coro_sync(_search())
    except Exception as e:
        results = [{"error": str(e)}]

    run_coro_sync(cache_set_json(cache_key, results[:limit], ttl=3600))
    return f"Similar Incidents for '{description[:50]}...': {results[:limit]}"
