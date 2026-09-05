"""Tools for searching MITRE ATT&CK techniques via Qdrant + Redis cache."""

from typing import Any, Dict, List
import hashlib
import json

from langchain.tools import tool

from app.database.vector_store import scroll_by_payload, search_vectors
from app.database.redis_client import cache_get_json, cache_set_json, run_coro_sync
from app.services.embedding_service import get_embedding


def get_mitre_technique_raw(technique_id: str) -> Dict[str, Any]:
    """Get structured detail for a MITRE ATT&CK technique from Qdrant (dict, not the
    LLM-formatted string `get_mitre_technique` returns) - for callers that need to
    persist/consume the fields directly instead of parsing a formatted string."""
    tid = technique_id.upper()
    cache_key = f"mitre_technique:{tid}"

    cached = run_coro_sync(cache_get_json(cache_key))
    if cached:
        return cached

    async def _fetch() -> Dict[str, Any]:
        points = await scroll_by_payload(
            "mitre_techniques",
            key="technique_id",
            value=tid,
            limit=1,
        )
        if not points:
            # Try without subtechnique suffix
            base = tid.split(".")[0]
            points = await scroll_by_payload(
                "mitre_techniques",
                key="technique_id",
                value=base,
                limit=1,
            )
        if points:
            payload = points[0].get("payload") or {}
            return {
                "id": payload.get("technique_id", tid),
                "name": payload.get("name", ""),
                "tactic": ", ".join(payload.get("tactics", []) or []),
                "description": payload.get("description", ""),
                "detection_methods": payload.get("detection_methods", []),
            }
        return {
            "id": tid,
            "name": "Unknown Technique",
            "tactic": "Unknown",
            "description": f"Technique {tid} not found in Qdrant. Run scripts/load_mitre.py.",
            "detection_methods": [],
        }

    technique = run_coro_sync(_fetch())
    run_coro_sync(cache_set_json(cache_key, technique, ttl=604800))
    return technique


@tool
def get_mitre_technique(technique_id: str) -> str:
    """Get detailed information about a specific MITRE ATT&CK technique from Qdrant."""
    technique = get_mitre_technique_raw(technique_id)
    return f"MITRE Technique {technique_id.upper()}: {technique}"


MITRE_SCORE_THRESHOLD = 0.65


def search_mitre_techniques_raw(query: str, limit: int = 5, score_threshold: float = MITRE_SCORE_THRESHOLD) -> List[Dict[str, Any]]:
    """Semantic search MITRE ATT&CK techniques via Qdrant embeddings, returning structured
    results (with scores) so callers can filter on actual similarity rather than
    regexing technique IDs out of a formatted string."""
    cache_key = f"mitre_search:{hashlib.md5(query.encode()).hexdigest()}:{limit}:{score_threshold}"

    cached = run_coro_sync(cache_get_json(cache_key))
    if cached is not None:
        return cached

    async def _search() -> List[Dict[str, Any]]:
        embedding = await get_embedding(query)
        hits = await search_vectors(
            "mitre_techniques",
            embedding,
            limit=limit,
            score_threshold=score_threshold,
        )
        results = []
        for hit in hits:
            payload = hit.get("payload") or {}
            results.append(
                {
                    "id": payload.get("technique_id", hit.get("id")),
                    "name": payload.get("name", ""),
                    "score": round(float(hit.get("score", 0)), 3),
                    "description": (payload.get("description") or "")[:200],
                }
            )
        return results

    try:
        final_results = run_coro_sync(_search())
    except Exception:
        final_results = []

    run_coro_sync(cache_set_json(cache_key, final_results, ttl=3600))
    return final_results


@tool
def search_mitre_techniques(query: str, limit: int = 5) -> str:
    """Semantic search MITRE ATT&CK techniques via Qdrant embeddings."""
    results = search_mitre_techniques_raw(query, limit=limit)
    return f"MITRE Search Results for '{query}': {results}"
