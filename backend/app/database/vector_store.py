"""Qdrant vector database client (768-dim, aligned with nomic-embed-text / pgvector)."""

from typing import List, Optional, Union
import uuid as uuid_lib

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

VECTOR_SIZE = 768  # Must match EMBEDDING_DIM / pgvector column

_client: Optional[QdrantClient] = None


def get_qdrant_client() -> QdrantClient:
    """Get or create Qdrant client."""
    global _client
    if _client is None:
        _client = QdrantClient(
            url=settings.qdrant_url,
            api_key=settings.qdrant_api_key if settings.qdrant_api_key else None,
        )
    return _client


def _point_id(raw: Optional[Union[str, int]], fallback_index: int):
    """Normalize IDs to UUID or int for Qdrant."""
    if raw is None:
        return fallback_index
    if isinstance(raw, int):
        return raw
    try:
        return str(uuid_lib.UUID(str(raw)))
    except (ValueError, AttributeError):
        # Deterministic UUID5 from string so retries overwrite same point
        return str(uuid_lib.uuid5(uuid_lib.NAMESPACE_URL, str(raw)))


async def ensure_collection(collection_name: str, vector_size: int = VECTOR_SIZE) -> None:
    """Ensure a collection exists with the expected vector size."""
    client = get_qdrant_client()
    try:
        info = client.get_collection(collection_name)
        existing = info.config.params.vectors.size
        if existing != vector_size:
            logger.warning(
                "Recreating Qdrant collection due to dim mismatch",
                collection=collection_name,
                existing=existing,
                expected=vector_size,
            )
            client.delete_collection(collection_name)
            raise Exception("recreate")
    except Exception:
        client.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(
                size=vector_size,
                distance=Distance.COSINE,
            ),
        )
        logger.info("Created Qdrant collection", collection=collection_name, size=vector_size)


async def upsert_vectors(
    collection_name: str,
    vectors: List[List[float]],
    payloads: List[dict],
    ids: Optional[List[str]] = None,
) -> None:
    """Upsert vectors into Qdrant collection."""
    if not vectors:
        return
    client = get_qdrant_client()
    dim = len(vectors[0])
    await ensure_collection(collection_name, dim)

    points = [
        PointStruct(
            id=_point_id(ids[i] if ids else None, i),
            vector=vectors[i],
            payload=payloads[i],
        )
        for i in range(len(vectors))
    ]
    client.upsert(collection_name=collection_name, points=points)


async def search_vectors(
    collection_name: str,
    query_vector: List[float],
    limit: int = 10,
    score_threshold: float = 0.5,
) -> List[dict]:
    """Search for similar vectors in Qdrant."""
    client = get_qdrant_client()
    results = client.search(
        collection_name=collection_name,
        query_vector=query_vector,
        limit=limit,
        score_threshold=score_threshold,
    )
    return [
        {
            "id": hit.id,
            "score": hit.score,
            "payload": hit.payload,
        }
        for hit in results
    ]


async def scroll_by_payload(
    collection_name: str,
    key: str,
    value: str,
    limit: int = 1,
) -> List[dict]:
    """Fetch points filtered by payload field (exact match)."""
    from qdrant_client.models import Filter, FieldCondition, MatchValue

    client = get_qdrant_client()
    points, _ = client.scroll(
        collection_name=collection_name,
        scroll_filter=Filter(
            must=[FieldCondition(key=key, match=MatchValue(value=value))]
        ),
        limit=limit,
        with_payload=True,
        with_vectors=False,
    )
    return [{"id": p.id, "payload": p.payload} for p in points]
