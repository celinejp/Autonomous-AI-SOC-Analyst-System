"""Qdrant vector database client."""

from typing import List, Optional

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from qdrant_client.http import models

from app.core.config import settings

# Qdrant client singleton
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


async def ensure_collection(collection_name: str, vector_size: int = 1536) -> None:
    """Ensure a collection exists in Qdrant."""
    client = get_qdrant_client()
    try:
        client.get_collection(collection_name)
    except Exception:
        client.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(
                size=vector_size,
                distance=Distance.COSINE,
            ),
        )


async def upsert_vectors(
    collection_name: str,
    vectors: List[List[float]],
    payloads: List[dict],
    ids: Optional[List[str]] = None,
) -> None:
    """Upsert vectors into Qdrant collection."""
    client = get_qdrant_client()
    await ensure_collection(collection_name, len(vectors[0]) if vectors else 1536)

    points = [
        PointStruct(
            id=ids[i] if ids else i,
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
    score_threshold: float = 0.7,
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

