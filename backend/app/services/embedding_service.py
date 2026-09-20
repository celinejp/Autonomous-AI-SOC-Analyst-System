"""Embedding service using Ollama nomic-embed-text."""

import json
import hashlib
from typing import List

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.database.redis_client import get_redis_client

logger = get_logger(__name__)

EMBEDDING_MODEL = "nomic-embed-text"
EMBEDDING_DIM = 768  # nomic-embed-text — must match pgvector + Qdrant VECTOR_SIZE
CACHE_TTL = 3600


class EmbeddingError(RuntimeError):
    """The embedding model could not produce a vector."""


async def get_embedding(text: str, use_cache: bool = True) -> List[float]:
    """Generate embedding using Ollama nomic-embed-text with Redis caching."""
    cache_key = f"embedding:{hashlib.md5(text.encode()).hexdigest()}"

    if use_cache:
        try:
            redis = get_redis_client()
            cached = await redis.get(cache_key)
            if cached:
                logger.debug("Cache hit for embedding")
                return json.loads(cached)
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")

    ollama_url = settings.ollama_base_url or "http://localhost:11434"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{ollama_url}/api/embeddings",
                json={"model": EMBEDDING_MODEL, "prompt": text},
            )
            response.raise_for_status()
            data = response.json()
            embedding = data.get("embedding", [])

            if not embedding:
                raise EmbeddingError("Ollama returned an empty embedding")

            if use_cache:
                try:
                    redis = get_redis_client()
                    await redis.setex(cache_key, CACHE_TTL, json.dumps(embedding))
                except Exception as e:
                    logger.warning(f"Failed to cache embedding: {e}")

            return embedding

    except EmbeddingError:
        raise
    except Exception as e:
        # Fail loudly: a fake vector would make every similarity result meaningless.
        logger.error(f"Ollama embedding error: {e}")
        raise EmbeddingError(f"Embedding service unavailable: {e}") from e
