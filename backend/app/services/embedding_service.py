"""Embedding service using Ollama nomic-embed-text."""

import json
import hashlib
from typing import List, Optional

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.database.redis_client import get_redis_client

logger = get_logger(__name__)

EMBEDDING_MODEL = "nomic-embed-text"
EMBEDDING_DIM = 768  # nomic-embed-text dimension
CACHE_TTL = 3600  # 1 hour


async def get_embedding(text: str, use_cache: bool = True) -> List[float]:
    """Generate embedding using Ollama nomic-embed-text with Redis caching."""
    
    # Create cache key
    cache_key = f"embedding:{hashlib.md5(text.encode()).hexdigest()}"
    
    # Check cache
    if use_cache:
        redis = get_redis_client()
        if redis:
            try:
                cached = redis.get(cache_key)
                if cached:
                    logger.debug(f"Cache hit for embedding")
                    return json.loads(cached)
            except Exception as e:
                logger.warning(f"Redis cache error: {e}")
    
    # Generate embedding via Ollama
    ollama_url = settings.ollama_base_url or "http://localhost:11434"
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{ollama_url}/api/embeddings",
                json={"model": EMBEDDING_MODEL, "prompt": text}
            )
            response.raise_for_status()
            data = response.json()
            embedding = data.get("embedding", [])
            
            if not embedding:
                logger.error("Empty embedding returned from Ollama")
                return _fallback_embedding(text)
            
            # Cache result
            if use_cache:
                redis = get_redis_client()
                if redis:
                    try:
                        redis.setex(cache_key, CACHE_TTL, json.dumps(embedding))
                    except Exception as e:
                        logger.warning(f"Failed to cache embedding: {e}")
            
            return embedding
            
    except Exception as e:
        logger.error(f"Ollama embedding error: {e}")
        return _fallback_embedding(text)


def _fallback_embedding(text: str) -> List[float]:
    """Fallback deterministic embedding when Ollama unavailable."""
    import hashlib
    hash_bytes = hashlib.sha256(text.encode()).digest()
    embedding = []
    for i in range(EMBEDDING_DIM):
        byte_idx = i % len(hash_bytes)
        embedding.append((hash_bytes[byte_idx] - 128) / 128.0)
    return embedding


async def get_batch_embeddings(texts: List[str]) -> List[List[float]]:
    """Generate embeddings for multiple texts."""
    embeddings = []
    for text in texts:
        emb = await get_embedding(text)
        embeddings.append(emb)
    return embeddings

