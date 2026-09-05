"""Embedding + vector sync service (Postgres pgvector + Qdrant dual-write)."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.database.vector_store import upsert_vectors, VECTOR_SIZE
from app.services.embedding_service import get_embedding, EMBEDDING_DIM

logger = get_logger(__name__)

assert EMBEDDING_DIM == VECTOR_SIZE == 768, "Embedding dims must stay aligned"


async def build_incident_search_text(session: AsyncSession, incident_id: str) -> Optional[str]:
    sql = text("""
        SELECT i.id, i.severity, i.status,
               r.executive_summary, r.technical_findings, r.root_cause
        FROM incidents i
        LEFT JOIN incident_reports r ON r.incident_id = i.id
        WHERE i.id = :incident_id
    """)
    result = await session.execute(sql, {"incident_id": incident_id})
    row = result.fetchone()
    if not row:
        return None

    parts = []
    if row.severity:
        parts.append(f"Severity: {row.severity}")
    if row.executive_summary:
        parts.append(row.executive_summary)
    if row.technical_findings:
        parts.append(row.technical_findings[:500])
    if row.root_cause:
        parts.append(f"Root cause: {row.root_cause}")
    return " ".join(parts) if parts else "Security incident"


async def sync_incident_vectors(session: AsyncSession, incident_id: str) -> dict:
    """
    Write embedding to Postgres (source of truth) then upsert to Qdrant.
    Idempotent — safe to retry from the embed job queue.
    """
    search_text = await build_incident_search_text(session, incident_id)
    if search_text is None:
        raise ValueError(f"Incident not found: {incident_id}")

    embedding = await get_embedding(search_text)
    if len(embedding) != EMBEDDING_DIM:
        raise ValueError(f"Bad embedding dim {len(embedding)}, expected {EMBEDDING_DIM}")

    embedding_str = "[" + ",".join(map(str, embedding)) + "]"
    await session.execute(
        text("""
            UPDATE incidents
            SET search_text = :search_text, embedding = CAST(:embedding AS vector)
            WHERE id = :incident_id
        """),
        {
            "search_text": search_text,
            "embedding": embedding_str,
            "incident_id": incident_id,
        },
    )
    await session.commit()

    # Dual-write to Qdrant for agent similarity tool (best-effort after Postgres commit)
    try:
        await upsert_vectors(
            collection_name="incidents",
            vectors=[embedding],
            payloads=[
                {
                    "incident_id": incident_id,
                    "search_text": search_text[:500],
                }
            ],
            ids=[incident_id],
        )
    except Exception as e:
        # Postgres already has the vector; Qdrant can catch up on retry
        logger.warning("Qdrant dual-write failed; will retry via queue", error=str(e))
        raise

    return {
        "incident_id": incident_id,
        "embedding_dim": len(embedding),
        "search_text_len": len(search_text),
    }
