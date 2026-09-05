"""Semantic search endpoints for incidents and MITRE techniques."""

from typing import List, Optional
from pydantic import BaseModel, Field

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database.postgres import get_db
from app.database.vector_store import get_qdrant_client
from app.services.embedding_service import get_embedding, EMBEDDING_DIM
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["semantic-search"])


class SemanticSearchRequest(BaseModel):
    """Request for semantic search."""
    query: str = Field(..., min_length=1, max_length=1000, description="Search query text")
    limit: int = Field(default=10, ge=1, le=50, description="Number of results")


class IncidentSearchResult(BaseModel):
    """Incident search result with similarity score."""
    id: str
    severity: Optional[str]
    status: Optional[str]
    confidence_score: float
    search_text: Optional[str]
    similarity: float
    created_at: Optional[str]


class SemanticSearchResponse(BaseModel):
    """Response for semantic search."""
    query: str
    results: List[IncidentSearchResult]
    total: int


class MITRESearchResult(BaseModel):
    """MITRE technique search result."""
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    similarity: float


class MITRESearchResponse(BaseModel):
    """Response for MITRE search."""
    query: str
    results: List[MITRESearchResult]
    total: int


@router.post("/incidents/search/semantic", response_model=SemanticSearchResponse)
async def semantic_search_incidents(
    request: SemanticSearchRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Search incidents by semantic similarity.
    
    Uses pgvector cosine similarity to find incidents matching the query meaning.
    """
    try:
        # Generate query embedding
        query_embedding = await get_embedding(request.query)
        
        if len(query_embedding) != EMBEDDING_DIM:
            raise HTTPException(status_code=500, detail="Embedding dimension mismatch")
        
        # Format embedding for PostgreSQL
        embedding_str = "[" + ",".join(map(str, query_embedding)) + "]"
        
        # Query using pgvector cosine similarity with raw SQL
        # Use string formatting for embedding (safe since we control the values)
        sql = text(f"""
            SELECT 
                id,
                severity,
                status,
                confidence_score,
                search_text,
                created_at,
                1 - (embedding <=> '{embedding_str}'::vector) as similarity
            FROM incidents
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> '{embedding_str}'::vector
            LIMIT {request.limit}
        """)
        
        result = await db.execute(sql)
        rows = result.fetchall()
        
        if not rows:
            return SemanticSearchResponse(
                query=request.query,
                results=[],
                total=0
            )
        
        results = []
        for row in rows:
            results.append(IncidentSearchResult(
                id=str(row.id),
                severity=getattr(row.severity, "value", row.severity) if row.severity else None,
                status=getattr(row.status, "value", row.status) if row.status else None,
                confidence_score=row.confidence_score or 0.0,
                search_text=row.search_text[:200] if row.search_text else None,
                similarity=round(row.similarity, 4) if row.similarity else 0.0,
                created_at=row.created_at.isoformat() if row.created_at else None
            ))
        
        return SemanticSearchResponse(
            query=request.query,
            results=results,
            total=len(results)
        )
        
    except Exception as e:
        logger.error(f"Semantic search error: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.get("/mitre/search", response_model=MITRESearchResponse)
async def search_mitre_techniques(
    q: str,
    limit: int = 10
):
    """
    Search MITRE ATT&CK techniques by semantic similarity.
    
    Uses Qdrant vector database to find relevant techniques.
    """
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Query too short")
    
    try:
        # Generate query embedding
        query_embedding = await get_embedding(q)
        
        # Search Qdrant
        client = get_qdrant_client()
        
        search_results = client.search(
            collection_name="mitre_techniques",
            query_vector=query_embedding,
            limit=min(limit, 50),
            with_payload=True
        )
        
        if not search_results:
            return MITRESearchResponse(
                query=q,
                results=[],
                total=0
            )
        
        results = []
        for hit in search_results:
            payload = hit.payload or {}
            results.append(MITRESearchResult(
                technique_id=payload.get("technique_id", ""),
                name=payload.get("name", ""),
                description=payload.get("description", "")[:500],
                tactics=payload.get("tactics", []),
                similarity=round(hit.score, 4)
            ))
        
        return MITRESearchResponse(
            query=q,
            results=results,
            total=len(results)
        )
        
    except Exception as e:
        logger.error(f"MITRE search error: {e}")
        # Return empty results instead of error for missing collection
        if "not found" in str(e).lower():
            return MITRESearchResponse(
                query=q,
                results=[],
                total=0
            )
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.post("/incidents/{incident_id}/generate-embedding")
async def generate_incident_embedding(
    incident_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Generate and store embedding for a specific incident."""
    try:
        # Get incident with report
        sql = text("""
            SELECT i.id, i.severity, i.status, 
                   r.executive_summary, r.technical_findings, r.root_cause
            FROM incidents i
            LEFT JOIN incident_reports r ON r.incident_id = i.id
            WHERE i.id = :incident_id
        """)
        result = await db.execute(sql, {"incident_id": incident_id})
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Build search text
        parts = []
        if row.severity:
            parts.append(f"Severity: {row.severity}")
        if row.executive_summary:
            parts.append(row.executive_summary)
        if row.technical_findings:
            parts.append(row.technical_findings[:500])
        if row.root_cause:
            parts.append(f"Root cause: {row.root_cause}")
        
        search_text = " ".join(parts) if parts else "Security incident"
        
        # Generate embedding
        embedding = await get_embedding(search_text)
        embedding_str = "[" + ",".join(map(str, embedding)) + "]"
        
        # Update incident
        update_sql = text("""
            UPDATE incidents
            SET search_text = :search_text, embedding = CAST(:embedding AS vector)
            WHERE id = :incident_id
        """)
        await db.execute(update_sql, {
            "search_text": search_text,
            "embedding": embedding_str,
            "incident_id": incident_id
        })
        await db.commit()
        
        return {"status": "success", "incident_id": incident_id, "embedding_dim": len(embedding)}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Embedding generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

