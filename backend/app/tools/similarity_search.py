"""Tool for semantic similarity search of past incidents."""

from typing import Dict, Any, List

from langchain.tools import tool

from app.database.vector_store import search_vectors


@tool
def search_similar_incidents(description: str, limit: int = 5) -> str:
    """Search for similar past incidents using semantic similarity.
    
    This tool searches through historical incidents to find cases with similar
    attack patterns, behaviors, or indicators. Helps identify recurring threats
    and apply lessons learned from previous incidents.
    
    Args:
        description: Natural language description of the current incident
        limit: Maximum number of similar incidents to return (default: 5)
    
    Returns:
        JSON string with similar incidents including:
        - incident_id: Unique identifier
        - similarity_score: How similar (0-1)
        - summary: Brief incident summary
        - resolution: How it was resolved
        - mitre_techniques: Associated MITRE techniques
    """
    # In production, this would:
    # 1. Generate embedding for description
    # 2. Search Qdrant incident collection
    # 3. Return most similar incidents
    
    # Mock response for demo
    results = [
        {
            "incident_id": "inc-001",
            "similarity_score": 0.87,
            "summary": "SSH brute force attack leading to lateral movement",
            "resolution": "Blocked source IP, rotated credentials, reviewed access logs",
            "mitre_techniques": ["T1110", "T1078"],
        },
        {
            "incident_id": "inc-045",
            "similarity_score": 0.82,
            "summary": "Multiple failed login attempts from suspicious IP",
            "resolution": "False positive - legitimate admin activity",
            "mitre_techniques": [],
        },
    ]
    
    return f"Similar Incidents for '{description[:50]}...': {results[:limit]}"

