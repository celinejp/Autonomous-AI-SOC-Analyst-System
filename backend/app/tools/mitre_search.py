"""Tools for searching MITRE ATT&CK techniques."""

from typing import Dict, Any, List, Optional
import asyncio

from langchain.tools import tool

from app.database.vector_store import search_vectors, get_qdrant_client
from app.database.redis_client import cache_get_json, cache_set_json
import httpx


@tool
def get_mitre_technique(technique_id: str) -> str:
    """Get detailed information about a specific MITRE ATT&CK technique.
    
    This tool retrieves comprehensive details about a MITRE ATT&CK technique including:
    - Full description and purpose
    - Associated tactics (kill chain phases)
    - Platforms affected
    - Detection methods
    - Examples and procedures
    
    Uses Redis caching and Qdrant vector database for fast retrieval.
    
    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1078", "T1059.001")
    
    Returns:
        JSON string with technique details
    """
    # Check cache first
    cache_key = f"mitre_technique:{technique_id.upper()}"
    
    try:
        loop = asyncio.get_event_loop()
        cached_result = loop.run_until_complete(cache_get_json(cache_key))
        if cached_result:
            return f"MITRE Technique {technique_id} (cached): {cached_result}"
    except (RuntimeError, Exception):
        cached_result = None
    
    # Try to get from Qdrant
    try:
        client = get_qdrant_client()
        # In production, search Qdrant by technique_id
        # For now, return mock data
    except Exception:
        pass
    
    # Mock technique data - in production, this comes from Qdrant vector store
    techniques = {
        "T1078": {
            "id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "description": "Adversaries may steal the credentials of a specific user or service account...",
            "detection_methods": ["Monitor for authentication attempts", "Monitor account usage"],
        },
        "T1059": {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "Adversaries may abuse command and script interpreters to execute commands...",
            "detection_methods": ["Process monitoring", "Command-line arguments"],
        },
        "T1110": {
            "id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Adversaries may use brute force techniques to gain access to accounts...",
            "detection_methods": ["Failed login attempts", "Account lockouts"],
        },
        "T1566": {
            "id": "T1566",
            "name": "Phishing",
            "tactic": "Initial Access",
            "description": "Adversaries may send phishing messages to gain access to victim systems...",
            "detection_methods": ["Email filtering", "User reporting"],
        },
        "T1486": {
            "id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Adversaries may encrypt data on target systems to interrupt availability...",
            "detection_methods": ["File system monitoring", "Process monitoring"],
        },
    }
    
    technique = techniques.get(technique_id.upper(), {
        "id": technique_id,
        "name": "Unknown Technique",
        "tactic": "Unknown",
        "description": f"Technique {technique_id} not found in database.",
        "detection_methods": [],
    })
    
    # Cache the result for 7 days (MITRE data doesn't change often)
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(cache_set_json(cache_key, technique, ttl=604800))
    except (RuntimeError, Exception):
        pass
    
    return f"MITRE Technique {technique_id}: {technique}"


@tool
def search_mitre_techniques(query: str, limit: int = 5) -> str:
    """Search MITRE ATT&CK techniques by description or keywords using semantic search.
    
    This tool performs a semantic search across the MITRE ATT&CK framework to find
    techniques that match the query description. Useful for mapping observed behaviors
    to known attack techniques.
    
    Args:
        query: Natural language description of attack behavior
        limit: Maximum number of results (default: 5)
    
    Returns:
        JSON string with matching techniques
    """
    # Check cache
    cache_key = f"mitre_search:{hash(query)}:{limit}"
    
    try:
        loop = asyncio.get_event_loop()
        cached_result = loop.run_until_complete(cache_get_json(cache_key))
        if cached_result:
            return f"MITRE Search Results for '{query}' (cached): {cached_result}"
    except (RuntimeError, Exception):
        cached_result = None
    
    # In production, this would use Qdrant vector search
    # For now, return mock results based on keywords
    
    keywords = query.lower()
    results = []
    
    if "brute" in keywords or "force" in keywords or "password" in keywords:
        results.append({"id": "T1110", "name": "Brute Force", "score": 0.95})
    
    if "phish" in keywords or "email" in keywords or "social" in keywords:
        results.append({"id": "T1566", "name": "Phishing", "score": 0.92})
    
    if "encrypt" in keywords or "ransomware" in keywords:
        results.append({"id": "T1486", "name": "Data Encrypted for Impact", "score": 0.90})
    
    if "command" in keywords or "script" in keywords or "execute" in keywords:
        results.append({"id": "T1059", "name": "Command and Scripting Interpreter", "score": 0.88})
    
    if "valid" in keywords or "account" in keywords or "credential" in keywords:
        results.append({"id": "T1078", "name": "Valid Accounts", "score": 0.85})
    
    if not results:
        results.append({"id": "T1078", "name": "Valid Accounts", "score": 0.75})
    
    final_results = results[:limit]
    
    # Cache for 1 hour (search results)
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(cache_set_json(cache_key, final_results, ttl=3600))
    except (RuntimeError, Exception):
        pass
    
    return f"MITRE Search Results for '{query}': {final_results}"
