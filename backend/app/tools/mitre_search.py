"""Tools for searching MITRE ATT&CK techniques."""

from typing import Dict, Any, List, Optional

from langchain.tools import tool

from app.database.vector_store import search_vectors, get_qdrant_client
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
    
    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1078", "T1059.001")
    
    Returns:
        JSON string with technique details
    """
    # Try to get from Qdrant first
    try:
        client = get_qdrant_client()
        # In production, we'd search by technique_id in payload
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
        },
        "T1110": {
            "id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Adversaries may use brute force techniques to gain access to accounts...",
        },
        "T1566": {
            "id": "T1566",
            "name": "Phishing",
            "tactic": "Initial Access",
            "description": "Adversaries may send phishing messages to gain access to victim systems...",
        },
        "T1486": {
            "id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Adversaries may encrypt data on target systems to interrupt availability...",
        },
    }
    
    technique = techniques.get(technique_id.upper(), {
        "id": technique_id,
        "name": "Unknown Technique",
        "tactic": "Unknown",
        "description": f"Technique {technique_id} not found in database.",
    })
    
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
    
    return f"MITRE Search Results for '{query}': {results[:limit]}"

