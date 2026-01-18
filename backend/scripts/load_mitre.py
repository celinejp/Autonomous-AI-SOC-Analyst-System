"""Load MITRE ATT&CK data into Qdrant vector database with Ollama embeddings."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import httpx
import asyncio
from typing import List, Dict, Any

from qdrant_client.models import PointStruct, VectorParams, Distance

from app.database.vector_store import get_qdrant_client
from app.services.embedding_service import get_embedding, EMBEDDING_DIM
from app.core.logging import get_logger

logger = get_logger(__name__)

MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


async def download_mitre_data() -> Dict[str, Any]:
    """Download MITRE ATT&CK data from GitHub."""
    logger.info("Downloading MITRE ATT&CK data...")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(MITRE_ATTACK_URL, timeout=60.0)
            response.raise_for_status()
            data = response.json()
            logger.info(f"Downloaded MITRE data: {len(data.get('objects', []))} objects")
            return data
    except Exception as e:
        logger.error(f"Failed to download MITRE data: {e}")
        return get_sample_techniques()


def get_sample_techniques() -> Dict[str, Any]:
    """Return sample MITRE techniques for demo."""
    return {
        "objects": [
            {"type": "attack-pattern", "x_mitre_id": "T1078", "name": "Valid Accounts",
             "description": "Adversaries may steal the credentials of a specific user or service account using credential access techniques.",
             "kill_chain_phases": [{"phase_name": "defense-evasion"}, {"phase_name": "persistence"}]},
            {"type": "attack-pattern", "x_mitre_id": "T1110", "name": "Brute Force",
             "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.",
             "kill_chain_phases": [{"phase_name": "credential-access"}]},
            {"type": "attack-pattern", "x_mitre_id": "T1059", "name": "Command and Scripting Interpreter",
             "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
             "kill_chain_phases": [{"phase_name": "execution"}]},
            {"type": "attack-pattern", "x_mitre_id": "T1486", "name": "Data Encrypted for Impact",
             "description": "Adversaries may encrypt data on target systems to interrupt availability. Ransomware.",
             "kill_chain_phases": [{"phase_name": "impact"}]},
            {"type": "attack-pattern", "x_mitre_id": "T1021", "name": "Remote Services",
             "description": "Adversaries may use valid accounts to log into a service for lateral movement.",
             "kill_chain_phases": [{"phase_name": "lateral-movement"}]},
            {"type": "attack-pattern", "x_mitre_id": "T1566", "name": "Phishing",
             "description": "Adversaries may send phishing messages to gain access to victim systems.",
             "kill_chain_phases": [{"phase_name": "initial-access"}]},
            {"type": "attack-pattern", "x_mitre_id": "T1055", "name": "Process Injection",
             "description": "Adversaries may inject code into processes to evade defenses and elevate privileges.",
             "kill_chain_phases": [{"phase_name": "defense-evasion"}, {"phase_name": "privilege-escalation"}]},
            {"type": "attack-pattern", "x_mitre_id": "T1003", "name": "OS Credential Dumping",
             "description": "Adversaries may dump credentials to obtain account login and credential material.",
             "kill_chain_phases": [{"phase_name": "credential-access"}]},
        ]
    }


def extract_techniques(mitre_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract technique objects from MITRE data."""
    techniques = []
    
    for obj in mitre_data.get("objects", []):
        if obj.get("type") == "attack-pattern" and obj.get("x_mitre_id"):
            technique = {
                "technique_id": obj.get("x_mitre_id"),
                "name": obj.get("name", ""),
                "description": obj.get("description", "")[:1000],
                "tactics": [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", [])],
                "platforms": obj.get("x_mitre_platforms", []),
            }
            techniques.append(technique)
    
    logger.info(f"Extracted {len(techniques)} techniques")
    return techniques


async def load_techniques_to_qdrant(techniques: List[Dict[str, Any]]):
    """Load techniques into Qdrant with Ollama embeddings."""
    client = get_qdrant_client()
    collection_name = "mitre_techniques"
    
    # Create collection
    try:
        client.recreate_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(size=EMBEDDING_DIM, distance=Distance.COSINE)
        )
        logger.info(f"Created collection {collection_name}")
    except Exception as e:
        logger.warning(f"Collection setup: {e}")
    
    points = []
    for idx, technique in enumerate(techniques):
        text_for_embedding = f"{technique['name']}: {technique['description']}"
        
        logger.info(f"Generating embedding for {technique['technique_id']} ({idx+1}/{len(techniques)})")
        embedding = await get_embedding(text_for_embedding, use_cache=False)
        
        point = PointStruct(
            id=idx,
            vector=embedding,
            payload={
                "technique_id": technique["technique_id"],
                "name": technique["name"],
                "description": technique["description"],
                "tactics": technique["tactics"],
                "platforms": technique.get("platforms", []),
            },
        )
        points.append(point)
        
        # Batch upload every 50 points
        if len(points) >= 50:
            client.upsert(collection_name=collection_name, points=points)
            logger.info(f"Uploaded {len(points)} techniques")
            points = []
    
    # Upload remaining
    if points:
        client.upsert(collection_name=collection_name, points=points)
        logger.info(f"Uploaded final {len(points)} techniques")
    
    logger.info(f"Successfully loaded {len(techniques)} techniques to Qdrant")


async def main():
    """Main function to load MITRE data."""
    logger.info("Starting MITRE ATT&CK data loading...")
    
    try:
        mitre_data = await download_mitre_data()
        techniques = extract_techniques(mitre_data)
        
        if not techniques:
            logger.warning("No techniques extracted, using sample data")
            techniques = extract_techniques(get_sample_techniques())
        
        await load_techniques_to_qdrant(techniques)
        logger.info("MITRE ATT&CK data loading complete!")
        
    except Exception as e:
        logger.error(f"Error loading MITRE data: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
