"""File intelligence lookup tool for hash reputation and analysis."""

from typing import List, Optional
from pydantic import BaseModel, Field
from langchain.tools import BaseTool


class FileIntelInput(BaseModel):
    """Input schema for file intelligence lookup."""

    hash_value: str = Field(description="MD5, SHA1, or SHA256 hash of the file")
    hash_type: str = Field(default="sha256", description="Type of hash: md5, sha1, or sha256")


class FileIntelResult(BaseModel):
    """File intelligence lookup result."""

    hash: str
    hash_type: str
    found: bool = False

    # Reputation
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    reputation_score: float = 0.0  # -100 to 100

    # Static analysis
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    file_names: List[str] = Field(default_factory=list)
    magic_bytes: Optional[str] = None
    is_signed: Optional[bool] = None
    signer: Optional[str] = None
    signature_valid: Optional[bool] = None

    # Threat classification
    malware_family: Optional[str] = None
    malware_type: Optional[str] = None  # trojan, ransomware, rat, miner, etc.
    threat_names: List[str] = Field(default_factory=list)

    # Behavioral indicators (from sandbox)
    creates_files: List[str] = Field(default_factory=list)
    modifies_registry: List[str] = Field(default_factory=list)
    network_connections: List[str] = Field(default_factory=list)
    processes_spawned: List[str] = Field(default_factory=list)
    persistence_mechanisms: List[str] = Field(default_factory=list)

    # ATT&CK mapping
    attack_techniques: List[str] = Field(default_factory=list)

    # Context
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    related_campaigns: List[str] = Field(default_factory=list)
    related_actors: List[str] = Field(default_factory=list)


class FileIntelTool(BaseTool):
    """File intelligence lookup tool."""

    name: str = "file_intelligence_lookup"
    description: str = (
        "Look up file hash reputation and analysis from threat intelligence sources "
        "(VirusTotal, Hybrid Analysis style). Returns malware family, reputation, "
        "behavioral indicators, and ATT&CK technique mapping."
    )
    args_schema: type[BaseModel] = FileIntelInput

    def _run(self, hash_value: str, hash_type: str = "sha256") -> str:
        """
        Query file intelligence.
        In production, integrate with:
        - VirusTotal API
        - Hybrid Analysis API
        - Internal malware database
        For demo, return simulated results for known test hashes.
        """
        # Demo mode: simulate results for test hashes
        demo_hashes = {
            "sha256": {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
                    "found": True,
                    "reputation_score": 0.0,
                    "harmless_count": 100,
                    "malicious_count": 0,
                },
                # Add more demo hashes as needed
            }
        }

        demo_data = demo_hashes.get(hash_type, {}).get(hash_value.lower(), {})

        if demo_data:
            result = FileIntelResult(
                hash=hash_value,
                hash_type=hash_type,
                found=True,
                **demo_data,
            )
        else:
            # Unknown hash - return neutral result
            result = FileIntelResult(
                hash=hash_value,
                hash_type=hash_type,
                found=False,
                reputation_score=0.0,
            )

        # Format as string for tool response
        return result.model_dump_json(indent=2)


async def _arun(self, hash_value: str, hash_type: str = "sha256") -> str:
    """Async version of file intelligence lookup."""
    return self._run(hash_value, hash_type)

# Monkey patch for async support
FileIntelTool._arun = _arun

