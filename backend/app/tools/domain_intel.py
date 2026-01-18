"""Domain/URL intelligence lookup tool."""

from typing import List, Optional
from pydantic import BaseModel, Field
from langchain.tools import BaseTool


class DomainIntelInput(BaseModel):
    """Input schema for domain intelligence lookup."""

    domain: str = Field(description="Domain name to look up")


class DomainIntelResult(BaseModel):
    """Domain intelligence lookup result."""

    domain: str
    found: bool = False

    # Reputation
    reputation_score: float = 0.0  # -100 to 100
    categories: List[str] = Field(default_factory=list)  # malware, phishing, c2, benign, etc.

    # WHOIS data
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    registrant_country: Optional[str] = None
    domain_age_days: Optional[int] = None

    # DNS data
    a_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)

    # Threat context
    is_dga: bool = False  # Domain Generation Algorithm
    dga_family: Optional[str] = None
    is_fast_flux: bool = False
    associated_malware: List[str] = Field(default_factory=list)
    associated_campaigns: List[str] = Field(default_factory=list)
    associated_actors: List[str] = Field(default_factory=list)

    # Historical data
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    recent_ips: List[str] = Field(default_factory=list)


class DomainIntelTool(BaseTool):
    """Domain intelligence lookup tool."""

    name: str = "domain_intelligence_lookup"
    description: str = (
        "Look up domain reputation and threat intelligence. Returns WHOIS data, "
        "DNS records, threat categorization, DGA detection, and historical context."
    )
    args_schema: type[BaseModel] = DomainIntelInput

    def _run(self, domain: str) -> str:
        """
        Query domain intelligence.
        In production, integrate with:
        - VirusTotal API
        - PassiveTotal API
        - Internal threat intelligence
        For demo, return simulated results.
        """
        # Demo mode: simulate results for test domains
        demo_domains = {
            "malicious-example.com": {
                "found": True,
                "reputation_score": -85.0,
                "categories": ["malware", "c2"],
                "domain_age_days": 5,
                "is_dga": True,
            },
            # Add more demo domains as needed
        }

        domain_lower = domain.lower()
        demo_data = demo_domains.get(domain_lower, {})

        if demo_data:
            result = DomainIntelResult(domain=domain, found=True, **demo_data)
        else:
            # Unknown domain - return neutral result
            result = DomainIntelResult(
                domain=domain,
                found=False,
                reputation_score=0.0,
                categories=["unknown"],
            )

        # Format as string for tool response
        return result.model_dump_json(indent=2)


async def _arun(self, domain: str) -> str:
    """Async version of domain intelligence lookup."""
    return self._run(domain)

# Monkey patch for async support
DomainIntelTool._arun = _arun

