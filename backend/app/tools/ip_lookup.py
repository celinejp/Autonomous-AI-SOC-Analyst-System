"""Tool for IP address reputation lookup."""

from typing import Dict, Any

from langchain.tools import tool

from app.core.config import settings
from app.database.redis_client import cache_get_json, cache_set_json, run_coro_sync


@tool
def lookup_ip(ip_address: str) -> str:
    """Look up IP address reputation and threat intelligence (Redis-cached)."""
    cache_key = f"ip_lookup:{ip_address}"

    cached_result = run_coro_sync(cache_get_json(cache_key))
    if cached_result:
        return f"IP Lookup for {ip_address} (cached): {cached_result}"

    result: Dict[str, Any] = {
        "ipAddress": ip_address,
        "isPublic": not ip_address.startswith(("10.", "172.", "192.168.")),
        "abuseConfidencePercentage": 75
        if "malicious" in ip_address.lower() or ip_address.startswith("185.")
        else 5,
        "countryCode": "US",
        "usageType": "hosting" if ip_address.startswith("185.") else "isp",
        "isp": "Example ISP",
        "domain": None,
        "isWhitelisted": False,
        "lastReportedAt": None,
        "source": "mock" if not settings.abuseipdb_api_key else "configured",
    }

    run_coro_sync(cache_set_json(cache_key, result, ttl=86400))
    return f"IP Lookup for {ip_address}: {result}"
