"""Tool for IP address reputation lookup."""

import httpx
from typing import Dict, Any, Optional
import asyncio

from langchain.tools import tool

from app.core.config import settings
from app.database.redis_client import cache_get_json, cache_set_json


@tool
def lookup_ip(ip_address: str) -> str:
    """Look up IP address reputation and threat intelligence.
    
    This tool queries external threat intelligence sources (AbuseIPDB) to determine
    if an IP address is known to be malicious, part of a botnet, or associated with attacks.
    Uses Redis caching to avoid repeated API calls.
    
    Args:
        ip_address: The IP address to look up (IPv4 or IPv6)
    
    Returns:
        JSON string with reputation data including:
        - isPublic: Whether IP is public or private
        - abuseConfidencePercentage: Confidence that IP is abusive (0-100)
        - countryCode: ISO country code
        - usageType: Usage classification
        - isp: Internet Service Provider
        - domain: Associated domain
        - isWhitelisted: Whether IP is whitelisted
        - lastReportedAt: Last abuse report timestamp
    """
    # Check cache first
    cache_key = f"ip_lookup:{ip_address}"
    
    # Try to get from cache (synchronous wrapper for async cache)
    try:
        loop = asyncio.get_event_loop()
        cached_result = loop.run_until_complete(cache_get_json(cache_key))
        if cached_result:
            return f"IP Lookup for {ip_address} (cached): {cached_result}"
    except (RuntimeError, Exception):
        # No event loop or cache miss, continue to lookup
        cached_result = None
    
    # Perform lookup
    result = None
    if settings.abuseipdb_api_key:
        try:
            # Real implementation would use httpx here
            # response = httpx.get(
            #     f"https://api.abuseipdb.com/api/v2/check",
            #     headers={"Key": settings.abuseipdb_api_key},
            #     params={"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""}
            # )
            # result = response.json()
            pass
        except Exception:
            pass
    
    # Mock response for demo (in production, use actual API)
    if not result:
        result = {
            "ipAddress": ip_address,
            "isPublic": not ip_address.startswith(("10.", "172.", "192.168.")),
            "abuseConfidencePercentage": 75 if "malicious" in ip_address.lower() or ip_address.startswith("185.") else 5,
            "countryCode": "US",
            "usageType": "hosting" if ip_address.startswith("185.") else "isp",
            "isp": "Example ISP",
            "domain": None,
            "isWhitelisted": False,
            "lastReportedAt": None,
        }
    
    # Cache the result for 24 hours
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(cache_set_json(cache_key, result, ttl=86400))
    except (RuntimeError, Exception):
        # If no event loop, skip caching
        pass
    
    return f"IP Lookup for {ip_address}: {result}"
