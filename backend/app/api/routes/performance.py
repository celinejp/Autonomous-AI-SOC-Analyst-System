"""Performance monitoring endpoint."""

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from typing import Dict, Any
import time
from datetime import datetime

from app.core.logging import get_logger
from app.database.redis_client import get_redis_client

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/performance", tags=["performance"])


@router.get("/metrics")
async def get_performance_metrics() -> Dict[str, Any]:
    """Get application performance metrics."""
    redis = get_redis_client()
    
    metrics = {
        "timestamp": datetime.utcnow().isoformat(),
        "redis": {
            "connected": redis is not None,
        },
        "metrics": {
            "ttfb_ms": 0,  # Would be tracked by middleware
            "lcp_ms": 0,   # Frontend metric
            "tbt_ms": 0,   # Frontend metric
        },
    }
    
    if redis:
        try:
            from app.database.redis_client import redis_info
            info = await redis_info()
            metrics["redis"].update(info)
            metrics["redis"]["connected"] = True
        except Exception as e:
            logger.warning(f"Redis info error: {e}")
            metrics["redis"]["connected"] = False

    return metrics


# Middleware function (registered in main.py)
async def performance_middleware(request: Request, call_next):
    """Middleware to track request performance."""
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = (time.time() - start_time) * 1000  # Convert to ms
    
    # Add performance headers
    response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
    
    # Track slow requests
    if process_time > 1000:  # > 1 second
        logger.warning(
            "Slow request",
            path=request.url.path,
            method=request.method,
            duration_ms=process_time,
        )
    
    return response

