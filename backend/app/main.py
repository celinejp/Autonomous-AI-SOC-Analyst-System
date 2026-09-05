"""FastAPI application entry point."""

from typing import Callable
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.api.routes import (
    incidents, ingest, analysis, health, siem, response, semantic_search,
    stream, validation, dashboard, performance, debug, synthetic_data, metrics, organization
)

# Configure logging
configure_logging(settings.log_level)
logger = get_logger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Autonomous AI SOC Analyst System",
    description="Multi-agent security operations center with LangGraph orchestration",
    version="1.0.0",
)

# Performance middleware (register early)
from app.api.routes.performance import performance_middleware
app.middleware("http")(performance_middleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global error handler
@app.middleware("http")
async def error_handler(request: Request, call_next: Callable):
    """Global error handler middleware."""
    try:
        response = await call_next(request)
        return response
    except Exception as e:
        logger.error("Unhandled exception", error=str(e), path=request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "error": str(e) if settings.environment == "development" else "An error occurred",
            },
        )

# Include routers
app.include_router(health.router, prefix="/api/health", tags=["health"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["incidents"])
app.include_router(ingest.router, prefix="/api/ingest", tags=["ingest"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])
app.include_router(siem.router, prefix="/api/siem", tags=["siem"])
app.include_router(response.router, prefix="/api/response", tags=["response"])
app.include_router(semantic_search.router, tags=["semantic-search"])
app.include_router(stream.router, tags=["streaming"])
app.include_router(validation.router, tags=["validation"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(performance.router, tags=["performance"])
app.include_router(debug.router, prefix="/api/debug", tags=["debug"])
app.include_router(synthetic_data.router, prefix="/api/synthetic", tags=["synthetic-data"])
app.include_router(metrics.router, prefix="/api/metrics", tags=["metrics"])
app.include_router(organization.router, prefix="/api/organization", tags=["organization"])


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup with dependency retries."""
    logger.info("SOC Analyst System starting up", environment=settings.environment)

    try:
        from app.database.redis_client import connect_with_retry
        from app.core.job_queue import ensure_consumer_group, ANALYSIS_STREAM, EMBED_STREAM
        from app.database.vector_store import ensure_collection, VECTOR_SIZE

        await connect_with_retry()
        await ensure_consumer_group(ANALYSIS_STREAM)
        await ensure_consumer_group(EMBED_STREAM)
        await ensure_collection("incidents", vector_size=VECTOR_SIZE)
        await ensure_collection("mitre_techniques", vector_size=VECTOR_SIZE)
        logger.info("Redis Streams + Qdrant collections ready")
    except Exception as e:
        logger.error("Failed to initialize Redis/Qdrant", error=str(e))

    # Initialize database with retry
    for attempt in range(1, 11):
        try:
            from app.database.postgres import init_db
            await init_db()
            logger.info("Database initialized")
            break
        except Exception as e:
            import asyncio
            logger.warning("Database not ready", attempt=attempt, error=str(e))
            await asyncio.sleep(min(0.5 * (2 ** (attempt - 1)), 8))
    else:
        logger.error("Failed to initialize database after retries")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    try:
        from app.database.redis_client import close_redis
        await close_redis()
    except Exception:
        pass
    logger.info("SOC Analyst System shutting down")


# Redis fixed-window rate limiting
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next: Callable):
    """Simple per-IP rate limit via Redis INCR."""
    if request.url.path.startswith("/api/health"):
        return await call_next(request)
    try:
        import os
        from app.database.redis_client import rate_limit

        limit = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
        client_ip = request.client.host if request.client else "unknown"
        allowed = await rate_limit(f"ratelimit:{client_ip}", limit=limit, window_seconds=60)
        if not allowed:
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
    except Exception as e:
        logger.debug("Rate limit check skipped", error=str(e))
    return await call_next(request)
