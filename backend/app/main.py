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
app.include_router(dashboard.router, tags=["dashboard"])
app.include_router(performance.router, tags=["performance"])
app.include_router(debug.router, prefix="/api/debug", tags=["debug"])
app.include_router(synthetic_data.router, prefix="/api/synthetic", tags=["synthetic-data"])
app.include_router(metrics.router, prefix="/api/metrics", tags=["metrics"])
app.include_router(organization.router, prefix="/api/organization", tags=["organization"])


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("SOC Analyst System starting up", environment=settings.environment)
    
    # Initialize database
    try:
        from app.database.postgres import init_db
        await init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.error("Failed to initialize database", error=str(e))


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("SOC Analyst System shutting down")
