"""FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.api.routes import incidents, ingest, analysis, health

# Configure logging
configure_logging(settings.log_level)
logger = get_logger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Autonomous AI SOC Analyst System",
    description="Multi-agent security operations center with LangGraph orchestration",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["incidents"])
app.include_router(ingest.router, prefix="/api/ingest", tags=["ingest"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("SOC Analyst System starting up", environment=settings.environment)


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("SOC Analyst System shutting down")

