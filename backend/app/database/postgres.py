"""PostgreSQL database connection and setup."""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

from app.core.config import settings

# Create async engine
engine = create_async_engine(
    settings.database_url.replace("postgresql://", "postgresql+asyncpg://"),
    echo=settings.environment == "development",
    future=True,
)

# Create session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def create_schema(target_engine) -> None:
    """Create everything a fresh database needs: the pgvector extension, the tables, and the vector index
    used for incident similarity search (cosine distance). Safe to run repeatedly."""
    from sqlalchemy import text

    from app.database import models  # noqa: F401  (registers the tables with Base)

    async with target_engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS incidents_embedding_idx ON incidents "
            "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
        ))


async def init_db() -> None:
    """Initialize the database (used at API/worker startup and by scripts/init_db.py)."""
    await create_schema(engine)
