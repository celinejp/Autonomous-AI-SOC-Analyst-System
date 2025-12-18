"""Initialize database schema and collections."""

import asyncio
from app.database.postgres import init_db, engine
from app.database.vector_store import ensure_collection


async def main():
    """Initialize all databases."""
    print("Initializing PostgreSQL database...")
    try:
        await init_db()
        print("✓ PostgreSQL initialized")
    except Exception as e:
        print(f"✗ PostgreSQL error: {e}")

    print("\nInitializing Qdrant collections...")
    try:
        # Incident embeddings collection
        await ensure_collection("incidents", vector_size=1536)
        print("✓ Qdrant 'incidents' collection created")
        
        # MITRE techniques collection
        await ensure_collection("mitre_techniques", vector_size=1536)
        print("✓ Qdrant 'mitre_techniques' collection created")
    except Exception as e:
        print(f"✗ Qdrant error: {e}")

    print("\nDatabase initialization complete!")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())

