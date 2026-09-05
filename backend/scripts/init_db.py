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
        from app.database.vector_store import VECTOR_SIZE

        # Incident embeddings collection (768 = nomic-embed-text / pgvector)
        await ensure_collection("incidents", vector_size=VECTOR_SIZE)
        print(f"✓ Qdrant 'incidents' collection created (dim={VECTOR_SIZE})")

        # MITRE techniques collection
        await ensure_collection("mitre_techniques", vector_size=VECTOR_SIZE)
        print(f"✓ Qdrant 'mitre_techniques' collection created (dim={VECTOR_SIZE})")
    except Exception as e:
        print(f"✗ Qdrant error: {e}")

    print("\nDatabase initialization complete!")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())

