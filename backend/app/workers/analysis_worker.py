"""SOC worker: consumes Redis Stream jobs for analysis and embedding sync."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import uuid
from datetime import datetime
from typing import List

from app.core.job_queue import (
    ANALYSIS_STREAM,
    EMBED_STREAM,
    ack_job,
    ensure_consumer_group,
    read_jobs,
    requeue_with_backoff,
)
from app.core.logging import configure_logging, get_logger
from app.core.config import settings
from app.database.postgres import AsyncSessionLocal, init_db
from app.database.redis_client import (
    acquire_lock,
    close_redis,
    connect_with_retry,
    hset_mapping,
    release_lock,
)
from app.database.vector_store import ensure_collection, VECTOR_SIZE
from app.core.cache import invalidate_incident_caches
from app.services.incident_service import IncidentService
from app.services.vector_sync_service import sync_incident_vectors
from app.orchestrator.langgraph_workflow import run_workflow_with_events

configure_logging(settings.log_level)
logger = get_logger(__name__)

AGENT_DURATIONS = {
    "ingest": 2,
    "detect": 8,
    "enrich": 5,
    "analyze": 15,
    "critique": 5,
    "plan_response": 10,
}
TOTAL_ESTIMATED_SECONDS = sum(AGENT_DURATIONS.values())

_shutdown = False


def _request_shutdown(*_args):
    global _shutdown
    _shutdown = True
    logger.info("Shutdown requested")


async def process_analysis_job(incident_id: str, raw_logs: List[str]) -> None:
    """Run LangGraph workflow under a per-incident distributed lock."""
    lock_key = f"lock:incident:{incident_id}"
    lock_token = str(uuid.uuid4())
    if not await acquire_lock(lock_key, ttl_seconds=600, token=lock_token):
        logger.warning("Incident already locked; skipping", incident_id=incident_id)
        return

    status_key = f"incident_status:{incident_id}"
    try:
        await hset_mapping(
            status_key,
            {
                "status": "analyzing",
                "progress_percent": "0",
                "current_agent": "ingest",
                "started_at": datetime.utcnow().isoformat(),
                "estimated_duration": str(TOTAL_ESTIMATED_SECONDS),
            },
            ttl=3600,
        )

        agents_completed = 0
        total_agents = len(AGENT_DURATIONS)
        final_state = None

        async with AsyncSessionLocal() as db:
            async for event in run_workflow_with_events(raw_logs, incident_id):
                event_type = event.get("type")
                if event_type == "agent_start":
                    agent = event.get("agent")
                    agents_completed += 1
                    progress = int((agents_completed / total_agents) * 100)
                    await hset_mapping(
                        status_key,
                        {"current_agent": agent or "", "progress_percent": str(progress)},
                    )
                elif event_type == "complete":
                    final_state = event["data"]
                    await hset_mapping(
                        status_key,
                        {
                            "status": "completed",
                            "progress_percent": "100",
                            "completed_at": datetime.utcnow().isoformat(),
                        },
                    )
                    break
                elif event_type == "error":
                    raise RuntimeError(event.get("error", "workflow error"))

            if final_state:
                await IncidentService.save_incident_from_state(db, final_state)
                await invalidate_incident_caches()
    except Exception as e:
        logger.error("Analysis job failed", incident_id=incident_id, error=str(e))
        await hset_mapping(status_key, {"status": "failed", "error": str(e)}, ttl=3600)
        raise
    finally:
        await release_lock(lock_key, token=lock_token)


async def process_embed_job(incident_id: str) -> None:
    async with AsyncSessionLocal() as db:
        await sync_incident_vectors(db, incident_id)
    await invalidate_incident_caches()


async def worker_loop(consumer_name: str) -> None:
    await connect_with_retry()
    await ensure_consumer_group(ANALYSIS_STREAM)
    await ensure_consumer_group(EMBED_STREAM)
    await ensure_collection("incidents", vector_size=VECTOR_SIZE)
    await ensure_collection("mitre_techniques", vector_size=VECTOR_SIZE)

    logger.info("Worker started", consumer=consumer_name)

    while not _shutdown:
        # Prefer analysis jobs, then embed jobs
        jobs = await read_jobs(ANALYSIS_STREAM, consumer_name, count=1, block_ms=2000)
        stream = ANALYSIS_STREAM
        if not jobs:
            jobs = await read_jobs(EMBED_STREAM, consumer_name, count=1, block_ms=2000)
            stream = EMBED_STREAM
        if not jobs:
            continue

        for msg_id, fields in jobs:
            try:
                if stream == ANALYSIS_STREAM:
                    incident_id = fields["incident_id"]
                    raw_logs = json.loads(fields["raw_logs"])
                    await process_analysis_job(incident_id, raw_logs)
                else:
                    await process_embed_job(fields["incident_id"])
                await ack_job(stream, msg_id)
            except Exception as e:
                logger.error("Job failed", stream=stream, msg_id=msg_id, error=str(e))
                await ack_job(stream, msg_id)
                await requeue_with_backoff(stream, fields)


async def main() -> None:
    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)
    consumer = os.getenv("WORKER_NAME", f"worker-{uuid.uuid4().hex[:8]}")

    # Wait for Postgres
    for attempt in range(1, 11):
        try:
            await init_db()
            break
        except Exception as e:
            logger.warning("Postgres not ready", attempt=attempt, error=str(e))
            await asyncio.sleep(min(0.5 * (2 ** (attempt - 1)), 8))
    else:
        raise SystemExit("Postgres unavailable")

    try:
        await worker_loop(consumer)
    finally:
        await close_redis()


if __name__ == "__main__":
    asyncio.run(main())
