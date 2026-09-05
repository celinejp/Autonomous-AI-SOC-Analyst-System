"""Redis Streams job queue for analysis and embedding work."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from app.core.logging import get_logger
from app.database.redis_client import get_redis_client

logger = get_logger(__name__)

ANALYSIS_STREAM = "soc:analysis:jobs"
EMBED_STREAM = "soc:embed:jobs"
CONSUMER_GROUP = "soc-workers"


async def ensure_consumer_group(stream: str, group: str = CONSUMER_GROUP) -> None:
    """Create consumer group if missing (idempotent)."""
    client = get_redis_client()
    try:
        await client.xgroup_create(stream, group, id="0", mkstream=True)
        logger.info("Created consumer group", stream=stream, group=group)
    except Exception as e:
        # BUSYGROUP = already exists
        if "BUSYGROUP" not in str(e):
            logger.warning("Consumer group create issue", stream=stream, error=str(e))


async def enqueue_analysis_job(incident_id: str, raw_logs: List[str]) -> str:
    """Enqueue log analysis job. Returns stream message id."""
    client = get_redis_client()
    await ensure_consumer_group(ANALYSIS_STREAM)
    msg_id = await client.xadd(
        ANALYSIS_STREAM,
        {
            "incident_id": incident_id,
            "raw_logs": json.dumps(raw_logs),
            "attempts": "0",
        },
        maxlen=5000,
        approximate=True,
    )
    # Mark queued in status hash
    status_key = f"incident_status:{incident_id}"
    await client.hset(
        status_key,
        mapping={
            "status": "queued",
            "progress_percent": "0",
            "current_agent": "",
            "message": "Queued for worker",
        },
    )
    await client.expire(status_key, 3600)
    logger.info("Enqueued analysis job", incident_id=incident_id, msg_id=msg_id)
    return msg_id


async def enqueue_embed_job(incident_id: str) -> str:
    """Enqueue post-save embedding / vector sync job (outbox-style)."""
    client = get_redis_client()
    await ensure_consumer_group(EMBED_STREAM)
    msg_id = await client.xadd(
        EMBED_STREAM,
        {"incident_id": incident_id, "attempts": "0"},
        maxlen=5000,
        approximate=True,
    )
    logger.info("Enqueued embed job", incident_id=incident_id, msg_id=msg_id)
    return msg_id


async def read_jobs(
    stream: str,
    consumer: str,
    count: int = 1,
    block_ms: int = 5000,
    group: str = CONSUMER_GROUP,
) -> List[Tuple[str, Dict[str, str]]]:
    """
    Read pending jobs via XREADGROUP.
    Returns list of (message_id, fields).
    """
    client = get_redis_client()
    await ensure_consumer_group(stream, group)
    results = await client.xreadgroup(
        groupname=group,
        consumername=consumer,
        streams={stream: ">"},
        count=count,
        block=block_ms,
    )
    jobs: List[Tuple[str, Dict[str, str]]] = []
    if not results:
        return jobs
    for _stream_name, messages in results:
        for msg_id, fields in messages:
            jobs.append((msg_id, fields))
    return jobs


async def ack_job(stream: str, msg_id: str, group: str = CONSUMER_GROUP) -> None:
    client = get_redis_client()
    await client.xack(stream, group, msg_id)


async def requeue_with_backoff(
    stream: str,
    fields: Dict[str, str],
    max_attempts: int = 3,
) -> bool:
    """
    Re-enqueue failed job with incremented attempts.
    Returns False if max attempts exceeded (dead-letter to stream:dlq).
    """
    client = get_redis_client()
    attempts = int(fields.get("attempts", "0")) + 1
    payload = dict(fields)
    payload["attempts"] = str(attempts)

    if attempts > max_attempts:
        await client.xadd(f"{stream}:dlq", payload, maxlen=1000, approximate=True)
        logger.error("Job moved to DLQ", stream=stream, fields=payload)
        return False

    await client.xadd(stream, payload, maxlen=5000, approximate=True)
    logger.warning("Requeued job", stream=stream, attempts=attempts)
    return True
