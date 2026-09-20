"""Redis Streams job queue (in-memory Redis)."""

import json

from app.core import job_queue


async def test_enqueue_writes_the_job_and_marks_the_incident_queued(fake_redis):
    await job_queue.enqueue_analysis_job("inc-1", ["log a", "log b"])

    assert await fake_redis.xlen(job_queue.ANALYSIS_STREAM) == 1
    status = await fake_redis.hgetall("incident_status:inc-1")
    assert status["status"] == "queued" and status["progress_percent"] == "0"


async def test_consumer_reads_and_acknowledges_a_job(fake_redis):
    await job_queue.enqueue_analysis_job("inc-1", ["log a"])

    jobs = await job_queue.read_jobs(job_queue.ANALYSIS_STREAM, "worker-1", block_ms=10)
    assert len(jobs) == 1
    msg_id, fields = jobs[0]
    assert fields["incident_id"] == "inc-1" and json.loads(fields["raw_logs"]) == ["log a"]

    await job_queue.ack_job(job_queue.ANALYSIS_STREAM, msg_id)
    pending = await fake_redis.xpending(job_queue.ANALYSIS_STREAM, job_queue.CONSUMER_GROUP)
    assert pending["pending"] == 0


async def test_a_second_consumer_does_not_get_a_job_already_delivered(fake_redis):
    await job_queue.enqueue_analysis_job("inc-1", ["log a"])
    assert len(await job_queue.read_jobs(job_queue.ANALYSIS_STREAM, "worker-1", block_ms=10)) == 1
    assert await job_queue.read_jobs(job_queue.ANALYSIS_STREAM, "worker-2", block_ms=10) == []


async def test_failed_job_is_retried_then_dead_lettered(fake_redis):
    fields = {"incident_id": "inc-1", "raw_logs": "[]", "attempts": "0"}
    for _ in range(3):
        assert await job_queue.requeue_with_backoff(job_queue.ANALYSIS_STREAM, fields, max_attempts=3) is True
        fields["attempts"] = str(int(fields["attempts"]) + 1)
    assert await fake_redis.xlen(job_queue.ANALYSIS_STREAM) == 3
    assert await fake_redis.xlen(f"{job_queue.ANALYSIS_STREAM}:dlq") == 0

    assert await job_queue.requeue_with_backoff(job_queue.ANALYSIS_STREAM, fields, max_attempts=3) is False
    assert await fake_redis.xlen(f"{job_queue.ANALYSIS_STREAM}:dlq") == 1
