"""The analysis worker: locking, progress tracking, saving and failure handling (workflow and DB faked)."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import pytest

from app.workers import analysis_worker as worker


def workflow(events):
    async def fake(raw_logs, incident_id):
        for event in events:
            yield event
    return fake


@pytest.fixture
def wired(monkeypatch, fake_redis):
    saved = AsyncMock()

    @asynccontextmanager
    async def fake_session():
        yield object()

    async def release_lock(key, token="1"):  # the real one is a Lua script, which fakeredis can't run without lupa
        if await fake_redis.get(key) == token:
            await fake_redis.delete(key)

    monkeypatch.setattr(worker, "release_lock", release_lock)
    monkeypatch.setattr(worker, "AsyncSessionLocal", fake_session)
    monkeypatch.setattr(worker.IncidentService, "save_incident_from_state", saved)
    monkeypatch.setattr(worker, "invalidate_incident_caches", AsyncMock())
    return saved


FINAL = {"incident_id": "inc-1", "alerts": []}
OK_EVENTS = [
    {"type": "agent_start", "agent": "ingest"},
    {"type": "agent_start", "agent": "detect"},
    {"type": "complete", "data": FINAL},
]


async def test_successful_job_saves_the_incident_and_reports_completion(monkeypatch, wired, fake_redis):
    monkeypatch.setattr(worker, "run_workflow_with_events", workflow(OK_EVENTS))

    await worker.process_analysis_job("inc-1", ["log"])

    wired.assert_awaited_once()
    assert wired.await_args.args[1] == FINAL
    status = await fake_redis.hgetall("incident_status:inc-1")
    assert status["status"] == "completed" and status["progress_percent"] == "100"
    assert not await fake_redis.exists("lock:incident:inc-1"), "lock must be released"


async def test_completed_is_reported_only_after_the_incident_is_saved(monkeypatch, wired, fake_redis):
    """A client polling status must never see "completed" before the saved incident exists."""
    seen = {}

    async def save(db, state):
        seen["status_during_save"] = (await fake_redis.hgetall("incident_status:inc-1")).get("status")

    monkeypatch.setattr(worker.IncidentService, "save_incident_from_state", save)
    monkeypatch.setattr(worker, "run_workflow_with_events", workflow(OK_EVENTS))

    await worker.process_analysis_job("inc-1", ["log"])

    assert seen["status_during_save"] == "analyzing"
    assert (await fake_redis.hgetall("incident_status:inc-1"))["status"] == "completed"


async def test_a_workflow_that_ends_without_a_result_is_a_failure(monkeypatch, wired, fake_redis):
    monkeypatch.setattr(worker, "run_workflow_with_events", workflow([{"type": "agent_start", "agent": "ingest"}]))

    with pytest.raises(RuntimeError, match="without a result"):
        await worker.process_analysis_job("inc-1", ["log"])

    assert (await fake_redis.hgetall("incident_status:inc-1"))["status"] == "failed"


async def test_workflow_error_marks_the_incident_failed_and_releases_the_lock(monkeypatch, wired, fake_redis):
    monkeypatch.setattr(worker, "run_workflow_with_events", workflow([{"type": "error", "error": "boom"}]))

    with pytest.raises(RuntimeError, match="boom"):
        await worker.process_analysis_job("inc-1", ["log"])

    status = await fake_redis.hgetall("incident_status:inc-1")
    assert status["status"] == "failed" and status["error"] == "boom"
    assert not await fake_redis.exists("lock:incident:inc-1")
    wired.assert_not_awaited()


async def test_an_incident_already_being_processed_is_skipped(monkeypatch, wired, fake_redis):
    await fake_redis.set("lock:incident:inc-1", "another-worker")
    monkeypatch.setattr(worker, "run_workflow_with_events", workflow(OK_EVENTS))

    await worker.process_analysis_job("inc-1", ["log"])

    wired.assert_not_awaited()
    assert await fake_redis.get("lock:incident:inc-1") == "another-worker"
