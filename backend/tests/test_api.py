"""HTTP API: log submission limits and the Demo Mode SSE stream (database, queue and workflow faked)."""

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.api.routes import stream as stream_route
from app.core.config import settings
from app.database.postgres import get_db
from app.main import app


@pytest.fixture
def client(monkeypatch):
    async def no_db():
        yield object()

    async def allow(*_a, **_k):
        return True

    monkeypatch.setattr("app.database.redis_client.rate_limit", allow)
    app.dependency_overrides[get_db] = no_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def queued(monkeypatch):
    enqueue = AsyncMock(return_value="1-0")
    monkeypatch.setattr("app.api.routes.ingest.enqueue_analysis_job", enqueue)
    monkeypatch.setattr("app.database.repositories.IncidentRepository.create", AsyncMock())
    return enqueue


class TestIngest:
    def test_analyze_queues_the_logs(self, client, queued):
        r = client.post("/api/ingest/analyze", json=["line one", "line two"])
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "queued" and body["logs_processed"] == 2
        queued.assert_awaited_once()
        assert queued.await_args.args[1] == ["line one", "line two"]

    def test_empty_submission_is_rejected(self, client, queued):
        assert client.post("/api/ingest/analyze", json=[]).status_code == 400

    def test_too_many_lines_is_rejected(self, client, queued, monkeypatch):
        monkeypatch.setattr(settings, "max_log_lines", 2)
        assert client.post("/api/ingest/analyze", json=["a", "b", "c"]).status_code == 413
        queued.assert_not_awaited()

    def test_upload_splits_lines_and_drops_blanks(self, client, queued):
        r = client.post("/api/ingest/upload", files={"file": ("a.log", b"one\n\ntwo\n")})
        assert r.status_code == 200 and r.json()["logs_processed"] == 2

    def test_oversized_upload_is_rejected(self, client, queued, monkeypatch):
        monkeypatch.setattr(settings, "max_upload_bytes", 10)
        assert client.post("/api/ingest/upload", files={"file": ("a.log", b"x" * 50)}).status_code == 413

    def test_non_utf8_upload_is_rejected(self, client, queued):
        assert client.post("/api/ingest/upload", files={"file": ("a.log", b"\xff\xfe\x00bad")}).status_code == 400

    def test_cors_allows_only_the_frontend_origin(self, client):
        ok = client.options("/api/ingest/analyze", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST"})
        bad = client.options("/api/ingest/analyze", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"})
        assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
        assert "access-control-allow-origin" not in bad.headers


FINAL_STATE = {"alerts": [{"severity": "high"}, {"severity": "critical"}], "logs": [{}] * 3, "confidence": 0.9, "iteration": 1}


def fake_workflow(events):
    async def gen(raw_logs, incident_id):
        for e in events:
            yield e
    return gen


@pytest.fixture
def demo(monkeypatch):
    saved = AsyncMock()

    @asynccontextmanager
    async def session():
        yield object()

    monkeypatch.setattr(stream_route, "AsyncSessionLocal", session)
    monkeypatch.setattr(stream_route.IncidentService, "save_incident_from_state", saved)
    monkeypatch.setattr(stream_route, "invalidate_incident_caches", AsyncMock())
    monkeypatch.setattr(stream_route, "run_workflow_with_events", fake_workflow([
        {"type": "agent_start", "agent": "ingest"},
        {"type": "agent_output", "agent": "ingest", "data": {"logs": [{"log_source": "auth"}]}},
        {"type": "agent_complete", "agent": "ingest"},
        {"type": "complete", "data": FINAL_STATE},
    ]))
    return saved


def sse_events(response):
    return [json.loads(line[6:]) for line in response.iter_lines() if line.startswith("data: ")]


class TestDemoStream:
    def test_streams_agent_progress_then_saves(self, client, demo):
        with client.stream("POST", "/api/v1/incidents/stream", json={"raw_logs": ["x"]}) as r:
            events = sse_events(r)
        names = [e["event"] for e in events]
        assert names == ["connected", "agent_start", "agent_output", "agent_complete", "workflow_complete", "saved", "end"]
        assert events[0]["agents"][0]["id"] == "ingest"
        assert events[4]["summary"]["severity"] == "critical" and events[4]["summary"]["total_alerts"] == 2
        demo.assert_awaited_once()

    def test_empty_logs_are_rejected(self, client, demo):
        assert client.post("/api/v1/incidents/stream", json={"raw_logs": []}).status_code == 422


async def test_the_incident_is_saved_even_if_nobody_reads_the_stream(demo):
    """Browser disconnected: events pile up unread, but the run still completes and saves."""
    import asyncio

    queue = asyncio.Queue()
    await stream_route._run_and_save(["x"], "inc-1", queue)

    demo.assert_awaited_once()
    assert queue.get_nowait()["type"] == "agent_start"
