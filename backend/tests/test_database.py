"""Persistence against a real PostgreSQL + pgvector (no LLM, no other services).

Set TEST_DATABASE_URL (default: the docker-compose Postgres, database `soc_test`); the tests skip if it
is unreachable. CI runs them against a pgvector service container.
"""

import os
import uuid
from datetime import datetime
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.database.models import AlertModel, IncidentModel, LogEntryModel
from app.database.postgres import create_schema
from app.database.repositories import IncidentRepository
from app.models.incident import (Alert, IncidentReport, IncidentStatus, IOCCollection, IOCEntry, ResponseAction,
                                 ResponsePlan, Severity)
from app.models.log_entry import LogEntry, LogSource
from app.services import vector_sync_service
from app.services.incident_service import IncidentService

pytestmark = pytest.mark.db

TEST_URL = os.getenv("TEST_DATABASE_URL", "postgresql+asyncpg://soc_user:soc_password@localhost:5433/soc_test")


@pytest_asyncio.fixture
async def session(monkeypatch):
    engine = create_async_engine(TEST_URL, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            # start from an empty database so the test also proves a fresh install can bootstrap itself
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
        await create_schema(engine)
    except Exception as e:
        await engine.dispose()
        pytest.skip(f"test database unavailable: {type(e).__name__}")
    # the save path enqueues an embedding job and busts caches; both need Redis, not under test here
    monkeypatch.setattr("app.core.job_queue.enqueue_embed_job", AsyncMock())
    monkeypatch.setattr("app.core.cache.invalidate_incident_caches", AsyncMock())
    async with AsyncSession(engine, expire_on_commit=False) as s:
        yield s
    async with AsyncSession(engine) as cleanup:
        await cleanup.execute(text("TRUNCATE incidents CASCADE"))
        await cleanup.commit()
    await engine.dispose()


def alert(severity, technique="T1110.001"):
    return Alert(timestamp=datetime.utcnow(), severity=severity, title=f"{severity.value} alert", description="d",
                 detection_rule="ATT&CK Rule: " + technique, related_logs=["0"], mitre_techniques=[technique])


def make_state(incident_id, severities=(Severity.HIGH,), ip="203.0.113.9"):
    log = LogEntry(timestamp=datetime.utcnow(), source_ip=ip, action="login_failed", status="failure",
                   log_source=LogSource.AUTH, raw_log=f"Failed password from {ip}")
    action = ResponseAction(priority="immediate", action_type="block_ip", action="Block IP", description="d",
                            target=ip, assigned_team="Network")
    return {
        "incident_id": incident_id, "logs": [log], "alerts": [alert(s) for s in severities], "confidence": 0.8,
        "threat_intel": {"mitre_techniques": []},
        "incident_report": IncidentReport(
            executive_summary="Brute force from " + ip, technical_findings="6 failures", root_cause="weak password",
            impact_assessment="possible takeover", confidence_score=0.8,
            indicators_of_compromise=IOCCollection(ip_addresses=[IOCEntry(value=ip, type="ip", recommended_action="block")])),
        "response_plan": ResponsePlan(incident_id=incident_id, containment_actions=[action], actions_by_team={"Network": [action]}),
        "agent_execution_log": [{"agent_name": "detection", "timestamp": datetime.utcnow().isoformat(), "duration_ms": 12.5}],
    }


async def test_a_fresh_database_gets_the_vector_extension_tables_and_index(session):
    tables = {r[0] for r in (await session.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'"))).fetchall()}
    assert {"incidents", "alerts", "incident_reports", "response_plans", "log_entries", "agent_execution_logs"} <= tables
    index = await session.scalar(text("SELECT indexdef FROM pg_indexes WHERE indexname='incidents_embedding_idx'"))
    assert index and "ivfflat" in index and "vector_cosine_ops" in index


async def test_a_completed_analysis_is_saved_and_read_back_whole(session):
    incident_id = str(uuid.uuid4())
    await IncidentService.save_incident_from_state(session, make_state(incident_id, (Severity.MEDIUM, Severity.CRITICAL)))

    incident = await IncidentRepository.model_to_pydantic(await IncidentRepository.get_by_id(session, incident_id))

    assert incident.severity == Severity.CRITICAL, "incident severity is the highest alert severity"
    assert len(incident.alerts) == 2 and incident.alerts[0].mitre_techniques == ["T1110.001"]
    assert incident.report.root_cause == "weak password"
    assert [i.value for i in incident.report.indicators_of_compromise.ip_addresses] == ["203.0.113.9"]
    assert list(incident.response_plan.actions_by_team) == ["Network"]
    assert (await session.scalar(select(func.count()).select_from(LogEntryModel).where(LogEntryModel.incident_id == incident_id))) == 1


async def test_saving_fills_in_the_placeholder_created_at_submission(session):
    """The API creates a LOW / in-progress placeholder; the worker's save must update that row, not add another."""
    incident_id = str(uuid.uuid4())
    await IncidentRepository.create(session, {"id": incident_id, "status": IncidentStatus.IN_PROGRESS, "severity": Severity.LOW, "confidence_score": 0.0})

    await IncidentService.save_incident_from_state(session, make_state(incident_id))

    assert (await session.scalar(select(func.count()).select_from(IncidentModel))) == 1
    saved = await IncidentRepository.get_by_id(session, incident_id)
    assert saved.severity == Severity.HIGH and saved.status == IncidentStatus.NEW and len(saved.alerts) == 1


async def test_list_filters_by_severity_and_status(session):
    high, low = str(uuid.uuid4()), str(uuid.uuid4())
    await IncidentService.save_incident_from_state(session, make_state(high, (Severity.HIGH,)))
    await IncidentService.save_incident_from_state(session, make_state(low, (Severity.MEDIUM,)))
    await IncidentRepository.update(session, low, {"status": IncidentStatus.FALSE_POSITIVE})

    assert [i.id for i in await IncidentRepository.list(session, severity=Severity.HIGH)] == [high]
    assert [i.id for i in await IncidentRepository.list(session, status=IncidentStatus.FALSE_POSITIVE)] == [low]


async def test_deleting_an_incident_removes_everything_that_belongs_to_it(session):
    incident_id = str(uuid.uuid4())
    await IncidentService.save_incident_from_state(session, make_state(incident_id))

    assert await IncidentRepository.delete(session, incident_id) is True

    for model in (AlertModel, LogEntryModel):
        assert (await session.scalar(select(func.count()).select_from(model))) == 0
    assert await IncidentRepository.delete(session, incident_id) is False


async def test_similar_incidents_are_found_by_pgvector_distance(session, monkeypatch):
    """Two incidents get embeddings; a query vector near one of them ranks it first (real pgvector cosine search)."""
    near, far = str(uuid.uuid4()), str(uuid.uuid4())
    for incident_id in (near, far):
        await IncidentService.save_incident_from_state(session, make_state(incident_id))

    def unit(axis):
        v = [0.0] * vector_sync_service.EMBEDDING_DIM
        v[axis] = 1.0
        return v

    vectors = iter([unit(0), unit(1)])
    monkeypatch.setattr(vector_sync_service, "get_embedding", AsyncMock(side_effect=lambda _t: next(vectors)))
    await vector_sync_service.sync_incident_vectors(session, near)
    await vector_sync_service.sync_incident_vectors(session, far)

    query = "[" + ",".join(map(str, unit(0))) + "]"
    rows = (await session.execute(text(
        "SELECT id, 1 - (embedding <=> CAST(:v AS vector)) AS similarity FROM incidents "
        "WHERE embedding IS NOT NULL ORDER BY embedding <=> CAST(:v AS vector)"), {"v": query})).fetchall()

    assert [str(r.id) for r in rows] == [near, far]
    assert rows[0].similarity == pytest.approx(1.0) and rows[1].similarity == pytest.approx(0.0)
