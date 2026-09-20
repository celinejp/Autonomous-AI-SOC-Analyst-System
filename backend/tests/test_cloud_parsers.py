"""Regression tests for the AWS/Azure/GCP JSON parsers and timestamp normalization.

Real cloud exports use Z-suffixed (or offset) ISO timestamps. Those must become
naive UTC datetimes: every DB timestamp column is TIMESTAMP WITHOUT TIME ZONE, and
a tz-aware value crashed incident save (asyncpg "can't subtract offset-naive and
offset-aware datetimes") until app.core.time_utils was introduced.
"""

import json
from datetime import datetime

import pytest

from app.agents.ingest_agent import (
    ingest_agent,
    parse_azure_activity_log,
    parse_cloudtrail_log,
    parse_gcp_audit_log,
)
from app.core.time_utils import ensure_naive_utc, parse_iso_timestamp_naive
from app.models.log_entry import LogSourceType

CLOUDTRAIL = {
    "eventTime": "2026-09-13T10:00:00Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "AssumeRole",
    "sourceIPAddress": "198.51.100.23",
    "awsRegion": "us-east-1",
    "recipientAccountId": "123456789012",
    "userIdentity": {"userName": "attacker"},
    "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/AdminRole"},
}

AZURE = {
    "time": "2026-09-13T10:00:00Z",
    "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
    "callerIpAddress": "198.51.100.24",
    "caller": "attacker@example.com",
    "tenantId": "tenant-1",
    "status": {"value": "Succeeded"},
}

GCP = {
    "timestamp": "2026-09-13T10:00:00Z",
    "protoPayload": {
        "methodName": "SetIamPolicy",
        "requestMetadata": {"callerIp": "198.51.100.25"},
        "authenticationInfo": {"principalEmail": "attacker@example.com"},
        "status": {"code": 0},
    },
    "resource": {"labels": {"project_id": "proj-1"}},
}


def test_z_suffix_becomes_naive_utc():
    ts = parse_iso_timestamp_naive("2026-09-13T10:00:00Z")
    assert ts == datetime(2026, 9, 13, 10, 0, 0)
    assert ts.tzinfo is None


def test_offset_is_converted_to_utc_not_just_stripped():
    ts = parse_iso_timestamp_naive("2026-09-13T12:00:00+02:00")
    assert ts == datetime(2026, 9, 13, 10, 0, 0)
    assert ts.tzinfo is None


def test_naive_input_is_unchanged():
    assert parse_iso_timestamp_naive("2026-09-13T10:00:00") == datetime(2026, 9, 13, 10, 0, 0)
    now = datetime.utcnow()
    assert ensure_naive_utc(now) is now


@pytest.mark.parametrize(
    "parser,event,ip,source_type",
    [
        (parse_cloudtrail_log, CLOUDTRAIL, "198.51.100.23", LogSourceType.CLOUD_TRAIL),
        (parse_azure_activity_log, AZURE, "198.51.100.24", LogSourceType.AZURE_MONITOR),
        (parse_gcp_audit_log, GCP, "198.51.100.25", LogSourceType.GCP_LOGGING),
    ],
)
def test_cloud_parsers_produce_naive_timestamps(parser, event, ip, source_type):
    log = parser(event)
    assert log.timestamp == datetime(2026, 9, 13, 10, 0, 0)
    assert log.timestamp.tzinfo is None
    assert log.source_ip == ip
    assert log.log_source_type == source_type


def test_cloudtrail_extracts_cloud_fields():
    log = parse_cloudtrail_log(CLOUDTRAIL)
    assert log.action == "AssumeRole"
    assert log.user == "attacker"
    assert log.aws_region == "us-east-1"
    assert log.aws_account == "123456789012"


async def test_ingest_agent_routes_each_cloud_format():
    state = {
        "raw_logs": [json.dumps(CLOUDTRAIL), json.dumps(AZURE), json.dumps(GCP)],
        "agent_execution_log": [],
    }
    result = await ingest_agent(state)
    types = [log.log_source_type for log in result["logs"]]
    assert types == [
        LogSourceType.CLOUD_TRAIL,
        LogSourceType.AZURE_MONITOR,
        LogSourceType.GCP_LOGGING,
    ]
    assert all(log.timestamp.tzinfo is None for log in result["logs"])
