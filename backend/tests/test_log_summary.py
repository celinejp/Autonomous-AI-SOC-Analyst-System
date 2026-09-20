"""What the Detection LLM is shown: structured fields, and large batches without silent truncation."""

import asyncio

from app.agents.detection_agent import _create_log_summary
from app.agents.ingest_agent import ingest_agent


def parse(lines):
    return asyncio.run(ingest_agent({"raw_logs": lines, "logs": [], "alerts": [], "agent_execution_log": []}))["logs"]


def test_small_batch_is_verbatim_and_includes_byte_counts():
    logs = parse(["proxy01: POST https://mega.nz/upload src=10.1.1.9 bytes_out=180MB"])
    summary = _create_log_summary(logs)
    assert "bytes_out=188743680" in summary and "STATISTICS" not in summary


def test_large_batch_keeps_statistics_and_late_failures_visible():
    lines = [f"Jan 15 10:00:{i % 60:02d} web sshd[1]: Accepted password for ok{i} from 10.0.0.{i % 200} port 22" for i in range(400)]
    lines += [f"Jan 15 11:00:{i:02d} web sshd[1]: Failed password for root from 203.0.113.9 port 22" for i in range(30)]
    summary = _create_log_summary(parse(lines))
    assert "BATCH STATISTICS over all 430 lines" in summary
    assert "203.0.113.9: events=30 failures=30" in summary
    assert "\n410: " in summary or "\n420: " in summary  # a late failure line is shown with its original index
    assert summary.count("\n") < 150  # bounded prompt size
