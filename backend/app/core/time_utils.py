"""Timestamp parsing helpers.

DB timestamp columns are TIMESTAMP WITHOUT TIME ZONE and the app uses naive UTC datetimes. External ISO
timestamps (CloudTrail/Azure/GCP, Windows events) parse as timezone-aware and would be rejected on insert, so
route them through these helpers instead of calling datetime.fromisoformat directly.
"""

from datetime import datetime, timezone


def ensure_naive_utc(value: datetime) -> datetime:
    """Strip tzinfo from an already-parsed datetime, converting to UTC first if
    it's aware, so it's safe to insert into a TIMESTAMP WITHOUT TIME ZONE column."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def parse_iso_timestamp_naive(value: str) -> datetime:
    """Parse an ISO-8601 string (Z-suffixed or with an explicit offset) into a
    naive UTC datetime, matching every other timestamp in this app."""
    return ensure_naive_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
