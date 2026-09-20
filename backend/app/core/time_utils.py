"""Timestamp parsing helpers.

Every DB timestamp column in this app is TIMESTAMP WITHOUT TIME ZONE, and the
rest of the codebase consistently uses naive UTC datetimes (datetime.utcnow()).
External timestamp strings - a real AWS CloudTrail/Azure/GCP export always
Z-suffixed - parse to timezone-*aware* datetimes via datetime.fromisoformat,
which asyncpg then refuses to insert into a naive column ("can't subtract
offset-naive and offset-aware datetimes"). Confirmed live: a real CloudTrail
event crashed incident save and dead-lettered after 3 retries. Route every
external ISO timestamp through this helper instead of calling
datetime.fromisoformat directly.
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
