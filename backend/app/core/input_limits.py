"""Input limits for submitted logs (upload size, line count, line length)."""

from typing import List

from fastapi import HTTPException

from app.core.config import settings


def validate_raw_logs(raw_logs: List[str]) -> List[str]:
    """Enforce size limits on submitted log lines (413 too large / 422 malformed)."""
    if not raw_logs:
        raise HTTPException(status_code=400, detail="No log entries provided")
    if len(raw_logs) > settings.max_log_lines:
        raise HTTPException(status_code=413, detail=f"Too many log lines: {len(raw_logs)} (max {settings.max_log_lines})")
    total = 0
    for line in raw_logs:
        if not isinstance(line, str):
            raise HTTPException(status_code=422, detail="Every log entry must be a string")
        if len(line) > settings.max_log_line_chars:
            raise HTTPException(status_code=422, detail=f"A log line exceeds {settings.max_log_line_chars} characters")
        total += len(line.encode("utf-8", errors="ignore"))
    if total > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail=f"Payload too large: {total} bytes (max {settings.max_upload_bytes})")
    return raw_logs
