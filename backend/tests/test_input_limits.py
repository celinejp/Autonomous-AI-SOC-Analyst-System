"""Input limits for submitted logs."""

import pytest
from fastapi import HTTPException

from app.core import input_limits as security
from app.core.config import settings


def test_line_count_limit(monkeypatch):
    monkeypatch.setattr(settings, "max_log_lines", 3)
    with pytest.raises(HTTPException) as e:
        security.validate_raw_logs(["a"] * 4)
    assert e.value.status_code == 413


def test_line_length_limit(monkeypatch):
    monkeypatch.setattr(settings, "max_log_line_chars", 10)
    with pytest.raises(HTTPException) as e:
        security.validate_raw_logs(["x" * 11])
    assert e.value.status_code == 422


def test_total_size_limit(monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 10)
    with pytest.raises(HTTPException) as e:
        security.validate_raw_logs(["12345678", "12345678"])
    assert e.value.status_code == 413


def test_valid_logs_pass():
    assert security.validate_raw_logs(["a", "b"]) == ["a", "b"]
