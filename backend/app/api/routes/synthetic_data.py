"""Synthetic log generation endpoint (sample lines for the UI's "Generate synthetic" button)."""

import random
from typing import Any, Dict

from fastapi import APIRouter, Body

router = APIRouter()



@router.post("/generate")
async def generate_synthetic_logs(
    body: Dict[str, Any] = Body(default_factory=dict),
):
    """
    Generate synthetic log lines for testing. Returns a list of log strings.
    Body: { "count": 5 } (default 5). Uses built-in samples.
    """
    count = int(body.get("count", 5))
    count = max(1, min(count, 50))
    samples = [
        "2024-01-15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45",
        "2024-01-15 10:00:01 sshd[1234]: Accepted publickey for admin from 203.0.113.45 port 54321 ssh2",
        "2024-01-15 14:30:00 powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        "2024-01-15 12:00:00 CloudTrail: AssumeRole attempted by user attacker@example.com for role AdminRole",
        "2024-01-15 11:30:00 firewall: Connection attempt from 203.0.113.45:54321 to 192.168.1.10:22 (blocked)",
    ]
    logs = [random.choice(samples) for _ in range(count)]
    return {"status": "success", "count": count, "logs": logs}
