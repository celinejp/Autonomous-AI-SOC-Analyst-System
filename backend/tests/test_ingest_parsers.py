"""Tests for the structured non-JSON log parsers in ingest_agent.

Covers the real-world formats that broke the old flat keyword-substring
parser: standard sshd auth logs, Windows Security Event (4624/4625) exports,
CEF-formatted appliance logs, and non-standard failure tokens (e.g. AUTH_FAIL)
that don't contain the literal substring "failed".
"""

from app.agents.ingest_agent import _parse_syslog_log


def test_sshd_failed_password():
    raw = "Aug 30 10:15:00 host sshd[1234]: Failed password for admin from 203.0.113.55 port 22 ssh2"
    log = _parse_syslog_log(raw)
    assert log.action == "login_failed"
    assert log.status == "failure"
    assert log.source_ip == "203.0.113.55"
    assert log.user == "admin"
    assert log.destination_port == 22


def test_sshd_accepted_password():
    raw = "Aug 30 10:15:10 host sshd[1234]: Accepted password for admin from 203.0.113.55 port 22 ssh2"
    log = _parse_syslog_log(raw)
    assert log.action == "login_success"
    assert log.status == "success"
    assert log.source_ip == "203.0.113.55"
    assert log.user == "admin"


def test_sshd_invalid_user():
    raw = "Aug 30 10:15:00 host sshd[1234]: Invalid user r00t from 198.51.100.9"
    log = _parse_syslog_log(raw)
    assert log.action == "login_failed"
    assert log.status == "failure"
    assert log.source_ip == "198.51.100.9"


def test_non_standard_auth_fail_token():
    """A log using AUTH_FAIL instead of the literal word 'failed' must still be
    classified as a failure -- this was silently misclassified as a success
    before the fix (the old parser only checked for the substring 'failed')."""
    raw = "Aug 30 10:15:00 host loginsvc[99]: AUTH_FAIL user=bob from 10.0.0.5"
    log = _parse_syslog_log(raw)
    assert log.status == "failure"


def test_windows_security_event_4625_failed_logon():
    raw = (
        "Aug 30 10:20:00 DC01 Microsoft-Windows-Security-Auditing: EventID=4625 "
        "An account failed to log on. Account Name: jdoe Logon Type: 3 "
        "Source Network Address: 10.0.0.15"
    )
    log = _parse_syslog_log(raw)
    assert log.action == "login_failed"
    assert log.status == "failure"
    assert log.event_id == 4625
    assert log.user == "jdoe"
    assert log.source_ip == "10.0.0.15"


def test_windows_security_event_4624_successful_logon():
    raw = (
        "Aug 30 10:21:00 DC01 Microsoft-Windows-Security-Auditing: EventID=4624 "
        "An account was successfully logged on. Account Name: jdoe Logon Type: 3 "
        "Source Network Address: 10.0.0.15"
    )
    log = _parse_syslog_log(raw)
    assert log.action == "login_success"
    assert log.status == "success"
    assert log.event_id == 4624


def test_cef_failed_login():
    raw = (
        "CEF:0|Acme|Firewall|1.0|100|Login Attempt|5|"
        "src=203.0.113.55 dst=10.0.0.1 dpt=22 duser=admin outcome=failure"
    )
    log = _parse_syslog_log(raw)
    assert log.status == "failure"
    assert log.source_ip == "203.0.113.55"
    assert log.destination_ip == "10.0.0.1"
    assert log.destination_port == 22
    assert log.user == "admin"


def test_cef_successful_login():
    raw = (
        "CEF:0|Acme|Firewall|1.0|100|Login Attempt|5|"
        "src=203.0.113.55 dst=10.0.0.1 dpt=22 duser=admin outcome=success"
    )
    log = _parse_syslog_log(raw)
    assert log.status == "success"
