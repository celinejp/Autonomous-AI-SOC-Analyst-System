#!/usr/bin/env python3
"""False-positive and recall-in-noise evaluation on generated benign Windows telemetry.

The public attack datasets are attack-only, so they cannot measure false alarms. This script generates
realistic BENIGN activity (seeded, so runs are repeatable), including the awkward cases that look a bit like
attacks: an admin running `net user`, `curl` to an internal API, control-panel rundll32, a legitimate updater
installing a service or a Run key, single mistyped passwords, benign PowerShell.

  1. Benign only:  batches of benign events -> how often does the detector raise an alert? (false-positive rate)
  2. Mixed:        a real attack capture (Splunk attack_data) shuffled into benign noise by timestamp ->
                   does the target rule still fire, and how many extra alerts does the noise add?
  3. --llm:        the full detection agent (LLM + rules) on benign batches of 100 events.

The generated data is synthetic and written by the project author: it is a sanity check for false alarms, not
a measurement of production noise.

Usage: python scripts/eval_false_positives.py [--batches 100] [--size 150] [--seed 7] [--llm] [--mixed]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import re
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.eval_public_datasets import CACHE, full_detection, is_llm_alert, pick_files, split_events  # noqa: E402
from app.agents.detection_agent import detect_rules_only  # noqa: E402
from app.agents.ingest_agent import ingest_agent  # noqa: E402
from app.detection.attack_rules import ATTACK_DETECTION_RULES  # noqa: E402

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
HOSTS = ["WS-014", "WS-021", "SRV-FILE01", "SRV-APP02", "DC01"]
USERS = ["alice", "bob", "carol", "dave", "svc_backup"]

# (image, command line, parent) - ordinary software and routine admin work
BENIGN_PROCESSES = [
    ("chrome.exe", '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer --lang=en-US', "chrome.exe"),
    ("msedge.exe", '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --profile-directory=Default', "explorer.exe"),
    ("svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule", "services.exe"),
    ("OneDrive.exe", '"C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background', "explorer.exe"),
    ("Teams.exe", '"C:\\Users\\bob\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"', "explorer.exe"),
    ("WINWORD.EXE", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Docs\\report.docx"', "explorer.exe"),
    ("EXCEL.EXE", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "C:\\Docs\\budget.xlsx"', "explorer.exe"),
    ("python.exe", "python.exe C:\\scripts\\report.py --daily", "cmd.exe"),
    ("git.exe", "git.exe status --porcelain", "code.exe"),
    ("code.exe", '"C:\\Users\\dave\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"', "explorer.exe"),
    ("notepad.exe", "notepad.exe C:\\Users\\carol\\notes.txt", "explorer.exe"),
    ("powershell.exe", 'powershell.exe -NoProfile -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5"', "explorer.exe"),
    ("powershell.exe", 'powershell.exe -NoProfile -File C:\\scripts\\cleanup-logs.ps1', "taskeng.exe"),
    ("cmd.exe", "cmd.exe /c dir C:\\Users\\alice\\Documents", "explorer.exe"),
    ("ping.exe", "ping.exe 10.0.0.1", "cmd.exe"),
    ("ipconfig.exe", "ipconfig /all", "cmd.exe"),
    ("hostname.exe", "hostname", "cmd.exe"),
    ("whoami.exe", "whoami /groups", "cmd.exe"),
    ("wuauclt.exe", "wuauclt.exe /detectnow", "svchost.exe"),
    ("MpCmdRun.exe", '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 1', "svchost.exe"),
    ("robocopy.exe", "robocopy.exe D:\\data \\\\SRV-FILE01\\backup /MIR /R:1", "cmd.exe"),
    # look-alikes: legitimate use of tools that attackers also use
    ("net.exe", "net user", "cmd.exe"),
    ("net.exe", "net localgroup administrators", "cmd.exe"),
    ("net.exe", "net use Z: \\\\SRV-FILE01\\shared", "cmd.exe"),
    ("wmic.exe", "wmic os get caption,version", "cmd.exe"),
    ("wmic.exe", "wmic cpu get name", "cmd.exe"),
    ("certutil.exe", "certutil.exe -hashfile C:\\installers\\setup.exe SHA256", "cmd.exe"),
    ("certutil.exe", "certutil.exe -dump C:\\certs\\corp-root.cer", "cmd.exe"),
    ("curl.exe", "curl.exe https://intranet.corp.local/api/health", "cmd.exe"),
    ("curl.exe", "curl.exe -s https://api.internal.corp/v1/status", "powershell.exe"),
    ("rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl", "explorer.exe"),
    ("rundll32.exe", "rundll32.exe printui.dll,PrintUIEntry /in /n\\\\printsrv\\HP-2F", "explorer.exe"),
    ("sc.exe", "sc.exe query wuauserv", "cmd.exe"),
    ("schtasks.exe", "schtasks.exe /query /fo LIST", "cmd.exe"),
    ("reg.exe", 'reg.exe query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /v ProductName', "cmd.exe"),
    ("bitsadmin.exe", "bitsadmin.exe /list /allusers", "cmd.exe"),
]
BENIGN_SCRIPTS = ["Get-ChildItem C:\\Logs -Recurse | Where-Object Length -gt 1MB", "Import-Module ActiveDirectory; Get-ADUser -Filter *",
                  "Get-Service | Where-Object Status -eq 'Running'", "Test-Connection srv-app02 -Count 2",
                  "Invoke-RestMethod https://intranet.corp.local/api/inventory"]
BENIGN_RUNKEYS = [
    ("HKU\\S-1-5-21-1-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive", "C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background"),
    ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth", "C:\\Windows\\system32\\SecurityHealthSystray.exe"),
]


def _ev(provider: str, channel: str, event_id: int, ts: datetime, host: str, data: dict) -> str:
    items = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event xmlns='{NS}'><System><Provider Name='{provider}'/><EventID>{event_id}</EventID>"
            f"<TimeCreated SystemTime='{ts.strftime('%Y-%m-%dT%H:%M:%S.%f')}Z'/><Channel>{channel}</Channel><Computer>{host}</Computer>"
            f"</System><EventData>{items}</EventData></Event>")


def benign_event(rng: random.Random, ts: datetime) -> str:
    host, user = rng.choice(HOSTS), rng.choice(USERS)
    kind = rng.choices(["process", "logon", "logoff", "network", "file", "dns", "script", "service", "runkey", "failed"],
                       weights=[38, 14, 10, 12, 8, 6, 4, 1, 1, 3])[0]
    sysmon = ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational")
    sec = ("Microsoft-Windows-Security-Auditing", "Security")
    if kind == "process":
        image, cmd, parent = rng.choice(BENIGN_PROCESSES)
        return _ev(*sysmon, 1, ts, host, {"Image": f"C:\\Windows\\System32\\{image}", "CommandLine": cmd.replace("&", "&amp;"),
                                          "ParentImage": f"C:\\Windows\\System32\\{parent}", "User": f"CORP\\{user}"})
    if kind == "logon":
        return _ev(*sec, 4624, ts, host, {"TargetUserName": user, "LogonType": rng.choice(["2", "3", "5", "11"]),
                                          "IpAddress": f"10.0.{rng.randint(1, 4)}.{rng.randint(2, 200)}"})
    if kind == "logoff":
        return _ev(*sec, 4634, ts, host, {"TargetUserName": user, "LogonType": "3"})
    if kind == "network":
        return _ev(*sysmon, 3, ts, host, {"Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "User": f"CORP\\{user}",
                                          "DestinationIp": f"10.0.{rng.randint(1, 4)}.{rng.randint(2, 200)}", "DestinationPort": rng.choice(["443", "445", "53", "80"])})
    if kind == "file":
        return _ev(*sysmon, 11, ts, host, {"Image": "C:\\Windows\\explorer.exe", "TargetFilename": f"C:\\Users\\{user}\\Documents\\file{rng.randint(1, 500)}.docx"})
    if kind == "dns":
        return _ev(*sysmon, 22, ts, host, {"Image": "C:\\Windows\\System32\\svchost.exe", "QueryName": rng.choice(["www.microsoft.com", "login.microsoftonline.com", "intranet.corp.local", "update.googleapis.com"])})
    if kind == "script":
        return _ev("Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational", 4104, ts, host, {"ScriptBlockText": rng.choice(BENIGN_SCRIPTS)})
    if kind == "service":  # a legitimate updater installing its service
        return _ev("Service Control Manager", "System", 7045, ts, host, {"ServiceName": rng.choice(["Google Update Service", "Microsoft Edge Update", "Zoom Service"]), "ImagePath": "C:\\Program Files\\Vendor\\svc.exe"})
    if kind == "runkey":
        key, value = rng.choice(BENIGN_RUNKEYS)
        return _ev(*sysmon, 13, ts, host, {"Image": "C:\\Windows\\explorer.exe", "TargetObject": key, "Details": value})
    return _ev(*sec, 4625, ts, host, {"TargetUserName": user, "LogonType": "3", "IpAddress": f"10.0.1.{rng.randint(2, 200)}"})  # one mistyped password


def benign_batch(rng: random.Random, size: int, start: datetime) -> List[tuple]:
    """(timestamp, xml) pairs spread over a working day."""
    return [(t, benign_event(rng, t)) for t in sorted(start + timedelta(seconds=rng.randint(0, 28800)) for _ in range(size))]


async def rule_alerts(lines: List[str]):
    state = await ingest_agent({"raw_logs": lines, "logs": [], "alerts": [], "agent_execution_log": []})
    return detect_rules_only(state["logs"])


def rule_of(alert) -> str:
    return alert.detection_rule.replace("ATT&CK Rule: ", "")


async def benign_only(batches: int, size: int, seed: int) -> Counter:
    rng = random.Random(seed)
    by_rule: Counter = Counter()
    noisy = 0
    for i in range(batches):
        lines = [x for _, x in benign_batch(rng, size, datetime(2026, 9, 1, 8) + timedelta(days=i))]
        alerts = await rule_alerts(lines)
        noisy += bool(alerts)
        for a in alerts:
            by_rule[rule_of(a)] += 1
    total = batches * size
    print(f"\n== Benign only, rules: {batches} batches x {size} events = {total} events ==")
    print(f"batches with at least one alert: {noisy}/{batches} ({noisy / batches:.0%}); alerts per 1000 events: {sum(by_rule.values()) * 1000 / total:.1f}")
    for rule, n in by_rule.most_common():
        print(f"  {rule:32s} {n}")
    return by_rule


async def benign_llm(batches: int, seed: int) -> None:
    rng = random.Random(seed + 1)
    noisy = llm_noisy = 0
    print(f"\n== Benign only, full detection agent (LLM + rules): {batches} batches x 100 events ==")
    for i in range(batches):
        lines = [x for _, x in benign_batch(rng, 100, datetime(2026, 9, 1, 8) + timedelta(days=i))]
        alerts = await full_detection(lines)
        llm_alerts = [a for a in alerts if is_llm_alert(a)]
        noisy += bool(alerts)
        llm_noisy += bool(llm_alerts)
        print(f"  batch {i + 1}: alerts={len(alerts)} (llm-only alerts={len(llm_alerts)}) " + ", ".join(a.title[:40] for a in llm_alerts[:2]))
    print(f"batches with any alert: {noisy}/{batches}; batches where the LLM alone raised an alert: {llm_noisy}/{batches}")


def _event_time(xml: str) -> datetime:
    m = re.search(r"SystemTime='(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", xml)
    return datetime.fromisoformat(m.group(1)) if m else datetime(2026, 9, 1)


async def mixed(seed: int, noise: int = 300) -> None:
    """Each rule's real capture (<= 300 events) blended into benign noise by timestamp."""
    repo = CACHE / "attack_data"
    rng = random.Random(seed + 2)
    hit = 0
    tested = 0
    print(f"\n== Real attack captures blended into {noise} benign events (rules) ==")
    for tid in ATTACK_DETECTION_RULES:
        capture = None
        for f in pick_files(repo, tid, 30 << 20, 6):
            local = CACHE / "splunk" / f.relative_to(repo).as_posix()
            if not local.exists():
                continue
            events = split_events(local.read_text(errors="ignore"))
            if events and len(events) <= 300 and events[0].lstrip().startswith(("<Event", "0", "1")):
                # keep only files that fire the rule on their own (the mixed test is about noise, not parsing)
                if any(rule_of(a) == tid for a in await rule_alerts(events)):
                    capture = events
                    break
        if not capture:
            print(f"  {tid:10s} (no small capture that fires alone)")
            continue
        times = [_event_time(e) for e in capture if "SystemTime" in e] or [datetime(2026, 9, 1, 8)]
        start = min(times)
        noise_pairs = [(t, benign_event(rng, t)) for t in sorted(start + timedelta(seconds=rng.randint(0, 3600)) for _ in range(noise))]
        merged = sorted([(_event_time(e) if "SystemTime" in e else start, e) for e in capture] + noise_pairs, key=lambda p: p[0])
        alerts = await rule_alerts([e for _, e in merged])
        fired = any(rule_of(a) == tid for a in alerts)
        extra = sorted({rule_of(a) for a in alerts} - {tid})
        tested += 1
        hit += fired
        print(f"  {tid:10s} still detected in noise: {'yes' if fired else 'NO '}  other rules fired: {extra}")
    print(f"target rule still fires in noise: {hit}/{tested}")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batches", type=int, default=100)
    ap.add_argument("--size", type=int, default=150)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--mixed", action="store_true", help="blend real attack captures into noise (needs the Splunk cache)")
    ap.add_argument("--llm", action="store_true", help="also run the LLM on benign batches (needs Ollama)")
    ap.add_argument("--llm-batches", type=int, default=10)
    args = ap.parse_args()
    by_rule = await benign_only(args.batches, args.size, args.seed)
    if args.mixed:
        await mixed(args.seed)
    if args.llm:
        await benign_llm(args.llm_batches, args.seed)
    out = ROOT / "tests" / "results" / "false_positive_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"benign_alerts_by_rule": dict(by_rule), "batches": args.batches, "size": args.size}, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
