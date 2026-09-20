# The 24 ATT&CK rules

MITRE ATT&CK is a public catalogue of attacker techniques, each with an ID (T1110 = brute force). The Detection
agent has **24 hand-written rules** in `backend/app/detection/attack_rules.py`. Separately, the whole MITRE catalogue
(~700 techniques) is loaded into Qdrant so any technique can be looked up and tagged on an alert; only these 24 have a
purpose-built rule.

| ID | Technique | Tactic | What the rule looks for |
|---|---|---|---|
| T1566.001 | Spearphishing Attachment | Initial Access | Office app spawning a shell/script host; mail-gateway attachment verdicts |
| T1110.001 | Password Guessing | Credential Access | 5+ failed logins from one IP+user within 60 s |
| T1110.003 | Password Spraying | Credential Access | 10+ failures from one IP across 5+ users within 5 min |
| T1059.001 | PowerShell | Execution | Encoded / hidden / download-cradle PowerShell (also in script-block logs) |
| T1059.003 | Windows Command Shell | Execution | cmd reaching admin shares; Office spawning cmd |
| T1547.001 | Registry Run Keys | Persistence | Run / RunOnce / Winlogon registry keys (any hive) |
| T1053.005 | Scheduled Task | Persistence | `schtasks /create`, event 4698 |
| T1136.001 | Local Account | Persistence | Event 4720, `net user/localgroup ... /add` |
| T1548.002 | Bypass UAC | Privilege Escalation | fodhelper/eventvwr/sdclt, UAC-bypass registry keys |
| T1003.001 | LSASS Memory | Credential Access | mimikatz, createdump/procdump/comsvcs against LSASS, LSASS access masks |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | Event 1102 (Security) / 104 (System) log cleared, `wevtutil cl` |
| T1562.001 | Disable or Modify Tools | Defense Evasion | `Set/Add-MpPreference`, Defender service stop, firewall off |
| T1087.001 | Local Account | Discovery | `net user`, `net localgroup`, `wmic useraccount` |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | Event 4624 logon type 10, `mstsc /v:`, one source RDP-ing to 3+ hosts |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | Admin-share paths (`\\host\C$`) in files or command lines, psexec |
| T1560.001 | Archive via Utility | Collection | 7z/rar/zip with a password |
| T1048.003 | Exfiltration Over Alternative Protocol | Exfiltration | 100 MB+ outbound, DNS data carried in long labels, nslookup with encoded data, WebDAV upload |
| T1490 | Inhibit System Recovery | Impact | `vssadmin delete`, `wmic shadowcopy delete`, `wbadmin delete`, bcdedit recovery off |
| T1218.011 | Rundll32 | Defense Evasion | rundll32 with script/UNC/temp-path/ordinal arguments |
| T1218.005 | Mshta | Defense Evasion | mshta running a URL, script or .hta |
| T1105 | Ingress Tool Transfer | Command and Control | certutil -urlcache, bitsadmin /transfer, curl/wget, Invoke-WebRequest |
| T1543.003 | Windows Service | Persistence | New service: events 7045 / 4697, `sc create`, `New-Service` |
| T1003.002 | Security Account Manager | Credential Access | `reg save HKLM\SAM`, ntdsutil/esentutl against SAM/NTDS |
| T1047 | Windows Management Instrumentation | Execution | `wmic process call create`, `/node:`, Invoke-CimMethod / Invoke-WmiMethod |

## How detection runs

1. **These 24 rules** read concrete fields of the parsed log (command line, parent process, event ID, logon type,
   registry key, DNS name, bytes out, ...), with real time windows.
2. **~15 keyword/threshold signatures** in `detection_agent.py` (ransomware, port scan, C2, SQL injection, ...). A
   signature and a rule reporting the same technique family are merged into one alert.
3. **The LLM**, for anything the rules don't cover. LLM-named technique IDs are kept only if a similarity search
   against the MITRE catalogue agrees (score >= 0.80).

A prompt-injection check also runs; instruction-like text inside a log becomes its own alert.

## Tested on real attack data

Each rule is tested by a unit-test sample (`tests/test_attack_rules.py`) **and** against public attack captures
(Splunk attack_data, EVTX-ATTACK-SAMPLES) with `backend/scripts/eval_public_datasets.py`. The real data exposed
gaps that the hand-written samples hid (real Windows event XML and multi-line event blocks weren't parsed; several
rules were too narrow). Six earlier rules that the public data could not exercise (port scan, beaconing, DNS
tunnelling, ransomware, phishing links, cloud upload) were replaced with techniques the data does contain
(rundll32, mshta, ingress tool transfer, service creation, SAM dumping, WMI); ransomware, port scans, C2 and
DNS tunnelling are still caught by the keyword signatures and the LLM. Results are in the README.

A false-positive test on generated benign Windows activity (`backend/scripts/eval_false_positives.py`) found five
rules too eager on legitimate use of the same tools (`curl` to an internal API, any `net user`, any service install,
any Run key, and a prompt-injection check that matched the `<System>` tag of every event). They now require
stronger evidence (a download to disk, several discovery commands together, a suspicious service binary or Run-key
value); false alarms fell from every benign batch to 1%, and the real captures still fire, also when buried in noise.

Limits: thresholds are sized for small batches, reputation and domain-age lookups are not done, and keyword
signatures are easy to evade.
