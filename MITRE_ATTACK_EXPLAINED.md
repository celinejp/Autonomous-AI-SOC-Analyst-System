# MITRE ATT&CK Explained - In Easy Words

## What is MITRE ATT&CK?

**MITRE ATT&CK** is like a **"playbook of hacker techniques"** that cybersecurity professionals use worldwide.

Think of it like this:
- **Sports**: Coaches study opponent plays to defend against them
- **Cybersecurity**: Security teams study hacker techniques (ATT&CK) to detect and stop attacks

## What Does "24+ MITRE ATT&CK Rules" Mean?

**In simple terms:** Your system can detect **24 different types of cyberattacks** that are documented in the MITRE ATT&CK framework.

Each "rule" is like a **detection pattern** for a specific attack technique.

## The 24 Attack Techniques Your System Detects

### 1. **Initial Access** (How hackers get in)
- **T1566.001** - Phishing with malicious email attachments
- **T1566.002** - Phishing with malicious links

**Real example:** "Someone sent an email with a virus attachment"

---

### 2. **Credential Access** (Stealing passwords)
- **T1110.001** - Brute force attacks (trying many passwords)
- **T1110.003** - Password spraying (trying one password on many accounts)
- **T1003.001** - Stealing passwords from computer memory

**Real example:** "Someone tried to guess the password 10 times in 1 minute"

---

### 3. **Execution** (Running malicious code)
- **T1059.001** - Malicious PowerShell commands
- **T1059.003** - Malicious command shell usage

**Real example:** "Someone ran a suspicious PowerShell script to download malware"

---

### 4. **Persistence** (Staying in the system)
- **T1547.001** - Adding malware to startup (runs every time computer starts)
- **T1053.005** - Creating scheduled tasks to run malware
- **T1136.001** - Creating new user accounts for backdoor access

**Real example:** "Malware added itself to Windows startup folder"

---

### 5. **Privilege Escalation** (Getting admin access)
- **T1548.002** - Bypassing Windows security (UAC bypass)

**Real example:** "Hacker bypassed Windows security to get admin rights"

---

### 6. **Defense Evasion** (Hiding from security tools)
- **T1070.001** - Deleting security logs to hide tracks
- **T1562.001** - Disabling antivirus/security software

**Real example:** "Hacker deleted event logs so we can't see what they did"

---

### 7. **Discovery** (Exploring the network)
- **T1087.001** - Finding user accounts on the system
- **T1046** - Scanning network for open ports/services

**Real example:** "Hacker scanned the network to find vulnerable computers"

---

### 8. **Lateral Movement** (Moving between computers)
- **T1021.001** - Using Remote Desktop (RDP) to access other computers
- **T1021.002** - Using Windows file sharing (SMB) to access other computers

**Real example:** "Hacker used RDP to jump from one computer to another"

---

### 9. **Collection** (Gathering data to steal)
- **T1560.001** - Compressing files before stealing them

**Real example:** "Hacker zipped up sensitive files before stealing them"

---

### 10. **Exfiltration** (Stealing data)
- **T1048.003** - Stealing large amounts of data (100MB+)
- **T1567.002** - Uploading stolen data to cloud storage (Dropbox, Google Drive)

**Real example:** "Hacker uploaded 500MB of customer data to Dropbox"

---

### 11. **Command and Control** (Controlling hacked computers)
- **T1071.001** - Malware communicating with hacker's server via web
- **T1071.004** - Malware hiding communication in DNS queries

**Real example:** "Malware is sending data to a hacker's server every 5 minutes"

---

### 12. **Impact** (Causing damage)
- **T1486** - Ransomware (encrypting files and demanding money)
- **T1490** - Deleting backups so victims can't recover

**Real example:** "Ransomware encrypted all files and left a ransom note"

---

## How Your System Uses These Rules

**Step 1:** System receives security logs (like "5 failed login attempts")

**Step 2:** Detection Agent checks logs against all 24 MITRE ATT&CK rules

**Step 3:** If a pattern matches (e.g., "5 failed logins in 60 seconds" = T1110.001 Brute Force)

**Step 4:** System creates an alert: "Brute Force Attack Detected - MITRE Technique T1110.001"

**Step 5:** System enriches the alert with context and creates a response plan

## Why This Matters for Your Resume

**"24+ MITRE ATT&CK rules"** shows that:
1. ✅ Your system detects **real, documented attack techniques** (not just generic alerts)
2. ✅ It follows **industry standards** (MITRE ATT&CK is used by major companies)
3. ✅ It provides **specific, actionable intelligence** (knows exactly what attack is happening)
4. ✅ It's **comprehensive** (covers the full attack lifecycle from initial access to impact)

## How to Explain This in an Interview

### Simple Version:
*"MITRE ATT&CK is a framework that documents how hackers attack systems. My system has detection rules for 24 different attack techniques - things like brute force attacks, ransomware, data theft, and lateral movement. When the system sees logs matching these patterns, it creates an alert with the specific MITRE technique ID, so security analysts know exactly what type of attack is happening."*

### Technical Version:
*"I implemented 24 MITRE ATT&CK detection rules covering the full attack lifecycle - from initial access techniques like phishing (T1566.001, T1566.002) through to impact techniques like ransomware (T1486). Each rule maps specific log patterns to ATT&CK techniques. For example, T1110.001 detects brute force by identifying 5+ failed authentication attempts within 60 seconds from the same source IP. This provides structured, standardized threat detection that security teams can immediately understand and respond to."*

### Banking Context:
*"For banks, MITRE ATT&CK mapping is critical because:*
1. *It provides standardized threat intelligence that security teams understand*
2. *It helps with compliance reporting - regulators want to know what types of attacks you're detecting*
3. *It enables threat hunting - analysts can search for specific techniques across historical data*
4. *It supports incident response - knowing the exact technique helps determine the right response*

*My system automatically maps every detected threat to the appropriate MITRE technique, so when a brute force attack happens, the alert says 'T1110.001 - Brute Force: Password Guessing' rather than just 'suspicious login activity.' This specificity is crucial for banks dealing with high-value targets."*

---

## Quick Reference: The 24 Techniques

| ID | Name | What It Detects |
|---|---|---|
| T1566.001 | Phishing Attachment | Malicious email attachments |
| T1566.002 | Phishing Link | Malicious email links |
| T1110.001 | Brute Force | Multiple failed password attempts |
| T1110.003 | Password Spraying | One password tried on many accounts |
| T1003.001 | LSASS Memory Dump | Password theft from memory |
| T1059.001 | PowerShell | Malicious PowerShell scripts |
| T1059.003 | Command Shell | Malicious command execution |
| T1547.001 | Registry Run Keys | Malware in startup |
| T1053.005 | Scheduled Tasks | Malicious scheduled tasks |
| T1136.001 | Create Account | Unauthorized account creation |
| T1548.002 | Bypass UAC | Windows security bypass |
| T1070.001 | Clear Event Logs | Log deletion to hide tracks |
| T1562.001 | Disable Tools | Antivirus/security disabled |
| T1087.001 | Account Discovery | Finding user accounts |
| T1046 | Network Service Discovery | Port scanning |
| T1021.001 | RDP | Remote desktop access |
| T1021.002 | SMB | Windows file sharing abuse |
| T1560.001 | Archive Data | Compressing files to steal |
| T1048.003 | Exfiltration Alternative Protocol | Large data theft |
| T1567.002 | Cloud Storage Exfiltration | Uploading stolen data to cloud |
| T1071.001 | Web Protocols C2 | Malware web communication |
| T1071.004 | DNS C2 | Malware DNS communication |
| T1486 | Data Encrypted | Ransomware |
| T1490 | Inhibit System Recovery | Backup deletion |

---

## Key Takeaway

**"24+ MITRE ATT&CK rules"** = Your system can automatically detect and classify 24 different types of cyberattacks using industry-standard techniques.

This is impressive because:
- Most security systems just detect "suspicious activity"
- Your system detects **specific, named attack techniques**
- This makes alerts more actionable and useful for security teams

