"""Generate realistic sample security logs for 5 attack scenarios."""

import json
import random
from datetime import datetime, timedelta
from typing import List

# Attack scenarios
SCENARIOS = {
    "brute_force_ssh": {
        "name": "Brute Force SSH Attack",
        "description": "Multiple failed SSH login attempts followed by successful login and lateral movement",
        "mitre_techniques": ["T1110", "T1078"],
    },
    "phishing_data_exfil": {
        "name": "Phishing → Credential Harvesting → Data Exfiltration",
        "description": "Phishing email leads to credential theft and large data transfers",
        "mitre_techniques": ["T1566", "T1539", "T1041"],
    },
    "ransomware_chain": {
        "name": "Ransomware Execution Chain",
        "description": "Reconnaissance, encryption, and C2 communication",
        "mitre_techniques": ["T1059", "T1486", "T1071"],
    },
    "insider_threat": {
        "name": "Insider Threat",
        "description": "Abnormal access patterns and unauthorized data downloads",
        "mitre_techniques": ["T1078", "T1083"],
    },
    "false_positive": {
        "name": "False Positive - Legitimate Admin Activity",
        "description": "Legitimate administrative activity that appears suspicious",
        "mitre_techniques": [],
    },
}


def generate_brute_force_ssh_logs(count: int = 150) -> List[dict]:
    """Generate brute force SSH attack logs."""
    logs = []
    attacker_ip = f"185.{random.randint(100, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    target_ip = "10.0.0.50"
    
    base_time = datetime.utcnow() - timedelta(hours=2)
    
    # Phase 1: Failed login attempts
    usernames = ["admin", "root", "user", "administrator", "test", "guest"]
    for i in range(count - 10):
        log_time = base_time + timedelta(seconds=i * 5)
        username = random.choice(usernames)
        
        logs.append({
            "timestamp": log_time.isoformat(),
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "destination_port": 22,
            "user": username,
            "action": "ssh_login_attempt",
            "status": "failure",
            "log_source": "auth",
            "raw_log": f"{log_time.isoformat()} {target_ip} sshd: Failed password for {username} from {attacker_ip} port {random.randint(40000, 60000)}",
        })
    
    # Phase 2: Successful login
    log_time = base_time + timedelta(seconds=(count - 10) * 5)
    logs.append({
        "timestamp": log_time.isoformat(),
        "source_ip": attacker_ip,
        "destination_ip": target_ip,
        "destination_port": 22,
        "user": "admin",
        "action": "ssh_login_attempt",
        "status": "success",
        "log_source": "auth",
        "raw_log": f"{log_time.isoformat()} {target_ip} sshd: Accepted password for admin from {attacker_ip} port {random.randint(40000, 60000)}",
    })
    
    # Phase 3: Lateral movement attempts
    for i in range(9):
        log_time = base_time + timedelta(seconds=(count - 9 + i) * 5)
        lateral_ip = f"10.0.0.{random.randint(51, 100)}"
        
        logs.append({
            "timestamp": log_time.isoformat(),
            "source_ip": target_ip,
            "destination_ip": lateral_ip,
            "destination_port": 22,
            "user": "admin",
            "action": "ssh_connection",
            "status": "success",
            "log_source": "auth",
            "raw_log": f"{log_time.isoformat()} {target_ip} sshd: Connection from {target_ip} to {lateral_ip}",
        })
    
    return logs


def generate_phishing_data_exfil_logs(count: int = 120) -> List[dict]:
    """Generate phishing to data exfiltration logs."""
    logs = []
    malicious_domain = f"{random.choice(['mail', 'secure', 'update'])}-{random.randint(1000, 9999)}.malicious.{random.choice(['com', 'net', 'org'])}"
    victim_ip = "10.0.0.75"
    
    base_time = datetime.utcnow() - timedelta(hours=4)
    
    # Phase 1: Phishing email (DNS queries)
    for i in range(20):
        log_time = base_time + timedelta(minutes=i)
        logs.append({
            "timestamp": log_time.isoformat(),
            "source_ip": victim_ip,
            "destination_ip": None,
            "destination_port": 53,
            "user": "user@company.com",
            "action": "dns_query",
            "status": "success",
            "log_source": "dns",
            "raw_log": f"{log_time.isoformat()} DNS query: {malicious_domain} from {victim_ip}",
        })
    
    # Phase 2: Credential submission (HTTP POST)
    log_time = base_time + timedelta(minutes=25)
    logs.append({
        "timestamp": log_time.isoformat(),
        "source_ip": victim_ip,
        "destination_ip": None,
        "destination_port": 443,
        "user": "user@company.com",
        "action": "http_post",
        "status": "success",
        "log_source": "http",
        "raw_log": f"{log_time.isoformat()} HTTP POST to {malicious_domain}/login username=user@company.com",
    })
    
    # Phase 3: Large data transfers (exfiltration)
    for i in range(count - 22):
        log_time = base_time + timedelta(minutes=30 + i * 2)
        transfer_size = random.randint(50 * 1024 * 1024, 500 * 1024 * 1024)  # 50-500 MB
        
        logs.append({
            "timestamp": log_time.isoformat(),
            "source_ip": victim_ip,
            "destination_ip": None,
            "destination_port": 443,
            "user": "user@company.com",
            "action": "data_transfer",
            "status": "success",
            "log_source": "http",
            "raw_log": f"{log_time.isoformat()} HTTP POST {transfer_size} bytes to {malicious_domain}/upload",
            "metadata": {"transfer_size": transfer_size},
        })
    
    return logs


def generate_ransomware_chain_logs(count: int = 180) -> List[dict]:
    """Generate ransomware execution chain logs."""
    logs = []
    attacker_ip = f"192.{random.randint(100, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    victim_ip = "10.0.0.100"
    c2_domain = f"c2-{random.randint(1000, 9999)}.{random.choice(['tk', 'ml', 'ga'])}"
    
    base_time = datetime.utcnow() - timedelta(hours=6)
    
    # Phase 1: Reconnaissance (port scans)
    for i in range(30):
        log_time = base_time + timedelta(seconds=i * 10)
        port = random.choice([445, 3389, 135, 139, 22, 80, 443])
        
        logs.append({
            "timestamp": log_time.isoformat(),
            "source_ip": attacker_ip,
            "destination_ip": victim_ip,
            "destination_port": port,
            "user": None,
            "action": "connection_attempt",
            "status": "success" if i % 3 == 0 else "failure",
            "log_source": "system",
            "raw_log": f"{log_time.isoformat()} Connection attempt from {attacker_ip} to {victim_ip}:{port}",
        })
    
    # Phase 2: Command execution
    log_time = base_time + timedelta(minutes=10)
    logs.append({
        "timestamp": log_time.isoformat(),
        "source_ip": attacker_ip,
        "destination_ip": victim_ip,
        "destination_port": 445,
        "user": "SYSTEM",
        "action": "command_execution",
        "status": "success",
        "log_source": "system",
        "raw_log": f"{log_time.isoformat()} Command executed: powershell.exe -EncodedCommand ...",
    })
    
    # Phase 3: Encryption activity
    for i in range(count - 80):
        log_time = base_time + timedelta(minutes=15 + i)
        file_path = f"C:\\Users\\Documents\\file{random.randint(1, 1000)}.docx"
        
        logs.append({
            "timestamp": log_time.isoformat(),
            "source_ip": victim_ip,
            "destination_ip": None,
            "destination_port": None,
            "user": "SYSTEM",
            "action": "file_encryption",
            "status": "success",
            "log_source": "system",
            "raw_log": f"{log_time.isoformat()} File encrypted: {file_path}",
        })
    
    # Phase 4: C2 communication
    for i in range(50):
        log_time = base_time + timedelta(minutes=20 + i * 2)
        logs.append({
            "timestamp": log_time.isoformat(),
            "source_ip": victim_ip,
            "destination_ip": None,
            "destination_port": 443,
            "user": None,
            "action": "dns_query",
            "status": "success",
            "log_source": "dns",
            "raw_log": f"{log_time.isoformat()} DNS query: {c2_domain} from {victim_ip}",
        })
    
    return logs


def generate_insider_threat_logs(count: int = 100) -> List[dict]:
    """Generate insider threat logs."""
    logs = []
    insider_ip = "10.0.0.25"
    insider_user = "john.doe@company.com"
    
    base_time = datetime.utcnow() - timedelta(hours=12)
    
    # Unusual access patterns (outside business hours, large data access)
    for i in range(count):
        log_time = base_time + timedelta(minutes=i * 15)
        hour = log_time.hour
        
        # Suspicious: access at unusual hours
        if hour < 6 or hour > 22:
            action = "database_query"
            db_name = random.choice(["customer_db", "financial_db", "employee_db"])
            
            logs.append({
                "timestamp": log_time.isoformat(),
                "source_ip": insider_ip,
                "destination_ip": "10.0.0.10",
                "destination_port": 5432,
                "user": insider_user,
                "action": action,
                "status": "success",
                "log_source": "system",
                "raw_log": f"{log_time.isoformat()} Database access: {insider_user} queried {db_name}",
            })
        
        # Large data downloads
        if i % 10 == 0:
            transfer_size = random.randint(100 * 1024 * 1024, 1000 * 1024 * 1024)  # 100MB-1GB
            
            logs.append({
                "timestamp": log_time.isoformat(),
                "source_ip": insider_ip,
                "destination_ip": None,
                "destination_port": 443,
                "user": insider_user,
                "action": "data_download",
                "status": "success",
                "log_source": "http",
                "raw_log": f"{log_time.isoformat()} Large download: {transfer_size} bytes by {insider_user}",
                "metadata": {"transfer_size": transfer_size},
            })
    
    return logs[:count]


def generate_false_positive_logs(count: int = 80) -> List[dict]:
    """Generate logs that look suspicious but are legitimate."""
    logs = []
    admin_ip = "10.0.0.5"
    admin_user = "admin@company.com"
    
    base_time = datetime.utcnow() - timedelta(hours=1)
    
    # Legitimate admin activity that might look suspicious:
    # - Multiple SSH connections (admin managing multiple servers)
    # - Large data transfers (backups)
    # - Unusual hours (admin working late)
    
    # Multiple SSH connections (legitimate server management)
    server_ips = [f"10.0.0.{i}" for i in range(20, 40)]
    for i in range(40):
        log_time = base_time + timedelta(minutes=i * 2)
        server_ip = random.choice(server_ips)
        
        logs.append({
            "timestamp": log_time.isoformat(),
            "source_ip": admin_ip,
            "destination_ip": server_ip,
            "destination_port": 22,
            "user": admin_user,
            "action": "ssh_connection",
            "status": "success",
            "log_source": "auth",
            "raw_log": f"{log_time.isoformat()} Admin SSH connection to {server_ip}",
        })
    
    # Large transfer (backup)
    for i in range(count - 40):
        log_time = base_time + timedelta(minutes=80 + i * 3)
        transfer_size = random.randint(500 * 1024 * 1024, 2000 * 1024 * 1024)  # 500MB-2GB
        
        logs.append({
            "timestamp": log_time.isoformat(),
            "source_ip": admin_ip,
            "destination_ip": "backup.company.com",
            "destination_port": 22,
            "user": admin_user,
            "action": "backup_transfer",
            "status": "success",
            "log_source": "system",
            "raw_log": f"{log_time.isoformat()} Backup transfer: {transfer_size} bytes to backup server",
            "metadata": {"transfer_size": transfer_size, "backup": True},
        })
    
    return logs


def generate_all_scenarios() -> dict:
    """Generate all attack scenarios."""
    all_logs = {}
    
    for scenario_key, scenario_info in SCENARIOS.items():
        if scenario_key == "brute_force_ssh":
            logs = generate_brute_force_ssh_logs()
        elif scenario_key == "phishing_data_exfil":
            logs = generate_phishing_data_exfil_logs()
        elif scenario_key == "ransomware_chain":
            logs = generate_ransomware_chain_logs()
        elif scenario_key == "insider_threat":
            logs = generate_insider_threat_logs()
        elif scenario_key == "false_positive":
            logs = generate_false_positive_logs()
        else:
            logs = []
        
        all_logs[scenario_key] = {
            "scenario": scenario_info,
            "logs": logs,
        }
    
    return all_logs


def main():
    """Generate and save sample data."""
    print("Generating sample security logs...")
    
    all_scenarios = generate_all_scenarios()
    
    # Save to JSON files
    for scenario_key, data in all_scenarios.items():
        filename = f"sample_data_{scenario_key}.json"
        output = {
            "scenario": data["scenario"],
            "logs": [log["raw_log"] for log in data["logs"]],  # Save as raw logs
        }
        
        with open(filename, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"✓ Generated {len(data['logs'])} logs for {data['scenario']['name']} -> {filename}")
    
    # Generate combined dataset (70% true positives, 30% false positives)
    combined_logs = []
    for scenario_key, data in all_scenarios.items():
        if scenario_key != "false_positive":
            combined_logs.extend([log["raw_log"] for log in data["logs"]])
    
    # Add false positives (30%)
    false_positive_count = int(len(combined_logs) * 0.3 / 0.7)
    combined_logs.extend([
        log["raw_log"] for log in all_scenarios["false_positive"]["logs"][:false_positive_count]
    ])
    
    random.shuffle(combined_logs)
    
    with open("sample_data_combined.json", "w") as f:
        json.dump({"logs": combined_logs}, f, indent=2)
    
    print(f"✓ Generated combined dataset with {len(combined_logs)} logs -> sample_data_combined.json")
    print("\nSample data generation complete!")


if __name__ == "__main__":
    main()

