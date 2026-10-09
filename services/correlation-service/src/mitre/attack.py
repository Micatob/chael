"""MITRE ATT&CK mapping for Chael SIEM correlation rules."""
from typing import Dict, List, Optional

# Technique ID -> {name, tactic, description}
ATTACK_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries attempt to guess credentials via brute force / password spraying."},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access", "description": "SSH/RDP/Windows logon password guessing."},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "Credential Access", "description": "Single password tried against many accounts."},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion / Persistence", "description": "Use of stolen or created accounts."},
    "T1136": {"name": "Create Account", "tactic": "Persistence", "description": "New local/domain account created (Event 4720)."},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "description": "Suspicious PowerShell execution."},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution", "description": "Suspicious cmd execution."},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence / Execution", "description": "Scheduled task created/updated (4698/4702)."},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence", "description": "New service installed (4697/7045)."},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence", "description": "Registry Run key modification."},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "Defense Evasion", "description": "Security log cleared (1102)."},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "description": "Ransomware-like file enumeration / .crypt extensions."},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Ransomware file encryption indicators."},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "description": "Network scanning (nmap/masscan)."},
    "T1040": {"name": "Network Sniffing", "tactic": "Credential Access / Collection", "description": "Anomalous network flows."},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "description": "Possible data exfiltration via flows."},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "description": "Mimikatz / credential dumping tools."},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion / Privilege Escalation", "description": "CobaltStrike / Meterpreter injection."},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "description": "Special privileges assigned (4672)."},
    "T1134": {"name": "Access Token Manipulation", "tactic": "Defense Evasion / Privilege Escalation", "description": "Explicit credential logon (4648)."},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access", "description": "Repeated auth errors exposing creds."},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact", "description": "Repeated firewall blocks / DoS pattern."},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance", "description": "Vulnerability / port scanning."},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access", "description": "Kerberos ticket abuse (roasting, forging)."},
    "T1558.001": {"name": "Golden Ticket", "tactic": "Credential Access", "description": "Forged Kerberos TGT with KRBTGT hash (Event 4768 anomalies)."},
    "T1558.002": {"name": "AS-REP Roasting", "tactic": "Credential Access", "description": "AS-REP roastable accounts, pre-auth disabled (Event 4768 without pre-auth / 4771)."},
    "T1558.003": {"name": "Kerberoasting", "tactic": "Credential Access", "description": "Requesting crackable service tickets, RC4 etype 0x17 (Event 4769 burst)."},
    "T1558.004": {"name": "Silver Ticket", "tactic": "Credential Access", "description": "Forged service ticket with service hash (Event 4769 anomalies)."},
    "T1550.002": {"name": "Pass the Hash", "tactic": "Lateral Movement", "description": "NTLM hash reuse for lateral movement (4624 type 3 + 4768/4769)."},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "description": "RDP lateral movement (4624 type 10, 4778/4779)."},
    "T1021.004": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "description": "SMB lateral movement (4624 type 3, 5140/5145)."},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "Lateral Movement", "description": "WinRM lateral movement (4624, 6/5985)."},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control", "description": "DNS tunneling / C2 over DNS (long labels, high entropy)."},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "description": "Data staged and exfiltrated over existing C2."},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control", "description": "Beaconing over HTTP/S to C2."},
}

# Sigma tag (attack.txxxx) -> technique ID
SIGMA_TAG_TO_TECHNIQUE = {
    "t1110": "T1110",
    "t1110_001": "T1110.001",
    "t1078": "T1078",
    "t1136": "T1136",
    "t1059_001": "T1059.001",
    "t1053": "T1053",
    "t1543": "T1543",
    "t1547_001": "T1547.001",
    "t1070_001": "T1070.001",
    "t1486": "T1486",
    "t1046": "T1046",
    "t1003": "T1003",
    "t1055": "T1055",
    "t1068": "T1068",
    "t1558": "T1558",
    "t1558_001": "T1558.001",
    "t1558_002": "T1558.002",
    "t1558_003": "T1558.003",
    "t1558_004": "T1558.004",
    "t1550_002": "T1550.002",
    "t1021_001": "T1021.001",
    "t1021_004": "T1021.004",
    "t1021_006": "T1021.006",
    "t1071_004": "T1071.004",
    "t1041": "T1041",
}


def normalize_sigma_tags(tags: List[str]) -> List[str]:
    """Convert Sigma tags like 'attack.t1110' / 'attack.credential_access' to technique IDs."""
    out: List[str] = []
    for tag in tags or []:
        t = tag.strip().lower()
        if t.startswith("attack.t"):
            key = t.replace("attack.", "").replace(".", "_")
            tech = SIGMA_TAG_TO_TECHNIQUE.get(key)
            if tech and tech not in out:
                out.append(tech)
            elif key.upper().replace("_", ".") not in out:
                # best-effort: T1110_001 -> T1110.001
                candidate = "T" + key[1:].upper().replace("_", ".")
                if candidate in ATTACK_TECHNIQUES and candidate not in out:
                    out.append(candidate)
    return out


def get_technique(technique_id: str) -> Optional[Dict[str, str]]:
    return ATTACK_TECHNIQUES.get(technique_id)


def mitre_for_rule(rule_id: str) -> Dict[str, str]:
    """Fallback MITRE mapping for built-in Chael rule IDs."""
    mapping = {
        "brute_force": {"technique_id": "T1110.001", "tactic": "Credential Access", "technique": "Brute Force: Password Guessing"},
        "ssh_brute_force": {"technique_id": "T1110.001", "tactic": "Credential Access", "technique": "Brute Force: Password Guessing"},
        "ssh_invalid_user": {"technique_id": "T1110", "tactic": "Credential Access", "technique": "Brute Force"},
        "rdp_brute_force": {"technique_id": "T1110.001", "tactic": "Credential Access", "technique": "Brute Force: Password Guessing"},
        "failed_logon_windows": {"technique_id": "T1110.001", "tactic": "Credential Access", "technique": "Brute Force: Password Guessing"},
        "account_lockout": {"technique_id": "T1110", "tactic": "Credential Access", "technique": "Brute Force"},
        "malware_detected": {"technique_id": "T1003", "tactic": "Credential Access", "technique": "OS Credential Dumping"},
        "ransomware_activity": {"technique_id": "T1486", "tactic": "Impact", "technique": "Data Encrypted for Impact"},
        "privilege_escalation": {"technique_id": "T1068", "tactic": "Privilege Escalation", "technique": "Exploitation for Privilege Escalation"},
        "account_manipulation": {"technique_id": "T1136", "tactic": "Persistence", "technique": "Create Account"},
        "persistence_service": {"technique_id": "T1543", "tactic": "Persistence", "technique": "Create or Modify System Process"},
        "registry_persistence": {"technique_id": "T1547.001", "tactic": "Persistence", "technique": "Registry Run Keys"},
        "log_clear": {"technique_id": "T1070.001", "tactic": "Defense Evasion", "technique": "Clear Windows Event Logs"},
        "network_scanner": {"technique_id": "T1046", "tactic": "Discovery", "technique": "Network Service Discovery"},
        "powershell_suspicious": {"technique_id": "T1059.001", "tactic": "Execution", "technique": "PowerShell"},
        "yara_critical_match": {"technique_id": "T1055", "tactic": "Defense Evasion / Privilege Escalation", "technique": "Process Injection"},
        "yara_high_match": {"technique_id": "T1055", "tactic": "Defense Evasion / Privilege Escalation", "technique": "Process Injection"},
        "yara_multi_match": {"technique_id": "T1055", "tactic": "Defense Evasion / Privilege Escalation", "technique": "Process Injection"},
        "critical_severity": {"technique_id": "T1595", "tactic": "Reconnaissance", "technique": "Active Scanning"},
        "kerberoasting": {"technique_id": "T1558.003", "tactic": "Credential Access", "technique": "Kerberoasting"},
        "asrep_roasting": {"technique_id": "T1558.002", "tactic": "Credential Access", "technique": "AS-REP Roasting"},
        "golden_ticket_suspect": {"technique_id": "T1558.001", "tactic": "Credential Access", "technique": "Golden Ticket"},
        "silver_ticket_suspect": {"technique_id": "T1558.004", "tactic": "Credential Access", "technique": "Silver Ticket"},
        "kerberos_bruteforce": {"technique_id": "T1110.001", "tactic": "Credential Access", "technique": "Brute Force: Password Guessing"},
        "pass_the_hash_suspect": {"technique_id": "T1550.002", "tactic": "Lateral Movement", "technique": "Pass the Hash"},
        "lateral_movement_rdp": {"technique_id": "T1021.001", "tactic": "Lateral Movement", "technique": "Remote Desktop Protocol"},
        "lateral_movement_smb": {"technique_id": "T1021.004", "tactic": "Lateral Movement", "technique": "SMB/Windows Admin Shares"},
        "dns_tunneling_suspect": {"technique_id": "T1071.004", "tactic": "Command and Control", "technique": "DNS"},
        "c2_beacon_suspect": {"technique_id": "T1071.001", "tactic": "Command and Control", "technique": "Web Protocols"},
        "persistence_schtask": {"technique_id": "T1053", "tactic": "Persistence / Execution", "technique": "Scheduled Task/Job"},
    }
    return mapping.get(rule_id, {"technique_id": "T1595", "tactic": "Reconnaissance", "technique": "Active Scanning"})
