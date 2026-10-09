"""Deterministic local fallback — always available, never hallucinates actions.

This is the differentiator vs big-SIEM AI: when Groq is off/rate-limited/offline,
analysts still get structured triage (MITRE suggestion, FP checklist, next steps).
"""
from typing import Dict, Any, List


def _risk_band(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def local_explain(incident: Dict[str, Any]) -> Dict[str, Any]:
    desc = (incident.get("description") or "").lower()
    artifacts = incident.get("artifacts") or {}
    score = int(incident.get("risk_score") or 0)
    mitre = incident.get("mitre_attack") or artifacts.get("mitre_attack") or []
    if isinstance(mitre, str):
        mitre = [mitre]

    likely: List[str] = []
    if "brute force" in desc or "failed" in desc or "4625" in desc:
        likely.append("Credential-guessing against exposed auth (check for successful logon right after the burst).")
    if "powershell" in desc:
        likely.append("Script execution burst (check command lines for encoded/IEX/download patterns).")
    if "mimikatz" in desc or "cobalt" in desc or "yara" in desc:
        likely.append("Malware/tooling indicator — treat host as compromised until proven otherwise.")
    if "ransomware" in desc or ".crypt" in desc:
        likely.append("Possible encryption activity — check file-write velocity + backups immediately.")
    if "log cleared" in desc or "1102" in desc:
        likely.append("Anti-forensics — preserve remaining logs, snapshot host.")
    if "nmap" in desc or "scan" in desc:
        likely.append("Reconnaissance — check if scanner is authorized (vuln scanner allowlist).")
    if "kerberoast" in desc or "4769" in desc or "service ticket" in desc:
        likely.append("Possible Kerberoasting (T1558.003) — check for RC4 etype 0x17 bursts, same SPN requested repeatedly, then force rotation of the service account password.")
    if "4771" in desc or "pre-auth" in desc or "as-rep" in desc or "asrep" in desc:
        likely.append("Possible AS-REP Roasting (T1558.002) — list accounts with pre-auth disabled, check 4768 without pre-auth, then enable pre-auth.")
    if "golden" in desc or "silver ticket" in desc or "0x17" in desc or "forged ticket" in desc:
        likely.append("Possible forged Kerberos ticket (T1558.001/.004) — check ticket lifetime anomalies, reset KRBTGT twice, rotate service passwords.")
    if "pass-the-hash" in desc or "pass the hash" in desc or "ntlm" in desc:
        likely.append("Possible Pass-the-Hash lateral movement (T1550.002) — hunt 4624 type-3 logons across hosts, isolate source.")
    if "rdp" in desc or "4778" in desc or "4779" in desc or "lateral" in desc:
        likely.append("Possible RDP lateral movement (T1021.001) — map source→dest host graph, check for first-time admin RDP.")
    if "dns" in desc and ("tunnel" in desc or "c2" in desc or "query" in desc):
        likely.append("Possible DNS tunneling/C2 (T1071.004) — inspect longest labels, query volume per host, block malicious domain at DNS firewall.")
    if not likely:
        likely.append("Unclassified pattern — correlate host + time window before escalating.")

    fp_checklist = [
        "Is the source IP an approved scanner / admin jump host?",
        "Is there a matching change ticket / maintenance window?",
        "Did the same host succeed right after failures (real compromise) or only fail (noise)?",
        "Is the volume consistent with baseline for this host/hour?",
        "Do other hosts show the same pattern (spray) or just one (targeted)?",
        "Is the geolocation of the source IP expected for this user/host?",
        "Are there known false-positive signatures for this detection rule?",
    ]
    next_steps = [
        "Hunt related logs for the same host ±30 min (use Hunt page).",
        "Enrich IOCs via External Hunt (VirusTotal/AbuseIPDB/Shodan).",
        "If risk >= 70: isolate host via SOAR (requires approval), block IOC at firewall.",
        "Check for lateral movement: same source IP across multiple hosts.",
        "Verify persistence: scheduled tasks, registry keys, WMI subscriptions on affected host.",
        "Collect forensic artifacts: memory dump, disk image, volatile data.",
        "Document timeline: what happened, when, and blast radius.",
        "Update detection rules: create YARA/Sigma rules for identified IOCs.",
    ]
    return {
        "engine": "local-fallback",
        "summary": f"{_risk_band(score)} incident ({score}/100): {incident.get('description', '')[:280]}",
        "likely_causes": likely,
        "mitre_attack": mitre,
        "false_positive_checklist": fp_checklist,
        "recommended_actions": next_steps,
        "confidence": 0.55,
        "requires_human_approval": True,
    }


def nl_to_dsl(question: str) -> Dict[str, Any]:
    """SOC-focused NL->query translator (no LLM needed for common cases)."""
    import re
    q = (question or "").lower()
    query: Dict[str, Any] = {"query": {"match_all": {}}, "size": 50, "sort": [{"timestamp": {"order": "desc"}}]}
    explanation = "Default: latest 50 logs."

    if "failed" in q and ("login" in q or "logon" in q or "ssh" in q or "rdp" in q):
        query = {"query": {"bool": {"must": [
            {"multi_match": {"query": "failed login logon", "fields": ["message"]}},
            {"range": {"timestamp": {"gte": "now-1h"}}}
        ]}}, "size": 50}
        explanation = "Failed authentication attempts in the last hour."
    elif "powershell" in q:
        query = {"query": {"bool": {"must": [
            {"match": {"source": "PowerShell"}},
            {"range": {"timestamp": {"gte": "now-24h"}}}
        ]}}, "size": 50}
        explanation = "PowerShell activity in the last 24 hours."
    elif "critical" in q:
        query = {"query": {"bool": {"must": [
            {"term": {"severity": "CRITICAL"}},
            {"range": {"timestamp": {"gte": "now-24h"}}}
        ]}}, "size": 50}
        explanation = "Critical severity events in the last 24 hours."
    elif "lateral movement" in q or "lateral" in q:
        query = {"query": {"bool": {"must": [
            {"multi_match": {"query": "lateral movement RDP WMI PsExec smb", "fields": ["message"]}},
            {"range": {"timestamp": {"gte": "now-24h"}}}
        ]}}, "size": 50}
        explanation = "Lateral movement indicators (RDP, WMI, PsExec, SMB)."
    elif "exfiltrat" in q or "data theft" in q or "data leak" in q:
        query = {"query": {"bool": {"must": [
            {"multi_match": {"query": "exfiltration upload large transfer outbound", "fields": ["message"]}},
            {"range": {"timestamp": {"gte": "now-24h"}}}
        ]}}, "size": 50}
        explanation = "Data exfiltration indicators."
    elif "persist" in q:
        query = {"query": {"bool": {"must": [
            {"multi_match": {"query": "persistence scheduled task registry run key wmi subscription startup", "fields": ["message"]}},
            {"range": {"timestamp": {"gte": "now-7d"}}}
        ]}}, "size": 50}
        explanation = "Persistence mechanism indicators in the last 7 days."
    elif "privilege" in q or "escalat" in q:
        query = {"query": {"bool": {"must": [
            {"multi_match": {"query": "privilege escalation admin token manipulation dll hijack", "fields": ["message"]}},
            {"range": {"timestamp": {"gte": "now-24h"}}}
        ]}}, "size": 50}
        explanation = "Privilege escalation indicators."
    elif "dns" in q and ("tunnel" in q or "c2" in q or "query" in q):
        query = {"query": {"bool": {"must": [
            {"multi_match": {"query": "dns tunneling c2 domain generation dga", "fields": ["message"]}},
            {"range": {"timestamp": {"gte": "now-24h"}}}
        ]}}, "size": 50}
        explanation = "DNS tunneling / C2 indicators."
    elif "brute" in q or "spray" in q:
        query = {"query": {"bool": {"must": [
            {"multi_match": {"query": "brute force password spray authentication failure", "fields": ["message"]}},
            {"range": {"timestamp": {"gte": "now-1h"}}}
        ]}}, "size": 50}
        explanation = "Brute force / password spray indicators."
    elif "malware" in q or "virus" in q or "trojan" in q:
        query = {"query": {"bool": {"must": [
            {"multi_match": {"query": "malware virus trojan ransomware detection", "fields": ["message"]}},
            {"range": {"timestamp": {"gte": "now-24h"}}}
        ]}}, "size": 50}
        explanation = "Malware detection events."
    elif "incident" in q and ("open" in q or "active" in q or "recent" in q):
        query = {"query": {"bool": {"must": [
            {"match": {"message": "incident"}},
            {"range": {"timestamp": {"gte": "now-24h"}}}
        ]}}, "size": 50}
        explanation = "Recent incident-related logs."
    elif "host" in q:
        m = re.search(r"host\s+([a-zA-Z0-9_.\-]+)", question or "")
        if m:
            query = {"query": {"bool": {"must": [
                {"term": {"host": m.group(1)}},
                {"range": {"timestamp": {"gte": "now-24h"}}}
            ]}}, "size": 50}
            explanation = f"Logs from host {m.group(1)} in the last 24 hours."
    elif "today" in q:
        query = {"query": {"range": {"timestamp": {"gte": "now-24h"}}}, "size": 50, "sort": [{"timestamp": {"order": "desc"}}]}
        explanation = "All logs from the last 24 hours."
    elif "hour" in q:
        query = {"query": {"range": {"timestamp": {"gte": "now-1h"}}}, "size": 50, "sort": [{"timestamp": {"order": "desc"}}]}
        explanation = "All logs from the last hour."

    return {"dsl": query, "explanation": explanation, "engine": "local-fallback"}
