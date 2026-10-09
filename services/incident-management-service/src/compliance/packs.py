"""Compliance framework packs: PCI-DSS 4.0, HIPAA, SOC2, NIST 800-53, MITRE coverage."""
from typing import Dict, List, Any

FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "PCI-DSS": {
        "version": "4.0",
        "controls": {
            "Req 8": {"title": "Identify and authenticate access", "keywords": ["brute force", "login", "auth", "password", "credential", "4625", "4740"]},
            "Req 10": {"title": "Log and monitor access", "keywords": ["log cleared", "1102", "audit policy", "4719"]},
            "Req 11": {"title": "Test security regularly", "keywords": ["scan", "nmap", "vulnerability", "malware", "yara"]},
            "Req 5": {"title": "Protect against malware", "keywords": ["malware", "mimikatz", "ransomware", "cobalt"]},
        },
    },
    "HIPAA": {
        "version": "HIPAA Security Rule",
        "controls": {
            "164.312(a)(1)": {"title": "Access Control", "keywords": ["login", "auth", "privilege", "4672", "4720", "access"]},
            "164.312(b)": {"title": "Audit Controls", "keywords": ["log cleared", "1102", "audit", "critical"]},
            "164.308(a)(6)": {"title": "Security Incident Procedures", "keywords": ["malware", "ransomware", "exfiltrat", "critical"]},
        },
    },
    "SOC2": {
        "version": "TSC 2017",
        "controls": {
            "CC6.1": {"title": "Logical access security", "keywords": ["brute force", "login", "auth", "privilege", "rdp", "ssh"]},
            "CC7.2": {"title": "Monitoring for anomalies", "keywords": ["anomaly", "ueba", "critical", "repeated", "scan"]},
            "CC7.3": {"title": "Incident response", "keywords": ["malware", "ransomware", "exfiltrat", "persistence"]},
        },
    },
    "NIST-800-53": {
        "version": "Rev 5",
        "controls": {
            "AC-2": {"title": "Account Management", "keywords": ["account created", "4720", "4728", "4732", "4740"]},
            "AC-6": {"title": "Least Privilege", "keywords": ["privilege", "4672", "4648", "escalat"]},
            "AU-2": {"title": "Audit Events", "keywords": ["1102", "4719", "log cleared", "audit"]},
            "AU-6": {"title": "Audit Review / Analysis", "keywords": ["critical", "repeated", "anomaly"]},
            "SI-3": {"title": "Malicious Code Protection", "keywords": ["malware", "yara", "mimikatz", "ransomware"]},
            "SI-4": {"title": "System Monitoring", "keywords": ["scan", "nmap", "powershell", "brute force"]},
            "IR-4": {"title": "Incident Handling", "keywords": ["exfiltrat", "persistence", "critical", "malware"]},
        },
    },
}


def map_incident_to_frameworks(incident: Dict[str, Any]) -> Dict[str, List[str]]:
    """Return {framework: [control_ids]} for one incident via keyword matching on description+artifacts."""
    desc = (incident.get("description") or "").lower()
    artifacts = incident.get("artifacts") or {}
    blob = desc + " " + str(artifacts).lower()
    out: Dict[str, List[str]] = {}
    for fw, meta in FRAMEWORKS.items():
        hits = []
        for ctrl_id, ctrl in meta["controls"].items():
            if any(kw.lower() in blob for kw in ctrl["keywords"]):
                hits.append(ctrl_id)
        # critical incidents always flag monitoring controls
        if (incident.get("risk_score") or 0) >= 90 and fw in ("SOC2", "NIST-800-53") and not hits:
            hits.append("CC7.2" if fw == "SOC2" else "IR-4")
        if hits:
            out[fw] = hits
    return out


def build_compliance_report(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    frameworks: Dict[str, Any] = {}
    for fw, meta in FRAMEWORKS.items():
        frameworks[fw] = {"version": meta["version"], "controls": {}, "total_violations": 0}
        for ctrl_id, ctrl in meta["controls"].items():
            frameworks[fw]["controls"][ctrl_id] = {"title": ctrl["title"], "violations": []}
    for inc in incidents:
        mapping = map_incident_to_frameworks(inc)
        entry = {
            "incident_id": inc.get("incident_id"),
            "timestamp": inc.get("timestamp"),
            "severity": "HIGH" if (inc.get("risk_score") or 0) >= 70 else "MEDIUM" if (inc.get("risk_score") or 0) >= 40 else "LOW",
            "description": inc.get("description"),
            "status": inc.get("status"),
        }
        for fw, ctrls in mapping.items():
            for c in ctrls:
                frameworks[fw]["controls"][c]["violations"].append(entry)
    for fw in frameworks:
        frameworks[fw]["total_violations"] = sum(len(c["violations"]) for c in frameworks[fw]["controls"].values())
    return {
        "frameworks": frameworks,
        "summary": {
            "total_incidents": len(incidents),
            "total_violations": sum(f["total_violations"] for f in frameworks.values()),
            "by_framework": {fw: f["total_violations"] for fw, f in frameworks.items()},
        },
    }
