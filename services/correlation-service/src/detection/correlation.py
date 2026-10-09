import logging
import time
from typing import Optional, List
from datetime import datetime, timezone, timedelta
from models.schema import NormalizedLog, Incident
from storage.factory import get_storage_client

logger = logging.getLogger(__name__)


def _utc_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class CorrelationEngine:
    """
    Rule-based correlation engine that detects incident patterns from logs.
    Backed by Redis for distributed, restart-resistant state.
    Falls back to in-memory dicts if Redis is unreachable.
    """
    def __init__(self):
        self.storage = get_storage_client()
        self._redis = None
        self._use_redis = False
        self._fallback_recent_logs: List[NormalizedLog] = []
        self._fallback_host_failure_counts: dict = {}

        self._brute_force_threshold = 10
        self._brute_force_window = 300
        self._repeated_error_threshold = 20
        self._repeated_error_window = 600

        self._in_memory_rules = {}
        self._init_settings()
        self._init_redis()

    def _init_settings(self):
        try:
            from config import settings
            self._brute_force_threshold = getattr(settings, 'BRUTE_FORCE_THRESHOLD', 5)
            self._brute_force_window = getattr(settings, 'BRUTE_FORCE_WINDOW_SECONDS', 300)
            self._repeated_error_threshold = getattr(settings, 'REPEATED_ERROR_THRESHOLD', 10)
            self._repeated_error_window = getattr(settings, 'REPEATED_ERROR_WINDOW_SECONDS', 300)
        except ImportError:
            pass

    def _seed_default_rules(self):
        try:
            from mitre.attack import mitre_for_rule
        except ImportError:
            def mitre_for_rule(rule_id):
                return {"technique_id": "", "tactic": "", "technique": ""}
        default_rules = [
            {
                "id": "brute_force",
                "name": "Brute Force Authentication",
                "condition": {"field": "message", "operator": "contains", "value": "failed"},
                "threshold": self._brute_force_threshold,
                "window_seconds": self._brute_force_window,
                "risk_score": 75,
                "description": "Brute force attack detected",
                "enabled": True
            },
            {
                "id": "critical_severity",
                "name": "Critical Severity Event",
                "condition": {"field": "severity", "operator": "equals", "value": "CRITICAL"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 90,
                "description": "Critical security event",
                "enabled": True
            },
            {
                "id": "yara_critical_match",
                "name": "YARA: Critical Severity Match",
                "condition": {"field": "severity", "operator": "equals", "value": "CRITICAL", "log_type": "yara"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 95,
                "description": "YARA rule with CRITICAL severity matched on endpoint",
                "enabled": True
            },
            {
                "id": "yara_high_match",
                "name": "YARA: High Severity Match",
                "condition": {"field": "severity", "operator": "equals", "value": "HIGH", "log_type": "yara"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 80,
                "description": "YARA rule with HIGH severity matched on endpoint",
                "enabled": True
            },
            {
                "id": "yara_multi_match",
                "name": "YARA: Multiple Matches on Same Host",
                "condition": {"field": "log_type", "operator": "equals", "value": "yara"},
                "threshold": 5,
                "window_seconds": 3600,
                "risk_score": 90,
                "description": "Multiple (5+) YARA matches on same host within 1 hour",
                "enabled": True
            },
            {
                "id": "malware_detected",
                "name": "Malware/Attack Tool Detected",
                "condition": {"field": "message", "operator": "contains", "value": "mimikatz"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 95,
                "description": "Known malware or attack tool detected on endpoint",
                "enabled": True
            },
            {
                "id": "ransomware_activity",
                "name": "Ransomware File Indicators",
                "condition": {"field": "message", "operator": "contains", "value": ".crypt"},
                "threshold": 5,
                "window_seconds": 600,
                "risk_score": 95,
                "description": "Possible ransomware file encryption detected (5+ suspicious extensions in 10m)",
                "enabled": True
            },
            {
                "id": "privilege_escalation",
                "name": "Privilege Escalation (EventID 4672)",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4672"},
                "threshold": 20,
                "window_seconds": 300,
                "risk_score": 70,
                "description": "Multiple special privilege assignments - investigate if unusual",
                "enabled": True
            },
            {
                "id": "account_manipulation",
                "name": "Account Created/Deleted",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4720"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 70,
                "description": "New user account created - monitor for unauthorized accounts",
                "enabled": True
            },
            {
                "id": "network_scanner",
                "name": "Network Scanner Detected",
                "condition": {"field": "message", "operator": "contains", "value": "nmap"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 70,
                "description": "Network scanning tool detected on host - possible reconnaissance",
                "enabled": True
            },
            {
                "id": "persistence_service",
                "name": "New Service Installed (EventID 4697)",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4697"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 75,
                "description": "New service installed - possible persistence mechanism",
                "enabled": True
            },
            {
                "id": "registry_persistence",
                "name": "Registry Run Key Modified",
                "condition": {"field": "message", "operator": "contains", "value": "CurrentVersion\\Run"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 75,
                "description": "Registry Run key modification - possible persistence",
                "enabled": True
            },
            # ── External Threat Detection Rules ──────────────────────────
            {
                "id": "failed_logon_windows",
                "name": "Windows Failed Logon Attempt",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4625"},
                "threshold": 10,
                "window_seconds": 300,
                "risk_score": 65,
                "description": "Multiple failed Windows logon attempts - possible brute force from external source",
                "enabled": True
            },
            {
                "id": "ssh_brute_force",
                "name": "SSH Brute Force",
                "condition": {"field": "metadata.event_type", "operator": "equals", "value": "ssh_failed_password"},
                "threshold": 8,
                "window_seconds": 300,
                "risk_score": 75,
                "description": "SSH brute force attack detected - multiple failed password attempts",
                "enabled": True
            },
            {
                "id": "ssh_invalid_user",
                "name": "SSH Invalid User Attempt",
                "condition": {"field": "metadata.event_type", "operator": "equals", "value": "ssh_invalid_user"},
                "threshold": 5,
                "window_seconds": 300,
                "risk_score": 70,
                "description": "SSH login attempts with invalid usernames - possible enumeration",
                "enabled": True
            },
            {
                "id": "rdp_brute_force",
                "name": "RDP Brute Force",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4625", "log_type": "windows"},
                "threshold": 15,
                "window_seconds": 300,
                "risk_score": 80,
                "description": "RDP brute force detected - multiple failed Windows logons from same source",
                "enabled": True
            },
            {
                "id": "log_clear",
                "name": "Security Log Cleared",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "1102"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 95,
                "description": "Security audit log cleared - evidence of anti-forensics",
                "enabled": True
            },
            {
                "id": "powershell_suspicious",
                "name": "PowerShell Suspicious Execution",
                "condition": {"field": "source", "operator": "contains", "value": "PowerShell"},
                "threshold": 20,
                "window_seconds": 600,
                # Low-fidelity burst: admin/scripting noise is common, so score
                # below 40 => auto-surfaces as LIKELY FP in triage + UI.
                "risk_score": 35,
                "description": "High volume of PowerShell activity - possible malicious script execution",
                "enabled": True,
                "fp_prone": True
            },
            {
                "id": "account_lockout",
                "name": "Account Lockout",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4740"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 75,
                "description": "Account locked out - likely from failed authentication attempts",
                "enabled": True
            },
            # ── Kerberos Attack Detection (T1558) ──────────────────────────
            {
                "id": "kerberoasting",
                "name": "Kerberoasting Suspected (T1558.003)",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4769"},
                "threshold": 10,
                "window_seconds": 300,
                "risk_score": 90,
                "description": "Possible Kerberoasting: 10+ Kerberos service ticket requests (4769) from same host in 5m - RC4 tickets requested for offline cracking",
                "enabled": True
            },
            {
                "id": "asrep_roasting",
                "name": "AS-REP Roasting Suspected (T1558.002)",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4771"},
                "threshold": 5,
                "window_seconds": 300,
                "risk_score": 85,
                "description": "Possible AS-REP Roasting: 5+ Kerberos pre-auth failures (4771) in 5m - accounts without pre-auth being enumerated",
                "enabled": True
            },
            {
                "id": "kerberos_bruteforce",
                "name": "Kerberos Brute Force (T1110)",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4768"},
                "threshold": 15,
                "window_seconds": 300,
                "risk_score": 80,
                "description": "Possible Kerberos brute force: 15+ TGT requests (4768) from same host in 5m",
                "enabled": True
            },
            {
                "id": "golden_ticket_suspect",
                "name": "Golden Ticket Suspected (T1558.001)",
                "condition": {"field": "message", "operator": "contains", "value": "0x17"},
                "threshold": 5,
                "window_seconds": 600,
                "risk_score": 95,
                "description": "Possible forged Kerberos ticket: repeated RC4 (0x17) encryption type anomalies - investigate Golden/Silver ticket forgery",
                "enabled": True
            },
            {
                "id": "pass_the_hash_suspect",
                "name": "Pass-the-Hash Suspected (T1550.002)",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4624"},
                "threshold": 10,
                "window_seconds": 300,
                "risk_score": 85,
                "description": "Possible Pass-the-Hash / lateral movement: 10+ network logons (4624) from same host in 5m",
                "enabled": True
            },
            {
                "id": "lateral_movement_rdp",
                "name": "RDP Lateral Movement Suspected (T1021.001)",
                "condition": {"field": "message", "operator": "contains", "value": "4778"},
                "threshold": 3,
                "window_seconds": 600,
                "risk_score": 80,
                "description": "Possible RDP lateral movement: multiple session reconnects (4778) in 10m",
                "enabled": True
            },
            {
                "id": "dns_tunneling_suspect",
                "name": "DNS Tunneling Suspected (T1071.004)",
                "condition": {"field": "message", "operator": "contains", "value": "dns-query"},
                "threshold": 50,
                "window_seconds": 300,
                "risk_score": 80,
                "description": "Possible DNS tunneling/C2: 50+ DNS queries from same host in 5m - check for long labels / high entropy",
                "enabled": True
            },
            {
                "id": "persistence_schtask",
                "name": "Scheduled Task Persistence (T1053)",
                "condition": {"field": "metadata.event_id", "operator": "equals", "value": "4698"},
                "threshold": 1,
                "window_seconds": 0,
                "risk_score": 75,
                "description": "Scheduled task created/updated (4698) - possible persistence mechanism",
                "enabled": True
            },
        ]
        for rule in default_rules:
            # Auto-enrich with MITRE ATT&CK if not already set (enterprise parity)
            try:
                m = mitre_for_rule(rule.get("id", ""))
                if m.get("technique_id") and not rule.get("technique_id"):
                    rule["technique_id"] = m["technique_id"]
                    rule["tactic"] = m.get("tactic", "")
                    rule["technique"] = m.get("technique", "")
                    rule["mitre_attack"] = [m["technique_id"]]
                    rule["source"] = rule.get("source", "builtin")
            except Exception:
                pass
            self.add_dynamic_rule(rule)

    def _init_redis(self):
        try:
            import redis as redis_module
            from config import settings
            self._redis = redis_module.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                password=settings.REDIS_PASSWORD or None,
                socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
                socket_connect_timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT,
                decode_responses=True,
            )
            self._redis.ping()
            self._use_redis = True
            logger.info("Redis connection established for correlation state")

            if not self._redis.exists("correlation_rules"):
                self._seed_default_rules()
        except Exception as e:
            logger.warning("Redis unavailable, falling back to in-memory state: %s", e)
            self._redis = None
            self._use_redis = False
            self._seed_default_rules()

    def get_dynamic_rules(self) -> List[dict]:
        import json
        if self._use_redis:
            try:
                rules_data = self._redis.hgetall("correlation_rules")
                return [json.loads(r) for r in rules_data.values()]
            except:
                pass
        return list(self._in_memory_rules.values())

    def add_dynamic_rule(self, rule: dict) -> bool:
        import json
        if self._use_redis:
            try:
                self._redis.hset("correlation_rules", rule["id"], json.dumps(rule))
                return True
            except:
                return False
        else:
            self._in_memory_rules[rule["id"]] = rule
            return True
            
    def delete_dynamic_rule(self, rule_id: str) -> bool:
        if self._use_redis:
            try:
                return self._redis.hdel("correlation_rules", rule_id) > 0
            except:
                return False
        else:
            if rule_id in self._in_memory_rules:
                del self._in_memory_rules[rule_id]
                return True
            return False

    def process_log(self, log: NormalizedLog) -> Optional[Incident]:
        logger.debug("Processing log: host=%s severity=%s", log.host, log.severity)
        
        # Check dynamic rules first (skip disabled rules)
        for rule in self.get_dynamic_rules():
            if not rule.get("enabled", True):
                continue
            incident = self._check_dynamic_rule(rule, log)
            if incident:
                return incident
                
        # Fallback to hardcoded repeated error rule (complex logic)
        incident = self._check_repeated_errors(log)
        if incident:
            return incident
            
        return None

    def _resolve_field(self, log: NormalizedLog, field_path: str):
        parts = field_path.split(".", 1)
        obj = getattr(log, parts[0], None)
        if obj is None:
            return None
        if len(parts) > 1:
            if isinstance(obj, dict):
                val = obj.get(parts[1])
                if val is None:
                    for k, v in obj.items():
                        if k.lower() == parts[1].lower():
                            val = v
                            break
                return val
            return getattr(obj, parts[1], None)
        return obj

    def _rule_artifacts(self, rule: dict, log: NormalizedLog, count: int = 1) -> dict:
        """Build incident artifacts with MITRE ATT&CK enrichment."""
        return {
            "rule_id": rule.get("id"),
            "rule_name": rule.get("name", rule.get("id")),
            "host": log.host,
            "count": count,
            "mitre_attack": rule.get("mitre_attack", []),
            "technique_id": rule.get("technique_id", ""),
            "tactic": rule.get("tactic", ""),
            "technique": rule.get("technique", ""),
            "attack_type": rule.get("id", "unknown"),
            "severity": rule.get("severity", ""),
            "source": rule.get("source", "builtin"),
        }

    def _fp_adjusted_score(self, rule: dict, log: NormalizedLog, base: int) -> tuple[int, str]:
        """Downgrade known-noise patterns below 40 so SOC auto-sees LIKELY FP.
        Returns (score, fp_hint). Keeps high-fidelity scores untouched."""
        try:
            msg = (getattr(log, "message", "") or "").lower()
            meta = getattr(log, "metadata", {}) or {}
            src_ip = str(meta.get("src_ip", "") or "").lower()
            fp_keywords = ("nmap", "masscan", "zmap", "nessus", "openvas",
                           "qualys", "approved scanner", "vuln scan",
                           "maintenance", "penetration test", "red team")
            is_fp_keyword = any(k in msg for k in fp_keywords)
            is_private_src = src_ip.startswith(
                ("10.", "192.168.", "127.", "::1")) or src_ip.startswith("172.")
            if rule.get("fp_prone") or (is_fp_keyword and is_private_src) or is_fp_keyword:
                # Cap noisy / scanner-like hits to FP band (<40)
                return min(int(base), 35), "likely-noise/scanner — verify allowlist before escalating"
        except Exception:
            pass
        return int(base), ""

    def _check_dynamic_rule(self, rule: dict, log: NormalizedLog) -> Optional[Incident]:
        cond = rule.get("condition", {})
        field = cond.get("field")
        op = cond.get("operator")
        val = cond.get("value")
        
        log_type_filter = cond.get("log_type")
        if log_type_filter and log.log_type != log_type_filter:
            return None
        
        field_value = self._resolve_field(log, field)
        if field_value is None:
            return None
            
        raw = field_value.value if hasattr(field_value, 'value') else field_value
        field_str = str(raw).lower()
        val_str = str(val).lower()
        
        matched = False
        if op == "contains":
            matched = val_str in field_str
        elif op == "equals":
            matched = val_str == field_str
            
        if not matched:
            return None
            
        threshold = rule.get("threshold", 1)
        if threshold <= 1:
            _score, _fp_hint = self._fp_adjusted_score(rule, log, rule.get("risk_score", 50))
            _art = self._rule_artifacts(rule, log, 1)
            if _fp_hint:
                _art["fp_hint"] = _fp_hint
                _art["likely_fp"] = True
            return Incident(
                risk_score=_score,
                source_logs=[log],
                description=f"{rule.get('description', 'Rule matched')} ({log.host})",
                artifacts=_art
            )
            
        # Threshold logic
        host_key = f"rule_{rule['id']}:{log.host}"
        if self._use_redis:
            try:
                count = self._redis.incr(host_key)
                if count == 1:
                    self._redis.expire(host_key, rule.get("window_seconds", 300))
            except:
                count = 1
        else:
            count = self._fallback_host_failure_counts.get(host_key, 0) + 1
            self._fallback_host_failure_counts[host_key] = count
            
        if count >= threshold:
            logger.info("Dynamic rule %s triggered for host %s", rule['id'], log.host)
            if self._use_redis:
                try: self._redis.delete(host_key)
                except: pass
            else:
                self._fallback_host_failure_counts[host_key] = 0
                
            _score2, _fp_hint2 = self._fp_adjusted_score(rule, log, rule.get("risk_score", 50))
            _art2 = self._rule_artifacts(rule, log, count)
            if _fp_hint2:
                _art2["fp_hint"] = _fp_hint2
                _art2["likely_fp"] = True
            return Incident(
                risk_score=_score2,
                source_logs=[log],
                description=f"{rule.get('description', 'Rule threshold met')} from {log.host} ({count} occurrences)",
                artifacts=_art2
            )
        return None



    def _check_repeated_errors(self, log: NormalizedLog) -> Optional[Incident]:
        if log.log_type in ("windows", "yara", "docker"):
            return None
        if log.severity not in ("ERROR", "CRITICAL"):
            return None
        now = datetime.now(timezone.utc)
        window_seconds = self._repeated_error_window

        if self._use_redis:
            sorted_set_key = f"recent_logs:{log.host}:{log.log_type}"
            cutoff = now.timestamp() - window_seconds
            self._redis.zremrangebyscore(sorted_set_key, "-inf", cutoff)
            member = f"{time.time_ns()}"
            self._redis.zadd(sorted_set_key, {member: now.timestamp()})
            self._redis.expire(sorted_set_key, window_seconds + 60)
            count = self._redis.zcard(sorted_set_key)
            if count >= self._repeated_error_threshold:
                logger.info("Repeated errors: host=%s type=%s count=%d", log.host, log.log_type, count)
                return Incident(
                    risk_score=60,
                    source_logs=[log],
                    description=f"Repeated {log.log_type} errors from host {log.host} ({count} occurrences)",
                    artifacts={"error_type": log.log_type, "host": log.host, "count": count}
                )
        else:
            window = timedelta(seconds=window_seconds)
            self._fallback_recent_logs = [
                l for l in self._fallback_recent_logs
                if now - _utc_aware(l.timestamp) < window
            ]
            similar = [l for l in self._fallback_recent_logs if l.host == log.host and l.log_type == log.log_type]
            if len(similar) >= self._repeated_error_threshold:
                logger.info("Repeated errors: host=%s type=%s count=%d", log.host, log.log_type, len(similar) + 1)
                return Incident(
                    risk_score=60,
                    source_logs=similar + [log],
                    description=f"Repeated {log.log_type} errors from host {log.host} ({len(similar)+1} occurrences)",
                    artifacts={"error_type": log.log_type, "host": log.host, "count": len(similar)+1}
                )
            self._fallback_recent_logs.append(log)
        return None


engine = CorrelationEngine()
