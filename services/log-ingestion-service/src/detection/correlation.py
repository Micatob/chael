import logging
import time
import re
import json
import math
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from models.schema import NormalizedLog, Incident, Severity
from storage.factory import get_storage_client

logger = logging.getLogger(__name__)


def _utc_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return R * 2 * math.asin(math.sqrt(a))


# ── Stage B: Correlation-based Filtering Configuration ─────────────────────
# These thresholds determine what gets stored vs dropped
CORRELATION_CFG = {
    "ssh_brute_force": {
        "single_failure": "drop",
        "medium_threshold": 5,
        "medium_window": 60,
        "high_threshold": 15,
        "high_window": 300,
    },
    "firewall_block": {
        "single_block": "drop",
        "threshold": 10,
        "window": 60,
    },
    "impossible_travel": {
        "min_distance_km": 1000,
        "max_time_minutes": 60,
    },
}

# ── Stage C: Alert Fatigue Prevention ──────────────────────────────────────
ALERT_FATIGUE_CFG = {
    "cooldown_seconds": 300,
    "max_alerts_per_source_per_hour": 50,
    "whitelisted_ips": ["127.0.0.1", "::1", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."],
}

# ── Forensics retention ──────────────────────────────────────────────────
# Production rule: NEVER drop telemetry. Sub-threshold auth failures and
# internal-range logs are stored (tagged forensics_only / fp_internal) so
# the evidence window survives even when no incident fires. Alerting on
# whitelisted ranges stays suppressed in RuleEngine.process_log.
STORE_SUBTHRESHOLD_LOGS = True
STORE_WHITELISTED_LOGS = True


class AlertFatigueManager:
    def __init__(self):
        self._alert_timestamps: Dict[str, List[float]] = {}
        self._rule_cooldowns: Dict[str, float] = {}

    def is_suppressed(self, rule_name: str, source_key: str, now: float = None) -> bool:
        # Pure check: must NOT record anything. Recording happens in
        # mark_alert() only when an alert actually fires — otherwise every
        # evaluated log consumes the hourly budget and mutes the source.
        if now is None:
            now = time.time()
        cooldown_key = f"{rule_name}:{source_key}"
        last_alert = self._rule_cooldowns.get(cooldown_key, 0)
        if now - last_alert < ALERT_FATIGUE_CFG["cooldown_seconds"]:
            return True
        source_hour_key = f"{source_key}:{int(now // 3600)}"
        recent = [
            t for t in self._alert_timestamps.get(source_hour_key, [])
            if now - t < 3600
        ]
        if len(recent) >= ALERT_FATIGUE_CFG["max_alerts_per_source_per_hour"]:
            return True
        return False

    def mark_alert(self, rule_name: str, source_key: str, now: float = None):
        if now is None:
            now = time.time()
        cooldown_key = f"{rule_name}:{source_key}"
        self._rule_cooldowns[cooldown_key] = now
        source_hour_key = f"{source_key}:{int(now // 3600)}"
        recent = [
            t for t in self._alert_timestamps.get(source_hour_key, [])
            if now - t < 3600
        ]
        recent.append(now)
        self._alert_timestamps[source_hour_key] = recent
        cutoff = now - 3600
        for key in list(self._alert_timestamps.keys()):
            if self._alert_timestamps[key] and (now - self._alert_timestamps[key][-1]) > 3600:
                del self._alert_timestamps[key]

    def is_whitelisted_ip(self, ip: str) -> bool:
        if not ip:
            return False
        for prefix in ALERT_FATIGUE_CFG["whitelisted_ips"]:
            if ip.startswith(prefix):
                return True
        return False


class CorrelationEngine:
    def __init__(self):
        self.storage = get_storage_client()
        self._redis = None
        self._use_redis = False
        self._fallback_state: Dict[str, Any] = {}
        self._fatigue = AlertFatigueManager()

        self._init_redis()

    def _init_redis(self):
        try:
            import redis as redis_module
            from config import settings
            self._redis = redis_module.Redis(
                host=settings.REDIS_HOST, port=settings.REDIS_PORT,
                db=settings.REDIS_DB, password=settings.REDIS_PASSWORD or None,
                socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
                socket_connect_timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT,
                decode_responses=True,
            )
            self._redis.ping()
            self._use_redis = True
            logger.info("Redis connected for correlation engine")
        except Exception as e:
            logger.warning("Redis unavailable, using in-memory: %s", e)

    def _incr_key(self, key: str, ttl: int = None) -> int:
        if self._use_redis:
            count = self._redis.incr(key)
            if count == 1 and ttl:
                self._redis.expire(key, ttl)
            return count
        now = time.time()
        if key not in self._fallback_state:
            self._fallback_state[key] = []
        self._fallback_state[key] = [t for t in self._fallback_state[key] if now - t < (ttl or 300)]
        self._fallback_state[key].append(now)
        return len(self._fallback_state[key])

    def _reset_key(self, key: str):
        if self._use_redis:
            self._redis.delete(key)
        else:
            self._fallback_state.pop(key, None)

    def _get_state(self, key: str, default=None):
        if self._use_redis:
            val = self._redis.get(key)
            return val if val is not None else default
        return self._fallback_state.get(key, default)

    def _set_state(self, key: str, value, ttl: int = None):
        if self._use_redis:
            self._redis.setex(key, ttl or 3600, value if isinstance(value, str) else json.dumps(value))
        else:
            self._fallback_state[key] = value

    def _source_key(self, log: NormalizedLog) -> str:
        ip = log.metadata.get("src_ip", "")
        host = log.host
        return ip or host

    def _should_index(self, log: NormalizedLog) -> bool:
        """Forensics-first gate: tag noisy telemetry, but STORE it.
        Returns False only for nothing by default — every log is evidence.
        Whitelisted (internal) sources are tagged fp_internal and never
        raise alerts (see RuleEngine.process_log), yet stay searchable."""
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        msg_lower = log.message.lower()
        source_ip = str(log.metadata.get("src_ip", ""))

        if self._fatigue.is_whitelisted_ip(source_ip):
            log.metadata["fp_internal"] = True
            if STORE_WHITELISTED_LOGS:
                return True
            logger.debug("Dropping log from whitelisted IP %s", source_ip)
            return False

        is_auth_failure = (
            event_id in (4625, 4740)
            or log.metadata.get("event_type") in ("ssh_failed_password", "ssh_invalid_user")
            or log.metadata.get("auth_result") == "failure"
        )

        if is_auth_failure:
            ip_key = f"auth_fail_ip:{source_ip}"
            count = self._incr_key(ip_key, CORRELATION_CFG["ssh_brute_force"]["medium_window"])
            if count < CORRELATION_CFG["ssh_brute_force"]["medium_threshold"]:
                log.metadata["forensics_only"] = True
                if not STORE_SUBTHRESHOLD_LOGS:
                    logger.debug("Stage B: dropping single auth failure from %s (count=%d)", source_ip, count)
                    return False
                return True

        is_firewall_block = any(p in msg_lower for p in ["block", "deny", "reject", "dropped"]) and "firewall" in log.source.lower()
        if is_firewall_block:
            fw_key = f"fw_block:{source_ip}"
            count = self._incr_key(fw_key, CORRELATION_CFG["firewall_block"]["window"])
            if count < CORRELATION_CFG["firewall_block"]["threshold"]:
                log.metadata["forensics_only"] = True
                if not STORE_SUBTHRESHOLD_LOGS:
                    logger.debug("Stage B: dropping single firewall block from %s (count=%d)", source_ip, count)
                    return False
                return True

        return True

    def __del__(self):
        if self._redis:
            try:
                self._redis.close()
            except Exception:
                pass


class RuleEngine:
    def __init__(self, correlation: CorrelationEngine):
        self.corr = correlation

    def process_log(self, log: NormalizedLog) -> Optional[Incident]:
        # Internal ranges stay searchable but never raise alerts
        # (config.yaml: false_positive_elimination.whitelisted_ips).
        src_ip = str(log.metadata.get("src_ip", ""))
        if src_ip and self.corr._fatigue.is_whitelisted_ip(src_ip):
            return None
        # Skip if fatigue manager suppresses
        source_key = self.corr._source_key(log)
        for rule_name, check_fn in self._rules():
            if self.corr._fatigue.is_suppressed(rule_name, source_key):
                continue
            incident = check_fn(log)
            if incident:
                self.corr._fatigue.mark_alert(rule_name, source_key)
                return incident
        return None

    def _rules(self):
        return [
            ("ssh_brute_force", self.check_ssh_brute_force),
            ("ssh_password_spray", self.check_ssh_password_spray),
            ("privilege_escalation", self.check_privilege_escalation),
            ("account_lockout_storm", self.check_account_lockout_storm),
            ("reverse_shell", self.check_reverse_shell),
            ("malware_indicator", self.check_malware_indicator),
            ("port_scan", self.check_port_scan),
            ("data_exfiltration", self.check_data_exfiltration),
            ("impossible_travel", self.check_impossible_travel),
            ("new_service", self.check_new_service),
            ("log_tampering", self.check_log_tampering),
            ("multi_fail_then_success", self.check_multi_fail_then_success),
            ("kerberoasting", self.check_kerberoasting),
            ("asrep_roasting", self.check_asrep_roasting),
            ("lateral_movement", self.check_lateral_movement),
            ("dns_tunneling", self.check_dns_tunneling),
        ]

    def _make_incident(self, log: NormalizedLog, rule_name: str, risk_score: int,
                       description: str, artifacts: dict = None) -> Incident:
        return Incident(
            risk_score=risk_score,
            source_logs=[log],
            description=description,
            artifacts={
                "rule": rule_name,
                "host": log.host,
                "source_ip": log.metadata.get("src_ip", ""),
                "user": log.metadata.get("user", ""),
                **(artifacts or {}),
            },
        )

    # ── RULE 1: SSH Brute Force ─────────────────────────────────────────────
    def check_ssh_brute_force(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        is_auth_failure = (
            event_id in (4625, 4740)
            or log.metadata.get("event_type") in ("ssh_failed_password", "ssh_invalid_user")
            or log.metadata.get("auth_result") == "failure"
        )
        if not is_auth_failure:
            return None

        source_ip = str(log.metadata.get("src_ip", log.metadata.get("source_ip", "")))
        if not source_ip:
            source_ip = log.host

        ip_key = f"ssh_bf:{source_ip}"
        count = self.corr._incr_key(ip_key, 300)

        if count >= 15:
            self.corr._reset_key(ip_key)
            return self._make_incident(
                log, "ssh_brute_force", 85,
                f"SSH Brute Force (HIGH): {count} failures from {source_ip} in 300s",
                {"failure_count": count, "src_ip": source_ip, "severity": "high"},
            )
        if count >= 5:
            return self._make_incident(
                log, "ssh_brute_force", 65,
                f"SSH Brute Force (MEDIUM): {count} failures from {source_ip} in 60s",
                {"failure_count": count, "src_ip": source_ip, "severity": "medium"},
            )
        return None

    # ── RULE 2: SSH Password Spray ──────────────────────────────────────────
    def check_ssh_password_spray(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        if log.metadata.get("event_type") not in ("ssh_failed_password", "ssh_invalid_user") and event_id != 4625:
            return None

        source_ip = str(log.metadata.get("src_ip", ""))
        user = log.metadata.get("user", "")
        if not source_ip or not user:
            return None

        spray_key = f"spray:{source_ip}:users"
        existing = self.corr._get_state(spray_key, "[]")
        users = set(json.loads(existing))
        users.add(user)
        self.corr._set_state(spray_key, json.dumps(list(users)), 300)

        count_key = f"spray:{source_ip}:count"
        total = self.corr._incr_key(count_key, 300)

        if total >= 20 and len(users) >= 3:
            self.corr._reset_key(count_key)
            self.corr._set_state(spray_key, "[]", 1)
            return self._make_incident(
                log, "ssh_password_spray", 80,
                f"SSH Password Spray: {total} attempts across {len(users)} users from {source_ip}",
                {"total_attempts": total, "unique_users": list(users), "src_ip": source_ip},
            )
        return None

    # ── RULE 3: Privilege Escalation ────────────────────────────────────────
    def check_privilege_escalation(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        msg_lower = log.message.lower()

        if event_id == 4672:
            dangerous = ["sedebugprivilege", "setakeownershipprivilege", "seloaddriverprivilege"]
            found = [p for p in dangerous if p in msg_lower]
            if found:
                return self._make_incident(
                    log, "privilege_escalation", 85,
                    f"Privilege Escalation: {', '.join(found)} assigned to {log.host}",
                    {"privileges": found, "event_id": 4672},
                )

        if "sudo" in msg_lower and "root" in msg_lower and "COMMAND" in msg_lower:
            user = log.metadata.get("user", "")
            cmd = log.metadata.get("command", "")
            priv_key = f"priv_esc:{log.host}:{user}"
            count = self.corr._incr_key(priv_key, 3600)
            if count >= 3:
                return self._make_incident(
                    log, "privilege_escalation", 75,
                    f"Frequent sudo to root by {user} on {log.host} ({count}x in 1h)",
                    {"user": user, "sudo_count": count, "last_command": cmd},
                )
        return None

    # ── RULE 4: Account Lockout Storm ───────────────────────────────────────
    def check_account_lockout_storm(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        if event_id != 4740:
            return None

        user = log.metadata.get("user", log.metadata.get("TargetUserName", ""))
        lockout_key = f"lockout:{user or log.host}"
        count = self.corr._incr_key(lockout_key, 120)

        if count >= 3:
            self.corr._reset_key(lockout_key)
            return self._make_incident(
                log, "account_lockout_storm", 70,
                f"Account Lockout Storm: {count} lockouts for {user or log.host} in 120s",
                {"lockout_count": count, "target_user": user},
            )
        return None

    # ── RULE 5: Reverse Shell Detection ─────────────────────────────────────
    def check_reverse_shell(self, log: NormalizedLog) -> Optional[Incident]:
        msg_lower = log.message.lower()
        indicators = [
            r"nc\s+-e\s+/", r"ncat\s+-e\s+/",
            r"bash\s+-i\s*[>&].*/tcp/", r"sh\s+-i\s*[>&].*/tcp/",
            r"python\s+-c\s+['\"].*socket.*bind", r"perl\s+-e\s+.*socket",
            r"powershell.*-e\s+[a-zA-Z0-9+/=]{100,}",
            r"powershell.*reverse", r"powershell.*bind",
        ]
        for pattern in indicators:
            if re.search(pattern, msg_lower):
                return self._make_incident(
                    log, "reverse_shell", 95,
                    f"Reverse Shell Detected on {log.host}: {log.message[:200]}",
                    {"indicator_pattern": pattern, "severity": "critical"},
                )
        return None

    # ── RULE 6: Malware Indicator ───────────────────────────────────────────
    def check_malware_indicator(self, log: NormalizedLog) -> Optional[Incident]:
        msg_lower = log.message.lower()
        high_confidence = [
            "mimikatz", "invoke-mimikatz", "cobaltstrike", "meterpreter",
            "empire", "covenant", "brute ratel", "sliver", "havoc",
        ]
        for tool in high_confidence:
            if tool in msg_lower:
                return self._make_incident(
                    log, "malware_indicator", 95,
                    f"Known Malware/Attack Tool on {log.host}: {tool}",
                    {"matched_tool": tool, "severity": "critical"},
                )

        suspicious_ps = [
            r"invoke-expression\s*\(", r"iex\s*\(",
            r"downloadstring\(.*http", r"downloadfile\(.*http",
            r"invoke-bloodhound", r"invoke-kerberoast",
        ]
        for pattern in suspicious_ps:
            if re.search(pattern, msg_lower):
                return self._make_incident(
                    log, "malware_indicator", 85,
                    f"Suspicious PowerShell on {log.host}: {log.message[:200]}",
                    {"matched_pattern": pattern},
                )
        return None

    # ── RULE 7: Port Scan Detection ─────────────────────────────────────────
    def check_port_scan(self, log: NormalizedLog) -> Optional[Incident]:
        msg_lower = log.message.lower()
        scan_tools = ["nmap", "masscan", "zmap", "nessus", "openvas"]
        for tool in scan_tools:
            if tool in msg_lower:
                # Low-fidelity: scanner string alone is often an approved vuln
                # sweep. Keep in FP band (<40) so SOC auto-filters as LIKELY FP.
                return self._make_incident(
                    log, "port_scan", 35,
                    f"Port Scan Tool Detected on {log.host}: {tool}",
                    {"matched_tool": tool, "severity": "low", "likely_fp": True,
                     "fp_hint": "scanner string only — confirm against approved-scanner allowlist"},
                )

        source_ip = str(log.metadata.get("src_ip", ""))
        if not source_ip:
            return None

        conn_count = log.metadata.get("rapid_connections", 0)
        if isinstance(conn_count, (int, float)) and conn_count > 20:
            return self._make_incident(
                log, "port_scan", 35,
                f"Rapid connections ({conn_count}) from {source_ip} - possible port scan",
                {"connection_count": conn_count, "src_ip": source_ip, "likely_fp": True,
                 "fp_hint": "connection-count heuristic only — correlate before escalating"},
            )

        ports = log.metadata.get("destination_ports", [])
        if isinstance(ports, list) and len(ports) >= 20:
            return self._make_incident(
                log, "port_scan", 35,
                f"Connection to {len(ports)} unique ports from {source_ip} - possible port scan",
                {"unique_ports": len(ports), "src_ip": source_ip, "likely_fp": True,
                 "fp_hint": "port-count heuristic only — correlate before escalating"},
            )
        return None

    # ── RULE 8: Data Exfiltration ──────────────────────────────────────────
    def check_data_exfiltration(self, log: NormalizedLog) -> Optional[Incident]:
        msg_lower = log.message.lower()
        outbound_ip = str(log.metadata.get("destination_ip", ""))
        bytes_sent = log.metadata.get("bytes_out", 0)

        if self.corr._fatigue.is_whitelisted_ip(outbound_ip):
            return None

        try:
            bytes_sent = int(bytes_sent) if bytes_sent else 0
        except (ValueError, TypeError):
            bytes_sent = 0

        if bytes_sent > 50_000_000:
            exfil_key = f"exfil:{outbound_ip or log.host}"
            total = self.corr._incr_key(exfil_key, 3600)
            if total >= 3:
                return self._make_incident(
                    log, "data_exfiltration", 90,
                    f"Large outbound transfer: {bytes_sent / 1_000_000:.1f}MB from {log.host} to {outbound_ip}",
                    {"bytes_sent": bytes_sent, "destination_ip": outbound_ip, "severity": "critical"},
                )

        known_bad = log.metadata.get("threat_intel_match", "")
        if known_bad and bytes_sent > 1_000_000:
            return self._make_incident(
                log, "data_exfiltration", 95,
                f"Data exfiltration to known bad IP {outbound_ip}: {bytes_sent / 1_000_000:.1f}MB",
                {"bytes_sent": bytes_sent, "destination_ip": outbound_ip, "threat_match": known_bad},
            )
        return None

    # ── RULE 9: Impossible Travel ──────────────────────────────────────────
    def check_impossible_travel(self, log: NormalizedLog) -> Optional[Incident]:
        source_ip = str(log.metadata.get("src_ip", ""))
        user = log.metadata.get("user", "")
        if not source_ip or not user:
            return None

        lat = log.metadata.get("geo_latitude")
        lon = log.metadata.get("geo_longitude")
        if lat is None or lon is None:
            return None

        travel_key = f"travel:{user}"
        last_loc = self.corr._get_state(travel_key)
        now = time.time()

        if last_loc:
            try:
                last = json.loads(last_loc) if isinstance(last_loc, str) else last_loc
                last_lat = last.get("lat", 0)
                last_lon = last.get("lon", 0)
                last_time = last.get("time", 0)
                distance = _haversine_km(last_lat, last_lon, float(lat), float(lon))
                time_diff = (now - last_time) / 60
                if distance > 1000 and time_diff < 60:
                    return self._make_incident(
                        log, "impossible_travel", 85,
                        f"Impossible travel for {user}: {distance:.0f}km in {time_diff:.0f}min",
                        {"user": user, "distance_km": round(distance), "time_minutes": round(time_diff)},
                    )
            except Exception:
                pass

        self.corr._set_state(travel_key, json.dumps({"lat": float(lat), "lon": float(lon), "time": now}), 3600)
        return None

    # ── RULE 10: New Service Installation ───────────────────────────────────
    def check_new_service(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        if event_id not in (4697, 7045):
            return None

        svc_key = f"new_svc:{log.host}"
        count = self.corr._incr_key(svc_key, 3600)

        if count >= 2:
            return self._make_incident(
                log, "new_service", 75,
                f"Multiple new services installed on {log.host} ({count} in 1h) - possible persistence",
                {"service_count": count, "severity": "medium"},
            )
        return None

    # ── RULE 11: Log Tampering ──────────────────────────────────────────────
    def check_log_tampering(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")

        if event_id == 1102:
            return self._make_incident(
                log, "log_tampering", 95,
                f"Security Log Cleared on {log.host} - possible anti-forensics (EventID 1102)",
                {"event_id": 1102, "severity": "critical"},
            )

        if event_id == 4719:
            return self._make_incident(
                log, "log_tampering", 85,
                f"Audit Policy Changed on {log.host} (EventID 4719)",
                {"event_id": 4719},
            )

        if event_id == 104:
            return self._make_incident(
                log, "log_tampering", 90,
                f"Event Log service stopped on {log.host} (EventID 104)",
                {"event_id": 104},
            )
        return None

    # ── RULE 13: Kerberoasting (T1558.003) ─────────────────────────────────
    def check_kerberoasting(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        msg_lower = log.message.lower()
        # Tooling shortcut: explicit kerberoast tooling in command lines
        if "kerberoast" in msg_lower or "rubeus" in msg_lower:
            return self._make_incident(
                log, "kerberoasting", 95,
                f"Kerberoasting tooling detected on {log.host}: {log.message[:200]}",
                {"event_id": event_id, "severity": "critical", "technique": "T1558.003"},
            )
        if event_id != 4769:
            return None
        # RC4 etype 0x17 is the crackable ticket type attackers request
        rc4 = "0x17" in log.message or "0x17" in str(log.metadata)
        key = f"kerberoast:{log.host}"
        count = self.corr._incr_key(key, 300)
        threshold = 5 if rc4 else 10
        if count >= threshold:
            self.corr._reset_key(key)
            return self._make_incident(
                log, "kerberoasting", 90,
                f"Kerberoasting suspected on {log.host}: {count} service-ticket requests (4769) in 5m"
                + (" with RC4 etype 0x17" if rc4 else ""),
                {"ticket_count": count, "rc4_etype": rc4, "technique": "T1558.003"},
            )
        return None

    # ── RULE 14: AS-REP Roasting (T1558.002) ───────────────────────────────
    def check_asrep_roasting(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        if event_id != 4771:
            return None
        key = f"asreproast:{log.host}"
        count = self.corr._incr_key(key, 300)
        if count >= 5:
            self.corr._reset_key(key)
            return self._make_incident(
                log, "asrep_roasting", 85,
                f"AS-REP Roasting suspected on {log.host}: {count} Kerberos pre-auth failures (4771) in 5m",
                {"failure_count": count, "technique": "T1558.002"},
            )
        return None

    # ── RULE 15: Lateral Movement (T1021 / T1550.002) ──────────────────────
    def check_lateral_movement(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        msg_lower = log.message.lower()
        if event_id in (4778, 4779):
            key = f"latmove:{log.host}"
            count = self.corr._incr_key(key, 600)
            if count >= 3:
                self.corr._reset_key(key)
                return self._make_incident(
                    log, "lateral_movement", 80,
                    f"RDP lateral movement suspected on {log.host}: {count} session events (4778/4779) in 10m",
                    {"session_count": count, "technique": "T1021.001"},
                )
            return None
        # NTLM network-logon burst (4624 type 3) hints Pass-the-Hash
        if event_id == 4624 and ("type 3" in msg_lower or "ntlm" in msg_lower):
            key = f"pth:{log.host}"
            count = self.corr._incr_key(key, 300)
            if count >= 10:
                self.corr._reset_key(key)
                return self._make_incident(
                    log, "lateral_movement", 85,
                    f"Pass-the-Hash suspected on {log.host}: {count} NTLM network logons in 5m",
                    {"logon_count": count, "technique": "T1550.002"},
                )
        return None

    # ── RULE 16: DNS Tunneling / C2 over DNS (T1071.004) ───────────────────
    def check_dns_tunneling(self, log: NormalizedLog) -> Optional[Incident]:
        msg_lower = log.message.lower()
        qname = str(log.metadata.get("query", log.metadata.get("qname", "")))
        blob = f"{msg_lower} {qname.lower()}"
        if "dns" not in blob and "query" not in blob and not qname:
            return None
        # Heuristics: very long label or many subdomains = tunnel-like
        longest_label = max((len(p) for p in qname.split(".") if p), default=0)
        labels = len([p for p in qname.split(".") if p])
        tunnel_like = longest_label >= 40 or labels >= 6 or len(qname) >= 100
        key = f"dnstun:{log.host}"
        count = self.corr._incr_key(key, 300)
        if (tunnel_like and count >= 10) or count >= 50:
            self.corr._reset_key(key)
            return self._make_incident(
                log, "dns_tunneling", 80,
                f"DNS tunneling suspected on {log.host}: {count} DNS queries in 5m"
                + (f" (label={longest_label}, depth={labels})" if qname else ""),
                {"query_count": count, "query": qname[:120], "technique": "T1071.004"},
            )
        return None

    # ── RULE 12: Multiple Failed Auth + Success ─────────────────────────────
    def check_multi_fail_then_success(self, log: NormalizedLog) -> Optional[Incident]:
        event_id = log.metadata.get("event_id") or log.metadata.get("EventID")
        source_ip = str(log.metadata.get("src_ip", ""))

        if event_id == 4625 or log.metadata.get("event_type") in ("ssh_failed_password", "ssh_invalid_user"):
            fail_key = f"fail2ok:{source_ip or log.host}:fails"
            count = self.corr._incr_key(fail_key, 1800)
            return None

        if event_id == 4624 or log.metadata.get("event_type") == "ssh_accepted":
            fail_key = f"fail2ok:{source_ip or log.host}:fails"
            fail_count = self.corr._get_state(fail_key)
            if fail_count:
                try:
                    fail_count = int(fail_count) if fail_count else 0
                except (ValueError, TypeError):
                    fail_count = 0
                if fail_count >= 10:
                    self.corr._reset_key(fail_key)
                    return self._make_incident(
                        log, "multi_fail_then_success", 90,
                        f"Successful login after {fail_count}+ failures from {source_ip or log.host}",
                        {"failure_count": fail_count, "src_ip": source_ip, "severity": "critical"},
                    )
        return None


engine = CorrelationEngine()
rule_engine = RuleEngine(engine)
