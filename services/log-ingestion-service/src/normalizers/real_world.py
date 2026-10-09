import logging
import re
from .base import BaseNormalizer
from models.schema import NormalizedLog, Severity
from typing import Any, Dict, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class WindowsNormalizer(BaseNormalizer):
    def normalize(self, raw: Dict[str, Any]) -> Optional[NormalizedLog]:
        try:
            event_id = raw.get("event_id")
            
            # Use specific severity mapping for Windows events
            severity = Severity.INFO
            if event_id in [4625]: # Logon failure - potential brute force
                severity = Severity.MEDIUM
            elif event_id in [4740]: # Account lockout
                severity = Severity.HIGH
            elif event_id in [4624]: # Success logon - routine, mark INFO
                severity = Severity.INFO
            elif event_id in [1102, 4719]: # Log clear, Audit policy change
                severity = Severity.CRITICAL
            elif event_id in [4720, 4726]: # User created/deleted
                severity = Severity.MEDIUM
            elif event_id in [4722, 4723, 4724, 4725]: # Password/account routine ops
                severity = Severity.INFO
            elif event_id in [4672]: # Special privileges assigned - routine for admins
                severity = Severity.INFO
            elif event_id in [4688]: # Process creation
                severity = Severity.INFO
            elif event_id in [4697]: # Service installed
                severity = Severity.MEDIUM
            elif event_id in [4768, 4769]: # Kerberos TGT / service ticket - INFO alone, rules count bursts
                severity = Severity.INFO
            elif event_id in [4771]: # Kerberos pre-auth failure - AS-REP roast / password guess signal
                severity = Severity.HIGH
            elif event_id in [4772]: # Kerberos ticket request failure
                severity = Severity.MEDIUM
            elif event_id in [4778, 4779]: # RDP session reconnect/disconnect - lateral movement signal
                severity = Severity.MEDIUM
            elif event_id in [4698, 4702]: # Scheduled task created/updated - persistence
                severity = Severity.MEDIUM
            elif event_id in [5156]: # Network connection allowed
                severity = Severity.INFO

            meta_extra: Dict[str, Any] = {}
            if event_id in (4103, 4104):
                decoded = decode_ps_encoded(str(raw.get("message", "")))
                if decoded:
                    meta_extra["ps_decoded"] = decoded
                    if severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM):
                        severity = Severity.HIGH

            merged = dict(raw)
            merged.update(meta_extra)
            return NormalizedLog(
                timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
                host=raw.get("computer_name", "localhost"),
                source=f"Windows:{raw.get('source', 'Security')}",
                log_type="windows",
                severity=severity,
                message=f"Event {event_id}: {raw.get('message', '')}",
                metadata=merged
            )
        except Exception as e:
            logger.error("Error in WindowsNormalizer: %s", e)
            return None

_SSH_FAIL_RE = re.compile(
    r'Failed\s+password\s+for\s+(?:\w+\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)'
)
_SSH_INVALID_RE = re.compile(
    r'Failed\s+password\s+for\s+invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)'
)
_SSH_ACCEPT_RE = re.compile(
    r'Accepted\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)'
)
_SUDO_RE = re.compile(
    r'sudo:\s+(?P<user>\S+)\s+.*?COMMAND=(?P<command>.+)$'
)

def _parse_syslog_metadata(message: str) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    if m := _SSH_FAIL_RE.search(message):
        meta["event_type"] = "ssh_failed_password"
        meta["user"] = m.group("user")
        meta["src_ip"] = m.group("src_ip")
        meta["port"] = int(m.group("port"))
        meta["service"] = "ssh"
    elif m := _SSH_INVALID_RE.search(message):
        meta["event_type"] = "ssh_invalid_user"
        meta["user"] = m.group("user")
        meta["src_ip"] = m.group("src_ip")
        meta["port"] = int(m.group("port"))
        meta["service"] = "ssh"
    elif m := _SSH_ACCEPT_RE.search(message):
        meta["event_type"] = "ssh_accepted"
        meta["user"] = m.group("user")
        meta["src_ip"] = m.group("src_ip")
        meta["port"] = int(m.group("port"))
        meta["service"] = "ssh"
    elif m := _SUDO_RE.search(message):
        meta["event_type"] = "sudo_command"
        meta["user"] = m.group("user")
        meta["command"] = m.group("command")
    if "Failed password" in message or "authentication failure" in message.lower():
        meta["auth_result"] = "failure"
    elif "Accepted password" in message:
        meta["auth_result"] = "success"
    return meta


class DockerNormalizer(BaseNormalizer):
    DOCKER_EVENT_SEVERITY_MAP = {
        "docker:die": "HIGH",
        "docker:oom": "HIGH",
        "docker:kill": "HIGH",
        "docker:destroy": "HIGH",
        "docker:remove": "MEDIUM",
        "docker:health_status: unhealthy": "CRITICAL",
        "docker:stop": "MEDIUM",
        "docker:restart": "MEDIUM",
        "docker:start": "LOW",
        "docker:stats": "INFO",
    }

    def normalize(self, raw: Dict[str, Any]) -> Optional[NormalizedLog]:
        try:
            meta = raw.get("metadata", {})
            docker_event_type = meta.get("docker_event_type", "")
            base_severity = self.DOCKER_EVENT_SEVERITY_MAP.get(docker_event_type, "INFO")

            return NormalizedLog(
                timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
                host=raw.get("host", "localhost"),
                source=f"docker:{meta.get('container_name', 'unknown')}",
                log_type="docker",
                severity=raw.get("severity", base_severity),
                message=raw.get("message", ""),
                metadata=meta,
            )
        except Exception as e:
            logger.error("Error in DockerNormalizer: %s", e)
            return None


class SyslogNormalizer(BaseNormalizer):
    def normalize(self, raw: Any) -> Optional[NormalizedLog]:
        try:
            if isinstance(raw, str):
                msg = raw
                host = "unknown"
                ts = datetime.now(timezone.utc).isoformat()
            elif isinstance(raw, dict):
                msg = raw.get("message", "")
                host = raw.get("host", "unknown")
                ts = raw.get("timestamp", datetime.now(timezone.utc).isoformat())
            else:
                return None

            severity = Severity.INFO
            msg_lower = msg.lower()
            if "failed password" in msg_lower or "authentication failure" in msg_lower:
                severity = Severity.HIGH
            elif "accepted password" in msg_lower:
                severity = Severity.LOW
            elif "kernel panic" in msg_lower or "segfault" in msg_lower or "oom-killer" in msg_lower:
                severity = Severity.CRITICAL
            elif "critical" in msg_lower and "error" not in msg_lower:
                severity = Severity.HIGH
            elif "error" in msg_lower:
                severity = Severity.MEDIUM
            elif "warning" in msg_lower:
                severity = Severity.LOW

            meta = _parse_syslog_metadata(msg)
            raw_provided = raw if isinstance(raw, dict) else {}
            meta.update({k: v for k, v in raw_provided.items() if k not in ("message", "host", "timestamp", "source_type")})

            return NormalizedLog(
                timestamp=ts,
                host=host,
                source="syslog",
                log_type="linux",
                severity=severity,
                message=msg,
                metadata=meta,
            )
        except Exception as e:
            logger.error("Error in SyslogNormalizer: %s", e)
            return None


_PS_ENC_RE = re.compile(r"-(?:enc|EncodedCommand)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)


def decode_ps_encoded(message: str) -> Optional[str]:
    """Decode PowerShell -EncodedCommand payloads (4104 obfuscation).
    Tries UTF-16LE (Windows default) then UTF-8. Returns None if undecodable."""
    m = _PS_ENC_RE.search(message or "")
    if not m:
        return None
    import base64
    blob = m.group(1)
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = base64.b64decode(blob).decode(encoding)
            if any(c.isprintable() or c.isspace() for c in text[:50]):
                return text[:2000]
        except Exception:
            continue
    return None


class GenericJSONNormalizer(BaseNormalizer):
    """Catch-all for structured JSON logs (forwarders, cloud hooks, EDR)."""

    def normalize(self, raw: Any) -> Optional[NormalizedLog]:
        try:
            if isinstance(raw, str):
                try:
                    import json as _json
                    raw = _json.loads(raw)
                except Exception:
                    return None
            if not isinstance(raw, dict):
                return None
            msg = str(raw.get("message") or raw.get("msg") or raw.get("event")
                      or raw.get("description") or raw.get("summary") or "")
            if not msg:
                import json as _json
                msg = _json.dumps(raw, default=str)[:2000]
            sev_raw = str(raw.get("severity") or raw.get("level") or "INFO").upper()
            severity = sev_raw if sev_raw in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") else Severity.INFO
            meta = {k: v for k, v in raw.items()
                    if k not in ("message", "msg", "host", "timestamp", "severity", "level")}
            decoded = decode_ps_encoded(msg)
            if decoded:
                meta["ps_decoded"] = decoded
                severity = Severity.HIGH
            return NormalizedLog(
                timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
                host=str(raw.get("host") or raw.get("hostname") or raw.get("computer_name", "unknown")),
                source=str(raw.get("source") or "generic_json"),
                log_type=str(raw.get("log_type") or "json"),
                severity=severity,
                message=msg,
                metadata=meta,
            )
        except Exception as e:
            logger.error("Error in GenericJSONNormalizer: %s", e)
            return None


class CEFNormalizer(BaseNormalizer):
    """Common Event Format (firewalls, proxies, IDS): CEF:0|Vendor|Prod|Ver|Sig|Name|Sev|k=v ..."""

    def normalize(self, raw: Any) -> Optional[NormalizedLog]:
        try:
            msg = raw if isinstance(raw, str) else (raw.get("message", "") if isinstance(raw, dict) else "")
            host = "unknown" if isinstance(raw, str) else str(raw.get("host", "unknown"))
            if not isinstance(msg, str) or not msg.startswith("CEF:"):
                return None
            header, _, extension = msg.partition("|")
            # header: CEF:version — remainder has 6 more pipe fields (escapes \|)
            parts = re.split(r"(?<!\\)\|", msg, maxsplit=7)
            vendor = parts[1] if len(parts) > 1 else ""
            product = parts[2] if len(parts) > 2 else ""
            sig = parts[4] if len(parts) > 4 else ""
            name = parts[5] if len(parts) > 5 else ""
            sev_raw = (parts[6] if len(parts) > 6 else "").strip().lower()
            severity = Severity.HIGH if sev_raw in ("high", "8", "9", "10") else \
                Severity.CRITICAL if sev_raw in ("critical",) else \
                Severity.MEDIUM if sev_raw in ("medium", "5", "6", "7") else \
                Severity.LOW if sev_raw in ("low", "1", "2", "3", "4") else Severity.INFO
            meta: Dict[str, Any] = {"cef_vendor": vendor, "cef_product": product,
                                    "cef_signature": sig, "cef_name": name}
            ext = parts[7] if len(parts) > 7 else extension
            for m in re.finditer(r"(\w+)=((?:[^= ]|\\=)+)", ext):
                meta[m.group(1)] = m.group(2).replace("\\=", "=").replace("\\\\", "\\")
            for ip_key in ("src", "dst", "sourceAddress", "destinationAddress"):
                if meta.get(ip_key) and "src_ip" not in meta:
                    meta["src_ip"] = meta[ip_key]
                    break
            return NormalizedLog(
                timestamp=datetime.now(timezone.utc).isoformat(),
                host=host,
                source=f"cef:{product or vendor or 'unknown'}",
                log_type="cef",
                severity=severity,
                message=f"{name or sig} [{vendor} {product}]".strip(),
                metadata=meta,
            )
        except Exception as e:
            logger.error("Error in CEFNormalizer: %s", e)
            return None
