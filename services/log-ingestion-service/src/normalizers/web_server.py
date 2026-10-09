import logging
import re
from .base import BaseNormalizer
from models.schema import NormalizedLog, Severity
from typing import Any, Dict, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_APACHE_COMBINED_RE = re.compile(
    r'(?P<host>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

_APACHE_ERROR_RE = re.compile(
    r'\[(?P<timestamp>[^\]]+)\] \[(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] '
    r'\[client (?P<client>[^\]]+)\] (?P<message>.+)'
)

_NGINX_ERROR_RE = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
    r'\[(?P<level>[^\]]+)\] (?P<pid>\d+)#\d+: (?P<message>.+)'
)


class ApacheAccessNormalizer(BaseNormalizer):
    def normalize(self, raw: Any) -> Optional[NormalizedLog]:
        try:
            if isinstance(raw, str):
                line = raw
            elif isinstance(raw, dict):
                line = raw.get("message", "")
            else:
                return None

            m = _APACHE_COMBINED_RE.match(line)
            if not m:
                return None

            status = int(m.group("status"))
            severity = Severity.INFO
            if status >= 500:
                severity = Severity.CRITICAL
            elif status >= 400:
                severity = Severity.MEDIUM
            elif status >= 300:
                severity = Severity.LOW

            path = m.group("path")
            if any(admin_path in path for admin_path in ["/admin", "/wp-admin", "/manager", "/console"]):
                if status in (401, 403):
                    severity = Severity.HIGH
                elif status == 200:
                    severity = Severity.MEDIUM

            return NormalizedLog(
                timestamp=datetime.now(timezone.utc).isoformat(),
                host=m.group("host"),
                source="apache:access",
                log_type="web",
                severity=severity,
                message=line,
                metadata={
                    "src_ip": m.group("host"),
                    "http_method": m.group("method"),
                    "path": path,
                    "http_status": status,
                    "size": m.group("size"),
                    "user_agent": m.group("agent"),
                    "referer": m.group("referer"),
                },
            )
        except Exception as e:
            logger.error("ApacheAccessNormalizer error: %s", e)
            return None


class NginxAccessNormalizer(BaseNormalizer):
    def normalize(self, raw: Any) -> Optional[NormalizedLog]:
        try:
            if isinstance(raw, str):
                line = raw
            elif isinstance(raw, dict):
                line = raw.get("message", "")
            else:
                return None

            m = _APACHE_COMBINED_RE.match(line)
            if not m:
                return None

            status = int(m.group("status"))
            severity = Severity.INFO
            if status >= 500:
                severity = Severity.CRITICAL
            elif status >= 400:
                severity = Severity.MEDIUM

            return NormalizedLog(
                timestamp=datetime.now(timezone.utc).isoformat(),
                host=m.group("host"),
                source="nginx:access",
                log_type="web",
                severity=severity,
                message=line,
                metadata={
                    "src_ip": m.group("host"),
                    "http_method": m.group("method"),
                    "path": m.group("path"),
                    "http_status": status,
                    "size": m.group("size"),
                    "user_agent": m.group("agent"),
                },
            )
        except Exception as e:
            logger.error("NginxAccessNormalizer error: %s", e)
            return None


class WebErrorNormalizer(BaseNormalizer):
    def normalize(self, raw: Any) -> Optional[NormalizedLog]:
        try:
            if isinstance(raw, str):
                line = raw
            elif isinstance(raw, dict):
                line = raw.get("message", "")
            else:
                return None

            severity = Severity.MEDIUM
            msg_lower = line.lower()

            if any(w in msg_lower for w in ["emerg", "alert", "critical"]):
                severity = Severity.CRITICAL
            elif any(w in msg_lower for w in ["error", "cannot", "failed"]):
                severity = Severity.HIGH
            elif any(w in msg_lower for w in ["warn", "notice"]):
                severity = Severity.LOW

            if "Permission denied" in line or "forbidden" in msg_lower:
                severity = Severity.HIGH
            if "proxy" in msg_lower and ("fail" in msg_lower or "timeout" in msg_lower):
                severity = Severity.MEDIUM

            return NormalizedLog(
                timestamp=datetime.now(timezone.utc).isoformat(),
                host="unknown",
                source="webserver:error",
                log_type="web",
                severity=severity,
                message=line,
                metadata={"raw_message": line},
            )
        except Exception as e:
            logger.error("WebErrorNormalizer error: %s", e)
            return None
