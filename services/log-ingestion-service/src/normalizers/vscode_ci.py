import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from .base import BaseNormalizer
from models.schema import NormalizedLog, Severity

logger = logging.getLogger(__name__)


class VSCodeNormalizer(BaseNormalizer):
    """Dev-workstation telemetry from Chael Sentinel for Code (user-space only).

    Expects JSON: {message, level, workspace, file, rule} — never raises,
    unknown shapes fall back to generic text (import-only, low noise).
    """

    def normalize(self, raw: Any) -> Optional[NormalizedLog]:
        try:
            if not isinstance(raw, dict):
                return None
            msg = str(raw.get("message") or raw.get("event") or "")[:2000]
            if not msg:
                return None
            level = str(raw.get("level") or raw.get("severity") or "INFO").upper()
            severity = level if level in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") else Severity.INFO
            # Secret-leak / exec-creation auto-escalates (small, high-signal).
            low = msg.lower()
            if "secret" in low or ".env" in low or "api_key" in low or "private key" in low:
                severity = Severity.HIGH
            meta = {
                "workspace": str(raw.get("workspace", ""))[:256],
                "file": str(raw.get("file", ""))[:512],
                "rule": str(raw.get("rule", ""))[:128],
                "ext_version": str(raw.get("ext_version", ""))[:32],
            }
            return NormalizedLog(
                timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
                host=str(raw.get("host", "localhost")),
                source="vscode",
                log_type="dev",
                severity=severity,
                message=msg,
                metadata={k: v for k, v in meta.items() if v},
            )
        except Exception as e:
            logger.error("Error in VSCodeNormalizer: %s", e)
            return None


class CINormalizer(BaseNormalizer):
    """CI log shipper (GitHub Action / GitLab component) — repo/commit scoped."""

    def normalize(self, raw: Any) -> Optional[NormalizedLog]:
        try:
            if not isinstance(raw, dict):
                return None
            msg = str(raw.get("message") or raw.get("event") or "")[:2000]
            if not msg:
                return None
            level = str(raw.get("level") or raw.get("severity") or "INFO").upper()
            severity = level if level in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") else Severity.INFO
            if "failed" in msg.lower() or "vulnerab" in msg.lower():
                severity = Severity.MEDIUM
            meta = {
                "repo": str(raw.get("repo", ""))[:256],
                "commit": str(raw.get("commit", ""))[:64],
                "workflow": str(raw.get("workflow", ""))[:128],
                "job": str(raw.get("job", ""))[:128],
            }
            return NormalizedLog(
                timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
                host=str(raw.get("host", "ci-runner")),
                source="ci",
                log_type="ci",
                severity=severity,
                message=msg,
                metadata={k: v for k, v in meta.items() if v},
            )
        except Exception as e:
            logger.error("Error in CINormalizer: %s", e)
            return None
