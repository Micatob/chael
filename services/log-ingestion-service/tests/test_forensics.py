import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import base64
import pytest
from models.schema import NormalizedLog
from detection.correlation import CorrelationEngine, RuleEngine
from normalizers.factory import NormalizerFactory
from api.routers.logs import canonical_log_hash


def _log(message, host="web-01", source="syslog", metadata=None):
    return NormalizedLog(host=host, source=source, log_type="linux",
                         severity="HIGH", message=message, metadata=metadata or {})


@pytest.fixture
def engines():
    corr = CorrelationEngine()
    return corr, RuleEngine(corr)


class TestForensicsRetention:
    def test_single_auth_failure_stored_not_dropped(self, engines):
        corr, _ = engines
        log = _log("Failed password for root from 203.0.113.9 port 22 ssh2",
                   metadata={"event_type": "ssh_failed_password", "src_ip": "203.0.113.9"})
        assert corr._should_index(log) is True
        assert log.metadata.get("forensics_only") is True

    def test_whitelisted_internal_stored_but_never_alerts(self, engines):
        corr, rules = engines
        log = _log("Failed password for root from 192.168.1.50 port 22 ssh2",
                   metadata={"event_type": "ssh_failed_password", "src_ip": "192.168.1.50"})
        assert corr._should_index(log) is True
        assert log.metadata.get("fp_internal") is True
        assert rules.process_log(log) is None

    def test_external_brute_force_still_alerts(self, engines):
        corr, rules = engines
        incident = None
        for _ in range(6):
            log = _log("Failed password for root from 203.0.113.99 port 22 ssh2",
                       metadata={"event_type": "ssh_failed_password", "src_ip": "203.0.113.99"})
            assert corr._should_index(log) is True
            incident = rules.process_log(log) or incident
        assert incident is not None


class TestLogIntegrity:
    def test_hash_stable(self):
        log = _log("test message").model_dump()
        assert canonical_log_hash(log) == canonical_log_hash(dict(log))

    def test_hash_detects_tamper(self):
        log = _log("original").model_dump()
        sealed = canonical_log_hash(log)
        log["message"] = "ALTERED"
        assert canonical_log_hash(log) != sealed

    def test_hash_ignores_seal_field(self):
        log = _log("m").model_dump()
        h1 = canonical_log_hash(log)
        log["metadata"] = {**(log.get("metadata") or {}), "log_hash": h1}
        assert canonical_log_hash(log) == h1


class TestNewNormalizers:
    def test_generic_json(self):
        n = NormalizerFactory.get("json")
        out = n.normalize({"host": "app-01", "message": "disk full on /var", "severity": "HIGH"})
        assert out is not None and out.host == "app-01" and out.message == "disk full on /var"

    def test_generic_json_unknown_source(self):
        assert NormalizerFactory.get("json") is not None
        assert NormalizerFactory.get("cef") is not None

    def test_cef_parses(self):
        n = NormalizerFactory.get("cef")
        out = n.normalize("CEF:0|PaloAlto|PAN-OS|10.0|THREAT|Malware blocked|High|src=203.0.113.7 dst=10.0.0.9")
        assert out is not None
        assert out.metadata.get("src_ip") == "203.0.113.7"
        assert out.severity in ("HIGH", "CRITICAL", "MEDIUM")

    def test_cef_rejects_non_cef(self):
        assert NormalizerFactory.get("cef").normalize("just a syslog line") is None

    def test_windows_4104_encoded_command_decoded(self):
        import base64 as _b64
        payload = _b64.b64encode("Invoke-Mimikatz".encode("utf-16-le")).decode()
        n = NormalizerFactory.get("windows")
        out = n.normalize({"event_id": 4104, "computer_name": "WIN-01",
                           "source": "PowerShell",
                           "message": f"Script block with -EncodedCommand {payload}"})
        assert out is not None
        assert "Invoke-Mimikatz" in (out.metadata.get("ps_decoded") or "")
        assert str(out.severity) in ("HIGH", "Severity.HIGH")
