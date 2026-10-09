import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Prevents DNS/connection delays for Redis in tests
os.environ["REDIS_HOST"] = "localhost"

from unittest.mock import patch, MagicMock

mock_opensearch = patch("opensearchpy.OpenSearch").start()
mock_redis = patch("redis.Redis", side_effect=Exception("Redis unavailable: test isolation")).start()
mock_indices = MagicMock()
mock_indices.exists.return_value = False
mock_indices.create.return_value = {}
mock_opensearch.return_value.indices = mock_indices
mock_opensearch.return_value.index.return_value = {}
mock_opensearch.return_value.get.side_effect = Exception("Not found")
mock_opensearch.return_value.update.return_value = {}
mock_opensearch.return_value.search.return_value = {"hits": {"hits": []}}
mock_opensearch.return_value.delete.return_value = {}

import pytest
from detection.correlation import CorrelationEngine
from models.schema import NormalizedLog

@pytest.fixture(autouse=True)
def reset_mocks():
    mock_opensearch.reset_mock()
    yield

@pytest.fixture(scope="function")
def engine():
    return CorrelationEngine()

@pytest.fixture
def brute_force_log():
    return NormalizedLog(
        host="web-server-01",
        source="syslog",
        log_type="linux",
        severity="HIGH",
        message="Failed password for admin from 203.0.113.42 port 22 ssh2",
        metadata={"event_type": "ssh_failed_password", "user": "admin", "src_ip": "203.0.113.42"},
    )

@pytest.fixture
def critical_log():
    return NormalizedLog(
        host="db-server-01",
        source="syslog",
        log_type="linux",
        severity="CRITICAL",
        message="CRITICAL: Unauthorized access detected on /etc/shadow",
        metadata={"event_type": "unauthorized_access"},
    )

@pytest.fixture
def normal_log():
    return NormalizedLog(
        host="web-server-01",
        source="syslog",
        log_type="linux",
        severity="INFO",
        message="Accepted password for admin from 203.0.113.42 port 22 ssh2",
        metadata={"event_type": "ssh_accepted", "user": "admin"},
    )
