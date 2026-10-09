import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import patch

# Block all external network calls that the investigation engine makes
mock_urlopen = patch("urllib.request.urlopen").start()
mock_urlopen.side_effect = Exception("Network blocked in tests")

import pytest
from incidents.investigation import InvestigationEngine


@pytest.fixture(autouse=True)
def auto_patch():
    mock_urlopen.reset_mock()
    yield


@pytest.fixture
def engine():
    return InvestigationEngine()


@pytest.fixture
def brute_force_incident():
    return {
        "incident_id": "inc-brute-001",
        "timestamp": "2026-06-01T10:00:00Z",
        "risk_score": 85,
        "source_logs": [
            {
                "timestamp": "2026-06-01T09:55:00Z",
                "host": "web-01",
                "source": "authlog",
                "message": "Failed password for user admin from 203.0.113.42 port 22",
            },
            {
                "timestamp": "2026-06-01T09:56:00Z",
                "host": "web-01",
                "source": "authlog",
                "message": "Failed password for user admin from 203.0.113.42 port 22",
            },
            {
                "timestamp": "2026-06-01T09:57:00Z",
                "host": "web-01",
                "source": "authlog",
                "message": "Failed password for user root from 203.0.113.42 port 22",
            },
            {
                "timestamp": "2026-06-01T09:58:00Z",
                "host": "web-01",
                "source": "authlog",
                "message": "Failed password for user admin from 198.51.100.7 port 443",
            },
            {
                "timestamp": "2026-06-01T09:59:00Z",
                "host": "mail-01",
                "source": "authlog",
                "message": "Failed password for user postmaster from 203.0.113.42 port 22",
            },
        ],
        "status": "OPEN",
        "description": "Multiple failed authentication attempts detected across hosts",
        "artifacts": {
            "attack_type": "brute_force",
            "target_host": "web-01",
            "failure_count": 5,
        },
    }


@pytest.fixture
def critical_incident():
    return {
        "incident_id": "inc-crit-001",
        "timestamp": "2026-06-01T11:00:00Z",
        "risk_score": 95,
        "source_logs": [
            {
                "timestamp": "2026-06-01T10:55:00Z",
                "host": "web-02",
                "source": "syslog",
                "message": "CVE-2025-1234 exploitation attempt detected from 198.51.100.99 on /wp-admin",
            },
        ],
        "status": "OPEN",
        "description": "Critical exploit attempt against public-facing application",
        "artifacts": {
            "event_type": "critical",
            "target_host": "web-02",
        },
    }


@pytest.fixture
def low_confidence_incident():
    return {
        "incident_id": "inc-low-001",
        "timestamp": "2026-06-01T12:00:00Z",
        "risk_score": 30,
        "source_logs": [
            {
                "timestamp": "2026-06-01T12:00:00Z",
                "host": "app-01",
                "source": "applog",
                "message": "Connection timeout from 10.0.0.1",
            },
        ],
        "status": "OPEN",
        "description": "Single connection timeout detected",
        "artifacts": {},
    }
