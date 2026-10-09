import sys
import os

# Disable Redis state in unit tests BEFORE settings import: on hosts without
# Docker DNS the 'redis' hostname lookup blocks ~40s per engine init.
os.environ["SOAR_REDIS_ENABLED"] = "false"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import patch, MagicMock

# Mock OpenSearch before any module imports
mock_opensearch = patch("opensearchpy.OpenSearch").start()
mock_indices = MagicMock()
mock_indices.exists.return_value = False
mock_indices.create.return_value = None
mock_opensearch.return_value.indices = mock_indices

import pytest
from fastapi.testclient import TestClient
from api.main import app


@pytest.fixture(autouse=True)
def auto_mock():
    mock_opensearch.reset_mock()
    yield


@pytest.fixture
def client():
    return TestClient(app)
