import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Set fixed JWT secret so tests can decode tokens
os.environ["JWT_SECRET"] = "fixed-test-secret-for-identity-service-tests"

from unittest.mock import patch

# Mock OpenSearch before any module imports trigger connection attempts
mock_opensearch = patch("opensearchpy.OpenSearch").start()
mock_indices = type("Indices", (), {"exists": lambda self, **kw: False, "create": lambda self, **kw: None, "delete": lambda self, **kw: None})()
mock_opensearch.return_value.indices = mock_indices
mock_opensearch.return_value.index.return_value = {}
mock_opensearch.return_value.get.side_effect = Exception("Not found")
mock_opensearch.return_value.update.return_value = {}
mock_opensearch.return_value.search.return_value = {"hits": {"hits": []}}
mock_opensearch.return_value.delete.return_value = {}

import pytest
from fastapi.testclient import TestClient

# Now safe to import — OpenSearch is mocked
from api.main import app


@pytest.fixture(autouse=True)
def reset_mocks():
    mock_opensearch.reset_mock()
    yield


@pytest.fixture
def client():
    return TestClient(app)
