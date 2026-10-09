import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import patch, MagicMock

mock_opensearch = patch("opensearchpy.OpenSearch").start()
mock_indices = MagicMock()
mock_indices.exists.return_value = False
mock_indices.create.return_value = {}
mock_opensearch.return_value.indices = mock_indices
mock_opensearch.return_value.index.return_value = {}
mock_opensearch.return_value.search.return_value = {
    "hits": {"hits": []}
}

import pytest
from ueba import UEBAEngine

@pytest.fixture(autouse=True)
def reset_mocks():
    mock_opensearch.reset_mock()
    yield

@pytest.fixture
def engine():
    return UEBAEngine()
