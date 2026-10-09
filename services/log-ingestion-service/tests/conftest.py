import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Set a fixed JWT secret so tests can generate matching tokens
os.environ["JWT_SECRET"] = "test-secret-for-chael-siem-unit-tests"

from unittest.mock import patch, MagicMock

mock_opensearch = patch("opensearchpy.OpenSearch").start()
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
from jose import jwt
from config import settings
from normalizers.factory import NormalizerFactory


@pytest.fixture
def auth_token():
    token = jwt.encode(
        {"id": "test-user", "role": "ADMIN", "tenant_id": "default"},
        settings.jwt_secret,
        algorithm=settings.JWT_ALGORITHM,
    )
    return token


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}

@pytest.fixture(autouse=True)
def reset_mocks():
    mock_opensearch.reset_mock()
    yield

@pytest.fixture
def factory():
    return NormalizerFactory

@pytest.fixture
def windows_log():
    return {"event_id": 4625, "computer_name": "WIN-DC01", "source": "Security", "message": "Logon failure"}

@pytest.fixture
def syslog_log():
    return {"message": "Failed password for root from 10.0.0.5 port 22 ssh2", "host": "web-01"}

@pytest.fixture
def docker_event():
    return {
        "host": "docker-host-01",
        "source": "docker",
        "log_type": "docker",
        "severity": "HIGH",
        "message": "Container nginx-proxy die (image: nginx:latest)",
        "metadata": {
            "docker_event_type": "docker:die",
            "container_name": "nginx-proxy",
            "container_id": "abc123def456",
            "container_image": "nginx:latest",
            "action": "die",
        },
    }

@pytest.fixture
def docker_stats_event():
    return {
        "host": "docker-host-01",
        "source": "docker",
        "log_type": "docker",
        "severity": "INFO",
        "message": "Container app stats — CPU: 45.2%, MEM: 62.1%",
        "metadata": {
            "docker_event_type": "docker:stats",
            "container_name": "app",
            "cpu_percent": 45.2,
            "mem_percent": 62.1,
        },
    }

@pytest.fixture
def aws_log():
    return {
        "detail": {
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/admin"},
            "sourceIPAddress": "198.51.100.1",
            "awsRegion": "us-east-1",
        }
    }

@pytest.fixture
def azure_log():
    return {
        "detail": {
            "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
            "status": {"value": "Succeeded"},
            "claims": {"name": "admin@contoso.com"},
            "resourceId": "/subscriptions/sub-123",
        }
    }

@pytest.fixture
def gcp_log():
    return {
        "protoPayload": {
            "methodName": "SetIamPolicy",
            "resourceName": "projects/my-project/buckets/my-bucket",
            "caller": "admin@my-project.iam.gserviceaccount.com",
        }
    }
