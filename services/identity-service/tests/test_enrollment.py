import secrets
from storage.opensearch_client import EnrollmentKeyStorage, AgentStorage


class TestEnrollmentKeyStorage:
    def test_create_key(self):
        storage = EnrollmentKeyStorage()
        key = secrets.token_hex(16)
        assert storage.create_key(key, "admin") is True

    def test_get_key_returns_none_for_missing(self):
        storage = EnrollmentKeyStorage()
        assert storage.get_key("nonexistent") is None

    def test_mark_key_used(self):
        storage = EnrollmentKeyStorage()
        key = secrets.token_hex(16)
        storage.create_key(key, "admin")
        assert storage.mark_used(key, "agent-01") is True

    def test_revoke_key(self):
        storage = EnrollmentKeyStorage()
        key = secrets.token_hex(16)
        storage.create_key(key, "admin")
        assert storage.revoke_key(key) is True

    def test_list_keys(self):
        storage = EnrollmentKeyStorage()
        keys = storage.list_keys()
        assert isinstance(keys, list)


class TestAgentStorage:
    def test_register_agent(self):
        storage = AgentStorage()
        result = storage.register_agent("test-id", "hash123", "agent-01", {})
        assert result is True

    def test_get_agent_returns_none_for_missing(self):
        storage = AgentStorage()
        assert storage.get_agent("nonexistent") is None

    def test_revoke_agent(self):
        storage = AgentStorage()
        assert storage.revoke_agent("test-id") is True

    def test_rotate_key(self):
        storage = AgentStorage()
        assert storage.rotate_key("test-id", "newhash456") is True

    def test_list_agents(self):
        storage = AgentStorage()
        agents = storage.list_agents()
        assert isinstance(agents, list)
