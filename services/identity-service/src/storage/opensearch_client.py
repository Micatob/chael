from opensearchpy import OpenSearch, ConnectionError
from config import settings
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

AGENTS_INDEX = "chaelsiem-agents"

SECURITY_EVENT_IDS = [
    4624, 4625, 4634, 4648, 4672, 4740, 4776, 4771, 4772,
    4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729,
    4732, 4733, 4743, 4756, 4781, 4735, 4737, 4738, 4741, 4742,
    4673, 4674, 4688, 4689,
    4719, 4739, 4704, 4705, 4706, 4715, 4716, 4717,
    4656, 4663, 4657, 4670,
    4608, 4609, 4616, 4697, 7045, 1102, 104,
    4103, 4104, 4105, 4106,
    4768, 4769, 4770, 4773,
    4649, 4778, 4779, 5152, 5154, 5156, 5157,
    4698, 4699, 4700, 4701, 4702,
]

class AgentStorage:
    def __init__(self):
        self.client = OpenSearch(
            hosts=[{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}],
            http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD) if settings.OPENSEARCH_USER else None,
            use_ssl=settings.OPENSEARCH_USE_SSL,
            verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
            timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )
        self._ensure_index()

    def _ensure_index(self):
        try:
            if not self.client.indices.exists(index=AGENTS_INDEX):
                self.client.indices.create(
                    index=AGENTS_INDEX,
                    body={
                        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                    "mappings": {
                        "properties": {
                            "agent_id": {"type": "keyword"},
                            "agent_key_hash": {"type": "keyword"},
                            "hostname": {"type": "keyword"},
                            "metadata": {"type": "object"},
                            "config": {"type": "object"},
                            "created_at": {"type": "date"},
                            "last_seen": {"type": "date"},
                            "current_version": {"type": "keyword"},
                            "last_heartbeat_metadata": {"type": "object"},
                            "revoked": {"type": "boolean"},
                            "revoked_at": {"type": "date"},
                        }
                    },
                    },
                )
                logger.info("Created index %s", AGENTS_INDEX)
        except Exception as e:
            logger.warning("Could not create index %s: %s", AGENTS_INDEX, e)

    def register_agent(self, agent_id: str, agent_key_hash: str, hostname: str, metadata: dict = None) -> bool:
        try:
            now = datetime.now(timezone.utc).isoformat()
            doc = {
                "agent_id": agent_id,
                "agent_key_hash": agent_key_hash,
                "hostname": hostname,
                "metadata": metadata or {},
                "created_at": now,
                "revoked": False,
            }
            self.client.index(index=AGENTS_INDEX, id=agent_id, body=doc, refresh="wait_for")
            return True
        except Exception as e:
            logger.error("Failed to register agent %s: %s", agent_id, e)
            return False

    def get_agent(self, agent_id: str) -> dict | None:
        try:
            resp = self.client.get(index=AGENTS_INDEX, id=agent_id)
            return resp["_source"]
        except Exception:
            return None

    def revoke_agent(self, agent_id: str) -> bool:
        try:
            self.client.update(
                index=AGENTS_INDEX,
                id=agent_id,
                body={"doc": {"revoked": True, "revoked_at": datetime.now(timezone.utc).isoformat()}},
                refresh="wait_for",
            )
            return True
        except Exception as e:
            logger.error("Failed to revoke agent %s: %s", agent_id, e)
            return False

    def rotate_key(self, agent_id: str, new_key_hash: str) -> bool:
        try:
            self.client.update(
                index=AGENTS_INDEX,
                id=agent_id,
                body={"doc": {"agent_key_hash": new_key_hash, "revoked": False, "revoked_at": None}},
                refresh="wait_for",
            )
            return True
        except Exception as e:
            logger.error("Failed to rotate key for agent %s: %s", agent_id, e)
            return False

    def delete_agent(self, agent_id: str) -> bool:
        try:
            self.client.delete(index=AGENTS_INDEX, id=agent_id, refresh="wait_for")
            return True
        except Exception as e:
            logger.error("Failed to delete agent %s: %s", agent_id, e)
            return False

    def get_agent_config(self, agent_id: str) -> dict:
        agent = self.get_agent(agent_id)
        if not agent:
            return {}
        return agent.get("config", self._default_config())

    def update_agent_config(self, agent_id: str, config: dict) -> bool:
        try:
            self.client.update(
                index=AGENTS_INDEX,
                id=agent_id,
                body={"doc": {"config": config}},
                refresh="wait_for",
            )
            return True
        except Exception as e:
            logger.error("Failed to update config for agent %s: %s", agent_id, e)
            return False

    def _default_config(self) -> dict:
        return {
            "windows_event_ids": list(SECURITY_EVENT_IDS),
            "windows_log": "Security",
            "powershell_log": True,
            "sysmon_log": True,
            "defender_log": True,
            "poll_interval": 2,
            "batch_size": 50,
        }

    def list_agents(self, include_revoked: bool = False) -> list[dict]:
        try:
            query = {"match_all": {}} if include_revoked else {"bool": {"must_not": {"term": {"revoked": True}}}}
            resp = self.client.search(
                index=AGENTS_INDEX,
                body={"query": query, "size": 1000, "sort": [{"created_at": {"order": "desc"}}]},
            )
            return [h["_source"] for h in resp["hits"]["hits"]]
        except Exception as e:
            logger.error("Failed to list agents: %s", e)
            return []


ENROLLMENT_INDEX = "chaelsiem-enrollment-keys"


class EnrollmentKeyStorage:
    def __init__(self):
        self.client = OpenSearch(
            hosts=[{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}],
            http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD) if settings.OPENSEARCH_USER else None,
            use_ssl=settings.OPENSEARCH_USE_SSL,
            verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
            timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )
        self._ensure_index()

    def _ensure_index(self):
        try:
            if not self.client.indices.exists(index=ENROLLMENT_INDEX):
                self.client.indices.create(
                    index=ENROLLMENT_INDEX,
                    body={
                        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                        "mappings": {
                            "properties": {
                                "key": {"type": "keyword"},
                                "created_at": {"type": "date"},
                                "created_by": {"type": "keyword"},
                                "used": {"type": "boolean"},
                                "used_at": {"type": "date"},
                                "used_by_hostname": {"type": "keyword"},
                                "revoked": {"type": "boolean"},
                            }
                        },
                    },
                )
                logger.info("Created index %s", ENROLLMENT_INDEX)
        except Exception as e:
            logger.warning("Could not create index %s: %s", ENROLLMENT_INDEX, e)

    def create_key(self, key: str, created_by: str) -> bool:
        try:
            now = datetime.now(timezone.utc).isoformat()
            doc = {
                "key": key,
                "created_at": now,
                "created_by": created_by,
                "used": False,
                "used_at": None,
                "used_by_hostname": None,
                "revoked": False,
            }
            self.client.index(index=ENROLLMENT_INDEX, id=key, body=doc, refresh="wait_for")
            return True
        except Exception as e:
            logger.error("Failed to create enrollment key: %s", e)
            return False

    def get_key(self, key: str) -> dict | None:
        try:
            resp = self.client.get(index=ENROLLMENT_INDEX, id=key)
            return resp["_source"]
        except Exception:
            return None

    def mark_used(self, key: str, hostname: str) -> bool:
        try:
            self.client.update(
                index=ENROLLMENT_INDEX,
                id=key,
                body={"doc": {"used": True, "used_at": datetime.now(timezone.utc).isoformat(), "used_by_hostname": hostname}},
                refresh="wait_for",
            )
            return True
        except Exception as e:
            logger.error("Failed to mark enrollment key used: %s", e)
            return False

    def revoke_key(self, key: str) -> bool:
        try:
            self.client.update(
                index=ENROLLMENT_INDEX,
                id=key,
                body={"doc": {"revoked": True}},
                refresh="wait_for",
            )
            return True
        except Exception as e:
            logger.error("Failed to revoke enrollment key: %s", e)
            return False

    def list_keys(self) -> list[dict]:
        try:
            resp = self.client.search(
                index=ENROLLMENT_INDEX,
                body={"query": {"match_all": {}}, "size": 1000, "sort": [{"created_at": {"order": "desc"}}]},
            )
            return [h["_source"] for h in resp["hits"]["hits"]]
        except Exception as e:
            logger.error("Failed to list enrollment keys: %s", e)
            return []
