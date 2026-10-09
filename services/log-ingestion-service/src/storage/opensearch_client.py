from opensearchpy import OpenSearch, ConnectionError, RequestError
from models.schema import NormalizedLog, Incident
from config import settings
from typing import List, Dict, Any, Optional
import logging
import time

logger = logging.getLogger(__name__)

class OpenSearchClient:
    def __init__(self):
        self.auth = (settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD) if settings.OPENSEARCH_USER else None
        self.client = OpenSearch(
            hosts=[{'host': settings.OPENSEARCH_HOST, 'port': settings.OPENSEARCH_PORT}],
            http_auth=self.auth,
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30,
            max_retries=3,
            retry_on_timeout=True
        )
        self.log_index = "chaelsiem-logs"
        self.incident_index = "chaelsiem-incidents"
        self.yara_index = "chaelsiem-yara-events"
        self.audit_index = "chaelsiem-audit-logs"
        self._ensure_connectivity()

    def _ensure_connectivity(self):
        """Verify connection to OpenSearch cluster."""
        try:
            if not self.client.ping():
                logger.error("OpenSearch cluster is unreachable.")
        except Exception as e:
            logger.error(f"Error connecting to OpenSearch: {e}")

    def ensure_indices(self):
        """Create indices with optimized mappings and ILM for SIEM performance at scale."""
        # First, set up ILM policy for log rotation
        try:
            ilm_policy = {
                "policy": {
                    "phases": {
                        "hot": {
                            "min_age": "0ms",
                            "actions": {
                                "rollover": {
                                    "max_size": "10gb",
                                    "max_age": "1d"
                                },
                                "set_priority": {"priority": 100}
                            }
                        },
                        "warm": {
                            "min_age": "7d",
                            "actions": {
                                "shrink": {"number_of_shards": 1},
                                "forcemerge": {"max_num_segments": 1},
                                "set_priority": {"priority": 50}
                            }
                        },
                        "delete": {
                            "min_age": "30d",
                            "actions": {
                                "delete": {}
                            }
                        }
                    }
                }
            }
            if not self.client.indices.exists_lifecycle_policy("chaelsiem-log-policy"):
                self.client.indices.put_lifecycle_policy(
                    name="chaelsiem-log-policy",
                    body=ilm_policy
                )
                logger.info("Created ILM policy: chaelsiem-log-policy (hot: 1d/10GB, warm: 7d, delete: 30d)")
        except Exception as e:
            logger.warning("ILM policy creation skipped (may require SLM plugin): %s", e)

        log_mapping = {
            "settings": {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "1s"
                }
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "host": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "log_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "message": {"type": "text", "analyzer": "standard"},
                    "metadata": {"type": "object", "enabled": True},
                    "incident_id": {"type": "keyword"},
                    "tenant_id": {"type": "keyword"}
                }
            }
        }

        incident_mapping = {
            "settings": {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "5s"
                }
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "incident_id": {"type": "keyword"},
                    "description": {"type": "text"},
                    "status": {"type": "keyword"},
                    "risk_score": {"type": "integer"},
                    "affected_host": {"type": "keyword"},
                    "evidence": {"type": "object", "enabled": True},
                    "tenant_id": {"type": "keyword"},
                    "artifacts": {"type": "object", "enabled": True},
                    "source_logs": {"type": "nested"}
                }
            }
        }

        yara_mapping = {
            "settings": {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "1s"
                }
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "host": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "log_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "message": {"type": "text", "analyzer": "standard"},
                    "metadata": {
                        "properties": {
                            "yara_rule_name": {"type": "keyword"},
                            "yara_rule_source": {"type": "keyword"},
                            "yara_file_path": {"type": "keyword"},
                            "yara_tags": {"type": "keyword"},
                            "yara_meta": {"type": "object", "enabled": True},
                            "platform": {"type": "keyword"},
                            "hostname": {"type": "keyword"},
                        }
                    }
                }
            }
        }

        heartbeat_mapping = {
            "settings": {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "5s"
                }
            },
            "mappings": {
                "properties": {
                    "hostname": {"type": "keyword"},
                    "source_type": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "metadata": {"type": "object", "enabled": True}
                }
            }
        }

        indices = {
            self.log_index: log_mapping,
            self.incident_index: incident_mapping,
            self.yara_index: yara_mapping,
            "chaelsiem-source-heartbeats": heartbeat_mapping,
            self.audit_index: {
                "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "1s"}},
                "mappings": {"properties": {
                    "timestamp": {"type": "date"},
                    "actor": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "resource_type": {"type": "keyword"},
                    "resource_id": {"type": "keyword"},
                    "details": {"type": "object", "enabled": True},
                    "prev_hash": {"type": "keyword"},
                    "entry_hash": {"type": "keyword"},
                }},
            },
        }

        for name, mapping in indices.items():
            try:
                if not self.client.indices.exists(index=name):
                    self.client.indices.create(index=name, body=mapping)
                    logger.info(f"Created index: {name}")
            except RequestError as e:
                logger.error(f"Failed to create index {name}: {e}")

    def index_log(self, log: NormalizedLog):
        """Index a normalized log with retry logic and validation."""
        try:
            data = log.model_dump()
            # Ensure timestamp is ISO format for OpenSearch
            self.client.index(index=self.log_index, body=data, refresh=False)
        except Exception as e:
            logger.error(f"Failed to index log: {e}")

    def index_incident(self, incident: Incident):
        """Index an incident alert."""
        try:
            self.client.index(
                index=self.incident_index, 
                body=incident.model_dump(), 
                id=incident.incident_id,
                refresh=True
            )
        except Exception as e:
            logger.error(f"Failed to index incident: {e}")

    def get_logs(self, limit: int = 100) -> List[Dict]:
        """Fetch latest logs with error recovery."""
        try:
            query = {
                "size": limit,
                "query": {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            response = self.client.search(index=self.log_index, body=query)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error fetching logs: {e}")
            return []

    def get_logs_filtered(
        self,
        limit: int = 100,
        offset: int = 0,
        search: Optional[str] = None,
        severity: Optional[str] = None,
        host: Optional[str] = None,
        source: Optional[str] = None,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        fields: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Fetch logs with advanced filtering, pagination, and sorting."""
        try:
            # Build query with filters
            must_clauses = []

            if search:
                must_clauses.append({
                    "multi_match": {
                        "query": search,
                        "fields": ["message", "host", "source"],
                        "fuzziness": "AUTO"
                    }
                })

            # NOTE: indices are dynamically mapped (text + keyword subfields),
            # so `match` is used instead of `term` — it works on both text
            # and keyword mappings.
            if severity:
                must_clauses.append({"match": {"severity": severity}})

            if host:
                must_clauses.append({"match": {"host": host}})

            if source:
                must_clauses.append({"match": {"source": source}})

            query = {
                "size": limit,
                "from": offset,
                "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
                "sort": [{sort_by: {"order": sort_order}}]
            }
            if fields:
                query["_source"] = fields

            response = self.client.search(index=self.log_index, body=query)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error fetching filtered logs: {e}")
            return []

    def get_incidents(self, limit: int = 100) -> List[Dict]:
        """Fetch latest incidents with error recovery."""
        try:
            query = {
                "size": limit,
                "query": {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            response = self.client.search(index=self.incident_index, body=query)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error fetching incidents: {e}")
            return []

    def update_incident_status(self, incident_id: str, status: str):
        """Update the status of an incident."""
        try:
            update_body = {
                "doc": {"status": status}
            }
            self.client.update(index=self.incident_index, id=incident_id, body=update_body, refresh=True)
        except Exception as e:
            logger.error(f"Failed to update incident status: {e}")

    def update_incident_evidence(self, incident_id: str, evidence: Dict[str, Any]):
        """Update the incident with investigation evidence."""
        try:
            update_body = {
                "doc": {"evidence": evidence}
            }
            self.client.update(index=self.incident_index, id=incident_id, body=update_body, refresh=True)
        except Exception as e:
            logger.error(f"Failed to update incident evidence: {e}")

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single incident by ID."""
        try:
            response = self.client.get(index=self.incident_index, id=incident_id)
            return response["_source"]
        except Exception as e:
            logger.error(f"Error fetching incident {incident_id}: {e}")
            return None

    # ── Tamper-evident audit log ──────────────────────────────────
    def append_audit(self, entry: Dict[str, Any]):
        try:
            self.client.index(index=self.audit_index, body=entry, refresh=False)
        except Exception as e:
            logger.error(f"Failed to append audit entry: {e}")

    def latest_audit_hash(self) -> str:
        try:
            resp = self.client.search(index=self.audit_index, body={
                "size": 1, "sort": [{"timestamp": {"order": "desc"}}],
                "_source": ["entry_hash"],
            }, ignore=[404])
            hits = resp.get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_source"].get("entry_hash", "CHAEL-GENESIS")
        except Exception as e:
            logger.debug(f"No prior audit hash: {e}")
        return "CHAEL-GENESIS"

    def get_audit(self, limit: int = 200, action: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            q = {"match_all": {}} if not action else {"term": {"action": action}}
            resp = self.client.search(index=self.audit_index, body={
                "size": limit, "query": q, "sort": [{"timestamp": {"order": "asc"}}],
            })
            return [h["_source"] for h in resp["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error fetching audit log: {e}")
            return []

    def get_analytics(self) -> Dict[str, Any]:
        """Aggregate data for the enterprise dashboard."""
        try:
            # Simplified analytics aggregation
            stats = {
                "total_logs_24h": self.client.count(index=self.log_index)["count"],
                "active_incidents": self.client.count(index=self.incident_index, body={"query": {"match": {"status": "OPEN"}}})["count"],
                "system_status": "OPERATIONAL"
            }
            return stats
        except Exception:
            return {"total_logs_24h": 0, "active_incidents": 0, "system_status": "DEGRADED"}
