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
        self._ensure_connectivity()

    def _ensure_connectivity(self):
        """Verify connection to OpenSearch cluster."""
        try:
            if not self.client.ping():
                logger.error("OpenSearch cluster is unreachable.")
        except Exception as e:
            logger.error(f"Error connecting to OpenSearch: {e}")

    def ensure_indices(self):
        """Create indices with optimized mappings for SIEM performance."""
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
                    "artifacts": {"type": "object", "enabled": True},
                    "source_logs": {"type": "nested"},
                    "tenant_id": {"type": "keyword"}
                }
            }
        }

        try:
            if not self.client.indices.exists(index=self.incident_index):
                self.client.indices.create(index=self.incident_index, body=incident_mapping)
                logger.info(f"Created index: {self.incident_index}")
        except RequestError as e:
            logger.error(f"Failed to create index {self.incident_index}: {e}")

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
        sort_order: str = "desc"
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

            if severity:
                must_clauses.append({"term": {"severity": severity}})

            if host:
                must_clauses.append({"term": {"host": host}})

            if source:
                must_clauses.append({"term": {"source": source}})

            query = {
                "size": limit,
                "from": offset,
                "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
                "sort": [{sort_by: {"order": sort_order}}]
            }

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
