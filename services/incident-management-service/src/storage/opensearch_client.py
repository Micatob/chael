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
                    "investigation_results": {"type": "object", "enabled": True},
                    "mitigation_history": {"type": "nested"},
                    "notes": {"type": "nested"},
                    "timeline": {"type": "nested"},
                    "tags": {"type": "keyword"},
                    "mitre_attack": {"type": "keyword"},
                    "compliance": {"type": "object", "enabled": True},
                    "assigned_to": {"type": "keyword"}
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

            response = self.client.search(index=self.log_index, body=query)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error fetching filtered logs: {e}")
            return []

    def get_incidents(self, limit: int = 500, status: Optional[str] = None) -> List[Dict]:
        """Fetch latest incidents with server-side filtering and source selection."""
        try:
            query_body: Dict[str, Any] = {
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "_source": ["incident_id", "timestamp", "description", "status", "risk_score", "affected_host", "attack_type"],
            }
            if status:
                query_body["query"] = {"match": {"status": status.upper()}}
            else:
                query_body["query"] = {"match_all": {}}
            response = self.client.search(index=self.incident_index, body=query_body)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error fetching incidents: {e}")
            return []

    def search_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        status: Optional[str] = None,
        risk_score_min: Optional[int] = None,
        risk_score_max: Optional[int] = None,
        host: Optional[str] = None,
        attack_type: Optional[str] = None,
        sort_by: str = "timestamp",
        sort_order: str = "desc"
    ) -> Dict[str, Any]:
        """Search incidents with advanced filtering."""
        try:
            must_clauses = []

            if search:
                must_clauses.append({
                    "multi_match": {
                        "query": search,
                        "fields": ["description", "incident_id"],
                        "fuzziness": "AUTO"
                    }
                })

            if status:
                must_clauses.append({"match": {"status": status.upper()}})

            if risk_score_min is not None or risk_score_max is not None:
                range_clause = {}
                if risk_score_min is not None:
                    range_clause["gte"] = risk_score_min
                if risk_score_max is not None:
                    range_clause["lte"] = risk_score_max
                must_clauses.append({"range": {"risk_score": range_clause}})

            if host:
                must_clauses.append({
                    "multi_match": {
                        "query": host,
                        "fields": ["artifacts.host", "artifacts.target_host"]
                    }
                })

            if attack_type:
                must_clauses.append({
                    "multi_match": {
                        "query": attack_type,
                        "fields": ["artifacts.attack_type", "artifacts.event_type"]
                    }
                })

            query = {
                "size": limit,
                "from": offset,
                "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
                "sort": [{sort_by: {"order": sort_order}}]
            }

            response = self.client.search(index=self.incident_index, body=query)
            hits = [hit["_source"] for hit in response["hits"]["hits"]]
            return {
                "hits": hits,
                "total": response["hits"]["total"]["value"],
                "took": response["took"]
            }
        except Exception as e:
            logger.error(f"Error searching incidents: {e}")
            return {"hits": [], "total": 0, "took": 0}

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
        """Aggregate data for the enterprise dashboard (single query)."""
        try:
            query = {
                "size": 0,
                "query": {"range": {"timestamp": {"gte": "now-24h"}}},
                "aggs": {
                    "open_incidents": {"filter": {"match": {"status": "OPEN"}}},
                    "investigating_incidents": {"filter": {"match": {"status": "INVESTIGATING"}}},
                    "severity_breakdown": {"terms": {"field": "status.keyword", "size": 10}},
                }
            }
            response = self.client.search(index=self.incident_index, body=query)
            # opensearch-py returns aggregations under "aggregations"
            aggs = response.get("aggregations", response.get("aggs", {}))
            total_logs = self.client.count(
                index=self.log_index,
                body={"query": {"range": {"timestamp": {"gte": "now-24h"}}}}
            )["count"]
            active = (
                aggs.get("open_incidents", {}).get("doc_count", 0)
                + aggs.get("investigating_incidents", {}).get("doc_count", 0)
            )
            return {
                "total_logs_24h": total_logs,
                "active_incidents": active,
                "system_status": "OPERATIONAL"
            }
        except Exception:
            return {"total_logs_24h": 0, "active_incidents": 0, "system_status": "DEGRADED"}

    def get_log_trend(self, intervals: int = 24) -> list:
        """Get hourly log ingestion trend using date histogram aggregation."""
        try:
            query = {
                "size": 0,
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": "now-24h",
                            "lte": "now"
                        }
                    }
                },
                "aggs": {
                    "logs_over_time": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1h",
                            "format": "HH:mm"
                        }
                    }
                }
            }
            response = self.client.search(index=self.log_index, body=query)
            buckets = response["aggregations"]["logs_over_time"]["buckets"]
            return [{"name": b["key_as_string"], "logs": b["doc_count"]} for b in buckets]
        except Exception as e:
            logger.error(f"Error fetching log trend: {e}")
            return []
