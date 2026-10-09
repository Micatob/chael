from opensearchpy import OpenSearch, RequestError
from models.schema import FlowRecord
from config import settings
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

class OpenSearchClient:
    def __init__(self):
        self.auth = (settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD) if settings.OPENSEARCH_USER else None
        self.client = OpenSearch(
            hosts=[{'host': settings.OPENSEARCH_HOST, 'port': settings.OPENSEARCH_PORT}],
            http_auth=self.auth,
            use_ssl=settings.OPENSEARCH_USE_SSL,
            verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
            ssl_show_warn=False,
            timeout=30,
            max_retries=3,
            retry_on_timeout=True
        )
        self.flow_index = "chaelsiem-flows"
        self._ensure_connectivity()

    def _ensure_connectivity(self):
        try:
            if not self.client.ping():
                logger.error("OpenSearch cluster is unreachable.")
        except Exception as e:
            logger.error(f"Error connecting to OpenSearch: {e}")

    def ensure_indices(self):
        flow_mapping = {
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
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "src_port": {"type": "integer"},
                    "dst_port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "bytes": {"type": "long"},
                    "packets": {"type": "long"},
                    "duration_seconds": {"type": "float"},
                    "src_host": {"type": "keyword"},
                    "dst_host": {"type": "keyword"},
                    "app_name": {"type": "keyword"},
                    "direction": {"type": "keyword"},
                    "metadata": {"type": "object", "enabled": True},
                    "tenant_id": {"type": "keyword"}
                }
            }
        }

        try:
            if not self.client.indices.exists(index=self.flow_index):
                try:
                    self.client.indices.create(index=self.flow_index, body=flow_mapping)
                    logger.info(f"Created index: {self.flow_index}")
                except RequestError as e:
                    # Handle race: if already exists
                    if "resource_already_exists_exception" in str(e):
                        logger.debug(f"Index {self.flow_index} already exists (race)")
                    else:
                        raise
        except RequestError as e:
            logger.error(f"Failed to create index {self.flow_index}: {e}")
        except Exception as e:
            logger.error(f"ensure_indices error for {self.flow_index}: {e}")

    def _ensure_index_exists(self):
        """Lazy ensure - called before queries that may hit missing index."""
        try:
            if not self.client.indices.exists(index=self.flow_index):
                self.ensure_indices()
        except Exception:
            pass

    def index_flow(self, flow: FlowRecord):
        try:
            data = flow.model_dump()
            self.client.index(index=self.flow_index, body=data, refresh=False)
        except Exception as e:
            logger.error(f"Failed to index flow: {e}")

    def get_flows(
        self,
        limit: int = 100,
        offset: int = 0,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        min_bytes: Optional[int] = None,
        sort_by: str = "timestamp",
        sort_order: str = "desc"
    ) -> List[Dict]:
        self._ensure_index_exists()
        try:
            must_clauses = []

            if src_ip:
                must_clauses.append({"term": {"src_ip": src_ip}})
            if dst_ip:
                must_clauses.append({"term": {"dst_ip": dst_ip}})
            if protocol:
                must_clauses.append({"term": {"protocol": protocol}})
            if min_bytes is not None:
                must_clauses.append({"range": {"bytes": {"gte": min_bytes}}})

            query = {
                "size": limit,
                "from": offset,
                "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
                "sort": [{sort_by: {"order": sort_order}}]
            }

            response = self.client.search(index=self.flow_index, body=query, params={"ignore_unavailable": "true"})
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            if "index_not_found_exception" in str(e):
                logger.debug(f"get_flows: index {self.flow_index} missing — returning []")
            else:
                logger.error(f"Error fetching flows: {e}")
            return []

    def get_flow_stats(self) -> Dict[str, Any]:
        self._ensure_index_exists()
        try:
            now = datetime.now(timezone.utc)
            twenty_four_hours_ago = now - timedelta(hours=24)

            try:
                count_resp = self.client.count(
                    index=self.flow_index,
                    body={"query": {"range": {"timestamp": {"gte": twenty_four_hours_ago.isoformat()}}}}
                )
            except Exception as ce:
                if "index_not_found_exception" in str(ce):
                    return {
                        "total_flows_24h": 0, "unique_src_ips": 0, "unique_dst_ips": 0,
                        "total_bytes": 0, "total_megabytes": 0,
                        "top_ports": [], "top_protocols": [], "top_src_ips": [], "top_dst_ips": []
                    }
                raise
            total_flows = count_resp["count"]

            # Aggregations
            agg_query = {
                "size": 0,
                "query": {"range": {"timestamp": {"gte": twenty_four_hours_ago.isoformat()}}},
                "aggs": {
                    "unique_src_ips": {"cardinality": {"field": "src_ip"}},
                    "unique_dst_ips": {"cardinality": {"field": "dst_ip"}},
                    "total_bytes": {"sum": {"field": "bytes"}},
                    "top_ports": {"terms": {"field": "dst_port", "size": 20}},
                    "top_protocols": {"terms": {"field": "protocol", "size": 10}},
                    "top_src_ips": {"terms": {"field": "src_ip", "size": 20}},
                    "top_dst_ips": {"terms": {"field": "dst_ip", "size": 20}},
                }
            }

            agg_resp = self.client.search(index=self.flow_index, body=agg_query, params={"ignore_unavailable": "true"})
            aggs = agg_resp.get("aggregations", {})

            return {
                "total_flows_24h": total_flows,
                "unique_src_ips": aggs.get("unique_src_ips", {}).get("value", 0),
                "unique_dst_ips": aggs.get("unique_dst_ips", {}).get("value", 0),
                "total_bytes": int(aggs.get("total_bytes", {}).get("value", 0)),
                "total_megabytes": round(int(aggs.get("total_bytes", {}).get("value", 0)) / (1024 * 1024), 2),
                "top_ports": [{"port": b["key"], "count": b["doc_count"]} for b in aggs.get("top_ports", {}).get("buckets", [])],
                "top_protocols": [{"protocol": b["key"], "count": b["doc_count"]} for b in aggs.get("top_protocols", {}).get("buckets", [])],
                "top_src_ips": [{"ip": b["key"], "count": b["doc_count"]} for b in aggs.get("top_src_ips", {}).get("buckets", [])],
                "top_dst_ips": [{"ip": b["key"], "count": b["doc_count"]} for b in aggs.get("top_dst_ips", {}).get("buckets", [])],
            }
        except Exception as e:
            logger.error(f"Error computing flow stats: {e}")
            return {
                "total_flows_24h": 0, "unique_src_ips": 0, "unique_dst_ips": 0,
                "total_bytes": 0, "total_megabytes": 0,
                "top_ports": [], "top_protocols": [], "top_src_ips": [], "top_dst_ips": []
            }
