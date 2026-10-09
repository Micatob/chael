import logging
from typing import Dict, Any, List, Optional

try:
    from opensearchpy import OpenSearch
    HAS_OPENSEARCH = True
except ImportError:
    HAS_OPENSEARCH = False

from config import settings

logger = logging.getLogger(__name__)

FEED_INDEX = "chaelsiem-threat-feed"


class OpenSearchFeedStorage:
    def __init__(self):
        self.client = None
        if HAS_OPENSEARCH:
            self._init_client()

    def _init_client(self):
        try:
            self.client = OpenSearch(
                hosts=[{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}],
                http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
                use_ssl=settings.OPENSEARCH_USE_SSL,
                verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
            )
            self._ensure_index()
        except Exception as e:
            logger.warning("Failed to init OpenSearch: %s", e)

    def _ensure_index(self):
        if not self.client:
            return
        try:
            if not self.client.indices.exists(index=FEED_INDEX):
                self.client.indices.create(
                    index=FEED_INDEX,
                    body={
                        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                        "mappings": {
                            "properties": {
                                "feed": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "value": {"type": "keyword"},
                                "description": {"type": "text"},
                                "tags": {"type": "keyword"},
                                "first_seen": {"type": "date"},
                                "tlp": {"type": "keyword"},
                            }
                        },
                    },
                )
                logger.info("Created index %s", FEED_INDEX)
        except Exception as e:
            logger.warning("Index creation error: %s", e)

    def store_iocs(self, iocs: List[Dict[str, Any]]):
        if not self.client or not iocs:
            return
        for ioc in iocs:
            try:
                self.client.index(index=FEED_INDEX, body=ioc, id=f"{ioc['feed']}-{ioc['type']}-{ioc['value']}")
            except Exception as e:
                logger.warning("Failed to store IOC %s: %s", ioc.get("value"), e)

    def search(self, field: str, value: str) -> List[Dict[str, Any]]:
        if not self.client:
            return []
        try:
            resp = self.client.search(
                index=FEED_INDEX,
                body={
                    "query": {"term": {field: value}},
                    "size": 10,
                },
            )
            return [h["_source"] for h in resp["hits"]["hits"]]
        except Exception as e:
            logger.warning("Search error for %s=%s: %s", field, value, e)
            return []

    def health(self) -> bool:
        return self.client is not None and self.client.ping()
