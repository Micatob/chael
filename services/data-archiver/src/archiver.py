import os
import json
import gzip
import logging
from datetime import datetime, timezone, timedelta
from opensearchpy import OpenSearch, helpers
from config import settings

logger = logging.getLogger("data-archiver")

class DataArchiver:
    def __init__(self):
        self.os_client = self._init_opensearch()
        os.makedirs(settings.ARCHIVE_DIR, exist_ok=True)
        
    def _init_opensearch(self):
        try:
            return OpenSearch(
                hosts=[{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}],
                http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
                use_ssl=settings.OPENSEARCH_USE_SSL,
                verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
            )
        except Exception as e:
            logger.error(f"Failed to connect to OpenSearch: {e}")
            return None

    def run_archive_cycle(self):
        if not self.os_client:
            logger.error("OpenSearch client not initialized. Aborting archive cycle.")
            return

        logger.info(f"Starting archive cycle. Retention: {settings.ARCHIVE_RETENTION_DAYS} days.")
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=settings.ARCHIVE_RETENTION_DAYS)
        cutoff_iso = cutoff_date.isoformat()
        
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "lt": cutoff_iso
                    }
                }
            }
        }
        
        indices = ["chaelsiem-logs-*", "chaelsiem-audit-logs"]
        
        for index_pattern in indices:
            try:
                self._archive_and_delete(index_pattern, query, cutoff_iso)
            except Exception as e:
                logger.error(f"Error processing index {index_pattern}: {e}")
                
        logger.info("Archive cycle completed.")

    def _archive_and_delete(self, index_pattern, query, cutoff_iso):
        logger.info(f"Scanning for old documents in {index_pattern} (older than {cutoff_iso})")
        
        # Scroll API to get all matching documents
        scroll_resp = self.os_client.search(
            index=index_pattern,
            body=query,
            scroll="2m",
            size=1000,
            ignore_unavailable=True
        )
        
        scroll_id = scroll_resp.get("_scroll_id")
        hits = scroll_resp.get("hits", {}).get("hits", [])
        
        if not hits:
            logger.info(f"No documents to archive for {index_pattern}.")
            return
            
        doc_count = 0
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_index_name = index_pattern.replace("*", "all").replace("-", "_")
        archive_path = os.path.join(settings.ARCHIVE_DIR, f"archive_{safe_index_name}_{timestamp_str}.jsonl.gz")
        
        logger.info(f"Writing matching documents to {archive_path}")
        
        # Write to gzipped jsonl file
        with gzip.open(archive_path, "wt", encoding="utf-8") as f:
            while hits:
                for hit in hits:
                    f.write(json.dumps(hit["_source"]) + "\n")
                    doc_count += 1
                
                scroll_resp = self.os_client.scroll(
                    scroll_id=scroll_id,
                    scroll="2m"
                )
                scroll_id = scroll_resp.get("_scroll_id")
                hits = scroll_resp.get("hits", {}).get("hits", [])
                
        logger.info(f"Archived {doc_count} documents to {archive_path}.")
        
        # Delete the archived documents from OpenSearch
        logger.info(f"Deleting the {doc_count} archived documents from {index_pattern}...")
        
        delete_resp = self.os_client.delete_by_query(
            index=index_pattern,
            body=query,
            conflicts="proceed",
            ignore_unavailable=True
        )
        
        deleted_count = delete_resp.get("deleted", 0)
        logger.info(f"Deleted {deleted_count} documents from {index_pattern}.")
