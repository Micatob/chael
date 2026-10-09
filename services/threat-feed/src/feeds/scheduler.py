import logging
from typing import List, Dict, Any
from .otx import OTXFeed
from .urlhaus import URLhausFeed
from .feodo import FeodoFeed
from .threatfox import ThreatFoxFeed
from storage.opensearch_client import OpenSearchFeedStorage
from config import settings

logger = logging.getLogger(__name__)


class FeedScheduler:
    def __init__(self):
        self.storage = OpenSearchFeedStorage()
        self.feeds = [
            OTXFeed(api_key=settings.OTX_API_KEY),
            URLhausFeed(),
            FeodoFeed(),
            ThreatFoxFeed(),
        ]

    def poll_all(self) -> int:
        total = 0
        for feed in self.feeds:
            try:
                iocs = feed.poll()
                self.storage.store_iocs(iocs)
                total += len(iocs)
            except Exception as e:
                logger.error("Feed poll failed: %s", e, exc_info=True)
        logger.info("Poll complete: %d new IOCs stored", total)
        return total
