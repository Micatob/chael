import json
import logging
import urllib.request
from typing import List, Dict, Any
from .base import BaseFeed

logger = logging.getLogger(__name__)


class URLhausFeed(BaseFeed):
    def poll(self) -> List[Dict[str, Any]]:
        iocs = []
        try:
            req = urllib.request.Request(
                "https://urlhaus.abuse.ch/downloads/csv_recent/",
                headers={"Accept": "text/csv", "User-Agent": "ChaelSIEM/1.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
            for line in text.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split(",")
                if len(parts) < 6:
                    continue
                url = parts[2].strip('"')
                status = parts[3].strip('"')
                threat = parts[5].strip('"')
                if status == "online":
                    iocs.append({
                        "feed": "urlhaus",
                        "type": "URL",
                        "value": url,
                        "description": f"URLhaus: {threat}",
                        "tags": [threat],
                        "first_seen": parts[0].strip('"'),
                    })
        except Exception as e:
            logger.warning("URLhaus poll error: %s", e)
        logger.info("URLhaus feed polled: %d indicators", len(iocs))
        return iocs[:1000]
