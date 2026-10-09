import json
import logging
import urllib.request
from typing import List, Dict, Any
from .base import BaseFeed

logger = logging.getLogger(__name__)


class FeodoFeed(BaseFeed):
    def poll(self) -> List[Dict[str, Any]]:
        iocs = []
        try:
            req = urllib.request.Request(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                headers={"Accept": "application/json", "User-Agent": "ChaelSIEM/1.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
            for entry in data:
                ip = entry.get("ip_address", "")
                if not ip:
                    continue
                first_seen_raw = entry.get("first_seen", "")
                first_seen = first_seen_raw.replace(" ", "T") + "Z" if first_seen_raw else ""
                iocs.append({
                    "feed": "feodo-tracker",
                    "type": "IP_ADDRESS",
                    "value": ip,
                    "description": f"Feodo Tracker: {entry.get('malware', 'unknown')} C2",
                    "tags": [entry.get("malware", "unknown"), "c2", "botnet"],
                    "first_seen": first_seen,
                    "reference": f"https://feodotracker.abuse.ch/browse/{ip}/",
                    "confidence": "high",
                })
        except Exception as e:
            logger.warning("Feodo Tracker poll error: %s", e)
        logger.info("Feodo Tracker feed polled: %d indicators", len(iocs))
        return iocs
