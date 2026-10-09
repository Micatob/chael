import json
import logging
import urllib.request
from typing import List, Dict, Any
from .base import BaseFeed

logger = logging.getLogger(__name__)


class OTXFeed(BaseFeed):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"

    def poll(self) -> List[Dict[str, Any]]:
        if not self.api_key:
            logger.info("No OTX_API_KEY configured, skipping AlienVault OTX poll")
            return []
        iocs = []
        for pulse_type in ["adversary", "malware", "known-exploited-vulnerability"]:
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/pulses/subscribed?limit=20&page=1",
                    headers={"X-OTX-API-KEY": self.api_key, "Accept": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                for pulse in data.get("results", []):
                    for indicator in pulse.get("indicators", []):
                        iocs.append({
                            "feed": "alienvault-otx",
                            "type": indicator.get("type", "").upper(),
                            "value": indicator.get("indicator", ""),
                            "description": pulse.get("description", "")[:500],
                            "pulse_name": pulse.get("name", ""),
                            "tlp": pulse.get("TLP", "WHITE"),
                            "tags": pulse.get("tags", []),
                            "reference": pulse.get("reference", ""),
                            "first_seen": indicator.get("created", ""),
                        })
            except Exception as e:
                logger.warning("OTX poll error for %s: %s", pulse_type, e)
        logger.info("OTX feed polled: %d indicators", len(iocs))
        return iocs
