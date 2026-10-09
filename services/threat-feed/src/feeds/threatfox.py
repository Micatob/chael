import json
import logging
import urllib.request
from typing import List, Dict, Any
from .base import BaseFeed

logger = logging.getLogger(__name__)

TYPE_MAP = {
    "ip:port": "IP_ADDRESS",
    "domain": "DOMAIN",
    "url": "URL",
    "md5_hash": "HASH_MD5",
    "sha1_hash": "HASH_SHA1",
    "sha256_hash": "HASH_SHA256",
}


class ThreatFoxFeed(BaseFeed):
    def poll(self) -> List[Dict[str, Any]]:
        iocs = []
        try:
            req = urllib.request.Request(
                "https://threatfox-api.abuse.ch/api/v1/",
                data=json.dumps({"query": "get_iocs", "days": 1}).encode(),
                headers={"Content-Type": "application/json", "User-Agent": "ChaelSIEM/1.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
            for entry in data.get("data", []):
                ioc_type = entry.get("ioc_type", "")
                ioc_value = entry.get("ioc", "")
                if not ioc_value:
                    continue
                mapped_type = TYPE_MAP.get(ioc_type, ioc_type.upper())
                first_seen_raw = entry.get("first_seen", "")
                first_seen = first_seen_raw.replace(" ", "T") + "Z" if first_seen_raw else ""
                iocs.append({
                    "feed": "threatfox",
                    "type": mapped_type,
                    "value": ioc_value,
                    "description": f"ThreatFox: {entry.get('malware_printable', 'unknown')}",
                    "tags": [
                        entry.get("malware_printable", "unknown"),
                        "threatfox",
                        entry.get("threat_type", ""),
                    ],
                    "first_seen": first_seen,
                    "reference": entry.get("reference", ""),
                    "confidence": entry.get("confidence_level", 50),
                })
        except Exception as e:
            logger.warning("ThreatFox poll error: %s", e)
        logger.info("ThreatFox feed polled: %d indicators", len(iocs))
        return iocs
