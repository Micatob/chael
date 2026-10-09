import re
import os
import yaml
from typing import List, Optional, Set

_CONFIG_CACHE = None


def _load_config(path: str = None) -> dict:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE
    search_paths = path or [
        "/etc/chael/config.yaml",
        os.path.expanduser("~/.chael/config.yaml"),
        os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"),
        "config.yaml",
    ]
    for p in search_paths:
        if os.path.exists(p):
            with open(p) as f:
                _CONFIG_CACHE = yaml.safe_load(f) or {}
            return _CONFIG_CACHE
    _CONFIG_CACHE = {}
    return _CONFIG_CACHE


class PreFilter:
    def __init__(self, config: dict = None):
        cfg = config or _load_config()
        pf = cfg.get("pre_filtering", {})

        self.enabled = pf.get("enabled", True)

        raw_allow = pf.get("allowlist_patterns", [])
        self.allow_patterns: List[re.Pattern] = [re.compile(p) for p in raw_allow]

        raw_block = pf.get("blocklist_patterns", [])
        self.block_patterns: List[re.Pattern] = [re.compile(p) for p in raw_block]

        self.whitelist_sources: Set[str] = set(pf.get("whitelist_sources", []))

        self.watched_event_ids: Set[int] = set()
        eids = pf.get("windows_event_ids", [])
        for eid in eids:
            try:
                self.watched_event_ids.add(int(eid))
            except (ValueError, TypeError):
                pass

    def should_forward(self, entry: dict) -> bool:
        if not self.enabled:
            return True

        source = entry.get("source", "")
        message = entry.get("message", "")
        log_type = entry.get("log_type", "")

        if self.whitelist_sources:
            matched_source = False
            for ws in self.whitelist_sources:
                if ws.lower() in source.lower():
                    matched_source = True
                    break
            if not matched_source:
                return False

        msg_lower = message.lower()

        for block_re in self.block_patterns:
            if block_re.search(msg_lower):
                return False

        for allow_re in self.allow_patterns:
            if allow_re.search(msg_lower):
                return True

        if log_type == "windows":
            event_id = entry.get("metadata", {}).get("EventID", 0)
            if event_id and self.watched_event_ids:
                if int(event_id) in self.watched_event_ids:
                    return True
                return False

        if log_type in ("docker", "yara", "registry"):
            return True

        return False
