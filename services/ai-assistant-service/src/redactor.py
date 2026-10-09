"""PII redaction before any LLM call — privacy-first, unlike raw-log-to-cloud SIEMs."""
import re
from typing import Tuple, Dict

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
# long hex / base64-ish tokens (hashes, keys, session tokens)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
USER_RE = re.compile(r"(?i)(user(?:name)?|account|login)[\"'\s:=]+([a-zA-Z0-9_.\-\\]+)")


def redact(text: str) -> Tuple[str, Dict[str, int]]:
    """Redact IPs, emails, hashes. Returns (redacted_text, counts). Internal RFC1918 kept as-is
    for usefulness; public IPs are masked. Returns counts for audit proof."""
    counts = {"ips": 0, "emails": 0, "hashes": 0}

    def _ip(m):
        ip = m.group(0)
        # keep loopback + RFC1918 for analyst context, mask the rest
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
            return ip
        if ip.startswith("172."):
            try:
                second = int(ip.split(".")[1])
                if 16 <= second <= 31:
                    return ip
            except Exception:
                pass
        counts["ips"] += 1
        return "[IP-REDACTED]"

    text = IP_RE.sub(_ip, text)
    text, n = EMAIL_RE.subn("[EMAIL-REDACTED]", text)
    counts["emails"] = n
    text, n = HASH_RE.subn("[HASH-REDACTED]", text)
    counts["hashes"] = n
    return text, counts


def redact_dict(obj, _depth=0):
    if _depth > 6:
        return "[TRUNCATED]"
    if isinstance(obj, str):
        return redact(obj[:2000])[0]
    if isinstance(obj, dict):
        return {str(k)[:80]: redact_dict(v, _depth + 1) for k, v in list(obj.items())[:40]}
    if isinstance(obj, list):
        return [redact_dict(x, _depth + 1) for x in obj[:20]]
    return obj
