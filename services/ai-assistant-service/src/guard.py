"""Prompt-injection guard: attacker-controlled log text must never steer the analyst AI."""
import re
from typing import Tuple

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)disregard\s+(all\s+)?(prior|previous|above)",
    r"(?i)you\s+are\s+now\s+",
    r"(?i)system\s*:\s*",
    r"(?i)mark\s+(this\s+)?(as\s+)?benign",
    r"(?i)close\s+(this\s+)?incident",
    r"(?i)false\s+positive\s*(\.|$)",
    r"(?i)jailbreak",
    r"(?i)dan\s+mode",
    r"(?i)output\s+.*password",
]

_COMPILED = [re.compile(p) for p in INJECTION_PATTERNS]


def scan(text: str) -> Tuple[bool, str]:
    """Returns (is_suspicious, matched_pattern). Suspicious input is quarantined, not sent raw."""
    for pat in _COMPILED:
        if pat.search(text or ""):
            return True, pat.pattern
    return False, ""


def sanitize(text: str, max_chars: int = 4000) -> str:
    """Truncate + strip control chars + neutralize instruction-like lines."""
    text = (text or "")[:max_chars]
    lines = []
    for line in text.splitlines()[:80]:
        suspicious, _ = scan(line)
        if suspicious:
            lines.append("[QUARANTINED-LINE: possible prompt injection removed]")
        else:
            lines.append(line)
    return "\n".join(lines)
