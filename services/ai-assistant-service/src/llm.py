"""Multi-provider LLM client with per-key/model circuit breakers and auto-failover.

Every (provider, model) is a "line". On HTTP 429 / 5xx / timeout a line enters
cooldown and the call rolls to the next line, then the next provider. Cooled-down
lines recover on their own (free-tier quota resets), so a throttled AI replaces
itself mid-session. The deterministic local fallback in analyzer.py is the final
safety net: this module raises when no line is usable, and main.py catches it.

Beats single-provider big-SIEM AI on: multi-key rotation, per-model circuit
breakers, Retry-After awareness, and an analyst-facing provider override.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from config import settings

logger = logging.getLogger("ai-assistant-llm")

AUTH_COOLDOWN_S = 900       # 401/403 — bad, expired, or revoked key
INFRA_COOLDOWN_S = 60       # transient 5xx / network / timeout
GENERIC_COOLDOWN_S = 600    # other 4xx (bad prompt etc.)

_lines: Dict[Tuple[str, str], Dict[str, Any]] = {}
_stats: Dict[str, int] = {"llm_calls": 0, "rotations": 0}


class _ProviderError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None,
                 retry_after: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after


def _groq_models() -> List[str]:
    raw = (getattr(settings, "GROQ_MODELS", "") or "").strip()
    if raw:
        models = [m.strip() for m in raw.split(",") if m.strip()]
        if models:
            return models
    # Backwards compat: single GROQ_MODEL. Retired llama-3.3-70b-versatile
    # 404s on Groq — transparently remap to a live model.
    legacy = (settings.GROQ_MODEL or "").strip() or "qwen/qwen3.8-27b"
    if legacy == "llama-3.3-70b-versatile":
        legacy = "qwen/qwen3.8-27b"
    return [legacy]


def _gemini_models() -> List[str]:
    raw = (getattr(settings, "GEMINI_MODELS", "") or "").strip()
    if raw:
        models = [m.strip() for m in raw.split(",") if m.strip()]
        if models:
            return models
    return ["gemini-2.5-flash"]


def _build_specs() -> Dict[str, Dict[str, Any]]:
    specs: Dict[str, Dict[str, Any]] = {}
    if settings.OPENROUTER_API_KEY:
        models = [m.strip() for m in settings.OPENROUTER_MODELS.split(",") if m.strip()]
        specs["openrouter"] = {
            "id": "openrouter",
            "label": "OpenRouter",
            "key": settings.OPENROUTER_API_KEY,
            "base_url": settings.OPENROUTER_BASE_URL,
            "models": models or ["meta-llama/llama-3.3-70b-instruct"],
            "timeout": settings.AI_TIMEOUT_S,
            "max_tokens": settings.GROQ_MAX_TOKENS,
        }
    if settings.GROQ_API_KEY:
        specs["groq"] = {
            "id": "groq",
            "label": "Groq",
            "key": settings.GROQ_API_KEY,
            "base_url": settings.GROQ_BASE_URL,
            "models": _groq_models(),
            "timeout": settings.GROQ_TIMEOUT_S or settings.AI_TIMEOUT_S,
            "max_tokens": settings.GROQ_MAX_TOKENS,
        }
    if getattr(settings, "GEMINI_API_KEY", ""):
        specs["gemini"] = {
            "id": "gemini",
            "label": "Gemini",
            "key": settings.GEMINI_API_KEY,
            "base_url": getattr(
                settings, "GEMINI_BASE_URL",
                "https://generativelanguage.googleapis.com/v1beta/openai",
            ),
            "models": _gemini_models(),
            "timeout": getattr(settings, "GEMINI_TIMEOUT_S", 0) or settings.AI_TIMEOUT_S,
            "max_tokens": getattr(settings, "GEMINI_MAX_TOKENS", 0) or settings.GROQ_MAX_TOKENS,
        }
    return specs


def _configured_providers() -> List[Dict[str, Any]]:
    specs = _build_specs()
    order = [p.strip().lower() for p in settings.AI_PROVIDER_ORDER.split(",") if p.strip()]
    ordered: List[Dict[str, Any]] = []
    seen = set()
    for name in order:
        if name in specs and name not in seen:
            ordered.append(specs[name])
            seen.add(name)
    for name, spec in specs.items():
        if name not in seen:
            ordered.append(spec)
    return ordered


def _line_state(provider: str, model: str) -> Dict[str, Any]:
    return _lines.setdefault((provider, model), {
        "cooldown_until": 0.0, "consecutive_failures": 0, "last_error": ""})


def _cooling(provider: str, model: str) -> bool:
    return time.time() < _lines.get((provider, model), {}).get("cooldown_until", 0.0)


def _mark_success(provider: str, model: str):
    st = _line_state(provider, model)
    st["cooldown_until"], st["consecutive_failures"], st["last_error"] = 0.0, 0, ""


def _mark_failure(provider: str, model: str, status_code: Optional[int],
                  retry_after: Optional[int], message: str) -> int:
    st = _line_state(provider, model)
    st["consecutive_failures"] += 1
    st["last_error"] = message
    if status_code == 429:
        secs = retry_after or settings.AI_KEY_COOLDOWN_S
    elif status_code in (401, 403):
        secs = AUTH_COOLDOWN_S
    elif status_code is None or status_code >= 500 or status_code == 408:
        secs = INFRA_COOLDOWN_S
    else:
        secs = GENERIC_COOLDOWN_S
    st["cooldown_until"] = time.time() + secs
    return secs


def _candidates(override: Optional[str]) -> List[Tuple[Dict[str, Any], str]]:
    if override and override.lower() != "auto":
        name, _, model = override.partition(":")
        name = name.lower()
        for spec in _configured_providers():
            if spec["id"] == name:
                return [(spec, model.strip() if model.strip() else spec["models"][0])]
        return []
    out = []
    for spec in _configured_providers():
        for m in spec["models"]:
            out.append((spec, m))
    return out


def _call(spec: Dict[str, Any], model: str, system: str, user: str,
          max_tokens: Optional[int]) -> Dict[str, Any]:
    return _call_messages(spec, model,
                          [{"role": "system", "content": system},
                           {"role": "user", "content": user}],
                          max_tokens)


def _call_messages(spec: Dict[str, Any], model: str,
                   messages: List[Dict[str, str]],
                   max_tokens: Optional[int]) -> Dict[str, Any]:
    url = f"{spec['base_url'].rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {spec['key']}", "Content-Type": "application/json"}
    if spec["id"] == "openrouter":
        headers["HTTP-Referer"] = "https://chael.local"
        headers["X-Title"] = "Chael SIEM AI Copilot"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": max_tokens or spec["max_tokens"],
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=spec["timeout"])
    except requests.exceptions.Timeout:
        raise _ProviderError(f"{spec['id']}:{model} timed out after {spec['timeout']}s")
    except requests.exceptions.RequestException as exc:
        raise _ProviderError(f"{spec['id']}:{model} request failed: {exc}")
    if resp.status_code != 200:
        detail = ""
        try:
            detail = str(resp.json().get("error", {}).get("message", ""))[:160]
        except Exception:
            pass
        retry_after = resp.headers.get("Retry-After")
        rt = int(retry_after) if retry_after and str(retry_after).isdigit() else None
        status = resp.status_code
        if status == 429:
            logger.warning("ai line %s:%s rate-limited (429, retry-after=%s)",
                           spec["id"], model, rt)
        raise _ProviderError(f"{spec['id']}:{model} HTTP {status} {detail}".strip(),
                             status_code=status, retry_after=rt)
    data = resp.json()
    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise _ProviderError(f"{spec['id']}:{model} malformed response: {exc}")
    return {"ok": True, "text": text, "provider": spec["id"], "model": model,
            "label": f"{spec['id']}:{model}", "usage": data.get("usage", {})}


def disabled_reason() -> Optional[str]:
    """Return None when LLM should be called, else a human explanation."""
    if not settings.AI_ENABLED:
        return "AI disabled (set AI_ENABLED=true)"
    if not _configured_providers():
        return "No AI provider key configured (set GROQ_API_KEY, GEMINI_API_KEY or OPENROUTER_API_KEY)"
    return None


def available() -> bool:
    return disabled_reason() is None


def status() -> List[Dict[str, Any]]:
    out = []
    for spec in _configured_providers():
        models = []
        for m in spec["models"]:
            st = _line_state(spec["id"], m)
            cooled = _cooling(spec["id"], m)
            models.append({
                "model": m,
                "state": "cooldown" if cooled else "ready",
                "cooldown_until": round(st["cooldown_until"], 1) if cooled else 0,
                "consecutive_failures": st["consecutive_failures"],
                "last_error": st.get("last_error", ""),
            })
        out.append({"provider": spec["id"], "label": spec["label"],
                    "configured": True, "models": models})
    return out


def primary_model() -> str:
    provs = _configured_providers()
    if provs:
        return f"{provs[0]['id']}:{provs[0]['models'][0]}"
    return f"groq:{_groq_models()[0]}"


def stats() -> Dict[str, int]:
    return dict(_stats)


def _run(candidates, call_fn) -> Dict[str, Any]:
    last_error = "no provider left"
    for i, (spec, model) in enumerate(candidates):
        try:
            result = call_fn(spec, model)
            _mark_success(spec["id"], model)
            _stats["llm_calls"] += 1
            return result
        except _ProviderError as exc:
            last_error = exc.message
            secs = _mark_failure(spec["id"], model, exc.status_code, exc.retry_after, exc.message)
            logger.warning("ai line %s:%s down (%s); cooled %ss, rotating%s",
                           spec["id"], model, exc.message, secs,
                           "" if i + 1 < len(candidates) else " — no lines left")
            _stats["rotations"] += 1
    raise RuntimeError(f"All AI lines exhausted ({last_error})")


def chat(system: str, user: str, max_tokens: Optional[int] = None,
         override: Optional[str] = None) -> Dict[str, Any]:
    """Call the best available LLM line. Rotates on 429/5xx/timeout.

    `override` pins an analyst-chosen provider(`groq`) or line(`openrouter:model`).
    Raises RuntimeError when no line can answer — caller falls back to local analysis.
    """
    if not settings.AI_ENABLED:
        raise RuntimeError("AI disabled (set AI_ENABLED=true)")
    candidates = _candidates(override)
    if not candidates:
        raise RuntimeError(f"Unknown AI provider override: {override}")
    pinned = bool(override and override.lower() != "auto")
    if not pinned:
        candidates = [(s, m) for (s, m) in candidates if not _cooling(s["id"], m)]
        if not candidates:
            candidates = _candidates(override)
            _stats["rotations"] += 1
    return _run(candidates, lambda spec, model: _call(spec, model, system, user, max_tokens))


def chat_messages(messages: List[Dict[str, str]], max_tokens: Optional[int] = None,
                  override: Optional[str] = None) -> Dict[str, Any]:
    """Multi-turn live chat. `messages` is an OpenAI-style list with roles
    system/user/assistant. Same rotation/failover as chat()."""
    if not settings.AI_ENABLED:
        raise RuntimeError("AI disabled (set AI_ENABLED=true)")
    candidates = _candidates(override)
    if not candidates:
        raise RuntimeError(f"Unknown AI provider override: {override}")
    pinned = bool(override and override.lower() != "auto")
    if not pinned:
        fresh = [(s, m) for (s, m) in candidates if not _cooling(s["id"], m)]
        if fresh:
            candidates = fresh
        else:
            _stats["rotations"] += 1
    # Clamp history: keep system + last 12 turns to bound cost/latency.
    msgs = list(messages or [])
    if len(msgs) > 13:
        system_msgs = [m for m in msgs if m.get("role") == "system"][:1]
        msgs = system_msgs + msgs[-(12):]
    return _run(candidates, lambda spec, model: _call_messages(spec, model, msgs, max_tokens))