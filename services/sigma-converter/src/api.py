import logging
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from sigma_converter import (
    SigmaRule, convert_sigma_to_chael_rule,
    bulk_convert_sigma_to_chael,
    fetch_sigma_rules_from_github,
    load_sigma_from_directory,
    SUPPORTED_OS,
)
import json

logger = logging.getLogger(__name__)

app = FastAPI(title="Sigma Rule Converter")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SigmaYamlInput(BaseModel):
    yaml_content: str


class ConvertedRule(BaseModel):
    title: str
    sigma_id: str
    severity: str
    type: str
    mitre_attack: List[str]
    chael_rule: dict


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "sigma-converter"}


@app.get("/api/sigma/health")
async def sigma_health():
    return {"status": "healthy", "service": "sigma-converter"}


@app.get("/metrics")
async def metrics():
    from starlette.responses import Response
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/")
async def root():
    return {
        "service": "Sigma Rule Converter",
        "version": "1.0.0",
        "endpoints": {
            "POST /api/sigma/convert": "Convert single Sigma YAML to Chael rule",
            "POST /api/sigma/convert-bulk": "Convert multiple Sigma YAMLs",
            "GET /api/sigma/fetch": "Fetch rules from SigmaHQ GitHub",
            "GET /api/sigma/list-formats": "List supported Sigma formats",
        },
    }


@app.get("/api/sigma/list-formats")
async def list_formats():
    return {
        "supported_os": SUPPORTED_OS,
        "rule_categories": [
            "windows/process_creation",
            "windows/registry",
            "windows/file_event",
            "windows/network_connection",
            "windows/builtin",
            "windows/sysmon",
            "linux",
            "macos",
            "cloud",
        ],
        "supported_operators": [
            "equals", "in_list", "contains", "endswith",
            "startswith", "regex", "base64offset", "windash",
        ],
    }


@app.post("/api/sigma/convert", response_model=dict)
async def convert_sigma(input_data: SigmaYamlInput):
    rule = SigmaRule.from_yaml(input_data.yaml_content)
    if not rule:
        raise HTTPException(status_code=400, detail="Invalid Sigma YAML format")
    try:
        chael_rule = convert_sigma_to_chael_rule(rule)
        return {
            "success": True,
            "rule": chael_rule,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Conversion failed: {e}")


class BulkConvertInput(BaseModel):
    rules: List[SigmaYamlInput]


@app.post("/api/sigma/convert-bulk", response_model=dict)
async def convert_sigma_bulk(input_data: BulkConvertInput):
    sigma_rules = []
    errors = []
    for i, item in enumerate(input_data.rules):
        rule = SigmaRule.from_yaml(item.yaml_content)
        if rule:
            sigma_rules.append(rule)
        else:
            errors.append({"index": i, "error": "Invalid Sigma YAML"})
    converted = bulk_convert_sigma_to_chael(sigma_rules)
    return {
        "success": True,
        "total": len(input_data.rules),
        "converted": len(converted),
        "errors": len(errors),
        "error_details": errors if errors else None,
        "rules": converted,
    }


@app.get("/api/sigma/fetch", response_model=dict)
async def fetch_sigma_rules(
    category: Optional[str] = Query(None, description="Rule category to fetch"),
    limit: int = Query(10, ge=1, le=100, description="Max rules to fetch"),
):
    try:
        sigma_rules = fetch_sigma_rules_from_github(category=category)
        sigma_rules = sigma_rules[:limit]
        converted = bulk_convert_sigma_to_chael(sigma_rules)
        return {
            "success": True,
            "source": "SigmaHQ/sigma",
            "category": category or "all",
            "total_fetched": len(sigma_rules),
            "total_converted": len(converted),
            "rules": converted,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch rules: {e}")


@app.get("/api/sigma/load-local", response_model=dict)
async def load_local_rules(
    path: str = Query("/sigma-rules", description="Directory path"),
):
    sigma_rules = load_sigma_from_directory(path)
    converted = bulk_convert_sigma_to_chael(sigma_rules)
    return {
        "success": True,
        "path": path,
        "total_found": len(sigma_rules),
        "total_converted": len(converted),
        "rules": converted,
    }


class DeployInput(BaseModel):
    yaml_content: str
    threshold: int = 1
    enabled: bool = True


def build_correlation_payload(rule: SigmaRule, chael_rule: dict) -> dict:
    """Map full converter output -> correlation-service CorrelationRule schema."""
    level = (rule.severity or "medium").lower()
    risk = {"low": 25, "medium": 50, "high": 75, "critical": 90}.get(level, 50)
    first_cond = None
    try:
        conds = (chael_rule.get("conditions") or {}).get("conditions", [])
        first_cond = conds[0] if conds else None
    except Exception:
        first_cond = None
    return {
        "id": chael_rule.get("sigma_id") or rule.id or rule.title.lower().replace(" ", "_"),
        "name": chael_rule.get("title", rule.title),
        "condition": {
            "field": (first_cond or {}).get("field", "message"),
            "operator": "contains" if (first_cond or {}).get("operator") not in ("equals", "contains") else (first_cond or {}).get("operator", "contains"),
            "value": str(((first_cond or {}).get("value", [""])[0] if isinstance((first_cond or {}).get("value"), list) else (first_cond or {}).get("value", ""))),
        },
        "threshold": 1,
        "window_seconds": chael_rule.get("timeframe_seconds") or 0,
        "risk_score": risk,
        "description": chael_rule.get("description", ""),
        "enabled": True,
        "mitre_attack": chael_rule.get("mitre_attack", []),
        "technique_id": (chael_rule.get("mitre_attack") or [""])[0] if chael_rule.get("mitre_attack") else "",
        "severity": chael_rule.get("severity", "MEDIUM"),
        "tags": chael_rule.get("tags", []),
        "source": "sigma",
    }


def push_rule_to_correlation(payload: dict, corr_url: str) -> dict:
    """POST one rule to correlation-service. Returns {deployed, error}."""
    import requests as _requests
    try:
        _requests.post(f"{corr_url}/api/correlation/rules/", json=payload, timeout=10).raise_for_status()
        return {"deployed": True, "error": ""}
    except Exception as e:
        return {"deployed": False, "error": str(e)[:300]}


@app.post("/api/sigma/deploy", response_model=dict)
async def deploy_to_correlation(input_data: SigmaYamlInput):
    """Convert a Sigma rule and push it live into correlation-service (no longer orphaned)."""
    import os as _os
    rule = SigmaRule.from_yaml(input_data.yaml_content)
    if not rule:
        raise HTTPException(status_code=400, detail="Invalid Sigma YAML format")
    chael_rule = convert_sigma_to_chael_rule(rule)
    payload = build_correlation_payload(rule, chael_rule)
    corr_url = _os.getenv("CORRELATION_SERVICE_URL", "http://correlation-service:8081")
    result = push_rule_to_correlation(payload, corr_url)
    if not result["deployed"]:
        # Return converted rule even if correlation is unreachable so UI can retry
        return {"success": True, "deployed": False, "error": result["error"], "rule": payload, "full": chael_rule}
    return {"success": True, "deployed": True, "rule": payload, "full": chael_rule}


class BulkDeployInput(BaseModel):
    category: Optional[str] = None
    limit: int = 50
    rules: Optional[List[str]] = None
    dry_run: bool = False


@app.post("/api/sigma/deploy-bulk", response_model=dict)
async def deploy_bulk(input_data: BulkDeployInput):
    """Bulk-load Sigma detections live: fetch N community rules (or convert the
    provided YAML list) and push each into correlation-service. dry_run converts
    without pushing so analysts can review first."""
    import os as _os
    limit = max(1, min(input_data.limit or 50, 200))
    if input_data.rules:
        yamls = input_data.rules[:limit]
        sigma_rules = [r for r in (SigmaRule.from_yaml(y) for y in yamls) if r]
        source = "provided"
    else:
        try:
            sigma_rules = fetch_sigma_rules_from_github(category=input_data.category)[:limit]
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"SigmaHQ fetch failed: {e}")
        source = "SigmaHQ/sigma"
    corr_url = _os.getenv("CORRELATION_SERVICE_URL", "http://correlation-service:8081")
    results = []
    deployed = 0
    for rule in sigma_rules:
        try:
            chael_rule = convert_sigma_to_chael_rule(rule)
            payload = build_correlation_payload(rule, chael_rule)
        except Exception as e:
            results.append({"id": getattr(rule, "id", "?"), "title": getattr(rule, "title", "?"),
                            "deployed": False, "error": f"convert: {e}"[:200]})
            continue
        if input_data.dry_run:
            results.append({"id": payload["id"], "title": payload["name"],
                            "deployed": False, "error": "dry_run",
                            "risk_score": payload["risk_score"]})
            continue
        push = push_rule_to_correlation(payload, corr_url)
        if push["deployed"]:
            deployed += 1
        results.append({"id": payload["id"], "title": payload["name"],
                        "deployed": push["deployed"], "error": push["error"]})
    return {"success": True, "source": source, "dry_run": input_data.dry_run,
            "total": len(sigma_rules), "deployed": deployed,
            "failed": len(sigma_rules) - deployed - (len(sigma_rules) if input_data.dry_run else 0),
            "results": results}