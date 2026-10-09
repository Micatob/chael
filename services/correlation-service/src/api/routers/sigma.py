import yaml
from fastapi import APIRouter, HTTPException, UploadFile, File, Body
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from .rules import CorrelationRule, RuleCondition


class SigmaTextRequest(BaseModel):
    yaml: str


class SigmaDeployRequest(BaseModel):
    yaml: str
    enabled: bool = True
    threshold_override: Optional[int] = None

router = APIRouter()

def _extract_mitre(tags: List[str]) -> Dict[str, Any]:
    """Extract MITRE technique IDs from Sigma tags (attack.tXXXX)."""
    try:
        from mitre.attack import normalize_sigma_tags, ATTACK_TECHNIQUES
    except ImportError:
        return {"mitre_attack": [], "technique_id": "", "tactic": "", "technique": ""}
    tech_ids = normalize_sigma_tags(tags or [])
    first = tech_ids[0] if tech_ids else ""
    info = ATTACK_TECHNIQUES.get(first, {}) if first else {}
    return {
        "mitre_attack": tech_ids,
        "technique_id": first,
        "tactic": info.get("tactic", ""),
        "technique": info.get("name", ""),
    }

def convert_sigma_to_chael_rule(sigma_yaml: str) -> CorrelationRule:
    """
    Very basic converter for Sigma to Chael rule format.
    Sigma usually has:
    title, id, logsource, detection (condition, selections)
    """
    try:
        sigma_dict = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}")

    if sigma_dict is None:
        raise ValueError("Empty YAML content")

    title = sigma_dict.get("title", "Imported Sigma Rule")
    rule_id = sigma_dict.get("id", title.lower().replace(" ", "_"))
    description = sigma_dict.get("description", "")
    
    detection = sigma_dict.get("detection", {})
    if not detection:
        raise ValueError("Missing 'detection' section in Sigma rule.")
        
    # Find the main selection
    # Sigma is complex, this is a highly simplified heuristic parser
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise ValueError("No selection logic found in Sigma detection section.")
        
    first_selection = list(selections.values())[0]
    
    # We will pick the first field and value to map to our simple condition
    if isinstance(first_selection, dict):
        field = list(first_selection.keys())[0]
        value = first_selection[field]
        operator = "equals"
        if isinstance(value, str) and ("*" in value or "?" in value):
            operator = "contains"
            value = value.replace("*", "")
    elif isinstance(first_selection, list):
        field = "message"
        value = first_selection[0]
        operator = "contains"
    else:
        field = "message"
        value = str(first_selection)
        operator = "contains"

    # Default thresholds
    threshold = 1
    window_seconds = 0
    risk_score = 60 # Default risk
    
    level = sigma_dict.get("level", "medium").lower()
    if level == "low":
        risk_score = 25
    elif level == "medium":
        risk_score = 50
    elif level == "high":
        risk_score = 75
    elif level == "critical":
        risk_score = 90
        
    condition = RuleCondition(field=field, operator=operator, value=str(value))
    
    mitre = _extract_mitre(sigma_dict.get("tags", []))

    return CorrelationRule(
        id=rule_id,
        name=title,
        condition=condition,
        threshold=threshold,
        window_seconds=window_seconds,
        risk_score=risk_score,
        description=description,
        mitre_attack=mitre["mitre_attack"],
        tactic=mitre["tactic"],
        technique=mitre["technique"],
        technique_id=mitre["technique_id"],
        severity=level.upper() if level else "MEDIUM",
        tags=sigma_dict.get("tags", []),
        source="sigma"
    )


@router.post("/convert")
async def convert_sigma(file: UploadFile = File(...)):
    """Upload a Sigma YAML file and convert it to a Chael rule."""
    if not file.filename.endswith(('.yml', '.yaml')):
        raise HTTPException(status_code=400, detail="Only YAML files are supported")
        
    content = await file.read()
    try:
        yaml_content = content.decode('utf-8')
        chael_rule = convert_sigma_to_chael_rule(yaml_content)
        return {"status": "success", "rule": chael_rule.dict()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Conversion error: {str(e)}")


@router.post("/convert/text")
async def convert_sigma_text(req: SigmaTextRequest):
    """Convert a Sigma YAML string (pasted text) to a Chael rule."""
    try:
        chael_rule = convert_sigma_to_chael_rule(req.yaml)
        return {"status": "success", "rule": chael_rule.dict()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Conversion error: {str(e)}")


@router.post("/deploy")
async def deploy_sigma(req: SigmaDeployRequest):
    """Convert Sigma YAML AND deploy it live as a correlation rule (wires sigma -> detection)."""
    from detection.correlation import engine
    try:
        chael_rule = convert_sigma_to_chael_rule(req.yaml)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    data = chael_rule.dict()
    if req.threshold_override is not None:
        data["threshold"] = req.threshold_override
    data["enabled"] = req.enabled
    data["source"] = "sigma"
    ok = engine.add_dynamic_rule(data)
    if not ok:
        raise HTTPException(status_code=500, detail="Converted but failed to save (Redis unavailable?)")
    return {"status": "deployed", "rule": data}


@router.post("/deploy/file")
async def deploy_sigma_file(file: UploadFile = File(...)):
    """Upload Sigma file AND deploy live."""
    from detection.correlation import engine
    if not file.filename.endswith(('.yml', '.yaml')):
        raise HTTPException(status_code=400, detail="Only YAML files are supported")
    content = await file.read()
    try:
        chael_rule = convert_sigma_to_chael_rule(content.decode('utf-8'))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    data = chael_rule.dict()
    data["source"] = "sigma"
    ok = engine.add_dynamic_rule(data)
    if not ok:
        raise HTTPException(status_code=500, detail="Converted but failed to save")
    return {"status": "deployed", "rule": data}


@router.get("/coverage")
async def sigma_coverage():
    """MITRE coverage: which techniques have live rules (Sigma-wired parity check)."""
    from detection.correlation import engine
    try:
        from mitre.attack import ATTACK_TECHNIQUES
    except ImportError:
        ATTACK_TECHNIQUES = {}
    rules = engine.get_dynamic_rules()
    covered: Dict[str, int] = {}
    for r in rules:
        for t in r.get("mitre_attack", []) or ([r.get("technique_id")] if r.get("technique_id") else []):
            if t:
                covered[t.upper()] = covered.get(t.upper(), 0) + 1
    missing = [tid for tid in ATTACK_TECHNIQUES if tid.upper() not in covered]
    return {
        "total_techniques": len(ATTACK_TECHNIQUES),
        "covered": len(covered),
        "coverage_pct": round(len(covered) / len(ATTACK_TECHNIQUES) * 100, 1) if ATTACK_TECHNIQUES else 0,
        "covered_map": covered,
        "missing": missing,
        "total_rules": len(rules),
    }
