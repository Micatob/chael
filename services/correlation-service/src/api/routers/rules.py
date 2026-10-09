import json
from fastapi import APIRouter, HTTPException, Body
from typing import List, Dict, Any
from pydantic import BaseModel

from detection.correlation import engine

router = APIRouter()

class RuleCondition(BaseModel):
    field: str
    operator: str
    value: str

class CorrelationRule(BaseModel):
    id: str
    name: str
    condition: RuleCondition
    threshold: int = 1
    window_seconds: int = 0
    risk_score: int = 50
    description: str = ""
    enabled: bool = True
    # MITRE ATT&CK tagging (enterprise parity)
    mitre_attack: List[str] = []
    tactic: str = ""
    technique: str = ""
    technique_id: str = ""
    severity: str = "MEDIUM"
    tags: List[str] = []
    source: str = "custom"  # custom | sigma | builtin

@router.get("/")
def list_rules() -> List[Dict[str, Any]]:
    return engine.get_dynamic_rules()

@router.post("/")
def create_rule(rule: CorrelationRule):
    success = engine.add_dynamic_rule(rule.dict())
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save rule (Redis unavailable?)")
    return {"status": "created", "rule": rule.dict()}

@router.put("/{rule_id}")
def update_rule(rule_id: str, rule: CorrelationRule):
    if rule.id != rule_id:
        raise HTTPException(status_code=400, detail="Rule ID mismatch")
    success = engine.add_dynamic_rule(rule.dict())
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update rule")
    return {"status": "updated", "rule": rule.dict()}

@router.patch("/{rule_id}/toggle")
def toggle_rule(rule_id: str):
    rules = engine.get_dynamic_rules()
    rule = next((r for r in rules if r["id"] == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule["enabled"] = not rule.get("enabled", True)
    success = engine.add_dynamic_rule(rule)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to toggle rule")
    return {"status": "toggled", "rule_id": rule_id, "enabled": rule["enabled"]}

@router.delete("/{rule_id}")
def delete_rule(rule_id: str):
    success = engine.delete_dynamic_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found or Redis unavailable")
    return {"status": "deleted", "id": rule_id}


@router.get("/mitre/techniques")
def list_mitre_techniques():
    """List supported MITRE ATT&CK techniques (for UI dropdowns)."""
    from mitre.attack import ATTACK_TECHNIQUES
    return {
        "total": len(ATTACK_TECHNIQUES),
        "techniques": [
            {"id": tid, **info} for tid, info in ATTACK_TECHNIQUES.items()
        ],
    }


@router.get("/by-mitre/{technique_id}")
def rules_by_technique(technique_id: str):
    """Find all rules mapped to a MITRE technique (coverage check)."""
    rules = engine.get_dynamic_rules()
    matched = [
        r for r in rules
        if technique_id.upper() in [str(x).upper() for x in r.get("mitre_attack", [])]
        or r.get("technique_id", "").upper() == technique_id.upper()
    ]
    return {"technique_id": technique_id.upper(), "total": len(matched), "rules": matched}
