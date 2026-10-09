import json
import logging
import os
import re
import yaml
import requests
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

SIGMA_TO_SEVERITY = {
    "high": "HIGH",
    "critical": "CRITICAL",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
}

SUPPORTED_OS = ["windows", "linux", "macos"]

RULE_TYPE_MAP = {
    "file_event": "file",
    "process_creation": "process",
    "image_load": "process",
    "registry_event": "registry",
    "network_connection": "network",
    "dns_query": "network",
    "pipe_created": "process",
    "wmi_event": "process",
    "dcom_error": "process",
    "raw_access_thread": "process",
    "driver_load": "process",
    "create_remote_thread": "process",
    "file_change": "file",
    "registry_add": "registry",
    "registry_set": "registry",
    "registry_delete": "registry",
    "process_access": "process",
    "process_termination": "process",
    "process_tampering": "process",
}


@dataclass
class SigmaRule:
    title: str
    id: str
    description: str = ""
    author: str = ""
    date: str = ""
    severity: str = "MEDIUM"
    status: str = "experimental"
    mitre_attack: List[str] = field(default_factory=list)
    logsource: Dict[str, str] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    false_positives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    original_yaml: str = ""
    category: str = ""
    product: str = ""
    service: str = ""

    @classmethod
    def from_yaml(cls, yaml_content: str) -> Optional["SigmaRule"]:
        try:
            data = yaml.safe_load(yaml_content)
            if not data or not isinstance(data, dict):
                return None
            if "title" not in data or "detection" not in data:
                return None

            logsource = data.get("logsource", {})
            mitre_tags = []
            for tag in data.get("tags", []):
                if tag.startswith("attack."):
                    mitre_tags.append(tag.replace("attack.", ""))

            return cls(
                title=data.get("title", "Untitled Rule"),
                id=data.get("id", ""),
                description=data.get("description", ""),
                author=data.get("author", ""),
                date=str(data.get("date", "")),
                severity=data.get("level", "medium").lower(),
                status=data.get("status", "experimental"),
                mitre_attack=mitre_tags,
                logsource=logsource,
                detection=data.get("detection", {}),
                false_positives=data.get("falsepositives", []),
                references=data.get("references", []),
                tags=data.get("tags", []),
                fields=data.get("fields", []),
                original_yaml=yaml_content,
                category=logsource.get("category", ""),
                product=logsource.get("product", ""),
                service=logsource.get("service", ""),
            )
        except yaml.YAMLError as e:
            logger.warning("Failed to parse Sigma YAML: %s", e)
            return None


def _convert_selection_to_condition(selection_name: str, selection: Any) -> Optional[Dict[str, Any]]:
    if isinstance(selection, str):
        return {"field": selection_name, "value": selection, "operator": "equals"}
    if isinstance(selection, list):
        return {"field": selection_name, "value": selection, "operator": "in_list"}
    if isinstance(selection, dict):
        conditions = []
        for key, val in selection.items():
            if key == "|contains" or key.startswith("|contains|"):
                if isinstance(val, list):
                    conditions.append({"field": selection_name, "value": val, "operator": "contains"})
                else:
                    conditions.append({"field": selection_name, "value": [val], "operator": "contains"})
            elif key == "|endswith":
                conditions.append({"field": selection_name, "value": [val] if isinstance(val, str) else val, "operator": "endswith"})
            elif key == "|startswith":
                conditions.append({"field": selection_name, "value": [val] if isinstance(val, str) else val, "operator": "startswith"})
            elif key == "|re" or key.startswith("|re|"):
                conditions.append({"field": selection_name, "value": [val] if isinstance(val, str) else val, "operator": "regex"})
            elif key == "|base64offset":
                conditions.append({"field": selection_name, "value": [val] if isinstance(val, str) else val, "operator": "base64offset"})
            elif key == "|all":
                if isinstance(val, list):
                    for item in val:
                        conditions.append({"field": selection_name, "value": item, "operator": "all"})
            elif key == "|windash" or key.startswith("|windash|"):
                conditions.append({"field": selection_name, "value": [val] if isinstance(val, str) else val, "operator": "windash"})
            else:
                if isinstance(val, list):
                    conditions.append({"field": key, "value": val, "operator": "equals"})
                else:
                    conditions.append({"field": key, "value": [val], "operator": "equals"})
        if len(conditions) == 1:
            return conditions[0]
        return {"operator": "and", "conditions": conditions}
    return None


def convert_sigma_to_chael_rule(sigma_rule: SigmaRule) -> Dict[str, Any]:
    severity = SIGMA_TO_SEVERITY.get(sigma_rule.severity, "MEDIUM")
    logsource = sigma_rule.logsource
    category = sigma_rule.category or logsource.get("category", "")
    product = sigma_rule.product or logsource.get("product", "")
    service = sigma_rule.service or logsource.get("service", "")

    detection_map = {
        "category": category,
        "product": product,
        "service": service,
        "event_id": logsource.get("definition", ""),
    }

    conditions = []
    detection = sigma_rule.detection
    condition_expr = detection.get("condition", "selection")

    selections = {}
    for key, val in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(val, dict):
            selections[key] = val

    if selections:
        for name, selection in selections.items():
            cond = _convert_selection_to_condition(name, selection)
            if cond:
                conditions.append(cond)

    if not conditions:
        conditions.append({"field": "message", "value": sigma_rule.title, "operator": "regex"})

    timeframe_match = re.search(r"(\d+)([smhd])", detection.get("timeframe", ""))
    timeframe_seconds = None
    if timeframe_match:
        val, unit = int(timeframe_match.group(1)), timeframe_match.group(2)
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        timeframe_seconds = val * multipliers.get(unit, 1)

    rule_type = RULE_TYPE_MAP.get(category, "generic")

    chael_rule = {
        "sigma_id": sigma_rule.id,
        "title": sigma_rule.title,
        "description": sigma_rule.description,
        "author": sigma_rule.author,
        "date": sigma_rule.date,
        "severity": severity,
        "status": sigma_rule.status,
        "mitre_attack": sigma_rule.mitre_attack,
        "tags": sigma_rule.tags,
        "references": sigma_rule.references,
        "false_positives": sigma_rule.false_positives,
        "type": rule_type,
        "detection_map": detection_map,
        "conditions": {
            "operator": "and",
            "conditions": conditions,
        },
        "timeframe_seconds": timeframe_seconds,
        "source": "sigma_converter",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "enabled": True,
    }

    return chael_rule


def fetch_sigma_rules_from_github(repo_url: str = None, category: str = None) -> List[SigmaRule]:
    base_url = repo_url or "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules"
    rules = []

    categories = [category] if category else [
        "windows/process_creation",
        "windows/registry",
        "windows/file_event",
        "windows/network_connection",
        "windows/builtin",
        "windows/sysmon",
        "linux",
        "macos",
        "cloud",
    ]

    for cat in categories:
        url = f"{base_url}/{cat}"
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code != 200:
                continue
            files = resp.text.split("\n")
            yaml_files = [f for f in files if f.endswith(".yml") or f.endswith(".yaml")]
            for yf in yaml_files[:50]:
                rule_url = f"{base_url}/{cat}/{yf}"
                try:
                    rule_resp = requests.get(rule_url, timeout=15)
                    if rule_resp.status_code == 200:
                        rule = SigmaRule.from_yaml(rule_resp.text)
                        if rule:
                            rules.append(rule)
                except Exception as e:
                    logger.debug("Failed to fetch %s: %s", rule_url, e)
        except Exception as e:
            logger.warning("Failed to fetch category %s: %s", cat, e)

    logger.info("Fetched %d Sigma rules from GitHub", len(rules))
    return rules


def load_sigma_from_directory(directory_path: str) -> List[SigmaRule]:
    rules = []
    if not os.path.isdir(directory_path):
        logger.warning("Directory not found: %s", directory_path)
        return rules

    for root, dirs, files in os.walk(directory_path):
        for f in files:
            if not (f.endswith(".yml") or f.endswith(".yaml")):
                continue
            filepath = os.path.join(root, f)
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    content = fh.read()
                rule = SigmaRule.from_yaml(content)
                if rule:
                    rules.append(rule)
            except Exception as e:
                logger.warning("Failed to load %s: %s", filepath, e)

    logger.info("Loaded %d Sigma rules from directory", len(rules))
    return rules


def bulk_convert_sigma_to_chael(sigma_rules: List[SigmaRule]) -> List[Dict[str, Any]]:
    converted = []
    for rule in sigma_rules:
        try:
            chael_rule = convert_sigma_to_chael_rule(rule)
            converted.append(chael_rule)
        except Exception as e:
            logger.warning("Failed to convert rule '%s': %s", rule.title, e)
    logger.info("Converted %d/%d Sigma rules to Chael format", len(converted), len(sigma_rules))
    return converted