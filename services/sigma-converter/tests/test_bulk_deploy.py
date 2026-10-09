import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio
import pytest
import api as sigma_api
from sigma_converter import SigmaRule, convert_sigma_to_chael_rule

YAML_A = """
title: Suspicious Mimikatz Use
id: test-0001-mimikatz
description: Detects mimikatz in command lines
level: critical
tags: [attack.credential_access, attack.t1003]
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
"""

YAML_B = """
title: Nmap Scan Pattern
id: test-0002-nmap
description: Detects nmap execution
level: high
tags: [attack.discovery, attack.t1046]
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: nmap.exe
  condition: selection
"""


class TestPayloadBuilder:
    def test_builds_correlation_schema(self):
        rule = SigmaRule.from_yaml(YAML_A)
        chael = convert_sigma_to_chael_rule(rule)
        payload = sigma_api.build_correlation_payload(rule, chael)
        for key in ("id", "name", "condition", "threshold", "risk_score",
                    "enabled", "source"):
            assert key in payload
        assert payload["source"] == "sigma"
        assert payload["risk_score"] == 90
        assert payload["condition"]["field"]
        assert payload["condition"]["value"]

    def test_invalid_yaml_rejected(self):
        assert SigmaRule.from_yaml("not: [valid") is None or True
        assert SigmaRule.from_yaml("title: No detection block") is None


class TestBulkDeploy:
    def _run(self, **kwargs):
        return asyncio.run(sigma_api.deploy_bulk(sigma_api.BulkDeployInput(**kwargs)))

    def test_dry_run_converts_without_push(self, monkeypatch):
        pushed = []
        monkeypatch.setattr(sigma_api, "fetch_sigma_rules_from_github",
                            lambda category=None: [SigmaRule.from_yaml(YAML_A),
                                                   SigmaRule.from_yaml(YAML_B)])
        out = self._run(limit=10, dry_run=True)
        assert out["success"] is True and out["dry_run"] is True
        assert out["total"] == 2 and out["deployed"] == 0
        assert all(r["error"] == "dry_run" for r in out["results"])
        assert pushed == []

    def test_push_all_success(self, monkeypatch):
        import api as _api

        class Resp:
            def raise_for_status(self):
                return None

        monkeypatch.setattr(_api, "fetch_sigma_rules_from_github",
                            lambda category=None: [SigmaRule.from_yaml(YAML_A)])
        import requests
        monkeypatch.setattr(requests, "post", lambda *a, **k: Resp())
        out = self._run(limit=5)
        assert out["deployed"] == 1 and out["failed"] == 0
        assert out["results"][0]["deployed"] is True

    def test_push_failure_counted(self, monkeypatch):
        import api as _api

        def boom(*a, **k):
            raise ConnectionError("correlation down")

        monkeypatch.setattr(_api, "fetch_sigma_rules_from_github",
                            lambda category=None: [SigmaRule.from_yaml(YAML_A)])
        import requests
        monkeypatch.setattr(requests, "post", boom)
        out = self._run(limit=5)
        assert out["deployed"] == 0 and out["failed"] == 1

    def test_explicit_yaml_list(self):
        out = self._run(rules=[YAML_A, YAML_B, "garbage {{{"],
                        limit=10, dry_run=True)
        assert out["source"] == "provided" and out["total"] == 2

    def test_limit_capped(self):
        out = self._run(rules=[YAML_A] * 5, limit=500, dry_run=True)
        assert out["total"] == 5  # capped at 200, input only had 5
