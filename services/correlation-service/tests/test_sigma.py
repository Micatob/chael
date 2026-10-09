import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import patch
import yaml

SAMPLE_SIGMA = """
title: Detect Brute Force via SSH
id: 12345678-1234-1234-1234-123456789012
status: test
description: Detects multiple failed SSH login attempts
logsource:
    category: authentication
    product: linux
detection:
    selection:
        message: 'Failed password*'
    condition: selection | count() >= 5
fields:
    - message
    - host
falsepositives:
    - Legitimate users mistyping passwords
level: high
"""

SAMPLE_SIGMA_WEAK = """
title: Generic Login Detection
id: 00000000-0000-0000-0000-000000000000
detection:
    selection:
        message: 'login*'
    condition: selection
level: low
"""


class TestSigmaConverter:
    def test_convert_brute_force_rule(self):
        from api.routers.sigma import convert_sigma_to_chael_rule
        result = convert_sigma_to_chael_rule(SAMPLE_SIGMA)
        assert result is not None
        assert result.name == "Detect Brute Force via SSH"
        assert result.condition.field == "message"
        assert result.condition.value == "Failed password"
        assert result.risk_score == 75

    def test_convert_low_level_rule(self):
        from api.routers.sigma import convert_sigma_to_chael_rule
        result = convert_sigma_to_chael_rule(SAMPLE_SIGMA_WEAK)
        assert result is not None
        assert result.risk_score == 25

    def test_invalid_yaml_returns_none(self):
        from api.routers.sigma import convert_sigma_to_chael_rule
        import pytest
        with pytest.raises((ValueError, yaml.YAMLError)):
            convert_sigma_to_chael_rule("not: valid: yaml: [[[")

    def test_empty_string_returns_none(self):
        from api.routers.sigma import convert_sigma_to_chael_rule
        import pytest
        with pytest.raises((ValueError, yaml.YAMLError)):
            convert_sigma_to_chael_rule("")
