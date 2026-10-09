import pytest


class TestAttackTypeDetection:
    def test_detects_brute_force_from_artifacts(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert result["attack_classification"] == "brute_force"

    def test_detects_critical_from_event_type(self, engine, critical_incident):
        result = engine.analyze(critical_incident)
        assert result["attack_classification"] == "critical"

    def test_detects_unknown_when_no_match(self, engine, low_confidence_incident):
        result = engine.analyze(low_confidence_incident)
        assert result["attack_classification"] == "unknown"


class TestSeverityAssessment:
    def test_critical_severity(self, engine, critical_incident):
        result = engine.analyze(critical_incident)
        assert result["severity_assessment"] == "CRITICAL"

    def test_high_severity(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert result["severity_assessment"] == "HIGH"

    def test_low_severity(self, engine, low_confidence_incident):
        result = engine.analyze(low_confidence_incident)
        assert result["severity_assessment"] == "LOW"


class TestIndicatorsExtraction:
    def test_extracts_ips(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        ips = result["indicators_extracted"]["ip_addresses"]
        assert "203.0.113.42" in ips
        assert "198.51.100.7" in ips

    def test_extracts_usernames(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        users = result["indicators_extracted"]["usernames"]
        assert "admin" in users
        assert "root" in users

    def test_extracts_cves(self, engine, critical_incident):
        result = engine.analyze(critical_incident)
        cves = result["indicators_extracted"]["cve_ids"]
        assert "CVE-2025-1234" in cves

    def test_no_extractions_on_low_confidence_incident(self, engine, low_confidence_incident):
        result = engine.analyze(low_confidence_incident)
        assert result["indicators_extracted"]["ip_addresses"] == ["10.0.0.1"]
        assert result["indicators_extracted"]["usernames"] == []


class TestIOCMatches:
    def test_ioc_matches_contains_ips(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        ioc_ips = [i for i in result["ioc_matches"] if i["type"] == "IP_ADDRESS"]
        assert len(ioc_ips) >= 2
        assert all(i["confidence"] > 0 for i in ioc_ips)

    def test_ioc_matches_contains_usernames(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        ioc_users = [i for i in result["ioc_matches"] if i["type"] == "USERNAME"]
        assert len(ioc_users) >= 1

    def test_ioc_matches_contains_cves(self, engine, critical_incident):
        result = engine.analyze(critical_incident)
        ioc_cves = [i for i in result["ioc_matches"] if i["type"] == "CVE"]
        assert len(ioc_cves) >= 1

    def test_ioc_has_ip_match(self, engine, low_confidence_incident):
        result = engine.analyze(low_confidence_incident)
        assert any(i["type"] == "IP_ADDRESS" for i in result["ioc_matches"])


class TestWalkthrough:
    def test_walkthrough_is_list_of_strings(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert isinstance(result["walkthrough"], list)
        assert len(result["walkthrough"]) > 0
        assert all(isinstance(s, str) for s in result["walkthrough"])

    def test_walkthrough_contains_mitre_ref(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        joined = " ".join(result["walkthrough"])
        assert "T1110" in joined or "T1190" in joined

    def test_walkthrough_mentions_attack_type(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        joined = " ".join(result["walkthrough"])
        assert "Brute Force" in joined or "brute_force" in joined


class TestFollowUpSteps:
    def test_follow_up_steps_key_exists(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert "follow_up_steps" in result

    def test_follow_up_steps_is_list_of_strings(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert isinstance(result["follow_up_steps"], list)
        assert len(result["follow_up_steps"]) > 0
        assert all(isinstance(s, str) for s in result["follow_up_steps"])

    def test_follow_up_steps_brute_force_has_IAM_audit(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        joined = " ".join(result["follow_up_steps"])
        assert "AUDIT" in joined

    def test_follow_up_steps_critical_has_forensic_imaging(self, engine, critical_incident):
        result = engine.analyze(critical_incident)
        joined = " ".join(result["follow_up_steps"])
        assert "IMAGING" in joined or "imaging" in joined

    def test_follow_up_steps_unknown_has_review(self, engine, low_confidence_incident):
        result = engine.analyze(low_confidence_incident)
        joined = " ".join(result["follow_up_steps"])
        assert "REVIEW" in joined or "review" in joined


class TestMitreTechnique:
    def test_mitre_maps_brute_force(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert result["mitre_technique"]["id"] == "T1110"
        assert result["mitre_technique"]["tactic"] == "Credential Access"

    def test_mitre_maps_critical(self, engine, critical_incident):
        result = engine.analyze(critical_incident)
        assert result["mitre_technique"]["id"] == "T1190"
        assert result["mitre_technique"]["tactic"] == "Initial Access"

    def test_mitre_empty_for_unknown(self, engine, low_confidence_incident):
        result = engine.analyze(low_confidence_incident)
        assert result["mitre_technique"]["id"] is None


class TestFalsePositiveChecklist:
    def test_fp_checklist_for_brute_force(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert len(result["false_positive_checklist"]) > 0
        assert any("scanner" in c.lower() for c in result["false_positive_checklist"])

    def test_fp_checklist_for_unknown(self, engine, low_confidence_incident):
        result = engine.analyze(low_confidence_incident)
        assert len(result["false_positive_checklist"]) > 0


class TestConfidenceScore:
    def test_confidence_high_with_multiple_logs(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert result["confidence_score"] >= 0.80
        assert result["confidence_label"] == "HIGH"

    def test_confidence_low_with_single_log(self, engine, low_confidence_incident):
        result = engine.analyze(low_confidence_incident)
        assert result["confidence_score"] <= 0.75
        assert result["confidence_label"] != "HIGH"


class TestVerdictGuide:
    def test_verdict_contains_action_instruction(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert "ACTION:" in result["soc_verdict_guide"]

    def test_verdict_contains_verdict_label(self, engine, brute_force_incident):
        result = engine.analyze(brute_force_incident)
        assert "VERDICT:" in result["soc_verdict_guide"]
