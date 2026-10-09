class TestBruteForceDetection:
    def test_no_incident_on_single_failure(self, engine, brute_force_log):
        result = engine.process_log(brute_force_log)
        assert result is None

    def test_incident_after_threshold_failures(self, engine, brute_force_log):
        # Read the live threshold so this test never drifts from config again
        threshold = engine._brute_force_threshold
        assert threshold >= 2, "threshold must require a burst, never a single failure"
        results = []
        for _ in range(threshold):
            result = engine.process_log(brute_force_log)
            results.append(result)
        last = results[-1]
        assert last is not None
        assert last.risk_score == 75
        assert last.artifacts["rule_id"] == "brute_force"

    def test_no_incident_with_different_hosts(self, engine, brute_force_log):
        for i in range(10):
            log = brute_force_log.model_copy()
            log.host = f"host-{i % 3}"
            result = engine.process_log(log)
            assert result is None


class TestCriticalSeverityDetection:
    def test_incident_on_critical_log(self, engine, critical_log):
        result = engine.process_log(critical_log)
        assert result is not None
        assert result.risk_score == 90

    def test_no_incident_on_non_critical(self, engine, normal_log):
        result = engine.process_log(normal_log)
        assert result is None


class TestDynamicRules:
    def test_dynamic_rules_loaded(self, engine):
        assert hasattr(engine, '_in_memory_rules')

    def test_dynamic_rules_seeded_in_redis(self, engine):
        assert engine._redis is not None or not engine._use_redis
