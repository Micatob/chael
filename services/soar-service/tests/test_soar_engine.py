import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import MagicMock, patch
import pytest
from soar.engine import SOAREngine, SOARAction


@pytest.fixture
def notifier():
    mock = MagicMock()
    mock.send_notification.return_value.success = True
    return mock


@pytest.fixture
def engine(notifier):
    return SOAREngine(notification_service=notifier)


@pytest.fixture
def brute_force_incident():
    class MockIncident:
        incident_id = "inc-test-001"
        risk_score = 85
        description = "Multiple brute force login attempts detected"
        artifacts = {"attack_type": "brute_force", "target_host": "203.0.113.42", "host": "web-01"}
        source_logs = []
    return MockIncident()


@pytest.fixture
def critical_incident():
    class MockIncident:
        incident_id = "inc-test-002"
        risk_score = 95
        description = "CRITICAL exploit attempt against web application"
        artifacts = {"target_host": "10.0.0.5", "host": "web-02"}
        source_logs = []
    return MockIncident()


class TestSOARAction:
    def test_action_created_with_pending_status(self):
        action = SOARAction("block_ip", {"ip": "1.2.3.4"})
        assert action.status == "PENDING"
        assert action.name == "block_ip"
        assert action.action_id is not None

    def test_to_dict_returns_correct_keys(self):
        action = SOARAction("isolate_host", {"host": "server-01"})
        d = action.to_dict()
        assert d["name"] == "isolate_host"
        assert d["status"] == "PENDING"
        assert "action_id" in d
        assert "created_at" in d


class TestPlaybookSelection:
    def test_selects_brute_force_playbook(self, engine, brute_force_incident):
        actions = engine._determine_playbook(brute_force_incident)
        assert len(actions) > 0
        assert actions[0]["action"] == "block_ip"

    def test_selects_critical_playbook(self, engine, critical_incident):
        actions = engine._determine_playbook(critical_incident)
        assert len(actions) > 0
        assert any(a["action"] == "isolate_host" for a in actions)

    def test_selects_default_playbook(self, engine):
        class MockIncident:
            incident_id = "inc-test-003"
            risk_score = 30
            description = "Minor event"
            artifacts = {}
            source_logs = []
        actions = engine._determine_playbook(MockIncident())
        assert len(actions) > 0


class TestTrigger:
    def test_trigger_returns_results_list(self, engine, brute_force_incident):
        results = engine.trigger(brute_force_incident)
        assert isinstance(results, list)
        assert len(results) > 0

    def test_trigger_executes_block_ip(self, engine, brute_force_incident):
        results = engine.trigger(brute_force_incident)
        block_results = [r for r in results if r["name"] == "block_ip"]
        assert len(block_results) >= 1
        assert block_results[0]["status"] in ("EXECUTED", "FAILED")

    def test_trigger_records_execution_history(self, engine, brute_force_incident):
        engine.trigger(brute_force_incident)
        assert len(engine._execution_history) > 0


class TestApproveAction:
    def test_approve_existing_action(self, engine, critical_incident):
        engine.trigger(critical_incident)
        action_id = engine._pending_actions[("inc-test-002", list(engine._pending_actions.keys())[0][1])]["action"].action_id
        result = engine.approve_action("inc-test-002", action_id)
        assert result is True

    def test_approve_nonexistent_action(self, engine):
        result = engine.approve_action("inc-nonexistent", "no-such-action")
        assert result is False

    def test_approve_updates_status(self, engine, critical_incident):
        engine.trigger(critical_incident)
        key = list(engine._pending_actions.keys())[0]
        action_id = key[1]
        engine.approve_action(key[0], action_id)
        assert engine._pending_actions[key]["status"] == "APPROVED"


class TestGetPendingActions:
    def test_get_pending_after_trigger(self, engine, critical_incident):
        # Critical playbook has indefinite isolate/block -> queued for approval
        engine.trigger(critical_incident)
        pending = engine.get_pending_actions("inc-test-002")
        assert len(pending) >= 1

    def test_low_impact_auto_executes_no_pending(self, engine, brute_force_incident):
        # Brute-force block is time-boxed (60m) -> auto-executes, not pending
        engine.trigger(brute_force_incident)
        pending = engine.get_pending_actions("inc-test-001")
        assert len(pending) == 0

    def test_reject_pending_action(self, engine, critical_incident):
        engine.trigger(critical_incident)
        keys = [k for k in engine._pending_actions.keys() if k[0] == "inc-test-002"]
        assert len(keys) >= 1
        for k in keys:
            assert engine.reject_action(k[0], k[1]) is True
        assert engine.get_pending_actions("inc-test-002") == []

    def test_approve_does_not_double_execute(self, engine, critical_incident):
        engine.trigger(critical_incident)
        key = list(engine._pending_actions.keys())[0]
        n_before = len(engine._execution_history)
        assert engine.approve_action(key[0], key[1], incident=critical_incident) is True
        n_after_first = len(engine._execution_history)
        assert n_after_first == n_before + 1
        assert engine.approve_action(key[0], key[1], incident=critical_incident) is True
        assert len(engine._execution_history) == n_after_first

    def test_pending_empty_after_none(self, engine):
        pending = engine.get_pending_actions("inc-nonexistent")
        assert len(pending) == 0


class TestPlaybookDefinitions:
    def test_brute_force_playbook_has_block_ip(self, engine):
        assert "BRUTE_FORCE" in engine.playbooks
        assert any(a["action"] == "block_ip" for a in engine.playbooks["BRUTE_FORCE"])

    def test_critical_playbook_has_isolate_host(self, engine):
        assert "CRITICAL" in engine.playbooks
        assert any(a["action"] == "isolate_host" for a in engine.playbooks["CRITICAL"])

    def test_repeated_errors_playbook_exists(self, engine):
        assert "REPEATED_ERRORS" in engine.playbooks

    def test_default_playbook_exists(self, engine):
        assert "DEFAULT" in engine.playbooks


class TestHealthEndpoint:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


class TestAgentTasks:
    def test_queue_and_poll(self, engine):
        task = engine.queue_agent_task("isolate", "web-01", incident_id="inc-1",
                                       hostname="web-01")
        assert task["status"] == "PENDING"
        assert task["action"] == "isolate"
        pending = engine.get_agent_tasks(hostname="web-01")
        assert any(t["task_id"] == task["task_id"] for t in pending)

    def test_targeted_task_hidden_from_others(self, engine):
        task = engine.queue_agent_task("block", "1.2.3.4", hostname="web-01")
        assert engine.get_agent_tasks(hostname="other-host") == [] or all(
            t["task_id"] != task["task_id"] for t in engine.get_agent_tasks(hostname="other-host"))

    def test_invalid_action_rejected(self, engine):
        with pytest.raises(ValueError):
            engine.queue_agent_task("rm-rf", "web-01")

    def test_missing_target_rejected(self, engine):
        with pytest.raises(ValueError):
            engine.queue_agent_task("isolate", "")

    def test_ack_and_report_lifecycle(self, engine, critical_incident):
        task = engine.queue_agent_task("isolate", "web-02", incident_id="inc-test-002")
        assert engine.ack_agent_task(task["task_id"], agent_id="agent-1") is True
        assert engine._agent_tasks[task["task_id"]]["status"] == "ACKED"
        n_before = len(engine._execution_history)
        assert engine.report_agent_task(task["task_id"], True, "netsh ok", agent_id="agent-1") is True
        assert engine._agent_tasks[task["task_id"]]["status"] == "DONE"
        assert len(engine._execution_history) == n_before + 1

    def test_report_unknown_task(self, engine):
        assert engine.report_agent_task("no-such-task", True) is False


class TestRecoverActions:
    def test_unisolate_executes(self, engine, critical_incident):
        from soar.engine import SOARAction
        action = SOARAction("unisolate_host", {"host": "web-02"})
        result = engine._execute_action(action, critical_incident)
        assert result["status"] in ("EXECUTED", "FAILED")

    def test_unblock_executes(self, engine, brute_force_incident):
        from soar.engine import SOARAction
        action = SOARAction("unblock_ip", {"ip": "203.0.113.42"})
        result = engine._execute_action(action, brute_force_incident)
        assert result["status"] in ("EXECUTED", "FAILED")


class FakeRedis:
    """Minimal hset/hgetall/delete stub for persistence tests."""

    def __init__(self):
        self.data = {}

    def hset(self, key, mapping=None, **kwargs):
        self.data.setdefault(key, {}).update(mapping or {})
        return len(mapping or {})

    def hgetall(self, key):
        return dict(self.data.get(key, {}))

    def delete(self, key):
        self.data.pop(key, None)
        return 1


class TestDurableState:
    def test_pending_survives_rebuild(self, notifier):
        from soar.engine import SOAREngine
        fake = FakeRedis()
        e1 = SOAREngine(notification_service=notifier, redis_client=fake)
        assert "kill_process" in e1.VALID_AGENT_ACTIONS
        assert "collect_triage" in e1.VALID_AGENT_ACTIONS

        class SevereIncident:
            incident_id = "inc-sev-9"
            risk_score = 95
            description = "CRITICAL exploit with malware markers"
            artifacts = {"attack_type": "critical", "host": "web-9", "target_host": "203.0.113.9"}
            source_logs = []

        results = e1.trigger(SevereIncident(), requested_by="analyst-jo")
        assert any(r["name"] == "agent:collect_triage" and r["status"] == "QUEUED" for r in results)
        pending = e1.get_pending_actions("inc-sev-9")
        assert len(pending) >= 1
        assert all(p.get("requested_by") == "analyst-jo" for p in pending)

        e2 = SOAREngine(notification_service=notifier, redis_client=fake)
        restored = e2.get_pending_actions("inc-sev-9")
        assert len(restored) == len(pending)
        assert restored[0]["action"].name == pending[0]["action"].name
        tasks = e2.get_agent_tasks(hostname="web-9")
        assert any(t["action"] == "collect_triage" for t in tasks)

    def test_triage_deduped_per_host(self, engine):
        class SevereIncident:
            incident_id = "inc-dedupe"
            risk_score = 90
            description = "CRITICAL malware"
            artifacts = {"attack_type": "critical", "host": "web-d"}
            source_logs = []

        engine.trigger(SevereIncident(), requested_by="a")
        engine.trigger(SevereIncident(), requested_by="a")
        triage = [t for t in engine._agent_tasks.values()
                  if t["action"] == "collect_triage" and t.get("hostname") == "web-d"]
        assert len(triage) == 1

    def test_no_triage_below_threshold(self, engine):
        class MinorIncident:
            incident_id = "inc-minor"
            risk_score = 20
            description = "Minor event"
            artifacts = {"host": "web-m"}
            source_logs = []

        engine.trigger(MinorIncident())
        assert not [t for t in engine._agent_tasks.values() if t["action"] == "collect_triage"]


class TestApprovalRBAC:
    def test_requested_by_recorded(self, engine, critical_incident):
        engine.trigger(critical_incident, requested_by="analyst-zoe")
        pending = engine.get_pending_actions("inc-test-002")
        assert len(pending) >= 1
        assert pending[0]["requested_by"] == "analyst-zoe"
