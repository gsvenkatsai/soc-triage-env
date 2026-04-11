"""
Tests for the reward computation function.
"""

import pytest
from environment.models import SOCState, ActionRecord, AlertSummary, Severity
from environment.reward import compute_reward


def make_state(actions_taken=None, severity=Severity.HIGH):
    """Helper to create a test state."""
    alert = AlertSummary(
        alert_id="test-001", title="Test Alert", severity=severity,
        timestamp="2024-06-01T10:00:00", description="Test alert description"
    )
    return SOCState(
        episode_id="test-ep",
        task_id="test",
        alert_id="test-001",
        alert_summary=alert,
        severity=severity,
        timestamp="2024-06-01T10:00:00",
        assets_involved=[],
        logs_available=[],
        actions_taken=actions_taken or [],
        step_count=0,
        max_steps=10,
    )


GT = {
    "correct_verdict": "escalate",
    "required_evidence": [
        {"action_type": "query_ip_reputation", "parameters": {"ip": "1.2.3.4"}},
        {"action_type": "pull_logs", "parameters": {"source": "auth.log"}},
    ],
    "relevant_actions": ["query_ip_reputation", "pull_logs", "check_asset_criticality"],
    "relevant_parameters": {
        "query_ip_reputation": ["1.2.3.4"],
        "pull_logs": ["auth.log", "network.log"],
        "check_asset_criticality": ["A001"],
    },
    "escalation_keywords": ["brute", "force", "ssh"],
    "containment_targets": {
        "block_ip": ["1.2.3.4"],
        "isolate_host": [],
    },
    "context": {},
}


class TestInvestigativeRewards:
    """Tests for investigative action rewards."""

    def test_relevant_action_with_relevant_params(self):
        state = make_state()
        action = ActionRecord(action_type="pull_logs", parameters={"source": "auth.log"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert total > 0  # Relevant action + relevant param
        assert "relevant_action" in components
        assert "relevant_parameter" in components

    def test_relevant_action_with_irrelevant_params(self):
        state = make_state()
        action = ActionRecord(action_type="pull_logs", parameters={"source": "email.log"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert "relevant_action" in components
        assert "irrelevant_parameter" in components

    def test_irrelevant_action(self):
        state = make_state()
        action = ActionRecord(action_type="lookup_user", parameters={"username": "bob"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert "irrelevant_action" in components
        assert total < 0  # Step cost + irrelevant

    def test_repeated_action_penalty(self):
        prior = [
            ActionRecord(action_type="pull_logs", parameters={"source": "auth.log"}, result="", step=0),
        ]
        state = make_state(actions_taken=prior)
        action = ActionRecord(action_type="pull_logs", parameters={"source": "auth.log"}, result="", step=1)
        total, components = compute_reward(state, action, GT)
        assert "repeated_action" in components
        assert total < 0

    def test_step_cost_always_applied(self):
        state = make_state()
        action = ActionRecord(action_type="pull_logs", parameters={"source": "auth.log"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert "step_cost" in components
        assert components["step_cost"] == -0.02

    def test_evidence_progress_bonus(self):
        state = make_state()
        action = ActionRecord(action_type="pull_logs", parameters={"source": "auth.log"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert "evidence_progress" in components
        assert components["evidence_progress"] > 0


class TestVerdictRewards:
    """Tests for verdict action rewards."""

    def test_correct_verdict_with_evidence(self):
        prior = [
            ActionRecord(action_type="query_ip_reputation", parameters={"ip": "1.2.3.4"}, result="", step=0),
            ActionRecord(action_type="pull_logs", parameters={"source": "auth.log"}, result="", step=1),
        ]
        state = make_state(actions_taken=prior)
        action = ActionRecord(action_type="escalate", parameters={"reason": "SSH brute force"}, result="", step=2)
        total, components = compute_reward(state, action, GT)
        assert components.get("verdict_correct", 0) == 0.30
        assert components.get("evidence_quality", 0) == 0.20
        assert total > 0.4

    def test_wrong_verdict_on_critical(self):
        state = make_state(severity=Severity.CRITICAL)
        action = ActionRecord(action_type="close_false_positive", parameters={"reason": "nah"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert components.get("verdict_wrong", 0) == -0.30
        assert total < 0

    def test_verdict_with_no_investigation(self):
        state = make_state()
        action = ActionRecord(action_type="escalate", parameters={"reason": "stuff"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert "no_investigation" in components
        assert components["no_investigation"] == -0.20

    def test_response_quality_keywords(self):
        prior = [ActionRecord(action_type="pull_logs", parameters={"source": "auth.log"}, result="", step=0)]
        state = make_state(actions_taken=prior)
        action = ActionRecord(action_type="escalate", parameters={"reason": "SSH brute force attack detected"}, result="", step=1)
        total, components = compute_reward(state, action, GT)
        assert "response_quality" in components
        assert components["response_quality"] > 0


class TestContainmentRewards:
    """Tests for containment action rewards."""

    def test_correct_block_ip(self):
        state = make_state()
        action = ActionRecord(action_type="block_ip", parameters={"ip": "1.2.3.4"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert "correct_containment" in components
        assert components["correct_containment"] == 0.10

    def test_wrong_block_ip(self):
        state = make_state()
        action = ActionRecord(action_type="block_ip", parameters={"ip": "8.8.8.8"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert "wrong_containment" in components

    def test_wrong_isolate_host(self):
        state = make_state()
        action = ActionRecord(action_type="isolate_host", parameters={"hostname": "web-server-01"}, result="", step=0)
        total, components = compute_reward(state, action, GT)
        assert "wrong_containment" in components
        assert components["wrong_containment"] == -0.15  # Heavier penalty