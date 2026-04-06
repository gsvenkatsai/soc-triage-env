from environment.models import SOCState, Action, AlertSummary, Severity
from environment.reward import compute_reward
from datetime import datetime


def make_state(actions_taken=[], severity=Severity.HIGH):
    alert = AlertSummary(
        alert_id="test-001", title="Test", severity=severity,
        timestamp=datetime.now(), description="Test alert"
    )
    return SOCState(
        alert_id="test-001", alert_summary=alert, severity=severity,
        timestamp=datetime.now(), assets_involved=[], logs_available=[],
        actions_taken=actions_taken, step_count=0, max_steps=10
    )


GT = {
    "correct_verdict": "escalate",
    "required_evidence": ["query_ip_reputation", "pull_logs"],
    "relevant_actions": ["query_ip_reputation", "pull_logs", "check_asset_criticality"],
    "kill_chain": None,
}


def test_relevant_action_bonus():
    state = make_state()
    action = Action(action_type="query_ip_reputation", parameters={}, result="", step=0)
    assert compute_reward(state, action, GT) == 0.10


def test_irrelevant_action_penalty():
    state = make_state()
    action = Action(action_type="lookup_user", parameters={}, result="", step=0)
    assert compute_reward(state, action, GT) == -0.05


def test_correct_verdict_with_evidence():
    prior = [
        Action(action_type="query_ip_reputation", parameters={}, result="", step=0),
        Action(action_type="pull_logs", parameters={}, result="", step=1),
    ]
    state = make_state(actions_taken=prior)
    action = Action(action_type="escalate", parameters={}, result="", step=2)
    assert compute_reward(state, action, GT) == 0.50


def test_wrong_verdict_critical_penalty():
    state = make_state(severity=Severity.CRITICAL)
    action = Action(action_type="close_false_positive", parameters={}, result="", step=0)
    reward = compute_reward(state, action, GT)
    assert reward < 0