import pytest
from environment.env import SOCEnvironment


def test_reset_returns_observation():
    env = SOCEnvironment()
    obs = env.reset(task_id=1, seed=42)
    assert obs.alert.title == "SSH Brute Force Detected"
    assert obs.step_count == 0


def test_step_changes_state():
    env = SOCEnvironment()
    env.reset(task_id=1, seed=42)
    obs, rew, done, info = env.step("query_ip_reputation 185.220.101.45")
    assert obs.step_count == 1
    assert not done


def test_verdict_ends_episode():
    env = SOCEnvironment()
    env.reset(task_id=1, seed=42)
    env.step("query_ip_reputation 185.220.101.45")
    _, _, done, _ = env.step("escalate confirmed brute force")
    assert done


def test_repeated_action_penalty():
    env = SOCEnvironment()
    env.reset(task_id=1, seed=42)
    env.step("query_ip_reputation 185.220.101.45")
    _, rew, _, _ = env.step("query_ip_reputation 185.220.101.45")
    assert rew == -0.10


def test_deterministic_reset():
    env = SOCEnvironment()
    obs1 = env.reset(task_id=1, seed=42)
    obs2 = env.reset(task_id=1, seed=42)
    assert obs1.alert.alert_id == obs2.alert.alert_id