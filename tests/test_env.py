"""
Tests for the SOC Triage Environment core logic.
"""

import pytest
from environment.env import SOCEnvironment


class TestReset:
    """Tests for environment reset."""

    def test_reset_task1_returns_observation(self):
        env = SOCEnvironment()
        obs = env.reset(task_id=1, seed=42)
        assert obs.alert.title == "SSH Brute Force Detected"
        assert obs.step_count == 0
        assert obs.done is False
        assert len(obs.available_actions) > 0

    def test_reset_task2_returns_observation(self):
        env = SOCEnvironment()
        obs = env.reset(task_id=2, seed=42)
        assert "Lateral Movement" in obs.alert.title
        assert obs.step_count == 0

    def test_reset_task3_returns_observation(self):
        env = SOCEnvironment()
        obs = env.reset(task_id=3, seed=42)
        assert "APT" in obs.alert.title
        assert obs.alert.severity == "CRITICAL"

    def test_reset_invalid_task_raises(self):
        env = SOCEnvironment()
        with pytest.raises(ValueError):
            env.reset(task_id=99)

    def test_deterministic_reset(self):
        env = SOCEnvironment()
        obs1 = env.reset(task_id=1, seed=42)
        obs2 = env.reset(task_id=1, seed=42)
        assert obs1.alert.alert_id == obs2.alert.alert_id
        assert obs1.alert.description == obs2.alert.description

    def test_different_seeds_may_differ(self):
        env = SOCEnvironment()
        obs1 = env.reset(task_id=1, seed=42)
        obs2 = env.reset(task_id=1, seed=99)
        # Both should be valid observations regardless of seed
        assert obs1.alert.title == obs2.alert.title  # Title stays same for task 1
        assert obs1.step_count == 0
        assert obs2.step_count == 0


class TestStep:
    """Tests for environment step logic."""

    def test_step_increments_count(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        obs, rew, done, info = env.step("pull_logs auth.log")
        assert obs.step_count == 1
        assert done is False

    def test_step_returns_reward(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        obs, rew, done, info = env.step("query_ip_reputation 185.220.101.45")
        assert isinstance(rew, float)

    def test_verdict_ends_episode(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("query_ip_reputation 185.220.101.45")
        obs, rew, done, info = env.step("escalate brute force confirmed")
        assert done is True
        assert obs.done is True

    def test_max_steps_ends_episode(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        # Take 10 steps (max for task 1) without a verdict
        actions = [
            "pull_logs auth.log",
            "pull_logs network.log",
            "pull_logs endpoint.log",
            "pull_logs email.log",
            "pull_logs dns.log",
            "pull_logs proxy.log",
            "query_ip_reputation 185.220.101.45",
            "check_asset_criticality A001",
            "lookup_user ubuntu",
            "correlate_alerts 60",
        ]
        for i, action in enumerate(actions):
            obs, rew, done, info = env.step(action)
            if done:
                break
        assert done is True

    def test_step_after_done_raises(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("escalate done")
        with pytest.raises(RuntimeError):
            env.step("pull_logs auth.log")

    def test_empty_action_handled(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        obs, rew, done, info = env.step("")
        assert rew < 0  # Empty action gets negative reward
        assert "error" in info

    def test_invalid_action_handled(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        obs, rew, done, info = env.step("invalid_action something")
        assert "Unknown action" in obs.last_action_result

    def test_repeated_action_penalty(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("query_ip_reputation 185.220.101.45")
        obs, rew, done, info = env.step("query_ip_reputation 185.220.101.45")
        assert rew < 0  # Repeated action should be penalized

    def test_reward_components_in_info(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        obs, rew, done, info = env.step("pull_logs auth.log")
        assert "reward_components" in info
        assert isinstance(info["reward_components"], dict)

    def test_containment_action(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        obs, rew, done, info = env.step("block_ip 185.220.101.45")
        assert "[CONTAINMENT]" in obs.last_action_result
        assert done is False  # containment doesn't end episode


class TestState:
    """Tests for state retrieval."""

    def test_state_after_reset(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        state = env.state_dict()
        assert state.alert_id == "ALERT-001"
        assert state.step_count == 0
        assert len(state.actions_taken) == 0

    def test_state_tracks_actions(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("pull_logs auth.log")
        env.step("query_ip_reputation 185.220.101.45")
        state = env.state_dict()
        assert state.step_count == 2
        assert len(state.actions_taken) == 2

    def test_state_tracks_verdict(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("escalate brute force")
        state = env.state_dict()
        assert state.verdict == "escalate"
        assert state.done is True